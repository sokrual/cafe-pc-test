using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Cafe;

public enum Role { Owner, Staff, Customer }

// The owner's rate card (10 Nov 2026), same on every PC. Money is always whole paise (₹1 = 100).
// 30 min ₹40, 1 hour ₹60, 1.5 hours ₹100, then ₹40 for each further 30 min; extra time past bought time is ₹40 per 30 min.
// GraceMin: free if the whole session is this short. BlockGraceMin: free minutes after each block or bought time ends.
// CarryOverDays: how long unused minutes stay usable (bought time and the unused part of a charged block).
/// Addresses the counter server answers: this PC, the shop network (private ranges) and Tailscale; never the internet.
public static class ShopNetwork
{
    public static bool Allows(System.Net.IPAddress? ip)
    {
        if (ip is null) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (System.Net.IPAddress.IsLoopback(ip)) return true;
        var b = ip.GetAddressBytes();
        return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] is >= 64 and <= 127)
            : ip.IsIPv6LinkLocal || (b[0] & 0xFE) == 0xFC; // link-local, unique local (Tailscale uses fd7a:...)
    }
}


/// Staff and owner PINs may be entered only on the counter PC or over Tailscale.
public static class StaffLoginNetwork
{
    public const string RefusalMessage = "Counter pages open only on the counter PC.";

    public static bool Allows(System.Net.IPAddress? remote, System.Net.IPAddress? local = null)
    {
        if (remote is null) return false;
        if (local is not null && remote.Equals(local)) return true;
        if (remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();
        if (System.Net.IPAddress.IsLoopback(remote)) return true;
        var b = remote.GetAddressBytes();
        if (remote.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            return b[0] == 100 && b[1] is >= 64 and <= 127;
        return remote.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            && b[0] == 0xfd && b[1] == 0x7a && b[2] == 0x11 && b[3] == 0x5c && b[4] == 0xa1 && b[5] == 0xe0;
    }
}

public record Rate(long Paise30 = 4000, long Paise60 = 6000, long Paise90 = 10000, long ExtraBlockPaise = 4000,
    int GraceMin = 5, int MinimumMin = 30, int BlockMin = 30, int BlockGraceMin = 5, int CarryOverDays = 7);

public record Bill(long SessionId, TimeSpan Used, long Charged, long Adjusted, long Paid)
{
    public long Due => Charged + Adjusted - Paid;
}

/// What a PC should show right now. Locked = lock screen (no session, or the admin locked it).
/// SelfLocked: the customer locked it (time keeps running; their PIN or staff unlocks it).
public record PcState(bool Locked, string? Message, long? Session, string? Mode, long ElapsedSec, long? LeftSec, bool SelfLocked = false, bool LockWhenTimeRunsOut = false);
public record OfflineSaleRequest(string SaleId, string Phone, string Code, long Step, int Minutes, string Method, string? UpiLast4, long? Session);

public class CafeException(string message) : Exception(message);

/// The admin PC's single source of truth: customers, sessions, money. Every public call is one transaction.
/// Money rows (ledger) and the audit log are append-only: the database itself refuses UPDATE and DELETE on them.
public sealed partial class CafeCore : IDisposable
{
    readonly SqliteConnection _db;
    readonly Func<DateTime> _now;
    readonly Action<string> _log;
    public Rate Rate { get; set; } = new();
    readonly HashSet<long> _timeLimitFailures = [];

    public CafeCore(string path, string key, Func<DateTime>? now = null, Action<string>? log = null)
    {
        _now = now ?? (() => DateTime.UtcNow);
        _log = log ?? (line => Console.Error.WriteLine(line));
        // Password makes Microsoft.Data.Sqlite send PRAGMA key; SQLite3 Multiple Ciphers encrypts the whole file
        _db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Password = key, Pooling = false }.ToString());
        _db.Open();
        // schema version: a newer program adds its changes as version 2, 3... and never reads a newer database by mistake
        const int SchemaVersion = 5; // 2: owner two-step login; 3: time-expiry setting; 4: offline sales; 5: separate offline secrets and per-person replay
        if (Scalar<long>("PRAGMA user_version") > SchemaVersion) { _db.Dispose(); throw new CafeException("The cafe data comes from a newer version of this program. Install the newer version."); }
        Exec("""
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, role INTEGER NOT NULL, name TEXT NOT NULL,
                phone TEXT NOT NULL UNIQUE, pin BLOB NOT NULL, fails INTEGER NOT NULL DEFAULT 0, locked_until TEXT);
            CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, pc TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users,
                prepaid_min INTEGER, plan_id INTEGER REFERENCES plans, group_id INTEGER, started TEXT NOT NULL, ended TEXT,
                paused_sec INTEGER NOT NULL DEFAULT 0, pause_from TEXT);
            CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users,
                minutes_left INTEGER NOT NULL, expires TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS shifts(id INTEGER PRIMARY KEY, staff_id INTEGER NOT NULL, opened TEXT NOT NULL, closed TEXT, counted INTEGER);
            -- kind: charge | adjust | pay | wallet. amount in paise, + or -.
            CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, at TEXT NOT NULL, by_user INTEGER NOT NULL, kind TEXT NOT NULL,
                amount INTEGER NOT NULL, session_id INTEGER, user_id INTEGER, method TEXT, ref TEXT, reason TEXT, shift_id INTEGER);
            -- each gaming PC: a secret token (only its SHA-256 is stored) and whether the admin has locked it
            CREATE TABLE IF NOT EXISTS pcs(name TEXT PRIMARY KEY, token BLOB NOT NULL UNIQUE, locked INTEGER NOT NULL DEFAULT 0, message TEXT,
                self_locked INTEGER NOT NULL DEFAULT 0, last_seen TEXT);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT NOT NULL, by_user INTEGER, action TEXT NOT NULL, detail TEXT);
            CREATE TABLE IF NOT EXISTS offline_sales(pc TEXT NOT NULL, sale_id TEXT NOT NULL, session_id INTEGER NOT NULL, staff_id INTEGER NOT NULL, step INTEGER NOT NULL, created TEXT NOT NULL, PRIMARY KEY(pc, sale_id));
            CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT OR IGNORE INTO settings(name, value) VALUES('lock_when_time_runs_out', '0');
            CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
            CREATE INDEX IF NOT EXISTS ledger_session ON ledger(session_id);
            CREATE INDEX IF NOT EXISTS ledger_user ON ledger(user_id, kind);
            CREATE INDEX IF NOT EXISTS sessions_open ON sessions(pc) WHERE ended IS NULL;
            """);
        if (Scalar<long>("PRAGMA user_version") < 2) // counter two-step secret, last counter-login step and recovery hash
            Exec("ALTER TABLE users ADD COLUMN totp BLOB; ALTER TABLE users ADD COLUMN totp_step INTEGER; ALTER TABLE users ADD COLUMN recovery BLOB;");
        if (Scalar<long>("PRAGMA user_version") < 5)
            Exec("ALTER TABLE users ADD COLUMN offline_totp BLOB; CREATE UNIQUE INDEX IF NOT EXISTS offline_sales_person_step ON offline_sales(staff_id, step);");
        Exec($"PRAGMA user_version = {SchemaVersion}");
        _ready = true;
        LoadRateCards();
    }

    public void Dispose() => _db.Dispose();

    /// The owner controls this setting; it is stored on the counter PC and defaults to off.
    public bool LockWhenTimeRunsOut => Tx(() => Scalar<long>("SELECT value FROM settings WHERE name = 'lock_when_time_runs_out'") == 1);

    public void SetLockWhenTimeRunsOut(long by, bool enabled) => Tx(() =>
    {
        RequireOwner(by);
        Exec("UPDATE settings SET value = @p0 WHERE name = 'lock_when_time_runs_out'", enabled ? "1" : "0");
        Audit(by, "setting_lock_when_time_runs_out", enabled ? "on" : "off");
    });

    // ---------------- people ----------------

    public long AddUser(long? by, Role role, string name, string phone, string pin)
    {
        // staff and owner logins work from any PC on the network, so their PINs must be much harder to guess
        var minPin = role == Role.Customer ? 4 : 6;
        if (pin.Length < minPin || pin.Length > 12 || !pin.All(char.IsAsciiDigit)) throw new CafeException($"PIN must be {minPin} to 12 digits");
        if (phone.Length is < 10 or > 13 || !phone.All(char.IsAsciiDigit)) throw new CafeException("The phone number must have 10 to 13 digits.");
        if (string.IsNullOrWhiteSpace(name) || name.Length > 60) throw new CafeException("The name can be at most 60 letters long.");
        return Tx(() =>
        {
            // the very first user is the owner; after that only the owner adds staff, staff add customers
            var count = Scalar<long>("SELECT count(*) FROM users");
            if (count == 0 ? role != Role.Owner : RoleOf(by) is not Role.Owner && !(RoleOf(by) == Role.Staff && role == Role.Customer))
                throw new CafeException("You cannot add this kind of user.");
            var id = Insert("INSERT INTO users(role, name, phone, pin) VALUES(@p0, @p1, @p2, @p3)", (int)role, name, phone, HashPin(pin));
            Audit(by ?? id, "add_user", $"user {id} role {role}");
            return id;
        });
    }

    /// PIN login with lockout: 3 wrong tries lock the account for 10 minutes.
    public long Login(string phone, string pin)
    {
        // A wrong PIN returns null instead of throwing inside the transaction, so the failed-try count is saved, not rolled back.
        long? id = Tx(() =>
        {
            using var r = Query("SELECT id, pin, fails, locked_until FROM users WHERE phone = @p0", phone);
            if (!r.Read()) return (long?)null;
            var (user, stored, fails, lockedUntil) = (r.GetInt64(0), (byte[])r[1], r.GetInt64(2), r.IsDBNull(3) ? (DateTime?)null : Time(r.GetString(3)));
            r.Close();
            if (lockedUntil > _now()) throw new CafeException("Too many wrong PINs. Try again in 10 minutes.");
            if (lockedUntil.HasValue)
            {
                // A completed lock starts a fresh three-attempt window.
                fails = 0;
                Exec("UPDATE users SET fails = 0, locked_until = NULL WHERE id = @p0", user);
            }
            if (!CheckPin(pin, stored))
            {
                Exec("UPDATE users SET fails = @p0, locked_until = @p1 WHERE id = @p2", fails + 1, fails + 1 >= 3 ? Iso(_now().AddMinutes(10)) : null, user);
                Audit(user, "login_failed", null);
                return null;
            }
            // with two-step login the count is cleared only after the app code too (StaffLogin), so codes cannot be guessed endlessly
            Exec("UPDATE users SET fails = 0, locked_until = NULL WHERE id = @p0 AND totp IS NULL", user);
            Audit(user, "login", null);
            return user;
        });
        return id ?? throw new CafeException("Wrong phone number or PIN."); // same message for unknown phone and wrong PIN
    }

    /// Staff and owner only: a customer's PIN must never open the counter pages (other customers' bills).
    public long StaffLogin(string phone, string pin, string? code = null)
    {
        var user = Login(phone, pin);
        // a wrong code returns false instead of throwing, so the failed-try count is saved (same as a wrong PIN)
        var ok = Tx(() =>
        {
            RequireStaff(user);
            using var r = Query("SELECT totp, totp_step, recovery FROM users WHERE id = @p0", user);
            r.Read();
            if (r.IsDBNull(0)) return true;
            var (key, last, recovery) = ((byte[])r[0], r.GetInt64(1), r.IsDBNull(2) ? null : (byte[])r[2]);
            r.Close();
            if (string.IsNullOrWhiteSpace(code)) throw new CafeException("Type the 6-digit code from the app on your phone.");
            if (TotpStep(key, code) is long step && step > last)
                Exec("UPDATE users SET totp_step = @p0, fails = 0, locked_until = NULL WHERE id = @p1", step, user);
            else if (recovery is not null && CryptographicOperations.FixedTimeEquals(recovery, SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(code.Trim().ToUpperInvariant()))))
            {
                Exec("UPDATE users SET recovery = NULL, fails = 0, locked_until = NULL WHERE id = @p0", user); // works once only
                Audit(user, "recovery_code_used", null);
            }
            else
            {
                Exec("UPDATE users SET fails = fails + 1, locked_until = CASE WHEN fails + 1 >= 5 THEN @p0 ELSE locked_until END WHERE id = @p1", Iso(_now().AddMinutes(15)), user);
                Audit(user, "login_failed", "two-step code");
                return false;
            }
            return true;
        });
        return ok ? user : throw new CafeException("Wrong code. Type the newest code from the app.");
    }

    // ---------------- sessions ----------------

    /// Pay-at-end: a stopwatch from 0, billed at stop by the rate card.
    public long StartPostpaid(long by, string pc, long user) => Start(by, pc, user, null, null);

    /// Prepaid countdown: the minutes are charged now. No money back, but unused minutes stay with the customer (see Stop).
    public long StartPrepaid(long by, string pc, long user, int minutes) => Tx(() =>
    {
        Minutes(minutes);
        var id = Start(by, pc, user, minutes, null);
        Ledger(by, "charge", Price(minutes), session: id, reference: $"prepaid {minutes} min");
        return id;
    });

    /// Time comes off the customer's plans and carried-over minutes; refused if nothing valid is left.
    public long StartOnPlan(long by, string pc, long user) => Tx(() =>
    {
        var plan = Scalar<long?>("SELECT id FROM plans WHERE user_id = @p0 AND minutes_left > 0 AND expires > @p1 ORDER BY expires LIMIT 1", user, Iso(_now()))
            ?? throw new CafeException("No plan time left. It has run out or expired.");
        return Start(by, pc, user, null, plan);
    });

    /// Minutes the customer can still play on plans and carried-over prepaid time (what the PC counts down from).
    public long PlanMinutesLeft(long user) => Tx(() =>
        Scalar<long>("SELECT coalesce(sum(minutes_left), 0) FROM plans WHERE user_id = @p0 AND minutes_left > 0 AND expires > @p1", user, Iso(_now())));

    long Start(long by, string pc, long user, int? prepaidMin, long? plan) => Tx(() =>
    {
        RequireStaffOrSelf(by, user);
        if (InUse(pc)) throw new CafeException($"{pc} is already in use");
        var id = Insert("INSERT INTO sessions(pc, user_id, prepaid_min, plan_id, started) VALUES(@p0, @p1, @p2, @p3, @p4)", pc, user, prepaidMin, plan, Iso(_now()));
        Audit(by, "start", $"session {id} on {pc} prepaid={prepaidMin} plan={plan}");
        return id;
    });

    public void AddTime(long by, long session, int minutes) => Tx(() =>
    {
        RequireStaff(by); Minutes(minutes); // negative minutes would be a staff discount, which only the owner may give
        if (Exec("UPDATE sessions SET prepaid_min = prepaid_min + @p0 WHERE id = @p1 AND ended IS NULL AND prepaid_min IS NOT NULL", minutes, session) == 0)
            throw new CafeException("Time can be added only for a prepaid customer who is playing.");
        Ledger(by, "charge", Price(minutes), session: session, reference: $"added {minutes} min");
        Audit(by, "add_time", $"session {session} +{minutes} min");
    });

    public void Pause(long by, long session) => Tx(() =>
    {
        RequireStaff(by);
        if (Exec("UPDATE sessions SET pause_from = @p0 WHERE id = @p1 AND ended IS NULL AND pause_from IS NULL", Iso(_now()), session) == 0)
            throw new CafeException("This customer is not playing right now.");
        Audit(by, "pause", $"session {session}");
    });

    /// Paused time is not charged unless the owner chooses to charge it.
    public void Resume(long by, long session, bool chargePausedTime = false) => Tx(() =>
    {
        if (chargePausedTime) RequireOwner(by); else RequireStaff(by);
        var from = Scalar<string?>("SELECT pause_from FROM sessions WHERE id = @p0 AND ended IS NULL", session) ?? throw new CafeException("This customer's time is not paused.");
        var paused = chargePausedTime ? 0 : (long)(_now() - Time(from)).TotalSeconds;
        Exec("UPDATE sessions SET paused_sec = paused_sec + @p0, pause_from = NULL WHERE id = @p1", paused, session);
        Audit(by, "resume", $"session {session} paused {paused}s charged={chargePausedTime}");
    });

    public void MoveSeat(long by, long session, string newPc) => Tx(() =>
    {
        RequireStaff(by);
        if (InUse(newPc)) throw new CafeException($"{newPc} is already in use");
        if (Exec("UPDATE sessions SET pc = @p0 WHERE id = @p1 AND ended IS NULL", newPc, session) == 0) throw new CafeException("This customer is not playing right now.");
        Audit(by, "move", $"session {session} to {newPc}");
    });

    /// One bill for several sessions (friends paying together). The group is named after its first session.
    public void JoinGroup(long by, long session, long groupOf) => Tx(() =>
    {
        RequireStaff(by);
        var g = Scalar<long?>("SELECT coalesce(group_id, id) FROM sessions WHERE id = @p0", groupOf) ?? throw new CafeException("This visit was not found.");
        Exec("UPDATE sessions SET group_id = @p0 WHERE id IN (@p1, @p0)", g, session);
        Audit(by, "group", $"session {session} joins group {g}");
    });

    /// Safe to call twice or at the same moment as the countdown's own stop: only the first call bills.
    /// at: when it really ended (a logout the PC queued while the admin PC was unreachable); default now.
    public Bill Stop(long by, long session, DateTime? at = null) => Tx(() =>
    {
        RequireStaffOrSelf(by, Scalar<long?>("SELECT user_id FROM sessions WHERE id = @p0", session) ?? throw new CafeException("This visit was not found."));
        var now = at ?? _now();
        if (Scalar<string?>("SELECT pause_from FROM sessions WHERE id = @p0 AND ended IS NULL", session) is string from) // stopping while paused ends the pause, uncharged
            Exec("UPDATE sessions SET paused_sec = paused_sec + @p0, pause_from = NULL WHERE id = @p1", Math.Max(0, (long)(now - Time(from)).TotalSeconds), session);
        if (Exec("UPDATE sessions SET ended = @p0 WHERE id = @p1 AND ended IS NULL", Iso(now), session) == 1)
        {
            Exec("UPDATE pcs SET self_locked = 0 WHERE name = (SELECT pc FROM sessions WHERE id = @p0)", session);
            var (used, prepaid, plan, user) = SessionUse(session);
            var usedMin = (int)Math.Ceiling(used.TotalMinutes); // bought time counts real minutes from the start, no grace
            if (prepaid is int bought)
            {
                if (usedMin < bought) CarryOver(by, user, bought - usedMin);
                else ChargeOvertime(by, session, user, used - TimeSpan.FromMinutes(bought), "past prepaid");
            }
            else if (plan is not null)
            {
                var left = usedMin; // take from the plans that expire first
                foreach (var (id, have) in Pairs("SELECT id, minutes_left FROM plans WHERE user_id = @p0 AND minutes_left > 0 AND expires > @p1 ORDER BY expires", user, Iso(_now())))
                {
                    var take = Math.Min(left, have);
                    Exec("UPDATE plans SET minutes_left = minutes_left - @p0 WHERE id = @p1", take, id);
                    Audit(by, "plan_use", $"plan {id} -{take} min");
                    if ((left -= (int)take) == 0) break;
                }
                if (left > 0) ChargeOvertime(by, session, user, used - TimeSpan.FromMinutes(usedMin - left), "past plan");
            }
            else
            {
                var billed = BillableMinutes(used);
                Ledger(by, "charge", Price(billed), session: session, user: user, reference: $"{billed} min");
                if (billed > usedMin) CarryOver(by, user, billed - usedMin); // the unused part of the last block
            }
            Audit(by, "stop", $"session {session} used {used}");
        }
        return BillFor(session);
    });

    // Over the bought time: 5 min grace, then 30-min blocks at the extra-block price; the unused part is kept.
    void ChargeOvertime(long by, long session, long user, TimeSpan over, string what)
    {
        var minutes = BillableMinutes(over, startGrace: false);
        if (minutes == 0) return;
        Ledger(by, "charge", minutes / Rate.BlockMin * Rate.ExtraBlockPaise, session: session, user: user, reference: $"{minutes} min {what}");
        var overMin = (int)Math.Ceiling(over.TotalMinutes);
        if (minutes > overMin) CarryOver(by, user, minutes - overMin);
    }

    // Unused prepaid minutes become a time balance for another day (no money back).
    void CarryOver(long by, long user, int minutes)
    {
        var id = Insert("INSERT INTO plans(user_id, minutes_left, expires) VALUES(@p0, @p1, @p2)", user, minutes, Iso(_now().AddDays(Rate.CarryOverDays)));
        Audit(by, "carry_over", $"user {user} {minutes} min kept as plan {id}");
    }

    // ---------------- PC control ----------------

    /// Owner registers a gaming PC once; the token goes into that PC's settings and is never shown again.
    public string AddPc(long by, string name) => Tx(() =>
    {
        RequireOwner(by);
        if (name.Length is < 1 or > 20 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c is ' ' or '-')) throw new CafeException("A PC name has 1 to 20 letters, numbers, spaces or dashes.");
        if (Scalar<long>("SELECT count(*) FROM pcs WHERE name = @p0", name) > 0) throw new CafeException("A PC with this name already exists.");
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Exec("INSERT INTO pcs(name, token, locked) VALUES(@p0, @p1, 0)", name, TokenHash(token));
        Audit(by, "add_pc", name);
        return token;
    });

    /// Which PC this token belongs to, or null.
    public string? PcByToken(string token) => Tx(() =>
        Scalar<string?>("SELECT name FROM pcs WHERE token = @p0", TokenHash(token)));

    /// Owner or staff lock a PC at any time (stop play, come to the counter). A running session is paused,
    /// so locked time is not charged; Unlock resumes it.
    public void Lock(long by, string pc, string? message = null) => Tx(() =>
    {
        RequireStaff(by);
        if (message?.Length > 200) throw new CafeException("The message can be at most 200 letters long.");
        if (Exec("UPDATE pcs SET locked = 1, message = @p0 WHERE name = @p1", message, pc) == 0) throw new CafeException($"no PC called {pc}");
        if (Scalar<long?>("SELECT id FROM sessions WHERE pc = @p0 AND ended IS NULL AND pause_from IS NULL", pc) is long s) Pause(by, s);
        Audit(by, "lock", $"{pc}: {message}");
    });

    public void Unlock(long by, string pc) => Tx(() =>
    {
        RequireStaff(by);
        if (Exec("UPDATE pcs SET locked = 0, self_locked = 0, message = NULL WHERE name = @p0", pc) == 0) throw new CafeException($"no PC called {pc}");
        if (Scalar<long?>("SELECT id FROM sessions WHERE pc = @p0 AND ended IS NULL AND pause_from IS NOT NULL", pc) is long s) Resume(by, s);
        Audit(by, "unlock", pc);
    });

    public PcState StateOf(string pc)
    {
        EnforceTimeLimits();
        return Tx(() =>
    {
        using var r = Query("SELECT locked, message, self_locked FROM pcs WHERE name = @p0", pc);
        if (!r.Read()) throw new CafeException($"no PC called {pc}");
        var (adminLocked, message, selfLocked) = (r.GetInt64(0) == 1, r.IsDBNull(1) ? null : r.GetString(1), r.GetInt64(2) == 1);
        r.Close();
        var lockOnExpiry = Scalar<long>("SELECT value FROM settings WHERE name = 'lock_when_time_runs_out'") == 1;
        if (Scalar<long?>("SELECT id FROM sessions WHERE pc = @p0 AND ended IS NULL", pc) is not long s) return new PcState(true, message, null, null, 0, null, false, lockOnExpiry);
        var (used, prepaid, plan, user) = SessionUse(s);
        var mode = prepaid is not null ? "prepaid" : plan is not null ? "plan" : "postpaid";
        long? left = prepaid is int b ? b * 60 - (long)used.TotalSeconds
                   : plan is not null ? PlanMinutesLeft(user) * 60 - (long)used.TotalSeconds : null;
        if (selfLocked && !adminLocked) message = "Locked by the customer. Their time is still running.";
        return new PcState(adminLocked || selfLocked, message, s, mode, (long)used.TotalSeconds, left, selfLocked && !adminLocked, lockOnExpiry);
        });
    }

    /// Customer logs in at a PC: plays on plan or carried-over time if there is any, otherwise pay-at-end.
    /// If the customer locked the PC themselves, only their own phone + PIN unlocks it.
    public PcState PcLogin(string pc, string phone, string pin) => Tx(() =>
    {
        var now = StateOf(pc);
        if (now.SelfLocked)
        {
            if (Login(phone, pin) != UserOf(now.Session)) throw new CafeException("Only the customer who locked this PC can unlock it.");
            Exec("UPDATE pcs SET self_locked = 0 WHERE name = @p0", pc);
            Audit(UserOf(now.Session), "self_unlock", pc);
            return StateOf(pc);
        }
        if (now.Session is not null) throw new CafeException("Someone is already using this PC.");
        if (Scalar<long>("SELECT locked FROM pcs WHERE name = @p0", pc) == 1) throw new CafeException("This PC is locked by the counter.");
        var user = Login(phone, pin);
        if (PlanMinutesLeft(user) > 0) StartOnPlan(user, pc, user); else StartPostpaid(user, pc, user);
        return StateOf(pc);
    });

    /// Customer steps away: the PC locks but their time keeps running (an admin lock pauses it instead).
    public PcState PcSelfLock(string pc) => Tx(() =>
    {
        var now = StateOf(pc);
        if (now.Session is not long s || now.Locked) throw new CafeException("Only a PC that is in use can be locked.");
        Exec("UPDATE pcs SET self_locked = 1 WHERE name = @p0", pc);
        Audit(UserOf(s), "self_lock", pc);
        return StateOf(pc);
    });

    /// The server's receipt time is the billing time. A PC-reported delay is only a review signal; it never reduces the bill.
    public Bill PcLogout(string pc, long secondsAgo = 0) => Tx(() =>
    {
        var s = StateOf(pc).Session ?? throw new CafeException("Nobody is logged in on this PC.");
        var reportedDelay = Math.Clamp(secondsAgo, 0, 7 * 24 * 3600); // a silly number must not crash the server
        var at = _now();
        var user = UserOf(s);
        // An honest outage and a tampered PC can both report a long delay, so staff can review the claim.
        if (reportedDelay > 120) Audit(user, "review_late_logout", $"session {s} on {pc} reported logout {reportedDelay / 60} min before the server received it");
        return Stop(user, s, at);
    });

    /// End prepaid or plan sessions at zero when the owner has enabled automatic locking.
    /// This runs on the server timer even when a gaming PC is offline; StateOf also calls it on reconnect.
    public void EnforceTimeLimits() => Tx(() =>
    {
        if (Scalar<long>("SELECT value FROM settings WHERE name = 'lock_when_time_runs_out'") != 1) return;
        using var r = Query("SELECT id, user_id FROM sessions WHERE ended IS NULL AND (prepaid_min IS NOT NULL OR plan_id IS NOT NULL)");
        var due = new List<(long session, long user)>();
        while (r.Read()) due.Add((r.GetInt64(0), r.GetInt64(1)));
        r.Close();
        foreach (var (session, user) in due)
        {
            var savepoint = $"time_limit_{session}";
            Exec($"SAVEPOINT {savepoint}");
            try
            {
                var (used, prepaid, plan, owner) = SessionUse(session);
                var limitSeconds = prepaid is int bought ? bought * 60L : plan is not null ? PlanMinutesLeft(owner) * 60L : long.MaxValue;
                if (used.TotalSeconds >= limitSeconds) Stop(user, session, _now());
                Exec($"RELEASE SAVEPOINT {savepoint}");
            }
            catch (Exception e)
            {
                Exec($"ROLLBACK TO SAVEPOINT {savepoint}");
                Exec($"RELEASE SAVEPOINT {savepoint}");
                if (_timeLimitFailures.Add(session))
                    _log($"time expiry failed for session {session}: {e.Message}");
            }
        }
    });

    /// Verify and post a counter sale recorded by the watchdog while this PC was offline.
    /// The PC token authenticates the device; the staff TOTP proves who took the payment.
    public long ProcessOfflineSale(string pc, OfflineSaleRequest sale) => Tx(() =>
    {
        if (!Guid.TryParseExact(sale.SaleId, "N", out _)) throw new CafeException("The offline sale reference is not valid.");
        if (Scalar<long?>( "SELECT session_id FROM offline_sales WHERE pc = @p0 AND sale_id = @p1", pc, sale.SaleId) is long prior) return prior;
        Minutes(sale.Minutes);
        if (sale.Minutes < Rate.MinimumMin || sale.Minutes % Math.Max(1, Rate.BlockMin) != 0)
            throw new CafeException($"Minutes must be a {Rate.BlockMin}-minute block from the rate card.");
        CashOrUpi(sale.Method, sale.UpiLast4);
        using var r = Query("SELECT id, offline_totp FROM users WHERE phone = @p0 AND role IN (@p1, @p2)", sale.Phone, (int)Role.Owner, (int)Role.Staff);
        if (!r.Read() || r.IsDBNull(1)) throw new CafeException("This account has not set up offline unlock.");
        var staff = r.GetInt64(0);
        var key = (byte[])r[1];
        r.Close();
        var nowStep = new DateTimeOffset(_now()).ToUnixTimeSeconds() / 30;
        if (sale.Step < nowStep - 7 * 24 * 60 * 60 / 30 || sale.Step > nowStep + 1
            || string.IsNullOrEmpty(sale.Code) || sale.Code.Length != 6 || !sale.Code.All(char.IsAsciiDigit)
            || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Totp(key, sale.Step)), Encoding.ASCII.GetBytes(sale.Code)))
            throw new CafeException("That offline authenticator code does not match or is outside the 7-day window.");
        if (Scalar<long?>("SELECT 1 FROM offline_sales WHERE staff_id = @p0 AND step = @p1", staff, sale.Step) is not null)
            throw new CafeException("That offline authenticator step was already used for a sale.");

        long session;
        long user;
        long? existingSession = sale.Session switch
        {
            > 0 => sale.Session,
            -1 => Scalar<long?>("SELECT id FROM sessions WHERE pc = @p0 AND ended IS NULL", pc),
            null => null,
            _ => throw new CafeException("The offline session reference is not valid.")
        };
        if (sale.Session == -1 && existingSession is null)
            throw new CafeException("The offline walk-in session could not be found.");
        if (existingSession is long existing)
        {
            if (Scalar<long?>( "SELECT id FROM sessions WHERE id = @p0 AND pc = @p1 AND ended IS NULL", existing, pc) is null)
                throw new CafeException("The session on this PC has already ended.");
            var (used, prepaid, plan, customer) = SessionUse(existing);
            user = customer;
            if (prepaid is int bought)
                Exec("UPDATE sessions SET prepaid_min = @p0 WHERE id = @p1", checked(bought + sale.Minutes), existing);
            else
            {
                var usedMin = (int)Math.Ceiling(used.TotalMinutes);
                if (plan is long planId)
                {
                    var available = (int)Scalar<long>("SELECT minutes_left FROM plans WHERE id = @p0", planId);
                    var take = Math.Min(usedMin, available);
                    if (take > 0)
                    {
                        Exec("UPDATE plans SET minutes_left = minutes_left - @p0 WHERE id = @p1", take, planId);
                        Audit(staff, "plan_use", $"plan {planId} -{take} min");
                    }
                    if (usedMin > take) ChargeOvertime(staff, existing, user, used - TimeSpan.FromMinutes(take), "before offline sale");
                }
                else
                {
                    var billed = BillableMinutes(used);
                    if (billed > 0) Ledger(staff, "charge", Price(billed), session: existing, user: user, reference: $"{billed} min before offline sale");
                    if (billed > usedMin) CarryOver(staff, user, billed - usedMin);
                }
                Exec("UPDATE sessions SET prepaid_min = @p0, plan_id = NULL WHERE id = @p1", checked(usedMin + sale.Minutes), existing);
            }
            if (Scalar<string?>("SELECT pause_from FROM sessions WHERE id = @p0", existing) is not null) Resume(staff, existing);
            session = existing;
        }
        else
        {
            user = Scalar<long?>("SELECT id FROM users WHERE phone = 'WALKIN' AND role = @p0", (int)Role.Customer)
                ?? Insert("INSERT INTO users(role, name, phone, pin) VALUES(@p0, 'Walk-in', 'WALKIN', @p1)", (int)Role.Customer, HashPin(Convert.ToHexString(RandomNumberGenerator.GetBytes(16))));
            session = Start(staff, pc, user, sale.Minutes, null);
        }

        var amount = Price(sale.Minutes);
        Ledger(staff, "charge", amount, session: session, user: user, reference: $"offline sale {sale.SaleId} {sale.Minutes} min");
        Ledger(staff, "pay", amount, session: session, user: user, method: sale.Method, reference: sale.UpiLast4);
        Exec("UPDATE pcs SET locked = 0, self_locked = 0, message = NULL WHERE name = @p0", pc);
        Exec("INSERT INTO offline_sales(pc, sale_id, session_id, staff_id, step, created) VALUES(@p0, @p1, @p2, @p3, @p4, @p5)", pc, sale.SaleId, session, staff, sale.Step, Iso(_now()));
        Audit(staff, "offline sale", $"PC {pc}, session {session}, {sale.Minutes} min, {sale.Method}");
        return session;
    });

    /// Refused offline sales are retained in the owner's review list; never include the authenticator code.
    public void ReviewOfflineSale(string pc, string saleId, string phone, string reason) => Tx(() =>
        Insert("INSERT INTO audit(at, by_user, action, detail) VALUES(@p0, NULL, 'review_offline_sale', @p1)", Iso(_now()), $"PC {pc}, sale {saleId}, account {phone}: {reason}"));

    /// Called on every status check, so a queued logout knows when the PC was last online.
    public void PcSeen(string pc) => Tx(() => { Exec("UPDATE pcs SET last_seen = @p0 WHERE name = @p1", Iso(_now()), pc); });

    /// Pay-at-end bill: free inside the start grace; otherwise the minimum, then whole blocks,
    /// with BlockGraceMin free after each block ends (e.g. 35 min = 1 block, 36 min = 2 blocks).
    public long Charge(TimeSpan used) => Price(BillableMinutes(used));

    int BillableMinutes(TimeSpan used, bool startGrace = true)
    {
        if (used <= TimeSpan.FromMinutes(startGrace ? Rate.GraceMin : Rate.BlockGraceMin)) return 0;
        var blocks = Math.Max(1, (int)Math.Ceiling((used.TotalMinutes - Rate.BlockGraceMin) / Rate.BlockMin));
        return Math.Max(Rate.MinimumMin, blocks * Rate.BlockMin);
    }

    // bought time and pay-at-end bills: whole 30-min blocks from the rate card
    long Price(int minutes) => (int)Math.Ceiling(minutes / (double)Rate.BlockMin) switch
    {
        <= 0 => 0, 1 => Rate.Paise30, 2 => Rate.Paise60, 3 => Rate.Paise90,
        var n => Rate.Paise90 + (n - 3) * Rate.ExtraBlockPaise,
    };

    // ---------------- money ----------------

    /// Bill for a session, or for its whole group if it is in one.
    public Bill BillFor(long session) => Tx(() =>
    {
        var g = Scalar<long?>("SELECT group_id FROM sessions WHERE id = @p0", session);
        var ids = g is null ? $"{session}" : string.Join(",", Column<long>("SELECT id FROM sessions WHERE group_id = @p0", g));
        var used = TimeSpan.Zero;
        foreach (var id in ids.Split(',')) used += SessionUse(long.Parse(id, CultureInfo.InvariantCulture)).used;
        long Sum(string kind) => Scalar<long>($"SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = @p0 AND session_id IN ({ids})", kind);
        return new Bill(g ?? session, used, Sum("charge"), Sum("adjust"), Sum("pay"));
    });

    /// Cash, UPI (staff types the last 4 digits of the UPI reference) or wallet; split payments are several calls.
    public void Pay(long by, long session, string method, long amount, string? upiLast4 = null) => Tx(() =>
    {
        RequireStaff(by);
        if (amount <= 0) throw new CafeException("The amount must be more than ₹0.");
        if (amount > BillFor(session).Due) throw new CafeException("That is more than the customer owes.");
        var user = UserOf(session);
        if (method == "wallet")
        {
            if (WalletBalance(user) < amount) throw new CafeException("Not enough money in the customer's wallet.");
            Ledger(by, "wallet", -amount, user: user, reference: $"paid session {session}");
        }
        else CashOrUpi(method, upiLast4);
        Ledger(by, "pay", amount, session: session, user: user, method: method, reference: upiLast4);
        Audit(by, "pay", $"session {session} {method} {amount}");
    });

    /// Money in the closed wallet: spend it here only, never cash out or transfer.
    /// An unstarted booking "moved to another day" is simply money left in the wallet.
    public void TopUp(long by, long user, string method, long amount, string? upiLast4 = null) => Tx(() =>
    {
        RequireStaff(by);
        if (amount <= 0) throw new CafeException("The amount must be more than ₹0.");
        CashOrUpi(method, upiLast4);
        Ledger(by, "pay", amount, user: user, method: method, reference: upiLast4 ?? "wallet top-up");
        Ledger(by, "wallet", amount, user: user, reference: "top-up");
        Audit(by, "top_up", $"user {user} {method} {amount}");
    });

    public long WalletBalance(long user) => Tx(() => Scalar<long>("SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = 'wallet' AND user_id = @p0", user));

    public long BuyPlan(long by, long user, int minutes, int validDays, long price, string method, string? upiLast4 = null) => Tx(() =>
    {
        RequireStaff(by); Minutes(minutes);
        if (validDays is < 1 or > 366 || price is < 0 or > 10_000_000) throw new CafeException("A plan needs 1 to 366 days and a price from ₹0 to ₹1,00,000.");
        CashOrUpi(method, upiLast4);
        var plan = Insert("INSERT INTO plans(user_id, minutes_left, expires) VALUES(@p0, @p1, @p2)", user, minutes, Iso(_now().AddDays(validDays)));
        Ledger(by, "pay", price, user: user, method: method, reference: upiLast4 ?? $"plan {plan}");
        Audit(by, "buy_plan", $"plan {plan} user {user} {minutes} min {validDays} days {price}");
        return plan;
    });

    /// Owner changes how long a plan or carried-over time stays valid (more days, or fewer with a negative number).
    public void ExtendPlan(long by, long plan, int days, string reason) => Tx(() =>
    {
        RequireOwner(by); RequireReason(reason);
        Exec("UPDATE plans SET expires = @p0 WHERE id = @p1", Iso(Time(Scalar<string>("SELECT expires FROM plans WHERE id = @p0", plan)).AddDays(days)), plan);
        Audit(by, "extend_plan", $"plan {plan} +{days} days: {reason}");
    });

    /// Owner only, always with a reason: discount or waiver (negative), extra charge (positive),
    /// or a correction of an earlier payment (kind "pay", negative to reverse). Nothing is ever edited in place.
    public void Adjust(long by, long session, long amount, string reason, bool correctPayment = false) => Tx(() =>
    {
        RequireOwner(by); RequireReason(reason);
        Ledger(by, correctPayment ? "pay" : "adjust", amount, session: session, reason: reason);
        Audit(by, correctPayment ? "correct_payment" : "adjust", $"session {session} {amount}: {reason}");
    });

    public long OpenShift(long by) => Tx(() =>
    {
        RequireStaff(by);
        if (OpenShiftOf(by) is not null) throw new CafeException("A shift is already open. Close it first.");
        var id = Insert("INSERT INTO shifts(staff_id, opened) VALUES(@p0, @p1)", by, Iso(_now()));
        Audit(by, "open_shift", $"shift {id}");
        return id;
    });

    /// Returns (expected cash, difference). Difference is counted minus expected: negative means cash is missing.
    public (long expected, long difference) CloseShift(long by, long countedCash) => Tx(() =>
    {
        var shift = OpenShiftOf(by) ?? throw new CafeException("No shift is open. Start a shift first.");
        var expected = Scalar<long>("SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = 'pay' AND method = 'cash' AND shift_id = @p0", shift);
        Exec("UPDATE shifts SET closed = @p0, counted = @p1 WHERE id = @p2", Iso(_now()), countedCash, shift);
        Audit(by, "close_shift", $"shift {shift} expected {expected} counted {countedCash}");
        return (expected, countedCash - expected);
    });

    public long ShiftTotal(long shift, string method) => Tx(() =>
        Scalar<long>("SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = 'pay' AND method = @p0 AND shift_id = @p1", method, shift));

    /// Things the owner should look at (late logouts after a network outage, for now).
    public List<string> ForReview() => Tx(() =>
    {
        using var r = Query("SELECT at, detail FROM audit WHERE action LIKE 'review_%' ORDER BY id DESC LIMIT 100");
        var list = new List<string>();
        while (r.Read()) list.Add($"{r.GetString(0)} {r.GetString(1)}");
        return list;
    });

    // ---------------- helpers ----------------

    (TimeSpan used, int? prepaid, long? plan, long user) SessionUse(long session)
    {
        using var r = Query("SELECT started, coalesce(ended, @p1), paused_sec, prepaid_min, plan_id, user_id, pause_from FROM sessions WHERE id = @p0", session, Iso(_now()));
        if (!r.Read()) throw new CafeException("This visit was not found.");
        var end = r.IsDBNull(6) ? Time(r.GetString(1)) : Time(r.GetString(6)); // a running pause doesn't count yet
        var used = end - Time(r.GetString(0)) - TimeSpan.FromSeconds(r.GetInt64(2));
        int? prepaid = r.IsDBNull(3) ? null : r.GetInt32(3);
        return (used < TimeSpan.Zero ? TimeSpan.Zero : used, prepaid, r.IsDBNull(4) ? null : r.GetInt64(4), r.GetInt64(5));
    }

    Role? RoleOf(long? user) => user is null ? null : (Role?)Scalar<long?>("SELECT role FROM users WHERE id = @p0", user);
    void RequireOwner(long by) { if (RoleOf(by) != Role.Owner) throw new CafeException("Only the owner can do this."); }
    void RequireStaff(long by) { if (RoleOf(by) is not (Role.Owner or Role.Staff)) throw new CafeException("Only staff or the owner can do this."); }
    void RequireStaffOrSelf(long by, long user) { if (by != user) RequireStaff(by); }
    long UserOf(long? session) => Scalar<long>("SELECT user_id FROM sessions WHERE id = @p0", session);
    bool InUse(string pc) => Scalar<long>("SELECT count(*) FROM sessions WHERE pc = @p0 AND ended IS NULL", pc) > 0;
    static byte[] TokenHash(string token) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token));
    // staff type the last 4 digits of the UPI reference so a payment can be matched to the bank statement
    static void CashOrUpi(string method, string? upiLast4)
    {
        if (method == "cash") return;
        if (method != "upi") throw new CafeException("Choose cash, UPI or wallet.");
        if (upiLast4 is not { Length: 4 } || !upiLast4.All(char.IsAsciiDigit)) throw new CafeException("For UPI, type the last 4 digits of the payment reference number.");
    }
    static void Minutes(int m) { if (m is < 1 or > 7 * 24 * 60) throw new CafeException("Minutes must be from 1 to 10080 (one week)."); }
    static void RequireReason(string reason) { if (string.IsNullOrWhiteSpace(reason)) throw new CafeException("Please write a reason."); }

    void Ledger(long by, string kind, long amount, long? session = null, long? user = null, string? method = null, string? reference = null, string? reason = null) =>
        Insert("INSERT INTO ledger(at, by_user, kind, amount, session_id, user_id, method, ref, reason, shift_id) VALUES(@p0, @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9)",
            Iso(_now()), by, kind, amount, session, user, method, reference, reason, OpenShiftOf(by));
    long? OpenShiftOf(long staff) => Scalar<long?>("SELECT id FROM shifts WHERE staff_id = @p0 AND closed IS NULL", staff);

    void Audit(long by, string action, string? detail) => Insert("INSERT INTO audit(at, by_user, action, detail) VALUES(@p0, @p1, @p2, @p3)", Iso(_now()), by, action, detail);

    // PINs: PBKDF2-SHA256, 600,000 rounds (OWASP 2023 figure), random 16-byte salt stored in front of the hash
    static byte[] HashPin(string pin)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        return [.. salt, .. Rfc2898DeriveBytes.Pbkdf2(pin, salt, 600_000, HashAlgorithmName.SHA256, 32)];
    }
    static bool CheckPin(string pin, byte[] stored) =>
        CryptographicOperations.FixedTimeEquals(stored.AsSpan(16), Rfc2898DeriveBytes.Pbkdf2(pin, stored.AsSpan(0, 16).ToArray(), 600_000, HashAlgorithmName.SHA256, 32));

    static string Iso(DateTime t) => t.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
    static DateTime Time(string s) => DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);

    T Tx<T>(Func<T> work)
    {
        lock (_db)
        {
            if (_tx is not null) return work(); // nested call joins the outer transaction
            _tx = _db.BeginTransaction();
            try { var result = work(); _tx.Commit(); return result; }
            catch { _tx.Rollback(); throw; }
            finally { _tx.Dispose(); _tx = null; }
        }
    }
    void Tx(Action work) => Tx(() => { work(); return 0; });
    SqliteTransaction? _tx;
    bool _ready; // set once the schema exists

    SqliteCommand Cmd(string sql, object?[] args)
    {
        // one connection is shared by every web request: touching it outside Tx() corrupts it (found on real Windows)
        if (_tx is null && _ready) throw new InvalidOperationException("database used outside a transaction");
        var c = _db.CreateCommand();
        c.CommandText = sql; c.Transaction = _tx;
        for (var i = 0; i < args.Length; i++) c.Parameters.AddWithValue($"@p{i}", args[i] ?? DBNull.Value);
        return c;
    }
    int Exec(string sql, params object?[] args) { using var c = Cmd(sql, args); return c.ExecuteNonQuery(); }
    long Insert(string sql, params object?[] args) { using var c = Cmd(sql + "; SELECT last_insert_rowid();", args); return (long)c.ExecuteScalar()!; }
    SqliteDataReader Query(string sql, params object?[] args) => Cmd(sql, args).ExecuteReader();
    T Scalar<T>(string sql, params object?[] args)
    {
        using var c = Cmd(sql, args);
        var v = c.ExecuteScalar();
        return v is null or DBNull ? default! : (T)Convert.ChangeType(v, Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T), CultureInfo.InvariantCulture);
    }
    List<(long, long)> Pairs(string sql, params object?[] args)
    {
        using var r = Query(sql, args);
        var list = new List<(long, long)>();
        while (r.Read()) list.Add((r.GetInt64(0), r.GetInt64(1)));
        return list;
    }
    List<T> Column<T>(string sql, params object?[] args)
    {
        using var r = Query(sql, args);
        var list = new List<T>();
        while (r.Read()) list.Add((T)Convert.ChangeType(r.GetValue(0), typeof(T), CultureInfo.InvariantCulture));
        return list;
    }
}
