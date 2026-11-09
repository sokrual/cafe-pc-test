using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Cafe;

public enum Role { Owner, Staff, Customer }

// Placeholder rate card until the real one arrives. Money is always whole paise (₹1 = 100).
public record Rate(long PerHourPaise = 6000, int GraceMin = 2, int MinimumMin = 30, int BlockMin = 30);

public record Bill(long SessionId, TimeSpan Used, long Charged, long Adjusted, long Paid)
{
    public long Due => Charged + Adjusted - Paid;
}

public class CafeException(string message) : Exception(message);

/// The admin PC's single source of truth: customers, sessions, money. Every public call is one transaction.
/// Money rows (ledger) and the audit log are append-only: the database itself refuses UPDATE and DELETE on them.
public sealed class CafeCore : IDisposable
{
    readonly SqliteConnection _db;
    readonly Func<DateTime> _now;
    public Rate Rate { get; set; } = new();

    public CafeCore(string path, string key, Func<DateTime>? now = null)
    {
        _now = now ?? (() => DateTime.UtcNow);
        // Password makes Microsoft.Data.Sqlite send PRAGMA key; SQLite3 Multiple Ciphers encrypts the whole file
        _db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Password = key, Pooling = false }.ToString());
        _db.Open();
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
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT NOT NULL, by_user INTEGER, action TEXT NOT NULL, detail TEXT);
            CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
            CREATE INDEX IF NOT EXISTS ledger_session ON ledger(session_id);
            CREATE INDEX IF NOT EXISTS ledger_user ON ledger(user_id, kind);
            CREATE INDEX IF NOT EXISTS sessions_open ON sessions(pc) WHERE ended IS NULL;
            """);
    }

    public void Dispose() => _db.Dispose();

    // ---------------- people ----------------

    public long AddUser(long? by, Role role, string name, string phone, string pin)
    {
        if (pin.Length < 4 || !pin.All(char.IsAsciiDigit)) throw new CafeException("PIN must be at least 4 digits");
        return Tx(() =>
        {
            // the very first user is the owner; after that only the owner adds staff, staff add customers
            var count = Scalar<long>("SELECT count(*) FROM users");
            if (count == 0 ? role != Role.Owner : RoleOf(by) is not Role.Owner && !(RoleOf(by) == Role.Staff && role == Role.Customer))
                throw new CafeException("not allowed to add this kind of user");
            var id = Insert("INSERT INTO users(role, name, phone, pin) VALUES(@p0, @p1, @p2, @p3)", (int)role, name, phone, HashPin(pin));
            Audit(by ?? id, "add_user", $"user {id} role {role}");
            return id;
        });
    }

    /// PIN login with lockout: 5 wrong tries lock the account for 15 minutes.
    public long Login(string phone, string pin)
    {
        // A wrong PIN returns null instead of throwing inside the transaction, so the failed-try count is saved, not rolled back.
        long? id = Tx(() =>
        {
            using var r = Query("SELECT id, pin, fails, locked_until FROM users WHERE phone = @p0", phone);
            if (!r.Read()) return (long?)null;
            var (user, stored, fails, lockedUntil) = (r.GetInt64(0), (byte[])r[1], r.GetInt64(2), r.IsDBNull(3) ? (DateTime?)null : Time(r.GetString(3)));
            r.Close();
            if (lockedUntil > _now()) throw new CafeException("too many wrong PINs, try again later");
            if (!CheckPin(pin, stored))
            {
                Exec("UPDATE users SET fails = @p0, locked_until = @p1 WHERE id = @p2", fails + 1, fails + 1 >= 5 ? Iso(_now().AddMinutes(15)) : null, user);
                Audit(user, "login_failed", null);
                return null;
            }
            Exec("UPDATE users SET fails = 0, locked_until = NULL WHERE id = @p0", user);
            Audit(user, "login", null);
            return user;
        });
        return id ?? throw new CafeException("wrong phone or PIN"); // same message for unknown phone and wrong PIN
    }

    // ---------------- sessions ----------------

    /// Pay-at-end: a stopwatch from 0, billed at stop by the rate card.
    public long StartPostpaid(long by, string pc, long user) => Start(by, pc, user, null, null);

    /// Prepaid countdown: the minutes are charged now; no refund once it starts.
    public long StartPrepaid(long by, string pc, long user, int minutes) => Tx(() =>
    {
        var id = Start(by, pc, user, minutes, null);
        Ledger(by, "charge", Price(minutes), session: id, reference: $"prepaid {minutes} min");
        return id;
    });

    /// Time comes off the customer's plan; refused if the plan has expired or is used up.
    public long StartOnPlan(long by, string pc, long user) => Tx(() =>
    {
        var plan = Scalar<long?>("SELECT id FROM plans WHERE user_id = @p0 AND minutes_left > 0 AND expires > @p1 ORDER BY expires LIMIT 1", user, Iso(_now()))
            ?? throw new CafeException("no valid plan (expired or used up)");
        return Start(by, pc, user, null, plan);
    });

    long Start(long by, string pc, long user, int? prepaidMin, long? plan) => Tx(() =>
    {
        RequireStaffOrSelf(by, user);
        if (Scalar<long>("SELECT count(*) FROM sessions WHERE pc = @p0 AND ended IS NULL", pc) > 0) throw new CafeException($"{pc} is already in use");
        var id = Insert("INSERT INTO sessions(pc, user_id, prepaid_min, plan_id, started) VALUES(@p0, @p1, @p2, @p3, @p4)", pc, user, prepaidMin, plan, Iso(_now()));
        Audit(by, "start", $"session {id} on {pc} prepaid={prepaidMin} plan={plan}");
        return id;
    });

    public void AddTime(long by, long session, int minutes) => Tx(() =>
    {
        RequireStaff(by);
        if (Exec("UPDATE sessions SET prepaid_min = prepaid_min + @p0 WHERE id = @p1 AND ended IS NULL AND prepaid_min IS NOT NULL", minutes, session) == 0)
            throw new CafeException("only a running prepaid session can get more time");
        Ledger(by, "charge", Price(minutes), session: session, reference: $"added {minutes} min");
        Audit(by, "add_time", $"session {session} +{minutes} min");
    });

    public void Pause(long by, long session) => Tx(() =>
    {
        RequireStaff(by);
        if (Exec("UPDATE sessions SET pause_from = @p0 WHERE id = @p1 AND ended IS NULL AND pause_from IS NULL", Iso(_now()), session) == 0)
            throw new CafeException("session is not running");
        Audit(by, "pause", $"session {session}");
    });

    /// Paused time is not charged unless the owner chooses to charge it.
    public void Resume(long by, long session, bool chargePausedTime = false) => Tx(() =>
    {
        if (chargePausedTime) RequireOwner(by); else RequireStaff(by);
        var from = Scalar<string?>("SELECT pause_from FROM sessions WHERE id = @p0 AND ended IS NULL", session) ?? throw new CafeException("session is not paused");
        var paused = chargePausedTime ? 0 : (long)(_now() - Time(from)).TotalSeconds;
        Exec("UPDATE sessions SET paused_sec = paused_sec + @p0, pause_from = NULL WHERE id = @p1", paused, session);
        Audit(by, "resume", $"session {session} paused {paused}s charged={chargePausedTime}");
    });

    public void MoveSeat(long by, long session, string newPc) => Tx(() =>
    {
        RequireStaff(by);
        if (Scalar<long>("SELECT count(*) FROM sessions WHERE pc = @p0 AND ended IS NULL", newPc) > 0) throw new CafeException($"{newPc} is already in use");
        if (Exec("UPDATE sessions SET pc = @p0 WHERE id = @p1 AND ended IS NULL", newPc, session) == 0) throw new CafeException("session is not running");
        Audit(by, "move", $"session {session} to {newPc}");
    });

    /// One bill for several sessions (friends paying together). The group is named after its first session.
    public void JoinGroup(long by, long session, long groupOf) => Tx(() =>
    {
        RequireStaff(by);
        var g = Scalar<long?>("SELECT coalesce(group_id, id) FROM sessions WHERE id = @p0", groupOf) ?? throw new CafeException("no such session");
        Exec("UPDATE sessions SET group_id = @p0 WHERE id IN (@p1, @p0)", g, session);
        Audit(by, "group", $"session {session} joins group {g}");
    });

    /// Safe to call twice or at the same moment as the countdown's own stop: only the first call bills.
    public Bill Stop(long by, long session) => Tx(() =>
    {
        RequireStaffOrSelf(by, Scalar<long?>("SELECT user_id FROM sessions WHERE id = @p0", session) ?? throw new CafeException("no such session"));
        if (Scalar<string?>("SELECT pause_from FROM sessions WHERE id = @p0 AND ended IS NULL", session) is string from) // stopping while paused ends the pause, uncharged
            Exec("UPDATE sessions SET paused_sec = paused_sec + @p0, pause_from = NULL WHERE id = @p1", (long)(_now() - Time(from)).TotalSeconds, session);
        if (Exec("UPDATE sessions SET ended = @p0 WHERE id = @p1 AND ended IS NULL", Iso(_now()), session) == 1)
        {
            var (used, prepaid, plan, user) = SessionUse(session);
            if (prepaid is null)
            {
                var minutes = (int)Math.Ceiling(used.TotalMinutes);
                if (plan is long p)
                {
                    var take = Math.Min(minutes, Scalar<long>("SELECT minutes_left FROM plans WHERE id = @p0", p));
                    Exec("UPDATE plans SET minutes_left = minutes_left - @p0 WHERE id = @p1", take, p);
                    Audit(by, "plan_use", $"plan {p} -{take} min");
                    minutes -= (int)take; // shortcut: plan time is taken minute by minute, with no grace or minimum; confirm with the owner
                    if (minutes > 0) Ledger(by, "charge", Charge(TimeSpan.FromMinutes(minutes)), session: session, user: user, reference: "beyond plan");
                }
                else Ledger(by, "charge", Charge(used), session: session, user: user, reference: $"{minutes} min");
            }
            Audit(by, "stop", $"session {session} used {used}");
        }
        return BillFor(session);
    });

    /// What the rate card says for a pay-at-end session: free inside the grace period, then the minimum, then whole blocks.
    public long Charge(TimeSpan used)
    {
        if (used <= TimeSpan.FromMinutes(Rate.GraceMin)) return 0;
        var minutes = Math.Max(Rate.MinimumMin, (int)Math.Ceiling(used.TotalMinutes / Rate.BlockMin) * Rate.BlockMin);
        return Price(minutes);
    }

    long Price(int minutes) => (minutes * Rate.PerHourPaise + 59) / 60; // round up to the paisa

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
        if (amount <= 0) throw new CafeException("amount must be positive");
        if (amount > BillFor(session).Due) throw new CafeException("more than is due");
        var user = Scalar<long>("SELECT user_id FROM sessions WHERE id = @p0", session);
        switch (method)
        {
            case "cash": break;
            case "upi" when upiLast4 is { Length: 4 } && upiLast4.All(char.IsAsciiDigit): break;
            case "upi": throw new CafeException("UPI needs the last 4 digits of the reference");
            case "wallet":
                if (WalletBalance(user) < amount) throw new CafeException("not enough in the wallet");
                Ledger(by, "wallet", -amount, user: user, reference: $"paid session {session}");
                break;
            default: throw new CafeException("pay by cash, upi or wallet");
        }
        Ledger(by, "pay", amount, session: session, user: user, method: method, reference: upiLast4);
        Audit(by, "pay", $"session {session} {method} {amount}");
    });

    /// Money in the closed wallet: spend it here only, never cash out or transfer.
    /// An unstarted booking "moved to another day" is simply money left in the wallet.
    public void TopUp(long by, long user, string method, long amount, string? upiLast4 = null) => Tx(() =>
    {
        RequireStaff(by);
        if (amount <= 0) throw new CafeException("amount must be positive");
        if (method == "upi" && upiLast4 is not { Length: 4 }) throw new CafeException("UPI needs the last 4 digits of the reference");
        if (method is not ("cash" or "upi")) throw new CafeException("top up by cash or upi");
        Ledger(by, "pay", amount, user: user, method: method, reference: upiLast4 ?? "wallet top-up");
        Ledger(by, "wallet", amount, user: user, reference: "top-up");
        Audit(by, "top_up", $"user {user} {method} {amount}");
    });

    public long WalletBalance(long user) => Scalar<long>("SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = 'wallet' AND user_id = @p0", user);

    public long BuyPlan(long by, long user, int minutes, int validDays, long price, string method, string? upiLast4 = null) => Tx(() =>
    {
        RequireStaff(by);
        if (method is not ("cash" or "upi") || (method == "upi" && upiLast4 is not { Length: 4 })) throw new CafeException("pay by cash, or upi with the last 4 digits");
        var plan = Insert("INSERT INTO plans(user_id, minutes_left, expires) VALUES(@p0, @p1, @p2)", user, minutes, Iso(_now().AddDays(validDays)));
        Ledger(by, "pay", price, user: user, method: method, reference: upiLast4 ?? $"plan {plan}");
        Audit(by, "buy_plan", $"plan {plan} user {user} {minutes} min {validDays} days {price}");
        return plan;
    });

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
        if (OpenShiftOf(by) is not null) throw new CafeException("a shift is already open");
        var id = Insert("INSERT INTO shifts(staff_id, opened) VALUES(@p0, @p1)", by, Iso(_now()));
        Audit(by, "open_shift", $"shift {id}");
        return id;
    });

    /// Returns (expected cash, difference). Difference is counted minus expected: negative means cash is missing.
    public (long expected, long difference) CloseShift(long by, long countedCash) => Tx(() =>
    {
        var shift = OpenShiftOf(by) ?? throw new CafeException("no open shift");
        var expected = Scalar<long>("SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = 'pay' AND method = 'cash' AND shift_id = @p0", shift);
        Exec("UPDATE shifts SET closed = @p0, counted = @p1 WHERE id = @p2", Iso(_now()), countedCash, shift);
        Audit(by, "close_shift", $"shift {shift} expected {expected} counted {countedCash}");
        return (expected, countedCash - expected);
    });

    public long ShiftTotal(long shift, string method) =>
        Scalar<long>("SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = 'pay' AND method = @p0 AND shift_id = @p1", method, shift);

    // ---------------- helpers ----------------

    (TimeSpan used, int? prepaid, long? plan, long user) SessionUse(long session)
    {
        using var r = Query("SELECT started, coalesce(ended, @p1), paused_sec, prepaid_min, plan_id, user_id, pause_from FROM sessions WHERE id = @p0", session, Iso(_now()));
        if (!r.Read()) throw new CafeException("no such session");
        var end = r.IsDBNull(6) ? Time(r.GetString(1)) : Time(r.GetString(6)); // a running pause doesn't count yet
        var used = end - Time(r.GetString(0)) - TimeSpan.FromSeconds(r.GetInt64(2));
        int? prepaid = r.IsDBNull(3) ? null : r.GetInt32(3);
        if (prepaid is int p && used > TimeSpan.FromMinutes(p)) used = TimeSpan.FromMinutes(p); // the PC locks at 0
        return (used < TimeSpan.Zero ? TimeSpan.Zero : used, prepaid, r.IsDBNull(4) ? null : r.GetInt64(4), r.GetInt64(5));
    }

    Role? RoleOf(long? user) => user is null ? null : (Role?)Scalar<long?>("SELECT role FROM users WHERE id = @p0", user);
    void RequireOwner(long by) { if (RoleOf(by) != Role.Owner) throw new CafeException("only the owner can do this"); }
    void RequireStaff(long by) { if (RoleOf(by) is not (Role.Owner or Role.Staff)) throw new CafeException("only staff or the owner can do this"); }
    void RequireStaffOrSelf(long by, long user) { if (by != user) RequireStaff(by); }
    static void RequireReason(string reason) { if (string.IsNullOrWhiteSpace(reason)) throw new CafeException("a reason is required"); }

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

    SqliteCommand Cmd(string sql, object?[] args)
    {
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
    List<T> Column<T>(string sql, params object?[] args)
    {
        using var r = Query(sql, args);
        var list = new List<T>();
        while (r.Read()) list.Add((T)Convert.ChangeType(r.GetValue(0), typeof(T), CultureInfo.InvariantCulture));
        return list;
    }
}
