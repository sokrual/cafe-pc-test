using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Cafe;

public record OfflineUnlockAccount(string Phone, string Secret, long LastStep);
public record PcInfo(string Name, bool InUse, bool Locked, string? LastSeen);

public sealed partial class CafeCore
{
    public bool IsOwner(long user) => Tx(() => RoleOf(user) == Role.Owner);

    // ---------------- PCs ----------------

    public List<PcInfo> Pcs(long by) => Tx(() =>
    {
        RequireStaff(by);
        using var r = Query("SELECT name, locked, last_seen FROM pcs ORDER BY name");
        var list = new List<(string, bool, string?)>();
        while (r.Read()) list.Add((r.GetString(0), r.GetInt64(1) == 1, r.IsDBNull(2) ? null : r.GetString(2)));
        r.Close();
        return list.Select(p => new PcInfo(p.Item1, InUse(p.Item1), p.Item2, p.Item3)).ToList();
    });

    /// Owner only. The PC's key stops working at once (a lost or replaced PC); add it again for a new key.
    public void RemovePc(long by, string name) => Tx(() =>
    {
        RequireOwner(by);
        if (InUse(name)) throw new CafeException("Someone is using this PC. Stop their time first.");
        if (Exec("DELETE FROM pcs WHERE name = @p0", name) == 0) throw new CafeException("No PC has this name.");
        Audit(by, "remove_pc", name);
    });

    // ---------------- PINs ----------------

    /// Only the owner can reset a forgotten PIN, for any account.
    public void ResetPin(long by, string phone, string pin) => Tx(() =>
    {
        var user = Scalar<long?>("SELECT id FROM users WHERE phone = @p0", phone) ?? throw new CafeException("No one has this phone number.");
        var role = RoleOf(user);
        RequireOwner(by);
        var minPin = role == Role.Customer ? 4 : 6;
        if (pin.Length < minPin || pin.Length > 12 || !pin.All(char.IsAsciiDigit)) throw new CafeException($"PIN must be {minPin} to 12 digits");
        Exec("UPDATE users SET pin = @p0, fails = 0, locked_until = NULL WHERE id = @p1", HashPin(pin), user);
        Audit(by, "reset_pin", $"user {user}");
    });

    // ---------------- owner two-step login ----------------
    // After the PIN, the owner types the 6-digit code from an authenticator app (TOTP, RFC 6238: 30-second codes).
    // Turning it on: the app gets a new secret (typed in or scanned), then one code from the app proves it matches.
    // That also gives a one-time recovery code to print and keep: it replaces the app code once, if the phone is lost.

    public static string NewTwoStepSecret() => Base32(RandomNumberGenerator.GetBytes(20));

    /// Owner enrollment for a staff account; staff use the same TOTP login and replay protection as the owner.
    public string StartTwoStepFor(long owner, string phone) => Tx(() =>
    {
        RequireOwner(owner);
        _ = Scalar<long?>( "SELECT id FROM users WHERE phone = @p0 AND role IN (@p1, @p2)", phone, (int)Role.Owner, (int)Role.Staff)
            ?? throw new CafeException("No owner or staff account has this phone number.");
        return NewTwoStepSecret();
    });

    public string TurnOnTwoStepFor(long owner, string phone, string secret, string code) => Tx(() =>
    {
        RequireOwner(owner);
        var user = Scalar<long?>( "SELECT id FROM users WHERE phone = @p0 AND role IN (@p1, @p2)", phone, (int)Role.Owner, (int)Role.Staff)
            ?? throw new CafeException("No owner or staff account has this phone number.");
        var key = FromBase32(secret);
        if (key.Length < 10 || TotpStep(key, code) is not long step)
            throw new CafeException("That code does not match. Type the 6 digits the app shows now.");
        var recovery = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        Exec("UPDATE users SET totp = @p0, totp_step = @p1, recovery = @p2, fails = 0, locked_until = NULL WHERE id = @p3",
            key, step, SHA256.HashData(Encoding.UTF8.GetBytes(recovery)), user);
        Audit(owner, "two_step_on", $"user {user}");
        return recovery;
    });

    /// Only enrolled owner and staff accounts are shared with a PC authenticated by its own device token.
    public List<OfflineUnlockAccount> OfflineUnlockAccounts() => Tx(() =>
    {
        using var r = Query("SELECT phone, totp, coalesce(totp_step, -1) FROM users WHERE role IN (@p0, @p1) AND totp IS NOT NULL ORDER BY id",
            (int)Role.Owner, (int)Role.Staff);
        var accounts = new List<OfflineUnlockAccount>();
        while (r.Read()) accounts.Add(new OfflineUnlockAccount(r.GetString(0), Base32((byte[])r[1]), r.GetInt64(2)));
        return accounts;
    });

    public string TurnOnTwoStep(long owner, string secret, string code) => Tx(() =>
    {
        RequireOwner(owner);
        var key = FromBase32(secret);
        if (key.Length < 10 || TotpStep(key, code) is not long step) throw new CafeException("That code does not match. Type the 6 digits the app shows now.");
        var recovery = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)); // 16 letters and numbers, to print
        Exec("UPDATE users SET totp = @p0, totp_step = @p1, recovery = @p2 WHERE id = @p3", key, step, SHA256.HashData(Encoding.UTF8.GetBytes(recovery)), owner);
        Audit(owner, "two_step_on", null);
        return recovery;
    });

    // the code's 30-second step if it matches now or one step either side (phone clocks drift a little), else null
    long? TotpStep(byte[] key, string code)
    {
        code = code.Trim();
        if (code.Length != 6 || !code.All(char.IsAsciiDigit)) return null;
        var now = new DateTimeOffset(_now()).ToUnixTimeSeconds() / 30;
        for (var step = now - 1; step <= now + 1; step++)
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Totp(key, step)), Encoding.ASCII.GetBytes(code))) return step;
        return null;
    }

    public static string Totp(byte[] key, long step)
    {
        var msg = BitConverter.GetBytes(step);
        if (BitConverter.IsLittleEndian) Array.Reverse(msg);
        var h = HMACSHA1.HashData(key, msg);
        var o = h[^1] & 0xF;
        var bin = ((h[o] & 0x7F) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
        return (bin % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    const string B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // RFC 4648, what authenticator apps expect
    public static string Base32(byte[] bytes)
    {
        var sb = new StringBuilder();
        int buf = 0, bits = 0;
        foreach (var b in bytes)
        {
            buf = ((buf << 8) | b) & 0xFFFF; bits += 8;
            while (bits >= 5) { sb.Append(B32[(buf >> (bits - 5)) & 31]); bits -= 5; }
        }
        if (bits > 0) sb.Append(B32[(buf << (5 - bits)) & 31]);
        return sb.ToString();
    }
    public static byte[] FromBase32(string text)
    {
        var bytes = new List<byte>();
        int buf = 0, bits = 0;
        foreach (var c in text.ToUpperInvariant().Replace(" ", "").TrimEnd('='))
        {
            var v = B32.IndexOf(c);
            if (v < 0) throw new CafeException("That set-up key is not valid.");
            buf = ((buf << 5) | v) & 0xFFFF; bits += 5;
            if (bits >= 8) { bytes.Add((byte)(buf >> (bits - 8))); bits -= 8; }
        }
        return [.. bytes];
    }
}

/// Counter logins: a random token per login. It remains valid until the user logs out.
public sealed class StaffTokens
{
    readonly ConcurrentDictionary<string, long> _tokens = new();

    public string Issue(long user)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        _tokens[token] = user;
        return token;
    }

    public long? Check(string token) => _tokens.TryGetValue(token, out var user) ? user : null;

    public void End(string token) => _tokens.TryRemove(token, out _);
    public int Count => _tokens.Count;
}
