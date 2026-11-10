using System.Text;
using Cafe;
using Microsoft.Data.Sqlite;
using Xunit;

// B5.1: adding and removing PCs, PIN resets, the owner's two-step login, staff auto-logout.
public sealed class AccountTests : IDisposable
{
    DateTime _clock = new(2026, 11, 10, 10, 0, 0, DateTimeKind.Utc);
    readonly string _file = Path.Combine(Path.GetTempPath(), $"cafe-acct-{Guid.NewGuid():N}.db");
    readonly CafeCore _cafe;
    readonly long _owner, _staff, _cust;

    public AccountTests()
    {
        _cafe = new CafeCore(_file, "test-key-123", () => _clock);
        _owner = _cafe.AddUser(null, Role.Owner, "Owner", "9000000001", "432100");
        _staff = _cafe.AddUser(_owner, Role.Staff, "Staff", "9000000002", "111111");
        _cust = _cafe.AddUser(_staff, Role.Customer, "Ravi", "9000000003", "2222");
    }
    public void Dispose() { _cafe.Dispose(); SqliteConnection.ClearAllPools(); File.Delete(_file); }

    string AppCode(string secret) => CafeCore.Totp(CafeCore.FromBase32(secret), new DateTimeOffset(_clock).ToUnixTimeSeconds() / 30);

    [Fact]
    public void Codes_match_the_published_test_values()
    {
        var key = Encoding.ASCII.GetBytes("12345678901234567890"); // RFC 6238 appendix B, last 6 digits
        Assert.Equal("287082", CafeCore.Totp(key, 59 / 30));
        Assert.Equal("081804", CafeCore.Totp(key, 1111111109 / 30));
        Assert.Equal("005924", CafeCore.Totp(key, 1234567890 / 30));
        Assert.Equal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", CafeCore.Base32(key)); // RFC 6238 key in Base32
        Assert.Equal(key, CafeCore.FromBase32("gezdgnbvgy3tqojqgezdgnbvgy3tqojq"));
        Assert.Equal(32, CafeCore.NewTwoStepSecret().Length);
    }

    [Fact]
    public void Owner_two_step_login_needs_a_fresh_code_and_the_recovery_code_works_once()
    {
        var secret = CafeCore.NewTwoStepSecret();
        Assert.Throws<CafeException>(() => _cafe.TurnOnTwoStep(_owner, secret, AppCode(secret) == "123456" ? "654321" : "123456")); // not the app's code
        var recovery = _cafe.TurnOnTwoStep(_owner, secret, AppCode(secret));
        Assert.Equal(16, recovery.Length);

        Assert.Throws<CafeException>(() => _cafe.StaffLogin("9000000001", "432100")); // PIN alone is not enough now
        _clock = _clock.AddSeconds(30);
        var code = AppCode(secret);
        Assert.Equal(_owner, _cafe.StaffLogin("9000000001", "432100", code));
        Assert.Throws<CafeException>(() => _cafe.StaffLogin("9000000001", "432100", code)); // the same code twice: refused
        Assert.Equal(_owner, _cafe.StaffLogin("9000000001", "432100", recovery.ToLowerInvariant()));
        Assert.Throws<CafeException>(() => _cafe.StaffLogin("9000000001", "432100", recovery)); // recovery code: once only
        Assert.Equal(_staff, _cafe.StaffLogin("9000000002", "111111")); // staff without two-step: PIN only
        Assert.Throws<CafeException>(() => _cafe.TurnOnTwoStep(_staff, secret, AppCode(secret))); // owner only
    }

    [Fact]
    public void Guessing_app_codes_locks_the_owner_out_even_with_the_right_PIN()
    {
        var secret = CafeCore.NewTwoStepSecret();
        _cafe.TurnOnTwoStep(_owner, secret, AppCode(secret));
        _clock = _clock.AddSeconds(30);
        var wrong = AppCode(secret) == "111111" ? "222222" : "111111";
        for (var i = 0; i < 5; i++) Assert.Throws<CafeException>(() => _cafe.StaffLogin("9000000001", "432100", wrong));
        var e = Assert.Throws<CafeException>(() => _cafe.StaffLogin("9000000001", "432100", AppCode(secret)));
        Assert.StartsWith("Too many wrong PINs", e.Message);
        _clock = _clock.AddMinutes(16);
        Assert.Equal(_owner, _cafe.StaffLogin("9000000001", "432100", AppCode(secret)));
    }

    [Fact]
    public void PIN_reset_follows_the_roles()
    {
        _cafe.ResetPin(_staff, "9000000003", "5555");
        Assert.Equal(_cust, _cafe.Login("9000000003", "5555"));
        Assert.Throws<CafeException>(() => _cafe.ResetPin(_staff, "9000000001", "999999")); // staff cannot reset the owner
        Assert.Throws<CafeException>(() => _cafe.ResetPin(_cust, "9000000003", "6666"));    // customers cannot reset
        Assert.Throws<CafeException>(() => _cafe.ResetPin(_owner, "9000000002", "1234"));   // staff PINs need 6+ digits
        _cafe.ResetPin(_owner, "9000000002", "222222");
        Assert.Equal(_staff, _cafe.StaffLogin("9000000002", "222222"));
    }

    [Fact]
    public void PCs_are_added_listed_and_removed_by_the_owner()
    {
        var token = _cafe.AddPc(_owner, "PC1");
        Assert.Throws<CafeException>(() => _cafe.AddPc(_owner, "PC1"));            // same name
        Assert.Throws<CafeException>(() => _cafe.AddPc(_owner, "PC'; DROP"));      // odd characters
        Assert.Throws<CafeException>(() => _cafe.AddPc(_staff, "PC2"));            // owner only
        Assert.Equal("PC1", _cafe.PcByToken(token));
        _cafe.PcLogin("PC1", "9000000003", "2222");
        Assert.True(_cafe.Pcs(_staff).Single().InUse);
        Assert.Throws<CafeException>(() => _cafe.RemovePc(_owner, "PC1"));         // in use
        _cafe.PcLogout("PC1", 0);
        _cafe.RemovePc(_owner, "PC1");
        Assert.Null(_cafe.PcByToken(token));                                        // its key stops working
        Assert.Empty(_cafe.Pcs(_staff));
    }

    [Fact]
    public void Staff_are_logged_out_after_30_minutes_without_use()
    {
        var clock = new DateTime(2026, 11, 10, 10, 0, 0, DateTimeKind.Utc);
        var tokens = new StaffTokens(() => clock);
        var t = tokens.Issue(_staff);
        clock = clock.AddMinutes(29);
        Assert.Equal(_staff, tokens.Check(t)); // each use starts the 30 minutes again
        clock = clock.AddMinutes(29);
        Assert.Equal(_staff, tokens.Check(t));
        clock = clock.AddMinutes(31);
        Assert.Null(tokens.Check(t));
        tokens.Issue(_owner);                  // old logins are cleared when someone logs in
        Assert.Equal(1, tokens.Count);
        var u = tokens.Issue(_owner);
        tokens.End(u);
        Assert.Null(tokens.Check(u));
        Assert.Null(tokens.Check("made-up"));
    }
}
