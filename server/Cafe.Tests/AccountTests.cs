using System.Text;
using Cafe;
using Microsoft.Data.Sqlite;
using Xunit;

// B5.1: adding and removing PCs, PIN resets, the owner's two-step login, counter login lifetime.
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
    // Windows sometimes holds the file a moment longer; a leftover temp file is harmless, a failed test here is not
    public void Dispose() { _cafe.Dispose(); SqliteConnection.ClearAllPools(); try { File.Delete(_file); } catch (IOException) { } }

    long CurrentStep => new DateTimeOffset(_clock).ToUnixTimeSeconds() / 30;
    string AppCode(string secret) => AppCode(secret, CurrentStep);
    string AppCode(string secret, long step) => CafeCore.Totp(CafeCore.FromBase32(secret), step);

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
    public void Owner_can_enroll_separate_counter_and_offline_authenticators_for_owner_and_staff()
    {
        var ownerCounter = CafeCore.NewTwoStepSecret();
        _cafe.TurnOnTwoStep(_owner, ownerCounter, AppCode(ownerCounter));
        var ownerOffline = _cafe.StartOfflineUnlockFor(_owner, "9000000001");
        Assert.NotEqual(ownerCounter, ownerOffline);
        Assert.Throws<CafeException>(() => _cafe.TurnOnOfflineUnlockFor(_owner, "9000000001", ownerCounter, AppCode(ownerCounter)));
        _cafe.TurnOnOfflineUnlockFor(_owner, "9000000001", ownerOffline, AppCode(ownerOffline));

        var staffCounter = _cafe.StartTwoStepFor(_owner, "9000000002");
        Assert.Equal(32, staffCounter.Length);
        var recovery = _cafe.TurnOnTwoStepFor(_owner, "9000000002", staffCounter, AppCode(staffCounter));
        Assert.Equal(16, recovery.Length);
        var staffOffline = _cafe.StartOfflineUnlockFor(_owner, "9000000002");
        Assert.NotEqual(staffCounter, staffOffline);
        Assert.Throws<CafeException>(() => _cafe.TurnOnOfflineUnlockFor(_owner, "9000000002", staffCounter, AppCode(staffCounter)));
        Assert.Throws<CafeException>(() => _cafe.TurnOnOfflineUnlockFor(_owner, "9000000002", ownerOffline, AppCode(ownerOffline)));
        _cafe.TurnOnOfflineUnlockFor(_owner, "9000000002", staffOffline, AppCode(staffOffline));

        Assert.Throws<CafeException>(() => _cafe.StaffLogin("9000000002", "111111"));
        _clock = _clock.AddSeconds(30);
        var code = AppCode(staffCounter);
        Assert.Equal(_staff, _cafe.StaffLogin("9000000002", "111111", code));
        Assert.Throws<CafeException>(() => _cafe.StaffLogin("9000000002", "111111", code));
        Assert.Throws<CafeException>(() => _cafe.StartTwoStepFor(_staff, "9000000002"));
        Assert.Throws<CafeException>(() => _cafe.TurnOnTwoStepFor(_staff, "9000000002", staffCounter, code));
        Assert.Throws<CafeException>(() => _cafe.StartOfflineUnlockFor(_owner, "9000000003"));

        var cached = _cafe.OfflineUnlockAccounts();
        Assert.Contains(cached, x => x.Phone == "9000000001" && x.Secret == ownerOffline);
        Assert.Contains(cached, x => x.Phone == "9000000002" && x.Secret == staffOffline);
        Assert.DoesNotContain(cached, x => x.Secret == ownerCounter || x.Secret == staffCounter);
        Assert.DoesNotContain(cached, x => x.Phone == "9000000003");
    }

    [Fact]
    public void Offline_unlock_limit_is_owner_only_and_duplicate_sales_create_a_named_owner_alert()
    {
        _cafe.AddPc(_owner, "PC1");
        _cafe.AddPc(_owner, "PC2");
        var counter = _cafe.StartTwoStepFor(_owner, "9000000002");
        _cafe.TurnOnTwoStepFor(_owner, "9000000002", counter, AppCode(counter));
        var offline = _cafe.StartOfflineUnlockFor(_owner, "9000000002");
        _cafe.TurnOnOfflineUnlockFor(_owner, "9000000002", offline, AppCode(offline));

        Assert.Equal(180, _cafe.MaxOfflineUnlockMinutes);
        Assert.Throws<CafeException>(() => _cafe.SetMaxOfflineUnlockMinutes(_staff, 60));
        _cafe.SetMaxOfflineUnlockMinutes(_owner, 60);
        Assert.Equal(60, _cafe.MaxOfflineUnlockMinutes);
        Assert.Throws<CafeException>(() => _cafe.ProcessOfflineSale("PC1",
            new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002", AppCode(offline), CurrentStep,
                90, "cash", null, null)));

        var step = CurrentStep;
        var first = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offline, step), step, 60, "cash", null, null);
        _cafe.ProcessOfflineSale("PC1", first);
        var duplicate = first with { SaleId = Guid.NewGuid().ToString("N"), Minutes = 30 };
        Assert.Throws<CafeException>(() => _cafe.ProcessOfflineSale("PC2", duplicate));

        var alert = Assert.Single(_cafe.OfflineUnlockAlerts(_owner));
        Assert.Contains("Staff", alert);
        Assert.Contains("PC1", alert);
        Assert.Contains("PC2", alert);
        Assert.Contains("60 minutes", alert);
        Assert.Contains("30 minutes", alert);

        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _file, Password = "test-key-123", Pooling = false }.ToString());
        db.Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT by_user, detail FROM audit WHERE action = 'setting_max_offline_unlock_minutes'";
        using var rows = cmd.ExecuteReader();
        Assert.True(rows.Read());
        Assert.Equal(_owner, rows.GetInt64(0));
        Assert.Contains("60", rows.GetString(1));
        Assert.False(rows.Read());
    }

    [Fact]
    public void Offline_unlock_off_removes_the_person_from_PC_data_without_disabling_counter_login()
    {
        var counter = _cafe.StartTwoStepFor(_owner, "9000000002");
        _cafe.TurnOnTwoStepFor(_owner, "9000000002", counter, AppCode(counter));
        var offline = _cafe.StartOfflineUnlockFor(_owner, "9000000002");
        _cafe.TurnOnOfflineUnlockFor(_owner, "9000000002", offline, AppCode(offline));
        Assert.Contains(_cafe.OfflineUnlockAccounts(), x => x.Phone == "9000000002");

        Assert.Throws<CafeException>(() => _cafe.SetOfflineUnlockEnabled(_staff, "9000000002", false));
        _cafe.SetOfflineUnlockEnabled(_owner, "9000000002", false);
        Assert.DoesNotContain(_cafe.OfflineUnlockAccounts(), x => x.Phone == "9000000002");
        Assert.Contains(_cafe.OfflineUnlockPeople(_owner), x => x.Phone == "9000000002" && x.HasSecret && !x.Enabled);

        _clock = _clock.AddSeconds(30);
        Assert.Equal(_staff, _cafe.StaffLogin("9000000002", "111111", AppCode(counter)));
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _file, Password = "test-key-123", Pooling = false }.ToString());
        db.Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT by_user, action FROM audit WHERE action = 'offline_unlock_off'";
        using var rows = cmd.ExecuteReader();
        Assert.True(rows.Read());
        Assert.Equal(_owner, rows.GetInt64(0));
        Assert.False(rows.Read());
    }

    [Fact]
    public void Owner_can_end_other_counter_logins_and_one_persons_logins_owner_only_and_audited()
    {
        var tokens = new StaffTokens();
        var currentOwner = tokens.Issue(_owner);
        var secondOwner = tokens.Issue(_owner);
        var staffLogin = tokens.Issue(_staff);
        Assert.Throws<CafeException>(() => _cafe.AuditEndOtherCounterLogins(_staff, 2));
        var endedOthers = tokens.EndAllExcept(currentOwner);
        _cafe.AuditEndOtherCounterLogins(_owner, endedOthers);
        Assert.Equal(2, endedOthers);
        Assert.Equal(_owner, tokens.Check(currentOwner));
        Assert.Null(tokens.Check(secondOwner));
        Assert.Null(tokens.Check(staffLogin));

        var staffLoginOne = tokens.Issue(_staff);
        var staffLoginTwo = tokens.Issue(_staff);
        var staffId = _cafe.CounterLoginUser(_owner, "9000000002");
        Assert.Throws<CafeException>(() => _cafe.CounterLoginUser(_staff, "9000000002"));
        Assert.Throws<CafeException>(() => _cafe.AuditEndPersonCounterLogins(_staff, "9000000002", 2));
        var endedPerson = tokens.EndFor(staffId);
        _cafe.AuditEndPersonCounterLogins(_owner, "9000000002", endedPerson);
        Assert.Equal(2, endedPerson);
        Assert.Null(tokens.Check(staffLoginOne));
        Assert.Null(tokens.Check(staffLoginTwo));
        Assert.Equal(_owner, tokens.Check(currentOwner));

        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _file, Password = "test-key-123", Pooling = false }.ToString());
        db.Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT by_user, action, detail FROM audit WHERE action IN ('end_other_counter_logins', 'end_person_counter_logins') ORDER BY id";
        using var rows = cmd.ExecuteReader();
        Assert.True(rows.Read()); Assert.Equal(_owner, rows.GetInt64(0)); Assert.Equal("end_other_counter_logins", rows.GetString(1));
        Assert.Contains("2", rows.GetString(2));
        Assert.True(rows.Read()); Assert.Equal(_owner, rows.GetInt64(0)); Assert.Equal("end_person_counter_logins", rows.GetString(1));
        Assert.Contains("9000000002", rows.GetString(2));
        Assert.False(rows.Read());
    }

    [Fact]
    public void Offline_sales_are_verified_once_and_extend_or_start_a_session()
    {
        _cafe.AddPc(_owner, "PC1");
        _cafe.AddPc(_owner, "PC2");
        var counterSecret = _cafe.StartTwoStepFor(_owner, "9000000002");
        _cafe.TurnOnTwoStepFor(_owner, "9000000002", counterSecret, AppCode(counterSecret));
        var offlineSecret = _cafe.StartOfflineUnlockFor(_owner, "9000000002");
        _cafe.TurnOnOfflineUnlockFor(_owner, "9000000002", offlineSecret, AppCode(offlineSecret));
        _clock = _clock.AddSeconds(30);
        var step = CurrentStep;
        var code = AppCode(offlineSecret, step);
        var active = _cafe.StartPrepaid(_staff, "PC1", _cust, 30);
        var saleId = Guid.NewGuid().ToString("N");
        var sale = new OfflineSaleRequest(saleId, "9000000002", code, step, 30, "cash", null, active);
        Assert.Equal(active, _cafe.ProcessOfflineSale("PC1", sale));
        Assert.Equal(active, _cafe.ProcessOfflineSale("PC1", sale));
        Assert.Equal(4000, _cafe.BillFor(active).Paid);
        var refusedId = Guid.NewGuid().ToString("N");
        Assert.Throws<CafeException>(() => _cafe.ProcessOfflineSale("PC1", sale with { SaleId = refusedId }));
        _cafe.ReviewOfflineSale("PC1", refusedId, "9000000002", "authenticator code already used");
        Assert.Contains(_cafe.ForReview(), item => item.Contains(refusedId, StringComparison.Ordinal));
        _clock = _clock.AddSeconds(30);
        var walkInStep = new DateTimeOffset(_clock).ToUnixTimeSeconds() / 30;
        var walkInSale = new OfflineSaleRequest(Guid.NewGuid().ToString("N"),
            "9000000002", AppCode(offlineSecret, walkInStep), walkInStep, 60, "upi", "1234", null);
        Assert.Throws<CafeException>(() => _cafe.ProcessOfflineSale("PC2", walkInSale with { UpiLast4 = null }));
        var walkIn = _cafe.ProcessOfflineSale("PC2", walkInSale);
        Assert.Equal(walkIn, _cafe.StateOf("PC2").Session);
        Assert.Equal(6000, _cafe.BillFor(walkIn).Paid);
        _clock = _clock.AddSeconds(30);
        var extensionStep = new DateTimeOffset(_clock).ToUnixTimeSeconds() / 30;
        var extended = _cafe.ProcessOfflineSale("PC2", new OfflineSaleRequest(Guid.NewGuid().ToString("N"),
            "9000000002", AppCode(offlineSecret, extensionStep), extensionStep, 30, "cash", null, -1));
        Assert.Equal(walkIn, extended);
        Assert.Equal(10000, _cafe.BillFor(walkIn).Paid);
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _file, Password = "test-key-123", Pooling = false }.ToString());
        db.Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT action, detail FROM audit WHERE action = 'offline sale'";
        using var rows = cmd.ExecuteReader();
        Assert.True(rows.Read()); Assert.Contains("PC1", rows.GetString(1));
        Assert.True(rows.Read()); Assert.Contains("PC2", rows.GetString(1));
        Assert.True(rows.Read()); Assert.Contains("PC2", rows.GetString(1));
        Assert.False(rows.Read());
    }


    [Fact]
    public void Offline_sales_ignore_counter_login_order_and_are_unique_per_person_and_step_across_PCs()
    {
        _cafe.AddPc(_owner, "PC1");
        _cafe.AddPc(_owner, "PC2");
        var counterSecret = _cafe.StartTwoStepFor(_owner, "9000000002");
        _cafe.TurnOnTwoStepFor(_owner, "9000000002", counterSecret, AppCode(counterSecret));
        var offlineSecret = _cafe.StartOfflineUnlockFor(_owner, "9000000002");
        _cafe.TurnOnOfflineUnlockFor(_owner, "9000000002", offlineSecret, AppCode(offlineSecret));

        var oldStep = CurrentStep;
        _clock = _clock.AddSeconds(30);
        var laterLoginStep = CurrentStep;
        Assert.Equal(_staff, _cafe.StaffLogin("9000000002", "111111", AppCode(counterSecret, laterLoginStep)));
        var olderSale = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offlineSecret, oldStep), oldStep, 30, "cash", null, null);
        var firstSession = _cafe.ProcessOfflineSale("PC1", olderSale);
        Assert.Equal(firstSession, _cafe.StateOf("PC1").Session);

        _clock = _clock.AddSeconds(30);
        var sameStep = CurrentStep;
        var sameStepSale = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offlineSecret, sameStep), sameStep, 30, "cash", null, -1);
        _cafe.ProcessOfflineSale("PC1", sameStepSale);
        // An offline sale must not consume the separate counter-login step.
        Assert.Equal(_staff, _cafe.StaffLogin("9000000002", "111111", AppCode(counterSecret, sameStep)));

        _clock = _clock.AddSeconds(30);
        var earlierPcStep = CurrentStep;
        var saleFromPc1 = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offlineSecret, earlierPcStep), earlierPcStep, 30, "cash", null, -1);
        _clock = _clock.AddSeconds(30);
        var laterPcStep = CurrentStep;
        var saleFromPc2 = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offlineSecret, laterPcStep), laterPcStep, 30, "cash", null, null);

        var secondSession = _cafe.ProcessOfflineSale("PC2", saleFromPc2);
        var thirdSession = _cafe.ProcessOfflineSale("PC1", saleFromPc1);
        Assert.Equal(secondSession, _cafe.StateOf("PC2").Session);
        Assert.Equal(firstSession, thirdSession);

        var reusedStep = saleFromPc2 with { SaleId = Guid.NewGuid().ToString("N"), Session = -1 };
        Assert.Throws<CafeException>(() => _cafe.ProcessOfflineSale("PC1", reusedStep));
    }

    [Fact]
    public void Offline_sales_reject_codes_more_than_seven_days_old_or_two_steps_in_the_future()
    {
        _cafe.AddPc(_owner, "PC1");
        var counterSecret = _cafe.StartTwoStepFor(_owner, "9000000002");
        _cafe.TurnOnTwoStepFor(_owner, "9000000002", counterSecret, AppCode(counterSecret));
        var offlineSecret = _cafe.StartOfflineUnlockFor(_owner, "9000000002");
        _cafe.TurnOnOfflineUnlockFor(_owner, "9000000002", offlineSecret, AppCode(offlineSecret));
        var nowStep = CurrentStep;
        var oldestValidStep = nowStep - 7 * 24 * 60 * 60 / 30;
        var oldestValid = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offlineSecret, oldestValidStep), oldestValidStep, 30, "cash", null, null);
        var session = _cafe.ProcessOfflineSale("PC1", oldestValid);
        var oneAheadStep = nowStep + 1;
        var oneAhead = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offlineSecret, oneAheadStep), oneAheadStep, 30, "cash", null, -1);
        _cafe.ProcessOfflineSale("PC1", oneAhead);

        var tooOldStep = nowStep - 7 * 24 * 60 * 60 / 30 - 1;
        var tooOld = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offlineSecret, tooOldStep), tooOldStep, 30, "cash", null, -1);
        Assert.Throws<CafeException>(() => _cafe.ProcessOfflineSale("PC1", tooOld));
        var futureStep = nowStep + 2;
        var tooFarAhead = new OfflineSaleRequest(Guid.NewGuid().ToString("N"), "9000000002",
            AppCode(offlineSecret, futureStep), futureStep, 30, "cash", null, -1);
        Assert.Throws<CafeException>(() => _cafe.ProcessOfflineSale("PC1", tooFarAhead));
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
    public void PIN_reset_is_owner_only_and_is_audited()
    {
        Assert.Throws<CafeException>(() => _cafe.ResetPin(_staff, "9000000003", "5555"));
        Assert.Throws<CafeException>(() => _cafe.ResetPin(_cust, "9000000003", "6666"));
        _cafe.ResetPin(_owner, "9000000003", "5555");
        Assert.Equal(_cust, _cafe.Login("9000000003", "5555"));
        Assert.Throws<CafeException>(() => _cafe.ResetPin(_owner, "9000000002", "1234"));
        _cafe.ResetPin(_owner, "9000000002", "222222");
        Assert.Equal(_staff, _cafe.StaffLogin("9000000002", "222222"));
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _file, Password = "test-key-123", Pooling = false }.ToString());
        db.Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT by_user, action, detail FROM audit WHERE action = 'reset_pin' ORDER BY id";
        using var rows = cmd.ExecuteReader();
        Assert.True(rows.Read());
        Assert.Equal(_owner, rows.GetInt64(0));
        Assert.Equal("reset_pin", rows.GetString(1));
        Assert.Equal($"user {_cust}", rows.GetString(2));
        Assert.True(rows.Read());
        Assert.Equal(_owner, rows.GetInt64(0));
        Assert.Equal($"user {_staff}", rows.GetString(2));
        Assert.False(rows.Read());
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
    public void Three_wrong_PINs_lock_every_role_for_ten_minutes()
    {
        foreach (var (phone, correct) in new[] { ("9000000001", "432100"), ("9000000002", "111111"), ("9000000003", "2222") })
        {
            for (var i = 0; i < 3; i++) Assert.Throws<CafeException>(() => _cafe.Login(phone, "0000"));
            var locked = Assert.Throws<CafeException>(() => _cafe.Login(phone, correct));
            Assert.StartsWith("Too many wrong PINs", locked.Message);
            _clock = _clock.AddMinutes(9).AddSeconds(59);
            Assert.Throws<CafeException>(() => _cafe.Login(phone, correct));
            _clock = _clock.AddSeconds(1);
            Assert.NotEqual(0, _cafe.Login(phone, correct));
        }
    }

    [Fact]
    public void Customer_gets_three_fresh_PIN_tries_after_the_ten_minute_lock()
    {
        for (var i = 0; i < 3; i++) Assert.Throws<CafeException>(() => _cafe.Login("9000000003", "0000"));
        Assert.Throws<CafeException>(() => _cafe.Login("9000000003", "2222"));

        _clock = _clock.AddMinutes(10);
        var unknown = Assert.Throws<CafeException>(() => _cafe.Login("9999999999", "2222")).Message;
        for (var i = 0; i < 2; i++)
            Assert.Equal(unknown, Assert.Throws<CafeException>(() => _cafe.Login("9000000003", "0000")).Message);
        Assert.Equal(unknown, Assert.Throws<CafeException>(() => _cafe.Login("9000000003", "0000")).Message);
        Assert.StartsWith("Too many wrong PINs", Assert.Throws<CafeException>(() => _cafe.Login("9000000003", "2222")).Message);

        _clock = _clock.AddMinutes(10);
        Assert.Equal(_cust, _cafe.Login("9000000003", "2222"));
    }

    [Fact]
    public void Counter_logins_remain_valid_until_explicit_logout()
    {
        var tokens = new StaffTokens();
        var t = tokens.Issue(_staff);
        var u = tokens.Issue(_owner);
        Assert.Equal(2, tokens.Count);
        Assert.Equal(_staff, tokens.Check(t));
        Assert.Equal(_owner, tokens.Check(u));
        Assert.Equal(_staff, tokens.Check(t));
        tokens.End(u);
        Assert.Null(tokens.Check(u));
        Assert.Equal(_staff, tokens.Check(t));
        tokens.End(t);
        Assert.Null(tokens.Check(t));
        Assert.Null(tokens.Check("made-up"));
    }
}
