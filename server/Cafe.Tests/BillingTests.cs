using Cafe;
using Microsoft.Data.Sqlite;
using Xunit;

// One test per check in the Phase 2 test plan (T2.x), plus the security rules the money depends on.
// Owner's rate card: 30 min ₹40, 1 h ₹60, 1.5 h ₹100, then ₹40 per 30 min; 5 min start grace, 30 min minimum,
// 30 min blocks, 5 min grace after each block; unused minutes of a charged block are kept for 7 days. Paise.
public sealed class BillingTests : IDisposable
{
    DateTime _clock = new(2026, 11, 9, 10, 0, 0, DateTimeKind.Utc);
    readonly string _file = Path.Combine(Path.GetTempPath(), $"cafe-test-{Guid.NewGuid():N}.db");
    readonly CafeCore _cafe;
    readonly long _owner, _staff, _cust;

    public BillingTests()
    {
        _cafe = new CafeCore(_file, "test-key-123", () => _clock);
        _owner = _cafe.AddUser(null, Role.Owner, "Owner", "9000000001", "432100");
        _staff = _cafe.AddUser(_owner, Role.Staff, "Staff", "9000000002", "111111");
        _cust = _cafe.AddUser(_staff, Role.Customer, "Ravi", "9000000003", "2222");
    }
    public void Dispose() { _cafe.Dispose(); SqliteConnection.ClearAllPools(); File.Delete(_file); }

    void Wait(double minutes) => _clock = _clock.AddMinutes(minutes);
    long PlayFor(double minutes, string pc = "PC1")
    {
        var s = _cafe.StartPostpaid(_staff, pc, _cust);
        Wait(minutes);
        return _cafe.Stop(_staff, s).Charged;
    }

    [Fact]
    public void Time_lock_setting_is_owner_only_and_off_keeps_the_existing_logout_behaviour()
    {
        _cafe.AddPc(_owner, "PC1");
        Assert.False(_cafe.LockWhenTimeRunsOut); // default is off
        Assert.Throws<CafeException>(() => _cafe.SetLockWhenTimeRunsOut(_staff, true));
        Assert.Throws<CafeException>(() => _cafe.SetLockWhenTimeRunsOut(_cust, true));

        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 30);
        Wait(31);
        _cafe.EnforceTimeLimits(); // off: the server does not end the session
        Assert.Equal(s, _cafe.StateOf("PC1").Session);
        Assert.Equal(4000, _cafe.Stop(_staff, s).Charged); // normal manual logout still bills as before
    }

    [Fact]
    public void Time_lock_on_ends_and_bills_a_prepaid_session_at_zero()
    {
        _cafe.AddPc(_owner, "PC1");
        _cafe.SetLockWhenTimeRunsOut(_owner, true);
        Assert.True(_cafe.LockWhenTimeRunsOut);
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 30);
        Wait(30);
        _cafe.EnforceTimeLimits();

        var state = _cafe.StateOf("PC1");
        Assert.True(state.Locked);
        Assert.Null(state.Session);
        Assert.Equal(TimeSpan.FromMinutes(30), _cafe.BillFor(s).Used);
        Assert.Equal(4000, _cafe.BillFor(s).Charged);
    }

    [Fact]
    public void Time_lock_on_ends_an_offline_pc_session_before_it_reconnects()
    {
        _cafe.AddPc(_owner, "PC1");
        _cafe.BuyPlan(_staff, _cust, 30, 7, 3000, "cash");
        _cafe.SetLockWhenTimeRunsOut(_owner, true);
        var started = _cafe.PcLogin("PC1", "9000000003", "2222");
        var session = started.Session!.Value;
        Wait(36); // no PC status checks: it is offline

        _cafe.EnforceTimeLimits(); // the counter server ends it without a PC request
        Assert.Null(_cafe.StateOf("PC1").Session); // on reconnect, the PC receives the lock screen state
        Assert.True(_cafe.StateOf("PC1").Locked);
        Assert.Equal(TimeSpan.FromMinutes(36), _cafe.BillFor(session).Used);
        Assert.Equal(4000, _cafe.BillFor(session).Charged); // six minutes past the plan: one ₹40 extra block
    }

    [Fact] public void T2_1_inside_grace_is_free() => Assert.Equal(0, PlayFor(1));

    [Fact]
    public void Unused_minutes_of_a_charged_block_are_kept_for_7_days_but_not_the_free_start()
    {
        Assert.Equal(0, PlayFor(5)); // free start: nothing charged, nothing kept
        Assert.Equal(0, _cafe.PlanMinutesLeft(_cust));
        Assert.Equal(6000, PlayFor(36)); // 1 hour charged, 24 min kept
        Assert.Equal(24, _cafe.PlanMinutesLeft(_cust));
        _clock = _clock.AddDays(7).AddMinutes(1);
        Assert.Equal(0, _cafe.PlanMinutesLeft(_cust)); // gone after 7 days
    }

    [Theory]
    [InlineData(5, 0)]       // exactly at the start grace: still free
    [InlineData(6, 4000)]    // just past it: the 30 min minimum, ₹40
    [InlineData(29, 4000)]
    [InlineData(30, 4000)]
    [InlineData(35, 4000)]   // inside the 5 min grace after the first block
    [InlineData(36, 6000)]   // grace over: 1 hour, ₹60
    [InlineData(61, 6000)]
    [InlineData(65, 6000)]
    [InlineData(66, 10000)]  // 1.5 hours, ₹100
    [InlineData(96, 14000)]  // past the card: ₹40 for each further 30 min
    public void T2_2_pay_at_end_follows_minimum_and_blocks(double minutes, long paise) => Assert.Equal(paise, PlayFor(minutes));

    [Fact]
    public void T2_3_prepaid_charges_up_front_then_grace_then_blocks()
    {
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 60);
        Assert.Equal(6000, _cafe.BillFor(s).Due);
        Wait(65); // 5 min past the hour: inside the grace
        Assert.Equal(6000, _cafe.Stop(_staff, s).Charged);
        Assert.Equal(0, _cafe.PlanMinutesLeft(_cust));

        var s2 = _cafe.StartPrepaid(_staff, "PC2", _cust, 60);
        Wait(75); // 15 min past: grace over, one more 30 min block
        var bill = _cafe.Stop(_staff, s2);
        Assert.Equal(TimeSpan.FromMinutes(75), bill.Used);
        Assert.Equal(10000, bill.Charged); // ₹60 bought + one ₹40 extra block
        Assert.Equal(15, _cafe.PlanMinutesLeft(_cust)); // the unused 15 min of that block are kept
    }

    [Fact]
    public void T2_3b_unused_prepaid_minutes_stay_for_another_day()
    {
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 30);
        Wait(2); // only 2 min played: no grace on bought time, 28 min kept
        _cafe.Stop(_staff, s);
        Assert.Equal(28, _cafe.PlanMinutesLeft(_cust));
        _clock = _clock.AddDays(3); // another day
        var again = _cafe.StartOnPlan(_cust, "PC4", _cust);
        Wait(20);
        Assert.Equal(0, _cafe.Stop(_cust, again).Charged);
        Assert.Equal(8, _cafe.PlanMinutesLeft(_cust));
    }

    [Fact]
    public void T2_4_pause_is_free_add_time_charges_move_keeps_time()
    {
        var s = _cafe.StartPostpaid(_staff, "PC1", _cust);
        Wait(20); _cafe.Pause(_staff, s);
        Wait(30); _cafe.Resume(_staff, s);
        _cafe.MoveSeat(_staff, s, "PC2");
        Assert.Throws<CafeException>(() => _cafe.StartPostpaid(_staff, "PC2", _cust)); // PC2 is now taken
        _cafe.StartPostpaid(_staff, "PC1", _staff); // PC1 is free again
        Wait(5);
        var bill = _cafe.Stop(_staff, s);
        Assert.Equal(TimeSpan.FromMinutes(25), bill.Used); // 20 + 5, the 30 paused minutes not counted
        Assert.Equal(4000, bill.Charged);

        var p = _cafe.StartPrepaid(_staff, "PC3", _cust, 30);
        _cafe.AddTime(_staff, p, 30);
        Assert.Equal(8000, _cafe.BillFor(p).Due); // ₹40 per 30 min recharge
    }

    [Fact]
    public void T2_4b_owner_can_charge_paused_time_staff_cannot()
    {
        var s = _cafe.StartPostpaid(_staff, "PC1", _cust);
        Wait(20); _cafe.Pause(_staff, s); Wait(30);
        Assert.Throws<CafeException>(() => _cafe.Resume(_staff, s, chargePausedTime: true));
        _cafe.Resume(_owner, s, chargePausedTime: true);
        Assert.Equal(TimeSpan.FromMinutes(50), _cafe.Stop(_staff, s).Used);
    }

    [Fact]
    public void Server_answers_the_shop_network_only()
    {
        foreach (var ok in new[] { "127.0.0.1", "::1", "10.1.2.3", "172.16.0.9", "172.31.255.1", "192.168.1.10", "169.254.3.4", "100.64.0.1", "100.127.9.9", "fe80::1", "fd7a:115c:a1e0::1", "::ffff:192.168.1.5" })
            Assert.True(ShopNetwork.Allows(System.Net.IPAddress.Parse(ok)), ok);
        foreach (var no in new[] { "8.8.8.8", "172.32.0.1", "192.169.0.1", "100.128.0.1", "11.0.0.1", "2001:4860::8888", "::ffff:8.8.8.8" })
            Assert.False(ShopNetwork.Allows(System.Net.IPAddress.Parse(no)), no);
        Assert.False(ShopNetwork.Allows(null));
    }

    [Fact]
    public void Staff_pages_are_only_allowed_on_the_counter_pc_or_tailscale()
    {
        foreach (var ok in new[] { "127.0.0.1", "::1", "100.64.0.1", "100.127.255.254", "::ffff:100.64.0.1", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0:ffff::1" })
            Assert.True(StaffLoginNetwork.Allows(System.Net.IPAddress.Parse(ok)), ok);
        foreach (var no in new[] { "10.1.2.3", "172.16.0.9", "192.168.1.10", "169.254.3.4", "100.63.255.255", "100.128.0.1", "8.8.8.8", "fd7a:115c:a1e1::1", "fd7b:115c:a1e0::1" })
            Assert.False(StaffLoginNetwork.Allows(System.Net.IPAddress.Parse(no)), no);
        Assert.True(StaffLoginNetwork.Allows(System.Net.IPAddress.Parse("192.168.1.20"), System.Net.IPAddress.Parse("192.168.1.20")));
        Assert.True(StaffLoginNetwork.Allows(System.Net.IPAddress.Parse("10.0.0.8"), System.Net.IPAddress.Parse("10.0.0.8")));
        Assert.False(StaffLoginNetwork.Allows(System.Net.IPAddress.Parse("192.168.1.20"), System.Net.IPAddress.Parse("192.168.1.21")));
        Assert.False(StaffLoginNetwork.Allows(null));
        Assert.Equal("Counter pages open only on the counter PC.", StaffLoginNetwork.RefusalMessage);
    }

    [Fact]
    public void T2_5b_group_members_leaving_at_different_times_add_up()
    {
        var lead = _cafe.StartPostpaid(_staff, "PC1", _cust);
        var a = _cafe.StartPostpaid(_staff, "PC2", _cust);
        var b = _cafe.StartPostpaid(_staff, "PC3", _cust);
        _cafe.JoinGroup(_staff, a, lead); _cafe.JoinGroup(_staff, b, lead);
        Wait(25); _cafe.Stop(_staff, a);    // 1 block
        Wait(20); _cafe.Stop(_staff, b);    // 45 min: 2 blocks
        Wait(40); _cafe.Stop(_staff, lead); // 85 min: 3 blocks
        var bill = _cafe.BillFor(lead);
        Assert.Equal(4000 + 6000 + 10000, bill.Due);
        Assert.Equal(TimeSpan.FromMinutes(25 + 45 + 85), bill.Used);
    }

    [Fact]
    public void T2_5_group_bill_across_four_pcs_is_one_total()
    {
        var lead = _cafe.StartPostpaid(_staff, "PC1", _cust);
        var others = new[] { "PC2", "PC3", "PC4" }.Select(pc => _cafe.StartPostpaid(_staff, pc, _cust)).ToList();
        foreach (var o in others) _cafe.JoinGroup(_staff, o, lead);
        Wait(45);
        foreach (var s in others.Prepend(lead)) _cafe.Stop(_staff, s);
        var bill = _cafe.BillFor(others[2]);
        Assert.Equal(lead, bill.SessionId);
        Assert.Equal(4 * 6000, bill.Due); // 45 min = 2 blocks = ₹60 each
        _cafe.Pay(_staff, lead, "cash", 24000);
        Assert.Equal(0, _cafe.BillFor(others[0]).Due);
    }

    [Fact]
    public void T2_6_plan_balance_expiry_and_owner_extension()
    {
        var plan = _cafe.BuyPlan(_staff, _cust, 600, 7, 50000, "cash");
        var s = _cafe.StartOnPlan(_cust, "PC1", _cust);
        Wait(180);
        Assert.Equal(0, _cafe.Stop(_cust, s).Charged); // 3 h off the plan, nothing to pay
        _clock = _clock.AddDays(8);
        Assert.Throws<CafeException>(() => _cafe.StartOnPlan(_cust, "PC1", _cust)); // day 8: expired
        Assert.Throws<CafeException>(() => _cafe.ExtendPlan(_staff, plan, 7, "goodwill"));
        Assert.Throws<CafeException>(() => _cafe.ExtendPlan(_owner, plan, 7, " "));
        _cafe.ExtendPlan(_owner, plan, 7, "customer was travelling");
        var s2 = _cafe.StartOnPlan(_cust, "PC1", _cust);
        Wait(450); // 420 min left, uses 450: 30 min beyond the plan is billed
        Assert.Equal(4000, _cafe.Stop(_cust, s2).Charged);
    }

    [Fact]
    public void T2_6b_plan_time_uses_the_same_grace_and_blocks()
    {
        _cafe.BuyPlan(_staff, _cust, 120, 7, 10000, "cash");
        foreach (var (play, left) in new[] { (2, 118), (33, 85), (40, 45) }) // exact minutes off, no grace while time is left
        {
            var s = _cafe.StartOnPlan(_cust, "PC1", _cust);
            Wait(play);
            Assert.Equal(0, _cafe.Stop(_cust, s).Charged);
            Assert.Equal(left, _cafe.PlanMinutesLeft(_cust));
        }
        var over = _cafe.StartOnPlan(_cust, "PC1", _cust);
        Wait(50); // 45 left: 5 min over is the grace
        Assert.Equal(0, _cafe.Stop(_cust, over).Charged);
        _cafe.BuyPlan(_staff, _cust, 30, 7, 3000, "cash");
        var over2 = _cafe.StartOnPlan(_cust, "PC1", _cust);
        Wait(36); // 30 left: 6 min over, grace gone, one 30 min block in money
        Assert.Equal(4000, _cafe.Stop(_cust, over2).Charged);
        Assert.Equal(24, _cafe.PlanMinutesLeft(_cust)); // the unused 24 min of that block are kept
    }

    [Fact]
    public void T2_7_wallet_top_up_spend_no_overdraw_no_cash_out()
    {
        _cafe.TopUp(_staff, _cust, "upi", 10000, "4821"); // a paid booking that never started stays here for another day
        Assert.Equal(10000, _cafe.WalletBalance(_cust));
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 60);
        _cafe.Pay(_staff, s, "wallet", 6000);
        Assert.Equal(4000, _cafe.WalletBalance(_cust));
        var s2 = _cafe.StartPrepaid(_staff, "PC2", _cust, 60);
        Assert.Throws<CafeException>(() => _cafe.Pay(_staff, s2, "wallet", 6000)); // only ₹40 left
        Assert.Throws<CafeException>(() => _cafe.TopUp(_staff, _cust, "wallet", 100)); // no moving wallet money around
        Assert.Throws<CafeException>(() => _cafe.TopUp(_staff, _cust, "upi", 100, "ab12")); // UPI digits only, everywhere
        Assert.Throws<CafeException>(() => _cafe.TopUp(_staff, _cust, "cash", -4000)); // no cash-out
    }

    [Fact]
    public void T2_8_discounts_owner_only_and_need_a_reason()
    {
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 60);
        Assert.Throws<CafeException>(() => _cafe.Adjust(_staff, s, -1000, "regular customer"));
        Assert.Throws<CafeException>(() => _cafe.Adjust(_owner, s, -1000, ""));
        _cafe.Adjust(_owner, s, -1000, "regular customer");
        Assert.Equal(5000, _cafe.BillFor(s).Due);
        Assert.Throws<CafeException>(() => _cafe.Adjust(_cust, s, -5000, "please"));
    }

    [Fact]
    public void T2_9_stop_twice_or_at_the_same_moment_bills_once()
    {
        var s = _cafe.StartPostpaid(_staff, "PC1", _cust);
        Wait(40);
        Parallel.For(0, 8, _ => _cafe.Stop(_staff, s)); // countdown, staff and a double click all at once
        _cafe.Stop(_cust, s);
        Assert.Equal(6000, _cafe.BillFor(s).Charged);
    }

    [Fact]
    public void T2_10_split_payment_and_shift_close_show_missing_cash()
    {
        var shift = _cafe.OpenShift(_staff);
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 120); // ₹140
        _cafe.Pay(_staff, s, "cash", 7000);
        Assert.Throws<CafeException>(() => _cafe.Pay(_staff, s, "upi", 7000));          // no last 4 digits
        Assert.Throws<CafeException>(() => _cafe.Pay(_staff, s, "upi", 8000, "1234")); // more than is due
        _cafe.Pay(_staff, s, "upi", 7000, "1234");
        Assert.Equal(0, _cafe.BillFor(s).Due);
        Assert.Equal(7000, _cafe.ShiftTotal(shift, "cash"));
        Assert.Equal(7000, _cafe.ShiftTotal(shift, "upi"));
        var (expected, difference) = _cafe.CloseShift(_staff, 6000); // ₹10 short in the drawer
        Assert.Equal(7000, expected);
        Assert.Equal(-1000, difference);
    }

    [Fact]
    public void Owner_or_staff_can_lock_any_pc_and_locked_time_is_free()
    {
        var token = _cafe.AddPc(_owner, "PC1");
        Assert.Throws<CafeException>(() => _cafe.AddPc(_staff, "PC2"));
        Assert.Equal("PC1", _cafe.PcByToken(token));
        Assert.Null(_cafe.PcByToken("made-up"));
        var s = _cafe.StartPostpaid(_staff, "PC1", _cust);
        Wait(20);
        Assert.False(_cafe.StateOf("PC1").Locked);
        Assert.Throws<CafeException>(() => _cafe.Lock(_cust, "PC1"));
        _cafe.Lock(_staff, "PC1", "Please come to the counter");
        Assert.Equal((true, "Please come to the counter"), (_cafe.StateOf("PC1").Locked, _cafe.StateOf("PC1").Message));
        Wait(30); // locked: not charged
        _cafe.Unlock(_owner, "PC1");
        Wait(5);
        Assert.Equal(TimeSpan.FromMinutes(25), _cafe.Stop(_staff, s).Used);
        Assert.True(_cafe.StateOf("PC1").Locked); // no session: lock screen
    }

    [Fact]
    public void Pc_login_uses_plan_time_first_then_pay_at_end_and_logout_bills()
    {
        _cafe.AddPc(_owner, "PC1");
        Assert.Throws<CafeException>(() => _cafe.PcLogin("PC1", "9000000003", "0000"));
        var st = _cafe.PcLogin("PC1", "9000000003", "2222");
        Assert.Equal(("postpaid", false, (long?)null), (st.Mode, st.Locked, st.LeftSec));
        Assert.Throws<CafeException>(() => _cafe.PcLogin("PC1", "9000000002", "111111")); // in use
        Wait(40);
        Assert.Equal(6000, _cafe.PcLogout("PC1").Charged); // 40 min: 1 hour charged, 20 min kept
        _cafe.BuyPlan(_staff, _cust, 60, 7, 5000, "cash");
        st = _cafe.PcLogin("PC1", "9000000003", "2222");
        Assert.Equal(("plan", 4800L), (st.Mode, st.LeftSec)); // 60 bought + 20 kept
        Wait(10);
        Assert.Equal(4200L, _cafe.StateOf("PC1").LeftSec);
        _cafe.Lock(_staff, "PC1");
        Assert.Throws<CafeException>(() => _cafe.PcLogout("PC9"));
    }

    [Fact]
    public void Customer_self_lock_keeps_time_running_and_only_they_or_staff_unlock()
    {
        _cafe.AddPc(_owner, "PC1");
        _cafe.AddUser(_staff, Role.Customer, "Other", "9000000004", "3333");
        _cafe.PcLogin("PC1", "9000000003", "2222");
        Wait(10);
        var st = _cafe.PcSelfLock("PC1");
        Assert.Equal((true, true), (st.Locked, st.SelfLocked));
        Wait(20); // stepped away: still charged
        Assert.Throws<CafeException>(() => _cafe.PcLogin("PC1", "9000000004", "3333")); // someone else
        Assert.Throws<CafeException>(() => _cafe.PcLogin("PC1", "9000000003", "9999")); // wrong PIN
        Assert.False(_cafe.PcLogin("PC1", "9000000003", "2222").Locked);
        Assert.Equal(1800, _cafe.StateOf("PC1").ElapsedSec);
        _cafe.PcSelfLock("PC1");
        _cafe.Unlock(_staff, "PC1"); // staff can always open it
        Assert.False(_cafe.StateOf("PC1").Locked);
        Assert.Equal(TimeSpan.FromMinutes(30), _cafe.PcLogout("PC1").Used);
        Assert.Throws<CafeException>(() => _cafe.PcSelfLock("PC1")); // nobody logged in
    }

    [Fact]
    public void Carry_over_lasts_30_days_by_default_and_the_owner_can_change_it()
    {
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 60);
        Wait(10); _cafe.Stop(_staff, s);
        Assert.Equal(50, _cafe.PlanMinutesLeft(_cust));
        _clock = _clock.AddDays(31);
        Assert.Equal(0, _cafe.PlanMinutesLeft(_cust)); // expired after the default 30 days
        _cafe.Rate = _cafe.Rate with { CarryOverDays = 90 }; // owner's own default
        var s2 = _cafe.StartPrepaid(_staff, "PC1", _cust, 60);
        Wait(30); _cafe.Stop(_staff, s2);
        _clock = _clock.AddDays(60);
        Assert.Equal(30, _cafe.PlanMinutesLeft(_cust));
    }

    [Fact]
    public void T1_4_offline_logout_is_billed_through_server_receipt_time()
    {
        _cafe.AddPc(_owner, "PC1");
        _cafe.PcLogin("PC1", "9000000003", "2222");
        Wait(20); _cafe.PcSeen("PC1");
        Wait(15);                      // customer logs out while the network is down
        Wait(60);                      // server receives the queued logout an hour later
        Assert.Equal(TimeSpan.FromMinutes(95), _cafe.PcLogout("PC1", 3600).Used);

        _cafe.PcLogin("PC1", "9000000003", "2222");
        Wait(10); _cafe.PcSeen("PC1");
        Wait(5);
        // A PC cannot reduce the bill by claiming an earlier logout time.
        Assert.Equal(TimeSpan.FromMinutes(15), _cafe.PcLogout("PC1", 5 * 3600).Used);
    }

    [Fact]
    public void Many_pcs_and_staff_at_once_never_break_the_database()
    {
        var tokens = Enumerable.Range(1, 15).Select(i => _cafe.AddPc(_owner, $"PC{i}")).ToArray();
        _cafe.PcLogin("PC1", "9000000003", "2222");
        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();
        Parallel.For(0, 3000, new ParallelOptions { MaxDegreeOfParallelism = 16 }, i =>
        {
            try
            {
                var pc = _cafe.PcByToken(tokens[i % 15])!;
                _cafe.PcSeen(pc); _cafe.StateOf(pc);
                _cafe.PlanMinutesLeft(_cust); _cafe.WalletBalance(_cust);
                if (i % 50 == 0) { _cafe.Lock(_staff, pc, "x"); _cafe.Unlock(_staff, pc); }
            }
            catch (Exception e) { errors.Add(e); }
        });
        Assert.Empty(errors);
        Assert.Equal(0, _cafe.PcLogout("PC1").Charged); // the database still works afterwards (no time passed: inside the grace)
    }

    [Fact]
    public void A_database_from_a_newer_version_is_refused()
    {
        _cafe.Dispose();
        using (var db = new SqliteConnection($"Data Source={_file};Password=test-key-123;Pooling=False"))
        {
            db.Open();
            using var c = db.CreateCommand(); c.CommandText = "PRAGMA user_version = 99"; c.ExecuteNonQuery();
        }
        Assert.Throws<CafeException>(() => new CafeCore(_file, "test-key-123"));
    }

    [Fact]
    public void Staff_cannot_sneak_a_discount_through_negative_or_silly_numbers()
    {
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 60);
        Assert.Throws<CafeException>(() => _cafe.AddTime(_staff, s, -60));
        Assert.Throws<CafeException>(() => _cafe.AddTime(_staff, s, 0));
        Assert.Throws<CafeException>(() => _cafe.StartPrepaid(_staff, "PC2", _cust, -30));
        Assert.Throws<CafeException>(() => _cafe.BuyPlan(_staff, _cust, -600, 7, 5000, "cash"));
        Assert.Throws<CafeException>(() => _cafe.BuyPlan(_staff, _cust, 600, 7, -5000, "cash"));
        Assert.Throws<CafeException>(() => _cafe.BuyPlan(_staff, _cust, 600, 0, 5000, "cash"));
        Assert.Throws<CafeException>(() => _cafe.StartPrepaid(_staff, "PC2", _cust, 100_000));
        Assert.Equal(6000, _cafe.BillFor(s).Due); // unchanged
    }

    [Fact]
    public void A_logout_dated_long_ago_is_flagged_for_the_owner()
    {
        _cafe.AddPc(_owner, "PC1");
        _cafe.PcLogin("PC1", "9000000003", "2222");
        Wait(1); _cafe.PcSeen("PC1");
        Wait(120);
        _cafe.PcLogout("PC1", 7200); // "I logged out 2 hours ago"
        var flagged = Assert.Single(_cafe.ForReview());
        Assert.Contains("PC1", flagged);
        _cafe.PcLogin("PC1", "9000000003", "2222");
        Wait(40); _cafe.PcSeen("PC1");
        _cafe.PcLogout("PC1", 5); // ordinary: not flagged
        Assert.Single(_cafe.ForReview());
    }

    [Fact]
    public void Customers_cannot_use_the_staff_login_and_silly_numbers_do_not_crash()
    {
        Assert.Throws<CafeException>(() => _cafe.StaffLogin("9000000003", "2222"));
        Assert.Equal(_staff, _cafe.StaffLogin("9000000002", "111111"));
        _cafe.AddPc(_owner, "PC1");
        _cafe.PcLogin("PC1", "9000000003", "2222");
        Wait(30); _cafe.PcSeen("PC1");
        Assert.Equal(TimeSpan.FromMinutes(30), _cafe.PcLogout("PC1", long.MaxValue).Used); // floored at the last contact
    }

    [Fact]
    public void Money_rows_cannot_be_edited_or_deleted_even_directly()
    {
        var s = _cafe.StartPrepaid(_staff, "PC1", _cust, 60);
        _cafe.Pay(_staff, s, "cash", 6000);
        _cafe.Dispose();
        using var db = new SqliteConnection($"Data Source={_file};Password=test-key-123;Pooling=False");
        db.Open();
        foreach (var sql in new[] { "UPDATE ledger SET amount = 0", "DELETE FROM ledger", "DELETE FROM audit", "UPDATE audit SET detail = ''" })
        {
            using var c = db.CreateCommand(); c.CommandText = sql;
            Assert.Throws<SqliteException>(() => c.ExecuteNonQuery());
        }
    }

    [Fact]
    public void Database_file_is_unreadable_without_the_key()
    {
        _cafe.TopUp(_staff, _cust, "cash", 500);
        _cafe.Dispose();
        SqliteConnection.ClearAllPools();
        var bytes = File.ReadAllBytes(_file);
        Assert.DoesNotContain("SQLite format 3", System.Text.Encoding.ASCII.GetString(bytes, 0, 16));
        Assert.DoesNotContain("Ravi", System.Text.Encoding.UTF8.GetString(bytes));
        using var wrong = new SqliteConnection($"Data Source={_file};Password=wrong-key;Pooling=False");
        Assert.ThrowsAny<SqliteException>(() => { wrong.Open(); using var c = wrong.CreateCommand(); c.CommandText = "SELECT count(*) FROM users"; c.ExecuteScalar(); });
    }

    [Fact]
    public void Pin_login_locks_after_five_wrong_tries_and_says_nothing_specific()
    {
        Assert.Equal(_cust, _cafe.Login("9000000003", "2222"));
        var unknown = Assert.Throws<CafeException>(() => _cafe.Login("9999999999", "2222")).Message;
        for (var i = 0; i < 5; i++) Assert.Equal(unknown, Assert.Throws<CafeException>(() => _cafe.Login("9000000003", "0000")).Message);
        Assert.Throws<CafeException>(() => _cafe.Login("9000000003", "2222")); // right PIN, but locked
        Wait(16);
        Assert.Equal(_cust, _cafe.Login("9000000003", "2222"));
    }

    [Fact]
    public void Roles_who_can_add_whom()
    {
        Assert.Throws<CafeException>(() => _cafe.AddUser(_owner, Role.Staff, "Short PIN", "9000000010", "1234")); // staff need 6+ digits
        Assert.Throws<CafeException>(() => _cafe.AddUser(_staff, Role.Customer, "Bad phone", "12345", "1234"));
        Assert.Throws<CafeException>(() => _cafe.AddUser(_staff, Role.Customer, new string('x', 61), "9000000011", "1234"));
        Assert.Throws<CafeException>(() => _cafe.AddUser(_staff, Role.Customer, "Long PIN", "9000000012", "1234567890123"));
        _cafe.AddPc(_owner, "PC1");
        Assert.Throws<CafeException>(() => _cafe.Lock(_staff, "PC1", new string('x', 201)));
        Assert.Throws<CafeException>(() => _cafe.AddUser(_staff, Role.Staff, "X", "9000000009", "1234"));
        Assert.Throws<CafeException>(() => _cafe.AddUser(_cust, Role.Customer, "X", "9000000009", "1234"));
        Assert.Throws<CafeException>(() => _cafe.AddUser(_staff, Role.Customer, "X", "9000000009", "12a4"));
        Assert.Throws<CafeException>(() => _cafe.StartPostpaid(_cust, "PC1", _staff)); // customers start only their own session
    }
}
