using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Input;
using FlaUI.Core.WindowsAPI;
using FlaUI.UIA3;
using Xunit;


// Phase 1 on a real Windows desktop: FlaUI plays the customer against the real server and the real PC program
// (CAFE_SERVER_EXE, CAFE_AGENT_EXE, CAFE_WATCHDOG_EXE), so this tests what ships, not a mock.
[Collection("desktop")] // one server port, one desktop: never two tests at once
public sealed class LockScreenTests : IDisposable
{
    readonly Rig _rig = new();
    Process _agent = null!;
    Application _app = null!;

    public void Dispose() { Rig.Kill(_agent); _rig.Dispose(); }

    [Fact]
    public async Task Pending_cleanup_keeps_the_lock_screen_blocked_with_counter_message()
    {
        var note = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "wipe", "request");
        var wipeDirectory = Path.GetDirectoryName(note)!;
        var createdWipeDirectory = !Directory.Exists(wipeDirectory);
        var createdNote = false;
        try
        {
            Assert.False(File.Exists(note), "a clean-up request was already present before the test");
            Directory.CreateDirectory(wipeDirectory);
            _agent = _rig.StartAgent();
            _app = Application.Attach(_agent.Id);
            LogIn("9000000003", "2222");
            Rig.WaitFor(() => Hidden("LockScreen"), 10, "login did not unlock the PC");
            File.WriteAllText(note, "");
            createdNote = true;
            Rig.WaitFor(() => !Hidden("LockScreen") && Text(Window("LockScreen"), "Message") == "Getting this PC ready for the next customer. Please wait.", 10,
                "new clean-up did not show the normal waiting message");
            Assert.False(Part(Window("LockScreen"), "Login").AsButton().IsEnabled, "login stayed enabled during clean-up");
            File.SetCreationTimeUtc(note, DateTime.UtcNow.AddMinutes(-3));
            Rig.WaitFor(() => Text(Window("LockScreen"), "Message") == "Please ask at the counter.", 10,
                "old clean-up did not show the counter message");
            File.Delete(note);
            Rig.WaitFor(() => Hidden("LockScreen"), 10, "PC did not return to its active session after the request cleared");
        }
        finally
        {
            Rig.Kill(_agent);
            if (createdNote) { try { File.Delete(note); } catch (IOException) { } }
            if (createdWipeDirectory)
            {
                try
                {
                    if (Directory.Exists(wipeDirectory) && !Directory.EnumerateFileSystemEntries(wipeDirectory).Any())
                        Directory.Delete(wipeDirectory);
                }
                catch (IOException) { }
            }
        }
    }

    [Fact]
    public async Task T1_1_to_T1_6_escape_login_locks_offline_logout()
    {
        try { await Scenario(); }
        catch { Rig.Screenshot(); throw; }
    }

    async Task Scenario()
    {
        _agent = _rig.StartAgent();
        using (var nonAgent = Process.Start(new ProcessStartInfo(Rig.Env("CAFE_WATCHDOG_EXE"), "--test-pipe-probe") { UseShellExecute = false })!)
        {
            Assert.True(nonAgent.WaitForExit(5000), "a non-agent pipe client was not refused promptly");
            Assert.Equal(0, nonAgent.ExitCode); // 1 means it received a response; 0 means the pipe rejected it
        }
        _app = Application.Attach(_agent.Id);
        var lockWin = Window("LockScreen");
        var desk = _rig.Ui.GetDesktop().BoundingRectangle;
        Assert.True(lockWin.BoundingRectangle.Contains(desk) || lockWin.BoundingRectangle == desk, $"lock screen {lockWin.BoundingRectangle} does not cover the screen {desk}");

        // T1.1 escape attempts while locked
        foreach (var (name, keys) in new (string, VirtualKeyShort[])[]
        {
            ("Alt+Tab", [VirtualKeyShort.ALT, VirtualKeyShort.TAB]), ("Win", [VirtualKeyShort.LWIN]),
            ("Win+R", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_R]), ("Win+D", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_D]),
            ("Alt+F4", [VirtualKeyShort.ALT, VirtualKeyShort.F4]), ("Ctrl+Esc", [VirtualKeyShort.CONTROL, VirtualKeyShort.ESCAPE]),
            ("Alt+Esc", [VirtualKeyShort.ALT, VirtualKeyShort.ESCAPE]),
        })
        {
            Keyboard.TypeSimultaneously(keys);
            Thread.Sleep(1200);
            Assert.False(_agent.HasExited, $"{name} closed the PC program");
            Assert.True(OnTop("LockScreen"), $"{name} got past the lock screen (foreground is now '{Rig.ForegroundTitle()}')");
        }
        using (var other = Process.Start(new ProcessStartInfo("cmd.exe", "/k title Escape-attempt") { UseShellExecute = true }))
        {
            Thread.Sleep(2500);
            Assert.True(OnTop("LockScreen"), $"another window stayed in front of the lock screen ('{Rig.ForegroundTitle()}')");
            Rig.Kill(other);
        }

        // wrong PIN, then the right one
        LogIn("9000000003", "0000");
        Rig.WaitFor(() => Text(Window("LockScreen"), "Error").Length > 0, 10, "no error shown for a wrong PIN");
        LogIn("9000000003", "2222");
        var staff = await _rig.StaffToken();
        Rig.WaitFor(() => _rig.State(staff)["session"] is not null, 10, "no session on the admin PC after login");
        var session = long.Parse(_rig.State(staff)["session"]!.ToString()!);
        var played = Stopwatch.StartNew();
        Rig.WaitFor(() => Hidden("LockScreen"), 10, "lock screen did not go away after login");
        Rig.WaitFor(() => System.Text.RegularExpressions.Regex.IsMatch(Text(Window("TimerWidget"), "TimerText"), @"^\d\d:\d\d$"), 10, "timer is not counting");

        // admin lock pauses and shows the message; unlock
        await _rig.Post("/staff/lock", new { pc = "PC1", message = "Please come to the counter" }, staff);
        Rig.WaitFor(() => !Hidden("LockScreen") && Text(Window("LockScreen"), "Message") == "Please come to the counter", 10, "admin lock did not show the lock screen");
        await _rig.Post("/staff/unlock", new { pc = "PC1", message = (string?)null }, staff);
        Rig.WaitFor(() => Hidden("LockScreen"), 10, "admin unlock did not hide the lock screen");

        // customer's own lock: time keeps running; another customer cannot open it; their own PIN can
        Click("TimerWidget", "SelfLock");
        Rig.WaitFor(() => !Hidden("LockScreen") && _rig.State(staff)["selfLocked"] is System.Text.Json.JsonElement { ValueKind: System.Text.Json.JsonValueKind.True }, 10, "customer lock did not lock");
        var before = _rig.ElapsedSec(staff);
        Thread.Sleep(4000);
        Assert.True(_rig.ElapsedSec(staff) >= before + 3, "time stopped during the customer's own lock");
        LogIn("9000000002", "111111");
        Rig.WaitFor(() => Text(Window("LockScreen"), "Error").Length > 0, 10, "someone else could open a customer's lock");
        LogIn("9000000003", "2222");
        Rig.WaitFor(() => Hidden("LockScreen"), 10, "the customer's own PIN did not unlock");

        // T1.4/T1.6 admin PC goes down: the PC keeps going; a logout made offline is billed to when it happened
        _rig.StopServer();
        Thread.Sleep(6000);
        Assert.True(Hidden("LockScreen") && !_agent.HasExited, "PC locked or crashed when the admin PC went away");
        Click("TimerWidget", "Logout");
        var loggedOutAt = played.Elapsed;
        Rig.WaitFor(() => !Hidden("LockScreen"), 10, "logout while offline did not lock the screen");
        Thread.Sleep(125000); // long enough for the server to flag the queued logout for staff review
        _rig.StartServer();
        staff = await _rig.StaffToken();
        Rig.WaitFor(() => _rig.State(staff)["session"] is null, 20, "queued logout never reached the admin PC");
        var used = TimeSpan.Parse(_rig.Bill(staff, session)["used"]!.ToString()!);
        Assert.True(used >= loggedOutAt + TimeSpan.FromSeconds(123), $"billed {used}, but the server received the queued logout after at least {loggedOutAt + TimeSpan.FromSeconds(18)}");
        var review = _rig.Review(staff);
        Assert.Contains(review, item =>
            item.Contains("PC1", StringComparison.Ordinal) &&
            item.Contains("reported logout", StringComparison.Ordinal));
    }

    // ---------------- helpers ----------------

    Window? Find(string id) => _app.GetAllTopLevelWindows(_rig.Ui).FirstOrDefault(w => w.Properties.AutomationId.ValueOrDefault == id);
    Window Window(string id) { Window? w = null; Rig.WaitFor(() => (w = Find(id)) is { IsOffscreen: false }, 20, $"window {id} never appeared"); return w!; }
    bool Hidden(string id) => Find(id) is null or { IsOffscreen: true };
    bool OnTop(string id) => Find(id) is { IsOffscreen: false } w && Rig.GetForegroundWindow() == w.Properties.NativeWindowHandle.Value;
    static AutomationElement Part(AutomationElement root, string id) => root.FindFirstDescendant(c => c.ByAutomationId(id)) ?? throw new InvalidOperationException($"no {id} on screen");
    static string Text(AutomationElement root, string id) => root.FindFirstDescendant(c => c.ByAutomationId(id))?.Name ?? "";
    void Click(string window, string button) => Part(Window(window), button).AsButton().Invoke();

    void LogIn(string phone, string pin)
    {
        var w = Window("LockScreen");
        Part(w, "Phone").AsTextBox().Text = phone;
        Part(w, "Pin").AsTextBox().Text = pin;
        Part(w, "Login").AsButton().Invoke();
    }
}

[Collection("desktop")]
public sealed class OfflineLockTests
{
    [Fact]
    public async Task Staff_authenticator_unlocks_offline_and_the_sale_reaches_the_server_ledger()
    {
        using var rig = new Rig();
        var agent = rig.StartAgent();
        try
        {
            using var app = Application.Attach(agent.Id);
            var secret = await rig.EnrollStaffTwoStep();
            var enrolledStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
            var cacheAfterSetup = DateTime.UtcNow;
            Rig.WaitFor(() => File.Exists(rig.OfflineCacheFile)
                && File.GetLastWriteTimeUtc(rig.OfflineCacheFile) > cacheAfterSetup, 20,
                "watchdog did not refresh the enrolled staff key");
            Rig.WaitFor(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 > enrolledStep, 35,
                "authenticator did not advance to a fresh step after enrollment");
            rig.StopServer();

            Window? Find() => app.GetAllTopLevelWindows(rig.Ui).FirstOrDefault(w => w.Properties.AutomationId.ValueOrDefault == "LockScreen");
            Window LockWindow()
            {
                Window? window = null;
                Rig.WaitFor(() => (window = Find()) is { IsOffscreen: false }, 20, "lock screen never appeared");
                return window!;
            }
            static AutomationElement Part(AutomationElement root, string id) =>
                root.FindFirstDescendant(c => c.ByAutomationId(id)) ?? throw new InvalidOperationException($"no {id} on screen");
            var lockScreen = LockWindow();
            Rig.WaitFor(() => !Part(LockWindow(), "StaffUnlock").IsOffscreen, 15, "offline staff unlock button did not appear");
            Part(lockScreen, "StaffUnlock").AsButton().Invoke();
            var code = Rig.AppCode(secret);
            Part(lockScreen, "StaffPhone").AsTextBox().Text = "9000000002";
            Part(lockScreen, "StaffCode").AsTextBox().Text = code;
            Part(lockScreen, "Minutes").AsTextBox().Text = "30";
            Part(lockScreen, "OfflineUnlockSubmit").AsButton().Invoke();
            Rig.WaitFor(() => Find() is null or { IsOffscreen: true }, 15, "offline staff unlock did not hide the lock screen");

            Window? timer = null;
            Rig.WaitFor(() => (timer = app.GetAllTopLevelWindows(rig.Ui).FirstOrDefault(w => w.Properties.AutomationId.ValueOrDefault == "TimerWidget")) is { IsOffscreen: false },
                15, "offline timer did not appear");
            Part(timer!, "SelfLock").AsButton().Invoke();
            var lockedAgain = LockWindow();
            Rig.WaitFor(() => !Part(lockedAgain, "StaffUnlock").IsOffscreen, 10, "offline staff unlock button did not return");
            Part(lockedAgain, "StaffUnlock").AsButton().Invoke();
            Part(lockedAgain, "StaffPhone").AsTextBox().Text = "9000000002";
            Part(lockedAgain, "StaffCode").AsTextBox().Text = code;
            Part(lockedAgain, "Minutes").AsTextBox().Text = "30";
            Part(lockedAgain, "OfflineUnlockSubmit").AsButton().Invoke();
            Rig.WaitFor(() => Part(lockedAgain, "Error").Name.Contains("Wrong phone number or code", StringComparison.OrdinalIgnoreCase),
                10, "the same authenticator step was accepted twice on one PC");

            rig.StartServer();
            var staff = await rig.OwnerToken();
            long? session = null;
            Rig.WaitFor(() => (session = rig.State(staff)["session"] is { } value && value.ToString() != "null"
                ? long.Parse(value.ToString()!) : null) is not null, 60, "offline sale was not reconciled to a server session");
            var bill = rig.Bill(staff, session!.Value);
            Assert.Equal(4000L, long.Parse(bill["paid"]!.ToString()!));
        }
        finally { Rig.Kill(agent); }
    }

    [Fact]
    public async Task Offline_unlock_refuses_a_stale_refresh_and_a_PC_clock_before_the_server_time()
    {
        using var rig = new Rig();
        var agent = rig.StartAgent();
        try
        {
            using var app = Application.Attach(agent.Id);
            var secret = await rig.EnrollStaffTwoStep();
            var cacheAfterSetup = DateTime.UtcNow;
            Rig.WaitFor(() => File.Exists(rig.OfflineCacheFile)
                && File.GetLastWriteTimeUtc(rig.OfflineCacheFile) > cacheAfterSetup, 20,
                "watchdog did not refresh the offline unlock cache");
            rig.StopServer();

            Window? Find() => app.GetAllTopLevelWindows(rig.Ui).FirstOrDefault(w => w.Properties.AutomationId.ValueOrDefault == "LockScreen");
            Window LockWindow()
            {
                Window? window = null;
                Rig.WaitFor(() => (window = Find()) is { IsOffscreen: false }, 20, "lock screen never appeared");
                return window!;
            }
            static AutomationElement Part(AutomationElement root, string id) =>
                root.FindFirstDescendant(c => c.ByAutomationId(id)) ?? throw new InvalidOperationException($"no {id} on screen");
            var screen = LockWindow();
            Rig.WaitFor(() => !Part(LockWindow(), "StaffUnlock").IsOffscreen, 15, "offline staff unlock button did not appear");
            Part(screen, "StaffUnlock").AsButton().Invoke();

            async Task TryAndExpect(string expected)
            {
                Part(screen, "StaffPhone").AsTextBox().Text = "9000000002";
                Part(screen, "StaffCode").AsTextBox().Text = Rig.AppCode(secret);
                Part(screen, "Minutes").AsTextBox().Text = "30";
                Part(screen, "OfflineUnlockSubmit").AsButton().Invoke();
                Rig.WaitFor(() => Part(screen, "Error").Name.Contains(expected, StringComparison.OrdinalIgnoreCase),
                    10, "offline unlock did not refuse: " + expected);
            }

            rig.SetOfflineRefresh(DateTime.UtcNow.AddDays(-8));
            await TryAndExpect("this PC has not reached the counter for 7 days");
            rig.SetOfflineRefresh(DateTime.UtcNow.AddMinutes(1));
            await TryAndExpect("PC clock is earlier than its last counter refresh");
        }
        finally { Rig.Kill(agent); }
    }

    [Fact]
    public async Task Three_wrong_offline_codes_pause_unlock_for_ten_minutes()
    {
        using var rig = new Rig();
        var agent = rig.StartAgent();
        try
        {
            using var app = Application.Attach(agent.Id);
            var secret = await rig.EnrollStaffTwoStep();
            var cacheAfterSetup = DateTime.UtcNow;
            Rig.WaitFor(() => File.Exists(rig.OfflineCacheFile)
                && File.GetLastWriteTimeUtc(rig.OfflineCacheFile) > cacheAfterSetup, 20, "watchdog did not cache staff keys");
            rig.StopServer();
            Window? Find() => app.GetAllTopLevelWindows(rig.Ui).FirstOrDefault(w => w.Properties.AutomationId.ValueOrDefault == "LockScreen");
            Window LockWindow()
            {
                Window? window = null;
                Rig.WaitFor(() => (window = Find()) is { IsOffscreen: false }, 20, "lock screen never appeared");
                return window!;
            }
            static AutomationElement Part(AutomationElement root, string id) =>
                root.FindFirstDescendant(c => c.ByAutomationId(id)) ?? throw new InvalidOperationException($"no {id} on screen");
            var screen = LockWindow();
            Rig.WaitFor(() => !Part(LockWindow(), "StaffUnlock").IsOffscreen, 15, "offline staff unlock button did not appear");
            Part(screen, "StaffUnlock").AsButton().Invoke();
            var valid = Rig.AppCode(secret);
            var wrong = valid == "000000" ? "000001" : "000000";
            for (var i = 0; i < 3; i++)
            {
                Part(screen, "StaffPhone").AsTextBox().Text = "9000000002";
                Part(screen, "StaffCode").AsTextBox().Text = wrong;
                Part(screen, "Minutes").AsTextBox().Text = "30";
                Part(screen, "OfflineUnlockSubmit").AsButton().Invoke();
                var expected = i == 2 ? "10 minutes" : "Wrong phone number or code";
                Rig.WaitFor(() => Part(screen, "Error").Name.Contains(expected, StringComparison.OrdinalIgnoreCase),
                    10, "wrong offline code was not rejected");
            }
            Rig.WaitFor(() => Part(screen, "Error").Name.Contains("10 minutes", StringComparison.OrdinalIgnoreCase), 10,
                "third wrong code did not pause offline unlock for ten minutes");
        }
        finally { Rig.Kill(agent); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Offline_time_limit_locks_only_when_the_last_owner_setting_is_on(bool enabled)
    {
        using var rig = new Rig(offlineLockTest: true);
        var agent = rig.StartAgent();
        try
        {
            using var app = Application.Attach(agent.Id);
            var owner = await rig.OwnerToken();
            await rig.Post("/staff/settings/time-lock", new { enabled }, owner);

            Window? Find() => app.GetAllTopLevelWindows(rig.Ui).FirstOrDefault(w => w.Properties.AutomationId.ValueOrDefault == "LockScreen");
            Window LockWindow()
            {
                Window? window = null;
                Rig.WaitFor(() => (window = Find()) is { IsOffscreen: false }, 20, "lock screen never appeared");
                return window!;
            }
            static AutomationElement Part(AutomationElement root, string id) =>
                root.FindFirstDescendant(c => c.ByAutomationId(id)) ?? throw new InvalidOperationException($"no {id} on screen");

            var lockScreen = LockWindow();
            Part(lockScreen, "Phone").AsTextBox().Text = "9000000003";
            Part(lockScreen, "Pin").AsTextBox().Text = "2222";
            Part(lockScreen, "Login").AsButton().Invoke();

            var staff = await rig.StaffToken();
            Rig.WaitFor(() => rig.State(staff)["session"] is not null, 10, "customer session did not start");
            Rig.WaitFor(() => Find() is null or { IsOffscreen: true }, 10, "login did not unlock the PC");
            rig.StopServer();

            Thread.Sleep(TimeSpan.FromSeconds(70));
            Assert.Equal(enabled, Find() is { IsOffscreen: false });
            if (enabled)
                Assert.Equal("Time is up. Please ask at the counter.", Part(Find()!, "Message").Name);
        }
        finally { Rig.Kill(agent); }
    }
}

// T1.2: a customer kills the PC program; the SYSTEM watchdog service brings it back.
[Collection("desktop")]
public sealed class WatchdogTests : IDisposable
{
    readonly Rig _rig = new();
    readonly string _exe = Rig.Env("CAFE_WATCHDOG_EXE");

    public void Dispose()
    {
        Sc("stop CafeWatchdog"); Thread.Sleep(1500); Sc("delete CafeWatchdog");
        foreach (var p in Process.GetProcessesByName("Cafe.Agent")) Rig.Kill(p);
        _rig.Dispose();
    }

    [Fact]
    public void Missing_key_keeps_the_lock_screen_running()
    {
        var args = Path.Combine(Path.GetDirectoryName(_exe)!, "watchdog.args");
        var backup = _rig.TokenFile + ".missing-test-backup";
        try
        {
            Sc("stop CafeWatchdog"); Sc("delete CafeWatchdog");
            File.WriteAllText(args, $"\"{Rig.Env("CAFE_AGENT_EXE")}\" {_rig.AgentArgs} --pipe-sid {WindowsIdentity.GetCurrent().User!.Value}");
            foreach (var dir in new[] { Path.GetDirectoryName(_exe)!, Path.GetDirectoryName(Rig.Env("CAFE_AGENT_EXE"))! })
            {
                Grant(dir, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX");
                Grant(dir, "/remove:g", "*S-1-5-11", "*S-1-1-0", "*S-1-5-4");
                Grant(Path.Combine(dir, "*"), "/reset", "/T");
            }
            File.Move(_rig.TokenFile, backup);
            Assert.Equal(0, Sc($"create CafeWatchdog binPath= \"{_exe}\" start= demand"));
            Assert.Equal(0, Sc("start CafeWatchdog"));
            Process? agent = null;
            Rig.WaitFor(() => (agent = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault()) is not null, 20,
                "watchdog did not start Cafe.Agent when the PC token was missing");
            var app = Application.Attach(agent!.Id);
            Rig.WaitFor(() => app.GetAllTopLevelWindows(_rig.Ui).Any(w =>
                w.Properties.AutomationId.ValueOrDefault == "LockScreen" && !w.IsOffscreen),
                15, "lock screen did not remain visible without the PC token");
            var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "logs");
            var log = Directory.GetFiles(logs, "watchdog-*").Select(File.ReadAllText).LastOrDefault() ?? "";
            Assert.Contains("PC pipe proxy start failed", log);
            Assert.Contains("retrying in 30 seconds", log);
        }
        finally
        {
            Sc("stop CafeWatchdog"); Thread.Sleep(1000); Sc("delete CafeWatchdog");
            foreach (var p in Process.GetProcessesByName("Cafe.Agent")) Rig.Kill(p);
            if (File.Exists(backup)) File.Move(backup, _rig.TokenFile, true);
        }
    }

    [Fact]
    public void T1_2_killed_pc_program_is_back_within_5_seconds_and_locked()
    {
        try
        {
            var args = Path.Combine(Path.GetDirectoryName(_exe)!, "watchdog.args");
            File.WriteAllText(args, $"\"{Rig.Env("CAFE_AGENT_EXE")}\" {_rig.AgentArgs} --pipe-sid {WindowsIdentity.GetCurrent().User!.Value}");
            Assert.Equal(0, Sc($"create CafeWatchdog binPath= \"{_exe}\" start= demand"));
            // a careless install (settings file writable by customers): the watchdog must refuse to run anything
            Grant(args, "*S-1-5-32-545:(M)");
            Assert.Equal(0, Sc("start CafeWatchdog"));
            Thread.Sleep(4000);
            Assert.Empty(Process.GetProcessesByName("Cafe.Agent"));
            Sc("stop CafeWatchdog"); Thread.Sleep(2000);
            // a proper install: admins change, everyone else may only read and run
            foreach (var dir in new[] { Path.GetDirectoryName(_exe)!, Path.GetDirectoryName(Rig.Env("CAFE_AGENT_EXE"))! })
            {
                Grant(dir, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX");
                Grant(dir, "/remove:g", "*S-1-5-11", "*S-1-1-0", "*S-1-5-4"); // Windows 11 gives new folders their own "Authenticated Users: Modify"
                Grant(Path.Combine(dir, "*"), "/reset", "/T"); // files take the folder's permissions (a /T grant strips their access)
            }
            Assert.Equal(0, Sc("start CafeWatchdog"));
            Process? first = null;
            Rig.WaitFor(() => (first = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault()) is not null, 20, "watchdog never started the PC program");
            Thread.Sleep(3000);
            first!.Kill(); // what a customer would do with Task Manager
            var gone = Stopwatch.StartNew();
            Process? back = null;
            Rig.WaitFor(() => (back = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault(p => p.Id != first.Id)) is not null, 10, "PC program was not restarted");
            Assert.True(gone.Elapsed < TimeSpan.FromSeconds(5), $"restart took {gone.Elapsed.TotalSeconds:F1} s (limit 5 s)");
            // a fake "Cafe.Agent" (a renamed copy of cmd.exe) must not fool the watchdog
            var fake = Path.Combine(_rig.Data, "Cafe.Agent.exe");
            File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), fake);
            using var decoy = Process.Start(new ProcessStartInfo(fake, "/k") { UseShellExecute = false, CreateNoWindow = true })!;
            back!.Kill();
            var gone2 = Stopwatch.StartNew();
            Process? back2 = null;
            Rig.WaitFor(() => (back2 = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault(p => p.Id != back.Id && p.Id != decoy.Id)) is not null, 10, "a renamed fake program fooled the watchdog");
            Assert.True(gone2.Elapsed < TimeSpan.FromSeconds(5), $"restart next to a fake took {gone2.Elapsed.TotalSeconds:F1} s");
            Rig.Kill(decoy);
            var app = Application.Attach(back2!.Id);
            Rig.WaitFor(() => app.GetAllTopLevelWindows(_rig.Ui).Any(w => w.Properties.AutomationId.ValueOrDefault == "LockScreen" && !w.IsOffscreen), 15, "restarted PC program does not show the lock screen");
        }
        catch
        {
            Rig.Screenshot();
            var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "logs");
            if (Directory.Exists(logs)) foreach (var f in Directory.GetFiles(logs, "watchdog-*")) Console.WriteLine($"--- {f}\n{File.ReadAllText(f)}");
            throw;
        }
    }

    static void Grant(string target, params string[] args)
    {
        var all = args.Length == 1 ? new[] { "/grant", args[0] } : args;
        using var p = Process.Start(new ProcessStartInfo("icacls.exe", $"\"{target}\" {string.Join(' ', all)}") { UseShellExecute = false, RedirectStandardOutput = true })!;
        p.WaitForExit(30000);
        Assert.Equal(0, p.ExitCode);
    }

    static int Sc(string args)
    {
        using var p = Process.Start(new ProcessStartInfo("sc.exe", args) { UseShellExecute = false, RedirectStandardOutput = true })!;
        p.WaitForExit(15000);
        return p.ExitCode;
    }
}

// PIN guessing from the network: after 10 tries in a minute from one address, the server stops answering logins.
[Collection("desktop")]
public sealed class ServerApiTests : IDisposable
{
    readonly Rig _rig = new();
    public void Dispose() => _rig.Dispose();

    [Fact]
    public async Task A_customer_PIN_does_not_open_the_counter_pages()
    {
        Assert.Equal(400, await _rig.TryStaffLogin("9000000003", "2222"));
        Assert.Equal(200, await _rig.TryStaffLogin("9000000002", "111111"));
    }

    [Fact]
    public async Task Login_guessing_is_cut_off_after_10_tries_a_minute()
    {
        var codes = new List<int>();
        for (var i = 0; i < 12; i++) codes.Add(await _rig.TryStaffLogin("9000000009", $"{i:000000}"));
        Assert.All(codes.Take(10), c => Assert.Equal(400, c)); // wrong phone or PIN
        Assert.All(codes.Skip(10), c => Assert.Equal(429, c)); // too many requests
    }

    [Fact]
    public async Task Staff_and_owner_get_expected_BitLocker_warning()
    {
        var staff = await _rig.StaffToken();
        var owner = await _rig.OwnerToken();
        var ct = TestContext.Current.CancellationToken;

        using (var response = _rig.Raw(HttpMethod.Get, "/staff/security/bitlocker", staff))
        {
            Assert.Equal(200, (int)response.StatusCode);
            using var json = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            Assert.Equal(System.Text.Json.JsonValueKind.Null, json.RootElement.GetProperty("warning").ValueKind);
        }

        using (var response = _rig.Raw(HttpMethod.Get, "/staff/security/bitlocker", owner))
        {
            Assert.Equal(200, (int)response.StatusCode);
            using var json = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            Assert.NotEqual(System.Text.Json.JsonValueKind.Null, json.RootElement.GetProperty("warning").ValueKind);
        }
    }

    [Fact]
    public async Task Owner_sets_offers_and_happy_hours_and_staff_put_an_offer_on_a_bill()
    {
        var owner = await _rig.OwnerToken();
        var staff = await _rig.StaffToken();
        await _rig.Post("/staff/rate-cards", new { name = "Happy", rate = new { paise30 = 2000, paise60 = 3000, paise90 = 5000, extraBlockPaise = 2000,
            graceMin = 5, minimumMin = 30, blockMin = 30, blockGraceMin = 5, carryOverDays = 7, carryOverMembersOnly = true } }, owner);
        await _rig.Post("/staff/happy-hours", new { card = "Happy", days = new[] { 6 }, fromMin = 0, toMin = 1, membersOnly = true }, owner);
        await _rig.Post("/staff/offers", new { name = "Diwali", percent = 20, membersOnly = false }, owner);
        await _rig.Post("/staff/sessions", new { pc = "PC1", phone = "9000000003", mode = "prepaid", minutes = 30 }, staff);
        var session = long.Parse(_rig.State(staff)["session"]!.ToString()!);
        await _rig.Post($"/staff/sessions/{session}/offer", new { name = "Diwali" }, staff);
        Assert.Equal("3200", _rig.Bill(staff, session)["due"]!.ToString()); // Rs 40 less 20%
        using var offers = _rig.Raw(HttpMethod.Get, "/staff/offers", staff);
        Assert.Contains("\"card\":\"Happy\"", await offers.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Owner_keeps_item_lists_and_staff_sell_items_on_a_bill_and_at_the_counter()
    {
        var owner = await _rig.OwnerToken();
        var staff = await _rig.StaffToken();
        var ct = TestContext.Current.CancellationToken;
        await _rig.Post("/staff/items", new { category = "Beverages", name = "Coke", price = 5000 }, owner);
        using (var byStaff = new HttpRequestMessage(HttpMethod.Post, "/staff/items") { Content = JsonContent.Create(new { category = "Beverages", name = "Tea", price = 1 }) })
        {
            byStaff.Headers.Authorization = new("Bearer", staff);
            Assert.Equal(400, (int)(await _rig.Http.SendAsync(byStaff, ct)).StatusCode); // only the owner sets prices
        }
        using var list = _rig.Raw(HttpMethod.Get, "/staff/items", staff);
        var coke = System.Text.Json.JsonDocument.Parse(await list.Content.ReadAsStringAsync(ct)).RootElement.GetProperty("items")[0].GetProperty("id").GetInt64();
        await _rig.Post("/staff/offers", new { name = "Half drinks", percent = 50, membersOnly = false, scope = new[] { "List: Beverages" } }, owner);
        await _rig.Post("/staff/sessions", new { pc = "PC1", phone = "9000000003", mode = "prepaid", minutes = 30 }, staff);
        var session = long.Parse(_rig.State(staff)["session"]!.ToString()!);
        await _rig.Post($"/staff/sessions/{session}/offer", new { name = "Half drinks" }, staff);
        await _rig.Post($"/staff/sessions/{session}/items", new { item = coke, qty = 2, note = "cold" }, staff);
        Assert.Equal("9000", _rig.Bill(staff, session)["due"]!.ToString()); // Rs 40 of time + Rs 100 of drinks, half off the drinks
        Assert.Contains("2 x Coke (cold)", _rig.Bill(staff, session)["lines"]!.ToString());
        await _rig.Post("/staff/counter-sales", new { item = coke, qty = 1, method = "cash" }, staff);
        var today = DateTime.UtcNow.AddHours(5.5).ToString("yyyy-MM-dd");
        using (var report = _rig.Raw(HttpMethod.Get, $"/staff/reports/items?from={today}&to={today}", owner))
            Assert.Contains("\"qty\":3", await report.Content.ReadAsStringAsync(ct));
        using (var notStaff = _rig.Raw(HttpMethod.Get, $"/staff/reports/items?from={today}&to={today}", staff)) Assert.Equal(400, (int)notStaff.StatusCode);
    }

    [Fact]
    public async Task Owner_sets_a_membership_plan_and_staff_sell_it_at_the_counter()
    {
        var owner = await _rig.OwnerToken();
        var staff = await _rig.StaffToken();
        await _rig.Post("/staff/membership-plans", new { name = "Monthly", days = 30, price = 50000 }, owner);
        using var byStaff = new HttpRequestMessage(HttpMethod.Post, "/staff/membership-plans") { Content = JsonContent.Create(new { name = "Cheap", days = 30, price = 100 }) };
        byStaff.Headers.Authorization = new("Bearer", staff);
        Assert.Equal(400, (int)(await _rig.Http.SendAsync(byStaff, TestContext.Current.CancellationToken)).StatusCode); // only the owner sets plans
        await _rig.Post("/staff/memberships", new { phone = "9000000003", plan = "Monthly", method = "cash" }, staff);
        using var who = _rig.Raw(HttpMethod.Get, "/staff/customers/9000000003", staff);
        Assert.Contains("\"plan\":\"Monthly\"", await who.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Counter_screen_page_is_locked_down_and_its_actions_work_for_staff_only()
    {
        using var page = _rig.Raw(HttpMethod.Get, "/staff/", null);
        Assert.Equal(200, (int)page.StatusCode);
        Assert.Contains("frame-ancestors 'none'", string.Join(" ", page.Headers.GetValues("Content-Security-Policy")));
        Assert.Contains("/staff/counter.js", await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        using (var script = _rig.Raw(HttpMethod.Get, "/staff/counter.js", null)) Assert.Contains("textContent", await script.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        using (var noLogin = _rig.Raw(HttpMethod.Get, "/staff/counter", null)) Assert.Equal(401, (int)noLogin.StatusCode); // the page has no data without a login

        var staff = await _rig.StaffToken();
        using (var who = _rig.Raw(HttpMethod.Get, "/staff/customers/9000000003", staff)) Assert.Contains("Test Customer", await who.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        await _rig.Post("/staff/sessions", new { pc = "PC1", phone = "9000000003", mode = "prepaid", minutes = 30 }, staff);
        var session = long.Parse(_rig.State(staff)["session"]!.ToString()!);
        using (var counter = _rig.Raw(HttpMethod.Get, "/staff/counter", staff))
        {
            var text = await counter.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Contains("\"customer\":\"Test Customer\"", text);
            Assert.Contains("\"toPay\":4000", text); // 30 min paid in advance: Rs 40 owed until paid
        }
        await _rig.Post($"/staff/sessions/{session}/time", new { minutes = 30 }, staff);
        await _rig.Post($"/staff/sessions/{session}/pay", new { method = "cash", amount = 8000 }, staff);
        await _rig.Post("/staff/lock", new { pc = "PC1" }, staff); // locking pauses the time
        Assert.Equal("True", _rig.State(staff)["locked"]!.ToString());
        await _rig.Post("/staff/unlock", new { pc = "PC1" }, staff);
        using (var gone = _rig.Raw(HttpMethod.Post, $"/staff/sessions/{session}/pause", staff)) Assert.Equal(404, (int)gone.StatusCode); // no pause without a lock
        await _rig.Post($"/staff/sessions/{session}/stop", new { }, staff);
        Assert.Equal("0", _rig.Bill(staff, session)["due"]!.ToString());
        Assert.Null(_rig.State(staff)["session"]);
        using (var cards = _rig.Raw(HttpMethod.Get, "/staff/rate-cards", staff)) Assert.Contains("\"name\":\"Standard\"", await cards.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        using var save = new HttpRequestMessage(HttpMethod.Post, "/staff/rate-cards") { Content = JsonContent.Create(new { name = "Cheap", rate = new { paise30 = 100, paise60 = 200, paise90 = 300, extraBlockPaise = 100, graceMin = 5, minimumMin = 30, blockMin = 30, blockGraceMin = 5, carryOverDays = 7 } }) };
        save.Headers.Authorization = new("Bearer", staff);
        Assert.Equal(400, (int)(await _rig.Http.SendAsync(save, TestContext.Current.CancellationToken)).StatusCode); // only the owner changes prices
    }
}

// Starts the real admin server on a temp data folder; HTTPS with the server's pinned certificate, like a gaming PC.
sealed class Rig : IDisposable
{
    const string Url = "https://127.0.0.1:5443";
    public readonly string Data = Path.Combine(Path.GetTempPath(), $"cafe-ui-{Guid.NewGuid():N}");
    readonly string _pcDir = Path.Combine(Path.GetTempPath(), $"cafe-pc-{Guid.NewGuid():N}"); // what a gaming PC holds: its token + the server's pin
    public readonly UIA3Automation Ui = new();
    readonly System.Text.StringBuilder _serverLog = new();
    Process? _server;
    Process? _watchdogProxy;
    HttpClient _http = null!;

    public Rig(bool offlineLockTest = false) => StartServer(offlineLockTest);
    public string TokenFile => Path.Combine(_pcDir, "pc.token");
    public string OfflineCacheFile => Path.Combine(_pcDir, "offline-unlock.bin");
    public string AgentArgs => $"--server {Url} --token-file \"{TokenFile}\" --pin-file \"{Path.Combine(_pcDir, "server.pin")}\" --name \"Test Cafe\" --logs \"{Path.Combine(_pcDir, "logs")}\"";

    public void StartServer(bool offlineLockTest = false)
    {
        var start = new ProcessStartInfo(Env("CAFE_SERVER_EXE"))
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var a in new[] { "--data", Data, "--seed-test", "--port", "5443" }) start.ArgumentList.Add(a);
        if (offlineLockTest) start.ArgumentList.Add("--seed-offline-lock");
        _server = new Process { StartInfo = start };
        _server.OutputDataReceived += (_, e) => { lock (_serverLog) _serverLog.AppendLine(e.Data); };
        _server.ErrorDataReceived += (_, e) => { lock (_serverLog) _serverLog.AppendLine(e.Data); };
        _server.Start(); _server.BeginOutputReadLine(); _server.BeginErrorReadLine();
        WaitFor(() => File.Exists(Path.Combine(Data, "server.pin")) && Ping(), 60, "server did not start", () => _serverLog.ToString());
        Directory.CreateDirectory(_pcDir);
        File.Copy(Path.Combine(Data, "pc1.token"), Path.Combine(_pcDir, "pc.token"), true);
        File.Copy(Path.Combine(Data, "server.pin"), Path.Combine(_pcDir, "server.pin"), true);
    }
    public Process StartAgent()
    {
        var sid = WindowsIdentity.GetCurrent().User!.Value;
        var proxy = new ProcessStartInfo(Env("CAFE_WATCHDOG_EXE")) { UseShellExecute = false };
        foreach (var a in new[] { "--test-proxy", "--server", Url, "--token-file", Path.Combine(_pcDir, "pc.token"),
            "--pin-file", Path.Combine(_pcDir, "server.pin"), "--pipe-sid", sid,
            "--agent-path", Env("CAFE_AGENT_EXE") }) proxy.ArgumentList.Add(a);
        proxy.RedirectStandardError = true;
        proxy.RedirectStandardOutput = true;
        _watchdogProxy = Process.Start(proxy)!;
        _watchdogProxy.ErrorDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine("watchdog proxy: " + e.Data); };
        _watchdogProxy.OutputDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine("watchdog proxy: " + e.Data); };
        _watchdogProxy.BeginErrorReadLine();
        _watchdogProxy.BeginOutputReadLine();
        Thread.Sleep(500);
        if (_watchdogProxy.HasExited) throw new InvalidOperationException("watchdog proxy exited with code " + _watchdogProxy.ExitCode);
        var agent = new ProcessStartInfo(Env("CAFE_AGENT_EXE")) { UseShellExecute = false };
        foreach (var a in new[] { "--name", "Test Cafe", "--logs", Path.Combine(_pcDir, "logs") }) agent.ArgumentList.Add(a);
        return Process.Start(agent)!;
    }

    public void StopServer() => Kill(_server);

    public void SetOfflineRefresh(DateTime serverTimeUtc)
    {
        var start = new ProcessStartInfo(Env("CAFE_WATCHDOG_EXE")) { UseShellExecute = false };
        foreach (var a in new[] { "--test-set-offline-refresh", "--test-mode", "--cache-file", OfflineCacheFile,
            "--server-time", serverTimeUtc.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture) })
            start.ArgumentList.Add(a);
        start.Environment["CAFE_TEST_MODE"] = "1";
        using var process = Process.Start(start)!;
        process.WaitForExit(15000);
        Assert.Equal(0, process.ExitCode);
    }

    public void Dispose()
    {
        Kill(_watchdogProxy); Kill(_server); Ui.Dispose(); _http.Dispose();
        foreach (var dir in new[] { Path.Combine(Data, "logs"), Path.Combine(_pcDir, "logs") }) // logs end up in the test output
            if (Directory.Exists(dir)) foreach (var f in Directory.GetFiles(dir)) Console.WriteLine($"--- {Path.GetFileName(f)}\n{File.ReadAllText(f)}");
        foreach (var dir in new[] { Data, _pcDir }) try { Directory.Delete(dir, true); } catch (IOException) { }
    }

    bool Ping()
    {
        var pin = File.ReadAllText(Path.Combine(Data, "server.pin")).Trim();
        _http?.Dispose();
        _http = new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, c, _, _) => c is not null && Convert.ToHexString(SHA256.HashData(c.RawData)) == pin }) { BaseAddress = new Uri(Url) };
        try { return _http.GetAsync("/pc/state").Result.StatusCode == System.Net.HttpStatusCode.Unauthorized; } // up, and refusing a missing token
        catch (AggregateException) { return false; }
    }

    public async Task<string> StaffToken()
    {
        var r = await _http.PostAsJsonAsync("/staff/login", new { phone = "9000000002", pin = "111111" });
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["token"];
    }
    public async Task<string> OwnerToken()
    {
        var r = await _http.PostAsJsonAsync("/staff/login", new { phone = "9000000001", pin = "432100" });
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["token"];
    }
    public async Task<string> EnrollStaffTwoStep()
    {
        var token = await OwnerToken();
        using var start = new HttpRequestMessage(HttpMethod.Post, "/staff/two-step/staff/start") { Content = JsonContent.Create(new { phone = "9000000002" }) };
        start.Headers.Authorization = new("Bearer", token);
        using var started = await _http.SendAsync(start);
        started.EnsureSuccessStatusCode();
        var secret = (await started.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["secret"];
        using var confirm = new HttpRequestMessage(HttpMethod.Post, "/staff/two-step/staff/on")
        { Content = JsonContent.Create(new { phone = "9000000002", secret, code = AppCode(secret) }) };
        confirm.Headers.Authorization = new("Bearer", token);
        using var enabled = await _http.SendAsync(confirm);
        enabled.EnsureSuccessStatusCode();

        using var offlineStart = new HttpRequestMessage(HttpMethod.Post, "/staff/two-step/offline/start")
        { Content = JsonContent.Create(new { phone = "9000000002" }) };
        offlineStart.Headers.Authorization = new("Bearer", token);
        using var offlineStarted = await _http.SendAsync(offlineStart);
        offlineStarted.EnsureSuccessStatusCode();
        var offlineSecret = (await offlineStarted.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["secret"];
        Assert.NotEqual(secret, offlineSecret);
        using var offlineConfirm = new HttpRequestMessage(HttpMethod.Post, "/staff/two-step/offline/on")
        { Content = JsonContent.Create(new { phone = "9000000002", secret = offlineSecret, code = AppCode(offlineSecret) }) };
        offlineConfirm.Headers.Authorization = new("Bearer", token);
        using var offlineEnabled = await _http.SendAsync(offlineConfirm);
        offlineEnabled.EnsureSuccessStatusCode();
        return offlineSecret;
    }
    public static string AppCode(string secret)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var key = new List<byte>(); int buffer = 0, bits = 0;
        foreach (var c in secret)
        {
            buffer = ((buffer << 5) | alphabet.IndexOf(c)) & 0xFFFF; bits += 5;
            if (bits >= 8) { key.Add((byte)(buffer >> (bits - 8))); bits -= 8; }
        }
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var message = BitConverter.GetBytes(step); if (BitConverter.IsLittleEndian) Array.Reverse(message);
        var hash = HMACSHA1.HashData(key.ToArray(), message); var offset = hash[^1] & 15;
        var binary = ((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }
    public async Task<int> TryStaffLogin(string phone, string pin) => (int)(await _http.PostAsJsonAsync("/staff/login", new { phone, pin })).StatusCode;
    public async Task Post(string path, object body, string token)
    {
        using var m = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        m.Headers.Authorization = new("Bearer", token);
        (await _http.SendAsync(m)).EnsureSuccessStatusCode();
    }
    public HttpClient Http => _http;
    public HttpResponseMessage Raw(HttpMethod method, string path, string? token)
    {
        using var m = new HttpRequestMessage(method, path);
        if (token is not null) m.Headers.Authorization = new("Bearer", token);
        return _http.Send(m);
    }
    Dictionary<string, object?> Get(string path, string token)
    {
        using var m = new HttpRequestMessage(HttpMethod.Get, path);
        m.Headers.Authorization = new("Bearer", token);
        return _http.Send(m).Content.ReadFromJsonAsync<Dictionary<string, object?>>().Result!;
    }
    public Dictionary<string, object?> State(string token) => Get("/staff/state/PC1", token);
    public Dictionary<string, object?> Bill(string token, long session) => Get($"/staff/bill/{session}", token);
    public List<string> Review(string token)
    {
        using var m = new HttpRequestMessage(HttpMethod.Get, "/staff/review");
        m.Headers.Authorization = new("Bearer", token);
        return _http.Send(m).Content.ReadFromJsonAsync<List<string>>().Result!;
    }
    public long ElapsedSec(string token) => long.Parse(State(token)["elapsedSec"]!.ToString()!);

    public static string Env(string name) => Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"set {name}");
    public static void Kill(Process? p) { try { if (p is { HasExited: false }) { p.Kill(true); p.WaitForExit(5000); } } catch (InvalidOperationException) { } }

    public static void WaitFor(Func<bool> ok, int seconds, string why, Func<string>? more = null)
    {
        var until = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < until) { try { if (ok()) return; } catch (Exception) { } Thread.Sleep(300); } // UI elements vanish mid-check; retry
        Assert.Fail(more is null ? why : $"{why}\n{more()}");
    }

    public static void Screenshot() => FlaUI.Core.Capturing.Capture.Screen().ToFile(Path.Combine(Environment.GetEnvironmentVariable("GITHUB_WORKSPACE") ?? ".", $"screen-{DateTime.Now:HHmmss}.png"));
    public static string ForegroundTitle() { var sb = new System.Text.StringBuilder(256); GetWindowText(GetForegroundWindow(), sb, 256); return sb.ToString(); }
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int max);
}