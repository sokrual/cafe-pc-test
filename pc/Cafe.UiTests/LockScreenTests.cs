using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;
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
        var escaped = new List<string>();
        foreach (var (name, keys) in new (string, VirtualKeyShort[])[]
        {
            ("Alt+Tab", [VirtualKeyShort.ALT, VirtualKeyShort.TAB]), ("Win", [VirtualKeyShort.LWIN]),
            ("Win+R", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_R]), ("Win+D", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_D]),
            ("Alt+F4", [VirtualKeyShort.ALT, VirtualKeyShort.F4]), ("Ctrl+Esc", [VirtualKeyShort.CONTROL, VirtualKeyShort.ESCAPE]),
            ("Alt+Esc", [VirtualKeyShort.ALT, VirtualKeyShort.ESCAPE]),
            // E3b, measured with no key blocker: Task Manager opened on the lock screen's desktop; Settings opened on the normal one
            ("Ctrl+Shift+Esc", [VirtualKeyShort.CONTROL, VirtualKeyShort.SHIFT, VirtualKeyShort.ESCAPE]), ("Win+U", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_U]),
        })
        {
            var running = Process.GetProcesses().Select(p => p.Id).ToHashSet();
            Keyboard.TypeSimultaneously(keys);
            Thread.Sleep(2500); // the measurement's wait: Settings and Task Manager were open by then
            var opened = Process.GetProcesses().Where(p => !running.Contains(p.Id) && p.ProcessName is "Taskmgr" or "Utilman" or "SystemSettings").ToList();
            if (opened.Count > 0) escaped.Add($"{name} opened {string.Join(", ", opened.Select(p => p.ProcessName))}");
            opened.ForEach(Rig.Kill);
            if (_agent.HasExited) escaped.Add($"{name} closed the PC program");
            else if (!OnTop("LockScreen")) escaped.Add($"{name} got past the lock screen (foreground is now '{Rig.ForegroundTitle()}')");
        }
        Assert.True(escaped.Count == 0, string.Join("\n", escaped)); // every key is tried, so one run shows each one that got through
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

    [Fact]
    public void E2_lock_screen_comes_back_after_being_minimised_and_stays_above_an_always_on_top_window()
    {
        Process? other = null;
        try
        {
            // E3b: other programs' windows are on the normal desktop. The lock screen meets them only when Windows
            // refuses its own desktop and it stays there too, so that is how this test starts it.
            _agent = _rig.StartAgent(lockOnNormalDesktop: true);
            _app = Application.Attach(_agent.Id);
            var handle = Window("LockScreen").Properties.NativeWindowHandle.Value;
            Assert.Equal("Default", Rig.InputDesktop());
            Rig.ShowWindow(handle, 6); // SW_MINIMIZE: what Show desktop (Win+D) does to every window
            Rig.WaitFor(() => !Rig.IsIconic(handle) && Rig.GetForegroundWindow() == handle, 2, "the minimised lock screen did not come back in front within 2 s",
                () => $"minimised {Rig.IsIconic(handle)}; foreground '{Rig.ForegroundTitle()}'");

            // an always-on-top window that never takes the focus (like a game overlay): only the lock screen's own
            // re-ordering puts it back in front, as the lock screen stays the focused window throughout
            other = Process.Start(new ProcessStartInfo("powershell.exe",
                "-NoProfile -Command \"Add-Type -ReferencedAssemblies System.Windows.Forms -TypeDefinition 'public class F : System.Windows.Forms.Form { protected override bool ShowWithoutActivation { get { return true; } } protected override System.Windows.Forms.CreateParams CreateParams { get { var p = base.CreateParams; p.ExStyle |= 0x08000008; return p; } } }'; $f = New-Object F; $f.Text = 'TopMost-attempt'; $f.Width = 400; $f.Height = 300; [System.Windows.Forms.Application]::Run($f)\"")
                { UseShellExecute = false, CreateNoWindow = true })!;
            var top = IntPtr.Zero;
            Rig.WaitFor(() => (top = Rig.FindWindow(null, "TopMost-attempt")) != IntPtr.Zero, 30, "the always-on-top test window never opened");
            Thread.Sleep(2000);
            // window handles only: UI Automation can time out while another program starts. Windows' own system dialogs
            // sit in a layer above every program; E3 (the lock screen on its own desktop) is for those.
            Assert.True(!Rig.Above(top, handle) && Rig.GetForegroundWindow() == handle,
                $"an always-on-top window stayed above the lock screen (test window above: {Rig.Above(top, handle)}; foreground {Rig.Describe(Rig.GetForegroundWindow())})");
            Assert.False(_agent.HasExited, "the PC program closed");
        }
        catch { Rig.Screenshot(); throw; }
        finally { Rig.Kill(other); }
    }

    [Fact]
    public async Task E3b_lock_screen_has_its_own_desktop_and_the_normal_desktop_comes_back_for_the_customer()
    {
        try
        {
            _agent = _rig.StartAgent();
            _app = Application.Attach(_agent.Id);
            Window("LockScreen"); // found on the desktop that has the screen
            var own = Rig.InputDesktop();
            Assert.StartsWith($"CafeLock-{_agent.Id}-", own);
            LogIn("9000000003", "2222");
            Rig.WaitFor(() => Rig.InputDesktop() == "Default" && Hidden("LockScreen"), 10, "login did not give the normal desktop back", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
            Window("TimerWidget"); // the timer is on the normal desktop, with the games
            var staff = await _rig.StaffToken();
            await _rig.Post("/staff/lock", new { pc = "PC1", message = "Please come to the counter" }, staff);
            Rig.WaitFor(() => Rig.InputDesktop() == own && Text(Window("LockScreen"), "Message") == "Please come to the counter", 10,
                "a lock from the counter did not give the screen to the lock screen's desktop", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
            await _rig.Post("/staff/unlock", new { pc = "PC1", message = (string?)null }, staff);
            Rig.WaitFor(() => Rig.InputDesktop() == "Default" && Hidden("LockScreen"), 10, "the counter's unlock did not give the normal desktop back", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
        }
        catch { Rig.Screenshot(); throw; }
    }

    // Windows refuses to give the normal desktop the screen while its own secure screen is up (measured on x64, run
    // 45119963759: the PC program's unlock was refused). The lock screen must ask again, or the customer is left on its
    // empty desktop while the time runs.
    [Fact]
    public void E3b_normal_desktop_comes_back_after_Windows_refused_it_at_the_unlock()
    {
        try
        {
            _agent = _rig.StartAgent(unlockRefusedOnce: true);
            _app = Application.Attach(_agent.Id);
            Window("LockScreen");
            LogIn("9000000003", "2222");
            Rig.WaitFor(() => Rig.InputDesktop() == "Default", 5, "the normal desktop did not come back after a refused unlock", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
            Window("TimerWidget"); // the customer's timer, on the normal desktop
        }
        catch { Rig.Screenshot(); throw; }
    }

    // The key blocker's thread moves to the lock screen's desktop first. If Windows then refuses the lock screen's thread,
    // the lock screen stays a window on the normal desktop, and the keys must still be blocked there.
    [Fact]
    public void E3b_keys_stay_blocked_when_Windows_refuses_the_lock_screens_thread_after_the_key_blockers()
    {
        try
        {
            _agent = _rig.StartAgent(lockThreadRefused: true);
            _app = Application.Attach(_agent.Id);
            Window("LockScreen");
            Assert.Equal("Default", Rig.InputDesktop());
            var escaped = new List<string>();
            foreach (var (name, keys) in new (string, VirtualKeyShort[])[]
            {
                ("Alt+Tab", [VirtualKeyShort.ALT, VirtualKeyShort.TAB]),
                ("Ctrl+Shift+Esc", [VirtualKeyShort.CONTROL, VirtualKeyShort.SHIFT, VirtualKeyShort.ESCAPE]),
            })
            {
                var running = Process.GetProcesses().Select(p => p.Id).ToHashSet();
                Keyboard.TypeSimultaneously(keys);
                Thread.Sleep(2500);
                var opened = Process.GetProcesses().Where(p => !running.Contains(p.Id) && p.ProcessName is "Taskmgr").ToList();
                if (opened.Count > 0) escaped.Add($"{name} opened Task Manager");
                opened.ForEach(Rig.Kill);
                if (!OnTop("LockScreen")) escaped.Add($"{name} got past the lock screen (foreground is now '{Rig.ForegroundTitle()}')");
            }
            Assert.True(escaped.Count == 0, string.Join("\n", escaped));
        }
        catch { Rig.Screenshot(); throw; }
    }

    // Windows hands back a desktop that already has the asked name, with its maker's rights, and does not say so (measured,
    // run 45110576185). So no other program may be able to make the lock screen's desktop first: here one made
    // "CafeLock-<process number>", the name the lock screen used before its name got a random part.
    [Fact]
    public void E3b_lock_screen_desktop_has_the_lock_screens_rights_when_another_program_made_one_for_its_process_number()
    {
        var taken = IntPtr.Zero;
        try
        {
            _agent = _rig.StartAgent();
            Rig.Pause(_agent, true);
            Assert.DoesNotContain(Rig.Desktops(), d => d.StartsWith($"CafeLock-{_agent.Id}")); // paused before it made its desktop
            taken = Rig.MakeDesktop($"CafeLock-{_agent.Id}");
            Assert.NotEqual(IntPtr.Zero, taken);
            Rig.Pause(_agent, false);
            Rig.WaitFor(() => Rig.InputDesktop().StartsWith($"CafeLock-{_agent.Id}"), 20, "the lock screen's desktop never had the screen", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
            // Windows itself and admins everything, the maker "read the rights" only; nothing for the sign-in the customer's programs share
            Assert.Equal("D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RC;;;OW)", Rig.InputDesktopRights());
        }
        catch { Rig.Screenshot(); throw; }
        finally { if (taken != IntPtr.Zero) Rig.CloseTaken(taken); }
    }

    [Fact]
    public void E3b_lock_screen_takes_the_screen_back_within_1_second_when_another_program_gives_it_to_the_normal_desktop()
    {
        try
        {
            _agent = _rig.StartAgent();
            _app = Application.Attach(_agent.Id);
            Window("LockScreen");
            var own = Rig.InputDesktop();
            Assert.StartsWith($"CafeLock-{_agent.Id}-", own);
            for (var round = 1; round <= 5; round++)
            {
                Thread.Sleep(600 + round * 130); // a different moment of the lock screen's 0.5 s timer each round
                Assert.True(Rig.SwitchToNormalDesktop(), $"round {round}: the test could not give the screen to the normal desktop");
                var since = Stopwatch.StartNew();
                while (Rig.InputDesktop() != own && since.ElapsedMilliseconds < 1000) Thread.Sleep(10);
                Assert.True(Rig.InputDesktop() == own, $"round {round}: the lock screen did not have the screen again within 1 s (the screen shows desktop '{Rig.InputDesktop()}')");
            }
            LogIn("9000000003", "2222"); // the lock screen still works after that
            Rig.WaitFor(() => Rig.InputDesktop() == "Default" && Hidden("LockScreen"), 10, "login did not give the normal desktop back", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
            Thread.Sleep(1500); // three turns of the timer: it must leave an unlocked PC's screen alone
            Assert.Equal("Default", Rig.InputDesktop());
        }
        catch { Rig.Screenshot(); throw; }
    }

    [Fact]
    public async Task E2_a_membership_ending_soon_shows_on_the_customers_timer()
    {
        try
        {
            var owner = await _rig.OwnerToken();
            await _rig.Post("/staff/membership-plans", new { name = "Day pass", days = 1, price = 5000 }, owner);
            await _rig.Post("/staff/memberships", new { phone = "9000000003", plan = "Day pass", method = "cash" }, await _rig.StaffToken());
            _agent = _rig.StartAgent();
            _app = Application.Attach(_agent.Id);
            LogIn("9000000003", "2222");
            Rig.WaitFor(() => Hidden("LockScreen"), 10, "lock screen did not go away after login");
            Rig.WaitFor(() => Text(Window("TimerWidget"), "Notice").StartsWith("Your Day pass membership ends on ", StringComparison.Ordinal), 15,
                "the membership notice did not show on the timer", () => $"notice '{Text(Window("TimerWidget"), "Notice")}'");
        }
        catch { Rig.Screenshot(); throw; }
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
            // E2: the owner uses 15-minute blocks; the offline rate card text and the price must follow
            var owner = await rig.OwnerToken();
            await rig.Post("/staff/rate-cards", new { name = "Quarter hours", rate = new { paise30 = 4000, paise60 = 6000, paise90 = 10000, extraBlockPaise = 4000,
                graceMin = 5, minimumMin = 15, blockMin = 15, blockGraceMin = 5, carryOverDays = 7, carryOverMembersOnly = true } }, owner);
            await rig.Post("/staff/rate-cards/use", new { name = "Quarter hours" }, owner);
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
            Rig.WaitFor(() => Part(lockScreen, "OfflineRate").Name.StartsWith("Rate card: 15 min ₹40, 30 min ₹60, 45 min ₹100; then ₹40 per 15 min.", StringComparison.Ordinal),
                10, "the offline rate card text does not follow the owner's block length", () => Part(lockScreen, "OfflineRate").Name);
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
            Assert.Equal(6000L, long.Parse(bill["paid"]!.ToString()!)); // 30 min = two 15-minute blocks
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
        const string oldProfileSetting = @"Software\GamingCafe\Agent";
        Registry.CurrentUser.DeleteSubKeyTree(oldProfileSetting, false);
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
            Rig.WaitFor(() => File.Exists(rig.TimeLockSettingFile)
                && System.Text.Json.JsonDocument.Parse(File.ReadAllText(rig.TimeLockSettingFile)).RootElement.GetProperty("lockWhenTimeRunsOut").GetBoolean() == enabled,
                10, "watchdog did not retain the last server-supplied time-lock setting");
            using (var restoredHive = Registry.CurrentUser.CreateSubKey(oldProfileSetting))
                restoredHive!.SetValue("LockWhenTimeRunsOut", enabled ? 0 : 1, RegistryValueKind.DWord); // stale install-time hive value
            rig.StopServer();

            Thread.Sleep(TimeSpan.FromSeconds(70));
            Assert.Equal(enabled, Find() is { IsOffscreen: false });
            if (enabled)
                Assert.Equal("Time is up. Please ask at the counter.", Part(Find()!, "Message").Name);
        }
        finally
        {
            Rig.Kill(agent);
            Registry.CurrentUser.DeleteSubKeyTree(oldProfileSetting, false);
        }
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
        Rig.ToNormalDesktop();
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
            Rig.ToNormalDesktop();
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
            // E3b: a killed program's desktop goes, and the screen goes to the normal desktop (measured: within 0.3 s).
            // The restarted program must make its own desktop and give it the screen.
            Rig.WaitFor(() => Rig.InputDesktop().StartsWith($"CafeLock-{back!.Id}-"), 15, "the restarted PC program's lock screen desktop does not have the screen",
                () => $"the screen shows desktop '{Rig.InputDesktop()}'");
            TestContext.Current.TestOutputHelper?.WriteLine($"T1.2: {gone.Elapsed.TotalSeconds:F1} s from the kill until the new lock screen desktop had the screen (checked every 0.3 s)");
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

    // The watchdog starts the PC program again when it ends, not at its next look up to a second later.
    // Measured: 1.0 s from a kill until the new lock screen covered the screen before, 0.17 s (x64) and 0.31 s (ARM) now.
    // 10 kills; the middle value counts. A program killed within a second of its start still waits out that second.
    [Fact]
    public void E3b_lock_screen_covers_again_within_half_a_second_of_a_kill()
    {
        try
        {
            StartWatchdog();
            string Mine(int pid) => $"CafeLock-{pid}-";
            var covered = new List<double>();
            var lines = new List<string>();
            for (var round = 1; round <= 10; round++)
            {
                Process? agent = null;
                Rig.WaitFor(() => (agent = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault(p => Rig.InputDesktop().StartsWith(Mine(p.Id)))) is not null, 20,
                    $"round {round}: no PC program's lock screen desktop has the screen", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
                Thread.Sleep(2000); // a program that has been running for a while, as on a cafe PC
                agent!.Kill();
                var t = Stopwatch.StartNew();
                double? open = null;
                string desktop;
                while (!((desktop = Rig.InputDesktop()).StartsWith("CafeLock-") && !desktop.StartsWith(Mine(agent.Id))) && t.Elapsed < TimeSpan.FromSeconds(20))
                {
                    if (desktop == "Default") open ??= t.Elapsed.TotalSeconds;
                    Thread.Sleep(10);
                }
                covered.Add(t.Elapsed.TotalSeconds);
                lines.Add($"round {round}: covered again after {covered[^1]:F2} s; the normal desktop had the screen {(open is null ? "at no look" : $"from {open:F2} s, so for {covered[^1] - open:F2} s")}");
            }
            var sorted = covered.Order().ToList();
            var middle = (sorted[4] + sorted[5]) / 2;
            TestContext.Current.TestOutputHelper?.WriteLine($"KILLGAP seconds from a kill until a new lock screen desktop had the screen: min {sorted[0]:F2}, middle {middle:F2}, max {sorted[9]:F2}\n" + string.Join("\n", lines));
            Assert.True(middle < 0.5, $"the middle of 10 kills was {middle:F2} s (limit 0.5 s): {string.Join(", ", covered.Select(c => c.ToString("F2")))}");
        }
        catch
        {
            Rig.Screenshot();
            var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "logs");
            if (Directory.Exists(logs)) foreach (var f in Directory.GetFiles(logs, "watchdog-*")) Console.WriteLine($"--- {f}\n{File.ReadAllText(f)}");
            throw;
        }
    }

    // the watchdog as installed: a service running the PC program from folders only admins can change. Its pipe to the PC
    // program needs the PC key protected for this machine, as INSTALL-PC keeps it; the rig's own key file is plain text.
    void StartWatchdog()
    {
        var key = File.ReadAllBytes(_rig.TokenFile);
        var input = new Blob { Length = key.Length, Data = Marshal.AllocHGlobal(key.Length) };
        Marshal.Copy(key, 0, input.Data, key.Length);
        Assert.True(CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x4 /*LOCAL_MACHINE*/, out var output), "the PC key could not be protected");
        var sealedKey = new byte[output.Length];
        Marshal.Copy(output.Data, sealedKey, 0, sealedKey.Length);
        Marshal.FreeHGlobal(input.Data);
        var keyFile = _rig.TokenFile + ".machine";
        File.WriteAllBytes(keyFile, sealedKey);
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(_exe)!, "watchdog.args"),
            $"\"{Rig.Env("CAFE_AGENT_EXE")}\" {_rig.AgentArgs.Replace(_rig.TokenFile, keyFile)} --pipe-sid {WindowsIdentity.GetCurrent().User!.Value}");
        foreach (var dir in new[] { Path.GetDirectoryName(_exe)!, Path.GetDirectoryName(Rig.Env("CAFE_AGENT_EXE"))! })
        {
            Grant(dir, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX");
            Grant(dir, "/remove:g", "*S-1-5-11", "*S-1-1-0", "*S-1-5-4");
            Grant(Path.Combine(dir, "*"), "/reset", "/T");
        }
        Assert.Equal(0, Sc($"create CafeWatchdog binPath= \"{_exe}\" start= demand"));
        Assert.Equal(0, Sc("start CafeWatchdog"));
    }

    // Any program of the same account can post "quit" to the PC program's threads (measured 32 and 38); WinForms then closes
    // that thread's windows at once (read in its source). A customer's program posts from the normal desktop. The lock
    // screen's and the key blocker's threads are on the lock screen's desktop, which only Windows and admins can open,
    // so round 2 posts from there as an admin, to show what would happen if a program ever got there. Each round: within
    // 3 s a lock screen desktop has the screen again, the normal desktop had it for under 0.5 s, and Ctrl+Shift+Esc opens
    // no Task Manager.
    [Fact]
    public void B53_a_quit_message_to_the_PC_programs_threads_leaves_the_PC_locked()
    {
        try
        {
            StartWatchdog();
            var failures = new List<string>();
            var lines = new List<string>();
            foreach (var (mainOnly, fromLockDesktop) in new[] { (false, false), (false, true), (true, false) })
            {
                var round = (mainOnly ? "the main thread" : "every thread but the main one") + (fromLockDesktop ? ", from the lock screen's desktop" : ", from the normal desktop");
                Process? agent = null;
                Rig.WaitFor(() => (agent = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault(p => Rig.InputDesktop().StartsWith($"CafeLock-{p.Id}-"))) is not null, 20,
                    $"{round}: no PC program's lock screen desktop has the screen", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
                Thread.Sleep(2000);
                Rig.ToNormalDesktop();
                agent!.Refresh();
                var main = (uint)agent.Threads.Cast<ProcessThread>().MinBy(t => t.StartTime)!.Id; // the first thread made is Main's
                var targets = agent.Threads.Cast<ProcessThread>().Select(t => (uint)t.Id).Where(id => (id == main) == mainOnly).ToList();
                if (fromLockDesktop) Rig.FollowScreen();
                var errors = targets.Select(id => PostThreadMessage(id, 0x0012 /*WM_QUIT*/, IntPtr.Zero, IntPtr.Zero) ? 0 : Marshal.GetLastWin32Error()).ToList();
                var posted = errors.Count(e => e == 0);
                Rig.ToNormalDesktop();
                var watch = Stopwatch.StartNew();
                var open = 0.0;
                for (var last = 0.0; watch.Elapsed < TimeSpan.FromSeconds(3); Thread.Sleep(10))
                {
                    var now = watch.Elapsed.TotalSeconds;
                    if (Rig.InputDesktop() == "Default") open += now - last;
                    last = now;
                }
                var locking = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault(p => Rig.InputDesktop().StartsWith($"CafeLock-{p.Id}-"));
                var running = Process.GetProcesses().Select(p => p.Id).ToHashSet();
                Rig.FollowScreen();
                Keyboard.TypeSimultaneously(VirtualKeyShort.CONTROL, VirtualKeyShort.SHIFT, VirtualKeyShort.ESCAPE);
                Thread.Sleep(2500);
                var taskManager = Process.GetProcesses().Where(p => !running.Contains(p.Id) && p.ProcessName == "Taskmgr").ToList();
                taskManager.ForEach(Rig.Kill);
                var who = locking is null ? "no lock screen has the screen" : locking.Id == agent.Id ? "the same program still locks the PC" : $"a new program (pid {locking.Id}) locks the PC";
                lines.Add($"{round}: quit posted to {posted} of {targets.Count} threads (refused with {string.Join(", ", errors.Where(e => e != 0).Distinct())}); the normal desktop had the screen for {open:F2} s; {who}; Task Manager {(taskManager.Count > 0 ? "OPENED" : "did not open")}");
                if (locking is null || open >= 0.5 || taskManager.Count > 0) failures.Add(lines[^1]);
            }
            TestContext.Current.TestOutputHelper?.WriteLine("QUIT " + string.Join("\nQUIT ", lines));
            Assert.True(failures.Count == 0, string.Join("\n", failures));
        }
        catch
        {
            Rig.Screenshot();
            var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "logs");
            if (Directory.Exists(logs)) foreach (var f in Directory.GetFiles(logs)) Console.WriteLine($"--- {f}\n{File.ReadAllText(f)}");
            throw;
        }
    }

    [DllImport("user32.dll", SetLastError = true)] static extern bool PostThreadMessage(uint thread, uint message, IntPtr w, IntPtr l);
    [StructLayout(LayoutKind.Sequential)] struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);

    // B5.3 part 3: a lock screen program that stops answering (here the test pauses it as a whole) is ended after 15 s and a
    // new one locks the PC. Locked: the counter's review list gets it, which the counter window speaks. During a visit: only
    // the owner's alerts on the counter screen.
    [Fact]
    public async Task B53_a_lock_screen_program_that_stops_answering_is_replaced_after_15_s_and_the_counter_is_told()
    {
        try
        {
            StartWatchdog();
            var staff = await _rig.StaffToken();
            var owner = await _rig.OwnerToken();
            var lines = new List<string>();
            foreach (var visit in new[] { false, true })
            {
                if (visit) await _rig.Post("/staff/sessions", new { pc = "PC1", phone = "9000000003", mode = "postpaid" }, staff);
                Process? agent = null;
                Rig.WaitFor(() => (agent = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault()) is not null
                    && (visit ? Rig.InputDesktop() == "Default" : Rig.InputDesktop().StartsWith($"CafeLock-{agent.Id}-")), 30,
                    visit ? "the PC did not unlock for the visit" : "no PC program's lock screen desktop has the screen", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
                var age = DateTime.Now - agent!.StartTime;
                if (age < TimeSpan.FromSeconds(16)) Thread.Sleep(TimeSpan.FromSeconds(16) - age); // past the watchdog's start-up allowance
                Rig.ToNormalDesktop();
                Rig.Pause(agent, true);
                var watch = Stopwatch.StartNew();
                Process? next = null;
                Rig.WaitFor(() => agent.HasExited && (next = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault(p => p.Id != agent.Id)) is not null, 40,
                    $"{(visit ? "during a visit" : "locked")}: the paused program was not replaced within 40 s");
                lines.Add($"{(visit ? "during a visit" : "locked")}: replaced after {watch.Elapsed.TotalSeconds:F1} s");
                Assert.InRange(watch.Elapsed.TotalSeconds, 14, 25);
            }
            TestContext.Current.TestOutputHelper?.WriteLine("STUCK " + string.Join("\nSTUCK ", lines));
            Rig.WaitFor(() => _rig.Review(staff).Any(t => t.EndsWith(" PC1: the lock screen stopped answering; it was restarted and the Customer's programs were closed")), 20,
                "the counter's review list did not get the locked PC's report", () => string.Join("\n", _rig.Review(staff)));
            List<string> Alerts() => _rig.Raw(HttpMethod.Get, "/staff/alerts", owner).Content.ReadFromJsonAsync<List<string>>().Result!;
            Rig.WaitFor(() => Alerts().Any(t => t.EndsWith(" PC1: the lock screen stopped answering during a visit and was restarted")), 20,
                "the owner's alerts did not get the restart during the visit", () => string.Join("\n", Alerts()));
            Assert.Single(_rig.Review(staff), t => t.Contains("lock screen")); // the restart during the visit has no voice
        }
        catch
        {
            Rig.Screenshot();
            var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "logs");
            if (Directory.Exists(logs)) foreach (var f in Directory.GetFiles(logs)) Console.WriteLine($"--- {f}\n{File.ReadAllText(f)}");
            throw;
        }
    }

    // B5.3 part 3: ended 3 times within a minute while locked, by someone other than the watchdog, a clean-up or setup mode.
    [Fact]
    public async Task B53_a_lock_screen_program_ended_3_times_within_a_minute_while_locked_is_reported_to_the_counter()
    {
        try
        {
            StartWatchdog();
            var staff = await _rig.StaffToken();
            bool Told() => _rig.Review(staff).Any(t => t.EndsWith(" PC1: the lock screen was ended 3 times within a minute; the Customer's programs were closed"));
            for (var end = 1; end <= 3; end++)
            {
                Process? agent = null;
                Rig.WaitFor(() => (agent = Process.GetProcessesByName("Cafe.Agent").FirstOrDefault(p => Rig.InputDesktop().StartsWith($"CafeLock-{p.Id}-"))) is not null, 20,
                    $"end {end}: no PC program's lock screen desktop has the screen", () => $"the screen shows desktop '{Rig.InputDesktop()}'");
                Thread.Sleep(3000); // it has polled the counter, so the watchdog knows the PC is locked
                if (end == 3) Assert.False(Told(), "reported after 2 ends");
                Rig.Kill(agent);
            }
            Rig.WaitFor(Told, 20, "the counter's review list did not get the report", () => string.Join("\n", _rig.Review(staff)));
        }
        catch
        {
            Rig.Screenshot();
            var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "logs");
            if (Directory.Exists(logs)) foreach (var f in Directory.GetFiles(logs)) Console.WriteLine($"--- {f}\n{File.ReadAllText(f)}");
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
    readonly UIA3Automation _ui = new();
    // The lock screen has its own Windows desktop, and a thread only reaches the windows of the desktop it is on.
    // So before every look at the windows, the calling thread moves to the desktop that has the screen: the tests
    // see what a person at the PC sees. Measured: the same objects, simulated keys and screenshots then work.
    public UIA3Automation Ui { get { FollowScreen(); return _ui; } }
    readonly System.Text.StringBuilder _serverLog = new();
    Process? _server;
    Process? _watchdogProxy;
    HttpClient _http = null!;

    public Rig(bool offlineLockTest = false) => StartServer(offlineLockTest);
    public string TokenFile => Path.Combine(_pcDir, "pc.token");
    public string OfflineCacheFile => Path.Combine(_pcDir, "offline-unlock.bin");
    public string TimeLockSettingFile => Path.Combine(_pcDir, "time-lock-setting.json");
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
        try
        {
            WaitFor(() => File.Exists(Path.Combine(Data, "server.pin")) && Ping(), 60, "server did not start", () => _serverLog.ToString());
            Directory.CreateDirectory(_pcDir);
            File.Copy(Path.Combine(Data, "pc1.token"), Path.Combine(_pcDir, "pc.token"), true);
            File.Copy(Path.Combine(Data, "server.pin"), Path.Combine(_pcDir, "server.pin"), true);
        }
        catch
        {
            Kill(_server); // A failed startup must not leave the server (or descendants) holding port 5443 for the next test.
            _server = null;
            throw;
        }
    }
    public Process StartAgent(bool lockOnNormalDesktop = false, bool lockThreadRefused = false, bool unlockRefusedOnce = false)
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
        if (lockOnNormalDesktop) agent.ArgumentList.Add("--test-lock-on-default"); // what the PC falls back to when Windows refuses the lock screen's own desktop
        if (unlockRefusedOnce) agent.ArgumentList.Add("--test-unlock-refused-once"); // Windows refuses the normal desktop at the first unlock, as it does while its own secure screen is up
        if (lockThreadRefused) agent.ArgumentList.Add("--test-lock-thread-refused"); // Windows moves the key blocker's thread to that desktop, then refuses the lock screen's
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
        Kill(_watchdogProxy); Kill(_server); _ui.Dispose(); _http.Dispose();
        // every test's PC programs have ended by now: their lock screen desktops must be gone and the screen back on the normal one
        WaitFor(() => InputDesktop() == "Default" && !Desktops().Any(d => d.StartsWith("CafeLock-")), 5, "a test left a lock screen desktop behind",
            () => $"desktops [{string.Join(", ", Desktops())}]; the screen shows desktop '{InputDesktop()}'");
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
        var r = await Http.PostAsJsonAsync("/staff/login", new { phone = "9000000002", pin = "111111" });
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["token"];
    }
    public async Task<string> OwnerToken()
    {
        var r = await Http.PostAsJsonAsync("/staff/login", new { phone = "9000000001", pin = "432100" });
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["token"];
    }
    public async Task<string> EnrollStaffTwoStep()
    {
        var token = await OwnerToken();
        using var start = new HttpRequestMessage(HttpMethod.Post, "/staff/two-step/staff/start") { Content = JsonContent.Create(new { phone = "9000000002" }) };
        start.Headers.Authorization = new("Bearer", token);
        using var started = await Http.SendAsync(start);
        started.EnsureSuccessStatusCode();
        var secret = (await started.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["secret"];
        using var confirm = new HttpRequestMessage(HttpMethod.Post, "/staff/two-step/staff/on")
        { Content = JsonContent.Create(new { phone = "9000000002", secret, code = AppCode(secret) }) };
        confirm.Headers.Authorization = new("Bearer", token);
        using var enabled = await Http.SendAsync(confirm);
        enabled.EnsureSuccessStatusCode();

        using var offlineStart = new HttpRequestMessage(HttpMethod.Post, "/staff/two-step/offline/start")
        { Content = JsonContent.Create(new { phone = "9000000002" }) };
        offlineStart.Headers.Authorization = new("Bearer", token);
        using var offlineStarted = await Http.SendAsync(offlineStart);
        offlineStarted.EnsureSuccessStatusCode();
        var offlineSecret = (await offlineStarted.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["secret"];
        Assert.NotEqual(secret, offlineSecret);
        using var offlineConfirm = new HttpRequestMessage(HttpMethod.Post, "/staff/two-step/offline/on")
        { Content = JsonContent.Create(new { phone = "9000000002", secret = offlineSecret, code = AppCode(offlineSecret) }) };
        offlineConfirm.Headers.Authorization = new("Bearer", token);
        using var offlineEnabled = await Http.SendAsync(offlineConfirm);
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
    public async Task<int> TryStaffLogin(string phone, string pin) => (int)(await Http.PostAsJsonAsync("/staff/login", new { phone, pin })).StatusCode;
    public async Task Post(string path, object body, string token)
    {
        using var m = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        m.Headers.Authorization = new("Bearer", token);
        (await Http.SendAsync(m)).EnsureSuccessStatusCode();
    }
    // Server calls are the only awaits in these tests, and after an await a test can go on, on another thread. The thread it
    // leaves must not stay on the lock screen's desktop (see ToNormalDesktop; seen in T1.1, runs 45011269480 and 45012237116).
    public HttpClient Http { get { ToNormalDesktop(); return _http; } }
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
    public static void Kill(Process? p) { ToNormalDesktop(); try { if (p is { HasExited: false }) { p.Kill(true); p.WaitForExit(5000); } } catch (InvalidOperationException) { } }

    public static void WaitFor(Func<bool> ok, int seconds, string why, Func<string>? more = null)
    {
        var until = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < until) { try { if (ok()) return; } catch (Exception) { } Thread.Sleep(300); } // UI elements vanish mid-check; retry
        Assert.Fail(more is null ? why : $"{why}\n{more()}");
    }

    [ThreadStatic] static IntPtr _followed; // the desktop handle this thread opened for itself
    public static void FollowScreen() => MoveThread(OpenInputDesktop(0, false, 0x10000000 /*GENERIC_ALL*/));
    // Before a PC program is ended. A test thread still on its lock screen's desktop keeps that desktop alive after the
    // program is gone: the screen stays on it, or goes to it when a later program is killed (measured in run 45011269480).
    public static void ToNormalDesktop() => MoveThread(OpenDesktop("Default", 0, false, 0x10000000 /*GENERIC_ALL*/));
    static void MoveThread(IntPtr desktop)
    {
        if (desktop == IntPtr.Zero) return;
        if (DesktopName(desktop) == DesktopName(GetThreadDesktop(GetCurrentThreadId())) || !SetThreadDesktop(desktop)) { CloseDesktop(desktop); return; }
        if (_followed != IntPtr.Zero) CloseDesktop(_followed);
        _followed = desktop;
    }
    public static List<string> Desktops()
    {
        var names = new List<string>();
        EnumDesktops(GetProcessWindowStation(), (name, _) => { names.Add(name); return true; }, IntPtr.Zero);
        return names;
    }
    delegate bool DesktopProc([MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr state);
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", EntryPoint = "EnumDesktopsW")] static extern bool EnumDesktops(IntPtr station, DesktopProc callback, IntPtr state);
    public static void Pause(Process program, bool pause) => Assert.Equal(0, pause ? NtSuspendProcess(program.Handle) : NtResumeProcess(program.Handle));
    [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr process);
    [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr process);
    public static IntPtr MakeDesktop(string name) => CreateDesktop(name, IntPtr.Zero, IntPtr.Zero, 0, 0x10000000 /*GENERIC_ALL*/, IntPtr.Zero); // rights: what Windows gives by itself
    public static void CloseTaken(IntPtr desktop) => CloseDesktop(desktop);
    [DllImport("user32.dll", EntryPoint = "CreateDesktopW", CharSet = CharSet.Unicode)] static extern IntPtr CreateDesktop(string name, IntPtr device, IntPtr mode, uint flags, uint access, IntPtr security);
    public static string InputDesktopRights()
    {
        var input = OpenInputDesktop(0, false, 0x00020000 /*READ_CONTROL*/);
        var descriptor = Marshal.AllocHGlobal(4096);
        try
        {
            if (input == IntPtr.Zero || !GetUserObjectSecurity(input, [4 /*the rights list*/], descriptor, 4096, out _)) return $"(cannot read: error {Marshal.GetLastWin32Error()})";
            return ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, 4, out var text, out _) ? Marshal.PtrToStringUni(text)! : $"(no text: error {Marshal.GetLastWin32Error()})";
        }
        finally { Marshal.FreeHGlobal(descriptor); CloseDesktop(input); }
    }
    [DllImport("user32.dll", SetLastError = true)] static extern bool GetUserObjectSecurity(IntPtr handle, int[] what, IntPtr descriptor, int length, out int needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor, uint revision, int what, out IntPtr text, out uint length);
    public static string InputDesktop()
    {
        var input = OpenInputDesktop(0, false, 0x0001 /*DESKTOP_READOBJECTS*/);
        if (input == IntPtr.Zero) return $"(cannot open: error {Marshal.GetLastWin32Error()})";
        try { return DesktopName(input); } finally { CloseDesktop(input); }
    }
    // what any program of the customer's can do while the PC is locked (measured): give the screen to the normal desktop
    public static bool SwitchToNormalDesktop()
    {
        var normal = OpenDesktop("Default", 0, false, 0x0100 /*DESKTOP_SWITCHDESKTOP*/);
        try { return normal != IntPtr.Zero && SwitchDesktop(normal); } finally { CloseDesktop(normal); }
    }
    [DllImport("user32.dll", EntryPoint = "OpenDesktopW", CharSet = CharSet.Unicode)] static extern IntPtr OpenDesktop(string name, uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] static extern bool SwitchDesktop(IntPtr desktop);
    static string DesktopName(IntPtr desktop)
    {
        var name = new char[256];
        return GetUserObjectInformation(desktop, 2 /*UOI_NAME*/, name, (uint)name.Length * 2, out _) ? new string(name).TrimEnd('\0') : "";
    }
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", CharSet = CharSet.Unicode)] static extern bool GetUserObjectInformation(IntPtr handle, int index, [Out] char[] info, uint bytes, out uint needed);

    public static void Screenshot() { FollowScreen(); ScreenToFile(); }
    static void ScreenToFile() => FlaUI.Core.Capturing.Capture.Screen().ToFile(Path.Combine(Environment.GetEnvironmentVariable("GITHUB_WORKSPACE") ?? ".", $"screen-{DateTime.Now:HHmmss}.png"));
    public static string Describe(IntPtr h)
    {
        var title = new System.Text.StringBuilder(256); GetWindowText(h, title, 256);
        var cls = new System.Text.StringBuilder(256); GetClassName(h, cls, 256);
        GetWindowThreadProcessId(h, out var pid);
        string process; try { process = Process.GetProcessById((int)pid).ProcessName; } catch (ArgumentException) { process = "?"; }
        return $"{h} '{title}' class {cls} process {process}";
    }
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int max);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint processId);
    public static string ForegroundTitle() { var sb = new System.Text.StringBuilder(256); GetWindowText(GetForegroundWindow(), sb, 256); return sb.ToString(); }
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int command);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr FindWindow(string? className, string title);
    // true when window a is in front of window b (Windows keeps top-level windows in one front-to-back list)
    public static bool Above(IntPtr a, IntPtr b) { for (var h = GetWindow(b, 3 /*GW_HWNDPREV*/); h != IntPtr.Zero; h = GetWindow(h, 3)) if (h == a) return true; return false; }
    [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr h, uint command);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int max);
}