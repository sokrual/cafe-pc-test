using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Input;
using FlaUI.Core.WindowsAPI;
using FlaUI.UIA3;
using WinForms = System.Windows.Forms;

// Throwaway measurements for E3b (the lock screen on its own Windows desktop). Never merged into main.
// The parent plays the UI tests; the child plays the lock screen program. Every line it prints is a measurement.
static class Program
{
    const uint All = 0x10000000;          // GENERIC_ALL
    const string AdminsOnly = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;RC;;;OW)"; // SYSTEM and admins: everything; the owner: read the rights only
    static readonly object Gate = new();
    static string _log = "";              // set in the child: its lines also go to this file, for the parent to read
    static IntPtr _hwnd;
    static HookProc? _lockHook, _defaultHook;
    delegate uint NativeStart(IntPtr state);
    static NativeStart? _native;
    [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr security, IntPtr stack, IntPtr start, IntPtr state, uint flags, out uint id);
    [DllImport("ole32.dll")] static extern void CoUninitialize();
    [DllImport("ole32.dll")] static extern int OleInitialize(IntPtr reserved); // kept alive so the garbage collector cannot free the callbacks

    static int Main(string[] args)
    {
        try { return args.Length > 0 && args[0] == "--child" ? Child(args) : Parent(); }
        catch (Exception e) { Say($"UNEXPECTED: {e}"); return 0; }
    }

    // ---------------- the lock screen stand-in ----------------
    // --child NAME SDDL LOGFILE self|serve sta|mta
    static int Child(string[] a)
    {
        var (name, sddl, mode, sta, how) = (a[1], a[2], a[4], a[5] == "sta", a[5]);
        _log = a[3];
        Say($"main thread desktop before CreateDesktop: '{Name(GetThreadDesktop(GetCurrentThreadId()))}'");
        var desk = Create(name, sddl);
        Say($"CreateDesktop '{name}' with rights {sddl}: {desk != IntPtr.Zero} error {Marshal.GetLastPInvokeError()}");
        if (desk == IntPtr.Zero) return 0;
        Say($"main thread desktop after CreateDesktop: '{Name(GetThreadDesktop(GetCurrentThreadId()))}'");
        var byName = OpenDesktop(name, 0, false, All);
        Say($"same account opens it again by name, all rights: {byName != IntPtr.Zero} error {Marshal.GetLastPInvokeError()}");
        if (byName != IntPtr.Zero) CloseDesktop(byName);

        new Thread(() =>
        {
            _defaultHook = (c, w, l) => { if (c >= 0 && (long)w is 0x100 or 0x104) Say($"hook on the Default desktop saw key 0x{Marshal.ReadInt32(l):X2}"); return CallNextHookEx(IntPtr.Zero, c, w, l); };
            Say($"keyboard hook from a Default-desktop thread: {SetWindowsHookEx(13, _defaultHook, GetModuleHandle(null), 0) != IntPtr.Zero}");
            WinForms.Application.Run();
        }) { IsBackground = true }.Start();

        var shown = new ManualResetEventSlim();
        ThreadStart run = () =>
        {
            try
            {
                if (how == "sta-late") { CoUninitialize(); Say("the thread undid .NET's own COM start (CoUninitialize)"); }
                var set = SetThreadDesktop(desk);
                Say($"SetThreadDesktop on a new {(sta ? "STA" : "MTA")} thread, own handle: {set} error {Marshal.GetLastPInvokeError()}");
                if (!set) return;
                if (how is "sta-late" or "native") Say($"OleInitialize after the move: 0x{OleInitialize(IntPtr.Zero):X}");
                var lockThread = Environment.CurrentManagedThreadId;
                _lockHook = (c, w, l) => { if (c >= 0 && (long)w is 0x100 or 0x104) Say($"hook on the lock desktop saw key 0x{Marshal.ReadInt32(l):X2}"); return CallNextHookEx(IntPtr.Zero, c, w, l); };
                Say($"keyboard hook from the lock-desktop thread: {SetWindowsHookEx(13, _lockHook, GetModuleHandle(null), 0) != IntPtr.Zero} error {Marshal.GetLastPInvokeError()}");
                var form = new WinForms.Form { Name = "LockScreen", Text = "Measure lock", FormBorderStyle = WinForms.FormBorderStyle.None, StartPosition = WinForms.FormStartPosition.Manual, Bounds = WinForms.SystemInformation.VirtualScreen, BackColor = Color.FromArgb(200, 30, 30), KeyPreview = true };
                var phone = new WinForms.TextBox { Name = "Phone", Width = 300, Left = 300, Top = 300 };
                var go = new WinForms.Button { Name = "Go", Text = "Go", Left = 300, Top = 340, BackColor = Color.White };
                go.Click += (_, _) => Say($"button clicked on thread {Environment.CurrentManagedThreadId} (lock thread is {lockThread}); Phone text is '{phone.Text}'");
                var late = new WinForms.TextBox { Name = "Late", Width = 300, Left = 300, Top = 460, Visible = false };
                var reveal = new WinForms.Button { Name = "Reveal", Text = "Reveal", Left = 420, Top = 340, BackColor = Color.White };
                reveal.Click += (_, _) => { Say($"reveal clicked on thread {Environment.CurrentManagedThreadId} (lock thread is {lockThread})"); late.Visible = true; Say("the hidden box is now shown"); };
                form.Controls.Add(late); form.Controls.Add(reveal);
                Say($"WinForms says this thread is {WinForms.Application.OleRequired()}; .NET says {Thread.CurrentThread.GetApartmentState()}");
                form.KeyDown += (_, e) => Say($"lock form saw key {e.KeyCode}");
                form.FormClosing += (_, e) => { if (e.CloseReason == WinForms.CloseReason.UserClosing) { e.Cancel = true; Say("close refused (Alt+F4 or a close message)"); } };
                var pin = new WinForms.TextBox { Name = "Pin", Width = 300, Left = 300, Top = 380, PlaceholderText = "PIN", UseSystemPasswordChar = true };
                var method = new WinForms.ComboBox { Name = "PaymentMethod", Width = 300, Left = 300, Top = 420, DropDownStyle = WinForms.ComboBoxStyle.DropDownList };
                method.Items.AddRange(["cash", "upi"]); method.SelectedIndex = 0;
                form.Controls.Add(phone); form.Controls.Add(go); form.Controls.Add(pin); form.Controls.Add(method);
                form.Shown += (_, _) => { _hwnd = form.Handle; Say($"lock form shown, bounds {form.Bounds}"); shown.Set(); };
                var look = new WinForms.Timer { Interval = 1000 };   // what is really on the screen, seen from the lock desktop
                var looks = 0;
                look.Tick += (_, _) => { if (++looks is 2 or 3) Say($"screen pixel seen from the lock-desktop thread: {Pixel()} (lock form is red 200,30,30); foreground is the lock form: {GetForegroundWindow() == form.Handle}"); };
                look.Start();
                WinForms.Application.Run(form);
            }
            catch (Exception e) { Say($"lock thread failed: {e}"); }
            finally { shown.Set(); }
        };
        if (how == "native") { _native = _ => { run(); return 0; }; Say($"lock thread made by Windows itself (CreateThread): {CreateThread(IntPtr.Zero, IntPtr.Zero, Marshal.GetFunctionPointerForDelegate(_native), IntPtr.Zero, 0, out _) != IntPtr.Zero}"); }
        else
        {
            var ui = new Thread(run) { IsBackground = true };
            if (sta) ui.SetApartmentState(ApartmentState.STA);
            ui.Start();
        }
        shown.Wait(20000);
        if (_hwnd == IntPtr.Zero) { Say("no lock form: stopping"); return 0; }

        Say($"SwitchDesktop to the lock desktop: {SwitchDesktop(desk)} error {Marshal.GetLastPInvokeError()}; input desktop now '{InputName()}'");
        if (mode == "self")
        {
            Thread.Sleep(3500);
            Say($"switch back to Default: {SwitchTo("Default")}; input desktop now '{InputName()}'");
            return 0;
        }
        Say($"READY hwnd {_hwnd}");
        Thread.Sleep(Timeout.Infinite);
        return 0;
    }

    // ---------------- the tester ----------------
    static int Parent()
    {
        using var me = WindowsIdentity.GetCurrent();
        Say($"Windows: {RuntimeInformation.OSDescription} {RuntimeInformation.OSArchitecture}; this program runs as {RuntimeInformation.ProcessArchitecture}; session {Process.GetCurrentProcess().SessionId}; account {me.Name}; admin rights on: {new WindowsPrincipal(me).IsInRole(WindowsBuiltInRole.Administrator)}");
        Say($"start: input desktop '{InputName()}'; desktops [{Desktops()}]");

        Say("");
        Say("== G. which kind of lock thread lets a UI Automation click run on the lock screen's own thread? ==");
        foreach (var how in new[] { "mta", "sta-late", "native" })
        {
            Say($"-- lock thread: {how}");
            var (gName, gLog) = ($"Measure-G-{how}", Path.GetTempFileName());
            var g = StartChild(gName, AdminsOnly, gLog, "serve", how);
            var gWait = Stopwatch.StartNew();
            while (gWait.Elapsed.TotalSeconds < 30 && !File.ReadAllText(gLog).Contains("READY hwnd")) Thread.Sleep(250);
            if (!File.ReadAllText(gLog).Contains("READY hwnd")) { Say("never ready"); try { g.Kill(); } catch (InvalidOperationException) { } Say($"switch back: {SwitchTo("Default")}"); continue; }
            OnLock(gName, "UI Automation presses Reveal, then looks for the box it shows and types in it", () =>
            {
                using var u = new UIA3Automation();
                var w = FlaUI.Core.Application.Attach(g.Id).GetAllTopLevelWindows(u).First();
                w.FindFirstDescendant(c => c.ByAutomationId("Reveal"))!.AsButton().Invoke();
                Thread.Sleep(1500);
                var box = w.FindFirstDescendant(c => c.ByAutomationId("Late"));
                if (box is not null) box.AsTextBox().Text = "55555";
                return $"box found: {box is not null}";
            });
            OnLock(gName, "then presses Go (is the lock thread still answering?)", () =>
            {
                using var u = new UIA3Automation();
                FlaUI.Core.Application.Attach(g.Id).GetAllTopLevelWindows(u).First().FindFirstDescendant(c => c.ByAutomationId("Go"))!.AsButton().Invoke();
                Thread.Sleep(1000); return "invoked";
            });
            OnLock(gName, "simulated key 9", () => { Keyboard.Type(VirtualKeyShort.KEY_9); Thread.Sleep(700); return "sent"; });
            g.Kill(); Thread.Sleep(800);
            Say($"after: input desktop '{InputName()}'{(InputName() == "Default" ? "" : "; switch back: " + SwitchTo("Default"))}");
        }
        return 0;
#pragma warning disable CS0162 // the earlier sections stay for the record; this round runs only G

        Say("");
        Say("== A. rights and thread rules (the child tests itself, then switches back) ==");
        var n = 0;
        foreach (var (label, sddl, apartment) in new[]
        {
            ("Windows' default rights, STA thread (round 1: refused, error 170)", "-", "sta"),
            ("Windows' default rights, MTA thread", "-", "mta"),
            ("SYSTEM only, owner refused (stands in for the Customer account's other programs), MTA", "D:P(A;;GA;;;SY)(A;;RC;;;OW)", "mta"),
            ("SYSTEM and admins, owner refused (the planned rights), MTA", AdminsOnly, "mta"),
        })
        {
            Say($"-- {label}");
            using var self = StartChild($"Measure-A{++n}", sddl, Path.GetTempFileName(), "self", apartment);
            if (!self.WaitForExit(40000)) { Say("child did not finish in 40 s: killed"); self.Kill(); }
            Say($"after the child left: input desktop '{InputName()}'; desktops [{Desktops()}]");
            if (InputName() != "Default") Say($"switch back by the tester: {SwitchTo("Default")}");
        }

        Say("");
        Say("== B. the tester against a lock screen on its own desktop (planned rights) ==");
        const string name = "Measure-B";
        var log = Path.GetTempFileName();
        var child = StartChild(name, AdminsOnly, log, "serve", "mta");
        var ready = Stopwatch.StartNew();
        while (ready.Elapsed.TotalSeconds < 40 && !File.ReadAllText(log).Contains("READY hwnd")) Thread.Sleep(250);
        var text = File.ReadAllText(log);
        if (!text.Contains("READY hwnd")) { Say("the child never became ready: stopping"); child.Kill(); Say($"switch back: {SwitchTo("Default")}"); return 0; }
        var hwnd = new IntPtr(long.Parse(text[(text.IndexOf("READY hwnd", StringComparison.Ordinal) + 11)..].Trim().Split('\r', '\n')[0]));
        Thread.Sleep(3500);
        Say($"while locked: input desktop '{InputName()}'; desktops [{Desktops()}]");

        Say("-- from a thread on the Default desktop (where the UI tests run today)");
        Try("is the lock form a valid window from here", () => $"{IsWindow(hwnd)}; found by title: {FindWindow(null, "Measure lock") != IntPtr.Zero}");
        Try("screen pixel seen from here", () => Pixel());
        Try("UI Automation by window handle", () => { using var u = new UIA3Automation(); var w = u.FromHandle(hwnd); return $"name '{w.Name}', {w.FindAllDescendants().Length} parts"; });
        Try("UI Automation by process", () => { using var u = new UIA3Automation(); return $"{FlaUI.Core.Application.Attach(child.Id).GetAllTopLevelWindows(u).Length} top-level windows"; });
        Try("plain window messages (set text, click)", () => Messages(hwnd, "11111"));
        Try("simulated key 5 (SendInput)", () => { Keyboard.Type(VirtualKeyShort.KEY_5); Thread.Sleep(700); return "sent"; });

        Say("-- from a tester thread moved to the lock desktop");
        OnLock(name, "UI Automation by window handle: set Phone, press Go", () =>
        {
            using var u = new UIA3Automation();
            var w = u.FromHandle(hwnd);
            var parts = w.FindAllDescendants().Length;
            w.FindFirstDescendant(c => c.ByAutomationId("Phone"))!.AsTextBox().Text = "98765";
            w.FindFirstDescendant(c => c.ByAutomationId("Go"))!.AsButton().Invoke();
            Thread.Sleep(700);
            return $"name '{w.Name}', {parts} parts, text set, button invoked";
        });
        OnLock(name, "UI Automation by process", () => { using var u = new UIA3Automation(); return $"{FlaUI.Core.Application.Attach(child.Id).GetAllTopLevelWindows(u).Length} top-level windows; desktop has {u.GetDesktop().FindAllChildren().Length} children"; });
        OnLock(name, "plain window messages (set text, click)", () => Messages(hwnd, "22222"));
        OnLock(name, "simulated key 7 (SendInput)", () => { Keyboard.Type(VirtualKeyShort.KEY_7); Thread.Sleep(700); return "sent"; });
        OnLock(name, "screen pixel seen from here", () => Pixel());

        Say("");
        Say("== C. Windows hotkeys while the lock desktop has the screen (the child's hook only watches, it blocks nothing) ==");
        foreach (var (label, keys, times) in new (string, VirtualKeyShort[], int)[]
        {
            ("Win", [VirtualKeyShort.LWIN], 1), ("Win+R", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_R], 1), ("Win+D", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_D], 1),
            ("Win+E", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_E], 1), ("Win+U", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_U], 1), ("Win+Tab", [VirtualKeyShort.LWIN, VirtualKeyShort.TAB], 1),
            ("Alt+Tab", [VirtualKeyShort.ALT, VirtualKeyShort.TAB], 1), ("Alt+Esc", [VirtualKeyShort.ALT, VirtualKeyShort.ESCAPE], 1), ("Ctrl+Esc", [VirtualKeyShort.CONTROL, VirtualKeyShort.ESCAPE], 1),
            ("Ctrl+Shift+Esc", [VirtualKeyShort.CONTROL, VirtualKeyShort.SHIFT, VirtualKeyShort.ESCAPE], 1), ("Shift five times", [VirtualKeyShort.SHIFT], 5),
            ("Alt+F4", [VirtualKeyShort.ALT, VirtualKeyShort.F4], 1),
            // Win+L and Ctrl+Alt+Del are left out: the first would lock the test machine for good, the second cannot be simulated
        })
        {
            var (defaultBefore, processesBefore) = (Windows(), Process.GetProcesses().Select(p => p.Id).ToHashSet());
            var onLock = OnLock(name, null, () =>
            {
                var before = Windows();
                for (var i = 0; i < times; i++) { Keyboard.TypeSimultaneously(keys); Thread.Sleep(150); }
                Thread.Sleep(2500);
                return string.Join("; ", Windows().Except(before));
            });
            var started = Process.GetProcesses().Where(p => !processesBefore.Contains(p.Id)).ToList();
            Say($"{label}: input desktop '{InputName()}'; lock form alive {OnLock(name, null, () => IsWindow(hwnd).ToString())}; new windows on the lock desktop [{onLock}]; new windows on Default [{string.Join("; ", Windows().Except(defaultBefore))}]; new programs [{string.Join(", ", started.Select(p => p.ProcessName))}]");
            foreach (var p in started.Where(p => p.ProcessName is "Taskmgr" or "osk" or "Utilman" or "Narrator" or "Magnify" or "AtBroker" or "SystemSettings" or "sethc" or "EaseOfAccessDialog"))
                try { p.Kill(); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            if (InputName() != name) Say($"   the screen left the lock desktop; put back: {SwitchTo(name)}");
        }

        Say("");
        Say("== E. can the UI tests keep their own threads and objects, and just follow the screen? ==");
        FlaUI.Core.AutomationElements.AutomationElement? kept = null;
        var first = new Thread(() =>
        {
            try
            {
                using var u = new UIA3Automation();   // made while this thread is on Default, like the test rig's shared one
                var app = FlaUI.Core.Application.Attach(child.Id);
                Say($"thread on Default, after using UI Automation there: {app.GetAllTopLevelWindows(u).Length} windows of the lock program seen; desktop has {u.GetDesktop().FindAllChildren().Length} children");
                var lockDesk = OpenDesktop(name, 0, false, All); var defaultDesk = OpenDesktop("Default", 0, false, All);
                Say($"the same thread moves to the lock desktop: {SetThreadDesktop(lockDesk)} error {Marshal.GetLastPInvokeError()}");
                Try("the same automation object, now on the lock desktop", () => { var all = app.GetAllTopLevelWindows(u); kept = all.FirstOrDefault(); if (kept is not null) kept.FindFirstDescendant(c => c.ByAutomationId("Phone"))!.AsTextBox().Text = "33333"; return $"{all.Length} windows seen; Phone set through it: {kept is not null}"; });
                Try("simulated key 8 from this thread", () => { Keyboard.Type(VirtualKeyShort.KEY_8); Thread.Sleep(500); return "sent"; });
                Say($"the same thread moves back to Default: {SetThreadDesktop(defaultDesk)} error {Marshal.GetLastPInvokeError()}");
                Try("the same automation object, back on Default", () => $"{app.GetAllTopLevelWindows(u).Length} windows of the lock program seen");
                Try("the lock form object kept from before, used from Default", () => $"name '{kept?.Name}'");
                Say($"the same thread moves to the lock desktop a second time: {SetThreadDesktop(lockDesk)} error {Marshal.GetLastPInvokeError()}");
                Try("the kept lock form object, used again on the lock desktop", () => { kept!.FindFirstDescendant(c => c.ByAutomationId("Go"))!.AsButton().Invoke(); Thread.Sleep(500); return $"name '{kept.Name}', button invoked"; });
                Say($"back to Default to finish: {SetThreadDesktop(defaultDesk)}; closing both handles: {CloseDesktop(lockDesk)} {CloseDesktop(defaultDesk)}");
            }
            catch (Exception e) { Say($"E failed: {e.GetType().Name}: {e.Message}"); }
        });
        first.Start(); first.Join();
        OnLock(name, "the lock form object made by the first thread, used by another thread on the lock desktop", () => { kept!.FindFirstDescendant(c => c.ByAutomationId("Phone"))!.AsTextBox().Text = "44444"; kept.FindFirstDescendant(c => c.ByAutomationId("Go"))!.AsButton().Invoke(); Thread.Sleep(500); return $"name '{kept.Name}', text set, button invoked"; });
        kept = null;

        Say("");
        Say("== D. another program switches the screen back to Default, then the lock program is killed while it has the screen ==");
        Say($"tester switches to Default while locked: {SwitchTo("Default")}; input desktop '{InputName()}'");
        Say($"tester switches to the lock desktop again: {SwitchTo(name)}; input desktop '{InputName()}'");
        Say($"before the kill: input desktop '{InputName()}'; desktops [{Desktops()}]");   // the tester holds no handle to the lock desktop here
        child.Kill();
        var (since, last) = (Stopwatch.StartNew(), "");
        while (since.Elapsed.TotalSeconds < 8)
        {
            var now = $"input desktop '{InputName()}'; desktops [{Desktops()}]";
            if (now != last) Say($"{since.Elapsed.TotalSeconds:0.0} s after the kill: {last = now}");
            Thread.Sleep(250);
        }
        Try("screen pixel seen from the Default desktop after the kill", () => Pixel());
        Say($"tester switches to Default: {SwitchTo("Default")}; input desktop '{InputName()}'; desktops [{Desktops()}]");

        Say("");
        Say("== F. the lock program is killed while a tester thread is still on its desktop ==");
        var logF = Path.GetTempFileName();
        var childF = StartChild("Measure-F", AdminsOnly, logF, "serve", "mta");
        var waitF = Stopwatch.StartNew();
        while (waitF.Elapsed.TotalSeconds < 40 && !File.ReadAllText(logF).Contains("READY hwnd")) Thread.Sleep(250);
        var release = new ManualResetEventSlim(); var attached = new ManualResetEventSlim();
        var stays = new Thread(() =>
        {
            var d = OpenDesktop("Measure-F", 0, false, All);
            Say($"a tester thread moves to the lock desktop and stays: {SetThreadDesktop(d)}");
            attached.Set(); release.Wait();
            var back = OpenDesktop("Default", 0, false, All);
            Say($"that thread moves to Default afterwards: {SetThreadDesktop(back)} error {Marshal.GetLastPInvokeError()}; closing the old handle: {CloseDesktop(d)}");
        });
        stays.Start(); attached.Wait();
        Say($"before the kill: input desktop '{InputName()}'; desktops [{Desktops()}]");
        childF.Kill();
        (since, last) = (Stopwatch.StartNew(), "");
        while (since.Elapsed.TotalSeconds < 5)
        {
            var now = $"input desktop '{InputName()}'; desktops [{Desktops()}]";
            if (now != last) Say($"{since.Elapsed.TotalSeconds:0.0} s after the kill: {last = now}");
            Thread.Sleep(250);
        }
        Say($"tester switches to Default: {SwitchTo("Default")}; input desktop '{InputName()}'");
        release.Set(); stays.Join(); Thread.Sleep(500);
        Say($"after the thread left: input desktop '{InputName()}'; desktops [{Desktops()}]");
        return 0;
    }

    static Process StartChild(string name, string sddl, string log, string mode, string apartment)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
        foreach (var a in new[] { "--child", name, sddl, log, mode, apartment }) start.ArgumentList.Add(a);
        return Process.Start(start)!;
    }

    static void Try(string what, Func<string> measure)
    {
        try { Say($"{what}: {measure()}"); }
        catch (Exception e) { Say($"{what}: FAILED {e.GetType().Name}: {e.Message}"); }
    }

    // runs the measurement on a fresh thread moved to the named desktop; no handle is left open afterwards
    static string OnLock(string desktop, string? what, Func<string> measure)
    {
        var result = "";
        var handle = IntPtr.Zero;
        var t = new Thread(() =>
        {
            handle = OpenDesktop(desktop, 0, false, All);
            var opened = $"{handle != IntPtr.Zero} error {Marshal.GetLastPInvokeError()}";
            if (handle == IntPtr.Zero || !SetThreadDesktop(handle)) { result = $"FAILED to move the thread: open {opened}, SetThreadDesktop error {Marshal.GetLastPInvokeError()}"; return; }
            try { result = measure(); }
            catch (Exception e) { result = $"FAILED {e.GetType().Name}: {e.Message}"; }
        });
        t.Start(); t.Join();
        if (handle != IntPtr.Zero) CloseDesktop(handle);
        if (what is not null) Say($"{what}: {result}");
        return result;
    }

    // the fallback for the UI tests if UI Automation cannot reach the lock desktop: the controls are ordinary windows
    static string Messages(IntPtr form, string phone)
    {
        IntPtr edit = IntPtr.Zero, button = IntPtr.Zero;
        EnumChildWindows(form, (h, _) =>
        {
            var cls = new StringBuilder(128); GetClassName(h, cls, cls.Capacity);
            if (cls.ToString().Contains("EDIT", StringComparison.OrdinalIgnoreCase)) edit = h;
            if (cls.ToString().Contains("BUTTON", StringComparison.OrdinalIgnoreCase)) button = h;
            return true;
        }, IntPtr.Zero);
        if (edit == IntPtr.Zero || button == IntPtr.Zero) return $"controls not found (text box {edit != IntPtr.Zero}, button {button != IntPtr.Zero}; error {Marshal.GetLastPInvokeError()})";
        SendMessage(edit, 0x000C /*WM_SETTEXT*/, IntPtr.Zero, phone);
        SendMessage(button, 0x00F5 /*BM_CLICK*/, IntPtr.Zero, null);
        Thread.Sleep(700);
        return $"text '{phone}' and a click sent";
    }

    // visible, titled top-level windows on the calling thread's desktop
    static List<string> Windows()
    {
        var list = new List<string>();
        EnumWindows((h, _) =>
        {
            var title = new StringBuilder(200); GetWindowText(h, title, title.Capacity);
            if (!IsWindowVisible(h) || title.Length == 0) return true;
            var cls = new StringBuilder(128); GetClassName(h, cls, cls.Capacity);
            GetWindowThreadProcessId(h, out var pid);
            var process = "?";
            try { using var p = Process.GetProcessById((int)pid); process = p.ProcessName; } catch (Exception e) when (e is ArgumentException or InvalidOperationException) { }
            list.Add($"'{title}' ({cls}, {process})");
            return true;
        }, IntPtr.Zero);
        return list;
    }

    static string Pixel()
    {
        using var bitmap = new Bitmap(1, 1);
        using (var g = Graphics.FromImage(bitmap)) g.CopyFromScreen(100, 100, 0, 0, new Size(1, 1));
        var c = bitmap.GetPixel(0, 0);
        return $"{c.R},{c.G},{c.B}";
    }

    static void Say(string line)
    {
        lock (Gate)
        {
            Console.WriteLine((_log == "" ? "" : "   child: ") + line);
            if (_log != "") File.AppendAllText(_log, line + Environment.NewLine);
        }
    }

    // ---------------- Windows desktops ----------------
    static IntPtr Create(string name, string sddl)
    {
        if (sddl == "-") return CreateDesktop(name, IntPtr.Zero, IntPtr.Zero, 0, All, IntPtr.Zero);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out _)) return IntPtr.Zero;
        var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
        try { return CreateDesktop(name, IntPtr.Zero, IntPtr.Zero, 0, All, ref attributes); }
        finally { var error = Marshal.GetLastPInvokeError(); LocalFree(descriptor); Marshal.SetLastPInvokeError(error); }
    }

    static string Name(IntPtr desktop)
    {
        var buffer = new char[256];
        return GetUserObjectInformation(desktop, 2 /*UOI_NAME*/, buffer, (uint)buffer.Length * 2, out _) ? new string(buffer).TrimEnd('\0') : $"(no name: error {Marshal.GetLastPInvokeError()})";
    }

    static string InputName()
    {
        var input = OpenInputDesktop(0, false, 0x0001 /*DESKTOP_READOBJECTS*/);
        if (input == IntPtr.Zero) return $"(cannot open: error {Marshal.GetLastPInvokeError()})";
        try { return Name(input); } finally { CloseDesktop(input); }
    }

    static string Desktops()
    {
        var names = new List<string>();
        EnumDesktops(GetProcessWindowStation(), (n, _) => { names.Add(n); return true; }, IntPtr.Zero);
        return string.Join(", ", names);
    }

    static string SwitchTo(string name)
    {
        var desktop = OpenDesktop(name, 0, false, 0x0100 /*DESKTOP_SWITCHDESKTOP*/);
        if (desktop == IntPtr.Zero) return $"False (cannot open '{name}': error {Marshal.GetLastPInvokeError()})";
        try { return SwitchDesktop(desktop) ? "True" : $"False (error {Marshal.GetLastPInvokeError()})"; } finally { CloseDesktop(desktop); }
    }

    delegate IntPtr HookProc(int code, IntPtr wParam, IntPtr lParam);
    delegate bool WindowProc(IntPtr window, IntPtr state);
    delegate bool DesktopProc([MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr state);
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }

    [DllImport("user32.dll", EntryPoint = "CreateDesktopW", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateDesktop(string name, IntPtr device, IntPtr mode, uint flags, uint access, IntPtr attributes);
    [DllImport("user32.dll", EntryPoint = "CreateDesktopW", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateDesktop(string name, IntPtr device, IntPtr mode, uint flags, uint access, ref SecurityAttributes attributes);
    [DllImport("user32.dll", EntryPoint = "OpenDesktopW", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenDesktop(string name, uint flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] static extern bool SwitchDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)] static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)] static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", EntryPoint = "EnumDesktopsW", SetLastError = true)] static extern bool EnumDesktops(IntPtr station, DesktopProc callback, IntPtr state);
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetUserObjectInformation(IntPtr handle, int index, [Out] char[] info, uint bytes, out uint needed);
    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr GetModuleHandle(string? name);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr SetWindowsHookEx(int id, HookProc callback, IntPtr module, uint thread);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern bool IsWindow(IntPtr window);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr FindWindow(string? className, string title);
    [DllImport("user32.dll")] static extern bool EnumWindows(WindowProc callback, IntPtr state);
    [DllImport("user32.dll", SetLastError = true)] static extern bool EnumChildWindows(IntPtr parent, WindowProc callback, IntPtr state);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder name, int max);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int max);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", EntryPoint = "SendMessageW", CharSet = CharSet.Unicode)] static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr wParam, string? lParam);
}
