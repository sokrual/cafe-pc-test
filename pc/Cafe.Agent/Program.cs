using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Cafe.Agent;

// The gaming PC program: a lock screen until a customer logs in, then a small timer that hides during games.
// It asks the admin PC every 2 s what to show; the admin PC is always right about time and money.
// Usage: Cafe.Agent --server https://ADMIN-PC:5443 [--token-file pc.token] [--pin-file server.pin] [--name "Gaming Cafe"] [--logs dir]
static class ProcessSecurity
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr descriptor, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetKernelObjectSecurity(IntPtr handle, uint securityInformation, IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr LocalFree(IntPtr memory);

    static bool IsCustomer(WindowsIdentity identity) => (identity.Name ?? "").Equals("Customer", StringComparison.OrdinalIgnoreCase)
        || (identity.Name ?? "").EndsWith("\\Customer", StringComparison.OrdinalIgnoreCase);

    public static void Harden()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!IsCustomer(identity))
        {
            Program.Log($"process DACL skipped for non-Customer identity {identity.Name}");
            return;
        }
        // OW (OWNER RIGHTS), not the Customer SID: without an OW entry Windows always lets the owner rewrite the DACL.
        // Other Customer programs may look at this program and wait for it, no more. Not "terminate": another Customer
        // program ended the lock screen with it. Not "read memory": after a login the PIN was found there (both measured).
        const string sddl = "D:P(A;;GA;;;SY)(D;;0x00040062;;;OW)(A;;GA;;;BA)(A;;0x00121400;;;OW)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (!SetKernelObjectSecurity(GetCurrentProcess(), 0x00000004, descriptor))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { LocalFree(descriptor); }
        Program.Log($"process DACL applied for Customer ({identity.User?.Value})");
    }

    // Another Customer program could open every thread of this one for every right: end it, freeze it, and "set context",
    // which changes what a thread runs (measured). Threads made from now on take the sign-in's default rights set here;
    // the threads already running get them one by one. Called after the --test-lock-desktop switch: a program started
    // after this change hangs (measured), and only that switch starts one.
    public static void HardenThreads()
    {
        using (var identity = WindowsIdentity.GetCurrent()) if (!IsCustomer(identity)) return;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00120800;;;OW)", 1, out var descriptor, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            GetSecurityDescriptorDacl(descriptor, out _, out var dacl, out _);
            if (!OpenProcessToken(GetCurrentProcess(), 0x0080 | 0x0008 /*ADJUST_DEFAULT | QUERY*/, out var token))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try { if (!SetTokenInformation(token, 6 /*TokenDefaultDacl*/, ref dacl, IntPtr.Size)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
            finally { CloseHandle(token); }
            foreach (ProcessThread t in Process.GetCurrentProcess().Threads)
            {
                var thread = OpenThread(0x00040000 /*WRITE_DAC*/, false, (uint)t.Id);
                if (thread == IntPtr.Zero) continue; // it ended since the list was made
                var error = SetSecurityInfo(thread, 6 /*kernel object*/, 0x80000004 /*protected DACL*/, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                CloseHandle(thread);
                if (error != 0) throw new System.ComponentModel.Win32Exception((int)error);
            }
        }
        finally { LocalFree(descriptor); }
        Program.Log("thread rights applied for Customer");
    }

    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetTokenInformation(IntPtr token, int infoClass, ref IntPtr info, int length);
    [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(IntPtr handle, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint access, bool inherit, uint id);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
}

static class Program
{
    static string _logDir = "";

    [STAThread]
    static void Main(string[] args)
    {
        string? Arg(string n) => Array.IndexOf(args, n) is var i and >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        _logDir = Arg("--logs") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cafe", "logs");
        ProcessSecurity.Harden();
        var testQueuePath = args.Contains("--test-queue-selflock", StringComparer.OrdinalIgnoreCase) ? "/pc/selflock"
            : args.Contains("--test-queue-logout", StringComparer.OrdinalIgnoreCase) ? "/pc/logout" : null;
        // lockdown check E3b.L1, run as Customer: see LockDesktop.Test
        if (Arg("--test-lock-desktop") is string lockDesktopTest) { Environment.ExitCode = LockDesktop.Test(lockDesktopTest); return; }
        ProcessSecurity.HardenThreads();
        if (testQueuePath is not null)
        {
            using var response = new WatchdogPipeClient().PostAsJsonAsync("/local/queue-action", new { path = testQueuePath }).GetAwaiter().GetResult();
            Environment.ExitCode = response.IsSuccessStatusCode ? 0 : 1;
            return;
        }
        Log($"started v{typeof(Program).Assembly.GetName().Version}");
        LockDesktop.Make(args.Contains("--test-lock-on-default", StringComparer.OrdinalIgnoreCase));
        LockDesktop.TestRefuseLockThread = args.Contains("--test-lock-thread-refused", StringComparer.OrdinalIgnoreCase);
        LockDesktop.TestRefuseUnlock = args.Contains("--test-unlock-refused-once", StringComparer.OrdinalIgnoreCase);
        ApplicationConfiguration.Initialize();
        var agent = new Agent(Arg("--name") ?? "Gaming Cafe");
        MessageLoop.RunForever();
        GC.KeepAlive(agent);
    }

    // never logs PINs or tokens; a log that can't be written must not stop the PC program
    public static void Log(string line)
    {
        try { Directory.CreateDirectory(_logDir); File.AppendAllText(Path.Combine(_logDir, $"agent-{DateTime.Now:yyyyMMdd}.log"), $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    public static string Fmt(long sec) => sec >= 3600 ? $"{sec / 3600}:{sec / 60 % 60:00}:{sec % 60:00}" : $"{sec / 60:00}:{sec % 60:00}";
}

public record PcState(bool Locked, string? Message, long? Session, string? Mode, long ElapsedSec, long? LeftSec, bool SelfLocked = false, bool LockWhenTimeRunsOut = false, string? Notice = null);
record ErrorBody(string Error);
record TimeLockSetting(bool LockWhenTimeRunsOut);
record OfflineUnlockReply(bool Success, string? Error, long? Step);
record OfflineUnlockInfo(OfflineUnlockRate? Rate, int EnabledAccounts, DateTime? LockedUntil, int PendingSales,
    int MaxOfflineUnlockMinutes, DateTime? LastRefreshServerUtc);
record OfflineUnlockRate(long Paise30, long Paise60, long Paise90, long ExtraBlockPaise, int MinimumMin, int BlockMin);

sealed class Agent : ApplicationContext
{
    readonly WatchdogPipeClient _watchdog = new();
    readonly List<string> _unacceptedActions = [];
    readonly object _unacceptedActionsGate = new();
    readonly SemaphoreSlim _sendGate = new(1, 1);
    readonly LockScreen _lock;
    readonly TimerWidget _timer;
    readonly SynchronizationContext _main = new WindowsFormsSynchronizationContext(); // this thread: all state stays here
    PcState _state = new(true, null, null, null, 0, null); // locked until the admin PC says otherwise
    DateTime _stateAt = DateTime.UtcNow;
    bool _online = true;
    // installed cafe PCs only: the SYSTEM watchdog cleans the Customer account when this note appears, then deletes it
    static readonly string WipeNote = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "wipe", "request");

    public Agent(string name)
    {
        KeyBlocker.Install(); // first: if Windows will not move its thread, the lock screen stays on the normal desktop with it
        var blockerMoved = LockDesktop.Own;
        _lock = LockScreen.Start(name, (phone, pin) => OnMain(() => Login(phone, pin)),
            (phone, code, minutes, method, upi) => OnMain(() => OfflineUnlock(phone, code, minutes, method, upi)));
        // Windows moved the key blocker's thread, then refused the lock screen's: the lock screen is a window on the normal
        // desktop, where that key blocker sees no keys. A second one, there.
        if (blockerMoved && !LockDesktop.Own) KeyBlocker.Install();
        _timer = new TimerWidget(Now, () => Send("/pc/logout", lockNow: true), () => Send("/pc/selflock", lockNow: true), () => Apply(_state with { Locked = true, Message = "Time is up. Please ask at the counter." }));
        KeyBlocker.Follow(_lock);
        var poll = new System.Windows.Forms.Timer { Interval = 2000 };
        poll.Tick += async (_, _) =>
        {
            Alive.Tick();
            var pending = WipePending();
            _lock.SetBusy(pending);
            if (pending) Apply(_state with { Locked = true, Message = WipeMessage() });
            await Refresh();
        };
        poll.Start();
        _lock.SetBusy(WipePending()); // a pending request must stay blocked immediately after a restart
        Apply(_state);
        _ = Refresh();
    }

    // time moves on between polls; the next poll corrects it
    (PcState state, long elapsed, long? left) Now()
    {
        var gone = (long)(DateTime.UtcNow - _stateAt).TotalSeconds;
        return (_state, _state.ElapsedSec + gone, _state.LeftSec - gone);
    }

    async Task Refresh()
    {
        try
        {
            await ReplayUnacceptedActions();
            if (await _watchdog.GetFromJsonAsync<TimeLockSetting>("/local/time-lock-setting") is { } remembered)
                _state = _state with { LockWhenTimeRunsOut = remembered.LockWhenTimeRunsOut };
            // a poll answer is older than any state applied while it was on its way (a login, a logout): drop it then.
            // CI caught one: the poll's "locked, no session" arrived just after the login, locked the PC again and
            // would have asked for the clean-up of the customer who had just logged in
            var asked = _changes;
            var serverState = await _watchdog.GetFromJsonAsync<PcState>("/pc/state");
            var offlineInfo = await _watchdog.GetFromJsonAsync<OfflineUnlockInfo>("/local/offline-unlock-info");
            if (offlineInfo?.PendingSales > 0)
            {
                _online = true;
                _lock.SetOffline(false);
                return; // never replay a logout or overwrite the local timer before the paid sale is reconciled
            }
            if (_state.Session == -1 && serverState is not null && _changes == asked)
                Apply(serverState); // the server decides whether the offline walk-in was accepted
            asked = _changes;
            if (await _watchdog.GetFromJsonAsync<PcState>("/pc/state") is { } s && _changes == asked)
            {
                Apply(s);
            }
            if (!_online) Program.Log("admin PC reachable again");
            _online = true;
            _lock.SetOffline(false);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException or System.Text.Json.JsonException)
        {
            if (_online) Program.Log($"admin PC unreachable, timing goes on here: {e.Message}");
            _online = false; // the session keeps running on the admin PC; this screen keeps counting from the last state
            _lock.SetOffline(true);
        }
    }

    int _changes;   // counts Apply calls (all on the UI thread)

    void Apply(PcState s)
    {
        _changes++;
        if (WipePending()) s = s with { Locked = true, Message = WipeMessage() };
        _lock.SetBusy(WipePending());
        if (_state.Session is > 0 && s.Session is null) AskForWipe(); // a server session ended, here or at the counter
        if (s.Locked != _state.Locked) Program.Log(s.Locked ? $"locked: {s.Message}" : $"unlocked, session {s.Session} ({s.Mode})");
        (_state, _stateAt) = (s, DateTime.UtcNow);
        if (s.Locked) { _timer.Hide(); _lock.ShowLocked(s.Message); }
        else { _lock.Unlock(); _timer.Tick(); }
    }

    // the lock screen has its own thread (see LockScreen.Start); what it asks for runs here, so the state has one thread
    Task<T> OnMain<T>(Func<Task<T>> work)
    {
        var done = new TaskCompletionSource<T>();
        _main.Post(async _ => { try { done.SetResult(await work()); } catch (Exception e) { done.SetException(e); } }, null);
        return done.Task;
    }

    async Task<string?> Login(string phone, string pin)
    {
        if (WipePending()) return WipeMessage();
        try
        {
            using var r = await _watchdog.PostAsJsonAsync("/pc/login", new { phone, pin });
            if (!r.IsSuccessStatusCode) return (await r.Content.ReadFromJsonAsync<ErrorBody>())?.Error ?? "Could not log in. Please try again.";
            var state = (await r.Content.ReadFromJsonAsync<PcState>())!;
            Apply(state);
            return null;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { return "This PC cannot reach the counter right now. Please ask at the counter."; }
    }

    async Task<string?> OfflineUnlock(string phone, string code, int minutes, string method, string? upiLast4)
    {
        if (_online) return "The counter is reachable. Please use normal login.";
        if (WipePending()) return WipeMessage();
        try
        {
            var request = new
            {
                saleId = Guid.NewGuid().ToString("N"),
                phone,
                code,
                minutes,
                method,
                upiLast4,
                session = _state.Session == -1 ? -1 : _state.Session is > 0 ? _state.Session : null
            };
            using var response = await _watchdog.PostAsJsonAsync("/local/offline-unlock", request);
            var result = await response.Content.ReadFromJsonAsync<OfflineUnlockReply>();
            if (!response.IsSuccessStatusCode || result?.Success != true)
                return result?.Error ?? "Offline unlock was refused. Please ask at the counter.";
            var (state, elapsed, left) = Now();
            var unlocked = state.Session is > 0
                ? state with { Locked = false, Message = null, Mode = "prepaid", ElapsedSec = elapsed, LeftSec = (left ?? 0) + minutes * 60L, SelfLocked = false }
                : state with { Locked = false, Message = null, Session = -1, Mode = "prepaid", ElapsedSec = 0, LeftSec = minutes * 60L, SelfLocked = false };
            Apply(unlocked);
            return null;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        { return "The watchdog is not available. Please ask at the counter."; }
    }

    static bool WipePending()
    {
        try { _ = File.GetAttributes(WipeNote); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        catch { return true; }
    }

    static string WipeMessage()
    {
        try
        {
            return File.GetCreationTimeUtc(WipeNote) < DateTime.UtcNow.AddMinutes(-2)
                ? "Please ask at the counter."
                : "Getting this PC ready for the next customer. Please wait.";
        }
        catch { return "Please ask at the counter."; }
    }

    static void AskForWipe()
    {
        if (!Directory.Exists(Path.GetDirectoryName(WipeNote))) return; // not an installed cafe PC (tests, development)
        try { using var request = new FileStream(WipeNote, FileMode.CreateNew, FileAccess.Write, FileShare.Read); Program.Log("asked for the logout clean-up"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Program.Log($"could not ask for the logout clean-up (error code {e.HResult & 0xffff})"); }
    }

    async Task<bool> ReplayUnacceptedActionsLocked()
    {
        while (true)
        {
            string? path;
            lock (_unacceptedActionsGate)
                path = _unacceptedActions.Count == 0 ? null : _unacceptedActions[0];
            if (path is null) return true;

            try
            {
                using var response = await _watchdog.PostAsJsonAsync("/local/queue-action", new { path });
                response.EnsureSuccessStatusCode();
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
            {
                Program.Log($"watchdog still has not accepted {path} (error code {e.HResult & 0xffff})");
                return false;
            }
            lock (_unacceptedActionsGate) _unacceptedActions.RemoveAt(0);
            Program.Log($"watchdog accepted previously unqueued {path}");
        }
    }

    async Task ReplayUnacceptedActions()
    {
        await _sendGate.WaitAsync();
        try { await ReplayUnacceptedActionsLocked(); }
        finally { _sendGate.Release(); }
    }

    // The SYSTEM watchdog saves each action to its protected, flushed queue before acknowledging it.
    async void Send(string path, bool lockNow)
    {
        if (path == "/pc/logout") AskForWipe();
        await _sendGate.WaitAsync();
        try
        {
            if (!await ReplayUnacceptedActionsLocked())
            {
                lock (_unacceptedActionsGate) _unacceptedActions.Add(path);
                Program.Log($"watchdog did not accept {path}; queued in memory behind earlier actions");
            }
            else
            {
                try
                {
                    using var response = await _watchdog.PostAsJsonAsync("/local/queue-action", new { path });
                    response.EnsureSuccessStatusCode();
                    Program.Log($"watchdog saved {path} for ordered delivery");
                }
                catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
                {
                    lock (_unacceptedActionsGate) _unacceptedActions.Add(path);
                    Program.Log($"watchdog did not accept {path}; queued in memory (error code {e.HResult & 0xffff})");
                }
            }
        }
        finally { _sendGate.Release(); }
        if (lockNow) Apply(_state with { Locked = true, Message = path == "/pc/logout" ? "Logged out. Please pay at the counter." : "Locked. Your time is still running." });
        await Refresh();
    }
}

sealed class LockScreen : Form
{
    readonly Label _message = new() { Name = "Message", AutoSize = false, Width = 520, Height = 60, ForeColor = Color.Gold, Font = new Font("Segoe UI", 14), TextAlign = ContentAlignment.MiddleCenter };
    readonly TextBox _phone = new() { Name = "Phone", Width = 320, Font = new Font("Segoe UI", 16), PlaceholderText = "Phone number" };
    readonly TextBox _pin = new() { Name = "Pin", Width = 320, Font = new Font("Segoe UI", 16), PlaceholderText = "PIN", UseSystemPasswordChar = true };
    readonly Button _go = new() { Name = "Login", Text = "Log in", Width = 320, Height = 48, Font = new Font("Segoe UI", 14, FontStyle.Bold), BackColor = Color.FromArgb(0, 120, 215), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
    readonly Button _staffUnlock = new() { Name = "StaffUnlock", Text = "Staff unlock", Width = 320, Height = 44, Visible = false };
    readonly TextBox _staffPhone = new() { Name = "StaffPhone", Width = 320, PlaceholderText = "Staff phone number" };
    readonly TextBox _staffCode = new() { Name = "StaffCode", Width = 320, PlaceholderText = "6-digit authenticator code" };
    readonly TextBox _minutes = new() { Name = "Minutes", Width = 320, PlaceholderText = "Minutes from the rate card" };
    readonly ComboBox _method = new() { Name = "PaymentMethod", Width = 320, DropDownStyle = ComboBoxStyle.DropDownList };
    readonly TextBox _upi = new() { Name = "UpiLast4", Width = 320, PlaceholderText = "UPI reference last 4 digits", Visible = false };
    readonly Label _offlineRate = new() { Name = "OfflineRate", Width = 520, Height = 42, ForeColor = Color.LightGray, TextAlign = ContentAlignment.MiddleCenter };
    readonly Button _submitOffline = new() { Name = "OfflineUnlockSubmit", Text = "Unlock and add time", Width = 320, Height = 48, Visible = false };
    bool _offlinePanel;
    readonly Label _error = new() { Name = "Error", AutoSize = false, Width = 520, Height = 40, ForeColor = Color.Salmon, Font = new Font("Segoe UI", 12), TextAlign = ContentAlignment.MiddleCenter };
    bool _busy;

    readonly Func<string, string, int, string, string?, Task<string?>> _offlineUnlock;

    // The lock screen gets its own thread, moved to the lock screen's own desktop before it makes any window.
    // Windows makes the thread (CreateThread), not .NET: .NET starts COM on its own threads before our code runs, and
    // then either Windows refuses the move (an STA thread, error 170) or WinForms runs without STA, where a click sent
    // by UI Automation ran on another thread and froze the screen (both measured). Here the order is ours: move
    // first, then start COM as STA. Other threads reach the lock screen through the public methods below, which post to it.
    public static LockScreen Start(string cafeName, Func<string, string, Task<string?>> login,
        Func<string, string, int, string, string?, Task<string?>> offlineUnlock)
    {
        LockScreen? screen = null;
        using var ready = new ManualResetEventSlim();
        _thread = _ =>
        {
            try
            {
                LockDesktop.MoveThreadHere(LockDesktop.TestRefuseLockThread);
                OleInitialize(IntPtr.Zero);
                screen = new LockScreen(cafeName, login, offlineUnlock);
                _ = screen.Handle; // made now, so that other threads can post to it
            }
            finally { ready.Set(); }
            MessageLoop.RunForever();
            return 0;
        };
        if (CreateThread(IntPtr.Zero, IntPtr.Zero, Marshal.GetFunctionPointerForDelegate(_thread), IntPtr.Zero, 0, out _) == IntPtr.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        ready.Wait();
        return screen ?? throw new InvalidOperationException("the lock screen could not start");
    }
    delegate uint ThreadBody(IntPtr state);
    static ThreadBody? _thread; // kept alive so the garbage collector cannot free the thread's code
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateThread(IntPtr security, IntPtr stack, IntPtr start, IntPtr state, uint flags, out uint id);
    [DllImport("ole32.dll")] static extern int OleInitialize(IntPtr reserved);

    LockScreen(string cafeName, Func<string, string, Task<string?>> login,
        Func<string, string, int, string, string?, Task<string?>> offlineUnlock)
    {
        _offlineUnlock = offlineUnlock;
        Name = "LockScreen"; Text = cafeName;
        FormBorderStyle = FormBorderStyle.None; ShowInTaskbar = false; TopMost = true;
        StartPosition = FormStartPosition.Manual; BackColor = Color.FromArgb(14, 14, 22);
        // Show the generic name until first-run setup can supply each cafe's own name.
        Control title = new Label { Text = cafeName, AutoSize = false, Width = 520, Height = 70, ForeColor = Color.White, Font = new Font("Segoe UI", 28, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter };
        var box = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        _method.Items.AddRange(["cash", "upi"]); _method.SelectedIndex = 0;
        foreach (Control c in new Control[] { title, _message, _phone, _pin, _go, _staffUnlock, _offlineRate, _staffPhone, _staffCode, _minutes, _method, _upi, _submitOffline, _error })
        { c.Margin = new Padding(100, 5, 100, 5); box.Controls.Add(c); }
        foreach (var c in new Control[] { _offlineRate, _staffPhone, _staffCode, _minutes, _method, _upi, _submitOffline }) c.Visible = false;
        _staffUnlock.Click += async (_, _) =>
        {
            _offlinePanel = !_offlinePanel;
            foreach (var c in new Control[] { _offlineRate, _staffPhone, _staffCode, _minutes, _method, _submitOffline }) c.Visible = _offlinePanel;
            _upi.Visible = _offlinePanel && _method.SelectedItem?.ToString() == "upi";
            if (_offlinePanel) await LoadOfflineRate();
        };
        _method.SelectedIndexChanged += (_, _) => _upi.Visible = _offlinePanel && _method.SelectedItem?.ToString() == "upi";
        _submitOffline.Click += async (_, _) =>
        {
            _submitOffline.Enabled = false;
            _error.Text = "";
            if (!int.TryParse(_minutes.Text.Trim(), out var minutes)) _error.Text = "Enter the minutes to add.";
            else _error.Text = await _offlineUnlock(_staffPhone.Text.Trim(), _staffCode.Text.Trim(), minutes,
                _method.SelectedItem?.ToString() ?? "cash", _upi.Visible ? _upi.Text.Trim() : null) ?? "";
            _staffCode.Text = "";
            _submitOffline.Enabled = !_busy;
        };
        Controls.Add(box);
        Resize += (_, _) => box.Location = new Point((ClientSize.Width - box.Width) / 2, (ClientSize.Height - box.Height) / 2);
        AcceptButton = _go;
        _go.Click += async (_, _) =>
        {
            _go.Enabled = false;
            _error.Text = await login(_phone.Text.Trim(), _pin.Text) ?? "";
            _pin.Text = ""; _go.Enabled = !_busy;
        };
        // anything that jumps in front (a popup, a hotkey we could not block) loses the foreground again within 0.5 s
        var keepFront = new System.Windows.Forms.Timer { Interval = 500 };
        keepFront.Tick += (_, _) =>
        {
            Alive.Send();
            if (!Visible) { LockDesktop.GiveBack(); return; }
            LockDesktop.Keep();
            if (WindowState == FormWindowState.Minimized) // Show desktop (Win+D) minimises windows
            { WindowState = FormWindowState.Normal; Bounds = SystemInformation.VirtualScreen; }
            Native.ToTop(Handle); // back above any newer always-on-top window, even one that did not take the focus
            if (Native.GetForegroundWindow() != Handle) Native.TakeForeground(Handle);
        };
        keepFront.Start();
    }

    async Task LoadOfflineRate()
    {
        try
        {
            var info = await new WatchdogPipeClient().GetFromJsonAsync<OfflineUnlockInfo>("/local/offline-unlock-info");
            _offlineRate.Text = info?.Rate is { } r
                ? $"Rate card: {r.BlockMin} min ₹{r.Paise30 / 100m:0.##}, {2 * r.BlockMin} min ₹{r.Paise60 / 100m:0.##}, {3 * r.BlockMin} min ₹{r.Paise90 / 100m:0.##}; then ₹{r.ExtraBlockPaise / 100m:0.##} per {r.BlockMin} min. Maximum per offline unlock: {info.MaxOfflineUnlockMinutes} min." // the owner sets the block length
                : "Offline unlock is not set up on this PC yet.";
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        { _offlineRate.Text = "Could not read the saved rate card. Please ask at the counter."; }
    }

    public void SetOffline(bool offline) => BeginInvoke(() =>
    {
        _staffUnlock.Visible = offline;
        if (!offline) _offlinePanel = false;
        foreach (var c in new Control[] { _offlineRate, _staffPhone, _staffCode, _minutes, _method, _submitOffline })
            c.Visible = offline && _offlinePanel;
        _upi.Visible = offline && _offlinePanel && _method.SelectedItem?.ToString() == "upi";
    });

    public void ShowLocked(string? message) => BeginInvoke(() =>
    {
        _message.Text = message ?? "Log in with your phone number and PIN.";
        _offlinePanel = false;
        foreach (var c in new Control[] { _offlineRate, _staffPhone, _staffCode, _minutes, _method, _submitOffline, _upi }) c.Visible = false;
        _go.Text = message?.StartsWith("Locked by the customer") == true ? "Unlock" : "Log in";
        Bounds = SystemInformation.VirtualScreen; // every monitor
        if (!Visible) { _error.Text = ""; _phone.Text = ""; Show(); LockDesktop.Show(true); }
        Native.TakeForeground(Handle);
        _phone.Focus();
    });

    public void Unlock() => BeginInvoke(() => { if (Visible) { LockDesktop.Show(false); Hide(); } });

    // nobody logs in while the last customer's apps and logins are being cleared
    public void SetBusy(bool busy) => BeginInvoke(() =>
    {
        _busy = busy;
        _go.Enabled = !busy;
        _staffUnlock.Enabled = !busy;
        _submitOffline.Enabled = !busy;
    });

    protected override void OnFormClosing(FormClosingEventArgs e) { if (e.CloseReason == CloseReason.UserClosing) e.Cancel = true; base.OnFormClosing(e); }
}

// The lock screen's own Windows desktop, like the Windows sign-in screen. Games in exclusive fullscreen, graphics-card
// overlays and Windows' own dialogs stay on the normal desktop, so they cannot sit above the lock screen.
// If Windows refuses any step, the lock screen stays a window on the normal desktop, as before, and the log says why.
// The watchdog ends a lock screen program that stops answering (B5.3 part 3). Each thread that must keep running (the main
// one, the lock screen's, each key blocker's) notes when it last ran; the lock screen's thread sends the oldest note to the
// watchdog once a second. Under full load the whole PC stalled for up to 9.1 s (measured), every thread at once, so after
// a late turn of its own the sender reports no stuck thread.
static class Alive
{
    static readonly Dictionary<int, long> Last = [];
    static readonly WatchdogPipeClient Pipe = new();
    static long _sent;
    static int _sending;
    public static void Tick() { lock (Last) Last[Environment.CurrentManagedThreadId] = Environment.TickCount64; }
    public static void Send()
    {
        Tick();
        var now = Environment.TickCount64;
        if (now - _sent < 1000 || Interlocked.Exchange(ref _sending, 1) == 1) return;
        long oldest;
        lock (Last) oldest = now - _sent > 2000 ? 0 : now - Last.Values.Min();
        _sent = now;
        _ = Task.Run(async () =>
        {
            try { using var _ = await Pipe.PostAsJsonAsync("/local/alive", new { oldest }); }
            catch (HttpRequestException) { } // the watchdog's silence rule covers it
            finally { _sending = 0; }
        });
    }
}

// Application.Run ends at a "quit" message, which any program of the same account can post, and WinForms then closes the
// thread's windows (read in its source). This loop does for these threads what Application.Run does, and skips "quit".
static class MessageLoop
{
    [ThreadStatic] static bool _told; // one log line per thread, however many quits arrive
    public static void RunForever()
    {
        while (true)
        {
            var got = GetMessage(out var msg, IntPtr.Zero, 0, 0);
            if (got == -1) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            if (got == 0) { if (!_told) Program.Log("a quit message was ignored"); _told = true; continue; }
            var m = Message.Create(msg.Window, (int)msg.Id, msg.W, msg.L);
            if (Application.FilterMessage(ref m)) continue;
            if (msg.Id is >= 0x0100 and <= 0x0109 && Control.FromChildHandle(msg.Window) is { } target // keys: Tab, Enter, shortcuts
                && target.PreProcessControlMessage(ref m) == PreProcessControlState.MessageProcessed) continue;
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }
    [StructLayout(LayoutKind.Sequential)] struct Msg { public IntPtr Window; public uint Id; public IntPtr W, L; public uint Time; public int X, Y; }
    [DllImport("user32.dll", EntryPoint = "GetMessageW", SetLastError = true)] static extern int GetMessage(out Msg msg, IntPtr window, uint first, uint last);
    [DllImport("user32.dll")] static extern bool TranslateMessage(ref Msg msg);
    [DllImport("user32.dll", EntryPoint = "DispatchMessageW")] static extern IntPtr DispatchMessage(ref Msg msg);
}

static class LockDesktop
{
    static IntPtr _own, _normal;
    static string _name = "";
    public static bool Own => _own != IntPtr.Zero;
    public static bool TestRefuseLockThread; // UI test: as if Windows moved the key blocker's thread and refused the lock screen's
    public static bool TestRefuseUnlock;     // UI test: as if Windows refused the normal desktop at the next unlock
    // Who may use the lock screen's desktop: Windows itself, admins (the owner's tools, the tests) and this program
    // through the handle it gets when it makes the desktop. Measured as a standard user: with these rights another
    // program of the same account cannot open the desktop for anything; with the rights Windows gives by itself it can
    // open it for everything. OW: the maker may read the rights, not change them.
    const string Rights = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;RC;;;OW)";

    public static void Make(bool testOnNormal)
    {
        if (!testOnNormal)
        {
            _normal = OpenDesktop("Default", 0, false, 0x0100 /*DESKTOP_SWITCHDESKTOP*/);
            // The process number in the name: a restarted program never meets the last one's desktop. The random part: no
            // other program can make a desktop with this name first. Windows would hand that one back, with its maker's
            // rights instead of ours, and not say so (measured).
            _name = $"CafeLock-{Environment.ProcessId}-{System.Security.Cryptography.RandomNumberGenerator.GetHexString(32)}";
            if (_normal != IntPtr.Zero && ProcessSecurity.ConvertStringSecurityDescriptorToSecurityDescriptor(Rights, 1, out var descriptor, out _))
            {
                var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
                _own = CreateDesktop(_name, IntPtr.Zero, IntPtr.Zero, 0, 0x10000000 /*GENERIC_ALL*/, ref security);
                ProcessSecurity.LocalFree(descriptor);   // keeps CreateDesktop's error for the log line below
            }
        }
        Program.Log(Own ? "lock screen has its own desktop"
            : testOnNormal ? "lock screen stays on the normal desktop (test switch)"
            : $"lock screen stays on the normal desktop: Windows refused the second desktop (error {Marshal.GetLastWin32Error()})");
    }

    // the key blocker's thread, then the lock screen's, call this before they make any window or hook (Windows moves no
    // thread that has one). A refusal for the first leaves both on the normal desktop.
    public static void MoveThreadHere(bool testRefused = false)
    {
        if (!Own || (!testRefused && SetThreadDesktop(_own))) return;
        Program.Log($"lock screen stays on the normal desktop: Windows refused to move its thread (error {Marshal.GetLastWin32Error()})");
        _own = IntPtr.Zero;
    }

    public static void Show(bool locked)
    {
        if (!Own) return;
        var given = !(TestRefuseUnlock && !locked) && SwitchDesktop(locked ? _own : _normal);
        if (!given) Program.Log($"could not give the screen to the {(locked ? "lock screen's" : "normal")} desktop (error {Marshal.GetLastWin32Error()})");
        if (!locked) TestRefuseUnlock = false;
        _owed = !locked && !given;
    }

    // Windows refuses to switch desktops while its own secure screen is up (measured: the screen that Ctrl+Alt+Del and
    // "lock this computer" show). A refused lock is asked again by Keep. A refused unlock is asked again here, by the same
    // timer: without it the customer stays on the lock screen's empty desktop while the time runs.
    static bool _owed; // an unlock still owes the normal desktop the screen
    public static void GiveBack()
    {
        if (!_owed || !SwitchDesktop(_normal)) return;
        _owed = false;
        Program.Log("the normal desktop has the screen (asked again after a refusal)");
    }

    // Any program can give the screen to the normal desktop while the PC is locked (measured), so the lock screen's
    // 0.5 s timer calls this. Asking for the desktop that already has the screen does nothing (measured: 0.02 ms,
    // no message reaches the lock screen, typing goes on), so it asks every time and never has to look first.
    static bool _refused; // one log line per refusal, not one every 0.5 s
    public static void Keep()
    {
        if (!Own) return;
        var refused = !SwitchDesktop(_own);
        if (refused && !_refused) Program.Log($"Windows refused to give the screen back to the lock screen's desktop (error {Marshal.GetLastWin32Error()}); asking again every 0.5 s");
        _refused = refused;
    }

    // Lockdown check E3b.L1 starts the program with this as Customer, a standard user. "make": make the desktop exactly as
    // the lock screen does, use the maker's own handle, then start this program once more, in the same Windows sign-in, to
    // try to open the desktop by name. 0 = made, own handle works, the other program was refused every time.
    public static int Test(string name)
    {
        if (name != "make")
        {
            // everything, switch the screen to it, read its windows, make a window, hooks, change its rights, read its rights
            foreach (var access in new uint[] { 0x10000000, 0x0100, 0x0001, 0x0002, 0x0008, 0x00040000, 0x00020000 })
            {
                if (OpenDesktop(name, 0, false, access) != IntPtr.Zero) return 3;   // opened
                if (Marshal.GetLastWin32Error() != 5) return 5;                      // refused, but not as "access denied"
            }
            return 0;
        }
        Make(false);
        if (!Own) return 1;
        var moved = false;
        var mover = new Thread(() => moved = SetThreadDesktop(_own));
        mover.Start(); mover.Join();
        if (!moved) return 2;
        using var other = Process.Start(Environment.ProcessPath!, ["--test-lock-desktop", _name]);
        return other.WaitForExit(30000) ? other.ExitCode : 4;
    }

    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("user32.dll", EntryPoint = "CreateDesktopW", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateDesktop(string name, IntPtr device, IntPtr mode, uint flags, uint access, ref SecurityAttributes security);
    [DllImport("user32.dll", EntryPoint = "OpenDesktopW", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenDesktop(string name, uint flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)] static extern bool SwitchDesktop(IntPtr desktop);
}

sealed class TimerWidget : Form
{
    readonly Label _text = new() { Name = "TimerText", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 18, FontStyle.Bold), ForeColor = Color.White };
    // the counter's note for this customer (for example: membership ends soon); hidden when there is none
    readonly Label _notice = new() { Name = "Notice", Dock = DockStyle.Top, Height = 0, Font = new Font("Segoe UI", 8), ForeColor = Color.Gold, TextAlign = ContentAlignment.MiddleCenter };
    readonly NotifyIcon _tray = new() { Icon = SystemIcons.Application, Visible = true, Text = "Cafe timer" };
    readonly Func<(PcState state, long elapsed, long? left)> _now;
    readonly Action _timeExpired;
    readonly HashSet<int> _warned = [];
    DateTime _peekUntil;

    public TimerWidget(Func<(PcState, long, long?)> now, Action logout, Action selfLock, Action timeExpired)
    {
        _now = now;
        _timeExpired = timeExpired;
        Name = "TimerWidget"; Text = "Cafe timer";
        FormBorderStyle = FormBorderStyle.None; ShowInTaskbar = false; TopMost = true;
        BackColor = Color.FromArgb(20, 20, 28); Opacity = 0.9; Size = new Size(190, 84); StartPosition = FormStartPosition.Manual;
        var wa = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
        var buttons = new TableLayoutPanel { Dock = DockStyle.Bottom, Height = 28, ColumnCount = 2 };
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50)); buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var away = new Button { Name = "SelfLock", Text = "Lock", Dock = DockStyle.Fill, FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Margin = Padding.Empty };
        var bye = new Button { Name = "Logout", Text = "Log out", Dock = DockStyle.Fill, FlatStyle = FlatStyle.Flat, ForeColor = Color.White, Margin = Padding.Empty };
        away.Click += (_, _) => selfLock();
        bye.Click += (_, _) => logout();
        buttons.Controls.Add(away, 0, 0); buttons.Controls.Add(bye, 1, 0);
        Controls.Add(_text); Controls.Add(_notice); Controls.Add(buttons);
        _tray.MouseClick += (_, _) => { _peekUntil = DateTime.UtcNow.AddSeconds(5); if (!_now().state.Locked) Visible = true; };
        var tick = new System.Windows.Forms.Timer { Interval = 1000 };
        tick.Tick += (_, _) => Tick();
        tick.Start();
    }

    public void Tick()
    {
        var (state, elapsed, left) = _now();
        if (state.Locked) { if (Visible) Hide(); return; }
        if (state.LockWhenTimeRunsOut && left is long remaining && remaining <= 0)
        {
            _timeExpired();
            return;
        }
        if ((state.Notice ?? "") != _notice.Text)
        {
            _notice.Text = state.Notice ?? "";
            _notice.Height = state.Notice is null ? 0 : 44;
            Height = 84 + _notice.Height;
            var wa = Screen.PrimaryScreen!.WorkingArea;
            Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
            if (state.Notice is not null) _tray.ShowBalloonTip(8000, "From the counter", state.Notice, ToolTipIcon.Info);
        }
        var shown = left is long l ? (l > 0 ? Program.Fmt(l) + " left" : "Time over") : Program.Fmt(elapsed);
        _text.Text = shown; _tray.Text = "Cafe timer " + shown;
        var warningMinutes = state.LockWhenTimeRunsOut ? new[] { 5, 1 } : new[] { 10, 5, 1 };
        foreach (var m in warningMinutes) // keep today's warnings when the setting is off
            if (left is long x && x <= m * 60 && x > 0 && _warned.Add(m))
            {
                var message = state.LockWhenTimeRunsOut
                    ? $"{m} minute{(m > 1 ? "s" : "")} left. Please ask at the counter for more time."
                    : $"{m} minute{(m > 1 ? "s" : "")} left";
                _tray.ShowBalloonTip(5000, "Time left", message, ToolTipIcon.Info);
            }
        if (left is null || left > 600) _warned.Clear();
        var gameInFront = Native.GameInFront(Handle, out var frontClass, out var frontProcess);
        var show = DateTime.UtcNow < _peekUntil || !gameInFront;
        if (Visible != show)
        {
            Program.Log($"timer {(show ? "shown" : "hidden")}; front class={frontClass} process={frontProcess}");
            Visible = show;
        }
    }

    protected override bool ShowWithoutActivation => true; // never take focus from a game
    protected override CreateParams CreateParams { get { var p = base.CreateParams; p.ExStyle |= 0x08000000 | 0x00000080; return p; } } // NOACTIVATE | TOOLWINDOW
    protected override void OnFormClosing(FormClosingEventArgs e) { if (e.CloseReason == CloseReason.UserClosing) e.Cancel = true; base.OnFormClosing(e); }
}

// Blocks the keys that leave the lock screen: Win, Alt+Tab, Alt+Esc, Alt+F4, Alt+Space, Ctrl+Esc.
// Ctrl+Alt+Del and Win+L cannot be blocked by any program; Windows policy handles those in B3.
static class KeyBlocker
{
    delegate IntPtr HookProc(int code, IntPtr wParam, IntPtr lParam);
    static HookProc? _proc; // kept alive so the garbage collector cannot free the callback
    static volatile bool _on;

    // The hook gets its own thread and message loop. On the screen's thread, any slow moment there (taking the
    // focus back, a redraw) delays every key; Windows lets a late key through and, after a few, drops the hook.
    // The thread sits on the lock screen's desktop: a hook sees only the keys typed on its own thread's desktop (measured).
    // Without it, Ctrl+Shift+Esc opened Task Manager on the lock screen's desktop and Win+U opened Settings (measured).
    public static void Install()
    {
        _on = true; // the PC starts locked
        var ready = new ManualResetEventSlim();
        var ok = false;
        var thread = new Thread(() =>
        {
            LockDesktop.MoveThreadHere();
            _proc ??= Hook; // one for every key blocker thread: Windows keeps calling it, so it must never be collected
            ok = SetWindowsHookEx(13 /*WH_KEYBOARD_LL*/, _proc, GetModuleHandle(null), 0) != IntPtr.Zero;
            ready.Set();
            if (!ok) return;
            var alive = new System.Windows.Forms.Timer { Interval = 500 };
            alive.Tick += (_, _) => Alive.Tick();
            alive.Start();
            MessageLoop.RunForever(); // Windows calls the hook through this thread's message loop
        }) { IsBackground = true, Name = "key blocker" };
        thread.Start();
        ready.Wait();
        if (!ok) throw new InvalidOperationException("keyboard hook failed");
    }

    public static void Follow(Form lockScreen)
    {
        _on = lockScreen.Visible;
        lockScreen.VisibleChanged += (_, _) => _on = lockScreen.Visible;
    }

    static IntPtr Hook(int code, IntPtr wParam, IntPtr lParam)
    {
        if (code >= 0 && _on)
        {
            var vk = Marshal.ReadInt32(lParam);
            var alt = (Marshal.ReadInt32(lParam, 8) & 0x20) != 0;
            var ctrl = (GetAsyncKeyState(0x11) & 0x8000) != 0;
            if (vk is 0x5B or 0x5C || (alt && vk is 0x09 or 0x1B or 0x73 or 0x20) || (ctrl && vk == 0x1B)) return 1;
        }
        return CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
    }

    [DllImport("user32.dll")] static extern IntPtr SetWindowsHookEx(int id, HookProc proc, IntPtr mod, uint thread);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] static extern short GetAsyncKeyState(int key);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr GetModuleHandle(string? name);
}

static class Native
{
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr pid);
    [DllImport("user32.dll")] static extern bool AttachThreadInput(uint a, uint b, bool attach);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out Rect r);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int max);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint processId);
    [StructLayout(LayoutKind.Sequential)] struct Rect { public int L, T, R, B; }

    // Windows refuses SetForegroundWindow from a background program unless it joins the foreground thread's input.
    // The Windows 11 Start and Search panels sit above every normal window, so if one is open, Escape closes it first.
    public static void TakeForeground(IntPtr h)
    {
        var fg = GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero);
        var me = GetCurrentThreadId();
        if (fg != me) AttachThreadInput(me, fg, true);
        SetForegroundWindow(h);
        if (fg != me) AttachThreadInput(me, fg, false);
        if (GetForegroundWindow() != h) { keybd_event(0x1B, 0, 0, 0); keybd_event(0x1B, 0, 2, 0); SetForegroundWindow(h); } // Escape down, up
        // a window that just opened (an updater, a console) can keep Windows from giving the focus back; a key press of
        // our own lifts that, and a lone Alt does nothing else (the key blocker only stops Alt with Tab, Esc, F4, Space)
        if (GetForegroundWindow() != h) { keybd_event(0x12, 0, 0, 0); SetForegroundWindow(h); keybd_event(0x12, 0, 2, 0); }
    }
    [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint flags, nuint extra);

    public static void ToTop(IntPtr h) => SetWindowPos(h, new IntPtr(-1) /*HWND_TOPMOST*/, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0010); // NOSIZE | NOMOVE | NOACTIVATE
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);

    public static bool GameInFront(IntPtr self, out string className, out string processName)
    {
        var h = GetForegroundWindow();
        className = "none";
        processName = "none";
        if (h == IntPtr.Zero) return false;

        var cls = new System.Text.StringBuilder(64);
        GetClassName(h, cls, cls.Capacity);
        className = cls.ToString();
        GetWindowThreadProcessId(h, out var processId);
        try
        {
            using var process = Process.GetProcessById((int)processId);
            processName = process.ProcessName;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }

        // Hidden windows and our own lock screen/agent windows are never games.
        if (!IsWindowVisible(h) || processId == Environment.ProcessId || h == self || h == GetShellWindow()) return false;
        if (className is "Progman" or "WorkerW" or "Shell_TrayWnd") return false;
        if (!GetWindowRect(h, out var r)) return false;
        var m = Screen.FromHandle(h).Bounds; // borderless-window games cover the whole monitor
        return r.L <= m.Left && r.T <= m.Top && r.R >= m.Right && r.B >= m.Bottom;
    }
}
