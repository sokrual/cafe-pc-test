using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Cafe.Agent;

// The gaming PC program: a lock screen until a customer logs in, then a small timer that hides during games.
// It asks the admin PC every 2 s what to show; the admin PC is always right about time and money.
// Usage: Cafe.Agent --server https://ADMIN-PC:5443 [--token-file pc.token] [--pin-file server.pin] [--name "Gaming Cafe"] [--logs dir]
static class Program
{
    static string _logDir = "";

    [STAThread]
    static void Main(string[] args)
    {
        string? Arg(string n) => Array.IndexOf(args, n) is var i and >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        _logDir = Arg("--logs") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cafe", "logs");
        Log($"started v{typeof(Program).Assembly.GetName().Version}");
        ApplicationConfiguration.Initialize();
        Application.Run(new Agent(Arg("--name") ?? "Gaming Cafe"));
    }

    // never logs PINs or tokens; a log that can't be written must not stop the PC program
    public static void Log(string line)
    {
        try { Directory.CreateDirectory(_logDir); File.AppendAllText(Path.Combine(_logDir, $"agent-{DateTime.Now:yyyyMMdd}.log"), $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    public static string Fmt(long sec) => sec >= 3600 ? $"{sec / 3600}:{sec / 60 % 60:00}:{sec % 60:00}" : $"{sec / 60:00}:{sec % 60:00}";
}

public record PcState(bool Locked, string? Message, long? Session, string? Mode, long ElapsedSec, long? LeftSec, bool SelfLocked = false, bool LockWhenTimeRunsOut = false);
record ErrorBody(string Error);
record OfflineUnlockReply(bool Success, string? Error, long? Step);
record OfflineUnlockInfo(OfflineUnlockRate? Rate, int EnabledAccounts, DateTime? LockedUntil, int PendingSales);
record OfflineUnlockRate(long Paise30, long Paise60, long Paise90, long ExtraBlockPaise, int MinimumMin, int BlockMin);

static class LockSetting
{
    const string KeyPath = @"Software\GamingCafe\Agent";
    public static bool Read()
    {
        try { using var key = Registry.CurrentUser.OpenSubKey(KeyPath); return key?.GetValue("LockWhenTimeRunsOut") is int value && value == 1; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return false; }
    }
    public static void Save(bool enabled)
    {
        try
        {
            if (Read() == enabled) return;
            using var key = Registry.CurrentUser.CreateSubKey(KeyPath);
            key?.SetValue("LockWhenTimeRunsOut", enabled ? 1 : 0, RegistryValueKind.DWord);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { Program.Log($"could not remember the time-lock setting (error code {e.HResult & 0xffff})"); }
    }
}

sealed class Agent : ApplicationContext
{
    readonly WatchdogPipeClient _watchdog = new();
    readonly LockScreen _lock;
    readonly TimerWidget _timer;
    PcState _state = new(true, null, null, null, 0, null, LockWhenTimeRunsOut: LockSetting.Read()); // locked until the admin PC says otherwise
    DateTime _stateAt = DateTime.UtcNow;
    readonly List<(string path, Stopwatch since)> _queue = []; // actions made while the admin PC was unreachable
    bool _online = true;
    // installed cafe PCs only: the SYSTEM watchdog cleans the Customer account when this note appears, then deletes it
    static readonly string WipeNote = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "wipe", "request");

    public Agent(string name)
    {
        _lock = new LockScreen(name, Login, OfflineUnlock);
        _timer = new TimerWidget(Now, () => Send("/pc/logout", lockNow: true), () => Send("/pc/selflock", lockNow: true), () => Apply(_state with { Locked = true, Message = "Time is up. Please ask at the counter." }));
        KeyBlocker.Install(() => _lock.Visible);
        var poll = new System.Windows.Forms.Timer { Interval = 2000 };
        poll.Tick += async (_, _) =>
        {
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
            var serverState = await _watchdog.GetFromJsonAsync<PcState>("/pc/state");
            var offlineInfo = await _watchdog.GetFromJsonAsync<OfflineUnlockInfo>("/local/offline-unlock-info");
            if (offlineInfo?.PendingSales > 0)
            {
                _online = true;
                _lock.SetOffline(false);
                return; // never replay a logout or overwrite the local timer before the paid sale is reconciled
            }
            if (_state.Session == -1 && serverState is { Session: null })
                _queue.RemoveAll(item => item.path == "/pc/logout");
            if (_state.Session == -1 && serverState is not null)
                Apply(serverState); // the server decides whether the offline walk-in was accepted
            while (_queue.Count > 0) // replay in order; the admin PC is told how long ago each one happened
            {
                var (path, since) = _queue[0];
                using var r = await _watchdog.PostAsync(path == "/pc/logout" ? $"{path}?ago={(long)since.Elapsed.TotalSeconds}" : path, null);
                Program.Log($"sent queued {path} ({(long)since.Elapsed.TotalSeconds}s late): {(int)r.StatusCode}");
                _queue.RemoveAt(0); // a 400 (e.g. already logged out at the counter) is final too
            }
            if (await _watchdog.GetFromJsonAsync<PcState>("/pc/state") is { } s)
            {
                LockSetting.Save(s.LockWhenTimeRunsOut);
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

    void Apply(PcState s)
    {
        if (WipePending()) s = s with { Locked = true, Message = WipeMessage() };
        _lock.SetBusy(WipePending());
        if (_state.Session is > 0 && s.Session is null) AskForWipe(); // a server session ended, here or at the counter
        if (s.Locked != _state.Locked) Program.Log(s.Locked ? $"locked: {s.Message}" : $"unlocked, session {s.Session} ({s.Mode})");
        (_state, _stateAt) = (s, DateTime.UtcNow);
        if (s.Locked) { _timer.Hide(); _lock.ShowLocked(s.Message); }
        else { _lock.Hide(); _timer.Tick(); }
    }

    async Task<string?> Login(string phone, string pin)
    {
        if (WipePending()) return WipeMessage();
        try
        {
            using var r = await _watchdog.PostAsJsonAsync("/pc/login", new { phone, pin });
            if (!r.IsSuccessStatusCode) return (await r.Content.ReadFromJsonAsync<ErrorBody>())?.Error ?? "Could not log in. Please try again.";
            var state = (await r.Content.ReadFromJsonAsync<PcState>())!;
            LockSetting.Save(state.LockWhenTimeRunsOut);
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

    // logout and customer lock: done now if the admin PC answers, otherwise queued and the screen locks anyway
    async void Send(string path, bool lockNow)
    {
        if (path == "/pc/logout") AskForWipe(); // also when the admin PC is offline
        _queue.Add((path, Stopwatch.StartNew())); // shortcut: the queue lives in memory; if this program is killed while offline the logout is lost and staff close the session
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

    public LockScreen(string cafeName, Func<string, string, Task<string?>> login,
        Func<string, string, int, string, string?, Task<string?>> offlineUnlock)
    {
        _offlineUnlock = offlineUnlock;
        Name = "LockScreen"; Text = cafeName;
        FormBorderStyle = FormBorderStyle.None; ShowInTaskbar = false; TopMost = true;
        StartPosition = FormStartPosition.Manual; BackColor = Color.FromArgb(14, 14, 22);
        // the cafe's logo (built into the program); the name in text if it is ever missing
        Control title = new Label { Text = "Gaming Cafe", AutoSize = false, Width = 520, Height = 70, ForeColor = Color.White, Font = new Font("Segoe UI", 28, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter };
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
        keepFront.Tick += (_, _) => { if (Visible && Native.GetForegroundWindow() != Handle) Native.TakeForeground(Handle); };
        keepFront.Start();
    }

    async Task LoadOfflineRate()
    {
        try
        {
            var info = await new WatchdogPipeClient().GetFromJsonAsync<OfflineUnlockInfo>("/local/offline-unlock-info");
            _offlineRate.Text = info?.Rate is { } r
                ? $"Rate card: 30 min ₹{r.Paise30 / 100m:0.##}, 60 min ₹{r.Paise60 / 100m:0.##}, 90 min ₹{r.Paise90 / 100m:0.##}; then ₹{r.ExtraBlockPaise / 100m:0.##} per {r.BlockMin} min"
                : "Offline unlock is not set up on this PC yet.";
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        { _offlineRate.Text = "Could not read the saved rate card. Please ask at the counter."; }
    }

    public void SetOffline(bool offline)
    {
        _staffUnlock.Visible = offline;
        if (!offline) _offlinePanel = false;
        foreach (var c in new Control[] { _offlineRate, _staffPhone, _staffCode, _minutes, _method, _submitOffline })
            c.Visible = offline && _offlinePanel;
        _upi.Visible = offline && _offlinePanel && _method.SelectedItem?.ToString() == "upi";
    }

    public void ShowLocked(string? message)
    {
        _message.Text = message ?? "Log in with your phone number and PIN.";
        _offlinePanel = false;
        foreach (var c in new Control[] { _offlineRate, _staffPhone, _staffCode, _minutes, _method, _submitOffline, _upi }) c.Visible = false;
        _go.Text = message?.StartsWith("Locked by the customer") == true ? "Unlock" : "Log in";
        Bounds = SystemInformation.VirtualScreen; // every monitor
        if (!Visible) { _error.Text = ""; _phone.Text = ""; Show(); }
        Native.TakeForeground(Handle);
        _phone.Focus();
    }

    // nobody logs in while the last customer's apps and logins are being cleared
    public void SetBusy(bool busy)
    {
        _busy = busy;
        _go.Enabled = !busy;
        _staffUnlock.Enabled = !busy;
        _submitOffline.Enabled = !busy;
    }

    protected override void OnFormClosing(FormClosingEventArgs e) { if (e.CloseReason == CloseReason.UserClosing) e.Cancel = true; base.OnFormClosing(e); }
}

sealed class TimerWidget : Form
{
    readonly Label _text = new() { Name = "TimerText", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 18, FontStyle.Bold), ForeColor = Color.White };
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
        Controls.Add(_text); Controls.Add(buttons);
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
    static Func<bool> _active = () => false;

    public static void Install(Func<bool> active)
    {
        _active = active; _proc = Hook;
        if (SetWindowsHookEx(13 /*WH_KEYBOARD_LL*/, _proc, GetModuleHandle(null), 0) == IntPtr.Zero) throw new InvalidOperationException("keyboard hook failed");
    }

    static IntPtr Hook(int code, IntPtr wParam, IntPtr lParam)
    {
        if (code >= 0 && _active())
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
    }
    [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint flags, nuint extra);

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
