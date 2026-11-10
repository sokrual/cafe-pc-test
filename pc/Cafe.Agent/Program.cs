using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Cafe.Agent;

// The gaming PC program: a lock screen until a customer logs in, then a small timer that hides during games.
// It asks the admin PC every 2 s what to show; the admin PC is always right about time and money.
// Usage: Cafe.Agent --server https://ADMIN-PC:5443 [--token-file pc.token] [--pin-file server.pin] [--name "Shinzx Gaming Hub"] [--logs dir]
static class Program
{
    static string _logDir = "";

    [STAThread]
    static void Main(string[] args)
    {
        string? Arg(string n) => Array.IndexOf(args, n) is var i and >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        string Read(string flag, string file) => File.ReadAllText(Arg(flag) ?? Path.Combine(AppContext.BaseDirectory, file)).Trim();
        _logDir = Arg("--logs") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cafe", "logs");
        Log($"started v{typeof(Program).Assembly.GetName().Version}");
        ApplicationConfiguration.Initialize();
        Application.Run(new Agent(new Uri(Arg("--server") ?? "https://127.0.0.1:5443"), Read("--token-file", "pc.token"), Read("--pin-file", "server.pin"), Arg("--name") ?? "Shinzx Gaming Hub"));
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

sealed class Agent : ApplicationContext
{
    readonly HttpClient _http;
    readonly LockScreen _lock;
    readonly TimerWidget _timer;
    PcState _state = new(true, null, null, null, 0, null); // locked until the admin PC says otherwise
    DateTime _stateAt = DateTime.UtcNow;
    readonly List<(string path, Stopwatch since)> _queue = []; // actions made while the admin PC was unreachable
    bool _online = true;
    // installed cafe PCs only: the SYSTEM watchdog cleans the Customer account when this note appears, then deletes it
    static readonly string WipeNote = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ShinzxCafe", "wipe", "request");

    public Agent(Uri server, string token, string pin, string name)
    {
        // only the admin PC's own certificate is accepted (pinned SHA-256), so nobody can pretend to be the counter
        var tls = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert is not null && Convert.ToHexString(SHA256.HashData(cert.RawData)) == pin };
        _http = new HttpClient(tls) { BaseAddress = server, Timeout = TimeSpan.FromSeconds(3) };
        _http.DefaultRequestHeaders.Add("X-Pc-Token", token);
        _lock = new LockScreen(name, Login);
        _timer = new TimerWidget(Now, () => Send("/pc/logout", lockNow: true), () => Send("/pc/selflock", lockNow: true));
        KeyBlocker.Install(() => _lock.Visible);
        var poll = new System.Windows.Forms.Timer { Interval = 2000 };
        poll.Tick += async (_, _) =>
        {
            var pending = WipePending();
            _lock.SetBusy(pending);
            if (pending) Apply(_state with { Locked = true, Message = "Please ask at the counter." });
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
            while (_queue.Count > 0) // replay in order; the admin PC is told how long ago each one happened
            {
                var (path, since) = _queue[0];
                using var r = await _http.PostAsync(path == "/pc/logout" ? $"{path}?ago={(long)since.Elapsed.TotalSeconds}" : path, null);
                Program.Log($"sent queued {path} ({(long)since.Elapsed.TotalSeconds}s late): {(int)r.StatusCode}");
                _queue.RemoveAt(0); // a 400 (e.g. already logged out at the counter) is final too
            }
            if (await _http.GetFromJsonAsync<PcState>("/pc/state") is { } s) Apply(s);
            if (!_online) Program.Log("admin PC reachable again");
            _online = true;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            if (_online) Program.Log($"admin PC unreachable, timing goes on here: {e.Message}");
            _online = false; // the session keeps running on the admin PC; this screen keeps counting from the last state
        }
    }

    void Apply(PcState s)
    {
        if (WipePending()) s = s with { Locked = true, Message = "Please ask at the counter." };
        if (_state.Session is not null && s.Session is null) AskForWipe(); // logged out, here or at the counter
        if (s.Locked != _state.Locked) Program.Log(s.Locked ? $"locked: {s.Message}" : $"unlocked, session {s.Session} ({s.Mode})");
        (_state, _stateAt) = (s, DateTime.UtcNow);
        if (s.Locked) { _timer.Hide(); _lock.ShowLocked(s.Message); }
        else { _lock.Hide(); _timer.Tick(); }
    }

    async Task<string?> Login(string phone, string pin)
    {
        if (WipePending()) return "Please ask at the counter.";
        try
        {
            using var r = await _http.PostAsJsonAsync("/pc/login", new { phone, pin });
            if (!r.IsSuccessStatusCode) return (await r.Content.ReadFromJsonAsync<ErrorBody>())?.Error ?? "Could not log in. Please try again.";
            Apply((await r.Content.ReadFromJsonAsync<PcState>())!);
            return null;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { return "This PC cannot reach the counter right now. Please ask at the counter."; }
    }

    static bool WipePending()
    {
        try { _ = File.GetAttributes(WipeNote); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        catch { return true; }
    }

    static void AskForWipe()
    {
        if (!Directory.Exists(Path.GetDirectoryName(WipeNote))) return; // not an installed cafe PC (tests, development)
        try { File.WriteAllText(WipeNote, ""); Program.Log("asked for the logout clean-up"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Program.Log($"could not ask for the logout clean-up: {e.Message}"); }
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
    readonly Label _error = new() { Name = "Error", AutoSize = false, Width = 520, Height = 40, ForeColor = Color.Salmon, Font = new Font("Segoe UI", 12), TextAlign = ContentAlignment.MiddleCenter };

    public LockScreen(string cafeName, Func<string, string, Task<string?>> login)
    {
        Name = "LockScreen"; Text = cafeName;
        FormBorderStyle = FormBorderStyle.None; ShowInTaskbar = false; TopMost = true;
        StartPosition = FormStartPosition.Manual; BackColor = Color.FromArgb(14, 14, 22);
        var title = new Label { Text = cafeName, AutoSize = false, Width = 520, Height = 70, ForeColor = Color.White, Font = new Font("Segoe UI", 28, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter };
        var box = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        foreach (Control c in new Control[] { title, _message, _phone, _pin, _go, _error }) { c.Margin = new Padding(100, 8, 100, 8); box.Controls.Add(c); }
        Controls.Add(box);
        Resize += (_, _) => box.Location = new Point((ClientSize.Width - box.Width) / 2, (ClientSize.Height - box.Height) / 2);
        AcceptButton = _go;
        _go.Click += async (_, _) =>
        {
            _go.Enabled = false;
            _error.Text = await login(_phone.Text.Trim(), _pin.Text) ?? "";
            _pin.Text = ""; _go.Enabled = true;
        };
        // anything that jumps in front (a popup, a hotkey we could not block) loses the foreground again within 0.5 s
        var keepFront = new System.Windows.Forms.Timer { Interval = 500 };
        keepFront.Tick += (_, _) => { if (Visible && Native.GetForegroundWindow() != Handle) Native.TakeForeground(Handle); };
        keepFront.Start();
    }

    public void ShowLocked(string? message)
    {
        _message.Text = message ?? "Log in with your phone number and PIN.";
        _go.Text = message?.StartsWith("Locked by the customer") == true ? "Unlock" : "Log in";
        Bounds = SystemInformation.VirtualScreen; // every monitor
        if (!Visible) { _error.Text = ""; _phone.Text = ""; Show(); }
        Native.TakeForeground(Handle);
        _phone.Focus();
    }

    const string Cleaning = "Please ask at the counter.";
    // nobody logs in while the last customer's apps and logins are being cleared
    public void SetBusy(bool busy)
    {
        if (busy == (_error.Text == Cleaning)) return;
        _go.Enabled = !busy; _error.Text = busy ? Cleaning : "";
    }

    protected override void OnFormClosing(FormClosingEventArgs e) { if (e.CloseReason == CloseReason.UserClosing) e.Cancel = true; base.OnFormClosing(e); }
}

sealed class TimerWidget : Form
{
    readonly Label _text = new() { Name = "TimerText", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 18, FontStyle.Bold), ForeColor = Color.White };
    readonly NotifyIcon _tray = new() { Icon = SystemIcons.Application, Visible = true, Text = "Cafe timer" };
    readonly Func<(PcState state, long elapsed, long? left)> _now;
    readonly HashSet<int> _warned = [];
    DateTime _peekUntil;

    public TimerWidget(Func<(PcState, long, long?)> now, Action logout, Action selfLock)
    {
        _now = now;
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
        var show = DateTime.UtcNow < _peekUntil || !Native.GameInFront(Handle);
        if (Visible != show) Visible = show;
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
    [DllImport("shell32.dll")] static extern int SHQueryUserNotificationState(out int state);
    [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out Rect r);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int max);
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

    public static bool GameInFront(IntPtr self)
    {
        if (SHQueryUserNotificationState(out var st) == 0 && st is 2 or 3 or 4) return true; // full screen, D3D exclusive, presentation
        var h = GetForegroundWindow();
        if (h == IntPtr.Zero || h == self || h == GetShellWindow()) return false;
        var cls = new System.Text.StringBuilder(64);
        GetClassName(h, cls, cls.Capacity);
        if (cls.ToString() is "Progman" or "WorkerW" or "Shell_TrayWnd") return false;
        if (!GetWindowRect(h, out var r)) return false;
        var m = Screen.FromHandle(h).Bounds; // borderless-window games cover the whole monitor
        return r.L <= m.Left && r.T <= m.Top && r.R >= m.Right && r.B >= m.Bottom;
    }
}
