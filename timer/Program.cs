using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ShinzxTimerTest;

// Phase 0 test build: desktop stopwatch that hides in the tray while a game is in front.
// With --log it also records every hide/show, missed game detections, focus steals and
// up to 3 spoken test messages during real play (T0.1 + T0.3), so nobody has to watch it.
static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        if (args.Contains("--selftest")) { Environment.Exit(SelfTest() ? 0 : 1); }
        var expires = Arg(args, "--expires");
        // shortcut: test build stops itself after the expiry date, in case FINISH-TEST is never run
        if (expires != null && DateTime.Now > DateTime.Parse(expires, System.Globalization.CultureInfo.InvariantCulture)) return;
        ApplicationConfiguration.Initialize();
        Application.Run(new TimerWidget(Arg(args, "--log"), Arg(args, "--games")));
    }

    static string? Arg(string[] a, string key) { var i = Array.IndexOf(a, key); return i >= 0 && i + 1 < a.Length ? a[i + 1] : null; }

    public static string Fmt(TimeSpan t) =>
        t.TotalHours >= 1 ? $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}" : $"{t.Minutes:00}:{t.Seconds:00}";

    // Voice rule for the test: speak only after a game has been in front for 2 min, at most once an hour, 3 times total.
    public static bool ShouldSpeak(TimeSpan gameFor, TimeSpan sinceLast, int spoken) =>
        spoken < 3 && gameFor >= TimeSpan.FromMinutes(2) && sinceLast >= TimeSpan.FromHours(1);

    // Release builds strip Debug.Assert, so check explicitly; exit code 0 = pass.
    static bool SelfTest() =>
        Fmt(TimeSpan.Zero) == "00:00" &&
        Fmt(TimeSpan.FromSeconds(59)) == "00:59" &&
        Fmt(TimeSpan.FromMinutes(61) + TimeSpan.FromSeconds(5)) == "1:01:05" &&
        Fmt(TimeSpan.FromHours(25)) == "25:00:00" &&
        !ShouldSpeak(TimeSpan.FromMinutes(1), TimeSpan.MaxValue, 0) &&
        ShouldSpeak(TimeSpan.FromMinutes(2), TimeSpan.MaxValue, 0) &&
        !ShouldSpeak(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), 1) &&
        !ShouldSpeak(TimeSpan.FromMinutes(5), TimeSpan.MaxValue, 3);
}

sealed class TimerWidget : Form
{
    readonly Stopwatch _clock = Stopwatch.StartNew();
    readonly Label _text = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 20, FontStyle.Bold), ForeColor = Color.White };
    readonly NotifyIcon _tray = new() { Icon = SystemIcons.Application, Visible = true, Text = "Shinzx timer" };
    readonly System.Windows.Forms.Timer _tick = new() { Interval = 1000 };
    readonly string? _log;
    readonly HashSet<string> _games = new(StringComparer.OrdinalIgnoreCase);
    bool _peek; DateTime _peekUntil;
    IntPtr _lastFg; DateTime? _gameSince; DateTime _lastSpoke = DateTime.MinValue; int _spoken;
    System.Speech.Synthesis.SpeechSynthesizer? _tts;

    public TimerWidget(string? logDir, string? gamesFile)
    {
        if (logDir != null) _log = Path.Combine(logDir, $"timer-{Environment.UserName}.log");
        if (gamesFile != null && File.Exists(gamesFile)) _games.UnionWith(File.ReadAllLines(gamesFile).Where(l => l.Length > 0));
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        BackColor = Color.FromArgb(20, 20, 28);
        Opacity = 0.85;
        Size = new Size(170, 56);
        StartPosition = FormStartPosition.Manual;
        var wa = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
        Controls.Add(_text);
        _tray.MouseClick += (_, _) => { _peek = true; _peekUntil = DateTime.UtcNow.AddSeconds(5); Visible = true; Log("PEEK"); };
        _tick.Tick += (_, _) => Tick();
        _tick.Start();
        Log($"START games_known={_games.Count}");
        Tick();
    }

    void Log(string msg)
    {
        if (_log == null) return;
        try { File.AppendAllText(_log, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\t{msg}{Environment.NewLine}"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { } // a missed log line must never crash the timer
    }

    void Tick()
    {
        var s = Program.Fmt(_clock.Elapsed);
        _text.Text = s;
        _tray.Text = "Shinzx timer " + s;
        if (_peek && DateTime.UtcNow > _peekUntil) _peek = false;

        var fg = Native.GetForegroundWindow();
        if (fg == Handle) Log("FOCUS_STOLEN"); // must never happen: the widget is no-activate
        var game = Native.GameInFront(fg, Handle);
        if (fg != _lastFg)
        {
            _lastFg = fg;
            var name = Native.ProcessName(fg);
            Log($"FG {name} game={game}");
            if (!game && _games.Contains(name)) Log($"MISSED {name}"); // a known game is in front but was not detected
        }

        _gameSince = game ? _gameSince ?? DateTime.Now : null;
        if (_log != null && game && Program.ShouldSpeak(DateTime.Now - _gameSince!.Value, DateTime.Now - _lastSpoke, _spoken)) Speak(fg);

        var show = _peek || !game;
        if (Visible != show) { Visible = show; Log(show ? "SHOW" : "HIDE"); }
    }

    void Speak(IntPtr fgBefore)
    {
        _spoken++; _lastSpoke = DateTime.Now;
        Log($"VOICE_START {_spoken} fg={Native.ProcessName(fgBefore)}");
        try { (_tts ??= new System.Speech.Synthesis.SpeechSynthesizer()).SetOutputToDefaultAudioDevice(); }
        catch (Exception e) { Log($"VOICE_DONE {_spoken} same_window=True error={e.Message}"); return; } // no sound device must not crash the timer
        System.Media.SystemSounds.Asterisk.Play();
        _tts.SpeakCompleted += Done;
        _tts.SpeakAsync("Shinzx Gaming Hub test message. No action needed.");
        void Done(object? _, System.Speech.Synthesis.SpeakCompletedEventArgs e)
        {
            _tts!.SpeakCompleted -= Done;
            var after = Native.GetForegroundWindow();
            Log($"VOICE_DONE {_spoken} same_window={after == fgBefore} error={e.Error?.Message ?? "none"}");
        }
    }

    // Never take focus from a game.
    protected override bool ShowWithoutActivation => true;
    protected override CreateParams CreateParams
    {
        get { var p = base.CreateParams; p.ExStyle |= 0x08000000 /*NOACTIVATE*/ | 0x00000080 /*TOOLWINDOW*/; return p; }
    }

    protected override void OnFormClosed(FormClosedEventArgs e) { Log("STOP"); _tray.Visible = false; _tray.Dispose(); _tts?.Dispose(); base.OnFormClosed(e); }
}

static class Native
{
    [DllImport("shell32.dll")] static extern int SHQueryUserNotificationState(out int state);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out Rect r);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int max);
    [StructLayout(LayoutKind.Sequential)] struct Rect { public int L, T, R, B; }

    public static string ProcessName(IntPtr h)
    {
        if (h == IntPtr.Zero) return "none";
        GetWindowThreadProcessId(h, out var pid);
        try { return Process.GetProcessById((int)pid).ProcessName; } catch (Exception e) when (e is ArgumentException or InvalidOperationException) { return "exited"; }
    }

    public static bool GameInFront(IntPtr h, IntPtr self)
    {
        // 2 = full-screen app, 3 = exclusive full-screen Direct3D, 4 = presentation mode
        if (SHQueryUserNotificationState(out var st) == 0 && st is 2 or 3 or 4) return true;
        if (h == IntPtr.Zero || h == self || h == GetShellWindow()) return false;
        var cls = new System.Text.StringBuilder(64);
        GetClassName(h, cls, cls.Capacity);
        if (cls.ToString() is "Progman" or "WorkerW" or "Shell_TrayWnd") return false;
        // borderless-window games don't set the states above, so also treat "covers the whole monitor" as a game
        if (!GetWindowRect(h, out var r)) return false;
        var m = Screen.FromHandle(h).Bounds;
        return r.L <= m.Left && r.T <= m.Top && r.R >= m.Right && r.B >= m.Bottom;
    }
}
