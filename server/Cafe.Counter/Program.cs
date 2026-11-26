// Cafe.Counter: the counter screen (the counter server's own page) in its own window, and the alerts: Windows' voice plus a
// popup that never takes the keyboard from a game. It runs as the person signed in to Windows on the counter PC.
// Usage: Cafe.Counter [--server https://127.0.0.1:5443] [--pin-file <server.pin>] [--log <file>] [--test-token <staff token>]
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Speech.Synthesis;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

static class Program
{
    public const string WebView2Page = "https://developer.microsoft.com/microsoft-edge/webview2/";
    static string? Arg(string[] a, string name) { var i = Array.IndexOf(a, name); return i >= 0 && i + 1 < a.Length ? a[i + 1] : null; }

    [STAThread]
    static void Main(string[] args)
    {
        // one window per Windows user: starting it again (desktop icon) brings the running one up, even from the tray
        using var show = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\GamingCafeCounterShow", out var first);
        if (!first) { show.Set(); return; }
        Application.EnableVisualStyles();
        var local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GamingCafe");
        var pinFile = Arg(args, "--pin-file") ?? Path.Combine(AppContext.BaseDirectory, "server.pin");
        if (!File.Exists(pinFile)) { MessageBox.Show("The counter's certificate fingerprint (server.pin) is missing. Run INSTALL-ADMIN again.", "Gaming Cafe counter"); return; }
        try { CoreWebView2Environment.GetAvailableBrowserVersionString(); }
        catch (WebView2RuntimeNotFoundException)
        {
            Link.Show("This PC is missing Microsoft WebView2, which the counter window needs. Open the page below, download the " +
                "\"Evergreen Bootstrapper\" and run it. Then start the counter again.", WebView2Page);
            return;
        }
        var window = new CounterWindow((Arg(args, "--server") ?? "https://127.0.0.1:5443").TrimEnd('/'), File.ReadAllText(pinFile).Trim(),
            Arg(args, "--log") ?? Path.Combine(local, "counter-log.txt"), Path.Combine(local, "CounterView"), Arg(args, "--test-token"));
        ThreadPool.RegisterWaitForSingleObject(show, (_, _) => window.BeginInvoke(new Action(window.ShowUp)), null, -1, false);
        Application.Run(window);
    }

    /// The counter's certificate is its own (no outside authority): it is trusted only if its SHA-256 matches server.pin.
    public static bool IsCounters(X509Certificate2? cert, string pin) =>
        cert is not null && Convert.ToHexString(SHA256.HashData(cert.RawData)).Equals(pin, StringComparison.OrdinalIgnoreCase);
}

/// A message with a link the person can click (Microsoft's download page).
static class Link
{
    public static void Show(string text, string url)
    {
        using var f = new Form { Text = "Gaming Cafe counter", Width = 560, Height = 220, StartPosition = FormStartPosition.CenterScreen };
        var l = new LinkLabel { Text = $"{text}\n\n{url}", Dock = DockStyle.Fill, Padding = new Padding(12) };
        l.Links.Add(text.Length + 2, url.Length, url);
        l.LinkClicked += (_, e) => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo((string)e.Link!.LinkData!) { UseShellExecute = true });
        f.Controls.Add(l);
        f.ShowDialog();
    }
}

sealed class CounterWindow : Form
{
    readonly string _server, _pin, _log;
    readonly HttpClient _http;
    readonly NotifyIcon _tray;
    readonly Popup _popup = new();
    readonly SpeechSynthesizer _voice = new();
    readonly System.Windows.Forms.Timer _voiceWait = new() { Interval = 15000 }; // a voice that never answers must not block the next ones
    readonly HashSet<string> _told = new(); // what is going on now and was already told, so each thing is told once
    string? _token;                         // the counter login of whoever is on shift, from the page; only in memory
    bool _fresh = true, _busy, _exiting, _quiet;

    public CounterWindow(string server, string pin, string log, string viewData, string? testToken)
    {
        (_server, _pin, _log, _token) = (server, pin, log, testToken);
        Directory.CreateDirectory(Path.GetDirectoryName(log)!);
        _http = new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, c, _, _) => Program.IsCounters(c, pin) })
        { BaseAddress = new Uri(server), Timeout = TimeSpan.FromSeconds(10) };
        Text = "Gaming Cafe counter"; Width = 1280; Height = 800; StartPosition = FormStartPosition.CenterScreen;
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;
        var web = new WebView2 { Dock = DockStyle.Fill };
        Controls.Add(web);
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open the counter", null, (_, _) => ShowUp());
        menu.Items.Add("Exit (no more alerts on this PC)", null, (_, _) => { _exiting = true; Close(); });
        _tray = new NotifyIcon { Icon = Icon, Text = "Gaming Cafe counter", ContextMenuStrip = menu, Visible = true };
        _tray.DoubleClick += (_, _) => ShowUp();
        _popup.Click += (_, _) => ShowUp();
        // closing the window keeps the alerts: it goes to the tray; only Exit in the tray menu ends the program
        FormClosing += (_, e) => { if (!_exiting && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); } };
        FormClosed += (_, _) => { _tray.Visible = false; Application.Exit(); };
        _voice.SpeakCompleted += (_, e) => { _voiceWait.Stop(); Log(e.Cancelled ? "voice: stopped" : e.Error is null ? "voice: spoke" : $"voice: could not speak ({e.Error.GetBaseException().Message})"); };
        _voiceWait.Tick += (_, _) => { _voiceWait.Stop(); Log("voice: no answer from Windows' voice in 15 s; skipped"); _voice.SpeakAsyncCancelAll(); };
        try { _voice.SetOutputToDefaultAudioDevice(); } catch (Exception e) { Log($"voice: no sound output ({e.Message})"); }
        Load += async (_, _) => await Open(web, viewData);
        var poll = new System.Windows.Forms.Timer { Interval = 3000 };
        poll.Tick += async (_, _) => await Poll();
        poll.Start();
        Log("started");
    }

    public void ShowUp() { Show(); if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal; Activate(); }

    async Task Open(WebView2 web, string viewData)
    {
        try
        {
            await web.EnsureCoreWebView2Async(await CoreWebView2Environment.CreateAsync(null, viewData));
            var page = web.CoreWebView2;
            page.ServerCertificateErrorDetected += (_, e) =>
            {
                var ok = Program.IsCounters(X509Certificate2.CreateFromPem(e.ServerCertificate.ToPemEncoding()), _pin);
                e.Action = ok ? CoreWebView2ServerCertificateErrorAction.AlwaysAllow : CoreWebView2ServerCertificateErrorAction.Cancel;
                if (!ok) Log("refused a certificate that is not the counter's");
            };
            // only the counter's own pages, in this one window
            page.NavigationStarting += (_, e) => { if (!e.Uri.StartsWith(_server + "/", StringComparison.Ordinal)) { e.Cancel = true; Log("kept the window on the counter page"); } };
            page.NewWindowRequested += (_, e) => e.Handled = true;
            page.NavigationCompleted += (_, e) => Log(e.IsSuccess ? "counter page opened" : $"counter page did not open ({e.WebErrorStatus})");
            // the page says who signed in (and out), so the alerts use the same login and stop at its logout
            page.WebMessageReceived += (_, e) =>
            {
                if (!e.Source.StartsWith(_server + "/", StringComparison.Ordinal)) return;
                using var m = JsonDocument.Parse(e.WebMessageAsJson);
                _token = m.RootElement.ValueKind == JsonValueKind.Object && m.RootElement.TryGetProperty("token", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
                _fresh = true; _told.Clear();
            };
            page.Navigate(_server + "/staff/");
        }
        catch (Exception e) { Log($"counter page did not open ({e.GetBaseException().Message})"); }
    }

    async Task Poll()
    {
        if (_token is null || _busy) return;
        _busy = true;
        try
        {
            var now = new Dictionary<string, string>();
            foreach (var d in await Get("/staff/pen-drives"))
                now[$"pen {d.GetProperty("id")}"] = $"{d.GetProperty("pc").GetString()}: a pen drive is waiting for an answer.";
            foreach (var r in await Get("/staff/counter"))
                if (!r.GetProperty("online").GetBoolean() && r.GetProperty("session").ValueKind == JsonValueKind.Number)
                    now[$"away {r.GetProperty("pc").GetString()} {r.GetProperty("session")}"] = $"{r.GetProperty("pc").GetString()} stopped reaching the counter during a visit.";
            foreach (var s in (await Get("/staff/review")).Select(x => x.GetString() ?? ""))
                if (s.IndexOf(": Microsoft Defender found a threat", StringComparison.Ordinal) is var at and > 0)
                    now["threat " + s] = s[(s.IndexOf(' ') + 1)..at] + ": Microsoft Defender found a threat on a pen drive.";
                else if (s.Contains("lock screen", StringComparison.Ordinal)) // the watchdog's report on a locked PC
                    now["tamper " + s] = s[(s.IndexOf(' ') + 1)..] + ".";
            // at a sign-in, items already on the owner's review list are old news; waiting pen drives and missing PCs are not
            if (_fresh) foreach (var k in now.Keys.Where(k => k.StartsWith("threat ", StringComparison.Ordinal) || k.StartsWith("tamper ", StringComparison.Ordinal))) _told.Add(k);
            _fresh = false;
            foreach (var (k, text) in now) if (_told.Add(k)) Alert(text);
            _told.IntersectWith(now.Keys); // a thing that ends and happens again is told again
            _quiet = false;
        }
        catch (HttpRequestException e) when (e.StatusCode == HttpStatusCode.Unauthorized) { _token = null; Log("the counter login ended; alerts wait for the next sign-in"); }
        catch (Exception e) { if (!_quiet) Log($"could not reach the counter ({e.GetBaseException().Message})"); _quiet = true; }
        finally { _busy = false; }
    }

    async Task<List<JsonElement>> Get(string path)
    {
        using var m = new HttpRequestMessage(HttpMethod.Get, path);
        m.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        using var r = await _http.SendAsync(m);
        r.EnsureSuccessStatusCode();
        return JsonSerializer.Deserialize<List<JsonElement>>(await r.Content.ReadAsStringAsync())!;
    }

    void Alert(string text)
    {
        Log("alert: " + text);
        _popup.Tell(text);
        _voice.SpeakAsync(text);
        _voiceWait.Stop(); _voiceWait.Start();
    }

    void Log(string line)
    {
        try { File.AppendAllText(_log, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {line}{Environment.NewLine}"); } catch (IOException) { }
    }
}

/// Bottom right, on top of everything, and it never takes the keyboard (measured over a full-screen game, run 45590388068).
sealed class Popup : Form
{
    readonly Label _text = new() { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 13), Padding = new Padding(10) };
    readonly System.Windows.Forms.Timer _hide = new() { Interval = 20000 };
    public Popup()
    {
        Text = "Gaming Cafe alert"; FormBorderStyle = FormBorderStyle.FixedToolWindow; ShowInTaskbar = false; TopMost = true;
        StartPosition = FormStartPosition.Manual; Width = 420; Height = 140;
        Controls.Add(_text);
        _text.Click += (_, e) => OnClick(e);
        _hide.Tick += (_, _) => { _hide.Stop(); Hide(); };
    }
    protected override bool ShowWithoutActivation => true;
    protected override CreateParams CreateParams { get { var p = base.CreateParams; p.ExStyle |= 0x08000000 | 0x8; return p; } } // NOACTIVATE | TOPMOST
    public void Tell(string text)
    {
        _text.Text = text;
        var area = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(area.Right - Width - 12, area.Bottom - Height - 12);
        Show();
        _hide.Stop(); _hide.Start();
    }
}
