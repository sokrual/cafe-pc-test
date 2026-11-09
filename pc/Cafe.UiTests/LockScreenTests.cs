using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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
    public async Task T1_1_to_T1_6_escape_login_locks_offline_logout()
    {
        try { await Scenario(); }
        catch { Rig.Screenshot(); throw; }
    }

    async Task Scenario()
    {
        _agent = Process.Start(new ProcessStartInfo(Rig.Env("CAFE_AGENT_EXE"), _rig.AgentArgs) { UseShellExecute = false })!;
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
        Thread.Sleep(20000); // 20 s more offline
        _rig.StartServer();
        staff = await _rig.StaffToken();
        Rig.WaitFor(() => _rig.State(staff)["session"] is null, 20, "queued logout never reached the admin PC");
        var used = TimeSpan.Parse(_rig.Bill(staff, session)["used"]!.ToString()!);
        Assert.True(used <= loggedOutAt + TimeSpan.FromSeconds(5), $"billed {used}, but the customer logged out after {loggedOutAt} (offline time was charged)");
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
    public void T1_2_killed_pc_program_is_back_within_5_seconds_and_locked()
    {
        try
        {
            var args = Path.Combine(Path.GetDirectoryName(_exe)!, "watchdog.args");
            File.WriteAllText(args, $"\"{Rig.Env("CAFE_AGENT_EXE")}\" {_rig.AgentArgs}");
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
            var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cafe", "logs");
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
    HttpClient _http = null!;

    public Rig() => StartServer();
    public string AgentArgs => $"--server {Url} --token-file \"{Path.Combine(_pcDir, "pc.token")}\" --pin-file \"{Path.Combine(_pcDir, "server.pin")}\" --name \"Test Cafe\" --logs \"{Path.Combine(_pcDir, "logs")}\"";

    public void StartServer()
    {
        _server = new Process { StartInfo = new(Env("CAFE_SERVER_EXE"), $"--data \"{Data}\" --seed-test --port 5443") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true } };
        _server.OutputDataReceived += (_, e) => { lock (_serverLog) _serverLog.AppendLine(e.Data); };
        _server.ErrorDataReceived += (_, e) => { lock (_serverLog) _serverLog.AppendLine(e.Data); };
        _server.Start(); _server.BeginOutputReadLine(); _server.BeginErrorReadLine();
        WaitFor(() => File.Exists(Path.Combine(Data, "server.pin")) && Ping(), 60, "server did not start", () => _serverLog.ToString());
        Directory.CreateDirectory(_pcDir);
        File.Copy(Path.Combine(Data, "pc1.token"), Path.Combine(_pcDir, "pc.token"), true);
        File.Copy(Path.Combine(Data, "server.pin"), Path.Combine(_pcDir, "server.pin"), true);
    }
    public void StopServer() => Kill(_server);

    public void Dispose()
    {
        Kill(_server); Ui.Dispose(); _http.Dispose();
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
    public async Task<int> TryStaffLogin(string phone, string pin) => (int)(await _http.PostAsJsonAsync("/staff/login", new { phone, pin })).StatusCode;
    public async Task Post(string path, object body, string token)
    {
        using var m = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        m.Headers.Authorization = new("Bearer", token);
        (await _http.SendAsync(m)).EnsureSuccessStatusCode();
    }
    Dictionary<string, object?> Get(string path, string token)
    {
        using var m = new HttpRequestMessage(HttpMethod.Get, path);
        m.Headers.Authorization = new("Bearer", token);
        return _http.Send(m).Content.ReadFromJsonAsync<Dictionary<string, object?>>().Result!;
    }
    public Dictionary<string, object?> State(string token) => Get("/staff/state/PC1", token);
    public Dictionary<string, object?> Bill(string token, long session) => Get($"/staff/bill/{session}", token);
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
