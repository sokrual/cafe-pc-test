using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Input;
using FlaUI.Core.WindowsAPI;
using FlaUI.UIA3;
using Xunit;

// Phase 1 (T1.1) on a real Windows desktop: FlaUI plays the customer. Starts the real server and the real
// PC program (paths in CAFE_SERVER_EXE / CAFE_AGENT_EXE), so this tests what ships, not a mock.
public sealed class LockScreenTests : IDisposable
{
    const string Url = "http://127.0.0.1:5080";
    readonly string _data = Path.Combine(Path.GetTempPath(), $"cafe-ui-{Guid.NewGuid():N}");
    readonly Process _server, _agent;
    readonly UIA3Automation _ui = new();
    readonly HttpClient _http = new() { BaseAddress = new Uri(Url) };
    readonly Application _app;

    public LockScreenTests()
    {
        _server = Process.Start(new ProcessStartInfo(Env("CAFE_SERVER_EXE"), $"--data \"{_data}\" --seed-test --urls {Url}") { UseShellExecute = false })!;
        WaitFor(() => File.Exists(Path.Combine(_data, "pc1.token")) && Ping(), 60, "server did not start");
        _agent = Process.Start(new ProcessStartInfo(Env("CAFE_AGENT_EXE"), $"--server {Url} --token-file \"{Path.Combine(_data, "pc1.token")}\" --name \"Test Cafe\"") { UseShellExecute = false })!;
        _app = Application.Attach(_agent.Id);
    }

    public void Dispose()
    {
        foreach (var p in new[] { _agent, _server }) { try { p.Kill(true); p.WaitForExit(5000); } catch (InvalidOperationException) { } }
        _ui.Dispose(); _http.Dispose();
        try { Directory.Delete(_data, true); } catch (IOException) { }
    }

    [Fact]
    public async Task T1_1_lock_screen_cannot_be_escaped_and_login_lock_logout_work()
    {
        var lockWin = Window("LockScreen");
        var desk = _ui.GetDesktop().BoundingRectangle;
        Assert.True(lockWin.BoundingRectangle.Contains(desk) || lockWin.BoundingRectangle == desk, $"lock screen {lockWin.BoundingRectangle} does not cover the screen {desk}");

        // escape attempts while locked
        var combos = new (string name, VirtualKeyShort[] keys)[]
        {
            ("Alt+Tab", [VirtualKeyShort.ALT, VirtualKeyShort.TAB]),
            ("Win", [VirtualKeyShort.LWIN]),
            ("Win+R", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_R]),
            ("Win+D", [VirtualKeyShort.LWIN, VirtualKeyShort.KEY_D]),
            ("Alt+F4", [VirtualKeyShort.ALT, VirtualKeyShort.F4]),
            ("Ctrl+Esc", [VirtualKeyShort.CONTROL, VirtualKeyShort.ESCAPE]),
            ("Alt+Esc", [VirtualKeyShort.ALT, VirtualKeyShort.ESCAPE]),
        };
        foreach (var (name, keys) in combos)
        {
            Keyboard.TypeSimultaneously(keys);
            Thread.Sleep(1200);
            Assert.False(_agent.HasExited, $"{name} closed the PC program");
            Assert.True(IsOnTop(lockWin), $"{name} got past the lock screen (foreground is now '{ForegroundTitle()}')");
        }

        // a program that opens on its own must not stay in front of the lock screen
        using (var other = Process.Start(new ProcessStartInfo("cmd.exe", "/k title Escape-attempt") { UseShellExecute = true }))
        {
            Thread.Sleep(2500);
            Assert.True(IsOnTop(lockWin), $"another window stayed in front of the lock screen ('{ForegroundTitle()}')");
            try { other?.Kill(true); } catch (InvalidOperationException) { }
        }

        // wrong PIN: stays locked and says so
        LogIn(lockWin, "9000000003", "0000");
        WaitFor(() => Text(lockWin, "Error").Length > 0, 10, "no error shown for a wrong PIN");
        Assert.True(IsOnTop(lockWin));

        // right PIN: lock screen goes, timer appears and counts
        LogIn(lockWin, "9000000003", "2222");
        WaitFor(() => lockWin.IsOffscreen || !lockWin.IsAvailable, 10, "lock screen did not go away after login");
        var staff = await StaffToken();
        WaitFor(() => State(staff)["session"] is not null, 10, "no session on the admin PC after login");
        // the timer hides while something full-screen is in front (as in a game); check it only when nothing is
        var fullScreenInFront = FullScreenInFront();
        if (!fullScreenInFront)
        {
            var timer = Window("TimerWidget");
            WaitFor(() => System.Text.RegularExpressions.Regex.IsMatch(Text(timer, "TimerText"), @"^\d\d:\d\d$"), 10, $"timer shows '{Text(timer, "TimerText")}'");
        }
        else Console.WriteLine($"timer widget check skipped: full-screen '{ForegroundTitle()}' is in front, so the timer is correctly hidden");

        // owner locks the PC from the counter: lock screen comes back with the message, and unlock removes it
        await Post("/staff/lock", new { pc = "PC1", message = "Please come to the counter" }, staff);
        WaitFor(() => Find("LockScreen") is { IsOffscreen: false } w && Text(w, "Message") == "Please come to the counter", 10, "admin lock did not show the lock screen");
        await Post("/staff/unlock", new { pc = "PC1", message = (string?)null }, staff);
        WaitFor(() => Find("LockScreen") is null or { IsOffscreen: true }, 10, "admin unlock did not hide the lock screen");

        // customer logs out: session ends on the admin PC and the lock screen is back
        if (!fullScreenInFront) Part(Window("TimerWidget"), "Logout").AsButton().Invoke();
        else (await PcPost("/pc/logout")).EnsureSuccessStatusCode();
        WaitFor(() => Find("LockScreen") is { IsOffscreen: false }, 10, "lock screen did not come back after logout");
        Assert.Null(State(staff)["session"]);
    }

    // ---------------- helpers ----------------

    static string Env(string name) => Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"set {name}");

    bool Ping()
    {
        try { return _http.GetAsync("/pc/state").Result.StatusCode == System.Net.HttpStatusCode.Unauthorized; } // up, and refusing a missing token
        catch (Exception e) when (e is HttpRequestException or AggregateException) { return false; }
    }

    static void WaitFor(Func<bool> ok, int seconds, string why)
    {
        var until = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < until) { try { if (ok()) return; } catch (Exception) { } Thread.Sleep(300); } // UI elements vanish mid-check; retry
        Assert.Fail(why);
    }

    Window? Find(string id) => _app.GetAllTopLevelWindows(_ui).FirstOrDefault(w => w.Properties.AutomationId.ValueOrDefault == id);
    Window Window(string id) { Window? w = null; WaitFor(() => (w = Find(id)) is not null, 20, $"window {id} never appeared"); return w!; }
    static AutomationElement Part(AutomationElement root, string id) => root.FindFirstDescendant(c => c.ByAutomationId(id)) ?? throw new InvalidOperationException($"no {id} on screen");
    static string Text(AutomationElement root, string id) => root.FindFirstDescendant(c => c.ByAutomationId(id))?.Name ?? "";

    static void LogIn(Window lockWin, string phone, string pin)
    {
        Part(lockWin, "Phone").AsTextBox().Text = phone;
        Part(lockWin, "Pin").AsTextBox().Text = pin;
        Part(lockWin, "Login").AsButton().Invoke();
    }

    bool IsOnTop(Window w) => !w.IsOffscreen && GetForegroundWindow() == w.Properties.NativeWindowHandle.Value;
    static string ForegroundTitle() { var sb = new System.Text.StringBuilder(256); GetWindowText(GetForegroundWindow(), sb, 256); return sb.ToString(); }

    async Task<string> StaffToken()
    {
        var r = await _http.PostAsJsonAsync("/staff/login", new { phone = "9000000002", pin = "1111" });
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["token"];
    }
    async Task Post(string path, object body, string token)
    {
        using var m = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        m.Headers.Authorization = new("Bearer", token);
        (await _http.SendAsync(m)).EnsureSuccessStatusCode();
    }
    Dictionary<string, object?> State(string token)
    {
        using var m = new HttpRequestMessage(HttpMethod.Get, "/staff/state/PC1");
        m.Headers.Authorization = new("Bearer", token);
        return _http.Send(m).Content.ReadFromJsonAsync<Dictionary<string, object?>>().Result!;
    }
    async Task<HttpResponseMessage> PcPost(string path)
    {
        using var m = new HttpRequestMessage(HttpMethod.Post, path);
        m.Headers.Add("X-Pc-Token", File.ReadAllText(Path.Combine(_data, "pc1.token")).Trim());
        return await _http.SendAsync(m);
    }

    static bool FullScreenInFront()
    {
        var h = GetForegroundWindow();
        return GetWindowRect(h, out var r) && r.L <= 0 && r.T <= 0 && r.R >= GetSystemMetrics(0) && r.B >= GetSystemMetrics(1);
    }
    [StructLayout(LayoutKind.Sequential)] struct Rect { public int L, T, R, B; }
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out Rect r);
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int i);

    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int max);
}
