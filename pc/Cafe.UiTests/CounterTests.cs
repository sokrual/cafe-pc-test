using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using FlaUI.Core.Definitions;
using Xunit;

// B5.3: the counter window (CAFE_COUNTER_EXE, built as it ships) against the real counter server. The page opens only
// with the counter's own certificate; alerts (popup and voice) come for a waiting pen drive, a Defender threat and a PC
// that stops reaching the counter during a visit, and not for an alert that stays on the counter screen (Wi-Fi).
[Collection("desktop")]
public sealed class CounterTests : IDisposable
{
    readonly Rig _rig = new();
    readonly string _dir = Path.Combine(Path.GetTempPath(), $"cafe-counter-{Guid.NewGuid():N}");
    Process? _counter;

    public void Dispose() { Rig.Kill(_counter); _rig.Dispose(); }

    string Pin => Path.Combine(_rig.Data, "server.pin");
    string Log => Path.Combine(_dir, "counter-log.txt");
    // Read without blocking the window's writes: it drops a log line when its file is busy (File.AppendAllText, IOException
    // ignored), and File.ReadAllText kept it busy. Measured: lost lines or a read error in 6 of 90 rounds on ARM (run
    // 45844004839); with this read, 0 of 180 rounds on both machines (run 45845923283).
    string LogText()
    {
        if (!File.Exists(Log)) return "";
        using var file = new FileStream(Log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return new StreamReader(file).ReadToEnd();
    }

    Process Start(string pinFile, params string[] more)
    {
        Directory.CreateDirectory(_dir);
        var start = new ProcessStartInfo(Rig.Env("CAFE_COUNTER_EXE")) { UseShellExecute = false };
        foreach (var a in new[] { "--pin-file", pinFile, "--log", Log }.Concat(more)) start.ArgumentList.Add(a);
        return Process.Start(start)!;
    }

    [Fact]
    public void B53_counter_window_opens_the_counter_page_only_with_the_counters_own_certificate()
    {
        _counter = Start(Pin);
        Rig.WaitFor(() => LogText().Contains("counter page opened"), 60, "the counter window did not open the counter page", LogText);
        Assert.NotNull(_rig.Ui.GetDesktop().FindFirstChild(c => c.ByName("Gaming Cafe counter")));

        using (var again = Start(Pin)) // the desktop icon again: no second program, the running window comes up
        {
            Assert.True(again.WaitForExit(15000), "a second counter window program kept running");
            Assert.False(_counter.HasExited, "the first counter window program ended");
        }

        Rig.Kill(_counter);
        File.Delete(Log);
        var wrong = Path.Combine(_dir, "wrong.pin");
        File.WriteAllText(wrong, new string('0', 64));
        _counter = Start(wrong);
        Rig.WaitFor(() => LogText().Contains("counter page did not open"), 60, "with a wrong fingerprint the window did not report a refusal", LogText);
        Assert.True(LogText().Contains("refused a certificate that is not the counter's"), "no refusal in the counter window's log:\n" + LogText());
        Assert.False(LogText().Contains("counter page opened"), "the page opened with a wrong fingerprint:\n" + LogText());
    }

    // The counter server's log file held open by another program (no sharing): every request still answers truly. Before
    // the fix a PC login answered 500 while the visit had started (run 45939488949).
    [Fact]
    public void Server_answers_truly_while_its_log_file_is_busy()
    {
        var key = File.ReadAllText(Path.Combine(_rig.Data, "pc1.token")).Trim();
        HttpResponseMessage Pc(HttpMethod method, string path, object? body = null)
        {
            using var m = new HttpRequestMessage(method, path) { Content = body is null ? null : JsonContent.Create(body) };
            m.Headers.Add("X-Pc-Token", key);
            m.Headers.Add("X-Pc-Bind", "counter-test-bind-0123456789");
            return _rig.Http.Send(m);
        }
        Assert.Equal(HttpStatusCode.OK, Pc(HttpMethod.Get, "/pc/state").StatusCode);
        var log = Directory.GetFiles(Path.Combine(_rig.Data, "logs"), "server-*.log").Single();
        using (new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.Equal(HttpStatusCode.OK, Pc(HttpMethod.Post, "/pc/login", new { phone = "9000000003", pin = "2222" }).StatusCode);
            Assert.Equal(HttpStatusCode.OK, Pc(HttpMethod.Post, "/pc/logout").StatusCode);
            Assert.Equal(HttpStatusCode.OK, Pc(HttpMethod.Post, "/pc/tamper", new { what = "stuck", locked = false }).StatusCode);
        }
    }

    [Fact]
    public async Task B53_alerts_pop_up_and_speak_for_a_pen_drive_a_Defender_threat_lock_screen_tampering_and_a_PC_lost_during_a_visit_but_not_for_a_WiFi_alert_or_a_restart()
    {
        var staff = await _rig.StaffToken();
        var key = File.ReadAllText(Path.Combine(_rig.Data, "pc1.token")).Trim();
        HttpResponseMessage Pc(HttpMethod method, string path, object? body = null)
        {
            using var m = new HttpRequestMessage(method, path) { Content = body is null ? null : JsonContent.Create(body) };
            m.Headers.Add("X-Pc-Token", key);
            m.Headers.Add("X-Pc-Bind", "counter-test-bind-0123456789");
            return _rig.Http.Send(m).EnsureSuccessStatusCode();
        }
        Pc(HttpMethod.Get, "/pc/state"); // PC1 is online
        await _rig.Post("/staff/sessions", new { pc = "PC1", phone = "9000000003", mode = "postpaid" }, staff);
        _counter = Start(Pin, "--test-token", staff);
        Rig.WaitFor(() => LogText().Contains("started"), 30, "the counter window did not start", LogText);

        Pc(HttpMethod.Post, "/pc/wifi-alert", new { network = "Free WiFi", router = "aa:bb:cc:dd:ee:ff" }); // stays on the screen only

        long id = 0; // the PC tells the counter about the plugged-in drive every few seconds, as the watchdog does
        Rig.WaitFor(() =>
        {
            Pc(HttpMethod.Get, "/pc/state");
            id = Pc(HttpMethod.Post, "/pc/pen-drive", new { device = @"USB\VID_0781&PID_5567\COUNTERTEST1", name = "SanDisk" })
                .Content.ReadFromJsonAsync<Dictionary<string, object?>>().Result!["id"] is { } v ? long.Parse(v.ToString()!) : 0;
            return LogText().Contains("alert: PC1: a pen drive is waiting for an answer.");
        }, 30, "no alert for the waiting pen drive", LogText);
        var popup = _rig.Ui.GetDesktop().FindFirstChild(c => c.ByName("Gaming Cafe alert"));
        Assert.NotNull(popup);
        Assert.Contains(popup.FindAllDescendants(c => c.ByControlType(ControlType.Text)), t => t.Name.Contains("a pen drive is waiting for an answer"));
        Rig.WaitFor(() => LogText().Contains("voice:"), 20, "the voice was not tried", LogText); // CI has no sound device: "could not speak" is fine

        await _rig.Post($"/staff/pen-drives/{id}", new { access = "read" }, staff);
        Pc(HttpMethod.Post, $"/pc/pen-drive/{id}/scan", new { threats = true });
        Rig.WaitFor(() => LogText().Contains("alert: PC1: Microsoft Defender found a threat on a pen drive."), 20, "no alert for the Defender threat", LogText);

        Pc(HttpMethod.Post, "/pc/tamper", new { what = "stuck", locked = false }); // a restart during a visit: on the screen only
        Pc(HttpMethod.Post, "/pc/tamper", new { what = "ended", locked = true });
        Rig.WaitFor(() => LogText().Contains("alert: PC1: the lock screen was ended 3 times within a minute; the Customer's programs were closed."), 20, "no alert for the lock screen report", LogText);

        // PC1 says nothing more; its visit is still open
        Rig.WaitFor(() => LogText().Contains("alert: PC1 stopped reaching the counter during a visit."), 45, "no alert for the PC lost during a visit", LogText);
        Assert.DoesNotContain("Wi-Fi", LogText());
        Assert.DoesNotContain("during a visit and was restarted", LogText());
        Assert.Single(Regex.Matches(LogText(), "alert: PC1: a pen drive is waiting"));
    }
}
