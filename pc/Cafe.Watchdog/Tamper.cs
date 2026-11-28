using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

// B5.3 part 3. The lock screen program reports once a second (/local/alive through the pipe, see PcProxy). The owner's rules
// (26 Nov): no report for 15 s, or a thread of it stuck for 15 s, ends it (a new one covers the screen in 0.17 to 0.31 s,
// measured). If the counter's last word was "locked", the Customer's programs are closed too and the counter is told, which
// speaks it; if unlocked, the counter only shows it. Ended 3 times within a minute while locked, other than by this
// watchdog, a clean-up or setup mode: the Customer's programs are closed and the counter is told. Another desktop holding the
// screen at 4 of the lock screen's looks in a row (2 s) while locked: the same.
static class Tamper
{
    const long Limit = 15_000; // the worst stall of the whole PC measured under full load was 9.1 s
    static long _aliveAt, _oldest, _lastLook, _stallAt, _quietUntil;
    static int _killed, _reporter, _ended;
    static volatile int _locked = -1; // the counter's last word: 1 locked, 0 unlocked, -1 nothing heard yet
    static readonly Queue<long> Ends = new();
    static readonly ConcurrentQueue<(string What, bool Locked)> Unsent = new();

    static volatile int _lost;
    static bool _screenTold;

    public static void Alive(int pid, long oldest, int lost)
    {
        _lost = lost;
        Interlocked.Exchange(ref _oldest, oldest);
        Interlocked.Exchange(ref _aliveAt, Environment.TickCount64);
        _reporter = pid;
    }

    /// The counter's answer to the lock screen program's state request, as it passes through the pipe.
    public static void CounterSays(string state)
    {
        try
        {
            using var d = JsonDocument.Parse(state);
            if (d.RootElement.TryGetProperty("locked", out var l) && l.ValueKind is JsonValueKind.True or JsonValueKind.False) _locked = l.GetBoolean() ? 1 : 0;
        }
        catch (JsonException) { }
    }
    static bool Locked => _locked != 0; // nothing heard from the counter yet: treat the PC as locked

    /// Once per turn of the watchdog's loop: a second apart, unless the whole PC stalled. agent: null while there is none
    /// running, or while the pipe it reports through is down.
    public static void Look(Process? agent, Func<int> closeCustomerPrograms, Action<string> log)
    {
        var now = Environment.TickCount64;
        if (now - _lastLook > 2000) _stallAt = now; // the watchdog stalled too, so the whole PC did (measured): no one to blame
        _lastLook = now;
        SendUnsent(log);
        // Silence counts only for a program that has reported. One that never could (signed in as someone other than the
        // Customer, whom the pipe refuses, as in CI's lockdown run 45793638146) is left alone, as before this check existed.
        if (agent is null || _reporter != agent.Id) { Interlocked.Exchange(ref _aliveAt, now); return; }
        // another desktop had the screen at 4 looks in a row (2 s) while locked: once per run of such looks
        if (_lost < 4) _screenTold = false;
        else if (!_screenTold && Locked)
        {
            _screenTold = true;
            log($"another desktop had the screen at {_lost} looks in a row; closed {closeCustomerPrograms()} of the Customer's programs");
            Tell("screen", true, log);
        }
        try { if ((DateTime.Now - agent.StartTime).TotalMilliseconds < Limit) return; } // still starting
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { return; }
        var silent = now - Math.Max(Interlocked.Read(ref _aliveAt), _stallAt);
        var stuck = Interlocked.Read(ref _oldest);
        if (silent <= Limit && stuck <= Limit) return;
        var locked = Locked;
        log(silent > Limit ? $"the lock screen program has not answered for {silent / 1000} s: ending it"
            : $"a thread of the lock screen program has not run for {stuck / 1000} s: ending it");
        _killed = agent.Id;
        try { agent.Kill(); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        Interlocked.Exchange(ref _oldest, 0);
        Interlocked.Exchange(ref _aliveAt, now);
        if (locked) log($"closed {closeCustomerPrograms()} of the Customer's programs");
        Tell("stuck", locked, log);
    }

    public static void Ended(int pid, bool inSetup, Func<int> closeCustomerPrograms, Action<string> log)
    {
        var now = Environment.TickCount64;
        if (pid == _ended) return; // already counted: the loop can see one end twice. shortcut: a next program given the same
        // process id by Windows would not be counted; Windows rarely reuses an id that fast, revisit if a 3-ends report goes missing
        _ended = pid;
        if (pid == _killed || pid != _reporter || inSetup || now < _quietUntil || !Locked) return; // only a program that reported
        Ends.Enqueue(now);
        while (Ends.Peek() < now - 60_000) Ends.Dequeue();
        if (Ends.Count < 3) return;
        Ends.Clear();
        log($"the lock screen program ended 3 times within a minute; closed {closeCustomerPrograms()} of the Customer's programs");
        Tell("ended", true, log);
    }

    /// A clean-up signs the Customer out of Windows, which ends the lock screen program: not tampering.
    public static void CleanupRan() => _quietUntil = Environment.TickCount64 + 30_000;

    static void Tell(string what, bool locked, Action<string> log) { Unsent.Enqueue((what, locked)); SendUnsent(log); }

    static void SendUnsent(Action<string> log)
    {
        while (Unsent.TryPeek(out var r))
            try
            {
                using var response = PcProxy.SendServerJson("/pc/tamper", new { what = r.What, locked = r.Locked });
                if (!response.IsSuccessStatusCode) log($"the counter refused the lock screen report ({(int)response.StatusCode})");
                Unsent.TryDequeue(out _);
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or OperationCanceledException or IOException or InvalidOperationException)
            { break; } // sent once the counter can be reached
    }
}
