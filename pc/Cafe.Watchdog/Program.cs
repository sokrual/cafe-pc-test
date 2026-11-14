using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Principal;

// Windows service, runs as SYSTEM: customers can neither stop nor kill it. Every second it checks that the PC program
// runs in the signed-in user's session and starts it there if not, so killing the PC program only blinks the screen.
// Reads one line from watchdog.args next to this exe: "<path to Cafe.Agent.exe>" <its arguments>
// (that file must sit in a folder only admins can change, or anyone could make SYSTEM start their program).
if (args.Contains("--test-pipe-probe", StringComparer.OrdinalIgnoreCase))
    Environment.ExitCode = PcProxy.TestPipeProbe();
else if (args.Contains("--test-agent-process-access", StringComparer.OrdinalIgnoreCase))
{
    var index = Array.FindIndex(args, x => x.Equals("--test-agent-process-access", StringComparison.OrdinalIgnoreCase));
    Environment.ExitCode = index + 1 < args.Length && int.TryParse(args[index + 1], out var pid)
        ? Native.TestAgentProcessAccess(pid) : 2;
}
else if (args.Contains("--test-read-lock-setting", StringComparer.OrdinalIgnoreCase))
{
    var keys = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "keys");
    Console.WriteLine(new OfflineUnlockStore(Path.Combine(keys, "offline-unlock.bin")).ReadLockWhenTimeRunsOut());
}
else if (args.Contains("--test-set-offline-refresh", StringComparer.OrdinalIgnoreCase))
{
    if (!args.Contains("--test-mode", StringComparer.OrdinalIgnoreCase)
        || Environment.GetEnvironmentVariable("CAFE_TEST_MODE") != "1")
        throw new InvalidOperationException("offline refresh test mode is not enabled");
    var cacheIndex = Array.FindIndex(args, x => x.Equals("--cache-file", StringComparison.OrdinalIgnoreCase));
    var timeIndex = Array.FindIndex(args, x => x.Equals("--server-time", StringComparison.OrdinalIgnoreCase));
    if (cacheIndex < 0 || cacheIndex + 1 >= args.Length || timeIndex < 0 || timeIndex + 1 >= args.Length)
        throw new InvalidOperationException("test cache file and server time are required");
    var serverTime = DateTime.Parse(args[timeIndex + 1], System.Globalization.CultureInfo.InvariantCulture,
        System.Globalization.DateTimeStyles.RoundtripKind);
    new OfflineUnlockStore(args[cacheIndex + 1]).SetLastRefreshServerUtcForTest(serverTime);
}
else if (args.Contains("--test-check-offline-refresh", StringComparer.OrdinalIgnoreCase))
{
    if (!args.Contains("--test-mode", StringComparer.OrdinalIgnoreCase)
        || Environment.GetEnvironmentVariable("CAFE_TEST_MODE") != "1")
        throw new InvalidOperationException("offline refresh test mode is not enabled");
    var cacheIndex = Array.FindIndex(args, x => x.Equals("--cache-file", StringComparison.OrdinalIgnoreCase));
    if (cacheIndex < 0 || cacheIndex + 1 >= args.Length)
        throw new InvalidOperationException("test cache file is required");
    var result = new OfflineUnlockStore(args[cacheIndex + 1]).TryUnlock(
        new OfflineUnlockRequest(Guid.NewGuid().ToString("N"), "", "", 30, "cash", null, null));
    Console.WriteLine(result.Error ?? "offline unlock was not refused");
    Environment.ExitCode = result.Error is null ? 1 : 0;
}
else if (args.Contains("--test-proxy", StringComparer.OrdinalIgnoreCase))
{
    PcProxy.StartTest(args);
    Thread.Sleep(Timeout.Infinite);
}
else ServiceBase.Run(new WatchdogService());

sealed class WatchdogService : ServiceBase
{
    readonly CancellationTokenSource _stop = new();
    public WatchdogService() => ServiceName = "CafeWatchdog";
    protected override void OnStart(string[] args) => new Thread(() => Watchdog.Run(_stop.Token)) { IsBackground = true }.Start();
    protected override void OnStop() => _stop.Cancel();
}

static class Watchdog
{
    // admin-only on an installed PC; not ProgramData\Cafe, where the lock screen (as Customer) writes and could plant files
    static readonly string Logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe", "logs");

    public static void Run(CancellationToken stop)
    {
        var argsFile = Path.Combine(AppContext.BaseDirectory, "watchdog.args");
        var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Cafe.Agent.exe"));
        var line = $"\"{path}\"";
        try
        {
            var configured = File.ReadAllText(argsFile).Trim();
            var match = Regex.Match(configured, "^\\\"([^\\\"]+)\\\"");
            if (!match.Success) throw new InvalidOperationException("watchdog.args has no quoted Cafe.Agent.exe path");
            path = Path.GetFullPath(match.Groups[1].Value);
            if (!Path.GetFileName(path).Equals("Cafe.Agent.exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
                throw new InvalidOperationException("watchdog.args must name the installed Cafe.Agent.exe");
            line = configured;
        }
        catch (Exception e) { Log($"ERROR reading watchdog.args: {e.Message}; guarding with the installed Cafe.Agent.exe and retrying the proxy"); }
        var exe = Path.GetFileNameWithoutExtension(path);
        // SYSTEM starts only files in admin-controlled locations.
        foreach (var f in new[] { AppContext.BaseDirectory, argsFile, path })
            if (WritableByNonAdmins(f)) { Log($"REFUSED: {f} can be changed by non-admin accounts; install into Program Files"); return; }
        Log($"v{typeof(Watchdog).Assembly.GetName().Version} watching {exe}");
        var proxyStarted = false;
        var nextProxyAttempt = DateTime.MinValue;
        var setup = Path.Combine(AppContext.BaseDirectory, "setup.flag"); // the installer's setup mode: no lock screen while the owner sets up
        var sid = Wipe.CustomerSid();
        uint? watched = null;
        HashSet<(int, DateTime)> trusted = [];
        string? cleanupReason = null;
        var nextCleanup = DateTime.MinValue;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                if (!proxyStarted && DateTime.UtcNow >= nextProxyAttempt)
                {
                    try
                    {
                        PcProxy.StartFromWatchdogArgs(line, path, stop, Log);
                        proxyStarted = true;
                        Log("PC pipe proxy started");
                    }
                    catch (Exception e)
                    {
                        Log($"PC pipe proxy start failed: {e.Message}; lock screen remains guarded; retrying in 30 seconds");
                        nextProxyAttempt = DateTime.UtcNow.AddSeconds(30);
                    }
                }
                if (Wipe.RequestExists())
                {
                    if (DateTime.UtcNow >= nextCleanup)
                    {
                        string? reason = null;
                        if (!Wipe.PrepareRequest(out var requestError, out var normalized))
                            reason = $"cleanup request path could not be made safe (error code {requestError})";
                        else
                        {
                            if (normalized) Log("unsafe cleanup request object removed without following it");
                            if (!Wipe.ServerHasNoSession(out var serverError))
                                reason = serverError == 0 ? "cleanup deferred (session active)" : $"cleanup deferred (server error code {serverError})";
                            else if (sid is null)
                                reason = "cleanup failed (error code 2)";
                            else
                            {
                                try
                                {
                                    var testMode = File.Exists(Path.Combine(AppContext.BaseDirectory, "test-wipe-mode.flag"));
                                    var report = Wipe.Run(sid, path, trusted, testMode);
                                    File.Delete(Wipe.Request); // only a completed reset releases the lock screen
                                    Log($"cleanup complete: {report}");
                                    cleanupReason = null;
                                    nextCleanup = DateTime.MinValue;
                                    watched = null; // the Windows session may have logged off and signed back in with the same id
                                    trusted = [];
                                }
                                catch (Exception e)
                                {
                                    reason = $"cleanup failed (error code {Wipe.ErrorCode(e)})";
                                    watched = null;
                                    trusted = [];
                                }
                            }
                        }
                        if (reason is not null)
                        {
                            if (reason != cleanupReason) Log(reason);
                            cleanupReason = reason;
                            // A server error may be transient (for example, while its listener is restarting).
                            // Retry it promptly; an active session or local cleanup failure keeps the 30-second backoff.
                            nextCleanup = DateTime.UtcNow.AddSeconds(reason.StartsWith("cleanup deferred (server error", StringComparison.Ordinal) ? 5 : 30);
                            if (reason.StartsWith("cleanup failed", StringComparison.Ordinal))
                                try { File.SetCreationTimeUtc(Wipe.Request, DateTime.UtcNow.AddMinutes(-3)); } catch { }
                        }
                    }
                }
                else
                {
                    cleanupReason = null;
                    nextCleanup = DateTime.MinValue;
                }
                // match the full path, not just the name: a customer's renamed copy of some other program must not count
                if (!File.Exists(setup) && ActiveSession() is uint s && !Process.GetProcessesByName(exe).Any(p => p.SessionId == s && Native.PathOf(p) == path))
                {
                    if (s != watched) { (watched, trusted) = (s, sid is null ? [] : Wipe.Trusted(sid)); Log($"session {s}: {trusted.Count} Windows programs kept at logout"); }
                    Log(Start(s, line) is int pid ? $"started {exe} in session {s} (pid {pid})" : $"could not start {exe} in session {s}: error {Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception e) { Log($"ERROR {e.Message}"); } // the loop must never die
            stop.WaitHandle.WaitOne(1000);
        }
        Log("stopped");
    }

    internal static bool WritableByNonAdmins(string file)
    {
        var acl = Directory.Exists(file)
            ? (System.Security.AccessControl.FileSystemSecurity)new DirectoryInfo(file).GetAccessControl()
            : File.Exists(file)
                ? new FileInfo(file).GetAccessControl()
                : new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(file))!).GetAccessControl();
        var anyone = new[] { "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", Wipe.CustomerSid() }; // Everyone, Authenticated Users, Users, Interactive, Customer
        // Write = write data/append/attributes only; "Modify" is not used because it also contains read and run
        const System.Security.AccessControl.FileSystemRights write = System.Security.AccessControl.FileSystemRights.Write
            | System.Security.AccessControl.FileSystemRights.Delete | System.Security.AccessControl.FileSystemRights.ChangePermissions | System.Security.AccessControl.FileSystemRights.TakeOwnership;
        return acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>()
            .Any(r => r.AccessControlType == System.Security.AccessControl.AccessControlType.Allow && anyone.Contains(r.IdentityReference.Value) && (r.FileSystemRights & write) != 0);
    }

    static void Log(string line)
    {
        try { Directory.CreateDirectory(Logs); File.AppendAllText(Path.Combine(Logs, $"watchdog-{DateTime.Now:yyyyMMdd}.log"), $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    // the session someone is signed in to and using (console or remote); null at the Windows sign-in screen
    static uint? ActiveSession()
    {
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var list, out var count)) return null;
        try
        {
            var size = Marshal.SizeOf<SessionInfo>();
            for (var i = 0; i < count; i++)
                if (Marshal.PtrToStructure<SessionInfo>(list + i * size) is { State: 0 /*active*/, SessionId: > 0 } si) return si.SessionId;
            return null;
        }
        finally { WTSFreeMemory(list); }
    }

    // start the program as the signed-in user, on their desktop, with their environment
    static int? Start(uint session, string commandLine)
    {
        if (!WTSQueryUserToken(session, out var user)) return null;
        IntPtr primary = IntPtr.Zero, env = IntPtr.Zero;
        try
        {
            if (!DuplicateTokenEx(user, 0x02000000 /*MAXIMUM_ALLOWED*/, IntPtr.Zero, 2 /*impersonation*/, 1 /*primary*/, out primary)) return null;
            CreateEnvironmentBlock(out env, primary, false);
            var si = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>(), lpDesktop = @"winsta0\default" };
            if (!CreateProcessAsUser(primary, null, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, false, 0x400 /*UNICODE_ENVIRONMENT*/, env, null, ref si, out var pi)) return null;
            Native.CloseHandle(pi.hThread); Native.CloseHandle(pi.hProcess);
            return pi.dwProcessId;
        }
        finally
        {
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
            if (primary != IntPtr.Zero) Native.CloseHandle(primary);
            Native.CloseHandle(user);
        }
    }

    [StructLayout(LayoutKind.Sequential)] struct SessionInfo { public uint SessionId; public IntPtr WinStationName; public int State; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo
    {
        public int cb; public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr list, out int count);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSQueryUserToken(uint session, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int type, out IntPtr copy);
    [DllImport("userenv.dll", SetLastError = true)] static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);
    [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr env);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(IntPtr token, string? app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string? dir, ref StartupInfo si, out ProcessInfo pi);
}

static class Native
{
    // full path of a running program; works for 32-bit, 64-bit and emulated programs, null if it exited or is protected
    public static string? PathOf(Process p)
    {
        var h = OpenProcess(0x1000 /*QUERY_LIMITED_INFORMATION*/, false, p.Id);
        if (h == IntPtr.Zero) return null;
        try { var sb = new StringBuilder(1024); var n = sb.Capacity; return QueryFullProcessImageName(h, 0, sb, ref n) ? Path.GetFullPath(sb.ToString()) : null; }
        finally { CloseHandle(h); }
    }

    public static int TestAgentProcessAccess(int pid)
    {
        foreach (var access in new[] { 0x0020, 0x0008, 0x0002, 0x0040, 0x00040000 })
        {
            var process = OpenProcess(access, false, pid);
            if (process != IntPtr.Zero) { CloseHandle(process); return access; }
            if (Marshal.GetLastWin32Error() != 5) return 10 + Marshal.GetLastWin32Error();
        }
        return 0;
    }

    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
