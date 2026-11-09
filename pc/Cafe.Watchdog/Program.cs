using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;

// Windows service, runs as SYSTEM: customers can neither stop nor kill it. Every second it checks that the PC program
// runs in the signed-in user's session and starts it there if not, so killing the PC program only blinks the screen.
// Reads one line from watchdog.args next to this exe: "<path to Cafe.Agent.exe>" <its arguments>
// (that file must sit in a folder only admins can change, or anyone could make SYSTEM start their program).
ServiceBase.Run(new WatchdogService());

sealed class WatchdogService : ServiceBase
{
    readonly CancellationTokenSource _stop = new();
    public WatchdogService() => ServiceName = "CafeWatchdog";
    protected override void OnStart(string[] args) => new Thread(() => Watchdog.Run(_stop.Token)) { IsBackground = true }.Start();
    protected override void OnStop() => _stop.Cancel();
}

static class Watchdog
{
    static readonly string Logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cafe", "logs");

    public static void Run(CancellationToken stop)
    {
        var line = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "watchdog.args")).Trim();
        var exe = Path.GetFileNameWithoutExtension(line.Split('"')[1]);
        Log($"watching {exe}");
        while (!stop.IsCancellationRequested)
        {
            try
            {
                if (ActiveSession() is uint s && !Process.GetProcessesByName(exe).Any(p => p.SessionId == s))
                    Log(Start(s, line) is int pid ? $"started {exe} in session {s} (pid {pid})" : $"could not start {exe} in session {s}: error {Marshal.GetLastWin32Error()}");
            }
            catch (Exception e) { Log($"ERROR {e.Message}"); } // the loop must never die
            stop.WaitHandle.WaitOne(1000);
        }
        Log("stopped");
    }

    static void Log(string line)
    {
        try { Directory.CreateDirectory(Logs); File.AppendAllText(Path.Combine(Logs, $"watchdog-{DateTime.Now:yyyyMMdd}.log"), $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}"); }
        catch (IOException) { }
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
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            return pi.dwProcessId;
        }
        finally
        {
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
            if (primary != IntPtr.Zero) CloseHandle(primary);
            CloseHandle(user);
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
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
}
