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
    // admin-only on an installed PC; not ProgramData\Cafe, where the lock screen (as Customer) writes and could plant files
    static readonly string Logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ShinzxCafe", "logs");

    public static void Run(CancellationToken stop)
    {
        var line = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "watchdog.args")).Trim();
        var path = Path.GetFullPath(line.Split('"')[1]);
        var exe = Path.GetFileNameWithoutExtension(path);
        // SYSTEM starts whatever these name: if ordinary accounts can change either, a customer could swap in their own program
        foreach (var f in new[] { AppContext.BaseDirectory, Path.Combine(AppContext.BaseDirectory, "watchdog.args"), path })
            if (WritableByNonAdmins(f)) { Log($"REFUSED: {f} can be changed by non-admin accounts; install into Program Files"); return; }
        Log($"v{typeof(Watchdog).Assembly.GetName().Version} watching {exe}");
        var setup = Path.Combine(AppContext.BaseDirectory, "setup.flag"); // the installer's setup mode: no lock screen while the owner sets up
        var sid = Wipe.CustomerSid();
        uint? watched = null;
        HashSet<(int, DateTime)> trusted = [];
        while (!stop.IsCancellationRequested)
        {
            try
            {
                if (File.Exists(Wipe.Request))
                {
                    Log(sid is null ? "wipe asked for, but there is no Customer account" : $"wipe: {Wipe.Run(sid, path, trusted)}");
                    File.Delete(Wipe.Request); // the lock screen lets the next customer log in once this is gone
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
        var acl = Directory.Exists(file) ? (System.Security.AccessControl.FileSystemSecurity)new DirectoryInfo(file).GetAccessControl() : new FileInfo(file).GetAccessControl();
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

    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
