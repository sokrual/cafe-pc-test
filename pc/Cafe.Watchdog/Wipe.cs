using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;

// Logout reset. The lock screen (running as Customer) leaves a note in ProgramData\\GamingCafe\\wipe.
// The watchdog, as SYSTEM, logs off Customer and swaps the entire profile folder and both registry hives to the
// protected owner baseline, clears Steam's saved logins and customer tasks, then releases the lock screen.
static class Wipe
{
    public const string User = "Customer";
    static readonly string Data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GamingCafe");
    public static readonly string Request = Path.Combine(Data, "wipe", "request");

    // Any object at the request path is a request. Errors are treated as pending so the PC stays blocked.
    public static bool RequestExists()
    {
        try { _ = File.GetAttributes(Request); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        catch { return true; }
    }

    // The request folder is writable by Customer. Replace directories and links with a plain marker file,
    // deleting only the objects themselves and never traversing a reparse point.
    public static bool PrepareRequest(out int error, out bool normalized)
    {
        error = 0;
        normalized = false;
        try
        {
            var attributes = File.GetAttributes(Request);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0 && LinkCount(Request) <= 1) return true;
            normalized = true;
            RemoveEntryNoFollow(Request);
            using var marker = new FileStream(Request, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            return true;
        }
        catch (Exception e) { error = ErrorCode(e); return false; }
    }

    static void RemoveEntryNoFollow(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            if ((attributes & FileAttributes.Directory) != 0) Directory.Delete(path);
            else File.Delete(path);
            return;
        }
        if ((attributes & FileAttributes.Directory) == 0) { File.Delete(path); return; }
        foreach (var child in Directory.EnumerateFileSystemEntries(path)) RemoveEntryNoFollow(child);
        Directory.Delete(path);
    }

    // The watchdog's proxy owns the pinned server connection and the only copy of the PC key.
    // The watchdog has the same PC token and certificate pin as the lock screen. A missing answer,
    // invalid response, or non-null session all mean "do not clean".
    public static bool ServerHasNoSession(out int error)
    {
        error = 0;
        try
        {
            using var response = PcProxy.SendServerRequest(HttpMethod.Get, "/pc/state");
            if (!response.IsSuccessStatusCode) throw new HttpRequestException(null, null, response.StatusCode); // e.g. an old PC key
            using var state = JsonDocument.Parse(response.Content.ReadAsStream());
            if (!state.RootElement.TryGetProperty("session", out var session)) { error = 13; return false; }
            return session.ValueKind == JsonValueKind.Null;
        }
        catch (Exception e) { error = ErrorCode(e); return false; }
    }

    public static int ErrorCode(Exception e)
    {
        if (e is HttpRequestException { StatusCode: { } status }) return (int)status;
        if (e.InnerException is SocketException socket) return socket.ErrorCode;
        if (e is System.ComponentModel.Win32Exception win32) return win32.NativeErrorCode;
        return e.HResult & 0xffff;
    }
    static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\";

    // Windows' own programs already running in the Customer session before any customer could log in
    // (the lock screen was up). They survive a wipe; anything else Customer runs is closed.
    public static HashSet<(int, DateTime)> Trusted(string sid) =>
        [.. Process.GetProcesses().Where(p => Owner(p) == sid && Native.PathOf(p) is string f && f.StartsWith(Windows, StringComparison.OrdinalIgnoreCase)
            && !f.EndsWith("\\explorer.exe", StringComparison.OrdinalIgnoreCase)).Select(p => (p.Id, StartOf(p)))];

    public static string? CustomerSid()
    {
        try { return new NTAccount(User).Translate(typeof(SecurityIdentifier)).Value; }
        catch (IdentityNotMappedException) { return null; } // not a cafe install (no Customer account): no wipes
    }

    public static string Run(string sid, string agent, HashSet<(int, DateTime)> trusted, bool testMode = false)
    {
        var clean = Path.Combine(Data, "clean-profile");
        var hiveSnapshot = Path.Combine(Data, "clean-profile-hive");
        var savedNtUser = Path.Combine(hiveSnapshot, "NTUSER.DAT");
        var savedUsrClass = Path.Combine(hiveSnapshot, "UsrClass.dat");
        if (!Directory.Exists(clean) || !File.Exists(savedNtUser))
            throw new InvalidOperationException("clean profile or registry hive unavailable");

        string? profile;
        using (var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"))
            profile = key?.GetValue("ProfileImagePath") as string;
        if (profile is null) throw new InvalidOperationException("Customer profile path unavailable");
        profile = Path.GetFullPath(Environment.ExpandEnvironmentVariables(profile));
        if (!string.Equals(Path.GetPathRoot(profile), Path.GetPathRoot(Data), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Customer profile and protected staging area must be on the same drive");

        var stageRoot = Path.Combine(Data, "profile-stage");
        var backupRoot = Path.Combine(Data, "profile-old");
        EnsureProtectedDirectory(stageRoot, null);
        EnsureProtectedDirectory(backupRoot, null);
        var stages = Directory.GetDirectories(stageRoot);
        var backups = Directory.GetDirectories(backupRoot);
        if (stages.Length > 1 || backups.Length > 1) throw new InvalidOperationException("unexpected profile reset staging state");
        var existingStage = stages.FirstOrDefault();
        var existingBackup = backups.FirstOrDefault();

        // Recover a service interruption between the two same-volume directory renames.
        if (!Directory.Exists(profile))
        {
            if (existingBackup is not null && existingStage is not null)
            {
                if (!testMode) LogoffCustomerIfPresent(sid);
                WaitForHiveUnload(sid, TimeSpan.FromSeconds(30));
                Directory.Move(existingStage, profile);
                DeleteOldProfile(existingBackup, clean);
                return "profile=reset recovered";
            }
            if (existingBackup is not null)
            {
                Directory.Move(existingBackup, profile);
                throw new InvalidOperationException("previous profile reset was interrupted; restored the Customer profile");
            }
            if (existingStage is not null)
            {
                if (!testMode) LogoffCustomerIfPresent(sid);
                WaitForHiveUnload(sid, TimeSpan.FromSeconds(30));
                Directory.Move(existingStage, profile);
                return "profile=reset recovered";
            }
            throw new InvalidOperationException("Customer profile folder unavailable");
        }
        if (existingBackup is not null && existingStage is null)
        {
            DeleteOldProfile(existingBackup, clean); // the previous swap completed; only backup deletion was interrupted
            return "profile=reset recovered";
        }
        if (existingBackup is not null) DeleteOldProfile(existingBackup, clean);
        if (existingStage is not null) Directory.Delete(existingStage, true);
        var stage = Path.Combine(stageRoot, Guid.NewGuid().ToString("N"));
        var backup = Path.Combine(backupRoot, Guid.NewGuid().ToString("N"));

        int? customerSession = null;
        if (!testMode)
        {
            var lockScreen = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(agent))
                .FirstOrDefault(p => Owner(p) == sid && string.Equals(Native.PathOf(p), agent, StringComparison.OrdinalIgnoreCase));
            if (lockScreen is null || lockScreen.SessionId == 0)
                throw new InvalidOperationException("Customer lock screen session unavailable");
            customerSession = lockScreen.SessionId;
        }

        var keep = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "keep-running.txt")).Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#')).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var programFiles = new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 }.Select(f => Environment.GetFolderPath(f) + "\\");
        var closed = new List<Process>();
        if (testMode)
        {
            // CI's lock screen runs as the runner rather than Customer; terminate it to exercise watchdog restart.
            foreach (var ui in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(agent)))
                if (ui.SessionId > 0 && string.Equals(Native.PathOf(ui), agent, StringComparison.OrdinalIgnoreCase))
                    try { ui.Kill(); closed.Add(ui); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
        foreach (var p in Process.GetProcesses())
        {
            if (Owner(p) != sid) continue;
            if (!testMode && trusted.Contains((p.Id, StartOf(p)))) continue;
            var f = Native.PathOf(p);
            if (!testMode && f == agent) continue;
            // Production logs off the whole Customer session below. These exceptions avoid an abrupt close
            // before Windows performs its normal session-end notifications.
            if (!testMode && f is not null && keep.Contains(Path.GetFileName(f)) && programFiles.Any(d => f.StartsWith(d, StringComparison.OrdinalIgnoreCase))
                && !Watchdog.WritableByNonAdmins(f) && !Watchdog.WritableByNonAdmins(Path.GetDirectoryName(f)!)) continue;
            try { p.Kill(); closed.Add(p); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
        foreach (var p in closed) if (!p.WaitForExit(5000)) throw new TimeoutException("customer process did not exit");

        var report = $"closed={closed.Count}";
        var links = RemoveLinks(profile, profile, clean);

        // Build a complete clean profile before logging off. Its parent is inaccessible to Customer;
        // the staged folder itself has the Customer ACL it needs after the atomic same-volume swap.
        Directory.CreateDirectory(stage);
        EnsureProtectedDirectory(stage, sid);
        int stagedExit;
        using (var rc = Process.Start(new ProcessStartInfo("robocopy.exe", $"\"{clean}\" \"{stage}\" /MIR /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP /XF NTUSER.DAT* ntuser.* UsrClass.dat*") { UseShellExecute = false, CreateNoWindow = true })!)
        {
            if (!rc.WaitForExit(300_000))
            {
                rc.Kill(true);
                rc.WaitForExit();
                throw new TimeoutException("clean profile staging timed out");
            }
            stagedExit = rc.ExitCode;
            if (stagedExit >= 8) throw new InvalidOperationException("clean profile staging failed");
        }
        File.Copy(savedNtUser, Path.Combine(stage, "NTUSER.DAT"), true);
        if (File.Exists(savedUsrClass))
        {
            var usrClass = Path.Combine(stage, @"AppData\Local\Microsoft\Windows\UsrClass.dat");
            Directory.CreateDirectory(Path.GetDirectoryName(usrClass)!);
            File.Copy(savedUsrClass, usrClass, true);
        }

        // These settings live outside the profile. Clear customer login material and tasks before the next sign-in.
        var steamCleaned = false;
        if (Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam")?.GetValue("InstallPath") is string steam)
        {
            var cfg = Path.Combine(steam, "config");
            if (Directory.Exists(cfg) && new DirectoryInfo(cfg).LinkTarget is null)
            {
                File.Delete(Path.Combine(cfg, "loginusers.vdf"));
                var main = Path.Combine(cfg, "config.vdf");
                var text = File.Exists(main) ? File.ReadAllText(main) : "";
                var cleaned = Regex.Replace(text, @"\s*""ConnectCache""\s*\{[^{}]*\}", "");
                if (cleaned != text) File.WriteAllText(main, cleaned);
                steamCleaned = true;
            }
        }

        var tasks = Path.Combine(Environment.SystemDirectory, "Tasks");
        var removed = 0;
        foreach (var task in Directory.EnumerateFiles(tasks, "*", SearchOption.AllDirectories))
        {
            string xml;
            try { xml = File.ReadAllText(task); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            if (!xml.Contains($">{sid}<") && !xml.Contains($"\\{User}<") && !xml.Contains($">{User}<")) continue;
            using var d = Process.Start(new ProcessStartInfo("schtasks.exe", $"/delete /tn \"{task[tasks.Length..]}\" /f") { UseShellExecute = false, CreateNoWindow = true })!;
            if (!d.WaitForExit(10_000))
            {
                d.Kill(true);
                d.WaitForExit();
                throw new TimeoutException("task removal timed out");
            }
            if (d.ExitCode != 0) throw new InvalidOperationException("task removal failed");
            removed++;
        }

        // Move caches while the old profile is still available, then retry after logoff if Windows had a file open.
        string[] caches = [@"AppData\Local\NVIDIA", @"AppData\LocalLow\NVIDIA", @"AppData\Local\AMD", @"AppData\Local\D3DSCache"];
        for (var i = 0; i < caches.Length; i++) Move(Path.Combine(profile, caches[i]), Path.Combine(stage, caches[i]));

        if (!testMode && !WTSLogoffSession(IntPtr.Zero, (uint)customerSession!.Value, false))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "could not log off the Customer Windows session");
        WaitForHiveUnload(sid, TimeSpan.FromSeconds(30));
        for (var i = 0; i < caches.Length; i++) Move(Path.Combine(profile, caches[i]), Path.Combine(stage, caches[i]));

        // The profile path in ProfileList stays stable. Replacing the folder also replaces NTUSER.DAT and UsrClass.dat.
        Directory.Move(profile, backup);
        try { Directory.Move(stage, profile); }
        catch
        {
            if (!Directory.Exists(profile) && Directory.Exists(backup)) Directory.Move(backup, profile);
            throw;
        }
        DeleteOldProfile(backup, clean);
        report += $"; profile=reset; links={links}; robocopy={stagedExit}; hive=restored; steam={(steamCleaned ? 1 : 0)}; tasks={removed}";
        return report;
    }

    static void LogoffCustomerIfPresent(string sid)
    {
        var process = Process.GetProcesses().FirstOrDefault(p => Owner(p) == sid && p.SessionId > 0);
        if (process is not null && !WTSLogoffSession(IntPtr.Zero, (uint)process.SessionId, false))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "could not log off the Customer session during reset recovery");
    }

    static void EnsureProtectedDirectory(string path, string? customerSid)
    {
        Directory.CreateDirectory(path);
        var grants = customerSid is null
            ? "\"*S-1-5-32-544:(OI)(CI)F\" \"*S-1-5-18:(OI)(CI)F\""
            : $"\"*{customerSid}:(OI)(CI)F\" \"*S-1-5-32-544:(OI)(CI)F\" \"*S-1-5-18:(OI)(CI)F\"";
        using var acl = Process.Start(new ProcessStartInfo("icacls.exe", $"\"{path}\" /inheritance:r /grant:r {grants}") { UseShellExecute = false, CreateNoWindow = true })!;
        if (!acl.WaitForExit(10_000))
        {
            acl.Kill(true);
            acl.WaitForExit();
            throw new TimeoutException("profile staging permissions timed out");
        }
        if (acl.ExitCode != 0) throw new InvalidOperationException("profile staging permissions failed");
    }

    static void DeleteOldProfile(string path, string clean)
    {
        if (!Directory.Exists(path)) return;
        _ = RemoveLinks(path, path, clean);
        using (var acl = Process.Start(new ProcessStartInfo("icacls.exe", $"\"{path}\" /reset /T /C") { UseShellExecute = false, CreateNoWindow = true })!)
        {
            if (!acl.WaitForExit(30_000))
            {
                acl.Kill(true);
                acl.WaitForExit();
                throw new TimeoutException("old profile permissions reset timed out");
            }
            if (acl.ExitCode != 0) throw new InvalidOperationException("old profile permissions reset failed");
        }
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            try { File.SetAttributes(file, FileAttributes.Normal); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        foreach (var dir in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories))
            try { File.SetAttributes(dir, FileAttributes.Directory); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        Directory.Delete(path, true);
    }

    static void WaitForHiveUnload(string sid, TimeSpan timeout)
    {
        var until = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < until)
        {
            using var hive = Registry.Users.OpenSubKey(sid);
            using var classes = Registry.Users.OpenSubKey(sid + "_Classes");
            if (hive is null && classes is null) return;
            Thread.Sleep(10);
        }
        throw new TimeoutException("Customer registry hives did not unload");
    }

    // A customer can leave links in the account: folder links (junctions) and hard links to files they cannot change
    // themselves. This SYSTEM clean-up must never copy over or delete through them, so they go first: a link pointing
    // outside the account is removed (only the link, never its target); links Windows makes inside the account stay.
    static int RemoveLinks(string dir, string profile, string clean)
    {
        var n = 0;
        foreach (var e in new DirectoryInfo(dir).EnumerateFileSystemInfos("*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0 }))
        {
            if (e.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                var target = e.LinkTarget is string t ? Path.GetFullPath(t, Path.GetDirectoryName(e.FullName)!) : null;
                if (target is not null && target.StartsWith(profile + "\\", StringComparison.OrdinalIgnoreCase)) continue;
                if (e is DirectoryInfo d) d.Delete(); else e.Delete();
                n++;
            }
            else if (e is DirectoryInfo d) n += RemoveLinks(d.FullName, profile, clean);
            // only files the copy will write over matter: deleting an extra file removes just that name
            else if (File.Exists(Path.Combine(clean, Path.GetRelativePath(profile, e.FullName))) && LinkCount(e.FullName) > 1) { e.Delete(); n++; }
        }
        return n;
    }

    static int LinkCount(string file)
    {
        try
        {
            using var h = File.OpenHandle(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var info = new byte[52]; // BY_HANDLE_FILE_INFORMATION: nNumberOfLinks at byte 40
            return GetFileInformationByHandle(h, info) ? BitConverter.ToInt32(info, 40) : 1;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return 1; } // held open by Windows: not a customer's
    }

    // the key's real path after any registry links; .NET only shows the name it was opened with
    static string RealName(RegistryKey key)
    {
        var buf = new byte[2048];
        return NtQueryKey(key.Handle, 3 /*KeyNameInformation*/, buf, buf.Length, out _) == 0 ? System.Text.Encoding.Unicode.GetString(buf, 4, BitConverter.ToInt32(buf, 0)) : "";
    }

    // a cache that cannot move (a file still open) is left where it is: worst case it is rebuilt, never an error
    static void Move(string from, string to)
    {
        if (!Directory.Exists(from)) return;
        try
        {
            if (Directory.Exists(to)) Directory.Delete(to, true);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            Directory.Move(from, to);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    static DateTime StartOf(Process p) { try { return p.StartTime; } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { return default; } }

    static string? Owner(Process p)
    {
        var h = Native.OpenProcess(0x1000 /*QUERY_LIMITED_INFORMATION*/, false, p.Id);
        if (h == IntPtr.Zero) return null;
        try
        {
            if (!OpenProcessToken(h, 0x8 /*TOKEN_QUERY*/, out var t)) return null;
            try
            {
                GetTokenInformation(t, 1 /*TokenUser*/, IntPtr.Zero, 0, out var size);
                var buf = Marshal.AllocHGlobal(size);
                try { return GetTokenInformation(t, 1, buf, size, out _) ? new SecurityIdentifier(Marshal.ReadIntPtr(buf)).Value : null; }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { Native.CloseHandle(t); }
        }
        finally { Native.CloseHandle(h); }
    }

    [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSLogoffSession(IntPtr server, uint sessionId, bool wait);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file, byte[] info);
    [DllImport("ntdll.dll")] static extern int NtQueryKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle key, int cls, byte[] info, int length, out int result);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int length, out int returned);
}
