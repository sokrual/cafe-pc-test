using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;

// Logout wipe. The lock screen (running as Customer) leaves a note in ProgramData\ShinzxCafe\wipe when a customer
// logs out; the watchdog, as SYSTEM, then closes everything that customer opened, puts the Customer account's files
// back to the owner's clean copy (that removes every app login: Discord, browsers, Epic, Riot ...), clears Steam's
// saved logins (kept in Steam's own folder, outside the account), and deletes the note. Until then the lock screen
// lets nobody log in.
static class Wipe
{
    public const string User = "Customer";
    static readonly string Data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ShinzxCafe");
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
    public static bool PrepareRequest(out int error)
    {
        error = 0;
        try
        {
            var attributes = File.GetAttributes(Request);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0) return true;
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

    // The watchdog has the same PC token and certificate pin as the lock screen. A missing answer,
    // invalid response, or non-null session all mean "do not clean".
    public static bool ServerHasNoSession(out int error)
    {
        error = 0;
        try
        {
            var line = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "watchdog.args"));
            var match = Regex.Match(line, @"--server\\s+(https://[^\\s\""]+)");
            if (!match.Success) { error = 87; return false; }
            var server = new Uri(match.Groups[1].Value);
            var token = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "pc.token")).Trim();
            var pin = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "server.pin")).Trim();
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                    cert is not null && Convert.ToHexString(SHA256.HashData(cert.RawData)).Equals(pin, StringComparison.OrdinalIgnoreCase)
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
            client.DefaultRequestHeaders.Add("X-Pc-Token", token);
            using var response = client.GetAsync(new Uri(server, "/pc/state")).GetAwaiter().GetResult();
            if (!response.IsSuccessStatusCode) { error = (int)response.StatusCode; return false; }
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

    public static string Run(string sid, string agent, HashSet<(int, DateTime)> trusted)
    {
        var keep = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "keep-running.txt")).Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#')).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var programFiles = new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 }.Select(f => Environment.GetFolderPath(f) + "\\");
        var closed = new List<Process>();
        foreach (var p in Process.GetProcesses())
        {
            if (Owner(p) != sid || trusted.Contains((p.Id, StartOf(p)))) continue;
            var f = Native.PathOf(p);
            if (f == agent) continue;
            // mouse/keyboard apps listed by the owner, only from folders customers cannot change (Steam's folder, for one,
            // is open to all users: a customer's program named like a mouse app there must not survive the clean-up)
            if (f is not null && keep.Contains(Path.GetFileName(f)) && programFiles.Any(d => f.StartsWith(d, StringComparison.OrdinalIgnoreCase))
                && !Watchdog.WritableByNonAdmins(f) && !Watchdog.WritableByNonAdmins(Path.GetDirectoryName(f)!)) continue;
            try { p.Kill(); closed.Add(p); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { } // already gone
        }
        foreach (var p in closed) p.WaitForExit(5000); // Explorer comes back by itself (Windows restarts it)

        var report = $"closed {closed.Count} programs";
        var profile = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}")?.GetValue("ProfileImagePath") as string;
        var clean = Path.Combine(Data, "clean-profile");
        if (profile is null || !Directory.Exists(clean)) throw new InvalidOperationException("clean profile unavailable");
        // graphics driver caches stay between customers (games load faster). robocopy /MIR deletes them even with
        // /XD (tested on CI), so they wait in an admin-only folder during the copy and come back after it
        string[] caches = [@"AppData\Local\NVIDIA", @"AppData\LocalLow\NVIDIA", @"AppData\Local\AMD", @"AppData\Local\D3DSCache"];
        var hold = Path.Combine(Data, "caches");
        if (Directory.Exists(hold)) Directory.Delete(hold, true); // left over from a clean-up that was cut off
        Directory.CreateDirectory(hold);
        var links = RemoveLinks(profile, profile, clean); // before any copy or delete here (no customer program runs any more)
        for (var i = 0; i < caches.Length; i++) Move(Path.Combine(profile, caches[i]), Path.Combine(hold, $"{i}"));
        int exitCode;
        try
        {
            using var rc = Process.Start(new ProcessStartInfo("robocopy.exe", $"\"{clean}\" \"{profile}\" /MIR /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP /XF NTUSER.DAT* ntuser.* UsrClass.dat*") { UseShellExecute = false, CreateNoWindow = true })!;
            if (!rc.WaitForExit(300_000))
            {
                rc.Kill(true);
                rc.WaitForExit();
                throw new TimeoutException("profile copy timed out");
            }
            exitCode = rc.ExitCode;
            if (exitCode >= 8) throw new InvalidOperationException("profile copy failed");
        }
        finally
        {
            for (var i = 0; i < caches.Length; i++) Move(Path.Combine(hold, $"{i}"), Path.Combine(profile, caches[i]));
        }
        report += $"; {links} links removed; files reset (robocopy {exitCode})"; // 0-7 = fine; files Windows keeps open are skipped

        if (Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam")?.GetValue("InstallPath") is string steam)
        {
            var cfg = Path.Combine(steam, "config");
            // customers can write in Steam's folder: never follow a link they could have put there
            if (Directory.Exists(cfg) && new DirectoryInfo(cfg).LinkTarget is null)
            {
                File.Delete(Path.Combine(cfg, "loginusers.vdf")); // the "remember me" accounts list
                var main = Path.Combine(cfg, "config.vdf");
                var text = File.Exists(main) ? File.ReadAllText(main) : "";
                var cleaned = Regex.Replace(text, @"\s*""ConnectCache""\s*\{[^{}]*\}", ""); // saved login keys
                if (cleaned != text) File.WriteAllText(main, cleaned);
                report += "; Steam logins cleared";
            }
        }
        // ways to start a program again for the next customer: autostart entries and scheduled tasks
        var runs = Path.Combine(Data, "run-keys.txt");
        using var hive = Registry.Users.OpenSubKey(sid, true); // loaded while Customer is signed in
        if (hive is not null && File.Exists(runs))
        {
            var saved = File.ReadAllLines(runs).Select(l => l.Split('\t', 3)).Where(p => p.Length == 3).ToList();
            foreach (var k in new[] { "Run", "RunOnce" })
            {
                using var key = hive.OpenSubKey($@"Software\Microsoft\Windows\CurrentVersion\{k}", true);
                if (key is null || !RealName(key).StartsWith($@"\REGISTRY\USER\{sid}\", StringComparison.OrdinalIgnoreCase)) continue; // a registry link out of the account
                foreach (var n in key.GetValueNames()) key.DeleteValue(n);
                foreach (var p in saved.Where(p => p[0] == k)) key.SetValue(p[1], p[2], p[2].Contains('%') ? RegistryValueKind.ExpandString : RegistryValueKind.String);
            }
            report += "; autostart list reset";
        }
        var tasks = Path.Combine(Environment.SystemDirectory, "Tasks");
        var removed = 0;
        foreach (var f in Directory.EnumerateFiles(tasks, "*", SearchOption.AllDirectories))
        {
            string xml;
            try { xml = File.ReadAllText(f); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            if (!xml.Contains($">{sid}<") && !xml.Contains($"\\{User}<") && !xml.Contains($">{User}<")) continue; // the task runs as Customer
            using var d = Process.Start(new ProcessStartInfo("schtasks.exe", $"/delete /tn \"{f[tasks.Length..]}\" /f") { UseShellExecute = false, CreateNoWindow = true })!;
            d.WaitForExit(10_000);
            removed++;
        }
        return report + $"; {removed} customer tasks removed";
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
                try { if (e is DirectoryInfo d) d.Delete(); else e.Delete(); n++; } catch (IOException) { } catch (UnauthorizedAccessException) { }
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

    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file, byte[] info);
    [DllImport("ntdll.dll")] static extern int NtQueryKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle key, int cls, byte[] info, int length, out int result);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int length, out int returned);
}
