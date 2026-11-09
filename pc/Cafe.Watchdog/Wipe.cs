using System.Diagnostics;
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
        if (profile is null || !Directory.Exists(clean)) report += "; no clean copy, files not reset";
        else
        {
            // graphics driver caches stay between customers (games load faster). robocopy /MIR deletes them even with
            // /XD (tested on CI), so they wait in an admin-only folder during the copy and come back after it
            string[] caches = [@"AppData\Local\NVIDIA", @"AppData\LocalLow\NVIDIA", @"AppData\Local\AMD", @"AppData\Local\D3DSCache"];
            var hold = Path.Combine(Data, "caches");
            if (Directory.Exists(hold)) Directory.Delete(hold, true); // left over from a clean-up that was cut off
            Directory.CreateDirectory(hold);
            for (var i = 0; i < caches.Length; i++) Move(Path.Combine(profile, caches[i]), Path.Combine(hold, $"{i}"));
            using var rc = Process.Start(new ProcessStartInfo("robocopy.exe", $"\"{clean}\" \"{profile}\" /MIR /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP /XF NTUSER.DAT* ntuser.* UsrClass.dat*") { UseShellExecute = false, CreateNoWindow = true })!;
            if (!rc.WaitForExit(300_000)) rc.Kill();
            for (var i = 0; i < caches.Length; i++) Move(Path.Combine(hold, $"{i}"), Path.Combine(profile, caches[i]));
            report += $"; files reset (robocopy {(rc.HasExited ? rc.ExitCode : -1)})"; // 0-7 = fine; files Windows keeps open are skipped
        }

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
                using var key = hive.CreateSubKey($@"Software\Microsoft\Windows\CurrentVersion\{k}");
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
        var h = OpenProcess(0x1000 /*QUERY_LIMITED_INFORMATION*/, false, p.Id);
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

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int length, out int returned);
}
