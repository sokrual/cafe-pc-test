using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

// D2 pen drives. The installer (pendrives.ps1) tells Windows not to set up any USB storage device (compatible ID
// USB\Class_08), so a plugged-in pen drive shows nothing. Every 5 seconds the watchdog reports each one to the counter
// and applies the answer: an allowed drive goes on Windows' own "allow these device IDs" list and is set up again;
// read-only uses Windows' StorageDevicePolicies\WriteProtect, which Windows reads when it sets a drive up.
// A drive that works without an answer from this visit is taken out of Windows again. Programs on it never run (D1).
static class PenDrives
{
    const string Restrictions = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
    const string StoragePolicies = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
    static readonly object Gate = new();
    static string? _statePath; // which drive has access now; in the keys folder, so only admins and Windows can change it

    public record Drive(string Device, string Name, bool Working);
    record Access(string Device, string Mode, long Id, string Name);
    record Answer(long Id, string? Access);

    public static void Init(string keysDirectory) => _statePath = Path.Combine(keysDirectory, "pen-drive.json");

    /// Off until the installer's second step and in setup mode, so the owner can use pen drives while setting the PC up.
    static bool On()
    {
        using var key = Registry.LocalMachine.OpenSubKey(Restrictions);
        return key?.GetValue("DenyDeviceIDs") is 1 && key.OpenSubKey("DenyDeviceIDs")?.GetValueNames().Length > 0;
    }

    public static void Check(HttpClient http, Action<string> log)
    {
        lock (Gate)
        {
            if (_statePath is null || !On()) return;
            var current = Read();
            if (AllowListed() != current?.Device) SetAllowList(current?.Device); // never allow a drive the state file does not name
            var drives = List();
            if (current is not null && !drives.Any(d => Same(d.Device, current.Device))) { End(current, "was taken out", log); current = null; }
            foreach (var drive in drives)
            {
                var answer = Ask(http, drive, log); // null: the counter PC could not be reached
                if (current is not null && Same(drive.Device, current.Device))
                {
                    if (answer is not null && answer.Access != current.Mode) { End(current, "lost its access (visit ended or another drive was allowed)", log); current = null; }
                    continue;
                }
                if (drive.Working) { Remove(drive.Device); log($"pen drive {drive.Name} was working without an answer from the counter; taken out of Windows"); continue; }
                if (answer?.Access is "read" or "write")
                {
                    if (current is not null) End(current, "replaced by another allowed drive", log);
                    current = Allow(http, drive, answer.Access, answer.Id, log);
                }
            }
        }
    }

    /// Logout from the lock screen, also when the counter PC cannot be reached: the allowed drive loses its access.
    public static void EndAccess(Action<string> log)
    {
        try { lock (Gate) { if (Read() is Access current) End(current, "visit ended at logout", log); } }
        catch (Exception e) { log("pen drive access end at logout failed: " + e.Message); }
    }

    static Answer? Ask(HttpClient http, Drive drive, Action<string> log)
    {
        try
        {
            using var response = http.PostAsJsonAsync("/pc/pen-drive", new { device = drive.Device, name = drive.Name }).GetAwaiter().GetResult();
            if ((int)response.StatusCode == 400) return new Answer(0, null); // nobody is playing: no access
            if (!response.IsSuccessStatusCode) return null;
            return JsonSerializer.Deserialize<Answer>(response.Content.ReadAsStringAsync().GetAwaiter().GetResult(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException or JsonException) { return null; }
    }

    static Access Allow(HttpClient http, Drive drive, string mode, long id, Action<string> log)
    {
        using (var key = Registry.LocalMachine.CreateSubKey(StoragePolicies)) key.SetValue("WriteProtect", mode == "read" ? 1 : 0, RegistryValueKind.DWord);
        var access = new Access(drive.Device, mode, id, drive.Name);
        Write(access); // first: if the PC stops right now, the next check still knows which drive to take back
        SetAllowList(drive.Device);
        var before = Letters();
        Remove(drive.Device); // set up again from scratch, now allowed and with the right write setting
        log($"pen drive {drive.Name} allowed {(mode == "read" ? "read-only" : "read and write")} (counter request {id})");
        _ = Task.Run(() => Scan(http, access, before, log));
        return access;
    }

    static void End(Access access, string why, Action<string> log)
    {
        SetAllowList(null);
        using (var key = Registry.LocalMachine.CreateSubKey(StoragePolicies)) key.SetValue("WriteProtect", 1, RegistryValueKind.DWord);
        if (_statePath is not null) File.Delete(_statePath);
        Remove(access.Device); // set up again: now blocked, so it shows on the counter again if it is still plugged in
        log($"pen drive {access.Name} {why}; access ended");
    }

    /// Microsoft Defender checks every new drive letter the allowed drive brought. Defender's own real-time
    /// protection also checks each file when it is opened.
    static void Scan(HttpClient http, Access access, HashSet<string> before, Action<string> log)
    {
        try
        {
            var defender = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
            List<string> added = [];
            for (var i = 0; i < 30 && added.Count == 0; i++) { Thread.Sleep(1000); added = Letters().Except(before).ToList(); }
            if (added.Count == 0) { log($"pen drive {access.Name}: no drive letter appeared to scan"); return; }
            if (!File.Exists(defender)) { log($"pen drive {access.Name}: Microsoft Defender is not on this PC; not scanned"); return; }
            var threats = false;
            foreach (var letter in added)
            {
                var exit = Run(defender, TimeSpan.FromMinutes(30), "-Scan", "-ScanType", "3", "-File", letter);
                log($"pen drive {access.Name}: Defender scan of {letter} ended with code {exit}");
                threats |= exit == 2; // 2: Defender found a threat
            }
            using var response = http.PostAsJsonAsync($"/pc/pen-drive/{access.Id}/scan", new { threats }).GetAwaiter().GetResult();
        }
        catch (Exception e) { log($"pen drive {access.Name}: scan report failed: {e.Message}"); }
    }

    /// CI only (no real USB there): reads USB storage through Windows' device functions, then gives a made-up drive
    /// read-only, then read and write, then ends its access at logout, checking the allow list and write setting each time.
    /// Exit 0: all as expected. The watchdog service must be stopped, as it would correct the allow list meanwhile.
    public static int SelfTest(string keysDirectory)
    {
        Action<string> log = Console.WriteLine;
        Init(keysDirectory);
        if (!On()) return 3;
        log($"USB storage devices now: {List().Count}");
        const string fake = @"USB\VID_FFFF&PID_FFFF\CAFETEST";
        using var http = new HttpClient { BaseAddress = new Uri("https://127.0.0.1:1") };
        var drive = new Drive(fake, "CI test drive", false);
        lock (Gate)
        {
            Allow(http, drive, "read", 0, log);
            if (AllowListed() != fake || WriteProtect() != 1 || Read()?.Device != fake) return 4;
            Allow(http, drive, "write", 0, log);
            if (AllowListed() != fake || WriteProtect() != 0) return 5;
        }
        EndAccess(log);
        return AllowListed() is null && WriteProtect() == 1 && Read() is null ? 0 : 6;
    }

    static int? WriteProtect() { using var key = Registry.LocalMachine.OpenSubKey(StoragePolicies); return key?.GetValue("WriteProtect") as int?; }

    static HashSet<string> Letters() => DriveInfo.GetDrives().Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
    static bool Same(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);

    static void Remove(string device)
    {
        var pnputil = Path.Combine(Environment.SystemDirectory, "pnputil.exe");
        Run(pnputil, TimeSpan.FromSeconds(60), "/remove-device", device, "/subtree");
        Run(pnputil, TimeSpan.FromSeconds(60), "/scan-devices");
    }

    static int Run(string exe, TimeSpan timeout, params string[] args)
    {
        var start = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        foreach (var a in args) start.ArgumentList.Add(a);
        using var p = Process.Start(start)!;
        _ = p.StandardOutput.ReadToEndAsync(); // keep the output pipe empty so the program never waits on it
        if (!p.WaitForExit(timeout)) { try { p.Kill(); } catch (InvalidOperationException) { } return -1; }
        return p.ExitCode;
    }

    static string? AllowListed()
    {
        using var key = Registry.LocalMachine.OpenSubKey(Restrictions + @"\AllowInstanceIDs");
        return key?.GetValue("1") as string;
    }

    static void SetAllowList(string? device)
    {
        using var key = Registry.LocalMachine.CreateSubKey(Restrictions);
        key.DeleteSubKeyTree("AllowInstanceIDs", false);
        using var list = key.CreateSubKey("AllowInstanceIDs");
        if (device is not null) list.SetValue("1", device);
        key.SetValue("AllowInstanceIDs", 1, RegistryValueKind.DWord);
    }

    static Access? Read()
    {
        try { return _statePath is not null && File.Exists(_statePath) ? JsonSerializer.Deserialize<Access>(File.ReadAllBytes(_statePath)) : null; }
        catch (JsonException) { return null; }
    }

    static void Write(Access access)
    {
        var temp = _statePath + ".new";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(JsonSerializer.SerializeToUtf8Bytes(access));
            stream.Flush(true);
        }
        PcProxy.ReplaceDurably(temp, _statePath!);
    }

    /// USB storage devices plugged in now: every USB device with the mass-storage compatible ID, set up or held back.
    public static List<Drive> List()
    {
        var list = new List<Drive>();
        var set = SetupDiGetClassDevsW(IntPtr.Zero, "USB", IntPtr.Zero, 0x2 /*DIGCF_PRESENT*/ | 0x4 /*DIGCF_ALLCLASSES*/);
        if (set == new IntPtr(-1)) return list;
        try
        {
            var data = new SpDevinfoData { cbSize = (uint)Marshal.SizeOf<SpDevinfoData>() };
            for (uint i = 0; SetupDiEnumDeviceInfo(set, i, ref data); i++)
            {
                if (!(Strings(set, ref data, 0x2 /*SPDRP_COMPATIBLEIDS*/)?.Any(id => id.Equals(@"USB\Class_08", StringComparison.OrdinalIgnoreCase)) ?? false)) continue;
                var id = new char[400];
                if (!SetupDiGetDeviceInstanceIdW(set, ref data, id, (uint)id.Length, out var length)) continue;
                var working = CM_Get_DevNode_Status(out var status, out _, data.DevInst, 0) == 0 && (status & 0x8 /*DN_STARTED*/) != 0;
                var name = BusName(set, ref data) ?? Strings(set, ref data, 0x0 /*SPDRP_DEVICEDESC*/)?.FirstOrDefault() ?? "USB storage";
                list.Add(new Drive(new string(id, 0, (int)length - 1), name, working));
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
        return list;
    }

    static string[]? Strings(IntPtr set, ref SpDevinfoData data, uint property)
    {
        SetupDiGetDeviceRegistryPropertyW(set, ref data, property, out _, null, 0, out var size);
        if (size == 0) return null;
        var buffer = new byte[size];
        if (!SetupDiGetDeviceRegistryPropertyW(set, ref data, property, out _, buffer, size, out _)) return null;
        return Encoding.Unicode.GetString(buffer).Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    // the product name the drive itself reports, for example "Cruzer Blade"
    static string? BusName(IntPtr set, ref SpDevinfoData data)
    {
        var key = new DevPropKey { fmtid = new Guid("540b947e-8b40-45bc-a8a2-6a0b894cbda2"), pid = 4 };
        SetupDiGetDevicePropertyW(set, ref data, ref key, out _, null, 0, out var size, 0);
        if (size == 0) return null;
        var buffer = new byte[size];
        if (!SetupDiGetDevicePropertyW(set, ref data, ref key, out _, buffer, size, out _, 0)) return null;
        var text = Encoding.Unicode.GetString(buffer).TrimEnd('\0').Trim();
        return text.Length > 0 ? text : null;
    }

    [StructLayout(LayoutKind.Sequential)] struct SpDevinfoData { public uint cbSize; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }
    [StructLayout(LayoutKind.Sequential)] struct DevPropKey { public Guid fmtid; public uint pid; }
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr SetupDiGetClassDevsW(IntPtr classGuid, string enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref SpDevinfoData data);
    [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiGetDeviceRegistryPropertyW(IntPtr set, ref SpDevinfoData data, uint property, out uint type, byte[]? buffer, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool SetupDiGetDeviceInstanceIdW(IntPtr set, ref SpDevinfoData data, char[] id, uint size, out uint required);
    [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiGetDevicePropertyW(IntPtr set, ref SpDevinfoData data, ref DevPropKey key, out uint type, byte[]? buffer, uint size, out uint required, uint flags);
    [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("cfgmgr32.dll")] static extern int CM_Get_DevNode_Status(out uint status, out uint problem, uint devInst, uint flags);
}
