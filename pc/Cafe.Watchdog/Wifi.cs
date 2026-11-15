using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

// D3 Wi-Fi: customers can join only the cafe's own Wi-Fi networks, through the cafe's own routers.
// The installer (wifi.ps1) asks the owner which nearby networks are the cafe's; "--wifi-apply" records the routers it
// can see under those names and sets Windows' own Wi-Fi filters (netsh wlan filters: only an admin can change them).
// Every 5 seconds Check() disconnects Wi-Fi joined through any other router, for example a phone hotspot renamed to
// the cafe's network name, and tells the owner's counter screen. Uses Windows' Wi-Fi functions (wlanapi.dll), so
// it works in every Windows language.
static class Wifi
{
    public record Setup(string[] Networks, string[] Routers);
    record Seen(string Network, string Router);
    static readonly HashSet<string> Reported = [];
    static readonly List<Seen> Unsent = [];

    public static string SetupPath(string keysDirectory) => Path.Combine(keysDirectory, "wifi.json");

    public static void Check(string keysDirectory, HttpClient http, Action<string> log)
    {
        var path = SetupPath(keysDirectory);
        if (!File.Exists(path)) return; // no Wi-Fi limits on this PC (no Wi-Fi card, setup mode, or not installed yet)
        var setup = JsonSerializer.Deserialize<Setup>(File.ReadAllBytes(path))!;
        using var wlan = Wlan.Open();
        if (wlan is null) return;
        foreach (var card in wlan.Cards())
        {
            var connected = wlan.Connection(card);
            if (connected is null || setup.Routers.Contains(connected.Router)) continue;
            wlan.Disconnect(card);
            if (Reported.Add(connected.Router))
            {
                log($"Wi-Fi \"{connected.Network}\" through unknown router {connected.Router}: disconnected");
                Unsent.Add(connected);
            }
        }
        while (Unsent.Count > 0)
            try
            {
                using var response = http.PostAsJsonAsync("/pc/wifi-alert", new { network = Unsent[0].Network, router = Unsent[0].Router }).GetAwaiter().GetResult();
                if (!response.IsSuccessStatusCode) break;
                Unsent.RemoveAt(0);
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException) { break; } // sent once the PC is back on the cafe network
    }

    /// Installer: the Wi-Fi networks this PC can see now, strongest first, one per line. Exit 3: no Wi-Fi on this PC.
    public static int Networks()
    {
        using var wlan = Wlan.Open();
        if (wlan is null || wlan.Cards().Count == 0) return 3;
        foreach (var name in Scan(wlan).Select(s => s.Network).Distinct()) Console.WriteLine(name);
        return 0;
    }

    /// Installer: only these networks, through the routers seen for them now. No names: Wi-Fi is closed to customers.
    public static int Apply(string keysDirectory, string[] networks)
    {
        using var wlan = Wlan.Open();
        if (wlan is null || wlan.Cards().Count == 0) return 3;
        var routers = Scan(wlan).Where(s => networks.Contains(s.Network)).Select(s => s.Router).Distinct().ToArray();
        foreach (var name in networks) Console.WriteLine($"{name}: {routers.Length} cafe router(s) recorded");
        Off(keysDirectory);
        foreach (var name in networks) Netsh("add", "filter", "permission=allow", $"ssid={name}", "networktype=infrastructure");
        Netsh("add", "filter", "permission=denyall", "networktype=infrastructure");
        Netsh("add", "filter", "permission=denyall", "networktype=adhoc");
        Netsh("set", "createalluserprofile", "enabled=no"); // only an admin can save a Wi-Fi network for every account
        var temp = SetupPath(keysDirectory) + ".new";
        File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(new Setup(networks, routers)));
        PcProxy.ReplaceDurably(temp, SetupPath(keysDirectory));
        return routers.Length > 0 || networks.Length == 0 ? 0 : 4; // 4: a chosen network had no router in range
    }

    /// Setup mode and uninstall: Windows' Wi-Fi filters back to none, and the router list removed.
    public static int Off(string keysDirectory)
    {
        var path = SetupPath(keysDirectory);
        if (!File.Exists(path)) return 0;
        foreach (var name in JsonSerializer.Deserialize<Setup>(File.ReadAllBytes(path))!.Networks)
            Netsh("delete", "filter", "permission=allow", $"ssid={name}", "networktype=infrastructure");
        Netsh("delete", "filter", "permission=denyall", "networktype=infrastructure");
        Netsh("delete", "filter", "permission=denyall", "networktype=adhoc");
        Netsh("set", "createalluserprofile", "enabled=yes"); // Windows' default
        File.Delete(path);
        return 0;
    }

    static List<Seen> Scan(Wlan wlan)
    {
        foreach (var card in wlan.Cards()) wlan.Scan(card);
        Thread.Sleep(4000); // Windows finishes a scan within about 4 seconds
        return wlan.Cards().SelectMany(c => wlan.Routers(c).Concat(wlan.Connection(c) is Seen now ? [now] : Array.Empty<Seen>())).ToList();
    }

    static void Netsh(params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        start.ArgumentList.Add("wlan");
        foreach (var a in args) start.ArgumentList.Add(a);
        using var p = Process.Start(start)!;
        Console.WriteLine($"netsh wlan {string.Join(' ', args)}: {p.StandardOutput.ReadToEnd().Trim()}");
        p.WaitForExit();
    }

    static string Mac(IntPtr at) => string.Join(":", Enumerable.Range(0, 6).Select(i => Marshal.ReadByte(at, i).ToString("x2")));

    static string? Ssid(IntPtr at) // DOT11_SSID: length, then up to 32 bytes
    {
        var length = Marshal.ReadInt32(at);
        if (length is < 1 or > 32) return null;
        var bytes = new byte[length];
        Marshal.Copy(at + 4, bytes, 0, length);
        var name = Encoding.UTF8.GetString(bytes);
        return name.Any(char.IsControl) ? null : name;
    }

    sealed class Wlan : IDisposable
    {
        readonly IntPtr _handle;
        Wlan(IntPtr handle) => _handle = handle;
        public static Wlan? Open() // null without Windows' Wi-Fi service (a PC with no Wi-Fi card, or Windows Server)
        {
            try { return WlanOpenHandle(2, IntPtr.Zero, out _, out var handle) == 0 ? new Wlan(handle) : null; }
            catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException) { return null; }
        }
        public void Dispose() => WlanCloseHandle(_handle, IntPtr.Zero);

        public List<Guid> Cards()
        {
            var cards = new List<Guid>();
            if (WlanEnumInterfaces(_handle, IntPtr.Zero, out var list) != 0) return cards;
            for (var i = 0; i < Marshal.ReadInt32(list); i++) cards.Add(Marshal.PtrToStructure<Guid>(list + 8 + i * 532)); // WLAN_INTERFACE_INFO is 532 bytes
            WlanFreeMemory(list);
            return cards;
        }

        public Seen? Connection(Guid card)
        {
            if (WlanQueryInterface(_handle, ref card, 7 /*current connection*/, IntPtr.Zero, out _, out var data, IntPtr.Zero) != 0) return null;
            try { return Marshal.ReadInt32(data) == 1 /*connected*/ && Ssid(data + 520) is string name ? new Seen(name, Mac(data + 560)) : null; }
            finally { WlanFreeMemory(data); }
        }

        public List<Seen> Routers(Guid card)
        {
            var routers = new List<Seen>();
            if (WlanGetNetworkBssList(_handle, ref card, IntPtr.Zero, 3 /*any*/, false, IntPtr.Zero, out var list) != 0) return routers;
            for (var i = 0; i < Marshal.ReadInt32(list + 4); i++)
            {
                var entry = list + 8 + i * 360; // WLAN_BSS_ENTRY is 360 bytes: SSID at 0, router address at 40
                if (Ssid(entry) is string name) routers.Add(new Seen(name, Mac(entry + 40)));
            }
            WlanFreeMemory(list);
            return routers;
        }

        public void Scan(Guid card) => WlanScan(_handle, ref card, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        public void Disconnect(Guid card) => WlanDisconnect(_handle, ref card, IntPtr.Zero);

        [DllImport("wlanapi.dll")] static extern int WlanOpenHandle(uint version, IntPtr reserved, out uint negotiated, out IntPtr handle);
        [DllImport("wlanapi.dll")] static extern int WlanCloseHandle(IntPtr handle, IntPtr reserved);
        [DllImport("wlanapi.dll")] static extern int WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr list);
        [DllImport("wlanapi.dll")] static extern int WlanQueryInterface(IntPtr handle, ref Guid card, int opcode, IntPtr reserved, out uint size, out IntPtr data, IntPtr type);
        [DllImport("wlanapi.dll")] static extern int WlanGetNetworkBssList(IntPtr handle, ref Guid card, IntPtr ssid, int type, bool secure, IntPtr reserved, out IntPtr list);
        [DllImport("wlanapi.dll")] static extern int WlanScan(IntPtr handle, ref Guid card, IntPtr ssid, IntPtr ie, IntPtr reserved);
        [DllImport("wlanapi.dll")] static extern int WlanDisconnect(IntPtr handle, ref Guid card, IntPtr reserved);
        [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr memory);
    }
}
