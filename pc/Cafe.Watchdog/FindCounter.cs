using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

// S5: the counter PC needs no fixed address. When it has not answered for 30 s, this PC asks the shop network where
// the cafe server is (UDP broadcast, port 5442; Cafe.Server answers "here"). It moves only to an address that shows
// the pinned certificate (server.pin) and accepts this PC's key: nobody else on the network can pass that. Then it
// saves the address (watchdog.args) and, if DNS went to the old address (the internet filter runs on the counter PC),
// points DNS to the new one (dns.ps1).
static class FindCounter
{
    public const int Port = 5442;
    static readonly byte[] Ask = "GAMINGCAFE-WHERE"u8.ToArray(), Here = "GAMINGCAFE-HERE"u8.ToArray();
    static DateTime _downSince = DateTime.MaxValue, _nextProbe = DateTime.MinValue, _nextSearch = DateTime.MinValue;

    /// Called every 5 s from the proxy's background loop. Returns a client for the counter's new address, or null.
    public static HttpClient? Check(HttpClient current, Func<Uri, HttpClient> newClient, Action<string> log)
    {
        var now = DateTime.UtcNow;
        if (now < _nextProbe) return null;
        _nextProbe = now.AddSeconds(10);
        if (Answers(current)) { _downSince = DateTime.MaxValue; return null; }
        if (_downSince == DateTime.MaxValue) _downSince = now;
        if (now - _downSince < TimeSpan.FromSeconds(30) || now < _nextSearch) return null;
        _nextSearch = now.AddSeconds(30);
        foreach (var ip in Search())
        {
            var uri = new UriBuilder(current.BaseAddress!) { Host = ip.ToString() }.Uri;
            if (uri.Host == current.BaseAddress!.Host) continue;
            var candidate = newClient(uri);
            try
            {
                using var answer = candidate.GetAsync("/pc/state").GetAwaiter().GetResult();
                if (answer.IsSuccessStatusCode)
                {
                    if (Answers(current)) { candidate.Dispose(); _downSince = DateTime.MaxValue; return null; }   // it came back meanwhile
                    _downSince = DateTime.MaxValue;
                    return candidate;
                }
                log($"counter search: {ip} answered HTTP {(int)answer.StatusCode} to this PC's key; not used");
            }
            catch (Exception e) { log($"counter search: {ip} failed the certificate or connection check ({e.GetBaseException().Message}); not used"); }
            candidate.Dispose();
        }
        return null;
    }

    /// Any HTTP answer from the pinned server counts (even 401); no connection or a wrong certificate does not.
    static bool Answers(HttpClient client)
    {
        try { using var _ = client.GetAsync("/pc/state").GetAwaiter().GetResult(); return true; }
        catch (Exception) { return false; }
    }

    static List<IPAddress> Search()
    {
        var found = new List<IPAddress>();
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0)) { EnableBroadcast = true };
        foreach (var to in Targets())
            try { udp.Send(Ask, Ask.Length, new IPEndPoint(to, Port)); } catch (SocketException) { }
        var until = DateTime.UtcNow.AddSeconds(2);
        while (DateTime.UtcNow < until && found.Count < 8)
        {
            udp.Client.ReceiveTimeout = Math.Max(1, (int)(until - DateTime.UtcNow).TotalMilliseconds);
            try
            {
                IPEndPoint? from = null;
                var reply = udp.Receive(ref from);
                if (reply.AsSpan().SequenceEqual(Here) && !found.Contains(from.Address)) found.Add(from.Address);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset) { }   // an address with nobody listening
            catch (SocketException) { break; }   // time is up
        }
        return found;
    }

    /// 255.255.255.255 and each network's own broadcast address (Windows may send the first on one network only).
    static IEnumerable<IPAddress> Targets()
    {
        yield return IPAddress.Broadcast;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            foreach (var a in nic.GetIPProperties().UnicastAddresses)
            {
                if (a.Address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(a.Address)) continue;
                var ip = a.Address.GetAddressBytes();
                var mask = a.IPv4Mask.GetAddressBytes();
                for (var i = 0; i < 4; i++) ip[i] |= (byte)~mask[i];
                yield return new IPAddress(ip);
            }
        }
    }

    /// Keep the new address for the next start, and move DNS with it when DNS went to the counter PC.
    public static void Save(Uri moved, Uri old, string dataDirectory, Action<string> log)
    {
        log($"counter PC found at {moved.Host} (was {old.Host}); certificate and key checked");
        try
        {
            var args = Path.Combine(AppContext.BaseDirectory, "watchdog.args");
            var line = Regex.Replace(File.ReadAllText(args), @"--server\s+https://[^\s""]+", $"--server {moved.GetLeftPart(UriPartial.Authority)}");
            File.WriteAllText(args + ".new", line);
            File.Move(args + ".new", args, overwrite: true);
        }
        catch (Exception e) { log("could not save the counter's new address: " + e.Message); }
        try
        {
            var dnsFile = Path.Combine(dataDirectory, "dns-server.txt");
            if (!File.Exists(dnsFile) || File.ReadAllText(dnsFile).Trim() != old.Host) return;   // DNS goes elsewhere (tests)
            var dns = Process.Start(new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                ArgumentList = { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(AppContext.BaseDirectory, "dns.ps1"), "-DnsServer", moved.Host, "-DataPath", dataDirectory },
                UseShellExecute = false,
                CreateNoWindow = true
            })!;
            if (!dns.WaitForExit(120_000)) { dns.Kill(); log("DNS move to the counter's new address timed out"); }
            else log(dns.ExitCode == 0 ? $"DNS now goes to {moved.Host}" : $"DNS move failed (exit {dns.ExitCode})");
        }
        catch (Exception e) { log("could not move DNS to the counter's new address: " + e.Message); }
    }
}
