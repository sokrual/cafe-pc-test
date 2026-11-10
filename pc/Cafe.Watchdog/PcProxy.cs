using System.IO.Pipes;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

static class PcProxy
{
    const uint PipeAccessDuplex = 0x00000003, FileFlagOverlapped = 0x40000000;
    const uint PipeTypeByte = 0, PipeWait = 0, PipeRejectRemoteClients = 0x00000008;
    const int MaxRequestBytes = 65536;
    static HttpClient? _http;
    static string? _agentPath;
    static Action<string> _log = message => Console.Error.WriteLine(message);
    static int _refusalLogged;
    static OfflineUnlockStore? _offline;
    sealed record Request(string Method, string Path, string? Body);
    sealed record Response(int Status, string Content);
    [StructLayout(LayoutKind.Sequential)]
    struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances, uint outBuffer, uint inBuffer, uint timeout, ref SecurityAttributes attributes);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    static string? Option(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    public static int TestPipeProbe()
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", "CafePc", PipeDirection.InOut);
            try { pipe.Connect(3000); }
            catch (TimeoutException) { return 2; } // no listening pipe
            catch (IOException) { return 0; } // the server accepted and immediately refused this process
            try
            {
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1024, true) { AutoFlush = true };
                writer.WriteLine("{\"Method\":\"GET\",\"Path\":\"/pc/state\",\"Body\":null}");
                using var reader = new StreamReader(pipe, Encoding.UTF8, false, 1024, true);
                return reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult() is null ? 0 : 1;
            }
            catch (IOException) { return 0; } // the server rejected this executable and closed its pipe
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("pipe probe could not connect: " + e.Message);
            return 2;
        }
    }

    public static void StartTest(string[] args)
    {
        var sid = Option(args, "--pipe-sid") ?? WindowsIdentity.GetCurrent().User!.Value;
        Start(Option(args, "--server") ?? throw new InvalidOperationException("test server URL missing"),
            Option(args, "--token-file") ?? throw new InvalidOperationException("test token file missing"),
            Option(args, "--pin-file") ?? throw new InvalidOperationException("test pin file missing"),
            sid,
            Option(args, "--agent-path") ?? throw new InvalidOperationException("test Cafe.Agent.exe path missing"),
            CancellationToken.None,
            message => Console.Error.WriteLine(message));
    }

    public static void StartFromWatchdogArgs(string line, string agentPath, CancellationToken stop, Action<string> log)
    {
        var server = Regex.Match(line, @"--server\s+(https://[^\s""]+)");
        if (!server.Success) throw new InvalidOperationException("watchdog server URL is missing or invalid");
        string? FileOption(string name)
        {
            var m = Regex.Match(line, Regex.Escape(name) + @"\s+(?:""([^""]+)""|(\S+))");
            return m.Success ? (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value) : null;
        }
        var data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ShinzxCafe", "keys");
        var token = FileOption("--token-file") ?? Path.Combine(data, "pc.token");
        var pin = FileOption("--pin-file") ?? Path.Combine(data, "server.pin");
        var sid = FileOption("--pipe-sid") ?? Wipe.CustomerSid()
            ?? throw new InvalidOperationException("Customer account is missing; refusing to open the PC pipe");
        Start(server.Groups[1].Value, token, pin, sid, agentPath, stop, log);
    }

    static void Start(string server, string tokenFile, string pinFile, string clientSid, string agentPath, CancellationToken stop, Action<string> log)
    {
        if (_http is not null) throw new InvalidOperationException("PC proxy already started");
        var serverUri = new Uri(server, UriKind.Absolute);
        if (serverUri.Scheme != Uri.UriSchemeHttps) throw new InvalidOperationException("PC server must use HTTPS");
        var pin = File.ReadAllText(pinFile).Trim();
        var token = File.ReadAllText(tokenFile).Trim();
        if (pin.Length != 64 || !Regex.IsMatch(pin, @"\A[0-9a-fA-F]{64}\z")) throw new InvalidOperationException("certificate pin is missing or invalid");
        if (string.IsNullOrWhiteSpace(token)) throw new InvalidOperationException("PC token is missing or empty");

        // Build the HTTP client and first listening pipe before publishing the proxy as started.
        // Missing keys, an invalid header, or a pipe/ACL failure must leave _http null for a clean retry.
        HttpClient? client = null;
        NamedPipeServerStream? firstPipe = null;
        try
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                    cert is not null && Convert.ToHexString(SHA256.HashData(cert.RawData)).Equals(pin, StringComparison.OrdinalIgnoreCase)
            };
            client = new HttpClient(handler) { BaseAddress = serverUri, Timeout = TimeSpan.FromSeconds(10) };
            client.DefaultRequestHeaders.Add("X-Pc-Token", token);
            var resolvedAgentPath = Path.GetFullPath(agentPath);
            _offline = new OfflineUnlockStore(Path.Combine(Path.GetDirectoryName(Path.GetFullPath(tokenFile))!, "offline-unlock.bin"));
            firstPipe = NewPipe(clientSid); // proves the protected listener can actually be created
            _agentPath = resolvedAgentPath;
            _log = log;
            _http = client;
            var listeningPipe = firstPipe;
            firstPipe = null;
            try { _ = Task.Run(() => Listen(clientSid, stop, listeningPipe), CancellationToken.None); }
            catch
            {
                _http = null;
                _agentPath = null;
                listeningPipe.Dispose();
                throw;
            }
            client = null; // ownership transferred to _http
            _ = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    RefreshOfflineUnlockData();
                    SyncOfflineSales();
                    try { await Task.Delay(TimeSpan.FromSeconds(30), stop); }
                    catch (OperationCanceledException) { break; }
                }
            }, CancellationToken.None);
        }
        catch
        {
            firstPipe?.Dispose();
            client?.Dispose();
            throw;
        }
    }

    public static void RefreshOfflineUnlockData()
    {
        try
        {
            var client = _http ?? throw new InvalidOperationException("PC proxy is not initialized");
            using var response = client.GetAsync("/pc/offline-unlock-data").GetAwaiter().GetResult();
            response.EnsureSuccessStatusCode();
            _offline?.UpdateFromServer(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException or InvalidOperationException)
        { _log("offline unlock data refresh deferred: " + e.Message); }
    }

    public static void SyncOfflineSales()
    {
        var client = _http;
        var store = _offline;
        if (client is null || store is null) return;
        foreach (var sale in store.PendingSales())
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, "/pc/offline-sales")
                { Content = JsonContent.Create(sale) };
                using var response = client.Send(request);
                if (response.IsSuccessStatusCode || (int)response.StatusCode is 400 or 409)
                {
                    store.RemovePending(sale.SaleId);
                    _log($"offline sale {sale.SaleId} reconciled: {(int)response.StatusCode}");
                    continue;
                }
                break;
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
            { _log("offline sale sync deferred: " + e.Message); break; }
        }
    }

    public static HttpResponseMessage SendServerRequest(HttpMethod method, string path)
    {
        using var request = new HttpRequestMessage(method, path);
        return (_http ?? throw new InvalidOperationException("PC proxy is not initialized")).Send(request);
    }

    static NamedPipeServerStream NewPipe(string clientSid)
    {
        var sddl = "D:P(A;;GA;;;SY)(A;;GRGW;;;" + clientSid + ")";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
            var handle = CreateNamedPipe(@"\\.\pipe\CafePc", PipeAccessDuplex | FileFlagOverlapped,
                PipeTypeByte | PipeWait | PipeRejectRemoteClients, 255, 65536, 65536, 0, ref attributes);
            if (handle == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return new NamedPipeServerStream(PipeDirection.InOut, true, false, new SafePipeHandle(handle, true));
        }
        finally { LocalFree(descriptor); }
    }

    static async Task Listen(string clientSid, CancellationToken stop, NamedPipeServerStream? firstPipe = null)
    {
        while (!stop.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = firstPipe ?? NewPipe(clientSid);
                firstPipe = null;
                await pipe.WaitForConnectionAsync(stop);
                // Transfer this connection to its own handler before creating the next listening instance.
                var accepted = pipe;
                pipe = null;
                _ = Task.Run(() => HandleClient(accepted, stop), CancellationToken.None);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { pipe?.Dispose(); break; }
            catch (Exception e)
            {
                pipe?.Dispose();
                _log("PC pipe listener: " + e.Message);
                if (stop.IsCancellationRequested) break;
                await Task.Delay(250, stop).ContinueWith(_ => { });
            }
        }
    }

    static async Task HandleClient(NamedPipeServerStream pipe, CancellationToken stop)
    {
        using (pipe)
        {
            try
            {
                if (!IsLockScreenClient(pipe, out var clientPath))
                {
                    RefuseOnce($"refused named-pipe client process: {clientPath ?? "unavailable"}");
                    return;
                }

                var line = await ReadBoundedLine(pipe, TimeSpan.FromSeconds(2), stop);
                if (line is null) return;
                var request = JsonSerializer.Deserialize<Request>(line);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true };
                if (request is not null && request.Method == "GET" && request.Path == "/local/offline-unlock-info" && request.Body is null)
                {
                    var info = _offline?.InfoJson() ?? "{}";
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new Response(200, info))).WaitAsync(TimeSpan.FromSeconds(2));
                    return;
                }
                if (request is not null && request.Method == "POST" && request.Path == "/local/offline-unlock" && request.Body is not null)
                {
                    var attempt = JsonSerializer.Deserialize<OfflineUnlockRequest>(request.Body)
                        ?? throw new JsonException("invalid offline unlock request");
                    var result = _offline?.TryUnlock(attempt) ?? new OfflineUnlockResult(false, "Offline unlock is not set up on this PC.", null);
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new Response(result.Success ? 200 : 400, JsonSerializer.Serialize(result)))).WaitAsync(TimeSpan.FromSeconds(2));
                    return;
                }
                if (request is null || !Allowed(request))
                {
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new Response(404, ""))).WaitAsync(TimeSpan.FromSeconds(2));
                    return;
                }
                using var message = new HttpRequestMessage(new HttpMethod(request.Method), request.Path);
                if (request.Body is not null) message.Content = new StringContent(request.Body, Encoding.UTF8, "application/json");
                using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
                requestTimeout.CancelAfter(TimeSpan.FromSeconds(3));
                using var response = await (_http ?? throw new InvalidOperationException("PC proxy is not initialized")).SendAsync(message, requestTimeout.Token);
                var content = await response.Content.ReadAsStringAsync(stop);
                await writer.WriteLineAsync(JsonSerializer.Serialize(new Response((int)response.StatusCode, content))).WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (Exception e) when (e is IOException or TimeoutException or JsonException or TaskCanceledException or InvalidOperationException)
            {
                // Each accepted client has its own handler; a stalled or malformed client cannot stop the listener.
                _log("PC pipe request ended: " + e.Message);
            }
            catch (Exception e) { _log("PC pipe request failed: " + e.Message); }
        }
    }

    static async Task<string?> ReadBoundedLine(Stream stream, TimeSpan timeout, CancellationToken stop)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(stop);
        limit.CancelAfter(timeout);
        using var data = new MemoryStream();
        var buffer = new byte[4096];
        while (data.Length <= MaxRequestBytes)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(), limit.Token);
            if (read == 0) return null;
            var newline = Array.IndexOf(buffer, (byte)'\n', 0, read);
            var count = newline >= 0 ? newline : read;
            if (data.Length + count > MaxRequestBytes) throw new InvalidDataException("pipe request exceeds 64 KB");
            data.Write(buffer, 0, count);
            if (newline >= 0)
            {
                if (newline != read - 1) throw new InvalidDataException("pipe request contains data after its line terminator");
                var line = new UTF8Encoding(false, true).GetString(data.ToArray());
                return line.EndsWith("\r", StringComparison.Ordinal) ? line[..^1] : line;
            }
        }
        throw new InvalidDataException("pipe request exceeds 64 KB");
    }

    static bool IsLockScreenClient(NamedPipeServerStream pipe, out string? clientPath)
    {
        clientPath = null;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid)) return false;
        var process = OpenProcess(0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, pid);
        if (process == IntPtr.Zero) return false;
        try
        {
            var name = new StringBuilder(1024);
            var size = name.Capacity;
            if (!QueryFullProcessImageName(process, 0, name, ref size)) return false;
            clientPath = Path.GetFullPath(name.ToString());
            return string.Equals(clientPath, _agentPath, StringComparison.OrdinalIgnoreCase);
        }
        finally { CloseHandle(process); }
    }

    static void RefuseOnce(string message)
    {
        if (Interlocked.Exchange(ref _refusalLogged, 1) == 0) _log(message);
    }

    static bool Allowed(Request r)
    {
        if (r.Method == "GET") return r.Path == "/pc/state" && r.Body is null;
        if (r.Method != "POST") return false;
        if (r.Path == "/pc/login") return r.Body is not null;
        if (r.Path == "/pc/selflock") return r.Body is null;
        return (r.Path == "/pc/logout" || Regex.IsMatch(r.Path, @"^/pc/logout\?ago=[0-9]{1,10}$")) && r.Body is null;
    }
}
