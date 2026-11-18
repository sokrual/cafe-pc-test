using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

// Gaming PCs update themselves: after INSTALL-ADMIN puts a new version on the counter PC, each gaming PC installs it the
// next time it is idle (locked, no customer, not in setup mode). It installs only a file list that carries a valid
// signature from the update key (the private half is the GitHub secret UPDATE_SIGNING_KEY; the public half is below),
// only a version newer than its own, and only files whose SHA-256 matches that list. So a hacked counter PC or another
// device on the shop network cannot make a gaming PC run its code. Each version is tried once; a failure is logged.
static class FindUpdate
{

    const string PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeJxN/NIuoF0DTZ5+NLh6R6Er2FHSazJ1uGzM5BJpViVO9ZAQKBS9cORGNZ84BDICpmUDMx/cPuIHwqlibQrI0w==";
    static DateTime _next = DateTime.UtcNow.AddMinutes(2);

    /// Called every 5 s from the proxy's background loop; does its work every 10 minutes.
    public static void Check(HttpClient http, Func<Uri, HttpClient> newClient, string dataDirectory, Action<string> log)
    {
        if (DateTime.UtcNow < _next) return;
        _next = DateTime.UtcNow.AddMinutes(10);
        var app = AppContext.BaseDirectory;
        if (File.Exists(Path.Combine(app, "setup.flag"))) return;   // the owner is setting this PC up
        using (var state = JsonDocument.Parse(http.GetStringAsync("/pc/state").GetAwaiter().GetResult()))
            if (!state.RootElement.GetProperty("locked").GetBoolean() || state.RootElement.GetProperty("session").ValueKind != JsonValueKind.Null) return;   // a customer is on it

        using var offer = http.GetAsync("/pc/update").GetAwaiter().GetResult();
        if (!offer.IsSuccessStatusCode) return;   // the counter has no update
        using var body = JsonDocument.Parse(offer.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        var manifest = Convert.FromBase64String(body.RootElement.GetProperty("manifest").GetString()!);
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(PublicKey), out _);
        if (!key.VerifyData(manifest, Convert.FromBase64String(body.RootElement.GetProperty("signature").GetString()!), HashAlgorithmName.SHA256))
        {
            log("update refused: its signature is not from the update key");
            return;
        }
        using var list = JsonDocument.Parse(manifest);
        var version = list.RootElement.GetProperty("version").GetInt64();
        var installedFile = Path.Combine(app, "update.json");
        long installed = 0;
        if (File.Exists(installedFile))
            using (var mine = JsonDocument.Parse(File.ReadAllBytes(installedFile))) installed = mine.RootElement.GetProperty("version").GetInt64();
        var work = Path.Combine(dataDirectory, "update");   // inside ProgramData\GamingCafe: admins and Windows only
        var tried = Path.Combine(work, "tried.txt");
        // PROOF RUN ONLY: a version already installed or already tried is not skipped, so S6.3 must fail

        var folder = Path.Combine(work, "new");
        if (Directory.Exists(folder)) Directory.Delete(folder, true);
        Directory.CreateDirectory(folder);
        var root = Path.GetFullPath(folder) + Path.DirectorySeparatorChar;
        using var download = newClient(http.BaseAddress!);
        download.Timeout = TimeSpan.FromMinutes(10);   // the lock screen's runtime is large
        foreach (var file in list.RootElement.GetProperty("files").EnumerateArray())
        {
            var path = file.GetProperty("path").GetString()!;
            var target = Path.GetFullPath(Path.Combine(root, path));
            if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase)) { log($"update refused: bad file path {path}"); return; }
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using (var from = download.GetStreamAsync("/pc/update/file/" + Uri.EscapeDataString(path).Replace("%2F", "/")).GetAwaiter().GetResult())
            using (var to = File.Create(target))
                from.CopyTo(to);
            using var check = File.OpenRead(target);
            if (!Convert.ToHexString(SHA256.HashData(check)).Equals(file.GetProperty("sha256").GetString(), StringComparison.OrdinalIgnoreCase))
            {
                log($"update refused: {path} does not match its signed checksum");
                return;
            }
        }
        File.WriteAllBytes(Path.Combine(folder, "update.json"), manifest);
        File.WriteAllText(Path.Combine(folder, "update.sig"), body.RootElement.GetProperty("signature").GetString()!);
        File.WriteAllText(tried, version.ToString());
        log($"installing update version {version} (installed: {installed}); this PC restarts when it is done");
        // a separate program: INSTALL-PC stops this watchdog on the way and starts the new one
        var run = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            ArgumentList = { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(folder, "install-pc.ps1"), "-Auto" },
            UseShellExecute = false,
            CreateNoWindow = true
        };
        if (File.Exists(Path.Combine(work, "ci-no-restart.flag"))) run.ArgumentList.Add("-Ci");   // the CI test only (admins-only folder)
        Process.Start(run);
    }
}
