using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Cafe;

// Admin PC server, HTTPS only. Gaming PCs call /pc/* with their own token and accept only this server's
// certificate (its fingerprint is in server.pin); staff call /staff/* after a PIN login.
// Usage: Cafe.Server [--data <folder>] [--port 5443] [--seed-test]   (seed = test users + PC1, for automated tests only)
var data = Arg("--data") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cafe");
Directory.CreateDirectory(Path.Combine(data, "logs"));
AdminsOnly(data);
void Log(string line) { lock (data) File.AppendAllText(Path.Combine(data, "logs", $"server-{DateTime.Now:yyyyMMdd}.log"), $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}"); }

using var cafe = new CafeCore(Path.Combine(data, "cafe.db"), DbKey(data));
if (args.Contains("--seed-test")) Seed(cafe, data);
var cert = Cert(data);

var builder = WebApplication.CreateBuilder();
builder.Host.UseWindowsService(o => o.ServiceName = "CafeServer"); // a Windows service at the cafe; a normal program in tests
builder.WebHost.ConfigureKestrel(k =>
{
    k.Listen(IPAddress.Any, int.Parse(Arg("--port") ?? "5443"), l => l.UseHttps(cert));
    k.Limits.MaxRequestBodySize = 16 * 1024; // every request here is tiny
});
// PIN guessing: besides the per-account lockout, each network address gets 10 login tries a minute
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("login", c => RateLimitPartition.GetFixedWindowLimiter(c.Connection.RemoteIpAddress?.ToString() ?? "?", _ => new() { PermitLimit = 10, Window = TimeSpan.FromMinutes(1) }));
});
builder.Logging.ClearProviders(); // our own log file below; never the request bodies (they carry PINs)
var app = builder.Build();
app.UseRateLimiter();
var staffTokens = new StaffTokens();

app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/staff")
        && !StaffLoginNetwork.Allows(ctx.Connection.RemoteIpAddress, ctx.Connection.LocalIpAddress))
    {
        ctx.Response.StatusCode = 403;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.Response.WriteAsync(StaffLoginNetwork.RefusalMessage);
        return;
    }
    await next(ctx);
});
app.Use(async (ctx, next) => // second wall behind the firewall rule: nothing from outside the shop network gets an answer
{
    if (ShopNetwork.Allows(ctx.Connection.RemoteIpAddress)) { await next(ctx); return; }
    ctx.Response.StatusCode = 403; Log($"refused {ctx.Connection.RemoteIpAddress}: not on the shop network");
});
app.Use(async (ctx, next) => // rule breaks become a 400 with a plain message, bad tokens a 401; never a stack trace
{
    try { await next(ctx); }
    catch (CafeException e) { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsJsonAsync(new { error = e.Message }); }
    catch (UnauthorizedAccessException) { ctx.Response.StatusCode = 401; Log($"refused {ctx.Request.Path} from {ctx.Connection.RemoteIpAddress}"); }
    catch (Exception e) { ctx.Response.StatusCode = 500; Log($"ERROR {ctx.Request.Path}: {e}"); }
});

string TokenOf(HttpContext c) => c.Request.Headers.Authorization.ToString().Replace("Bearer ", "");
long Owner(HttpContext c) { var u = Staff(c); return cafe.IsOwner(u) ? u : throw new CafeException("Only the owner can do this."); }
string Pc(HttpContext c) => cafe.PcByToken(c.Request.Headers["X-Pc-Token"].ToString()) ?? throw new UnauthorizedAccessException();
long Staff(HttpContext c)
{
    return staffTokens.Check(TokenOf(c)) ?? throw new UnauthorizedAccessException();
}

app.MapGet("/pc/state", (HttpContext c) => { var pc = Pc(c); var st = cafe.StateOf(pc); cafe.PcSeen(pc); return st; });
app.MapPost("/pc/login", (HttpContext c, LoginBody b) => { var pc = Pc(c); var st = cafe.PcLogin(pc, b.Phone, b.Pin); Log($"{pc} login session {st.Session}"); return st; }).RequireRateLimiting("login");
app.MapPost("/pc/selflock", (HttpContext c) => cafe.PcSelfLock(Pc(c)));
app.MapPost("/pc/logout", (HttpContext c, long? ago) => { var pc = Pc(c); var bill = cafe.PcLogout(pc, ago ?? 0); Log($"{pc} logout session {bill.SessionId} used {bill.Used} (sent {ago ?? 0}s late)"); return bill; });

app.MapPost("/staff/login", (HttpContext c, LoginBody b) =>
{
    var user = cafe.StaffLogin(b.Phone, b.Pin, b.Code);
    return Results.Ok(new { token = staffTokens.Issue(user) }); // shortcut: in memory, so a server restart logs staff out
}).RequireRateLimiting("login");
app.MapPost("/staff/logout", (HttpContext c) => { staffTokens.End(TokenOf(c)); return Results.Ok(); });
app.MapPost("/staff/users", (HttpContext c, UserBody b) => new { id = cafe.AddUser(Staff(c), b.Role, b.Name, b.Phone, b.Pin) });
app.MapPost("/staff/users/pin", (HttpContext c, LoginBody b) => { cafe.ResetPin(Staff(c), b.Phone, b.Pin); return Results.Ok(); });
app.MapGet("/staff/pcs", (HttpContext c) => cafe.Pcs(Staff(c)));
app.MapGet("/staff/settings/time-lock", (HttpContext c) => { Owner(c); return new { lockWhenTimeRunsOut = cafe.LockWhenTimeRunsOut }; });
app.MapPost("/staff/settings/time-lock", (HttpContext c, TimeLockBody b) => { cafe.SetLockWhenTimeRunsOut(Owner(c), b.Enabled); return new { lockWhenTimeRunsOut = cafe.LockWhenTimeRunsOut }; });
// the reply is what the new gaming PC needs: its key (shown once) and the server's certificate fingerprint
app.MapPost("/staff/pcs", (HttpContext c, PcBody b) => new { token = cafe.AddPc(Staff(c), b.Pc), pin = File.ReadAllText(Path.Combine(data, "server.pin")) });
app.MapDelete("/staff/pcs/{pc}", (HttpContext c, string pc) => { cafe.RemovePc(Staff(c), pc); return Results.Ok(); });
app.MapPost("/staff/two-step/start", (HttpContext c) =>
{
    Owner(c);
    var secret = CafeCore.NewTwoStepSecret();
    return new { secret, uri = $"otpauth://totp/Shinzx%20Cafe?secret={secret}&issuer=Shinzx%20Cafe" };
});
app.MapPost("/staff/two-step/on", (HttpContext c, TwoStepBody b) => new { recovery = cafe.TurnOnTwoStep(Owner(c), b.Secret, b.Code) });
app.MapPost("/staff/lock", (HttpContext c, PcBody b) => { cafe.Lock(Staff(c), b.Pc, b.Message); return cafe.StateOf(b.Pc); });
app.MapPost("/staff/unlock", (HttpContext c, PcBody b) => { cafe.Unlock(Staff(c), b.Pc); return cafe.StateOf(b.Pc); });
app.MapGet("/staff/state/{pc}", (HttpContext c, string pc) => { Staff(c); return cafe.StateOf(pc); });
app.MapGet("/staff/bill/{session:long}", (HttpContext c, long session) => { Staff(c); return cafe.BillFor(session); });
app.MapGet("/staff/review", (HttpContext c) => { Staff(c); return cafe.ForReview(); });

Log($"started v{System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version}, certificate {cert.Thumbprint}");
app.Lifetime.ApplicationStarted.Register(() => _ = Task.Run(async () =>
{
    using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
    try
    {
        while (await timer.WaitForNextTickAsync(app.Lifetime.ApplicationStopping))
        {
            try { cafe.EnforceTimeLimits(); }
            catch (Exception e) { Log($"time expiry check failed: {e.Message}"); }
        }
    }
    catch (OperationCanceledException) { }
}));
app.Run();

string? Arg(string name) => Array.IndexOf(args, name) is var i and >= 0 && i + 1 < args.Length ? args[i + 1] : null;

// DPAPI machine scope lets any Windows account on this PC decrypt db.key, so only Administrators and SYSTEM may
// open this folder (the server runs as a SYSTEM service at the cafe; staff Windows accounts can't read it).
static void AdminsOnly(string dir)
{
    var acl = new System.Security.AccessControl.DirectorySecurity();
    acl.SetAccessRuleProtection(true, false);
    foreach (var sid in new[] { "S-1-5-32-544", "S-1-5-18" })
        acl.AddAccessRule(new(new System.Security.Principal.SecurityIdentifier(sid), System.Security.AccessControl.FileSystemRights.FullControl,
            System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
            System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
    new DirectoryInfo(dir).SetAccessControl(acl);
}

// The database key is random, made once, and stored encrypted with Windows DPAPI for this machine only.
static string DbKey(string data)
{
    var file = Path.Combine(data, "db.key");
    if (!File.Exists(file)) File.WriteAllBytes(file, ProtectedData.Protect(RandomNumberGenerator.GetBytes(32), null, DataProtectionScope.LocalMachine));
    return Convert.ToHexString(ProtectedData.Unprotect(File.ReadAllBytes(file), null, DataProtectionScope.LocalMachine));
}

// Our own certificate, made once (10 years), stored DPAPI-encrypted. PCs pin its SHA-256, so no outside CA is involved.
static X509Certificate2 Cert(string data)
{
    var file = Path.Combine(data, "server.pfx.dpapi");
    if (!File.Exists(file))
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=cafe-admin", key, HashAlgorithmName.SHA256);
        using var made = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        File.WriteAllBytes(file, ProtectedData.Protect(made.Export(X509ContentType.Pfx), null, DataProtectionScope.LocalMachine));
    }
    var cert = X509CertificateLoader.LoadPkcs12(ProtectedData.Unprotect(File.ReadAllBytes(file), null, DataProtectionScope.LocalMachine), null);
    File.WriteAllText(Path.Combine(data, "server.pin"), Convert.ToHexString(SHA256.HashData(cert.RawData))); // goes into each PC's settings
    return cert;
}

static void Seed(CafeCore cafe, string data)
{
    if (File.Exists(Path.Combine(data, "pc1.token"))) return; // already seeded
    var owner = cafe.AddUser(null, Role.Owner, "Owner", "9000000001", "432100");
    var staff = cafe.AddUser(owner, Role.Staff, "Staff", "9000000002", "111111");
    cafe.AddUser(staff, Role.Customer, "Test Customer", "9000000003", "2222");
    File.WriteAllText(Path.Combine(data, "pc1.token"), cafe.AddPc(owner, "PC1"));
}

record LoginBody(string Phone, string Pin, string? Code = null);
record UserBody(Role Role, string Name, string Phone, string Pin);
record TwoStepBody(string Secret, string Code);
record PcBody(string Pc, string? Message);
record TimeLockBody(bool Enabled);
