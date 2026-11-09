using System.Collections.Concurrent;
using System.Security.Cryptography;
using Cafe;

// Admin PC server. Gaming PCs call /pc/* with their own token; staff call /staff/* after a PIN login.
// Usage: Cafe.Server --data <folder> [--urls http://0.0.0.0:5080] [--seed-test]  (seed = test users + PC1, for CI only)
var data = Arg("--data") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cafe");
Directory.CreateDirectory(data);
using var cafe = new CafeCore(Path.Combine(data, "cafe.db"), DbKey(data));
if (args.Contains("--seed-test")) Seed(cafe, data);

var app = WebApplication.CreateSlimBuilder(Arg("--urls") is string u ? ["--urls", u] : []).Build(); // our own flags are not web settings
var staffTokens = new ConcurrentDictionary<string, (long user, DateTime until)>();

app.Use(async (ctx, next) => // rule breaks become a 400 with a plain message, bad tokens a 401; never a stack trace
{
    try { await next(ctx); }
    catch (CafeException e) { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsJsonAsync(new { error = e.Message }); }
    catch (UnauthorizedAccessException) { ctx.Response.StatusCode = 401; }
});

string Pc(HttpContext c) => cafe.PcByToken(c.Request.Headers["X-Pc-Token"].ToString()) ?? throw new UnauthorizedAccessException();
long Staff(HttpContext c)
{
    var t = c.Request.Headers.Authorization.ToString().Replace("Bearer ", "");
    return staffTokens.TryGetValue(t, out var s) && s.until > DateTime.UtcNow ? s.user : throw new UnauthorizedAccessException();
}

app.MapGet("/pc/state", (HttpContext c) => cafe.StateOf(Pc(c)));
app.MapPost("/pc/login", (HttpContext c, LoginBody b) => cafe.PcLogin(Pc(c), b.Phone, b.Pin));
app.MapPost("/pc/logout", (HttpContext c) => cafe.PcLogout(Pc(c)));

app.MapPost("/staff/login", (LoginBody b) =>
{
    var user = cafe.Login(b.Phone, b.Pin);
    var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    staffTokens[token] = (user, DateTime.UtcNow.AddHours(12)); // shortcut: in memory, so a server restart logs staff out
    return new { token };
});
app.MapPost("/staff/lock", (HttpContext c, PcBody b) => { cafe.Lock(Staff(c), b.Pc, b.Message); return cafe.StateOf(b.Pc); });
app.MapPost("/staff/unlock", (HttpContext c, PcBody b) => { cafe.Unlock(Staff(c), b.Pc); return cafe.StateOf(b.Pc); });
app.MapGet("/staff/state/{pc}", (HttpContext c, string pc) => { Staff(c); return cafe.StateOf(pc); });

app.Run();

string? Arg(string name) => Array.IndexOf(args, name) is var i and >= 0 && i + 1 < args.Length ? args[i + 1] : null;

// The database key is random, made once, and stored encrypted with Windows DPAPI for this machine only.
static string DbKey(string data)
{
    var file = Path.Combine(data, "db.key");
    if (!File.Exists(file)) File.WriteAllBytes(file, ProtectedData.Protect(RandomNumberGenerator.GetBytes(32), null, DataProtectionScope.LocalMachine));
    return Convert.ToHexString(ProtectedData.Unprotect(File.ReadAllBytes(file), null, DataProtectionScope.LocalMachine));
}

static void Seed(CafeCore cafe, string data)
{
    if (File.Exists(Path.Combine(data, "pc1.token"))) return; // already seeded
    var owner = cafe.AddUser(null, Role.Owner, "Owner", "9000000001", "4321");
    var staff = cafe.AddUser(owner, Role.Staff, "Staff", "9000000002", "1111");
    cafe.AddUser(staff, Role.Customer, "Test Customer", "9000000003", "2222");
    File.WriteAllText(Path.Combine(data, "pc1.token"), cafe.AddPc(owner, "PC1"));
}

record LoginBody(string Phone, string Pin);
record PcBody(string Pc, string? Message);
