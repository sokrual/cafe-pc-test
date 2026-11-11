using System.Globalization;

namespace Cafe;

public record MembershipPlan(string Name, int Days, long Price);
/// Ends: the end of the last paid period (renewals bought in advance included).
public record Membership(string Plan, DateTime Ends);

public sealed partial class CafeCore
{
    void LoadMemberships() => Tx(() => Exec("""
        CREATE TABLE IF NOT EXISTS membership_plans(name TEXT PRIMARY KEY, days INTEGER NOT NULL, price INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS memberships(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users, plan TEXT NOT NULL,
            starts TEXT NOT NULL, ends TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS memberships_user ON memberships(user_id, ends);
        """));

    public List<MembershipPlan> MembershipPlans(long by) => Tx(() =>
    {
        RequireStaff(by);
        using var r = Query("SELECT name, days, price FROM membership_plans ORDER BY days, name");
        var plans = new List<MembershipPlan>();
        while (r.Read()) plans.Add(new MembershipPlan(r.GetString(0), r.GetInt32(1), r.GetInt64(2)));
        return plans;
    });

    /// Owner only. Members who already paid keep their period; a new price applies to the next sale.
    public void SaveMembershipPlan(long by, MembershipPlan plan) => Tx(() =>
    {
        RequireOwner(by);
        var name = plan.Name.Trim();
        if (name.Length is < 1 or > 40 || name.Any(ch => char.IsControl(ch) || ch is '/' or '\\'))
            throw new CafeException("The membership name must be 1 to 40 letters long, without / or \\.");
        if (plan.Days is < 1 or > 366) throw new CafeException("A membership lasts 1 to 366 days.");
        if (plan.Price is <= 0 or > 10_000_000) throw new CafeException("The price must be more than ₹0 and at most ₹1,00,000.");
        Exec("INSERT INTO membership_plans(name, days, price) VALUES(@p0, @p1, @p2) ON CONFLICT(name) DO UPDATE SET days = excluded.days, price = excluded.price",
            name, plan.Days, plan.Price);
        Audit(by, "membership_plan_saved", $"{name}: {plan.Days} days, {plan.Price} paise");
    });

    public void DeleteMembershipPlan(long by, string name) => Tx(() =>
    {
        RequireOwner(by);
        if (Exec("DELETE FROM membership_plans WHERE name = @p0", name) == 0) throw new CafeException("There is no membership with this name.");
        Audit(by, "membership_plan_deleted", name);
    });

    /// One membership at a time: one bought while another runs starts when that one ends (same plan or a new one),
    /// so periods never overlap. The member's kept time moves on to the new end with it.
    public DateTime SellMembership(long by, long user, string planName, string method, string? upiLast4 = null) => Tx(() =>
    {
        RequireStaff(by);
        if (RoleOf(user) != Role.Customer) throw new CafeException("Only a customer can become a member.");
        var plan = MembershipPlans(by).SingleOrDefault(p => p.Name == planName) ?? throw new CafeException("There is no membership with this name.");
        CashOrUpi(method, upiLast4);
        var current = MembershipOf(user);
        var starts = current?.Ends ?? _now();
        var ends = starts.AddDays(plan.Days);
        Insert("INSERT INTO memberships(user_id, plan, starts, ends) VALUES(@p0, @p1, @p2, @p3)", user, plan.Name, Iso(starts), Iso(ends));
        if (current is not null)
            Exec("UPDATE plans SET expires = @p0 WHERE user_id = @p1 AND expires = @p2", Iso(ends), user, Iso(current.Ends));
        Ledger(by, "pay", plan.Price, user: user, method: method, reference: upiLast4 ?? $"membership {plan.Name}");
        Audit(by, "membership_sold", $"user {user} {plan.Name} until {Iso(ends)} {plan.Price} paise");
        return ends;
    });

    /// The membership running right now, or null.
    public Membership? MembershipOf(long user) => Tx(() =>
    {
        var now = Iso(_now());
        if (Scalar<string?>("SELECT plan FROM memberships WHERE user_id = @p0 AND starts <= @p1 AND ends > @p1", user, now) is not string plan) return null;
        var ends = Scalar<string>("SELECT max(ends) FROM memberships WHERE user_id = @p0", user);
        return new Membership(plan, DateTime.Parse(ends, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal));
    });

    /// Shown to the member on their PC in the last 3 days.
    string? MembershipNotice(long user) =>
        MembershipOf(user) is { } m && m.Ends - _now() <= TimeSpan.FromDays(3)
            ? $"Your {m.Plan} membership ends on {Day(m.Ends)}. Renew at the counter to keep your saved time."
            : null;

    static string Day(DateTime utc) => utc.AddHours(5.5).ToString("d MMM", CultureInfo.InvariantCulture); // Indian time
}
