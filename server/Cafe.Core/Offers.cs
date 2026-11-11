using System.Globalization;
using System.Text.Json;

namespace Cafe;

/// A happy hour: sessions that START inside the window are billed on this rate card for the whole session.
/// Days: 1 = Monday ... 7 = Sunday. FromMin/ToMin: minutes after midnight, Indian time, same day.
public record HappyHour(long Id, string Card, int[] Days, int FromMin, int ToMin, bool MembersOnly);
/// A named offer staff can put on one bill: Percent off every charge of that session. From/To: optional dates (Indian time).
public record Offer(string Name, int Percent, bool MembersOnly, DateOnly? From = null, DateOnly? To = null);

public sealed partial class CafeCore
{
    // Prices for one session come from the rate it started with (see Start). Tx is per thread, so a thread-local is safe.
    [ThreadStatic] static Rate? _sessionRate;

    void LoadOffers() => Tx(() =>
    {
        Exec("""
            CREATE TABLE IF NOT EXISTS happy_hours(id INTEGER PRIMARY KEY, card TEXT NOT NULL, days TEXT NOT NULL,
                from_min INTEGER NOT NULL, to_min INTEGER NOT NULL, members_only INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS offers(name TEXT PRIMARY KEY, percent INTEGER NOT NULL, members_only INTEGER NOT NULL, from_day TEXT, to_day TEXT);
            """);
        if (Scalar<long>("SELECT count(*) FROM pragma_table_info('sessions') WHERE name = 'rate'") == 0) // the rate, happy hour and offer of each session
            Exec("ALTER TABLE sessions ADD COLUMN rate TEXT; ALTER TABLE sessions ADD COLUMN happy TEXT; ALTER TABLE sessions ADD COLUMN offer TEXT; ALTER TABLE sessions ADD COLUMN offer_pct INTEGER;");
    });

    static DateTime India(DateTime utc) => utc.AddHours(5.5);

    // Called once when a session starts: a happy hour's card if one applies, otherwise the card in use.
    void PriceSession(long session, long user)
    {
        var local = India(_now());
        var day = ((int)local.DayOfWeek + 6) % 7 + 1;
        var minute = local.Hour * 60 + local.Minute;
        var member = MembershipOf(user) is not null;
        var happy = HappyHours().FirstOrDefault(h => h.Days.Contains(day) && h.FromMin <= minute && minute < h.ToMin && (member || !h.MembersOnly)
            && Scalar<string?>("SELECT card FROM rate_cards WHERE name = @p0", h.Card) is not null);
        var card = happy is null ? JsonSerializer.Serialize(_rate) : Scalar<string>("SELECT card FROM rate_cards WHERE name = @p0", happy.Card);
        Exec("UPDATE sessions SET rate = @p0, happy = @p1 WHERE id = @p2", card, happy?.Card, session);
    }

    /// Runs f with the prices of this session (older sessions without a stored rate use the card in use).
    T WithSessionRate<T>(long session, Func<T> f)
    {
        var previous = _sessionRate;
        _sessionRate = Scalar<string?>("SELECT rate FROM sessions WHERE id = @p0", session) is string json ? JsonSerializer.Deserialize<Rate>(json) : null;
        try { return f(); } finally { _sessionRate = previous; }
    }

    // ---------------- happy hours (owner) ----------------

    public List<HappyHour> HappyHours() => Tx(() =>
    {
        using var r = Query("SELECT id, card, days, from_min, to_min, members_only FROM happy_hours ORDER BY from_min");
        var list = new List<HappyHour>();
        while (r.Read()) list.Add(new HappyHour(r.GetInt64(0), r.GetString(1), r.GetString(2).Split(',').Select(int.Parse).ToArray(),
            r.GetInt32(3), r.GetInt32(4), r.GetInt64(5) == 1));
        return list;
    });

    public long AddHappyHour(long by, HappyHour h) => Tx(() =>
    {
        RequireOwner(by);
        if (Scalar<string?>("SELECT name FROM rate_cards WHERE name = @p0", h.Card) is null) throw new CafeException("There is no rate card with this name.");
        if (h.Days.Length == 0 || h.Days.Any(d => d is < 1 or > 7)) throw new CafeException("Pick at least one day.");
        if (h.FromMin < 0 || h.ToMin > 24 * 60 || h.FromMin >= h.ToMin) throw new CafeException("The happy hour must end after it starts, on the same day.");
        var id = Insert("INSERT INTO happy_hours(card, days, from_min, to_min, members_only) VALUES(@p0, @p1, @p2, @p3, @p4)",
            h.Card, string.Join(',', h.Days.Distinct().Order()), h.FromMin, h.ToMin, h.MembersOnly ? 1 : 0);
        Audit(by, "happy_hour_added", $"{id}: {h.Card} days {string.Join(',', h.Days)} {h.FromMin}-{h.ToMin} members_only={h.MembersOnly}");
        return id;
    });

    public void DeleteHappyHour(long by, long id) => Tx(() =>
    {
        RequireOwner(by);
        if (Exec("DELETE FROM happy_hours WHERE id = @p0", id) == 0) throw new CafeException("This happy hour was not found.");
        Audit(by, "happy_hour_deleted", $"{id}");
    });

    // ---------------- offers (owner sets them, staff use them) ----------------

    public List<Offer> Offers() => Tx(() =>
    {
        using var r = Query("SELECT name, percent, members_only, from_day, to_day FROM offers ORDER BY name");
        var list = new List<Offer>();
        while (r.Read()) list.Add(new Offer(r.GetString(0), r.GetInt32(1), r.GetInt64(2) == 1,
            r.IsDBNull(3) ? null : DateOnly.Parse(r.GetString(3), CultureInfo.InvariantCulture), r.IsDBNull(4) ? null : DateOnly.Parse(r.GetString(4), CultureInfo.InvariantCulture)));
        return list;
    });

    public void SaveOffer(long by, Offer o) => Tx(() =>
    {
        RequireOwner(by);
        var name = o.Name.Trim();
        if (name.Length is < 1 or > 40 || name.Any(ch => char.IsControl(ch) || ch is '/' or '\\'))
            throw new CafeException("The offer name must be 1 to 40 letters long, without / or \\.");
        if (o.Percent is < 1 or > 100) throw new CafeException("The discount must be 1% to 100%.");
        if (o.From > o.To) throw new CafeException("The offer must end on or after the day it starts.");
        Exec("INSERT INTO offers(name, percent, members_only, from_day, to_day) VALUES(@p0, @p1, @p2, @p3, @p4) " +
             "ON CONFLICT(name) DO UPDATE SET percent = excluded.percent, members_only = excluded.members_only, from_day = excluded.from_day, to_day = excluded.to_day",
            name, o.Percent, o.MembersOnly ? 1 : 0, o.From?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), o.To?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        Audit(by, "offer_saved", $"{name}: {o.Percent}% members_only={o.MembersOnly} {o.From}-{o.To}");
    });

    public void DeleteOffer(long by, string name) => Tx(() =>
    {
        RequireOwner(by);
        if (Exec("DELETE FROM offers WHERE name = @p0", name) == 0) throw new CafeException("There is no offer with this name.");
        Audit(by, "offer_deleted", name);
    });

    /// Staff or owner put one offer on a session's bill. Never on a happy-hour session, never two offers.
    public void ApplyOffer(long by, long session, string name) => Tx(() =>
    {
        RequireStaff(by);
        var offer = Offers().SingleOrDefault(o => o.Name == name) ?? throw new CafeException("There is no offer with this name.");
        var today = DateOnly.FromDateTime(India(_now()));
        if (offer.From > today || offer.To < today) throw new CafeException("This offer is not running today.");
        using (var r = Query("SELECT user_id, happy, offer FROM sessions WHERE id = @p0", session))
        {
            if (!r.Read()) throw new CafeException("This visit was not found.");
            var user = r.GetInt64(0);
            if (!r.IsDBNull(1)) throw new CafeException("Happy hour prices already apply to this visit. No offer on top.");
            if (!r.IsDBNull(2)) throw new CafeException($"This bill already has the offer {r.GetString(2)}. Only one offer at a time.");
            r.Close();
            if (offer.MembersOnly && MembershipOf(user) is null) throw new CafeException("This offer is for members only.");
        }
        // a discount after payment would leave money owed back and the cash drawer short of the books
        if (Scalar<long>("SELECT count(*) FROM ledger WHERE kind = 'pay' AND session_id = @p0", session) > 0)
            throw new CafeException("Put the offer on the bill before taking payment.");
        Exec("UPDATE sessions SET offer = @p0, offer_pct = @p1 WHERE id = @p2", offer.Name, offer.Percent, session);
        Audit(by, "offer_applied", $"session {session}: {offer.Name} {offer.Percent}%");
        SyncOffer(by, session);
    });

    // Keeps the offer's discount equal to its percent of all charges so far; called again after every new charge.
    void SyncOffer(long by, long session)
    {
        using var r = Query("SELECT offer, offer_pct, user_id FROM sessions WHERE id = @p0 AND offer IS NOT NULL", session);
        if (!r.Read()) return;
        var (name, pct, user) = (r.GetString(0), r.GetInt64(1), r.GetInt64(2));
        r.Close();
        var charges = Scalar<long>("SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = 'charge' AND session_id = @p0", session);
        var given = Scalar<long>("SELECT coalesce(sum(amount), 0) FROM ledger WHERE kind = 'adjust' AND session_id = @p0 AND reason = @p1", session, $"offer {name}");
        var change = -(charges * pct / 100) - given; // the discount rounds down to the paisa, in the cafe's favour
        if (change != 0) Ledger(by, "adjust", change, session: session, user: user, reason: $"offer {name}");
    }
}
