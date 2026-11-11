using System.Text.Json;

namespace Cafe;

/// A named rate card. Exactly one is in use; the others are kept for later (offers, happy hours, another season).
/// Paise30/60/90 are the prices for 1, 2 and 3 blocks of BlockMin minutes (30 min by default).
public record RateCard(string Name, bool InUse, Rate Rate);

public sealed partial class CafeCore
{
    // New install: the rate card in the code becomes "Standard", in use. After that the database decides.
    void LoadRateCards() => Tx(() =>
    {
        Exec("CREATE TABLE IF NOT EXISTS rate_cards(name TEXT PRIMARY KEY, card TEXT NOT NULL, in_use INTEGER NOT NULL DEFAULT 0)");
        if (Scalar<long>("SELECT count(*) FROM rate_cards") == 0)
            Exec("INSERT INTO rate_cards(name, card, in_use) VALUES('Standard', @p0, 1)", JsonSerializer.Serialize(Rate));
        Rate = JsonSerializer.Deserialize<Rate>(Scalar<string>("SELECT card FROM rate_cards WHERE in_use = 1"))!;
    });

    public List<RateCard> RateCards(long by) => Tx(() =>
    {
        RequireStaff(by);
        using var r = Query("SELECT name, in_use, card FROM rate_cards ORDER BY in_use DESC, name");
        var cards = new List<RateCard>();
        while (r.Read()) cards.Add(new RateCard(r.GetString(0), r.GetInt64(1) == 1, JsonSerializer.Deserialize<Rate>(r.GetString(2))!));
        return cards;
    });

    /// Owner only. Adds a card or changes one; a change to the card in use applies to the next charge.
    public void SaveRateCard(long by, string name, Rate rate) => Tx(() =>
    {
        RequireOwner(by);
        name = name.Trim();
        if (name.Length is < 1 or > 40 || name.Any(ch => char.IsControl(ch) || ch is '/' or '\\'))
            throw new CafeException("The rate card name must be 1 to 40 letters long, without / or \\.");
        Check(rate);
        Exec("INSERT INTO rate_cards(name, card) VALUES(@p0, @p1) ON CONFLICT(name) DO UPDATE SET card = excluded.card", name, JsonSerializer.Serialize(rate));
        if (Scalar<long>("SELECT in_use FROM rate_cards WHERE name = @p0", name) == 1) Rate = rate;
        Audit(by, "rate_card_saved", $"{name}: {JsonSerializer.Serialize(rate)}");
    });

    public void UseRateCard(long by, string name) => Tx(() =>
    {
        RequireOwner(by);
        var card = Scalar<string?>("SELECT card FROM rate_cards WHERE name = @p0", name) ?? throw new CafeException("There is no rate card with this name.");
        Exec("UPDATE rate_cards SET in_use = (name = @p0)", name);
        Rate = JsonSerializer.Deserialize<Rate>(card)!;
        Audit(by, "rate_card_in_use", name);
    });

    public void DeleteRateCard(long by, string name) => Tx(() =>
    {
        RequireOwner(by);
        var inUse = Scalar<long?>("SELECT in_use FROM rate_cards WHERE name = @p0", name) ?? throw new CafeException("There is no rate card with this name.");
        if (inUse == 1) throw new CafeException("This rate card is in use. Put another one in use first.");
        Exec("DELETE FROM rate_cards WHERE name = @p0", name);
        Audit(by, "rate_card_deleted", name);
    });

    static void Check(Rate r)
    {
        const long MaxPaise = 1_000_000; // ₹10,000 for one block: far above any real price, stops a typing slip
        if (r.BlockMin is < 5 or > 240) throw new CafeException("A block must be 5 to 240 minutes.");
        if (new[] { r.Paise30, r.Paise60, r.Paise90, r.ExtraBlockPaise }.Any(p => p is <= 0 or > MaxPaise))
            throw new CafeException("Every price must be more than ₹0 and at most ₹10,000.");
        if (r.MinimumMin < 0 || r.MinimumMin > 3 * r.BlockMin) throw new CafeException("The minimum must be 0 to 3 blocks.");
        if (r.GraceMin is < 0 or > 30) throw new CafeException("The free start must be 0 to 30 minutes.");
        if (r.BlockGraceMin < 0 || r.BlockGraceMin >= r.BlockMin) throw new CafeException("The free minutes after a block must be shorter than a block.");
        if (r.CarryOverDays is < 0 or > 366) throw new CafeException("Saved time must last 0 to 366 days.");
    }
}
