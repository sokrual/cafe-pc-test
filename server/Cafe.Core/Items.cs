using System.Text.Json;

namespace Cafe;

/// Something the cafe sells besides play time: a drink, a snack, a meal, a T-shirt. Price in paise.
public record Item(long Id, string Category, string Name, long Price);
public record ItemList(List<string> Categories, List<Item> Items);
/// One row of the items report: how many were sold and for how much (before any offer on the bill).
public record ItemSale(string Category, string Item, long Qty, long Amount);
/// One line of a bill: a charge (time or an item), an offer or owner adjustment, or a payment.
public record BillLine(string Kind, string Text, long Amount, string? Category = null);

public sealed partial class CafeCore
{
    /// The name an offer uses for play time. No item category may take it.
    public const string PlayTime = "Play time";

    void LoadItems() => Tx(() =>
    {
        Exec("""
            CREATE TABLE IF NOT EXISTS item_categories(name TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, category TEXT NOT NULL REFERENCES item_categories(name),
                name TEXT NOT NULL, price INTEGER NOT NULL, UNIQUE(category, name));
            """);
        if (Scalar<long>("SELECT count(*) FROM pragma_table_info('ledger') WHERE name = 'item'") == 0) // what was sold, and the offer's scope
            Exec("""
                ALTER TABLE ledger ADD COLUMN category TEXT; ALTER TABLE ledger ADD COLUMN item TEXT;
                ALTER TABLE ledger ADD COLUMN qty INTEGER; ALTER TABLE ledger ADD COLUMN note TEXT;
                ALTER TABLE offers ADD COLUMN scope TEXT; ALTER TABLE sessions ADD COLUMN offer_scope TEXT;
                """);
        // a new install starts with four lists; the owner renames, adds or deletes them (they never come back)
        if (Exec("INSERT OR IGNORE INTO settings(name, value) VALUES('items_seeded', '1')") == 1)
            Exec("INSERT OR IGNORE INTO item_categories(name) VALUES('Beverages'), ('Snacks'), ('Food'), ('Merchandise')");
    });

    public ItemList Items(long by) => Tx(() =>
    {
        RequireStaff(by);
        var items = new List<Item>();
        using (var r = Query("SELECT id, category, name, price FROM items ORDER BY category, name"))
            while (r.Read()) items.Add(new Item(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetInt64(3)));
        return new ItemList(Column<string>("SELECT name FROM item_categories ORDER BY name"), items);
    });

    public void SaveCategory(long by, string name) => Tx(() =>
    {
        RequireOwner(by);
        name = CleanName(name, 30, "The list name");
        if (name.Equals(PlayTime, StringComparison.OrdinalIgnoreCase)) throw new CafeException($"\"{PlayTime}\" is kept for offers. Pick another name.");
        if (Exec("INSERT OR IGNORE INTO item_categories(name) VALUES(@p0)", name) == 0) throw new CafeException("A list with this name already exists.");
        Audit(by, "item_category_added", name);
    });

    public void DeleteCategory(long by, string name) => Tx(() =>
    {
        RequireOwner(by);
        if (Scalar<long>("SELECT count(*) FROM items WHERE category = @p0", name) > 0) throw new CafeException("Delete the items in this list first.");
        if (Exec("DELETE FROM item_categories WHERE name = @p0", name) == 0) throw new CafeException("There is no list with this name.");
        Audit(by, "item_category_deleted", name);
    });

    /// Owner only. Same list and name changes the price. Past bills keep the price they were sold at.
    public void SaveItem(long by, string category, string name, long price) => Tx(() =>
    {
        RequireOwner(by);
        name = CleanName(name, 40, "The item name");
        if (price is < 1 or > 1_000_000) throw new CafeException("The price must be from ₹0.01 to ₹10,000.");
        if (Scalar<string?>("SELECT name FROM item_categories WHERE name = @p0", category) is null) throw new CafeException("There is no list with this name.");
        Exec("INSERT INTO items(category, name, price) VALUES(@p0, @p1, @p2) ON CONFLICT(category, name) DO UPDATE SET price = excluded.price", category, name, price);
        Audit(by, "item_saved", $"{category} / {name}: {price}");
    });

    public void DeleteItem(long by, long id) => Tx(() =>
    {
        RequireOwner(by);
        if (Exec("DELETE FROM items WHERE id = @p0", id) == 0) throw new CafeException("This item was not found.");
        Audit(by, "item_deleted", $"{id}");
    });

    /// Staff add an item to a visit that is still going; it is paid with the rest of the bill.
    public void SellItem(long by, long session, long item, int qty, string? note = null) => Tx(() =>
    {
        RequireStaff(by);
        var user = Scalar<long?>("SELECT user_id FROM sessions WHERE id = @p0 AND ended IS NULL", session)
            ?? throw new CafeException("Items can be added only to a visit that is still going. Use a counter sale instead.");
        var (it, n, text) = Sale(item, qty, note);
        Ledger(by, "charge", it.Price * n, session: session, user: user, category: it.Category, item: it.Name, qty: n, note: text);
        SyncOffer(by, session);
        Audit(by, "item_sold", $"session {session}: {n} x {it.Category} / {it.Name}{(text is null ? "" : $" ({text})")}");
    });

    /// Someone buys at the counter without playing: charged and paid at once, in the open shift.
    public long CounterSale(long by, long item, int qty, string? note, string method, string? upiLast4 = null) => Tx(() =>
    {
        RequireStaff(by);
        var (it, n, text) = Sale(item, qty, note);
        CashOrUpi(method, upiLast4);
        var amount = it.Price * n;
        Ledger(by, "charge", amount, category: it.Category, item: it.Name, qty: n, note: text);
        Ledger(by, "pay", amount, method: method, reference: upiLast4);
        Audit(by, "counter_sale", $"{n} x {it.Category} / {it.Name} {method} {amount}{(text is null ? "" : $" ({text})")}");
        return amount;
    });

    /// Owner only: what sold between two days (Indian time, both days included), before offers.
    public List<ItemSale> ItemReport(long by, DateOnly from, DateOnly to) => Tx(() =>
    {
        RequireOwner(by);
        if (from > to) throw new CafeException("The report must end on or after the day it starts.");
        var start = from.ToDateTime(TimeOnly.MinValue).AddHours(-5.5);
        var end = to.AddDays(1).ToDateTime(TimeOnly.MinValue).AddHours(-5.5);
        using var r = Query("SELECT category, item, sum(qty), sum(amount) FROM ledger WHERE kind = 'charge' AND item IS NOT NULL AND at >= @p0 AND at < @p1 GROUP BY category, item ORDER BY category, item",
            Iso(start), Iso(end));
        var list = new List<ItemSale>();
        while (r.Read()) list.Add(new ItemSale(r.GetString(0), r.GetString(1), r.GetInt64(2), r.GetInt64(3)));
        return list;
    });

    (Item item, int qty, string? note) Sale(long item, int qty, string? note)
    {
        if (qty is < 1 or > 100) throw new CafeException("The quantity must be from 1 to 100.");
        note = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        if (note is { Length: > 100 } || note?.Any(char.IsControl) == true) throw new CafeException("The note can be at most 100 letters long.");
        using var r = Query("SELECT id, category, name, price FROM items WHERE id = @p0", item);
        if (!r.Read()) throw new CafeException("This item was not found.");
        return (new Item(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetInt64(3)), qty, note);
    }

    static string CleanName(string name, int max, string what)
    {
        name = (name ?? "").Trim();
        if (name.Length < 1 || name.Length > max || name.Any(ch => char.IsControl(ch) || ch is '/' or '\\'))
            throw new CafeException($"{what} must be 1 to {max} letters long, without / or \\.");
        return name;
    }

    /// Checks an offer's scope: empty means the whole bill; otherwise "Play time" and/or item lists.
    string? ScopeJson(string[]? scope)
    {
        if (scope is null || scope.Length == 0) return null;
        var lists = Column<string>("SELECT name FROM item_categories");
        foreach (var s in scope)
            if (s != PlayTime && !lists.Contains(s)) throw new CafeException($"There is no list called \"{s}\".");
        return JsonSerializer.Serialize(scope.Distinct().Order(StringComparer.Ordinal).ToArray());
    }

    List<BillLine> Lines(string ids)
    {
        using var r = Query($"SELECT kind, amount, ref, reason, method, category, item, qty, note FROM ledger WHERE kind IN ('charge', 'adjust', 'pay') AND session_id IN ({ids}) ORDER BY id");
        var lines = new List<BillLine>();
        string? S(int i) => r.IsDBNull(i) ? null : r.GetString(i);
        while (r.Read())
        {
            var kind = r.GetString(0);
            var text = kind switch
            {
                "charge" when S(6) is string item => $"{r.GetInt64(7)} x {item}{(S(8) is string note ? $" ({note})" : "")}",
                "charge" => $"{PlayTime}: {S(2)}",
                "adjust" => S(3) ?? "Adjustment",
                _ when S(4) is string method => $"Paid by {method}{(S(2) is string reference ? $" {reference}" : "")}",
                _ => $"Payment correction: {S(3)}", // the owner's correction of an earlier payment (always has a reason)
            };
            lines.Add(new BillLine(kind, text, r.GetInt64(1), kind == "charge" ? S(5) ?? PlayTime : null));
        }
        return lines;
    }
}
