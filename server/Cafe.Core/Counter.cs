using System.Globalization;

namespace Cafe;

/// One row of the counter screen. Online: the PC asked for its state in the last 15 seconds.
/// Locked: staff locked it. SelfLocked: the customer locked it. ToPay: owed right now, including a running pay-at-end bill.
public record CounterRow(string Pc, bool Online, bool Locked, bool SelfLocked, string? Message, long? Session, string? Mode,
    long ElapsedSec, long? LeftSec, string? Customer, long ToPay);
public record CustomerInfo(long Id, string Name, string Phone, long PlanMinutes, long Wallet, Membership? Membership);

public sealed partial class CafeCore
{
    public List<CounterRow> Counter(long by) => Pcs(by).Select(p =>
    {
        var s = StateOf(p.Name);
        var online = p.LastSeen is string seen && _now() - DateTime.Parse(seen, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal) < TimeSpan.FromSeconds(15);
        if (s.Session is not long id) return new CounterRow(p.Name, online, p.Locked, false, s.Message, null, null, 0, null, null, 0);
        return Tx(() =>
        {
            var customer = Scalar<string>("SELECT u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = @p0", id);
            var toPay = BillFor(id).Due + (s.Mode == "postpaid" ? Charge(TimeSpan.FromSeconds(s.ElapsedSec)) : 0);
            return new CounterRow(p.Name, online, p.Locked, s.SelfLocked, s.Message, id, s.Mode, s.ElapsedSec, s.LeftSec, customer, toPay);
        });
    }).ToList();

    public CustomerInfo FindCustomer(long by, string phone) => Tx(() =>
    {
        RequireStaff(by);
        var id = Scalar<long?>("SELECT id FROM users WHERE phone = @p0 AND role = @p1", phone, (int)Role.Customer)
            ?? throw new CafeException("No customer has this phone number.");
        return new CustomerInfo(id, Scalar<string>("SELECT name FROM users WHERE id = @p0", id), phone, PlanMinutesLeft(id), WalletBalance(id), MembershipOf(id));
    });
}
