using System.Text.RegularExpressions;

namespace Cafe;

public sealed partial class CafeCore
{
    /// The PC's watchdog disconnected a Wi-Fi router that was not recorded at install (for example a phone hotspot
    /// given the cafe's network name). It goes on the owner's alerts.
    public void PcWifiAlert(string pc, string network, string router) => Tx(() =>
    {
        if (!Regex.IsMatch(router, "^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")) throw new CafeException("The router address is not valid.");
        network = new string(network.Where(c => !char.IsControl(c)).ToArray()).Trim();
        if (network.Length > 32) network = network[..32];
        if (Scalar<long>("SELECT count(*) FROM audit WHERE action = 'wifi_alert' AND at >= @p0 AND detail LIKE @p1", Iso(_now().AddHours(-1)), pc + ":%") >= 5)
            return; // at most 5 an hour per PC on the alerts list; the PC's own log has every one
        Insert("INSERT INTO audit(at, by_user, action, detail) VALUES(@p0, NULL, 'wifi_alert', @p1)", Iso(_now()),
            $"{pc}: Wi-Fi \"{network}\" through a router the cafe did not set up ({router}); the PC disconnected it");
    });
}
