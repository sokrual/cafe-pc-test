using Cafe;
using Microsoft.Data.Sqlite;
using Xunit;

// D3: a PC that joins a Wi-Fi router the cafe did not set up tells the owner's counter screen.
public sealed class WifiTests : IDisposable
{
    readonly string _file = Path.Combine(Path.GetTempPath(), $"cafe-wifi-{Guid.NewGuid():N}.db");
    readonly CafeCore _cafe;
    readonly long _owner, _staff;

    public WifiTests()
    {
        _cafe = new CafeCore(_file, "test-key-123", () => new DateTime(2026, 11, 15, 10, 0, 0, DateTimeKind.Utc));
        _owner = _cafe.AddUser(null, Role.Owner, "Owner", "9000000001", "432100");
        _staff = _cafe.AddUser(_owner, Role.Staff, "Staff", "9000000002", "111111");
        _cafe.AddPc(_owner, "PC1");
    }
    public void Dispose() { _cafe.Dispose(); SqliteConnection.ClearAllPools(); try { File.Delete(_file); } catch (IOException) { } }

    [Fact]
    public void An_unknown_router_goes_on_the_owners_alerts_at_most_five_an_hour()
    {
        _cafe.PcWifiAlert("PC1", "Cafe\u0007 WiFi", "a4:2b:b0:11:22:33");
        var alert = Assert.Single(_cafe.OfflineUnlockAlerts(_owner));
        Assert.Contains("PC1: Wi-Fi \"Cafe WiFi\" through a router the cafe did not set up (a4:2b:b0:11:22:33)", alert);
        Assert.Throws<CafeException>(() => _cafe.OfflineUnlockAlerts(_staff)); // owner only, like offline unlock alerts
        Assert.Throws<CafeException>(() => _cafe.PcWifiAlert("PC1", "x", "not-a-router"));
        for (var i = 0; i < 9; i++) _cafe.PcWifiAlert("PC1", "Cafe WiFi", $"a4:2b:b0:11:22:4{i}");
        Assert.Equal(5, _cafe.OfflineUnlockAlerts(_owner).Count);
    }
}
