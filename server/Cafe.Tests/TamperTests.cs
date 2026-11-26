using Cafe;
using Microsoft.Data.Sqlite;
using Xunit;

// B5.3 part 3: the watchdog tells the counter when the lock screen was tampered with.
public sealed class TamperTests : IDisposable
{
    readonly string _file = Path.Combine(Path.GetTempPath(), $"cafe-tamper-{Guid.NewGuid():N}.db");
    readonly CafeCore _cafe;
    readonly long _owner;

    public TamperTests()
    {
        _cafe = new CafeCore(_file, "test-key-123", () => new DateTime(2026, 11, 26, 10, 0, 0, DateTimeKind.Utc));
        _owner = _cafe.AddUser(null, Role.Owner, "Owner", "9000000001", "432100");
        _cafe.AddPc(_owner, "PC1");
    }
    public void Dispose() { _cafe.Dispose(); SqliteConnection.ClearAllPools(); try { File.Delete(_file); } catch (IOException) { } }

    [Fact]
    public void A_locked_PC_goes_on_the_review_list_and_an_unlocked_one_on_the_counter_screen_at_most_five_an_hour()
    {
        _cafe.PcTamper("PC1", "ended", locked: true);
        Assert.Contains(_cafe.ForReview(), t => t.EndsWith(" PC1: the lock screen was ended 3 times within a minute; the Customer's programs were closed"));
        Assert.Empty(_cafe.OfflineUnlockAlerts(_owner));
        _cafe.PcTamper("PC1", "stuck", locked: false);
        Assert.Contains(_cafe.OfflineUnlockAlerts(_owner), t => t.EndsWith(" PC1: the lock screen stopped answering during a visit and was restarted"));
        Assert.Single(_cafe.ForReview()); // no voice for a restart during a visit
        Assert.Throws<CafeException>(() => _cafe.PcTamper("PC1", "anything", locked: true));
        Assert.Throws<CafeException>(() => _cafe.PcTamper("PC1", "screen", locked: false));
        for (var i = 0; i < 9; i++) _cafe.PcTamper("PC1", "screen", locked: true);
        Assert.Equal(5, _cafe.ForReview().Count + _cafe.OfflineUnlockAlerts(_owner).Count);
    }
}
