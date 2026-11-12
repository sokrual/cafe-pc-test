using Cafe;
using Xunit;

public sealed class CounterDiskProtectionTests
{
    [Fact]
    public void BitLocker_warning_is_owner_only_and_clears_when_protection_reads_on()
    {
        var status = new CounterDiskProtection();
        status.SetState("Off");

        Assert.Null(status.WarningFor(false));
        Assert.Equal(CounterDiskProtection.OffWarning, status.WarningFor(true));

        status.SetState("On");
        Assert.Null(status.WarningFor(true));
    }

    [Fact]
    public void Missing_BitLocker_command_has_a_guide_warning_for_the_owner_only()
    {
        var status = new CounterDiskProtection();
        status.SetState("Unavailable");

        Assert.Null(status.WarningFor(false));
        Assert.Equal(CounterDiskProtection.UnavailableWarning, status.WarningFor(true));
    }
}
