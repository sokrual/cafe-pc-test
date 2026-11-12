namespace Cafe;

/// The counter server keeps this status in memory only. It never reads or stores a BitLocker recovery key.
public sealed class CounterDiskProtection
{
    public const string OffWarning = "Disk encryption (BitLocker) is off on this counter PC. If the PC or its disk is stolen, the cafe data can be read. Turn it on: see SECURITY-GUIDE.txt, part 1.";
    public const string UnavailableWarning = "BitLocker is not available on this counter PC (Windows Home may not include it). See SECURITY-GUIDE.txt, part 1.";
    public const string UnknownWarning = "Could not check BitLocker on this counter PC. Check disk encryption: see SECURITY-GUIDE.txt, part 1.";

    private string _state = "Unknown";

    public void SetState(string state)
    {
        _state = state is "On" or "Off" or "Unavailable" ? state : "Unknown";
    }

    public string? WarningFor(bool isOwner)
    {
        if (!isOwner) return null;
        return _state switch
        {
            "On" => null,
            "Off" => OffWarning,
            "Unavailable" => UnavailableWarning,
            _ => UnknownWarning
        };
    }
}
