namespace Cafe;

public sealed partial class CafeCore
{
    static readonly Dictionary<string, string> TamperText = new()
    {
        ["stuck"] = "the lock screen stopped answering; it was restarted and the Customer's programs were closed",
        ["ended"] = "the lock screen was ended 3 times within a minute; the Customer's programs were closed",
        ["screen"] = "another program kept taking the screen from the lock screen; the Customer's programs were closed",
    };

    /// B5.3 part 3: the PC's watchdog saw the lock screen tampered with. On a locked PC it goes on the owner's review list,
    /// which the counter window speaks and shows. On an unlocked PC the lock screen was only restarted: the counter screen
    /// shows it, with no voice (decided 26 Nov).
    public void PcTamper(string pc, string what, bool locked) => Tx(() =>
    {
        if (!TamperText.TryGetValue(what, out var text)) throw new CafeException("Unknown lock screen report.");
        if (!locked && what != "stuck") throw new CafeException("Unknown lock screen report.");
        if (Scalar<long>("SELECT count(*) FROM audit WHERE action IN ('review_lock_screen', 'lock_screen_restarted') AND at >= @p0 AND detail LIKE @p1",
            Iso(_now().AddHours(-1)), pc + ":%") >= 5)
            return; // at most 5 an hour per PC; the PC's own log has every one
        Insert("INSERT INTO audit(at, by_user, action, detail) VALUES(@p0, NULL, @p1, @p2)", Iso(_now()),
            locked ? "review_lock_screen" : "lock_screen_restarted",
            locked ? $"{pc}: {text}" : $"{pc}: the lock screen stopped answering during a visit and was restarted");
    });
}
