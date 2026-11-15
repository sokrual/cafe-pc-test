namespace Cafe;

/// A pen drive Windows is holding back on a gaming PC, waiting for staff or the owner at the counter.
public record PenDriveRequest(long Id, string Pc, string Name, string? Customer, string Requested);
/// Access: null while nobody has answered yet; "block", "read" (read-only) or "write" (read and write).
public record PenDriveAnswer(long Id, string? Access);

public sealed partial class CafeCore
{
    static readonly string[] PenDriveAccess = ["block", "read", "write"];

    /// The PC reports a pen drive every few seconds while it is plugged in. One request per drive per visit:
    /// asking again returns the same answer, so a drive pulled out and plugged back in keeps its answer until logout.
    public PenDriveAnswer PcPenDrive(string pc, string device, string name) => Tx(() =>
    {
        if (device.Length is < 1 or > 200 || device.Any(c => c is < ' ' or > '~')) throw new CafeException("The pen drive's Windows ID is not valid.");
        name = new string(name.Where(c => !char.IsControl(c)).ToArray()).Trim();
        if (name.Length == 0) name = "USB storage";
        if (name.Length > 80) name = name[..80];
        var session = Scalar<long?>("SELECT id FROM sessions WHERE pc = @p0 AND ended IS NULL", pc)
            ?? throw new CafeException("Nobody is using this PC. A pen drive can be allowed only during a visit.");
        using (var r = Query("SELECT id, access FROM pen_drives WHERE pc = @p0 AND session_id = @p1 AND device = @p2", pc, session, device))
            if (r.Read())
            {
                var answer = new PenDriveAnswer(r.GetInt64(0), r.IsDBNull(1) ? null : r.GetString(1));
                r.Close();
                Exec("UPDATE pen_drives SET last_seen = @p0 WHERE id = @p1", Iso(_now()), answer.Id);
                return answer;
            }
        if (Scalar<long>("SELECT count(*) FROM pen_drives WHERE pc = @p0 AND session_id = @p1", pc, session) >= 10)
            throw new CafeException("This PC has asked about 10 pen drives in this visit. Ask the customer to come to the counter.");
        var id = Insert("INSERT INTO pen_drives(pc, session_id, device, name, requested, last_seen) VALUES(@p0, @p1, @p2, @p3, @p4, @p4)",
            pc, session, device, name, Iso(_now()));
        Audit(UserOf(session), "pen_drive_request", $"{pc}: {name} ({device})");
        return new PenDriveAnswer(id, null);
    });

    /// Pen drives waiting for an answer that are still plugged in (seen by their PC in the last 15 seconds).
    public List<PenDriveRequest> PenDriveRequests(long by) => Tx(() =>
    {
        RequireStaff(by);
        using var r = Query("""
            SELECT p.id, p.pc, p.name, u.name, p.requested FROM pen_drives p
            JOIN sessions s ON s.id = p.session_id JOIN users u ON u.id = s.user_id
            WHERE p.access IS NULL AND s.ended IS NULL AND p.last_seen >= @p0 ORDER BY p.id
            """, Iso(_now().AddSeconds(-15)));
        var list = new List<PenDriveRequest>();
        while (r.Read()) list.Add(new(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4)));
        return list;
    });

    /// Staff or the owner answer. Only one pen drive per PC has access at a time: allowing a new one sends the
    /// earlier one back to "waiting", and its PC takes its access away.
    public void AnswerPenDrive(long by, long id, string access) => Tx(() =>
    {
        RequireStaff(by);
        if (!PenDriveAccess.Contains(access)) throw new CafeException("Choose Block, Allow read-only or Allow read and write.");
        using var r = Query("""
            SELECT p.pc, p.session_id, p.name, p.device FROM pen_drives p JOIN sessions s ON s.id = p.session_id
            WHERE p.id = @p0 AND p.access IS NULL AND s.ended IS NULL
            """, id);
        if (!r.Read()) throw new CafeException("This pen drive was already answered, or the visit has ended.");
        var (pc, session, name, device) = (r.GetString(0), r.GetInt64(1), r.GetString(2), r.GetString(3));
        r.Close();
        if (access != "block")
            foreach (var other in Column<long>("SELECT id FROM pen_drives WHERE pc = @p0 AND session_id = @p1 AND access IN ('read', 'write')", pc, session))
            {
                Exec("UPDATE pen_drives SET access = NULL, answered = NULL, answered_by = NULL WHERE id = @p0", other);
                Audit(by, "pen_drive_access_ended", $"{pc}: {Scalar<string>("SELECT name FROM pen_drives WHERE id = @p0", other)}; another pen drive was allowed; visit {session}");
            }
        Exec("UPDATE pen_drives SET access = @p0, answered = @p1, answered_by = @p2 WHERE id = @p3", access, Iso(_now()), by, id);
        Audit(by, "pen_drive_" + access, $"{pc}: {name} ({device}); visit {session}");
    });

    /// The PC's Microsoft Defender scan of an allowed pen drive. A threat goes on the owner's review list.
    public void PcPenDriveScan(string pc, long id, bool threats) => Tx(() =>
    {
        var session = Scalar<long?>("SELECT session_id FROM pen_drives WHERE id = @p0 AND pc = @p1", id, pc)
            ?? throw new CafeException("No such pen drive on this PC.");
        var name = Scalar<string>("SELECT name FROM pen_drives WHERE id = @p0", id);
        Audit(UserOf(session), threats ? "review_pen_drive_threat" : "pen_drive_scan_clean",
            threats ? $"{pc}: Microsoft Defender found a threat on the pen drive {name}" : $"{pc}: {name}");
    });
}
