using Cafe;
using Microsoft.Data.Sqlite;
using Xunit;

// D2: a pen drive waits for staff or the owner; one answer per drive per visit; one allowed drive per PC; all logged.
public sealed class PenDriveTests : IDisposable
{
    DateTime _clock = new(2026, 11, 14, 10, 0, 0, DateTimeKind.Utc);
    readonly string _file = Path.Combine(Path.GetTempPath(), $"cafe-pen-{Guid.NewGuid():N}.db");
    readonly CafeCore _cafe;
    readonly long _owner, _staff, _cust;
    const string Stick = @"USB\VID_0781&PID_5567\4C530001234567891234", Other = @"USB\VID_090C&PID_1000\AA00000000000077";

    public PenDriveTests()
    {
        _cafe = new CafeCore(_file, "test-key-123", () => _clock);
        _owner = _cafe.AddUser(null, Role.Owner, "Owner", "9000000001", "432100");
        _staff = _cafe.AddUser(_owner, Role.Staff, "Staff", "9000000002", "111111");
        _cust = _cafe.AddUser(_staff, Role.Customer, "Ravi", "9000000003", "2222");
        _cafe.AddPc(_owner, "PC1");
    }
    public void Dispose() { _cafe.Dispose(); SqliteConnection.ClearAllPools(); try { File.Delete(_file); } catch (IOException) { } }

    List<string> Audit()
    {
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _file, Password = "test-key-123", Pooling = false }.ToString());
        db.Open();
        using var c = db.CreateCommand();
        c.CommandText = "SELECT action || ' ' || coalesce(by_user, '') || ' ' || coalesce(detail, '') FROM audit WHERE action LIKE '%pen_drive%' ORDER BY id";
        using var r = c.ExecuteReader();
        var list = new List<string>();
        while (r.Read()) list.Add(r.GetString(0));
        return list;
    }

    [Fact]
    public void A_pen_drive_waits_for_the_counter_and_keeps_its_answer_for_the_visit()
    {
        Assert.Throws<CafeException>(() => _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade")); // nobody playing: nothing to allow
        var visit = _cafe.StartPostpaid(_staff, "PC1", _cust);
        var asked = _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade");
        Assert.Null(asked.Access);
        Assert.Equal(asked, _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade")); // asked again: same request, no second prompt
        var waiting = Assert.Single(_cafe.PenDriveRequests(_staff));
        Assert.Equal(("PC1", "Cruzer Blade", "Ravi"), (waiting.Pc, waiting.Name, waiting.Customer));

        Assert.Throws<CafeException>(() => _cafe.AnswerPenDrive(_cust, asked.Id, "write")); // customers cannot answer
        Assert.Throws<CafeException>(() => _cafe.AnswerPenDrive(_staff, asked.Id, "everything"));
        _cafe.AnswerPenDrive(_staff, asked.Id, "read");
        Assert.Equal("read", _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade").Access); // pulled out and back in: still read-only
        Assert.Empty(_cafe.PenDriveRequests(_owner));
        Assert.Throws<CafeException>(() => _cafe.AnswerPenDrive(_owner, asked.Id, "write")); // answered once only

        _cafe.Stop(_staff, visit);
        Assert.Throws<CafeException>(() => _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade")); // visit over: access over
        _cafe.StartPostpaid(_staff, "PC1", _cust);
        var next = _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade");
        Assert.NotEqual(asked.Id, next.Id);
        Assert.Null(next.Access); // the next visit asks again

        var log = Audit();
        Assert.Contains(log, l => l.StartsWith($"pen_drive_request {_cust} PC1: Cruzer Blade"));
        Assert.Contains(log, l => l.StartsWith($"pen_drive_read {_staff} PC1: Cruzer Blade ({Stick})"));
    }

    [Fact]
    public void Only_one_pen_drive_per_PC_has_access_and_the_owner_is_logged_too()
    {
        _cafe.StartPostpaid(_staff, "PC1", _cust);
        var first = _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade");
        var second = _cafe.PcPenDrive("PC1", Other, "Jet\u0007Flash"); // control characters are dropped from the name
        _cafe.AnswerPenDrive(_owner, first.Id, "write");
        _cafe.AnswerPenDrive(_owner, second.Id, "read");
        Assert.Null(_cafe.PcPenDrive("PC1", Stick, "Cruzer Blade").Access); // back to waiting: its PC takes the access away
        Assert.Equal("read", _cafe.PcPenDrive("PC1", Other, "JetFlash").Access);
        _cafe.AnswerPenDrive(_staff, first.Id, "block");
        Assert.Equal("read", _cafe.PcPenDrive("PC1", Other, "JetFlash").Access); // a block does not end the other's access

        var log = Audit();
        Assert.Contains(log, l => l.StartsWith($"pen_drive_write {_owner} PC1: Cruzer Blade"));
        Assert.Contains(log, l => l.StartsWith($"pen_drive_access_ended {_owner} PC1: Cruzer Blade"));
        Assert.Contains(log, l => l.StartsWith($"pen_drive_read {_owner} PC1: JetFlash"));
        Assert.Contains(log, l => l.StartsWith($"pen_drive_block {_staff} PC1: Cruzer Blade"));
    }

    [Fact]
    public void An_unplugged_drive_leaves_the_counter_list_and_bad_ids_are_refused()
    {
        _cafe.StartPostpaid(_staff, "PC1", _cust);
        _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade");
        _clock = _clock.AddSeconds(16); // the PC stopped reporting it: the customer took it out
        Assert.Empty(_cafe.PenDriveRequests(_staff));
        Assert.Throws<CafeException>(() => _cafe.PcPenDrive("PC1", "USB\\VID_1\n", "x"));
        Assert.Throws<CafeException>(() => _cafe.PcPenDrive("PC1", "", "x"));
        for (var i = 1; i < 10; i++) _cafe.PcPenDrive("PC1", Stick + i, "x");
        Assert.Throws<CafeException>(() => _cafe.PcPenDrive("PC1", Stick + "X", "x")); // at most 10 per visit
    }

    [Fact]
    public void A_threat_found_by_Defender_goes_on_the_review_list()
    {
        _cafe.StartPostpaid(_staff, "PC1", _cust);
        var asked = _cafe.PcPenDrive("PC1", Stick, "Cruzer Blade");
        _cafe.AnswerPenDrive(_staff, asked.Id, "write");
        _cafe.PcPenDriveScan("PC1", asked.Id, threats: false);
        Assert.Empty(_cafe.ForReview());
        _cafe.PcPenDriveScan("PC1", asked.Id, threats: true);
        Assert.Contains(_cafe.ForReview(), t => t.Contains("PC1: Microsoft Defender found a threat on the pen drive Cruzer Blade"));
        _cafe.AddPc(_owner, "PC2");
        Assert.Throws<CafeException>(() => _cafe.PcPenDriveScan("PC2", asked.Id, threats: true)); // only its own PC reports it
    }
}
