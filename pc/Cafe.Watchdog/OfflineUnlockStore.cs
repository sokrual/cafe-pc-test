using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

sealed record OfflineUnlockAccount(string Phone, string Secret);
sealed record OfflineUnlockRate(long Paise30 = 4000, long Paise60 = 6000, long Paise90 = 10000,
    long ExtraBlockPaise = 4000, int GraceMin = 5, int MinimumMin = 30, int BlockMin = 30,
    int BlockGraceMin = 5, int CarryOverDays = 7);
sealed record OfflineUnlockRequest(string SaleId, string Phone, string Code, int Minutes,
    string Method, string? UpiLast4, long? Session);
sealed record OfflineUnlockSale(string SaleId, string Phone, string Code, long Step, int Minutes,
    string Method, string? UpiLast4, long? Session);
sealed record OfflineUnlockResult(bool Success, string? Error, long? Step);
sealed record OfflineUnlockInfo(OfflineUnlockRate? Rate, int EnabledAccounts, DateTime? LockedUntil);

sealed class OfflineUnlockStore
{
    sealed class State
    {
        public OfflineUnlockRate? Rate { get; set; }
        public List<OfflineUnlockAccount> Accounts { get; set; } = [];
        public Dictionary<string, long> UsedSteps { get; set; } = new(StringComparer.Ordinal);
        public int WrongTries { get; set; }
        public DateTime? LockedUntil { get; set; }
        public List<OfflineUnlockSale> Pending { get; set; } = [];
    }

    static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };
    readonly string _path;
    readonly object _gate = new();

    public OfflineUnlockStore(string path) => _path = path;

    State Read()
    {
        if (!File.Exists(_path)) return new State();
        var protectedBytes = File.ReadAllBytes(_path);
        var clear = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
        return JsonSerializer.Deserialize<State>(clear, Json) ?? throw new InvalidDataException("offline unlock cache is empty");
    }

    void Write(State state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var clear = JsonSerializer.SerializeToUtf8Bytes(state);
        var protectedBytes = ProtectedData.Protect(clear, null, DataProtectionScope.LocalMachine);
        var temp = _path + ".new";
        File.WriteAllBytes(temp, protectedBytes);
        File.Move(temp, _path, true);
    }

    public void UpdateFromServer(string json)
    {
        var data = JsonSerializer.Deserialize<ServerData>(json, Json) ?? throw new InvalidDataException("server offline unlock data is invalid");
        lock (_gate)
        {
            var state = Read();
            state.Rate = data.Rate;
            state.Accounts = data.Accounts ?? [];
            Write(state);
        }
    }

    public string InfoJson()
    {
        lock (_gate)
        {
            var state = Read();
            return JsonSerializer.Serialize(new OfflineUnlockInfo(state.Rate, state.Accounts.Count, state.LockedUntil));
        }
    }

    public OfflineUnlockResult TryUnlock(OfflineUnlockRequest request)
    {
        lock (_gate)
        {
            var state = Read();
            var now = DateTime.UtcNow;
            if (state.LockedUntil is DateTime until && until > now)
                return new(false, "Offline unlock is paused for 10 minutes after three wrong attempts.", null);
            if (state.LockedUntil is not null) { state.LockedUntil = null; state.WrongTries = 0; }

            bool Fail(string message)
            {
                state.WrongTries++;
                if (state.WrongTries >= 3) state.LockedUntil = now.AddMinutes(10);
                Write(state);
                return false;
            }

            if (state.Rate is null || state.Accounts.Count == 0)
                return new(false, "Offline staff unlock is not set up on this PC.", null);
            if (!Guid.TryParseExact(request.SaleId, "N", out _))
                return new(false, "The offline sale reference is not valid.", null);
            if (request.Phone.Length is < 10 or > 13 || !request.Phone.All(char.IsAsciiDigit)
                || request.Code.Length != 6 || !request.Code.All(char.IsAsciiDigit))
                return new(Fail("Enter the staff phone number and six-digit app code."), "Wrong phone number or code.", null);
            if (request.Minutes < state.Rate.MinimumMin || request.Minutes > 10080
                || request.Minutes % Math.Max(1, state.Rate.BlockMin) != 0)
                return new(false, $"Minutes must be a {state.Rate.BlockMin}-minute block from the last rate card.", null);
            if (request.Method == "upi")
            {
                if (request.UpiLast4 is not { Length: 4 } || !request.UpiLast4.All(char.IsAsciiDigit))
                    return new(false, "For UPI, enter the last four digits of the payment reference.", null);
            }
            else if (request.Method != "cash") return new(false, "Choose cash or UPI.", null);

            var account = state.Accounts.FirstOrDefault(a => a.Phone == request.Phone);
            var nowStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
            long? matched = null;
            if (account is not null)
            {
                var key = DecodeBase32(account.Secret);
                for (var step = nowStep - 1; step <= nowStep + 1; step++)
                {
                    if (step <= state.UsedSteps.GetValueOrDefault(request.Phone, -1)) continue;
                    if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Totp(key, step)), Encoding.ASCII.GetBytes(request.Code)))
                        matched = step;
                }
            }
            if (matched is null)
                return new(Fail("Wrong phone number or code."), "Wrong phone number or code.", null);

            var sale = new OfflineUnlockSale(request.SaleId, request.Phone, request.Code, matched.Value,
                request.Minutes, request.Method, request.UpiLast4, request.Session);
            state.UsedSteps[request.Phone] = matched.Value;
            state.WrongTries = 0;
            state.LockedUntil = null;
            state.Pending.Add(sale);
            Write(state);
            return new(true, null, matched.Value);
        }
    }

    public List<OfflineUnlockSale> PendingSales()
    {
        lock (_gate) return Read().Pending.ToList();
    }

    public void RemovePending(string saleId)
    {
        lock (_gate)
        {
            var state = Read();
            state.Pending.RemoveAll(s => s.SaleId == saleId);
            Write(state);
        }
    }

    static byte[] DecodeBase32(string text)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var c in text.ToUpperInvariant().Replace(" ", "").TrimEnd('='))
        {
            var value = alphabet.IndexOf(c);
            if (value < 0) throw new InvalidDataException("offline unlock key is invalid");
            buffer = ((buffer << 5) | value) & 0xFFFF;
            bits += 5;
            if (bits >= 8) { bytes.Add((byte)(buffer >> (bits - 8))); bits -= 8; }
        }
        return [.. bytes];
    }

    static string Totp(byte[] key, long step)
    {
        var message = BitConverter.GetBytes(step);
        if (BitConverter.IsLittleEndian) Array.Reverse(message);
        var hash = HMACSHA1.HashData(key, message);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    sealed record ServerData(OfflineUnlockRate Rate, List<OfflineUnlockAccount>? Accounts);
}
