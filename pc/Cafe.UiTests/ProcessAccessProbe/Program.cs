using System.ComponentModel;
using System.Runtime.InteropServices;

if (args.Length != 1 || !uint.TryParse(args[0], out var processId)) return 2;

const uint ProcessCreateThread = 0x0002;
const uint ProcessVmWrite = 0x0020;
const uint ProcessDupHandle = 0x0040;
const uint WriteDac = 0x00040000;
foreach (var access in new[] { ProcessVmWrite, ProcessCreateThread, ProcessDupHandle, WriteDac })
{
    var handle = Native.OpenProcess(access, false, processId);
    if (handle == IntPtr.Zero)
    {
        var error = Marshal.GetLastWin32Error();
        if (error == 5) continue;
        Console.Error.WriteLine($"OpenProcess({access:X}) failed with {new Win32Exception(error).Message}");
        return 3;
    }
    Native.CloseHandle(handle);
    Console.Error.WriteLine($"Customer unexpectedly opened Cafe.Agent with access 0x{access:X}");
    return 1;
}
return 0;

static class Native
{
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);
}
