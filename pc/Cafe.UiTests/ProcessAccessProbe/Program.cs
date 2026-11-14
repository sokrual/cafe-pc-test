using System.ComponentModel;
using System.Runtime.InteropServices;

if (args.Length != 1 || !uint.TryParse(args[0], out var processId)) return 2;

const uint ProcessCreateThread = 0x0002;
const uint ProcessVmWrite = 0x0020;
const uint ProcessDupHandle = 0x0040;
const uint WriteDac = 0x00040000;
foreach (var access in new[] { ProcessVmWrite, ProcessCreateThread, ProcessDupHandle, WriteDac })
{
    var handle = OpenProcess(access, false, processId);
    if (handle == IntPtr.Zero)
    {
        if (Marshal.GetLastWin32Error() == 5) continue;
        Console.Error.WriteLine($"OpenProcess({access:X}) failed with {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
        return 3;
    }
    CloseHandle(handle);
    Console.Error.WriteLine($"Customer unexpectedly opened Cafe.Agent with access 0x{access:X}");
    return 1;
}
return 0;

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool CloseHandle(IntPtr handle);
