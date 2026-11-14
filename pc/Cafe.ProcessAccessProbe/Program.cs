using System.Runtime.InteropServices;

internal static class Program
{
    static int Main(string[] args)
    {
        if (args.Length != 1 || !int.TryParse(args[0], out var pid)) return 2;
        foreach (uint access in new uint[] { 0x20, 0x8, 0x2, 0x40, 0x40000 })
        {
            var handle = OpenProcess(access, false, pid);
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
                return 1;
            }
            if (Marshal.GetLastWin32Error() != 5) return 2;
        }
        return 0;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
}
