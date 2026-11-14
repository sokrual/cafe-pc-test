using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Cafe.Agent;

static class ProcessSecurity
{
    const int DaclSecurityInformation = 0x00000004;

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, uint revision, out IntPtr descriptor, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetKernelObjectSecurity(IntPtr handle, int securityInformation, IntPtr descriptor);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);

    public static void ProtectCustomerAccess()
    {
        SecurityIdentifier customer;
        try { customer = (SecurityIdentifier)new NTAccount(Environment.MachineName, "Customer").Translate(typeof(SecurityIdentifier)); }
        catch (IdentityNotMappedException) { return; }

        // Customer can query and wait for the lock screen, but cannot inject or change its process DACL.
        var sddl = $"D:P(D;;0x006A;;;{customer.Value})(D;;WD;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00101000;;;{customer.Value})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (!SetKernelObjectSecurity(GetCurrentProcess(), DaclSecurityInformation, descriptor))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { LocalFree(descriptor); }
    }
}
