using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Security.Principal;
using Xunit;

[Collection("desktop")]
public sealed class ProcessSecurityTests
{
    [Fact]
    public void Customer_cannot_inject_into_its_own_lock_screen_process()
    {
        using (var existing = Process.Start(new ProcessStartInfo("net.exe", "user Customer")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        })!)
        {
            existing.WaitForExit();
            if (existing.ExitCode == 0) Assert.Skip("Customer already exists on this machine; refusing to change its credentials.");
        }

        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(5)) + "Aa9!";
        RunNet("user", "Customer", password, "/add", "/passwordchg:no", "/expires:never");
        var testDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "CafeProcessAccessTest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDirectory);
        var script = Path.Combine(testDirectory, "probe.ps1");
        File.WriteAllText(script, """
            $source = 'using System; using System.Runtime.InteropServices; public static class CafeProcessAccessProbe { [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid); [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle); public static int Check(int pid) { foreach (uint access in new uint[] { 0x20, 0x2, 0x40, 0x40000 }) { var handle = OpenProcess(access, false, pid); if (handle != IntPtr.Zero) { CloseHandle(handle); return 1; } if (Marshal.GetLastWin32Error() != 5) return 2; } return 0; } }'
            Add-Type -TypeDefinition $source
            exit [CafeProcessAccessProbe]::Check([int]$args[0])
            """);

        using var rig = new Rig();
        Process? proxy = null;
        Process? agent = null;
        try
        {
            var sourceDirectory = Path.GetDirectoryName(Rig.Env("CAFE_AGENT_EXE"))!;
            foreach (var file in Directory.GetFiles(sourceDirectory))
                File.Copy(file, Path.Combine(testDirectory, Path.GetFileName(file)), true);
            var agentExe = Path.Combine(testDirectory, "Cafe.Agent.exe");
            var customerSid = new NTAccount("Customer").Translate(typeof(SecurityIdentifier)).Value;

            var proxyStart = new ProcessStartInfo(Rig.Env("CAFE_WATCHDOG_EXE")) { UseShellExecute = false };
            foreach (var arg in new[]
            {
                "--test-proxy", "--server", "https://127.0.0.1:5443",
                "--token-file", rig.TokenFile,
                "--pin-file", Path.Combine(Path.GetDirectoryName(rig.TokenFile)!, "server.pin"),
                "--pipe-sid", customerSid, "--agent-path", agentExe
            }) proxyStart.ArgumentList.Add(arg);
            proxy = Process.Start(proxyStart)!;
            Thread.Sleep(500);
            Assert.False(proxy.HasExited, "watchdog test proxy exited before Agent startup");

            // Start the Agent as Customer too: OWNER RIGHTS must stop the process owner
            // from restoring write access to its own process.
            agent = StartAsCustomer(password, agentExe, ["--name", "Test Cafe"], testDirectory);
            var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            var result = -1;
            var until = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < until)
            {
                result = RunAsCustomer(password, powershell, script, agent.Id, testDirectory);
                if (result == 0) break;
                Thread.Sleep(500); // wait for Cafe.Agent to apply its process DACL at startup
            }
            Assert.Equal(0, result);
        }
        finally
        {
            Rig.Kill(agent);
            Rig.Kill(proxy);
            try { RunNet("user", "Customer", "/delete"); } catch { }
            try { Directory.Delete(testDirectory, true); } catch (IOException) { }
        }
    }

    static void RunNet(params string[] args)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("net.exe")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);
        process.Start();
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, "net.exe failed: " + output);
    }

    static Process StartAsCustomer(string password, string executable, string[] arguments, string workingDirectory)
    {
        var command = new StringBuilder($"\"{executable}\" " + string.Join(" ", arguments.Select(Quote)));
        var startup = new StartupInfo { Cb = Marshal.SizeOf<StartupInfo>(), Desktop = @"winsta0\default", Flags = 1, ShowWindow = 0 };
        if (!CreateProcessWithLogonW("Customer", ".", password, 1, executable, command, 0x00000400,
            IntPtr.Zero, workingDirectory, ref startup, out var process))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try { return Process.GetProcessById((int)process.ProcessId); }
        finally { CloseHandle(process.Thread); CloseHandle(process.Process); }
    }

    static int RunAsCustomer(string password, string executable, string script, int pid, string workingDirectory)
    {
        var command = new StringBuilder($"\"{executable}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {Quote(script)} {pid}");
        var startup = new StartupInfo { Cb = Marshal.SizeOf<StartupInfo>(), Desktop = @"winsta0\default", Flags = 1, ShowWindow = 0 };
        if (!CreateProcessWithLogonW("Customer", ".", password, 1, executable, command, 0x00000400,
            IntPtr.Zero, workingDirectory, ref startup, out var process))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (WaitForSingleObject(process.Process, 30000) != 0)
                throw new TimeoutException("Customer process-access probe did not finish.");
            if (!GetExitCodeProcess(process.Process, out var exitCode))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return unchecked((int)exitCode);
        }
        finally { CloseHandle(process.Thread); CloseHandle(process.Process); }
    }

    static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo
    {
        public int Cb;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public short ShowWindow, Reserved2;
        public IntPtr Reserved2Pointer, StdInput, StdOutput, StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation
    {
        public IntPtr Process, Thread;
        public uint ProcessId, ThreadId;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessWithLogonW(string user, string domain, string password, uint logonFlags,
        string applicationName, StringBuilder commandLine, uint creationFlags, IntPtr environment,
        string currentDirectory, ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
}
