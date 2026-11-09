CAFE PC SOFTWARE (test repo)

Software to run a small gaming cafe: 10 to 15 Windows 11 Pro gaming PCs and one counter (admin) PC
on the same shop network. Payment is cash or UPI. Nothing runs on the internet; all data stays on the counter PC.
Made by Turyos Ventures. Work in progress, not ready for real customers yet.

WHAT IS IN HERE

server/   The counter PC program: customers, sessions, billing, payments (C#, .NET 10, encrypted SQLite).
          Cafe.Core = the rules and the database. Cafe.Server = the HTTPS service the gaming PCs talk to.
          Cafe.Tests = billing and security tests.
pc/       The gaming PC programs.
          Cafe.Agent = the lock screen and the on-screen timer. Runs in the customer's Windows session.
          Cafe.Watchdog = a Windows service (runs as SYSTEM). Keeps the lock screen running and does the
          clean-up after each customer logs out.
          Cafe.UiTests = lock screen tests that click through the real screens.
install/  Installers for the counter PC and the gaming PCs, the Level A allow-list script, and HOW-TO-INSTALL.txt.
kit/      The "Phase 0" test kit for one real cafe PC (1 to 2 days, changes nothing for customers).
timer/    The small timer program the Phase 0 kit tests with.
ci/       Test scripts the GitHub workflow runs on real Windows machines.

HOW IT IS TESTED

Every push runs .github/workflows/phase0-windows.yml on GitHub's Windows Server 2025 (x64) and
Windows 11 (arm) machines. Jobs:
  server-tests   billing, encryption, logins, roles
  pc-ui-tests    lock screen and watchdog
  lockdown       both installers, the logout clean-up, what a customer cannot do, Level A, uninstall
  kit            the Phase 0 kit, start to finish, and the owner zip
Each job uploads its results and logs as artifacts on the run page.

BUILD

.NET 10 SDK. The pc/ projects build for Windows only.
  dotnet build server/Cafe.Server
  dotnet test --project server/Cafe.Tests

THIRD-PARTY

AdGuard Home (GPL-3.0) is the web filter on the counter PC. It is not stored in this repo; install-admin.ps1
downloads a fixed version from AdGuard's own GitHub release and checks its SHA-256 before installing it.
NuGet packages: see the .csproj files.
