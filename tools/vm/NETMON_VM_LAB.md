# NetMon clean Windows VM lab

This lab tests the actual unsigned installer on a disposable Windows machine. It covers a first-time install, frozen-app startup and login-page response, uninstall, and an in-place previous-release-to-current-release upgrade with user-data preservation.

## Host setup

1. Install Oracle VirtualBox 7: `winget install --id Oracle.VirtualBox --exact`.
2. Download the official 90-day Windows 11 Enterprise evaluation ISO from Microsoft to `C:\VMs\NetMon-Lab\ISO\Windows11EnterpriseEval-25H2-en-us.iso`.
3. Create a local credential only for the disposable VM: `$credential = Get-Credential netmontest`.
4. Provision and start it:
   `powershell -ExecutionPolicy Bypass -File .\tools\vm\New-NetMonTestVm.ps1 -GuestCredential $credential -Start`
5. After Windows setup and Guest Additions finish, shut down the VM and take the required baseline snapshot:
   `& 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' snapshot 'NetMon-Win11-Clean' take clean-windows`

Do not use a personal password. The scripts keep the disposable guest password in a temporary file only for VirtualBox, zero the unmanaged BSTR copy, and delete the file in a `finally` block.

## Release verification

Build the current installer, then run:

`powershell -ExecutionPolicy Bypass -File .\tools\vm\Invoke-NetMonVmSmoke.ps1 -CurrentInstaller .\installer\Output\NetMon-Setup-0.5.0.exe -PreviousInstaller .\installer\Output\NetMon-Setup-0.4.0.exe -GuestCredential $credential -RestoreCleanSnapshot`

The guest-side smoke script refuses to run without an explicit disposable-VM confirmation. It does not reboot the host or guest, and it removes NetMon plus test data at the end unless asked to preserve state.
