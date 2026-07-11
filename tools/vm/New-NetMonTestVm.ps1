# Provision a clean Windows 11 Enterprise evaluation VM for installer testing.
[CmdletBinding()]
param(
    [string]$IsoPath = "C:\VMs\NetMon-Lab\ISO\Windows11EnterpriseEval-25H2-en-us.iso",
    [string]$VmName = "NetMon-Win11-Clean",
    [string]$VmBaseFolder = "C:\VMs\NetMon-Lab\VMs",
    [int]$MemoryMB = 8192,
    [int]$CpuCount = 4,
    [int]$DiskGB = 80,
    [Parameter(Mandatory)] [PSCredential]$GuestCredential,
    [switch]$Start
)

$ErrorActionPreference = "Stop"
$VBox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if (-not (Test-Path $VBox)) { throw "VirtualBox is not installed. Run: winget install --id Oracle.VirtualBox --exact" }
$IsoPath = (Resolve-Path -LiteralPath $IsoPath).Path
New-Item -ItemType Directory -Force -Path $VmBaseFolder | Out-Null

& $VBox showvminfo $VmName *> $null
if ($LASTEXITCODE -eq 0) { throw "VM '$VmName' already exists. Restore its clean snapshot or choose another name." }

$DiskPath = Join-Path $VmBaseFolder "$VmName\$VmName.vdi"
$PasswordFile = Join-Path $env:TEMP "netmon-vm-$([guid]::NewGuid().ToString('N')).password"
$Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($GuestCredential.Password)
try {
    $PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
    [IO.File]::WriteAllText($PasswordFile, $PlainPassword, [Text.Encoding]::UTF8)
    $PlainPassword = $null

    & $VBox createvm --name $VmName --ostype Windows11_64 --basefolder $VmBaseFolder --register
    if ($LASTEXITCODE -ne 0) { throw "VirtualBox could not create the VM." }
    & $VBox modifyvm $VmName --memory $MemoryMB --cpus $CpuCount --vram 128 --firmware efi --tpm-type 2.0 --ioapic on --nested-paging on --paravirt-provider hyperv --graphicscontroller vboxsvga --nic1 nat --clipboard-mode disabled --drag-and-drop disabled
    if ($LASTEXITCODE -ne 0) { throw "VirtualBox could not configure the VM." }
    & $VBox createmedium disk --filename $DiskPath --size ($DiskGB * 1024) --format VDI --variant Standard
    & $VBox storagectl $VmName --name SATA --add sata --controller IntelAhci --portcount 3 --bootable on
    & $VBox storageattach $VmName --storagectl SATA --port 0 --device 0 --type hdd --medium $DiskPath
    $StartType = if ($Start) { "gui" } else { "none" }
    & $VBox unattended install $VmName --iso=$IsoPath --user=$($GuestCredential.UserName) --user-password-file=$PasswordFile --admin-password-file=$PasswordFile --full-user-name="NetMon Tester" --locale=en_US --country=US --language=en-US --time-zone="America/Chicago" --hostname="netmon-test.local" --install-additions --start-vm=$StartType
    if ($LASTEXITCODE -ne 0) { throw "VirtualBox unattended Windows setup preparation failed." }
}
catch {
    Write-Warning "Provisioning failed. The partial VM is intentionally retained for diagnosis: $VmName"
    throw
}
finally {
    if ($Bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
    if (Test-Path $PasswordFile) { Remove-Item -LiteralPath $PasswordFile -Force }
}

Write-Host "VM '$VmName' is configured from the official Microsoft evaluation ISO." -ForegroundColor Green
if (-not $Start) { Write-Host "Start installation with: `"$VBox`" startvm `"$VmName`" --type gui" }
Write-Host "After Windows setup and Guest Additions finish, shut down and run:" 
Write-Host "  `"$VBox`" snapshot `"$VmName`" take clean-windows --description `"Clean Windows before any NetMon install`""
