#Requires -RunAsAdministrator
<#
    Lvl0's Extension Exterminator (Chrome / Edge)

    1. PROBE  - scans every user profile on the machine for installed extensions.
    2. MATCH  - compares what's installed against your kill list.
    3. KILL   - removes only the matches, in all three places that keep them alive:
                  * blocklist policy   (disable + prevent reinstall)
                  * external reg keys  (stop auto re-add, all hives)
                  * on-disk folders    (the actual files, every user/profile)

    Usage:
      .\ExtensionExterminatorOS.ps1       # kill matches (runs immediately)
#>

# Add Chrome/Edge extension IDs to be killed.
$KillList = @(
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",
    # FoxyProxy
    "gcknhkkoolaabfmlnjonogaaifnjlfnp"
)

$Browsers = @{
    "chrome.exe" = @{ Name="Google Chrome"; PolicyRoot="HKLM:\SOFTWARE\Policies\Google\Chrome";  ExtSub="Software\Google\Chrome\Extensions";  UserData="Google\Chrome\User Data" }
    "msedge.exe" = @{ Name="Microsoft Edge"; PolicyRoot="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; ExtSub="Software\Microsoft\Edge\Extensions"; UserData="Microsoft\Edge\User Data" }
}

# Determine installed browsers
$RegistryPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\Clients\StartMenuInternet",
    "HKLM:\SOFTWARE\Clients\StartMenuInternet",
    "HKCU:\SOFTWARE\Clients\StartMenuInternet"
)

# Fetches the .exe for each installed browser
$InstalledBrowsers = foreach ($Path in $RegistryPaths) {
    if (-not (Test-Path $Path)) { continue }
    Get-ChildItem $Path | ForEach-Object {
        $CmdKey = "$($_.PSPath)\shell\open\command"
        if (-not (Test-Path $CmdKey)) { return }
        $Cmd = (Get-ItemProperty $CmdKey)."(default)"
        if     ($Cmd -match '^"([^"]+)"')  { $Exe = $Matches[1] }
        elseif ($Cmd -match '^(.+?\.exe)') { $Exe = $Matches[1] }
        else                               { $Exe = $Cmd }
        [PSCustomObject]@{ BrowserName=$_.GetValue(""); Executable=(Split-Path $Exe -Leaf).ToLower() }
    }
}

$InstalledBrowsers = $InstalledBrowsers | Sort-Object Executable -Unique

# Inventory installed extensions across all user profiles
function Get-InstalledExtensions {
    $items = @()
    foreach ($Browser in $InstalledBrowsers) {
        $Info = $Browsers[$Browser.Executable]
        if (-not $Info) { continue }

        Get-ChildItem "C:\Users\*\AppData\Local\$($Info.UserData)\*\Extensions\*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.FullName -match 'Users\\([^\\]+)\\AppData\\Local\\.+?\\User Data\\([^\\]+)\\Extensions\\([^\\]+)$') {
                $items += [PSCustomObject]@{ Exe=$Browser.Executable; Browser=$Info.Name; User=$Matches[1]; Profile=$Matches[2]; Id=$Matches[3]; Path=$_.FullName }
            }
        }
    }
    return $items
}

# Match installed extensions against the kill list
$Targets = Get-InstalledExtensions | Where-Object { $KillList -contains $_.Id }

$Targets | Sort-Object Browser, Id | Format-Table Browser, User, Profile, Id -AutoSize

# Action helpers
function Remove-RegKey {
    param([string]$Key)
    if (-not (Test-Path $Key)) { return }
    try { Remove-Item $Key -Recurse -Force -ErrorAction Stop; Write-Host "    removed reg: $Key" -ForegroundColor Green }
    catch { Write-Host "    reg delete failed: $Key" -ForegroundColor Red }
}
function Remove-Dir {
    param([string]$Dir)
    if (-not (Test-Path $Dir)) { return }
    try { Remove-Item $Dir -Recurse -Force -ErrorAction Stop; Write-Host "    removed files: $Dir" -ForegroundColor Green }
    catch { Write-Host "    file delete failed (browser open?): $Dir" -ForegroundColor Red }
}
function Add-ToBlocklist {
    param([string]$PolicyRoot, [string]$Id)
    $Key = "$PolicyRoot\ExtensionInstallBlocklist"
    if (-not (Test-Path $Key)) { New-Item $Key -Force | Out-Null }
    $Props    = Get-ItemProperty $Key
    $Existing = @($Props.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { $_.Value })
    if ($Existing -contains $Id) { Write-Host "    already blocklisted: $Id" -ForegroundColor DarkGray; return }
    $Numbers = @($Props.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { [int]$_.Name })
    $Next    = if ($Numbers) { ($Numbers | Measure-Object -Maximum).Maximum + 1 } else { 1 }
    New-ItemProperty $Key -Name "$Next" -Value $Id -PropertyType String -Force | Out-Null
}
function Get-ExtRegPaths {
    param([string]$ExtSub, [string]$Id)
    $paths = @(
        "HKLM:\$ExtSub\$Id",
        "HKLM:\SOFTWARE\Wow6432Node\$($ExtSub -replace '^Software\\','')\$Id",
        "HKCU:\$ExtSub\$Id"
    )
    Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
        ForEach-Object { $paths += "Registry::HKEY_USERS\$($_.PSChildName)\$ExtSub\$Id" }
    return $paths
}

# Remove matches, grouped by browser
foreach ($Group in ($Targets | Group-Object Exe)) {
    $Info = $Browsers[$Group.Name]
    $Ids = $Group.Group.Id | Sort-Object -Unique

    foreach ($Id in $Ids) {
        Add-ToBlocklist -PolicyRoot $Info.PolicyRoot -Id $Id
        foreach ($p in (Get-ExtRegPaths -ExtSub $Info.ExtSub -Id $Id)) { Remove-RegKey $p }
    }
    foreach ($t in $Group.Group) { Remove-Dir $t.Path }
}

# Summary of what was killed
Write-Host "`n=== Killed ===" -ForegroundColor Cyan
if ($Targets) {
    $Targets | Sort-Object Browser, Id -Unique | ForEach-Object {
        Write-Host "  $($_.Browser): $($_.Id)" -ForegroundColor Green
    }
} else {
    Write-Host "  Nothing matched the kill list." -ForegroundColor DarkGray
}
