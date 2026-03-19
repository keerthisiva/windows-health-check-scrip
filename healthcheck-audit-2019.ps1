<#
.SYNOPSIS
    Windows Server 2019 CIS Benchmark - AUDIT ONLY Script (v2 - Enhanced)

.DESCRIPTION
    Audits the server against CIS Benchmark L1 values.
    Does NOT make any changes to the system.

    STATUS DEFINITIONS:
      PASS           - Policy is configured and matches the CIS required value.
      FAIL           - Policy is configured but does NOT match the required value.
      NOT_CONFIGURED - The registry KEY PATH exists, but the specific VALUE is not set.
                       Windows may apply a built-in default. Requires manual review.
      NOT_FOUND      - The registry KEY PATH itself does not exist on this server.
                       The feature/policy may not be installed or was never configured.
      MANUAL         - Cannot be checked programmatically; requires manual inspection.

.OUTPUT
    Audit_Results_[Timestamp]\CIS_Audit_Report.html
    Audit_Results_[Timestamp]\CIS_Audit_Report.csv

.USAGE
    Run as Administrator (Read-Only - No changes made):
    .\CIS_Audit_v2.ps1
#>

# ============================================================
# SETUP
# ============================================================
$StartTime   = Get-Date
$Timestamp   = $StartTime.ToString("yyyyMMdd-HHmmss")
$WorkDir     = "$PSScriptRoot\Audit_Results_$Timestamp"
$ReportFile  = "$WorkDir\CIS_Audit_Report.html"
$CsvFile     = "$WorkDir\CIS_Audit_Report.csv"
$SeceditFile = "$WorkDir\secedit_export.inf"

New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
Write-Host "[INFO] Output directory: $WorkDir" -ForegroundColor Cyan

# ============================================================
# GLOBAL RESULTS STORE
# ============================================================
$script:AuditResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# ============================================================
# POLICY READERS
# ============================================================

Function Get-SecPolicyValue {
    param([string]$Key)
    try {
        $line = Select-String -Path $SeceditFile -Pattern "^\s*$Key\s*=" -CaseSensitive
        if ($line) { return ($line.ToString().Split('=',2)[1]).Trim() }
    } catch {}
    return $null
}

$global:_AuditPolCache = $null
Function Get-AuditPolValue {
    param([string]$Subcategory)
    if ($null -eq $global:_AuditPolCache) {
        $global:_AuditPolCache = @{}
        try {
            auditpol /get /category:* /r | ConvertFrom-Csv | ForEach-Object {
                $val = switch ($_."Inclusion Setting") {
                    "No Auditing"         { 0 }
                    "Success"             { 1 }
                    "Failure"             { 2 }
                    "Success and Failure" { 3 }
                    default               { -1 }
                }
                $global:_AuditPolCache[$_.Subcategory] = $val
            }
        } catch {}
    }
    return $global:_AuditPolCache[$Subcategory]
}

# Returns a hashtable: @{ KeyExists=$bool; Value=$val }
# KeyExists = $false  → the registry key PATH does not exist  → NOT_FOUND
# KeyExists = $true, Value = $null → the value name is absent  → NOT_CONFIGURED
# KeyExists = $true, Value = <val> → value is present          → compare for PASS/FAIL
Function Get-RegInfo {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path $Path)) {
        return @{ KeyExists = $false; Value = $null }
    }
    try {
        $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        return @{ KeyExists = $true; Value = $val }
    } catch {
        return @{ KeyExists = $true; Value = $null }
    }
}

# Legacy simple reader kept for backward-compat in custom checks
Function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

# ============================================================
# RESULT RECORDER
# ============================================================

Function Record-Result {
    param(
        [string]$Section,
        [string]$ID,
        [string]$Title,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [ValidateSet('PASS','FAIL','NOT_CONFIGURED','NOT_FOUND','MANUAL')][string]$Status
    )
    $script:AuditResults.Add([PSCustomObject]@{
        Section       = $Section
        ID            = $ID
        Title         = $Title
        CurrentValue  = $CurrentValue
        ExpectedValue = $ExpectedValue
        Status        = $Status
        Timestamp     = $StartTime.ToString("yyyy-MM-dd HH:mm:ss")
    })
}

# ============================================================
# ENHANCED REGISTRY CHECK HELPER
# Distinguishes: PASS / FAIL / NOT_CONFIGURED / NOT_FOUND
# ============================================================

Function Check-RegistryValue {

    param(
        [string]$Section,
        [string]$ID,
        [string]$Title,
        [string]$Path,
        [string]$Name,
        $Expected,
        [string]$ExpectedDisplay = $null,
        [string]$CompareMode = "Exact"
    )

    $info = Get-RegInfo -Path $Path -Name $Name
    $disp = if ($null -eq $ExpectedDisplay) { "$Expected" } else { $ExpectedDisplay }

    # Registry key path does not exist
    if (-not $info.KeyExists) {
        Record-Result $Section $ID $Title "KEY PATH NOT FOUND: $Path" $disp "NOT_FOUND"
        return
    }

    # Registry value not defined
    if ($null -eq $info.Value -or $info.Value -eq "") {
        Record-Result $Section $ID $Title "VALUE NOT CONFIGURED" $disp "NOT_CONFIGURED"
        return
    }

    $current = $info.Value
    $currentDisplay = "$current"

    $pass = $false

    switch ($CompareMode) {

        "Exact" {
            $pass = ($current.ToString() -eq $Expected.ToString())
        }

        "GTE" {
            $pass = ([int]$current -ge [int]$Expected)
        }

        "LTE" {
            $pass = ([int]$current -le [int]$Expected)
        }

        "GTE_NonZero" {
            $pass = ([int]$current -ge [int]$Expected -and [int]$current -gt 0)
        }

        default {
            $pass = ($current.ToString() -eq $Expected.ToString())
        }
    }
 # Detect default OS value (policy not configured)
    $policyPath = $Path -replace "SOFTWARE\\Microsoft\\Windows","SOFTWARE\\Policies\\Microsoft\\Windows"

    if (!(Test-Path $policyPath)) {
        Record-Result $Section $ID $Title "POLICY NOT CONFIGURED (default value present)" $disp "NOT_CONFIGURED"
        return
    }
    if ($pass) {
        Record-Result $Section $ID $Title $currentDisplay $disp "PASS"
    }
    else {
        Record-Result $Section $ID $Title $currentDisplay $disp "FAIL"
    }
}

# ============================================================
# NEW HELPER: Checks Policy Path FIRST, then Registry Value
# ============================================================
Function Check-PolicyRegistryValue {

    param(
        [string]$Section,
        [string]$ID,
        [string]$Title,
        [string]$PolicyPath,
        [string]$Name,
        $Expected,
        [string]$ExpectedDisplay = $null,
        [string]$CompareMode = "Exact"
    )

    $disp = if ($null -eq $ExpectedDisplay) { "$Expected" } else { $ExpectedDisplay }

    # POLICY PATH must exist
    if (!(Test-Path $PolicyPath)) {
        Record-Result $Section $ID $Title "POLICY NOT CONFIGURED (path missing)" $disp "NOT_CONFIGURED"
        return
    }

    $info = Get-RegInfo -Path $PolicyPath -Name $Name

    if ($null -eq $info.Value -or $info.Value -eq "") {
        Record-Result $Section $ID $Title "VALUE NOT CONFIGURED" $disp "NOT_CONFIGURED"
        return
    }

    $current = $info.Value
    $currentDisplay = "$current"

    $pass = $false

    switch ($CompareMode) {
        "Exact" { $pass = ($current.ToString() -eq $Expected.ToString()) }
        "GTE"   { $pass = ([int]$current -ge [int]$Expected) }
        "LTE"   { $pass = ([int]$current -le [int]$Expected) }
    }

    Record-Result $Section $ID $Title $currentDisplay $disp $(if($pass){"PASS"}else{"FAIL"})
}

# ============================================================
# NEW HELPER: Checks Policy Path FIRST, then Registry Value
# ============================================================
Function Check-PolicyRegistryValue {

    param(
        [string]$Section,
        [string]$ID,
        [string]$Title,
        [string]$PolicyPath,
        [string]$Name,
        $Expected,
        [string]$ExpectedDisplay = $null,
        [string]$CompareMode = "Exact"
    )

    $disp = if ($null -eq $ExpectedDisplay) { "$Expected" } else { $ExpectedDisplay }

    # POLICY PATH must exist
    if (!(Test-Path $PolicyPath)) {
        Record-Result $Section $ID $Title "POLICY NOT CONFIGURED (path missing)" $disp "NOT_CONFIGURED"
        return
    }

    $info = Get-RegInfo -Path $PolicyPath -Name $Name

    if ($null -eq $info.Value -or $info.Value -eq "") {
        Record-Result $Section $ID $Title "VALUE NOT CONFIGURED" $disp "NOT_CONFIGURED"
        return
    }

    $current = $info.Value
    $currentDisplay = "$current"

    $pass = $false

    switch ($CompareMode) {
        "Exact" { $pass = ($current.ToString() -eq $Expected.ToString()) }
        "GTE"   { $pass = ([int]$current -ge [int]$Expected) }
        "LTE"   { $pass = ([int]$current -le [int]$Expected) }
    }

    Record-Result $Section $ID $Title $currentDisplay $disp $(if($pass){"PASS"}else{"FAIL"})
}

Function Check-SecurityOption {

    param(
        [string]$Section,
        [string]$ID,
        [string]$Title,
        [string]$Path,
        [string]$Name,
        $Expected,
        [string]$ExpectedDisplay = $null,
        [string]$CompareMode = "Exact",
        $DefaultValue = $null
    )

    $info = Get-RegInfo -Path $Path -Name $Name
    $disp = if ($null -eq $ExpectedDisplay) { "$Expected" } else { $ExpectedDisplay }

    # Key must exist
    if (-not $info.KeyExists) {
        Record-Result $Section $ID $Title "KEY PATH NOT FOUND: $Path" $disp "NOT_FOUND"
        return
    }

    # 🔥 KEY DIFFERENCE: Handle default values
    $current = $info.Value

    if ($null -eq $current -or $current -eq "") {
        if ($null -ne $DefaultValue) {
            $current = $DefaultValue
        } else {
            Record-Result $Section $ID $Title "VALUE NOT CONFIGURED" $disp "NOT_CONFIGURED"
            return
        }
    }

    $currentDisplay = "$current"
    $pass = $false

    switch ($CompareMode) {

        "Exact" {
            $pass = ($current.ToString() -eq $Expected.ToString())
        }

        "GTE" {
            $pass = ([int]$current -ge [int]$Expected)
        }

        "LTE" {
            $pass = ([int]$current -le [int]$Expected)
        }

        "RANGE" {
            $pass = ([int]$current -ge $Expected[0] -and [int]$current -le $Expected[1])
        }

        default {
            $pass = ($current.ToString() -eq $Expected.ToString())
        }
    }

    Record-Result $Section $ID $Title $currentDisplay $disp $(if($pass){"PASS"}else{"FAIL"})
}
# ============================================================
# SECTION 1: ACCOUNT POLICIES  (via secedit – always configured)
# ============================================================

Function Audit-AccountPolicies {
    Write-Host "  [1] Account Policies..." -ForegroundColor White
    $S = "1. Account Policies"

    $v = [int](Get-SecPolicyValue "PasswordHistorySize")
    Record-Result $S "1.1.1" "Enforce password history" "$v passwords" ">= 24 passwords" $(if($v -ge 24){"PASS"}else{"FAIL"})

    $v = [int](Get-SecPolicyValue "MaximumPasswordAge")
    Record-Result $S "1.1.2" "Maximum password age" "$v days" "<= 180 and > 0" $(if($v -le 180 -and $v -gt 0){"PASS"}else{"FAIL"})

    $v = [int](Get-SecPolicyValue "MinimumPasswordAge")
    Record-Result $S "1.1.3" "Minimum password age" "$v days" ">= 1" $(if($v -ge 1){"PASS"}else{"FAIL"})

    $v = [int](Get-SecPolicyValue "MinimumPasswordLength")
    Record-Result $S "1.1.4" "Minimum password length" "$v characters" ">= 15" $(if($v -ge 15){"PASS"}else{"FAIL"})

    $v = [int](Get-SecPolicyValue "PasswordComplexity")
    Record-Result $S "1.1.5" "Password complexity requirements" $(if($v -eq 1){"Enabled"}else{"Disabled"}) "Enabled (1)" $(if($v -eq 1){"PASS"}else{"FAIL"})

    $v = [int](Get-SecPolicyValue "ClearTextPassword")
    Record-Result $S "1.1.6" "Store passwords using reversible encryption" $(if($v -eq 0){"Disabled"}else{"Enabled"}) "Disabled (0)" $(if($v -eq 0){"PASS"}else{"FAIL"})

    $v = [int](Get-SecPolicyValue "LockoutDuration")
    Record-Result $S "1.2.1" "Account lockout duration" "$v minutes" ">= 30 (or -1 = forever)" $(if($v -ge 30 -or $v -eq -1){"PASS"}else{"FAIL"})

    $v = [int](Get-SecPolicyValue "LockoutBadCount")
    Record-Result $S "1.2.2" "Account lockout threshold" "$v attempts" "1 to 5" $(if($v -ge 1 -and $v -le 5){"PASS"}else{"FAIL"})

    $v = [int](Get-SecPolicyValue "ResetLockoutCount")
    Record-Result $S "1.2.4" "Reset account lockout counter after" "$v minutes" ">= 30" $(if($v -ge 30){"PASS"}else{"FAIL"})
}

# ============================================================
# SECTION 2.2: USER RIGHTS ASSIGNMENT
# ============================================================

Function Resolve-SidsToNames {
    param([string]$RawValue)
    if ([string]::IsNullOrWhiteSpace($RawValue)) { return "No One" }
    $names = @()
    foreach ($item in ($RawValue -split ",")) {
        $clean = $item.Trim().TrimStart('*')
        try {
            $sid  = New-Object System.Security.Principal.SecurityIdentifier($clean)
            $name = $sid.Translate([System.Security.Principal.NTAccount]).Value
            $names += $name.Split('\')[-1]
        } catch { $names += $clean }
    }
    return ($names | Sort-Object) -join ", "
}

Function Resolve-NamesToSids {
    param([string[]]$Names)
    $sids = @()
    foreach ($name in $Names) {
        if ($name -eq "No One") { continue }
        try {
            $nt  = New-Object System.Security.Principal.NTAccount($name)
            $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
            $sids += "*$($sid.Value)"
        } catch {
            try {
                $nt  = New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME\$name")
                $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
                $sids += "*$($sid.Value)"
            } catch { $sids += $name }
        }
    }
    return $sids
}

Function Check-UserRight {
    param(
        [string]$Section,
        [string]$ID,
        [string]$Title,
        [string]$Privilege,
        [string]$ExpectedNames,
        [string]$Mode = "Exact"
    )
    $raw     = Get-SecPolicyValue $Privilege
    $current = Resolve-SidsToNames -RawValue $raw

    # If secedit has no entry, the privilege is unconfigured
    if ($null -eq $raw) {
        $dispExpected = if ($ExpectedNames -eq "No One") { "No One" } else { "$ExpectedNames ($Mode)" }
        Record-Result $Section $ID $Title "NOT CONFIGURED in security policy" $dispExpected "NOT_CONFIGURED"
        return
    }

    $expList = if ($ExpectedNames -eq "No One") { @() } else { ($ExpectedNames -split ",") | ForEach-Object { $_.Trim() } }
    $expSids = Resolve-NamesToSids -Names $expList | Sort-Object

    $curSids = @()
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $curSids = ($raw -split ",") | ForEach-Object { $_.Trim() } | Sort-Object
    }

    $pass = $false
    if ($Mode -eq "Exact") {
        if ($ExpectedNames -eq "No One" -and $curSids.Count -eq 0) { $pass = $true }
        else { $pass = (($expSids -join ",") -eq ($curSids -join ",")) }
    } elseif ($Mode -eq "Include") {
        if ($expSids.Count -eq 0) { $pass = $true }
        else { $pass = ($expSids | Where-Object { $curSids -notcontains $_ }).Count -eq 0 }
    }

    $dispExpected = if ($ExpectedNames -eq "No One") { "No One" } else { "$ExpectedNames ($Mode)" }
    Record-Result $Section $ID $Title $current $dispExpected $(if($pass){"PASS"}else{"FAIL"})
}

Function Audit-UserRights {
    Write-Host "  [2.2] User Rights Assignment..." -ForegroundColor White
    $S = "2.2 User Rights Assignment"

    Check-UserRight $S "2.2.1"  "Access Credential Manager as trusted caller"         "SeTrustedCredManAccessPrivilege"   "No One"
    Check-UserRight $S "2.2.3"  "Access this computer from the network"                "SeNetworkLogonRight"               "Administrators, Authenticated Users"
    Check-UserRight $S "2.2.4"  "Act as part of the operating system"                  "SeTcbPrivilege"                    "No One"
    Check-UserRight $S "2.2.6"  "Adjust memory quotas for a process"                   "SeIncreaseQuotaPrivilege"          "Administrators, LOCAL SERVICE, NETWORK SERVICE"
    Check-UserRight $S "2.2.8"  "Allow log on locally"                                 "SeInteractiveLogonRight"           "Administrators"
    Check-UserRight $S "2.2.10" "Allow log on through Remote Desktop Services"         "SeRemoteInteractiveLogonRight"     "Administrators, Remote Desktop Users"
    Check-UserRight $S "2.2.11" "Back up files and directories"                        "SeBackupPrivilege"                 "Administrators"
    Check-UserRight $S "2.2.12" "Change the system time"                               "SeSystemtimePrivilege"             "Administrators, LOCAL SERVICE"
    Check-UserRight $S "2.2.13" "Change the time zone"                                 "SeTimeZonePrivilege"               "Administrators, LOCAL SERVICE"
    Check-UserRight $S "2.2.14" "Create a pagefile"                                    "SeCreatePagefilePrivilege"         "Administrators"
    Check-UserRight $S "2.2.15" "Create a token object"                                "SeCreateTokenPrivilege"            "No One"
    Check-UserRight $S "2.2.16" "Create global objects"                                "SeCreateGlobalPrivilege"           "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"
    Check-UserRight $S "2.2.17" "Create permanent shared objects"                      "SeCreatePermanentPrivilege"        "No One"
    Check-UserRight $S "2.2.19" "Create symbolic links"                                "SeCreateSymbolicLinkPrivilege"     "Administrators"
    Check-UserRight $S "2.2.20" "Debug programs"                                       "SeDebugPrivilege"                  "Administrators"
    Check-UserRight $S "2.2.22" "Deny access to this computer from the network"        "SeDenyNetworkLogonRight"           "Guests, Local account" "Include"
    Check-UserRight $S "2.2.23" "Deny log on as a batch job"                           "SeDenyBatchLogonRight"             "Guests" "Include"
    Check-UserRight $S "2.2.24" "Deny log on as a service"                             "SeDenyServiceLogonRight"           "Guests" "Include"
    Check-UserRight $S "2.2.25" "Deny log on locally"                                  "SeDenyInteractiveLogonRight"       "Guests" "Include"
    Check-UserRight $S "2.2.27" "Deny log on through Remote Desktop Services"          "SeDenyRemoteInteractiveLogonRight" "Guests, Local account" "Include"
    Check-UserRight $S "2.2.29" "Enable computer/user accounts trusted for delegation" "SeEnableDelegationPrivilege"       "No One"
    Check-UserRight $S "2.2.30" "Force shutdown from a remote system"                  "SeRemoteShutdownPrivilege"         "Administrators"
    Check-UserRight $S "2.2.31" "Generate security audits"                             "SeAuditPrivilege"                  "LOCAL SERVICE, NETWORK SERVICE"
    Check-UserRight $S "2.2.33" "Impersonate a client after authentication"            "SeImpersonatePrivilege"            "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"
    Check-UserRight $S "2.2.34" "Increase scheduling priority"                         "SeIncreaseBasePriorityPrivilege"   "Administrators"
    Check-UserRight $S "2.2.35" "Load and unload device drivers"                       "SeLoadDriverPrivilege"             "Administrators"
    Check-UserRight $S "2.2.36" "Lock pages in memory"                                 "SeLockMemoryPrivilege"             "No One"
    Check-UserRight $S "2.2.39" "Manage auditing and security log"                     "SeSecurityPrivilege"               "Administrators"
    Check-UserRight $S "2.2.40" "Modify an object label"                               "SeRelabelPrivilege"                "No One"
    Check-UserRight $S "2.2.41" "Modify firmware environment values"                   "SeSystemEnvironmentPrivilege"      "Administrators"
    Check-UserRight $S "2.2.42" "Perform volume maintenance tasks"                     "SeManageVolumePrivilege"           "Administrators"
    Check-UserRight $S "2.2.43" "Profile single process"                               "SeProfileSingleProcessPrivilege"   "Administrators"
    Check-UserRight $S "2.2.44" "Profile system performance"                           "SeSystemProfilePrivilege"          "Administrators, NT SERVICE\WdiServiceHost"
    Check-UserRight $S "2.2.45" "Replace a process level token"                        "SeAssignPrimaryTokenPrivilege"     "LOCAL SERVICE, NETWORK SERVICE"
    Check-UserRight $S "2.2.46" "Restore files and directories"                        "SeRestorePrivilege"                "Administrators"
    Check-UserRight $S "2.2.47" "Shut down the system"                                 "SeShutdownPrivilege"               "Administrators"
    Check-UserRight $S "2.2.49" "Take ownership of files or other objects"             "SeTakeOwnershipPrivilege"          "Administrators"
}

# ============================================================
# SECTION 2.3: SECURITY OPTIONS
# ============================================================

Function Audit-SecurityOptions {
    Write-Host "  [2.3] Security Options..." -ForegroundColor White
    $S   = "2.3 Security Options"
    $Sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $Lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $MS1 = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $Srv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $Wks = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

    Check-RegistryValue $S "2.3.1.1" "Accounts: Block Microsoft accounts" $Sys "NoConnectedUser" 3 "3 (Users cannot add or log on)"

    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    $guestStatus = if ($guest.Enabled) { "Enabled" } else { "Disabled" }
    Record-Result $S "2.3.1.2" "Accounts: Guest account status" $guestStatus "Disabled" $(if(-not $guest.Enabled){"PASS"}else{"FAIL"})

    Check-RegistryValue $S "2.3.1.3" "Limit local account blank passwords to console" $Lsa "LimitBlankPasswordUse" 1 "1 (Enabled)"

    $adminAcct = Get-LocalUser | Where-Object { $_.SID -like "*-500" } | Select-Object -First 1
    $adminName = if ($adminAcct) { $adminAcct.Name } else { "Unknown" }
    Record-Result $S "2.3.1.4" "Rename administrator account" $adminName "Not 'Administrator'" $(if($adminName -ne "Administrator"){"PASS"}else{"FAIL"})

    $guestAcct = Get-LocalUser | Where-Object { $_.SID -like "*-501" } | Select-Object -First 1
    $guestName = if ($guestAcct) { $guestAcct.Name } else { "Unknown" }
    Record-Result $S "2.3.1.5" "Rename guest account" $guestName "Not 'Guest'" $(if($guestName -ne "Guest"){"PASS"}else{"FAIL"})

    Check-RegistryValue $S "2.3.2.1" "Audit: Force audit policy subcategory settings"   $Lsa "SCENoApplyLegacyAuditPolicy" 1 "1 (Enabled)"
    Check-SecurityOption $S "2.3.2.2" "Audit: Shut down if unable to log security audits" $Lsa "CrashOnAuditFail" 0 "0 (Disabled)" "Exact" 0
    Check-RegistryValue $S "2.3.4.1" "Devices: Prevent users installing printer drivers" "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" 1 "1 (Enabled)"

    Check-RegistryValue $S "2.3.6.1" "Domain member: Digitally encrypt/sign channel (always)"  $Srv "RequireSignOrSeal"     1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.6.2" "Domain member: Digitally encrypt channel (possible)"     $Srv "SealSecureChannel"     1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.6.3" "Domain member: Digitally sign channel (possible)"        $Srv "SignSecureChannel"     1 "1 (Enabled)"
    Check-SecurityOption $S "2.3.6.4" "Domain member: Disable machine account password changes" $Srv "DisablePasswordChange" 0 "0 (Disabled)" "Exact" 0    Check-RegistryValue $S "2.3.6.5" "Domain member: Maximum machine account password age"     $Srv "MaximumPasswordAge"    30 "30 days"
    Check-RegistryValue $S "2.3.6.6" "Domain member: Require strong session key"               $Srv "RequireStrongKey"      1 "1 (Enabled)"

    Check-SecurityOption $S "2.3.7.1" "Interactive logon: Do not require CTRL+ALT+DEL" $Sys "DisableCAD" 0 "0 (Disabled)" "Exact" 0
    Check-RegistryValue $S "2.3.7.2" "Interactive logon: Don't display last signed-in" $Sys "DontDisplayLastUserName" 1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.7.3" "Interactive logon: Machine inactivity limit"     $Sys "InactivityTimeoutSecs"   900 "<= 900 and > 0 seconds" "LTE"

    $msgText  = Get-RegValue $Sys "LegalNoticeText"
    $msgTitle = Get-RegValue $Sys "LegalNoticeCaption"
    Record-Result $S "2.3.7.4" "Interactive logon: Message text for users"  $(if($msgText){"Configured"}else{"(empty)"})  "Configured (not empty)" $(if($msgText){"PASS"}else{"FAIL"})
    Record-Result $S "2.3.7.5" "Interactive logon: Message title for users" $(if($msgTitle){"Configured"}else{"(empty)"}) "Configured (not empty)" $(if($msgTitle){"PASS"}else{"FAIL"})

    Check-SecurityOption $S "2.3.7.7" "Interactive logon: Prompt user to change password before expiry" $Sys "PasswordExpiryWarning" @(5,14) "5-14 days" "RANGE" 14
    Check-RegistryValue $S "2.3.7.8" "Interactive logon: Require DC authentication to unlock"     $Sys "ForceUnlockLogon"     1  "1 (Enabled)"

    Check-RegistryValue $S "2.3.8.1" "MS network client: Digitally sign communications (always)"    $Wks "RequireSecuritySignature" 1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.8.2" "MS network client: Digitally sign communications (if server)" $Wks "EnableSecuritySignature"  1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.8.3" "MS network client: Send unencrypted password (DISABLED)"      $Wks "EnablePlainTextPassword"  0 "0 (Disabled)"

    Check-RegistryValue $S "2.3.9.1" "MS network server: Idle time before suspending session"        $Srv "AutoDisconnect"           15 "<= 15 minutes" "LTE"
    Check-RegistryValue $S "2.3.9.2" "MS network server: Digitally sign communications (always)"     $Srv "RequireSecuritySignature" 1  "1 (Enabled)"
    Check-RegistryValue $S "2.3.9.3" "MS network server: Digitally sign communications (if client)"  $Srv "EnableSecuritySignature"  1  "1 (Enabled)"
    Check-RegistryValue $S "2.3.9.4" "MS network server: Disconnect clients when logon hours expire"  $Srv "EnableForcedLogOff"       1  "1 (Enabled)"

    # 2.3.9.5 – custom: requires value >= 1
    $info = Get-RegInfo $Srv "SmbServerNameHardeningLevel"
    if (-not $info.KeyExists) {
        Record-Result $S "2.3.9.5" "MS network server: Server SPN target name validation" "KEY PATH NOT FOUND" ">= 1" "NOT_FOUND"
    } elseif ($null -eq $info.Value) {
        Record-Result $S "2.3.9.5" "MS network server: Server SPN target name validation" "VALUE NOT CONFIGURED" ">= 1" "NOT_CONFIGURED"
    } else {
        $spn = $info.Value
        Record-Result $S "2.3.9.5" "MS network server: Server SPN target name validation" "$spn" ">= 1" $(if([int]$spn -ge 1){"PASS"}else{"FAIL"})
    }

    Check-RegistryValue $S "2.3.10.1"  "Network access: Allow anonymous SID/Name translation"     $Lsa "TurnOffAnonymousAu"       1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.10.2"  "Network access: No anonymous enumeration of SAM accounts" $Lsa "RestrictAnonymousSAM"     1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.10.3"  "Network access: No anonymous enumeration of SAM/shares"   $Lsa "RestrictAnonymous"        1 "1 (Enabled)"
    Check-SecurityOption $S "2.3.10.5" "Network access: Let Everyone permissions apply to anonymous users" $Lsa "EveryoneIncludesAnonymous" 0 "0 (Disabled)" "Exact" 0
    # Named pipes – empty = compliant
    $npVal  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
    $npPass = ($null -eq $npVal -or ($npVal -is [array] -and $npVal.Count -eq 0) -or $npVal -eq "")
    $npDisp = if ($npPass) { "(empty - correct)" } else { "$($npVal -join ', ')" }
    Record-Result $S "2.3.10.7" "Network access: Named Pipes accessible anonymously" $npDisp "(empty / None)" $(if($npPass){"PASS"}else{"FAIL"})

    # Registry paths – must have values set
    $rrpInfo = Get-RegInfo "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" "Machine"
    if (-not $rrpInfo.KeyExists) {
        Record-Result $S "2.3.10.8" "Network access: Remotely accessible registry paths" "KEY PATH NOT FOUND" "Configured (specific paths only)" "NOT_FOUND"
    } elseif ($null -eq $rrpInfo.Value) {
        Record-Result $S "2.3.10.8" "Network access: Remotely accessible registry paths" "VALUE NOT CONFIGURED" "Configured (specific paths only)" "NOT_CONFIGURED"
    } else {
        $rrpDisp = "Configured ($(@($rrpInfo.Value).Count) path(s))"
        Record-Result $S "2.3.10.8" "Network access: Remotely accessible registry paths" $rrpDisp "Configured (specific paths only)" "PASS"
    }

    $rrpsInfo = Get-RegInfo "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" "Machine"
    if (-not $rrpsInfo.KeyExists) {
        Record-Result $S "2.3.10.9" "Network access: Remotely accessible registry paths and sub-paths" "KEY PATH NOT FOUND" "Configured (specific paths only)" "NOT_FOUND"
    } elseif ($null -eq $rrpsInfo.Value) {
        Record-Result $S "2.3.10.9" "Network access: Remotely accessible registry paths and sub-paths" "VALUE NOT CONFIGURED" "Configured (specific paths only)" "NOT_CONFIGURED"
    } else {
        $rrpsDisp = "Configured ($(@($rrpsInfo.Value).Count) path(s))"
        Record-Result $S "2.3.10.9" "Network access: Remotely accessible registry paths and sub-paths" $rrpsDisp "Configured (specific paths only)" "PASS"
    }

    Check-RegistryValue $S "2.3.10.10" "Network access: Restrict anonymous access to pipes/shares" $Lsa "NullSessionShares"  1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.10.11" "Network access: Restrict clients allowed remote SAM calls" $Lsa "RestrictRemoteSAM"  "O:BAG:BAD:(A;;RC;;;BA)" "O:BAG:BAD:(A;;RC;;;BA)"

    # Shares that can be accessed anonymously – empty = compliant
    $saVal  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares"
    $saPass = ($null -eq $saVal -or ($saVal -is [array] -and $saVal.Count -eq 0) -or $saVal -eq "")
    $saDisp = if ($saPass) { "(empty - correct)" } else { "$($saVal -join ', ')" }
    Record-Result $S "2.3.10.12" "Network access: Shares accessible anonymously" $saDisp "(empty / None)" $(if($saPass){"PASS"}else{"FAIL"})

    Check-SecurityOption $S "2.3.10.13" "Network access: Sharing and security model for local accounts" $Sys "ForceGuest" 0 "0 (Classic)" "Exact" 0
    Check-RegistryValue $S "2.3.11.1"  "Network security: Allow LocalSystem NTLM identity"        $Lsa "UseMachineId"             1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.11.2"  "Network security: Allow LocalSystem NULL session fallback" $MS1 "allownullsessionfallback" 0 "0 (Disabled)"
    Check-RegistryValue $S "2.3.11.3"  "Network security: Allow PKU2U online identities"          "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" "AllowOnlineID" 0 "0 (Disabled)"
    Check-RegistryValue $S "2.3.11.4"  "Network security: Kerberos encryption types"              "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes" 2147483616 "2147483616 (AES128/AES256)"
    Check-RegistryValue $S "2.3.11.5"  "Network security: Do not store LAN Manager hash"          $Lsa "NoLMHash"                 1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.11.7"  "Network security: LAN Manager authentication level"       $Lsa "LmCompatibilityLevel"     5 "5 (NTLMv2 only)"
    Check-RegistryValue $S "2.3.11.8"  "Network security: LDAP client signing requirements"       "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" "LDAPClientIntegrity" 1 "1 (Negotiate signing)"
    Check-RegistryValue $S "2.3.11.9"  "Network security: Min session security NTLM clients"      $MS1 "NtlmMinClientSec"        537395200 "537395200 (NTLMv2+128bit)"
    Check-RegistryValue $S "2.3.11.10" "Network security: Min session security NTLM servers"      $MS1 "NtlmMinServerSec"        537395200 "537395200 (NTLMv2+128bit)"

    # NTLM audit/restrict (custom display)
    $ntlmInInfo = Get-RegInfo "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AuditReceivingNTLMTraffic"
    if (-not $ntlmInInfo.KeyExists) {
        Record-Result $S "2.3.11.11" "Network security: Restrict NTLM: Audit Incoming NTLM Traffic" "KEY PATH NOT FOUND" "2 (Enable auditing for all accounts)" "NOT_FOUND"
    } elseif ($null -eq $ntlmInInfo.Value) {
        Record-Result $S "2.3.11.11" "Network security: Restrict NTLM: Audit Incoming NTLM Traffic" "VALUE NOT CONFIGURED" "2 (Enable auditing for all accounts)" "NOT_CONFIGURED"
    } else {
        $ntlmIn     = $ntlmInInfo.Value
        $ntlmInDisp = switch ([int]$ntlmIn) { 0{"Disabled"} 1{"Enable for domain accounts"} 2{"Enable for all accounts"} default{"Unknown ($ntlmIn)"} }
        Record-Result $S "2.3.11.11" "Network security: Restrict NTLM: Audit Incoming NTLM Traffic" $ntlmInDisp "2 (Enable auditing for all accounts)" $(if([int]$ntlmIn -eq 2){"PASS"}else{"FAIL"})
    }

    $ntlmOutInfo = Get-RegInfo "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictSendingNTLMTraffic"
    if (-not $ntlmOutInfo.KeyExists) {
        Record-Result $S "2.3.11.13" "Network security: Restrict NTLM: Outgoing NTLM traffic" "KEY PATH NOT FOUND" ">= 1 (Audit all or Deny all)" "NOT_FOUND"
    } elseif ($null -eq $ntlmOutInfo.Value) {
        Record-Result $S "2.3.11.13" "Network security: Restrict NTLM: Outgoing NTLM traffic" "VALUE NOT CONFIGURED" ">= 1 (Audit all or Deny all)" "NOT_CONFIGURED"
    } else {
        $ntlmOut     = $ntlmOutInfo.Value
        $ntlmOutDisp = switch ([int]$ntlmOut) { 0{"Allow all"} 1{"Audit all"} 2{"Deny all"} default{"Unknown ($ntlmOut)"} }
        Record-Result $S "2.3.11.13" "Network security: Restrict NTLM: Outgoing NTLM traffic" $ntlmOutDisp ">= 1 (Audit all or Deny all)" $(if([int]$ntlmOut -ge 1){"PASS"}else{"FAIL"})
    }

    Check-SecurityOption $S "2.3.13.1" "Shutdown: Allow system shutdown without logon" $Sys "ShutdownWithoutLogon" 0 "0 (Disabled)" "Exact" 0
    Check-RegistryValue $S "2.3.15.1" "System objects: Require case insensitivity"     "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" "ObCaseInsensitive" 1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.15.2" "System objects: Strengthen default permissions" "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" 1 "1 (Enabled)"

    Check-RegistryValue $S "2.3.17.1" "UAC: Admin Approval Mode for Built-in Administrator" $Sys "FilterAdministratorToken"   1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.17.2" "UAC: Behavior of elevation prompt for administrators" $Sys "ConsentPromptBehaviorAdmin" 2 "2 (Prompt on secure desktop)"
    Check-RegistryValue $S "2.3.17.3" "UAC: Behavior of elevation prompt for standard users" $Sys "ConsentPromptBehaviorUser"  0 "0 (Automatically deny)"
    Check-RegistryValue $S "2.3.17.4" "UAC: Detect application installations"               $Sys "EnableInstallerDetection"   1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.17.5" "UAC: Elevate UIAccess from secure locations only"    $Sys "EnableSecureUIAPaths"       1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.17.6" "UAC: Run all administrators in Admin Approval Mode"  $Sys "EnableLUA"                  1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.17.7" "UAC: Switch to secure desktop when prompting"        $Sys "PromptOnSecureDesktop"      1 "1 (Enabled)"
    Check-RegistryValue $S "2.3.17.8" "UAC: Virtualize file and registry write failures"    $Sys "EnableVirtualization"       1 "1 (Enabled)"
}

# ============================================================
# SECTION 9: WINDOWS FIREWALL
# ============================================================

Function Audit-Firewall {
    Write-Host "  [9] Windows Firewall..." -ForegroundColor White
    $S      = "9. Windows Firewall"
    $FWBase = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
    $profileMap = [ordered]@{ "1" = "Domain"; "2" = "Private"; "3" = "Public" }

    foreach ($num in $profileMap.Keys) {
        $profile = $profileMap[$num]
        $pk  = "$FWBase\${profile}Profile"
        $lk  = "$pk\Logging"

        Check-RegistryValue $S "9.$num.1" "${profile}: Firewall state"             $pk "EnableFirewall"             1 "1 (On)"
        Check-RegistryValue $S "9.$num.2" "${profile}: Inbound connections"         $pk "DefaultInboundAction"       1 "1 (Block)"
        Check-RegistryValue $S "9.$num.3" "${profile}: Outbound connections"        $pk "DefaultOutboundAction"      0 "0 (Allow)"
        Check-RegistryValue $S "9.$num.4" "${profile}: Display notification"        $pk "DisableNotifications"       1 "1 (No)"
        Check-RegistryValue $S "9.$num.6" "${profile}: Log file size"               $lk "LogFileSize"                16384 ">= 16384" "GTE"
        Check-RegistryValue $S "9.$num.7" "${profile}: Log dropped packets"         $lk "LogDroppedPackets"          1 "1 (Yes)"
        Check-RegistryValue $S "9.$num.8" "${profile}: Log successful connections"  $lk "LogSuccessfulConnections"   1 "1 (Yes)"
    }
}

# ============================================================
# SECTION 17: ADVANCED AUDIT POLICY
# ============================================================

Function Check-AuditRule {
    param(
        [string]$Section,
        [string]$ID,
        [string]$Title,
        [string]$Subcategory,
        [int]$Expected,
        [string]$Mode = "Exact"
    )
    $current         = [int](Get-AuditPolValue -Subcategory $Subcategory)
    $dispMap         = @{ 0="No Auditing"; 1="Success"; 2="Failure"; 3="Success and Failure" }
    $expMap          = @{ 1="Success"; 2="Failure"; 3="Success and Failure" }
    $currentDisplay  = if ($dispMap.ContainsKey($current)) { $dispMap[$current] } else { "Unknown ($current)" }
    $expectedDisplay = if ($Mode -eq "Include") { "Include $($expMap[$Expected])" } else { $expMap[$Expected] }

    $pass = $false
    if ($Mode -eq "Exact")   { $pass = ($current -eq $Expected) }
    if ($Mode -eq "Include") { $pass = (($current -band $Expected) -eq $Expected) }

    Record-Result $Section $ID $Title $currentDisplay $expectedDisplay $(if($pass){"PASS"}else{"FAIL"})
}

Function Audit-AdvancedAudit {
    Write-Host "  [17] Advanced Audit Policy..." -ForegroundColor White
    $S = "17. Advanced Audit Policy"

    Check-AuditRule $S "17.1.1" "Audit Credential Validation"           "Credential Validation"           3 "Exact"
    Check-AuditRule $S "17.2.1" "Audit Application Group Management"    "Application Group Management"    3 "Exact"
    Check-AuditRule $S "17.2.5" "Audit Security Group Management"       "Security Group Management"       1 "Include"
    Check-AuditRule $S "17.2.6" "Audit User Account Management"         "User Account Management"         3 "Exact"
    Check-AuditRule $S "17.3.1" "Audit PNP Activity"                    "PNP Activity"                    1 "Include"
    Check-AuditRule $S "17.3.2" "Audit Process Creation"                "Process Creation"                1 "Include"
    Check-AuditRule $S "17.5.1" "Audit Account Lockout"                 "Account Lockout"                 2 "Include"
    Check-AuditRule $S "17.5.2" "Audit Group Membership"                "Group Membership"                1 "Include"
    Check-AuditRule $S "17.5.3" "Audit Logoff"                          "Logoff"                          1 "Include"
    Check-AuditRule $S "17.5.4" "Audit Logon"                           "Logon"                           3 "Exact"
    Check-AuditRule $S "17.5.5" "Audit Other Logon/Logoff Events"       "Other Logon/Logoff Events"       3 "Exact"
    Check-AuditRule $S "17.5.6" "Audit Special Logon"                   "Special Logon"                   1 "Include"
    Check-AuditRule $S "17.6.1" "Audit Detailed File Share"             "Detailed File Share"             2 "Include"
    Check-AuditRule $S "17.6.2" "Audit File Share"                      "File Share"                      3 "Exact"
    Check-AuditRule $S "17.6.3" "Audit Other Object Access Events"      "Other Object Access Events"      3 "Exact"
    Check-AuditRule $S "17.6.4" "Audit Removable Storage"               "Removable Storage"               3 "Exact"
    Check-AuditRule $S "17.7.1" "Audit Audit Policy Change"             "Audit Policy Change"             1 "Include"
    Check-AuditRule $S "17.7.2" "Audit Authentication Policy Change"    "Authentication Policy Change"    1 "Include"
    Check-AuditRule $S "17.7.3" "Audit Authorization Policy Change"     "Authorization Policy Change"     1 "Include"
    Check-AuditRule $S "17.7.4" "Audit MPSSVC Rule-Level Policy Change" "MPSSVC Rule-Level Policy Change" 3 "Exact"
    Check-AuditRule $S "17.7.5" "Audit Other Policy Change Events"      "Other Policy Change Events"      2 "Include"
    Check-AuditRule $S "17.8.1" "Audit Sensitive Privilege Use"         "Sensitive Privilege Use"         3 "Exact"
    Check-AuditRule $S "17.9.1" "Audit IPsec Driver"                    "IPsec Driver"                    3 "Exact"
    Check-AuditRule $S "17.9.2" "Audit Other System Events"             "Other System Events"             3 "Exact"
    Check-AuditRule $S "17.9.3" "Audit Security State Change"           "Security State Change"           1 "Include"
    Check-AuditRule $S "17.9.4" "Audit Security System Extension"       "Security System Extension"       1 "Include"
    Check-AuditRule $S "17.9.5" "Audit System Integrity"                "System Integrity"                3 "Exact"
}

# ============================================================
# SECTION 18: ADMINISTRATIVE TEMPLATES
# ============================================================

Function Audit-AdminTemplates {
    Write-Host "  [18] Administrative Templates..." -ForegroundColor White
    $S    = "18. Administrative Templates"
    $PW   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
    $PSys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $PSvc = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $PTrm = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $PDef = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

    # 18.1 Lock Screen
    Check-RegistryValue $S "18.1.1.1" "Prevent enabling lock screen camera"     "$PW\Personalization"      "NoLockScreenCamera"        1 "1 (Enabled)"
    Check-RegistryValue $S "18.1.1.2" "Prevent enabling lock screen slide show" "$PW\Personalization"      "NoLockScreenSlideshow"     1 "1 (Enabled)"
    Check-RegistryValue $S "18.1.2.2" "Disable Online Speech Recognition"       "$PW\InputPersonalization" "AllowInputPersonalization"  0 "0 (Disabled)"

    # 18.4 Security / MSS
    Check-RegistryValue $S "18.4.1" "Apply UAC restrictions to local accounts on network logons"  $PSys                                                              "LocalAccountTokenFilterPolicy"   0 "0 (Enabled restriction)"
    Check-RegistryValue $S "18.4.2" "Configure RPC packet level privacy for incoming connections" "HKLM:\SYSTEM\CurrentControlSet\Control\Print"                     "RpcAuthnLevelPrivacyEnabled"      1 "1 (Enabled)"
    Check-RegistryValue $S "18.4.3" "Configure SMB v1 client driver (Disable)"                   "$PSvc\mrxsmb10"                                                   "Start"                            4 "4 (Disabled)"
    Check-RegistryValue $S "18.4.4" "Configure SMB v1 server (Disable)"                          "$PSvc\LanmanServer\Parameters"                                    "SMB1"                             0 "0 (Disabled)"
    Check-RegistryValue $S "18.4.5" "Enable Certificate Padding"                                  "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"            "EnableCertPaddingCheck"           1 "1 (Enabled)"
    Check-RegistryValue $S "18.4.6" "Enable SEHOP"                                                "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"   "DisableExceptionChainValidation"  0 "0 (SEHOP enabled)"
    Check-RegistryValue $S "18.4.7" "LSA Protection (RunAsPPL)"                                   "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"                      "RunAsPPL"                         1 "1 (Enabled)"
    Check-RegistryValue $S "18.4.8" "NetBT NodeType configuration (P-node)"                       "$PSvc\NetBT\Parameters"                                           "NodeType"                         2 "2 (P-node)"
    Check-RegistryValue $S "18.4.9" "WDigest Authentication (Disable)"                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"              0 "0 (Disabled)"

    # 18.5 MSS Legacy
    Check-RegistryValue $S "18.5.1" "Disable AutoAdminLogon"         "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"         "0" "0 (Disabled)"
    Check-RegistryValue $S "18.5.2" "IPv6 Source Routing protection" "$PSvc\Tcpip6\Parameters"                                      "DisableIPSourceRouting"  2  "2 (Highest)"
    Check-RegistryValue $S "18.5.3" "IPv4 Source Routing protection" "$PSvc\Tcpip\Parameters"                                       "DisableIPSourceRouting"  2  "2 (Highest)"
    Check-RegistryValue $S "18.5.4" "Disable ICMP Redirects"         "$PSvc\Tcpip\Parameters"                                       "EnableICMPRedirect"      0  "0 (Disabled)"
    Check-RegistryValue $S "18.5.6" "No Name Release On Demand"      "$PSvc\NetBT\Parameters"                                       "NoNameReleaseOnDemand"   1  "1 (Enabled)"
    Check-RegistryValue $S "18.5.8" "Enable Safe DLL search mode"    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"       "SafeDllSearchMode"       1  "1 (Enabled)"

    # 18.5.9 – ScreenSaverGracePeriod stored as String
    $ssgpInfo = Get-RegInfo "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScreenSaverGracePeriod"
    if (-not $ssgpInfo.KeyExists) {
        Record-Result $S "18.5.9" "MSS: ScreenSaverGracePeriod <= 5 seconds" "KEY PATH NOT FOUND" "<= 5 seconds" "NOT_FOUND"
    } elseif ($null -eq $ssgpInfo.Value) {
        Record-Result $S "18.5.9" "MSS: ScreenSaverGracePeriod <= 5 seconds" "VALUE NOT CONFIGURED" "<= 5 seconds" "NOT_CONFIGURED"
    } else {
        $ssgp = $ssgpInfo.Value
        Record-Result $S "18.5.9" "MSS: ScreenSaverGracePeriod <= 5 seconds" "$ssgp seconds" "<= 5 seconds" $(if([int]$ssgp -le 5 -and [int]$ssgp -ge 0){"PASS"}else{"FAIL"})
    }

    # 18.5.12 – Security event log warning
    $wlInfo = Get-RegInfo "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" "WarningLevel"
    if (-not $wlInfo.KeyExists) {
        Record-Result $S "18.5.12" "MSS: Security event log warning threshold <= 90%" "KEY PATH NOT FOUND" "<= 90%" "NOT_FOUND"
    } elseif ($null -eq $wlInfo.Value) {
        Record-Result $S "18.5.12" "MSS: Security event log warning threshold <= 90%" "VALUE NOT CONFIGURED" "<= 90%" "NOT_CONFIGURED"
    } else {
        $wl = $wlInfo.Value
        Record-Result $S "18.5.12" "MSS: Security event log warning threshold <= 90%" "$wl%" "<= 90%" $(if([int]$wl -le 90){"PASS"}else{"FAIL"})
    }

    # 18.6 Network
    Check-RegistryValue $S "18.6.4.1"  "Configure NetBIOS settings (Disable on public networks)" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableNetbios"               0 "0 (Disabled on public)"
    Check-RegistryValue $S "18.6.4.2"  "Turn off multicast name resolution"                      "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"             0 "0 (Disabled)"
    Check-PolicyRegistryValue $S "18.6.8.1" "Disable insecure guest logons"                      "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth" 0 "0 (Disabled)"    
    Check-RegistryValue $S "18.6.11.2" "Prohibit Network Bridge"                                 "$PW\Network Connections"                                "NC_AllowNetBridge"           0 "0 (Disabled)"
    Check-RegistryValue $S "18.6.11.3" "Prohibit Internet Connection Sharing"                    "$PW\Network Connections"                                "NC_ShowSharedAccessUI"       0 "0 (Disabled)"
    Check-RegistryValue $S "18.6.11.4" "Require elevation for network location"                  "$PW\Network Connections"                                "NC_StdDomainUserSetLocation" 1 "1 (Enabled)"

    # 18.6.14.1 Hardened UNC Paths
    $uncBase     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
    $uncKeyNL    = '\\*\NETLOGON'
    $uncKeySV    = '\\*\SYSVOL'
    $uncNetlogon = Get-RegValue $uncBase $uncKeyNL
    $uncSysvol   = Get-RegValue $uncBase $uncKeySV
    if (-not (Test-Path $uncBase)) {
        Record-Result $S "18.6.14.1" "Hardened UNC Paths (NETLOGON and SYSVOL)" "KEY PATH NOT FOUND" "RequireMutualAuthentication+Integrity+Privacy" "NOT_FOUND"
    } else {
        $uncPass = ($null -ne $uncNetlogon -and $uncNetlogon -match 'RequireMutualAuthentication' -and
                    $null -ne $uncSysvol   -and $uncSysvol   -match 'RequireMutualAuthentication')
        $uncDisp = "NETLOGON=$(if($uncNetlogon){'set'}else{'NOT SET'}), SYSVOL=$(if($uncSysvol){'set'}else{'NOT SET'})"
        Record-Result $S "18.6.14.1" "Hardened UNC Paths (NETLOGON and SYSVOL)" $uncDisp "RequireMutualAuthentication+Integrity+Privacy" $(if($uncPass){"PASS"}else{"FAIL"})
    }

    Check-RegistryValue $S "18.6.21.1" "Minimize simultaneous connections to Internet/Domain" "$PW\WcmSvc\GroupPolicy" "fMinimizeConnections" 3 "3 (Prevent Wi-Fi when on Ethernet)"

    # 18.7 Print Spooler / RPC
    $PPrinters = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $PPRPC     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
    $PPnP      = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

    Check-RegistryValue $S "18.7.2"  "Configure Redirection Guard (Enabled)"              $PPrinters "RedirectionguardPolicy"                     1 "1 (Redirection Guard Enabled)"
    Check-RegistryValue $S "18.7.3"  "RPC connection: Protocol = RPC over TCP"            $PPRPC     "RpcUseNamedPipeProtocol"                    0 "0 (RPC over TCP)"
    Check-RegistryValue $S "18.7.4"  "RPC connection: Authentication = Default"           $PPRPC     "RpcAuthentication"                          0 "0 (Default)"
    Check-RegistryValue $S "18.7.5"  "RPC listener: Protocols = RPC over TCP"             $PPRPC     "RpcProtocols"                               5 "5 (RPC over TCP)"
    Check-RegistryValue $S "18.7.6"  "RPC listener: Authentication = Negotiate or higher" $PPRPC     "ForceKerberosForRpc"                        0 "0 (Negotiate)"
    Check-RegistryValue $S "18.7.7"  "Configure RPC over TCP port = 0"                    $PPRPC     "RpcTcpPort"                                 0 "0"
    Check-RegistryValue $S "18.7.8"  "Limit print driver install to Administrators"        $PPrinters "RestrictDriverInstallationToAdministrators" 1 "1 (Enabled)"
    Check-RegistryValue $S "18.7.9"  "Manage Queue-specific files (Color profiles only)"  $PPrinters "CopyFilesPolicy"                            1 "1 (Limit to Color profiles)"
    Check-RegistryValue $S "18.7.10" "Point and Print: Warn on new connection install"     $PPnP      "NoWarningNoElevationOnInstall"              0 "0 (Show warning and elevation)"
    Check-RegistryValue $S "18.7.11" "Point and Print: Warn on driver update"              $PPnP      "UpdatePromptSettings"                       0 "0 (Show warning and elevation)"

    # 18.9 System
    Check-RegistryValue $S "18.9.3.1"  "Include command line in process events"          "$PW\Audit"                 "ProcessCreationIncludeCmdLine_Enabled" 1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.4.1"  "Encryption Oracle Remediation"                   "$PW\CredentialsDelegation" "AllowEncryptionOracle"                 2 "2 (Force Updated Clients)"
    Check-RegistryValue $S "18.9.4.2"  "Delegation of non-exportable credentials"        "$PW\CredentialsDelegation" "AllowProtectedCreds"                   1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.7.2"  "Prevent device metadata retrieval from Internet" "$PW\Device Metadata"       "PreventDeviceMetadataFromNetwork"      1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.13.1" "Boot-Start Driver Initialization Policy"         "$PW\System"                "DriverLoadPolicy"                      1 "1 (Good, unknown, bad but critical)"

    # 18.9.19.x Group Policy processing
    $GPReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    $GPSec = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
    Check-RegistryValue $S "18.9.19.2" "Registry policy: Apply during background processing" $GPReg "NoBackgroundPolicy" 0 "0 (Apply)"
    Check-RegistryValue $S "18.9.19.3" "Registry policy: Process even if GPO not changed"    $GPReg "NoGPOListChanges"   0 "0 (Always process)"
    Check-RegistryValue $S "18.9.19.4" "Security policy: Apply during background processing" $GPSec "NoBackgroundPolicy" 0 "0 (Apply)"
    Check-RegistryValue $S "18.9.19.5" "Security policy: Process even if GPO not changed"    $GPSec "NoGPOListChanges"   0 "0 (Always process)"
    Check-RegistryValue $S "18.9.19.6" "Continue experiences on this device (Disabled)"      "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"                      "EnableCdp"               0 "0 (Disabled)"
    Check-RegistryValue $S "18.9.19.7" "Turn off background refresh of Group Policy"         "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"       "DisableBkGndGroupPolicy" 0 "0 (Disabled)"

    Check-RegistryValue $S "18.9.20.1.1" "Turn off downloading print drivers over HTTP"          $PPrinters                                                           "DisableWebPnPDownload" 1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.20.1.5" "Turn off Internet download for Web publishing wizards" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices"         1 "1 (Enabled)"

    Check-RegistryValue $S "18.9.24.1" "Kernel DMA Protection: Block all external devices" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy" 0 "0 (Block All)"

    # 18.9.25 LAPS
    $LAPS = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    Check-RegistryValue $S "18.9.25.1" "LAPS: Configure password backup directory"             $LAPS "BackupDirectory"                1  "1 (Active Directory) or 2 (Azure AD)"
    Check-RegistryValue $S "18.9.25.2" "LAPS: Do not allow password expiration beyond policy"  $LAPS "PwdExpirationProtectionEnabled" 1  "1 (Enabled)"
    Check-RegistryValue $S "18.9.25.3" "LAPS: Enable password encryption"                      $LAPS "ADPasswordEncryptionEnabled"    1  "1 (Enabled)"
    Check-RegistryValue $S "18.9.25.4" "LAPS: Password Complexity (Large+Small+Num+Special)"   $LAPS "PasswordComplexity"             4  "4 (Large+small+numbers+special)"

    $lapsLenInfo = Get-RegInfo $LAPS "PasswordLength"
    if (-not $lapsLenInfo.KeyExists) {
        Record-Result $S "18.9.25.5" "LAPS: Password Length >= 15" "KEY PATH NOT FOUND" ">= 15 characters" "NOT_FOUND"
    } elseif ($null -eq $lapsLenInfo.Value) {
        Record-Result $S "18.9.25.5" "LAPS: Password Length >= 15" "VALUE NOT CONFIGURED" ">= 15 characters" "NOT_CONFIGURED"
    } else {
        Record-Result $S "18.9.25.5" "LAPS: Password Length >= 15" "$($lapsLenInfo.Value) characters" ">= 15 characters" $(if([int]$lapsLenInfo.Value -ge 15){"PASS"}else{"FAIL"})
    }

    $lapsAgeInfo = Get-RegInfo $LAPS "PasswordAgeDays"
    if (-not $lapsAgeInfo.KeyExists) {
        Record-Result $S "18.9.25.6" "LAPS: Password Age <= 30 days" "KEY PATH NOT FOUND" "<= 30 days" "NOT_FOUND"
    } elseif ($null -eq $lapsAgeInfo.Value) {
        Record-Result $S "18.9.25.6" "LAPS: Password Age <= 30 days" "VALUE NOT CONFIGURED" "<= 30 days" "NOT_CONFIGURED"
    } else {
        $la = [int]$lapsAgeInfo.Value
        Record-Result $S "18.9.25.6" "LAPS: Password Age <= 30 days" "$la days" "<= 30 days" $(if($la -le 30 -and $la -gt 0){"PASS"}else{"FAIL"})
    }

    $lapsGraceInfo = Get-RegInfo $LAPS "PostAuthenticationResetDelay"
    if (-not $lapsGraceInfo.KeyExists) {
        Record-Result $S "18.9.25.7" "LAPS: Post-auth grace period 1-8 hours" "KEY PATH NOT FOUND" "1 to 8 hours" "NOT_FOUND"
    } elseif ($null -eq $lapsGraceInfo.Value) {
        Record-Result $S "18.9.25.7" "LAPS: Post-auth grace period 1-8 hours" "VALUE NOT CONFIGURED" "1 to 8 hours" "NOT_CONFIGURED"
    } else {
        $lg = [int]$lapsGraceInfo.Value
        Record-Result $S "18.9.25.7" "LAPS: Post-auth grace period 1-8 hours" "$lg hours" "1 to 8 hours" $(if($lg -ge 1 -and $lg -le 8){"PASS"}else{"FAIL"})
    }

    Check-RegistryValue $S "18.9.25.8" "LAPS: Post-auth actions = Reset password and logoff" $LAPS "PostAuthenticationActions" 3 ">= 3 (Reset password and logoff)"

    # 18.9.28 Logon
    Check-RegistryValue $S "18.9.28.1" "Block user from showing account details on sign-in" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin" 1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.28.2" "Do not display network selection UI"                "$PW\System" "DontDisplayNetworkSelectionUI"     1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.28.3" "No enumerate connected users on domain"             "$PW\System" "DontEnumerateConnectedUsers"       1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.28.4" "Enumerate local users (Disable)"                    "$PW\System" "EnumerateLocalUsers"               0 "0 (Disabled)"
    Check-RegistryValue $S "18.9.28.5" "Turn off app notifications on lock screen"          "$PW\System" "DisableLockScreenAppNotifications" 1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.28.6" "Turn off picture password sign-in"                  "$PW\System" "BlockPicturePassword"              1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.28.7" "Turn on convenience PIN sign-in (Disable)"          "$PW\System" "AllowDomainPINLogon"               0 "0 (Disabled)"

    # 18.9.33.6 Power
    $PowerGUID = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    Check-RegistryValue $S "18.9.33.6.3" "Require password when waking (on battery)" $PowerGUID "DCSettingIndex" 1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.33.6.4" "Require password when waking (plugged in)" $PowerGUID "ACSettingIndex" 1 "1 (Enabled)"

    # 18.9.35 Remote Assistance
    Check-RegistryValue $S "18.9.35.1" "Offer Remote Assistance (Disable)"     "$PW\RemoteAssistance" "fAllowToGetHelp" 0 "0 (Disabled)"
    Check-RegistryValue $S "18.9.35.2" "Solicited Remote Assistance (Disable)" "$PW\RemoteAssistance" "fAllowToGetHelp" 0 "0 (Disabled)"

    Check-RegistryValue $S "18.9.36.1" "Enable RPC Endpoint Mapper Client Authentication" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution" 1 "1 (Enabled)"

    Check-RegistryValue $S "18.9.51.1.1" "Enable Windows NTP Client"  "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" "Enabled" 1 "1 (Enabled)"
    Check-RegistryValue $S "18.9.51.1.2" "Disable Windows NTP Server" "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" "Enabled" 0 "0 (Disabled)"

    # 18.10 Windows Components
    Check-RegistryValue $S "18.10.5.1"   "Allow Microsoft accounts to be optional"           $PSys                           "MSAOptional"                         1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.7.1"   "Disallow Autoplay for non-volume devices"           "$PW\Explorer"                  "NoAutoplayfornonVolume"              1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.7.2"   "AutoRun default: Do not execute autorun commands"   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"          1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.7.3"   "Turn off Autoplay on all drives"                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 "255 (All drives)"
    Check-RegistryValue $S "18.10.8.1.1" "Configure enhanced anti-spoofing"                   "$PW\Biometrics\FacialFeatures" "EnhancedAntiSpoofing"             1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.12.1"  "Turn off cloud consumer account state"              "$PW\CloudContent"              "DisableConsumerAccountStateContent"  1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.12.2"  "Turn off Microsoft consumer experiences"            "$PW\CloudContent"              "DisableWindowsConsumerFeatures"      1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.13.1"  "Require pin for pairing"                            "$PW\Connect"                   "RequirePinForPairing"                1 ">= 1"
    Check-RegistryValue $S "18.10.14.1"  "Do not display password reveal button"              "$PW\CredUI"                    "DisablePasswordReveal"               1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.14.2"  "Enumerate admin accounts on elevation (Disable)"    "$PW\CredUI"                    "EnumerateAdministrators"             0 "0 (Disabled)"

    # Data Collection
    $DC = "$PW\DataCollection"
    Check-RegistryValue $S "18.10.15.1" "Allow Diagnostic Data (Security only)"    $DC "AllowTelemetry"                 0 "0 (Security/Off)"
    Check-RegistryValue $S "18.10.15.3" "Disable OneSettings Downloads"            $DC "DisableOneSettingsDownloads"    1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.15.4" "Do not show feedback notifications"       $DC "DoNotShowFeedbackNotifications" 1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.15.5" "Enable OneSettings Auditing"              $DC "EnableOneSettingsAuditing"      1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.15.6" "Limit Diagnostic Log Collection"          $DC "LimitDiagnosticLogCollection"   1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.15.7" "Limit Dump Collection"                    $DC "LimitDumpCollection"            1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.15.8" "Disable Insider Preview Builds"           "$PW\PreviewBuilds" "AllowBuildPreview" 0 "0 (Disabled)"

    # App Installer
    $AI = "$PW\AppInstaller"
    Check-RegistryValue $S "18.10.17.1" "Disable App Installer"                   $AI "EnableAppInstaller"                    0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.17.2" "Disable App Installer Experimental"      $AI "EnableAppInstallerExperimentalFeatures" 0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.17.3" "Disable App Installer Hash Override"     $AI "EnableAppInstallerHashOverride"         0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.17.4" "Disable App Installer ms-appinstaller"   $AI "EnableMSAppInstallerProtocol"           0 "0 (Disabled)"

    # Event Log Sizes
    $EL = "$PW\EventLog"
    Check-RegistryValue $S "18.10.25.1.1" "Application log: Retention" "$EL\Application" "Retention" 0 "0 (Overwrite as needed)" "GTE"
    Check-RegistryValue $S "18.10.25.1.2" "Application log: Max size"  "$EL\Application" "MaxSize"   32768  ">= 32768 KB"  "GTE"
    Check-RegistryValue $S "18.10.25.2.1" "Security log: Retention"    "$EL\Security"    "Retention" 0 "0 (Overwrite as needed)" "GTE"
    Check-RegistryValue $S "18.10.25.2.2" "Security log: Max size"     "$EL\Security"    "MaxSize"   196608 ">= 196608 KB" "GTE"
    Check-RegistryValue $S "18.10.25.3.1" "Setup log: Retention"       "$EL\Setup"       "Retention" 0 "0 (Overwrite as needed)" "GTE"
    Check-RegistryValue $S "18.10.25.3.2" "Setup log: Max size"        "$EL\Setup"       "MaxSize"   32768  ">= 32768 KB"  "GTE"
    Check-RegistryValue $S "18.10.25.4.1" "System log: Retention"      "$EL\System"      "Retention" 0 "0 (Overwrite as needed)" "GTE"
    Check-RegistryValue $S "18.10.25.4.2" "System log: Max size"       "$EL\System"      "MaxSize"   32768  ">= 32768 KB"  "GTE"

    Check-RegistryValue $S "18.10.41.1" "Block consumer Microsoft account user authentication" "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth" 1 "1 (Enabled)"

    # Remote Desktop Services
    Check-RegistryValue $S "18.10.56.2.2"    "RDP: Do not allow password saving"     "$PTrm\Client"              "DisablePasswordSaving"  1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.56.3.3.2"  "RDP: Do not allow drive redirection"   "$PTrm\WinStations\RDP-Tcp" "fDisableCdm"            1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.56.3.9.1"  "RDP: Always prompt for password"       $PTrm                       "fPromptForPassword"     1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.56.3.9.2"  "RDP: Require secure RPC communication" $PTrm                       "fEncryptRPCTraffic"     1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.56.3.9.3"  "RDP: Require SSL security layer"       $PTrm                       "SecurityLayer"          2 "2 (SSL)"
    Check-RegistryValue $S "18.10.56.3.9.4"  "RDP: Require NLA"                      $PTrm                       "UserAuthentication"     1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.56.3.9.5"  "RDP: Set encryption level to High"     $PTrm                       "MinEncryptionLevel"     3 "3 (High)"
    Check-RegistryValue $S "18.10.56.3.11.1" "RDS: Delete temp folders upon exit"    $PTrm                       "DeleteTempDirsOnExit"   1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.56.3.11.2" "RDS: Use temp folders per session"     $PTrm                       "PerSessionTempDir"      1 "1 (Enabled)"

    Check-RegistryValue $S "18.10.57.1"   "Prevent downloading of enclosures (RSS)"      "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload"            1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.58.3"   "Allow indexing of encrypted files (Disabled)" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"  "AllowIndexingEncryptedStoresOrItems" 0 "0 (Disabled)"
    Check-PolicyRegistryValue $S "18.10.75.2.1" "Configure Windows Defender SmartScreen"       "$PW\System"                                                "EnableSmartScreen"                   1 "1 (Enabled)"

    Check-RegistryValue $S "18.10.80.1" "Disable user control over installs"             "$PW\Installer" "EnableUserControl"            0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.80.2" "Disable always install with elevated privs"      "$PW\Installer" "AlwaysInstallElevated"        0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.81.1" "Disable auto sign-in after restart"              $PSys           "DisableAutomaticRestartSignOn" 1 "1 (Enabled)"

    # WinRM
    $WRMc = "$PW\WindowsRemoteManagement\Client"
    $WRMs = "$PW\WindowsRemoteManagement\Service"
    Check-RegistryValue $S "18.10.88.1.1" "WinRM Client: Disable Basic Auth"    $WRMc "AllowBasic"       0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.88.1.2" "WinRM Client: Disable unencrypted"   $WRMc "AllowUnencrypted" 0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.88.1.3" "WinRM Client: Disallow Digest auth"  $WRMc "DisallowDigest"   1 "1 (Enabled)"
    Check-RegistryValue $S "18.10.88.2.1" "WinRM Service: Disable Basic Auth"   $WRMs "AllowBasic"       0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.88.2.3" "WinRM Service: Disable unencrypted"  $WRMs "AllowUnencrypted" 0 "0 (Disabled)"
    Check-RegistryValue $S "18.10.88.2.4" "WinRM Service: Disallow RunAs creds" $WRMs "DisableRunAs"     1 "1 (Enabled)"

    # Windows Update
    $WU_AU = "$PW\WindowsUpdate\AU"
    $WU    = "$PW\WindowsUpdate"
    Check-PolicyRegistryValue $S "18.10.92.1.1" "No auto-restart with logged-on users" $WU_AU "NoAutoRebootWithLoggedOnUsers" 0
    Check-PolicyRegistryValue $S "18.10.92.2.1" "Configure Automatic Updates"          $WU_AU "NoAutoUpdate" 0
    Check-PolicyRegistryValue $S "18.10.92.2.2" "Scheduled install day"                $WU_AU "ScheduledInstallDay" 0
    Check-PolicyRegistryValue $S "18.10.92.4.1" "Manage preview builds"                $WU_AU "ManagePreviewBuilds" 0

    # Feature/Quality update deferral – multi-value check
    $fuStatusInfo = Get-RegInfo $WU "DeferFeatureUpdates"
    $fuDaysInfo   = Get-RegInfo $WU "DeferFeatureUpdatesPeriodInDays"

    if (!(Test-Path $WU)) {
        Record-Result $S "18.10.92.4.2" "Defer Feature Updates >= 180 days" "POLICY NOT CONFIGURED" "Enabled=1, Days >= 180" "NOT_CONFIGURED"
    }
    elseif ($null -eq $fuStatusInfo.Value -or $null -eq $fuDaysInfo.Value) {
        Record-Result $S "18.10.92.4.2" "Defer Feature Updates >= 180 days" "VALUE NOT CONFIGURED" "Enabled=1, Days >= 180" "NOT_CONFIGURED"
    }
    else {
        $fuPass = ($fuStatusInfo.Value -eq 1 -and [int]$fuDaysInfo.Value -ge 180)

        Record-Result $S "18.10.92.4.2" "Defer Feature Updates >= 180 days" `
        "Enabled=$($fuStatusInfo.Value), Days=$($fuDaysInfo.Value)" `
        "Enabled=1, Days >= 180" `
        $(if($fuPass){"PASS"}else{"FAIL"})
    }

    $quStatusInfo = Get-RegInfo $WU "DeferQualityUpdates"
    $quDaysInfo   = Get-RegInfo $WU "DeferQualityUpdatesPeriodInDays"
    if (-not $quStatusInfo.KeyExists) {
        Record-Result $S "18.10.92.4.3" "Defer Quality Updates = 0 days" "KEY PATH NOT FOUND" "Enabled=1, Days=0" "NOT_FOUND"
    } elseif ($null -eq $quStatusInfo.Value -or $null -eq $quDaysInfo.Value) {
        Record-Result $S "18.10.92.4.3" "Defer Quality Updates = 0 days" "VALUE NOT CONFIGURED" "Enabled=1, Days=0" "NOT_CONFIGURED"
    } else {
        $quPass = ($quStatusInfo.Value -eq 1 -and [int]$quDaysInfo.Value -eq 0)
        Record-Result $S "18.10.92.4.3" "Defer Quality Updates = 0 days" "Enabled=$($quStatusInfo.Value), Days=$($quDaysInfo.Value)" "Enabled=1, Days=0" $(if($quPass){"PASS"}else{"FAIL"})
    }
}

# ============================================================
# HTML REPORT GENERATOR  (5 statuses)
# ============================================================

Function Export-HtmlReport {
    $total    = $script:AuditResults.Count
    $passed   = ($script:AuditResults | Where-Object { $_.Status -eq 'PASS' }).Count
    $failed   = ($script:AuditResults | Where-Object { $_.Status -eq 'FAIL' }).Count
    $notconf  = ($script:AuditResults | Where-Object { $_.Status -eq 'NOT_CONFIGURED' }).Count
    $notfound = ($script:AuditResults | Where-Object { $_.Status -eq 'NOT_FOUND' }).Count
    $manual   = ($script:AuditResults | Where-Object { $_.Status -eq 'MANUAL' }).Count
    $score    = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }
    $barColor = if ($score -ge 80) { "#27ae60" } elseif ($score -ge 50) { "#f39c12" } else { "#e74c3c" }

    $sections    = $script:AuditResults | Group-Object -Property Section | Sort-Object Name
    $sectionHtml = ""

    foreach ($group in $sections) {
        $secPass  = ($group.Group | Where-Object { $_.Status -eq 'PASS' }).Count
        $secTotal = $group.Group.Count
        $secScore = if ($secTotal -gt 0) { [math]::Round(($secPass / $secTotal) * 100, 0) } else { 0 }
        $sColor   = if ($secScore -ge 80) { "#27ae60" } elseif ($secScore -ge 50) { "#f39c12" } else { "#e74c3c" }

        $sectionHtml += "<div class='section'>"
        $sectionHtml += "<div class='section-header'>"
        $sectionHtml += "<span class='section-title'>$($group.Name)</span>"
        $sectionHtml += "<span class='section-stats'>$secPass / $secTotal Passed &nbsp;<span class='sec-badge' style='background:$sColor'>$secScore%</span></span>"
        $sectionHtml += "</div>"
        $sectionHtml += "<table><thead><tr><th style='width:90px'>CIS ID</th><th>Check Title</th><th style='width:130px;text-align:center'>Status</th><th>Current Value on Server</th><th>CIS Required Value</th></tr></thead><tbody>"

        foreach ($row in ($group.Group | Sort-Object ID)) {
            $statusClass = switch ($row.Status) {
                "PASS"           { "status-pass" }
                "FAIL"           { "status-fail" }
                "NOT_CONFIGURED" { "status-notconf" }
                "NOT_FOUND"      { "status-notfound" }
                default          { "status-manual" }
            }
            $statusLabel = switch ($row.Status) {
                "PASS"           { "&#10003; PASS" }
                "FAIL"           { "&#10007; FAIL" }
                "NOT_CONFIGURED" { "&#9675; NOT CONFIGURED" }
                "NOT_FOUND"      { "&#10006; NOT FOUND" }
                default          { "&#9888; MANUAL" }
            }
            $rowClass = switch ($row.Status) {
                "PASS"           { "row-pass" }
                "FAIL"           { "row-fail" }
                "NOT_CONFIGURED" { "row-notconf" }
                "NOT_FOUND"      { "row-notfound" }
                default          { "row-manual" }
            }
            $sectionHtml += "<tr class='$rowClass'>"
            $sectionHtml += "<td class='cis-id'>$($row.ID)</td>"
            $sectionHtml += "<td>$($row.Title)</td>"
            $sectionHtml += "<td class='status-cell'><span class='$statusClass'>$statusLabel</span></td>"
            $sectionHtml += "<td class='value-cell'>$($row.CurrentValue)</td>"
            $sectionHtml += "<td class='value-cell expected'>$($row.ExpectedValue)</td>"
            $sectionHtml += "</tr>"
        }
        $sectionHtml += "</tbody></table></div>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CIS Benchmark Audit Report - $($env:COMPUTERNAME)</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap');
  :root {
    --bg:#0f1117; --surface:#1a1d2e; --surface2:#232640; --border:#2e3250;
    --accent:#4f8ef7;
    --pass:#1a3a2a; --pass-text:#4ade80; --pass-border:#166534;
    --fail:#3a1a1a; --fail-text:#f87171; --fail-border:#991b1b;
    --notconf:#1e2a3a; --notconf-text:#60a5fa; --notconf-border:#1d4ed8;
    --notfound:#2a1e3a; --notfound-text:#c084fc; --notfound-border:#7c3aed;
    --manual:#2a2a1a; --manual-text:#fbbf24; --manual-border:#92400e;
    --text:#e2e8f0; --text-muted:#8892a4;
    --mono:'IBM Plex Mono',monospace; --sans:'IBM Plex Sans',sans-serif;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:var(--sans); background:var(--bg); color:var(--text); line-height:1.5; }
  .banner { background:linear-gradient(135deg,#1a1d2e,#0f1117); border-bottom:1px solid var(--border); padding:32px 40px 28px; }
  .banner-top { display:flex; align-items:flex-start; justify-content:space-between; gap:20px; flex-wrap:wrap; }
  .banner-label { font-family:var(--mono); font-size:11px; color:var(--accent); letter-spacing:.15em; text-transform:uppercase; margin-bottom:6px; }
  .banner h1 { font-size:26px; font-weight:700; color:#fff; letter-spacing:-.02em; }
  .banner-meta { margin-top:10px; display:flex; gap:24px; flex-wrap:wrap; }
  .meta-item { font-size:12px; color:var(--text-muted); }
  .meta-item strong { color:var(--text); font-weight:500; }
  .score-card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:18px 24px; min-width:200px; text-align:center; }
  .score-label { font-family:var(--mono); font-size:10px; color:var(--text-muted); letter-spacing:.1em; text-transform:uppercase; margin-bottom:6px; }
  .score-value { font-family:var(--mono); font-size:42px; font-weight:600; line-height:1; color:$barColor; }
  .score-sub { font-size:11px; color:var(--text-muted); margin-top:4px; }
  .stats-row { display:flex; gap:12px; padding:20px 40px; background:var(--surface); border-bottom:1px solid var(--border); flex-wrap:wrap; }
  .stat-box { flex:1; min-width:100px; background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:12px 14px; }
  .stat-num { font-family:var(--mono); font-size:22px; font-weight:600; }
  .stat-name { font-size:10px; color:var(--text-muted); text-transform:uppercase; letter-spacing:.05em; margin-top:2px; }
  .stat-total    .stat-num { color:var(--accent); }
  .stat-pass     .stat-num { color:var(--pass-text); }
  .stat-fail     .stat-num { color:var(--fail-text); }
  .stat-notconf  .stat-num { color:var(--notconf-text); }
  .stat-notfound .stat-num { color:var(--notfound-text); }
  .stat-manual   .stat-num { color:var(--manual-text); }
  .legend { padding:12px 40px 0; background:var(--surface); display:flex; gap:16px; flex-wrap:wrap; }
  .legend-item { display:flex; align-items:center; gap:6px; font-size:11px; color:var(--text-muted); }
  .legend-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
  .progress-wrap { padding:12px 40px 20px; background:var(--surface); }
  .progress-bar-bg { height:6px; background:var(--border); border-radius:3px; overflow:hidden; }
  .progress-bar-fill { height:100%; width:$($score)%; background:$barColor; border-radius:3px; }
  .content { padding:24px 40px 40px; max-width:1500px; margin:0 auto; }
  .section { margin-bottom:28px; background:var(--surface); border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  .section-header { display:flex; align-items:center; justify-content:space-between; padding:14px 20px; background:var(--surface2); border-bottom:1px solid var(--border); }
  .section-title { font-size:14px; font-weight:600; color:#fff; }
  .section-stats { font-size:12px; color:var(--text-muted); display:flex; align-items:center; gap:10px; }
  .sec-badge { display:inline-block; padding:2px 8px; border-radius:20px; font-family:var(--mono); font-size:11px; font-weight:600; color:#fff; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  thead tr { background:rgba(255,255,255,.03); border-bottom:1px solid var(--border); }
  th { padding:10px 14px; text-align:left; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.07em; color:var(--text-muted); }
  tbody tr { border-bottom:1px solid rgba(255,255,255,.04); }
  tbody tr:last-child { border-bottom:none; }
  tbody tr:hover { background:rgba(255,255,255,.02); }
  .row-pass     { border-left:3px solid #166534; }
  .row-fail     { border-left:3px solid #991b1b; }
  .row-notconf  { border-left:3px solid #1d4ed8; }
  .row-notfound { border-left:3px solid #7c3aed; }
  .row-manual   { border-left:3px solid #92400e; }
  td { padding:9px 14px; vertical-align:middle; }
  .cis-id { font-family:var(--mono); font-size:12px; color:var(--accent); white-space:nowrap; }
  .status-cell { text-align:center; }
  .status-pass     { display:inline-block; padding:3px 8px; background:var(--pass);     color:var(--pass-text);     border:1px solid var(--pass-border);     border-radius:4px; font-family:var(--mono); font-size:10px; font-weight:600; white-space:nowrap; }
  .status-fail     { display:inline-block; padding:3px 8px; background:var(--fail);     color:var(--fail-text);     border:1px solid var(--fail-border);     border-radius:4px; font-family:var(--mono); font-size:10px; font-weight:600; white-space:nowrap; }
  .status-notconf  { display:inline-block; padding:3px 8px; background:var(--notconf);  color:var(--notconf-text);  border:1px solid var(--notconf-border);  border-radius:4px; font-family:var(--mono); font-size:10px; font-weight:600; white-space:nowrap; }
  .status-notfound { display:inline-block; padding:3px 8px; background:var(--notfound); color:var(--notfound-text); border:1px solid var(--notfound-border); border-radius:4px; font-family:var(--mono); font-size:10px; font-weight:600; white-space:nowrap; }
  .status-manual   { display:inline-block; padding:3px 8px; background:var(--manual);   color:var(--manual-text);   border:1px solid var(--manual-border);   border-radius:4px; font-family:var(--mono); font-size:10px; font-weight:600; white-space:nowrap; }
  .value-cell { font-family:var(--mono); font-size:11px; color:var(--text-muted); max-width:280px; word-break:break-all; }
  .value-cell.expected { color:#94a3b8; }
  .report-footer { text-align:center; padding:24px 40px; font-size:11px; color:var(--text-muted); border-top:1px solid var(--border); font-family:var(--mono); }
</style>
</head>
<body>
<div class="banner">
  <div class="banner-top">
    <div>
      <div class="banner-label">CIS Benchmark Audit Report &mdash; Enhanced (v2)</div>
      <h1>Windows Server 2019 &mdash; Security Compliance</h1>
      <div class="banner-meta">
        <div class="meta-item"><strong>Host:</strong> $($env:COMPUTERNAME)</div>
        <div class="meta-item"><strong>Domain:</strong> $($env:USERDNSDOMAIN)</div>
        <div class="meta-item"><strong>Date:</strong> $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</div>
        <div class="meta-item"><strong>Benchmark:</strong> CIS Microsoft Windows Server 2019 v3.0</div>
      </div>
    </div>
    <div class="score-card">
      <div class="score-label">Compliance Score</div>
      <div class="score-value">$($score)%</div>
      <div class="score-sub">$passed of $total checks passed</div>
    </div>
  </div>
</div>
<div class="stats-row">
  <div class="stat-box stat-total">   <div class="stat-num">$total</div>   <div class="stat-name">Total Checks</div></div>
  <div class="stat-box stat-pass">    <div class="stat-num">$passed</div>  <div class="stat-name">&#10003; Pass</div></div>
  <div class="stat-box stat-fail">    <div class="stat-num">$failed</div>  <div class="stat-name">&#10007; Fail</div></div>
  <div class="stat-box stat-notconf"> <div class="stat-num">$notconf</div> <div class="stat-name">&#9675; Not Configured</div></div>
  <div class="stat-box stat-notfound"><div class="stat-num">$notfound</div><div class="stat-name">&#10006; Not Found</div></div>
  <div class="stat-box stat-manual">  <div class="stat-num">$manual</div>  <div class="stat-name">&#9888; Manual</div></div>
</div>
<div class="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#4ade80"></div> <strong>PASS</strong> &ndash; Policy set and matches CIS requirement</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f87171"></div> <strong>FAIL</strong> &ndash; Policy set but does NOT match CIS requirement</div>
  <div class="legend-item"><div class="legend-dot" style="background:#60a5fa"></div> <strong>NOT CONFIGURED</strong> &ndash; Registry key exists but this value is absent (Windows default applies)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#c084fc"></div> <strong>NOT FOUND</strong> &ndash; Registry key path does not exist on this server (feature not installed / never configured)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#fbbf24"></div> <strong>MANUAL</strong> &ndash; Cannot be checked programmatically</div>
</div>
<div class="progress-wrap">
  <div class="progress-bar-bg"><div class="progress-bar-fill"></div></div>
</div>
<div class="content">
$sectionHtml
</div>
<div class="report-footer">
  CIS Audit Script v2 (Enhanced) &nbsp;|&nbsp; $($env:COMPUTERNAME) &nbsp;|&nbsp; $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
</div>
</body>
</html>
"@

    $html | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Host "  [HTML] Report saved: $ReportFile" -ForegroundColor Green
}

# ============================================================
# CSV EXPORT
# ============================================================

Function Export-CsvReport {
    $script:AuditResults | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
    Write-Host "  [CSV]  Report saved: $CsvFile" -ForegroundColor Green
}

# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  CIS BENCHMARK AUDIT v2 - AUDIT ONLY MODE" -ForegroundColor Cyan
Write-Host "  No changes will be made to this system"    -ForegroundColor Yellow
Write-Host "  Statuses: PASS | FAIL | NOT_CONFIGURED | NOT_FOUND | MANUAL" -ForegroundColor White
Write-Host "============================================`n" -ForegroundColor Cyan

Write-Host "[STEP 1] Exporting security policy..." -ForegroundColor Cyan
secedit /export /cfg $SeceditFile /quiet
if (-not (Test-Path $SeceditFile)) {
    Write-Error "FATAL: secedit export failed. Run as Administrator."
    exit 1
}

Write-Host "[STEP 2] Running audit checks..." -ForegroundColor Cyan
Audit-AccountPolicies
Audit-UserRights
Audit-SecurityOptions
Audit-Firewall
Audit-AdvancedAudit
Audit-AdminTemplates

Write-Host "[STEP 3] Generating reports..." -ForegroundColor Cyan
Export-HtmlReport
Export-CsvReport

Remove-Item $SeceditFile -Force -ErrorAction SilentlyContinue

$total    = $script:AuditResults.Count
$passed   = ($script:AuditResults | Where-Object { $_.Status -eq 'PASS' }).Count
$failed   = ($script:AuditResults | Where-Object { $_.Status -eq 'FAIL' }).Count
$notconf  = ($script:AuditResults | Where-Object { $_.Status -eq 'NOT_CONFIGURED' }).Count
$notfound = ($script:AuditResults | Where-Object { $_.Status -eq 'NOT_FOUND' }).Count
$manual   = ($script:AuditResults | Where-Object { $_.Status -eq 'MANUAL' }).Count
$score    = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE" -ForegroundColor Green
Write-Host "  Total          : $total"    -ForegroundColor White
Write-Host "  PASS           : $passed"   -ForegroundColor Green
Write-Host "  FAIL           : $failed"   -ForegroundColor Red
Write-Host "  NOT_CONFIGURED : $notconf"  -ForegroundColor Blue
Write-Host "  NOT_FOUND      : $notfound" -ForegroundColor Magenta
Write-Host "  MANUAL         : $manual"   -ForegroundColor Yellow
Write-Host "  Score (PASS%)  : $score%"   -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  HTML Report : $ReportFile" -ForegroundColor Cyan
Write-Host "  CSV Report  : $CsvFile"    -ForegroundColor Cyan
Write-Host ""
