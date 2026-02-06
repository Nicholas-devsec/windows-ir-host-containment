<#
Windows IR Containment Script (Host-Level Only)

PURPOSE
-------
Performs host-level incident response containment actions for a specified user.
Designed for use during active investigations to immediately reduce attacker access
while preserving a clear audit trail.

EXECUTION REQUIREMENTS
----------------------
- Must be run in an elevated PowerShell session (Administrator)
- Local execution only (no remote targeting)
- Active Directory actions require the AD PowerShell module

BASIC USAGE
-----------
.\Invoke-IRContainment.ps1 -Username <username>

EXAMPLES
--------
Dry run (no changes made):
.\Invoke-IRContainment.ps1 -Username nicholas -WhatIfMode

Run with interactive confirmation:
.\Invoke-IRContainment.ps1 -Username nicholas

Run without confirmation (use with caution):
.\Invoke-IRContainment.ps1 -Username nicholas -Force

Run and reboot host after containment:
.\Invoke-IRContainment.ps1 -Username nicholas -Force -Reboot

SAFETY NOTES
------------
- Disables the specified AD account (if AD module is available)
- Resets the account password with a random high-entropy value (not disclosed)
- Terminates active logon sessions and user-owned processes
- Purges local Kerberos tickets
- Actions are logged to C:\IR\ with timestamps 
- Results are exported to CSV for review

WARNING
-------
This script performs high impact containment actions.
Review things properly before execution
Use -WhatIfMode to validate behavior before live containment.

#>


[CmdletBinding(ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [string]$Username,

    [switch]$Reboot,
    [switch]$Force,
    [switch]$WhatIfMode
)

#Setup 
$BaseDir = "C:\IR"
if (!(Test-Path $BaseDir)) {
    New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
}

$LogFile = Join-Path $BaseDir ("ir_actions_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
$Results = New-Object System.Collections.Generic.List[object]

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    "$ts | $Level | OP=$env:USERNAME | HOST=$env:COMPUTERNAME | $Message" |
        Tee-Object -FilePath $LogFile -Append | Out-Null
}

function Add-Result {
    param(
        [string]$Action,
        [string]$Status,
        [string]$Details = "",
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $obj = [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Operator     = $env:USERNAME
        Host         = $env:COMPUTERNAME
        Action       = $Action
        Status       = $Status
        Details      = $Details
        ErrorType    = $ErrorRecord.Exception.GetType().FullName
        ErrorMessage = $ErrorRecord.Exception.Message
        ErrorId      = $ErrorRecord.FullyQualifiedErrorId
    }

    $Results.Add($obj) | Out-Null
}

function Invoke-Step {
    param(
        [string]$Action,
        [scriptblock]$Body
    )
    try {
        & $Body
    } catch {
        Add-Result -Action $Action -Status "Failed" -Details "Exception thrown" -ErrorRecord $_
        Write-Log -Level "ERROR" -Message "$Action failed: $($_.Exception.Message)"
    }
}

Write-Log -Level "INFO" -Message "IR containment started for user: $Username"

#Safety Check 
if (-not $Force) {
    Write-Host "Target user: $Username" -ForegroundColor Yellow
    Write-Host "Target host: $env:COMPUTERNAME" -ForegroundColor Yellow
    $confirm = Read-Host "Type YES to continue"
    if ($confirm -ne "YES") {
        Write-Log -Level "WARN" -Message "Operator aborted execution"
        return
    }
}

# AD Module 
$ADLoaded = $false
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ADLoaded = $true
} catch {
    Write-Log -Level "ERROR" -Message "ActiveDirectory module not available"
}

#Disable AD Account 
Invoke-Step -Action "DisableADAccount" -Body {
    if (-not $ADLoaded) {
        Add-Result -Action "DisableADAccount" -Status "Skipped" -Details "AD module unavailable"
        return
    }

    $user = Get-ADUser -Identity $Username -Properties Enabled,whenChanged -ErrorAction Stop

    if (-not $user.Enabled) {
        Add-Result -Action "DisableADAccount" -Status "AlreadyContained" `
            -Details "Account already disabled (whenChanged=$($user.whenChanged))"
        return
    }

    if ($WhatIfMode) {
        Add-Result -Action "DisableADAccount" -Status "Skipped" -Details "WhatIfMode"
        return
    }

    Disable-ADAccount -Identity $Username -ErrorAction Stop
    $verify = Get-ADUser -Identity $Username -Properties Enabled,whenChanged

    Add-Result -Action "DisableADAccount" -Status "Success" `
        -Details "Account disabled (whenChanged=$($verify.whenChanged))"
}

# Reset Password 
Invoke-Step -Action "ResetADPassword" -Body {
    if (-not $ADLoaded) {
        Add-Result -Action "ResetADPassword" -Status "Skipped" -Details "AD module unavailable"
        return
    }

    if ($WhatIfMode) {
        Add-Result -Action "ResetADPassword" -Status "Skipped" -Details "WhatIfMode"
        return
    }

    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $pw = [Convert]::ToBase64String($bytes)

    Set-ADAccountPassword -Identity $Username -Reset `
        -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop

    Set-ADUser -Identity $Username -ChangePasswordAtLogon $true -ErrorAction Stop

    Add-Result -Action "ResetADPassword" -Status "Success" `
        -Details "Password reset completed (not disclosed)"
}

#Enumerate Sessions 
Invoke-Step -Action "EnumerateSessions" -Body {
    $sessions = quser 2>$null | Select-Object -Skip 1 |
        Where-Object { $_ -match "^\s*$Username\s" }

    if (-not $sessions) {
        Add-Result -Action "EnumerateSessions" -Status "NotFound" -Details "No active sessions"
        return
    }

    Add-Result -Action "EnumerateSessions" -Status "Success" `
        -Details ($sessions -join " | ")
}

#  3.4 Terminate Sessions 
Invoke-Step -Action "TerminateSessions" -Body {
    $sessions = quser 2>$null | Select-Object -Skip 1 |
        Where-Object { $_ -match "^\s*$Username\s" }

    if (-not $sessions) {
        Add-Result -Action "TerminateSessions" -Status "NotFound" -Details "No sessions to terminate"
        return
    }

    if ($WhatIfMode) {
        Add-Result -Action "TerminateSessions" -Status "Skipped" -Details "WhatIfMode"
        return
    }

    foreach ($line in $sessions) {
        $id = ($line -split '\s+')[2]
        logoff $id
        Add-Result -Action "TerminateSessions" -Status "Success" -Details "Logged off session ID $id"
    }
}

#Enumerate User Processes 
Invoke-Step -Action "EnumerateUserProcesses" -Body {
    $procs = Get-CimInstance Win32_Process | ForEach-Object {
        try {
            $owner = $_ | Invoke-CimMethod -MethodName GetOwner
            if ($owner.User -eq $Username) {
                [pscustomobject]@{
                    PID = $_.ProcessId
                    Name = $_.Name
                    ParentPID = $_.ParentProcessId
                    CommandLine = $_.CommandLine
                }
            }
        } catch {}
    }

    if (-not $procs) {
        Add-Result -Action "EnumerateUserProcesses" -Status "NotFound" -Details "No user-owned processes"
        return
    }

    # Show first 10 processes can be tweaked as needed
    Add-Result -Action "EnumerateUserProcesses" -Status "Success" `
        -Details (($procs | Select-Object -First 10 | ForEach-Object {
            "PID=$($_.PID) NAME=$($_.Name)"
        }) -join "; ")
}

#3.6 Terminate User Processes 
Invoke-Step -Action "TerminateUserProcesses" -Body {
    $procs = Get-CimInstance Win32_Process | ForEach-Object {
        try {
            $owner = $_ | Invoke-CimMethod -MethodName GetOwner
            if ($owner.User -eq $Username) { $_ }
        } catch {}
    }

    if (-not $procs) {
        Add-Result -Action "TerminateUserProcesses" -Status "NotFound" -Details "No processes to terminate"
        return
    }

    if ($WhatIfMode) {
        Add-Result -Action "TerminateUserProcesses" -Status "Skipped" -Details "WhatIfMode"
        return
    }

    foreach ($p in $procs) {
        Stop-Process -Id $p.ProcessId -Force
        Add-Result -Action "TerminateUserProcesses" -Status "Success" `
            -Details "Killed PID $($p.ProcessId) ($($p.Name))"
    }
}

# Purge Kerberos Tickets 
Invoke-Step -Action "PurgeKerberosTickets" -Body {
    if ($WhatIfMode) {
        Add-Result -Action "PurgeKerberosTickets" -Status "Skipped" -Details "WhatIfMode"
        return
    }

    klist purge | Out-Null
    Add-Result -Action "PurgeKerberosTickets" -Status "Success" -Details "Kerberos cache purged (local)"
}

# 3.8 Optional Reboot 
if ($Reboot) {
    Invoke-Step -Action "OptionalReboot" -Body {
        if ($WhatIfMode) {
            Add-Result -Action "OptionalReboot" -Status "Skipped" -Details "WhatIfMode"
            return
        }

        Restart-Computer -Force
        Add-Result -Action "OptionalReboot" -Status "Success" -Details "Reboot initiated"
    }
}

# Final Summary 
Write-Log -Level "INFO" -Message "IR containment completed"

$Results | Format-Table -AutoSize
$Results | Export-Csv (Join-Path $BaseDir "ir_results.csv") -NoTypeInformation
