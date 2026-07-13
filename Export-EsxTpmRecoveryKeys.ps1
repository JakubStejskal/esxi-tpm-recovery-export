<#
.SYNOPSIS
    Exports ESXi encryption (TPM) recovery keys from every host across one or
    more vCenters and writes them to a single timestamped CSV.

.DESCRIPTION
    ESXi 7.0U2+ / 8.x keeps its ConfigStore encrypted and bound to the TPM.
    After a system-board / TPM replacement, a host whose recovery key was NOT
    captured beforehand can only be recovered by a full reinstall
    (see Broadcom KB 312109). This script captures those keys PROACTIVELY so
    you can store them off-host in a password vault.

    Flow:
      1. Asks which vCenter(s) to scan (interactive, unless -VCenter is given).
      2. Prompts for vCenter credentials via a graphical dialog.
      3. Connects to each vCenter and enumerates its ESXi hosts
         (optionally narrowed down to specific hosts with -VMHost).
      4. Prompts for ESXi host (root) credentials via a graphical dialog.
      5. Connects to each host directly and runs the esxcli equivalent of:
             esxcli system settings encryption recovery list
      6. Exports vCenter / host / RecoveryID / Key / status to one CSV.

    CLI equivalent per host:
        esxcli system settings encryption recovery list

.PARAMETER VCenter
    One or more vCenter FQDNs/IPs. If omitted, the script asks interactively.

.PARAMETER VMHost
    Limit the export to specific ESXi host(s) instead of every host in the
    vCenter(s). Accepts one or more names as registered in vCenter (FQDN or IP),
    a short hostname (matches the FQDN prefix), or a wildcard pattern such as
    'esx0*'. Matching is case-insensitive. A pattern that matches no host in any
    scanned vCenter is reported as 'HOST NOT FOUND' in the CSV.
    (Not named -Host: that would clash with PowerShell's automatic $Host.)

.PARAMETER OutputPath
    Target CSV path. Defaults to the current directory with a timestamp.

.EXAMPLE
    .\Export-EsxTpmRecoveryKeys.ps1
    Prompts for everything (vCenters, vCenter login, host login).

.EXAMPLE
    .\Export-EsxTpmRecoveryKeys.ps1 -VCenter vcenter-a.example.com,vcenter-b.example.com

.EXAMPLE
    .\Export-EsxTpmRecoveryKeys.ps1 -VCenter vcenter-a.example.com -VMHost esx01.example.com
    Exports the recovery key of a single host only.

.EXAMPLE
    .\Export-EsxTpmRecoveryKeys.ps1 -VCenter vcenter-a.example.com -VMHost esx01,esx02,'esxdr-*'
    Short names and wildcards; several hosts at once.

.NOTES
    Requires : VMware.PowerCLI  (Install-Module VMware.PowerCLI -Scope CurrentUser)
    License  : MIT — provided as-is, no warranty.

    SECURITY: the output CSV contains recovery keys in PLAINTEXT. Move it into a
    password vault immediately and delete the file. Never commit it anywhere.
#>

[CmdletBinding()]
param(
    [string[]]$VCenter,

    [ValidateNotNullOrEmpty()]
    [string[]]$VMHost,

    [string]$OutputPath = ".\ESXi_TPM_RecoveryKeys_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# --- Prerequisites -----------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name VMware.PowerCLI)) {
    throw "VMware.PowerCLI is not installed. Run: Install-Module VMware.PowerCLI -Scope CurrentUser"
}
Import-Module VMware.PowerCLI -ErrorAction Stop | Out-Null

# Tolerate self-signed vCenter/host certs; don't persist anything to the profile.
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCEIP $false -Scope Session -Confirm:$false | Out-Null

# --- 1) Which vCenter(s) to scan --------------------------------------------
if (-not $VCenter -or $VCenter.Count -eq 0) {
    $entry = Read-Host "Enter vCenter FQDN(s) or IP(s) to scan (comma- or space-separated)"
    $VCenter = $entry -split '[,\s]+' | Where-Object { $_ -ne '' }
}
if (-not $VCenter -or $VCenter.Count -eq 0) {
    throw "No vCenter specified. Nothing to do."
}
Write-Host ("vCenters to scan: {0}" -f ($VCenter -join ', ')) -ForegroundColor Cyan
if ($VMHost) {
    Write-Host ("Host filter     : {0}" -f ($VMHost -join ', ')) -ForegroundColor Cyan
}

# --- 2) Credentials (graphical prompts) -------------------------------------
# On Windows PowerShell 5.1 these pop a GUI dialog. In PowerShell 7 the prompt
# may fall back to the console depending on host/OS configuration.
$vcCred   = $Host.UI.PromptForCredential('vCenter login',
                'Enter an account with privileges to read host encryption settings.',
                '', '')
if (-not $vcCred) { throw "vCenter credentials are required." }

$hostCred = $Host.UI.PromptForCredential('ESXi host login',
                'Enter the ESXi host account (e.g. root) used to read the recovery key.',
                'root', '')
if (-not $hostCred) { throw "ESXi host credentials are required." }

$results = New-Object System.Collections.Generic.List[object]

# -VMHost patterns that matched at least one host (to report the ones that never did).
$matchedPatterns = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$vcUnreachable   = $false

# --- 3-5) Enumerate hosts per vCenter, pull recovery keys directly ----------
foreach ($vc in $VCenter) {

    Write-Host "==> Connecting to vCenter $vc ..." -ForegroundColor Cyan
    try {
        $vcConn = Connect-VIServer -Server $vc -Credential $vcCred -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "  Cannot connect to $vc : $($_.Exception.Message)"
        $vcUnreachable = $true
        $results.Add([pscustomobject]@{
            vCenter = $vc; VMHost = '(N/A)'; HostVersion = ''
            RecoveryID = ''; RecoveryKey = ''
            Status = "VCENTER CONNECT FAILED: $($_.Exception.Message)"
        })
        continue
    }

    $hosts = @(Get-VMHost -Server $vcConn | Sort-Object Name)
    Write-Host ("  {0} host(s) found" -f $hosts.Count) -ForegroundColor DarkGray

    if ($VMHost) {
        # Match the registered name as-is (FQDN/IP/wildcard) or as a short hostname.
        $hosts = @($hosts | Where-Object {
            $name = $_.Name
            $hit  = $false
            foreach ($p in $VMHost) {
                if ($name -like $p -or $name -like "$p.*") { [void]$matchedPatterns.Add($p); $hit = $true }
            }
            $hit
        })
        Write-Host ("  {0} host(s) match the -VMHost filter" -f $hosts.Count) -ForegroundColor DarkGray
    }

    foreach ($h in $hosts) {

        $hostVer = "$($h.Version)-$($h.Build)"

        # Connect DIRECTLY to the host with the host credential to read the key.
        $hConn = $null
        try {
            $hConn  = Connect-VIServer -Server $h.Name -Credential $hostCred -Force -ErrorAction Stop
            $esxcli = Get-EsxCli -VMHost (Get-VMHost -Server $hConn) -V2 -ErrorAction Stop
            $rec    = $esxcli.system.settings.encryption.recovery.list.Invoke()

            if (-not $rec) {
                $results.Add([pscustomobject]@{
                    vCenter = $vc; VMHost = $h.Name; HostVersion = $hostVer
                    RecoveryID = ''; RecoveryKey = ''
                    Status = 'NO RECOVERY KEY (encryption not active?)'
                })
            }
            else {
                foreach ($r in $rec) {
                    $results.Add([pscustomobject]@{
                        vCenter = $vc; VMHost = $h.Name; HostVersion = $hostVer
                        RecoveryID = $r.RecoveryID; RecoveryKey = $r.Key
                        Status = 'OK'
                    })
                }
                Write-Host ("    {0}  OK" -f $h.Name) -ForegroundColor Green
            }
        }
        catch {
            Write-Warning ("    {0}  ERROR: {1}" -f $h.Name, $_.Exception.Message)
            $results.Add([pscustomobject]@{
                vCenter = $vc; VMHost = $h.Name; HostVersion = $hostVer
                RecoveryID = ''; RecoveryKey = ''
                Status = "HOST ERROR: $($_.Exception.Message)"
            })
        }
        finally {
            if ($hConn) { Disconnect-VIServer -Server $hConn -Confirm:$false -ErrorAction SilentlyContinue }
        }
    }

    Disconnect-VIServer -Server $vcConn -Confirm:$false -ErrorAction SilentlyContinue
}

# Report -VMHost patterns that matched nothing (typo, wrong vCenter, host not managed).
$notFound = if ($vcUnreachable) { 'HOST NOT FOUND (some vCenter(s) were unreachable)' }
            else                { 'HOST NOT FOUND in scanned vCenter(s)' }
foreach ($p in $VMHost) {
    if (-not $matchedPatterns.Contains($p)) {
        Write-Warning "Host '$p': $notFound"
        $results.Add([pscustomobject]@{
            vCenter = '(N/A)'; VMHost = $p; HostVersion = ''
            RecoveryID = ''; RecoveryKey = ''
            Status = $notFound
        })
    }
}

# --- 6) Output ---------------------------------------------------------------
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$okCount = ($results | Where-Object Status -eq 'OK').Count
Write-Host ""
Write-Host ("Done. {0} key(s) written to:" -f $okCount) -ForegroundColor Yellow
Write-Host ("  {0}" -f (Resolve-Path $OutputPath).Path) -ForegroundColor Yellow
Write-Host ""
Write-Host "!! The CSV contains recovery keys in PLAINTEXT. Move it into a password" -ForegroundColor Red
Write-Host "   vault, then delete the file. Do NOT commit it to any repository." -ForegroundColor Red

# On-screen summary WITHOUT the key material.
$results | Format-Table vCenter, VMHost, HostVersion, RecoveryID, Status -AutoSize
