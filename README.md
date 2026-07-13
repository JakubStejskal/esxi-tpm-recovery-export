# ESXi TPM Recovery Key Export

A PowerShell / PowerCLI script that exports **ESXi encryption (TPM) recovery
keys** from every host across one or more vCenters into a single timestamped CSV.

## Why

ESXi 7.0 U2+ / 8.x keeps its ConfigStore encrypted and bound to the host TPM.
After a **system-board or TPM replacement**, a host whose recovery key was *not*
captured beforehand can only be brought back by a **full reinstall**
(Broadcom KB 312109 — "Unable to restore the system configuration. A security
violation was detected."). This script captures those keys **proactively** so
you can keep them off-host in a password vault.

Per-host CLI equivalent:

```
esxcli system settings encryption recovery list
```

## What it does

1. Asks which vCenter(s) to scan (interactive, or pass `-VCenter`).
2. Prompts for **vCenter credentials** in a graphical dialog.
3. Connects to each vCenter and enumerates its ESXi hosts (optionally narrowed
   to specific hosts with `-VMHost`).
4. Prompts for **ESXi host (root) credentials** in a graphical dialog.
5. Connects to each host directly and reads its recovery key(s).
6. Exports `vCenter, VMHost, HostVersion, RecoveryID, RecoveryKey, Status`
   to one CSV.

## Requirements

- Windows PowerShell 5.1 (recommended — graphical credential prompt is reliable
  there; on PowerShell 7 the prompt may fall back to the console).
- [VMware.PowerCLI](https://developer.vmware.com/powercli):

  ```powershell
  Install-Module VMware.PowerCLI -Scope CurrentUser
  ```

## Usage

```powershell
# Fully interactive (asks for vCenters, then both logins)
.\Export-EsxTpmRecoveryKeys.ps1

# Pre-seed the vCenter list
.\Export-EsxTpmRecoveryKeys.ps1 -VCenter vcenter-a.example.com,vcenter-b.example.com

# Custom output path
.\Export-EsxTpmRecoveryKeys.ps1 -OutputPath C:\secure\keys.csv

# Target a single host (name as registered in vCenter, or short hostname)
.\Export-EsxTpmRecoveryKeys.ps1 -VCenter vcenter-a.example.com -VMHost esx01.example.com

# Several hosts / wildcards
.\Export-EsxTpmRecoveryKeys.ps1 -VCenter vcenter-a.example.com -VMHost esx01,esx02,'esxdr-*'
```

### Host filter (`-VMHost`)

- Without `-VMHost` every host in the scanned vCenter(s) is processed.
- Accepts FQDN / IP as shown in vCenter, a short hostname (matches the FQDN
  prefix, e.g. `esx01` → `esx01.example.com`) or a wildcard (`esx0*`). Matching
  is case-insensitive.
- A pattern that matches no host in any scanned vCenter is logged as a warning
  and written to the CSV with status `HOST NOT FOUND` (with a note if any
  vCenter could not be reached, so the host may simply live there).
- Named `-VMHost` rather than `-Host` because `$Host` is a reserved PowerShell
  automatic variable.

## ⚠️ Security

The output CSV contains recovery keys in **plaintext**. Move it into a password
vault (KeePass or equivalent) immediately and **delete the file**. Never commit
it to any repository — `.gitignore` in this repo already excludes `*.csv`.

## License

MIT — see [LICENSE](LICENSE). Provided as-is, without warranty.
