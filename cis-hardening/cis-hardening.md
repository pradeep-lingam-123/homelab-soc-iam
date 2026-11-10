# CIS hardening: DC01

Assessment of the lab domain controller against the **CIS Microsoft Windows Server 2022 Benchmark**, using Wazuh 4.14 Security Configuration Assessment (policy `cis_win2022`), followed by scripted remediation and a rescan.

## Results

| Scan | Passed | Failed | Total | Score |
| --- | --- | --- | --- | --- |
| Baseline (5 Nov 2026) | 102 | 257 | 359 | 28% |
| After script (5 Nov 2026) | 210 | 149 | 359 | 58% |
| After script and GPO account policy (5 Nov 2026) | 217 | 142 | 359 | 60% |

115 previously failing checks now pass. Screenshot: `after-score.png`. The raw Wazuh export is kept out of the repo. Applied settings log: `applied-settings.csv`.

## Key finding

The baseline showed the domain's minimum password length below 14 characters, even though `Harden-ADLab.ps1` had set a 14-character minimum. The script changed the policy directly on the domain object, and the **Default Domain Policy** GPO reapplied its own values at the next policy refresh. The control looked configured but wasn't in force.

**Fix:** set password and lockout policy inside the Default Domain Policy GPO (14-character minimum, 24-password history, 365-day maximum age, 1-day minimum age, lockout after 5 attempts for 15 minutes). `net accounts`, the GPO backup report and the rescan all confirm the values are now in force, and the 7 related checks pass. Lesson: verify a control by measuring it, not by trusting the script that set it.

## What was changed

`CIS-Harden-DC01.ps1` applies each setting tagged with its CIS ID. Account policies were set in the Default Domain Policy GPO and backed up with `Backup-GPO` to `gpo-backup/`.

| Area | CIS sections | What it does |
| --- | --- | --- |
| Password and lockout policy | 1.1.1 to 1.1.6, 1.2.1 to 1.2.4 | 14-character minimum, 24-password history, lockout after 5 attempts for 15 minutes |
| Audit policy | 2.3.2.1, 17.x (19 subcategories) | Subcategory auditing made authoritative, adds credential validation, group changes, file share, policy change and privilege use events |
| Logging and visibility | 18.9.3.1, 18.10.87.x, 18.10.26.x, 18.5.12 | Command lines in process creation events, PowerShell script block logging and transcription, larger event logs |
| Credential and authentication | 2.3.x, 18.9.25.x, 18.9.4.x, 18.10.89.x | NTLMv2 only, LSA protection, no custom LSASS plug-ins, SMB client signing, CredSSP oracle fix, WinRM hardening |
| Print Spooler | 5.1, 18.4.2, 18.7.x, 18.9.20.1.x | Spooler disabled on the DC, print RPC and driver installation locked down |
| Legacy protocols and network stack | 18.4.x, 18.5.x, 18.6.8.1, 18.6.14.1 | SMBv1 off, NetBIOS P-node, source routing and ICMP redirects off, hardened UNC paths for SYSVOL and NETLOGON |
| AutoPlay and AutoRun | 18.10.7.x | Disabled for all drives |
| Remote Desktop | 18.10.57.x | NLA required, high encryption, no saved passwords or drive redirection, idle and disconnect limits |
| Microsoft Defender | 18.10.43.x | File hash computation, removable drive and email scanning, PUA blocking |
| Windows Firewall | 9.1.x, 9.2.x, 9.3.x | On for all profiles, inbound blocked by default, logging of dropped and allowed connections |

## Deliberately not applied

| Check | Reason |
| --- | --- |
| 2.3.11.4 Kerberos encryption types AES only | Would remove RC4 and block the planned Kerberoasting detection exercise. Accepted risk, documented |
| 2.3.5.3, 2.3.5.4 LDAP channel binding and signing | May break the LDAP queries used by the attack-simulation tooling. Revisit after Phase 4 |
| 2.3.11.9, 2.3.11.10 NTLM minimum session security | Needs testing against the attack-simulation tooling first |
| 2.3.17.x User Account Control | Changes the admin workflow on the only DC. Planned for a later pass |
| 2.3.1.4, 2.3.1.5 Rename administrator and guest accounts | Planned for a later pass with the build scripts updated |
| 9.3.5, 9.3.6 Public profile ignores local firewall rules | If the DC misidentifies its network as Public at boot, AD traffic could be dropped |
| 18.6.19.2.1 Disable IPv6 | Microsoft advises against disabling IPv6 on domain controllers |
| 18.9.5.x Virtualisation-based security and Credential Guard | VirtualBox doesn't expose the required hardware features |
| 18.7.3, 18.7.4, 18.7.5 Print RPC connection settings | Expected values in the policy file need checking against the setting descriptions first |
| Checks marked MS only | Apply to member servers, not domain controllers |
| Windows Update scheduling, telemetry and consumer features | Out of scope for this pass |

## Reproduce or roll back

1. Take a VirtualBox snapshot of DC01.
2. Run `CIS-Harden-DC01.ps1` as Administrator.
3. Set account policies in the Default Domain Policy GPO, or restore them from `gpo-backup/` with `Import-GPO`.
4. Run `gpupdate /force` and restart DC01.
5. Roll back by restoring the `pre-cis` snapshot.
