# Cybersecurity Home Lab — SOC & IAM

A self-built, segmented virtual lab demonstrating network security, identity
and access management, SIEM/detection engineering, and adversary simulation.
Built end-to-end on VirtualBox (laptop-hosted, isolated from the host network),
documented phase by phase with reusable scripts and verification evidence.

> **Design constraint:** 16GB RAM host. VMs run in modules with snapshots
> between sessions rather than all at once — a deliberate resource-constrained
> lab design, noted where it influenced tooling choices.

---

## Objectives
- Practise enterprise network segmentation and firewalling
- Deploy and **harden** Active Directory (blue-team / IAM focus)
- Stand up a SIEM and build detections against simulated attacks
- Run an end-to-end attack→detect exercise
- Bridge to embedded-security research (fTPM / TPM emulation)

## Architecture
```
Host (VirtualBox)
│
pfSense firewall  ── WAN: NAT ──→ internet
│
└── LAN "labnet" (192.168.10.0/24)
      ├── DC01          192.168.10.10   Windows Server 2022 — Domain Controller
      ├── Wazuh Server  192.168.10.20   SIEM (manager + indexer + dashboard)
      ├── Kali          (Phase 4)       Attacker
      └── Mgmt / client VMs
```

| Segment | Range | Purpose |
|---------|-------|---------|
| WAN | NAT (10.0.2.0/24) | Internet access via host |
| LAN (`labnet`) | 192.168.10.0/24 | Isolated lab segment |

## Build phases
- [x] **Phase 1 — Network Backbone** (pfSense firewall, segmentation, DHCP)
- [x] **Phase 2 — Active Directory & IAM hardening**
- [x] **Phase 3 — SIEM / Detection** (Wazuh)
- [x] **CIS Benchmark hardening** (DC01 raised from 28% to 60%)
- [ ] **Vulnerability management** (scan, triage, patch and verify, in progress)
- [ ] Phase 4 — Adversary simulation (Kali → Kerberoasting → detection)
- [ ] Phase 5 — Embedded / TPM tie-in (swtpm, links to fTPM research)

## Tech stack
VirtualBox · pfSense CE · Windows Server 2022 (AD DS, DNS, GPO) ·
Ubuntu Server · Wazuh · PowerShell · Git/GitHub

---

## Phase 1 — Network Backbone

**Stack:** pfSense CE 2.8.1 (FreeBSD), VirtualBox — SATA/AHCI disk + EFI.

A pfSense VM provides a firewalled, segmented lab network. All other VMs sit on
an internal network (`labnet`) behind it, isolated from the host/home network.

| Interface | Config |
|-----------|--------|
| WAN (em0) | NAT adapter, DHCP client |
| LAN (em1) | Static `192.168.10.1/24`, internal network `labnet` |
| DHCP (LAN) | `192.168.10.100`–`.200` |

**Firewall rules:** LAN↔LAN allowed; LAN→host-network blocked (isolation).

**Verification:** an Ubuntu Server 24.04 management VM leased `192.168.10.100`
via DHCP and routed to the internet through pfSense, confirming the backbone
end to end.

**Build note:** the pfSense installer initially looped on "Non-system disk"
when the virtual disk was on an IDE controller. Moving the disk to a
**SATA (AHCI)** controller and enabling **EFI** resolved it — a reminder that
guest firmware/controller choices matter per-OS.

---

## Phase 2 — Active Directory & IAM Hardening

**Stack:** Windows Server 2022 Standard (Desktop Experience) — single DC forest.

### Domain
- `DC01`, static `192.168.10.10` on `labnet`, DNS self + forwarder `192.168.10.1`
- Promoted to a new forest **`lab.local`** (NetBIOS `LAB`, FL Windows Server 2016)

### Directory structure (built via PowerShell — `scripts/Build-ADLab.ps1`)
```
lab.local
 └─ Corp
     ├─ Departments (IT, HR, Finance)
     ├─ Users
     ├─ Groups
     ├─ ServiceAccounts
     └─ Workstations
```
- OUs protected from accidental deletion
- Role-based security groups (permissions via groups, never per-user)
- Users provisioned with `ChangePasswordAtLogon` and group membership at creation

### Hardening baseline (`scripts/Harden-ADLab.ps1`)
- **Password & lockout policy:** 14-char minimum, complexity, 24-password
  history, 90-day max age, lockout after 5 attempts / 15 min
- **Advanced audit policy:** logon/logoff, Kerberos ticket operations
  (4768/4769), account & group management, process creation — the telemetry
  the SIEM consumes in Phase 3
- **Legacy protocols disabled:** LLMNR and NetBIOS-over-TCP (common
  credential-theft vectors)

### Control validation (negative test)
Attempting to provision a service account with a non-compliant password was
**rejected by the domain**, confirming the 14-char complexity baseline is
actively enforced rather than merely configured.
See [`Docs/control-validation.md`](Docs/control-validation.md).

**Update, November 2026:** the CIS scan later showed the 14-character policy was
no longer in force. The Default Domain Policy GPO had silently overwritten the
values the script set on the domain. The policy is now set in the GPO itself and
confirmed by a rescan. See [CIS Benchmark hardening](#cis-benchmark-hardening).

### Intentional weakness (for Phase 4)
A service account `svc-sql` was created with a Service Principal Name
(`MSSQLSvc/dc01.lab.local:1433`), making it **Kerberoastable** — a deliberate,
documented target for the Phase 4 attack→detect exercise. *(Not a
misconfiguration — an intentional purple-team artifact.)*

---

## Phase 3 — SIEM / Detection (Wazuh)

**Stack:** Wazuh 4.14 all-in-one (manager + indexer + dashboard) on Ubuntu
Server; agent-based Windows log collection.

| Component | Detail |
|-----------|--------|
| Wazuh server | Static `192.168.10.20`, 4GB/2 cores |
| Install | Assisted all-in-one (`wazuh-install.sh -a`) |
| Dashboard | `https://192.168.10.20` (self-signed TLS) |
| Monitored endpoint | DC01 via Wazuh agent (ports 1514/1515) |

### Design decision — Wazuh over Security Onion
Security Onion's practical baseline (~12–16GB RAM) exceeds what a 16GB host can
allocate while keeping pfSense and the DC running concurrently. Wazuh delivers
equivalent SIEM/XDR capability (log ingestion, detection rules, MITRE ATT&CK
mapping, dashboards, alerting) in a ~4GB footprint, allowing the **SIEM,
target, and attacker to run simultaneously** — a prerequisite for live
attack→detect exercises. Choosing the tool that fits the resource envelope
while preserving capability is a deliberate engineering trade-off.

### Agent-based Windows log collection
The Wazuh agent runs on DC01 and reads the Windows Security event log locally,
shipping it to the manager over an authenticated, encrypted channel. This
captures native event IDs (4624/4625 logon, **4769** Kerberos service ticket,
4720+ account management) with full fidelity. The Phase 2 audit policy is what
makes these events available — **you can only detect what you first chose to
log.**

**Verification:** all Wazuh services `active (running)`; DC01 reported
**Active** in the Agents view; logon events (4624) confirmed flowing after a
test logon.

---

## CIS Benchmark hardening

**Benchmark:** CIS Microsoft Windows Server 2022 Benchmark v2.0.0, assessed on
DC01 with Wazuh configuration assessment (SCA).

| Stage | Passed | Failed | Score |
|-------|--------|--------|-------|
| Baseline | 102 | 257 | 28% |
| After `CIS-Harden-DC01.ps1` | 210 | 149 | 58% |
| After fixing the policy at GPO level | 217 | 142 | 60% |

The script applies 110 settings, each tagged with its CIS ID, and logs every
change to `applied-settings.csv`. Settings that would break the lab, such as
AES-only Kerberos before the Phase 4 exercise, are left out with a documented
reason. Full write-up, exceptions and rollback steps:
[`cis-hardening/cis-hardening.md`](cis-hardening/cis-hardening.md).

---

## Vulnerability management

DC01 had never been patched since its March 2022 build (20348.587). Wazuh
vulnerability detection found **1,753 CVEs**. Cross-referencing them with CISA's
Known Exploited Vulnerabilities catalogue flagged **83 as actively exploited**,
17 of them used in ransomware campaigns. Matching findings to the roles DC01
actually runs put 260 out of scope, leaving 1,493 to prioritise by exploitation,
exposure and severity.

| Severity | Before | After patching |
|----------|--------|----------------|
| Critical | 30 | in progress |
| High | 1,240 | in progress |
| On CISA KEV | 83 | in progress |

Report and prioritised findings:
[`vulnerability-triage/vulnerability-report.md`](vulnerability-triage/vulnerability-report.md).
Monthly Patch Tuesday tracking: [`patch-log.md`](patch-log.md).

---

## Phase 4 — Adversary Simulation *(planned)*
Kali attacker on `labnet`; Kerberoast `svc-sql`, crack the ticket offline,
then detect the attack in Wazuh via event **4769**. Each attack paired with its
corresponding detection — the headline attack→detect artifacts.

## Phase 5 — Embedded / TPM tie-in *(planned)*
Software-TPM (swtpm) demo of key generation/attestation, linking the lab to
RSS-based physical-layer-security / fTPM dissertation research.

---

## Repository layout
```
homelab-soc-iam/
├── README.md
├── patch-log.md               # monthly Patch Tuesday tracking
├── scripts/
│   ├── Build-ADLab.ps1        # OUs, groups, users
│   ├── Harden-ADLab.ps1       # password/audit policy, legacy-protocol disable
│   └── Create-WeakAccount.ps1 # deliberately Kerberoastable svc-sql
├── cis-hardening/             # CIS script, results, GPO backup
├── vulnerability-triage/      # report, KEV matches, hotfix lists
├── Docs/
│   └── control-validation.md  # password-policy negative test
└── Screenshots/               # verification evidence per phase
```

## Notes
- VM disk images (`*.vdi`, `*.iso`) are excluded via `.gitignore`.
- Raw Wazuh exports are kept out of the repo. Write-ups and derived lists are published.
- Lab passwords are typed in at run time. The one exception is the deliberately
  weak `svc-sql` password, which is the Phase 4 target.
- Screenshots are scrubbed of sensitive/real-network data.
- Lab IPs (`192.168.10.0/24`) are private and non-routable.
