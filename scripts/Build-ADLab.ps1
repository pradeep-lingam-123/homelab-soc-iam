<#
.SYNOPSIS
    Builds the Active Directory structure for the homelab-soc-iam lab.

.DESCRIPTION
    Creates the OU hierarchy, role-based security groups, and user accounts
    for the lab.local domain, following IAM best practices:
      - Least privilege (permissions via groups, never per-user)
      - ChangePasswordAtLogon (admins never know user passwords)
      - OUs protected from accidental deletion
      - Object types separated into OUs for targeted GPOs

    Run on the Domain Controller (DC01) in an ELEVATED PowerShell session
    (right-click PowerShell -> Run as Administrator).

.NOTES
    Domain      : lab.local
    Author      : Pradeep
    Environment : VirtualBox home lab, single-DC forest
    Idempotency : Safe-ish to re-run; existing objects will throw
                  "already exists" errors that can be ignored.
#>

# ---------------------------------------------------------------------------
# Pre-flight: confirm the AD module is available and we're on the domain
# ---------------------------------------------------------------------------
Import-Module ActiveDirectory -ErrorAction Stop
$domain = (Get-ADDomain).DistinguishedName    # e.g. DC=lab,DC=local
Write-Host "Target domain: $domain" -ForegroundColor Cyan

# ===========================================================================
# BLOCK 1 - Organizational Unit (OU) structure
# ---------------------------------------------------------------------------
# Builds a hierarchy mirroring a real enterprise. Separate OUs for Users,
# Groups, ServiceAccounts, and Workstations let us target different GPOs at
# different object types later. ProtectedFromAccidentalDeletion prevents an
# OU full of accounts being deleted by mistake (an operational safeguard).
# ===========================================================================
Write-Host "`n[Block 1] Creating OU structure..." -ForegroundColor Yellow

New-ADOrganizationalUnit -Name "Corp" -Path $domain -ProtectedFromAccidentalDeletion $true

$corpPath = "OU=Corp,$domain"
New-ADOrganizationalUnit -Name "Departments"     -Path $corpPath -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Users"           -Path $corpPath -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Groups"          -Path $corpPath -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "ServiceAccounts" -Path $corpPath -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Workstations"    -Path $corpPath -ProtectedFromAccidentalDeletion $true

$deptPath = "OU=Departments,OU=Corp,$domain"
New-ADOrganizationalUnit -Name "IT"      -Path $deptPath -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "HR"      -Path $deptPath -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Finance" -Path $deptPath -ProtectedFromAccidentalDeletion $true

Write-Host "[Block 1] OU structure created." -ForegroundColor Green

# ===========================================================================
# BLOCK 2 - Security groups (role-based access control)
# ---------------------------------------------------------------------------
# Security groups grant permissions. The IAM principle: assign rights to
# GROUPS, add USERS to groups - never assign rights to individuals. The
# privileged groups (Helpdesk-Admins, Workstation-Admins) let us delegate
# SPECIFIC admin rights instead of handing out Domain Admin = least privilege.
# ===========================================================================
Write-Host "`n[Block 2] Creating security groups..." -ForegroundColor Yellow

$groupPath = "OU=Groups,OU=Corp,$domain"

# Department groups - for resource access by team
New-ADGroup -Name "IT-Staff"      -GroupScope Global -GroupCategory Security -Path $groupPath
New-ADGroup -Name "HR-Staff"      -GroupScope Global -GroupCategory Security -Path $groupPath
New-ADGroup -Name "Finance-Staff" -GroupScope Global -GroupCategory Security -Path $groupPath

# Role-based privileged groups - delegated, scoped admin rights
New-ADGroup -Name "Helpdesk-Admins"    -GroupScope Global -GroupCategory Security -Path $groupPath
New-ADGroup -Name "Workstation-Admins" -GroupScope Global -GroupCategory Security -Path $groupPath

Write-Host "[Block 2] Security groups created." -ForegroundColor Green

# ===========================================================================
# BLOCK 3 - User accounts
# ---------------------------------------------------------------------------
# Users are created with proper attributes (UPN, department, standard jsmith
# naming). Two IAM best practices baked in:
#   - ChangePasswordAtLogon: users set their own password at first logon,
#     so admins never know it.
#   - Group membership assigned at creation: access via role groups only.
# ===========================================================================
Write-Host "`n[Block 3] Creating user accounts..." -ForegroundColor Yellow

$userPath = "OU=Users,OU=Corp,$domain"

# The initial password is typed in at run time, so it is never stored in the
# script or the repo. It must meet the domain password policy, and users are
# forced to change it at first logon.
$defaultPassword = Read-Host "Initial password for new lab users" -AsSecureString

function New-LabUser {
    param(
        [string]$First,
        [string]$Last,
        [string]$Dept,
        [string[]]$Groups
    )
    # sAMAccountName = first initial + surname, lower-case (e.g. jsmith)
    $sam = ($First.Substring(0,1) + $Last).ToLower()

    New-ADUser `
        -Name                 "$First $Last" `
        -GivenName            $First `
        -Surname              $Last `
        -SamAccountName       $sam `
        -UserPrincipalName    "$sam@lab.local" `
        -Path                 $userPath `
        -AccountPassword      $defaultPassword `
        -ChangePasswordAtLogon $true `
        -Enabled              $true `
        -Department           $Dept

    # Add the user to their department group + any role groups
    foreach ($g in $Groups) {
        Add-ADGroupMember -Identity $g -Members $sam
    }

    Write-Host "  Created user: $sam ($Dept)" -ForegroundColor Green
}

# Create a realistic set of users across departments
New-LabUser -First "James" -Last "Smith"  -Dept "IT"      -Groups @("IT-Staff","Helpdesk-Admins")
New-LabUser -First "Sarah" -Last "Jones"  -Dept "IT"      -Groups @("IT-Staff")
New-LabUser -First "Priya" -Last "Patel"  -Dept "HR"      -Groups @("HR-Staff")
New-LabUser -First "David" -Last "Brown"  -Dept "Finance" -Groups @("Finance-Staff")
New-LabUser -First "Emma"  -Last "Wilson" -Dept "Finance" -Groups @("Finance-Staff")

Write-Host "[Block 3] User accounts created." -ForegroundColor Green

# ===========================================================================
# BLOCK 4 - Verification
# ---------------------------------------------------------------------------
# Confirms the OUs, users (with department), and group memberships exist.
# ===========================================================================
Write-Host "`n[Block 4] Verifying..." -ForegroundColor Yellow

Write-Host "`n--- Organizational Units ---" -ForegroundColor Cyan
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName | Format-Table -AutoSize

Write-Host "`n--- Users ---" -ForegroundColor Cyan
Get-ADUser -Filter * -SearchBase "OU=Users,OU=Corp,$domain" -Properties Department |
    Select-Object Name, SamAccountName, Department | Format-Table -AutoSize

Write-Host "`n--- IT-Staff members ---" -ForegroundColor Cyan
Get-ADGroupMember -Identity "IT-Staff" | Select-Object Name | Format-Table -AutoSize

Write-Host "`nAD lab build complete." -ForegroundColor Green
