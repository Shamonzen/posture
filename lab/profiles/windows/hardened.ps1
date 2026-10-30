# Hardened profile (after guard_lab and common.ps1, on the `base` snapshot): the same accounts and
# settings as weak.ps1, each one fixed.
Wait-LabAD
$password = Get-LabSecret LAB_WEAK_USER_PASSWORD
function New-LabUser([string]$Name) {
    New-ADUser $Name -AccountPassword $password -Enabled $true -PassThru
}

# Service account without an SPN on a user object, AES only.
New-LabUser svc-sql | Set-ADUser -KerberosEncryptionType AES128, AES256
New-LabUser legacy.app | Out-Null
New-LabUser temp.user | Out-Null
# One Domain Admin besides Administrator: password expires, can't be delegated.
New-LabUser adm.ops | Set-ADUser -AccountNotDelegated $true
New-LabUser adm.helpdesk | Out-Null
New-LabUser adm.backup | Out-Null
Add-ADGroupMember 'Domain Admins' -Members adm.ops
New-LabUser old.admin | Out-Null
New-LabUser old.contractor | Disable-ADAccount

# Computers: no unconstrained delegation; Windows LAPS schema (in WS2019 since the April 2023 update).
Update-LapsADSchema -Credential (Get-LabAdmin) -Confirm:$false
foreach ($name in 'ws01', 'ws02') {
    # shortcut: these placeholder objects have no machine behind them to run the LAPS client, so the
    # expiry it would write is stamped here; replace with a domain-joined VM if the lab grows one.
    New-ADComputer $name -OtherAttributes @{ 'msLAPS-PasswordExpirationTime' = (Get-Date).AddDays(30).ToFileTimeUtc() }
}

# Applied after the users exist, so the lab password needn't meet the new 14-character minimum.
Set-LabPolicy -Password @{
    MinimumPasswordLength = 14; LockoutBadCount = 5; LockoutDuration = 15; ResetLockoutCount = 15
    PasswordComplexity = 1; ClearTextPassword = 0
} -Security @{ RequireSecuritySignature = 1; LDAPServerIntegrity = 2; LmCompatibilityLevel = 5 }
# Ordinary users may no longer join computers to the domain (the default quota is 10).
Set-ADObject $DomainDN -Replace @{ 'ms-DS-MachineAccountQuota' = 0 } -Credential (Get-LabAdmin)

Set-ItemProperty 'HKLM:\SOFTWARE\PostureLab' -Name profile -Value hardened
