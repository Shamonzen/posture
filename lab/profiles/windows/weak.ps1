# Weak profile (after guard_lab and common.ps1, on the `base` snapshot): one misconfiguration
# per AD / DC check planned for checks/ad/. Lab only: the DC sits on an isolated host-only network.
Wait-LabAD
$password = Get-LabSecret LAB_WEAK_USER_PASSWORD
function New-LabUser([string]$Name) {
    New-ADUser $Name -AccountPassword $password -Enabled $true -PassThru
}

# Kerberoastable: a user account with an SPN (T1558.003).
New-LabUser svc-sql | Set-ADUser -ServicePrincipalNames @{ Add = 'MSSQLSvc/sql01.posture.test:1433' }
# AS-REP roastable: Kerberos pre-authentication off (T1558.004).
New-LabUser legacy.app | Set-ADAccountControl -DoesNotRequirePreAuth $true
# PASSWD_NOTREQD: the account may have an empty password.
New-LabUser temp.user | Set-ADAccountControl -PasswordNotRequired $true
# Admins: password never expires, and more Domain Admins than the job needs.
New-LabUser adm.ops | Set-ADUser -PasswordNeverExpires $true
New-LabUser adm.helpdesk | Out-Null
New-LabUser adm.backup | Out-Null
Add-ADGroupMember 'Domain Admins' -Members adm.ops, adm.helpdesk, adm.backup
# adminCount orphan: flagged as protected, but in no protected group (AdminSDHolder leftovers).
New-LabUser old.admin | Set-ADUser -Replace @{ adminCount = 1 }
# Never-used account, left enabled.
New-LabUser old.contractor | Out-Null

# Computers: unconstrained delegation on a non-DC (T1558), and no LAPS on either.
New-ADComputer ws01 -PassThru | Set-ADAccountControl -TrustedForDelegation $true
New-ADComputer ws02

# Password policy and DC host settings (SMB signing, LDAP signing, NTLM level).
Set-LabPolicy -Password @{ MinimumPasswordLength = 7; LockoutBadCount = 0; ClearTextPassword = 1 } `
    -Security @{ RequireSecuritySignature = 0; LDAPServerIntegrity = 1; LmCompatibilityLevel = 1 }

Set-ItemProperty 'HKLM:\SOFTWARE\PostureLab' -Name profile -Value weak
