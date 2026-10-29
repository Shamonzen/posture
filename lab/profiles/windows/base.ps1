# Base provisioner (after guard_lab and common.ps1), once the new DC is back up: the audit
# account. lab.sh then saves the `base` snapshot that both profiles start from.
Wait-LabAD

# An ordinary domain user (LDAP reads need nothing more) that may use WinRM without being an
# admin, and can't be delegated if it is ever phished.
if (-not (Get-ADUser -Filter "sAMAccountName -eq 'posture'")) {
    New-ADUser posture -DisplayName 'Posture audit' -Enabled $true `
        -AccountPassword (Get-LabSecret POSTURE_AUDIT_PASSWORD)
}
Set-ADUser posture -AccountNotDelegated $true
Add-ADGroupMember 'Remote Management Users' -Members posture
