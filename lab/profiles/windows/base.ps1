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

# LDAPS: AD DS serves TLS on 636 once LocalMachine\My holds a Server Authentication certificate
# for the DC's name that it can use and trust. Otherwise it logs event 1220 (8009030e) and 636
# resets every handshake: the key must be in the legacy SChannel CSP (not CNG), and a
# self-signed certificate must also be in the machine's Root store. AD DS then picks it up by
# itself, no restart. lab.sh exports it so posture can pin it (--ca-file); a simple bind inside
# verified TLS meets "LDAP signing required".
$fqdn = 'posture-dc.posture.test'
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq "CN=$fqdn"
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Subject "CN=$fqdn" -CertStoreLocation Cert:\LocalMachine\My `
        -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(5) `
        -Provider 'Microsoft RSA SChannel Cryptographic Provider' -KeySpec KeyExchange `
        -TextExtension @(
            "2.5.29.17={text}DNS=$fqdn&DNS=posture-dc&IPAddress=192.168.57.10",
            '2.5.29.37={text}1.3.6.1.5.5.7.3.1'
        )
}
$root = New-Object Security.Cryptography.X509Certificates.X509Store Root, LocalMachine
$root.Open('ReadWrite')
$root.Add($cert)
$root.Close()
