# Helpers for the DC profiles (prepended after guard_lab, before the profile itself).

$DomainDN = 'DC=posture,DC=test'
$DefaultDomainPolicy = '31B2F340-016D-11D2-945F-00C04FB984F9'
$DefaultDCPolicy = '6AC1786C-016F-11D2-945F-00C04fB984F9'
$SecurityKeys = @{
    RequireSecuritySignature = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    LDAPServerIntegrity = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    LmCompatibilityLevel = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
}

function Wait-LabAD {
    # After a reboot or a snapshot restore, the AD cmdlets fail until AD Web Services is up.
    $deadline = (Get-Date).AddMinutes(10)
    while ($true) {
        try { Get-ADDomain | Out-Null; return }
        catch { if ((Get-Date) -gt $deadline) { throw } ; Start-Sleep -Seconds 10 }
    }
}

function Get-LabSecret([string]$Name) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if (-not $value) { throw "$Name is not set (copy .env.example to .env in the repo root)" }
    ConvertTo-SecureString $value -AsPlainText -Force
}

function Get-LabAdmin {
    # vagrant is only in BUILTIN\Administrators after promotion: enough for users and SYSVOL, not
    # for GPO objects or the schema. The domain Administrator can (adding vagrant to Domain or
    # Schema Admins would skew the privileged-group checks).
    [pscredential]::new('POSTURE\Administrator', (Get-LabSecret LAB_DOMAIN_ADMIN_PASSWORD))
}

function Set-LabGpo([string]$Guid, [string]$Section, [hashtable]$Settings) {
    # Password policy and DC security options live in these two default GPOs: a direct registry
    # or Set-ADDefaultDomainPasswordPolicy change would be reverted by the next policy refresh.
    # So edit the GPO's security template in SYSVOL and bump its version, then gpupdate.
    $gpo = "$env:SystemRoot\SYSVOL\domain\Policies\{$Guid}"
    $inf = "$gpo\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    $lines = [Collections.Generic.List[string]](Get-Content $inf -Encoding Unicode)
    $start = $lines.IndexOf("[$Section]")
    if ($start -lt 0) { $lines.Add("[$Section]"); $start = $lines.Count - 1 }
    foreach ($key in $Settings.Keys) {
        $at = $start + 1
        while ($at -lt $lines.Count -and -not $lines[$at].StartsWith('[') -and
               ($lines[$at] -split '=', 2)[0].Trim() -ne $key) { $at++ }
        $line = "$key = $($Settings[$key])"
        if ($at -lt $lines.Count -and -not $lines[$at].StartsWith('[')) { $lines[$at] = $line }
        else { $lines.Insert($at, $line) }
    }
    Set-Content $inf $lines -Encoding Unicode

    $dn = "CN={$Guid},CN=Policies,CN=System,$DomainDN"
    $version = (Get-ADObject $dn -Properties versionNumber).versionNumber + 1  # +1 = machine half
    Set-ADObject $dn -Replace @{ versionNumber = $version } -Credential (Get-LabAdmin)
    (Get-Content "$gpo\GPT.INI") -replace '^Version=\d+', "Version=$version" |
        Set-Content "$gpo\GPT.INI" -Encoding ASCII
}

function Set-LabPolicy([hashtable]$Password, [hashtable]$Security) {
    # $Security: value name -> DWORD, written as GptTmpl.inf registry values (4 = REG_DWORD).
    Set-LabGpo $DefaultDomainPolicy 'System Access' $Password
    $values = @{}
    foreach ($name in $Security.Keys) {
        $path = $SecurityKeys[$name] -replace '^HKLM:\\SYSTEM', 'MACHINE\System'
        $values["$path\$name"] = "4,$($Security[$name])"
    }
    Set-LabGpo $DefaultDCPolicy 'Registry Values' $values
    gpupdate /force | Out-Null

    # Fail the provisioner now if a setting did not take, rather than record the wrong profile.
    $policy = Get-ADDefaultDomainPasswordPolicy
    $effective = @{
        MinimumPasswordLength = $policy.MinPasswordLength
        PasswordComplexity = [int]$policy.ComplexityEnabled
        LockoutBadCount = $policy.LockoutThreshold
        ClearTextPassword = [int]$policy.ReversibleEncryptionEnabled
    }
    foreach ($name in $Security.Keys) {
        $effective[$name] = (Get-ItemProperty $SecurityKeys[$name]).$name
    }
    foreach ($name in @($Password.Keys) + @($Security.Keys)) {
        $want = if ($Password.ContainsKey($name)) { $Password[$name] } else { $Security[$name] }
        if ($effective.ContainsKey($name) -and "$($effective[$name])" -ne "$want") {
            throw "policy did not apply: $name is $($effective[$name]), expected $want"
        }
    }
}
