# Permissions

Posture only reads. Each target gets the least an audit needs; a fact it can't read with these
rights is reported as `error`, never as a pass.

## Linux
A dedicated `posture` user over an SSH key. [`deploy/sudoers.posture`](../deploy/sudoers.posture)
allows exactly the commands that need root, with exact arguments.

## Active Directory (LDAP)
An ordinary domain user, over LDAPS with the DC's certificate verified (`--ca-file` to pin it).
Any authenticated user can read the objects the AD checks use. LAPS passwords are never
requested, only their expiry times.

## Domain controller host settings (WinRM, `--winrm`)
The same account, which also needs:

- membership of **Remote Management Users** on the DC (WinRM logon, no admin rights);
- read access to one registry key that ordinary users can't read,
  `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` (LDAP signing). Without it, the LDAP
  signing check reports `error`. Grant it on each DC, as an administrator:

```powershell
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$acl = Get-Acl $key
$acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new('DOMAIN\posture', 'ReadKey', 'Allow'))
Set-Acl $key $acl
```

The other keys (`LanmanServer\Parameters`, `Control\Lsa`) are readable by any user. Posture
runs one fixed `Get-Item` script per key and reads named values only. WinRM runs on HTTP 5985
with NTLM: the password is never sent, and every message is sealed. Upgrade path: a JEA
endpoint that exposes only these reads, or HTTPS 5986.

## Azure
Milestone 11.
