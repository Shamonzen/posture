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
A service principal (or your own `az login` identity) with read-only rights on the
subscription and in Microsoft Graph. Posture makes 10 fixed GET requests
(`REQUESTS` in [`collectors/azure.py`](../src/posture/collectors/azure.py)); the HTTP client
refuses any other method before it is sent.

| Right | Where | Used by |
|---|---|---|
| **Reader** role | the subscription | subscription, storage accounts, NSGs, Activity Log diagnostic settings, Defender plans |
| `Policy.Read.All` | Microsoft Graph, application | Security Defaults, Conditional Access policies, authorization policy (guest settings) |
| `RoleManagement.Read.Directory` | Microsoft Graph, application | Global Administrator role assignments |
| `Directory.Read.All` | Microsoft Graph, application | the principal (name, user or app) expanded on each assignment |
| `AuditLog.Read.All` | Microsoft Graph, application | admins' MFA registration (`userRegistrationDetails`, needs Entra ID P1 or P2) |

Without one of them, the facts it feeds are `error` (Conditional Access unreadable and Security
Defaults off: the MFA and legacy-auth checks are `error`, not a pass). Reader can't read storage
keys or secrets, and Posture never asks for them.

Create the app registration once, as someone who can grant admin consent (Privileged Role
Administrator or Global Administrator) and assign roles on the subscription (Owner or User
Access Administrator):

```bash
SUB=<subscription-id>
APP=$(az ad app create --display-name posture-reader --query appId -o tsv)
az ad sp create --id "$APP"
az role assignment create --assignee "$APP" --role Reader --scope "/subscriptions/$SUB"
GRAPH=00000003-0000-0000-c000-000000000000
for p in Policy.Read.All RoleManagement.Read.Directory Directory.Read.All AuditLog.Read.All; do
  id=$(az ad sp show --id $GRAPH --query "appRoles[?value=='$p'].id" -o tsv)
  az ad app permission add --id "$APP" --api $GRAPH --api-permissions "$id=Role"
done
az ad app permission admin-consent --id "$APP"
az ad app credential reset --id "$APP"  # prints the secret once: keep it out of the repo
```

Then run with `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` in the
environment (or a certificate / federated credential, which `azure-identity` also reads):
`uv run posture collect azure --subscription "$SUB" -o out/azure.json`. An `az login` user
(Reader plus Global Reader, say) also works for a quick look, but the Azure CLI's own Graph token
may not carry every scope above; whatever it can't read comes out as `error`. Remove the app (`az ad app delete --id "$APP"`) when the audit is done.
