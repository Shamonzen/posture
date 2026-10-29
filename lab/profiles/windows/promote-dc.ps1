# Promote provisioner (after guard_lab): runs once at the first `vagrant up`. Marks the VM as
# the lab DC and promotes it to a new forest, posture.test (.test is reserved, so it can never
# collide with a real domain). Vagrant reboots it afterwards; the base provisioner follows.

New-Item 'HKLM:\SOFTWARE\PostureLab' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\PostureLab' -Name vm -Value posture-dc
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { return }  # already a DC

$admin = Get-LabSecret LAB_DOMAIN_ADMIN_PASSWORD
# The local Administrator becomes the domain Administrator: give it the lab password first.
Set-LocalUser Administrator -Password $admin
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Install-ADDSForest -DomainName posture.test -DomainNetbiosName POSTURE -InstallDns `
    -SafeModeAdministratorPassword $admin -NoRebootOnCompletion -Force | Out-Null
