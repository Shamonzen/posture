# Prepended by the Vagrantfile to every Windows lab profile script: refuse to run anywhere but
# the Posture lab DC. Checks the exact hostname, an address on the lab's host-only network, and
# (except for the promote provisioner, which creates it) the lab marker registry key.
$ErrorActionPreference = 'Stop'

function guard_lab {
    $marker = if ($env:POSTURE_LAB_MARKER) { $env:POSTURE_LAB_MARKER } else { 'HKLM:\SOFTWARE\PostureLab' }
    if ($env:COMPUTERNAME -ne 'posture-dc') {
        Write-Error "guard_lab: '$env:COMPUTERNAME' is not a Posture lab VM, refusing to run" -ErrorAction Continue
        exit 1
    }
    if (-not (Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -like '192.168.57.*')) {
        Write-Error 'guard_lab: no address in 192.168.57.0/24, refusing to run' -ErrorAction Continue
        exit 1
    }
    if ($env:POSTURE_LAB_BASE -ne '1' -and -not (Test-Path $marker)) {
        Write-Error "guard_lab: $marker is missing (the promote provisioner never ran here), refusing to run" -ErrorAction Continue
        exit 1
    }
}

guard_lab
