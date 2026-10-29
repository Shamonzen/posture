#!/usr/bin/env bash
# Posture lab driver. Runs vagrant only from lab/ and only on the posture-* VMs, always named
# explicitly (CLAUDE.md, hard rule 3). Usage: bash lab/lab.sh <command>
set -euo pipefail

LAB="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$LAB")"
VMS=(posture-dc posture-ubuntu posture-rocky)
LINUX_VMS=(posture-ubuntu posture-rocky) # the DC is recorded by the AD collectors (milestone 9)
cd "$LAB"

usage() {
    cat << 'EOF'
up [vm...]                create/start the VMs; first time: base provisioning + `base` snapshot
weak | hardened [vm...]   restore `base`, then apply that profile
record <profile>          audit each Linux VM and save the recordings to tests/fixtures/recordings/<os>-<profile>
test                      pytest -m lab against the running VMs
status | halt [vm...]     show or stop the VMs
destroy [vm...]           delete the VMs (and their known host keys)
[vm...] defaults to every VM: posture-dc posture-ubuntu posture-rocky
EOF
}

keys() {
    if [ ! -f keys/posture_ed25519 ]; then
        mkdir -p keys
        ssh-keygen -q -t ed25519 -N "" -C posture-lab -f keys/posture_ed25519
    fi
}

# The VMs named after the command (default: all), each one checked against VMS.
targets=("${@:2}")
[ "${1:-}" != record ] || targets=()
[ ${#targets[@]} -gt 0 ] || targets=("${VMS[@]}")
for vm in "${targets[@]}"; do
    [[ " ${VMS[*]} " == *" $vm "* ]] || { echo "unknown lab VM: $vm" >&2; exit 1; }
done

case "${1:-}" in
    up)
        keys
        for vm in "${targets[@]}"; do
            if [ "$vm" = posture-dc ] && ! vagrant snapshot list "$vm" 2> /dev/null | grep -qw base; then
                # Promote, then reboot from outside: the new DC refuses WinRM logons until it has
                # rebooted, so `vagrant reload` hangs on its graceful shutdown and ACPI is ignored.
                # A hard power-off is safe once promotion has finished.
                vagrant up "$vm" --provision-with promote
                VBoxManage controlvm "$vm" poweroff
                vagrant up "$vm" --no-provision
                vagrant provision "$vm" --provision-with base
            else
                vagrant up "$vm"
            fi
            vagrant snapshot list "$vm" | grep -qw base || vagrant snapshot save "$vm" base
        done
        ;;
    weak | hardened)
        for vm in "${targets[@]}"; do
            vagrant snapshot restore --no-provision "$vm" base
            vagrant provision "$vm" --provision-with "$1"
        done
        ;;
    record)
        profile="${2:?usage: lab.sh record weak|hardened}"
        cd "$ROOT"
        for vm in "${LINUX_VMS[@]}"; do
            ssh -F lab/ssh-config -o BatchMode=yes -o LogLevel=ERROR "$vm" cat /etc/posture-lab | grep -qx "profile=$profile" \
                || { echo "$vm is not on the $profile profile (run: lab.sh $profile)" >&2; exit 1; }
            dir="tests/fixtures/recordings/${vm#posture-}-$profile"
            rm -rf "$dir"
            uv run posture collect linux --ssh "$vm" --ssh-config lab/ssh-config \
                --record "$dir" -o "out/${vm#posture-}-$profile.json"
        done
        ;;
    test)
        cd "$ROOT"
        uv run pytest -m lab
        ;;
    status) for vm in "${targets[@]}"; do vagrant status "$vm"; done ;;
    halt) for vm in "${targets[@]}"; do vagrant halt "$vm"; done ;;
    destroy)
        for vm in "${targets[@]}"; do vagrant destroy -f "$vm"; done
        rm -f keys/known_hosts
        ;;
    *)
        usage
        exit 1
        ;;
esac
