#!/usr/bin/env bash
# Posture lab driver. Runs vagrant only from lab/ and only on the posture-* VMs, always named
# explicitly (CLAUDE.md, hard rule 3). Usage: bash lab/lab.sh <command>
set -euo pipefail

LAB="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$LAB")"
VMS=(posture-ubuntu posture-rocky)
cd "$LAB"

usage() {
    cat << 'EOF'
up                 create/start the VMs; first time: base provisioning + `base` snapshot
weak | hardened [vm...]   restore `base`, then apply that profile (default: every VM)
record <profile>   audit each VM and save the recordings to tests/fixtures/recordings/<os>-<profile>
test               pytest -m lab against the running VMs
status | halt      show or stop the VMs
destroy            delete the VMs (and their known host keys)
EOF
}

keys() {
    if [ ! -f keys/posture_ed25519 ]; then
        mkdir -p keys
        ssh-keygen -q -t ed25519 -N "" -C posture-lab -f keys/posture_ed25519
    fi
}

case "${1:-}" in
    up)
        keys
        vagrant up "${VMS[@]}"
        for vm in "${VMS[@]}"; do
            vagrant snapshot list "$vm" | grep -qw base || vagrant snapshot save "$vm" base
        done
        ;;
    weak | hardened)
        targets=("${@:2}")
        [ ${#targets[@]} -gt 0 ] || targets=("${VMS[@]}")
        for vm in "${targets[@]}"; do
            [[ " ${VMS[*]} " == *" $vm "* ]] || { echo "unknown lab VM: $vm" >&2; exit 1; }
        done
        for vm in "${targets[@]}"; do
            vagrant snapshot restore --no-provision "$vm" base
            vagrant provision "$vm" --provision-with "$1"
        done
        ;;
    record)
        profile="${2:?usage: lab.sh record weak|hardened}"
        cd "$ROOT"
        for vm in "${VMS[@]}"; do
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
    status) vagrant status "${VMS[@]}" ;;
    halt) vagrant halt "${VMS[@]}" ;;
    destroy)
        vagrant destroy -f "${VMS[@]}"
        rm -f keys/known_hosts
        ;;
    *)
        usage
        exit 1
        ;;
esac
