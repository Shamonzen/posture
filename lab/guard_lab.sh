#!/usr/bin/env bash
# Prepended by the Vagrantfile to every lab profile script: refuse to run anywhere but a
# Posture lab VM. Checks the exact hostname, an address on the lab's host-only network, and
# (except for the base provisioner, which creates it) the lab marker file.
set -euo pipefail

guard_lab() {
    local marker="${POSTURE_LAB_MARKER:-/etc/posture-lab}"
    case "$(hostname)" in
        posture-ubuntu | posture-rocky) ;;
        *)
            echo "guard_lab: '$(hostname)' is not a Posture lab VM, refusing to run" >&2
            exit 1
            ;;
    esac
    if ! ip -4 -o addr show | grep -q ' inet 192\.168\.57\.'; then
        echo "guard_lab: no address in 192.168.57.0/24, refusing to run" >&2
        exit 1
    fi
    if [ "${POSTURE_LAB_BASE:-0}" != 1 ] && [ ! -f "$marker" ]; then
        echo "guard_lab: $marker is missing (the base provisioner never ran here), refusing to run" >&2
        exit 1
    fi
}

guard_lab
