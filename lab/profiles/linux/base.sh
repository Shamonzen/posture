# Base provisioner (after guard_lab): runs once at the first `vagrant up`; lab.sh then saves
# the `base` snapshot that both profiles start from.

echo "vm=$(hostname)" > /etc/posture-lab
. /etc/os-release

# The audit account: SSH key only, sudo limited to the exact commands in deploy/sudoers.posture.
id posture > /dev/null 2>&1 || useradd -m -s /bin/bash -c "Posture audit" posture
passwd -l posture
install -d -m 700 -o posture -g posture /home/posture/.ssh
install -m 600 -o posture -g posture /tmp/posture_ed25519.pub /home/posture/.ssh/authorized_keys
visudo -cf /tmp/sudoers.posture
install -m 440 /tmp/sudoers.posture /etc/sudoers.d/posture

# firewalld must exist on Rocky so the weak profile can stop it (firewall-cmd then reports
# "not running" instead of "command not found").
if [ "$ID" = rocky ]; then
    dnf -y -q install firewalld
fi
