# Weak profile (after guard_lab, on the `base` snapshot): one misconfiguration per Linux check
# in checks/linux/. Lab only: these VMs sit on an isolated host-only network.

echo "profile=weak" >> /etc/posture-lab
. /etc/os-release

# SSH (LNX-SSH-001..008). sshd keeps the first value it reads, so a 00- drop-in wins.
cat > /etc/ssh/sshd_config.d/00-posture-lab.conf << 'EOF'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
DisableForwarding no
Ciphers +aes128-cbc,aes256-cbc
MACs +hmac-sha1
KexAlgorithms +diffie-hellman-group14-sha1
EOF
sshd -t
systemctl try-reload-or-restart ssh 2> /dev/null || systemctl try-reload-or-restart sshd

# Accounts and sudo (LNX-ACC-001/002, LNX-SUDO-001..003).
id toor > /dev/null 2>&1 || useradd -o -u 0 -g 0 -M -d /root -s /bin/bash -c "backup root" toor
id guest > /dev/null 2>&1 || useradd -m -s /bin/bash guest
passwd -d guest
id alice > /dev/null 2>&1 || useradd -m -s /bin/bash alice
echo 'alice ALL=(ALL) NOPASSWD: ALL' > /tmp/90-posture-lab-alice
visudo -cf /tmp/90-posture-lab-alice
install -m 440 /tmp/90-posture-lab-alice /etc/sudoers.d/90-posture-lab-alice
if grep -qE '^Defaults\s+use_pty' /etc/sudoers; then
    sed -E 's/^(Defaults\s+use_pty)/#\1/' /etc/sudoers > /tmp/sudoers.weak
    visudo -cf /tmp/sudoers.weak
    install -m 440 /tmp/sudoers.weak /etc/sudoers
fi

# Files (LNX-FILE-001..005).
chmod 644 /etc/shadow
chmod g+w /etc/group
chmod 644 /etc/ssh/sshd_config
printf '#!/bin/sh\n# posture lab: world-writable on purpose\n' > /etc/cron.daily/posture-lab-backup
chmod 777 /etc/cron.daily/posture-lab-backup
chmod u+s /usr/bin/find

# Firewall (LNX-FW-001/002).
if [ "$ID" = ubuntu ]; then
    ufw --force disable
else
    systemctl disable --now firewalld
fi

# Updates (LNX-UPD-001..003): refresh the cache so the box's pending security updates show,
# then backdate it and turn off everything that would refresh or install on its own.
if [ "$ID" = ubuntu ]; then
    apt-get update -q
    touch -d '40 days ago' /var/lib/apt/lists
    printf 'APT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Unattended-Upgrade "0";\n' \
        > /etc/apt/apt.conf.d/20auto-upgrades
    systemctl disable --now apt-daily.timer apt-daily-upgrade.timer
else
    dnf -q makecache
    touch -d '40 days ago' /var/cache/dnf
    systemctl disable --now dnf-makecache.timer
fi

# Logging (LNX-LOG-001..003).
if [ "$ID" = rocky ]; then
    systemctl disable auditd
    service auditd stop # auditd refuses `systemctl stop`
    auditctl -D
fi
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\n' > /etc/systemd/journald.conf.d/00-posture-lab.conf
systemctl restart systemd-journald
