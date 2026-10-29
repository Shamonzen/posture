# Hardened profile (after guard_lab, on the `base` snapshot): every check in checks/linux/
# passes. Mostly the checks' own remediation scripts.

echo "profile=hardened" >> /etc/posture-lab
. /etc/os-release

# SSH.
cat > /etc/ssh/sshd_config.d/00-posture-lab.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 4
DisableForwarding yes
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
EOF
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
sshd -t
systemctl try-reload-or-restart ssh 2> /dev/null || systemctl try-reload-or-restart sshd

# Setuid review (LNX-FILE-005): the VirtualBox Guest Additions install VBoxDRMClient setuid
# root for desktop resizing, which a headless server doesn't need.
chmod u-s /opt/VBoxGuestAdditions-*/bin/VBoxDRMClient 2> /dev/null || true

# sudo defaults.
printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\n' > /tmp/00-posture-defaults
visudo -cf /tmp/00-posture-defaults
install -m 440 /tmp/00-posture-defaults /etc/sudoers.d/00-posture-defaults

# Firewall: allow SSH before turning it on.
if [ "$ID" = ubuntu ]; then
    ufw allow OpenSSH
    ufw default deny incoming
    ufw --force enable
else
    systemctl enable --now firewalld
    firewall-cmd --permanent --zone=public --set-target=default
    firewall-cmd --permanent --zone=public --add-service=ssh
    firewall-cmd --reload
fi

# Updates: install what's pending, then keep it automatic.
if [ "$ID" = ubuntu ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get -y -q upgrade
    apt-get -y -q install unattended-upgrades
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
        > /etc/apt/apt.conf.d/20auto-upgrades
else
    dnf -y -q upgrade --security
    dnf -y -q install dnf-automatic
    systemctl enable --now dnf-automatic-install.timer
fi

# Logging.
if [ "$ID" = ubuntu ]; then
    apt-get -y -q install auditd
fi
printf '%s\n' '-w /etc/passwd -p wa -k identity' '-w /etc/shadow -p wa -k identity' \
    '-w /etc/group -p wa -k identity' '-w /etc/gshadow -p wa -k identity' \
    '-w /etc/sudoers -p wa -k scope' '-w /etc/sudoers.d -p wa -k scope' \
    > /etc/audit/rules.d/50-posture.rules
augenrules --load
systemctl enable --now auditd
mkdir -p /etc/systemd/journald.conf.d /var/log/journal
printf '[Journal]\nStorage=persistent\n' > /etc/systemd/journald.conf.d/00-posture-lab.conf
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald

# The box's well-known "vagrant" passwords.
passwd -l root
passwd -l vagrant

# Last: Vagrant's own `vagrant ALL=(ALL) NOPASSWD: ALL` fails LNX-SUDO-001 like any other such
# rule. After this, `vagrant provision` can't sudo on this VM; lab.sh always restores the
# `base` snapshot before applying a profile, so that's fine.
# Ubuntu's box grants it to the user, Rocky's to the %vagrant group.
vagrant_sudoers="$(grep -rlE '^%?vagrant\s' /etc/sudoers.d || true)"
if [ -n "$vagrant_sudoers" ]; then
    rm -f $vagrant_sudoers
fi
