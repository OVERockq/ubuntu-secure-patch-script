#!/bin/bash
# 시스템 패키지를 업데이트하고 업그레이드합니다.
# - update_system: 시스템 패키지를 업데이트하고 업그레이드합니다.
# - configure_automatic_updates: 자동 업데이트를 설정합니다.
# - configure_firewall: UFW를 사용하여 방화벽을 설정하고 기본 정책을 설정합니다.
# - disable_unused_filesystems: 사용하지 않는 파일 시스템을 비활성화합니다.
# - set_password_policies: 강력한 비밀번호 정책을 설정합니다.
# - disable_root_login: 루트 로그인 비활성화합니다.
# - configure_ssh: SSH 설정을 강화합니다.
# - configure_auditd: 시스템 감사 로그를 설정하고 시작합니다.
# - setup_log_rotation: 로그 회전을 설정합니다.
# - configure_user_permissions: 사용자 권한과 디렉토리를 설정합니다.
# - configure_logging: 시스템 로그 설정을 강화합니다.
# - configure_rkhunter: 루트킷 검사를 위한 rkhunter를 설정합니다.
# - configure_fail2ban: 비정상 로그인 시도를 방지하기 위해 fail2ban을 설치하고 설정합니다.

# Function to update and upgrade the system
update_system() {
    sudo apt-get update -y || { echo "Failed to update package list"; exit 1; }
    sudo apt-get upgrade -y || { echo "Failed to upgrade packages"; exit 1; }
    sudo apt-get dist-upgrade -y || { echo "Failed to perform dist-upgrade"; exit 1; }
    sudo apt-get autoremove -y || { echo "Failed to remove unused packages"; exit 1; }
    sudo apt-get autoclean -y || { echo "Failed to clean up"; exit 1; }
    echo "System updated and upgraded"
}

# Function to configure automatic updates
configure_automatic_updates() {
    sudo apt-get install unattended-upgrades -y || { echo "Failed to install unattended-upgrades"; exit 1; }
    sudo dpkg-reconfigure --priority=low unattended-upgrades || { echo "Failed to configure unattended-upgrades"; exit 1; }
    echo "Automatic updates configured"
}

# Function to configure firewall using UFW
configure_firewall() {
    load_config
    sudo apt-get install ufw -y
    sudo ufw default $UFW_DEFAULT_INCOMING incoming
    sudo ufw default $UFW_DEFAULT_OUTGOING outgoing
    sudo ufw allow from $UFW_ALLOW_IP1 to any port $UFW_ALLOW_PORT_SSH
    sudo ufw allow from $UFW_ALLOW_IP2 to any port $UFW_ALLOW_PORT_SSH
    sudo ufw disable
    echo "Firewall configured and disabled. After Development, set enable."
}

# Function to disable unused filesystems
disable_unused_filesystems() {
    echo "install cramfs /bin/true" | sudo tee -a /etc/modprobe.d/cramfs.conf
    echo "install freevxfs /bin/true" | sudo tee -a /etc/modprobe.d/freevxfs.conf
    echo "install jffs2 /bin/true" | sudo tee -a /etc/modprobe.d/jffs2.conf
    echo "install hfs /bin/true" | sudo tee -a /etc/modprobe.d/hfs.conf
    echo "install hfsplus /bin/true" | sudo tee -a /etc/modprobe.d/hfsplus.conf
    echo "install squashfs /bin/true" | sudo tee -a /etc/modprobe.d/squashfs.conf
    echo "install udf /bin/true" | sudo tee -a /etc/modprobe.d/udf.conf
    echo "Unused filesystems disabled"
}

# Function to set password policies
set_password_policies() {
    load_config
    sudo apt-get install libpam-pwquality -y
    sudo sed -i 's/# \(.*pam_pwquality.so.*\)/\1/' /etc/pam.d/common-password
    sudo sed -i "/pam_pwquality.so/ s/\$/ retry=$PW_RETRY minlen=$PW_MINLEN difok=$PW_DIFOK/" /etc/pam.d/common-password
    echo "minlen = $PW_MINLEN" | sudo tee -a /etc/security/pwquality.conf
    echo "dcredit = $PW_D_CREDIT" | sudo tee -a /etc/security/pwquality.conf
    echo "ucredit = $PW_U_CREDIT" | sudo tee -a /etc/security/pwquality.conf
    echo "ocredit = $PW_O_CREDIT" | sudo tee -a /etc/security/pwquality.conf
    echo "lcredit = $PW_L_CREDIT" | sudo tee -a /etc/security/pwquality.conf
    echo "Password policies set"
}

# Function to disable root login
disable_root_login() {
    sudo passwd -l root
    echo "Root login disabled"
}

# Function to configure SSH
configure_ssh() {
    load_config
    sudo sed -i "s/^#*Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
    sudo sed -i "s/^#*PermitRootLogin .*/PermitRootLogin $SSH_PERMIT_ROOT_LOGIN/" /etc/ssh/sshd_config
    sudo sed -i "s/^#*PasswordAuthentication .*/PasswordAuthentication $SSH_PASSWORD_AUTH/" /etc/ssh/sshd_config
    sudo sed -i "s/^#*MaxAuthTries .*/MaxAuthTries $SSH_MAX_AUTH_TRIES/" /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo "SSH configuration updated"
}

# Function to configure auditd
configure_auditd() {
    sudo apt-get install auditd -y
    sudo systemctl enable auditd
    sudo systemctl start auditd
    echo "Auditd installed and enabled"
}

# Function to set up log rotation
setup_log_rotation() {
    sudo apt-get install logrotate -y
    sudo logrotate /etc/logrotate.conf
    echo "Log rotation set up"
}

# Function to configure user permissions and directories
configure_user_permissions() {
    sudo chmod -R go-w /home/*
    sudo chmod 700 /root
    sudo chmod 755 /etc
    echo "User permissions and directories configured"
}

# Function to configure system logging
configure_logging() {
    sudo apt-get install rsyslog -y
    sudo systemctl enable rsyslog
    sudo systemctl start rsyslog
    echo "System logging configured"
}

# Function to configure rkhunter
configure_rkhunter() {
    load_config
    sudo apt-get install rkhunter -y
    sudo rkhunter --update
    sudo rkhunter --propupd
    echo "$RKHUNTER_CRON_TIME root /usr/bin/rkhunter --check --cronjob" | sudo tee -a /etc/crontab
    echo "Rootkit Hunter installed and configured"
}

# Function to install and configure fail2ban
configure_fail2ban() {
    load_config
    sudo apt-get install fail2ban -y
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    echo "[sshd]
enabled = $FAIL2BAN_SSH_ENABLED
port = $FAIL2BAN_SSH_PORT
logpath = %(sshd_log)s
maxretry = $FAIL2BAN_MAXRETRY" | sudo tee /etc/fail2ban/jail.local
    sudo systemctl restart fail2ban
    echo "Fail2Ban installed and configured"
}

# Function to set ownership and permissions for /etc/shadow file
secure_shadow_file() {
    sudo chown root:shadow /etc/shadow
    sudo chmod 400 /etc/shadow
    echo "/etc/shadow file ownership and permissions set"
}

# Function to set ownership and permissions for /etc/passwd file
secure_passwd_file() {
    sudo chown root:root /etc/passwd
    sudo chmod 644 /etc/passwd
    echo "/etc/passwd file ownership and permissions set"
}

# Main script execution
main() {
    update_system
    configure_automatic_updates
    configure_firewall
    disable_unused_filesystems
    set_password_policies
    disable_root_login
    configure_ssh
    configure_auditd
    setup_log_rotation
    configure_user_permissions
    configure_logging
    configure_rkhunter
    configure_fail2ban
    secure_shadow_file
    secure_passwd_file
    set_timezone
    set_history_format
}

# 환경설정 함수 (히스토리 포맷 등)
set_history_format() {
    load_config
    export HISTTIMEFORMAT=$HISTTIMEFORMAT
    export HISTSIZE=$HISTSIZE
    echo "History format and size set"
}

# 국내시간으로 변경
sudo ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime

# History 포멧 변경
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
export HISTSIZE=4000

# usps.conf 파일이 없으면 생성 (기본값 포함)
if [ ! -f ./usps.conf ]; then
    cat <<EOF > ./usps.conf
# 시스템 기본 설정
TIMEZONE=Asia/Seoul

# SSH 설정
SSH_PORT=22
SSH_PERMIT_ROOT_LOGIN=no
SSH_PASSWORD_AUTH=no
SSH_MAX_AUTH_TRIES=3

# UFW 방화벽 설정
UFW_DEFAULT_INCOMING=deny
UFW_DEFAULT_OUTGOING=allow
UFW_ALLOW_IP1=192.168.0.0/22
UFW_ALLOW_IP2=172.16.0.0/16
UFW_ALLOW_PORT_SSH=22

# 비밀번호 정책
PW_MINLEN=12
PW_RETRY=3
PW_DIFOK=3
PW_D_CREDIT=-1
PW_U_CREDIT=-1
PW_O_CREDIT=-1
PW_L_CREDIT=-1

# Fail2Ban 설정
FAIL2BAN_SSH_ENABLED=true
FAIL2BAN_SSH_PORT=22
FAIL2BAN_MAXRETRY=3

# rkhunter 설정
RKHUNTER_CRON_TIME="0 1 * * *"

# 기타
HISTSIZE=4000
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
EOF
fi

# usps.conf 값 불러오기 함수
load_config() {
    source ./usps.conf
}

# Function to set timezone from usps.conf
set_timezone() {
    load_config
    sudo ln -sf /usr/share/zoneinfo/$TIMEZONE /etc/localtime
    echo "Timezone set to $TIMEZONE"
}

# whiptail 기반 메인 메뉴
show_menu() {
    while true; do
        CHOICE=$(whiptail --title "    Ubuntu 보안 패치 스크립트 1.0 by ikkcu    " --menu "원하는 작업을 선택하세요." 20 60 10 \
        "1" "보안 패치" \
        "2" "설정 수정" \
        "3" "종료" 3>&1 1>&2 2>&3)

        case $CHOICE in
            "1")
                run_patch_menu
                ;;
            "2")
                edit_config_menu
                ;;
            "3")
                exit 0
                ;;
            *)
                exit 1
                ;;
        esac
    done
}

# 보안 패치 실행 whiptail 체크리스트
run_patch_menu() {
    PATCH_OPTIONS=$(whiptail --scrolltext --title "    Ubuntu 보안 패치 스크립트 1.0 by ikkcu    " --checklist \
    "실행할 패치 항목을 선택하세요 (스페이스로 선택, 엔터로 실행):" 20 60 12 \
    "update_system" "시스템 업데이트" ON \
    "set_timezone" "시간대 설정" ON \
    "configure_automatic_updates" "자동 업데이트 설정" ON \
    "configure_firewall" "방화벽 설정" ON \
    "disable_unused_filesystems" "미사용 파일시스템 비활성화" ON \
    "set_password_policies" "비밀번호 정책 설정" ON \
    "disable_root_login" "루트 로그인 비활성화" ON \
    "configure_ssh" "SSH 설정 강화" ON \
    "configure_auditd" "감사 로그 설정" ON \
    "setup_log_rotation" "로그 회전 설정" ON \
    "configure_user_permissions" "사용자 권한/디렉토리 설정" ON \
    "configure_logging" "시스템 로그 설정" ON \
    "configure_rkhunter" "루트킷 검사 설정" ON \
    "configure_fail2ban" "Fail2Ban 설정" ON \
    "secure_shadow_file" "/etc/shadow 보안" ON \
    "secure_passwd_file" "/etc/passwd 보안" ON \
    3>&1 1>&2 2>&3)

    # 선택된 항목 실행
    for opt in $PATCH_OPTIONS; do
        opt=$(echo $opt | tr -d '"')
        $opt
    done
}

# 설정 수정 메뉴 (vi로 usps.conf 편집)
edit_config_menu() {
    vi ./usps.conf
}

# whiptail 메뉴 실행
show_menu
