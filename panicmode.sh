#!/bin/bash

# Author: root0emir
# Securonis GNU/Linux Panic Mode Script 
# Version : 1.0

# Tor durumunu kontrol etme 
check_tor_status() {
    tor_check=$(curl -s https://check.torproject.org/api/ip)
    if echo "$tor_check" | grep -q '"IsTor":true'; then
        echo "Tor is running."
    else
        echo "Tor is not running."
    fi
}

# DNS sızıntı testi
dns_leak_test() {
    echo "Checking DNS Leak..."
    dig +short @resolver1.opendns.com myip.opendns.com
}

# VPN durumunu kontrol etme
check_vpn_status() {
    if ip a | grep -q "tun0"; then
        echo "VPN is running."
    else
        echo "VPN is not running."
    fi
}

# Sistem durumu bilgilerini gösterme
system_status() {
    echo "Uptime: $(uptime -p)"
    echo "Load Average: $(cat /proc/loadavg)"
    echo "RAM Usage: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
    echo "CPU Usage: $(top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\([0-9.]*\)%* id.*/\1/' | awk '{print 100 - $1}')%"
    echo "-------------------------------------"
    echo "Disk Usage:"
    df -h
}

# Sistem bilgilerini gösterme
system_info() {
    echo "OS: $(lsb_release -ds)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "CPU Info: $(lscpu | grep 'Model name')"
    echo "Memory Info: $(free -h)"
    echo "Disk Info: $(lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,UUID)"
}

# Ağ durumunu gösterme
network_status() {
    ip a | grep inet
}

# IP adresini kontrol etme
check_ip() {
    curl ifconfig.me
}

# DNS sunucusunu değiştirme
change_dns() {
    echo "Changing DNS to Cloudflare (1.1.1.1)..."
    echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
}

# Ağ izlerini silme (BleachBit kullanarak)
delete_network_traces() {
    echo "Deleting network traces with BleachBit..."
    sudo apt-get install -y bleachbit
    bleachbit -c system.cache system.recent_documents system.tmp system.trash
    echo "Network traces deleted."
}

# Gizlilik durumunu kontrol etme
check_privacy_status() {
    echo "Checking privacy settings..."
    ps aux | grep tor
    sudo ufw status
    sudo apparmor_status
}

# Güvenlik taraması yapma
security_scan() {
    echo "Running detailed security scan..."
    sudo apt install -y clamav
    sudo freshclam
    sudo clamscan -r --bell -i --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" /
}

# İzleri temizleme
cleaning_traces() {
    echo "Cleaning traces..."
    history -c && history -w
    rm -rf ~/.cache ~/.bash_history ~/.zsh_history ~/.mozilla/firefox/*.default-release/places.sqlite ~/.config/google-chrome/Default/History
    sudo rm -rf /tmp/* /var/tmp/* /var/log/*
    echo "Traces cleaned."
}

# RAM'i silme
wipe_ram() {
    echo "Wiping RAM..."
    sync; echo 3 > /proc/sys/vm/drop_caches
    sudo sh -c "echo 1 > /proc/sys/vm/drop_caches"
}

# Diski güvenli bir şekilde silme
wipe_disk() {
    read -p "Enter the disk to wipe (e.g., /dev/sdX): " disk
    sudo shred -v -n 5 -z "$disk"
}

# Hostname'i değiştirme
change_hostname() {
    read -p "Enter new hostname: " new_host
    sudo hostnamectl set-hostname "$new_host"
}

# Fiziksel güvenliği etkinleştirme
physical_security() {
    echo "Activating physical security measures..."

    # USB portlarını engelle
    echo "Disabling USB ports..."
    sudo sh -c "echo 'blacklist usb-storage' > /etc/modprobe.d/blacklist-usb.conf"

    # Tüm aktif oturumları kilitle
    echo "Locking all active sessions..."
    sudo pkill -KILL -u $(whoami)

    # Ekran ve klavye girişlerini engelle
    echo "Disabling screen/keyboard input..."
    sudo setterm -blank force

    # Eğer TPM varsa, TPM güvenliği etkinleştir
    echo "Enabling TPM security
   
    # Donanım güvenliği
    echo "Physical security measures are now in place."
}

# Çekirdek güvenlik durumunu kontrol etme
check_kernel_security_status() {
    echo "Checking kernel security status..."
    sudo /usr/local/bin/kernelcheck
}

# Paranoia modunu etkinleştirme
activate_paranoia_mode() {
    echo "Activating paranoia mode..."
    sudo /usr/local/bin/paranoia
}

# Paranoia modunu devre dışı bırakma
deactivate_paranoia_mode() {
    echo "Deactivating paranoia mode..."
    sudo /usr/local/bin/paranoiadeactivate
}

# Sistemi yok etme
nuke_the_system() {
    echo "Nuking the system..."
    sudo /usr/local/bin/nuke2system
}

# Disk şifrelemesi kontrolü
check_disk_encryption() {
    echo "Checking disk encryption..."
    sudo lsblk -o NAME,FSTYPE,MOUNTPOINT,UUID
}

# Güvenlik güncellemelerini kontrol etme
check_security_updates() {
    echo "Checking for security updates..."
    sudo apt update && sudo apt list --upgradable | grep -i security
}

# Tüm IP bilgilerini kontrol etme
check_all_ip_info() {
    echo "Checking all IP information..."
    curl ifconfig.me/all
}

# MAC adresini spoof etme
spoof_mac() {
    read -p "Enter network interface (e.g., eth0, wlan0): " iface
    sudo ifconfig "$iface" down
    sudo macchanger -r "$iface"
    sudo ifconfig "$iface" up
    echo "MAC address spoofed."
}

# Boş alanı silme
wipe_free_space() {
    echo "Wiping free space..."
    sudo dd if=/dev/zero of=/zerofillfile bs=1M
    sudo rm -f /zerofillfile
    echo "Free space wiped."
}

# SSL/TLS fingerprint doğrulama
ssl_tls_fingerprint_verification() {
    read -p "Enter domain to verify: " domain
    echo | openssl s_client -connect "$domain":443 2>/dev/null | openssl x509 -fingerprint -noout
}

# Firewall kurallarını sıkılaştırma
harden_firewall() {
    echo "Hardening firewall rules..."
    sudo ufw default deny incoming
    sudo ufw default deny outgoing
    sudo ufw enable
    echo "Firewall hardened."
}

# Ağ trafiğini izleme
monitor_network_traffic() {
    echo "Monitoring network traffic..."
    sudo iftop -i $(ip route | grep '^default' | awk '{print $5}')
}

# Güvenli dosya silme
secure_delete() {
    read -p "Enter file or directory to securely delete: " target
    sudo srm -rv "$target"
}

# ASCII giriş menüsü
while true; do
    clear
    echo "====================================="
    echo "         System and Network          "
    echo "====================================="
    echo "Hostname: $(hostname)"
    echo "IP Address: $(hostname -I | awk '{print $1}')"
    echo "====================================="
    echo "           System Status             "
    echo "====================================="
    system_status
    echo "====================================="
    echo "           System Info               "
    echo "====================================="
    system_info
    echo "====================================="
    echo "           Network Info              "
    echo "====================================="
    network_status
    echo "====================================="
    echo "              Menu                   "
    echo "====================================="
    echo "1) Check IP"
    echo "2) DNS Leak Test"
    echo "3) Change DNS"
    echo "4) Delete Network Traces"
    echo "5) Check Privacy Status"
    echo "6) Check Tor Status"
    echo "7) Security Scan (ClamAV)"
    echo "8) Cleaning Traces"
    echo "9) Wipe RAM"
    echo "10) Wipe Disk"
    echo "11) Change Hostname"
    echo "12) Check Kernel Security Status"
    echo "13) Activate Paranoia Mode"
    echo "14) Deactivate Paranoia Mode"
    echo "15) Activate Physical Security"
    echo "16) Nuke The System"
    echo "17) Check Disk Encryption"
    echo "18) Check Security Updates"
    echo "19) Check VPN Status"
    echo "20) Check All IP Information"
    echo "21) Spoof MAC Address"
    echo "22) Wipe Free Space"
    echo "23) SSL/TLS Fingerprint Verification"
    echo "24) Harden Firewall"
    echo "25) Monitor Network Traffic"
    echo "26) Secure Delete"
    echo "0) Exit"
    echo "====================================="
    read -p "Choose an option: " choice
    
    case $choice in
        1) check_ip ;;
        2) dns_leak_test ;;
        3) change_dns ;;
        4) delete_network_traces ;;
        5) check_privacy_status ;;
        6) check_tor_status ;;
        7) security_scan ;;
        8) cleaning_traces ;;
        9) wipe_ram ;;
        10) wipe_disk ;;
        11) change_hostname ;;
        12) check_kernel_security_status ;;
        13) activate_paranoia_mode ;;
        14) deactivate_paranoia_mode ;;
        15) physical_security ;;
        16) nuke_the_system ;;  
        17) check_disk_encryption ;;
        18) check_security_updates ;;
        19) check_vpn_status ;;
        20) check_all_ip_info ;;
        21) spoof_mac ;;
        22) wipe_free_space ;;
        23) ssl_tls_fingerprint_verification ;;
        24) harden_firewall ;;
        25) monitor_network_traffic ;;
        26) secure_delete ;;
        0) exit 0 ;;
        *) echo "Invalid option. Try again." ;;
    esac
    read -p "Press Enter to continue..." dummy
done
