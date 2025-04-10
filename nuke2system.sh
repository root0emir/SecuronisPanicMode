#!/bin/bash

# Warning: This script will securely destroy the system. All data will be lost. This action is irreversible.
echo "WARNING: This script will securely destroy the system. All data will be lost. This action is irreversible."
echo "NOTE: Ensure that you are running this script with root permissions."

echo "This action will:"
echo "1. Overwrite all files with random data."
echo "2. Delete all system logs."
echo "3. Overwrite and delete all user home directories."
echo "4. Overwrite swap space."
echo "5. Overwrite and delete the root directory."
echo "6. Overwrite and delete the boot directory."
echo "7. Overwrite all partitions with random data."
echo "8. Reboot the system."

echo "Type 'EXIT' at any prompt to cancel the operation and exit."

read -p "Are you absolutely sure you want to proceed? Type 'YES' to continue: " confirmation
if [[ "$confirmation" == "EXIT" ]]; then
    echo "Operation cancelled."
    exit 1
elif [[ "$confirmation" != "YES" ]]; then
    echo "Operation cancelled."
    exit 1
fi

read -p "This will permanently delete all data. Type 'DELETE' to confirm: " delete_confirmation
if [[ "$delete_confirmation" == "EXIT" ]]; then
    echo "Operation cancelled."
    exit 1
elif [[ "$delete_confirmation" != "DELETE" ]]; then
    echo "Operation cancelled."
    exit 1
fi

read -p "This action is irreversible. Type 'I UNDERSTAND' to proceed: " understand_confirmation
if [[ "$understand_confirmation" == "EXIT" ]]; then
    echo "Operation cancelled."
    exit 1
elif [[ "$understand_confirmation" != "I UNDERSTAND" ]]; then
    echo "Operation cancelled."
    exit 1
fi

echo "Starting secure system destruction in 10 seconds..."
sleep 10

# Function to securely delete files and directories
secure_delete() {
    local target=$1
    if [[ -e $target ]]; then
        echo "Overwriting and deleting $target..."
        dd if=/dev/urandom of=$target bs=1M status=progress || true
        rm -rf $target
    fi
}

# Overwrite files with random data and then delete them
echo "Overwriting and deleting all files..."
find / -type f -exec sh -c 'dd if=/dev/urandom of={} bs=1M status=none; rm -f {}' \; || true

# Overwrite and delete system logs
secure_delete /var/log/syslog
secure_delete /var/log/auth.log

# Overwrite and delete user home directories
for user_home in /home/*; do
    secure_delete $user_home
done

# Overwrite swap space
swap_device=$(swapon --show=NAME --noheadings)
if [[ -n "$swap_device" ]]; then
    echo "Overwriting swap space..."
    swapoff $swap_device
    dd if=/dev/urandom of=$swap_device bs=1M status=progress || true
    mkswap $swap_device
    swapon $swap_device
fi

# Overwrite and delete root directory
secure_delete /root

# Overwrite and delete boot directory
secure_delete /boot

# Overwrite and delete all partitions
for partition in $(lsblk -ln -o NAME | grep -v '^loop' | grep -v '^ram' | grep -v 'boot'); do
    echo "Overwriting /dev/$partition..."
    dd if=/dev/urandom of=/dev/$partition bs=1M status=progress || true
done

# Additional security measures
echo "Clearing inodes and file system journals..."
find / -type f -exec chattr +s {} \;
find / -type f -exec wipe -q -Q 3 -f {} \;

echo "Clearing memory..."
sync
echo 3 > /proc/sys/vm/drop_caches
swapoff -a && swapon -a

# Sync and reboot
sync
echo "System destruction complete. Rebooting now..."
reb
