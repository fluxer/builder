#!/bin/bash
# Builder - Bash script to build GNU/Linux Live CD/DVDs
#
# Copyright (c) 2012-2016, Ivailo Monev
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Redistributions in binary or source form shall be available free of charge
#    unless otherwise stated by Ivailo Monev.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

export LANG=C LC_ALL=C
unset ALL_OFF BOLD BLUE GREEN RED YELLOW
if [[ -t 2 ]]; then
    # prefer terminal safe colored and bold text when tput is supported
    if tput setaf 0 &>/dev/null; then
        ALL_OFF="$(tput sgr0)"
        BOLD="$(tput bold)"
        BLUE="${BOLD}$(tput setaf 4)"
        GREEN="${BOLD}$(tput setaf 2)"
        RED="${BOLD}$(tput setaf 1)"
        YELLOW="${BOLD}$(tput setaf 3)"
    else
        ALL_OFF="\e[1;0m"
        BOLD="\e[1;1m"
        BLUE="${BOLD}\e[1;34m"
        GREEN="${BOLD}\e[1;32m"
        RED="${BOLD}\e[1;31m"
        YELLOW="${BOLD}\e[1;33m"
    fi
fi
readonly ALL_OFF BOLD BLUE GREEN RED YELLOW

msg() {
    printf "${ALL_OFF}${GREEN}=>${ALL_OFF}${BOLD} ${@}${ALL_OFF}\n"
}

warn() {
    printf "${ALL_OFF}${YELLOW}=>${ALL_OFF}${BOLD} ${@}${ALL_OFF}\n" >&2
}

error() {
    printf "${ALL_OFF}${RED}=>${ALL_OFF}${BOLD} ${@}${ALL_OFF}\n" >&2
    return 1
}

die() {
    printf "${ALL_OFF}${RED}=>${ALL_OFF}${BOLD} Hewston, we have a problem${ALL_OFF}\n" >&2
    exit 1
}

unmount_pseudo() {
    msg "Unmounting pseudo filesystems"
    for i in dev/pts dev proc sys tmp;do
        if mountpoint -q "${FILESYSTEM_DIR}/$i" ;then
            umount -fl "${FILESYSTEM_DIR}/$i" || die
        fi
    done

    for i in $(grep "${FILESYSTEM_DIR}" /proc/mounts | cut -d' ' -f2 | sed 's|\040| |g');do
        if mountpoint -q "$i" ;then
            umount -fl "$i" || die
        fi
    done
}

cd "${0%/*}" || die

runtime_check() {
    if [ "$(id -u)" != "0" ];then
        error "You are not root!"
        exit 1
    fi

    if [[ -z "$(which mksquashfs)" || -z "$(which grub-mkrescue)" \
        || -z "$(which xorriso)" ]];then
        error "You need squashfs-tools, grub(2) and xorriso installed"
        exit 1
    fi

    if [ ! -f "profile/preferences.conf" ];then
        error "profile/preferences.conf doesn't exists"
        exit 1
    fi

    if [ ! -d "profile/root_overlay" ];then
        error "profile/root_overlay doesn't exists"
        exit 1
    fi

    if [ ! -d "profile/iso_overlay" ];then
        error "profile/iso_overlay doesn't exists"
        exit 1
    fi

    if [ ! -f "profile/squash.exclude" ];then
        error "profile/squash.exclude doesn't exist"
        exit 1
    fi
}

#================ Check if root filesystem exists/is valid ================#

Check() {
    msg "Checking filesystem"
    if [ ! "${FILESYSTEM_DIR}" ];then
        error "{FILESYSTEM_DIR} is null"
        exit 1
    elif [ ! -d "${FILESYSTEM_DIR}" ];then
        error "The filesystem path doesn't exists"
        exit 1
    elif [ ! -d "${FILESYSTEM_DIR}/etc" ] || [ ! -d "${FILESYSTEM_DIR}/root" ] \
        || [ ! -e "${FILESYSTEM_DIR}/bin/bash" ];then
        error "The filesystem path isn't usable or has been corruped"
        exit 1
    fi
}

#========================== Purge root filesystem =========================#

Clean() {
    if [ -d "${FILESYSTEM_DIR}" ];then
        unmount_pseudo
        msg "Purging: ${FILESYSTEM_DIR}"
        rm -rf "${FILESYSTEM_DIR}" || die
    else
        msg "There is nothing to purge"
    fi

    if [ -d "${ISO_DIR}" ];then
        msg "Purging: ${ISO_DIR}"
        rm -rf "${ISO_DIR}" || die
    else
        msg "There is nothing to purge"
    fi
}

#========================== Setup root filesystem =========================#

Setup() {
    msg "Copying root filesystem overlay"
    cp -rf "profile/root_overlay"/* "${FILESYSTEM_DIR}" || die
    if Chroot "which runscript" ;then
        Chroot "rc-update add live_config boot"
        Chroot "rc-update add live_install default"
        Chroot "rc-update add live_eject shutdown"
    fi
}

#=========================== Interactive chroot ===========================#

Chroot() {
    if which systemd-nspawn 1>/dev/null && pgrep systemd 1>/dev/null;then
        systemd-nspawn --share-system -D "${FILESYSTEM_DIR}" $@ || die
    else
        local EXPORTS i rv
        EXPORTS="XDG_CACHE_HOME=/root/.cache XDG_DATA_HOME=/root XDG_CONFIG_HOME=/root/.config"
        EXPORTS="${EXPORTS} HOME=/root LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin"

        msg "Preparing chroot"
        cp -f /etc/resolv.conf "${FILESYSTEM_DIR}/etc" || die
        ln -sf /proc/mounts "${FILESYSTEM_DIR}/etc/mtab" || die

        msg "Mounting pseudo filesystems"
        for i in dev dev/pts proc sys tmp;do
            if ! mountpoint -q "${FILESYSTEM_DIR}/$i" ;then
                mkdir -p "${FILESYSTEM_DIR}/$i" || die
                mount --bind "/$i" "${FILESYSTEM_DIR}/$i" || die
            fi
        done

        env ${EXPORTS} chroot "${FILESYSTEM_DIR}" $@
    fi

    rv="$?"
    unmount_pseudo

    return "$rv"
}
#============= Prepare the root filesystem and copy kernel images ==============#

Build() {
    local sfs size modules format efi linux vmlinuz iso

    msg "Removing previous initramfs image files"
    find "${FILESYSTEM_DIR}/boot/" -name "*.img" -delete || die

    mkdir -p "${ISO_DIR}/live"
    msg "Generating kernel images"
    Chroot mkinitfs -m="${KERNEL_MODULES}" -k=auto || die

    msg "Copying boot files"
    linux="$(ls ${FILESYSTEM_DIR}/boot/*.img | tail -1)"
    vmlinuz="$(ls ${FILESYSTEM_DIR}/boot/* | grep -E 'vmlinuz-*|vmlinuz*|kernel-*' | tail -1)"
    cp -f "${linux}" "${ISO_DIR}/live/linux.gz" || die
    cp -f "${vmlinuz}" "${ISO_DIR}/live/vmlinuz" || die

    msg "Removing current initramfs image files"
    find "${FILESYSTEM_DIR}/boot/" -name "*.img" -delete || die

    #======================= Squash the root filesystem ======================#
    msg "Calculating filesystem size"
    # FIXME: busybox du does not support --exclude-from
    size=$(du --exclude-from="${EXCLUDE_CONF}" -s "${FILESYSTEM_DIR}" | cut -f1)
    echo "${size}" > "${ISO_DIR}/live/root.size" || die

    msg "Compressing filesystem to SquashFS image"
    sfs="${ISO_DIR}/live/root.sfs"
    mksquashfs "${FILESYSTEM_DIR}" "${sfs}" -wildcards -ef "${EXCLUDE_CONF}" ${SQUASH_OPTIONS} || die

    #========================== Copy ISO overlay ==========================#
    msg "Copying ISO image overlay"
    cp -rf "profile/iso_overlay"/* "${ISO_DIR}" || die

    msg "Setting up grub.cfg"
    sed -i "s|__TITLE__|${TITLE}|g" "${ISO_DIR}/boot/grub/grub.cfg" || die
    sed -i "s|__BOOT_OPTIONS__|${BOOT_OPTIONS}|g" "${ISO_DIR}/boot/grub/grub.cfg" || die
    sed -i "s|__FALLBACK_OPTIONS__|${BOOT_FALLBACK_OPTIONS}|g" "${ISO_DIR}/boot/grub/grub.cfg" || die
    sed -i "s|__ARCH__|$(uname -m)|g" "${ISO_DIR}/boot/grub/grub.cfg" || die
    sed -i "s|__RELEASE__|$(date +%Y%m%d)|g" "${ISO_DIR}/boot/grub/grub.cfg" || die

    #========================== Prepare EFI/UEFI ==========================#
    modules="boot chain configfile fat ext2 linux normal ntfs part_gpt part_msdos"
    format=""
    efi="${ISO_DIR}/efi.img"
    for dir in /lib/grub /usr/lib/grub;do
        [ -d "$dir/i386-efi" ] && format="i386-efi"
        [ -d "$dir/x86_64-efi" ] && format="x86_64-efi"
    done
    if [[ -n "$format" && -n $(which mformat) ]];then
        msg "Creating EFI image"
        grub-mkimage -o "${efi}" -O "$format" -p "" $modules || die
    else
        warn "Either GRUB does not support EFI or mtools is not installed"
        rm -f "${efi}"
    fi

    #========================= Create ISO image ===========================#
    msg "Creating ISO"
    iso="$(pwd)/$(echo ${BUILD_PROFILE} | tr '[:lower:]' '[:upper:]')-$(uname -m)-$(date +%Y%m%d).iso"
    grub-mkrescue -o "${iso}" "${ISO_DIR}" -- -volid "${ISO}" ${GRUB_OPTIONS} || die
}

#========================== Arguments handler ==========================#

Usage () {
echo "
 Builder v4.3.0 - Bash script to build GNU/Linux Live CD/DVDs

  Usage: '# ${0##*/} <profile> <option> [<option>] [<option>]..'

  Options:

     -s|--setup                   Setup root filesystem
     -c|--chroot                  Chroot into the filesystem
     -b|--build                   Build ISO image
     -t|--clean                   Purge all temporary files
     -h|--help                    Print this message

 Developer: Ivailo Monev (a.k.a SmiL3y)
 E-Mail: xakepa10@gmail.com
"
}

runtime_check
if [ "$#" -gt "1" ];then
    export BUILD_PROFILE="${1}" && shift
    export FILESYSTEM_DIR="$(pwd)/${BUILD_PROFILE}_root_$(uname -m)"
    export ISO_DIR="$(pwd)/${BUILD_PROFILE}_iso_$(uname -m)"
    source "profile/preferences.conf"
    export EXCLUDE_CONF="profile/squash.exclude"

    args_array=("$@")
    for arg in "${args_array[@]}";do
        case "${arg}" in
            # Main options
            -s|--setup) Check && Setup ;;
            -c|--chroot) Check && Chroot "/bin/bash -l" || die ;;
            -b|--build) Check && Build ;;
            -t|--clean) Check && Clean ;;
            -h|--help) Usage ;;
            -*) warn "Unrecognized argument: ${arg}" ;;
        esac
    done
else
    Usage
fi
