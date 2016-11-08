#!/bin/bash
# Builder - a tool to create Live CD/DVD/USB GNU/Linux images
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

# a work-in-progress root filesystem extracting script
# WARNING: it does not cleanup after itself properly on unexpected fail

set -e

if [ -z "$1" ];then
    echo "pass a path to ISO image"
    exit 1
elif [ ! -f "$1" ];then
    echo "$1 is not a file"
    exit 2
elif [ "$(id -u)" != "0" ];then
    echo "execute the script as root user"
    exit 4
fi

tmp="$(mktemp -d)"
echo " >> Mounting $1 to $tmp"
mount "$1" "$tmp"
if [ -e "$tmp/crux-media" ];then
    echo "ISO is CRUX"
    root="$(pwd)/crux_root_$(uname -m)"
    if [ -d "$root" ];then
        echo "$root aleady exists"
        umount -fl "$tmp"
        exit 5
    fi
    mkdir -p "$root/var/lib/pkg"
    touch "$root/var/lib/pkg/db"
    echo "Extracting rootfs"
    tar -xpf "$tmp/rootfs.tar.xz" -C "$root"
    echo "Extracting pkgutils"
    tar -xf "$tmp/tools/"pkgutils* usr/bin/pkgadd
    echo "Installing core packages"
    for pkg in "$tmp/crux/core/"*;do
        ./usr/bin/pkgadd -f "$pkg" -r "$root"
    done
    rm -rf usr/
elif [ -e "$tmp/live/root.sfs" ];then
    echo "ISO is Entropy GNU/Linux"
    root="$(pwd)/entropy_root_$(uname -m)"
    if [ -d "$root" ];then
        echo "$root aleady exists"
        umount -fl "$tmp"
        exit 5
    fi
    unsquashfs -d "$root" "$tmp/live/root.sfs"
else
    echo "Unknown ISO image"
    umount -fl "$tmp"
    exit 6    
fi

echo "Unmounting $tmp"
umount -fl "$tmp"
echo "Removing $tmp"
rm -rf "$tmp"