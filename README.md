## Requirements on the host

bash, squashfs-tools, grub (version 2 or later), xorriso

## Requirements in the root filesystem

squashfs-tools, grub (version 2 or later), file, busybox, kernel with
overlayfs support (>=3.18.x) and [mkinitfs](https://github.com/fluxer/mkinitfs)
and optionally dialog for the installer.

## The concept

The tool is basicly a Bash script that supports several major distriutions. It
comes along with files neccessary to create a custom initramfs image that can
boot a SquashFS compressed image of root filesystem created from a directory on
your hard-drive and the whole thing is packed into ISO image via GRUB
(version 2) that can be booted from CD/DVD/USB.

## Use cases

There are a few reasons you should use this project:

1. create a Live CD/DVD from existing installation of your favourite
   distribution that has everything you need (the remastersys concept)

2. you favourite distribution does not provide easy to use tools to make a
   customized Live CD/DVD 

3. you favourite distribution does not provide Live CD/DVD images at all but
   only installation media images

4. you favourite distribution does not provide Live CD/DVD images that can
   not boot from a USB media or uses unreliable boot method such as requiring
   the boot media to have a specifiec label that many USB writing tools do not
   set properly

5. create smaller ISO image by compressing the SquashFS image with XZ and in
   addition strip all package files used by the distribution installer, for an
   example CRUX ISOs can be 2-3x smaller if rebuild with this tool.

## Possible quircks

Since the ISO image created by this tool will have a structure that the
distribution's installer (if existent) will not support you will have to
perform installation yourself, unless it uses BSD-style init system for
which a very simple installer service is provided.

## How to use

There are a few options for the first step but the idea is to have a working
root filesystem that matches \<profile\>\_root\_\<arch\> for the build script to
work with in the top-level directory of a local copy of this repository:

1. bootstrap a root filesystem for your distribution:
   [https://wiki.archlinux.org/index.php/Archbootstrap](https://wiki.archlinux.org/index.php/Archbootstrap)
   [https://wiki.debian.org/Debootstrap](https://wiki.debian.org/Debootstrap)
   [http://www.funtoo.org/Funtoo_Linux_Installation#Installing_the_Stage_3_tarball](http://www.funtoo.org/Funtoo_Linux_Installation#Installing_the_Stage_3_tarball)

2. use existing installation, just mount the root (and /boot, /usr, etc. if
   required) to \<profile\>\_root\_\<arch\>

3. extract a root filesystem tarball, Arch Linux and Gentoo provide such

4. extract the SquashFS image from a Live CD/DVD image of a distribution, for an
   example ISO images can be decompressed via archive manager, then in the
   directory you extract it to you will find casper/filesystem.squashfs
   (for Ubuntu) or a similar .sfs/.sqfs file that you can extract via:
   ```unsquashfs <path to SquashFS image> -d <profile>_root_<arch>```
   A work-in-progress script to do this is provided in the tools directory
   which may eventually be merged into the main build script.

After you do this all you have to do is call build.sh with the proper arguments
to setup the root filesystem and create ISO image for you:
```sudo bash ./build.sh <profile> -s -b```

## License

See COPYING, the files that will be bundled with the ISO image are public
domain licensed. The initramfs tool is periodic copy from my BFP project
with adjustments when needed to cut the fat.

## TODO

OpenRC alternatives support
