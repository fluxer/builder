#!/usr/bin/python2

import sys, argparse, tempfile, subprocess, shutil, os, gzip, bz2, glob, ast, re

app_version = "1.10.1 (c3061ad)"

tmpdir = None
keep = False
try:
    import libmessage, libmisc
    message = libmessage.Message()
    misc = libmisc.Misc()

    tmpdir = tempfile.mkdtemp()
    kernel = os.uname()[2]
    busybox = misc.whereis('busybox')
    strip = True
    image = '/boot/initramfs-%s.img' % kernel
    compression = 'gzip'
    recovery = True
    modules = []
    for m in os.listdir('/sys/module'):
        if os.path.isdir('/sys/module/%s/sections' % m):
            modules.append(m)

    parser = argparse.ArgumentParser(prog='mkinitfs', description='MkInitfs')
    parser.add_argument('-T', '--busytest', action='store_true', \
        help='Test whether Busybox supports requried functionality')
    parser.add_argument('-t', '--tmp', type=str, default=tmpdir, \
        help='Change temporary directory')
    parser.add_argument('-b', '--busybox', type=str, default=busybox, \
        help='Change busybox binary')
    parser.add_argument('-k', '--kernel', type=str, default=kernel, \
        help='Change kernel version')
    parser.add_argument('-m', '--modules', type=str, nargs='+', \
        default=modules, help='Change modules')
    parser.add_argument('-s', '--strip', type=ast.literal_eval, \
        choices=[True, False], default=strip, \
        help='Change whether to strip binraries and libraries')
    parser.add_argument('-i', '--image', type=str, default=image, \
        help='Change output image')
    parser.add_argument('-c', '--compression', type=str, default=compression, \
        choices=('cat', 'gzip', 'bzip2'), \
        help='Change image compression method')
    parser.add_argument('-r', '--recovery', type=ast.literal_eval, \
        choices=[True, False], default=recovery, \
        help='Change wheather to create recovery image')
    parser.add_argument('--keep', action='store_true', \
        help='Keep temporary directory')
    parser.add_argument('--debug', action='store_true', \
        help='Enable debug messages')
    parser.add_argument('--version', action='version', \
        version='MkInitfs v' + app_version, \
        help='Show MkInitfs version and exit')
    ARGS = parser.parse_args()

    if ARGS.tmp != tmpdir:
        tmpdir = ARGS.tmp

    if ARGS.keep:
        keep = True

    if ARGS.debug:
        message.DEBUG = True

    modsdir = None
    kernels = []
    for moddir in ('/lib/modules', '/lib32/modules', '/lib64/modules', \
        '/usr/lib/modules', '/usr/lib32/modules', '/usr/lib64/modules'):
        if not os.path.exists(moddir) or os.path.islink(moddir):
            continue
        for kernel in os.listdir(moddir):
            kerndir = '%s/%s' % (moddir, kernel)
            if os.path.isfile('%s/modules.dep' % kerndir) and \
                os.path.isfile('%s/modules.builtin' % kerndir):
                kernels.append(kerndir)
    for kernel in kernels:
        if os.path.basename(kernel) == ARGS.kernel:
            modsdir = kernel
    if not modsdir and len(kernels) >= 1:
        modsdir = kernels[0]
        ARGS.kernel = os.path.basename(kernels[0])
        message.sub_warning('Last resort kernel detected', ARGS.kernel)

    if not modsdir:
        message.critical('Unable to find modules directory')
        sys.exit(2)

    # if cross-building and no custom image is set update ARGS.image
    if ARGS.kernel != kernel and ARGS.image == image:
        ARGS.image = '/boot/initramfs-%s.img' % ARGS.kernel

    lcopied = []
    def copy_item(src):
        ''' Copy method that handles binaries, symlinks and whatnot '''
        sdir = os.path.dirname(src)
        if os.path.islink(sdir):
            copy_item(sdir)
            misc.dir_create('%s/%s' % (ARGS.tmp, \
                os.path.dirname(os.path.realpath(src))))
        else:
            misc.dir_create('%s/%s' % (ARGS.tmp, sdir))
        if os.path.islink(src):
            if src in lcopied:
                message.sub_debug('Already linked', src)
                return
            sreal = os.readlink(src)
            sfixed = src.replace('/etc/mkinitfs/root', '')
            sdest = '%s%s' % (ARGS.tmp, sfixed)
            if os.path.islink(sdest):
                message.sub_debug('Already exists', src)
                return
            message.sub_debug('Linking', sreal)
            message.sub_debug('To', sdest)
            os.symlink(sreal, sdest)
            lcopied.append(src)
        elif os.path.isdir(src):
            if src in lcopied:
                message.sub_debug('Already copied', src)
                return
            sfixed = src.replace('/etc/mkinitfs/root', '')
            sdest = '%s/%s' % (ARGS.tmp, sfixed)
            if os.path.isdir(sdest):
                message.sub_debug('Already exists', src)
                for sfile in os.listdir(src):
                    copy_item('%s/%s' % (src, sfile))
                return
            message.sub_debug('Copying', src)
            message.sub_debug('To', sdest)
            shutil.copytree(src, sdest, symlinks=True)
            lcopied.append(src)
        elif os.path.isfile(src):
            ltocopy = misc.system_scanelf(src, sflags='-L').split(',')
            ltocopy.append(src)
            for sfile in ltocopy:
                if sfile in lcopied:
                    message.sub_debug('Already copied', sfile)
                    continue
                elif not sfile:
                    continue
                sfixed = sfile.replace('/etc/mkinitfs/root', '')
                if os.path.islink(sfile):
                    copy_item(sfile)
                    sfile = '%s/%s' % (os.path.dirname(sfile), os.readlink(sfile))
                sdest = '%s/%s' % (ARGS.tmp, sfixed)
                if os.path.isfile(sdest):
                    message.sub_debug('Already exists', src)
                    return
                message.sub_debug('Copying', sfile)
                message.sub_debug('To', sdest)
                shutil.copy2(sfile, sdest)
                lcopied.append(sfile)
                copy_item(sfile)
        else:
            message.warning('File or directory does not exist', src)

    # TODO: use the function once busybox has a more complete modinfo applet
    def copy_module(name):
        message.sub_debug('Searching for module', name)
        try:
            if misc.system_communicate((ARGS.busybox, 'modinfo', '-k', ARGS.kernel, name)):
                modpath = misc.system_communicate((ARGS.busybox, 'modinfo', '-k', ARGS.kernel, '-F', 'filename', name))
                moddepends = misc.system_communicate((ARGS.busybox, 'modinfo', '-k', ARGS.kernel, '-F', 'depends', name))
                if moddepends:
                    for moddepend in moddepends.strip().split(','):
                        copy_module(moddepend.strip())
                copy_item(modpath)
        except:
            message.warning('Module not found', name)

    def create_image(src, image, method):
        misc.system_command((ARGS.busybox, 'depmod', ARGS.kernel, '-b', ARGS.tmp))

        data = misc.system_communicate('%s find . | %s cpio -o -H newc' % \
            (ARGS.busybox, ARGS.busybox), bshell=True, cwd=src)
        if method == 'gzip':
            with gzip.GzipFile(image, 'wb') as gzipf:
                gzipf.write(data)
        elif method == 'bzip2':
            with bz2.BZ2File(image, 'wb') as bzipf:
                bzipf.write(data)
        else:
            misc.file_write(image, data)

    message.info('Runtime information')
    message.sub_info('BUSYTEST', ARGS.busytest)
    message.sub_info('TMP', ARGS.tmp)
    message.sub_info('BUSYBOX', ARGS.busybox)
    message.sub_info('KERNEL', ARGS.kernel)
    message.sub_info('MODULES', ARGS.modules)
    message.sub_info('STRIP', ARGS.strip)
    message.sub_info('IMAGE', ARGS.image)
    message.sub_info('COMPRESSION', ARGS.compression)
    message.sub_info('RECOVERY', ARGS.recovery)

    if ARGS.busytest:
        message.sub_info('Testing busybox compatibility')
        busycommands = {
            'modprobe': ['-b'],
            'find': ('-type', '-name', '-exec'),
            'cpio': ('-o', '-H'),
            # TODO: 'modinfo', ('-k', '-F')
            'depmod': ['-b'],
            'mknod': ['-m'],
            'echo': ['-e'],
            'mkdir': ['-p'],
            'mount': ('-t', '-o', 'move'),
            'modprobe': ('-q', '-b', '-a'),
            'ln': ('-s', '-f'),
            'mdev': ['-s'],
            'sort': ['-u'],
            'reboot': ['-f'],
            'main': ('--install', '[-s]', 'touch,', 'xargs,', 'switch_root,', 'sync,', 'blkid,'),
        }
        compatible = True
        for command in busycommands:
            message.sub_debug('Checking for compat with', command)
            if command == 'main':
                commoutput = subprocess.check_output((ARGS.busybox, '--help'), stderr=subprocess.STDOUT)
            else:
                commoutput = subprocess.check_output((ARGS.busybox, command, '--help'), stderr=subprocess.STDOUT)
            for arg in busycommands[command]:
                message.sub_debug('Testing argument', arg)
                if not re.findall('\\s%s\\s' % re.escape(arg), commoutput):
                    if command == 'main':
                        message.sub_critical('Argument/applet %s not supported' % arg)
                    else:
                        message.sub_critical('Argument %s not supported by %s' % (arg, command))
                    compatible = False
        if not compatible:
            sys.exit(1)
        sys.exit(0)

    message.sub_info('Copying root overlay')
    if os.path.isdir('/etc/mkinitfs/root'):
        for spath in misc.list_all('/etc/mkinitfs/root'):
            copy_item(spath)
    else:
        message.sub_warning('Root filesystem overlay missing')

    message.sub_info('Installing Busybox')
    message.sub_debug('Installing binary')
    copy_item(ARGS.busybox)
    message.sub_debug('Creating symlinks')
    misc.system_command((ARGS.busybox, '--install', '-s', '%s/bin' % ARGS.tmp))

    message.sub_info('Copying files')
    if os.path.isdir('/etc/mkinitfs/files'):
        for sfile in misc.list_files('/etc/mkinitfs/files'):
            if not sfile.endswith('.conf'):
                message.sub_debug('Skipping', sfile)
                continue
            message.sub_debug('Reading', sfile)
            for line in misc.file_readsmart(sfile):
                items = glob.glob(line)
                # glob returns null and the warning in copy_item() may not be
                # reached if iterating directly over the value fom glob.glob()
                if not items:
                    message.warning('File or directory does not exist', line)
                    continue
                for item in items:
                    copy_item(item)

    message.sub_info('Copying modules')
    if os.path.isdir('/etc/mkinitfs/modules'):
        for sfile in misc.list_files('/etc/mkinitfs/modules'):
            if not sfile.endswith('.conf'):
                message.sub_debug('Skipping', sfile)
                continue
            message.sub_debug('Reading', sfile)
            for line in misc.file_readsmart(sfile):
                if not line in ARGS.modules:
                    ARGS.modules.append(line)

    for module in ARGS.modules:
        # in case ARGS.modules equals ['']
        if not module:
            continue
        found = False
        for line in misc.file_read('%s/modules.dep' % modsdir).splitlines():
            base = line.split(':')[0]
            depends = line.split(':')[1].split()
            if '/%s.ko' % module in base \
                or '/%s.ko' % module.replace('_', '-') in base:
                found = True
                copy_item('%s/%s' % (modsdir, base.strip()))
                for dep in depends:
                    copy_item('%s/%s' % (modsdir, dep.strip()))
        if not found:
            for line in misc.file_read('%s/modules.builtin' % modsdir).splitlines():
                if '/%s.ko' % module in line \
                    or '/%s.ko' % module.replace('_', '-') in line:
                    message.sub_debug('Module is builtin', module)
                    found = True
        if not found:
            message.sub_warning('Module not found', module)
    # to minimize the computation in the initramfs unpack the modules now
    for sfile in misc.list_files('%s/%s' % (ARGS.tmp, modsdir)):
        if misc.archive_supported(sfile):
            message.sub_debug('Decompressing', sfile)
            misc.archive_decompress(sfile, os.path.dirname(sfile))
            message.sub_debug('Removing', sfile)
            os.unlink(sfile)

    message.sub_info('Copying module files')
    for sfile in os.listdir(modsdir):
        if sfile.startswith('modules.'):
            copy_item('%s/%s' % (modsdir, sfile))

    message.sub_info('Creating essential nodes')
    dev_dir = '%s/dev' % ARGS.tmp
    misc.dir_create(dev_dir)
    misc.system_command((ARGS.busybox, 'mknod', '-m', '640', \
        '%s/console' % dev_dir, 'c', '5', '1'))
    misc.system_command((ARGS.busybox, 'mknod', '-m', '664', \
        '%s/null' % dev_dir, 'c', '1', '0'))

    message.sub_info('Creating shared libraries cache')
    etc_dir = '%s/etc' % ARGS.tmp
    misc.dir_create(etc_dir)
    # to surpress a warning
    ldconf = '%s/ld.so.conf' % etc_dir
    if not os.path.isfile(ldconf):
        misc.file_write(ldconf, '')
    misc.system_command((misc.whereis('ldconfig'), '-r', ARGS.tmp))

    if ARGS.strip:
        message.sub_info('Stripping binraries and libraries')
        strip = misc.whereis('strip')
        for sfile in misc.list_files(ARGS.tmp):
            smime = misc.file_mime(sfile)
            if smime in ('application/x-executable', \
                'application/x-sharedlib', 'application/x-archive'):
                message.sub_debug('Stripping', sfile)
                misc.system_command((strip, '--strip-all', sfile))

    message.sub_info('Creating optimized image')
    create_image(ARGS.tmp, ARGS.image, ARGS.compression)

    if ARGS.recovery:
        message.sub_info('Creating recovery image')
        copy_item(modsdir)
        recovery = ARGS.image.replace('.img', '-recovery.img')
        create_image(ARGS.tmp, recovery, ARGS.compression)

except subprocess.CalledProcessError as detail:
    message.critical('SUBPROCESS', detail)
    sys.exit(3)
except shutil.Error as detail:
    message.critical('SHUTIL', detail)
    sys.exit(4)
except OSError as detail:
    message.critical('OS', detail)
    sys.exit(5)
except IOError as detail:
    message.critical('IO', detail)
    sys.exit(6)
except KeyboardInterrupt:
    message.critical('Interrupt signal received')
    sys.exit(7)
except SystemExit:
    sys.exit(2)
except Exception as detail:
    message.critical('Unexpected error', detail)
    sys.exit(1)
finally:
    if tmpdir and os.path.isdir(tmpdir) and not keep:
        message.info('Cleaning up...')
        misc.dir_remove(tmpdir)
    if not 'stable' in app_version and sys.exc_info()[0]:
        raise
