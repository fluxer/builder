#!/usr/bin/python2

'''
A messaging module with fancy printing, logging and piped process handling.

Unbuffered() is not something you should deal with, it will be used to override
standard output forcing it to flush if stdout is not a TTY. Same goes for
colors - if stdout is not TTY then they will be automatically disabled. It also
logs everything passed to the messager via syslog unless told otherwise. And
the cherry is that it can raise Exception if the CATCH attribute is set to
value evaluated as True.
'''

import sys, curses, syslog

# http://stackoverflow.com/questions/107705/python-output-buffering
class Unbuffered(object):
    ''' Override output behaviour to suitable for piped process '''
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        ''' Write to stdout without buffering '''
        self.stream.write(data)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)


class Message(object):
    ''' Print fancy messages with logging '''
    def __init__(self):
        self.LOG = True
        self.LOG_STATUS = [syslog.LOG_DEBUG, syslog.LOG_CRIT, syslog.LOG_ALERT, syslog.LOG_INFO]
        self.DEBUG = False
        self.CATCH = False

        try:
            curses.setupterm()
            self.COLORS = curses.tigetnum('colors')
        except curses.error:
            self.COLORS = 0

        if self.COLORS >= 8 and sys.stdout.isatty():
            self.cmarker = '\033[1;34m'
            self.cinfo = '\033[1;32m'
            self.cwarning = '\033[1;33m'
            self.ccritical = '\033[1;31m'
            self.cdebug = '\033[1;36m'
            self.cnormal = '\033[0m'
        else:
            self.cmarker = ''
            self.cinfo = ''
            self.cwarning = ''
            self.ccritical = ''
            self.cdebug = ''
            self.cnormal = ''
            sys.stdout = Unbuffered(sys.stdout)
            sys.stderr = Unbuffered(sys.stderr)

    def normalize(self, variant):
        ''' Convert variable to string suitable for logging '''
        if isinstance(variant, (list, tuple, bool, Exception)):
            variant = str(variant)
        if not isinstance(variant, str):
            variant = variant.encode('utf-8')
        return variant

    def base(self, prefix, msg, marker, status, printer=sys.stdout):
        ''' Base printer '''
        msgcolor = ''
        markcolor = ''
        markmsg = ''
        marklog = ''
        if status == syslog.LOG_DEBUG:
            if not self.DEBUG:
                return
            msgcolor = self.cdebug
            markcolor = self.cdebug
        elif status == syslog.LOG_CRIT:
            if self.CATCH and marker:
                raise Exception(msg, marker)
            elif self.CATCH:
                raise Exception(msg)
            msgcolor = self.ccritical
            markcolor = self.ccritical
        elif status == syslog.LOG_ALERT:
            msgcolor = self.cwarning
            markcolor = self.cwarning
        elif status == syslog.LOG_INFO:
            msgcolor = self.cmarker
            markcolor = self.cinfo
        else:
            raise Exception('Unknown status', status)
        basemsg = '%s%s%s %s' % (msgcolor, prefix, self.cnormal, msg)
        if marker is not None:
            markmsg = ': %s%s%s' % (markcolor, marker, self.cnormal)
            marklog = ': %s' % marker
        printer.write('%s%s\n' % (basemsg, markmsg))
        if self.LOG and status in self.LOG_STATUS:
            msg = self.normalize(msg)
            marklog = self.normalize(marklog)
            syslog.syslog(status, '%s%s' % (msg, marklog))

    def info(self, msg, marker=None):
        ''' Print message with information status '''
        self.base('*', msg, marker, syslog.LOG_INFO)

    def warning(self, msg, marker=None):
        ''' Print message with warning status '''
        self.base('*', msg, marker, syslog.LOG_ALERT, sys.stderr)

    def critical(self, msg, marker=None):
        ''' Print message with critical status '''
        self.base('*', msg, marker, syslog.LOG_CRIT, sys.stderr)

    def debug(self, msg, marker=None):
        ''' Print message with debug status '''
        self.base('*', msg, marker, syslog.LOG_DEBUG)

    def sub_info(self, msg, marker=None):
        ''' Print message with information status '''
        self.base('  ->', msg, marker, syslog.LOG_INFO)

    def sub_warning(self, msg, marker=None):
        ''' Print message with warning status '''
        self.base('  ->', msg, marker, syslog.LOG_ALERT, sys.stderr)

    def sub_critical(self, msg, marker=None):
        ''' Print message with critical status '''
        self.base('  =>', msg, marker, syslog.LOG_CRIT, sys.stderr)

    def sub_debug(self, msg, marker=None):
        ''' Print message with debug status '''
        self.base('  ->', msg, marker, syslog.LOG_DEBUG)
