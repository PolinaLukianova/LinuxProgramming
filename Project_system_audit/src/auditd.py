import os
import sys
import time
import threading
import pwd
import signal
import traceback

import psutil
from inotify_simple import INotify, flags

from logger import AuditLogger
from telegram_notifier import TelegramNotifier
from ptrace_helper import ptrace_attach, ptrace_detach
from auto_reporter import AutoReporter


LOG = AuditLogger(rotate=False)
TG = TelegramNotifier() 

WATCH_PATHS = ['/etc', '/var/log', '/tmp']


class ProcessPoller(threading.Thread):
    """Опрашивает список процессов и фиксирует появление/завершение."""

    def __init__(self, interval=1.0):
        super().__init__(daemon=True)
        self.interval = interval
        self.known = {}
        self._stop = threading.Event()

    def snapshot(self):
        res = {}
        for p in psutil.process_iter(['pid', 'create_time', 'username',
                                      'cmdline', 'ppid', 'name', 'exe']):
            try:
                info = p.info
                res[info['pid']] = info
            except Exception:
                continue
        return res

    def run(self):
        self.known = self.snapshot()
        while not self._stop.is_set():
            try:
                current = self.snapshot()

                # --- новые процессы ---
                for pid, info in current.items():
                    if pid not in self.known:
                        user = info.get('username')
                        cmd = ' '.join(info.get('cmdline') or [info.get('name') or ''])
                        ppid = info.get('ppid')

                        LOG.log(
                            ev_type='proc:START',
                            user=user,
                            pid=pid, ppid=ppid,
                            cmd=cmd,
                            info={'create_time': info.get('create_time')}
                        )

                        # СОМНИТЕЛЬНЫЕ процессы → отправка Telegram
                        if cmd and ('/tmp' in cmd or cmd.endswith('.sh')):
                            TG.send_message(f"<b>Подозрительный процесс</b>\nPID: {pid}\nCMD: {cmd}")

                # --- завершённые процессы ---
                for pid in list(self.known.keys()):
                    if pid not in current:
                        old = self.known[pid]
                        user = old.get('username')
                        cmd = ' '.join(old.get('cmdline') or [old.get('name') or ''])
                        LOG.log(
                            ev_type='proc:EXIT',
                            user=user, pid=pid,
                            ppid=old.get('ppid'),
                            cmd=cmd,
                            info={'last_seen': time.time()}
                        )

                self.known = current

            except Exception as e:
                LOG.log(ev_type='error:proc_poller',
                        info={'err': str(e), 'trace': traceback.format_exc()})

            time.sleep(self.interval)

    def stop(self):
        self._stop.set()


class FileMonitor(threading.Thread):
    def __init__(self, paths):
        super().__init__(daemon=True)
        self.inotify = INotify()
        self.paths = paths
        self.watches = {}

    def run(self):
        for p in self.paths:
            if os.path.exists(p):
                try:
                    wd = self.inotify.add_watch(
                        p,
                        flags.CREATE | flags.DELETE |
                        flags.MODIFY | flags.MOVED_FROM | flags.MOVED_TO
                    )
                    self.watches[wd] = p
                except Exception as e:
                    LOG.log(ev_type='error:inotify_add', path=p, info={'err': str(e)})

        while True:
            try:
                events = self.inotify.read(timeout=1000)
                for ev in events:
                    base = self.watches.get(ev.wd, '')
                    filename = ev.name
                    types = [f.name for f in flags.from_mask(ev.mask)]

                    LOG.log(
                        ev_type='file:' + ','.join(types),
                        path=os.path.join(base, filename),
                        info={'mask': ev.mask, 'cookie': ev.cookie}
                    )

            except Exception as e:
                LOG.log(ev_type='error:inotify',
                        info={'err': str(e), 'trace': traceback.format_exc()})
                time.sleep(1)


class NetworkPoller(threading.Thread):
    def __init__(self, interval=5.0):
        super().__init__(daemon=True)
        self.interval = interval
        self.known = set()
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                conns = []
                for c in psutil.net_connections(kind='inet'):
                    try:
                        l = f'{c.laddr.ip}:{c.laddr.port}' if c.laddr else ''
                        r = f'{c.raddr.ip}:{c.raddr.port}' if c.raddr else ''
                        conns.append((c.fd, c.pid, l, r, c.status))
                    except Exception:
                        continue

                cur = set(conns)

                # новые соединения
                for item in cur - self.known:
                    fd, pid, l, r, status = item
                    LOG.log('net:NEW', pid=pid, info={'laddr': l, 'raddr': r, 'status': status})

                # закрытые соединения
                for item in self.known - cur:
                    fd, pid, l, r, status = item
                    LOG.log('net:CLOSED', pid=pid, info={'laddr': l, 'raddr': r, 'status': status})

                self.known = cur

            except Exception as e:
                LOG.log(ev_type='error:net',
                        info={'err': str(e), 'trace': traceback.format_exc()})

            time.sleep(self.interval)


def handle_signals(signum, frame):
    LOG.log(ev_type='daemon:signal', info={'signal': signum})
    sys.exit(0)


def main():
#    if os.geteuid() != 0:
#        print("auditd must be run as root")
#        sys.exit(1)

    signal.signal(signal.SIGTERM, handle_signals)
    signal.signal(signal.SIGINT, handle_signals)

    pm = ProcessPoller(interval=1.0)
    fm = FileMonitor(WATCH_PATHS)
    nm = NetworkPoller(interval=5.0)

    pm.start()
    fm.start()
    nm.start()

    LOG.log(ev_type='daemon:started', info={'paths': WATCH_PATHS})
    TG.send_message("<b>Audit daemon started</b>")

    auto_rep = AutoReporter(logger=LOG, send_on_start=False)
    auto_rep.start()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()

