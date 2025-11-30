# src/logger.py
import sqlite3
import json
import os
import threading
import time
from datetime import datetime
import gzip
import shutil

from telegram_notifier import TelegramNotifier

# --- Пути к БД и логам ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(DATA_DIR, "events.db")
JSON_LOG = os.path.join(LOG_DIR, "events.jsonl")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

MAX_DB_SIZE = 50 * 1024 * 1024   # 50 MB  (можно изменить)


class AuditLogger:
    def __init__(self, rotate=True):
        """
        rotate=True — разрешена ротация БД и JSON (для демона)
        rotate=False — только чтение (для GUI)
        """
        self._lock = threading.Lock()
        self._rotate_enabled = rotate

        # Перед открытием — проверяем БД на размер, только если включена ротация
        if self._rotate_enabled:
            self._rotate_db_if_needed(force_check=True)

        self._conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        self._init_db()

        self._rotate_interval = 24 * 3600
        self._last_rotate = time.time()

        # Telegram notifier
        self.tg = TelegramNotifier()

    # ---------- База данных ----------
    def _init_db(self):
        c = self._conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            type TEXT,
            user TEXT,
            pid INTEGER,
            ppid INTEGER,
            cmd TEXT,
            path TEXT,
            info TEXT
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ts ON events(ts)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_type ON events(type)')
        self._conn.commit()

    # ---------- Запись события ----------
    def log(self, ev_type, user=None, pid=None, ppid=None, cmd=None, path=None, info=None):
        ts = datetime.utcnow().isoformat() + "Z"
        info_json = json.dumps(info or {})

        with self._lock:
            try:
                c = self._conn.cursor()
                c.execute(
                    'INSERT INTO events (ts,type,user,pid,ppid,cmd,path,info) VALUES (?,?,?,?,?,?,?,?)',
                    (ts, ev_type, user, pid, ppid, cmd, path, info_json)
                )
                self._conn.commit()
            except Exception as e:
                with open(os.path.join(LOG_DIR, "events_fallback.jsonl"), "a") as f:
                    f.write(json.dumps({
                        "ts": ts, "type": ev_type, "user": user,
                        "pid": pid, "ppid": ppid, "cmd": cmd,
                        "path": path, "info": info, "err": str(e)
                    }) + "\n")

            try:
                with open(JSON_LOG, "a") as f:
                    f.write(json.dumps({
                        "ts": ts, "type": ev_type, "user": user,
                        "pid": pid, "ppid": ppid, "cmd": cmd,
                        "path": path, "info": info
                    }) + "\n")
            except:
                pass

        # Telegram уведомления
        important_events = ['critical', 'error']
        if ev_type in important_events:
            msg = (
                f"<b>Audit event detected</b>\n"
                f"Type: <b>{ev_type}</b>\n\n"
                f"Info:\n<pre>{json.dumps(info or {}, indent=2, ensure_ascii=False)}</pre>"
            )
            self.tg.send_message(msg)

        # Ротация JSON-логов по времени
        if self._rotate_enabled:
            self._rotate_if_needed()
            self._rotate_db_if_needed()

    # ---------- Запросы ----------
    def query(self, where_clause='', params=()):
        q = 'SELECT id,ts,type,user,pid,ppid,cmd,path,info FROM events '
        if where_clause:
            q += ' WHERE ' + where_clause
        q += ' ORDER BY ts DESC LIMIT 1000'

        c = self._conn.cursor()
        c.execute(q, params)
        rows = c.fetchall()
        return [dict(r) for r in rows]

    # ---------- Ротация JSON-логов ----------
    def _rotate_if_needed(self):
        now = time.time()
        if now - self._last_rotate > self._rotate_interval:
            self._rotate_json_log()
            self._last_rotate = now

    def _rotate_json_log(self):
        try:
            ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            if os.path.exists(JSON_LOG):
                gz = JSON_LOG + "." + ts + ".gz"
                with open(JSON_LOG, "rb") as f_in, gzip.open(gz, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(JSON_LOG)
        except Exception as e:
            print("JSON rotation error:", e)

    # ---------- Ротация базы данных ----------
    def _rotate_db_if_needed(self, force_check=False):
        if not self._rotate_enabled:
            return

        if not os.path.exists(DB_PATH):
            return

        size = os.path.getsize(DB_PATH)
        if size < MAX_DB_SIZE and not force_check:
            return

        # Закрыть текущее соединение
        try:
            self._conn.commit()
            self._conn.close()
        except:
            pass

        ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        archived = DB_PATH + "." + ts

        shutil.move(DB_PATH, archived)

        with open(archived, "rb") as f_in, gzip.open(archived + ".gz", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(archived)

        print(f"[DB ROTATION] Archived: {archived}.gz")

        # Создать новую БД
        self._conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def query_period(self, start_ts, end_ts):
    # Конвертируем в правильный формат, если нужно
        if 'T' not in start_ts:
        # Если пришел datetime объект или другой формат
            from datetime import datetime
            if isinstance(start_ts, datetime):
                start_ts = start_ts.isoformat() + "Z"
            if isinstance(end_ts, datetime):
                end_ts = end_ts.isoformat() + "Z"
    
        c = self._conn.cursor()
        sql = "SELECT * FROM events WHERE ts BETWEEN ? AND ? ORDER BY ts"
        c.execute(sql, (start_ts, end_ts))
        rows = c.fetchall()
        return [dict(r) for r in rows]

    def refresh_connection(self):
        """Обновить соединение после ротации или при GUI"""
        if hasattr(self, '_conn'):
            try:
                self._conn.commit()
                self._conn.close()
            except:
                pass
        self._conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()
