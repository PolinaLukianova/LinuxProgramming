import threading
import time
from reporter import Reporter
from telegram_notifier import TelegramNotifier
from datetime import datetime, timedelta

class AutoReporter(threading.Thread):
    def __init__(self, logger, interval=24*3600, send_on_start=False):
        super().__init__(daemon=True)
        self.logger = logger
        self.rep = Reporter(logger)
        self.tg = TelegramNotifier()
        self.interval = interval
        self.send_on_start = send_on_start

    def run(self):
        # Отправка отчёта при старт
        if self.send_on_start:
            self.send_report()

        while True:
            time.sleep(self.interval)
            self.send_report()

    def send_report(self):
        now = datetime.utcnow()
        start = now - timedelta(days=1)
        
        # Конвертация в строки ISO
        start_str = start.isoformat() + "Z"
        end_str = now.isoformat() + "Z"

        txt = self.rep.build_text_report(start_str, end_str)
        plot = self.rep.plot_period(start_str, end_str)

        self.tg.send_report(txt, plot)
