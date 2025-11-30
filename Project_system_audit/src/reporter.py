import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from io import BytesIO
from datetime import datetime

CRITICAL_TYPES = {
    "proc:EXEC",
    "file_deleted",
    "priv_escalation",
    "audit_violation",
    "critical",
}

class Reporter:
    def __init__(self, logger):
        self.logger = logger

    def basic_stats(self):
        rows = self.logger.query('', ())
        df = pd.DataFrame(rows)
        if df.empty:
            return None
        return df['type'].value_counts()

    def plot_event_counts(self):
        counts = self.basic_stats()
        if counts is None:
            return None

        fig = plt.figure()
        counts.plot(kind='bar')

        buf = BytesIO()
        fig.savefig(buf, format='png')
        buf.seek(0)
        return buf


    def get_period_stats(self, start, end):
        rows = self.logger.query_period(start, end)
        df = pd.DataFrame(rows)
        if df.empty:
            return None, None

        # статистика по типам
        type_stats = df['type'].value_counts()

        # выделение важных событий
        if "type" in df.columns:
            important = df[df["type"].isin(CRITICAL_TYPES)]
        else:
            important = pd.DataFrame()

        return type_stats, important

    def build_text_report(self, start, end):

        # Приводим start/end к ISO-строкам
        if hasattr(start, "isoformat"):
            start_str = start.isoformat() + "Z"
        else:
            start_str = str(start)

        if hasattr(end, "isoformat"):
            end_str = end.isoformat() + "Z"
        else:
            end_str = str(end)

        # Запрос событий
        events = self.logger.query_period(start_str, end_str)
        total = len(events)

        important = [e for e in events if e["type"] in ("critical", "error")]
        imp_count = len(important)

        # Статистика по типам
        counts = {}
        for e in events:
            t = e["type"]
            counts[t] = counts.get(t, 0) + 1

        # Формирование текста отчёта
        lines = []
        lines.append(f"<b>Отчёт за период:</b>\n{start_str} → {end_str}\n\n")
        lines.append(f"<b>Всего событий:</b> {total}\n")
        lines.append(f"<b>Важных событий:</b> {imp_count}\n\n")

        lines.append("<b>СТАТИСТИКА ПО ТИПАМ:</b>\n")
        for k, v in sorted(counts.items(), key=lambda x: -x[1]):
            lines.append(f" * {k} — {v}\n")
        lines.append("\n")

        if imp_count == 0:
            lines.append("<b>Важных событий за период не обнаружено.</b>\n")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"\n<b>Отчёт сформирован:</b> {now}")

        return "".join(lines)

    def plot_period(self, start, end):
        rows = self.logger.query_period(start, end)
        df = pd.DataFrame(rows)
        if df.empty:
            return None

        fig = plt.figure()
        df['type'].value_counts().plot(kind="bar")

        buf = BytesIO()
        fig.savefig(buf, format='png')
        buf.seek(0)
        return buf
