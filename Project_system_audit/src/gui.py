# src/gui.py
import sys
from PyQt5 import QtWidgets, QtCore
from logger import AuditLogger
from reporter import Reporter
from PyQt5 import QtWidgets, QtCore
from datetime import timezone


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Audit Tool GUI')
        self.resize(1000, 600)

        self.logger = AuditLogger(rotate=False)
        print(f"[DEBUG] Using DB: {self.logger._conn.execute('PRAGMA database_list').fetchall()}")
        rows = self.logger.query('', ())
        print(f"[DEBUG] Number of events in DB: {len(rows)}")
        
        self.reporter = Reporter(self.logger)

        self.init_ui()

        # Загружаем все события сразу после запуска
        QtCore.QTimer.singleShot(100, self.show_all)

    def init_ui(self):
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        # Фильтры
        filter_layout = QtWidgets.QHBoxLayout()
        self.user_in = QtWidgets.QLineEdit()
        self.user_in.setPlaceholderText('user')
        self.type_in = QtWidgets.QLineEdit()
        self.type_in.setPlaceholderText('type (e.g. proc:EXEC)')
        self.search_btn = QtWidgets.QPushButton('Search')
        self.search_btn.clicked.connect(self.search)
        self.show_all_btn = QtWidgets.QPushButton('Show All')
        self.show_all_btn.clicked.connect(self.show_all)
        filter_layout.addWidget(self.user_in)
        filter_layout.addWidget(self.type_in)
        filter_layout.addWidget(self.search_btn)
        filter_layout.addWidget(self.show_all_btn)
        layout.addLayout(filter_layout)

        # Таблица событий
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(['ts', 'type', 'user', 'pid', 'cmd', 'path'])
        layout.addWidget(self.table)

        # Кнопка для отчета
        rep_btn = QtWidgets.QPushButton('Show graphic')
        rep_btn.clicked.connect(self.show_report)
        layout.addWidget(rep_btn)

        central.setLayout(layout)
        self.setCentralWidget(central)

        self.send_report_btn = QtWidgets.QPushButton("Send report")
        self.send_report_btn.clicked.connect(self.send_report)
        layout.addWidget(self.send_report_btn)

        self.refresh_btn = QtWidgets.QPushButton("Refresh data")
        self.refresh_btn.clicked.connect(self.refresh_data)
        layout.addWidget(self.refresh_btn)


    def search(self):
        user = self.user_in.text().strip()
        typ = self.type_in.text().strip()
        where = []
        params = []

        if user:
            where.append('user LIKE ?')
            params.append(f'%{user}%')
        if typ:
            where.append('type LIKE ?')
            params.append(f'%{typ}%')

        where_clause = ' AND '.join(where)
        rows = self.logger.query(where_clause, tuple(params))
        self.populate_table(rows)

    

    def show_all(self):
        rows = self.logger.query('', ())
        self.populate_table(rows)

    def populate_table(self, rows):
        self.table.setRowCount(0)
        if not rows:
            QtWidgets.QMessageBox.information(self, 'Info', 'События не найдены')
            return

        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(r.get('ts', '')))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(r.get('type', '')))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(r.get('user', ''))))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(r.get('pid', ''))))
            self.table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(r.get('cmd', ''))))
            self.table.setItem(row, 5, QtWidgets.QTableWidgetItem(str(r.get('path', ''))))

        print(f"[GUI] Loaded {len(rows)} events")  # Для отладки

    def show_report(self):
        buf = self.reporter.plot_event_counts()
        if buf is None:
            QtWidgets.QMessageBox.information(self, 'Report', 'Нет данных')
            return

        from PyQt5.QtGui import QPixmap
        from PyQt5.QtWidgets import QLabel

        pix = QPixmap()
        pix.loadFromData(buf.getvalue())
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle('Report')
        v = QtWidgets.QVBoxLayout()
        lbl = QLabel()
        lbl.setPixmap(pix)
        v.addWidget(lbl)
        dlg.setLayout(v)
        dlg.exec_()

    def send_report(self):
        start, end = self.select_period()
        if not start or not end:
            return

        print(f"[DEBUG] Period: {start} to {end}")  # Отладочная информация
        
        # Проверим, есть ли события за этот период
        test_rows = self.logger.query_period(start, end)
        print(f"[DEBUG] Found {len(test_rows)} events in period")  # Отладочная информация
        
        text = self.reporter.build_text_report(start, end)
        plot = self.reporter.plot_period(start, end)

        if text and "не найдено" not in text:
            self.logger.tg.send_report(text, plot)
            QtWidgets.QMessageBox.information(self, "Отправлено", "Отчёт отправлен в Telegram")
        else:
            QtWidgets.QMessageBox.warning(self, "Ошибка", "Нет данных для отчёта за выбранный период")

    def refresh_data(self):
        """Обновить соединение с БД и перезагрузить таблицу"""
        self.logger.refresh_connection()
        self.show_all()
        QtWidgets.QMessageBox.information(self, "Обновлено", "Данные обновлены")

    def show_all(self):
        self.logger.refresh_connection()
        rows = self.logger.query('', ())
        self.populate_table(rows)

    def select_period(self):
        from datetime import datetime, timedelta
        
        items = [
            "Последний час",
            "Последние 24 часа", 
            "Последняя неделя",
            "Выбрать вручную"
        ]
        
        item, ok = QtWidgets.QInputDialog.getItem(self, "Период отчёта", "Выберите:", items, 0, False)
        if not ok:
            return None, None

        now_utc = datetime.utcnow()
        
        if item == "Последний час":
            start = now_utc - timedelta(hours=1)
            end = now_utc
        elif item == "Последние 24 часа":
            start = now_utc - timedelta(days=1)
            end = now_utc
        elif item == "Последняя неделя":
            start = now_utc - timedelta(days=7)
            end = now_utc
        else:
            # Ручной ввод
            dialog = QtWidgets.QDialog(self)
            dialog.setWindowTitle("Выбор периода")
            layout = QtWidgets.QFormLayout()

            start_date = QtWidgets.QDateEdit(calendarPopup=True)
            end_date = QtWidgets.QDateEdit(calendarPopup=True)
            start_time = QtWidgets.QTimeEdit()
            end_time = QtWidgets.QTimeEdit()

            now_local = datetime.now()
            start_date.setDate(now_local.date())
            end_date.setDate(now_local.date())
            start_time.setTime(QtCore.QTime(0, 0))
            end_time.setTime(QtCore.QTime.currentTime())

            layout.addRow("Дата начала:", start_date)
            layout.addRow("Время начала:", start_time)
            layout.addRow("Дата конца:", end_date)
            layout.addRow("Время конца:", end_time)

            btn_ok = QtWidgets.QPushButton("OK")
            btn_cancel = QtWidgets.QPushButton("Отмена")

            btn_ok.clicked.connect(dialog.accept)
            btn_cancel.clicked.connect(dialog.reject)

            h = QtWidgets.QHBoxLayout()
            h.addWidget(btn_ok)
            h.addWidget(btn_cancel)
            layout.addRow(h)

            dialog.setLayout(layout)

            if dialog.exec_() == QtWidgets.QDialog.Accepted:
                start_dt = datetime.combine(start_date.date().toPyDate(), start_time.time().toPyTime())
                end_dt = datetime.combine(end_date.date().toPyDate(), end_time.time().toPyTime())
                # Конвертируем локальное время в UTC
                start = start_dt.astimezone().astimezone(timezone.utc).replace(tzinfo=None)
                end = end_dt.astimezone().astimezone(timezone.utc).replace(tzinfo=None)
            else:
                return None, None

        # Форматируем в тот же формат, что используется в логгере
        start_ts = start.isoformat() + "Z"
        end_ts = end.isoformat() + "Z"
        
        return start_ts, end_ts



if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
