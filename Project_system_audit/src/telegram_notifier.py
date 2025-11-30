import requests
import textwrap

class TelegramNotifier:
    def __init__(self):
        # Telegram Bot API токен
        self.token = "7268967990:AAFru96kq3zCAL0-I1ui27Y7zEsB5XKj85w"

        # ID твоего чата (получен через getUpdates)
        self.chat_id = 795820434

        # URL для отправки сообщений
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_message(self, text):
        """
        Отправляет сообщение в Telegram.
        Если текст слишком длинный — разбивает на части.
        """

        if not text:
            return

        # Telegram ограничивает длину текста 4096 символами
        max_len = 4000
        lines = text.splitlines()
        chunks = []
        current = ""
        
        for line in lines:
            if len(current) + len(line) + 1 > max_len:
                chunks.append(current)
                current = ""
            current +=line + "\n"
        
        if current: 
            chunks.append(current)

        for chunk in chunks:
            try:
                data = {
                    "chat_id": self.chat_id,
                    "text": chunk,
                    "parse_mode": "HTML"
                }

                response = requests.post(self.api_url, data=data, timeout=5)

                if response.status_code != 200:
                    print("Telegram API error:", response.text)

            except Exception as e:
                print("Telegram send failed:", e)
    
    def send_photo(self, file_obj):
        url = f"https://api.telegram.org/bot{self.token}/sendPhoto"
        files = {"photo": ("report.png", file_obj.getvalue())}
        data = {"chat_id": self.chat_id}

        try:
            r = requests.post(url, data=data, files=files, timeout=5)
            if r.status_code != 200:
                print("Telegram error:", r.text)
        except Exception as e:
            print("Telegram send_photo failed:", e)


    def send_report(self, text, plot_buf):
        if text:
            self.send_message(text)
        if plot_buf:
            self.send_photo(plot_buf)


