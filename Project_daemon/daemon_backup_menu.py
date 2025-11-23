import os

def start_daemon():
    os.system("sudo systemctl start mybackup")
    print("Демон запущен.")

def stop_daemon():
    os.system("sudo systemctl stop mybackup")
    print("Демон остановлен.")

def restart_daemon():
    os.system("sudo systemctl restart mybackup")
    print("Демон перезапущен.")

def enable_daemon():
    os.system("sudo systemctl enable mybackup")
    print("Автозапуск демона включен")

def show_status():
    status_path = "/home/vboxuser/Project_mybackup/status.json"
    if os.path.exists(status_path):
        with open(status_path, 'r', encoding='utf-8') as f:
            data = f.read()
        print(data)
    else:
        print("Статус-файл не найден.")

def show_logs():
    os.system("sudo journalctl -u mybackup -n 20 --no-pager")

def reload_daemon():
    os.system("sudo systemctl daemon-reload")
    print("Демон перезагружен")

def main_menu():
    while True:
        print("Menu")
        print("1. Запустить демон")
        print("2. Остановить демон")
        print("3. Перезапустить демон")
        print("4. Показать статус")
        print("5. Просмотреть журнал")
        print("6. Выйти")
        print("7. Перезагрузка")
        print("8. Автозапуск")

        choice = input("Выберите действие (1-8): ").strip()

        if choice == "1":
            start_daemon()
        elif choice == "2":
            stop_daemon()
        elif choice == "3":
            restart_daemon()
        elif choice == "4":
            show_status()
        elif choice == "5":
            show_logs()
        elif choice == "6":
            break
        elif choice == "7":
            reload_daemon()
        elif choice == "8":
            enable_daemon()()
        else:
            print("Неверный ввод. Попробуйте снова.")

if __name__ == "__main__":
    main_menu()