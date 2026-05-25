import socket
import json

# Настройки подключения к твоему серверу (измени IP и порт, если необходимо)
HOST = '217.71.129.139'
PORT = 6063

def send(cmd, data=None):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        
        request = {"command": cmd}
        
        # Интеграция параметров под логику process_access и report_incident
        if cmd == 'process_access' and data:
            request["ticket_code"] = data.get("ticket_code")
            request["zone"] = data.get("zone")
            request["reporter"] = data.get("reporter")
        elif cmd == 'report_incident' and data:
            request["data"] = data
            
        sock.send(json.dumps(request).encode('utf-8'))
        response = sock.recv(2048).decode('utf-8')
        sock.close()
        return json.loads(response)
    except socket.timeout:
        return {"status": "error", "message": "Сервер не отвечает"}
    except ConnectionRefusedError:
        return {"status": "error", "message": "Сервер недоступен"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def main():
    # Запрашиваем данные сессии сотрудника (как в present.js)
    print("="*40)
    print("АУТЕНТИФИКАЦИЯ НА СЛУЖЕБНОМ ПОСТУ")
    print("="*40)
    reporter = input("Введите ваш логин (staff/guard): ") or "staff"
    current_zone = input("Введите имя контролируемой зоны (или Enter для пропуска): ") or None
    
    while True:
        print("\n" + "="*40)
        print("КОНТРОЛЬ ДОСТУПА И БЕЗОПАСНОСТЬ")
        print("="*40)
        print("1. Проверить / Сканировать билет")
        print("2. Просмотр реестра билетов")
        print("3. Журнал инцидентов безопасности")
        print("4. Сообщить об инциденте (вручную)")
        if current_zone:
            print(f"[*] Ваш пост: {current_zone} | Регистратор: {reporter}")
        else:
            print(f"[*] Свободный контроль | Регистратор: {reporter}")
        print("0. Выход")
        print("="*40)
        
        choice = input("Выбор: ")
        
        # 1. Сканирование / Валидация билета
        if choice == '1':
            print("\n--- СКАНИРОВАНИЕ БИЛЕТА ---")
            ticket_code = input("Считайте или введите код билета: ")
            
            payload = {
                "ticket_code": ticket_code,
                "zone": current_zone,
                "reporter": reporter
            }
            
            resp = send('process_access', payload)
            if resp['status'] == 'ok':
                print(f"\n[УСПЕШНО] {resp['message']}")
                print(f"Допуск разрешен в: {resp['zone']}")
            else:
                print(f"\n[ОТКАЗ В ДОСТУПЕ] {resp['message']}")
        
        # 2. Просмотр списка всех билетов
        elif choice == '2':
            resp = send('get_tickets')
            if resp['status'] == 'ok':
                print("\nРЕЕСТР БИЛЕТОВ В СУБД:")
                print(f"{'Код':<6} | {'Владелец':<20} | {'Зона допуска':<15} | {'Статус':<8}")
                print("-" * 60)
                for t in resp['tickets']:
                    status_str = "ВНУТРИ" if t['is_inside'] else "СНАРУЖИ"
                    print(f"{t['ticket_code']:<6} | {t['owner_name']:<20} | {t['assigned_zone']:<15} | {status_str:<8}")
            else:
                print(f"Ошибка получения данных: {resp['message']}")
        
        # 3. Просмотр журнала инцидентов
        elif choice == '3':
            resp = send('get_incidents')
            if resp['status'] == 'ok':
                print("\nЖУРНАЛ НАРУШЕНИЙ:")
                if not resp['incidents']:
                    print("  [Лог пуст. Нарушений не зафиксировано]")
                for i in resp['incidents']:
                    print(f" [{i['id']}] {i['timestamp'][:19]} | Тип: {i['type']} ({i['severity']})")
                    print(f"  Описание: {i['description']}")
                    print(f"  Регистратор: {i['reporter_login']}\n" + "-"*30)
            else:
                print(f"Ошибка получения данных: {resp['message']}")
        
        # 4. Ручной рапорт об инциденте
        elif choice == '4':
            print("\n--- РЕГИСТРАЦИЯ ИНЦИДЕНТА ---")
            i_type = input("Тип нарушения (Security/Access/Manual): ")
            severity = input("Уровень критичности (Low/High): ")
            description = input("Описание происшествия: ")
            
            payload = {
                "type": i_type,
                "severity": severity,
                "description": description,
                "reporter_login": reporter
            }
            
            resp = send('report_incident', payload)
            if resp['status'] == 'ok':
                print(f"\n[ОК] {resp['message']}")
            else:
                print(f"\n[ОШИБКА] {resp['message']}")
        
        elif choice == '0':
            print("Завершение сессии контроля доступа.")
            break
        else:
            print("Неверный ввод. Повторите выбор.")

if __name__ == '__main__':
    main()