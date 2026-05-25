import socket
import json
from datetime import datetime

# Настройки сервера (можешь поменять IP и порт на свои)
HOST = '172.17.46.168'
PORT = 1200

# Начальные данные из твоей СУБД (из файла dataAccess.js)
USERS = [
    {"login": "admin", "password": "123", "role": "admin"},
    {"login": "staff", "password": "111", "role": "employee"}
]

TICKETS = [
    {"ticket_code": "T1", "owner_name": "Иван Петров", "phone": "+7-900-123-45-67", "is_inside": False, "event_name": "Осенний фестиваль", "assigned_zone": "Основной зал", "event_max_capacity": 5},
    {"ticket_code": "T2", "owner_name": "Александр Смирнов", "phone": "+7-901-234-56-78", "is_inside": False, "event_name": "Осенний фестиваль", "assigned_zone": "VIP", "event_max_capacity": 5},
    {"ticket_code": "T3", "owner_name": "Олег Окунев", "phone": "+7-902-345-67-89", "is_inside": False, "event_name": "Конференция безопасности", "assigned_zone": "Главный зал", "event_max_capacity": 3}
]

INCIDENTS = []
INCIDENT_ID_COUNTER = 1

def handle_request(data):
    global INCIDENT_ID_COUNTER
    try:
        request = json.loads(data)
        cmd = request.get('command')
        
        # 1. Получить список всех билетов (аналог команды viewAllTickets)
        if cmd == 'get_tickets':
            return json.dumps({"status": "ok", "tickets": TICKETS}, ensure_ascii=False)
        
        # 2. Получить список всех инцидентов (аналог команды getIncidents)
        elif cmd == 'get_incidents':
            return json.dumps({"status": "ok", "incidents": INCIDENTS}, ensure_ascii=False)
        
        # 3. Сканирование / Проверка билета на входе (аналог processAccess)
        elif cmd == 'process_access':
            ticket_code = request.get('ticket_code')
            current_zone = request.get('zone')  # Зона, на которой стоит охранник
            reporter = request.get('reporter', 'system')

            # Ищем билет в нашей базе
            ticket = next((t for t in TICKETS if t['ticket_code'] == ticket_code), None)

            if not ticket:
                # Если не найден — регистрируем инцидент низкого уровня
                incident = {"id": INCIDENT_ID_COUNTER, "type": "Access", "severity": "Low", "description": f"Unknown ticket: {ticket_code}", "timestamp": datetime.now().isoformat(), "reporter_login": reporter}
                INCIDENTS.append(incident)
                INCIDENT_ID_COUNTER += 1
                return json.dumps({"status": "error", "message": "Билет не найден"}, ensure_ascii=False)

            if ticket['is_inside']:
                # Если уже внутри — инцидент высокого уровня (Повторный вход)
                incident = {"id": INCIDENT_ID_COUNTER, "type": "Security", "severity": "High", "description": f"Duplicate entry: {ticket_code}", "timestamp": datetime.now().isoformat(), "reporter_login": reporter}
                INCIDENTS.append(incident)
                INCIDENT_ID_COUNTER += 1
                return json.dumps({"status": "error", "message": "Повторный вход! Доступ запрещен"}, ensure_ascii=False)

            # Проверка совпадения зон контроля доступа
            if current_zone and ticket['assigned_zone'] != current_zone:
                incident = {"id": INCIDENT_ID_COUNTER, "type": "Security", "severity": "High", "description": f"Zone mismatch for ticket {ticket_code}: expected {ticket['assigned_zone']}, scanned at {current_zone}", "timestamp": datetime.now().isoformat(), "reporter_login": reporter}
                INCIDENTS.append(incident)
                INCIDENT_ID_COUNTER += 1
                return json.dumps({"status": "error", "message": f"Доступ запрещен: билет для зоны {ticket['assigned_zone']}"}, ensure_ascii=False)

            # Если всё успешно пройдено — меняем статус билета
            ticket['is_inside'] = True
            return json.dumps({"status": "ok", "message": "Вход разрешен", "zone": ticket['assigned_zone']}, ensure_ascii=False)
        
        # 4. Ручная регистрация инцидента (аналог reportIncident)
        elif cmd == 'report_incident':
            incident_data = request.get('data', {})
            incident = {
                "id": INCIDENT_ID_COUNTER,
                "type": incident_data.get('type', 'Manual'),
                "severity": incident_data.get('severity', 'Low'),
                "description": incident_data.get('description', 'No description'),
                "timestamp": datetime.now().isoformat(),
                "reporter_login": incident_data.get('reporter_login', 'staff')
            }
            INCIDENTS.append(incident)
            INCIDENT_ID_COUNTER += 1
            return json.dumps({"status": "ok", "message": "Инцидент успешно зарегистрирован"}, ensure_ascii=False)
        
        else:
            return json.dumps({"status": "error", "message": "Неизвестная команда"}, ensure_ascii=False)
            
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(3)
    print(f"Сервер СУБД контроля доступа запущен на {HOST}:{PORT}")
    
    while True:
        conn, addr = server_socket.accept()
        print(f"Подключение от КП (клиента): {addr}")
        
        data = conn.recv(2048).decode('utf-8')
        print(f"Получены JSON-данные: {data}")
        
        if data:
            response = handle_request(data)
            print(f"Отправка ответа клиенту: {response[:100]}...")
            conn.send(response.encode('utf-8'))
        else:
            print("Данные не получены")
        
        conn.close()
        print("Соединение закрыто\n")

if __name__ == '__main__':
    main()