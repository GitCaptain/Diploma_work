from constants import *
import socket
import threading
from sys import argv
import ssl
from cryptography.fernet import Fernet  # Заменить
from common_functions_and_data_structures import *
import traceback


def get_input() -> str:
    return input().strip()


class Friend(User):
    def __init__(self, socket: 'socket.socket' = None, client_id: int = 0, address: 'tuple(str, int)' = None, login: str = ''):
        super().__init__(socket, client_id, address)
        self.login = login


class Client:

    def __init__(self, server_hostname: str = 'localhost'):
        server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        server_socket.connect((server_hostname, PORT_TO_CONNECT))
        self.private_address = server_socket.getsockname()
        self.server = Friend(address=server_hostname, socket=server_socket, client_id=0)
        self.friendly_users = dict()  # id: Friend
        self.p2p_connected = dict()  # id: Friend
        self.id = 0  # не аутентифицирован

    def run(self) -> None:
        server_handler_thread = threading.Thread(target=self.server_handler)
        server_handler_thread.start()

        user_handler_thread = threading.Thread(target=self.user_handler)
        user_handler_thread.start()

    def server_handler(self, target: Friend = None) -> None:
        if not target:
            target = self.server
        try:
            while True:
                message = get_message_from_client(target)
                if not message:  # Что-то пошло не так и сервер отключился
                    break
                if message.message_type == COMMAND:
                    self.command_handler(message)
                elif message.message_type == MESSAGE:
                    self.message_handler(message)
                else:
                    pass
        except Exception as e:
            print(traceback.format_exc())
            print("id:", target.id)
        finally:
            pass

    def get_pending_messages(self) -> None:
        while not self.id:
            pass
        message = Message(message_type=COMMAND, message=str(GET_PENDING_MESSAGES))
        send_message_to_client(self.server, message)

    def command_handler(self, message: Message) -> None:
        # message.bytes_message = b'command_type ...'
        data = message.message.split()
        command = int(data[0])
        if command == REGISTRATION_SUCCESS:  # переработать (логин может быть занят), вынести в отдельную функцию
            # message.bytes_message  = b'... uid'
            uid = int(data[1])
            self.id = uid
            print("Вы успешно зарегистрированы, id:", uid)
        elif command == AUTHENTICATION_SUCCESS:
            # message.bytes_message  = b'... uid'
            uid = int(data[1])
            self.id = uid
            print("Вход в систему успешно выполнен, id:", uid)
        elif command == USER_ALREADY_EXIST:  # переработать, вынести в отдельную функцию
            print("Пользователь с таким логином уже существует")
        elif command == NOT_AUTHENTICATED:
            print("Невозможно выполнить запрос, сперва необходимо зарегистрироваться или войти")
        elif command == WRONG_LOGIN:
            print("Пользователя с таким логином не существует")
        elif command == WRONG_PASSWORD:
            print("Неверный пароль")
        elif command == USER_NOT_EXIST:
            print("Пользователь не найден")
        elif command == USER_FOUND:
            # message.bytes_message = b'... uid login'
            uid = int(data[1])
            self.friendly_users[uid] = Friend(client_id=uid, login=data[2])
            print("Пользователь найден, uid:", data[1])
        elif command == P2P_CONNECTION_DATA:
            print("Подключено к", data[1])
            # message.bytes_message = b'... uid ip port'
            friend_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            friend_id = int(data[1])
            friend_address = data[2], int(data[3])
            friend_socket.connect(friend_address)
            friend = Friend(socket=friend_socket, client_id=friend_id, address=friend_address)
            self.p2p_connected[friend_id] = friend
            tunnel_connection_thread = threading.Thread(target=self.server_handler, args=(friend,))
            tunnel_connection_thread.start()
        elif command == P2P_ACCEPT_CONNECTION:
            friend_socket, friend_address = self.server.socket.accept()
            friend = Friend(socket=friend_socket, address=friend_address)
            tunnel_connection_thread = threading.Thread(target=self.server_handler, args=(friend,))
            tunnel_connection_thread.start()
        elif command == USER_OFFLINE:
            print("Пользователь сейчас не в сети")
        else:
            pass

    def message_handler(self, message: Message) -> None:
        print("received from:\n", message.sender_id,
              "\nmessage:\n", message.message, sep="")

    def get_id_by_login(self) -> None:
        login = input("Введите логин\n")
        if not login:
            return
        message = Message(message_type=COMMAND)
        message.message = "{} {}".format(GET_USER_ID_BY_LOGIN, login)
        send_message_to_client(self.server, message)

    def log_in(self, auth_type: int) -> None:
        if self.id:
            print("Вы уже вошли")
            return
        if auth_type == LOG_IN:
            get_pending_thread = threading.Thread(target=self.get_pending_messages)
            get_pending_thread.start()
        message = Message(message_type=COMMAND)
        login = input("Введите логин\n")
        password = input("Введите пароль\n")
        if not login or not password:
            return

        message.message = "{} {} {}".format(auth_type, login, password)
        send_message_to_client(self.server, message)

    def delete_account(self) -> None:
        message = Message(message_type=COMMAND)
        message.message = str(DELETE_USER)
        send_message_to_client(self.server, message)
        self.id = 0
        print("Пользователь удален")

    def log_out(self) -> None:
        message = Message(message_type=COMMAND)
        message.message = str(LOG_OUT)
        send_message_to_client(self.server, message)
        self.id = 0
        print("Вы вышли из системы, войдите или зарегистрируйтесь для продолжения")

    def get_user_message(self, p2p=False) -> None:
        if not self.id:
            print("Невозможно отправить сообщение. Сперва необходимо войти или зарегистрироваться")
            return
        sender_id = self.id
        receiver_id = ""
        while not receiver_id.isdigit():
            receiver_id = input("Введите id получателя:\n")
        receiver_id = int(receiver_id)
        if not p2p:
            target = self.server
        else:
            if receiver_id in self.p2p_connected:
                target = self.p2p_connected[receiver_id]
            else:
                print("Подключение не установлено")
                return
        message = Message(message_type=MESSAGE, message=input("Введите сообщение:\n"),
                          receiver_id=receiver_id, sender_id=sender_id)
        send_message_to_client(target, message)

    def get_user_command(self) -> None:
        user_input = input("Введите тип команды\n")
        if not user_input:
            return
        message_type = int(user_input)
        if message_type == REGISTER_USER or message_type == LOG_IN:
            self.log_in(message_type)
        elif message_type == DELETE_USER:
            self.delete_account()
        elif message_type == GET_USER_ID_BY_LOGIN:
            self.get_id_by_login()
        elif message_type == LOG_OUT:
            self.log_out()
        elif message_type == CREATE_P2P_CONNECTION:
            self.create_p2p_connection()
        else:
            pass

    def user_handler(self) -> None:
        print("Список команд для сервера:\n",
              REGISTER_USER, " - Регистрация {login, password}\n",
              LOG_IN, " - Вход {login, password}\n",
              DELETE_USER, " - Удалить аккаунт\n",
              GET_USER_ID_BY_LOGIN, " - Найти пользователя\n",
              CREATE_P2P_CONNECTION, " - Создать p2p соединение\n",
              LOG_OUT, " - Выход\n",
              sep="")
        while True:
            user_input = input("Введите тип команды (0 - команда серверу, 1 - человеку, 2 - человеку напрямую)\n")
            if not user_input or not user_input.isdigit():
                continue
            user_input = int(user_input)
            if user_input == 0:
                self.get_user_command()
            elif user_input == 1:
                self.get_user_message()
            elif user_input == 2:
                self.get_user_message(True)

    def create_p2p_connection(self, user_id=None):
        user_id = int(input("Введите id пользователя\n"))
        if user_id in self.p2p_connected:
            return
        message = Message(message_type=COMMAND, sender_id=self.id)
        message.message = "{} {}".format(CREATE_P2P_CONNECTION, user_id)
        send_message_to_client(self.server, message)


def main():

    address = '192.168.56.1'
    if len(argv) > 1:
        address = argv[1]

    client = Client(address)
    client.run()


if __name__ == '__main__':
    main()
