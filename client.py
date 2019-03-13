from constants import *
import socket
import threading
from sys import argv
import ssl
from cryptography.fernet import Fernet  # Заменить
from common_functions_and_data_structures import *


def get_input() -> str:
    return input().strip()


class Client:

    def __init__(self, server_hostname: str = 'localhost'):
        server_socket = socket.socket()
        server_socket.connect((server_hostname, PORT_TO_CONNECT))
        self.server = User(address=server_hostname, socket=server_socket)
        self.friendly_users = dict()  # id: User
        self.id = 0  # не аутентифицирован

    def run(self) -> None:
        server_handler_thread = threading.Thread(target=self.server_handler)
        server_handler_thread.start()

        get_pending_thread = threading.Thread(target=self.get_pending_messages)
        get_pending_thread.start()

        user_handler_thread = threading.Thread(target=self.user_handler)
        user_handler_thread.start()

    def server_handler(self) -> None:
        try:
            while True:
                message = get_message_from_client(self.server)
                if not message:  # Что-то пошло не так и сервер отключился
                    break
                if message.message_type == COMMAND:
                    self.command_handler(message)
                elif message.message_type == MESSAGE:
                    self.message_handler(message)
                else:
                    pass
        except Exception as e:
            print("Exception: {}".format(e))
        finally:
            pass

    def get_pending_messages(self) -> None:
        while not self.id:
            pass
        message = Message(message_type=COMMAND, bytes_message=get_bytes_string(str(GET_PENDING_MESSAGES)))
        send_message_to_client(self.server, message)

    def command_handler(self, message: Message) -> None:
        # message.bytes_message = b'command_type ...'
        data = get_decoded_data(message.bytes_message).split()
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
            self.friendly_users[data[1]] = data[2]
            print("Пользователь найден, uid:", data[1])

    def message_handler(self, message: Message) -> None:
        print("received from:\n", message.sender_id,
              "\nmessage:\n", get_decoded_data(message.bytes_message), sep="")

    def get_id_by_login(self) -> None:
        login = input("Введите логин\n")
        if not login:
            return
        message = Message(message_type=COMMAND)
        message.bytes_message = get_bytes_string(str(GET_USER_ID_BY_LOGIN) + " " + login)
        send_message_to_client(self.server, message)

    def authentication(self, auth_type: int) -> None:
        message = Message(message_type=COMMAND)
        login = input("Введите логин\n")
        password = input("Введите пароль\n")
        if not login or not password:
            return
        message.bytes_message = get_bytes_string(str(auth_type) + " " + login + " " + password)
        send_message_to_client(self.server, message)

    def delete_account(self) -> None:
        message = Message(message_type=COMMAND)
        message.bytes_message = get_bytes_string(str(DELETE_USER))
        send_message_to_client(self.server, message)
        self.id = 0
        print("Пользователь удален")

    def log_out(self) -> None:
        message = Message(message_type=COMMAND)
        message.bytes_message = get_bytes_string(str(LOG_OUT))
        send_message_to_client(self.server, message)
        self.id = 0
        print("Вы вышли из системы, войдите или зарегистрируйтесь для продолжения")

    def get_user_message(self) -> None:
        if not self.id:
            print("Невозможно отправить сообщение. Сперва необходимо войти или зарегистрироваться")
            return
        sender_id = self.id
        receiver_id = ""
        while not receiver_id.isdigit():
            receiver_id = input("Введите id получателя:\n")
        receiver_id = int(receiver_id)
        message = Message(message_type=MESSAGE, bytes_message=get_bytes_string(input("Введите сообщение:\n")),
                          receiver_id=receiver_id, sender_id=sender_id)
        send_message_to_client(self.server, message)

    def get_user_command(self) -> None:
        user_input = input("Введите тип команды\n")
        if not user_input:
            return
        message_type = int(user_input)
        if message_type == REGISTER_USER or message_type == AUTHENTICATE_USER:
            self.authentication(message_type)
        elif message_type == DELETE_USER:
            self.delete_account()
        elif message_type == GET_USER_ID_BY_LOGIN:
            self.get_id_by_login()
        elif message_type == LOG_OUT:
            self.log_out()
        else:
            pass

    def user_handler(self) -> None:
        print("Список команд для сервера:\n",
              REGISTER_USER, " - Регистрация {login, password}\n",
              AUTHENTICATE_USER, " - Вход {login, password}\n",
              DELETE_USER, " - Удалить аккаунт\n",
              GET_USER_ID_BY_LOGIN, " - Найти пользователя\n",
              LOG_OUT, " - Выход\n",
              sep="")
        while True:
            user_input = input("Введите тип команды (0 - команда серверу, иначе сообщение человеку)\n")
            if not user_input or not user_input.isdigit():
                continue
            user_input = int(user_input)
            if user_input > 0:
                self.get_user_message()
            else:
                self.get_user_command()


def main():

    address = '192.168.56.1'
    if len(argv) > 1:
        address = argv[1]

    client = Client(address)
    client.run()


if __name__ == '__main__':
    main()
