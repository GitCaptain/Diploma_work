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

    def command_handler(self, message: Message) -> None:
        # message.bytes_message = b'command_type ...'
        data = get_decoded_data(message.bytes_message).split()
        data[0] = int(data[0])
        if data[0] == REGISTRATION_SUCCESS:  # переработать (логин может быть занят), вынести в отдельную функцию
            # message.bytes_message  = b'... uid'
            uid = int(data[1])
            self.id = uid
            print("Вы успешно зарегистрированы, id:", uid)
        elif data[0] == AUTHENTICATION_SUCCESS:
            # message.bytes_message  = b'... uid'
            uid = int(data[1])
            self.id = uid
            print("Вход в систему успешно выполнен, id:", uid)
        elif data[0] == USER_ALREADY_EXIST:  # переработать, вынести в отдельную функцию
            print("Пользователь с таким логином уже существует")
        elif data[0] == NOT_AUTHENTICATED:
            print("Невозможно выполнить запрос, сперва необходимо зарегистрироваться или войти")
        elif data[0] == WRONG_LOGIN:
            print("Пользователя с таким логином не существует")
        elif data[0] == WRONG_PASSWORD:
            print("Неверный пароль")

    def message_handler(self, message: Message) -> None:
        print("received from:\n", message.sender_id,
              "\nmessage:\n", get_decoded_data(message.bytes_message), sep="")

    def user_handler(self) -> None:
        print("Список команд для сервера:\n",
              REGISTER_USER, " - Регистрация {login, password}\n",
              AUTHENTICATE_USER, " - Вход {login, password}\n",
              DELETE_USER, " - Удалить аккаунт\n", sep="")
        while True:
            user_input = input("Введите id пользователя, для отправки сообщения(0 - команда серверу)\n")
            if not user_input:
                continue
            message_type = int(user_input)
            if message_type > 0:
                if not self.id:
                    print("Невозможно отправить сообщение. Сперва необходимо войти или зарегистрироваться")
                    continue
                receiver_id = message_type
                sender_id = self.id
                message = Message(message_type=MESSAGE, bytes_message=get_bytes_string(input("Введите сообщение:\n")),
                                  receiver_id=receiver_id, sender_id=sender_id)
            else:
                user_input = input("Введите тип команды\n")
                if not user_input:
                    continue
                message_type = int(user_input)
                message = Message(message_type=COMMAND)
                if message_type == REGISTER_USER or message_type == AUTHENTICATE_USER:
                    login = input("Введите логин\n")
                    password = input("Введите пароль\n")
                    message.bytes_message = get_bytes_string(str(message_type) + " " + login + " " + password)
                elif message_type == DELETE_USER:
                    message.bytes_message = get_bytes_string(str(message_type))
            send_message_to_client(self.server, *get_prepared_message(message))


def main():

    address = '192.168.56.1'
    if len(argv) > 1:
        address = argv[1]

    client = Client(address)
    client.run()


if __name__ == '__main__':
    main()
