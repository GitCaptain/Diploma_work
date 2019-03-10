from constants import *
from database import Database
import socket
import ssl
import threading  # заменить на настоящуюю многопоточность
import hashlib


class User:
    # Структура, содержащая данные о клиенте
    def __init__(self, socket: socket.socket, client_id: int = None, address: str = None):
        self.socket = socket
        self.id = client_id
        self.address = address


class Message:
    # Структура содержащая данные о сообщении
    def __init__(self, message_type: int = None, receiver_id: int = None, sender_id: int = None, length: int = None, bytes_message: bytes = None):
        self.message_type = message_type
        self.receiver_id = receiver_id
        self.length = length
        self.bytes_message = bytes_message
        self.sender_id = sender_id


class Server:

    connected_users = dict()  # список подключенных user'ов (клиентов) client_id: user
    host = ''  # Подключение принимаем от любого компьютера в сети
    max_queue = 5  # число соединений, которые будут находиться в очереди соединений до вызова accept
    # список команд доступных для сервера
    commands = ['/commands - показать список команд и их описание',
                '/end - остановить работу сервера']

    def __init__(self):
        # создаем сокет, работающий по протоколу TCP
        self.server_socket = socket.socket()
        # (хост, порт) = хост - машина которую мы слушаем, если не указана, то принимаются связи от всех машин,
        # порт - номер порта который принимает соединение
        self.server_socket.bind((self.host, port_to_connect))
        self.server_socket.listen(self.max_queue)
        self.thread_locals = threading.local()
        # Инициализируем базу данных
        Database(need_init=True)

    @staticmethod
    def get_hash(string: str, hash_func=hashlib.sha1) -> str:
        return hash_func(string).hexidigest()

    @staticmethod
    def get_message_from_client(user: User) -> MESSAGE:

        # служебное сообщение, с данными о клиентсвом сообщении, должно умещаться в один mes_size
        message_data = user.socket.recv(mes_size)  # message_data = b'MESS_TYPE length receiver_id ...'
        if not message_data:  # Клиент отключился
            return None
        message_data.split()

        length = int(message_data[1])
        b_message = ""
        while len(b_message) < length:
            # Нужно получить не больше чем осталось от сообщения, иначе можно получить начало следующего
            message_part = user.socket.recv(min(mes_size, length - len(b_message)))
            if not message_part:  # Клиент отключился
                b_message = None
                break
            b_message += message_part
        message = MESSAGE(message_type=int(message_data[0]),
                          receiver_id=message_data[2],
                          message_length=length,
                          bytes_message=b_message
                          )
        return message

    def send_message_to_client(self, receiver: User, message_data: bytes, message: bytes) -> None:
        # Возможно, параметр receiver - ненужен, и вообще метод возможно следует сделать статичкским
        if not receiver.id and not receiver.socket or not message_data:
            return
        elif not receiver.socket:
            client_socket = self.connected_users[receiver.id]
        else:
            client_socket = receiver.socket
        client_socket.sendall(message_data)
        client_socket.sendall(message)

    def process_command(self, user: User, message: MESSAGE) -> int:
        if not message.bytes_message:
            return False
        # message.bytes_message = b'command_type ...'
        data = message.bytes_message.split()
        data[0] = int(data[0])
        if data[0] == REGISTER_USER:
            # message.bytes_message  = b'... login password'
            uid = self.thread_locals.database.add_user(data[1], Server.get_hash(data[2]))
            return uid
        elif data[0] == DELETE_USER:
            if not user.id:
                return False
            self.thread_locals.database.delete_user(user.id)
            return True
        elif data[0] == AUTHENTICATE_USER:
            if not user.socket or not self.client_authentication(user):
                return False
            return True

    @staticmethod
    def get_prepared_message(message: MESSAGE) -> tuple(bytes, bytes):
        message.length = len(message.bytes_message)
        message_data = bytes("{message_type} {length} {sender_id}".format(
                        message_type=message.message_type, length=message.length, sender_id=message.sender_id
                        ), encoding)

        return message_data, message.bytes_message

    def client_authentication(self, user: User) -> bool:
        # secure_context = ssl.create_default_context()  # возможно нужен не дефолтный контекст, почитать
        # ssl_client = secure_context.wrap_socket(client, server_side=True)

        response_message = MESSAGE(message_type=COMMAND, sender_id=user.id)
        while user.id is None or user.id < 1:
            if user.id == WRONG_LOGIN:
                response_message.bytes_string = bytes(str(WRONG_LOGIN), encoding)
                self.send_message_to_client(user, *Server.get_prepared_message(response_message))
            elif user.id == WRONG_PASSWORD:
                response_message.bytes_string = bytes(str(WRONG_PASSWORD), encoding)
                self.send_message_to_client(user, *Server.get_prepared_message(response_message))
            message = Server.get_message_from_client(user)
            if not message.bytes_message:
                return False
            login, password = message.bytes_message.split()  # просто для тестирования, потом будет шифрование и т.д.
            user.id = self.thread_locals.database.check_person(login, Server.get_hash(password))
        response_message.bytes_string = bytes(str(AUTHENTICATION_SUCCESS), encoding)
        self.send_message_to_client(user, *Server.get_prepared_message(response_message))
        return True

    def process_message(self, message: MESSAGE) -> None:
        receiver = self.connected_users[message.receiver_id]
        self.send_message_to_client(receiver, *Server.get_prepared_message(message))

    def process_client(self, user: User) -> None:
        # Возможно, что при заверщении работы сервера будет обращение к закрытому клиентскому сокету, и вылезет ошибка,
        # но это не страшно, просто нужно написать какой-нибудь обработчик или закрыть

        self.thread_locals.database = Database()
        authenticated = self.client_authentication(user)
        if not authenticated:
            return
        self.connected_users[user.id] = user
        try:
            while True:
                message = Server.get_message_from_client(user)
                if not message.bytes_message:
                    break
                if message.message_type == MESSAGE:
                    self.process_message(message)
                elif message.message_type == COMMAND:
                    self.process_command(user, message)
                else:
                    pass
        except Exception as e:
            print("Exception: {}".format(e.args[0]))
        finally:
            user.socket.shutdown(socket.SHUT_RDWR)
            user.socket.close()
            self.connected_users.pop(user.id)
            print("disconnected: {}".format(user.address))

    # нужно научиться нормально завершать сервер
    def server_command_handler(self) -> None:
        while True:
            command = input()
            if not command.startswith('/'):
                continue
            if command == '/commands':
                for c in self.commands:
                    print(c)
            if command == '/end':
                for c in self.connected_users:
                    c.socket.shutdown(socket.SHUT_RDWR)
                    c.socket.close()
                self.connected_users.clear()
                self.server_socket.close()
                self.server_socket.shutdown(2)
                print("server stopped")
                break

    def run(self) -> None:
        command_handler = threading.Thread(target=self.server_command_handler)
        command_handler.start()
        print("type /commands to see a list of available commands")
        print("the server is running\nhost: {}, port: {}".format(
            socket.gethostbyname(socket.getfqdn()),
            port_to_connect)
        )

        while True:
            connected_socket, connected_addres = self.server_socket.accept()
            print("connected:", connected_addres)
            user = User(socket=connected_socket, address=connected_addres)
            send_thread = threading.Thread(target=self.process_client, args=(user,))
            send_thread.start()


def main():
    server = Server()
    server.run()


if __name__ == '__main__':
    main()
