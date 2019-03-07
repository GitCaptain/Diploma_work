from constants import *
from database import Database
import socket
import ssl
import threading  # заменить на настоящуюю многопоточность
import hashlib


class Server:

    connected_sockets = dict()  # список подключенных сокетов (клиентов) client_id: client_socket
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
        self.database = Database()

    @staticmethod
    def get_message_from_client(client_socket, data=None):

        if not data:  # служебное сообщение, с данными о клиентсвом сообщении, должно умещаться в один mes_size
            b_message = client_socket.recv(mes_size)  # b_message = b'REQ_TYPE, ...' - ints
        else:  # сообщение от клиента
            # data = b'length, id, ...'
            length = data[0] + len(data)
            client_id = data[1]
            b_message = data
            while len(b_message) < length:
                data = client_socket.recv(min(mes_size, length - len(b_message)))  # Нужно получить не больше чем осталось от сообщения, иначе можно получить начало следующего
                b_message += data

        return b_message

    def send_message(self, id_to_send=None, client_socket=None, message=None):
        if not id_to_send and not client_socket or not message:
            return
        elif not client_socket:
            self.connected_sockets[id_to_send].sendall(message)
        else:
            client_socket.sendall(message)

    def process_command(self, client_socket, data):
        pass

    def client_authentication(self, client_socket):
        # secure_context = ssl.create_default_context()  # возможно нужен не дефолтный контекст, почитать
        # ssl_client = secure_context.wrap_socket(client, server_side=True)
        login, password = get_message_from_client(client_socket).split()  # просто тестирование
        client_exist = self.database.check_person(login, hashlib.sha1(password).hexdigest())
        return client_exist

    def process_client(self, client_socket, client_address):
        # Возможно, что при заверщении работы сервера будет обращение к закрытому клиентскому сокету, и вылезет ошибка,
        # но это не страшно, просто нужно написать какой-нибудь обработчик или закрыть

        client_id = self.client_authentication()

        while client_id < 1:
            if not client_id:
                self.send_message(client_socket=client_socket, message=b"Пользователя с таким логином не существует")
            if client_id < 0:
                self.send_message(client_socket=client_socket, message=b"Неверный пароль")
            client_id = self.client_authentication()

        self.connected_sockets[client_id] = client_socket

        try:
            while True:
                data = self.get_message_from_client(client_socket)  # data = b'REQ_TYPE, ...' - ints
                if not data:
                    break
                if data[0] == MESSAGE:
                    self.process_message(client_socket, data[1:])
                elif data[0] == COMMAND:
                    self.process_command(client_socket, data[1:])
                else:
                    pass
        except Exception as e:
            pass
        finally:
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
            self.connected_sockets.pop(client_id)
            print("disconnected: {}".format(client_address))

    # нужно научиться нормально завершать сервер
    def server_command_handler(self):
        while True:
            command = input()
            if not command.startswith('/'):
                continue
            if command == '/commands':
                for c in self.commands:
                    print(c)
            if command == '/end':
                for c in self.connected_sockets:
                    c.shutdown(socket.SHUT_RDWR)
                    c.close()
                self.connected_sockets.clear()
                self.server_socket.close()
                self.server_socket.shutdown(2)
                print("server stopped")
                break

    def run(self):

        command_handler = threading.Thread(target=self.server_command_handler)
        command_handler.start()

        print("type /commands to see a list of available commands")
        print("the server is running\nhost: {}, port: {}".format(socket.gethostbyname(socket.getfqdn()), port_to_connect))

        while True:
            connected_socket, connected_addres = self.server_socket.accept()
            print("connected:", connected_addres)
            send_thread = threading.Thread(target=self.process_client, args=(connected_socket, connected_addres))
            send_thread.start()


def main():
    server = Server()
    server.run()


if __name__ == '__main__':
    main()
