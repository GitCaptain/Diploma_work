from constants import *
import socket
import ssl
import threading  # заменить на настоящуюю многопоточность


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

    def process_message(self, data, client):
        # data = b'length, id, ...'
        length = data[0] + len(data)
        client_id = data[1]
        b_message = data

        # получение сообщения
        while len(b_message) < length:
            data = client.recv(min(mes_size, length - len(b_message)))  # Нужно получить не больше чем осталось от сообщения, иначе можно получить начало следующего
            b_message += data

        # отправка сообщения
        self.connected_sockets[client_id].sendall(data)

    def process_command(self, data, client):
        pass

    def get_client_id(self, client, client_address):
        pass

    def client_authentication(self, client):
        secure_context = ssl.create_default_context()  # возможно нужен не дефолтный контекст, почитать
        ssl_client = secure_context.wrap_socket(client, server_side=True)




    def process_client(self, client, client_address):
        # Возможно, что при заверщении работы сервера будет обращение к закрытому клиентскому сокету, и вылезет ошибка,
        # но это не страшно, просто нужно написать какой-нибудь обработчик или закрыть

        self.client_authentication()

        client_id = self.get_client_id(client, client_address)  # Получать ID нужно из базы данных, после того как клиент успешно авторизуется
        self.connected_sockets[client_id] = client
        client.sendall(bytes("your ID: " + client_id + "\n", encoding))

        try:
            while True:

                data = client.recv(mes_size)  # data = b'REQ_TYPE, ...' - ints

                if not data:
                    break

                if data[0] == MESSAGE:
                    self.process_message(data[1:], client)
                elif data[0] == COMMAND:
                    self.process_command(data[1:], client)
                else:
                    pass
        except Exception as e:
            pass
        finally:
            client.shutdown(socket.SHUT_RDWR)
            client.close()
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
