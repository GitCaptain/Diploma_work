from common_functions_and_data_structures import *
from database import Database
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import threading  # заменить на настоящуюю многопоточность
import traceback
import ssl


class Server:

    authenticated_users = dict()  # список подключенных user'ов (клиентов) client_id: user
    host = ''  # Подключение принимаем от любого компьютера в сети
    max_queue = 5  # число соединений, которые будут находиться в очереди соединений до вызова accept
    # список команд доступных для сервера
    commands = ['/commands - показать список команд и их описание',
                '/end - остановить работу сервера']

    def __init__(self):
        # создаем сокет, работающий по протоколу TCP
        self.server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        # (хост, порт) = хост - машина которую мы слушаем, если не указана, то принимаются связи от всех машин,
        # порт - номер порта который принимает соединение
        self.server_socket.bind((self.host, PORT_TO_CONNECT))
        self.server_socket.listen(self.max_queue)
        self.thread_locals = threading.local()
        self.id = SERVER_ID
        # Инициализируем базу данных
        Database(need_server_init=True)

    def process_command(self, user: User, message: Message) -> bool:  # разнести все по функциям
        # message.message = 'command_type ...'
        data = message.message.split()
        command = int(data[0])
        if not self.thread_locals.user_authenticated and command != LOG_IN and command != REGISTER_USER:
            message = Message(message_type=COMMAND, message=str(NOT_AUTHENTICATED))
            send_message_to_client(user, message)
            return False
        if command == REGISTER_USER:
            # data  = [..., 'login', 'password']
            if not self.client_registration(user, data[1], data[2]):
                return False
            return True
        elif command == DELETE_USER:  # переработать, вынести в отдельную функцию
            self.thread_locals.user_authenticated = False
            if not user.id:
                return False
            self.thread_locals.database.delete_user(user.id)
            self.authenticated_users.pop(user.id)
            user.id = 0
            return True
        elif command == LOG_IN:
            # data = [..., 'login', 'password']
            if not self.client_authentication(user, data[1], data[2]):
                return False
            return True
        elif command == GET_USER_ID_BY_LOGIN:  # переработать, вынести в отдельную функцию
            # data = [..., 'login']
            login = data[1]
            uid = self.thread_locals.database.get_id_by_login(login)
            message = Message(message_type=COMMAND)
            if uid == DB_USER_NOT_EXIST:
                message.message = str(USER_NOT_EXIST)
            else:
                message.message = "{} {} {}".format(USER_FOUND, uid, login)
            send_message_to_client(user, message)
        elif command == LOG_OUT:  # переработать, вынести в отдельную функцию
            self.thread_locals.user_authenticated = False
            if not user.id:
                return False
            self.authenticated_users.pop(user.id)
            user.id = 0
            return True
        elif command == GET_PENDING_MESSAGES:
            pendings = self.thread_locals.database.get_pending_messages(user.id)
            message = Message(message_type=MESSAGE, receiver_id=user.id)
            for sender_id, pending_message in pendings:
                message.sender_id = sender_id
                message.message = pending_message
                send_message_to_client(user, message)
        elif command == CREATE_P2P_CONNECTION:
            # data = [..., 'P2P_CONNECTION_TYPE', 'peer_id','con_type'] or
            # data = [..., 'P2P_ADDRESS', 'peer_id', 'private_ip', 'private_port']
            command_type = int(data[1])
            second_peer_id = int(data[2])
            message = Message(message_type=COMMAND, receiver_id=user.id)
            if second_peer_id not in self.authenticated_users:
                message.message = str(P2P_USER_OFFLINE)
                send_message_to_client(user, message)
                return False
            second_peer = self.authenticated_users[second_peer_id]

            message = Message(message_type=COMMAND, receiver_id=second_peer.id)
            command_to_peer = P2P_CONNECTION_DATA
            if command_type == P2P_ADDRESS:
                user_private_address = data[3], int(data[4])
                message.message = "{} {} {} {} {} {} {}".format(command_to_peer, command_type, user.id,
                                                                *user.public_address, *user_private_address)
            elif command_type == P2P_CONNECTION_TYPE:
                message.message = "{} {} {} {}".format(command_to_peer, command_type, user.id, data[3])

            send_message_to_client(second_peer, message)

        else:
            pass

    def client_registration(self, user: User, login: str, password: str) -> bool:
        uid = self.thread_locals.database.add_user(login, get_hash(password))

        response_message = Message(message_type=COMMAND, sender_id=self.id)
        if uid == DB_USER_ALREADY_EXIST:
            response_message.message = str(USER_ALREADY_EXIST)
            send_message_to_client(user, response_message)
            return False
        user.id = uid
        self.thread_locals.user_authenticated = True
        self.authenticated_users[user.id] = user
        response_message.message = "{} {}".format(REGISTRATION_SUCCESS, uid)
        send_message_to_client(user, response_message)
        return True

    def client_authentication(self, user: User, login: str, password: str) -> bool:
        # secure_context = ssl.create_default_context()  # возможно нужен не дефолтный контекст, почитать
        # ssl_client = secure_context.wrap_socket(client, server_side=True)
        uid = self.thread_locals.database.check_person(login, get_hash(password))
        response_message = Message(message_type=COMMAND, sender_id=self.id)
        if uid == DB_WRONG_LOGIN:
            response_message.message = str(WRONG_LOGIN)
            send_message_to_client(user, response_message)
            return False
        elif uid == DB_WRONG_PASSWORD:
            response_message.message = str(WRONG_PASSWORD)
            send_message_to_client(user, response_message)
            return False
        user.id = uid
        self.thread_locals.user_authenticated = True
        self.authenticated_users[user.id] = user
        response_message.message = "{} {}".format(AUTHENTICATION_SUCCESS, uid)
        send_message_to_client(user, response_message)
        return True

    def process_message(self, message: Message) -> None:
        if message.receiver_id in self.authenticated_users:
            receiver = self.authenticated_users[message.receiver_id]
            send_message_to_client(receiver, message)
        elif self.thread_locals.database.check_if_user_exist(user_id=message.receiver_id):
            self.thread_locals.database.add_pending_message(sender_id=message.sender_id,
                                                            receiver_id=message.receiver_id,
                                                            message=message.message)
        else:
            receiver = self.authenticated_users[message.sender_id]
            message.receiver_id = message.sender_id
            message.sender_id = 0
            message.message_type = COMMAND
            message.message = str(USER_NOT_EXIST)
            send_message_to_client(receiver, message)

    def process_client(self, user: User) -> None:
        # Возможно, что при заверщении работы сервера будет обращение к закрытому клиентскому сокету, и вылезет ошибка,
        # но это не страшно, просто нужно написать какой-нибудь обработчик или закрыть
        self.thread_locals.user_authenticated = False
        self.thread_locals.database = Database()
        try:
            while True:
                message = get_message_from_client(user)
                if not message:
                    break
                if self.thread_locals.user_authenticated and message.message_type == MESSAGE:
                    self.process_message(message)
                elif message.message_type == COMMAND:
                    self.process_command(user, message)
                else:
                    pass
        except Exception as e:
            print(traceback.format_exc())
            print("Exception: {}".format(e.args))
        finally:
            user.socket.shutdown(socket.SHUT_RDWR)
            user.socket.close()
            if user.id:
                self.authenticated_users.pop(user.id)
            print("disconnected: {}".format(user.public_address))

    def stop_client_handling(self):
        pass

    # нужно научиться нормально завершать сервер
    def server_command_handler(self) -> None:
        print("type /commands to see a list of available commands")
        while True:
            command = input()
            if not command.startswith('/'):
                continue
            if command == '/commands':
                for c in self.commands:
                    print(c)
            if command == '/end':
                for c in self.authenticated_users:
                    c.socket.shutdown(socket.SHUT_RDWR)
                    c.socket.close()
                self.authenticated_users.clear()
                self.server_socket.close()
                self.server_socket.shutdown(2)
                print("server stopped")
                break

    def run(self) -> None:
        command_handler = threading.Thread(target=self.server_command_handler)
        command_handler.start()
        print("the server is running\nhost: {}, port: {}".format(
            socket.gethostbyname(socket.getfqdn()),
            PORT_TO_CONNECT)
        )
        secure_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        secure_context.load_cert_chain(certfile='secure/server.pem', keyfile='secure/server.key')
        while True:
            connected_socket, connected_addres = self.server_socket.accept()
            print("connected:", connected_addres)

            secure_connected_socket = secure_context.wrap_socket(connected_socket, server_side=True)
            symmetric_key = get_random_bytes(16)  # 128 bit length key is enough
            send_message_to_client(User(sock=secure_connected_socket),
                                   message=Message(message_type=AUTH, message=symmetric_key))
            connected_socket = secure_connected_socket.unwrap()

            user = User(sock=connected_socket, public_address=connected_addres, symmetric_key=symmetric_key)
            process_user_thread = threading.Thread(target=self.process_client, args=(user,))
            process_user_thread.start()


def main():
    server = Server()
    server.run()


if __name__ == '__main__':
    main()
