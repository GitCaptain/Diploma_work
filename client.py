import socket
import threading
import ssl
from cryptography.fernet import Fernet  # Заменить
from common_functions_and_data_structures import *
import traceback
import sys
import time
import selectors


def get_input(prompt_str: str) -> str:
    return input(prompt_str).strip()


class Friend(User):
    def __init__(self, socket: 'socket.socket' = None, client_id: int = 0,
                 public_address: 'tuple(str, int)' = None, private_address: 'tuple(str, int)' = None, login: str = ''):
        super().__init__(socket, client_id, public_address)
        self.login = login
        self.private_address = private_address


class Client:

    def __init__(self, server_hostname: str = 'localhost'):
        server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        self.p2p_tcp_connection_possible = True
        try:
            if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):  # linux, Mac OS
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, True)
            elif sys.platform == 'win32' or sys.platform == 'cygwin':  # windows
                # on Windows, REUSEADDR already implies REUSEPORT
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        except:
            self.p2p_tcp_connection_possible = False

        server_socket.connect((server_hostname, PORT_TO_CONNECT))
        self.private_address = server_socket.getsockname()

        if self.p2p_tcp_connection_possible:
            self.max_queue = 5
            self.p2p_listener = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            self.p2p_listener.bind(self.private_address)
            self.p2p_listener.listen(self.max_queue)

        self.server = Friend(public_address=server_hostname, socket=server_socket, client_id=0)
        self.friendly_users = dict()  # id: Friend
        self.p2p_connected = dict()  # id: Friend
        self.id = 0  # не аутентифицирован
        self.lock = threading.Lock()

    def run(self) -> None:
        server_handler_thread = threading.Thread(target=self.server_handler)
        server_handler_thread.start()

        user_handler_thread = threading.Thread(target=self.user_handler)
        user_handler_thread.start()

        peer_keep_alive_thread = threading.Thread(target=self.peer_handler)
        peer_keep_alive_thread.start()

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
            print("Exception: {}".format(e.args))
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
        # message.message = 'command_type ...'
        data = message.message.split()
        command = int(data[0])
        if command == REGISTRATION_SUCCESS:  # переработать (логин может быть занят), вынести в отдельную функцию
            # data = [.., 'uid']
            uid = int(data[1])
            self.id = uid
            print("Вы успешно зарегистрированы, id:", uid)
        elif command == AUTHENTICATION_SUCCESS:
            # data  = [.., 'uid']
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
            # data = [.., 'uid', 'login']
            uid = int(data[1])
            self.friendly_users[uid] = Friend(client_id=uid, login=data[2])
            print("Пользователь найден, uid:", data[1])
        elif command == P2P_ACCEPT_CONNECTION or command == P2P_CONNECTION_DATA:
            # data = [..., 'uid', 'con_type', 'private_ip', 'private_port', 'public_ip', 'public_port']
            peer_uid = int(data[1])
            con_type = int(data[2])

            if con_type == P2P_UDP or not self.p2p_tcp_connection_possible:
                con_type = P2P_UDP
            else:
                con_type = P2P_TCP

            peer_priv = data[3], int(data[4])
            peer_pub = data[5], int(data[6])
            peer = Friend(client_id=peer_uid, public_address=peer_pub, private_address=peer_priv)

            if command == P2P_ACCEPT_CONNECTION:
                self.create_p2p_connection(int(data[1]), False)

            initiator = False
            if command == P2P_CONNECTION_DATA:
                initiator = True

            if con_type == P2P_TCP:
                self.begin_p2p_tcp_connection(peer, initiator)
            elif con_type == P2P_UDP:
                self.begin_p2p_udp_connection(peer, initiator)
            else:
                pass
        elif command == P2P_USER_OFFLINE:
            print("Пользователь сейчас не в сети")
        elif command == P2P_KEEP_ALIVE:
            print("connection keeps alive")
        else:
            pass

    def message_handler(self, message: Message) -> None:
        print("received from:\n", message.sender_id,
              "\nmessage:\n", message.message, sep="")

    def get_id_by_login(self) -> None:
        login = get_input("Введите логин\n")
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
        login = get_input("Введите логин\n")
        password = get_input("Введите пароль\n")
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
            receiver_id = get_input("Введите id получателя:\n")
        receiver_id = int(receiver_id)
        if not p2p:
            target = self.server
        else:
            if receiver_id in self.p2p_connected:
                target = self.p2p_connected[receiver_id]
            else:
                print("Подключение не установлено")
                return
        message = Message(message_type=MESSAGE, message=get_input("Введите сообщение:\n"),
                          receiver_id=receiver_id, sender_id=sender_id)
        send_message_to_client(target, message)

    def get_user_command(self) -> None:
        user_input = get_input("Введите тип команды\n")
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
            user_id = int(get_input("Введите id пользователя\n"))
            self.create_p2p_connection(user_id)
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
            user_input = get_input("Введите тип команды (0 - команда серверу, 1 - человеку, 2 - человеку напрямую)\n")
            if not user_input or not user_input.isdigit():
                continue
            user_input = int(user_input)
            if user_input == 0:
                self.get_user_command()
            elif user_input == 1:
                self.get_user_message()
            elif user_input == 2:
                self.get_user_message(True)

    def create_p2p_connection(self, user_id: int, create: bool = True):
        if user_id in self.p2p_connected:
            return
        message = Message(message_type=COMMAND, sender_id=self.id)

        if self.p2p_tcp_connection_possible:
            con_type = P2P_TCP
        else:
            con_type = P2P_UDP

        if create:
            command = CREATE_P2P_CONNECTION
        else:
            command = P2P_CONNECTION_DATA
        message.message = "{} {} {} {} {}".format(command, user_id, con_type, *self.private_address)
        send_message_to_client(self.server, message)

    def begin_p2p_tcp_connection(self, peer: Friend, initiator: bool = True):

        private_connector = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        public_connector = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        connection_attempts = 0
        max_connection_attempts = 5
        priv_connected = False
        pub_connected = False
        peer_accepted = False
        connection_done = False
        selector = selectors.DefaultSelector()
        selector.register(self.p2p_listener, selectors.EVENT_READ)

        def setup_connection(socket, address, connected_status):
            if not connected_status:
                try:
                    socket.connect(address)
                except socket.error as e:
                    print(traceback.format_exc())
                    print(e.strerror)
                    time.sleep(1)
                else:
                    connected_status = True
            return connected_status

        while connection_attempts < max_connection_attempts:
            connection_attempts += 1

            priv_connected = setup_connection(private_connector, peer.private_address, priv_connected)
            pub_connected = setup_connection(public_connector, peer.public_address, pub_connected)

            listener = selector.select(timeout=1)  # wait 1 sec at most

            if listener:  # Входящее соединение
                # listener = [(), ..]
                listener = listener[0][0].fileobj  # self.p2p_listener
                peer.socket, _ = listener.accept()
                peer_accepted = True
                # handshake()


            if priv_connected:
                # handshake()
                pass
            if pub_connected:
                pass
                # handshake()

            sock = None
            if initiator:
                # проверить статусы рукопожатий и добавить пиров в порядке: приват, паблик, ацептед
                if priv_connected:
                    sock = private_connector
                elif pub_connected:
                    sock = private_connector
                elif peer_accepted:
                    sock = peer.socket
            else:
                # проверить статусы рукопожатий и добавить пиров в порядке: ацептед, приват, паблик
                if peer_accepted:
                    sock = peer.socket
                elif priv_connected:
                    sock = private_connector
                elif pub_connected:
                    sock = private_connector

            if sock:
                peer.socket = sock
                self.lock.acquire()
                self.p2p_connected[peer.id] = peer
                mes = Message(message_type=MESSAGE, message="hello, peer!")
                send_message_to_client(peer, mes)
                self.lock.release()
                connection_done = True

            if connection_done:  # если подключение установилось завершаем цикл
                break
        if connection_done:
            print("connected", sock)
        else:
            self.begin_p2p_udp_connection(peer)

    def begin_p2p_udp_connection(self, peer: Friend):
        print('udp dont work yet')

    def peer_handler(self):
        # dont close peer connections
        mes = Message(message_type=COMMAND, message=str(P2P_KEEP_ALIVE), sender_id=self.id)
        while True:
            pass
            #for peer in self.p2p_connected.values():
                #send_message_to_client(peer, mes)


def main():

    address = '192.168.56.1'
    if len(sys.argv) > 1:
        address = sys.argv[1]

    client = Client(address)
    client.run()


if __name__ == '__main__':
    main()
