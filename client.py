import threading
from common_functions_and_data_structures import *
import traceback
import sys
import time
import selectors
import ssl
from client_database import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
from collections import namedtuple


def get_input(prompt_str: str) -> str:
    return input(prompt_str).strip()


def connect_to_address(socket_connector, address):
    connected = True
    try:
        socket_connector.connect(address)
    except ConnectionRefusedError or ConnectionAbortedError:
        connected = False
    return connected


def RSA_decrypt(rsa_key: RSA.RsaKey, message: bytes) -> bytes:
    """
    Расшифровываем сообщение ассиметричным ключом
    :param rsa_key:
    :param message:
    :return: расшифрованное сообщение
    """
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(message)


def RSA_encrypt(rsa_key: RSA.RsaKey, message: bytes) -> bytes:
    """
    Зашифровываем сообщение ассиметричным ключом
    :param rsa_key:
    :param message:
    :return: зашифрованное сообщение
    """
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(message)


class Friend(User):
    """
    Класс для представления данных о друге и истории переписки с ним
    """
    def __init__(self, sock: socket.socket = None, client_id: int = 0, public_address: 'tuple(str, int)' = None,
                 private_address: 'tuple(str, int)' = None, login: str = '', symmetric_key: bytes = None,
                 public_key: RSA.RsaKey = None, secret_session_id: int = None):
        super().__init__(sock=sock, client_id=client_id, public_address=public_address, symmetric_key=symmetric_key)
        self.login = login
        self.private_address = private_address
        self.public_key = public_key

        # все списки чатов имеют следующую структуру:
        # message_info = namedtuple("message_info", "sender message") является ли данный друг отправителем
        # (если нет, то он получатель) и само сообщение
        # [message_info, ..]
        self.secret_p2p_chat = list()
        self.p2p_chat = list()
        self.secret_chat = list()
        self.chat = list()
        self.secret_session_id = secret_session_id


class Client:

    def __init__(self, server_hostname: str = 'localhost'):

        secure_server_tcp_socket = self.connect_and_auth_server((server_hostname, PORT_TO_CONNECT))
        # основной сокет для работы с сервером
        server_tcp_socket, server_symmetric_key = self.get_server_secret_key(secure_server_tcp_socket)

        # сокет для UDP подключений от других клиентов, в случае если не удается установить TCP соединение
        # self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.p2p_tcp_connection_possible = True
        try:
            if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):  # linux, Mac OS, android
                server_tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
                server_tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, True)
            elif sys.platform == 'win32' or sys.platform == 'cygwin':  # windows
                # on Windows, REUSEADDR already implies REUSEPORT
                server_tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        except AttributeError:  # Не установлены SO_REUSEPORT или SO_REUSEADDR
            self.p2p_tcp_connection_possible = False

        self.private_tcp_address = server_tcp_socket.getsockname()

        if self.p2p_tcp_connection_possible:
            self.max_queue = 5
            self.p2p_tcp_listener = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            self.p2p_tcp_listener.bind(self.private_tcp_address)
            self.p2p_tcp_listener.listen(self.max_queue)

        self.friendly_users = dict()  # id: Friend
        self.p2p_connected = set()  # id's of connected friends

        self.server = Friend(public_address=server_hostname, sock=server_tcp_socket, client_id=SERVER_ID,
                             symmetric_key=server_symmetric_key)
        self.friendly_users[SERVER_ID] = self.server

        self.id = USER_NOT_AUTHENTICATED  # не аутентифицирован
        self.login = None
        self.lock = threading.Lock()
        self.thread_locals = threading.local()
        self.connector = Peer2PeerConnector(self)
        self.public_key = self.private_key = None

        ClientUserDatabase(need_client_init=True)
        # ClientMessageDatabase(need_client_init=True)
        key_init_thread = threading.Thread(target=self.init_keys)
        friend_init_thread = threading.Thread(target=self.init_friends)
        key_init_thread.start()
        friend_init_thread.start()
        key_init_thread.join()
        friend_init_thread.join()

    def run(self) -> None:
        server_handler_thread = threading.Thread(target=self.server_handler)
        server_handler_thread.start()

        user_handler_thread = threading.Thread(target=self.user_handler)
        user_handler_thread.start()

    def start_post_authentication_init(self):
        """
        Подгружаем все необходимое, что нельзя было подгрузить до авторизации
        :return:
        """
        self.init_messages()

    def init_friends(self) -> None:
        """
        Инициализируем список друзей, выгружая его из БД
        :return:
        """
        self.thread_locals.users_database = ClientUserDatabase()
        friend_generator = self.thread_locals.users_database.get_friend_list()
        for friend in friend_generator:
            fid = friend[DB_COLUMN_NAME_FRIEND_ID]
            flogin = friend[DB_COLUMN_NAME_LOGIN]
            fpublickey = self.thread_locals.users_database.get_friends_public_key(fid)
            fpublickey = RSA.import_key(fpublickey)
            self.friendly_users[fid] = Friend(client_id=fid, login=flogin, public_key=fpublickey)

    def init_keys(self) -> None:
        """
        Создаем ассиметричные ключи, если они еще не были созданы, иначе загружем их
        :return:
        """
        secure = 'secure' + os.sep
        if not os.path.exists(secure + 'private.pem') or not os.path.exists(secure + 'public.pem'):
            # либо ключ еще не был создан, либо с ним что-то случилось, генерируем новую пару
            key_pair = RSA.generate(RSA_KEY_LEN_IN_BITS)
            self.private_key = key_pair.export_key()
            self.public_key = key_pair.publickey().export_key()
            with open(secure + 'private.pem', 'wb') as priv, open(secure + 'public.pem', 'wb') as publ:
                priv.write(self.private_key)
                publ.write(self.public_key)
        else:
            # возвращаем сохраненный ключ
            with open(secure + 'private.pem', 'rb') as priv, open(secure + 'public.pem', 'rb') as publ:
                self.private_key = priv.read()
                self.public_key = publ.read()

    def init_messages(self) -> None:
        """
        параллельно получаем сообщения из локальной БД и от сервера
        :return:
        """
        local_messages_thread = threading.Thread(target=self.init_local_messages)
        server_messages_thread = threading.Thread(target=self.init_server_messages)
        local_messages_thread.start()
        server_messages_thread.start()
        local_messages_thread.join()
        server_messages_thread.join()

    def init_local_messages(self) -> None:
        """
        Запускаем параллельное получение секретных и обычных сообщений из локальной БД для всех друзей
        :return:
        """
        thread_list = []
        for friend_id in self.friendly_users:
            if friend_id == SERVER_ID:
                continue
            friend_id_message_init_thread = threading.Thread(target=self.init_messages_with_id(friend_id))
            friend_id_message_init_thread.start()
            thread_list.append(friend_id_message_init_thread)
            friend_id_secret_message_init_thread = threading.Thread(target=self.init_messages_with_id(friend_id, True))
            friend_id_secret_message_init_thread.start()
            thread_list.append(friend_id_secret_message_init_thread)

        for thread in thread_list:  # ждем, пока все сообщения будут загружены из БД
            thread.join()

    def init_server_messages(self) -> None:
        """
        Запрашиваем у сервера все переписки, прошедшие через него, секретные и обычные
        :return:
        """
        message = Message(message_type=COMMAND, sender_id=self.id, receiver_id=SERVER_ID)
        for friend_id in self.friendly_users:
            if friend_id == SERVER_ID:
                continue
            message.message = f"{GET_MESSAGES} {friend_id}"
            send_message_to_client(self.server, message, self.server.symmetric_key)

    def init_messages_with_id(self, friend_id: int, secret: bool = False) -> None:
        """
        Выгружаем p2p чат с friend_id из БД
        :param friend_id:
        :param secret: елси True, выгружаем секретный чат, иначе обычный
        :return:
        """
        self.thread_locals.message_database = ClientMessageDatabase()
        message_generator = self.thread_locals.message_database.get_message_history(friend_id, secret)
        if secret:
            mes_list = self.friendly_users[friend_id].secret_p2p_chat
        else:
            mes_list = self.friendly_users[friend_id].p2p_chat
        for message in message_generator:
            mes_list.append(message)

    @staticmethod
    def connect_and_auth_server(server_address: '(str, int)') -> socket:
        """
        Создаем ssl соединение с сервером, тем самым аутентифицируя его
        :param server_address:
        :return: ssl socket, который будет использоваться для безопасного установления общего симметричного ключа
        """
        secure_context = ssl.create_default_context(cafile='secure/CA.pem')
        # обязательно вернуть ТРУ, когда будет сервер нейм, либо разобраться с альтнеймами в серитфикатах
        secure_context.check_hostname = False
        server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        secure_server_socket = secure_context.wrap_socket(server_socket)
        while not connect_to_address(secure_server_socket, server_address):
            print("подключение не удалось")
            time.sleep(3)  # Ждем, несколько секунд, прежде чем подключиться снова
        print("Подключено")
        return secure_server_socket

    @staticmethod
    def get_server_secret_key(secure_socket: socket) -> '(socket, bytes)':
        """
        Получаем секретный ключ, с помощью которого будем общаться с сервером в дальнейшем,
        данное сообщение не нужно проверять на подлинность и расшифровывать, т.к. этим занимается ssl
        :param secure_socket: ssl socket из которого получим секретный ключ
        :return: обычный сокет, через который будем общаться с сервером, используя полученный секретный ключ
        и сам секретный ключ
        """
        symmetric_key = get_message_from_client(User(sock=secure_socket)).message
        return secure_socket.unwrap(), symmetric_key

    def server_handler(self, target: Friend = None) -> None:
        if not target:
            target = self.server
        self.thread_locals.message_database = ClientMessageDatabase()
        self.thread_locals.users_database = ClientUserDatabase()
        self.thread_locals.message_manager = ReceivedMessageManager(self)
        try:
            while True:
                message = get_message_from_client(target)
                if not message:  # Что-то пошло не так и сервер отключился
                    break
                self.thread_locals.message_manager.handle(message)

        except Exception as e:
            print("Exception: {}".format(e.args))
            print(traceback.format_exc())
            print("id:", target.id)
        finally:
            pass

    def get_user_message(self, p2p=False, secret=False) -> None:
        if self.id == USER_NOT_AUTHENTICATED:
            print("Невозможно отправить сообщение. Сперва необходимо войти или зарегистрироваться")
            return

        receiver_id = ""
        while not receiver_id.isdigit():
            receiver_id = get_input("Введите id получателя:\n")
        receiver_id = int(receiver_id)

        if secret:
            if receiver_id not in self.friendly_users:
                print("Для начала секретного чата необходимо добавить пользователя в друзья")
                return
            receiver = self.friendly_users[receiver_id]
            self.create_secret_chat(receiver.id)
            # ждем пока установится сессионный ключ, чтоб можно было отправить сообщение - говно, переделать!!!
            while not receiver.symmetric_key:
                pass
            key = receiver.symmetric_key
        else:
            key = self.server.symmetric_key

        if not p2p:
            target = self.server
        else:
            if receiver_id in self.p2p_connected:
                target = self.friendly_users[receiver_id]
            else:
                print("Подключение не установлено")
                return
        message = Message(message_type=MESSAGE, message=get_input("Введите сообщение:\n"),
                          receiver_id=receiver_id, sender_id=self.id, secret=secret)
        send_message_to_client(target, message, key)

    def get_user_command(self) -> None:
        user_input = get_input("Введите тип команды\n")
        if not user_input:
            return
        message_type = int(user_input)
        if message_type == REGISTER_USER or message_type == LOG_IN:
            self.log_in(message_type)
        elif message_type == DELETE_USER:
            self.delete_account()
        elif message_type == ADD_FRIEND_BY_LOGIN or message_type == ADD_FRIEND_BY_ID:
            self.add_friend()
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
              CREATE_P2P_CONNECTION, " - Создать p2p соединение\n",
              ADD_FRIEND_BY_LOGIN, " - добавить друга по логину\n",
              ADD_FRIEND_BY_ID, " - добавить друга по id\n",
              LOG_OUT, " - Выход\n",
              sep="")
        while True:
            user_input = get_input("Введите тип команды:\n"
                                   "0 - команда серверу,\n"
                                   "1 - человеку,\n"
                                   "2 - человеку напрямую\n"
                                   "3 - шифр человеку\n"
                                   "4 - шифр напрямую\n")
            if not user_input or not user_input.isdigit():
                continue
            user_input = int(user_input)
            if user_input == 0:
                self.get_user_command()
            elif user_input == 1:
                self.get_user_message()
            elif user_input == 2:
                self.get_user_message(p2p=True)
            elif user_input == 3:
                self.get_user_message(secret=True)
            elif user_input == 4:
                self.get_user_message(p2p=True, secret=True)

    def add_friend(self, friend_login: str = None, friend_id: int = None) -> None:
        """
        Запрашиваем данные о клиенте с логином friend_login или id friend_id у сервера
        :param friend_login:
        :param friend_id:
        :return:
        """
        message = Message(message_type=BYTES_COMMAND, sender_id=self.id, receiver_id=SERVER_ID)
        if not friend_login and not friend_id:
            friend_login = get_input("Введите логин\n")
        if self.login == friend_login or self.id == friend_id:
            print("нельзя добавить себя в друзья")
        if friend_id:
            message.message = f"{ADD_FRIEND_BY_ID} {friend_id}"
        elif friend_login:
            message.message = f"{ADD_FRIEND_BY_LOGIN} {friend_login}"

        send_message_to_client(self.server, message, self.server.symmetric_key)

    def log_in(self, auth_type: int) -> None:
        if self.id:
            print("Вы уже вошли")
            return
        message = Message(message_type=BYTES_COMMAND, sender_id=self.id, receiver_id=SERVER_ID, secret=True)
        login = get_input("Введите логин\n")
        password = get_input("Введите пароль\n")
        if not login or not password:
            return
        self.login = login
        message.message = get_bytes_string(f"{auth_type} {login} {password}")
        if auth_type == REGISTER_USER:
            message.message += b' ' + self.public_key
        send_message_to_client(self.server, message, self.server.symmetric_key)

    def delete_account(self) -> None:
        message = Message(message_type=COMMAND, sender_id=self.id, receiver_id=SERVER_ID)
        message.message = str(DELETE_USER)
        send_message_to_client(self.server, message, self.server.symmetric_key)
        self.id = 0
        print("Пользователь удален")

    def log_out(self) -> None:
        message = Message(message_type=COMMAND, sender_id=self.id, receiver_id=SERVER_ID)
        message.message = str(LOG_OUT)
        send_message_to_client(self.server, message, self.server.symmetric_key)
        self.id = 0
        print("Вы вышли из системы, войдите или зарегистрируйтесь для продолжения")

    def create_p2p_connection(self, user_id: int, creator: bool = True) -> None:
        if user_id in self.p2p_connected:
            return

        self.connector.new_connection_task(user_id, initiator=creator)

    def create_secret_chat(self, friend_id: int) -> None:
        """
        Запускаем процедуру обмена ключами с friend_id, и ждем ее завершения
        :param friend_id:
        :return:
        """
        if self.friendly_users[friend_id].symmetric_key:
            return
        self.symmetric_key_exchange_with_friend(friend_id)

    def symmetric_key_exchange_with_friend(self, friend_id: int) -> None:
        """
        Создаем ключ, для секретноей переписки с другом (без разницы P2P или через сервер), шифруем его открыты ключом
        друга и отсылаем ему через сервер
        :param friend_id:
        :return:
        """
        key = get_random_bytes(SYMMETRIC_KEY_LEN_IN_BYTES)
        self.friendly_users[friend_id].symmetric_key = key
        cipher_rsa = PKCS1_OAEP.new(self.friendly_users[friend_id].public_key)
        key = cipher_rsa.encrypt(key)
        # secret = False, т.к. симметричный ключ уже зашифрован публичным ключом друга, и дополнительная защита не нужна
        message = Message(message_type=BYTES_COMMAND, secret=False, sender_id=self.id, receiver_id=SERVER_ID,
                          message=get_bytes_string(f"{SYMMETRIC_KEY_EXCHANGE} {friend_id} ") + key)
        send_message_to_client(self.server, message, self.server.symmetric_key)


class ReceivedMessageManager:
    """
    Класс для обработки входящих сообщений
    Заполняет списки истории сообщений приходящих с сервера, расшифровывая секретные
    Управляет остальными сообщениями все время работы клиента
    """
    def __init__(self, client: Client):
        self.client = client

        # session: key - для расшифровки секретных сообщений хранившихся в БД сервера
        self.session_keys = dict()
        self.message = namedtuple("message_info", "sender message")

    def handle(self, message: Message):

        # Сперва, если сообщение зашифровано, его нужно расшифровать
        if message.secret:
            key = self.client.friendly_users[message.sender_id].symmetric_key
            message.message = get_decrypted_message(message.message, key, message.tag, message.nonce, message.secret)

        # Если сообщение должно быть текстовым, то его нужно преобразовать к такому виду
        if message.message_type != BYTES_COMMAND and message.message_type != BYTES_MESSAGE:
            message.message = get_text_from_bytes_data(message.message)

        if message.message_type == COMMAND or message.message_type == BYTES_COMMAND:
            self.command_handler(message)
        elif message.message_type == MESSAGE or message.message_type == BYTES_MESSAGE:
            self.message_handler(message)
        else:
            pass

    def command_handler(self, message: Message):
        # message.message = 'command_type ...'
        # разделять нужно именно по пробелу, чтоб не убирать \n (если их убрать, то например полученный
        # открытый улюч пользователя неудастся восстановить)
        if message.message_type == BYTES_COMMAND:
            sep = b' '
        else:
            sep = ' '
        data = message.message.split(sep)

        command = int(data[0])
        if command == REGISTRATION_SUCCESS or command == AUTHENTICATION_SUCCESS: # переработать, вынести в отдельную функцию
            # data = [.., 'uid']
            uid = int(data[1])
            self.client.id = uid
            print("Вход в систему успешно выполнен, id:", uid)
            self.client.start_post_authentication_init()
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
        elif command == FRIEND_DATA:
            # data = [.., b'uid', b'login', b'public_key']
            uid = int(data[1])
            login = get_text_from_bytes_data(data[2])
            public_key = get_public_key_from_parts(data[3:])
            self.client.thread_locals.users_database.add_friend(uid, login, public_key)
            public_key = RSA.import_key(public_key)
            friend = Friend(client_id=uid, login=login, public_key=public_key)
            self.client.friendly_users[uid] = friend
            print("Пользователь найден, uid:", uid)
        elif command == P2P_CONNECTION_DATA:
            # data = [..., 'P2P_CONNECTION_TYPE', peer_id', 'con_type'] or
            # data = [..., 'P2P_ADDRESS', 'peer_id', 'public_ip', 'public_port', 'private_ip', 'private_port'] or
            # data = [..., b'P2P_CONNECTION_SYMMETRIC_KEY', b'peer_id', b'symmetric_key']
            command_type = int(data[1])
            peer_id = int(data[2])

            if self.client.connector.peer_data[0] is None:
                # данный клиент не инициатор соединения, и не соединяется с другим клиентом
                self.client.connector.new_connection_task(peer_id, False)

            if self.client.connector.peer_data[0] == peer_id:  # получили данные от нужного пользователя
                if command_type == P2P_CONNECTION_TYPE:
                        self.client.connector.set_connection_type(int(data[3]))
                elif command_type == P2P_ADDRESS:
                        public_address = (data[3], int(data[4]))
                        private_address = (data[5], int(data[6]))
                        self.client.connector.set_connection_data(public_address, private_address)
                else:
                    pass
        elif command == USER_OFFLINE:
            # data = [.., 'id']
            self.client.connector.stop_task()
            print(f"Пользователь {data[1]} сейчас не в сети")
        elif command == MESSAGE_FROM_DATABASE or command == SECRET_MESSAGE_FROM_DATABASE:
            self.add_message(data)
        elif command == MESSAGE_KEY_FROM_DATABASE:
            self.add_session_key(data)
        elif command == ALL_MESSAGES_SENDED:
            self.clear()
        elif command == SYMMETRIC_KEY:
            # data = [.., b'friend_id', b'key']
            friend_id = int(data[1])
            friend = self.client.friendly_users[friend_id]
            if not friend.symmetric_key:
                encrypted_key = data[2]
                friend.symmetric_key = RSA_decrypt(self.client.private_key, encrypted_key)
        elif command == GET_SESSION_KEY:
            # data = [.., 'session_id', 'friend_id']
            session_id = data[1]
            friend_id = int(data[2])
            self.client.friendly_users[friend_id].secret_session_id = session_id
            friend = self.client.friendly_users[friend_id]
            while not friend.symmetric_key:
                # Ждем доставки и расшифровки сессионного ключа
                pass
            session_key = RSA_encrypt(friend.public_key, friend.symmetric_key)
            message = Message(message_type=BYTES_COMMAND, receiver_id=SERVER_ID, sender_id=self.client.id,
                              message=get_bytes_string(f"{SESSION_ENCRYPTED_KEY} {session_id} {friend_id} ")
                                      + session_key)
            send_message_to_client(self.client.server, message, self.client.server.symmetric_key)
        else:
            pass

    def message_handler(self, message: Message):
        print("received from:\n", message.sender_id,
              "\nmessage:\n", message.message, sep="")

    def add_session_key(self, session_key_info: list) -> None:
        # session_key_info = [..., b'session_id', b'key']
        session_id = int(session_key_info[1])
        key = RSA_decrypt(self.client.private_key, session_key_info[2])
        self.session_keys[session_id] = key

    def add_message(self, message_info: list) -> None:
        """
        Добавляет сообщения пришедшие из БД сервера в список сообщений пользователя
        :param message_info: [b'type', b'sender', b'receiver'[, b'session_id'], b'message'[, b'tag', b'nonce']] -
                                список данных о сообщении пришедшем с сервера
        :return:
        """
        is_secret = (int(message_info[0]) == SECRET_MESSAGE_FROM_DATABASE)
        sender_id = int(message_info[1])
        receiver_id = int(message_info[2])

        if self.client.id == sender_id:
            friend_id = receiver_id
            sender = True
        else:
            friend_id = sender_id
            sender = False

        if is_secret:
            session_id = message_info[3]
            message_pos = 4
            message = message_info[message_pos]
            tag = message_info[5]
            nonce = message_info[6]
            message = get_decrypted_message(message, self.session_keys[session_id], tag, nonce)
        else:
            message_pos = 3
            message = message_info[message_pos]

        message = self.message._make((sender, get_text_from_bytes_data(message)))

        if is_secret:
            self.client.friendly_users[friend_id].secret_chat.append(message)
        else:
            self.client.friendly_users[friend_id].chat.append(message)

    def clear(self) -> None:
        """
        удаляем ненужные атрибуты из памяти после получения сообщений с БД сервера.
        Удаляем session_keys, cipher_rsa
        :return:
        """
        del self.session_keys


class Peer2PeerConnector:

    def __init__(self, peer: Client):
        self.client = peer
        self.client_initiator = False
        self.peer_data_items_count = 4
        # id, connection_type, public_address, private_address
        self.peer_data = [None for _ in range(self.peer_data_items_count)]

        self.connection_type_stated = False
        self.connection_data_stated = False
        self.task_in_process = False
        self.max_connection_attempts = 5

    def run_task(self) -> None:
        message = Message(message_type=COMMAND, sender_id=self.client.id, receiver_id=SERVER_ID)
        command = CREATE_P2P_CONNECTION

        # Выбираем тип соединения
        command_type = P2P_CONNECTION_TYPE
        if self.client.p2p_tcp_connection_possible:
            con_type = P2P_TCP
        else:
            con_type = P2P_UDP

        message.message = "{} {} {} {}".format(command, command_type, self.peer_data[0], con_type)
        send_message_to_client(self.client.server, message, self.client.server.symmetric_key)

        while not self.connection_type_stated and self.task_in_process:
            pass

        if not self.task_in_process:
            return

        # Устанавливаем данные для соединения
        command_type = P2P_ADDRESS
        if self.peer_data[1] == P2P_UDP:
            pass
        else:
            message.message = "{} {} {} {} {}".format(command, command_type, self.peer_data[0],
                                                      *self.client.private_tcp_address)
            send_message_to_client(self.client.server, message, self.client.server.symmetric_key)

        while not self.connection_data_stated and self.task_in_process:
            pass

        if not self.task_in_process:
            return

        if self.peer_data[1] == P2P_UDP:
            pass
        else:
            self.start_tcp_connection()

    def new_connection_task(self, id_to_connect: int, initiator: bool) -> bool:

        can_start_new_connection = True
        self.client.lock.acquire()
        if self.task_in_process:
            can_start_new_connection = False
        else:
            self.task_in_process = True
        self.client.lock.release()
        if not can_start_new_connection:
            return False

        # id, connection_type, public_address, private_address
        self.peer_data = [None for _ in range(self.peer_data_items_count)]
        self.peer_data[0] = id_to_connect
        self.client_initiator = initiator
        new_task = threading.Thread(target=self.run_task)
        new_task.start()
        return True

    def set_connection_type(self, connection_type: int) -> None:
        self.peer_data[1] = P2P_UDP
        if connection_type == P2P_TCP and self.client.p2p_tcp_connection_possible:
            self.peer_data[1] = P2P_TCP
        self.connection_type_stated = True

    def stop_task(self) -> None:
        self.task_in_process = False

    def set_connection_data(self, public_address: (str, int), private_address: (str, int)) -> None:
        self.peer_data[2] = public_address
        self.peer_data[3] = private_address
        self.connection_data_stated = True

    def start_tcp_connection(self) -> None:
        public_connector = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        private_connector = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        peer_public_address = self.peer_data[2]
        peer_private_address = self.peer_data[3]
        peer_accepted = False
        connection_done = False
        selector = selectors.DefaultSelector()
        selector.register(self.client.p2p_tcp_listener, selectors.EVENT_READ)

        connection_attempts = 0
        final_socket = None
        while connection_attempts < self.max_connection_attempts:
            connection_attempts += 1

            connected_to_peer_private_address = connect_to_address(private_connector, peer_private_address)
            connected_to_peer_public_address = connect_to_address(public_connector, peer_public_address)

            listener = selector.select(timeout=1)  # wait 1 sec at most

            if listener:  # Входящее соединение
                # listener = [(), ..]
                listener = listener[0][0].fileobj  # self.p2p_listener
                peer_socket, peer_address = listener.accept()
                peer_accepted = True
                # handshake()

            if peer_accepted:
                # нужно проверить какой адрес мы приняли публичный или приватный и отбросить второй, на случай,
                # если оба пользователя в одной локальной сети и были подключены оба адресса (но принят то только один)
                if connected_to_peer_private_address and peer_address == peer_private_address:
                    connected_to_peer_public_address = False
                elif connected_to_peer_public_address and peer_address == peer_public_address:
                    connected_to_peer_private_address = False

            if connected_to_peer_private_address:
                # handshake()
                pass
            if connected_to_peer_public_address:
                pass
                # handshake()

            if self.client_initiator:
                # проверить статусы рукопожатий и добавить пиров в порядке: приват, паблик, ацептед
                if connected_to_peer_private_address:
                    final_socket = private_connector
                elif connected_to_peer_public_address:
                    final_socket = public_connector
                elif peer_accepted:
                    final_socket = peer_socket
            else:
                # проверить статусы рукопожатий и добавить пиров в порядке: ацептед, приват, паблик
                if peer_accepted:
                    final_socket = peer_socket
                elif connected_to_peer_private_address:
                    final_socket = private_connector
                elif connected_to_peer_public_address:
                    final_socket = public_connector

            if final_socket:
                connected_id = self.peer_data[0]
                connected_peer = self.client.friendly_users[connected_id]
                connected_peer.private_address = peer_private_address
                connected_peer.public_address = peer_public_address
                connected_peer.sock = final_socket
                self.client.p2p_connected.add(connected_id)
                connection_done = True

            if connection_done:  # если подключение установилось завершаем цикл
                break

        if connection_done:
            print("connected", final_socket)
            peer = self.client.friendly_users[self.peer_data[0]]
            new_peer_handler = threading.Thread(target=self.client.server_handler, args=(peer,))
            new_peer_handler.start()

        self.task_in_process = False

    def restart_connection(self):
        pass


def main():

    address = '192.168.56.1'
    if len(sys.argv) > 1:
        address = sys.argv[1]

    client = Client(address)
    client.run()


if __name__ == '__main__':
    main()
