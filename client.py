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
from queue import Queue

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
    cipher_rsa = PKCS1_OAEP.new(rsa_key, SHA256)
    return cipher_rsa.decrypt(message)


def RSA_encrypt(rsa_key: RSA.RsaKey, message: bytes) -> bytes:
    """
    Зашифровываем сообщение ассиметричным ключом
    :param rsa_key:
    :param message:
    :return: зашифрованное сообщение
    """
    cipher_rsa = PKCS1_OAEP.new(rsa_key, SHA256)
    return cipher_rsa.encrypt(message)


# Будет использоваться для представления сообщений в списках сообщений клиента.
# is_sender - True, если клиент является отправителем, иначе False,
# message - само сообщение
message_item = namedtuple("message_item", "is_sender message")


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

        # все списки чатов состоят из message_item'ов
        self.secret_p2p_chat = list()
        self.p2p_chat = list()
        self.secret_chat = list()
        self.chat = list()
        self.secret_session_id = secret_session_id


class Client:

    def __init__(self, server_hostname: str = 'localhost', event_queue: Queue=None):
        """

        :param server_hostname:
        :param event_queue: Очередь для связи с шрафическим интерфейсом, если есть, то stdout не нужен
        """

        self.event_queue = event_queue
        self.server_hostname = server_hostname
        self.friendly_users = dict()  # id: Friend
        self.p2p_connected = set()  # id's of connected friends
        self.id = USER_NOT_AUTHENTICATED  # не аутентифицирован
        self.p2p_tcp_connection_possible = None
        self.private_tcp_address = None
        self.server = None
        self.login = None
        self.p2p_tcp_listener = None
        self.max_listen_queue = 0
        self.lock = threading.Lock()
        self.thread_locals = threading.local()
        self.connector = Peer2PeerConnector(self)
        self.public_key = self.private_key = None
        self.time_to_stop = False

    def run(self) -> None:
        self.main_init()
        server_handler_thread = threading.Thread(target=self.server_handler)
        server_handler_thread.start()

        if not self.event_queue:
            user_handler_thread = threading.Thread(target=self.user_handler)
            user_handler_thread.start()

    # методы для установки соединения с сервером
    def connection_init(self):
        secure_server_tcp_socket = self.connect_and_auth_server((self.server_hostname, PORT_TO_CONNECT))
        # основной сокет для работы с сервером
        server_tcp_socket, server_symmetric_key = self.get_server_secret_key(secure_server_tcp_socket)
        self.server = Friend(public_address=self.server_hostname, sock=server_tcp_socket, client_id=SERVER_ID,
                             symmetric_key=server_symmetric_key)
        self.friendly_users[SERVER_ID] = self.server
        self.private_tcp_address = server_tcp_socket.getsockname()

    def connect_and_auth_server(self, server_address: '(str, int)') -> socket:
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
            if not self.event_queue:
                print("подключение не удалось")
            time.sleep(3)  # Ждем, несколько секунд, прежде чем подключиться снова
        if not self.event_queue:
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
        # тут ключ по частям собирать не нужно, т.к. я передаю только его и нигде не делаю split
        symmetric_key = get_message_from_client(User(sock=secure_socket)).message
        return secure_socket.unwrap(), symmetric_key
    # -----------------------------

    # методы для инициализации клиента
    def main_init(self) -> None:

        self.connection_init()

        # сокет для UDP подключений от других клиентов, в случае если не удается установить TCP соединение
        # self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.p2p_tcp_connection_possible = True
        try:
            if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):  # linux, Mac OS, android
                self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
                self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, True)
            elif sys.platform == 'win32' or sys.platform == 'cygwin':  # windows
                # on Windows, REUSEADDR already implies REUSEPORT
                self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        except AttributeError:  # Не установлены SO_REUSEPORT или SO_REUSEADDR
            self.p2p_tcp_connection_possible = False

        if self.p2p_tcp_connection_possible:
            self.max_listen_queue = 5
            self.p2p_tcp_listener = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            self.p2p_tcp_listener.bind(self.private_tcp_address)
            self.p2p_tcp_listener.listen(self.max_listen_queue)

        ClientUserDatabase(need_client_init=True)
        # ClientMessageDatabase(need_client_init=True)
        key_init_thread = threading.Thread(target=self.init_asymmetric_keys)
        friend_init_thread = threading.Thread(target=self.init_friends)
        key_init_thread.start()
        friend_init_thread.start()
        key_init_thread.join()
        friend_init_thread.join()

    def init_friends(self) -> None:
        """
        Инициализируем список друзей, выгружая его из БД
        :return:
        """

        # Заполнять список друзей и получать открытый ключ для каждого из них их БД нужно отдельно,
        # т.к. внутри БД меняется возвращаемое значение self.cursor.fetchone при обращении к разным ее методам
        self.thread_locals.users_database = ClientUserDatabase()
        friend_generator = self.thread_locals.users_database.get_friend_list()
        for friend in friend_generator:
            fid = friend[DB_COLUMN_NAME_FRIEND_ID]
            flogin = friend[DB_COLUMN_NAME_LOGIN]
            self.friendly_users[fid] = Friend(client_id=fid, login=flogin)

        for fid in self.friendly_users:
            if fid == SERVER_ID:
                continue
            fpublickey = self.thread_locals.users_database.get_friends_public_key(fid)
            fpublickey = RSA.import_key(fpublickey)
            self.friendly_users[fid].public_key = fpublickey

    def init_asymmetric_keys(self) -> None:
        """
        Создаем ассиметричные ключи, если они еще не были созданы, иначе загружем их
        :return:
        """
        secure = 'secure' + os.sep
        if not os.path.exists(secure + 'private.pem') or not os.path.exists(secure + 'public.pem'):
            # либо ключ еще не был создан, либо с ним что-то случилось, генерируем новую пару
            key_pair = RSA.generate(RSA_KEY_LEN_IN_BITS)
            self.private_key = key_pair
            self.public_key = key_pair.publickey()
            with open(secure + 'private.pem', 'wb') as priv, open(secure + 'public.pem', 'wb') as publ:
                priv.write(self.private_key.export_key())
                publ.write(self.public_key.export_key())
        else:
            # возвращаем сохраненный ключ
            with open(secure + 'private.pem', 'rb') as priv, open(secure + 'public.pem', 'rb') as publ:
                self.private_key = RSA.import_key(priv.read())
                self.public_key = RSA.import_key(publ.read())

    def start_post_authentication_init(self):
        """
        Подгружаем все необходимое, что нельзя было подгрузить до авторизации
        :return:
        """
        self.init_messages()
        if self.event_queue:
            self.event_queue.put((GUI_INIT_DONE,))

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
        message = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=SERVER_ID)
        for friend_id in self.friendly_users:
            if friend_id == SERVER_ID:
                continue
            message.message = f"{CLIENT_GET_MESSAGES} {friend_id}"
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
            mes_list.append(message_item(not message[DB_COLUMN_NAME_MESSAGE_RECEIVED], message[DB_COLUMN_NAME_MESSAGE]))
    # -----------------------------

    # методы для взаимодействия с пользователем в консольном режиме
    def user_handler(self) -> None:
        # для сохранения отправляемых p2p сообщений
        self.thread_locals.message_database = ClientMessageDatabase()
        print("Список команд для сервера:\n",
              CLIENT_REGISTER_USER, " - Регистрация {login, password}\n",
              CLIENT_LOG_IN, " - Вход {login, password}\n",
              CLIENT_DELETE_USER, " - Удалить аккаунт\n",
              CLIENT_CREATE_P2P_CONNECTION, " - Создать p2p соединение\n",
              CLIENT_ADD_FRIEND_BY_LOGIN, " - добавить друга по логину\n",
              CLIENT_ADD_FRIEND_BY_ID, " - добавить друга по id\n",
              CLIENT_LOG_OUT, " - Выход\n",
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
                self.ask_user_message()
            elif user_input == 2:
                self.ask_user_message(p2p=True)
            elif user_input == 3:
                self.ask_user_message(secret=True)
            elif user_input == 4:
                self.ask_user_message(p2p=True, secret=True)

    def get_user_command(self) -> None:
        user_input = get_input("Введите тип команды\n")
        if not user_input:
            return
        message_type = int(user_input)
        if message_type == CLIENT_REGISTER_USER or message_type == CLIENT_LOG_IN:
            self.ask_registration_data(message_type)
        elif message_type == CLIENT_DELETE_USER:
            self.delete_account()
        elif message_type == CLIENT_ADD_FRIEND_BY_LOGIN or message_type == CLIENT_ADD_FRIEND_BY_ID:
            self.ask_friend_login_to_add()
        elif message_type == CLIENT_LOG_OUT:
            self.log_out()
        elif message_type == CLIENT_CREATE_P2P_CONNECTION:
            user_id = int(get_input("Введите id пользователя\n"))
            self.create_p2p_connection(user_id)
        else:
            pass

    def print_message_history(self, friend_id: int, secret: bool, p2p: bool):

        to_print = self.get_message_history(friend_id, secret, p2p)
        for mes_item in to_print:
            if mes_item.is_sender:
                print("snd: ", end='')
            else:
                print("rcv: ", end='')
            print(mes_item.message)

    def ask_user_message(self, p2p=False, secret=False) -> None:
        if self.id == USER_NOT_AUTHENTICATED:
            print("Невозможно отправить сообщение. Сперва необходимо войти или зарегистрироваться")
            return

        receiver_id = ""
        while not receiver_id.isdigit():
            receiver_id = get_input("Введите id получателя:\n")
        receiver_id = int(receiver_id)

        if receiver_id not in self.friendly_users:
            self.friendly_users[receiver_id] = Friend(client_id=receiver_id)

        if secret and not self.friendly_users[receiver_id].symmetric_key:
            self.symmetric_key_exchange_with_friend(receiver_id)

        self.print_message_history(receiver_id, secret, p2p)

        message_text = get_input("Введите сообщение:\n")

        self.send_message(message_text, receiver_id, p2p, secret)

    def ask_registration_data(self, auth_type: int):
        if self.id:
            print("Вы уже вошли")
            return
        login = get_input("Введите логин\n")
        password = get_input("Введите пароль\n")
        self.log_in(login, password, auth_type)

    def ask_friend_login_to_add(self):
        friend_login = get_input("Введите логин\n")
        if friend_login:
            self.add_friend(friend_login=friend_login)
    # -----------------------------

    # методы - обработчики
    def server_handler(self, target: Friend = None) -> None:
        if not target:
            target = self.server
        # для сохранения получаемых p2p сообщений
        self.thread_locals.message_database = ClientMessageDatabase()
        self.thread_locals.users_database = ClientUserDatabase()
        self.thread_locals.message_manager = ReceivedMessageManager(self)
        # Если мы общаемся не с сервером, значит общаемся через p2p
        p2p = (target != self.server)
        while True:
            try:
                message = get_message_from_client(target)
                if not message:  # Что-то пошло не так и сервер отключился
                    break
                self.thread_locals.message_manager.handle(message, p2p)
            except ConnectionError as e:
                if target == self.server:
                    if not self.event_queue:
                        print("Соединение разорвано")
                    else:
                        self.event_queue.put((GUI_CLIENT_CONNECTION_ERROR, ))
                    self.connection_init()
                    self.clear_on_log_out()
                    self.server_handler()
                break
            except Exception as e:
                if not self.event_queue:
                    print(f"Exception: {e.args}")
                    print(traceback.format_exc())
                    print("id:", target.id)
                    print("нужно выключить и включить")
                else:
                    self.event_queue.put((GUI_CLIENT_ERROR,))
                break
            finally:
                pass

    def log_in(self, login: str, password: str, auth_type: int) -> None:
        if self.id:
            return
        if not self.check_login_and_password(login, password):
            if self.event_queue:
                self.event_queue.put((GUI_BAD_PASSWORD_OR_LOGIN, ))
            else:
                print('логин и пароль должны состоять из строчных латинских букв, цифр, '
                      'символов подчеркивания и начинаться с буквы')
            return
        message = Message(mes_type=BYTES_COMMAND, sender_id=self.id, receiver_id=SERVER_ID, secret=True)
        self.login = login
        message.message = get_bytes_string(f"{auth_type} {login} {password}")
        if auth_type == CLIENT_REGISTER_USER:
            public_key_bytes = self.public_key.export_key()
            beg, end = count_spaces_at_the_edges(public_key_bytes)
            message.message += b' ' + get_bytes_string(f"{beg}") + b' ' + get_bytes_string(f"{end}") + b' ' \
                               + public_key_bytes
        send_message_to_client(self.server, message, self.server.symmetric_key)

    def check_login_and_password(self, login: str, password: str) -> bool:

        def check_str(string: str) -> bool:
            if not string or not string.islower() or not string[0].isalpha():
                return False
            english_alph = 'abcdefghijklmnopqrstuvwxyz'
            for c in string:
                if c not in english_alph and not c.isdigit() and c != '_':
                    return False
            return True

        return check_str(login) and check_str(password)

    def clear_on_log_out(self):
        self.id = USER_NOT_AUTHENTICATED
        self.thread_locals.message_database = None
        self.thread_locals.users_database = None
        self.thread_locals.message_manager = None

    def delete_account(self) -> None:
        message = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=SERVER_ID)
        message.message = str(CLIENT_DELETE_USER)
        send_message_to_client(self.server, message, self.server.symmetric_key)
        self.clear_on_log_out()
        if not self.event_queue:
            print("Пользователь удален")
        else:
            self.event_queue.put((GUI_USER_LOG_OUT,))

    def log_out(self) -> None:
        message = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=SERVER_ID)
        message.message = str(CLIENT_LOG_OUT)
        send_message_to_client(self.server, message, self.server.symmetric_key)
        self.clear_on_log_out()
        if not self.event_queue:
            print("Вы вышли из системы, войдите или зарегистрируйтесь для продолжения")
        else:
            self.event_queue.put((GUI_USER_LOG_OUT,))

    def add_friend(self, friend_login: str = None, friend_id: int = None) -> None:
        """
        Запрашиваем данные о клиенте с логином friend_login или id friend_id у сервера
        :param friend_login:
        :param friend_id:
        :return:
        """
        message = Message(mes_type=BYTES_COMMAND, sender_id=self.id, receiver_id=SERVER_ID)
        if not friend_login and not friend_id:
            return
        if self.login == friend_login or self.id == friend_id:
            if not self.event_queue:
                print("нельзя добавить себя в друзья")
        if friend_id in self.friendly_users:
            # TODO проверять по логину и сообщать в гуй
            if not self.event_queue:
                print("пользлватель уже у вас в друзьях")
        if friend_id:
            message.message = f"{CLIENT_ADD_FRIEND_BY_ID} {friend_id}"
        elif friend_login:
            message.message = f"{CLIENT_ADD_FRIEND_BY_LOGIN} {friend_login}"

        send_message_to_client(self.server, message, self.server.symmetric_key)

    def send_message(self, message_text: str, receiver_id: int, p2p: bool, secret: bool) -> None:

        if secret:
            receiver = self.friendly_users[receiver_id]
            if not receiver.symmetric_key:
                if self.event_queue:
                    self.event_queue.put((GUI_SECRET_KEY_NOT_STATED,))
                else:
                    print('Секретный ключ не установлен')
                return
            key = receiver.symmetric_key
        else:
            key = self.server.symmetric_key

        if not p2p:
            target = self.server
        else:
            if receiver_id in self.p2p_connected:
                target = self.friendly_users[receiver_id]
            else:
                if not self.event_queue:
                    print("Подключение не установлено")
                else:
                    self.event_queue.put((GUI_CONNECTION_NOT_ESTABLISHED,))
                return

        if p2p:
            # Добавляем сообщение в локальную БД пользователя
            self.thread_locals.message_database.add_message(receiver_id, False, secret, message_text)

        mes_item = message_item(True, message_text)
        self.add_message_item(receiver_id, mes_item, p2p, secret)

        message = Message(mes_type=MESSAGE, message=message_text,
                          receiver_id=receiver_id, sender_id=self.id, secret=secret)
        send_message_to_client(target, message, key)

    def get_message_history(self, friend_id: int, secret: bool, p2p: bool) -> message_item:
        friend = self.friendly_users[friend_id]

        if not secret and not p2p:
            message_history = friend.chat
        elif secret and not p2p:
            message_history = friend.secret_chat
        elif not secret and p2p:
            message_history = friend.p2p_chat
        elif secret and p2p:
            message_history = friend.secret_p2p_chat

        for mes_item in message_history:
            yield mes_item

    def add_message_item(self, friend_id: int, mes_item: message_item, p2p: bool, secret: bool):
        friend = self.friendly_users[friend_id]
        if not p2p and not secret:
            friend.chat.append(mes_item)
        elif not p2p and secret:
            friend.secret_chat.append(mes_item)
        elif p2p and not secret:
            friend.p2p_chat.append(mes_item)
        elif p2p and secret:
            friend.secret_p2p_chat.append(mes_item)

    def create_p2p_connection(self, user_id: int, creator: bool = True) -> None:
        if user_id in self.p2p_connected or user_id == self.id or user_id == SERVER_ID:
            return

        self.connector.new_connection_task(user_id, initiator=creator)

    def symmetric_key_exchange_with_friend(self, friend_id: int) -> None:
        # TODO: Сделать так, чтоб при одновременном обмене ключом ничего не ломалось.
        """
        Создаем ключ, для секретноей переписки с другом (без разницы P2P или через сервер), шифруем его открыты ключом
        друга и отсылаем ему через сервер
        :param friend_id:
        :return:
        """
        key = get_random_bytes(SYMMETRIC_KEY_LEN_IN_BYTES)
        self.friendly_users[friend_id].symmetric_key = key

        friend_encrypted_key = RSA_encrypt(self.friendly_users[friend_id].public_key, key)
        frnd_beg, frnd_end = count_spaces_at_the_edges(friend_encrypted_key)

        self_encrypted_key = RSA_encrypt(self.public_key, key)
        self_beg, self_end = count_spaces_at_the_edges(self_encrypted_key)

        # secret = False, т.к. симметричный ключ уже зашифрован публичным ключом, и дополнительная защита не нужна
        # b' split ' нужен, т.к. в ключе могут быть символы b' ' и при разделении по пробелам на сервере, он распадется
        # на части, по этому слову сервер будет знать, где заканчивается один ключ и начинается другой, также
        # нужно передать количество пробелов в начале и конце каждого ключа, т.к. эти пробелы по другому не восстановить
        message = Message(mes_type=BYTES_COMMAND, secret=False, sender_id=self.id, receiver_id=SERVER_ID,
                          message=get_bytes_string(f"{CLIENT_SYMMETRIC_KEY_EXCHANGE} {friend_id} "
                                                   f"{self_beg} {self_end} {frnd_beg} {frnd_end} ")
                                  + self_encrypted_key + b' split ' + friend_encrypted_key)
        send_message_to_client(self.server, message, self.server.symmetric_key)

    def get_friend_list(self):
        for friend in self.friendly_users.values():
            yield friend.login, friend.id

    def exit_program(self):
        self.time_to_stop = True
    # -----------------------------


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
        # для размещения информации о текущем секретном сообщении получаемом от сервера, пока оно не пришло полностью
        self.current_secret_message_info = list()

    def handle(self, message: Message, p2p: bool):

        # Сперва, если сообщение зашифровано, его нужно расшифровать
        if message.secret:
            key = self.client.friendly_users[message.sender_id].symmetric_key
            message.message = get_decrypted_message(message.message, key, message.tag, message.nonce, message.secret)

        # Если сообщение должно быть текстовым, то его нужно преобразовать к такому виду
        if message.type != BYTES_COMMAND and message.type != BYTES_MESSAGE:
            message.message = get_text_from_bytes_data(message.message)

        if message.type == COMMAND or message.type == BYTES_COMMAND:
            self.command_handler(message)
        elif message.type == MESSAGE or message.type == BYTES_MESSAGE:
            self.message_handler(message, p2p)
        else:
            pass

    def command_handler(self, message: Message):
        # message.message = 'command_type ...'
        # разделять нужно именно по пробелу, чтоб не убирать \n (если их убрать, то например полученный
        # открытый улюч пользователя неудастся восстановить)
        if message.type == BYTES_COMMAND:
            sep = b' '
        else:
            sep = ' '

        if message.type != BYTES_COMMAND or \
                (not message.message.startswith(get_bytes_string(f"{SERVER_MESSAGE_FROM_DATABASE}")) and
                 not message.message.startswith(get_bytes_string(f"{SERVER_SECRET_MESSAGE_FROM_DATABASE}"))):
            # Сообщения приходящие из БД сервера не надо разбивать на части, их потом сложно собрать
            data = message.message.split(sep)
            command = int(data[0])
        else:
            first_space = message.message.find(sep)
            command = int(message.message[:first_space])
            data = message.message

        if command == SERVER_REGISTRATION_SUCCESS or command == SERVER_AUTHENTICATION_SUCCESS:
            self.on_success_auth(data)
        elif command == SERVER_USER_ALREADY_EXIST:
            self.on_registration_fail()
        elif command == SERVER_NOT_AUTHENTICATED:
            self.on_not_authenticated()
        elif command == SERVER_WRONG_LOGIN or command == SERVER_WRONG_PASSWORD:
            self.on_authentication_fail(command)
        elif command == SERVER_USER_NOT_EXIST:
            self.on_user_not_found()
        elif command == SERVER_FRIEND_DATA:
            self.on_friend_data(data)
        elif command == P2P_CONNECTION_DATA:
            self.on_p2p_connection_data(data)
        elif command == SERVER_USER_OFFLINE:
            self.on_user_offline(data)
        elif command == SERVER_MESSAGE_FROM_DATABASE or command == SERVER_SECRET_MESSAGE_FROM_DATABASE:
            self.on_db_message(data)
        elif command == SERVER_MESSAGE_KEY_FROM_DATABASE:
            self.on_message_key(data)
        elif command == SERVER_SYMMETRIC_KEY:
            self.on_symmetric_key(data)
        elif command == SERVER_ALL_MESSAGES_SENT:
            self.clear()
        else:
            pass

    def on_symmetric_key(self, data):
        # data = [.., b'friend_id', b'spaces_at_begin', b'spaces_at_end', b'key']
        friend_id = int(data[1])
        beg, end = int(data[2]), int(data[3])
        encrypted_key = get_key_from_parts(beg, data[4:], end)
        if friend_id not in self.client.friendly_users:
            self.client.friendly_users[friend_id] = Friend(client_id=friend_id)
        friend = self.client.friendly_users[friend_id]
        friend.symmetric_key = RSA_decrypt(self.client.private_key, encrypted_key)

    def on_message_key(self, data):
        self.add_session_key(data)

    def on_db_message(self, data):
        self.add_message_from_server_database(data)

    def on_user_offline(self, data):
        # data = [.., 'id']
        peer_id = int(data[1])
        self.client.connector.stop_task(peer_id)
        if not self.client.event_queue:
            print(f"Пользователь {peer_id} сейчас не в сети")
        else:
            self.client.event_queue.put((SERVER_USER_OFFLINE, ))

    def on_p2p_connection_data(self, data):
        # data = [..., 'P2P_CONNECTION_TYPE', peer_id', 'con_type'] or
        # data = [..., 'P2P_ADDRESS', 'peer_id', 'public_ip', 'public_port', 'private_ip', 'private_port'] or
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

    def on_friend_data(self, data):
        # data = [.., b'uid', b'login', b'spaces_at_begin', b'spaces_at_end', b'public_key']
        uid = int(data[1])
        login = get_text_from_bytes_data(data[2])
        beg, end = int(data[3]), int(data[4])
        public_key = get_key_from_parts(beg, data[5:], end)
        self.client.thread_locals.users_database.add_friend(uid, login, public_key)
        public_key = RSA.import_key(public_key)
        friend = Friend(client_id=uid, login=login, public_key=public_key)
        self.client.friendly_users[uid] = friend
        if not self.client.event_queue:
            print("Пользователь найден, uid:", uid)
            print("Друзья:", self.client.friendly_users)
        else:
            self.client.event_queue.put((GUI_FRIEND_ITEM, login, uid))

    def on_user_not_found(self):
        if not self.client.event_queue:
            print("Пользователь не найден")
        else:
            self.client.event_queue.put((SERVER_USER_NOT_EXIST, ))

    def on_authentication_fail(self, fail_type):
        if fail_type == SERVER_WRONG_LOGIN:
            print("Пользователя с таким логином не существует")
        elif fail_type == SERVER_WRONG_PASSWORD:
            print("Неверный пароль")
        if self.client.event_queue:
            self.client.event_queue.put((fail_type, ))

    def on_not_authenticated(self):
        if not self.client.event_queue:
            print("Невозможно выполнить запрос, сперва необходимо зарегистрироваться или войти")

    def on_registration_fail(self):
        if not self.client.event_queue:
            print("Пользователь с таким логином уже существует")
        else:
            self.client.event_queue.put((SERVER_USER_ALREADY_EXIST,))

    def on_success_auth(self, data):
        # data = [.., 'uid']
        uid = int(data[1])
        self.client.id = uid
        if not self.client.event_queue:
            print("Вход в систему успешно выполнен, id:", uid)
        else:
            self.client.event_queue.put((SERVER_AUTHENTICATION_SUCCESS, self.client.login))
        self.client.start_post_authentication_init()

    def message_handler(self, message: Message, p2p: bool):
        # Нужно добавить сообщение в БД, в список сообщений клиента и отобразить
        if message.sender_id not in self.client.friendly_users:
            self.client.friendly_users[message.sender_id] = Friend(client_id=message.sender_id)
        sender = self.client.friendly_users[message.sender_id]

        # Добавляем в список сообщений клиента
        mes_item = message_item(False, message.message)
        self.client.add_message_item(sender.id, mes_item, p2p, message.secret)

        # отображаем
        if not self.client.event_queue:
            print("received from:\n", message.sender_id, "\nmessage:\n", message.message, sep="")
        else:
            self.client.event_queue.put((GUI_MESSAGE_ITEM, message.sender_id, message.message, message.secret, p2p))

        # Добавляем в БД, только p2p сообщения, остальные хранятся в БД сервера
        if p2p:
            self.client.thread_locals.message_database.add_message(sender.id, True, message.secret, message.message)

    def add_session_key(self, session_key_info: list) -> None:
        # session_key_info = [..., b'session_id', b'spaces_at_begin', b'spaces_at_end', b'key']
        session_id = int(session_key_info[1])
        beg, end = int(session_key_info[2]), int(session_key_info[3])
        encrypted_key = get_key_from_parts(beg, session_key_info[4:], end)
        key = RSA_decrypt(self.client.private_key, encrypted_key)
        self.session_keys[session_id] = key

    def add_message_from_server_database(self, message_info: bytes) -> None:
        """
        Добавляет сообщения пришедшие из БД сервера в список сообщений пользователя
        :param message_info: строка байт данных о сообщении пришедшем с сервера, может быть нескольких видов:
        1) b'MESSAGE_FROM_DATABASE sender_id receiver_id message'
        2) b'SECRET_MESSAGE_FROM_DATABASE data sender_id receiver_id session_id'
        3) b'SECRET_MESSAGE_FROM_DATABASE mes message'
        4) b'SECRET_MESSAGE_FROM_DATABASE tag tag'
        5) b'SECRET_MESSAGE_FROM_DATABASE nonce nonce'
        Если пришло сообщение первого типа, можно сразу добавлять его в список сообщений,
        остальные 4 сообщения должны приходить подряд и добавить сообщение можно будет только
        когда придет последнее
        :return:
        """

        sep_pos = message_info.find(b' ')
        mes_type = int(message_info[:sep_pos])
        message_info = message_info[sep_pos+1:]
        if mes_type == SERVER_MESSAGE_FROM_DATABASE:
            # Елси сообщение не секретное, то сразу добавляем его и выходим
            sep_pos = message_info.find(b' ')
            sender_id = int(message_info[:sep_pos])
            message_info = message_info[sep_pos+1:]
            sep_pos = message_info.find(b' ')
            receiver_id = int(message_info[:sep_pos])
            message = message_info[sep_pos+1:]
            if self.client.id == sender_id:
                sender = True
                friend_id = receiver_id
            else:
                sender = False
                friend_id = sender_id
            message = message_item(sender, get_text_from_bytes_data(message))
            self.client.friendly_users[friend_id].chat.append(message)
            return

        # сообщение - секретное
        sep_pos = message_info.find(b' ')
        secret_type = message_info[:sep_pos]
        message_info = message_info[sep_pos+1:]
        if secret_type == b'data':
            # sender_id, receiver_id, session_id, message, tag, nonce
            self.current_secret_message_info = [None for _ in range(6)]
            # тут можно делать split
            self.current_secret_message_info[:3] = map(int, message_info.split(b' '))  # -> sender, receiver, session_id
        elif secret_type == b'mes':
            self.current_secret_message_info[3] = message_info
        elif secret_type == b'tag':
            self.current_secret_message_info[4] = message_info
        elif secret_type == b'nonce':
            # все данные получены, теперь надо добавить сообщение в список
            self.current_secret_message_info[5] = message_info

            sender_id = int(self.current_secret_message_info[0])
            receiver_id = int(self.current_secret_message_info[1])

            if self.client.id == sender_id:
                sender = True
                friend_id = receiver_id
            else:
                sender = False
                friend_id = sender_id

            session_id = int(self.current_secret_message_info[2])
            message = self.current_secret_message_info[3]
            tag = self.current_secret_message_info[4]
            nonce = self.current_secret_message_info[5]
            message = get_decrypted_message(message, self.session_keys[session_id], tag, nonce, True)
            message = get_text_from_bytes_data(message)
            self.client.friendly_users[friend_id].secret_chat.append(message_item(sender, message))
        else:
            # такого быть не должно
            pass

    def clear(self) -> None:
        """
        удаляем ненужные атрибуты из памяти после получения сообщений с БД сервера.
        Удаляем session_keys, cipher_rsa
        :return:
        """
        self.current_secret_message_info.clear()
        self.session_keys.clear()


class Peer2PeerConnector:
    """
    Класс для установления соединения между двумя людьми напрямую, без сервера.
    За раз можно установить только одно соединение (т.е. не параллельно)
    """

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
        message = Message(mes_type=COMMAND, sender_id=self.client.id, receiver_id=SERVER_ID)
        command = CLIENT_CREATE_P2P_CONNECTION

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

    def stop_task(self, peer_id: int) -> None:
        if self.peer_data[0] == peer_id:
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

            # TODO процедура проверки правильности подключения
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
                connected_peer.socket = final_socket
                self.client.p2p_connected.add(connected_id)
                connection_done = True

            if connection_done:  # если подключение установилось завершаем цикл
                break

        if connection_done:
            if not self.client.event_queue:
                print("connected", final_socket)
            else:
                self.client.event_queue.put((GUI_P2P_CONNECTION_DONE,))
            peer = self.client.friendly_users[self.peer_data[0]]
            new_peer_handler = threading.Thread(target=self.client.server_handler, args=(peer,))
            new_peer_handler.start()
        else:
            if not self.client.event_queue:
                print("p2p подключение не удалось")
            else:
                self.client.event_queue.put((GUI_P2P_CONNECTION_FAIL,))

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
