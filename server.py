from common_functions_and_data_structures import *
from server_database import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import threading  # заменить на настоящуюю многопоточность
import traceback
import ssl


class Server:

    def __init__(self):

        self.host = ''  # Подключение принимаем от любого компьютера в сети
        self.max_queue = 5  # число соединений, которые будут находиться в очереди соединений до вызова accept
        # список команд доступных для сервера
        self.commands = ['/commands - показать список команд и их описание',
                         '/end - остановить работу сервера']

        # создаем сокет, работающий по протоколу TCP
        self.server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        # (хост, порт) = хост - машина которую мы слушаем, если не указана, то принимаются связи от всех машин,
        # порт - номер порта который принимает соединение
        self.server_socket.bind((self.host, PORT_TO_CONNECT))
        self.server_socket.listen(self.max_queue)

        self.authenticated_users = dict()  # список подключенных user'ов (клиентов) client_id: user
        self.thread_locals = threading.local()
        self.lock = threading.Lock()
        self.id = SERVER_ID
        # Инициализируем базу данных
        ServerUserDatabase(need_server_init=True)
        ServerMessageDatabase(need_server_init=True)

    def process_command(self, user: User, message: Message) -> bool:  # разнести все по функциям
        # message.message = 'command_type ...'
        data = message.message.split()
        command = int(data[0])
        if not self.thread_locals.user_authenticated and command != LOG_IN and command != REGISTER_USER:
            message = Message(message_type=COMMAND, message=str(NOT_AUTHENTICATED))
            send_message_to_client(user, message)
            return False
        if command == REGISTER_USER:
            # data  = [..., b'login', b'password', b'public_key']
            if not self.client_registration(user, data[1], data[2], data[3]):
                return False
            return True
        elif command == LOG_IN:
            # data = [..., b'login', b'password']
            if not self.client_authentication(user, data[1], data[2]):
                return False
            return True
        elif command == DELETE_USER or command == LOG_OUT:  # переработать, вынести в отдельную функцию
            self.thread_locals.user_authenticated = False
            if not user.id:
                return False
            if command == DELETE_USER:
                self.thread_locals.users_database.delete_user(user.id)
            self.authenticated_users.pop(user.id)
            user.id = 0
            return True
        elif command == ADD_FRIEND_BY_LOGIN:  # переработать, вынести в отдельную функцию
            # data = [..., 'login']
            login = data[1]
            user = self.thread_locals.users_database.get_client_by_login(login)
            message = Message()
            if user == DB_USER_NOT_EXIST:
                message.message_type = COMMAND
                message.message = str(USER_NOT_EXIST)
            else:
                message.message_type = BYTES_COMMAND
                message.message = get_bytes_string(f"{FRIEND_DATA} {user[DB_COLUMN_NAME_USER_ID]} "
                                                   f"{user[DB_COLUMN_NAME_USER_LOGIN]} ") + \
                                  user[DB_COLUMN_NAME_USER_PUBLIC_KEY]
            send_message_to_client(user, message)
        elif command == CREATE_P2P_CONNECTION:
            # data = [..., 'P2P_CONNECTION_TYPE', 'peer_id','con_type'] or
            # data = [..., 'P2P_ADDRESS', 'peer_id', 'private_ip', 'private_port'] or
            # data = [..., b'P2P_CONNECTION_SYMMETRIC_KEY', b'peer_id', b'symmetric_key']
            command_type = int(data[1])
            second_peer_id = int(data[2])
            message = Message(message_type=COMMAND, receiver_id=user.id)
            if second_peer_id not in self.authenticated_users:
                message.message = str(USER_OFFLINE)
                send_message_to_client(user, message)
                return False
            second_peer = self.authenticated_users[second_peer_id]

            message = Message(receiver_id=second_peer.id)
            command_to_peer = P2P_CONNECTION_DATA
            if command_type == P2P_ADDRESS:
                message.message_type = COMMAND
                user_private_address = data[3], int(data[4])
                message.message = "{} {} {} {} {} {} {}".format(command_to_peer, command_type, user.id,
                                                                *user.public_address, *user_private_address)
            elif command_type == P2P_CONNECTION_TYPE:
                message.message_type = COMMAND
                message.message = "{} {} {} {}".format(command_to_peer, command_type, user.id, data[3])
            elif command_type == P2P_CONNECTION_SYMMETRIC_KEY:
                message.message_type = BYTES_COMMAND
                message.message = get_bytes_string("{} {} {} ".format(command_to_peer, command_type, user.id)) + data[3]
            send_message_to_client(second_peer, message)
        elif command == GET_MESSAGES:
            # data = [.., 'users_friend_id']
            users_friend_id = int(data[1])
            self.send_usual_message_history(user, users_friend_id)
            self.send_encrypted_message_history(user, users_friend_id)
        else:
            pass

    def send_usual_message_history(self, user: User, users_friend_id: int) -> None:
        """
        Высылаем нещифрованную переписку между user.id и users_friend_id из БД пользователю.
        :param user:
        :param users_friend_id:
        :return:
        """
        message_generator = self.thread_locals.messages_database.get_message_history(user.id, users_friend_id)
        message = Message(message_type=BYTES_COMMAND)
        for db_mes in message_generator:  # db_mes = (from: int, to: int, mes: bytes)
            message.message = get_bytes_string(f"{MESSAGE_FROM_DATABASE} "
                                               f"{db_mes[DB_COLUMN_NAME_SENDER_ID]} "
                                               f"{db_mes[DB_COLUMN_NAME_RECEIVER_ID]} ") \
                              + db_mes[DB_COLUMN_NAME_MESSAGE]
            send_message_to_client(user, message)

    def send_encrypted_message_history(self, user: User, users_friend_id: int) -> None:
        """
        Высылаем шифрованную переписку между user.id и users_friend_id из БД пользователю.
        :param user:
        :param users_friend_id:
        :return:
        """
        message_generator = self.thread_locals.messages_database.get_message_history(user.id, users_friend_id, True)
        session = -1  # несуществующая сессия
        message = Message(message_type=BYTES_COMMAND)
        for db_mes in message_generator:  # db_mes = (ses_id:int, from:int, to:int, mes:bytes, tag:bytes, nonce:bytes)
            if db_mes[DB_TABLE_NAME_SESSION_ID] != session:
                mes = Message(message_type=BYTES_COMMAND)
                session = db_mes[DB_TABLE_NAME_SESSION_ID]
                session_key = self.thread_locals.messages_database.get_session_key(session, user.id, users_friend_id)
                if user.id < users_friend_id:
                    session_key = session_key[0]
                else:
                    session_key = session_key[1]
                mes.message = get_bytes_string(f"{MESSAGE_KEY_FROM_DATABASE} ") + session_key
                send_message_to_client(user, mes)
            message.message = get_bytes_string(f"{MESSAGE_FROM_DATABASE} {db_mes[DB_COLUMN_NAME_SENDER_ID]} "
                                               f"{db_mes[DB_COLUMN_NAME_RECEIVER_ID]} ") \
                              + db_mes[DB_COLUMN_NAME_MESSAGE] + b' '\
                              + db_mes[DB_COLUMN_NAME_MESSAGE_TAG] + b' '\
                              + db_mes[DB_COLUMN_NAME_MESSAGE_NONCE]
            send_message_to_client(user, message)

    def client_registration(self, user: User, login: bytes, password: bytes, public_key: bytes) -> bool:
        """
        Регистрируем нового пользователя
        :param user:
        :param login:
        :param password:
        :param public_key:
        :return: True, если регистрация прошла успешно, т.е. логин не был занят и ничего другого плохого не случилось,
                 иначе False
        """
        saltl = get_random_bytes(8)
        saltr = get_random_bytes(8)

        self.lock.acquire()
        uid = self.thread_locals.users_database.add_user(login, get_hash(password, saltl, saltr),
                                                         saltl, saltr, public_key)
        self.lock.release()

        response_message = Message(message_type=COMMAND, sender_id=self.id)
        if uid == DB_USER_ALREADY_EXIST:
            response_message.message = str(USER_ALREADY_EXIST)
            send_message_to_client(user, response_message)
            return False
        user.id = uid
        self.thread_locals.user_authenticated = True
        self.authenticated_users[user.id] = user
        response_message.message = f"{REGISTRATION_SUCCESS} {uid}"
        send_message_to_client(user, response_message)
        return True

    def client_authentication(self, user: User, login: bytes, password: bytes) -> bool:
        """
        Авторизуем пользователя
        :param user:
        :param login:
        :param password:
        :return: True, если пара логин/пароль есть в БД, иначе False
        """
        saltl, saltr = self.thread_locals.users_database.get_salt_by_login(login)
        uid = self.thread_locals.users_database.check_client_authentication_data(login,
                                                                                 get_hash(password, saltl, saltr))
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
        response_message.message = f"{AUTHENTICATION_SUCCESS} {uid}"
        send_message_to_client(user, response_message)
        return True

    def process_message(self, message: Message) -> None:
        """
        пересылает сообщение message.message от message.sender_id к mesage.receiver_id, а также добавляет это сообщение
        в БД
        :param message:
        :return:
        """
        if message.receiver_id in self.authenticated_users:
            receiver = self.authenticated_users[message.receiver_id]
            send_message_to_client(receiver, message)
        if self.thread_locals.users_database.check_if_user_exist(user_id=message.receiver_id):
            if message.secret:
                session_id = self.authenticated_users[message.sender_id].session_ids[message.receiver_id]
                self.thread_locals.messages_database.add_secret_message(session_id=session_id,
                                                                        sender_id=message.sender_id,
                                                                        receiver_id=message.receiver_id,
                                                                        message=message.message,
                                                                        message_tag=message.tag,
                                                                        message_nonce=message.nonce)
            else:
                self.thread_locals.messages_database.add_message(sender_id=message.sender_id,
                                                                 receiver_id=message.receiver_id,
                                                                 message=message.message)
        else:
            receiver = self.authenticated_users[message.sender_id]
            message.receiver_id = message.sender_id
            message.sender_id = SERVER_ID
            message.message_type = COMMAND
            message.message = str(USER_NOT_EXIST)
            send_message_to_client(receiver, message)

    def process_client(self, user: User) -> None:
        # Возможно, что при заверщении работы сервера будет обращение к закрытому клиентскому сокету, и вылезет ошибка,
        # но это не страшно, просто нужно написать какой-нибудь обработчик или закрыть
        self.thread_locals.user_authenticated = False
        self.thread_locals.users_database = ServerUserDatabase()
        self.thread_locals.messages_database = ServerMessageDatabase()
        try:
            while True:
                message = get_message_from_client(user, server=True)
                if not message:
                    break
                if self.thread_locals.user_authenticated and (message.message_type == MESSAGE or
                                                              message.message_type == BYTES_MESSAGE):
                    self.process_message(message)
                elif message.message_type == COMMAND or message.message_type == BYTES_COMMAND:
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
            symmetric_key = get_random_bytes(SYMMETRIC_KEY_LEN_IN_BYTES)
            send_message_to_client(User(sock=secure_connected_socket, symmetric_key=AUTH_NOT_SECRET_KEY),
                                   message=Message(message_type=COMMAND, message=symmetric_key))
            connected_socket = secure_connected_socket.unwrap()

            user = User(sock=connected_socket, public_address=connected_addres, symmetric_key=symmetric_key)
            process_user_thread = threading.Thread(target=self.process_client, args=(user,))
            process_user_thread.start()


def main():
    server = Server()
    server.run()


if __name__ == '__main__':
    main()
