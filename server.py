from common_functions_and_data_structures import *
from server_database import *
from Crypto.Random import get_random_bytes
import threading  # заменить на настоящуюю многопоточность, если возможно
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
        # разделять нужно именно по пробелу, чтоб не убирать \n (если их убрать, то например полученный
        # открытый улюч пользователя неудастся восстановить)
        if message.type == BYTES_COMMAND:
            sep = b' '
        else:
            sep = ' '
        data = message.message.split(sep)
        command = int(data[0])
        if not self.thread_locals.user_authenticated and command != CLIENT_LOG_IN and command != CLIENT_REGISTER_USER:
            message = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=ID_ERROR,
                              message=str(SERVER_NOT_AUTHENTICATED))
            send_message_to_client(user, message, user.symmetric_key)
            return False
        if command == CLIENT_REGISTER_USER:
            # data  = [..., b'login', b'password', b'sp_beg', b'sp_end', b'public_key']
            if not self.client_registration(user, data[1], data[2], int(data[3]), int(data[4]), data[5:]):
                return False
            return True
        elif command == CLIENT_LOG_IN:
            # data = [..., b'login', b'password']
            if not self.client_authentication(user, data[1], data[2]):
                return False
            return True
        elif command == CLIENT_DELETE_USER or command == CLIENT_LOG_OUT:  # переработать, вынести в отдельную функцию
            self.thread_locals.user_authenticated = False
            if not user.id:
                return False
            if command == CLIENT_DELETE_USER:
                self.thread_locals.users_database.delete_user(user.id)
            self.authenticated_users.pop(user.id)
            user.id = 0
            return True
        elif command == CLIENT_ADD_FRIEND_BY_LOGIN or command == CLIENT_ADD_FRIEND_BY_ID:
            # data = [..., b'login' or b'id']
            self.send_client_data(user, command, data[1])
        elif command == CLIENT_CREATE_P2P_CONNECTION:
            # data = [..., 'P2P_CONNECTION_TYPE', 'peer_id','con_type'] or
            # data = [..., 'P2P_ADDRESS', 'peer_id', 'private_ip', 'private_port']

            command_type = int(data[1])
            second_peer_id = int(data[2])
            message = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=user.id)
            if second_peer_id not in self.authenticated_users:
                message.message = f"{SERVER_USER_OFFLINE} {second_peer_id}"
                send_message_to_client(user, message, user.symmetric_key)
                return False
            second_peer = self.authenticated_users[second_peer_id]

            message = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=second_peer.id)
            command_to_peer = P2P_CONNECTION_DATA
            if command_type == P2P_ADDRESS:
                user_private_address = data[3], int(data[4])
                message.message = f"{command_to_peer} {command_type} {user.id} " \
                                  f"{user.public_address[0]} {user.public_address[1]} " \
                                  f"{user_private_address[0]} {user_private_address[1]}"
            elif command_type == P2P_CONNECTION_TYPE:
                message.message = f"{command_to_peer} {command_type} {user.id} {data[3]}"
            send_message_to_client(second_peer, message, user.symmetric_key)
        elif command == CLIENT_GET_MESSAGES:
            # data = [.., 'users_friend_id']
            users_friend_id = int(data[1])
            self.send_usual_message_history(user, users_friend_id)
            self.send_encrypted_message_history(user, users_friend_id)
            send_message_to_client(user, Message(mes_type=COMMAND, sender_id=self.id, receiver_id=user.id,
                                                 message=str(SERVER_ALL_MESSAGES_SENT)), user.symmetric_key)
        elif command == CLIENT_SYMMETRIC_KEY_EXCHANGE:
            # data = [..., b'peer_id', b'user_beg', b'user_end', b'peer_beg', b'peer_end',
            # b'user_encrypted_key', b'friend_encrypted_key']
            peer_id = int(data[1])

            # возможно, что при разбиении по пробелу, ключи также распались на части (тоесть содержали пробел) тогда
            # перед тем как работать с ними дальше их нужно собрать из этих частей, разделителем между ключами служит
            # b'split'. user_beg, user_end - количество пробелов в начале и конце ключа пользователя, peer_beg peer_end
            # - аналогично, для его друга
            split = data.index(b'split')
            user_beg, user_end = int(data[2]), int(data[3])
            peer_beg, peer_end = int(data[4]), int(data[5])

            user_encrypted_key = get_key_from_parts(user_beg, data[6:split], user_end)
            peer_encrypted_key = get_key_from_parts(peer_beg, data[split+1:], peer_end)

            session_id = self.thread_locals.messages_database.get_new_session_id(user.id, peer_id)
            # Добавляем пару сессионных ключей в БД
            self.thread_locals.messages_database.add_session_key_pair(session_id, user.id, peer_id,
                                                                      user_encrypted_key, peer_encrypted_key)

            # если клиент в сети, то он сразу получает свой ключ
            if peer_id in self.authenticated_users:
                receiver = self.authenticated_users[peer_id]
                message = Message(mes_type=BYTES_COMMAND, receiver_id=receiver.id, sender_id=SERVER_ID)
                message.message = get_bytes_string(f"{SERVER_SYMMETRIC_KEY} {user.id} {peer_beg} {peer_end} ") \
                                  + peer_encrypted_key
                send_message_to_client(receiver, message, receiver.symmetric_key)

            return True

        else:
            pass

    def send_client_data(self, user: User, command_type: int, login_or_id: bytes) -> None:
        """
        Отправляем данные клиенту user о клиенте с данным логином или id
        :param user:
        :param command_type: если ADD_FRIEND_BY_ID, значит пришло id, если ADD_FRIEND_BY_LOGIN, значит пришел логин
        :param login_or_id:
        :return:
        """
        if command_type == CLIENT_ADD_FRIEND_BY_ID:
            login = self.thread_locals.users_database.get_client_login_by_id(int(login_or_id))
        else:
            login = login_or_id

        if login == DB_USER_NOT_EXIST:
            friend_data = DB_USER_NOT_EXIST
        else:
            friend_data = self.thread_locals.users_database.get_client_by_login(login)

        if friend_data == DB_USER_NOT_EXIST:
            message_to_user = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=user.id)
            message_to_user.message = str(SERVER_USER_NOT_EXIST)
        else:
            message_to_user = Message(mes_type=BYTES_COMMAND, sender_id=self.id, receiver_id=user.id)
            key = friend_data[DB_COLUMN_NAME_USER_PUBLIC_KEY]
            beg, end = count_spaces_at_the_edges(key)
            message_to_user.message = get_bytes_string(f"{SERVER_FRIEND_DATA} {friend_data[DB_COLUMN_NAME_USER_ID]} ") + \
                                      friend_data[DB_COLUMN_NAME_USER_LOGIN] + get_bytes_string(f" {beg} {end} ") + key
        send_message_to_client(user, message_to_user, user.symmetric_key)

    def send_usual_message_history(self, user: User, users_friend_id: int) -> None:
        """
        Высылаем нещифрованную переписку между user.id и users_friend_id из БД пользователю.
        :param user:
        :param users_friend_id:
        :return:
        """
        message_generator = self.thread_locals.messages_database.get_message_history(user.id, users_friend_id)
        message = Message(mes_type=BYTES_COMMAND, sender_id=self.id, receiver_id=user.id)
        for db_mes in message_generator:  # db_mes = (from: int, to: int, mes: bytes)
            message.message = get_bytes_string(f"{SERVER_MESSAGE_FROM_DATABASE} "
                                               f"{db_mes[DB_COLUMN_NAME_SENDER_ID]} "
                                               f"{db_mes[DB_COLUMN_NAME_RECEIVER_ID]} ") \
                              + db_mes[DB_COLUMN_NAME_MESSAGE]
            send_message_to_client(user, message, user.symmetric_key)

    def send_encrypted_message_history(self, user: User, users_friend_id: int) -> None:
        """
        Высылаем шифрованную переписку между user.id и users_friend_id из БД пользователю.
        :param user:
        :param users_friend_id:
        :return:
        """
        message_generator = self.thread_locals.messages_database.get_message_history(user.id, users_friend_id, True)
        session_id = -1  # несуществующая сессия
        message = Message(mes_type=BYTES_COMMAND, sender_id=self.id, receiver_id=user.id)
        # нужно еще одно подключение к БД сообщений, т.к. мы одновременно получаем и сообщения и ключи из разных таблиц
        session_key_db_connection = ServerMessageDatabase()
        for db_mes in message_generator:  # db_mes = (ses_id:int, from:int, to:int, mes:bytes, tag:bytes, nonce:bytes)
            if db_mes[DB_COLUMN_NAME_SESSION_ID] != session_id:
                mes = Message(mes_type=BYTES_COMMAND, sender_id=self.id, receiver_id=user.id)
                session_id = db_mes[DB_COLUMN_NAME_SESSION_ID]
                session_key = session_key_db_connection.get_session_key(session_id, user.id, users_friend_id)
                if user.id < users_friend_id:
                    session_key = session_key[0]
                else:
                    session_key = session_key[1]
                beg, end = count_spaces_at_the_edges(session_key)
                mes.message = get_bytes_string(
                    f"{SERVER_MESSAGE_KEY_FROM_DATABASE} {session_id} {beg} {end} ") + session_key
                send_message_to_client(user, mes, user.symmetric_key)
            # отправляем 4 сообщения подряд с инфо о сообщении, самим сообщением, затем его тег и нонс, чтоб клиент смог
            # их восстановить (хз как восстанавливать, если отправлять их одним сообщением)
            message.message = get_bytes_string(f"{SERVER_SECRET_MESSAGE_FROM_DATABASE} data "
                                               f"{db_mes[DB_COLUMN_NAME_SENDER_ID]} "
                                               f"{db_mes[DB_COLUMN_NAME_RECEIVER_ID]} {session_id}")
            send_message_to_client(user, message, user.symmetric_key)
            message.message = get_bytes_string(f"{SERVER_SECRET_MESSAGE_FROM_DATABASE} mes ") + db_mes[DB_COLUMN_NAME_MESSAGE]
            send_message_to_client(user, message, user.symmetric_key)
            message.message = get_bytes_string(f"{SERVER_SECRET_MESSAGE_FROM_DATABASE} tag ") + \
                              db_mes[DB_COLUMN_NAME_MESSAGE_TAG]
            send_message_to_client(user, message, user.symmetric_key)
            message.message = get_bytes_string(f"{SERVER_SECRET_MESSAGE_FROM_DATABASE} nonce ") + \
                              db_mes[DB_COLUMN_NAME_MESSAGE_NONCE]
            send_message_to_client(user, message, user.symmetric_key)

    def client_registration(self, user: User, login: bytes, password: bytes, spaces_at_begin: int, spaces_at_end: int,
                            public_key: list) -> bool:
        """
        Регистрируем нового пользователя
        :param user:
        :param login:
        :param password:
        :param spaces_at_begin: количество пробелов в начале ключа
        :param spaces_at_end: количество пробелов в конце ключа
        :param public_key: открытый ключ, возможно распавшийся на несколько частей
        :return: True, если регистрация прошла успешно, т.е. логин не был занят и ничего другого плохого не случилось,
                 иначе False
        """

        public_key = get_key_from_parts(spaces_at_begin, public_key, spaces_at_end)

        saltl = get_random_bytes(8)
        saltr = get_random_bytes(8)

        self.lock.acquire()
        uid = self.thread_locals.users_database.add_user(login, get_hash(password, saltl, saltr),
                                                         saltl, saltr, public_key)
        self.lock.release()

        response_message = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=ID_ERROR)
        if uid == DB_USER_ALREADY_EXIST:
            response_message.message = str(SERVER_USER_ALREADY_EXIST)
            send_message_to_client(user, response_message, user.symmetric_key)
            return False
        user.id = uid
        response_message.receiver_id = uid
        self.thread_locals.user_authenticated = True
        self.authenticated_users[user.id] = user
        response_message.message = f"{SERVER_REGISTRATION_SUCCESS} {uid}"
        send_message_to_client(user, response_message, user.symmetric_key)
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
        hashed_password = get_hash(password, saltl, saltr)
        uid = self.thread_locals.users_database.check_client_authentication_data(login, hashed_password)
        response_message = Message(mes_type=COMMAND, sender_id=self.id, receiver_id=ID_ERROR)
        if uid == DB_WRONG_LOGIN:
            response_message.message = str(SERVER_WRONG_LOGIN)
            send_message_to_client(user, response_message, user.symmetric_key)
            return False
        elif uid == DB_WRONG_PASSWORD:
            response_message.message = str(SERVER_WRONG_PASSWORD)
            send_message_to_client(user, response_message, user.symmetric_key)
            return False
        user.id = uid
        response_message.receiver_id = uid
        self.thread_locals.user_authenticated = True
        self.authenticated_users[user.id] = user
        response_message.message = f"{SERVER_AUTHENTICATION_SUCCESS} {uid}"
        send_message_to_client(user, response_message, user.symmetric_key)
        return True

    def process_message(self, message: Message) -> None:
        """
        пересылает сообщение message от message.sender_id к mesage.receiver_id, а также добавляет это сообщение
        в БД
        :param message:
        :return:
        """
        # TODO Сделать что-нибудь при попытке отправить сообщение удаленному пользователю
        if not message.secret:
            # сообщение не зашифровано, но подписано ключом, который знает отправитель и сервер,
            # нужно проверить подлинность этого сообщения ключом сервера и отправителя и, если оно не повреждено,
            # переподписать ключом известным серверу и получателю, иначе прекратить обработку сообщения
            sid = message.sender_id
            message.message = get_decrypted_message(message.message, self.authenticated_users[sid].symmetric_key,
                                                    message.tag, message.nonce)
            if message.message == BROKEN_MESSAGE:
                return
        if message.receiver_id in self.authenticated_users:
            receiver = self.authenticated_users[message.receiver_id]
            send_message_to_client(receiver, message, receiver.symmetric_key, need_encrypt=not message.secret)
        if self.thread_locals.users_database.check_if_user_exist(user_id=message.receiver_id):
            if message.secret:
                session_id = self.thread_locals.messages_database.get_current_session_id(message.sender_id,
                                                                                         message.receiver_id)
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
            message.type = COMMAND
            message.message = str(SERVER_USER_NOT_EXIST)
            send_message_to_client(receiver, message, receiver.symmetric_key)

    def process_client(self, user: User) -> None:
        # Возможно, что при заверщении работы сервера будет обращение к закрытому клиентскому сокету, и вылезет ошибка,
        # но это не страшно, просто нужно написать какой-нибудь обработчик или закрыть
        self.thread_locals.user_authenticated = False
        self.thread_locals.users_database = ServerUserDatabase()
        self.thread_locals.messages_database = ServerMessageDatabase()
        try:
            while True:
                message = get_message_from_client(user)
                if not message:
                    break

                if self.thread_locals.user_authenticated and (message.type == MESSAGE or
                                                              message.type == BYTES_MESSAGE):
                    # пользовательские сообщения пересылаются и добавляются в БД как есть,
                    # без расшифровки и приведения к текстовому виду
                    self.process_message(message)
                elif message.type == COMMAND or message.type == BYTES_COMMAND:
                    # секретную команду (например передача пароля) нужно расшифровать,
                    message.message = get_decrypted_message(message.message, user.symmetric_key,
                                                            message.tag, message.nonce, message.secret)
                    # а если оно имеет тип COMMAND, то еще и преобразовать в текст
                    if message.type == COMMAND:
                        message.message = get_text_from_bytes_data(message.message)
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
            send_message_to_client(receiver=User(sock=secure_connected_socket),
                                   # данное сообщение не нужно шифровать, т.к. оно передается по ssl каналу
                                   message=Message(mes_type=COMMAND, sender_id=self.id, receiver_id=ID_ERROR,
                                                   message=symmetric_key),
                                   # параметр key в данном случае передается только для того, чтоб функция работала,
                                   # на самом деле ничего шифроваться не будет,
                                   # а подпись этого сообщения нигде не проверяется
                                   key=NOT_SECRET_KEY)

            connected_socket = secure_connected_socket.unwrap()

            user = User(sock=connected_socket, public_address=connected_addres, symmetric_key=symmetric_key)
            process_user_thread = threading.Thread(target=self.process_client, args=(user,))
            process_user_thread.start()


def main():
    server = Server()
    server.run()


if __name__ == '__main__':
    main()
