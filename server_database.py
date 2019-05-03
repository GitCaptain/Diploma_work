from database import *
from constants import DB_USER_NOT_EXIST, DB_WRONG_LOGIN, DB_USER_ALREADY_EXIST, DB_WRONG_PASSWORD


DB_FOLDER = "data"
DB_NAME_USERS = "server_users_database.sqlite"
DB_PATH_USERS = DB_FOLDER + os.sep + DB_NAME_USERS
DB_NAME_MESSAGE = "server_messages_database.sqlite"
DB_PATH_MESSAGE = DB_FOLDER + os.sep + DB_NAME_MESSAGE

DB_TABLE_NAME_USER_LIST = "user_list"
DB_TABLE_NAME_SESSION_ID = "session_id_list"

DB_PREFIX_ENCRYPTED_KEYS = "encrypted_session_keys"
DB_PREFIX_SECRET_MESSAGES_HISTORY = "secret_message_history"
DB_PREFIX_MESSAGE_HISTORY = "message_history"


DB_COLUMN_NAME_RECEIVER_ID = "receiver_id"
DB_COLUMN_NAME_SENDER_ID = "sender_id"
DB_COLUMN_NAME_MESSAGE = "message"
DB_COLUMN_NAME_MESSAGE_TAG = "message_tag"
DB_COLUMN_NAME_MESSAGE_NONCE = "message_nonce"
DB_COLUMN_NAME_SESSION_ID = "session_id"
DB_COLUMN_NAME_FIRST_CLIENT = "first"
DB_COLUMN_NAME_SECOND_CLIENT = "second"
DB_COLUMN_NAME_KEY_ENC_BY_FIRST = "key_encrypted_by_first_id"
DB_COLUMN_NAME_KEY_ENC_BY_SECOND = "key_encrypted_by_second_id"
DB_COLUMN_NAME_USER_ID = "uid"
DB_COLUMN_NAME_USER_LOGIN = "login"
DB_COLUMN_NAME_USER_PASSWORD = "hashed_password"
DB_COLUMN_NAME_USER_PUBLIC_KEY = "public_key"
DB_COLUMN_NAME_SALT_LEFT = "saltl"
DB_COLUMN_NAME_SALT_RIGHT = "saltr"

DB_COLUMN_PROPERTY_TEXT = "TEXT"
DB_COLUMN_PROPERTY_INTEGER = "INTEGER"
DB_COLUMN_PROPERTY_NOT_NULL = "NOT NULL"
DB_COLUMN_PROPERTY_PRIMARY_KEY = "PRIMARY KEY"


class ServerMessageDatabase(MessageDatabase):
    """
    Класс для работы с базой данных сообщений хранящихся на сервере,
    таблица содержащая переписку или какие-то другие данные 2х клиентов всегда имеет имя типа "prefix_id1_id2",
    где id1 < id2, suffix - некоторая константа DB_PREFIX
    """
    def __init__(self, path: str = DB_PATH_MESSAGE, need_server_init: bool = False):
        super().__init__(path=path)

        if need_server_init:
            self.init_server_database()

    def init_server_database(self) -> None:
        """
        Создаем все необходимые таблицы, если их еще нет
        :return:
        """
        self.create_session_id_table()

    def create_message_table(self, id1: int = None, id2: int = None, table_name: str = None) -> None:
        """
        Создаем таблицу для хранения не зашифрованной переписки между клиентами id1 и id2,
        в таблице хранится кто отправил сообщение, кто получил и само сообщение
        :param id1: id первого клиента участвующего в переписке
        :param id2: id второго клиента
        :param table_name: имя таблицы для хранения их сообщений
        :return: None
        """
        if not table_name and (not id1 or not id2):
            raise TypeError
        if not table_name:
            table_name = f"{DB_PREFIX_MESSAGE_HISTORY}{DB_SEP}{min(id1, id2)}{DB_SEP}{max(id1, id2)}"
        columns = (f"{DB_COLUMN_NAME_SENDER_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_RECEIVER_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_MESSAGE} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}")
        self.create_table(table_name, columns)

    def create_secret_message_table(self, id1: int = None, id2: int = None, table_name: str = None) -> None:
        """
        Создаем таблицу для хранения зашифрованной переписки между клиентами id1 и id2,
        в таблице хранится номер сессии (чтоб можно было получить ключ для расшифровки сообщений),
        кто отправил сообщение, кто получил и само сообщение, а также данные, нужные для его расшифровки на клиентской
        стороне
        :param id1: id первого клиента участвующего в переписке
        :param id2: id второго клиента
        :param table_name: имя таблицы для хранения их сообщений
        :return: None
        """
        if not table_name and (not id1 or not id2):
            raise TypeError
        if not table_name:
            if id1 > id2:
                id1, id2 = id2, id1
            table_name = f"{DB_PREFIX_SECRET_MESSAGES_HISTORY}{DB_SEP}{id1}{DB_SEP}{id2}"

        columns = (f"{DB_COLUMN_NAME_SESSION_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_SENDER_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_RECEIVER_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_MESSAGE} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_MESSAGE_TAG} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_MESSAGE_NONCE} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}")
        self.create_table(table_name, columns)

    def create_session_keys_table(self, id1: int, id2: int) -> None:
        """
        Создаем таблицу для хранения зашифрованных открытыми ключами пользователей симметричных ключей, использованных
        для переписки в сессии session_id
        в таблице хранится номер сессии, и ключ зашифрованный публичным ключом пользователя id1 и пользователя id2
        :param id1: id первого клиента участвующего в переписке
        :param id2: id второго клиента
        :return: None
        """
        if id1 > id2:
            id1, id2 = id2, id1
        tb_name = f"{DB_PREFIX_ENCRYPTED_KEYS}{DB_SEP}{id1}{DB_SEP}{id2}"
        columns = (f"{DB_COLUMN_NAME_SESSION_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL} "
                   f"{DB_COLUMN_PROPERTY_PRIMARY_KEY}",
                   f"{DB_COLUMN_NAME_KEY_ENC_BY_FIRST} {DB_COLUMN_PROPERTY_TEXT}",
                   f"{DB_COLUMN_NAME_KEY_ENC_BY_SECOND} {DB_COLUMN_PROPERTY_TEXT}")
        self.create_table_if_not_exist(tb_name, columns)

    def create_session_id_table(self):
        """
        Создаем таблицу для хранения текущего значения session_id для каждой пары клиентов с id1 и id2
        :return:
        """
        table_name = DB_TABLE_NAME_SESSION_ID
        columns = (f"{DB_COLUMN_NAME_SESSION_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_FIRST_CLIENT} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_SECOND_CLIENT} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}")
        self.create_table_if_not_exist(table_name, columns)

    def add_message(self, sender_id: int, receiver_id: int, message: bytes) -> None:
        """
        Добавление не шифрованного сообщения в таблицу сосбщений.
        :param sender_id:
        :param receiver_id:
        :param message:
        :return:
        """
        tb_name = f"{DB_PREFIX_MESSAGE_HISTORY}{DB_SEP}{min(sender_id, receiver_id)}{DB_SEP}" \
                  f"{max(sender_id, receiver_id)}"
        if not self.check_if_table_exist(table_name=tb_name):
            self.create_message_table(table_name=tb_name)
        row_values = (sender_id, receiver_id, memoryview(message))
        self.insert_into_table(tb_name, row_values)

    def add_secret_message(self, session_id: int, sender_id: int, receiver_id: int, message: bytes, message_tag: bytes,
                           message_nonce: bytes) -> None:
        """
        Добавление шифрованного сообщения в таблицу
        :param session_id:
        :param sender_id:
        :param receiver_id:
        :param message:
        :param message_tag:
        :param message_nonce:
        :return:
        """
        tb_name = f"{DB_PREFIX_SECRET_MESSAGES_HISTORY}{DB_SEP}{min(sender_id, receiver_id)}{DB_SEP}" \
                  f"{max(sender_id, receiver_id)}"
        if not self.check_if_table_exist(table_name=tb_name):
            self.create_secret_message_table(table_name=tb_name)
        row_values = (session_id, sender_id, receiver_id,
                      memoryview(message), memoryview(message_tag), memoryview(message_nonce))
        self.insert_into_table(tb_name, row_values)

    def add_session_key_pair(self, session_id: int, id1: int, id2: int, key_encrypted_by_first_id: bytes,
                             key_encrypted_by_second_id: bytes) -> None:
        """
        Добавление пары сессионных ключей в таблицу ключа в таблицу
        !!! id1 < id2, сперва проверяем это условие и меняем местами id и keys, потом записываем в таблицу данные
        сначала об id1, затем id2
        :param session_id:
        :param id1:
        :param id2:
        :param key_encrypted_by_first_id: симметричный сессионный ключ зашифрованный открытым ключом первого клиента
        :param key_encrypted_by_second_id: аналогично для второго
        :return:
        """
        if id1 > id2:
            id1, id2 = id2, id1
            key_encrypted_by_first_id, key_encrypted_by_second_id = \
                key_encrypted_by_second_id, key_encrypted_by_first_id
        tb_name = f"{DB_PREFIX_ENCRYPTED_KEYS}{DB_SEP}{id1}{DB_SEP}{id2}"

        if not self.check_if_table_exist(tb_name):
            self.create_session_keys_table(id1, id2)

        row_values = (session_id, key_encrypted_by_first_id, key_encrypted_by_second_id)

        self.insert_into_table(tb_name, row_values)

    def add_session_key(self, session_id: int, key_holder_id: int, second_id: int, encrypted_key: bytes) -> None:
        """
        Добавление сессионного ключа в таблицу
        :param session_id:
        :param key_holder_id: пользователь, чьим публичным ключом зашифрован данный сессионный ключ
        :param second_id: второй пользователь
        :param encrypted_key: симметричный сессионный ключ зашифрованный открытым ключом key_holder'a
        :return:
        """

        tb_name = f"{DB_PREFIX_ENCRYPTED_KEYS}{DB_SEP}{min(key_holder_id, second_id)}{DB_SEP}" \
                  f"{max(key_holder_id, second_id)}"

        if not self.check_if_table_exist(tb_name):
            self.create_session_keys_table({DB_PREFIX_ENCRYPTED_KEYS})

        # Проверяем, есть ли текущая session_id в таблице (тоесть один из общающихся, уже прислал свой ключ
        execute_str = f"SELECT {DB_GET_EVERYTHING} FROM {tb_name} WHERE {DB_COLUMN_NAME_SESSION_ID}=:session_id;"
        self.cursor.execute(execute_str, {"session_id": session_id})

        if self.cursor.fetchone():
            # session_id уже есть в таблице
            pass
        else:
            # необходимо перед добавлением ключа добавить session_id
            execute_str = f"INSERT INTO {tb_name}({DB_COLUMN_NAME_SESSION_ID}) VALUES(:session_id);"
            self.cursor.execute(execute_str, {"session_id": session_id})

        if key_holder_id < second_id:
            # ключ человека с меньшим id - первый в таблице
            insert_columm = DB_COLUMN_NAME_KEY_ENC_BY_FIRST
        else:
            # ключ человека с большим id - второй в таблице
            insert_columm = DB_COLUMN_NAME_KEY_ENC_BY_SECOND

        execute_str = f"INSERT INTO {tb_name}({insert_columm}) VALUES(:encrypted_key)"
        self.cursor.execute(execute_str, {"encrypted_key": encrypted_key})

    def get_message_history(self, id1: int, id2: int, get_secret: bool = False) -> sql.Row:
        """
        Получаем переписку пользователей id1 и id2
        :param id1:
        :param id2:
        :param get_secret: Нужны зашифрованные сообщения или обычные
        :return: sql.Row object - что-то типо tuple но чуть удобнее, задается в параметре self.cursor.row_factory
        """
        if id1 > id2:
            id1, id2 = id2, id1
        if get_secret:
            tb_name = f"{DB_PREFIX_SECRET_MESSAGES_HISTORY}{DB_SEP}"
        else:
            tb_name = f"{DB_PREFIX_MESSAGE_HISTORY}{DB_SEP}"
        tb_name += f"{id1}{DB_SEP}{id2}"

        if self.check_if_table_exist(tb_name):
            self.cursor.execute(f"SELECT {DB_GET_EVERYTHING} FROM {tb_name};")
            result = self.cursor.fetchone()
        else:
            result = None
        while result:
            yield result
            result = self.cursor.fetchone()

    def get_session_key(self, session_id: int, id1: int, id2: int) -> bytes:
        """
        Получаем пару ключей для session_id, сперва ключ для меньшего id, затем для большего
        :param session_id:
        :param id1:
        :param id2:
        :return:
        """
        if id1 > id2:
            id1, id2 = id2, id1
        tb_name = f"{DB_PREFIX_ENCRYPTED_KEYS}{DB_SEP}{id1}{DB_SEP}{id2}"
        if not self.check_if_table_exist(tb_name):
            return None
        execute_str = f"SELECT {DB_COLUMN_NAME_KEY_ENC_BY_FIRST}, {DB_COLUMN_NAME_KEY_ENC_BY_SECOND} " \
                      f"FROM {tb_name} " \
                      f"WHERE {DB_COLUMN_NAME_SESSION_ID}=:session_id;"
        self.cursor.execute(execute_str, {"session_id": session_id})
        return self.cursor.fetchone()

    def get_new_session_id(self, id1: int, id2: int) -> int:
        """
        Получаем текущий current_session_id для клиентов id1 и id2, если их еще нет в таблице, то добавляем их
        с current_session_id = 1, если они уже есть, то возвращаем текущее значение, и увеличиваем его в таблице на 1
        !!!id1 < id2
        :param id1:
        :param id2:
        :return: текущий current_session_id для пары клиентов id1 и id2
        """
        if id1 > id2:
            id1, id2 = id2, id1
        current_session_id = self.get_current_session_id(id1, id2)
        if current_session_id == 0:
            # нужно добавить новую запись в таблицу, иначе нечего будет обновлять
            row_values = (current_session_id, id1, id2)
            self.insert_into_table(DB_TABLE_NAME_SESSION_ID, row_values)

        new_session_id = current_session_id + 1
        execute_str = f"UPDATE {DB_TABLE_NAME_SESSION_ID} " \
                      f"SET {DB_COLUMN_NAME_SESSION_ID}=:new_session_id " \
                      f"WHERE {DB_COLUMN_NAME_FIRST_CLIENT}=:id1 and {DB_COLUMN_NAME_SECOND_CLIENT}=:id2;"
        self.cursor.execute(execute_str, {"new_session_id": new_session_id, "id1": id1, "id2": id2})
        self.database_connection.commit()
        return new_session_id

    def get_current_session_id(self, id1: int, id2: int) -> int:
        """
        Получаем текущий current_session_id для клиентов id1 и id2
        :param id1:
        :param id2:
        :return: session_id, если такой есть в таблице, иначе 0
        """
        if id1 > id2:
            id1, id2 = id2, id1
        execute_str = f"SELECT {DB_COLUMN_NAME_SESSION_ID} " \
                      f"FROM {DB_TABLE_NAME_SESSION_ID} " \
                      f"WHERE {DB_COLUMN_NAME_FIRST_CLIENT}=:id1 and {DB_COLUMN_NAME_SECOND_CLIENT}=:id2;"
        self.cursor.execute(execute_str, {"id1": id1, "id2": id2})
        current_session_id = self.cursor.fetchone()
        if current_session_id:
            return current_session_id[DB_COLUMN_NAME_SESSION_ID]
        return 0


class ServerUserDatabase(UserDatabase):
    """
    Класс для работы с базой данных клиентов, хранящейся на сервере.
    """
    def __init__(self, path: str = DB_PATH_USERS, need_server_init: bool = False):
        super().__init__(path=path)

        if need_server_init:
            self.init_server_database()

    def init_server_database(self) -> None:
        """
        Создаем все необходимые таблицы, если их еще нет
        :return:
        """
        tb_name = DB_TABLE_NAME_USER_LIST
        columns = (f"{DB_COLUMN_NAME_USER_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL} "
                   f"{DB_COLUMN_PROPERTY_PRIMARY_KEY}",
                   f"{DB_COLUMN_NAME_USER_LOGIN} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_USER_PASSWORD} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_SALT_LEFT} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_SALT_RIGHT} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_USER_PUBLIC_KEY} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}")
        self.create_table_if_not_exist(tb_name, columns)

    def check_client_authentication_data(self, login: bytes, hashed_password: bytes) -> int:
        """
        Сверяем данные присланные от пользователя с данными, хранязимися в базе, чтоб определить является ли клиент тем,
        за кого себя выдает.
        :param login:
        :param hashed_password:
        :return: При успешной аутентификации возвращаем id клиента
        """
        self.cursor.execute(f"SELECT {DB_COLUMN_NAME_USER_ID}, {DB_COLUMN_NAME_USER_PASSWORD} "
                            f"FROM {DB_TABLE_NAME_USER_LIST} "
                            f"WHERE {DB_COLUMN_NAME_USER_LOGIN}=:login;",
                            {"login": memoryview(login)})
        query_result = self.cursor.fetchone()
        if not query_result:  # пользователя не существует
            return DB_WRONG_LOGIN
        elif hashed_password != query_result[DB_COLUMN_NAME_USER_PASSWORD]:
            return DB_WRONG_PASSWORD  # неверный пароль
        else:
            return query_result[DB_COLUMN_NAME_USER_ID]  # возвращаем uid пользователя

    def get_users_count(self) -> int:
        """
        Подсчитываем сколько пользователей зарегистрировано
        :return: количество пользователей хранящихся в БД
        """
        self.cursor.execute(f"SELECT COUNT({DB_GET_EVERYTHING}) "
                            f"FROM {DB_TABLE_NAME_USER_LIST};")
        result = self.cursor.fetchone()
        if not result:
            result = 0
        else:
            result = result[0]
        return result

    def add_user(self, login: bytes, hashed_password: bytes, saltl: bytes, saltr: bytes, public_key: bytes) -> int:
        """
        Добавляем нового пользователя в базу данных
        !!! ТОЛЬКО ОДИН ПОЛЬЗОВАТЕЛЬ МОЖЕТ РЕГИСТРИРОВАТЬСЯ, ОДНОВРЕМЕННО НЕСКОЛЬКИМ НЕЛЬЗЯ, Т.К. ЭТО СЛОМАЕТ
        max_user_id И ТОГДА ГГ БАЗЕ ДАННЫХ (ВОЗМОЖНО СЛЕДУЕТ ПРИДУМАТЬ ДРУГОЙ СПОСОБ РЕГИСТРАЦИИ)
        :param login:
        :param hashed_password:
        :param saltl: данные использованные для "засаливания пароля"
        :param saltr:
        :param public_key:
        :return: id присвоенный клиенту
        """

        if self.check_if_user_exist(login=login):  # пользователь уже существует
            return DB_USER_ALREADY_EXIST
        tb_name = DB_TABLE_NAME_USER_LIST

        # получаем максимальный номер user'a
        self.cursor.execute(f"SELECT MAX({DB_COLUMN_NAME_USER_ID}) FROM {DB_TABLE_NAME_USER_LIST}")
        user_id = self.cursor.fetchone()[0]
        if not user_id:  # таблица создана только что
            user_id = 0

        user_id += 1

        row_values = (user_id, memoryview(login), memoryview(hashed_password), memoryview(saltl),
                      memoryview(saltr), memoryview(public_key))
        self.insert_into_table(tb_name, row_values)
        return user_id

    def delete_user(self, user_id: int) -> None:
        """
        Удаляем пользователя с uid = user_id из БД
        :param user_id:
        :return:
        """
        self.cursor.execute(f"DELETE FROM {DB_TABLE_NAME_USER_LIST} "
                            f"WHERE {DB_COLUMN_NAME_USER_ID}=:uid;",
                            {"uid": user_id})
        self.database_connection.commit()

    def update_user_password(self, user_id: int, new_hashed_password: bytes, saltl: bytes, saltr: bytes) -> None:
        """
        Обновляем пароль и соли для клиента с uid = user_id
        :param user_id:
        :param new_hashed_password: новый пароль
        :param saltl: новые соли
        :param saltr:
        :return:
        """
        self.cursor.execute(f"UPDATE {DB_TABLE_NAME_USER_LIST} "
                            f"SET {DB_COLUMN_NAME_USER_PASSWORD}=:hashed_password, "
                            f"{DB_COLUMN_NAME_SALT_LEFT}=:saltl, {DB_COLUMN_NAME_SALT_RIGHT}=:saltr "
                            f"WHERE {DB_COLUMN_NAME_USER_ID}=:uid;",
                            {"hashed_password": memoryview(new_hashed_password), "uid": user_id,
                             "saltl": memoryview(saltl), "saltr": memoryview(saltr)})
        self.database_connection.commit()

    def check_if_user_exist(self, user_id: int = None, login: bytes = None) -> bool:
        """
        Проверяем есть ли пользователь с логином=login или id=user_id в БД
        :param user_id:
        :param login:
        :return: True, если такой пользователь есть, иначе False
        """
        if not user_id and not login:
            return False
        if login:
            self.cursor.execute(f"SELECT {DB_COLUMN_NAME_USER_ID} "
                                f"FROM {DB_TABLE_NAME_USER_LIST} "
                                f"WHERE {DB_COLUMN_NAME_USER_LOGIN}=:login;", {"login": memoryview(login)})
        elif user_id:
            self.cursor.execute(f"SELECT {DB_COLUMN_NAME_USER_ID} "
                                f"FROM {DB_TABLE_NAME_USER_LIST} "
                                f"WHERE {DB_COLUMN_NAME_USER_ID}=:uid;", {"uid": user_id})
        result = self.cursor.fetchone()
        if result:
            return True
        return False

    def get_client_by_login(self, login: bytes) -> int or sql.Row:
        """
        Возвращаем id, login, public_key пользователя с логином login если такой существует,
        иначе константу DB_USER_NOT_EXIST
        :param login:
        :return: id пользователя или DB_USER_NOT_EXIST
        """
        self.cursor.execute(f"SELECT {DB_COLUMN_NAME_USER_ID}, {DB_COLUMN_NAME_USER_LOGIN}, "
                            f"{DB_COLUMN_NAME_USER_PUBLIC_KEY} "
                            f"FROM {DB_TABLE_NAME_USER_LIST} "
                            f"WHERE {DB_COLUMN_NAME_USER_LOGIN}=:login;",
                            {"login": memoryview(login)})
        user = self.cursor.fetchone()
        if user:
            return user
        return DB_USER_NOT_EXIST

    def get_client_login_by_id(self, uid: int) -> int or bytes:
        """
        :param uid:
        :return: login клиента с id = uid, если такой существует, иначе DB_USER_NOT_EXIST
        """
        self.cursor.execute(f"SELECT {DB_COLUMN_NAME_USER_LOGIN} "
                            f"FROM {DB_TABLE_NAME_USER_LIST} "
                            f"WHERE {DB_COLUMN_NAME_USER_ID}=:id;",
                            {"id": uid})
        login = self.cursor.fetchone()
        if login:
            return login[DB_COLUMN_NAME_USER_LOGIN]
        return DB_USER_NOT_EXIST

    def get_salt_by_login(self, login: bytes) -> (bytes, bytes):
        """
        Возвращаем соль, использованную при регистрации пользователя с логином login и добавлении его в БД.
        Нужно для аутентификации.
        :param login:
        :return: соль испрользованная при регистрации, если пользоваетль с таким логином существует,
        иначе две пустых строки байт
        """
        self.cursor.execute(f"SELECT {DB_COLUMN_NAME_SALT_LEFT}, {DB_COLUMN_NAME_SALT_RIGHT} "
                            f"FROM {DB_TABLE_NAME_USER_LIST} "
                            f"WHERE {DB_COLUMN_NAME_USER_LOGIN}=:login;",
                            {"login": memoryview(login)})
        salts = self.cursor.fetchone()
        if not salts:
            salts = b'', b''
        return salts

    def get_client_public_key_by_id(self, uid: int) -> bytes:
        """
        Возвращаем публичный ключ пользователя
        :param uid:
        :return: публичный ключ пользователя, если такой существует, иначе DB_USER_NOT_EXIST
        """
        self.cursor.execute(f"SELECT {DB_COLUMN_NAME_USER_PUBLIC_KEY} "
                            f"FROM {DB_TABLE_NAME_USER_LIST} "
                            f"WHERE {DB_COLUMN_NAME_USER_ID}=:id;",
                            {"id": uid})
        pk = self.cursor.fetchone()
        if pk:
            return pk[DB_COLUMN_NAME_USER_PUBLIC_KEY]
        return DB_USER_NOT_EXIST
