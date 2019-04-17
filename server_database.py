from database import *
from constants import *


DB_FOLDER = "data"
DB_NAME_USERS = "users_database.sqlite"
DB_PATH_USERS = DB_FOLDER + os.sep + DB_NAME_USERS
DB_NAME_MESSAGE = "messages_database.sqlite"
DB_PATH_MESSAGE = DB_FOLDER + os.sep + DB_NAME_MESSAGE


class ServerMessageDatabase(MessageDatabase):

    def __init__(self, path: str = DB_PATH_MESSAGE, need_server_init: bool = False):
        super().__init__(path=path)

        if need_server_init:
            self.init_server_database()

    def init_server_database(self) -> None:
        # Создаем все необходимые таблицы, если их еще нет
        self.cursor.execute("CREATE TABLE IF NOT EXISTS pending_messages("
                            "receiver_id INTEGER NOT NULL, "
                            "sender_id INTEGER NOT NULL, "
                            "message TEXT NOT NULL"
                            ");")

    def add_pending_message(self, message: str, sender_id: int, receiver_id: int) -> None:
        self.cursor.execute("INSERT INTO pending_messages "
                            "VALUES(:receiver, :sender, :message);",
                            {"receiver": receiver_id, "sender": sender_id, "message": message})
        self.database_connection.commit()

    def get_pending_messages(self, receiver_id: int) -> list:
        self.cursor.execute("SELECT sender_id, message "
                            "FROM pending_messages "
                            "WHERE receiver_id=:receiver_id;",
                            {"receiver_id": receiver_id})
        data = self.cursor.fetchall()
        self.cursor.execute("DELETE "
                            "FROM pending_messages "
                            "WHERE receiver_id=:receiver_id;",
                            {"receiver_id": receiver_id})
        self.database_connection.commit()
        return data

    def add_message_table(self, id1: int, id2: int) -> None:
        pass

    def add_secret_message_table(self, id1: int, id2: int) -> None:
        pass

    def add_message(self) -> None:
        pass

    def add_secret_message(self) -> None:
        pass


class ServerUserDatabase(UserDatabase):

    def __init__(self, path: str = DB_PATH_USERS, need_server_init: bool = False):
        super().__init__(path=path)

        # получаем максимальный номер user'a
        self.cursor.execute("SELECT MAX(uid) "
                            "FROM user_list;")
        self.max_user_id = self.cursor.fetchone()[0]
        if not self.max_user_id:  # таблица создана только что
            self.max_user_id = 0

        if need_server_init:
            self.init_server_database()

    def init_server_database(self) -> None:
        # Создаем все необходимые таблицы, если их еще нет
        self.cursor.execute("CREATE TABLE IF NOT EXISTS user_list("
                            "uid INTEGER NOT NULL PRIMARY KEY, "
                            "login TEXT NOT NULL, "
                            "hashed_password TEXT NOT NULL, "
                            "saltl TEXT NOT NULL, "
                            "saltr TEXT NOT NULL, "
                            "public_key TEXT NOT NULL"
                            ");")

    def check_person(self, login: str, hashed_password: str) -> int:
        self.cursor.execute("SELECT uid, hashed_password "
                            "FROM user_list "
                            "WHERE login=:login;",
                            {"login": login})
        query_result = self.cursor.fetchone()
        if not query_result:  # пользователя не существует
            return DB_WRONG_LOGIN
        elif hashed_password != query_result[1]:
            return DB_WRONG_PASSWORD  # неверный пароль
        else:
            return query_result[0]  # возвращаем uid пользователя

    def get_users_count(self) -> int:
        self.cursor.execute("SELECT "
                            "COUNT(*)"
                            "FROM user_list;")
        return self.cursor.fetchone()[0]

    def add_user(self, login: str, hashed_password: str, saltl: memoryview, saltr: memoryview,
                 public_key: memoryview) -> int:
        # !!! ТОЛЬКО ОДИН ПОЛЬЗОВАТЕЛЬ МОЖЕТ РЕГИСТРИРОВАТЬСЯ, ОДНОВРЕМЕННО НЕСКОЛЬКИМ НЕЛЬЗЯ, Т.К. ЭТО СЛОМАЕТ
        # max_user_id И ТОГДА ГГ БАЗЕ ДАННЫХ (ВОЗМОЖНО СЛЕДУЕТ ПРИДУМАТЬ ДРУГОЙ СПОСОБ РЕГИСТРАЦИИ)
        if self.check_if_user_exist(login=login):  # пользователь уже существует
            return DB_USER_ALREADY_EXIST
        self.max_user_id += 1
        self.cursor.execute("INSERT INTO user_list "
                            "VALUES(:uid, :login, :hpass, :saltl, :saltr, :public_key);",
                            {"uid": self.max_user_id, "login": login, "hpass": hashed_password,
                             "saltl": saltl, "saltr": saltr, "public_key": public_key})
        self.database_connection.commit()
        return self.max_user_id

    def delete_user(self, user_id: int) -> None:
        self.cursor.execute("DELETE FROM user_list "
                            "WHERE uid=:uid",
                            {"uid": user_id})
        self.database_connection.commit()

    def update_user_password(self, user_id: int, new_hashed_password: str,
                             saltl: memoryview, saltr: memoryview) -> None:
        self.cursor.execute("UPDATE user_list "
                            "SET hashed_password=:hashed_password, saltl=:saltl, saltr=:saltr "
                            "WHERE uid=:uid",
                            {"hashed_password": new_hashed_password, "uid": user_id, "saltl": saltl, "saltr": saltr})
        self.database_connection.commit()

    def check_if_user_exist(self, user_id: int = None, login: str = None) -> bool:
        if not user_id and not login:
            return False
        if login:
            self.cursor.execute("SELECT uid "
                                "FROM user_list "
                                "WHERE login=:login", {"login": login})
        elif user_id:
            self.cursor.execute("SELECT uid "
                                "FROM user_list "
                                "WHERE uid=:uid", {"uid": user_id})
        result = self.cursor.fetchone()
        if result:
            return True
        return False

    def get_id_by_login(self, login: str) -> int:
        self.cursor.execute("SELECT uid "
                            "FROM user_list "
                            "WHERE login=:login;",
                            {"login": login})
        uid = self.cursor.fetchone()
        if uid:
            return uid[0]
        return DB_USER_NOT_EXIST

    def get_salt_by_login(self, login: str) -> (bytes, bytes):
        self.cursor.execute("SELECT saltl, saltr "
                            "FROM user_list "
                            "WHERE login=:login", {"login": login})
        salts = self.cursor.fetchone()
        if not salts:
            salts = b'', b''
        return salts
