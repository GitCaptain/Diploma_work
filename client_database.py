from database import *


DB_FOLDER = "data"
DB_NAME_USERS = "users_database.sqlite"
DB_PATH_USERS = DB_FOLDER + os.sep + DB_NAME_USERS
DB_NAME_MESSAGE = "messages_database.sqlite"
DB_PATH_MESSAGE = DB_FOLDER + os.sep + DB_NAME_MESSAGE

DB_TABLE_NAME_FRIEND_LIST = "friend_list"

DB_SUFFIX_SECRET_MESSAGES = "secret"

DB_COLUMN_NAME_MESSAGE_RECEIVED = "message_received"  # Это сообщение я получил, а не отправил
DB_COLUMN_NAME_MESSAGE = "message"
DB_COLUMN_NAME_FRIEND_PUBLIC_KEY = "public_key"
DB_COLUMN_NAME_FRIEND_ID = "id"
DB_COLUMN_NAME_LOGIN = "login"

DB_COLUMN_PROPERTY_TEXT = "TEXT"
DB_COLUMN_PROPERTY_INTEGER = "INTEGER"
DB_COLUMN_PROPERTY_NOT_NULL = "NOT NULL"
DB_COLUMN_PROPERTY_PRIMARY_KEY = "PRIMARY KEY"


class ClientMessageDatabase(MessageDatabase):
    """
    Класс для работы с БД сообщений, хранящихся на стороне клиента.
    """
    def __init__(self, path: str = DB_PATH_MESSAGE):
        super().__init__(path=path)

    def create_message_table(self, friend_id: int = None, table_name: str = None, secret_messages: bool = False)\
            -> None:
        """
        Создаем таблицу сообщений, полученных и отправленных в ходе P2P общения с пользователем friend_id
        :param friend_id:
        :param table_name:
        :param secret_messages: если True, то таблица для сообщений полученных в результате секретной переписки,
        иначе обычной
        :return:
        """
        if not table_name and not friend_id:
            raise TypeError
        if not table_name:
            tb_name = f"{friend_id}"
            if secret_messages:
                tb_name += f" {DB_SUFFIX_SECRET_MESSAGES}"
        columns = (f"{DB_COLUMN_NAME_MESSAGE_RECEIVED} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_MESSAGE} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}")
        self.create_table_if_not_exist(tb_name, columns)

    def add_message(self, friend_id: int, message_received: bool, message_secret: bool, message: str) -> None:
        """
        Добавляем сообщение message в диалог с friend_id
        :param friend_id:
        :param message_received: True, если сообщение получено, False, если отправлено
        :param message_secret: True, если сообщение секретно, False, если нет
        :param message:
        :return:
        """
        tb_name = f"{friend_id}"
        if message_secret:
            tb_name += f" {DB_SUFFIX_SECRET_MESSAGES}"
        if not self.check_if_table_exist(table_name=tb_name):
            self.create_message_table(tb_name)
        row_values = (message_received, message)
        self.insert_into_table(tb_name, row_values)

    def get_message_history(self, friend_id: int, get_secret: bool = False) -> sql.Row:
        """
        Вытаскиваем из БД переписку с пользователем friend_id
        :param friend_id:
        :param get_secret: True - переписка из шифорванных сообщений, False - нет
        :return:
        """
        tb_name = f"{friend_id}"
        if get_secret:
            tb_name += f" {DB_SUFFIX_SECRET_MESSAGES}"
        self.cursor.execute("SELECT * FROM :tb_name;", {"tb_name": tb_name})
        result = self.cursor.fetchone()
        while result:
            yield result
            result = self.cursor.fetchone()


class ClientUserDatabase(UserDatabase):
    """
    Класс для работы с БД пользователей, которые являются "друзьями" текущего пользователя
    """
    def __init__(self, path: str = DB_PATH_USERS, need_client_init: bool = False):
        super().__init__(path=path)

        if need_client_init:
            self.init_client_database()

    def init_client_database(self) -> None:
        """
        Создаем все необходимые таблицы
        :return:
        """
        tb_name = DB_TABLE_NAME_FRIEND_LIST
        columns = (f"{DB_COLUMN_NAME_FRIEND_ID} {DB_COLUMN_PROPERTY_INTEGER} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_LOGIN} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}",
                   f"{DB_COLUMN_NAME_FRIEND_PUBLIC_KEY} {DB_COLUMN_PROPERTY_TEXT} {DB_COLUMN_PROPERTY_NOT_NULL}")
        self.create_table_if_not_exist(tb_name, columns)

    def add_friend(self, friend_id: int, login: str, public_key: bytes) -> None:
        """
        Добавляем друга с заданными параметрами в БД
        :param friend_id:
        :param login:
        :param public_key:
        :return:
        """
        columns = (friend_id, login, memoryview(public_key))
        self.insert_into_table(DB_TABLE_NAME_FRIEND_LIST, columns)

    def delete_friend(self, friend_id: int) -> None:
        """
        Удаляем друга friend_id из БД друзей
        :param friend_id:
        :return:
        """
        execute_str = f"DELETE FROM {DB_TABLE_NAME_FRIEND_LIST} " \
                      f"WHERE {DB_COLUMN_NAME_FRIEND_ID}=:friend_id;"
        self.cursor.execute(execute_str, {"friend_id": friend_id})
        self.database_connection.commit()

    def get_friend_list(self) -> sql.Row:
        """
        Получаем список друзей пользоваетеля, без их публичных ключей, т.к. они нужны в другом месте
        :return: sql.Row объект с информацией о друге
        """
        execute_str = f"SELECT {DB_COLUMN_NAME_FRIEND_ID}, {DB_COLUMN_NAME_LOGIN}" \
                      f"FROM {DB_TABLE_NAME_FRIEND_LIST};"
        self.cursor.execute(execute_str)
        result = self.cursor.fetchone()
        while result:
            yield result
            result = self.cursor.fetchone()

    def get_friends_public_key(self, friend_id: int) -> bytes:
        """
        Получаем публичный ключ пользователя friend_id
        :param friend_id:
        :return: public_key
        """
        execute_str = f"SELECT {DB_COLUMN_NAME_FRIEND_PUBLIC_KEY} " \
                      f"FROM {DB_TABLE_NAME_FRIEND_LIST} " \
                      f"WHERE {DB_COLUMN_NAME_FRIEND_ID}=:friend_id;"
        self.cursor.execute(execute_str, {"friend_id": friend_id})
        return self.cursor.fetchone()[DB_COLUMN_NAME_FRIEND_PUBLIC_KEY]
