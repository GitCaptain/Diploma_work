import sqlite3 as sql
import os

DB_SEP = '_'
DB_GET_EVERYTHING = '*'


class Database:
    """
    Общий класс для работы с БД, определяет для этого самые общие методы.
    """
    def __init__(self, path: str):
        try:
            if not os.path.exists(path):
                _dir, file = os.path.split(path)
                if not os.path.exists(_dir):
                    os.mkdir(_dir)  # создаем папку, в которой будет лежать БД
                open(path, 'w+').close()  # Создаем файл базы данных, если его еще не было
            self.database_connection = sql.connect(path)
        except sql.Error as e:
            print("database connection error: {}", e.args[0])
        self.cursor = self.database_connection.cursor()
        self.cursor.row_factory = sql.Row

    def __del__(self):
        self.cursor.close()
        self.database_connection.close()

    def execute(self):
        pass

    def check_if_table_exist(self, table_name: str) -> int:
        """
        Проверяем существут ли таблица table_name в базе данных
        :param table_name:
        :return: 1 если такая таблица существует, иначе 0
        """
        self.cursor.execute("SELECT count(*) "
                            "FROM sqlite_master "
                            "WHERE type='table' AND name=:table_name;",
                            {"table_name": table_name})

        exist = self.cursor.fetchone()[0]
        return exist

    def create_table(self, table_name: str, ordered_columns_info: 'tuple(str)') -> None:
        """
        Создаем таблцу с именем table_name в БД, с полями и их свойствами перечисленными в ordered_columns_info.
        :param table_name:
        :param ordered_columns_info: Упорядоченные названия полей и их свойства
        :return:
        """
        str_to_execute = f"CREATE TABLE {table_name}(" \
                         f"{self.get_table_params_string_from_args(ordered_columns_info)}" \
                         f");"
        self.cursor.execute(str_to_execute)

    def create_table_if_not_exist(self, table_name, ordered_columns_info: 'tuple(str)') -> None:
        """
        То же, что и create_table, но только проверяет, что создаваемая таблица еще не существует в БД
        :param table_name:
        :param ordered_columns_info: Упорядоченные названия полей и их свойства
        :return:
        """
        str_to_execute = f"CREATE TABLE IF NOT EXISTS {table_name}(" \
                         f"{self.get_table_params_string_from_args(ordered_columns_info)}" \
                         f");"
        self.cursor.execute(str_to_execute)

    def insert_into_table(self, table_name: str, ordered_values: tuple) -> None:
        """
        Добавляет значения из кортежа ordered_values в таблицу table_name
        :param table_name:
        :param ordered_values: упорядоченный список значений в строке, которая будет добавлена в таблицу
        :return:
        """
        execute_str = f"INSERT INTO {table_name} VALUES (" \
                      f"{self.get_table_params_string_from_args(tuple('?'*len(ordered_values)))}" \
                      f");"
        self.cursor.execute(execute_str, ordered_values)
        self.database_connection.commit()

    @staticmethod
    def get_table_params_string_from_args(args: 'tuple(str)') -> str:
        """
        Вспомогательный метод, склеивает кортеж аргументов в одну строку с запятыми
        :param args: кортеж строк, которые надо склеить
        :return:
        """
        return ', '.join(args)

    #  Бесполезные функции, удалить потом
    def test_func(self, data, data2):
        self.cursor.execute("CREATE TABLE IF NOT EXISTS test1(data TEXT);")
        self.cursor.execute("INSERT INTO test1 "
                            "VALUES (:data);",
                            {"data": memoryview(data)})
        self.cursor.execute("INSERT INTO test1 "
                            "VALUES (:data);",
                            {"data": data2})
        self.database_connection.commit()

        self.cursor.execute("SELECT * FROM test1")
        return self.cursor.fetchall()


class UserDatabase(Database):
    """
    Класс переходник между классом БД и пользовательскими классами БД сообщений и пользоваелей, пока что не пригодился,
    но может быть в будующем
    """
    def __init__(self, path: str = None):
        super().__init__(path=path)


class MessageDatabase(Database):
    """
    Класс переходник между классом БД и серверными классами БД сообщений и пользоваелей, пока что не пригодился,
    но может быть в будующем
    """
    def __init__(self, path):
        super().__init__(path=path)


if __name__ == '__main__':
    """
    db = Database(path="data/testDB.db")
    print("total:", db.get_users_count())
    print("max_id:", db.max_user_id)
    print("add duck" + str(db.max_user_id) + ": hi", db.add_user("duck" + str(db.max_user_id), "hi"))
    db.update_user_password(db.max_user_id, "hi" * (db.max_user_id//2))
    print("add duck" + str(db.max_user_id) + ": hi", db.add_user("duck" + str(db.max_user_id), "hi"))
    print("check duck: hi", db.check_person("duck", "hi"))
    print("add duck2: hi2", db.add_user("duck2", "hi2"))
    print("add duck: hi", db.add_user("duck", "hi"))
    print("add duck3: hi3", db.add_user("duck3", "hi3"))
    db.delete_user(db.max_user_id)
    print("total:", db.get_users_count())
    print("max_id:", db.max_user_id)
    db.clean()
    """
    db = Database(path="data/testDB.db")
    r = db.test_func(b'data', 5)
    for row in r:
        print(row['data'])
    result1 = db.check_if_table_exist('str')
    db.create_table_if_not_exist("shiat", ("data TEXT NOT NULL", "pole BLOB"))
    db.insert_into_table("shiat", ("c", "ceceeb"))
    result2 = db.check_if_table_exist('shit')
    print(type(result1), result2)
