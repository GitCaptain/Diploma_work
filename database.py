import sqlite3 as sql
import os


class Database:

    def __init__(self, path: str):
        try:
            if not os.path.exists(path):
                open(path, 'w+').close()  # Создаем файл базы данных, если его еще не было
            self.database_connection = sql.connect(path)
        except sql.Error as e:
            print("database connection error: {}", e.args[0])
        self.cursor = self.database_connection.cursor()

    def __del__(self):
        self.database_connection.close()

    def execute(self, kwargs):
        pass


class UserDatabase(Database):

    def __init__(self, path: str = None):
        super().__init__(path)


class MessageDatabase(Database):

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
