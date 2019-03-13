import sqlite3 as sql
from constants import *


class Database:

    def __init__(self, db: 'Database' = None, path: str = None, need_init: bool = False):
        # предполагается, что файл с базой данных есть на диске, нужно обернуть все трай кетчами или тип того
        try:
            if db:
                self.database_connection = db
            elif path:
                self.database_connection = sql.connect(path)
            else:
                self.database_connection = sql.connect("data/users_database.sqlite")
        except sql.Error as e:
            print("database connection error: {}", e.args[0])
        self.cursor = self.database_connection.cursor()

        if need_init:
            self.init_database()

        # получаем максимальный номер user'a
        self.cursor.execute("SELECT MAX(uid) "
                            "FROM user_list;")
        self.max_user_id = self.cursor.fetchone()[0]
        if not self.max_user_id:  # таблица создана только что
            self.max_user_id = 0

    def init_database(self) -> None:
        # Создаем все необходимые таблицы, если их еще нет
        self.cursor.execute("CREATE TABLE IF NOT EXISTS user_list("
                            "uid INTEGER PRIMARY KEY NOT NULL, "
                            "login TEXT NOT NULL, "
                            "hashed_password TEXT NOT NULL"
                            ");")

    def check_person(self, login: str, hashed_password: str, pre_registration_check: bool = False) -> int:
        self.cursor.execute("SELECT uid, hashed_password "
                            "FROM user_list "
                            "WHERE login=:login;",
                            {"login": login})
        query_result = self.cursor.fetchone()
        if not query_result:  # пользователя не существует
            return DB_WRONG_LOGIN
        elif hashed_password != query_result[1] and not pre_registration_check:
            return DB_WRONG_PASSWORD  # неверный пароль
        else:
            return query_result[0]  # возвращаем uid пользователя

    def get_users_count(self) -> int:
        self.cursor.execute("SELECT "
                            "COUNT(*)"
                            "FROM user_list;")
        return self.cursor.fetchone()[0]

    def add_user(self, login: str, hashed_password: str) -> int:
        # !!! ТОЛЬКО ОДИН ПОЛЬЗОВАТЕЛЬ МОЖЕТ РЕГИСТРИРОВАТЬСЯ, ОДНОВРЕМЕННО НЕСКОЛЬКИМ НЕЛЬЗЯ, Т.К. ЭТО СЛОМАЕТ
        # max_user_id И ТОГДА ГГ БАЗЕ ДАННЫХ (ВОЗМОЖНО СЛЕДУЕТ ПРИДУМАТЬ ДРУГОЙ СПОСОБ РЕГИСТРАЦИИ)
        if self.check_person(login, hashed_password, pre_registration_check=True) != DB_WRONG_LOGIN:  # пользователь уже существует
            return DB_USER_ALREADY_EXIST
        self.max_user_id += 1
        self.cursor.execute("INSERT INTO user_list "
                            "VALUES(:uid, :login, :hpass);",
                            {"uid": self.max_user_id, "login": login, "hpass": hashed_password})
        self.database_connection.commit()
        return self.max_user_id

    def delete_user(self, user_id: int) -> None:
        self.cursor.execute("DELETE FROM user_list "
                            "WHERE uid=:uid",
                            {"uid": user_id})
        self.database_connection.commit()

    def update_user_password(self, user_id, new_hashed_password) -> None:
        self.cursor.execute("UPDATE user_list "
                            "SET hashed_password=:hashed_password "
                            "WHERE uid=:uid",
                            {"hashed_password": new_hashed_password, "uid": user_id})
        self.database_connection.commit()

    def __del__(self):
        self.database_connection.close()

    def get_id_by_login(self, login) -> int:
        self.cursor.execute("SELECT uid "
                            "FROM user_list "
                            "WHERE login=:login;",
                            {"login": login})
        uid = self.cursor.fetchone()
        if uid:
            return uid[0]
        return DB_USER_NOT_EXIST

    def clean(self):
        # НЕ ИСПОЛЬЗОВАТЬ!!! ИЛИ ПОДУМАТЬ ПРЕЖДЕ ЧЕМ ИСПОЛЬЗОВАТЬ, ФУНКЦИЮ ПИСАЛ ТОЛЬКО ДЛЯ ТОГО, ЧТОБ ПОТЕСТИТЬ
        # УДАЛЯЕТ ВСЕ СТРОКИ С ОДИНАКОВЫМИ ЛОГИНАМИ КРОМЕ ПЕРВОЙ ВСТРЕЧЕННОЙ
        self.cursor.execute("SELECT login FROM user_list")
        st = set(self.cursor.fetchall())
        for c in st:
            login = c[0]
            self.cursor.execute("SELECT uid "
                                "FROM user_list "
                                "WHERE login=?",
                                (login,))
            good_uid = self.cursor.fetchone()[0]
            self.cursor.execute("DELETE FROM user_list "
                                "WHERE login=? AND uid!=?",
                                (login, good_uid))
            self.database_connection.commit()


if __name__ == '__main__':
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
