import sqlite3 as sql


class Database:

    def __init__(self, db=None, path=None):
        # предполагается, что файл с базой данных есть на диске, нужно обернуть все трай кетчами или тип того
        if db:
            self.database = db
        elif path:
            self.database = sql.connect(path)
        else:
            self.database = sql.connect("data/users_database.db")
        self.cursor = self.database.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS user_list("
                            "uid INTEGER PRIMARY KEY NOT NULL, "
                            "login TEXT NOT NULL, "
                            "hashed_password TEXT NOT NULL"
                            ");")
        self.cursor.execute("SELECT MAX(uid) "
                            "FROM user_list;")
        self.max_user_id = self.cursor.fetchone()[0]
        if not self.max_user_id:  # таблица создана только что
            self.max_user_id = 0

    def create_table(self):
        pass

    def get_users_count(self):
        self.cursor.execute("SELECT "
                            "COUNT(*)"
                            "FROM user_list;")
        return self.cursor.fetchone()[0]

    def check_person(self, login, hashed_password):
        self.cursor.execute("SELECT uid, hashed_password "
                            "FROM user_list "
                            "WHERE login=:login;",
                            {"login": login})
        query_result = self.cursor.fetchone()
        if not query_result:  # пользователя не существует
            return 0
        elif hashed_password != query_result[1]:
            return -1  # неверный пароль
        else:
            return query_result[0]  # возвращаем uid пользователя

    def add_user(self, login, hashed_password):
        # !!! ТОЛЬКО ОДИН ПОЛЬЗОВАТЕЛЬ МОЖЕТ РЕГИСТРИРОВАТЬСЯ, ОДНОВРЕМЕННО НЕСКОЛЬКИМ НЕЛЬЗЯ, Т.К. ЭТО СЛОМАЕТ
        # max_user_id И ТОГДА ГГ БАЗЕ ДАННЫХ (ВОЗМОЖНО СЛЕДУЕТ ПРИДУМАТЬ ДРУГОЙ СПОСОБ РЕГИСТРАЦИИ)
        if self.check_person(login, hashed_password) > 0:  # пользователь уже существует
            return False
        self.max_user_id += 1
        self.cursor.execute("INSERT INTO user_list "
                            "VALUES(:uid, :login, :hpass);",
                            {"uid": self.max_user_id, "login": login, "hpass": hashed_password})
        self.database.commit()
        return self.max_user_id

    def delete_user(self, user_id):
        self.cursor.execute("DELETE FROM user_list "
                            "WHERE uid=:uid",
                            {"uid": user_id})
        self.database.commit()

    def update_user_password(self, user_id, new_hashed_password):
        self.cursor.execute("UPDATE user_list "
                            "SET hashed_password=:hashed_password "
                            "WHERE uid=:uid",
                            {"hashed_password": new_hashed_password, "uid": user_id})
        self.database.commit()

    def __del__(self):
        self.database.close()

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
            self.database.commit()


if __name__ == '__main__':
    db = Database(path="data/testDB.db")
    print("total:", db.get_users_count())
    print("max_id:", db.max_user_id)
    print("add dick" + str(db.max_user_id) + ": hui", db.add_user("dick" + str(db.max_user_id), "hui"))
    db.update_user_password(db.max_user_id, "hui" * (db.max_user_id//2))
    print("add dick" + str(db.max_user_id) + ": hui", db.add_user("dick" + str(db.max_user_id), "hui"))
    print("check dick: hui", db.check_person("dick", "hui"))
    print("add dick2: hui2", db.add_user("dick2", "hui2"))
    print("add dick: hui", db.add_user("dick", "hui"))
    print("add dick3: hui3", db.add_user("dick3", "hui3"))
    db.delete_user(db.max_user_id)
    print("total:", db.get_users_count())
    print("max_id:", db.max_user_id)
    db.clean()

