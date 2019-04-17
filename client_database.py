from database import *
from constants import *


DB_FOLDER = "data"
DB_NAME_USERS = "users_database.sqlite"
DB_PATH_USERS = DB_FOLDER + os.sep + DB_NAME_USERS
DB_NAME_MESSAGE = "messages_database.sqlite"
DB_PATH_MESSAGE = DB_FOLDER + os.sep + DB_NAME_MESSAGE


class ClientMessageDatabase(MessageDatabase):

    def __init__(self, path: str = DB_PATH_MESSAGE):
        super().__init__(path=path)


class ClientUserDatabase(UserDatabase):

    def __init__(self, path: str = DB_PATH_USERS):
        super().__init__(path=path)
