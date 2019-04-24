
# General consts
ENCODING = "utf-8"
PORT_TO_CONNECT = 9090
MESSAGE_SIZE = 4096
MESSAGE_DATA_SIZE = 20
MESSAGE_DATA_ITEMS_COUNT = 4
SERVER_ID = 0
USER_NOT_AUTHENTICATED = 0
SYMMETRIC_KEY_LEN_IN_BYTES = 32  # 256 bit length key is enough
AES_NONCE_LENGTH_IN_BYTES = 16
RSA_KEY_LEN_IN_BITS = 2048

# ключ известный всем на свете, костыль нужный для аутентификации пользователя и сервера, во время ssl соединения,
# а также для подписи не секретных сообщений, т.к. симметричный ключ может быть не установлен, между парой пользователей
NOT_SECRET_KEY = b'sixteen byte key'


# database consts (<=0)
DB_USER_NOT_EXIST = -4
DB_WRONG_PASSWORD = -1
DB_WRONG_LOGIN = 0
DB_USER_ALREADY_EXIST = 0

# Request consts
MESSAGE = 1
COMMAND = 2
BYTES_MESSAGE = 3
BYTES_COMMAND = 4
MESSAGE_ERROR = 5
ID_ERROR = 6

# Command to server consts
LOG_IN = 1
REGISTER_USER = 2
DELETE_USER = 3
ADD_FRIEND_BY_LOGIN = 4
ADD_FRIEND_BY_ID = 5
LOG_OUT = 6
GET_MESSAGES = 7
CREATE_P2P_CONNECTION = 8
SYMMETRIC_KEY_EXCHANGE = 9

# Server response
WRONG_LOGIN = 1
WRONG_PASSWORD = 2
USER_ALREADY_EXIST = 3
AUTHENTICATION_SUCCESS = 4
REGISTRATION_SUCCESS = 5
NOT_AUTHENTICATED = 6

USER_NOT_EXIST = 7
FRIEND_DATA = 8
USER_OFFLINE = 9

P2P_TCP = 10
P2P_UDP = 11
P2P_CONNECTION_TYPE = 12
P2P_ADDRESS = 13
P2P_CONNECTION_DATA = 14

SYMMETRIC_KEY = 15
MESSAGE_FROM_DATABASE = 16
MESSAGE_KEY_FROM_DATABASE = 17
SECRET_MESSAGE_FROM_DATABASE = 18
ALL_MESSAGES_SENDED = 19
