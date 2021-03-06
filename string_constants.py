

"""
This file generated automatically by "make_string_consts_from_int_consts.py",
it contains string constants used in the program.
"""


# General consts
ENCODING = "utf-8"
PORT_TO_CONNECT = 9090
MESSAGE_SIZE = 4096
MESSAGE_DATA_SIZE = 20
MESSAGE_DATA_ITEMS_COUNT = 4
SERVER_ID = 0

# database_consts (<=0)
DB_USER_NOT_EXIST = -4
DB_WRONG_PASSWORD = -1
DB_WRONG_LOGIN = 0
DB_USER_ALREADY_EXIST = 0

# Request Consts
MESSAGE = '1'
COMMAND = '2'

# Command to server Consts
LOG_IN = '1'
REGISTER_USER = '2'
DELETE_USER = '3'
GET_USER_ID_BY_LOGIN = '4'
LOG_OUT = '5'
GET_PENDING_MESSAGES = '6'
CREATE_P2P_CONNECTION = '7'

# Server response
WRONG_LOGIN = '1'
WRONG_PASSWORD = '2'
USER_ALREADY_EXIST = '3'
AUTHENTICATION_SUCCESS = '4'
REGISTRATION_SUCCESS = '5'
NOT_AUTHENTICATED = '6'

USER_NOT_EXIST = '7'
USER_FOUND = '8'

P2P_USER_OFFLINE = '9'
P2P_TCP = '10'
P2P_UDP = '11'
P2P_KEEP_ALIVE = '12'
P2P_CONNECTION_TYPE = '13'
P2P_ADDRESS = '14'
P2P_CONNECTION_DATA = '15'
