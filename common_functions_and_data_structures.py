import hashlib
from constants import *


class User:
    # Структура, содержащая данные о клиенте
    def __init__(self, socket: 'socket.socket', client_id: int = 0, public_address: 'tuple(str, int)' = None):
        self.socket = socket
        self.id = client_id
        self.public_address = public_address


class Message:
    # Структура содержащая данные о сообщении
    def __init__(self, message_type: int = None, receiver_id: int = 0, sender_id: int = 0, length: int = 0, message: str = ""):
        self.message_type = message_type
        self.receiver_id = receiver_id
        self.length = length
        self.message = message
        self.sender_id = sender_id

    def __bool__(self):
        return bool(self.message)


def get_hash(string: str, hash_func=hashlib.sha1) -> str:
    return hash_func(get_bytes_string(string)).hexdigest()


def get_message_from_client(user: User) -> Message:
    # служебное сообщение, с данными о клиентсвом сообщении, должно умещаться в один mes_size
    message_data = user.socket.recv(MESSAGE_SIZE)  # message_data = b'MESS_TYPE length receiver_id sender_id'
    if not message_data:  # Клиент отключился
        return Message()
    message_data = message_data.split()

    b_message = b""
    # Вместе с данными о сообщении успело придти и само сообщение и мы получили как минимум его начало, отделенное " "
    # Если получили еще и данные о следующем сообщении, то пока что хз, что с этим делать
    b_message = b_message.join(message_data[MESSAGE_DATA_ITEMS_COUNT:])

    message_type = int(message_data[0])
    length = int(message_data[1])
    receiver_id = int(message_data[2])
    sender_id = int(message_data[3])

    while len(b_message) < length:
        # Нужно получить не больше чем осталось от сообщения, иначе можно получить начало следующего
        message_part = user.socket.recv(min(MESSAGE_SIZE, length - len(b_message)))
        if not message_part:  # Клиент отключился
            b_message = b""
            break
        b_message += message_part
    message = Message(message_type=message_type,
                      receiver_id=receiver_id,
                      sender_id=sender_id,
                      length=length,
                      message=get_text_from_bytes_data(b_message)
                      )
    return message


def get_prepared_message(message: Message) -> (bytes, bytes):
    message.message = " " + message.message
    message.length = len(message.message)
    message_data = bytes("{message_type} {length} {receiver_id} {sender_id}".format(
                    message_type=message.message_type, length=message.length, receiver_id=message.receiver_id,
                    sender_id=message.sender_id
                    ), ENCODING)
    return message_data, get_bytes_string(message.message)


def send_message_to_client(receiver: User, message: Message) -> None:
    message_data, message = get_prepared_message(message)
    if not receiver.socket or not message_data:
        return
    receiver.socket.sendall(message_data)
    receiver.socket.sendall(message)


def get_bytes_string(string: str) -> bytes:
    return bytes(string, ENCODING)


def get_text_from_bytes_data(data: bytes) -> str:
    return data.decode(ENCODING)
