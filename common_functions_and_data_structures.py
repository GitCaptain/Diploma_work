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

    # служебное сообщение, с данными о клиентсвом сообщении
    # message_data = b'MESS_TYPE length receiver_id sender_id'
    message_data = b""
    while True:
        part = user.socket.recv(MESSAGE_DATA_SIZE)
        if not part:
            message_data = b""
            break
        message_data += part[:-1]
        if int(part[-1]) == 48:  # ord('0') = 48
            break

    if not message_data:  # Клиент отключился
        return Message()

    message_data = message_data.split()

    message_type = int(message_data[0])
    length = int(message_data[1])
    receiver_id = int(message_data[2])
    sender_id = int(message_data[3])

    b_message = b""
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
    message.message = get_bytes_string(message.message)
    message.length = len(message.message)
    message_data_str = "{message_type} {length} {receiver_id} {sender_id}".format(
                    message_type=message.message_type, length=message.length, receiver_id=message.receiver_id,
                    sender_id=message.sender_id)

    step = MESSAGE_DATA_SIZE-1
    message_data = []

    # чтобы избежать ситуации когда мы получаем вместе с данными о сообщение и его само и возможно еще и часть
    # следующих данных и т.д. данные о сообщении будут передаваться порциями по MESSAGE_DATA_SIZE символов,
    # последний символ которых равен 1, если еще есть данные об этом сообщении и 0 иначе.
    message_data_str += " " * (step - (len(message_data_str) % step))
    cnt = len(message_data_str) // step
    for i in range(cnt):
        part = message_data_str[i*step:(i+1)*step] + "1"
        message_data.append(part)

    message_data[-1] = message_data[-1][:-1] + "0"

    for i, part in enumerate(message_data):
        message_data[i] = get_bytes_string(part)

    return message_data, message.message


def send_message_to_client(receiver: User, message: Message) -> None:
    message_data, message = get_prepared_message(message)
    if not receiver.socket or not message_data:
        return
    for data_part in message_data:
        receiver.socket.sendall(data_part)
    receiver.socket.sendall(message)


def get_bytes_string(string: str) -> bytes:
    return bytes(string, ENCODING)


def get_text_from_bytes_data(data: bytes) -> str:
    return data.decode(ENCODING)


if __name__ == '__main__':
    d, _ = get_prepared_message(Message(message="123", message_type="test" * 20))
    print(*map(len, d))
    print(d)

