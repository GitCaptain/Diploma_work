import hashlib
from constants import *
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


class User:
    # Структура, содержащая данные о клиенте
    def __init__(self, sock: socket.socket, client_id: int = 0, public_address: 'tuple(str, int)' = None,
                 symmetric_key: bytes = None):
        self.socket = sock
        self.id = client_id
        self.public_address = public_address
        self.symmetric_key = symmetric_key


class Message:
    # Структура содержащая данные о сообщении
    def __init__(self, message_type: int = None, receiver_id: int = 0, sender_id: int = 0, length: int = 0,
                 message: (bytes, str) = "", secret: bool = False, message_tag: bytes = b'', message_nonce: bytes = b''):
        self.message_type = message_type
        self.receiver_id = receiver_id
        self.length = length
        self.message = message
        self.sender_id = sender_id
        self.secret = secret
        self.tag = message_tag
        self.nonce = message_nonce

    def __bool__(self):
        return bool(self.message)


def get_hash(string: str, hash_func=hashlib.sha1) -> str:
    return hash_func(get_bytes_string(string)).hexdigest()


def get_encrypted_message(message: bytes, key: bytes, need_encrypt: bool = False) -> (bytes, bytes, bytes):
    if need_encrypt:
        # nonce - a value that must never be reused for any other encryption done with this key.
        # For MODE_EAX, there are no restrictions on its length (recommended: 16 bytes).
        cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(AES_NONCE_LENGTH_IN_BYTES))
        ciphertext, tag = cipher.encrypt_and_digest(message)
        nonce = cipher.nonce
    else:
        mac = HMAC.new(key, digestmod=SHA256)
        mac.update(message)
        tag = mac.digest()
        ciphertext = message
        nonce = b''
    return ciphertext, tag, nonce


def get_decrypted_message(message: Message, key: bytes, need_decrypt: bool = False) -> Message:
    try:
        if need_decrypt:
            cipher = AES.new(key, AES.MODE_EAX, message.nonce)
            message.message = cipher.decrypt_and_verify(message.message, message.tag)
        else:
            mac = HMAC.new(key, digestmod=SHA256)
            mac.update(message.message)
            mac.verify(message.tag)
    except ValueError:  # Сообщение повреждено при передаче
        mes = b'Message corrupted during transmission'
        return Message(message_type=message.message_type,
                       message=mes,
                       receiver_id=message.receiver_id,
                       sender_id=message.sender_id,
                       length=len(mes),
                       secret=False)
    return message


def get_message_from_client(user: User, server: bool = False) -> Message:

    # служебное сообщение, с данными о клиентсвом сообщении
    # message_data = b'message_type message_length receiver_id sender_id secret tag_length nonce_length'
    # После него получаем message, tag, nonce
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
    message_length = int(message_data[1])
    receiver_id = int(message_data[2])
    sender_id = int(message_data[3])
    secret = int(message_data[4])
    tag_length = int(message_data[5])
    nonce_length = int(message_data[6])

    def recv_message(length):
        b_message = b""
        while len(b_message) < length:
            # Нужно получить не больше чем осталось от сообщения, иначе можно получить начало следующего
            message_part = user.socket.recv(min(MESSAGE_SIZE, length - len(b_message)))
            if not message_part:  # Клиент отключился
                b_message = b""
                break
            b_message += message_part
        return b_message

    b_message = recv_message(message_length)
    tag = recv_message(tag_length)
    nonce = recv_message(nonce_length)

    message = Message(message_type=message_type,
                      receiver_id=receiver_id,
                      sender_id=sender_id,
                      length=message_length,
                      message=b_message,
                      secret=bool(secret),
                      message_tag=tag,
                      message_nonce=nonce)

    if not message.message_type == AUTH:
        message = get_decrypted_message(message, user.symmetric_key, message.secret)
        if not message.message_type == BYTES_COMMAND and not message.message_type == BYTES_MESSAGE:
            message.message = get_text_from_bytes_data(message.message)

    return message


def get_prepared_message(message: Message, symmetric_key: bytes) -> (bytes, bytes):
    message.message = get_bytes_string(message.message)

    if not message.message_type == AUTH:
        message.message, tag, nonce = get_encrypted_message(message.message, symmetric_key, need_encrypt=message.secret)
    else:
        tag = nonce = b''

    message.length = len(message.message)
    message_data_str = "{message_type} " \
                       "{message_length} " \
                       "{receiver_id} " \
                       "{sender_id} " \
                       "{secret} " \
                       "{tag_length} " \
                       "{nonce_length}"\
        .format(message_type=message.message_type,
                message_length=message.length,
                receiver_id=message.receiver_id,
                sender_id=message.sender_id,
                secret=int(message.secret),
                tag_length=len(tag),
                nonce_length=len(nonce))

    step = MESSAGE_DATA_SIZE-1
    message_data = []

    # чтобы избежать ситуации когда мы получаем вместе с данными о сообщение и его само и возможно еще и часть
    # следующих данных и т.д. данные о сообщении будут передаваться порциями ровно по MESSAGE_DATA_SIZE символов,
    # последний символ которых равен 1, если еще есть данные об этом сообщении и 0 иначе.
    message_data_str += " " * (step - (len(message_data_str) % step))
    cnt = len(message_data_str) // step
    for i in range(cnt):
        part = message_data_str[i*step:(i+1)*step] + "1"
        message_data.append(part)

    message_data[-1] = message_data[-1][:-1] + "0"

    for i, part in enumerate(message_data):
        message_data[i] = get_bytes_string(part)

    return message_data, message.message, tag, nonce


def send_message_to_client(receiver: User, message: Message) -> None:
    message_data, message, tag, nonce = get_prepared_message(message, receiver.symmetric_key)
    if not receiver.socket or not message_data:
        return
    for data_part in message_data:
        receiver.socket.sendall(data_part)
    receiver.socket.sendall(message)
    receiver.socket.sendall(tag)
    receiver.socket.sendall(nonce)


def get_bytes_string(string: str) -> bytes:
    if isinstance(string, bytes):  # если вдруг пришли сразу байты (например ключ шифрования)
        return string
    return bytes(string, ENCODING)


def get_text_from_bytes_data(data: bytes) -> str:
    return data.decode(ENCODING)


if __name__ == '__main__':
    d, _ = get_prepared_message(Message(message="123", message_type="test" * 20))
    print(*map(len, d))
    print(d)

