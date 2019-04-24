from constants import *
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


class User:
    """
    Структура, содержащая данные о клиенте
    """
    def __init__(self, sock: socket.socket, client_id: int = 0, public_address: 'tuple(str, int)' = None,
                 symmetric_key: bytes = None):
        self.socket = sock
        self.id = client_id
        self.public_address = public_address
        self.symmetric_key = symmetric_key


class Message:
    """
    Структура содержащая данные о сообщении
    """
    def __init__(self, type: int, receiver_id: int, sender_id: int, length: int = 0, message: (bytes, str) = "",
                 secret: bool = False, message_tag: bytes = b'', message_nonce: bytes = b'',
                 secret_session_id: int = 0):
        self.type = type
        self.receiver_id = receiver_id
        self.length = length
        self.message = message
        self.sender_id = sender_id
        self.secret = secret
        self.tag = message_tag
        self.nonce = message_nonce
        self.secret_session_id = secret_session_id

    def __bool__(self):
        return bool(self.message)


BROKEN_MESSAGE = Message(type=MESSAGE_ERROR, sender_id=ID_ERROR, receiver_id=ID_ERROR)


def get_hash(string: bytes, saltl: bytes = b'', saltr: bytes = b'', hash_func=SHA256) -> bytes:
    """
    Получаем хеш строки string с "солью"
    :param string:
    :param saltl: "соль" (набор байт) которая будет приписана слева к строке
    :param saltr: то-же самое, но справа
    :param hash_func: функция хеширования
    :return: хеш строки
    """
    return hash_func.new(data=saltl + string + saltr).digest()


def get_encrypted_message(message: bytes, key: bytes, need_encrypt: bool = False) -> (bytes, bytes, bytes):
    """
    Подписывает или зашифровывает сообщение
    :param message:
    :param key:
    :param need_encrypt: нужно ли шифровать сообщение
    :return: Подписанное (зашифрованное) сообщение, tag и nonce, нужные для проверки подлинности сообщения получателем
    """
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


def get_decrypted_message(message: bytes, key: bytes, tag: bytes, nonce: bytes, need_decrypt: bool = False) -> \
        bytes or int:
    """
    Проверяет подпись и при необходимости расшифровывает сообщение
    :param message:
    :param key:
    :param tag:
    :param nonce:
    :param need_decrypt: Нужно ли расшифровывать сообщение
    :return: Расшифрованное (проверенное) сообщение, если оно не повреждено, иначе константу MESSAGE_ERROR
    """
    try:
        if need_decrypt:
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            message = cipher.decrypt_and_verify(message, tag)
        else:
            mac = HMAC.new(key, digestmod=SHA256)
            mac.update(message)
            mac.verify(tag)
    except ValueError:  # Сообщение повреждено при передаче
        return MESSAGE_ERROR
    return message


def get_message_from_client(user: User, server: bool = False) -> Message:
    """
    Получаем сообщение от user'a
    :param user:
    :param server:
    :return: полученное сообщение
    """
    # служебное сообщение, с данными о клиентсвом сообщении
    # message_data = b'message_type message_length receiver_id sender_id secret tag_length nonce_length secret_sess_id'
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
        return BROKEN_MESSAGE

    message_data = message_data.split()

    message_type = int(message_data[0])
    message_length = int(message_data[1])
    receiver_id = int(message_data[2])
    sender_id = int(message_data[3])
    secret = int(message_data[4])
    tag_length = int(message_data[5])
    nonce_length = int(message_data[6])
    secret_session_id = int(message_data[7])

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

    message = Message(type=message_type,
                      receiver_id=receiver_id,
                      sender_id=sender_id,
                      length=message_length,
                      message=b_message,
                      secret=bool(secret),
                      message_tag=tag,
                      message_nonce=nonce,
                      secret_session_id=secret_session_id)

    """
    if server:
        print("server got:", message.message, "\nfrom", message.sender_id, "to", message.receiver_id)
    """
    return message


def get_prepared_message(message: Message, symmetric_key: bytes) -> (bytes, bytes, bytes, bytes):
    """
    Подготавливает сообщение к отправке, внося все необходимые данные
    :param message:
    :param symmetric_key:
    :return: Данные о сообщении (отправляются перед сообщением), зашифрованное (подписанное сообщение), его tag и nonce
    """
    message.message = get_bytes_string(message.message)

    message.message, tag, nonce = get_encrypted_message(message.message, symmetric_key, need_encrypt=message.secret)

    message.length = len(message.message)
    message_data_str = f"{message.type} " \
                       f"{message.length} " \
                       f"{message.receiver_id} " \
                       f"{message.sender_id} " \
                       f"{int(message.secret)} " \
                       f"{len(tag)} " \
                       f"{len(nonce)} " \
                       f"{message.secret_session_id}"

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


def send_message_to_client(receiver: User, message: Message, key: bytes) -> None:
    """
    Отправляет сообщение клиенту
    :param receiver:
    :param message:
    :param key: симметричный ключ, известный отправителю и КОНЕЧНОМУ получателю
    (т.е. не серверу, а именно конечному клиенту, если это не сервер)
    :return:
    """
    message_data, message, tag, nonce = get_prepared_message(message, key)
    if not receiver.socket or not message_data:
        return
    for data_part in message_data:
        receiver.socket.sendall(data_part)
    receiver.socket.sendall(message)
    receiver.socket.sendall(tag)
    receiver.socket.sendall(nonce)


def get_bytes_string(string: str or bytes or memoryview) -> bytes:
    """
    Возвращает string преобразованный в bytes
    :param string:
    :return:
    """
    if isinstance(string, memoryview):  # если вдруг пришли memoryview (например из БД пришли ключи)
        return bytes(string)
    if isinstance(string, bytes):  # если вдруг пришли сразу байты (например ключ шифрования)
        return string
    return bytes(string, ENCODING)


def get_text_from_bytes_data(data: bytes) -> str:
    """
    Возвращает строку в кодировке ENCODING полученную из data
    :param data:
    :return:
    """
    return data.decode(ENCODING)


def get_key_from_parts(public_key_parts: list) -> bytes:
    """
    Могло (а может и нет, но на всякий случай предусмотрим это) оказаться, что в public_key клиентa
    оказался один или несколько пробелов, тогда во время data.split() public_key клиента распался
    на несколько частей, которые необходимо склеить, вставив между ними пробел
    :param public_key_parts: части на которые распался public_key
    :return: собранный public_key
    """
    return b' '.join(public_key_parts)


if __name__ == '__main__':
    d, _ = get_prepared_message(Message(message="123", type="test" * 20))
    print(*map(len, d))
    print(d)

