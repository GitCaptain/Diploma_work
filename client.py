from constants import *


class Client:

    def __init__(self, use_transport_layer_security=False, use_program_security=False, server_hostname='localhost'):
        import socket

        self.cipher = use_program_security
        self.socket = socket.socket()

        if use_transport_layer_security:
            import ssl
            context = ssl.create_default_context()
            # context.load_verify_locations("server_cert.pem")
            context.load_verify_locations("ssl_cert.pem")
            context.check_hostname = False
            self.socket = context.wrap_socket(self.socket, server_hostname=server_hostname)

        if use_program_security:
            from cryptography.fernet import Fernet
            with open("key", 'r') as key_file:
                self.fernet_key = bytes(key_file.readline().strip(), encoding=encoding)
            self.fernet = Fernet(self.fernet_key)

        self.socket.connect((server_hostname, port_to_connect))
        server_data = self.socket.recv(mes_size).decode()  #Получаем ID
        print(server_data.strip())
        self.id = server_data.split()[2]

    def run(self):
        import threading
        user_thread = threading.Thread(target=self.user_data)
        #user_thread.setDaemon(True)
        user_thread.start()

        while True:
            server_data = self.socket.recv(mes_size)
            if self.cipher:
                server_data = self.fernet.decrypt(server_data)
            if not server_data:
                break
            print(server_data.decode())

    def user_data(self):
        while True:
            user_data = input()
            user_data = "recv from " + self.id + ": " + user_data
            if self.cipher:
                user_data = self.fernet.encrypt(bytes(user_data, encoding=encoding))
            else:
                user_data = bytes(user_data, encoding)
            if user_data:  # не отсылаем пустую строку, это ломает что-то внутри _ssl.c
                self.socket.send(user_data)


def main():
    from sys import argv

    address = '192.168.56.1'
    tls = False
    cipher = False

    for arg in argv[1:]:
        if arg == '--tls':
            tls = True
        elif arg == '--cipher':
            cipher = True
        else:
            address = arg

    client = Client(tls, cipher, address)
    client.run()


if __name__ == '__main__':
    main()
