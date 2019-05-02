from gui import *
from client import *
import threading

if __name__ == '__main__':
    server_address = '192.168.56.1'
    a = {HANDLER_ENTER: None, HANDLER_REGISTER: None}
    user = Client(server_address)
    interface = GUI(a)
    interface.prepare_main_window()
    client_thread = threading.Thread(target=user.run)
    client_thread.start()

    interface.run()
    client_thread.join()
