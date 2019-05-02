from gui import *
from client import *
import threading

if __name__ == '__main__':
    server_address = '192.168.56.1'

    user = Client(server_address)

    login_window_handlers = {HANDLER_ENTER: user.log_in, HANDLER_REGISTER: user.log_in}
    main_window_handlers = {}

    interface_handlers = {AUTHENTICATION_HANDLERS: login_window_handlers,
                          MAIN_WINDOW_HANDLERS: main_window_handlers}

    interface = GUI(handlers=interface_handlers)

    client_thread = threading.Thread(target=user.run)
    client_thread.start()

    interface.run()
    client_thread.join()
