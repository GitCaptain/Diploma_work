from gui import *
from client import *
import threading
from queue import Queue

if __name__ == '__main__':

    event_queue = Queue()

    server_address = '192.168.56.1'
    user = Client(server_address, event_queue=event_queue)

    login_window_handlers = {HANDLER_ENTER_BUTTON: user.log_in,
                             HANDLER_REGISTER_BUTTON: user.log_in}

    main_window_handlers = {HANDLER_GET_FRIENDS: user.get_friend_list,
                            HANDLER_ADD_FRIEND: user.add_friend,
                            HANDLER_GET_MESSAGE: user.get_message_history,
                            HANDLER_SEND_MESSAGE: user.send_message,
                            HANDLER_LOG_OUT: user.log_out,
                            HANDLER_DELETE_USER: user.delete_account,
                            HANDLER_P2P_CONNECTION: user.create_p2p_connection}

    interface_handlers = {AUTHENTICATION_HANDLERS: login_window_handlers,
                          MAIN_WINDOW_HANDLERS: main_window_handlers}

    interface = GUI(handlers=interface_handlers, event_queue=event_queue)

    client_thread = threading.Thread(target=user.run)
    client_thread.start()

    interface.run()
    client_thread.join()
