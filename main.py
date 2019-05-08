from gui2 import *
from client import *
import threading
from queue import Queue

if __name__ == '__main__':

    event_queue = Queue()

    server_address = '192.168.56.1'
    user = Client(server_address, event_queue=event_queue)
    user.thread_locals.message_database = ClientMessageDatabase()
    user.thread_locals.users_database = ClientUserDatabase()

    login_window_handlers = {HANDLER_ENTER_BUTTON: user.log_in,
                             HANDLER_REGISTER_BUTTON: user.log_in}

    main_window_handlers = {HANDLER_GET_MESSAGE: user.get_message_history,
                            HANDLER_SEND_MESSAGE: user.send_message,
                            HANDLER_P2P_CONNECTION: user.create_p2p_connection,
                            HANDLER_SECRET_KEY_EXCHANGE: user.symmetric_key_exchange_with_friend}

    friend_list_handlers = {HANDLER_ADD_FRIEND: user.add_friend,
                            HANDLER_LOG_OUT: user.log_out,
                            HANDLER_DELETE_USER: user.delete_account,
                            HANDLER_GET_FRIENDS: user.get_friend_list}

    interface_handlers = {AUTHENTICATION_HANDLERS: login_window_handlers,
                          MAIN_WINDOW_HANDLERS: main_window_handlers,
                          FRIEND_LIST_HANDLERS: friend_list_handlers}

    interface = GUI(handlers=interface_handlers, event_queue=event_queue)

    client_thread = threading.Thread(target=user.run)

    client_thread.start()
    interface.run()
    client_thread.join()
    # exit(0)
