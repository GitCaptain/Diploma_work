from gui2 import *
from client import *
import threading
from queue import Queue

if __name__ == '__main__':

    event_queue = Queue()

    server_address = SERVER_ADDRESS

    user = Client(server_address, event_queue=event_queue)
    user.thread_locals.message_database = ClientMessageDatabase()
    user.thread_locals.users_database = ClientUserDatabase()

    login_window_handlers = {HANDLER_ENTER_BUTTON: user.log_in,
                             HANDLER_REGISTER_BUTTON: user.log_in}

    main_window_handlers = {HANDLER_GET_MESSAGE: user.get_message_history,
                            HANDLER_SEND_MESSAGE: user.send_message,
                            HANDLER_SEND_FILE: user.send_file,
                            HANDLER_P2P_CONNECTION: user.create_p2p_connection,
                            HANDLER_SECRET_KEY_EXCHANGE: user.symmetric_key_exchange_with_friend,
                            HANDLER_EXTRACT_MESSAGE: extract_message}

    friend_list_handlers = {HANDLER_ADD_FRIEND: user.add_friend,
                            HANDLER_LOG_OUT: user.log_out,
                            HANDLER_DELETE_USER: user.delete_account,
                            HANDLER_GET_FRIENDS: user.get_friend_list}

    interface_handlers = {AUTHENTICATION_HANDLERS: login_window_handlers,
                          MAIN_WINDOW_HANDLERS: main_window_handlers,
                          FRIEND_LIST_HANDLERS: friend_list_handlers,
                          STOP_BACKEND: user.exit_program}

    interface = GUI(handlers=interface_handlers, event_queue=event_queue)

    client_thread = threading.Thread(target=user.run)

    client_thread.start()
    interface.run()
    client_thread.join()
