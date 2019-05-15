from tkinter import *
from tkinter.messagebox import *
from constants import *
from queue import Queue, Empty
from sys import exit

MESSENGER_NAME = "deep low moan"

AUTHENTICATION_HANDLERS = 0
MAIN_WINDOW_HANDLERS = 1
FRIEND_LIST_HANDLERS = 2
STOP_BACKEND = 3

HANDLER_REGISTER_BUTTON = 'register'
HANDLER_ENTER_BUTTON = 'enter'
HANDLER_GET_FRIENDS = 'get friends'
HANDLER_ADD_FRIEND = 'add friend'
HANDLER_LOG_OUT = 'log out'
HANDLER_DELETE_USER = 'delete user'
HANDLER_GET_MESSAGE = 'get message'
HANDLER_SEND_MESSAGE = 'send message'
HANDLER_P2P_CONNECTION = 'p2p'
HANDLER_SECRET_KEY_EXCHANGE = 'secret'

WINDOW_CHANGE_AUTHENTICATION_WINDOW = 'open auth'
WINDOW_CHANGE_MAIN_WINDOW = 'open main'
WINDOW_CHANGE_FRIEND_LIST_WINDOW = 'open friends'


class PixelSizedButton(Button):
    """
    Кнопка, размеры которой можно задать в пикселях
    """
    def __init__(self, master=None, **kwargs):
        if 'image' in kwargs:
            self.img = kwargs['image']
        else:
            self.img = PhotoImage()
        super().__init__(master, image=self.img, compound=CENTER, **kwargs)


class PixelSizedLabel(Label):
    """
    Метка, размеры которой можно задать в пикселях
    """
    def __init__(self, master=None, **kwargs):
        if 'image' in kwargs:
            self.img = kwargs['image']
        else:
            self.img = PhotoImage()
        super().__init__(master, image=self.img, compound=CENTER, **kwargs)


class EntryWithTemplateString(Entry):

    TEMPLATE_STRING = 'templatestring'
    CLEAR_ON_RETURN = 'clearonreturn'

    def __init__(self, master=None, **kwargs):

        if self.TEMPLATE_STRING in kwargs:
            self.template = kwargs.pop(self.TEMPLATE_STRING)
        else:
            self.template = ''

        if self.CLEAR_ON_RETURN in kwargs:
            self.clear_on_ret = kwargs.pop(self.CLEAR_ON_RETURN)
        else:
            self.clear_on_ret = False

        super().__init__(master, kwargs)
        self.template_stated = False
        self.insert_template_string()

        self.bind('<Key>', self.delete_template_string)
        self.bind('<Button-1>', self.delete_template_string)
        self.bind('<FocusIn>', self.delete_template_string)
        self.bind('<Return>', self.on_enter_pressed)
        self.bind('<FocusOut>', self.on_focus_out)

    def on_focus_out(self, *args):
        if not self.template_stated and self.get() == '':
            self.insert_template_string()

    def delete_template_string(self, *args):
        if self.template_stated:
            self.delete(0, END)
            self.config(fg='black')
            self.template_stated = False

    def insert_template_string(self, *args):
        self.delete(0, END)
        self.config(fg='grey')
        self.insert(0, self.template)
        self.template_stated = True

    def on_enter_pressed(self, *args):
        if self.clear_on_ret:
            self.insert_template_string()


class LoginWindow(Frame):

    def __init__(self, master=None, handlers=None, **kwargs):

        super().__init__(master, kwargs)
        self.handlers = handlers

        self.auth_window = Frame(self)
        self.auth_window.pack(expand=YES, fill=BOTH)

        entry_width = 100
        button_width = 100
        button_height = 40
        self.login_var = StringVar()
        self.login_entry = EntryWithTemplateString(self.auth_window, width=entry_width,
                                                   **{EntryWithTemplateString.TEMPLATE_STRING: 'логин:'})
        self.login_entry.config(textvariable=self.login_var)
        self.login_entry.pack(side=TOP, expand=YES)

        self.password_var = StringVar()
        self.password_entry = EntryWithTemplateString(self.auth_window, width=entry_width,
                                                      **{EntryWithTemplateString.TEMPLATE_STRING: 'пароль:'})
        self.password_entry.config(textvariable=self.password_var)
        self.password_entry.pack(side=TOP, expand=YES)

        self.enter_button = PixelSizedButton(self.auth_window, width=button_width, height=button_height, text='Вход')
        self.enter_button.pack(side=TOP, expand=YES)

        self.register_button = PixelSizedButton(self.auth_window, width=button_width, height=button_height,
                                                text='Регистрация')
        self.register_button.pack(side=TOP, expand=YES)

        self.set_handlers()

    def set_handlers(self):

        self.register_button.config(command=(lambda: self.get_registration_data(CLIENT_REGISTER_USER)))
        self.register_button.bind('<Return>', (lambda *args: self.get_registration_data(CLIENT_REGISTER_USER)))
        self.enter_button.config(command=(lambda: self.get_registration_data(CLIENT_LOG_IN)))
        self.enter_button.bind('<Return>', (lambda *args: self.get_registration_data(CLIENT_LOG_IN)))

        self.login_entry.bind('<Return>', lambda *args: self.password_entry.focus_set())
        self.password_entry.bind('<Return>', lambda *args: self.enter_button.focus_set())

    def get_registration_data(self, auth_type):
        password = self.password_var.get()
        login = self.login_var.get()
        if not password or not login:
            showerror('Некорректный ввод', 'Заполните все поля')
            return
        self.handlers[HANDLER_REGISTER_BUTTON](login, password, auth_type)


class ChatWindow(Frame):

    SELECTED_CHAT = 1
    SELECTED_SECRET_CHAT = 2
    SELECTED_P2P_CHAT = 3
    SELECTED_SECRET_P2P_CHAT = 4

    BUTTON_NAME_CHAT = "чат"
    BUTTON_NAME_SECRET_CHAT = "секретный чат"
    BUTTON_NAME_P2P_CHAT = "p2p чат"
    BUTTON_NAME_SECRET_P2P_CHAT = "секретный p2p чат"

    def __init__(self, master, handlers, selected_id, selected_login, event_queue, **kwargs):
        super().__init__(master, kwargs)
        self.handlers = handlers
        self.chat_selected = None
        self.selected_friend_id = selected_id
        self.selected_friend_login = selected_login
        self.event_queue = event_queue

        # ----------------------------- верхняя полоска с информацией
        settings_frame_height = 20
        self.settings_frame = Frame(self, height=settings_frame_height)
        self.settings_frame.pack(side=TOP, fill=X, anchor=N)

        self.back_button = Button(self.settings_frame, text="назад")
        self.back_button.pack(side=LEFT, fill=Y)

        self.chat_info_label = Label(self.settings_frame, text=f"чат с {self.selected_friend_login}")
        self.chat_info_label.pack(side=LEFT, fill=Y)

        self.start_p2p_button = Button(self.settings_frame, text="Установить p2p соединение")
        self.start_p2p_button.pack(side=RIGHT, fill=Y)

        self.exchange_keys_button = Button(self.settings_frame, text="установить секретный ключ")
        self.exchange_keys_button.pack(side=RIGHT, fill=Y)
        # ----------------------------- верхняя полоска с информацией

        # ----------------------------- кнопки выбора чата
        self.chat_button_frame = Frame(self)
        self.chat_button_frame.pack(side=TOP, fill=BOTH)

        self.chat_button = Button(self.chat_button_frame, text=self.BUTTON_NAME_CHAT)
        self.chat_button.pack(side=LEFT, fill=Y)

        self.secret_chat_button = Button(self.chat_button_frame, text=self.BUTTON_NAME_SECRET_CHAT)
        self.secret_chat_button.pack(side=LEFT, fill=Y)

        self.p2p_chat_button = Button(self.chat_button_frame, text=self.BUTTON_NAME_P2P_CHAT)
        self.p2p_chat_button.pack(side=LEFT, fill=Y)

        self.secret_p2p_chat_button = Button(self.chat_button_frame, text=self.BUTTON_NAME_SECRET_P2P_CHAT)
        self.secret_p2p_chat_button.pack(side=LEFT, fill=Y)
        # ----------------------------- кнопки выбора чата

        # ----------------------------- Frame все связанное с чатом
        self.chat_frame = Frame(self)
        self.chat_frame.pack(side=RIGHT, fill=BOTH, expand=YES)

        # ----------------------------- окно чата
        self.dialog_frame = Frame(self.chat_frame)
        self.dialog_frame.pack(side=TOP, fill=BOTH, expand=YES)

        self.dialog_frame_scrollbar = Scrollbar(self.dialog_frame)
        self.dialog_frame_scrollbar.pack(side=RIGHT, fill=Y)

        self.dialog_frame_listbox = Listbox(self.dialog_frame)
        self.dialog_frame_listbox.pack(side=LEFT, fill=BOTH, expand=YES)

        self.dialog_frame_listbox.config(yscrollcommand=self.dialog_frame_scrollbar.set)
        self.dialog_frame_scrollbar.config(command=self.dialog_frame_listbox.yview)
        # ----------------------------- окно чата

        # ----------------------------- ввод сообщения
        message_frame_height = 20
        self.message_frame = Frame(self.chat_frame, height=message_frame_height)
        self.message_frame.pack(side=BOTTOM, fill=X)

        self.message_var = StringVar()
        self.message_entry = EntryWithTemplateString(self.message_frame, templatestring='Введите сообщение:',
                                                     textvariable=self.message_var,
                                                     **{EntryWithTemplateString.CLEAR_ON_RETURN: True})
        self.message_entry.pack(side=LEFT, fill=BOTH, expand=YES)

        self.send_button = PixelSizedButton(self.message_frame, text='отослать')
        self.send_button.pack(side=RIGHT)
        # ----------------------------- ввод сообщения

        # ----------------------------- Frame все связанное с чатом

        self.set_handlers()
        self.update_view(self.selected_friend_id, False, False)

    def set_handlers(self):

        self.back_button.config(command=self.go_back)
        self.start_p2p_button.config(command=self.start_p2p)
        self.exchange_keys_button.config(command=self.exchange_keys)

        self.chat_button.config(command=self.show_chat)
        self.secret_chat_button.config(command=self.show_secret_chat)
        self.p2p_chat_button.config(command=self.show_p2p_chat)
        self.secret_p2p_chat_button.config(command=self.show_secret_p2p_chat)

        self.message_entry.bind('<Return>', self.send_message)
        self.send_button.config(command=self.send_message)

    def start_p2p(self):
        self.handlers[HANDLER_P2P_CONNECTION](self.selected_friend_id, True)

    def exchange_keys(self):
        self.handlers[HANDLER_SECRET_KEY_EXCHANGE](self.selected_friend_id)

    def go_back(self):
        self.event_queue.put((WINDOW_CHANGE_FRIEND_LIST_WINDOW, ))

    def send_message(self, *args):
        message = self.message_var.get()
        if not message or self.message_entry.template_stated:
            return

        secret, p2p = False, False
        if self.chat_selected == self.SELECTED_SECRET_CHAT:
            secret = True
        elif self.chat_selected == self.SELECTED_P2P_CHAT:
            p2p = True
        elif self.chat_selected == self.SELECTED_SECRET_P2P_CHAT:
            secret = True
            p2p = True

        self.message_entry.on_enter_pressed()
        self.insert_message(message, True)
        self.handlers[HANDLER_SEND_MESSAGE](message, self.selected_friend_id, p2p, secret)

    def show_chat(self):
        self.chat_selected = self.SELECTED_CHAT
        self.chat_info_label.config(text=f"{self.BUTTON_NAME_CHAT} с {self.selected_friend_login}")
        self.chat_button.config(text=self.BUTTON_NAME_CHAT)
        self.update_view(self.selected_friend_id, False, False)

    def show_secret_chat(self):
        self.chat_selected = self.SELECTED_SECRET_CHAT
        self.chat_info_label.config(text=f"{self.BUTTON_NAME_SECRET_CHAT} с {self.selected_friend_login}")
        self.secret_chat_button.config(text=self.BUTTON_NAME_SECRET_CHAT)
        self.update_view(self.selected_friend_id, True, False)

    def show_p2p_chat(self):
        self.chat_selected = self.SELECTED_P2P_CHAT
        self.chat_info_label.config(text=f"{self.BUTTON_NAME_P2P_CHAT} с {self.selected_friend_login}")
        self.p2p_chat_button.config(text=self.BUTTON_NAME_P2P_CHAT)
        self.update_view(self.selected_friend_id, False, True)

    def show_secret_p2p_chat(self):
        self.chat_selected = self.SELECTED_SECRET_P2P_CHAT
        self.chat_info_label.config(text=f"{self.BUTTON_NAME_SECRET_P2P_CHAT} с {self.selected_friend_login}")
        self.secret_p2p_chat_button.config(text=self.BUTTON_NAME_SECRET_P2P_CHAT)
        self.update_view(self.selected_friend_id, True, True)

    def insert_message(self, text, is_sender):
        if is_sender:
            text = f"Отправлено: {text}"
        else:
            text = f"Принято: {text}"
        self.dialog_frame_listbox.insert(END, text)
        self.dialog_frame_listbox.see(END)

    def update_view(self, uid, secret, p2p):
        # TODO когда сообщения приходят от другого клиента чат сменяется без обновления метки, исправить
        self.dialog_frame_listbox.delete(0, END)
        for message in self.handlers[HANDLER_GET_MESSAGE](uid, secret, p2p):
            self.insert_message(message.message, message.is_sender)
        self.dialog_frame_listbox.see(END)


class FriendListWindow(Frame):

    def __init__(self, master, handlers, event_queue, login, **kwargs):

        super().__init__(master, kwargs)
        self.handlers = handlers
        self.event_queue = event_queue
        self.client_login = login
        # ----------------------------- поиск и кнопка добавить
        self.search_frame = Frame(self)
        self.search_frame.pack(side=TOP, fill=X)

        self.add_var = StringVar()
        self.add_entry = EntryWithTemplateString(self.search_frame, textvariable=self.add_var,
                                                 templatestring='логин: ')
        self.add_entry.pack(side=TOP, fill=X)

        self.add_button = PixelSizedButton(self.search_frame, text='Добавить друга')
        self.add_button.pack(side=TOP, fill=X)
        # ----------------------------- поиск и кнопка добавить

        # ----------------------------- Список друзей
        self.friend_list_frame = Frame(self)
        self.friend_list_frame.pack(side=TOP, fill=BOTH, expand=YES)

        self.friend_list_scrollbar = Scrollbar(self.friend_list_frame)
        self.friend_list_scrollbar.pack(side=RIGHT, fill=Y)

        self.friend_list_listbox = Listbox(self.friend_list_frame)
        self.friend_list_listbox.pack(side=LEFT, fill=BOTH, expand=YES)

        self.friend_list_listbox.config(yscrollcommand=self.friend_list_scrollbar.set)
        self.friend_list_scrollbar.config(command=self.friend_list_listbox.yview)
        # ----------------------------- Список друзей

        # ----------------------------- нижняя полоска инфо
        self.settings_frame = Frame(self)
        self.settings_frame.pack(side=BOTTOM, fill=X)

        self.login_label = Label(self.settings_frame, text=f"вход выполнен: {self.client_login}")
        self.login_label.pack(side=TOP)

        self.exit_button = PixelSizedButton(self.settings_frame, text='Выйти из аккаунта')
        self.exit_button.pack(side=TOP, fill=BOTH)

        self.delete_button = PixelSizedButton(self.settings_frame, text='Удалить аккаунт')
        self.delete_button.pack(side=TOP, fill=BOTH)
        # ----------------------------- нижняя полоска инфо

        self.set_handlers()

    def set_handlers(self):
        self.delete_button.config(command=self.handlers[HANDLER_DELETE_USER])
        self.exit_button.config(command=self.handlers[HANDLER_LOG_OUT])

        self.add_entry.bind('<Return>', self.add_friend)
        self.add_button.config(command=self.add_friend)

        self.delete_button.config(command=self.delete_user)
        self.exit_button.config(command=self.log_out)

        self.friend_list_listbox.bind('<Double-Button-1>', self.show_chat_with_friend)
        self.friend_list_listbox.bind('<Return>', self.show_chat_with_friend)

    def update_friend_list(self):
        friend_generator = self.handlers[HANDLER_GET_FRIENDS]()
        for friend in friend_generator:
            self.add_item_into_friend_list(friend)

    def add_item_into_friend_list(self, friend_item):
        flogin, fid = friend_item
        if fid != SERVER_ID:
            self.friend_list_listbox.insert(0, f"{flogin}: {fid}")

    def add_friend(self, *args):
        login = self.add_var.get()
        if login and not self.add_entry.template_stated:
            self.handlers[HANDLER_ADD_FRIEND](login)
            self.add_entry.insert_template_string()

    def log_out(self):
        self.handlers[HANDLER_LOG_OUT]()

    def delete_user(self):
        self.handlers[HANDLER_DELETE_USER]()

    def show_chat_with_friend(self, *args):
        selected = self.friend_list_listbox.curselection()
        if selected:
            selected = self.friend_list_listbox.get(selected[0])
            login, uid = selected.split(':')
            uid = int(uid)
            self.event_queue.put((WINDOW_CHANGE_MAIN_WINDOW, login, uid))


class GUI:

    def __init__(self, handlers=None, event_queue=None):
        self.root = Tk()
        self.root.title(MESSENGER_NAME)
        self.handlers = handlers
        self.check_interval_in_milliseconds = 10

        self.client_authenticated = False
        self.client_login = ''
        self.client_init_done = False
        self.even_queue = event_queue
        self.login_window = None
        self.chat_window = None
        self.friend_list_window = None
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def run_authentication_window(self):

        self.clear_root()
        self.root.geometry("280x140")
        self.root.resizable(width=False, height=False)

        self.login_window = LoginWindow(self.root, handlers=self.handlers[AUTHENTICATION_HANDLERS])
        self.login_window.pack(fill=BOTH, expand=YES)

    def run_main_window(self, flogin, fid):

        self.clear_root()
        self.root.geometry("600x400")
        self.root.resizable(width=True, height=True)
        self.root.title(f"{self.client_login}'s {MESSENGER_NAME}")
        self.chat_window = ChatWindow(master=self.root,
                                      handlers=self.handlers[MAIN_WINDOW_HANDLERS],
                                      event_queue=self.even_queue,
                                      selected_id=fid,
                                      selected_login=flogin)

        self.chat_window.pack(fill=BOTH, expand=YES)

    def run_friend_list_window(self):
        self.clear_root()
        self.root.geometry("250x400")
        self.root.resizable(width=False, height=True)

        self.friend_list_window = FriendListWindow(master=self.root,
                                                   handlers=self.handlers[FRIEND_LIST_HANDLERS],
                                                   event_queue=self.even_queue,
                                                   login=self.client_login)
        self.friend_list_window.update_friend_list()
        self.friend_list_window.pack(fill=BOTH, expand=YES)

    def on_success_auth(self, data):
        # data = ['login']
        self.client_authenticated = True
        self.client_login = data[0]
        self.run_friend_list_window()

    def on_fail_auth(self, fail_type):
        if fail_type == SERVER_WRONG_LOGIN:
            showerror("Ошибка входа", "Пользователя с таким логином не существует")
        elif fail_type == SERVER_WRONG_PASSWORD:
            showerror("Ошибка входа", "Неверный пароль")
        self.client_authenticated = False

    def on_log_out(self):
        self.client_authenticated = False
        self.run_authentication_window()

    def run(self):
        self.run_authentication_window()
        self.check_queue()
        self.root.mainloop()

    def clear_root(self):
        """
        Уничтожает все элементы находящиеся в self.root (и их дочерние элементы)
        и восстанавливает настройки по умолчанию
        :return:
        """
        self.root.title(MESSENGER_NAME)
        for e in self.root.slaves():
            e.destroy()

    def check_queue(self):
        try:
            event = self.even_queue.get(block=False)
        except Empty:
            event = None
        if event:
            self.event_handler(event)
        self.root.after(self.check_interval_in_milliseconds, self.check_queue)

    def event_handler(self, event):
        event, *data = event
        if event == SERVER_AUTHENTICATION_SUCCESS:
            self.on_success_auth(data)
        elif event == SERVER_WRONG_LOGIN or event == SERVER_WRONG_PASSWORD:
            self.on_fail_auth(event)
        elif event == CLIENT_LOG_OUT or event == CLIENT_DELETE_USER:
            self.on_authentication_window()
        elif event == GUI_FRIEND_ITEM:
            self.update_friend_list(data)
        elif event == GUI_INIT_DONE:
            self.on_client_init_done()
        elif event == GUI_USER_LOG_OUT:
            self.on_log_out()
        elif event == GUI_CONNECTION_NOT_ESTABLISHED:
            self.on_connection_not_established()
        elif event == GUI_MESSAGE_ITEM:
            self.on_message_item(data)
        elif event == SERVER_USER_OFFLINE:
            self.on_user_offline()
        elif event == SERVER_USER_NOT_EXIST:
            self.on_user_not_found()
        elif event == SERVER_USER_ALREADY_EXIST:
            self.on_registration_fail()
        elif event == GUI_P2P_CONNECTION_FAIL:
            self.on_p2p_connection_fail()
        elif event == GUI_P2P_CONNECTION_DONE:
            self.on_p2p_connection_done()
        elif event == GUI_SECRET_KEY_NOT_STATED:
            self.on_secret_key_not_stated()
        elif event == WINDOW_CHANGE_MAIN_WINDOW:
            self.on_main_window(data)
        elif event == WINDOW_CHANGE_AUTHENTICATION_WINDOW:
            self.on_authentication_window()
        elif event == WINDOW_CHANGE_FRIEND_LIST_WINDOW:
            self.on_friend_list_window()
        elif event == GUI_BAD_PASSWORD_OR_LOGIN:
            self.on_bad_login()
        elif event == GUI_CLIENT_ERROR:
            self.on_client_error(data)

    def on_client_error(self, data):
        # data = ['error mes']
        if not data:
            data = ["Перезапустите приложение"]
        showerror("Ошибка", data[0])

    def on_bad_login(self):
        showerror('Некорректный ввод', 'логин и пароль должны состоять из строчных латинских букв, цифр, '
                                       'символов подчеркивания и начинаться с буквы')

    def on_secret_key_not_stated(self):
        showerror('Ошибка ключа', 'Невозможно начать секретный чат.\nСперва необходимо установить секретный ключ.')

    def on_friend_list_window(self):
        self.run_friend_list_window()

    def on_authentication_window(self):
        self.run_authentication_window()

    def on_main_window(self, data):
        # data = ['login', uid]
        self.run_main_window(data[0], data[1])

    def on_p2p_connection_done(self):
        showinfo('p2p соединение', 'p2p соединение успешно установлено')

    def on_p2p_connection_fail(self):
        showinfo('p2p соединение', 'не удалосьб утсановить p2p соединение')

    def on_registration_fail(self):
        showerror('Регистрация не удалась', "пользователь с таким логином уже существует")

    def on_user_not_found(self):
        showerror('Невозможно добавить пользователя в друзья', 'Пользователя с таким логином не существует')

    def on_user_offline(self):
        showerror('Невозможно установить p2p соединение', 'Пользователь не в сети')

    def on_message_item(self, data):
        # data = [uid, text, secret, p2p]
        uid = data[0]
        text = data[1]
        secret = data[2]
        p2p = data[3]
        if self.chat_window.selected_friend_id == uid:
            # открыт чат с нужным пользователем
            # TODO: проверять, какой чат обновляем, например если пришло секретное сообщение, а чат открыт обычный, то
            # TODO: обновлять его не нужно, а нужно поставить * на нужной кнопке
            self.chat_window.update_view(uid, secret, p2p)
        else:
            # TODO Поставить * у нужного друга в списке
            pass

    def on_connection_not_established(self):
        showerror('Ошибка p2p соединения', 'Невозможно начать p2p чат.\nСперва необходимо установить p2p соединение.')

    def on_client_init_done(self):
        self.client_init_done = True

    def update_friend_list(self, data):
        # data = ('flogin', fid)
        flogin, fid = data
        if not self.client_authenticated:
            return
        self.friend_list_window.friend_list_listbox.insert(0, f"{flogin}: {fid}")

    def on_close(self):
        if askokcancel("Выйти", "Вы действительно хотите выйти?"):
            self.clear_root()
            self.root.destroy()
            # TODO вместе с фронтендом выключать бекенд
            self.handlers[STOP_BACKEND]()  # Завершаем не только frontend, но и backend


if __name__ == '__main__':
    pass
