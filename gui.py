from tkinter import *
from tkinter.messagebox import *
from constants import *
from queue import Queue, Empty
from sys import exit

MESSENGER_NAME = "deep low moan"

AUTHENTICATION_HANDLERS = 0
MAIN_WINDOW_HANDLERS = 1

HANDLER_REGISTER_BUTTON = 'register'
HANDLER_ENTER_BUTTON = 'enter'
HANDLER_GET_FRIENDS = 'get friends'
HANDLER_ADD_FRIEND = 'add friend'
HANDLER_LOG_OUT = 'log out'
HANDLER_DELETE_USER = 'delete user'
HANDLER_GET_MESSAGE = 'get message'
HANDLER_SEND_MESSAGE = 'send message'
HANDLER_P2P_CONNECTION = 'p2p'


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


class FrameWithScrolledListBox(Frame):
    """
    Список элементов со встроенной полосой прокрутки
    """

    SCROLLBAR_SIDE = 'scrollbarside'
    LISTBOX_SIDE = 'listboxside'

    def __init__(self, master=None, scrollbar=None, listbox=None, **kwargs):

        if self.SCROLLBAR_SIDE in kwargs:
            self.sbside = kwargs.pop(self.SCROLLBAR_SIDE)
        else:
            self.sbside = LEFT

        if self.LISTBOX_SIDE in kwargs:
            self.lbside = kwargs.pop(self.LISTBOX_SIDE)
        else:
            self.lbside = RIGHT

        super().__init__(master, kwargs)

        if not scrollbar:
            self.scrollbar = Scrollbar(self)
        else:
            self.scrollbar = scrollbar

        if not listbox:
            self.listbox = Listbox(self)
        else:
            self.listbox = listbox

        self.scrollbar.config(command=self.listbox.yview)
        self.listbox.config(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side=self.sbside, fill=Y, expand=NO)
        self.listbox.pack(side=self.lbside, fill=BOTH, expand=YES)


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


class MainWindow(Frame):

    SELECTED_CHAT = 1
    SELECTED_SECRET_CHAT = 2
    SELECTED_P2P_CHAT = 3
    SELECTED_SECRET_P2P_CHAT = 4

    BUTTON_NAME_CHAT = "сообщения"
    BUTTON_NAME_SECRET_CHAT = "секретные сообщения"
    BUTTON_NAME_P2P_CHAT = "p2p сообщения"
    BUTTON_NAME_SECRET_P2P_CHAT = "секретные p2p сообщения"

    def __init__(self, master=None, handlers=None, **kwargs):
        super().__init__(master, kwargs)
        self.handlers = handlers
        self.master = master
        self.chat_selected = None
        self.selected_friend = -1
        # ----------------------------- верхняя полоска settings
        settings_frame_height = 20
        self.settings_frame = Frame(self, height=settings_frame_height)
        self.settings_frame.pack(side=TOP, fill=X, anchor=N)

        settings_button_width = 100
        settings_entry_width = 20
        padx = 5

        self.filler = PixelSizedLabel(self.settings_frame, width=14)
        self.filler.pack(side=LEFT, fill=Y)

        self.add_var = StringVar()
        self.add_entry = EntryWithTemplateString(self.settings_frame, textvariable=self.add_var,
                                                 width=settings_entry_width,
                                                 templatestring='логин: ')
        self.add_entry.pack(side=LEFT, fill=Y)

        self.add_button = PixelSizedButton(self.settings_frame, width=settings_button_width, text='Добавить друга')
        self.add_button.pack(side=LEFT, fill=Y, padx=padx)

        self.exit_button = PixelSizedButton(self.settings_frame, width=settings_button_width, text='Выйти из аккаунта')
        self.exit_button.pack(side=RIGHT, fill=Y)

        self.delete_button = PixelSizedButton(self.settings_frame, width=settings_button_width, text='Удалить аккаунт')
        self.delete_button.pack(side=RIGHT, fill=Y, padx=padx)
        # ----------------------------- верхняя полоска settings

        # ----------------------------- основной frame
        self.main_frame = Frame(self)
        self.main_frame.pack(side=TOP, fill=BOTH, expand=YES, anchor=N)
        # ----------------------------- основной frame

        # ----------------------------- Frame со списком друзей
        friend_list_width = 40
        self.friend_list = FrameWithScrolledListBox(self.main_frame, scrollbarside=LEFT, listboxside=RIGHT,
                                                    width=friend_list_width)
        self.friend_list.pack(side=LEFT, fill=Y)
        # ----------------------------- Frame со списком друзей

        # ----------------------------- Frame все связанное с чатом
        self.chat_frame = Frame(self.main_frame)
        self.chat_frame.pack(side=RIGHT, fill=BOTH, expand=YES)
        # ----------------------------- Frame все связанное с чатом

        # ----------------------------- метка чата с пользователем
        self.label_friend_name = Label(self.chat_frame, text="чат с: ", anchor=W)
        self.label_friend_name.pack(side=TOP, fill=X)
        # ----------------------------- метка чата с пользователем

        # ----------------------------- выбор чата
        self.chat_type_select_frame = Frame(self.chat_frame)
        self.chat_type_select_frame.pack(side=TOP, fill=X)

        self.chat_button = PixelSizedButton(self.chat_type_select_frame, text=self.BUTTON_NAME_CHAT)
        self.chat_button.pack(side=LEFT, fill=Y)

        self.secret_chat_button = PixelSizedButton(self.chat_type_select_frame, text=self.BUTTON_NAME_SECRET_CHAT)
        self.secret_chat_button.pack(side=LEFT, fill=Y)

        self.p2p_chat_button = PixelSizedButton(self.chat_type_select_frame, text=self.BUTTON_NAME_P2P_CHAT)
        self.p2p_chat_button.pack(side=LEFT, fill=Y)

        self.secret_p2p_chat_button = PixelSizedButton(self.chat_type_select_frame,
                                                       text=self.BUTTON_NAME_SECRET_P2P_CHAT)
        self.secret_p2p_chat_button.pack(side=LEFT, fill=Y)
        # ----------------------------- выбор чата

        # ----------------------------- окно чата
        self.dialog_frame = FrameWithScrolledListBox(self.chat_frame, scrollbarside=RIGHT, listboxside=LEFT)
        self.dialog_frame.pack(side=TOP, fill=BOTH, expand=YES)
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

        self.set_handlers()

    def set_handlers(self):
        self.add_entry.bind('<Return>', self.add_friend)
        self.add_button.config(command=self.add_friend)

        self.delete_button.config(command=self.delete_user)
        self.exit_button.config(command=self.log_out)

        self.friend_list.listbox.bind('<Double-Button-1>', self.update_chosen_friend_and_show_chat)
        self.friend_list.listbox.bind('<Button-1>', self.update_chosen_friend_and_show_chat)
        self.friend_list.listbox.bind('<Return>', self.update_chosen_friend_and_show_chat)
        self.friend_list.listbox.bind('<FocusIn>', self.update_chosen_friend_and_show_chat)

        self.chat_button.config(command=self.show_chat)
        self.secret_chat_button.config(command=self.show_secret_chat)
        self.p2p_chat_button.config(command=self.show_p2p_chat)
        self.secret_p2p_chat_button.config(command=self.show_secret_p2p_chat)

        self.message_entry.bind('<Return>', self.send_message)
        self.send_button.config(command=self.send_message)

    def update_chosen_friend_and_show_chat(self, *args):

        #self.selected_friend = self.friend_list.listbox.curselection()[0]
        self.selected_friend = self.friend_list.listbox.curselection()
        if self.selected_friend:
            self.selected_friend = self.selected_friend[0]
        self.show_chat()

    def send_message(self, *args):
        selected = self.get_friend(self.selected_friend)
        message = self.message_var.get()
        if not message or selected[1] < 0 or not self.chat_selected or self.message_entry.template_stated:
            return
        login, uid = selected
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
        self.handlers[HANDLER_SEND_MESSAGE](message, uid, p2p, secret)

    def get_friend(self, index):
        friend = self.friend_list.listbox.get(index).split(':')
        if friend:
            login, uid = friend
            uid = int(uid)
            return login, uid
        return '', -1

    def get_selected_friend(self):
        return self.get_friend(self.selected_friend)

    def show_chat(self):
        selected = self.get_selected_friend()
        if selected[1] < 0:
            return
        self.chat_selected = self.SELECTED_CHAT
        login, uid = selected
        self.label_friend_name.config(text=f"чат с {login}")
        self.chat_button.config(text=self.BUTTON_NAME_CHAT)
        self.update_view(uid, False, False)

    def show_secret_chat(self):
        selected = self.get_selected_friend()
        if selected[1] < 0:
            return
        self.chat_selected = self.SELECTED_SECRET_CHAT
        login, uid = selected
        self.label_friend_name.config(text=f"секретный чат с {login}")
        self.secret_chat_button.config(text=self.BUTTON_NAME_SECRET_CHAT)
        self.update_view(uid, True, False)

    def show_p2p_chat(self):
        selected = self.get_selected_friend()
        if selected[1] < 0:
            return
        self.chat_selected = self.SELECTED_P2P_CHAT
        login, uid = selected
        self.label_friend_name.config(text=f"p2p чат с {login}")
        self.p2p_chat_button.config(text=self.BUTTON_NAME_P2P_CHAT)
        self.update_view(uid, False, True)

    def show_secret_p2p_chat(self):
        selected = self.get_selected_friend()
        if selected[1] < 0:
            return
        login, uid = selected
        self.chat_selected = self.SELECTED_SECRET_P2P_CHAT
        self.label_friend_name.config(text=f"секретный p2p чат с {login}")
        self.secret_p2p_chat_button.config(text=self.BUTTON_NAME_SECRET_P2P_CHAT)
        self.update_view(uid, True, True)

    def insert_message(self, text, is_sender):
        if is_sender:
            text = f"Отправлено: {text}"
        else:
            text = f"Принято: {text}"
        self.dialog_frame.listbox.insert(END, text)
        self.dialog_frame.listbox.see(END)

    def update_view(self, uid, secret, p2p):
        self.selected_friend = uid
        self.dialog_frame.listbox.delete(0, END)
        for message in self.handlers[HANDLER_GET_MESSAGE](uid, secret, p2p):
            self.insert_message(message.message, message.is_sender)
        self.dialog_frame.listbox.see(END)

    def log_out(self):
        self.handlers[HANDLER_LOG_OUT]()

    def delete_user(self):
        self.handlers[HANDLER_DELETE_USER]()

    def add_friend(self, *args):
        login = self.add_var.get()
        if login and not self.add_entry.template_stated:
            self.handlers[HANDLER_ADD_FRIEND](login)

    def update_friend_list(self):
        friend_generator = self.handlers[HANDLER_GET_FRIENDS]()
        for friend in friend_generator:
            self.add_item_into_friend_list(friend)

    def add_item_into_friend_list(self, friend_item):
        flogin, fid = friend_item
        if fid != SERVER_ID:
            self.friend_list.listbox.insert(0, f"{flogin}: {fid}")


class GUI:

    def __init__(self, handlers=None, event_queue=None):
        self.root = Tk()
        self.root.title(MESSENGER_NAME)
        self.handlers = handlers
        self.check_interval_in_milliseconds = 10

        self.client_authenticated = False
        self.client_init_done = False
        self.even_queue = event_queue
        self.login_window = None
        self.main_window = None

    def run_authentication_window(self):

        self.clear_root()
        self.root.geometry("280x140")
        self.root.resizable(width=False, height=False)

        self.login_window = LoginWindow(self.root, handlers=self.handlers[AUTHENTICATION_HANDLERS])
        self.login_window.pack(fill=BOTH, expand=YES)

    def run_main_window(self):

        self.clear_root()
        self.root.geometry("600x400")
        self.root.resizable(width=True, height=True)

        self.main_window = MainWindow(self.root, handlers=self.handlers[MAIN_WINDOW_HANDLERS])
        self.main_window.pack(fill=BOTH, expand=YES)
        self.main_window.update_friend_list()

    def on_success_auth(self):
        self.client_authenticated = True
        self.run_main_window()

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
        :return:
        """
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
            self.run_main_window()
        elif event == SERVER_WRONG_LOGIN or event == SERVER_WRONG_PASSWORD:
            self.on_fail_auth(event)
        elif event == CLIENT_LOG_OUT or event == CLIENT_DELETE_USER:
            self.run_authentication_window()
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
        if self.main_window.get_selected_friend[1] == uid:
            # открыт чат с нужным пользователем
            # TODO: проверять, какой чат обновляем, например если пришло секретное сообщение, а чат открыт обычный, то
            # обновлять его не нужно
            self.main_window.update_view(uid, secret, p2p)
        else:
            # TODO Поставить * у нужного друга в списке
            pass

    def on_connection_not_established(self):
        if askyesno('Соединение не установлено',
                    'Для начала общения p2p нужно установить соединение.\nУстановить соединение?'):
            login, uid = self.main_window.get_selected_friend()
            if uid < 0:
                return
            self.handlers[MAIN_WINDOW_HANDLERS][HANDLER_P2P_CONNECTION](uid, True)

    def on_client_init_done(self):
        self.client_init_done = True

    def update_friend_list(self, data):
        # data = ('flogin', fid)
        flogin, fid = data
        if not self.client_authenticated:
            return
        self.main_window.friend_list.insert(f"{flogin}: {fid}")

    def on_close(self):
        if askokcancel("Выйти", "Вы действительно хотите выйти?"):
            self.clear_root()
            self.root.destroy()
            exit(0)  # Завершаем не только frontend, но и backend


if __name__ == '__main__':
    pass
