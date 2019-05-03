from tkinter import *
from tkinter.messagebox import *
from constants import *
from queue import Queue, Empty
from sys import exit
from common_functions_and_data_structures import get_text_from_bytes_data

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


SCROLLBAR_SIDE = 'scrollbarside'
LISTBOX_SIDE = 'listboxside'


class FrameWithScrolledListBox(Frame):
    """
    Список элементов со встроенной полосой прокрутки
    """
    def __init__(self, master=None, scrollbar=None, listbox=None, **kwargs):

        if SCROLLBAR_SIDE in kwargs:
            self.sbside = kwargs.pop(SCROLLBAR_SIDE)
        else:
            self.sbside = LEFT

        if LISTBOX_SIDE in kwargs:
            self.lbside = kwargs.pop(LISTBOX_SIDE)
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


TEMPLATE_STRING = 'templatestring'
CLEAR_ON_RETURN = 'clearonreturn'


class EntryWithTemplateString(Entry):

    def __init__(self, master=None, **kwargs):

        if TEMPLATE_STRING in kwargs:
            self.template = kwargs.pop(TEMPLATE_STRING)
        else:
            self.template = ''

        if CLEAR_ON_RETURN in kwargs:
            self.clear_on_ret = kwargs.pop(CLEAR_ON_RETURN)
        else:
            self.clear_on_ret = False

        super().__init__(master, kwargs)
        self.template_stated = False
        self.insert_template_string()

        self.bind('<Key>', self.delete_template_string)
        self.bind('<Button-1>', self.delete_template_string)
        self.bind('<Return>', self._get)

    def delete_template_string(self, *arg):
        if self.template_stated:
            self.delete(0, END)
            self.config(fg='black')
            self.template_stated = False

    def insert_template_string(self, *arg):
        self.delete(0, END)
        self.config(fg='grey')
        self.insert(0, self.template)
        self.template_stated = True

    def _get(self, *arg):
        res = self.get()
        if self.clear_on_ret:
            self.insert_template_string()
        return res


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
        self.login_entry = EntryWithTemplateString(self.auth_window, width=entry_width, **{TEMPLATE_STRING: 'логин:'})
        self.login_entry.config(textvariable=self.login_var)
        self.login_entry.pack(side=TOP, expand=YES)

        self.password_var = StringVar()
        self.password_entry = EntryWithTemplateString(self.auth_window, width=entry_width,
                                                      **{TEMPLATE_STRING: 'пароль:'})
        self.password_entry.config(textvariable=self.password_var)
        self.password_entry.pack(side=TOP, expand=YES)

        self.register_button = PixelSizedButton(self.auth_window, width=button_width, height=button_height,
                                                text='Регистрация')
        self.register_button.pack(side=TOP, expand=YES)

        self.enter_button = PixelSizedButton(self.auth_window, width=button_width, height=button_height, text='Вход')
        self.enter_button.pack(side=TOP, expand=YES)
        self.set_handlers()

    def set_handlers(self):
        self.register_button.config(command=(lambda: self.get_registration_data(REGISTER_USER)))
        self.enter_button.config(command=(lambda: self.get_registration_data(LOG_IN)))

    def get_registration_data(self, auth_type):
        password = self.password_var.get()
        login = self.login_var.get()
        if not password or not login:
            showerror('Некорректный ввод', 'Заполните все поля')
            return
        self.handlers[HANDLER_REGISTER_BUTTON](login, password, auth_type)


CHAT_SELECTED = 0
SECRET_CHAT_SELECTED = 1
P2P_CHAT_SELECTED = 2
SECRET_P2P_CHAT_SELECTED = 3


class MainWindow(Frame):

    def __init__(self, master=None, handlers=None, **kwargs):
        super().__init__(master, kwargs)
        self.handlers = handlers
        self.master = master
        self.chat_selected = None
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

        self.chat_button = PixelSizedButton(self.chat_type_select_frame, text="сообщения")
        self.chat_button.pack(side=LEFT, fill=Y)

        self.secret_chat_button = PixelSizedButton(self.chat_type_select_frame, text="секретные сообщения")
        self.secret_chat_button.pack(side=LEFT, fill=Y)

        self.p2p_chat_button = PixelSizedButton(self.chat_type_select_frame, text="p2p сообщения")
        self.p2p_chat_button.pack(side=LEFT, fill=Y)

        self.secret_p2p_chat_button = PixelSizedButton(self.chat_type_select_frame, text="секретные p2p сообщения")
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
                                                     textvariable=self.message_var)
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

        self.friend_list.listbox.bind('<Button-1>', self.show_chat)
        self.friend_list.listbox.bind('<Return>', self.show_chat)

        self.chat_button.config(command=self.show_chat)
        self.secret_chat_button.config(command=self.show_secret_chat)
        self.p2p_chat_button.config(command=self.show_p2p_chat)
        self.secret_p2p_chat_button.config(command=self.show_secret_p2p_chat)

        self.message_entry.bind('<Return>', self.send_message)
        self.send_button.config(command=self.send_message)

    def send_message(self, *args):
        selected = self.get_selected_friend()
        message = self.message_var.get()
        if not message or selected[1] < 0 or not self.chat_selected:
            return
        login, uid = selected
        if self.chat_selected == CHAT_SELECTED:
            secret = False
            p2p = False
        elif self.chat_selected == SECRET_CHAT_SELECTED:
            secret = True
            p2p = False
        elif self.chat_selected == P2P_CHAT_SELECTED:
            secret = False
            p2p = True
        elif self.chat_selected == SECRET_P2P_CHAT_SELECTED:
            secret = True
            p2p = True

        self.handlers[HANDLER_SEND_MESSAGE](uid, secret, p2p)

    def get_selected_friend(self):
        index = self.friend_list.listbox.curselection()
        if not index:
            return ('', -1)
        login, uid = self.friend_list.listbox.get(index).split(':')
        uid = int(uid)
        return login, uid

    def show_chat(self, *args):
        selected = self.get_selected_friend()
        if selected[1] < 0:
            return
        self.chat_selected = CHAT_SELECTED
        login, uid = selected
        self.label_friend_name.config(text=f"чат с {login}")
        self.update_view(uid, False, False)

    def show_secret_chat(self):
        selected = self.get_selected_friend()
        if selected[1] < 0:
            return
        self.chat_selected = SECRET_CHAT_SELECTED
        login, uid = selected
        self.label_friend_name.config(text=f"секретный чат с {login}")
        self.update_view(uid, True, False)

    def show_p2p_chat(self):
        selected = self.get_selected_friend()
        if selected[1] < 0:
            return
        self.chat_selected = P2P_CHAT_SELECTED
        login, uid = selected
        self.label_friend_name.config(text=f"p2p чат с {login}")
        self.update_view(uid, False, True)

    def show_secret_p2p_chat(self):
        selected = self.get_selected_friend()
        if selected[1] < 0:
            return
        login, uid = selected
        self.chat_selected = SECRET_P2P_CHAT_SELECTED
        self.label_friend_name.config(text=f"секретный p2p чат с {login}")
        self.update_view(uid, True, True)

    def update_view(self, uid, secret, p2p):
        self.dialog_frame.listbox.delete(0, END)
        for message in self.handlers[HANDLER_GET_MESSAGE](uid, secret, p2p):
            if message.is_sender:
                text = f"Отправлено: {message.message}"
            else:
                text = f"Принято: {message.message}"
            self.dialog_frame.listbox.insert(END, text)

    def log_out(self):
        self.handlers[HANDLER_LOG_OUT]()

    def delete_user(self):
        self.handlers[HANDLER_DELETE_USER]()

    def add_friend(self, *args):
        login = self.add_var.get()
        if login:
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
        # TODO выключать бекенд вместе с фронтендом
        # self.root.protocol("WM_DELETE_WINDOW", self.on_close)

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
        if fail_type == WRONG_LOGIN:
            showerror("Ошибка входа", "Пользователя с таким логином не существует")
        elif fail_type == WRONG_PASSWORD:
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
        if event == AUTHENTICATION_SUCCESS:
            self.run_main_window()
        elif event == WRONG_LOGIN or event == WRONG_PASSWORD:
            self.on_fail_auth(event)
        elif event == LOG_OUT or event == DELETE_USER:
            self.run_authentication_window()
        elif event == FRIEND_ITEM:
            self.update_friend_list(data)
        elif event == INIT_DONE:
            self.on_client_init_done()

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
    a = {HANDLER_ENTER_BUTTON: None, HANDLER_REGISTER_BUTTON: None}
    a = GUI(a)
    a.run()
