from tkinter import *
from tkinter.messagebox import *
from constants import *

MESSENGER_NAME = "deep low moan"

AUTHENTICATION_HANDLERS = 'auth'
MAIN_WINDOW_HANDLERS = 'main'
HANDLER_REGISTER = 'register'
HANDLER_ENTER = 'enter'


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


class GUI:

    def __init__(self, handlers=None):
        self.root = Tk()
        self.root.title(MESSENGER_NAME)
        self.handlers = handlers

        self.login_window = None
        self.main_window = None

    def prepare_authentication_window(self):

        self.clear_root()
        self.root.geometry("280x140")
        self.root.resizable(width=False, height=False)

        self.login_window = LoginWindow(self.root, handlers=self.handlers[AUTHENTICATION_HANDLERS])
        self.login_window.pack(fill=BOTH, expand=YES)

    def prepare_main_window(self):

        self.clear_root()
        self.root.geometry("600x400")
        self.root.resizable(width=True, height=True)

        self.main_window = MainWindow(self.root)
        self.main_window.pack(fill=BOTH, expand=YES)

    def on_success_auth(self):
        self.prepare_main_window()

    def on_fail_auth(self):
        pass

    def run(self):
        self.prepare_authentication_window()
        self.root.mainloop()

    def clear_root(self):
        """
        Уничтожает все элементы находящиеся в self.root (и их дочерние элементы)
        :return:
        """
        for e in self.root.slaves():
            e.destroy()


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
        self.handlers[HANDLER_REGISTER](login, password, auth_type)


class MainWindow(Frame):

    def __init__(self, master=None, **kwargs):
        super().__init__(master, kwargs)

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

        self.message_entry = EntryWithTemplateString(self.message_frame, templatestring='Введите сообщение:')
        self.message_entry.pack(side=LEFT, fill=BOTH, expand=YES)

        self.send_button = PixelSizedButton(self.message_frame, text='отослать')
        self.send_button.pack(side=RIGHT)
        # ----------------------------- ввод сообщения

    def set_handlers(self):
        pass


if __name__ == '__main__':
    a = {HANDLER_ENTER: None, HANDLER_REGISTER: None}
    a = GUI(a)
    a.run()
