from tkinter import *

MESSENGER_NAME = "deep low moan"

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
        Button.__init__(self, master, image=self.img, compound=CENTER, **kwargs)


class PixelSizedLabel(Label):
    """
    Метка, размеры которой можно задать в пикселях
    """
    def __init__(self, master=None, **kwargs):
        if 'image' in kwargs:
            self.img = kwargs['image']
        else:
            self.img = PhotoImage()
        Label.__init__(self, master, image=self.img, compound=CENTER, **kwargs)


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

        Frame.__init__(self, master, kwargs)

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


class EntryWithTemplateString(Entry):

    def __init__(self, master=None, **kwargs):

        if TEMPLATE_STRING in kwargs:
            self.template = kwargs.pop(TEMPLATE_STRING)
        else:
            self.template = ''

        Entry.__init__(self, master, kwargs)
        self.template_stated = False
        self.insert_template_string()

        self.bind('<Key>', self.delete_template_string)
        self.bind('<Button-1>', self.delete_template_string)
        self.bind('<FocusOut>', self.insert_template_string)
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
        self.insert_template_string()
        return res


class GUI:

    def __init__(self, handlers=None):
        self.root = Tk()
        self.root.title(MESSENGER_NAME)
        self.handlers = handlers

    def prepare_authentication_window(self):

        self.clear_root()
        self.root.geometry("280x140")
        self.root.resizable(width=False, height=False)

        auth_window = Frame(self.root)
        auth_window.pack(expand=YES, fill=BOTH)

        entry_width = 100
        button_width = 100
        button_height = 40
        login_var = StringVar()
        login_entry = Entry(auth_window, width=entry_width)
        login_entry.config(textvariable=login_var)
        login_entry.pack(side=TOP, expand=YES)

        password_var = StringVar()
        password_entry = Entry(auth_window, width=entry_width)
        password_entry.config(textvariable=password_var)
        password_entry.pack(side=TOP, expand=YES)

        register_button = PixelSizedButton(auth_window, width=button_width, height=button_height)
        #register_button.config(text="Регистрация", command=(lambda: self.handlers[REGISTER](login_var, password_var)))
        register_button.config(command=(lambda: self.on_success_auth()))
        register_button.pack(side=TOP, expand=YES)

        enter_button = PixelSizedButton(auth_window, width=button_width, height=button_height)
        enter_button.config(text="Вход", command=(lambda: self.handlers[HANDLER_ENTER](login_var, password_var)))
        enter_button.pack(side=TOP, expand=YES)

    def on_success_auth(self):
        self.prepare_main_window()

    def on_fail_auth(self):
        pass

    def prepare_main_window(self):

        self.clear_root()
        self.root.geometry("600x400")
        self.root.resizable(width=True, height=True)

        # ----------------------------- верхняя полоска settings
        settings_frame_height = 20
        settings_frame = Frame(self.root, height=settings_frame_height)
        settings_frame.pack(side=TOP, fill=X, anchor=N)

        settings_button_width = 100
        settings_entry_width = 20
        padx = 5

        filler = PixelSizedLabel(settings_frame, width=14)
        filler.pack(side=LEFT, fill=Y)

        add_var = StringVar()
        add_entry = EntryWithTemplateString(settings_frame, textvariable=add_var, width=settings_entry_width,
                                            templatestring='логин: ')
        add_entry.pack(side=LEFT, fill=Y)

        add_button = PixelSizedButton(settings_frame, width=settings_button_width, text='Добавить друга')
        add_button.pack(side=LEFT, fill=Y, padx=padx)

        exit_button = PixelSizedButton(settings_frame, width=settings_button_width, text='Выйти из аккаунта')
        exit_button.pack(side=RIGHT, fill=Y)

        delete_button = PixelSizedButton(settings_frame, width=settings_button_width, text='Удалить аккаунт')
        delete_button.pack(side=RIGHT, fill=Y, padx=padx)
        # ----------------------------- верхняя полоска settings

        # ----------------------------- основной frame
        main_frame = Frame(self.root)
        main_frame.pack(side=TOP, fill=BOTH, expand=YES, anchor=N)
        # ----------------------------- основной frame

        # ----------------------------- Frame со списком друзей
        friend_list_width = 40
        friend_list = FrameWithScrolledListBox(main_frame, scrollbarside=LEFT, listboxside=RIGHT,
                                               width=friend_list_width)
        friend_list.pack(side=LEFT, fill=Y)
        # ----------------------------- Frame со списком друзей

        # ----------------------------- Frame все связанное с чатом
        chat_frame = Frame(main_frame)
        chat_frame.pack(side=RIGHT, fill=BOTH, expand=YES)
        # ----------------------------- Frame все связанное с чатом

        # ----------------------------- метка чата с пользователем
        label_friend_name = Label(chat_frame, text="чат с: ", anchor=W)
        label_friend_name.pack(side=TOP, fill=X)
        # ----------------------------- метка чата с пользователем

        # ----------------------------- выбор чата
        chat_type_select_frame = Frame(chat_frame)
        chat_type_select_frame.pack(side=TOP, fill=X)

        chat_button = PixelSizedButton(chat_type_select_frame, text="сообщения")
        chat_button.pack(side=LEFT, fill=Y)

        secret_chat_button = PixelSizedButton(chat_type_select_frame, text="секретные сообщения")
        secret_chat_button.pack(side=LEFT, fill=Y)

        p2p_chat_button = PixelSizedButton(chat_type_select_frame, text="p2p сообщения")
        p2p_chat_button.pack(side=LEFT, fill=Y)

        secret_p2p_chat_button = PixelSizedButton(chat_type_select_frame, text="секретные p2p сообщения")
        secret_p2p_chat_button.pack(side=LEFT, fill=Y)
        # ----------------------------- выбор чата

        # ----------------------------- окно чата
        dialog_frame = FrameWithScrolledListBox(chat_frame, scrollbarside=RIGHT, listboxside=LEFT)
        dialog_frame.pack(side=TOP, fill=BOTH, expand=YES)
        # ----------------------------- окно чата

        # ----------------------------- ввод сообщения
        message_frame_height = 20
        message_frame = Frame(chat_frame, height=message_frame_height)
        message_frame.pack(side=BOTTOM, fill=X)

        message_entry = EntryWithTemplateString(message_frame, templatestring='Введите сообщение:')
        message_entry.pack(side=LEFT, fill=BOTH, expand=YES)

        send_button = PixelSizedButton(message_frame, text='отослать')
        send_button.pack(side=RIGHT)
        # ----------------------------- ввод сообщения

    def run(self):
        self.root.mainloop()

    def clear_root(self):
        """
        Уничтожает все элементы находящиеся в self.root (и их дочерние элементы)
        :return:
        """
        for e in self.root.slaves():
            e.destroy()


if __name__ == '__main__':
    a = {HANDLER_ENTER: None, HANDLER_REGISTER: None}
    a = GUI(a)
    a.prepare_main_window()
    a.run()
