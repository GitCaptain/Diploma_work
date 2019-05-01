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


SCROLLBAR_SIDE = 'scrollbarside'
LISTBOX_SIDE = 'listboxside'


class ScrolledListBox:
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

        if not scrollbar:
            self.scrollbar = Scrollbar(master)
        else:
            self.scrollbar = scrollbar

        if not listbox:
            self.listbox = Listbox(master)
        else:
            self.listbox = listbox

        self.scrollbar.config(command=self.listbox.yview)
        self.listbox.config(yscrollcommand=self.scrollbar.set)

    def _pack(self):
        self.scrollbar.pack(side=self.sbside, fill=Y, expand=YES)
        self.listbox.pack(side=self.lbside, fill=BOTH, expand=YES)

    def __getattr__(self, item):
        if item == 'pack':
            return self._pack
        else:
            return getattr(self.scrollbar, item)



"""
class FrameWithScrolledListBox(Frame):

    def __init__(self, master=None, **kwargs):
        Frame.__init__(self, master, kwargs)

        self.scrollbar = Scrollbar(self)
        self.listbox = Listbox(self)

        self.scrollbar.config(command=self.listbox.yview)
        self.listbox.config(yscrollcommand=self.scrollbar.set)

        if SCROLLBAR_SIDE not in kwargs:
            sbside = LEFT
        else:
            sbside = kwargs[SCROLLBAR_SIDE]

        if LISTBOX_SIDE not in kwargs:
            lbside = RIGHT
        else:
            lbside = kwargs[LISTBOX_SIDE]

        self.scrollbar.pack(side=sbside, fill=Y, expand=YES)
        self.listbox.pack(side=lbside, fill=X, expand=YES)

    def add_listbox_element(self):
        pass
"""


class GUI:

    def __init__(self, handlers=None):
        self.root = Tk()
        self.root.title(MESSENGER_NAME)
        self.handlers = handlers

    def prepare_authentication_window(self):
        self.root.geometry("280x140")
        self.root.resizable(width=False, height=False)

        auth_window = Frame(self.root)
        auth_window.pack(expand=YES, fill=BOTH)

        login_var = StringVar()
        login_entry = Entry(auth_window, width=100)
        login_entry.config(textvariable=login_var)
        login_entry.pack(side=TOP, expand=YES)

        password_var = StringVar()
        password_entry = Entry(auth_window, width=100)
        password_entry.config(textvariable=password_var)
        password_entry.pack(side=TOP, expand=YES)

        register_button = PixelSizedButton(auth_window, width=100, height=40)
        #register_button.config(text="Регистрация", command=(lambda: self.handlers[REGISTER](login_var, password_var)))
        register_button.config(command=(lambda: self.on_success_auth()))
        register_button.pack(side=TOP, expand=YES)

        enter_button = PixelSizedButton(auth_window, width=100, height=40)
        enter_button.config(text="Вход", command=(lambda: self.handlers[HANDLER_ENTER](login_var, password_var)))
        enter_button.pack(side=TOP, expand=YES)

    def on_success_auth(self):
        self.clear_root()
        self.prepare_main_window()

    def on_fail_auth(self):
        pass

    def prepare_main_window(self):
        self.root.geometry("800x600")

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
    b = ScrolledListBox()
    b.pack()
    b.mainloop()
    a = {HANDLER_ENTER: None, HANDLER_REGISTER: None}
    a = GUI(a)
    a.prepare_authentication_window()
    a.run()
