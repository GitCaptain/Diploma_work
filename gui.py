from tkinter import *
from tkinter.ttk import *

MESSENGER_NAME = "deep low moan"
REGISTRATION_TYPE = 0
ENTER_TYPE = 1


class StartWindow(Frame):

    def __init__(self, master=None):
        super().__init__(master)
        self.init_window()
        self.master = master

    def init_window(self):
        registration_button = Button(text="Регистрация", command=self.registration)
        registration_button.pack()

        enter_button = Button(text="Вход", command=self.enter)
        enter_button.pack()

    def registration(self):
        AuthenticationWindow(self.master, REGISTRATION_TYPE)

    def enter(self):
        AuthenticationWindow(self.master, ENTER_TYPE)


class AuthenticationWindow(Toplevel):

    def __init__(self, master, type):
        super().__init__(master)
        self.init_window()
        if type == REGISTRATION_TYPE:
            self.target = "Регистрация"
        elif type == ENTER_TYPE:
            self.target = "Вход"

    def init_window(self):
        self.title(self.target)
        self.resizable(False, False)
        self.focus_get()
        self.grab_set()


class MainWindow(Frame):

    def __init__(self, master=None):
        super().__init__(master)
        self.init_window()

    def init_window(self):
        pass


def main():
    root = Tk()
    root.title(MESSENGER_NAME)
    root.geometry("300x400")
    root.resizable(False, False)
    gui = StartWindow(master=root)
    gui.pack()
    gui.mainloop()


if __name__ == '__main__':
    main()
