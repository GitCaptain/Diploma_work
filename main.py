import gui
import client


if __name__ == '__main__':
    server_address = ""

    user = client.Client(server_address)
    interface = gui.GUI()
    user.run()
    interface.run()
