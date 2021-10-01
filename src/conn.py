import os
import socket
from enum import Enum, auto


class sockType(Enum):
    SERVER = auto()
    CLIENT = auto()


class transferType(Enum):
    FILE = auto()
    FILESTART = auto()
    NOTIF = auto()
    PING = auto()
    END = auto()
    ERROR = auto()


class Connection:
    def __init__(self, ip, port, connType):
        self.sock = None
        self.conn = None
        self.fileTransfer = False
        if connType == sockType.CLIENT:
            self.connect(ip, port)
        else:
            self.listen(ip, port)

    def connect(self, ip, port):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((ip, port))

    def listen(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((ip, port))
        self.sock.listen(1)
        self.conn, _ = self.sock.accept()

    def receiveWrapper(self):
        data = self.conn.recv(2 ** 28)
        print("Received data of size", len(data))
        self.conn.sendall("OK".encode("utf-8"))
        return data

    def receive(self):
        try:
            message = self.receiveWrapper()
            if not self.fileTransfer:
                message = message.decode("utf-8").split(" ")
                if transferType.FILE.name == message[0]:
                    filename = message[1]
                    size = int(message[2])
                    self.fileTransfer = True
                    print("Incoming file!!")
                    symKey = self.receiveWrapper()
                    print("Received symkey")
                    return (filename, symKey, size), transferType.FILESTART
                elif transferType.NOTIF.name == message[0]:
                    print("[Message received]", message[1])
                    return None, transferType.NOTIF
            else:
                try:
                    message = message.decode('utf-8')
                    if message == "END":
                        print("End of file reached")
                        self.fileTransfer = False
                        message = self.receiveWrapper()
                        return (message, True), transferType.FILE
                except UnicodeError:
                    print("File snippet received")
                    return (message, False), transferType.FILE
            return None, transferType.ERROR
        except ConnectionAbortedError:
            return None, transferType.END

    def sendWrapper(self, data):
        print("Sending", len(data), "bytes...")
        self.conn.sendall(data)
        response = self.conn.recv(1024)
        if response.decode("utf-8") != "OK":
            print("Error, confirmation not received, got", response, "instead")
            return False
        print("Data sent and received correctly")
        return True

    def sendStartFile(self, filename, size, symKey):
        if not self.sendWrapper("FILE {} {}".format(filename, size).encode("utf-8")):
            return False
        if not self.sendWrapper(symKey):
            return False
        return True

    def send(self, data):
        if not self.sendWrapper(data):
            return False
        return True

    def sendEndFile(self, signature):
        print("End of file")
        if not self.sendWrapper("END".encode("utf-8")):
            return False
        if not self.sendWrapper(signature):
            return False
        return True

    def close(self):
        if self.sock:
            self.sock.close()
        else:
            self.conn.close()
