import socket
import enum


class sockType(enum.Enum):
    SERVER = enum.auto()
    CLIENT = enum.auto()


class Connection:
    def __init__(self, ip, port, connType):
        self.sock = None
        self.conn = None
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

    def receive(self):

        def processFile(msg):
            nonlocal self
            size = int(msg)
            print("Received filesize", size, "Sending OK message...")
            self.conn.sendall("OK".encode("utf-8"))

            file = bytearray()
            while True:
                request = self.conn.recv(104857600)
                if not request:
                    print("Error, incomplete file")
                    return
                file = file + request
                print("Received", len(file), "bytes...")
                if len(file) == size:
                    break
            return file

        message = self.conn.recv(4096).decode("utf-8").split(" ", 1)
        if "FILE" == message[0]:
            return processFile(message[1])
        elif "NOTIF" == message[0]:
            print("[Message received]", message[1])
            return

    def send(self, data, isMessage=False):
        if not isMessage:
            self.conn.sendall("FILE {}".format(len(data)).encode("utf-8"))
            response = self.conn.recv(1024)
            if response.decode("utf-8") != "OK":
                print("Error, confirmation not received, got", response, "instead")
                return False
        self.conn.sendall(data)
        return True

    def close(self):
        if self.sock:
            self.sock.close()
        else:
            self.conn.close()
