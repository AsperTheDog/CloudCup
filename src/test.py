from crypto import CrModule
from os.path import join, exists
import os
from conn import Connection, sockType
import sys

testDirs = {"root": "TestObjects", "input": "In", "output": "Out", "cr": "Crypt"}


def cryptoTest():
    test = CrModule()

    if exists(join("Keys", "pass.bin")):
        test.auth("pwd")
    else:
        test.reg("pwd")

    with open(join(join(testDirs['root'], testDirs['input']), "test.gif"), "rb") as origFile:
        with open(join(join(testDirs['root'], testDirs['cr']), "test.bin"), "wb") as destFile:
            destFile.write(test.encrypt(origFile.read()))

    with open(join(join(testDirs['root'], testDirs['cr']), "test.bin"), "rb") as origFile:
        with open(join(join(testDirs['root'], testDirs['output']), "test.gif"), "wb") as destFile:
            destFile.write(test.decrypt(origFile.read()))


def sockTest():
    if sys.argv[1] == "client":
        con = Connection("127.0.0.1", 25565, sockType.CLIENT)
        with open(join(join(testDirs['root'], testDirs['input']), "test.mp4"), "rb") as origFile:
            con.send(origFile.read())
    else:
        con = Connection("127.0.0.1", 25565, sockType.SERVER)
        file = con.receive()
        with open(join(join(testDirs['root'], testDirs['output']), "test.mp4"), "wb") as destFile:
            destFile.write(file)


if __name__ == "__main__":
    cryptoTest()

