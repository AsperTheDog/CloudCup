from crypto import CrModule
from os.path import join, exists
import os
from conn import Connection, sockType, transferType
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


def largeCryptTest():
    test = CrModule()

    if exists(join("Keys", "pass.bin")):
        test.auth("pwd")
    else:
        test.reg("pwd")

    symKey, sig = test.largeEncrypt(
        join(join(testDirs['root'], testDirs['input']), "test3.7z"),
        join(join(testDirs['root'], testDirs['cr']), "test3.bin")
    )

    test.largeDecrypt(
        join(join(testDirs['root'], testDirs['cr']), "test3.bin"),
        join(join(testDirs['root'], testDirs['output']), "test3.7z"),
        symKey,
        sig
    )


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


def bigCryptoSockTest():
    cr = CrModule()
    if exists(join("Keys", "pass.bin")):
        cr.auth("pwd")
    else:
        cr.reg("pwd")
    if sys.argv[1] == "client":
        con = Connection("127.0.0.1", 25565, sockType.CLIENT)
        size = os.path.getsize(join(join(testDirs['root'], testDirs['input']), "test3.7z"))
        sizeCount = 0
        with open(join(join(testDirs['root'], testDirs['input']), "test3.7z"), "rb") as origFile:
            symKey = cr.startEncrypt()
            con.sendStartFile("test3.7z", size, symKey)
            while True:
                chunk = origFile.read(2 ** 28)
                sizeCount += len(chunk)
                if sizeCount == size:
                    crChunk, sig = cr.endEncrypt(chunk)
                    con.send(crChunk)
                    break
                else:
                    crChunk = cr.addEncrypt(chunk)
                    con.send(crChunk)
        con.sendEndFile(sig)
    else:
        con = Connection("127.0.0.1", 25565, sockType.SERVER)
        while True:
            data, ttype = con.receive()
            if ttype == transferType.FILESTART:
                cr.startDecrypt(data[1])
                size = data[2]
                break
        sizeCount = 0
        with open(join(join(testDirs['root'], testDirs['output']), data[0]), "wb") as destFile:
            while True:
                data, ttype = con.receive()
                if ttype == transferType.FILE:
                    if not data[1]:
                        sizeCount += len(data[0])
                        if sizeCount >= size:
                            chunk = cr.endEncrypt(data[0])
                        else:
                            chunk = cr.addDecrypt(data[0])
                        destFile.write(chunk)
                    else:
                        sig = data[0]
                        break
        if not cr.verify(join(join(testDirs['root'], testDirs['output']), "test.mp4"), sig):
            print("Invalid file")
        else:
            print("Transation complete!!")


if __name__ == "__main__":
    bigCryptoSockTest()
