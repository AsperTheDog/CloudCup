from crypto import CrModule
from os.path import join, exists

testDirs = {"root": "TestObjects", "input": "In", "output": "Out", "cr": "Crypt"}

test = CrModule()

if exists(join("Keys", "pass.bin")):
    test.auth("pwd")
else:
    test.reg("pwd")

with open(join(join(testDirs['root'], testDirs['input']), "test.mp4"), "rb") as origFile:
    with open(join(join(testDirs['root'], testDirs['cr']), "test.bin"), "wb") as destFile:
        destFile.write(test.encrypt(origFile.read()))

with open(join(join(testDirs['root'], testDirs['cr']), "test.bin"), "rb") as origFile:
    with open(join(join(testDirs['root'], testDirs['output']), "test.mp4"), "wb") as destFile:
        destFile.write(test.decrypt(origFile.read()))