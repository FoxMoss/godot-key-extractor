import time

import distorm3

from utils import loadExecutable

path = input("Enter the path to the executable: ")

s = time.time()
codeDump, codeAddr, dataDump, dataAddr, fileType = loadExecutable(path)

disassembly = distorm3.DecodeGenerator(codeAddr, codeDump, distorm3.Decode64Bits)

if fileType == "windows":
    keyOffset = 69
    instSuffix = ("[RBX+RDI]", "[RDI+RBX]")

elif fileType == "linux":
    keyOffset = 10
    instSuffix = ("[RAX+RBP]", "[RBP+RAX]")

key = None
for offset, size, instruction, hexdump in disassembly:
    if instruction.startswith("MOVZX R15D, BYTE") and instruction.endswith(
        instSuffix
    ):
        relativeOffset = offset - keyOffset - codeAddr
        keyCode = codeDump[relativeOffset : relativeOffset + 7]
        keyInstruction = distorm3.Decode(0, keyCode, distorm3.Decode64Bits)[0][2]
        keyAddr = int(keyInstruction[14:-1], 16) + offset - keyOffset - dataAddr + 7
        key = dataDump[keyAddr : keyAddr + 32].hex()
        break

e = time.time()
print(f"Time: {e - s:.2f}s")

if key:
    print(f"Key: {key}")
