import elftools.elf.elffile
import pefile

import time
import distorm3


def loadExecutable(path):
    if path.endswith(".exe"):
        return *loadWindowsExecutable(path), "windows"
    elif path.endswith(".x86_64"):
        return *loadLinuxExecutable(path), "linux"
    else:
        raise Exception("Unknown file format")


def loadLinuxExecutable(path):
    elf = elftools.elf.elffile.ELFFile(open(path, "rb"))
    for section in elf.iter_sections():
        if section.name == ".text":
            codeDump = section.data()
            codeAddr = section["sh_addr"]
        elif section.name == ".data":
            dataDump = section.data()
            dataAddr = section["sh_addr"]
            break
    elf.close()

    return codeDump, codeAddr, dataDump, dataAddr


def loadWindowsExecutable(path):
    pe = pefile.PE(path, fast_load=True)
    for section in pe.sections:
        if section.Name.decode().strip("\x00") == ".text":
            codeDump = section.get_data()
            codeAddr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        elif section.Name.decode().strip("\x00") == ".rdata":
            codeDump += section.get_data()
        elif section.Name.decode().strip("\x00") == ".data":
            dataDump = section.get_data()
            dataAddr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            break
    pe.close()

    return codeDump, codeAddr, dataDump, dataAddr


def extract(path, self):
    s = time.time()
    codeDump, codeAddr, dataDump, dataAddr, fileType = loadExecutable(path)

    disassembly = distorm3.DecodeGenerator(
        codeAddr, codeDump, distorm3.Decode64Bits)

    if fileType == "windows":
        keyOffset = 69
        instSuffix = ("[RBX+RDI]", "[RDI+RBX]")

    elif fileType == "linux":
        keyOffset = 10
        instSuffix = ("[RAX+RBP]", "[RBP+RAX]")

    key = None
    index = 0
    for offset, size, instruction, hexdump in disassembly:
        index += 1
        self.progressbar.set(index/len(disassembly))

        if instruction.startswith("MOVZX R15D, BYTE") and instruction.endswith(
            instSuffix
        ):
            relativeOffset = offset - keyOffset - codeAddr
            keyCode = codeDump[relativeOffset: relativeOffset + 7]
            keyInstruction = distorm3.Decode(
                0, keyCode, distorm3.Decode64Bits)[0][2]
            keyAddr = int(keyInstruction[14:-1], 16) + \
                offset - keyOffset - dataAddr + 7
            key = dataDump[keyAddr: keyAddr + 32].hex()
            break

    e = time.time()
    print(f"Time: {e - s:.2f}s")

    if key:
        print(f"Key: {key}")
    return key
