import elftools.elf.elffile
import pefile


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
