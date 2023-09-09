import lief
from lief import PE
import pefile
import shutil


BYTE_SIZE = 0x1
WORD_SIZE = 0x2
DWORD_SIZE = 0x4
QWORD_SIZE = 0x8

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
ENTRY_EXPORT = IMAGE_DIRECTORY_ENTRY_EXPORT

SECTION_EXPORT_CHARACTERISTICS = 0x40000040
SECTION_EXPORT_DEFAULT_SIZE = 0x28
SECTION_EXPORT_NAME = '.edata'
SECTION_SIZE_ALIGN = 0X200


# [================================]
# CLASSES
# [================================]


class Symbol():
    def __init__(self, adress, ordinal, name):
        self.address = adress
        self.ordinal = ordinal
        self.name = name


# [================================]
# PUBLIC
# [================================]


def init(_edit_path, _new_path):
    global edit_path
    global new_path
    edit_path = _edit_path
    new_path = _new_path

    if not (edit_path == new_path):
        shutil.copyfile(edit_path, new_path)


def check_section(section_name):
    pe = pefile.PE(edit_path)

    for section in pe.sections:
        if section_name == section.Name.decode().replace('\x00', ''):
            pe.close()
            return True

    pe.close()
    return False


def check_last_section(section_name):
    pe = pefile.PE(edit_path)

    if section_name == pe.sections[-1].Name.decode().replace('\x00', ''):
        pe.close()
        return True

    pe.close()
    return False


def get_export_symbols():
    pe = pefile.PE(edit_path)

    ls_symb = []
    for symb in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        ls_symb.append(Symbol(symb.address, symb.ordinal, symb.name))

    pe.close()
    return ls_symb


def get_new_symbols(symbol_names):
    symbols = []
    for symbol_name in symbol_names:
        symbols.append(Symbol(-1, -1, symbol_name))

    return symbols


def set_export_section(export_section_name):
    pe = pefile.PE(new_path)

    export_section = __get_section_by_name(pe, export_section_name)
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[ENTRY_EXPORT].VirtualAddress = export_section.VirtualAddress
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[ENTRY_EXPORT].Size = export_section.Misc_VirtualSize
    pe.OPTIONAL_HEADER.CheckSum = 0

    __set_default_export_section(pe, export_section)

    pe.write(new_path)
    pe.close()


def set_section_name(section_name_old, section_name_new):
    pe = pefile.PE(new_path)

    section = __get_section_by_name(pe, section_name_old)
    section.Name = section_name_new.encode()
    pe.set_bytes_at_offset(section.get_file_offset(),
                           section_name_new.encode())

    pe.write(new_path)
    pe.close()


def add_new_section(section_name):
    binary = lief.parse(new_path)

    section = PE.Section(section_name)
    section.virtual_size = SECTION_EXPORT_DEFAULT_SIZE
    section.size = SECTION_SIZE_ALIGN + section.virtual_size - \
        section.virtual_size % SECTION_SIZE_ALIGN
    section.characteristics = SECTION_EXPORT_CHARACTERISTICS
    binary.add_section(section)

    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(new_path)


def add_symbols_export_section(export_section_name, symbols):
    pe = pefile.PE(new_path)

    export_section = __get_section_by_name(pe, export_section_name)
    for symbol in symbols:
        __add_symbol_export_section(pe, export_section, symbol)

    pe.write(new_path)
    pe.close()


# [================================]
# PRIVATE
# [================================]


def __symbol_encode(symbol):
    if type(symbol) is bytes:
        return symbol + b'\x00'
    elif type(symbol) is str:
        return symbol.encode('utf-8') + b'\x00'
    else:
        return None


def __get_section_by_name(pe, section_name):
    for section in pe.sections:
        if section_name == section.Name.decode().replace('\x00', ''):
            return section


def __set_default_export_section(pe, export_section):
    DIRECTORY_EXPORT = export_section.PointerToRawData
    dir_offset = 0

    NAME_ADDRESS = export_section.VirtualAddress + SECTION_EXPORT_DEFAULT_SIZE
    ADDRESS_OF_FUNCTION = export_section.VirtualAddress + SECTION_EXPORT_DEFAULT_SIZE
    ADDRESS_OF_RVA = export_section.VirtualAddress + SECTION_EXPORT_DEFAULT_SIZE
    ADDRESS_OF_ORDINAL = export_section.VirtualAddress + SECTION_EXPORT_DEFAULT_SIZE

    ls_data = [
        [DWORD_SIZE, 0x0],
        [DWORD_SIZE, 0x0],
        [WORD_SIZE, 0x0],
        [WORD_SIZE, 0x0],
        [DWORD_SIZE, NAME_ADDRESS],
        [DWORD_SIZE, 0x1],
        [DWORD_SIZE, 0x0],
        [DWORD_SIZE, 0x0],
        [DWORD_SIZE, ADDRESS_OF_FUNCTION],
        [DWORD_SIZE, ADDRESS_OF_RVA],
        [DWORD_SIZE, ADDRESS_OF_ORDINAL],
    ]

    for i in range(0, len(ls_data)):
        data = ls_data[i]
        if data[0] == DWORD_SIZE:
            pe.set_dword_at_offset(DIRECTORY_EXPORT + dir_offset, data[1])
            dir_offset = dir_offset + DWORD_SIZE
        elif data[0] == WORD_SIZE:
            pe.set_word_at_offset(DIRECTORY_EXPORT + dir_offset, data[1])
            dir_offset = dir_offset + WORD_SIZE


def __add_symbol_export_section(pe, export_section, symbol):
    RAW_TO_VIRTUAL_ADDRESS = export_section.VirtualAddress - \
        export_section.PointerToRawData
    START_FN_VAR = export_section.PointerToRawData - \
        export_section.PointerToRawData % 0x1000 + \
        pe.DIRECTORY_ENTRY_EXPORT.struct.sizeof()
    SYMBOL_START = pe.DIRECTORY_ENTRY_EXPORT.struct.get_file_offset() + \
        pe.DIRECTORY_ENTRY_EXPORT.struct.sizeof()
    SYMBOLS_LEN = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) + 1
    OFFSET_ORDINAL_STR = 0x6

    __add_symbol_data_header(pe, len(symbol.name))
    __add_symbol_data_export_directory(pe)
    __add_symbol_data_export_section(export_section, len(symbol.name))

    start_fn_address = SYMBOL_START
    start_name_address = SYMBOL_START + DWORD_SIZE*(SYMBOLS_LEN)
    start_ordinal_address = SYMBOL_START + 2*DWORD_SIZE*(SYMBOLS_LEN)
    start_name_str_address = SYMBOL_START + \
        (2*DWORD_SIZE + WORD_SIZE)*(SYMBOLS_LEN) + OFFSET_ORDINAL_STR

    newSymbol = pefile.ExportData(
        ordinal=symbol.ordinal,
        address=symbol.address,
        name=symbol.name
    )

    if newSymbol.ordinal == -1:
        newSymbol.ordinal = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) + 1

    if (len(pe.DIRECTORY_ENTRY_EXPORT.symbols) > 0) and (newSymbol.address == -1):
        newSymbol.address = pe.DIRECTORY_ENTRY_EXPORT.symbols[-1].address + DWORD_SIZE
    elif newSymbol.address == -1:
        newSymbol.address = START_FN_VAR + DWORD_SIZE*(SYMBOLS_LEN-1)

    pe.DIRECTORY_ENTRY_EXPORT.symbols.append(newSymbol)

    for symb in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        symbol_name = __symbol_encode(symb.name)

        pe.set_dword_at_rva(start_fn_address, symb.address)
        pe.set_dword_at_rva(start_name_address,
                            start_name_str_address + RAW_TO_VIRTUAL_ADDRESS)
        pe.set_word_at_rva(start_ordinal_address, symb.ordinal-1)
        pe.set_bytes_at_rva(start_name_str_address, symbol_name)

        start_fn_address = start_fn_address + DWORD_SIZE
        start_name_address = start_name_address + DWORD_SIZE
        start_ordinal_address = start_ordinal_address + WORD_SIZE
        start_name_str_address = start_name_str_address + len(symbol_name)


def __add_symbol_data_header(pe, symbol_name_len):
    HEADER_FILE_EXPORT = pe.OPTIONAL_HEADER.DATA_DIRECTORY[ENTRY_EXPORT]

    pe.FILE_HEADER.NumberOfSymbols = pe.FILE_HEADER.NumberOfSymbols + 1
    HEADER_FILE_EXPORT.Size = HEADER_FILE_EXPORT.Size + \
        symbol_name_len + 2*DWORD_SIZE + WORD_SIZE


def __add_symbol_data_export_directory(pe):
    pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions = pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions + 1
    pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames = pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames + 1
    pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames + DWORD_SIZE
    pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals + 2*DWORD_SIZE
    pe.DIRECTORY_ENTRY_EXPORT.struct.Name = pe.DIRECTORY_ENTRY_EXPORT.struct.Name + \
        2*DWORD_SIZE + WORD_SIZE


def __add_symbol_data_export_section(export_section, symbol_name_len):
    export_section.Misc_VirtualSize = export_section.Misc_VirtualSize + \
        symbol_name_len + 2*DWORD_SIZE + WORD_SIZE
    export_section.SizeOfRawData = SECTION_SIZE_ALIGN + export_section.Misc_VirtualSize - \
        export_section.Misc_VirtualSize % SECTION_SIZE_ALIGN
