import lief
from lief import PE
import pefile
import shutil
import re


BYTE_SIZE = 0x1
WORD_SIZE = 0x2
DWORD_SIZE = 0x4
QWORD_SIZE = 0x8

SYMBOL_DATA_NAME = 0
SYMBOL_DATA_VALUE = 1

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
ENTRY_EXPORT = IMAGE_DIRECTORY_ENTRY_EXPORT

SECTION_EXPORT_CHARACTERISTICS = 0x40000040
SECTION_EXPORT_DEFAULT_SIZE = 0x28
SECTION_EXPORT_NAME = '.edata'
SECTION_ADDRESS_ALIGN = 0X1000
SECTION_SIZE_ALIGN = 0X200

NAME_INDEX = 4
ADDRESS_OF_FUNCTION_INDEX = 8
ADDRESS_OF_NAMES_INDEX = 9
ADDRESS_OF_ORDINALS_INDEX = 10
OFFSET_ORDINAL_STR = 0x6

SYMBOL_FUNCTION = 'function'
SYMBOL_NAME = 'name'
SYMBOL_ORDINAL = 'ordinal'
SYMBOL_NAME_STR = 'name_str'
SYMBOL_VALUE_PTR = 'value_ptr'


# [================================]
# CLASSES
# [================================]


class Symbol():
    def __init__(self, adress, ordinal, name):
        self.address = adress
        self.ordinal = ordinal
        self.name = name
        self.value = None
        self.is_new = True

    def set_name(self, name):
        self.name = name

    def set_value(self, value):
        self.value = value

    def set_is_new(self, is_new):
        self.is_new = is_new


class ExportSection():
    def __init__(self, entry_data, entry_offset, symbols):
        self.entry_data = entry_data
        self.entry_offset = entry_offset
        self.symbols = symbols

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
    pe = pefile.PE(new_path)

    for section in pe.sections:
        if section_name == section.Name.decode().replace('\x00', ''):
            pe.close()
            return True

    pe.close()
    return False


def check_last_section(section_name):
    pe = pefile.PE(new_path)

    if section_name == pe.sections[-1].Name.decode().replace('\x00', ''):
        pe.close()
        return True

    pe.close()
    return False


def get_export_symbols(export_section_name, make_new=False):
    pe = pefile.PE(new_path)
    export_section = __get_section_by_name(pe, export_section_name)
    ls_symb = __get_export_symbols(pe, export_section, make_new)
    pe.close()
    return ls_symb


def get_new_symbols(str_symbol_list):
    symbols = []
    for str_symbol in str_symbol_list:
        symbol_data = re.split(",|;|:", str_symbol)
        symbol_name = symbol_data[SYMBOL_DATA_NAME]
        symbol_value = symbol_data[SYMBOL_DATA_VALUE]

        symbol = Symbol(-1, -1, symbol_name)
        symbol.set_value(int(symbol_value))
        symbol.set_is_new(True)
        symbols.append(symbol)

    return symbols


def get_export_section_data(export_section_name):
    pe = pefile.PE(new_path)
    export_section = __get_section_by_name(pe, export_section_name)
    entry_data = __get_entry_export_section_data(pe)
    entry_offset = __get_export_section_entry_offset(pe, export_section)
    symbols = __get_export_symbols(pe, export_section)
    pe.close()

    export_section_data = ExportSection(entry_data, entry_offset, symbols)
    return export_section_data


def get_export_section_data_size(export_section_data):
    SYMBOLS_LEN = len(export_section_data.symbols)
    SYMBOL_DATA_OFFSET = export_section_data.entry_offset + SECTION_EXPORT_DEFAULT_SIZE
    SYMBOL_NAME_OFFSET = SYMBOL_DATA_OFFSET + \
        (2*DWORD_SIZE + WORD_SIZE)*(SYMBOLS_LEN)
    SYMBOL_NAME_OFFSET = SYMBOL_NAME_OFFSET + OFFSET_ORDINAL_STR

    export_section_data_size = SYMBOL_NAME_OFFSET
    for symbol in export_section_data.symbols:
        symbol_name = __symbol_encode(symbol.name)
        export_section_data_size = export_section_data_size + len(symbol_name)

    return export_section_data_size


def set_default_export_section(export_section_name, section_entry_offset=0):
    pe = pefile.PE(new_path)

    export_section = __get_section_by_name(pe, export_section_name)
    __set_directory_entry_export(pe, export_section, section_entry_offset)
    __set_default_entry_export_section(
        pe, export_section, section_entry_offset)

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


def delete_section(section_name):
    binary = lief.parse(new_path)
    binary.remove_section(section_name)
    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(new_path)


def add_new_section(section_name, section_size=SECTION_EXPORT_DEFAULT_SIZE):
    binary = lief.parse(new_path)

    section = PE.Section(section_name)
    section.virtual_size = section_size
    section.size = SECTION_SIZE_ALIGN + section.virtual_size - \
        section.virtual_size % SECTION_SIZE_ALIGN
    section.characteristics = SECTION_EXPORT_CHARACTERISTICS
    binary.add_section(section)

    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(new_path)


def add_symbols_export_section(export_section_name, symbols):
    entry_offset = DWORD_SIZE * len(symbols)
    export_section_data = get_export_section_data(export_section_name)
    export_section_data.entry_offset = export_section_data.entry_offset + entry_offset

    pe = pefile.PE(new_path)
    __set_directory_entry_export_to_none(pe)
    pe.write(new_path)
    pe.close()

    delete_section(export_section_name)
    export_section_data.symbols.extend(symbols)
    section_size = get_export_section_data_size(export_section_data)
    add_new_section(export_section_name, section_size)
    set_default_export_section(
        export_section_name, export_section_data.entry_offset)

    pe = pefile.PE(new_path)
    export_section = __get_section_by_name(pe, export_section_name)
    __set_update_symbol_export_section(pe, export_section, export_section_data)
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


def __get_export_symbols(pe, export_section, make_new=False):
    ls_symb = []

    if not (export_section == None):
        MIN_OFFSET = export_section.get_file_offset()
        MAX_OFFSET = pe.DIRECTORY_ENTRY_EXPORT.struct.get_file_offset()

    for symb in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        symbol = Symbol(symb.address, symb.ordinal, symb.name)
        if not (type(symb.name) == 'str'):
            symbol.set_name(symbol.name.decode())
        symbol.set_is_new(make_new)

        if not (export_section == None):
            raw_address = __get_virtual_to_raw_address(
                export_section, symbol.address)
            if (raw_address >= MIN_OFFSET) and (raw_address < MAX_OFFSET):
                value = pe.get_dword_at_rva(raw_address)
                symbol.set_value(value)

        ls_symb.append(symbol)

    return ls_symb


def __get_section_by_name(pe, section_name):
    for section in pe.sections:
        if section_name == section.Name.decode().replace('\x00', ''):
            return section


def __get_raw_to_virtual_address(export_section, raw_address):
    RAW_TO_VIRTUAL_ADDRESS = export_section.VirtualAddress - \
        export_section.PointerToRawData
    return raw_address + RAW_TO_VIRTUAL_ADDRESS


def __get_virtual_to_raw_address(export_section, virtual_address):
    VIRTUAL_TO_RAW_ADDRESS = export_section.PointerToRawData - \
        export_section.VirtualAddress
    return virtual_address + VIRTUAL_TO_RAW_ADDRESS


def __get_export_section_entry_offset(pe, export_section):
    HEADER_FILE_EXPORT = pe.OPTIONAL_HEADER.DATA_DIRECTORY[ENTRY_EXPORT]
    return HEADER_FILE_EXPORT.VirtualAddress - export_section.VirtualAddress


def __get_entry_export_section_data(pe):
    data_list = [
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.Characteristics],
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp],
        [WORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.MajorVersion],
        [WORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.MinorVersion],
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.Name],
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.Base],
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions],
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames],
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions],
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames],
        [DWORD_SIZE, pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals],
    ]

    return data_list


def __set_default_entry_export_section(pe, export_section, section_entry_offset):
    DEFAULT_ADDRESS = export_section.VirtualAddress + \
        section_entry_offset + SECTION_EXPORT_DEFAULT_SIZE
    NAME_ADDRESS = DEFAULT_ADDRESS
    ADDRESS_OF_FUNCTION = DEFAULT_ADDRESS
    ADDRESS_OF_NAMES = DEFAULT_ADDRESS
    ADDRESS_OF_ORDINAL = DEFAULT_ADDRESS

    data_list = [
        [DWORD_SIZE, 0x0],
        [DWORD_SIZE, 0x0],
        [WORD_SIZE, 0x0],
        [WORD_SIZE, 0x0],
        [DWORD_SIZE, NAME_ADDRESS],
        [DWORD_SIZE, 0x1],
        [DWORD_SIZE, 0x0],
        [DWORD_SIZE, 0x0],
        [DWORD_SIZE, ADDRESS_OF_FUNCTION],
        [DWORD_SIZE, ADDRESS_OF_NAMES],
        [DWORD_SIZE, ADDRESS_OF_ORDINAL],
    ]

    __set_entry_export_section(
        pe, export_section, data_list, section_entry_offset)


def __set_entry_export_section(pe, export_section, data_list, section_entry_offset=0):
    DIRECTORY_EXPORT = export_section.PointerToRawData + section_entry_offset
    dir_offset = 0

    for i in range(0, len(data_list)):
        data = data_list[i]
        if data[0] == DWORD_SIZE:
            pe.set_dword_at_offset(DIRECTORY_EXPORT + dir_offset, data[1])
            dir_offset = dir_offset + DWORD_SIZE
        elif data[0] == WORD_SIZE:
            pe.set_word_at_offset(DIRECTORY_EXPORT + dir_offset, data[1])
            dir_offset = dir_offset + WORD_SIZE

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        pe.DIRECTORY_ENTRY_EXPORT.struct.Characteristics = data_list[0][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp = data_list[1][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.MajorVersion = data_list[2][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.MinorVersion = data_list[3][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.Name = data_list[4][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.Base = data_list[5][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions = data_list[6][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames = data_list[7][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions = data_list[8][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames = data_list[9][1]
        pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals = data_list[10][1]


def __set_directory_entry_export(pe, export_section, section_entry_offset):
    HEADER_FILE_EXPORT = pe.OPTIONAL_HEADER.DATA_DIRECTORY[ENTRY_EXPORT]
    HEADER_FILE_EXPORT.VirtualAddress = export_section.VirtualAddress + section_entry_offset
    HEADER_FILE_EXPORT.Size = export_section.Misc_VirtualSize - section_entry_offset

    pe.FILE_HEADER.NumberOfSymbols = 0
    pe.OPTIONAL_HEADER.CheckSum = 0
    pe.OPTIONAL_HEADER.SizeOfImage = pe.OPTIONAL_HEADER.SizeOfImage + SECTION_ADDRESS_ALIGN
    pe.OPTIONAL_HEADER.SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders + SECTION_SIZE_ALIGN


def __set_directory_entry_export_to_none(pe):
    HEADER_FILE_EXPORT = pe.OPTIONAL_HEADER.DATA_DIRECTORY[ENTRY_EXPORT]
    HEADER_FILE_EXPORT.VirtualAddress = 0
    HEADER_FILE_EXPORT.Size = 0

    pe.FILE_HEADER.NumberOfSymbols = 0
    pe.OPTIONAL_HEADER.CheckSum = 0
    pe.OPTIONAL_HEADER.SizeOfImage = pe.OPTIONAL_HEADER.SizeOfImage + SECTION_ADDRESS_ALIGN
    pe.OPTIONAL_HEADER.SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders + SECTION_SIZE_ALIGN
    pe.set_dword_at_offset(HEADER_FILE_EXPORT.get_file_offset(), 0)
    pe.set_dword_at_offset(
        HEADER_FILE_EXPORT.get_file_offset() + DWORD_SIZE, 0)


def __set_update_symbol_export_section(pe, export_section, export_section_data):
    SYMBOL_DATA_START = __get_virtual_to_raw_address(
        export_section, pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions)
    SYMBOL_VALUE_START = pe.DIRECTORY_ENTRY_EXPORT.struct.get_file_offset() - \
        export_section_data.entry_offset
    SYMBOLS_LEN = len(export_section_data.symbols)
    START_ORDINAL_STR = SYMBOL_DATA_START + \
        (2*DWORD_SIZE + WORD_SIZE)*(SYMBOLS_LEN)

    pe.DIRECTORY_ENTRY_EXPORT.symbols.clear()

    start_address = {
        SYMBOL_FUNCTION: SYMBOL_DATA_START,
        SYMBOL_NAME: SYMBOL_DATA_START + DWORD_SIZE*(SYMBOLS_LEN),
        SYMBOL_ORDINAL: SYMBOL_DATA_START + 2*DWORD_SIZE*(SYMBOLS_LEN),
        SYMBOL_NAME_STR: START_ORDINAL_STR + OFFSET_ORDINAL_STR
    }

    start_data = {
        SYMBOL_ORDINAL: 1,
        SYMBOL_VALUE_PTR: SYMBOL_VALUE_START
    }

    for symbol in export_section_data.symbols:
        newSymbol = pefile.ExportData(
            ordinal=symbol.ordinal,
            address=symbol.address,
            name=symbol.name.encode()
        )

        __add_symbol_data_export_directory(pe)
        __add_symbol_data_file_header(pe)
        __set_config_symbol(pe, export_section, start_data, symbol)
        __set_write_memory_symbol(pe, export_section, start_address, symbol)

        pe.DIRECTORY_ENTRY_EXPORT.symbols.append(newSymbol)


def __set_config_symbol(pe, export_section, start_data, symbol):
    if symbol.ordinal == -1:
        symbol.ordinal = start_data[SYMBOL_ORDINAL]

    if (symbol.address == -1):
        symbol.address = __get_raw_to_virtual_address(
            export_section, start_data[SYMBOL_VALUE_PTR])

    if not (symbol.value == None):
        pe.set_dword_at_rva(start_data[SYMBOL_VALUE_PTR], symbol.value)
        start_data[SYMBOL_VALUE_PTR] = start_data[SYMBOL_VALUE_PTR] + DWORD_SIZE

    start_data[SYMBOL_ORDINAL] = start_data[SYMBOL_ORDINAL] + 1


def __set_write_memory_symbol(pe, export_section, start_address, symbol):
    symbol_name = __symbol_encode(symbol.name)
    pe.set_dword_at_rva(start_address[SYMBOL_FUNCTION], symbol.address)
    pe.set_dword_at_rva(start_address[SYMBOL_NAME], __get_raw_to_virtual_address(
        export_section, start_address[SYMBOL_NAME_STR]))
    pe.set_word_at_rva(start_address[SYMBOL_ORDINAL], symbol.ordinal-1)
    pe.set_bytes_at_rva(start_address[SYMBOL_NAME_STR], symbol_name)

    start_address[SYMBOL_FUNCTION] = start_address[SYMBOL_FUNCTION] + DWORD_SIZE
    start_address[SYMBOL_NAME] = start_address[SYMBOL_NAME] + DWORD_SIZE
    start_address[SYMBOL_ORDINAL] = start_address[SYMBOL_ORDINAL] + WORD_SIZE
    start_address[SYMBOL_NAME_STR] = start_address[SYMBOL_NAME_STR] + \
        len(symbol_name)


def __add_symbol_data_file_header(pe):
    pe.FILE_HEADER.NumberOfSymbols = pe.FILE_HEADER.NumberOfSymbols + 1


def __add_symbol_data_export_directory(pe):
    pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions = pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions + 1
    pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames = pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames + 1
    pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames + DWORD_SIZE
    pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals + 2*DWORD_SIZE
    pe.DIRECTORY_ENTRY_EXPORT.struct.Name = pe.DIRECTORY_ENTRY_EXPORT.struct.Name + \
        2*DWORD_SIZE + WORD_SIZE
