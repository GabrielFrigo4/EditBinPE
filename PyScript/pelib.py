# [================================]
# IMPORT MODULES
# [================================]


import pefile
import shutil
import math
import re


# [================================]
# PUBLIC VARIABLES / CONST
# [================================]


BYTE_NULL = 0x0
BYTE_SIZE = 0x1
WORD_SIZE = 0x2
DWORD_SIZE = 0x4
QWORD_SIZE = 0x8

BYTE_MAX = (0xFF+1)**BYTE_SIZE
WORD_MAX = (0xFF+1)**WORD_SIZE
DWORD_MAX = (0xFF+1)**DWORD_SIZE
QWORD_MAX = (0xFF+1)**QWORD_SIZE

SYMBOL_DATA_NAME = 0
SYMBOL_DATA_VALUE = 1

NAME_INDEX = 4
ADDRESS_OF_FUNCTION_INDEX = 8
ADDRESS_OF_NAMES_INDEX = 9
ADDRESS_OF_ORDINALS_INDEX = 10
OFFSET_ORDINAL_STR = 0x6

SYMBOL_FUNCTION = 'function'
SYMBOL_ORDINAL = 'ordinal'
SYMBOL_NAME_RVA = 'name_rva'
SYMBOL_NAME_STR = 'name_str'
SYMBOL_VALUE_PTR = 'value_ptr'

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
ENTRY_EXPORT = IMAGE_DIRECTORY_ENTRY_EXPORT

SECTION_EXPORT_CHARACTERISTICS = 0x40000040
SECTION_EXPORT_DEFAULT_SIZE = 0x28
SECTION_EXPORT_NAME = '.edata'
SECTION_SIZE = 0x28


# [================================]
# PRIVATE VARIABLES / CONST
# [================================]


__OK = 0
__ERROR = -1
__state = __OK


# [================================]
# CLASSES
# [================================]


## [SYMBOL] ##
class Symbol():
    # [INIT] #
    def __init__(self, adress, ordinal, name, value=None, is_new=True):
        self.__address__ = adress
        self.__ordinal__ = ordinal
        self.__name_rva__ = -1
        self.__name__ = name
        self.__value__ = value

        self.__address_ptr__ = -1
        self.__ordinal_ptr__ = -1
        self.__name_rva_ptr__ = -1
        self.__name_ptr__ = -1
        self.__value_ptr__ = -1

        self.is_new = is_new

    # [GET VALUES] #
    def get_address(self):
        return self.__address__

    def get_ordinal(self):
        return self.__ordinal__

    def get_name_rva(self):
        return self.__name_rva__

    def get_name(self):
        return self.__name__

    def get_value(self):
        return self.__value__

    # [GET PTR] #
    def get_address_ptr(self):
        return self.__address_ptr__

    def get_ordinal_ptr(self):
        return self.__ordinal_ptr__

    def get_name_rva_ptr(self):
        return self.__name_rva_ptr__

    def get_name_ptr(self):
        return self.__name_ptr__

    def get_value_ptr(self):
        return self.__value_ptr__

    # [GET] #
    def get_is_new(self):
        return self.__is_new__

    # [SET VALUES] #
    def set_address(self, address):
        self.__address__ = address

    def set_ordinal(self, ordinal):
        self.__ordinal__ = ordinal

    def set_name_rva(self, name_rva):
        self.__name_rva__ = name_rva

    def set_name(self, name):
        self.__name__ = name

    def set_value(self, value):
        self.__value__ = value

    # [SET PTR] #
    def set_address_ptr(self, address_ptr):
        self.__address_ptr__ = address_ptr

    def set_ordinal_ptr(self, ordinal_ptr):
        self.__ordinal_ptr__ = ordinal_ptr

    def set_name_rva_ptr(self, name_rva_ptr):
        self.__name_rva_ptr__ = name_rva_ptr

    def set_name_ptr(self, name_ptr):
        self.__name_ptr__ = name_ptr

    def set_value_ptr(self, value_ptr):
        self.__value_ptr__ = value_ptr

    # [SET] #
    def set_is_new(self, is_new):
        self.__is_new__ = is_new


## [EXPORT_SECTION] ##
class ExportSection():
    # [INIT] #
    def __init__(self, entry_data, entry_offset, symbols, section):
        self.__entry_data__ = entry_data
        self.__entry_offset__ = entry_offset
        self.__symbols__ = symbols
        self.__section__ = section

    # [GET] #
    def get_entry_data(self):
        return self.__entry_data__

    def get_entry_offset(self):
        return self.__entry_offset__

    def get_symbols(self):
        return self.__symbols__

    def get_section(self):
        return self.__section__

    # [SET] #
    def set_entry_data(self, entry_data):
        self.__entry_data__ = entry_data

    def set_entry_offset(self, entry_offset):
        self.__entry_offset__ = entry_offset

    def set_symbols(self, symbols):
        self.__symbols__ = symbols

    def set_section(self, section):
        self.__section__ = section

# [================================]
# PUBLIC FUNCTIONS
# [================================]


def init(_edit_path, _new_path):
    global edit_path
    global new_path
    edit_path = _edit_path
    new_path = _new_path

    if not (edit_path == new_path):
        shutil.copyfile(edit_path, new_path)

    global SECTION_VIRTUAL_ALIGN
    global SECTION_RAW_ALIGN
    SECTION_VIRTUAL_ALIGN = __ERROR
    SECTION_RAW_ALIGN = __ERROR

    with pefile.PE(new_path) as pe:
        SECTION_VIRTUAL_ALIGN = pe.OPTIONAL_HEADER.SectionAlignment
        SECTION_RAW_ALIGN = pe.OPTIONAL_HEADER.FileAlignment


def check_section(section_name):
    ret = False
    with pefile.PE(new_path) as pe:
        for section in pe.sections:
            if section_name == section.Name.decode().replace('\x00', ''):
                ret = True
                break
    return ret


def check_last_section(section_name):
    ret = False
    with pefile.PE(new_path) as pe:
        if section_name == pe.sections[-1].Name.decode().replace('\x00', ''):
            ret = True
        else:
            ret = False
    return ret


def get_export_symbols(export_section_name, make_new=False):
    with pefile.PE(new_path) as pe:
        export_section = __get_section_by_name(pe, export_section_name)
        ls_symb = __get_export_symbols(pe, export_section, make_new)
    return ls_symb


def get_new_symbols(str_symbol_list):
    symbols = []
    for str_symbol in str_symbol_list:
        symbol_data = re.split(",|;|:", str_symbol)
        symbol_name = symbol_data[SYMBOL_DATA_NAME]
        symbol_value = symbol_data[SYMBOL_DATA_VALUE]

        symbol = Symbol(-1, -1, symbol_name, int(symbol_value), True)
        symbols.append(symbol)

    return symbols


def get_export_section_data(export_section_name):
    with pefile.PE(new_path) as pe:
        export_section = __get_section_by_name(pe, export_section_name)
        entry_data = __get_entry_export_section_data(pe)
        entry_offset = __get_export_section_entry_offset(pe, export_section)
        symbols = __get_export_symbols(pe, export_section)

    export_section_data = ExportSection(
        entry_data, entry_offset, symbols, export_section)
    return export_section_data


def get_export_section_data_size(export_section_data):
    SYMBOLS_LEN = len(export_section_data.get_symbols())
    SYMBOL_DATA_OFFSET = export_section_data.get_entry_offset() + \
        SECTION_EXPORT_DEFAULT_SIZE
    SYMBOL_NAME_OFFSET = SYMBOL_DATA_OFFSET + \
        (2*DWORD_SIZE + WORD_SIZE)*(SYMBOLS_LEN)
    SYMBOL_NAME_OFFSET = SYMBOL_NAME_OFFSET + OFFSET_ORDINAL_STR

    export_section_data_size = SYMBOL_NAME_OFFSET
    for symbol in export_section_data.get_symbols():
        symbol_name = __symbol_name_encode(symbol.get_name())
        export_section_data_size = export_section_data_size + len(symbol_name)

    return export_section_data_size


def set_default_export_section(export_section_name, section_entry_offset=0):
    with pefile.PE(new_path) as pe:
        export_section = __get_section_by_name(pe, export_section_name)
        __set_directory_entry_export(pe, export_section, section_entry_offset)
        __set_default_entry_export_section(
            pe, export_section, section_entry_offset)

        pe.write(new_path)


def set_section_name(section_name_old, section_name_new):
    with pefile.PE(new_path) as pe:
        section = __get_section_by_name(pe, section_name_old)
        section.Name = section_name_new.encode()

        offset = section.get_file_offset()
        pe.set_bytes_at_offset(offset, section_name_new.encode())

        pe.write(new_path)


def set_export_section_size(export_section_name, export_section_data):
    delete_last_section()
    section_size = get_export_section_data_size(export_section_data)
    add_new_section(export_section_name, section_size)
    set_default_export_section(
        export_section_name, export_section_data.get_entry_offset())


def set_directory_entry_export_to_none():
    with pefile.PE(new_path) as pe:
        __set_directory_entry_export_to_none(pe)
        pe.write(new_path)


def delete_last_section():
    sec_numb = __ERROR
    sec_numb_offset = __ERROR

    size_of_image = __ERROR
    size_of_image_offset = __ERROR

    section_raw_size = __ERROR
    section_raw_address = __ERROR

    with pefile.PE(new_path) as pe:
        sec_numb = pe.FILE_HEADER.NumberOfSections - 1
        sec_numb_offset = pe.FILE_HEADER.get_field_absolute_offset(
            'NumberOfSections')

        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage - SECTION_VIRTUAL_ALIGN
        size_of_image_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset(
            'SizeOfImage')

        section_raw_size = pe.sections[-1].SizeOfRawData
        section_raw_address = pe.sections[-1].PointerToRawData

    data = __get_data_file(new_path)
    __set_word_at_data(data, sec_numb_offset, sec_numb)
    __set_dword_at_data(data, size_of_image_offset, size_of_image)
    __delete_bytes_at_data(data, section_raw_address, section_raw_size)
    __set_data_file(new_path, data)


def add_new_section(section_name, section_size=SECTION_EXPORT_DEFAULT_SIZE):
    sec_numb = __ERROR
    sec_numb_offset = __ERROR

    size_of_image = __ERROR
    size_of_image_offset = __ERROR

    section_offset = __ERROR
    section_virtual_size = section_size
    section_virtual_address = __ERROR
    section_raw_size = __minimum_multiple(section_size, SECTION_RAW_ALIGN)
    section_raw_address = __ERROR
    section_characteristics = SECTION_EXPORT_CHARACTERISTICS

    with pefile.PE(new_path) as pe:
        sec_numb = pe.FILE_HEADER.NumberOfSections + 1
        sec_numb_offset = pe.FILE_HEADER.get_field_absolute_offset(
            'NumberOfSections')

        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage + SECTION_VIRTUAL_ALIGN
        size_of_image_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset(
            'SizeOfImage')

        section_offset = pe.sections[-1].get_file_offset() + SECTION_SIZE
        section_virtual_address = pe.sections[-1].VirtualAddress + __minimum_multiple(
            pe.sections[-1].Misc_VirtualSize, SECTION_VIRTUAL_ALIGN)
        section_raw_address = pe.sections[-1].PointerToRawData + __minimum_multiple(
            pe.sections[-1].SizeOfRawData, SECTION_RAW_ALIGN)

    data = __get_data_file(new_path)
    __set_word_at_data(data, sec_numb_offset, sec_numb)
    __set_dword_at_data(data, size_of_image_offset, size_of_image)
    __add_bytes_null_at_data(data, section_raw_address, section_raw_size)

    __set_bytes_at_data(data, section_offset + 0x0,
                        __symbol_name_encode(section_name))
    __set_dword_at_data(data, section_offset + 0x8, section_virtual_size)
    __set_dword_at_data(data, section_offset + 0xC, section_virtual_address)
    __set_dword_at_data(data, section_offset + 0x10, section_raw_size)
    __set_dword_at_data(data, section_offset + 0x14, section_raw_address)
    __set_dword_at_data(data, section_offset + 0x24, section_characteristics)
    __set_data_file(new_path, data)


def add_symbols_export_section(export_section_name, symbols):
    entry_offset = DWORD_SIZE * len(symbols)
    export_section_data = get_export_section_data(export_section_name)

    export_section_data.set_entry_offset(
        export_section_data.get_entry_offset() + entry_offset)
    export_section_data.get_symbols().extend(symbols)

    set_directory_entry_export_to_none()
    set_export_section_size(export_section_name, export_section_data)

    with pefile.PE(new_path) as pe:
        export_section = __get_section_by_name(pe, export_section_name)
        export_section_data.set_section(export_section)
        __set_update_export_section_data(pe, export_section_data)
        pe.write(new_path)

    data = __get_data_file(new_path)
    __set_update_export_section_memory(export_section_data, data)
    __set_data_file(new_path, data)


# [================================]
# PRIVATE FUNCTIONS
# [================================]


def __minimum_multiple(val, mul):
    min = math.floor(val/mul) * mul
    if min < val:
        min += mul
    return min


def __get_state(value):
    if (value > __ERROR):
        return __OK
    else:
        return __ERROR


def __update_state(value):
    __state = __get_state(value)


def __check_state():
    if (__state == __OK):
        return
    print('ERROR: LOCAL STATE HAS ERROR VALUE!')
    exit()


def __check_value(value):
    __update_state(value)
    __check_state()


def __symbol_name_encode(symbol_name):
    if type(symbol_name) is bytes:
        return symbol_name + b'\x00'
    elif type(symbol_name) is str:
        return symbol_name.encode() + b'\x00'
    else:
        return None


def __get_export_symbols(pe, export_section, make_new=False):
    ls_symb = []

    if not (export_section == None):
        MIN_OFFSET = export_section.get_file_offset()
        MAX_OFFSET = pe.DIRECTORY_ENTRY_EXPORT.struct.get_file_offset()

    for symb in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        symbol = Symbol(symb.address, symb.ordinal, symb.name)
        if not (type(symbol.get_name()) == 'str'):
            symbol.set_name(symbol.get_name().decode())
        symbol.set_is_new(make_new)

        if not (export_section == None):
            raw_address = __get_virtual_to_raw_address(
                export_section, symbol.get_address())
            if (raw_address >= MIN_OFFSET) and (raw_address < MAX_OFFSET):
                data = __get_data_file(new_path)
                value = __get_dword_at_data(data, raw_address)
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

    offset = HEADER_FILE_EXPORT.get_file_offset()
    pe.set_dword_at_offset(offset, 0)
    offset = offset + DWORD_SIZE
    pe.set_dword_at_offset(offset, 0)


def __set_directory_entry_export_to_none(pe):
    HEADER_FILE_EXPORT = pe.OPTIONAL_HEADER.DATA_DIRECTORY[ENTRY_EXPORT]
    HEADER_FILE_EXPORT.VirtualAddress = 0
    HEADER_FILE_EXPORT.Size = 0

    pe.FILE_HEADER.NumberOfSymbols = 0
    pe.OPTIONAL_HEADER.CheckSum = 0

    offset = HEADER_FILE_EXPORT.get_file_offset()
    pe.set_dword_at_offset(offset, 0)
    offset = offset + DWORD_SIZE
    pe.set_dword_at_offset(offset, 0)


def __set_update_export_section_memory(export_section_data, file_data):
    for symbol in export_section_data.get_symbols():
        symbol_name = __symbol_name_encode(symbol.get_name())
        __set_dword_at_data(
            file_data, symbol.get_address_ptr(), symbol.get_address())
        __set_dword_at_data(
            file_data, symbol.get_name_rva_ptr(), symbol.get_name_rva())
        __set_dword_at_data(
            file_data, symbol.get_ordinal_ptr(), symbol.get_ordinal() - 1)
        __set_bytes_at_data(file_data, symbol.get_name_ptr(), symbol_name)
        if not (symbol.get_value() == None):
            __set_dword_at_data(
                file_data, symbol.get_value_ptr(), symbol.get_value())


def __set_update_export_section_data(pe, export_section_data):
    SYMBOL_DATA_START = __get_virtual_to_raw_address(
        export_section_data.get_section(), pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions)
    SYMBOL_VALUE_START = pe.DIRECTORY_ENTRY_EXPORT.struct.get_file_offset() - \
        export_section_data.get_entry_offset()
    SYMBOLS_LEN = len(export_section_data.get_symbols())
    START_ORDINAL_STR = SYMBOL_DATA_START + \
        (2*DWORD_SIZE + WORD_SIZE)*(SYMBOLS_LEN)

    pe.DIRECTORY_ENTRY_EXPORT.symbols.clear()

    start_address = {
        SYMBOL_FUNCTION: SYMBOL_DATA_START,
        SYMBOL_NAME_RVA: SYMBOL_DATA_START + DWORD_SIZE*(SYMBOLS_LEN),
        SYMBOL_ORDINAL: SYMBOL_DATA_START + 2*DWORD_SIZE*(SYMBOLS_LEN),
        SYMBOL_NAME_STR: START_ORDINAL_STR + OFFSET_ORDINAL_STR
    }

    start_data = {
        SYMBOL_ORDINAL: 1,
        SYMBOL_VALUE_PTR: SYMBOL_VALUE_START
    }

    for symbol in export_section_data.get_symbols():
        newSymbol = pefile.ExportData(
            ordinal=symbol.get_ordinal(),
            address=symbol.get_address(),
            name=symbol.get_name().encode()
        )

        __set_start_data_symbol(
            export_section_data.get_section(), start_data, symbol)
        __set_start_address_symbol(
            export_section_data.get_section(), start_address, symbol)
        __add_symbol_data_export_directory(pe)
        __add_symbol_data_file_header(pe)

        pe.DIRECTORY_ENTRY_EXPORT.symbols.append(newSymbol)


def __set_start_data_symbol(export_section, start_data, symbol):
    if symbol.get_ordinal() == -1:
        symbol.set_ordinal(start_data[SYMBOL_ORDINAL])

    if (symbol.get_address() == -1):
        symbol.set_address(__get_raw_to_virtual_address(
            export_section, start_data[SYMBOL_VALUE_PTR]))

    if not (symbol.get_value() == None):
        symbol.set_value_ptr(start_data[SYMBOL_VALUE_PTR])
        start_data[SYMBOL_VALUE_PTR] = start_data[SYMBOL_VALUE_PTR] + DWORD_SIZE

    start_data[SYMBOL_ORDINAL] = start_data[SYMBOL_ORDINAL] + 1


def __set_start_address_symbol(export_section, start_address, symbol):
    symbol_name = __symbol_name_encode(symbol.get_name())
    symbol.set_address_ptr(start_address[SYMBOL_FUNCTION])
    symbol.set_ordinal_ptr(start_address[SYMBOL_ORDINAL])
    symbol.set_name_rva_ptr(start_address[SYMBOL_NAME_RVA])
    symbol.set_name_ptr(start_address[SYMBOL_NAME_STR])

    symbol.set_name_rva(__get_raw_to_virtual_address(
        export_section, start_address[SYMBOL_NAME_STR]))

    start_address[SYMBOL_FUNCTION] = start_address[SYMBOL_FUNCTION] + DWORD_SIZE
    start_address[SYMBOL_NAME_RVA] = start_address[SYMBOL_NAME_RVA] + DWORD_SIZE
    start_address[SYMBOL_ORDINAL] = start_address[SYMBOL_ORDINAL] + WORD_SIZE
    start_address[SYMBOL_NAME_STR] = start_address[SYMBOL_NAME_STR] + \
        len(symbol_name)


def __add_symbol_data_export_directory(pe):
    pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions = pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions + 1
    pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames = pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames + 1
    pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames + DWORD_SIZE
    pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals + 2*DWORD_SIZE
    pe.DIRECTORY_ENTRY_EXPORT.struct.Name = pe.DIRECTORY_ENTRY_EXPORT.struct.Name + \
        2*DWORD_SIZE + WORD_SIZE


def __add_symbol_data_file_header(pe):
    pe.FILE_HEADER.NumberOfSymbols = pe.FILE_HEADER.NumberOfSymbols + 1
    offset = pe.FILE_HEADER.get_file_offset() + 2*WORD_SIZE + 2*DWORD_SIZE
    pe.set_dword_at_offset(offset, pe.FILE_HEADER.NumberOfSymbols)


# [================================]
# PRIVATE FUNCTIONS DATA
# [================================]


def __get_data_file(path):
    with open(path, '+br') as file:
        data = bytearray(file.read())
    return data


def __set_data_file(path, data):
    with open(path, '+bw') as file:
        file.write(data)


# [================================]
# PRIVATE FUNCTIONS MEMORY
# [================================]


def __get_byte_at_data(data, offset):
    offset = int(offset)
    if len(data) < offset + BYTE_SIZE:
        print(f'__get_byte_at_data error: offset is incorrect')
        return
    return data[offset]


def __get_word_at_data(data, offset):
    offset = int(offset)
    word = 0
    if len(data) < offset + WORD_SIZE:
        print(f'__get_word_at_data error: offset is incorrect')
        return
    for i in reversed(range(WORD_SIZE)):
        byte = data[offset + i]
        word = word * BYTE_MAX + byte
    return word


def __get_dword_at_data(data, offset):
    offset = int(offset)
    dword = 0
    if len(data) < offset + DWORD_SIZE:
        print(f'__get_dword_at_data error: offset is incorrect')
        return
    for i in reversed(range(DWORD_SIZE)):
        byte = data[offset + i]
        dword = dword * BYTE_MAX + byte
    return dword


def __get_qword_at_data(data, offset):
    offset = int(offset)
    qword = 0
    if len(data) < offset + QWORD_SIZE:
        print(f'__get_qword_at_data error: offset is incorrect')
        return
    for i in reversed(range(QWORD_SIZE)):
        byte = data[offset + i]
        qword = qword * BYTE_MAX + byte
    return qword


def __get_bytes_at_data(data, offset, length):
    offset = int(offset)
    length = int(length)
    if len(data) < length + offset:
        print(f'__get_bytes_at_data error: length and offset is incorrect')
        return
    return data[offset:(offset+length)]


def __set_byte_at_data(data, offset, byte):
    offset = int(offset)
    byte = int(byte)
    if (byte < 0) or (byte >= BYTE_MAX):
        print(f'__set_byte_at_data error: byte={byte} is incorrect')
        return
    if len(data) < offset + BYTE_SIZE:
        print(f'__set_byte_at_data error: offset is incorrect')
        return
    data[offset] = byte


def __set_word_at_data(data, offset, word):
    offset = int(offset)
    word = int(word)
    if (word < 0) or (word >= WORD_MAX):
        print(f'__set_word_at_data error: word={word} is incorrect')
        return
    if len(data) < offset + WORD_SIZE:
        print(f'__set_word_at_data error: offset is incorrect')
        return
    for i in range(WORD_SIZE):
        rest = int(word % BYTE_MAX)
        word = int((word - rest) / BYTE_MAX)
        data[offset + i] = rest


def __set_dword_at_data(data, offset, dword):
    offset = int(offset)
    dword = int(dword)
    if (dword < 0) or (dword >= DWORD_MAX):
        print(f'__set_dword_at_data error: dword={dword} is incorrect')
        return
    if len(data) < offset + DWORD_SIZE:
        print(f'__set_dword_at_data error: offset is incorrect')
        return
    for i in range(DWORD_SIZE):
        rest = int(dword % BYTE_MAX)
        dword = int((dword - rest) / BYTE_MAX)
        data[offset + i] = rest


def __set_qword_at_data(data, offset, qword):
    offset = int(offset)
    qword = int(qword)
    if (qword < 0) or (qword >= QWORD_MAX):
        print(f'__set_qword_at_data error: qword={qword} is incorrect')
        return
    if len(data) < offset + QWORD_SIZE:
        print(f'__set_qword_at_data error: offset is incorrect')
        return
    for i in range(QWORD_SIZE):
        rest = int(qword % BYTE_MAX)
        qword = int((qword - rest) / BYTE_MAX)
        data[offset + i] = rest


def __set_bytes_at_data(data, offset, bytes):
    offset = int(offset)
    if len(data) < len(bytes) + offset:
        print(f'__set_bytes_at_data error: length of bytes and offset is incorrect')
        return
    for i in range(len(bytes)):
        data[offset + i] = bytes[i]


def __add_byte_at_data(data, offset, byte):
    offset = int(offset)
    byte = int(byte)
    if (byte < 0) or (byte >= BYTE_MAX):
        print(f'__add_byte_at_data error: byte={byte} is incorrect')
        return
    data.insert(offset, byte)


def __add_word_at_data(data, offset, word):
    offset = int(offset)
    word = int(word)
    if (word < 0) or (word >= WORD_MAX):
        print(f'__add_word_at_data error: word={word} is incorrect')
        return
    for i in range(WORD_SIZE):
        rest = int(word % BYTE_MAX)
        word = int((word - rest) / BYTE_MAX)
        data.insert(offset + i, rest)


def __add_dword_at_data(data, offset, dword):
    offset = int(offset)
    dword = int(dword)
    if (dword < 0) or (dword >= DWORD_MAX):
        print(f'__add_dword_at_data error: dword={dword} is incorrect')
        return
    for i in range(DWORD_SIZE):
        rest = int(dword % BYTE_MAX)
        dword = int((dword - rest) / BYTE_MAX)
        data.insert(offset + i, rest)


def __add_qword_at_data(data, offset, qword):
    offset = int(offset)
    qword = int(qword)
    if (qword < 0) or (qword >= QWORD_MAX):
        print(f'__add_qword_at_data error: qword={qword} is incorrect')
        return
    for i in range(QWORD_SIZE):
        rest = int(qword % BYTE_MAX)
        qword = int((qword - rest) / BYTE_MAX)
        data.insert(offset + i, rest)


def __add_bytes_at_data(data, offset, bytes):
    offset = int(offset)
    for i in range(len(bytes)):
        data.insert(offset + i, bytes[i])


def __add_bytes_null_at_data(data, offset, length):
    offset = int(offset)
    for i in range(length):
        data.insert(offset + i, BYTE_NULL)


def __delete_byte_at_data(data, offset):
    offset = int(offset)
    if len(data) < offset + BYTE_SIZE:
        print(f'__delete_byte_at_data error: offset is incorrect')
        return
    del data[offset]


def __delete_word_at_data(data, offset):
    offset = int(offset)
    word = 0
    if len(data) < offset + WORD_SIZE:
        print(f'__delete_word_at_data error: offset is incorrect')
        return
    for i in reversed(range(WORD_SIZE)):
        del data[offset + i]


def __delete_dword_at_data(data, offset):
    offset = int(offset)
    dword = 0
    if len(data) < offset + DWORD_SIZE:
        print(f'__delete_dword_at_data error: offset is incorrect')
        return
    for i in reversed(range(DWORD_SIZE)):
        del data[offset + i]


def __delete_qword_at_data(data, offset):
    offset = int(offset)
    qword = 0
    if len(data) < offset + QWORD_SIZE:
        print(f'__delete_qword_at_data error: offset is incorrect')
        return
    for i in reversed(range(QWORD_SIZE)):
        del data[offset + i]


def __delete_bytes_at_data(data, offset, length):
    offset = int(offset)
    length = int(length)
    if len(data) < length + offset:
        print(f'__delete_bytes_at_data error: length and offset is incorrect')
        return
    del data[offset:(offset+length)]
