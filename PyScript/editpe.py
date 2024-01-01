import sys
import pelib
import time

if len(sys.argv) == 1:
    print("type \"editpe --help\"")
    exit()
elif sys.argv[1] == "--help":
    print("""EditPE Python Script!!!
arg1 = input_file
arg2 = output_file
arg3... = symbol_data
symbol_data = \"simbol_name,symbol_value\" or
\"simbol_name;symbol_value\" or \"simbol_name:symbol_value\"""")
    exit()


SLEEP_TIME = 0.75
edit_path = sys.argv[1]
new_path = sys.argv[2]
str_symbol_list = sys.argv[3:]
current_symbols = []


time.sleep(SLEEP_TIME)
pelib.init(edit_path, new_path)

if not (pelib.check_last_section(pelib.SECTION_EXPORT_NAME)):
    if pelib.check_section(pelib.SECTION_EXPORT_NAME):
        current_symbols = pelib.get_export_symbols(True)
        pelib.set_section_name(pelib.SECTION_EXPORT_NAME,
                               pelib.SECTION_EXPORT_NAME+'o')

    pelib.create_last_section(pelib.SECTION_EXPORT_NAME)
    pelib.set_default_export_section(pelib.SECTION_EXPORT_NAME)

current_symbols.extend(pelib.get_new_symbols(str_symbol_list))
pelib.add_symbols_export_section(pelib.SECTION_EXPORT_NAME, current_symbols)

for current_symbol in pelib.get_export_symbols(pelib.SECTION_EXPORT_NAME):
    name = current_symbol.get_name()
    value = current_symbol.get_value()
    if not (value == None):
        value = hex(value)
    print(f"{name}: {value}")

time.sleep(SLEEP_TIME)
