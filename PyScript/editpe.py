import sys
import pelib


edit_path = sys.argv[1]
new_path = sys.argv[2]
symbols = sys.argv[3:]


current_symbols = None
pelib.init(edit_path, new_path)
if not (pelib.check_last_section(pelib.SECTION_EXPORT_NAME)):
    if pelib.check_section(pelib.SECTION_EXPORT_NAME):
        current_symbols = pelib.get_export_symbols()
        pelib.set_section_name(pelib.SECTION_EXPORT_NAME,
                               pelib.SECTION_EXPORT_NAME+'o')

    pelib.add_new_section(pelib.SECTION_EXPORT_NAME)
    pelib.set_export_section(pelib.SECTION_EXPORT_NAME)

if not (current_symbols == None):
    pelib.add_symbols_export_section(
        pelib.SECTION_EXPORT_NAME, current_symbols)

pelib.add_symbols_export_section(
    pelib.SECTION_EXPORT_NAME, pelib.get_new_symbols(symbols))
