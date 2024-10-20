# Copyright (c) YOUWILLDIE666.
# Licensed under the GPL-3.0 license. See LICENSE.txt file for full license information.

########################################################################
#  main.py - dumps offsets based on the address of the first function  #
########################################################################


import idautils, idaapi, idc
import tkinter as tk
from tkinter import filedialog
import os

# Constants
COMMENT_HEADER = "/*\n * Base Address: {}\n */\n"
BASE_ADDRESS = None
for func in idautils.Functions():
    BASE_ADDRESS = func
    break

def write_header(file, base_name, is_header, is_header_pp): # i know this looks strange
    if is_header:
        file.write(f"#ifndef {base_name}_H\n#define {base_name}_H\n\n")
    elif is_header_pp:
        file.write("#pragma once\n\n")
    file.write("#include <stdint.h>\n\n")
    file.write("const static uint32_t function_offsets[] = {\n")

def write_offsets(file, ea_list, comment_prefix):
    for ea in ea_list:
        name = idc.get_func_name(ea) if comment_prefix == 'function' else idc.get_name(ea)
        offset = ea - BASE_ADDRESS
        if offset > 0 and offset < 0x7fffffff and name != None: # or 0xffffff i don't really know
            file.write(f"    {hex(offset)}, // {name}\n")

def write_data_offsets(file):
    file.write("const static uint32_t data_offsets[] = {\n")
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg and seg.type == idaapi.SEG_DATA:
            write_offsets(file, idautils.DataRefsFrom(seg_ea), 'data')
            for item_ea, item_name in idautils.Names():
                if seg.start_ea <= item_ea < seg.end_ea:
                    write_offsets(file, [item_ea], 'data')
    file.write("};\n")

def dump_offsets(filename):
    base_name = os.path.splitext(os.path.basename(filename))[0].replace(' ', '_').upper()
    file_ext = filename.split('.')[-1]

    is_header = file_ext in {'h', 'hpp'}
    is_header_pp = file_ext == 'hpp'
    is_cpp = file_ext in {'cpp', 'cxx', 'cc', 'c++'}

    if not (is_header or is_cpp or is_header_pp):
        print("Unsupported file extension. Defaulting to C++")
        is_cpp = True

    with open(filename, 'w') as file:
        file.write(COMMENT_HEADER.format(BASE_ADDRESS))
        write_header(file, base_name, is_header, is_header_pp)
        write_offsets(file, idautils.Functions(), 'function')
        file.write("};\n\n")
        write_data_offsets(file)
        if is_header:
            file.write(f"\n#endif // {base_name}_H")

def select_file() -> str:
    root = tk.Tk()
    root.withdraw()
    return filedialog.asksaveasfilename(
        defaultextension=".cpp",
        filetypes=[("C++ Files", ("*.cpp", "*.hpp")), ("C Files", ("*.c", ".h")), ("All Files", "*.*")]
    )

output_file = select_file()

if output_file:
    dump_offsets(output_file)
    print(f"Offsets have been written to {output_file}")
else:
    print("No file selected. Offsets not written.")