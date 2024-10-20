# Copyright (c) YOUWILLDIE666.
# Licensed under the GPL-3.0 license. See LICENSE.txt file in the project root for full license information.

########################################################################
#  main.py - dumps offsets based on the address of the first function  #
########################################################################

# P.S. I won't switch to PyQt (at least for now)

import idautils, idaapi, idc
import tkinter as tk
from tkinter import filedialog # ???
import os

# Constants
COMMENT_HEADER = "/*\n * Base Address: {}\n */\n"
BASE_ADDRESS = idaapi.get_imagebase()

def write_header(file, base_name, is_header_int):
    hstr_map = {
        1: f"#ifndef {base_name}_H\n#define {base_name}_H\n\n",
        2: "#pragma once\n\n"
    }
    hstr = hstr_map.get(is_header_int, "")
    file.write(hstr)
    file.write("#include <stdint.h>\n\n")
    file.write("const static uint32_t function_offsets[] = {\n")

def write_offsets(file, ea_list, comment_prefix):
    for ea in ea_list:
        name = idc.get_func_name(ea) if comment_prefix == 'function' else idc.get_name(ea)
        offset = ea - BASE_ADDRESS
        if offset > 0 and name:
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
    h_map = {
        'h': 1,
        'hpp': 2
    }
    
    is_header_int = h_map.get(file_ext, 0)
    is_header_bool = file_ext in {'h', 'hpp'}
    is_cpp = file_ext in {'cpp', 'cxx', 'cc', 'c++'}

    if not (is_header_bool or is_cpp):
        print("Unsupported file extension. Defaulting to C++")
        is_cpp = True

    try:
        with open(filename, 'w') as file:
            file.write(COMMENT_HEADER.format(hex(BASE_ADDRESS)))
            write_header(file, base_name, is_header_int)
            write_offsets(file, idautils.Functions(), 'function')
            file.write("};\n\n")
            write_data_offsets(file)
            if is_header_bool:
                file.write(f"\n#endif // {base_name}_H")
    except Exception as e:
        print(e)

def select_file() -> str:
    root = tk.Tk()
    root.withdraw()
    return filedialog.asksaveasfilename(
        defaultextension=".cpp",
        filetypes=[
            ("C++ Files", ("*.cpp", "*.cxx", "*.c++", "*.cc", "*.hpp", "*.hxx", "*.h++", "*.hh")),
            ("C Files", ("*.c", ".h")),
            ("All Files", "*.*")
        ]
    )

if __name__ == "__main__":
    output_file = select_file()

    if output_file:
        dump_offsets(output_file)
        print(f"Offsets have been dumped to {output_file}")
    else:
        print("No file selected. Offsets not dumped.")