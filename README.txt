IDA plugin that dumps offsets of functions/data into a C/C++ file
Tested on: IDA Pro 9.0
---
Usage:
1. Disassemble a file
2. Wait for the initial auto-analysis to finish
3. Press `File>Script file...` or hold Alt and press F two times
4. Select main.py
5. Set the output file
6. Done
---
NOTE: this plugin is designed to work with MetaPC,
      this means you could get wrong addresses if
      you choose another processor type
      (maybe I'll do something with it)