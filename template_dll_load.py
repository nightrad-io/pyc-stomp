#stolen from xcancel.com/cvancooten
froms sys import argv
import ctypes
result = ctypes.WinDLL(argv[1])
result.update()
