package winapi

/*
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <windows.h>
#include <synchapi.h>
#include <string.h>

HANDLE readPipe;
HANDLE writePipe;
HANDLE hConOut;
HANDLE hStdout;
BOOL neededConsole;

FILE* in;
FILE* out;
FILE* err;

BOOL CreateConsole() {
    neededConsole = AllocConsole();
    if (neededConsole) {
        freopen_s(&in, "CONOUT$", "w", stdout);
        freopen_s(&out, "CONOUT$", "w", stderr);
        freopen_s(&err, "CONIN$", "r", stdin);
        HANDLE hConOut = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        HANDLE hConIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
        SetStdHandle(STD_ERROR_HANDLE, hConOut);
        SetStdHandle(STD_INPUT_HANDLE, hConIn);
        printf("CONSOLE ALLOCED TEST!\n");
        return TRUE;
    }
    return FALSE;
}

BOOL DeleteConsole() {
    // we dont close stderr handle because its pointing to stdout.
    CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
    CloseHandle(GetStdHandle(STD_INPUT_HANDLE));
    _close(_fileno(in));
    _close(_fileno(out));
    _close(_fileno(err));
    FreeConsole();
    return TRUE;
}

int CaptureStdoutReturnPipeFD() {
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    SECURITY_ATTRIBUTES sa = { sizeof(sa),NULL,TRUE };
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        fprintf(stderr, "Failed to create pipe\n");
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)writePipe, O_WRONLY | _O_TEXT);
    _dup2(fd, _fileno(stdout));
    return fd;
}

void t() {
    printf("HELLO\n");
}

char* GetStdoutGuiProcess(VOID* addressOfEntryPoint) {
    CreateConsole();
    printf("Hit Enter!\n");
    // save stdout
    int ogStdOut = _dup(_fileno(stdout));
    int pipeFD = CaptureStdoutReturnPipeFD();
    // code needs to run here
    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)addressOfEntryPoint, 0, 0, NULL);
	Sleep(5000);
    //WaitForSingleObject(hThread, INFINITE);
    fflush(stdout);
    /// READ FROM PIPE
    CloseHandle(writePipe);
    char* buffer = (char*)malloc(sizeof(char) * 301);
    char tmpBuffer[300];
    DWORD read = 0;
    BOOL success = FALSE;
    DWORD outputSz = 0;
    DWORD chunkSz = 300;
    while (1) {
        success = ReadFile(readPipe, tmpBuffer, chunkSz, &read, NULL);
        if (!success || !read)
            break;
        memcpy(buffer + outputSz, tmpBuffer, read);
        outputSz += read;
        if (read == chunkSz) {
            buffer = (char*)realloc(buffer, outputSz + chunkSz);
        }
        else {
            memset(buffer + outputSz, 0, 1); // set null
            break;
        }
    }
    // close handles
    CloseHandle(readPipe); // -> dont need to call _close(pipeFd)
    // close original stdout
    _dup2(ogStdOut, _fileno(stdout));
    _close(ogStdOut);
    DeleteConsole();
    return buffer;
}
*/
