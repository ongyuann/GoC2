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

int t() {
    printf("HELLO!\n");
    return 0;
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
        return TRUE;
    }
    return FALSE;
}

char* RevertStdoutGUI(int ogStdOut) {
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


int CaptureStdoutReturnPipeFD() {
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    SECURITY_ATTRIBUTES sa = { sizeof(sa),NULL,TRUE };
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)writePipe, O_WRONLY | _O_TEXT);
    _dup2(fd, _fileno(stdout));
    return fd;
}

char* GetStdoutConsoleProcess(VOID* addressOfEntryPoint){
    HANDLE readPipe;
    HANDLE writePipe;
    HANDLE hConOut;
    HANDLE hStdout;
    BOOL neededConsole;
    FILE* in;
    FILE* out;
    FILE* err;
    int ogStdOut = _dup(_fileno(stdout));
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	SECURITY_ATTRIBUTES sa = {sizeof(sa),NULL,TRUE};
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        return -1;
    }
    int pipeFd = _open_osfhandle((intptr_t)writePipe, O_WRONLY | _O_TEXT);
    _dup2(pipeFd, _fileno(stdout));
        HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)addressOfEntryPoint, 0, 0, NULL);
    if (hThread == NULL){
        return NULL;
    }
    WaitForSingleObject(hThread,INFINITE);
    fflush(stdout);
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
    fflush(stdout);
    CloseHandle(readPipe);
    _dup2(ogStdOut, 1);
    return buffer;
}



char* GetStdoutGuiProcess(VOID* addressOfEntryPoint) {
    CreateConsole();
    // save stdout
    int ogStdOut = _dup(_fileno(stdout));
    int pipeFD = CaptureStdoutReturnPipeFD();
    // code needs to run here
    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)addressOfEntryPoint,0, 0, NULL);
    if (hThread == NULL){
        return NULL;
    }
    WaitForSingleObject(hThread, INFINITE);
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

/////////// code that doesnt need a console below
int SaveStdout() {
    return _dup(_fileno(stdout));
}

int CaptureStdout() {
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	SECURITY_ATTRIBUTES sa = {sizeof(sa),NULL,TRUE};
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)writePipe, O_WRONLY | _O_TEXT);
    _dup2(fd, _fileno(stdout));
    return fd;
}

void RevertStdout(int ogFD,int currentFD) {
    fflush(stdout);
    _close(currentFD);
    _dup2(ogFD, 1);
    _close(ogFD);
    return;
}

char* ReturnStdoutBuffer() {
    CloseHandle(writePipe);
    char* buffer = (char*)malloc(sizeof(char)*301);
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
    CloseHandle(readPipe);
    return buffer;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func ExecuteFunctionSaveOutputGUI(entry unsafe.Pointer) (string, error) {
	var stdoutBuffer *C.char = C.GetStdoutGuiProcess(entry)
	if stdoutBuffer == nil {
		return "", fmt.Errorf("didnt work")
	}
	result := C.GoString(stdoutBuffer)
	C.free(unsafe.Pointer(stdoutBuffer))
	return result, nil

}

func ExecuteFunctionSaveOutputConsole(entry unsafe.Pointer) (string, error) {
	/*old, new := CaptureStdout()
	hThread, err := CreateThread(0, 0, uintptr(entry), 0, 0, nil)
	if err != nil {
		return "", err
	}
	windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
	RevertStdout(old, new)
	stdoutBuffer := GetStdoutBuffer()
	*/
	var stdoutBuffer *C.char = C.GetStdoutConsoleProcess(entry)
	result := C.GoString(stdoutBuffer)
	C.free(unsafe.Pointer(stdoutBuffer))
	return result, nil
}

func CaptureStdout() (int, int) {
	ogStdout := C.SaveStdout()
	newStdout := C.CaptureStdout()
	return int(ogStdout), int(newStdout)
}

func RevertStdout(og, new int) {
	ogStdout := C.int(og)
	newStdout := C.int(new)
	C.RevertStdout(ogStdout, newStdout)
}

func GetStdoutBuffer() string {
	var stdoutBuffer *C.char = C.ReturnStdoutBuffer()
	result := C.GoString(stdoutBuffer)
	C.free(unsafe.Pointer(stdoutBuffer))
	return result
}
