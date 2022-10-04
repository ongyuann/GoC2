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

void ReAttachStdout(){
	AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
	freopen("CONIN$", "r", stdin);
}

int SaveStdout() {
    return _dup(_fileno(stdout));
}

int CaptureStdout() {
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	SECURITY_ATTRIBUTES sa = {sizeof(sa),NULL,TRUE};
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        fprintf(stderr, "Failed to create pipe\n");
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)writePipe, O_WRONLY | _O_TEXT);
    _dup2(fd, _fileno(stdout));
	//setvbuf(stdout,NULL,_IONBF,0);
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
///////////////////////////////////


#define BUFFER_SIZE 1024
#define _WAIT_TIMEOUT 5000

BOOL create_pipe(HANDLE* pipeRead, HANDLE* pipeWrite) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa),NULL,TRUE };
    return CreatePipe(pipeRead, pipeWrite, &sa, 0);
}

void redirect_io(FILE* hFrom, HANDLE hTo) {
    int fd = _open_osfhandle((intptr_t)hTo, _O_TEXT);
    _dup2(fd, _fileno(hFrom));
    setvbuf(hFrom, NULL, _IONBF, 0); //Disable buffering.
}

void restore_io(int stdoutFd, int stderrFd) {
    _dup2(stdoutFd, _fileno(stdout));
    _dup2(stderrFd, _fileno(stderr));
}

DWORD WINAPI hello_world(LPVOID lpParam) {
    puts("Hello World!\n");
    perror("Welp\n");
    for (int i = 0; i < 1024; i++) {
        printf("%d - ", i);
    }

    return 0;
}

BOOL createPipe(HANDLE* pipeRead, HANDLE* pipeWrite) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    return CreatePipe(pipeRead, pipeWrite, &sa, 0);
}

void redirectIO(FILE* hFrom, HANDLE hTo) {
    int fd = _open_osfhandle((intptr_t)hTo, _O_TEXT);
    _dup2(fd, _fileno(hFrom));
    setvbuf(hFrom, NULL, _IONBF, 0); //Disable buffering.
}

void restoreIO(int stdoutFd, int stderrFd, HANDLE stdoutHandle, HANDLE stderrHandle) {
    _dup2(stdoutFd, _fileno(stdout));
    _dup2(stderrFd, _fileno(stderr));
    SetStdHandle(STD_OUTPUT_HANDLE, stdoutHandle);
    SetStdHandle(STD_ERROR_HANDLE, stderrHandle);
}

BOOL createConsole() {
    if (!AllocConsole()) {
        return FALSE;
    }
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);

    HANDLE hConOut = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
    SetStdHandle(STD_ERROR_HANDLE, hConOut);
    return TRUE;
}

DWORD WINAPI helloWorld(LPVOID lpParam) {
    puts("Hello World!\n");
    return 0;
}


#define BUFFER_SIZE 1024
#define _WAIT_TIMEOUT 5000
#define ARRAY_MODULES_SIZE 128
#define NT_FAIL(status) (status < 0)

char* doit() {
    HANDLE stdoutHandle = INVALID_HANDLE_VALUE;
    HANDLE stderrHandle = INVALID_HANDLE_VALUE;
    HANDLE pipeReadOutput = INVALID_HANDLE_VALUE;
    HANDLE pipeWriteOutput = INVALID_HANDLE_VALUE;
    HANDLE pipeReadError = INVALID_HANDLE_VALUE;
    HANDLE pipeWriteError = INVALID_HANDLE_VALUE;
    int stdoutFd = -1;
    int stderrFd = -1;
    int readResult = -1;
    DWORD waitResult = -1;
    BOOL isThreadFinished = FALSE;
    BOOL wasConsoleCreated = FALSE;
    unsigned char recvBuffer[BUFFER_SIZE];
    DWORD bytesRead = 0;
    DWORD remainingDataOutput = 0;
    DWORD remainingDataError = 0;
    DWORD cbNeeded = -1;
    HMODULE loadedModules[ARRAY_MODULES_SIZE * sizeof(HMODULE)];


    wasConsoleCreated = createConsole();
    stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    stderrHandle = GetStdHandle(STD_ERROR_HANDLE);
    stdoutFd = _dup(_fileno(stdout));
    stderrFd = _dup(_fileno(stderr));
    if (!wasConsoleCreated) {
        printf("No console\n");
        helloWorld(0);
        return 0;
    }
    createPipe(&pipeReadOutput, &pipeWriteOutput);
    createPipe(&pipeReadError, &pipeWriteError);
    redirectIO(stdout, pipeWriteOutput);
    redirectIO(stderr, pipeWriteError);

    DWORD dwThreadId = -1;
    HANDLE hThread = CreateThread(
        NULL,
        0,
        helloWorld,
        NULL,
        0,
        &dwThreadId);

    WaitForSingleObject(hThread, INFINITE);
    char* buffer = (char*)malloc(sizeof(char) * 301);
    char tmpBuffer[300];
    DWORD read = 0;
    BOOL success = FALSE;
    DWORD outputSz = 0;
    DWORD chunkSz = 300;
    while (1) {
        success = ReadFile(pipeReadOutput, tmpBuffer, chunkSz, &read, NULL);
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
    restoreIO(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
    if (wasConsoleCreated) {
        CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
        CloseHandle(GetStdHandle(STD_ERROR_HANDLE));
		CloseHandle(pipeWriteOutput);
		CloseHandle(pipeReadOutput);
		CloseHandle(pipeWriteError);
		CloseHandle(pipeReadError);
        FreeConsole();
		return buffer;
    }
    CloseHandle(pipeWriteOutput);
    CloseHandle(pipeReadOutput);
    CloseHandle(pipeWriteError);
    CloseHandle(pipeReadError);
    return buffer;
}






*/
import "C"
import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Test() string {
	var b *C.char = C.doit()
	result := C.GoString(b)
	C.free(unsafe.Pointer(b))
	return result
}

func ReAttachStdout() {
	C.ReAttachStdout()
}

func CaptureStdout() (int, int) {
	//C.ReAttachStdout()
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

func InitConsoleHandles() error {
	// Retrieve standard handles.
	hIn, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return errors.New("Failed to retrieve standard input handler.")
	}
	hOut, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return errors.New("Failed to retrieve standard output handler.")
	}
	hErr, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if err != nil {
		return errors.New("Failed to retrieve standard error handler.")
	}

	// Wrap handles in files. /dev/ prefix just to make it conventional.
	stdInF := os.NewFile(uintptr(hIn), "/dev/stdin")
	if stdInF == nil {
		return errors.New("Failed to create a new file for standard input.")
	}
	stdOutF := os.NewFile(uintptr(hOut), "/dev/stdout")
	if stdOutF == nil {
		return errors.New("Failed to create a new file for standard output.")
	}
	stdErrF := os.NewFile(uintptr(hErr), "/dev/stderr")
	if stdErrF == nil {
		return errors.New("Failed to create a new file for standard error.")
	}

	// Set handles for standard input, output and error devices.
	err = windows.SetStdHandle(windows.STD_INPUT_HANDLE, windows.Handle(stdInF.Fd()))
	if err != nil {
		return errors.New("Failed to set standard input handler.")
	}
	err = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(stdOutF.Fd()))
	if err != nil {
		return errors.New("Failed to set standard output handler.")
	}
	err = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(stdErrF.Fd()))
	if err != nil {
		return errors.New("Failed to set standard error handler.")
	}

	// Update golang standard IO file descriptors.
	os.Stdin = stdInF
	os.Stdout = stdOutF
	os.Stderr = stdErrF

	return nil
}
