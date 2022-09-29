package enumhandles

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

// DUPLICATE_SAME_ACCESS = (0x00000002)
//#define SystemHandleInformation 16
//#define ObjectBasicInformation 0
//#define ObjectNameInformation 1
//#define ObjectTypeInformation 2

const (
	ObjectTypeInformation   = 2
	SystemHandleInformation = 16
	ObjectBasicInformation  = 0
	ObjectNameInformation   = 1
)

func GetHandles() (string, error) {
	// get all handles
	var results string
	var handleInfoSize = uint32(0x1000)
	hHeap, err := winapi.HeapCreate(0, handleInfoSize*4, 0)
	if err != nil {
		return "", err
	}
	handleInfo, err := winapi.HeapAlloc(syscall.Handle(hHeap), 0x8, handleInfoSize)
	if err != nil {
		return "", err
	}
	for {
		ntstatus := winapi.NtQuerySystemInformation(16, (*byte)(unsafe.Pointer(handleInfo)), handleInfoSize, nil)
		if ntstatus == 0xC0000004 {
			// realloc
			handleInfoSize *= 2
			handleInfo, err = winapi.HeapReAlloc(syscall.Handle(hHeap), 0x8, handleInfo, handleInfoSize)
			if handleInfo == 0 {
				return "", err
			}
		} else {
			break
		}
	}
	// should have enough memory now.
	handleInformation := (*winapi.SystemHandleInformationT)(unsafe.Pointer(handleInfo))
	handle := handleInformation.Handles[0]
	handleAddress := uintptr(unsafe.Pointer(&handleInformation.Handles[0]))
	var dupeHandle uintptr
	var hProcess syscall.Handle
	for i := 0; i < int(handleInformation.Count); i++ {
		// will need to increase handleInformation.Handles address by size of struct
		//fmt.Printf("Handle Pid %d\n", handle.UniqueProcessId)
		hProcess, err = winapi.OpenProcess(windows.PROCESS_DUP_HANDLE|syscall.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, 0, uint32(handle.UniqueProcessId))
		if err != nil {
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		if ntsuccess := winapi.NtDuplicateObject(uintptr(hProcess), uintptr(handle.HandleValue), uintptr(winapi.GetCurrentProcess()), &dupeHandle, 0, 0, winapi.DUPLICATE_SAME_ACCESS); ntsuccess != 0 {
			windows.CloseHandle(windows.Handle(dupeHandle))
			windows.CloseHandle(windows.Handle(hProcess))
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		//query object type
		objectTypeInfo, err := winapi.HeapAlloc(syscall.Handle(hHeap), 0x8, 0x1000)
		if err != nil {
			windows.CloseHandle(windows.Handle(dupeHandle))
			windows.CloseHandle(windows.Handle(hProcess))
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		if ntsuccess := winapi.NtQueryObject(dupeHandle, ObjectTypeInformation, (*byte)(unsafe.Pointer(objectTypeInfo)), 0x1000, nil); ntsuccess != 0 {
			windows.CloseHandle(windows.Handle(dupeHandle))
			windows.CloseHandle(windows.Handle(hProcess))
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		objectTypeInformation := (*winapi.ObjectTypeInformationT)(unsafe.Pointer(objectTypeInfo))
		if !FilterObjectTypes(objectTypeInformation.TypeName.Buffer) {
			windows.CloseHandle(windows.Handle(dupeHandle))
			windows.CloseHandle(windows.Handle(hProcess))
			winapi.HeapFree(hHeap, 0, objectTypeInfo)
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		if handle.GrantedAccess == 0x0012019f {
			windows.CloseHandle(windows.Handle(dupeHandle))
			windows.CloseHandle(windows.Handle(hProcess))
			winapi.HeapFree(hHeap, 0, objectTypeInfo)
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		if fileType, _ := windows.GetFileType(windows.Handle(dupeHandle)); fileType == windows.FILE_TYPE_PIPE {
			windows.CloseHandle(windows.Handle(dupeHandle))
			windows.CloseHandle(windows.Handle(hProcess))
			winapi.HeapFree(hHeap, 0, objectTypeInfo)
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		objectNameInfo, err := winapi.HeapAlloc(syscall.Handle(hHeap), 0x8, 0x1000)
		if err != nil {
			windows.CloseHandle(windows.Handle(dupeHandle))
			windows.CloseHandle(windows.Handle(hProcess))
			winapi.HeapFree(hHeap, 0, objectTypeInfo)
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		//////////////////////
		var returnLength uint32
		result := winapi.NtQueryObject(dupeHandle, ObjectNameInformation, (*byte)(unsafe.Pointer(objectNameInfo)), 0x1000, &returnLength)
		//fmt.Printf("result -> %x %d\n", result, returnLength)
		if result != 0 {
			objectNameInfo, err = winapi.HeapReAlloc(syscall.Handle(hHeap), 0x8, objectNameInfo, returnLength)
			if err != nil {
				windows.CloseHandle(windows.Handle(dupeHandle))
				windows.CloseHandle(windows.Handle(hProcess))
				winapi.HeapFree(hHeap, 0, objectTypeInfo)
				handleAddress += 24                                                       // move pointer over by size of struct
				handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
				continue
			} else {
				if ntsuccess := winapi.NtQueryObject(dupeHandle, ObjectNameInformation, (*byte)(unsafe.Pointer(objectNameInfo)), returnLength, &returnLength); ntsuccess != 0 {
					pid, _ := windows.GetProcessId(windows.Handle(hProcess))
					typeName := windows.UTF16PtrToString(objectTypeInformation.TypeName.Buffer)
					results += fmt.Sprintf("PID: %d VALUE: 0x%x HANDLE OBJECT: %x ACCESS: 0x%x TYPE: %s OBJECT NAME: ??? TPID: ??? TEXE: ???\n", pid, handle.HandleValue, handle.Object, handle.GrantedAccess, typeName)
					winapi.HeapFree(hHeap, 0, objectNameInfo)
					winapi.HeapFree(hHeap, 0, objectTypeInfo)
					windows.CloseHandle(windows.Handle(dupeHandle))
					windows.CloseHandle(windows.Handle(hProcess))
					handleAddress += 24                                                       // move pointer over by size of struct
					handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
					continue
				}
			}
		}
		//fmt.Printf("GOT TO OBJECT NAME SECTION\n!")
		// cast buffer to unicode string
		objectName := (*winapi.UnicodeString)(unsafe.Pointer(objectNameInfo))
		// check if its a file type and weed out .dll files
		// here we check what type it is to get process handle or thread handle
		exeName := make([]uint16, windows.MAX_PATH)
		err = windows.GetModuleBaseName(windows.Handle(hProcess), 0, &exeName[0], windows.MAX_PATH)
		if err != nil {
			winapi.HeapFree(hHeap, 0, objectTypeInfo)
			winapi.HeapFree(hHeap, 0, objectNameInfo)
			windows.CloseHandle(windows.Handle(dupeHandle))
			windows.CloseHandle(windows.Handle(hProcess))
			handleAddress += 24                                                       // move pointer over by size of struct
			handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
			continue
		}
		typeName := windows.UTF16PtrToString(objectTypeInformation.TypeName.Buffer)
		if typeName == "File" {
			if !FilterFiles(objectName.Buffer) {
				// skipping dlls
				winapi.HeapFree(hHeap, 0, objectTypeInfo)
				winapi.HeapFree(hHeap, 0, objectNameInfo)
				windows.CloseHandle(windows.Handle(dupeHandle))
				windows.CloseHandle(windows.Handle(hProcess))
				handleAddress += 24                                                       // move pointer over by size of struct
				handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
				continue
			}
		}
		exeNameStr := windows.UTF16PtrToString(&exeName[0])
		var targetPid uint32
		targetPidPtr := make([]uint16, windows.MAX_PATH)
		var targetPidStr string = "???"
		pid, _ := windows.GetProcessId(windows.Handle(hProcess))
		//////////////////////////////////
		if typeName == "Process" {
			targetPid, _ = windows.GetProcessId(windows.Handle(dupeHandle))
			// handle to own process skipping.
			if targetPid == pid {
				winapi.HeapFree(hHeap, 0, objectTypeInfo)
				winapi.HeapFree(hHeap, 0, objectNameInfo)
				windows.CloseHandle(windows.Handle(dupeHandle))
				windows.CloseHandle(windows.Handle(hProcess))
				handleAddress += 24                                                       // move pointer over by size of struct
				handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
				continue
			}
			// only check for full access
			if handle.GrantedAccess != 0x1fffff {
				winapi.HeapFree(hHeap, 0, objectTypeInfo)
				winapi.HeapFree(hHeap, 0, objectNameInfo)
				windows.CloseHandle(windows.Handle(dupeHandle))
				windows.CloseHandle(windows.Handle(hProcess))
				handleAddress += 24                                                       // move pointer over by size of struct
				handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
				continue
			}
			if ok := winapi.GetProcessImageFileNameW(dupeHandle, &targetPidPtr[0], windows.MAX_PATH); ok != 0 {
				trimmed := winapi.PathFindFileNameW(&targetPidPtr[0])
				targetPidStr = windows.UTF16PtrToString(trimmed)
				if strings.ToLower(targetPidStr) == strings.ToLower(exeNameStr) {
					winapi.HeapFree(hHeap, 0, objectTypeInfo)
					winapi.HeapFree(hHeap, 0, objectNameInfo)
					windows.CloseHandle(windows.Handle(dupeHandle))
					windows.CloseHandle(windows.Handle(hProcess))
					handleAddress += 24                                                       // move pointer over by size of struct
					handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
					continue
				}
			}
		}
		if typeName == "Thread" {
			targetPid = winapi.GetProcessIdOfThread(dupeHandle)
			// handle to own process skipping.
			if targetPid == pid {
				winapi.HeapFree(hHeap, 0, objectTypeInfo)
				winapi.HeapFree(hHeap, 0, objectNameInfo)
				windows.CloseHandle(windows.Handle(dupeHandle))
				windows.CloseHandle(windows.Handle(hProcess))
				handleAddress += 24                                                       // move pointer over by size of struct
				handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
				continue
			}
			// only check for full access
			if handle.GrantedAccess != 0x1fffff {
				winapi.HeapFree(hHeap, 0, objectTypeInfo)
				winapi.HeapFree(hHeap, 0, objectNameInfo)
				windows.CloseHandle(windows.Handle(dupeHandle))
				windows.CloseHandle(windows.Handle(hProcess))
				handleAddress += 24                                                       // move pointer over by size of struct
				handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
				continue
			}
			tmpProc, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION, false, targetPid)
			if err != nil {
				winapi.HeapFree(hHeap, 0, objectTypeInfo)
				winapi.HeapFree(hHeap, 0, objectNameInfo)
				windows.CloseHandle(windows.Handle(dupeHandle))
				windows.CloseHandle(windows.Handle(hProcess))
				handleAddress += 24                                                       // move pointer over by size of struct
				handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
				continue
			} else {
				if ok := winapi.GetProcessImageFileNameW(uintptr(tmpProc), &targetPidPtr[0], windows.MAX_PATH); ok != 0 {
					trimmed := winapi.PathFindFileNameW(&targetPidPtr[0])
					targetPidStr = windows.UTF16PtrToString(trimmed)
				}
				windows.CloseHandle(tmpProc)
				if strings.ToLower(targetPidStr) == strings.ToLower(exeNameStr) {
					winapi.HeapFree(hHeap, 0, objectTypeInfo)
					winapi.HeapFree(hHeap, 0, objectNameInfo)
					windows.CloseHandle(windows.Handle(dupeHandle))
					windows.CloseHandle(windows.Handle(hProcess))
					handleAddress += 24                                                       // move pointer over by size of struct
					handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
					continue
				}
			}
		}
		///////////////
		if objectName.Length > 0 {
			objName := windows.UTF16PtrToString(objectName.Buffer)
			if typeName == "Process" || typeName == "Thread" {
				results += fmt.Sprintf("PID: %d EXE: %s VALUE: 0x%x  ACCESS: 0x%x TYPE: %s OBJECT NAME: %s TPID: %d TEXE: %s\n", pid, exeNameStr, handle.HandleValue, handle.GrantedAccess, typeName, objName, targetPid, targetPidStr)
			} else {
				results += fmt.Sprintf("PID: %d EXE: %s VALUE: 0x%x  ACCESS: 0x%x TYPE: %s OBJECT NAME: %s \n", pid, exeNameStr, handle.HandleValue, handle.GrantedAccess, typeName, objName)
			}
		} else {
			if typeName == "Process" || typeName == "Thread" {
				results += fmt.Sprintf("PID: %d EXE: %s VALUE: 0x%x  ACCESS: 0x%x TYPE: %s TPID: %d TEXE: %s\n", pid, exeNameStr, handle.HandleValue, handle.GrantedAccess, typeName, targetPid, targetPidStr)
			} else {
				results += fmt.Sprintf("PID: %d EXE: %s VALUE: 0x%x  ACCESS: 0x%x TYPE: %s\n", pid, exeNameStr, handle.HandleValue, handle.GrantedAccess, typeName)
			}
		}
		winapi.HeapFree(hHeap, 0, objectTypeInfo)
		winapi.HeapFree(hHeap, 0, objectNameInfo)
		windows.CloseHandle(windows.Handle(dupeHandle))
		windows.CloseHandle(windows.Handle(hProcess))
		handleAddress += 24                                                       // move pointer over by size of struct
		handle = *(*winapi.SystemHandleTableEntry)(unsafe.Pointer(handleAddress)) // dereference pointer and copy data to handle
		// loop end
	}
	windows.CloseHandle(windows.Handle(dupeHandle))
	windows.CloseHandle(windows.Handle(hProcess))
	winapi.HeapFree(hHeap, 0, handleInfo)
	return results, nil
}

func FilterFiles(name *uint16) bool {
	n := windows.UTF16PtrToString(name)
	if !strings.Contains(n, ".") {
		// if directory return false
		return false
	}
	if strings.HasSuffix(n, ".dll") {
		return false
	}
	if strings.HasSuffix(n, ".mui") {
		return false
	}
	if strings.HasSuffix(n, ".ttf") {
		return false
	}
	return true
}

func FilterObjectTypes(name *uint16) bool {
	n := windows.UTF16PtrToString(name)
	/*if strings.Contains(n, "Directory") {
		return true
	}*/

	/*if strings.Contains(n, "File") {
		return true
	}*/
	/*if strings.Contains(n, "Key") {
		return true
	}*/
	if strings.Contains(n, "Process") {
		return true
	}
	if strings.Contains(n, "Thread") {
		return true
	}
	if strings.Contains(n, "Token") {
		return true
	}
	return false
}
