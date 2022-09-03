package winapi

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// https://github.com/sherifeldeeb/win-netstat/blob/efa1aff6aafc/iphlpapi.go#L30
var (
	pIphlpapi          = syscall.NewLazyDLL("Iphlpapi.dll")
	pGetRTTAndHopCount = pIphlpapi.NewProc("GetRTTAndHopCount")
	procGetTCPTable2   = pIphlpapi.NewProc("GetTcpTable2")
)

type TCP_CONNECTION_OFFLOAD_STATE uint32

const ANY_SIZE = 1

type MIB_TCPTABLE2 struct {
	DwNumEntries uint32
	Table        [ANY_SIZE]MIB_TCPROW2
}

type MIB_TCPROW2 struct {
	DwState        uint32
	DwLocalAddr    uint32
	DwLocalPort    uint32
	DwRemoteAddr   uint32
	DwRemotePort   uint32
	DwOwningPid    uint32
	DwOffloadState TCP_CONNECTION_OFFLOAD_STATE
}

const (
	TcpConnectionOffloadStateInHost TCP_CONNECTION_OFFLOAD_STATE = iota
	TcpConnectionOffloadStateOffloading
	TcpConnectionOffloadStateOffloaded
	TcpConnectionOffloadStateUploading
	TcpConnectionOffloadStateMax
)

type MIB_TCP_STATE int32

var TCPStatuses = map[MIB_TCP_STATE]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RECEIVED",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT_1",
	7:  "FIN_WAIT_2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE",
}

func ParseIPv4(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr&255, addr>>8&255, addr>>16&255, addr>>24&255)
}

func ParseIPv6(addr [16]byte) string {
	var ret [16]byte
	for i := 0; i < 16; i++ {
		ret[i] = uint8(addr[i])
	}

	// convert []byte to net.IP
	ip := net.IP(ret[:])
	return ip.String()
}

func DecodePort(port uint32) uint16 {
	return syscall.Ntohs(uint16(port))
}

func GetUintptrFromBool(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func GetTcpTable2(tcpTable *MIB_TCPTABLE2, bufSize *uint32, order bool) (errcode error) {
	r1, _, _ := syscall.Syscall(procGetTCPTable2.Addr(), 3, uintptr(unsafe.Pointer(tcpTable)), uintptr(unsafe.Pointer(bufSize)), GetUintptrFromBool(order))
	if r1 != 0 {
		errcode = syscall.Errno(r1)
	}
	return
}

func inet_addr(ipaddr string) uint32 {
	var (
		ip                 = strings.Split(ipaddr, ".")
		ip1, ip2, ip3, ip4 uint64
		ret                uint32
	)
	ip1, _ = strconv.ParseUint(ip[0], 10, 8)
	ip2, _ = strconv.ParseUint(ip[1], 10, 8)
	ip3, _ = strconv.ParseUint(ip[2], 10, 8)
	ip4, _ = strconv.ParseUint(ip[3], 10, 8)
	ret = uint32(ip4)<<24 + uint32(ip3)<<16 + uint32(ip2)<<8 + uint32(ip1)
	return ret
}

func GetRTTAndHopCount(address string) bool {
	addr := inet_addr(address)
	var hopCount uint64
	hopCount = 1
	var maxHops uint64 = 60
	var roundtrip uint64
	ok, _, _ := pGetRTTAndHopCount.Call(uintptr(addr), uintptr(unsafe.Pointer(&hopCount)), uintptr(maxHops), uintptr(unsafe.Pointer(&roundtrip)))
	if ok == 0 {
		return false
	}
	return true
}
