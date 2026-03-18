package privdrop

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Well-known Linux capability numbers. Only capabilities actually used
// by terrarium are listed.
const (
	capNetAdmin = 12 // CAP_NET_ADMIN
)

// capNames maps capability names (lowercase, without "cap_" prefix in
// the key) to their kernel number. The input format uses the full
// "cap_net_admin" form; lookup strips the "cap_" prefix.
var capNames = map[string]int{
	"net_admin": capNetAdmin,
}

// ParseCaps parses a setpriv-style capability string into a bitmask
// and a clearAll flag. Supported formats:
//
//   - "+cap_net_admin" sets CAP_NET_ADMIN in the returned bitmask.
//   - "-all" sets clearAll to true and returns a zero bitmask.
func ParseCaps(s string) (uint64, bool, error) {
	if s == "" {
		return 0, false, nil
	}

	if s == "-all" {
		return 0, true, nil
	}

	if !strings.HasPrefix(s, "+") {
		return 0, false, fmt.Errorf("unsupported cap modifier %q (expected +cap_name or -all)", s)
	}

	name := strings.TrimPrefix(s[1:], "cap_")

	num, ok := capNames[name]
	if !ok {
		return 0, false, fmt.Errorf("unknown capability %q", s[1:])
	}

	return 1 << num, false, nil
}

// capLastCap reads /proc/sys/kernel/cap_last_cap to determine the
// highest valid capability number on this kernel.
func capLastCap() (int, error) {
	return capLastCapFrom("/proc/sys/kernel/cap_last_cap")
}

// capLastCapFrom reads the highest valid capability number from the
// given path. Separated from [capLastCap] for testing.
func capLastCapFrom(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading cap_last_cap: %w", err)
	}

	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parsing cap_last_cap: %w", err)
	}

	return n, nil
}

// Kernel capability v2 structures for the capget/capset syscalls.
// Version 2 uses two data elements to cover capabilities 0-63.
const linuxCapabilityVersion2 = 0x20071026

// capHeader is the __user_cap_header_struct for capget/capset.
type capHeader struct {
	Version uint32
	PID     int32
}

// capData is one element of the __user_cap_data_struct array.
// Version 2 requires two elements: [0] covers caps 0-31, [1] covers
// caps 32-63.
type capData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

// setCaps calls the capset syscall to set effective, permitted, and
// inheritable capability sets. Each argument is a 64-bit bitmask;
// bits 0-31 go to data[0] and bits 32-63 go to data[1].
func setCaps(effective, permitted, inheritable uint64) error {
	hdr := capHeader{
		Version: linuxCapabilityVersion2,
		PID:     0, // current process
	}

	data := [2]capData{
		{
			//nolint:gosec // G115: intentional truncation to low 32 bits.
			Effective:   uint32(effective),
			Permitted:   uint32(permitted),   //nolint:gosec // G115
			Inheritable: uint32(inheritable), //nolint:gosec // G115
		},
		{
			Effective:   uint32(effective >> 32),   //nolint:gosec // G115
			Permitted:   uint32(permitted >> 32),   //nolint:gosec // G115
			Inheritable: uint32(inheritable >> 32), //nolint:gosec // G115
		},
	}

	//nolint:gosec // G103: required for capset syscall kernel ABI.
	_, _, errno := unix.Syscall(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}

	return nil
}
