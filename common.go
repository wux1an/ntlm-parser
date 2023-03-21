package ntlm_parser

import (
	"encoding/binary"
	"fmt"
	"time"
)

type NTLMMessageType string

var (
	NEGOTIATE_MESSAGE    = NTLMMessageType("NEGOTIATE_MESSAGE (type 1)")
	CHALLENGE_MESSAGE    = NTLMMessageType("CHALLENGE_MESSAGE (type 2)")
	AUTHENTICATE_MESSAGE = NTLMMessageType("AUTHENTICATE_MESSAGE (type 3)")
)

type NTLMMessage interface {
	Parse(buffer []byte) (NTLMMessage, error)
}

// osVersionMap
//
// reference: https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
// https://www.gaijin.at/en/infos/windows-version-numbers
var osVersionMap = map[string]string{
	"5.2.3790":   "Windows Server 2003",
	"6.0.6001":   "Windows Server 2008",
	"6.0.6002":   "Windows Server 2008",
	"6.0.6003":   "Windows Server 2008",
	"6.1.7600":   "Windows Server 2008",
	"6.1.7601":   "Windows Server 2008",
	"6.2.9200":   "Windows Server 2012",
	"6.3.9600":   "Windows Server 2012",
	"10.0.14393": "Windows Server 2016",
	"10.0.17763": "Windows Server 2019",
	"10.0.20348": "Windows Server 2022",
}

type OSVersionStructure struct {
	MajorVersion int
	MinorVersion int
	BuildNumber  int
	Unknown      int
}

func (o OSVersionStructure) LongString() string {
	var v = fmt.Sprintf("%d.%d.%d", o.MajorVersion, o.MinorVersion, o.BuildNumber)
	var vv = osVersionMap[v]
	if vv == "" {
		vv = "Other"
	}

	return fmt.Sprintf("%s (%s)", vv, o.ShortString())
}

func (o OSVersionStructure) ShortString() string {
	return fmt.Sprintf("%d.%d.%d.%d", o.MajorVersion, o.MinorVersion, o.BuildNumber, o.Unknown)
}

type SecurityBuffer struct {
	Length    int
	Allocated int
	Offset    int
}

func getSecBuf(buf []byte, offset int) SecurityBuffer {
	return SecurityBuffer{
		Length:    int(binary.LittleEndian.Uint16(buf[offset : offset+2])),
		Allocated: int(binary.LittleEndian.Uint16(buf[offset+2 : offset+4])),
		Offset:    int(binary.LittleEndian.Uint32(buf[offset+4 : offset+8])),
	}
}

func getSecBufDataWithFlag(buf []byte, secBuf SecurityBuffer, decodeFlag uint32) string {
	var u = decodeFlag | 0x1 // NTLMSSP_NEGOTIATE_UNICODE
	if u != 1 {              // don't use unicode， use ucs2
		return bytesToUCS2(buf[secBuf.Offset : secBuf.Offset+secBuf.Length])
	}
	return string(buf[secBuf.Offset : secBuf.Offset+secBuf.Length])
}

func fileTimeToDate(timestamp uint64) time.Time {
	return time.UnixMilli(int64(timestamp/10000 - 11644473600000)).UTC()
}

func getOSVersionStructure(buf []byte, offset int) OSVersionStructure {
	return OSVersionStructure{
		MajorVersion: int(buf[offset]),
		MinorVersion: int(buf[offset+1]),
		BuildNumber:  int(binary.LittleEndian.Uint16(buf[offset+2 : offset+4])),
		Unknown:      int(binary.BigEndian.Uint32(buf[offset+4 : offset+8])),
	}
}
