package ntlm_parser

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
	"unicode/utf16"
)

// TargetInfo
//
// reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
type TargetInfo struct {
	Type    int
	Length  int
	Content string
}

type TargetInfoWrapper struct {
	EOL                 string `json:"eol,omitempty"`
	NetBIOSComputerName string `json:"net-bios-computer-name,omitempty"`
	NetBIOSDomainName   string `json:"net-bios-domain-name,omitempty"`
	DnsComputerName     string `json:"dns-computer-name,omitempty"`
	DnsDomainName       string `json:"dns-domain-name,omitempty"`
	DnsTreeName         string `json:"dns-tree-name,omitempty"`
	Flags               string `json:"flags,omitempty"`
	Timestamp           string `json:"timestamp,omitempty"`
	SingleHost          string `json:"single-host,omitempty"`
	TargetName          string `json:"target-name,omitempty"`
	ChannelBindings     string `json:"channel-bindings,omitempty"`
}

type NTLMType2 struct {
	NTLMMessage

	TargetNameSecBuf SecurityBuffer
	TargetInfoSecBuf SecurityBuffer

	MessageType        NTLMMessageType
	Flags              string
	Challenge          string
	Context            string
	OsVersionStructure OSVersionStructure
	TargetNameData     string
	TargetInfoData     []TargetInfo
}

func (N NTLMType2) Parse(buffer []byte) (NTLMMessage, error) {
	var targetNameSecBuf = getSecBuf(buffer, 12)
	var flag = binary.LittleEndian.Uint32(buffer[20:24])
	targetNameData := getSecBufDataWithFlag(buffer, targetNameSecBuf, flag)
	var result = &NTLMType2{
		MessageType:      CHALLENGE_MESSAGE,
		TargetNameSecBuf: targetNameSecBuf,
		Flags:            getFlags(flag),
		Challenge:        hex.EncodeToString(buffer[24:32]),
		TargetNameData:   targetNameData,
	}

	if targetNameSecBuf.Offset != 32 {
		// NTLM v2
		result.Context = hex.EncodeToString(buffer[32:40])
		result.TargetInfoSecBuf = getSecBuf(buffer, 40)

		result.TargetInfoData = getTargetInfo(buffer, result.TargetInfoSecBuf)
	}

	if targetNameSecBuf.Offset != 48 {
		// NTLM version 3: OS Version structure
		result.OsVersionStructure = getOSVersionStructure(buffer, 48)
	}

	return result, nil
}

func (N NTLMType2) TargetInfoWrapper() TargetInfoWrapper {
	var result = TargetInfoWrapper{}
	var valueMap = map[int]*string{
		0x0000: &result.EOL,
		0x0001: &result.NetBIOSComputerName,
		0x0002: &result.NetBIOSDomainName,
		0x0003: &result.DnsComputerName,
		0x0004: &result.DnsDomainName,
		0x0005: &result.DnsTreeName,
		0x0006: &result.Flags,
		0x0007: &result.Timestamp,
		0x0008: &result.SingleHost,
		0x0009: &result.TargetName,
		0x000A: &result.ChannelBindings,
	}

	for _, info := range N.TargetInfoData {
		sptr, exist := valueMap[info.Type]
		if !exist {
			continue
		}

		*sptr = info.Content
	}

	return result
}

func bytesToUCS2(data []byte) string {
	words := make([]uint16, len(data)/2)
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &words)
	if err != nil {
		panic(err)
	}

	return string(utf16.Decode(words))
}

func getTargetInfo(buffer []byte, secBuf SecurityBuffer) []TargetInfo {
	var result []TargetInfo
	var offsetBuffer = buffer[secBuf.Offset : secBuf.Offset+secBuf.Length]
	var offset = 0
	for offset < secBuf.Length {
		var item = TargetInfo{
			Type:   int(binary.LittleEndian.Uint16(offsetBuffer[offset+0 : offset+2])),
			Length: int(binary.LittleEndian.Uint16(offsetBuffer[offset+2 : offset+4])),
		}

		if item.Type <= 5 {
			item.Content = bytesToUCS2(buffer[secBuf.Offset+offset+4 : secBuf.Offset+offset+4+item.Length])
		}

		if item.Type == 7 {
			var low = binary.LittleEndian.Uint32(offsetBuffer[offset+4 : offset+8])
			var high = binary.LittleEndian.Uint32(offsetBuffer[offset+8 : offset+12])
			var date = fileTimeToDate(uint64(high)*uint64(math.Pow(2, 32)) + uint64(low))
			item.Content = date.UTC().Format(`2006-01-02T15:04:05.999Z`) // 2020-11-18T19:08:09.844Z
		}
		result = append(result, item)
		offset += 2 + 2 + item.Length
	}

	return result
}
