package ntlm_parser

import (
	"encoding/binary"
	"encoding/hex"
	"sort"
)

type LMResponseData struct {
	Hex string
}

type NTLMResponseData struct {
	Hex string
}

type NTLMType3v1 struct {
	NTLMMessage

	LmResponse      SecurityBuffer
	NtlmResponse    SecurityBuffer
	TargetName      SecurityBuffer
	UserName        SecurityBuffer
	WorkstationName SecurityBuffer

	MessageType         NTLMMessageType
	Version             int
	LmResponseData      LMResponseData
	NtlmResponseData    NTLMResponseData
	TargetNameData      string
	UserNameData        string
	WorkstationNameData string
}

func (N NTLMType3v1) Parse(buffer []byte) (NTLMMessage, error) {
	var (
		lmResponse      = getSecBuf(buffer, 12)
		ntlmResponse    = getSecBuf(buffer, 20)
		targetName      = getSecBuf(buffer, 28)
		userName        = getSecBuf(buffer, 36)
		workstationName = getSecBuf(buffer, 44)
	)

	var flag = binary.LittleEndian.Uint32(buffer[60:64])

	var lmResponseData = getLmResponseData(buffer, lmResponse)
	var ntlmResponseData = getNtlmResponseData(buffer, ntlmResponse)
	var targetNameData = getSecBufDataWithFlag(buffer, targetName, flag)
	var userNameData = getSecBufDataWithFlag(buffer, userName, flag)
	var workstationNameData = getSecBufDataWithFlag(buffer, workstationName, flag)

	var type3v1 = &NTLMType3v1{
		MessageType:         AUTHENTICATE_MESSAGE,
		Version:             1,
		LmResponse:          lmResponse,
		NtlmResponse:        ntlmResponse,
		TargetName:          targetName,
		UserName:            userName,
		WorkstationName:     workstationName,
		LmResponseData:      lmResponseData,
		NtlmResponseData:    ntlmResponseData,
		TargetNameData:      targetNameData,
		UserNameData:        userNameData,
		WorkstationNameData: workstationNameData,
	}

	var offsets = []SecurityBuffer{lmResponse, ntlmResponse, targetName, userName, workstationName}
	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i].Offset < offsets[j].Offset
	})
	var firstOffset = offsets[0].Offset

	// NTLM version 1
	if firstOffset == 52 {
		return type3v1, nil
	}

	// NTLM version 2
	var type3v2 = &NTLMType3v2{
		NTLMType3v1: *type3v1,
	}
	type3v2.Version = 2
	type3v2.SessionKey = getSecBuf(buffer, 52)
	type3v2.Flags = getFlags(flag)
	if firstOffset == 64 { // NTLM version 2
		return type3v2, nil
	}

	// NTLM version 3
	var type3v3 = &NTLMType3v3{
		NTLMType3v2: *type3v2,
	}
	type3v3.Version = 3
	type3v3.OsVersionStructure = getOSVersionStructure(buffer, 64)

	return type3v3, nil
}

func getNtlmResponseData(buffer []byte, secBuf SecurityBuffer) NTLMResponseData {
	var buf = buffer[secBuf.Offset : secBuf.Offset+secBuf.Length]
	return NTLMResponseData{Hex: hex.EncodeToString(buf)}
}

func getLmResponseData(buffer []byte, secBuf SecurityBuffer) LMResponseData {
	var buf = buffer[secBuf.Offset : secBuf.Offset+secBuf.Length]
	return LMResponseData{Hex: hex.EncodeToString(buf)}
}

type NTLMType3v2 struct {
	NTLMType3v1

	SessionKey SecurityBuffer

	Flags string
}

type NTLMType3v3 struct {
	NTLMType3v2

	OsVersionStructure OSVersionStructure
}
