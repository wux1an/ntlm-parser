package ntlm_parser

import (
	"encoding/binary"
)

type NTLMType1 struct {
	SuppliedDomain      SecurityBuffer
	SuppliedWorkstation SecurityBuffer

	MessageType             NTLMMessageType
	Flags                   string
	OsVersionStructure      OSVersionStructure
	SuppliedDomainData      string
	SuppliedWorkstationData string
}

func (N NTLMType1) Parse(buffer []byte) (NTLMMessage, error) {
	var flag = binary.LittleEndian.Uint32(buffer[12:16])
	result := &NTLMType1{
		MessageType: NEGOTIATE_MESSAGE,
		Flags:       getFlags(flag),
	}

	if len(buffer) == 16 {
		// NTLM version 1.
		return result, nil
	}

	result.SuppliedDomain = getSecBuf(buffer, 16)
	result.SuppliedWorkstation = getSecBuf(buffer, 24)

	if result.SuppliedDomain.Offset != 32 {
		// NTLM version 3: OS Version structure.
		result.OsVersionStructure = getOSVersionStructure(buffer, 32)
	}

	result.SuppliedDomainData = getSecBufData(
		buffer,
		result.SuppliedDomain,
	)

	result.SuppliedWorkstationData = getSecBufData(
		buffer,
		result.SuppliedWorkstation,
	)

	return result, nil
}

func getSecBufData(buf []byte, secBuf SecurityBuffer) string {
	return string(buf[secBuf.Offset : secBuf.Offset+secBuf.Length])
}
