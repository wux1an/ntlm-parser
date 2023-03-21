package ntlm_parser

import (
	"strings"
)

type Flag struct {
	label string
	value uint32
}

var ntlmFlags = []Flag{
	{value: 0x1, label: "NTLMSSP_NEGOTIATE_UNICODE"},                      // A
	{value: 0x2, label: "NTLMSSP_NEGOTIATE_OEM"},                          // B
	{value: 0x4, label: "NTLMSSP_REQUEST_TARGET"},                         // C
	{value: 0x8, label: "R10"},                                            // r10 (0)
	{value: 0x10, label: "NTLMSSP_NEGOTIATE_SIGN"},                        // D
	{value: 0x20, label: "NTLMSSP_NEGOTIATE_SEAL"},                        // E
	{value: 0x40, label: "NTLMSSP_NEGOTIATE_DATAGRAM"},                    // F
	{value: 0x80, label: "NTLMSSP_NEGOTIATE_LM_KEY"},                      // G
	{value: 0x100, label: "R9"},                                           // r9 (0)
	{value: 0x200, label: "NTLMSSP_NEGOTIATE_NTLM"},                       // H
	{value: 0x400, label: "R8"},                                           // r8 (0)
	{value: 0x800, label: "ANONYMOUS_J"},                                  // J
	{value: 0x1000, label: "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED"},       // K
	{value: 0x2000, label: "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED"},  // L
	{value: 0x4000, label: "R7"},                                          // r7 (0)
	{value: 0x8000, label: "NTLMSSP_NEGOTIATE_ALWAYS_SIGN"},               // M
	{value: 0x10000, label: "NTLMSSP_TARGET_TYPE_DOMAIN"},                 // N
	{value: 0x20000, label: "NTLMSSP_TARGET_TYPE_SERVER"},                 // O
	{value: 0x40000, label: "R6"},                                         // r6 (0)
	{value: 0x80000, label: "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY"}, // P
	{value: 0x100000, label: "NTLMSSP_NEGOTIATE_IDENTIFY"},                // Q
	{value: 0x200000, label: "R5"},                                        // r5 (0)
	{value: 0x400000, label: "NTLMSSP_REQUEST_NON_NT_SESSION_KEY"},        // R
	{value: 0x800000, label: "NTLMSSP_NEGOTIATE_TARGET_INFO"},             // S
	{value: 0x1000000, label: "R4"},                                       // r4 (0)
	{value: 0x2000000, label: "NTLMSSP_NEGOTIATE_VERSION"},                // T
	{value: 0x4000000, label: "R3"},                                       // r3 (0)
	{value: 0x8000000, label: "R2"},                                       // r2 (0)
	{value: 0x10000000, label: "R1"},                                      // r1 (0)
	{value: 0x20000000, label: "NTLMSSP_NEGOTIATE_128"},                   // U
	{value: 0x40000000, label: "NTLMSSP_NEGOTIATE_KEY_EXCH"},              // V
	{value: 0x80000000, label: "NTLMSSP_NEGOTIATE_56"},                    // W
}

func getFlags(value uint32) string {
	var labels []string
	for _, f := range ntlmFlags {
		if f.value&value != 0 {
			labels = append(labels, f.label)
		}
	}

	var result = strings.Join(labels, " ")
	return strings.ReplaceAll(result, `NTLMSSP_NEGOTIATE_`, "")
}
