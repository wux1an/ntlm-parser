package ntlm_parser

import (
	"reflect"
	"testing"
)

func TestNtlmParseType1(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		action  func(str string) (NTLMMessage, error)
		want    NTLMMessage
		wantErr bool
	}{
		{
			name:   "NTLM Type 1 Unit Test (base64)",
			args:   args{str: "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw=="},
			action: FromBase64,
			want: NTLMMessage(&NTLMType1{
				SuppliedDomain:      SecurityBuffer{Length: 0, Allocated: 0, Offset: 0},
				SuppliedWorkstation: SecurityBuffer{Length: 0, Allocated: 0, Offset: 0},
				MessageType:         NEGOTIATE_MESSAGE,
				Flags:               "UNICODE OEM NTLMSSP_REQUEST_TARGET NTLM ALWAYS_SIGN EXTENDED_SESSIONSECURITY VERSION 128 56",
				OsVersionStructure: OSVersionStructure{
					MajorVersion: 10,
					MinorVersion: 0,
					BuildNumber:  18362,
					Unknown:      15,
				},
				SuppliedDomainData:      "",
				SuppliedWorkstationData: "",
			}),
			wantErr: false,
		},
		{
			name:   "NTLM Type 1 Unit Test (hex)",
			args:   args{str: "4e544c4d53535000010000000732000006000600330000000b000b0028000000050093080000000f574f524b53544154494f4e444f4d41494e"},
			action: FromHex,
			want: NTLMMessage(&NTLMType1{
				SuppliedDomain:      SecurityBuffer{Length: 6, Allocated: 6, Offset: 51},
				SuppliedWorkstation: SecurityBuffer{Length: 11, Allocated: 11, Offset: 40},
				MessageType:         NEGOTIATE_MESSAGE,
				Flags:               "UNICODE OEM NTLMSSP_REQUEST_TARGET NTLM OEM_DOMAIN_SUPPLIED OEM_WORKSTATION_SUPPLIED",
				OsVersionStructure: OSVersionStructure{
					MajorVersion: 5,
					MinorVersion: 0,
					BuildNumber:  2195,
					Unknown:      15,
				},
				SuppliedDomainData:      "DOMAIN",
				SuppliedWorkstationData: "WORKSTATION",
			}),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.action(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromBase64() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNtlmParseType2(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		action  func(str string) (NTLMMessage, error)
		want    NTLMMessage
		wantErr bool
	}{
		{
			name:   "NTLM Type 2 Unit Test (base64)",
			args:   args{str: "TlRMTVNTUAACAAAABgAGADgAAAA1goniaaCGDXCRRNUAAAAAAAAAAIIAggA+AAAACgC6RwAAAA9KAEwARwACAAYASgBMAEcAAQAQAEMASABPAFUAQwBIAE8AVQAEABIAagBsAGcALgBsAG8AYwBhAGwAAwAkAGMAaABvAHUAYwBoAG8AdQAuAGoAbABnAC4AbABvAGMAYQBsAAUAEgBqAGwAZwAuAGwAbwBjAGEAbAAHAAgAQH6UJ9691gEAAAAA"},
			action: FromBase64,
			want: NTLMMessage(&NTLMType2{
				MessageType:      CHALLENGE_MESSAGE,
				TargetNameSecBuf: SecurityBuffer{Length: 6, Allocated: 6, Offset: 56},
				Flags:            "UNICODE NTLMSSP_REQUEST_TARGET SIGN SEAL NTLM ALWAYS_SIGN NTLMSSP_TARGET_TYPE_DOMAIN EXTENDED_SESSIONSECURITY TARGET_INFO VERSION 128 KEY_EXCH 56",
				Challenge:        "69a0860d709144d5",
				TargetNameData:   "JLG",
				Context:          "0000000000000000",
				TargetInfoSecBuf: SecurityBuffer{Length: 130, Allocated: 130, Offset: 62},
				TargetInfoData: []TargetInfo{
					{Type: 2, Length: 6, Content: "JLG"},
					{Type: 1, Length: 16, Content: "CHOUCHOU"},
					{Type: 4, Length: 18, Content: "jlg.local"},
					{Type: 3, Length: 36, Content: "chouchou.jlg.local"},
					{Type: 5, Length: 18, Content: "jlg.local"},
					{Type: 7, Length: 8, Content: "2020-11-18T19:08:09.844Z"},
					{Type: 0, Length: 0, Content: ""},
				},
				OsVersionStructure: OSVersionStructure{
					MajorVersion: 10,
					MinorVersion: 0,
					BuildNumber:  18362,
					Unknown:      15,
				},
			}),
			wantErr: false,
		}, {
			name: "NTLM Type 2 Unit Test (hex)",
			args: args{str: "4e544c4d53535000020000000c000c003000000001028100" +
				"0123456789abcdef0000000000000000620062003c000000" +
				"44004f004d00410049004e0002000c0044004f004d004100" +
				"49004e0001000c0053004500520056004500520004001400" +
				"64006f006d00610069006e002e0063006f006d0003002200" +
				"7300650072007600650072002e0064006f006d0061006900" +
				"6e002e0063006f006d0000000000",
			},
			action: FromHex,
			want: NTLMMessage(&NTLMType2{
				MessageType:      CHALLENGE_MESSAGE,
				Flags:            "UNICODE NTLM NTLMSSP_TARGET_TYPE_DOMAIN TARGET_INFO",
				TargetNameSecBuf: SecurityBuffer{Length: 12, Allocated: 12, Offset: 48},
				Challenge:        "0123456789abcdef",
				TargetNameData:   "DOMAIN",
				Context:          "0000000000000000",
				TargetInfoSecBuf: SecurityBuffer{Length: 98, Allocated: 98, Offset: 60},
				TargetInfoData: []TargetInfo{
					{Type: 2, Length: 12, Content: "DOMAIN"},
					{Type: 1, Length: 12, Content: "SERVER"},
					{Type: 4, Length: 20, Content: "domain.com"},
					{Type: 3, Length: 34, Content: "server.domain.com"},
					{Type: 0, Length: 0, Content: ""},
				},
			}),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.action(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromBase64() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNtlmParseType3(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		action  func(str string) (NTLMMessage, error)
		want    NTLMMessage
		wantErr bool
	}{
		{
			name: "NTLM Type 3 Unit Test (base64)",
			args: args{str: "TlRMTVNTUAADAAAAGAAYAHQAAAAiASIBjAAAAAAAAABYAAAADAA" +
				"MAFgAAAAQABAAZAAAABAAEACuAQAANYKI4goAukcAAAAP1KMCwe" +
				"XeFIr6zmSmiHFWSWoAbABvAHUAaQBzAEMASABPAFUAQwBIAE8AV" +
				"QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC5/Vhnk2GTLD131k8c" +
				"NfZcAQEAAAAAAADSVClUh73WAX873ENT+QbPAAAAAAIABgBKAEw" +
				"ARwABABAAQwBIAE8AVQBDAEgATwBVAAQAEgBqAGwAZwAuAGwAbw" +
				"BjAGEAbAADACQAYwBoAG8AdQBjAGgAbwB1AC4AagBsAGcALgBsA" +
				"G8AYwBhAGwABQASAGoAbABnAC4AbABvAGMAYQBsAAcACADSVClU" +
				"h73WAQYABAACAAAACAAwADAAAAAAAAAAAQAAAAAgAAC4YcwjyK/" +
				"gKSgZikWqPXs8y5udtMrVNidXg4R7uFJFPgoAEAAAAAAAAAAAAA" +
				"AAAAAAAAAACQAcAEgAVABUAFAALwBsAG8AYwBhAGwAaABvAHMAd" +
				"AAAAAAAAAAAAAG7NbE8iPK1v5zqEu20+5Q=",
			},
			action: FromBase64,
			want: NTLMMessage(&NTLMType3v3{
				NTLMType3v2: NTLMType3v2{
					NTLMType3v1: NTLMType3v1{
						MessageType:     AUTHENTICATE_MESSAGE,
						Version:         3,
						LmResponse:      SecurityBuffer{Length: 24, Allocated: 24, Offset: 116},
						NtlmResponse:    SecurityBuffer{Length: 290, Allocated: 290, Offset: 140},
						TargetName:      SecurityBuffer{Length: 0, Allocated: 0, Offset: 88},
						UserName:        SecurityBuffer{Length: 12, Allocated: 12, Offset: 88},
						WorkstationName: SecurityBuffer{Length: 16, Allocated: 16, Offset: 100},
						LmResponseData:  LMResponseData{Hex: "000000000000000000000000000000000000000000000000"},
						NtlmResponseData: NTLMResponseData{
							Hex: "b9fd58679361932c3d77d64f1c35f65c0101000000000000d254295487" +
								"bdd6017f3bdc4353f906cf00000000020006004a004c00470001001000" +
								"430048004f005500430048004f005500040012006a006c0067002e006c" +
								"006f00630061006c0003002400630068006f007500630068006f007500" +
								"2e006a006c0067002e006c006f00630061006c00050012006a006c0067" +
								"002e006c006f00630061006c0007000800d254295487bdd60106000400" +
								"020000000800300030000000000000000100000000200000b861cc23c8" +
								"afe02928198a45aa3d7b3ccb9b9db4cad536275783847bb852453e0a00" +
								"10000000000000000000000000000000000009001c0048005400540050" +
								"002f006c006f00630061006c0068006f00730074000000000000000000",
						},
						TargetNameData:      "",
						UserNameData:        "jlouis",
						WorkstationNameData: "CHOUCHOU",
					},
					SessionKey: SecurityBuffer{Length: 16, Allocated: 16, Offset: 430},
					Flags:      "UNICODE NTLMSSP_REQUEST_TARGET SIGN SEAL NTLM ALWAYS_SIGN EXTENDED_SESSIONSECURITY TARGET_INFO VERSION 128 KEY_EXCH 56",
				},
				OsVersionStructure: OSVersionStructure{
					MajorVersion: 10,
					MinorVersion: 0,
					BuildNumber:  18362,
					Unknown:      15,
				},
			}),
			wantErr: false,
		},
		{
			name: "NTLM Type 3 Unit Test (hex)",
			args: args{str: "4e544c4d5353500003000000180018006a00000018001800" +
				"820000000c000c0040000000080008004c00000016001600" +
				"54000000000000009a0000000102000044004f004d004100" +
				"49004e00750073006500720057004f0052004b0053005400" +
				"4100540049004f004e00c337cd5cbd44fc9782a667af6d42" +
				"7c6de67c20c2d3e77c5625a98c1c31e81847466b29b2df46" +
				"80f39958fb8c213a9cc6",
			},
			action: FromHex,
			want: NTLMMessage(&NTLMType3v2{
				NTLMType3v1: NTLMType3v1{
					MessageType:         AUTHENTICATE_MESSAGE,
					Version:             2,
					LmResponse:          SecurityBuffer{Length: 24, Allocated: 24, Offset: 106},
					NtlmResponse:        SecurityBuffer{Length: 24, Allocated: 24, Offset: 130},
					TargetName:          SecurityBuffer{Length: 12, Allocated: 12, Offset: 64},
					UserName:            SecurityBuffer{Length: 8, Allocated: 8, Offset: 76},
					WorkstationName:     SecurityBuffer{Length: 22, Allocated: 22, Offset: 84},
					LmResponseData:      LMResponseData{Hex: "c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56"},
					NtlmResponseData:    NTLMResponseData{Hex: "25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6"},
					TargetNameData:      "DOMAIN",
					UserNameData:        "user",
					WorkstationNameData: "WORKSTATION",
				},
				SessionKey: SecurityBuffer{Length: 0, Allocated: 0, Offset: 154},
				Flags:      "UNICODE NTLM",
			}),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.action(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromBase64() got = %v, want %v", got, tt.want)
			}
		})
	}
}
