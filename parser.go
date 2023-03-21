package ntlm_parser

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
)

func FromBase64(str string) (NTLMMessage, error) {
	if data, err := base64.StdEncoding.DecodeString(str); err != nil {
		return nil, err
	} else {
		return FromBytes(data)
	}
}

func FromHex(str string) (NTLMMessage, error) {
	if data, err := hex.DecodeString(str); err != nil {
		return nil, err
	} else {
		return FromBytes(data)
	}
}

func FromBytes(data []byte) (r NTLMMessage, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New("invalid ntlm message")
		}
	}()

	var m = map[string]func(data []byte) (NTLMMessage, error){
		"4e544c4d5353500001000000": NTLMType1{}.Parse,
		"4e544c4d5353500002000000": NTLMType2{}.Parse,
		"4e544c4d5353500003000000": NTLMType3v1{}.Parse,
	}

	var f = m[hex.EncodeToString(data[0:12])]
	if f != nil {
		return f(data)
	} else {
		return nil, errors.New("unknown ntlm message")
	}
}
