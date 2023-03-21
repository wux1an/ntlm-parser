package ntlm_parser

import (
	"encoding/json"
	"fmt"
)

func ExampleFromBase64() {
	var msg, _ = FromBase64("....")
	var type2 = msg.(*NTLMType2)

	var jsonStr, _ = json.MarshalIndent(type2.TargetInfoWrapper(), "", "  ")
	fmt.Printf("OsVersion:  %s\n", type2.OsVersionStructure.LongString())
	fmt.Printf("TargetInfo: %s\n", jsonStr)
}
