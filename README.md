# NTLM Parser

📑 A library that parses ntlm information   
📝 Rewritten from https://github.com/jlguenego/ntlm-parser library in Golang

[Demo: ntlm-parser-cli](https://github.com/wux1an/ntlm-parser-cli/releases)

## Usage

```
go get https://github.com/jlguenego/ntlm-parser
```

```go
package main

import (
	"encoding/json"
	"fmt"
	parser "github.com/wux1an/ntlm-parser"
)

func main() {
	var msg, _ = parser.FromBase64("....")
	var type2 = msg.(*parser.NTLMType2)

	var jsonStr, _ = json.MarshalIndent(type2.TargetInfoWrapper(), "", "  ")
	fmt.Printf("OsVersion:  %s\n", type2.OsVersionStructure.LongString())
	fmt.Printf("TargetInfo: %s\n", jsonStr)
}
```