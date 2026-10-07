// Sandfly Security Linux Process Decloaking Utility
package main

/*
This utility will decloak Process IDs (PIDS) being hidden by common and not-so-common Loadable Kernel Module
stealth rootkits on Linux.

Sandfly produces an agentless Linux endpoint detection and incident response platform (EDR). Sandfly hunts for threats
against your Linux systems without loading any agents on your endpoints and works against most distributions and architectures

Please see our website for more information or a free trial:

https://www.sandflysecurity.com

MIT License

Copyright (c) 2020-2022 Sandfly Security Ltd.
https://www.sandflysecurity.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Version: 1.0.6
Date: 2022-11-15
Author: Sandfly Security @SandflySecurity
*/

import (
	"fmt"
	"log"

	"github.com/sandflysecurity/sandfly-processdecloak/processutils"
)

const (
	constVersion = "1.0.6"
)

func main() {
	fmt.Printf("sandfly-processdecloak Version %s\n", constVersion)
	fmt.Printf("Copyright (c) 2020-2022 Sandfly Security\n")
	fmt.Printf("Agentless Security for Linux  - www.sandflysecurity.com\n\n")
	fmt.Printf("Decloaking hidden Process IDs (PIDS) on Linux host.\n")

	hiddenPIDs, err := processutils.DecloakPIDs()
	if err != nil {
		log.Fatalf("error analyzing PIDs: %#v\n", err)
	}

	if len(hiddenPIDs) > 0 {
		for x := range hiddenPIDs {
			status, err := processutils.Status(hiddenPIDs[x])
			if err != nil {
				log.Fatalf("error reporting status on hidden PID %d : %#v", hiddenPIDs[x], err)
			}
			fmt.Printf("Found hidden PID: %d with name: %s\n", hiddenPIDs[x], status.Name)
		}
	} else {
		fmt.Printf("No hidden PIDs found.\n")
	}
}
