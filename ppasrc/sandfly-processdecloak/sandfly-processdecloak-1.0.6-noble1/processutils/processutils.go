// Sandfly processdecloak process utilities.
package processutils

/*
This utility will decloak Process IDs (PIDS) being hidden by common and not-so-common Loadable Kernel Module
stealth rootkits on Linux.

Sandfly Security produces an agentless intrusion detection and incident response platform for Linux. You can
find out more about how it works at: https://www.sandflysecurity.com

MIT License

Copyright (c) 2020 Sandfly Security Ltd.
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
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	// ConstMinPID minimum PID value allowed for process checks.
	ConstMinPID = 1
	// ConstMaxPID maximum PID value allowed for process checks. 64bit linux is 2^22. This value is a limiter.
	ConstMaxPID = 4194304
	// ConstHiddenVerifyDelay is seconds to wait if we see a hidden PID to re-verify it really is hidden (anti-race)
	ConstHiddenVerifyDelay = 1
)

// PIDStatus Struct
type PIDStatus struct {
	Name  string `json:"name"`
	Umask string `json:"umask"`
	State string `json:"state"`
	Tgid  int    `json:"tgid"`
	Ngid  int    `json:"ngid"`
	PID   int    `json:"pid"`
	PPID  int    `json:"ppid"`
}

// DecloakPIDs gets all the PIDS running on the system by bruteforcing all available PID values and seeing if hiding.
func DecloakPIDs() (PidList []int, err error) {

	for pid := ConstMinPID; pid < ConstMaxPID; pid++ {
		pidHidden, err := IsPidHidden(pid, true)
		if err != nil {
			return PidList, err
		} else if pidHidden {
			PidList = append(PidList, pid)
		}
	}

	return PidList, nil
}

// IsPidHidden pass in a PID number and we'll check if it is trying to hide.
func IsPidHidden(pid int, raceVerify bool) (pidHidden bool, err error) {
	// raceVerify - Makes this basically run itself twice if we find a process is flagged as hidden to
	// eliminate possible race condition alerts (e.g. PID /proc entry disappears during second part of this
	// check).
	if pid < ConstMinPID || pid > ConstMaxPID {
		return pidHidden, fmt.Errorf("PID must be between %d and %d", ConstMinPID, ConstMaxPID)
	}

	// This will detect certain types of hiding rookits that affect lstat() calls.
	// Try to read the maps files for the PID. A definite path can reveal hidden dirs under /proc.
	// The hidden dirs are normally just threads, but it could also be a suspect which we'll get to
	// under this.
	// err may just mean the PID attempt to read failed which is OK as we are brute forcing them all and
	// it just may not be there any more or wasn't there when we looked. Ignore the error.
	maps, _ := PidMaps(pid)
	// Any maps files that return as 0 are threads so we'll not report them. Only maps files with data will
	// be things we're interested in.
	if len(maps) > 0 {
		pidstatus, err := Status(pid)
		if err != nil {
			// Again if we have an error with pidstatus it may mean the PID was there when we read the maps, but now
			// when we went to get the status file it wasn't there or some other problem happened as the PID
			// may have went away mid-course. We are looking for hidden PIDs which may be simply transient threads so
			// we'll ignore these issues and just assume the PID vanished vs. reporting the error. Otherwise we
			// may flag PIDs that were in the middle of going away and get false alerts.
			return false, nil
		}
		// If PID equals the tgid then it belongs to itself and is not a thread/child. Do not compare PID 0 or
		// less as they are invalid and maybe the PID was not found when we just looked.
		if pidstatus.PID == pidstatus.Tgid && pidstatus.PID > 0 {
			// Now with this pid that matched all criteria, we'll see if we can stat the
			// top directory for it. If not, then something is hiding it. We should be able to stat
			// legitimate PIDs even if not showing under /proc due to being threads/children.
			pidPath := path.Join("/proc", strconv.Itoa(pid))
			_, err = os.Lstat(pidPath)
			// An error means lstat failed and something is hidden. We already know the PID is there above
			// because we could read the maps file. So why can't we stat it?
			if err != nil {
				pidHidden = true
			}

			// Secondary check to find other LKM rootkit hiding like Reptile. This rootkit will obscure directory
			// reads at the top level. We will read the directory and see if the PID shows in the standard directory
			// listing we receive. If not, then it's missing and will be flagged.
			//
			// Only do this check if the above check didn't return hidden already.
			if pidHidden == false {
				files, err := ioutil.ReadDir("/proc")
				if err != nil {
					return pidHidden, fmt.Errorf("there was an error reading the /proc directory to find hidden PIDS: %v", err)
				}
				pidHidden = true
				for _, f := range files {
					pidToCheck, _ := strconv.Atoi(f.Name())
					if pid == pidToCheck {
						pidHidden = false
						break
					}
				}
			}
		}
	}

	// Do a double check if the PID is really hidden. This eliminates possible race condition which can happen if
	// a PID vanishes during a check as can happen. If we see the same PID hiding twice after a brief delay,
	// then it's probably hiding and didn't simply stop running.
	if pidHidden && raceVerify {
		// Don't re-verify this check the second time around. We only need to do this once.
		time.Sleep(time.Second * ConstHiddenVerifyDelay)
		pidHidden, err = IsPidHidden(pid, false)
		if err != nil {
			return pidHidden, err
		}
	}

	return pidHidden, nil
}

// PidMaps retrieves any /proc/PID/maps that a process has associated with it.
func PidMaps(pid int) (pidMaps []string, err error) {

	if pid < ConstMinPID || pid > ConstMaxPID {
		return pidMaps, fmt.Errorf("PID must be between %d and %d", ConstMinPID, ConstMaxPID)
	}

	pidPath := path.Join("/proc", strconv.Itoa(pid), "/maps")

	f, err := os.Open(pidPath)
	if err != nil {
		return pidMaps, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pidMaps = append(pidMaps, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return pidMaps, fmt.Errorf("error reading process maps file")
	}

	return pidMaps, nil
}

// Status returns abbreviated status values of a process.
func Status(pid int) (pidstatus PIDStatus, err error) {

	if pid < ConstMinPID || pid > ConstMaxPID {
		return pidstatus, fmt.Errorf("PID must be between %d and %d", ConstMinPID, ConstMaxPID)
	}

	statPath := path.Join("/proc", strconv.Itoa(pid), "/status")

	f, err := os.Open(statPath)
	if err != nil {
		return pidstatus, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineEntry := strings.Split(scanner.Text(), ":")
		// Check entry is at least 2 or more.
		if len(lineEntry) < 2 {
			return pidstatus, fmt.Errorf("cannot parse entry in status file due to incorrect length")
		}

		// Check that our line data is at least 1 length long. Otherwise the entry is empty and we just
		// carry on.
		lineData := strings.Fields(lineEntry[1])
		if len(lineData) > 0 {
			switch lineEntry[0] {
			case "Name":
				pidstatus.Name = lineData[0]
			case "Umask":
				pidstatus.Umask = lineData[0]
			case "State":
				pidstatus.State = lineData[0]
			case "Tgid":
				pidstatus.Tgid, err = strconv.Atoi(lineData[0])
				if err != nil {
					return pidstatus, fmt.Errorf("cannot convert tgid value to an integer: %v", err)
				}
			case "Ngid":
				pidstatus.Ngid, err = strconv.Atoi(lineData[0])
				if err != nil {
					return pidstatus, fmt.Errorf("cannot convert ngid value to an integer: %v", err)
				}
			case "Pid":
				pidstatus.PID, err = strconv.Atoi(lineData[0])
				if err != nil {
					return pidstatus, fmt.Errorf("cannot convert pid value to an integer: %v", err)
				}
			case "PPid":
				pidstatus.PPID, err = strconv.Atoi(lineData[0])
				if err != nil {
					return pidstatus, fmt.Errorf("cannot convert ppid value to an integer: %v", err)
				}
			}
		}
	}

	return pidstatus, nil
}
