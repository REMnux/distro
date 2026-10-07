# What is sandfly-processdecloak?

`sandfly-processdecloak` is a utility to quickly scan for Linux Process IDs (PIDs) that are hidden by common and 
not-so-common loadable kernel module stealth rootkits and decloak them so they are visible.

# Features

* Written in Golang and is portable across multiple architectures with no modifications.
* Standalone binary requires no dependencies and can be used instantly without loading any libraries.
* Not affected by ld_preload style rootkits or tampered shared libraries on suspect hosts.
* Works against LKM rootkits such as Diamorphine, Reptile and variants. 
* Very lightweight and will not hook into kernel or cause system instability. 

# How Do I Use This?

Usage of `sandfly-processdecloak`:

Simply build and run `sandfly-processdecloak` on the command line. Hidden PIDs will be shown if found. 

# Examples

When run, the program will show all clean or PIDs that are suspicious:

## Clean System

```
root@sandfly-clean:~# ./sandfly-processdecloak
sandfly-processdecloak Version 1.0
Copyright (c) 2020 Sandfly Security - www.sandflysecurity.com

Decloaking hidden Process IDs (PIDS) on Linux host.
No hidden PIDs found.
```

## Reptile style LKM stealth rootkit

```
root@sandfly-dirty:~# ./sandfly-processdecloak 
sandfly-processdecloak Version 1.0

Copyright (c) 2020 Sandfly Security - www.sandflysecurity.com

Decloaking hidden Process IDs (PIDS) on Linux host.
Found hidden PID: 11468 with name: reptile_hidden
Found hidden PID: 15070 with name: reptile_shell
```

## Diamorphine style LKM stealth rootkit
```
root@sandfly-dirty:~# ./sandfly-processdecloak
sandfly-processdecloak Version 1.0

Copyright (c) 2020 Sandfly Security - www.sandflysecurity.com

Decloaking hidden Process IDs (PIDS) on Linux host.
Found hidden PID: 7171 with name: diamorphine_hid
```

# Build

* Install latest version of golang (www.golang.org)
* Use the following command:

`go get github.com/sandflysecurity/sandfly-processdecloak`

* Or clone the repo under your Golang src directory.
* Go into the repo directory and build it with instructions below.

## Basic Build

On the system architecture you want to compile for, copy the sources under your Golang src directory and run:

`go build sandfly-processdecloak.go`

## Build Scripts

There are a some basic build scripts that build for various platforms. You can use these to build or modify to suit.
For Incident Responders, it might be useful to keep pre-compiled binaries ready to go on your investigation box.

`build.sh` - Generic build for whatever architecture you are on when run.

`build_all.sh` - Builds all binaries for AMD, Intel, MIPS and Arm Linux architectures. 

`build_linux_adm64.sh` - Build for AMD64/Intel 64 bit architecture.
`build_linux_386.sh` - Build for 386/32 bit archtecture.
`build_linux_arm.sh` - Build for generic Arm archtecture.
`build_linux_arm5.sh` - Build for Armv5 archtecture.
`build_linux_arm6.sh` - Build for Armv6 archtecture.
`build_linux_arm7.sh` - Build for Armv7 archtecture.
`build_linux_arm64.sh` - Build for Arm 64 bit archtecture.
`build_linux_mips.sh` - Build for MIPS archtecture.
`build_linux_mips64.sh` - Build for MIPS 64 bit archtecture.

## Linux AMD/Intel64 Command Line Build

To build for basic Linux, go into the files under the Golang src directory and build:

`env GOOS=linux GOARCH=amd64 go build -o sandfly-processdecloak -ldflags="-s -w" 

Or for generic 386:

`env GOOS=linux GOARCH=386 go build -o sandfly-processdecloak -ldflags="-s -w"`

You can do the same for any supported Golang architecture on Linux. 

# False Positives

It's possible to flag a legitimate PID that is not actually cloaked. You will need to manually investigate the
/proc/PID directory to check if it is legitimate. Please report false positives to us if you find them. 

# Agentless Linux Security

Sandfly Security produces an agentless endpoint detection and incident response platform (EDR) for Linux. 
Automated entropy checks are just one of thousands of things we search for to find intruders without loading 
any software on your Linux endpoints.

Get a free license and learn more below:

https://www.sandflysecurity.com
@SandflySecurity

