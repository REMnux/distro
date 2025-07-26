/*
    Copyright 2013 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

#ifdef WIN32
    #include <windows.h>
    #include <tlhelp32.h>
#else
    #include <unistd.h>
    #include <sys/ptrace.h>

    typedef void *      HANDLE;
    typedef uint32_t    DWORD;
#endif



u32     g_fixed_rva     = 0;



#ifdef WIN32
void winerr(void) {
    u8      *message = NULL;

    FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL,
      GetLastError(),
      0,
      (char *)&message,
      0,
      NULL);

    if(message) {
        printf("\nError: %s\n", message);
        LocalFree(message);
    } else {
        printf("\nError: unknown Windows error\n");
    }
    exit(1);
}
#endif



#ifdef WIN32
#ifdef NO_VIRTUALPROTECTEX  // for jurassik Windows
    int VirtualProtectEx(HANDLE hp, void *addr, int size, DWORD flags, DWORD *dummy) { return(0); }
#endif
int read_mem(HANDLE hp, void *addr, void *buff, int size) {
    DWORD   ret,
            old;
    int     vp  = 0,
            wp;

    if(!(hp && (hp != INVALID_HANDLE_VALUE))) return(-1);
    vp = VirtualProtectEx(hp, addr, size, PAGE_READONLY, &old);
    wp = ReadProcessMemory(hp, addr, buff, size, &ret);
    if(vp) VirtualProtectEx(hp, addr, size, old, &old);
    if(!wp) return(-1);
    if(ret != size) return(-1);
    return(ret);
}
int write_mem(HANDLE hp, void *addr, void *buff, int size) {
    DWORD   ret,
            old;
    int     vp  = 0,
            wp;

    if(!(hp && (hp != INVALID_HANDLE_VALUE))) return(-1);
    vp = VirtualProtectEx(hp, addr, size, PAGE_READWRITE, &old);
    wp = WriteProcessMemory(hp, addr, buff, size, &ret);
    if(vp) VirtualProtectEx(hp, addr, size, old, &old);
    if(!wp) return(-1);
    if(ret != size) return(-1);
    return(ret);
}
#endif



    // thanx to the extalia.com forum

u8 *process_list(u8 *myname, DWORD *mypid, DWORD *size) {
#ifdef WIN32
    PROCESSENTRY32  Process;
    MODULEENTRY32   Module;
    HANDLE          snapProcess,
                    snapModule;
    DWORD           retpid = 0;
    int             len;
    BOOL            b;
    u8              tmpbuff[60],
                    *process_name,
                    *module_name,
                    *module_print,
                    *tmp;

    if(mypid) retpid = *mypid;
    if(!myname && !retpid) {
        printf(
            "  pid/addr/size       process/module name\n"
            "  ---------------------------------------\n");
    }

#define PROCESS_START(X,Y) \
            snap##X = CreateToolhelp32Snapshot(Y, Process.th32ProcessID); \
            X.dwSize = sizeof(X); \
            for(b = X##32First(snap##X, &X); b; b = X##32Next(snap##X, &X)) { \
                X.dwSize = sizeof(X);
#define PROCESS_END(X) \
            } \
            CloseHandle(snap##X);

    Process.th32ProcessID = 0;
    PROCESS_START(Process, TH32CS_SNAPPROCESS)
        process_name = Process.szExeFile;

        if(!myname && !retpid) {
            printf("  %-10lu ******** %s\n",
                Process.th32ProcessID,
                process_name);
        }
        if(myname && stristr(process_name, myname)) {
            retpid = Process.th32ProcessID;
        }

        PROCESS_START(Module, TH32CS_SNAPMODULE)
            module_name = Module.szExePath; // szModule?

            len = strlen(module_name);
            if(len >= 60) {
                tmp = strrchr(module_name, '\\');
                if(!tmp) tmp = strrchr(module_name, '/');
                if(!tmp) tmp = module_name;
                len -= (tmp - module_name);
                snprintf(tmpbuff, sizeof(tmpbuff) - 1,
                    "%.*s...%s",
                    54 - len,
                    module_name,
                    tmp);
                module_print = tmpbuff;
            } else {
                module_print = module_name;
            }

            if(!myname && !retpid) {
                printf("    %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
            }
            if(!retpid) {
                if(myname && stristr(module_name, myname)) {
                    retpid = Process.th32ProcessID;
                }
            }
            if(retpid && mypid && (Process.th32ProcessID == retpid)) {
                printf("- %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
                *mypid = retpid;
                if(size) *size = Module.modBaseSize;
                return(Module.modBaseAddr);
            }

        PROCESS_END(Module)

    PROCESS_END(Process)

#undef PROCESS_START
#undef PROCESS_END

#else

    //system("ps -eo pid,cmd");
    printf("\n"
        "- use ps to know the pids of your processes, like:\n"
        "  ps -eo pid,cmd\n");

#endif

    return(NULL);
}



int process_read_par(u8 *pname, u32 *mem_offset, u32 *mem_size) {
    int     tmp_o   = INVALID_OFFSET,
            tmp_s   = 0;
    u8      *p;

    if(mem_offset) *mem_offset = INVALID_OFFSET;
    if(mem_size)   *mem_size   = 0;

    p = strchr(pname, ':');
    if(p) {
        *p++ = 0;
        if(sscanf(p, "%x:%x", &tmp_o, &tmp_s) < 1) {
            printf("\n"
                "Error: you must specify both offset and size in hex, example:\n"
                "       -P 1234:00401234\n"
                "       -P 1234:00401234:1234\n"
            );
            exit(1);
            return(-1);
        }
        if(mem_offset) *mem_offset = tmp_o;
        if(mem_size)   *mem_size   = tmp_s;
    }
    return(0);
}



u8 *process_read(u8 *pname, int *fdlen) {
    u32     mem_offset  = INVALID_OFFSET,
            mem_size    = 0;

#ifdef WIN32

    HANDLE  process;
    DWORD   tmp,
            pid,
            size;
    int     t,
            len;
    u8      *baddr,
            *buff;

    g_fixed_rva = 0;                                    // win and linux
    if(fdlen) *fdlen = 0;                               // win and linux
    if(!pname && !pname[0]) return(NULL);               // win and linux
    process_read_par(pname, &mem_offset, &mem_size);    // win and linux

    if(pname) {
        len = 0;
        sscanf(pname, "%u%n", &t, &len);
        pid = t;
        if(len != strlen(pname)) pid = 0;
    }

    baddr = process_list(pid ? NULL : pname, &pid, &size);
    if(!baddr) {
        printf("\nError: process name/PID not found, use -p\n");
        exit(1);
    }

    printf(
        "- pid %u\n"
        "- base address 0x%08x\n",
        (u32)pid, (u32)baddr);

    process = OpenProcess(
        PROCESS_VM_READ,
        FALSE,
        pid);
    if(!process) winerr();

    if(mem_offset != INVALID_OFFSET) {
        baddr = (void *)mem_offset;
        if(mem_size) {
            size  = mem_size;
        } else {
            // sorry, just a quick way to avoid enumeration
            // it will be improved in future... maybe
            for(size = 0;; size += sizeof(tmp)) {
                if(!ReadProcessMemory(
                    process,
                    (void *)(baddr + size),
                    &tmp,
                    sizeof(tmp),
                    &tmp)
                ) break;
            }
        }
    }
    printf("- offset %p size %08x\n", baddr, (u32)size);

    buff = malloc(size);
    if(!buff) std_err();

    size = read_mem(process, (void *)baddr, buff, size);
    if(size == -1) winerr();

    CloseHandle(process);

#else

    // Linux is not much supported, this is just a work-around

    pid_t   pid;
    u32     baddr,
            size,
            buffsz,
            data;
    u8      *buff;

    g_fixed_rva = 0;                                    // win and linux
    if(fdlen) *fdlen = 0;                               // win and linux
    if(!pname && !pname[0]) return(NULL);               // win and linux
    process_read_par(pname, &mem_offset, &mem_size);    // win and linux

    pid = atoi(pname);
    baddr = 0x08048000; // sorry, not completely supported at the moment
                        // and reading /proc/PID/maps doesn't sound good

    if(mem_offset) baddr = mem_offset;

    printf(
        "- pid %u\n"
        "- try using base address 0x%08x\n",
        pid, baddr);

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) std_err();

    size    = 0;
    buffsz  = 0;
    buff    = NULL;

    for(errno = 0; ; size += 4) {
        if(mem_size && (size >= mem_size)) break;

        if(!(size & 0xfffff)) fputc('.', stdout);

        data = ptrace(PTRACE_PEEKDATA, pid, (void *)baddr + size, NULL);
        if(errno) {
            if(errno != EIO) std_err();
            break;
        }

        if(size >= buffsz) {
            buffsz += 0x80000;
            buff = realloc(buff, buffsz);
            if(!buff) std_err();
        }
        memcpy(buff + size, &data, 4);
    }
    fputc('\n', stdout);
    buff = realloc(buff, size);
    if(!buff) std_err();

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) std_err();

#endif

    g_fixed_rva = (u32)baddr;
    if(fdlen) *fdlen = size;
    return(buff);
}



int set_pid_int3(u8 *pname, u32 int3) {
    int     ret = -1;
#ifdef WIN32
    HANDLE  process;
    DWORD   pid;
    int     t,
            len;

    if(!pname && !pname[0]) return -1;
    process_read_par(pname, NULL, NULL);

    if(pname) {
        len = 0;
        sscanf(pname, "%u%n", &t, &len);
        pid = t;
        if(len != strlen(pname)) pid = 0;
    }

    if(!pid) {
        process_list(pname, &pid, NULL);
    }
    if(!pid) return -1;

    printf("- pid %u\n", (int)pid);

    process = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        pid);
    if(!process) winerr();
    printf("- write INT3 at offset %08x\n", int3);
    ret = write_mem(process, (LPVOID)int3, "\xcc", 1);
    if(ret < 0) printf("Error: write_mem failed\n");
    CloseHandle(process);
#else
    printf("\nError: PID INT3 is not supported on this operating system\n");
    exit(1);
#endif
    return ret;
}
