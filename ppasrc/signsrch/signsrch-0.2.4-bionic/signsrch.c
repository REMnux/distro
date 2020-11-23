/*
    Copyright 2007-2016 Luigi Auriemma

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include "show_dump.h"

typedef unsigned char   uchar;
typedef unsigned short  ushort;
typedef unsigned long   ulong;

#ifndef ISS // -Wdeclaration-after-statement
    #define MAINPROG
    #include "disasm.h"
#endif

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;

#ifdef WIN32
    #include <direct.h>
    #include <windows.h>
    #include <tlhelp32.h>
    #define PATHSLASH   '\\'
    #define sleepms(X)  Sleep(X)
#else
    #include <dirent.h>
    #include <unistd.h>
    #include <sys/ptrace.h>

    #define stricmp strcasecmp
    #define strnicmp strncasecmp
    //#define stristr strcasestr
    #define PATHSLASH   '/'
    #define sleepms(X)  usleep(X * 1000)
    typedef void *      HANDLE;
    typedef uint32_t    DWORD;
#endif
#include "threads.h"



#define VER                 "0.2.4"
#define STD_ERR             std_err()
#define mystrdup            strdup
#define PATHSZ              2000
#define MAX_AND_DISTANCE    ((pattern_len < (3000/32)) ? (pattern_len * 32) : 3000) // was 3000
#define SIGNFILE            "/usr/share/signsrch/signsrch.sig"
#define SIGNFILEWEB         "http://aluigi.org/mytoolz/signsrch.sig.zip"
#define INVALID_OFFSET      (-1)
#define FREEZ(X)            if(X) { free(X); X = NULL; }

#ifdef SEARCH_DEBUG
    #define signsrch_search search_non_hashed
#else
    #define signsrch_search search_hashed
#endif

#define SCAN_SIGNS(FROM, TO, FILEMEM, FILEMEMSZ) \
        for(i = FROM; i < TO; i++) { \
            if(g_sign[i]->disabled) continue; \
            g_sign[i]->offset = signsrch_search(FILEMEM, FILEMEMSZ, g_sign[i]->data, g_sign[i]->size, g_sign[i]->and); \
        }



#pragma pack(1)
typedef struct {
    u8      *title;
    u8      *data;
    u16     size;
    u8      and;
    u8      is_crc;
    u32     offset;
    u8      disabled;
} sign_t;
#pragma pack()

typedef struct {
    u32     offset;
    int     sign_num;
    int     done;
} result_t;

typedef struct {
    u8      *filemem;   // pointer to the original one, don't free it
    int     filememsz;  // having them here may be useful in future

    // thread specific:
    int     from_sign;
    int     to_sign;
    int     done;
} thread_info_t;



sign_t  **g_sign        = NULL;
u64     g_force_rva     = 0;
int     g_signs         = 0,
        g_alt_endian    = 1,
        g_do_rva        = 1,
        myendian        = 1;    // big endian
int     g_signatures_to_scans = 0;
u8      **g_signatures_to_scan = NULL;



void parse_signatures_to_scan(u8 *arg);
quick_thread(signsrch_thread, thread_info_t *info);
int get_cpu_number(void);
int sort_results(result_t *result, int results);
int signsrch_int3(u32 int3, int argi, int argc, char **argv);
char *stristr(const char *String, const char *Pattern);
int check_is_dir(u8 *fname);
int recursive_dir(u8 *filedir, int filedirsz);
void find_functions(u8 *filemem, int filememsz, u32 store_offset, int sign_num);
void std_err(void);
u8 *get_main_path(u8 *fname, u8 *argv0);
void free_sign(void);
u8 *fd_read(u8 *name, int *fdlen);
void fd_write(u_char *name, u_char *data, int datasz);
u32 search_non_hashed(u8 *filemem, int filememsz, u8 *pattbuff, int pattsize, int and);
#include "parse_exe.c"
void help(u8 *arg0);
#include "scan.c"
#include "signcfg.c"
#include "signcrc.c"
#include "hal_search.c"
#include "process.c"



parse_exe_t g_pe = {NULL};



int main(int argc, char *argv[]) {
    static  u8  bckdir[PATHSZ + 1]  = "",
                filedir[PATHSZ + 1] = "";

    thread_info_t   *thread_info    = NULL;
    result_t        *result         = NULL;
    files_t         *files          = NULL;

    int     filememsz   = 0;
    u8      *filemem    = NULL;

    time_t  benchkmark;
    u32     i,
            j,
            n,
            found,
            offset,
            int3        = INVALID_OFFSET;
    int     argi,
            threads,
            force_threads = 0,
            listsign    = 0,
            dumpsign    = 0,
            input_total_files = 0,
            exe_scan    = 0;    // 0=to_be_set -1=no_scan 1=do_scan 2=do_scan+references
    u8      *pid        = NULL,
            *dumpfile   = NULL,
            *sign_file  = NULL,
            *p          = NULL,
            *filter_in_files_tmp = NULL;
    char    **argx      = NULL;

    setbuf(stdin,  NULL);
    //setbuf(stdout, NULL); // better performances, everything is on one line
    setbuf(stderr, NULL);

    fputs("\n"
        "Signsrch " VER "\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "  optimized search function by Andrew http://www.team5150.com/~andrew/\n"
        "  disassembler engine by Oleh Yuschuk\n"
        "\n", stderr);

    if(argc < 2) {
        help(argv[0]);
    }

    for(i = 1; i < argc; i++) {
        if(!stricmp(argv[i], "--help")) help(argv[0]);
        if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) break;
        switch(argv[i][1]) {

            #define NO_ARGV_ERROR(X) \
                if(!argv[++i]) { \
                    printf("\nError: " X " needed\n"); \
                    exit(1); \
                }

            case '-':
            case 'h':
            case '?':                                       help(argv[0]);              break;
            case 'l':                                       listsign  = 1;              break;
            case 'L': NO_ARGV_ERROR("signature number")     dumpsign  = atoi(argv[i]);  break;
            case 's': NO_ARGV_ERROR("signature filename")   sign_file = argv[i];        break;
            case 'p':                                       pid = "";                   break;
            case 'P': NO_ARGV_ERROR("process name or pid")  pid = argv[i];              break;
            case 'd': NO_ARGV_ERROR("dump file name")       dumpfile = argv[i];         break;
            case 'e':                                       exe_scan = 1;               break;
            case 'F':                                       exe_scan = 2;               break;
            case 'E':                                       exe_scan = -1;              break;
            case 'b':                                       g_alt_endian = 0;           break;
            case '3': NO_ARGV_ERROR("INT3 offset")          int3 = get_num(argv[i]);    break;
            case 'f': NO_ARGV_ERROR("filter wildcard")      filter_in_files_tmp = argv[i]; break;
            case 'S': NO_ARGV_ERROR("signature to scan")    parse_signatures_to_scan(argv[i]); break;
            case 't': NO_ARGV_ERROR("number of threads")    force_threads = atoi(argv[i]); break;
            case 'a': NO_ARGV_ERROR("forced image address") g_force_rva = get_num(argv[i]); break;
            default: {
                printf("\nError: wrong argument (%s)\n", argv[i]);
                exit(1);
                break;
            }
        }
    }
    argi = i;

    if(*(char *)&myendian) myendian = 0;    // little endian

    if(pid && !pid[0]) {    // pid ""
        process_list(NULL, NULL, NULL);
        goto quit;
    }

    benchkmark = time(NULL);

    if(int3 != INVALID_OFFSET) {
        if(pid) {
            set_pid_int3(pid, int3);
        } else {
            signsrch_int3(int3, argi, argc, argv);
        }
        printf("- done\n");
        return(0);  // exit
    }

    argx = calloc(argc + 1, sizeof(char *));
    if(!argx) std_err();
    for(i = 0; i < argc; i++) {
        argx[i] = strdup(argv[i]);
    }
    argx[i] = NULL;
    argv = argx;

redo:
    if(listsign) {
        // do nothing now
    } else if(dumpsign) {
        // do nothing now
    } else {
        if(pid) {
            filemem = process_read(pid, &filememsz);
            if(!exe_scan) exe_scan = -1;
            g_do_rva = 0;
        } else {
            if(argi == argc) {
                printf("\nError: you must specify the file to scan\n");
                exit(1);
            }
            if(check_is_dir(argv[argi])) {
                fprintf(stderr, "- start the scanning of the input folder: %s\n", argv[argi]);
                if(filter_in_files_tmp) {
                    if(!filter_in_files_tmp[0]) filter_in_files_tmp = "*.exe;*.dll";
                    filter_in_files = build_filter(filter_in_files_tmp);
                    FREEZ(filter_in_files_tmp)
                }
                if(!getcwd(bckdir, PATHSZ)) STD_ERR;
                if(chdir(argv[argi]) < 0) STD_ERR;
                strcpy(filedir, ".");
                recursive_dir(filedir, PATHSZ);

                files = add_files(NULL, 0, &input_total_files);
                if(input_total_files <= 0) {
                    fprintf(stderr, "\nError: the input folder is empty\n");
                    exit(1);
                }
                if(chdir(bckdir) < 0) STD_ERR;

                argv = realloc(argv, (argc + input_total_files + 1) * sizeof(char *));
                if(!argv) std_err();
                p = argv[argi]; // will be freed later!
                for(i = argc - 1; i >= argi; i--) {
                    argv[i + input_total_files] = argv[i + 1];
                }
                argv[argc + input_total_files] = NULL;
                for(i = 0; i < input_total_files; i++) {
                    argv[argi + i] = malloc(strlen(p) + 1 + strlen(files[i].name) + 1);
                    sprintf(argv[argi + i], "%s%c%s", p, PATHSLASH, files[i].name);
                }
                argc--; // remove argv[argi]
                argc += input_total_files;
                input_total_files = 0;
                FREEZ(p)
            }
            filemem = fd_read(argv[argi], &filememsz);
        }
        printf("- %u bytes allocated\n", filememsz);
    }

    if(dumpfile) {
        fd_write(dumpfile, filemem, filememsz);
        goto quit;
    }

    if(!g_sign) {
        printf("- load signatures\n");

        if(
            read_cfg(sign_file ? sign_file : get_main_path(SIGNFILE, argv[0]))
        < 0) std_err();
        
        printf("- %u signatures in the database\n", g_signs);
        if(!dumpsign) signcrc();

        if(g_signatures_to_scan) {
            // blacklist all
            for(j = 0; j < g_signs; j++) {
                g_sign[j]->disabled = 1;
            }
            // whitelist
            for(i = 0; i < g_signatures_to_scans; i++) {
                n = atoi(g_signatures_to_scan[i]);
                if(n <= 0) {
                    for(j = 0; j < g_signs; j++) {
                        if(stristr(g_sign[j]->title, g_signatures_to_scan[i])) break;
                    }
                    if(j < g_signs) n = j;
                    else n = -1;
                } else {
                    n--;    // number + 1
                }
                
                if((n >= 0) && (n < g_signs)) {
                    g_sign[n]->disabled = 0;
                }
            }
        }
    }
    
    if(dumpsign > 0) {
        dumpsign--;
        if(dumpsign >= g_signs) {
            printf("\nError: wrong signature number\n");
            exit(1);
        }
        printf("  %s\n", g_sign[dumpsign]->title);
        show_dump(g_sign[dumpsign]->data, g_sign[dumpsign]->size, stdout);
        goto quit;
    }

    if(listsign) {
        printf("\n"
            "  num  description [bits.endian.size]\n"
            "-------------------------------------\n");
        for(i = 0; i < g_signs; i++) {
            if(g_sign[i]->disabled) continue;
            printf("  %-4u %s\n", i + 1, g_sign[i]->title);
        }
        printf("\n");
        goto quit;
    }

    if(filememsz > (10 * 1024 * 1024)) {   // more than 10 megabytes
        printf(
            "- WARNING:\n"
            "  the file loaded in memory is very big so the scanning may take many time\n");
    }

    if(exe_scan > 0) {
        if(pe_parse_exe(&g_pe, filemem, filememsz, 1) < 0) {
            printf(
                "- input is not an executable or is not supported by this tool\n"
                "  the data will be handled in raw mode\n");
            exe_scan = 0;
        }
    }

    threads = get_cpu_number();
    if(threads <= 0) threads = 1;
    if(force_threads > 0) threads = force_threads;
    printf("- start %d threads\n", threads);

    printf(
        "- start signatures scanning:\n"
        "\n"
        "  offset   num  description [bits.endian.size]\n"
        "  --------------------------------------------\n");

    if(threads <= 1) {

        SCAN_SIGNS(
            0,
            g_signs,
            filemem,
            filememsz)

    } else {

        thread_info = calloc(threads, sizeof(thread_info_t));
        if(!thread_info) std_err();

        n = 0;
        for(i = 0; i < threads; i++) {
            thread_info[i].filemem     = filemem;
            thread_info[i].filememsz   = filememsz;
            thread_info[i].from_sign   = n;
            if(i >= (threads - 1))  n  = g_signs;
            else                    n += (g_signs / threads);
            thread_info[i].to_sign     = n;

            quick_threadx(signsrch_thread, &thread_info[i]);
        }

        for(;;) {
            for(i = 0; i < threads; i++) {
                if(!thread_info[i].done) break;
            }
            if(i >= threads) break;
            sleepms(100);
        }

        FREEZ(thread_info)
    }

    result = calloc(g_signs + 1, sizeof(result_t));
    if(!result) std_err();

        // sorting: step one

    found = 0;
    for(i = 0; i < g_signs; i++) {
        if(g_sign[i]->disabled) continue;
        if(g_sign[i]->offset == INVALID_OFFSET) continue;
        result[found].offset   = g_sign[i]->offset;
        result[found].sign_num = i;
        result[found].done     = 0;
        found++;
    }

        // sorting: step two

    sort_results(result, found);

        // visualization

    for(i = 0; i < found; i++) {
        offset = result[i].offset;
        if(g_force_rva) {
            offset += g_force_rva;
        } else {
            if(exe_scan > 0) offset = (u32)pe_file2rva(&g_pe, offset); // full RVA
            if(exe_scan < 0) offset += g_fixed_rva;     // no EXE scan, use static image address
        }
        if(exe_scan == 2) {                         // references
            find_functions(filemem, filememsz, offset, result[i].sign_num);
            fputc('.', stderr);
        } else {
            printf("  %08x %-4u %s\n", offset, result[i].sign_num + 1, g_sign[result[i].sign_num]->title);
        }
    }

    if(exe_scan == 2) {
        fputc('\n', stderr);
        find_functions(filemem, filememsz, -1, -1);
    }

    printf("\n- %u signatures found in the file in %u seconds\n", found, (u32)(time(NULL) - benchkmark));

    FREEZ(result)
    FREEZ(filemem)
    FREEZ(g_pe.section)
    if(++argi < argc) {
        fputc('\n', stdout);
        goto redo;
    }

quit:
    free_sign();
    fprintf(stderr, "- done\n");
    return(0);
}



void parse_signatures_to_scan(u8 *arg) {
    u8      *p,
            *l;

    for(p = arg; *p; p = l) {
        l = strchr(p, ',');
        if(l) *l++ = 0;
        else  l = p + strlen(p);
        
        g_signatures_to_scan = realloc(g_signatures_to_scan, g_signatures_to_scans * sizeof(u8 *));
        g_signatures_to_scan[g_signatures_to_scans++] = p;  //no need of strdup(p);
    }
}



quick_thread(signsrch_thread, thread_info_t *info) {
    int     i;

    SCAN_SIGNS(
        info->from_sign,
        info->to_sign,
        info->filemem,
        info->filememsz)

    info->done = 1;
    return(0);
}



int get_cpu_number(void) {
    #ifdef WIN32
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        return info.dwNumberOfProcessors;
    #else
        #ifdef _SC_NPROCESSORS_ONLN
        return sysconf(_SC_NPROCESSORS_ONLN);
        #endif
    #endif
    return(-1);
}



int sort_results(result_t *result, int results) {
    result_t    rtmp;
    int         i,
                j;

    if(!results) return(-1);
    for(i = 0; i < (results - 1); i++) {
        for(j = i + 1; j < results; j++) {
            if(result[i].offset > result[j].offset) {
                memcpy(&rtmp,      &result[i], sizeof(result_t));
                memcpy(&result[i], &result[j], sizeof(result_t));
                memcpy(&result[j], &rtmp,      sizeof(result_t));
            }
        }
    }
    return(0);
}



int signsrch_int3(u32 int3, int argi, int argc, char **argv) {
#ifdef WIN32
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    int     i,
            cmdlen;
    char    *cmd,
            *error;

    if(int3 == INVALID_OFFSET) return(-1);

    cmdlen = 0;
    for(i = argi; i < argc; i++) {
        cmdlen += 1 + strlen(argv[i]) + 1 + 1;
    }
    cmd = malloc(cmdlen + 1);
    if(!cmd) std_err();
    cmdlen = 0;
    for(i = argi; i < argc; i++) {
        cmdlen += sprintf(cmd + cmdlen, "\"%s\" ", argv[i]);
    }

    GetStartupInfo(&si);
    if(!CreateProcess(NULL, cmd, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0, (char *)&error, 0, NULL);
        printf("\n"
            "Error: problems during the launching of\n"
            "       %s\n"
            "       Windows reported this error: %s\n"
            "\n", cmd, error);
        LocalFree(error);
        exit(1);
    }
    for(i = 0; i < 2; i++) {
        if(i) Sleep(2000);  // in case of packed executables, maybe to fix in future
        SuspendThread(pi.hThread);
        write_mem(pi.hProcess, (LPVOID)int3, "\xcc", 1);
        ResumeThread(pi.hThread);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
#else
    printf("\nError: the INT3 option is not supported on this platform\n");
    exit(1);
#endif
    printf("- process launched with INT3 applied at address %08x\n", int3);
    return(0);
}



int check_is_dir(u8 *fname) {
    struct stat xstat;

    if(!fname) return(1);
    if(stat(fname, &xstat) < 0) return(0);
    if(!S_ISDIR(xstat.st_mode)) return(0);
    return(1);
}



void find_functions(u8 *filemem, int filememsz, u32 store_offset, int sign_num) {
#ifndef ISS
    static  result_t    *offsets_array  = NULL;
    static  int offsets = 0,
                offsets_max = 0;

    t_disasm da;
    u32     func;
    int     i,
            asm_size,
            section_exe,
            offset;
    u8      *addr,
            *limit;

    lowercase   = 1;
    extraspace  = 1;
    showmemsize = 1;

    if(sign_num >= 0) {
        if(offsets >= offsets_max) {
            offsets_max += 512;
            offsets_array = realloc(offsets_array, offsets_max * sizeof(result_t));
            if(!offsets_array) std_err();
        }
        offsets_array[offsets].offset   = store_offset;
        offsets_array[offsets].sign_num = sign_num;
        offsets_array[offsets].done     = 0;
        offsets++;
        return;
    }

    for(section_exe = 0; section_exe < g_pe.sections; section_exe++) {

        // only the sections tagged as executable
        if(!(g_pe.section[section_exe].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))) continue;

        i = g_pe.section[section_exe].PointerToRawData + g_pe.section[section_exe].SizeOfRawData;
        if((i < 0) || (i > filememsz)) continue;
        limit = filemem + i;
        addr  = filemem + g_pe.section[section_exe].PointerToRawData;

    // from the old dump2func
    // this part of the code (used by -F) will be rewritten from scratch in future
    // maybe using a different disassembly library and adding multiple references
    // to the same function instead of just the first one

    for(        ; addr < limit; addr += asm_size) {
        asm_size = olly_Disasm(addr, limit - addr, 0, &da, DISASM_CODE); // DISASM_DATA);
        if(asm_size <= 0) break;

        if(g_do_rva) func = (u32)pe_file2rva(&g_pe, addr - filemem);
        else         func = (u32)((addr - filemem) + g_pe.imagebase);

        for(i = 0; i < offsets; i++) {
            if(offsets_array[i].done) continue;
            // the instruction covers the offset
            if((func <= offsets_array[i].offset) && ((func + asm_size) >= offsets_array[i].offset)) break;
        }
        if(i < offsets) goto set_offset;

        if(!(
            ((da.cmdtype & C_TYPEMASK) == C_CMD) ||
            ((da.cmdtype & C_TYPEMASK) == C_PSH) ||
            ((da.cmdtype & C_TYPEMASK) == C_DAT) ||
            ((da.cmdtype & C_TYPEMASK) == C_JMP) ||
            ((da.cmdtype & C_TYPEMASK) == C_JMC) ||
            ((da.cmdtype & C_TYPEMASK) == C_RTF)
        )) {
            continue;
        }

        for(i = 0;; i++) {
                 if(i == 0) offset = da.adrconst;   // mov eax, dword ptr [4*ecx+OFFSET]
            else if(i == 1) offset = da.immconst;   // mov eax, OFFSET
            else if(i == 2) offset = da.jmpconst;
            else if(i == 3) offset = da.jmptable;   // this is wrong, will be fixed in future
            else {
                offset = 0;
                break;
            }
            if(offset <= 0) continue;
            if((void *)offset <= (void *)g_pe.imagebase) continue;
            break;
        }
        if(offset <= 0) continue;

        for(i = 0; i < offsets; i++) {
            if(offsets_array[i].done) continue;
            if(offset == offsets_array[i].offset) break;
        }
        if(i >= offsets) continue;

set_offset:
        offsets_array[i].offset = func;
        offsets_array[i].done   = 1;
        fputc('.', stderr);
    }
    }
    fputc('\n', stderr);

    sort_results(offsets_array, offsets);

    for(i = 0; i < offsets; i++) {
        printf("  %08x %-4u %s\n", offsets_array[i].offset, offsets_array[i].sign_num + 1, g_sign[offsets_array[i].sign_num]->title);
    }

    // free the offsets for reusing them later!
    offsets = 0;
    // no need of freeing offsets_array
#endif
}



u8 *get_main_path(u8 *fname, u8 *argv0) {
    static u8   fullname[PATHSZ + 1];
    u8      *p;

#ifdef WIN32
    GetModuleFileName(NULL, fullname, sizeof(fullname));
#else
    sprintf(fullname, "%.*s", sizeof(fullname), argv0);
#endif

    p = strrchr(fullname, '\\');
    if(!p) p = strrchr(fullname, '/');
    if(!p) p = fullname - 1;
    sprintf(p + 1, "%.*s", sizeof(fullname) - (p - fullname), fname);
    return(fullname);
}



void free_sign(void) {
    int     i;

    if(!g_sign) return;
    for(i = 0; i < g_signs; i++) {
        FREEZ(g_sign[i]->title)
        FREEZ(g_sign[i]->data)
        FREEZ(g_sign[i])
    }
    FREEZ(g_sign);
    g_signs = 0;
}



u8 *fd_read(u8 *name, int *fdlen) {
    struct  stat    xstat;
    FILE    *fd;
    int     len,
            memsize,
            filesize;
    u8      *buff;

    if(!strcmp(name, "-")) {
        printf("- open %s\n", "stdin");
        filesize = 0;
        memsize  = 0;
        buff     = NULL;
        for(;;) {
            if(filesize >= memsize) {
                memsize += 0x80000;
                buff = realloc(buff, memsize);
                if(!buff) std_err();
            }
            len = fread(buff + filesize, 1, memsize - filesize, stdin);
            if(!len) break;
            filesize += len;
        }
        buff = realloc(buff, filesize);
        if(!buff) std_err();

    } else {
        printf("- open file \"%s\"\n", name);
        fd = fopen(name, "rb");
        if(!fd) std_err();
        fstat(fileno(fd), &xstat);
        filesize = xstat.st_size;
        buff = malloc(filesize);
        if(!buff) std_err();
        filesize = fread(buff, 1, filesize, fd);
        fclose(fd);
    }

    if(fdlen) *fdlen = filesize;
    return(buff);
}



void fd_write(u_char *name, u_char *data, int datasz) {
    FILE    *fd;

    printf("- create file %s\n", name);
    fd = fopen(name, "rb");
    if(fd) {
        fclose(fd);
        printf("- file already exists, do you want to overwrite it (y/N)?\n  ");
        fflush(stdin);
        if(tolower(fgetc(stdin)) != 'y') exit(1);
    }
    fd = fopen(name, "wb");
    if(!fd) std_err();
    fwrite(data, datasz, 1, fd);
    fclose(fd);
}



// old non-fast search, unused
u32 search_non_hashed(u8 *filemem, int filememsz, u8 *pattern, int pattern_len, int and) {
    u32     offset     = 0,
            min_offset = -1;
    int     max_and_distance;
    u8      *pattlimit,
            *limit,
            *patt,
            *p;

    if(filememsz < pattern_len) return(-1);

    max_and_distance = MAX_AND_DISTANCE;

    and >>= 3;
    limit     = filemem + filememsz - pattern_len;
    pattlimit = pattern + pattern_len - and;

    if(and) {
        p = filemem;
        for(patt = pattern; patt <= pattlimit; patt += and) {
            for(p = filemem; p <= limit; p++) {
                if(!memcmp(p, patt, and)) {
                    offset = p - filemem;
                    if(offset < min_offset) min_offset = offset;
                    if((offset - min_offset) > max_and_distance) return(-1);
                    break;
                }
            }
            if(p > limit) return(-1);
        }
        return(min_offset);
    } else {
        for(p = filemem; p <= limit; p++) {
            if(!memcmp(p, pattern, pattern_len)) {
                return(p - filemem);
            }
        }
    }
    return(-1);
}



void help(u8 *arg0) {
    printf("\n"
        "Usage: %s [options] [file1] ... [fileN]\n"
        "\n"
        "Options:\n"
        "-l       list the available signatures in the database\n"
        "-L NUM   show the data of the signature NUM\n"
        "-s FILE  use the signature file FILE ("SIGNFILE")\n"
        "-p       list the running processes and their modules\n"
        "-P PID[] use the process/module identified by its pid or part of name/path\n"
        "         it accepts also offset and the optionally size in hex\n"
        "         -P PID:OFFSET or -P PID:OFFSET:SIZE\n"
        "         the PID value must be used instead of [file*]\n"
        "-d FILE  dump the process memory (like -P) in FILE\n"
        "-e       consider the input file as an executable (PE/ELF), useful to show the\n"
        "         rva addresses instead of the file offsets\n"
        "-F       as above but returns the address of the first instruction that points\n"
        "         to the found signature, for example where the AES Td0 table is used,\n"
        "         something like an automatic \"Find references\" of Ollydbg\n"
        "-E       disable the automatic executable parsing used with -P\n"
        "-b       disable the scanning of the big endian versions of the signatures\n"
#ifdef WIN32
        "-3 OFF   execute the file placing an INT3 byte (0xcc) at the specified offset\n"
        "         (memory address, not file offset!), remember to have a debugger set\n"
        "         as \"Just-in-time\" debugger.\n"
        "         if -P is specified, the int3 will be placed directly in the process\n"
#endif
        "-f W     wildcard used to filter the file to parse if you specify a folder\n"
        "         for example -f \"*.exe;*.dll\"\n"
        "-S N,... scan only the signatures identified by their index number or by part\n"
        "         of title, eg. -S zipcrypto,10,11\n"
        "-t NUM   force the usage of NUM threads\n"
        "-a ADDR  force the usage of ADDR as base address for the results\n"
        "\n"
        "use - for stdin\n"
        "the tool accepts folders too\n"
        "URL for the updated "SIGNFILE": "SIGNFILEWEB"\n"
        "\n", arg0);
    exit(1);
}



char *stristr(const char *String, const char *Pattern)
{
      char *pptr, *sptr, *start;

      for (start = (char *)String; *start; start++)
      {
            /* find start of pattern in string */
            for ( ; (*start && (toupper(*start) != toupper(*Pattern))); start++)
                  ;
            if (!*start)
                  return 0;

            pptr = (char *)Pattern;
            sptr = (char *)start;

            while (toupper(*sptr) == toupper(*pptr))
            {
                  sptr++;
                  pptr++;

                  /* if end of pattern then pattern was found */

                  if (!*pptr)
                        return (start);
            }
      }
      return 0;
}



void std_err(void) {
    perror("\nError");
    exit(1);
}

