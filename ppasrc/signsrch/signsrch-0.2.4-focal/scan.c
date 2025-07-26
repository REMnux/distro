/*
    Copyright 2012-2013 Luigi Auriemma

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
#else
    #include <dirent.h>
#endif



typedef struct {
    u8      *name;
    //int     offset; // unused at the moment
    int     size;
} files_t;
u8  **filter_in_files   = NULL;



int check_wildcard(u8 *fname, u8 *wildcard) {
    u8      *f      = fname,
            *w      = wildcard,
            *last_w = NULL,
            *last_f = NULL;

    if(!fname) return -1;
    if(!wildcard) return -1;
    while(*f || *w) {
        if(!*w && !last_w) return -1;
        if(*w == '?') {
            if(!*f) break;
            w++;
            f++;
        } else if(*w == '*') {
            w++;
            last_w = w;
            last_f = f;
        } else {
            if(!*f) break;
            if(((*f == '\\') || (*f == '/')) && ((*w == '\\') || (*w == '/'))) {
                f++;
                w++;
            } else if(tolower(*f) != tolower(*w)) {
                if(!last_w) return -1;
                w = last_w;
                if(last_f) f = last_f;
                f++;
                if(last_f) last_f = f;
            } else {
                f++;
                w++;
            }
        }
    }
    if(*f || *w) return -1;
    return 0;
}



int check_wildcards(u8 *fname, u8 **list) {
    int     i;

    // no wildcards to check = ok
    if(!list) return(0);
    for(i = 0; list[i]; i++) {
        if(!check_wildcard(fname, list[i])) return(0);
    }
    return(-1);
}



#include "utils.c"



// necessary to avoid that Windows handles the format... even if delimited by quotes
u8 **build_filter(u8 *filter) {
    int     i,
            len,
            ret_n;
    u8      *tmp_filter,
            *p,
            *l,
            **ret   = NULL;

    if(!filter || !filter[0]) return(NULL);

    tmp_filter = strdup(filter);

    ret_n = 0;
    for(p = tmp_filter; p && *p; p = l) {
        for(     ; *p &&  strchr(" \t\r\n", *p); p++);

        for(l = p; *l && !strchr(",;|\r\n", *l); l++);
        if(!*l) l = NULL;
        else    *l++ = 0;

        p = skip_delimit(p);
        if(!p[0]) continue;

        // "{}.exe" (/bin/find like)
        find_replace_string(p, NULL, "{}", -1, "*", -1);

        // "\"*.exe\""
        len = strlen(p);
        if((p[0] == '\"') && (p[len - 1] == '\"')) {
            len -= 2;
            mymemmove(p, p + 1, len);
            p[len] = 0;
        }

        ret = realloc(ret, (ret_n + 1) * sizeof(u8 *));
        if(!ret) STD_ERR;
        ret[ret_n] = strdup(p);
        ret_n++;
    }

    if(ret) {
        ret = realloc(ret, (ret_n + 1) * sizeof(u8 *));
        if(!ret) STD_ERR;
        ret[ret_n] = NULL;
    }
    for(i = 0; ret[i]; i++) {
        fprintf(stderr, "- filter %3d: %s\n", (int32_t)(i + 1), ret[i]);
    }
    FREEZ(tmp_filter)
    return(ret);
}



files_t *add_files(u8 *fname, int fsize, int *ret_files) {
    static int      filesi  = 0,
                    filesn  = 0;
    static files_t  *files  = NULL;
    files_t         *ret;

    if(ret_files) {
        *ret_files = filesi;
        files = realloc(files, sizeof(files_t) * (filesi + 1)); // not needed, but it's ok
        if(!files) std_err();
        files[filesi].name   = NULL;
        //files[filesi].offset = 0;
        files[filesi].size   = 0;
        ret    = files;
        filesi = 0;
        filesn = 0;
        files  = NULL;
        return(ret);
    }

    if(!fname) return(NULL);
    if(check_wildcards(fname, filter_in_files) < 0) return(NULL);

    if(filesi >= filesn) {
        filesn += 1024;
        files = realloc(files, sizeof(files_t) * filesn);
        if(!files) std_err();
    }
    files[filesi].name   = strdup(fname);
    //files[filesi].offset = 0;
    files[filesi].size   = fsize;
    filesi++;
    return(NULL);
}



#define recursive_dir_skip_path 0
//#define recursive_dir_skip_path 2
int recursive_dir(u8 *filedir, int filedirsz) {
    int     plen,
            namelen,
            ret     = -1;

#ifdef WIN32
    static int      winnt = -1;
    OSVERSIONINFO   osver;
    WIN32_FIND_DATA wfd;
    HANDLE          hFind = INVALID_HANDLE_VALUE;

    if(!filedir) return(ret);

    if(winnt < 0) {
        osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&osver);
        if(osver.dwPlatformId >= VER_PLATFORM_WIN32_NT) {
            winnt = 1;
        } else {
            winnt = 0;
        }
    }

    plen = strlen(filedir);
    if((plen + 4) >= filedirsz) goto quit;
    strcpy(filedir + plen, "\\*.*");
    plen++;

    if(winnt) { // required to avoid problems with Vista and Windows7!
        hFind = FindFirstFileEx(filedir, FindExInfoStandard, &wfd, FindExSearchNameMatch, NULL, 0);
    } else {
        hFind = FindFirstFile(filedir, &wfd);
    }
    if(hFind == INVALID_HANDLE_VALUE) goto quit;
    do {
        if(!strcmp(wfd.cFileName, ".") || !strcmp(wfd.cFileName, "..")) continue;

        namelen = strlen(wfd.cFileName);
        if((plen + namelen) >= filedirsz) goto quit;
        //strcpy(filedir + plen, wfd.cFileName);
        memcpy(filedir + plen, wfd.cFileName, namelen);
        filedir[plen + namelen] = 0;

        if(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if(recursive_dir(filedir, filedirsz) < 0) goto quit;
        } else {
            add_files(filedir + recursive_dir_skip_path, wfd.nFileSizeLow, NULL);
        }
    } while(FindNextFile(hFind, &wfd));
    ret = 0;

quit:
    if(hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
#else
    struct  stat    xstat;
    struct  dirent  **namelist;
    int     n,
            i;
    char    *name;

    if(!filedir) return(ret);

    n = scandir(filedir, &namelist, NULL, NULL);
    if(n < 0) {
        if(stat(filedir, &xstat) < 0) {
            fprintf(stderr, "**** %s", filedir);
            std_err();
        }
        add_files(filedir + recursive_dir_skip_path, xstat.st_size, NULL);
        return(0);
    }

    plen = strlen(filedir);
    if((plen + 1) >= filedirsz) goto quit;
    strcpy(filedir + plen, "/");
    plen++;

    for(i = 0; i < n; i++) {
        name = namelist[i]->d_name;
        if(!strcmp(name, ".") || !strcmp(name, "..")) continue;

        namelen = strlen(name);
        if((plen + namelen) >= filedirsz) goto quit;
        //strcpy(filedir + plen, name);
        memcpy(filedir + plen, name, namelen);
        filedir[plen + namelen] = 0;

        if(stat(filedir, &xstat) < 0) {
            fprintf(stderr, "**** %s", filedir);
            std_err();
        }
        if(S_ISDIR(xstat.st_mode)) {
            if(recursive_dir(filedir, filedirsz) < 0) goto quit;
        } else {
            add_files(filedir + recursive_dir_skip_path, xstat.st_size, NULL);
        }
        free(namelist[i]);
    }
    ret = 0;

quit:
    for(; i < n; i++) free(namelist[i]);
    free(namelist);
#endif
    filedir[plen - 1] = 0;
    return(ret);
}

