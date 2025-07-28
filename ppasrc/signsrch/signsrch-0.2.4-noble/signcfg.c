/*
    Copyright 2007-2013 Luigi Auriemma

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

#define TYPE_8BIT       (1 << 0)
#define TYPE_16BIT      (1 << 1)
#define TYPE_32BIT      (1 << 2)
#define TYPE_64BIT      (1 << 3)
#define TYPE_FLOAT      (1 << 4)
#define TYPE_DOUBLE     (1 << 5)
#define TYPE_CRC        (1 << 6)
#define TYPE_FORCE_HEX  (1 << 7)
#define TYPE_AND        (1 << 8)
#define TYPE_NOBIG      (1 << 9)



#define ENDIAN_LITTLE   0
#define ENDIAN_BIG      1



enum {
    CMD_TITLE,
    CMD_TYPE,
    CMD_DATA,
    CMD_NONE = -1
};



u64     g_current_type      = 0;
u8      *g_current_title    = NULL;



int delimit(u8 *data) {
    u8      *p;

    if(!data) return(0);
    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
    return(p - data);
}



int string_tolower(u8 *data) {
    u8      *p;

    if(!data) return(0);
    for(p = data; *p; p++) {
        *p = tolower(*p);
    }
    return(p - data);
}



u64 readbase(u8 *data, int size, int *ret_len) {
    static const u8 table[] = "0123456789abcdef";
    u64     num;
    int     sign = 0;
    u8      c,
            *p,
            *s;

    if(ret_len) *ret_len = 0;
    if(!data || !data[0]) return(0);
    p = data;

    if(*p == '-') {  // useless in calcc but can be useful in other programs
        sign = -1;
        p++;
    }

    if((strlen(p) > 2) && (p[0] == '0') && (p[1] == 'x')) {
        size = 16;      // hex
        p += 2;
    } else if((size == 10) && (p[0] == '0')) {
        size = 8;       // octal
        p++;
    }

    for(num = 0; *p; p++) {
        c = tolower(*p); // needed
        s = memchr(table, c, size);
        if(!s) break;
        num = (num * size) + (s - table);
    }
    if(sign < 0) num = -num;
    if(ret_len) *ret_len = p - data;
    return(num);
}



u64 get_fmt_char(u8 **data) {
    u64     n = 0;
    int     len;
    u8      *p;

    if(!data) return(0);
    p = *data;
    if(!p || !p[0]) {
        *data = NULL;
        return(0);
    }
    if(p[0] == '\\') {    // \n and so on
        len = 0;
        switch(p[1]) {
            case 0:    n = 0;    break;
            case '0':  n = '\0'; break;
            case 'a':  n = '\a'; break;
            case 'b':  n = '\b'; break;
            case 'e':  n = '\e'; break;
            case 'f':  n = '\f'; break;
            case 'n':  n = '\n'; break;
            case 'r':  n = '\r'; break;
            case 't':  n = '\t'; break;
            case 'v':  n = '\v'; break;
            case '\"': n = '\"'; break;
            case '\'': n = '\''; break;
            case '\\': n = '\\'; break;
            case '?':  n = '\?'; break;
            case '.':  n = '.';  break;
            case ' ':  n = ' ';  break;
            case 'x':  n = readbase(p + 2, 16, &len);   break;  // hex
            default:   n = readbase(p + 1,  8, &len);   break;  // auto
        }
        len += 2;
    } else {
        len = 1;
        n = p[0]; // 'a'
    }

    p += len;
    if(!p[0]) {
        *data = NULL;
    } else {
        *data = p;
    }
    return(n);
}



int check_num_type(u8 *data) {
    int     c,
            ret = 0;
    u8      *p;

    if(!data) return(ret);
    for(p = data; (c = *p); p++) {
        if((c >= '0') && (c <= '9')) {
            // ret = 0;
        } else if((c >= 'a') && (c <= 'f')) {
            ret = TYPE_FORCE_HEX;
        } else if(c == '.') {
            ret = TYPE_FLOAT;
            break;
        }
    }
    return(ret);
}



u64 get_num(u8 *data) {
    float   numf;
    double  numlf;
    int     chk;
    u64     num;
    u32     tmp32;
    u8      *p;

    if(!data || !data[0]) return(0);

    num = 0;
    if(data[0] == '\'') {
        p = data + 1;
        num = get_fmt_char(&p);
    } else {
        string_tolower(data);

        if(data[0] == '_') data++;
        chk = check_num_type(data);

        if(!strcmp(data, "int_min")) {                                  // INT_MIN
            num = (u64)0x80000000;
        } else if(!strcmp(data, "int_max")) {                           // INT_MAX
            num = (u64)0x7fffffff;
        } else if(!strcmp(data, "i64_min")) {                           // I64_MIN
            num = (u64)0x8000000000000000ULL;
        } else if(!strcmp(data, "i64_max")) {                           // I64_MAX
            num = (u64)0x7fffffffffffffffULL;
        } else if(g_current_type & TYPE_DOUBLE) {                         // DOUBLE
            //if(chk != TYPE_FLOAT) printf("- %s\n  a double without dot???\n", g_current_title);
            numlf = atof(data);
            memcpy(&num, &numlf, sizeof(numlf));
        } else if(strchr(data, '.') || (g_current_type & TYPE_FLOAT)) {   // FLOAT
            //if(chk != TYPE_FLOAT) printf("- %s\n  a float without dot???\n", g_current_title);
            numf = atof(data);
            memcpy(&tmp32, &numf, 4);
            num = tmp32;
        } else if(strstr(data, "0x") || strchr(data, '$') || strchr(data, 'h') || (g_current_type & TYPE_FORCE_HEX)){
            if(chk == TYPE_FLOAT) goto error;                           // HEX
            num = readbase(data, 16, NULL);
        } else {                                                        // DECIMAL
            if((chk == TYPE_FORCE_HEX) || (chk == TYPE_FLOAT)) goto error;
            num = readbase(data, 10, NULL);
        }
    }

    return(num);

error:
    printf("\n"
        "Error: %s\n"
        "       get_num() the number \"%s\" doesn't match the type specified\n",
        g_current_title,
        data);
    free_sign();
    exit(1);
    return(0);
}



u8 *get_cfg_cmd(u8 *line, int *cmdnum) {
    static const u8 *command[] = {
            "TITLE",
            "TYPE",
            "DATA",
            NULL
    };
    int     i,
            cmdret;
    u8      *cmd,
            *p,
            *l;

    cmdret = CMD_NONE;
    if(cmdnum) *cmdnum = CMD_NONE;

    delimit(line);

    for(p = line; *p && (*p <= ' '); p++);  // clear start
    if(!*p) return(NULL);

    cmd = p;

    for(l = line + strlen(line) - 1; (l >= p) && (*l <= ' '); l--); // clear end
    if(l[0]) l[1] = 0;

    if(strchr("=#/;", cmd[0])) return(NULL);  // comments

    for(p = cmd; *p && (*p > ' '); p++);    // find where the command ends

    for(i = 0; command[i]; i++) {
        if(!memcmp(cmd, command[i], p - cmd)) {
            cmdret = i;
            break;
        }
    }

    if(cmdret != CMD_NONE) {    // skip the spaces between the comamnd and the instructions
        for(; *p && (*p <= ' '); p++);
        // never enable: if(!*p) return(NULL);
        cmd = p;
    }

    // do not enable this or will not work!
    // if(strchr("=#/;", cmd[0])) return("");

    if(cmdnum) *cmdnum = cmdret;
    return(cmd);
}



    /* here we catch each line (till line feed) */
    /* returns a pointer to the next line       */
u8 *get_line(u8 *data) {
    u8      *p;

    if(!data) return(NULL);
    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    if(!*p) return(NULL);
    *p = 0;
    for(++p; *p && ((*p == '\n') || (*p == '\r')); p++);
    if(!*p) return(NULL);
    return(p);
}



    /* here we catch each element of the line */
    /* returns a pointer to the next element  */
u8 *get_element(u8 **data, int *isastring) {
    u8      *p;

    if(isastring) *isastring = 0;
    if(!data) return(NULL);
    p = *data;

    if(p[0] == '\'') {
        for(++p; *p; p++) {
            if(p[0] == '\'') {
                p++;
                break;
            }
        }
    } else if((p[0] == '/') && (p[1] == '*')) {    // /* comment */
        for(p += 2; *p; p++) {
            if((p[0] == '*') && (p[1] == '/')) {
                p += 2;
                break;
            }
        }
    } else if(*p == '"') {                  // string
        if(isastring) *isastring = 1;
        p++;
        for(*data = p; *p && (*p != '\"'); p++) {
            if(*p == '\\') {
                p++;
                if(!*p) break;
            }
        }
    } else {
        if(isastring) *isastring = 0;   // the following are delimiters
        while(*p && !strchr(" \t,{}()\\", *p)) {
            if((*p == '%') || (*p == '*')) {    // + and - are ok, it's not easy to make distinction between inline operations and negative/positive numbers of exponential floats
                fprintf(stderr, "\nError: found some invalid chars in the list\n");
                exit(1);
            }
            p++;
        }
    }

    if(!*p) return(NULL);                   // end of line
    *p = 0;

    for(++p; *p && ((*p == '\t') || (*p == ' ')); p++);
    if(!*p) return(NULL);                   // start of next line
    return(p);
}



int cfg_title(u8 *line) {
    FREEZ(g_current_title)
    g_current_title = strdup(line);
    return(0);
}



int cfg_type(u8 *line) {
    u8      *next,
            *sc,
            *scn;

    if(!line) return(-1);
    g_current_type = 0;

    next = NULL;
    do {
        next = get_line(line);

        sc  = line;
        scn = NULL;
        do {
            scn = get_element(&sc, NULL);

            if(strchr("#/;", sc[0])) break; // comments, ';' is used also at the end of the C structures

            string_tolower(sc); // so no need to use stri*

#define C(X)    !strcmp(sc, X)
#define S(X)    strstr(sc, X)
            if(C("unsigned")) continue;
            if(C("signed")) continue;
            if(!strncmp(sc, "u_", 2)) sc += 2;
            if(sc[0] == 'u') sc++;

            if(S("64") || S("longlong") || S("filetime"))           g_current_type |= TYPE_64BIT;
            if(S("32") || C("int")  || C("dword") || S("long") ||
               S("bool") || S("void") || S("handle") || S("time"))  g_current_type |= TYPE_32BIT;
            if(S("16") || C("word") || S("short") || S("wchar"))    g_current_type |= TYPE_16BIT;
            if(S("8")  || S("char") || S("byte")  || S("string"))   g_current_type |= TYPE_8BIT;

            if(C("float") || C("double"))                           g_current_type |= TYPE_FLOAT;
            if(C("crc")   || C("checksum"))                         g_current_type |= TYPE_CRC;
            if(C("hex")   || C("forcehex"))                         g_current_type |= TYPE_FORCE_HEX;
            if(C("and")   || C("&&"))                               g_current_type |= TYPE_AND;
            if(C("nobig"))                                          g_current_type |= TYPE_NOBIG;
#undef C
#undef S

            sc = scn;
        } while(scn);

        line = next;
    } while(next);
    return(0);
}



u8 *cfg_add_element(u8 *op, int *oplen, u64 num, int bits, int endian) {
    int     len = *oplen;

    if(!op) len = 0;
    if(!g_alt_endian && (endian == ENDIAN_BIG)) return(op); // no endian alternative
    if(bits % 8) bits = (bits + 7) & (~7);
    if((bits == 8) && (endian == ENDIAN_BIG)) return(op);   // avoid duplicate

    if((int64_t)num >= 0) {
        if((bits == 8)  && (num > 0xff))        goto error;
        if((bits == 16) && (num > 0xffff))      goto error;
        if((bits == 32) && (num > 0xffffffff))  goto error;
    }

    len += (bits / 8);
    op = realloc(op, len);
    if(!op) std_err();

    if(bits == 8) {
        op[len - 1] = num;

    } else if(bits == 16) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 2] = (num      );
            op[len - 1] = (num >>  8);
        } else {
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }

    } else if(bits == 32) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 4] = (num      );
            op[len - 3] = (num >>  8);
            op[len - 2] = (num >> 16);
            op[len - 1] = (num >> 24);
        } else {
            op[len - 4] = (num >> 24);
            op[len - 3] = (num >> 16);
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }

    } else if(bits == 64) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 8] = (num      );
            op[len - 7] = (num >>  8);
            op[len - 6] = (num >> 16);
            op[len - 5] = (num >> 24);
            op[len - 4] = (num >> 32);
            op[len - 3] = (num >> 40);
            op[len - 2] = (num >> 48);
            op[len - 1] = (num >> 56);
        } else {
            op[len - 8] = (num >> 56);
            op[len - 7] = (num >> 48);
            op[len - 6] = (num >> 40);
            op[len - 5] = (num >> 32);
            op[len - 4] = (num >> 24);
            op[len - 3] = (num >> 16);
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }
    }

    *oplen = len;
    return(op);

error:
    printf("\n"
        "Error: %u) %s\n"
        "       the number 0x%08x%08x is bigger than %d bits\n"
        "       check your signature file, probably you must increate the TYPE size\n",
        g_signs, g_current_title,
        (u32)((num >> 32) & 0xffffffff), (u32)(num & 0xffffffff), bits);
    free_sign();
    exit(1);
    return(NULL);
}    



void add_sign(u8 *type, u8 *endian, u8 *data, int datasize, int bits, int is_crc) {
    static int  g_signs_max = 0; // avoid many reallocs

    if(!datasize) return;
    if(!type || !type[0]) endian = "";
    if(g_signs >= g_signs_max) {
        g_signs_max += 4096;   // a big amount
        g_sign = realloc(g_sign, g_signs_max * sizeof(sign_t *));
        if(!g_sign) std_err();
    }
    g_sign[g_signs]         = calloc(1, sizeof(sign_t));
    if(!g_sign[g_signs]) std_err();
    g_sign[g_signs]->title  = malloc(strlen(g_current_title) + strlen(type) + strlen(endian) + 10 + 16 + 1);
    sprintf(g_sign[g_signs]->title, "%s [%s.%s.%u%s]",
        g_current_title, type, endian, datasize, (g_current_type & TYPE_AND) ? "&" : "");
    g_sign[g_signs]->data   = data;
    g_sign[g_signs]->size   = datasize;
    g_sign[g_signs]->and    = 0;
    g_sign[g_signs]->is_crc = is_crc;
    g_sign[g_signs]->offset = INVALID_OFFSET;
    if(g_current_type & TYPE_AND) g_sign[g_signs]->and = bits;
    g_signs++;
}



#include "crc.c"



int mycrc(u64 num, int bits, int endian, int rever, int bitmask_side) {
    int     opcrclen    = 0;
    u8      *opcrc      = NULL;
    u8      tmp[256],
            type[32];

    // do nothing because it's the same of ENDIAN_LITTLE
    if((endian == ENDIAN_BIG) && (bits <= 8)) return(-1);

    opcrc = crc_make_table(NULL, &opcrclen,
        num,
        bits,
        endian,
        rever,
        bitmask_side,
        (void *)cfg_add_element);

    if(!opcrc) return(-1);

         if(bits <= 8)  sprintf(tmp, "0x%02x",     (int)(num & 0xff));
    else if(bits <= 16) sprintf(tmp, "0x%04x",     (int)(num & 0xffff));
    else if(bits <= 32) sprintf(tmp, "0x%08x",     (int)(num));
    else                sprintf(tmp, "0x%08x%08x", (int)(num >> 32), (int)num);

    sprintf(tmp + strlen(tmp),
        " %ce%s%s",
        endian ? 'b' : 'l',
        rever ? " rev" : "norev",
        (bitmask_side > 0) ? " 1" : " int_min");

    sprintf(type, "crc%d", bits);

    add_sign(type, tmp, opcrc, opcrclen, bits, 1);

    return(0);
}



int cfg_data(u8 *line) {
    int     opi8len     = 0,
            opi16len    = 0,
            opi32len    = 0,
            opi64len    = 0,
            opifltlen   = 0,
            opidbllen   = 0;
    u8      *opi8       = NULL,
            *opi16      = NULL,
            *opi32      = NULL,
            *opi64      = NULL,
            *opiflt     = NULL,
            *opidbl     = NULL;

    int     opb8len     = 0,
            opb16len    = 0,
            opb32len    = 0,
            opb64len    = 0,
            opbfltlen   = 0,
            opbdbllen   = 0;
    u8      *opb8       = NULL,   // NEVER used
            *opb16      = NULL,
            *opb32      = NULL,
            *opb64      = NULL,
            *opbflt     = NULL,
            *opbdbl     = NULL;

    int     opstrlen    = 0;
    u8      *opstr      = NULL;

    u64     num;
    int     i,
            isastring   = 0;
    u8      *next,
            *sc,
            *scn,
            *p;

    if(!line) return(-1);
    if(!g_current_type) g_current_type |= TYPE_8BIT;

    next = NULL;
    do {
        next = get_line(line);

        sc  = line;
        scn = NULL;
        do {
            scn = get_element(&sc, &isastring);

            if((sc[0] == '/') && (sc[1] == '*')) goto scn_continue; // don't touch
            if((sc[0] == '#') || (sc[0] == '/') || (sc[0] == ';')) break; // comments, ';' is used also at the end of the C structures
            if(!sc[0]) goto scn_continue;

            if(isastring) {
                for(p = sc; p;) {
                    num = get_fmt_char(&p);
                    opstr = cfg_add_element(opstr, &opstrlen, num, 8, ENDIAN_LITTLE);
                }
                goto scn_continue;
            }

            num = get_num(sc);

            if(g_current_type & TYPE_CRC) {

#define DOIT(TYPENAME, BITS)  \
                if(g_current_type & TYPENAME) { \
                    for(i = 0; i < 2; i++) { \
                        mycrc(num, BITS, i, 0, 0); \
                        mycrc(num, BITS, i, 0, 1); \
                        mycrc(num, BITS, i, 1, 0); \
                        mycrc(num, BITS, i, 1, 1); \
                    } \
                }

                DOIT(TYPE_8BIT,   8)
                DOIT(TYPE_16BIT,  16)
                DOIT(TYPE_32BIT,  32)
                DOIT(TYPE_64BIT,  64)

#undef DOIT

                goto scn_continue;
            }

#define DOIT(TYPENAME, NAME, BITS)  \
            if(g_current_type & TYPENAME) {  \
                opi##NAME = cfg_add_element(opi##NAME, &opi##NAME##len, num, BITS, ENDIAN_LITTLE);  \
                opb##NAME = cfg_add_element(opb##NAME, &opb##NAME##len, num, BITS, ENDIAN_BIG);     \
            }

            DOIT(TYPE_8BIT,   8,   8)
            DOIT(TYPE_16BIT,  16,  16)
            DOIT(TYPE_32BIT,  32,  32)
            DOIT(TYPE_64BIT,  64,  64)
            DOIT(TYPE_FLOAT,  flt, 32)

                /* stupid and lame work-around for double and float */
                /* but it works 8-) */
            if(g_current_type & TYPE_FLOAT) {   // if float = do double too
                g_current_type |= TYPE_DOUBLE;  // enable double
                num = get_num(sc);              // re-read the number
                DOIT(TYPE_DOUBLE, dbl, 64)      // add it
                g_current_type ^= TYPE_DOUBLE;  // disable double
            }

#undef DOIT

scn_continue:
            sc = scn;
        } while(scn);

        line = next;
    } while(next);

    if(g_current_type & TYPE_CRC) return(0);

#define DOIT(NAME, BITS, TYPE)    \
    if(opi##NAME) add_sign(TYPE, "le", opi##NAME, opi##NAME##len, BITS, 0); \
    if(g_current_type & TYPE_NOBIG) {                                       \
        FREEZ(opb##NAME)                                                    \
    }                                                                       \
    if(opb##NAME) {                                                         \
        if(opi##NAME) { /* remove duplicates! */                            \
            if(!memcmp(opi##NAME, opb##NAME, opb##NAME##len)) {             \
                FREEZ(opb##NAME)                                            \
            } else {                                                        \
                add_sign(TYPE, "be", opb##NAME, opb##NAME##len, BITS, 0);   \
            }                                                               \
        }                                                                   \
    }

    DOIT(8,     8,      "")
    DOIT(16,    16,     "16")
    DOIT(32,    32,     "32")
    DOIT(64,    64,     "64")
    DOIT(flt,   32,     "float")
    DOIT(dbl,   64,     "double") 
    if(opstr) add_sign("", "", opstr, opstrlen, 8, 0);

#undef DOIT
    return(0);
}



int cfg_cmd(int cmdnum, u8 *line) {
    switch(cmdnum) {
        case CMD_TITLE: cfg_title(line);    break;
        case CMD_TYPE:  cfg_type(line);     break;
        case CMD_DATA:  cfg_data(line);     break;
        default:                            break;
    }
    return(0);
}



int read_cfg(u8 *filename) {
    FILE    *fd;
    int     len,
            currlen,
            bufflen,
            oldnum,
            cmdnum,
            tmp;
    u8      line[256],
            *buff,
            *buff_limit,
            *data,
            *ins;

    printf("- open file %s\n", filename);
    fd = fopen(filename, "rb");
    if(!fd) return(-1); //std_err();

    bufflen    = 256;
    buff       = malloc(bufflen + 1);
    if(!buff) std_err();
    data       = buff;
    buff_limit = buff + bufflen;
    buff[0]    = 0;
    line[0]    = 0;
    oldnum     = CMD_NONE;

    while(fgets(line, sizeof(line), fd)) {
        ins = get_cfg_cmd(line, &cmdnum);
        if(!ins) continue;

        if(oldnum == CMD_NONE) oldnum = cmdnum;
        if(cmdnum == CMD_NONE) cmdnum = oldnum;
        if(cmdnum != oldnum) {
            tmp    = cmdnum;
            cmdnum = oldnum;
            oldnum = tmp;

            cfg_cmd(cmdnum, buff);

            data = buff;
        }

        len = strlen(ins);  // allocation
        if((data + len) >= buff_limit) {
            currlen    = data - buff;
            bufflen    = currlen + 1 + len + 1; // 1 for \n and 1 for the final NULL byte
            buff       = realloc(buff, bufflen + 1);
            if(!buff) std_err();
            data       = buff + currlen;
            buff_limit = buff + bufflen;
        }

        if(data > buff) data += sprintf(data, "\n");
        data += sprintf(data, "%s", ins);
        line[0] = 0;
    }
        // the remaining line
    cmdnum = oldnum;
    if((cmdnum != CMD_NONE) && (data != buff)) cfg_cmd(cmdnum, buff);

    FREEZ(buff)
    fclose(fd);
    return(0);
}
