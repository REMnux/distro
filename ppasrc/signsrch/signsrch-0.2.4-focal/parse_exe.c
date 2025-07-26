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

#ifdef WIN32
    #include <windows.h>
#else
    #include "pe_nonwin.h"
#endif

#define PARSE_EXE_SECNAMESZ 32
#define PARSE_EXE_MYPAD(X)  ((X + (pe->sec_align - 1)) & (~(pe->sec_align - 1)))
#define PARSE_EXE_MIN(a,b)  ((a)<(b)?(a):(b))
#define PARSE_EXE_MAX(a,b)  ((a)>(b)?(a):(b))
#define pe_myswap16(X)      X = pe_swap16(X)
#define pe_myswap32(X)      X = pe_swap32(X)
#define pe_myswap64(X)      X = pe_swap64(X)



typedef struct {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} MYIMAGE_NT_HEADERS32;

typedef struct {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} MYIMAGE_NT_HEADERS64;

typedef struct {    // from http://hte.sf.net
    u32     vsize;
    u32     base_reloc_addr;
    u32     flags;
    u32     page_map_index;
    u32     page_map_count;
    u8      name[4];
} vxd_section_t;

typedef struct {
    u8      e_ident[16];
    u16     e_type;
    u16     e_machine;
    u32     e_version;
    u32     e_entry;
    u32     e_phoff;
    u32     e_shoff;
    u32     e_flags;
    u16     e_ehsize;
    u16     e_phentsize;
    u16     e_phnum;
    u16     e_shentsize;
    u16     e_shnum;
    u16     e_shstrndx;
} elf32_header_t;

typedef struct {
    u8      e_ident[16];
    u16     e_type;
    u16     e_machine;
    u32     e_version;
    u64     e_entry;
    u64     e_phoff;
    u64     e_shoff;
    u32     e_flags;
    u16     e_ehsize;
    u16     e_phentsize;
    u16     e_phnum;
    u16     e_shentsize;
    u16     e_shnum;
    u16     e_shstrndx;
} elf64_header_t;

typedef struct {
    u32     sh_name;
    u32     sh_type;
    u32     sh_flags;
    u32     sh_addr;     
    u32     sh_offset;
    u32     sh_size;
    u32     sh_link;
    u32     sh_info;
    u32     sh_addralign;
    u32     sh_entsize;
} elf32_section_t;

typedef struct {
    u32     sh_name;
    u32     sh_type;
    u64     sh_flags;
    u64     sh_addr;     
    u64     sh_offset;
    u64     sh_size;
    u32     sh_link;
    u32     sh_info;
    u64     sh_addralign;
    u64     sh_entsize;
} elf64_section_t;

typedef struct {
    u8      Name[PARSE_EXE_SECNAMESZ + 1];
    u32     VirtualAddress;
    u32     VirtualSize;
    int     VirtualSize_off;
    u32     PointerToRawData;
    u32     SizeOfRawData;
    u32     Characteristics;
} pe_section_t;



typedef struct {
    u8          *imagebase;
    u8          *entrypoint;
    int         sections;
    int         sec_align;
    //u8          *image;
    int         image_size;
    int         bits;
    pe_section_t    *section;
} parse_exe_t;



static int  pe_myendian = 0;



static u16 pe_swap16(u16 n) {
    if(pe_myendian) {
        n = (((n & 0xff00) >> 8) |
             ((n & 0x00ff) << 8));
    }
    return n;
}



static u32 pe_swap32(u32 n) {
    if(pe_myendian) {
        n = (((n & 0xff000000) >> 24) |
             ((n & 0x00ff0000) >>  8) |
             ((n & 0x0000ff00) <<  8) |
             ((n & 0x000000ff) << 24));
    }
    return n;
}



static u64 pe_swap64(u64 n) {
    if(pe_myendian) {
        n = (u64)(((u64)(n) & 0xffLL) << (u64)56) |
            (u64)(((u64)(n) & 0xff00LL) << (u64)40) |
            (u64)(((u64)(n) & 0xff0000LL) << (u64)24) |
            (u64)(((u64)(n) & 0xff000000LL) << (u64)8) |
            (u64)(((u64)(n) & 0xff00000000LL) >> (u64)8) |
            (u64)(((u64)(n) & 0xff0000000000LL) >> (u64)24) |
            (u64)(((u64)(n) & 0xff000000000000LL) >> (u64)40) |
            (u64)(((u64)(n) & 0xff00000000000000LL) >> (u64)56);
    }
    return n;
}



int pe_parse_PE(parse_exe_t *pe, u8 *filemem, int filememsz, int full_parsing) {
    IMAGE_DOS_HEADER        *doshdr;
    MYIMAGE_NT_HEADERS32    *nt32hdr;
    MYIMAGE_NT_HEADERS64    *nt64hdr;
    IMAGE_ROM_HEADERS       *romhdr;
    IMAGE_OS2_HEADER        *os2hdr;
    IMAGE_VXD_HEADER        *vxdhdr;
    IMAGE_SECTION_HEADER    *sechdr;
    vxd_section_t           *vxdsechdr;
    u32     t;
    int     i;
    u8      *p;

    if(!pe) return -1;
    pe->bits = 32;

    pe_myendian = 1;
    if(*(char *)&pe_myendian) pe_myendian = 0;    // little endian

    if(!filemem) return(-1);
    p = filemem;
    doshdr  = (IMAGE_DOS_HEADER *)p;
    if(pe_myendian) {  // big endian
        pe_myswap16(doshdr->e_magic);
        pe_myswap16(doshdr->e_cs);
        pe_myswap16(doshdr->e_cparhdr);
        pe_myswap32(doshdr->e_lfanew);
        pe_myswap16(doshdr->e_ip);
    }
    if(doshdr->e_magic != IMAGE_DOS_SIGNATURE) return(-1);

    if(doshdr->e_cs) {  // note that the following instructions have been tested on various executables but I'm not sure if they are perfect
        t = doshdr->e_cparhdr * 16;
        if(doshdr->e_cs < 0x8000) t += doshdr->e_cs * 16;
        p += t;
    } else {
        if(doshdr->e_lfanew && (doshdr->e_lfanew < filememsz)) {
            p += doshdr->e_lfanew;
        } else {
            p += sizeof(IMAGE_DOS_HEADER);
        }
    }

    nt32hdr = (MYIMAGE_NT_HEADERS32 *)p;
    nt64hdr = (MYIMAGE_NT_HEADERS64 *)p;
    romhdr  = (IMAGE_ROM_HEADERS *)p;
    os2hdr  = (IMAGE_OS2_HEADER *)p;
    vxdhdr  = (IMAGE_VXD_HEADER *)p;

    if(pe_swap32(nt32hdr->Signature) == IMAGE_NT_SIGNATURE) {
        if(pe_swap32(nt32hdr->OptionalHeader.Magic) == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

            if(pe_myendian) {
                pe_myswap32(nt32hdr->Signature);
                pe_myswap16(nt32hdr->OptionalHeader.Magic);
                pe_myswap32(nt32hdr->OptionalHeader.ImageBase);
                pe_myswap32(nt32hdr->OptionalHeader.SectionAlignment);
                pe_myswap32(nt32hdr->OptionalHeader.AddressOfEntryPoint);
                pe_myswap16(nt32hdr->FileHeader.NumberOfSections);
            }

            p += sizeof(MYIMAGE_NT_HEADERS32);
            pe->imagebase   = (u8 *)nt32hdr->OptionalHeader.ImageBase;
            pe->sec_align   = nt32hdr->OptionalHeader.SectionAlignment;
            pe->entrypoint  = pe->imagebase + nt32hdr->OptionalHeader.AddressOfEntryPoint;
            pe->sections    = nt32hdr->FileHeader.NumberOfSections;

        } else if(pe_swap32(nt64hdr->OptionalHeader.Magic) == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            pe->bits = 64;

            if(pe_myendian) {
                pe_myswap32(nt64hdr->Signature);
                pe_myswap16(nt64hdr->OptionalHeader.Magic);
                pe_myswap64(nt64hdr->OptionalHeader.ImageBase);
                pe_myswap32(nt64hdr->OptionalHeader.SectionAlignment);
                pe_myswap32(nt64hdr->OptionalHeader.AddressOfEntryPoint);
                pe_myswap16(nt64hdr->FileHeader.NumberOfSections);
            }

            p += sizeof(MYIMAGE_NT_HEADERS64);
            pe->imagebase   = (u8 *)nt64hdr->OptionalHeader.ImageBase;
            pe->sec_align   = nt64hdr->OptionalHeader.SectionAlignment;
            pe->entrypoint  = pe->imagebase + nt64hdr->OptionalHeader.AddressOfEntryPoint;
            pe->sections    = nt64hdr->FileHeader.NumberOfSections;

        } else if(pe_swap16(romhdr->OptionalHeader.Magic) == IMAGE_ROM_OPTIONAL_HDR_MAGIC) {

            if(pe_myendian) {
                pe_myswap16(romhdr->OptionalHeader.Magic);
                pe_myswap32(romhdr->OptionalHeader.AddressOfEntryPoint);
            }

            p += sizeof(IMAGE_ROM_HEADERS);
            pe->imagebase   = NULL;
            pe->sec_align   = 0x1000;  // default in case not available;
            pe->entrypoint  = pe->imagebase + romhdr->OptionalHeader.AddressOfEntryPoint;
            pe->sections    = 0;
            pe->section     = NULL;
            return(0);

        } else {
            return(-1);
        }

        if(full_parsing) {
            pe->section = calloc(sizeof(pe_section_t), pe->sections);
            if(!pe->section) return(-1);

            sechdr = (IMAGE_SECTION_HEADER *)p;
            for(i = 0; i < pe->sections; i++) {
                if(pe_myendian) {
                    pe_myswap32(sechdr[i].VirtualAddress);
                    pe_myswap32(sechdr[i].Misc.VirtualSize);
                    pe_myswap32(sechdr[i].PointerToRawData);
                    pe_myswap32(sechdr[i].SizeOfRawData);
                    pe_myswap32(sechdr[i].Characteristics);
                }
                strncpy(pe->section[i].Name, sechdr[i].Name, IMAGE_SIZEOF_SHORT_NAME);
                pe->section[i].VirtualAddress   = sechdr[i].VirtualAddress;
                pe->section[i].VirtualSize      = sechdr[i].Misc.VirtualSize;
                pe->section[i].VirtualSize_off  = ((u8 *)&(sechdr[i].Misc.VirtualSize)) - filemem;
                pe->section[i].PointerToRawData = sechdr[i].PointerToRawData;
                pe->section[i].SizeOfRawData    = sechdr[i].SizeOfRawData;
                pe->section[i].Characteristics  = sechdr[i].Characteristics;
                if(!pe->section[i].VirtualSize) pe->section[i].VirtualSize = pe->section[i].SizeOfRawData;  // Watcom
            }
        }

    } else if(pe_swap16(os2hdr->ne_magic) == IMAGE_OS2_SIGNATURE) {

        if(pe_myendian) {
            pe_myswap16(os2hdr->ne_magic);
            pe_myswap16(os2hdr->ne_align);
            pe_myswap32(os2hdr->ne_csip);
        }

        p += sizeof(IMAGE_OS2_HEADER);
        pe->imagebase   = NULL;
        pe->sec_align   = os2hdr->ne_align;
        pe->entrypoint  = pe->imagebase + os2hdr->ne_csip;
        pe->sections    = 0;
        sechdr          = NULL;

    } else if(
      (pe_myswap16(vxdhdr->e32_magic) == IMAGE_OS2_SIGNATURE_LE) ||  // IMAGE_VXD_SIGNATURE is the same signature
      (pe_myswap16(vxdhdr->e32_magic) == 0x3357) ||                  // LX, W3 and W4: I guess they are the same... I hope
      (pe_myswap16(vxdhdr->e32_magic) == 0x3457) ||
      (pe_myswap16(vxdhdr->e32_magic) == 0x584C)) {

        if(pe_myendian) {
            pe_myswap16(vxdhdr->e32_magic);
            pe_myswap32(vxdhdr->e32_pagesize);
            pe_myswap32(vxdhdr->e32_objcnt);
            pe_myswap32(vxdhdr->e32_datapage);
            pe_myswap32(vxdhdr->e32_eip);
        }

        p += sizeof(IMAGE_VXD_HEADER);
        pe->imagebase   = NULL;
        pe->sec_align   = vxdhdr->e32_pagesize;
        pe->entrypoint  = NULL; // handled later
        pe->sections    = vxdhdr->e32_objcnt;

        if(full_parsing) {
            pe->section = calloc(sizeof(pe_section_t), pe->sections);
            if(!pe->section) return(-1);

            t = vxdhdr->e32_datapage;
            vxdsechdr = (vxd_section_t *)p;
            for(i = 0; i < pe->sections; i++) {
                if(pe_myendian) {
                    pe_myswap32(vxdsechdr[i].base_reloc_addr);
                    pe_myswap32(vxdsechdr[i].vsize);
                    pe_myswap32(vxdsechdr[i].flags);
                }
                strncpy(pe->section[i].Name, vxdsechdr[i].name, 4);
                pe->section[i].VirtualAddress   = vxdsechdr[i].base_reloc_addr;
                pe->section[i].VirtualSize      = vxdsechdr[i].vsize;
                pe->section[i].VirtualSize_off  = ((u8 *)&(vxdsechdr[i].vsize)) - filemem;
                pe->section[i].PointerToRawData = t;
                pe->section[i].SizeOfRawData    = vxdsechdr[i].vsize;
                pe->section[i].Characteristics  = vxdsechdr[i].flags;
                t += PARSE_EXE_MYPAD(pe->section[i].SizeOfRawData);
                if(!pe->entrypoint && (t > vxdhdr->e32_eip)) {    // I'm not totally sure if this is correct but it's not an important field
                    pe->entrypoint = (u8 *)vxdhdr->e32_eip + pe->section[i].VirtualAddress;
                }
            }
        }

    } else {
        pe->imagebase   = NULL;
        pe->sec_align   = 0;
        pe->entrypoint  = pe->imagebase + ((doshdr->e_cs < 0x8000) ? doshdr->e_ip : 0);
        pe->sections    = 0;
    }
    return(p - filemem);
}



int pe_parse_ELF32(parse_exe_t *pe, u8 *filemem, int filememsz, int full_parsing) {
    elf32_section_t *elf32sec   = NULL;
    elf64_section_t *elf64sec   = NULL;
    elf32_header_t  *elf32hdr;
    elf64_header_t  *elf64hdr;
    int     i;
    u8      *p;

    if(!pe) return -1;
    pe->bits = 32;

    pe_myendian = 1;
    if(*(char *)&pe_myendian) pe_myendian = 0;    // little endian

    if(!filemem) return(-1);
    p = filemem;
    elf32hdr = (elf32_header_t *)p;
    elf64hdr = (elf64_header_t *)p;
    if(memcmp(elf32hdr->e_ident, "\x7f""ELF", 4)) return(-1);

    if(((elf32hdr->e_ident[5] == 1) && pe_myendian) || ((elf32hdr->e_ident[5] != 1) && !pe_myendian)) {
        pe_myendian = !pe_myendian;
    }

    if(elf32hdr->e_ident[4] == 1) {
        p += sizeof(elf32_header_t);

        pe_myswap32(elf32hdr->e_entry);
        pe_myswap16(elf32hdr->e_shnum);
        pe_myswap32(elf32hdr->e_shoff);
        pe_myswap16(elf32hdr->e_shstrndx);

        pe->entrypoint  = (u8 *)elf32hdr->e_entry;
        pe->sections    = elf32hdr->e_shnum;

        elf32sec = (elf32_section_t *)(filemem + elf32hdr->e_shoff);

    } else if(elf64hdr->e_ident[4] == 2) {
        p += sizeof(elf64_header_t);

        pe_myswap64(elf64hdr->e_entry);
        pe_myswap16(elf64hdr->e_shnum);
        pe_myswap64(elf64hdr->e_shoff);
        pe_myswap16(elf64hdr->e_shstrndx);

        pe->entrypoint  = (u8 *)elf64hdr->e_entry;
        pe->sections    = elf64hdr->e_shnum;

        elf64sec = (elf64_section_t *)(filemem + elf64hdr->e_shoff);

    } else {
        return -1;
    }

    pe->imagebase   = NULL;
    pe->sec_align   = 0;

    if(full_parsing) {

        pe->section = calloc(sizeof(pe_section_t), pe->sections);
        if(!pe->section) return(-1);

        // some ELF files have invalid sh_addralign
        //    pe->section[i].VirtualAddress   = elf##X##sec[i].sh_addralign ? ((elf##X##sec[i].sh_addr + elf##X##sec[i].sh_addralign - 1) & ~(elf##X##sec[i].sh_addralign - 1)) : elf##X##sec[i].sh_addr;

        #define pe_elfsec(X) \
            strncpy(pe->section[i].Name, filemem + elf##X##sec[elf##X##hdr->e_shstrndx].sh_offset + elf##X##sec[i].sh_name, PARSE_EXE_SECNAMESZ); \
            pe->section[i].VirtualAddress   = elf##X##sec[i].sh_addr; \
            pe->section[i].VirtualSize      = elf##X##sec[i].sh_size; \
            pe->section[i].VirtualSize_off  = ((u8 *)&(elf##X##sec[i].sh_size)) - filemem; \
            pe->section[i].PointerToRawData = elf##X##sec[i].sh_offset; \
            pe->section[i].SizeOfRawData    = (elf##X##sec[i].sh_type & 8) ? 0 : elf##X##sec[i].sh_size; \
            pe->section[i].Characteristics  = elf##X##sec[i].sh_flags;


        for(i = 0; i < pe->sections; i++) {
            if(elf32sec) {
                pe_myswap32(elf32sec[i].sh_name);
                pe_myswap32(elf32sec[i].sh_addr);
                pe_myswap32(elf32sec[i].sh_offset);
                pe_myswap32(elf32sec[i].sh_size);
                pe_myswap32(elf32sec[i].sh_flags);
                pe_elfsec(32)
            } else {
                pe_myswap32(elf64sec[i].sh_name);
                pe_myswap64(elf64sec[i].sh_addr);
                pe_myswap64(elf64sec[i].sh_offset);
                pe_myswap64(elf64sec[i].sh_size);
                pe_myswap64(elf64sec[i].sh_flags);
                pe_elfsec(64)
            }
            pe->section[i].Name[PARSE_EXE_SECNAMESZ]  = 0;
            if(!pe->section[i].VirtualSize) pe->section[i].VirtualSize = pe->section[i].SizeOfRawData;  // Watcom
        }
    }

    i = p - filemem;
    if(i > filememsz) return(-1);
    return(i);
}



u64 pe_rva2file(parse_exe_t *pe, u8 *va) {
    u64     diff,
            fa;
    int     i,
            ret;

    if(!pe) return -1;

    fa   = va - pe->imagebase;
    ret  = -1;
    diff = -1;
    for(i = 0; i < pe->sections; i++) {
        if((pe->sections > 1) && !pe->section[i].VirtualAddress) continue;
        if((fa >= pe->section[i].VirtualAddress) && (fa < (pe->section[i].VirtualAddress + pe->section[i].VirtualSize))) {
            if((fa - pe->section[i].VirtualAddress) < diff) {
                diff = fa - pe->section[i].VirtualAddress;
                ret  = i;
            }
        }
    }
    //if(ret < 0) return(-1);
    if(ret < 0) return(fa);
    return(pe->section[ret].PointerToRawData + fa - pe->section[ret].VirtualAddress);
}



u8 *pe_file2rva(parse_exe_t *pe, u64 file) {
    u64     diff;
    int     i,
            ret;

    if(!pe) return NULL;

    ret  = -1;
    diff = -1;
    for(i = 0; i < pe->sections; i++) {
        if((file >= pe->section[i].PointerToRawData) && (file < (pe->section[i].PointerToRawData + pe->section[i].SizeOfRawData))) {
            if((file - pe->section[i].PointerToRawData) < diff) {
                diff = file - pe->section[i].PointerToRawData;
                ret  = i;
            }
        }
    }
    //if(ret < 0) return(-1);
    if(ret < 0) return(pe->imagebase + file);
    return(pe->imagebase + pe->section[ret].VirtualAddress + file - pe->section[ret].PointerToRawData);
}



int pe_get_section(parse_exe_t *pe, u64 file) {
    u64     diff;
    int     i,
            ret;

    if(!pe) return -1;

    ret  = -1;
    diff = -1;
    for(i = 0; i < pe->sections; i++) {
        if((file >= pe->section[i].PointerToRawData) && (file < (pe->section[i].PointerToRawData + pe->section[i].SizeOfRawData))) {
            if((file - pe->section[i].PointerToRawData) < diff) {
                diff = file - pe->section[i].PointerToRawData;
                ret  = i;
            }
        }
    }
    return(ret);
}



void pe_print_characteristics(u32 characteristics) {
    printf("  %08x:", characteristics);
    #define pe_print_characteristics2(X) if(characteristics & X) printf(" %s", #X)
    #ifndef WIN64
    pe_print_characteristics2(IMAGE_SCN_TYPE_REG);
    pe_print_characteristics2(IMAGE_SCN_TYPE_DSECT);
    pe_print_characteristics2(IMAGE_SCN_TYPE_NOLOAD);
    pe_print_characteristics2(IMAGE_SCN_TYPE_GROUP);
    pe_print_characteristics2(IMAGE_SCN_TYPE_COPY);
    pe_print_characteristics2(IMAGE_SCN_TYPE_OVER);
    #endif
    pe_print_characteristics2(IMAGE_SCN_TYPE_NO_PAD);
    pe_print_characteristics2(IMAGE_SCN_CNT_CODE);
    pe_print_characteristics2(IMAGE_SCN_CNT_INITIALIZED_DATA);
    pe_print_characteristics2(IMAGE_SCN_CNT_UNINITIALIZED_DATA);
    pe_print_characteristics2(IMAGE_SCN_LNK_OTHER);
    pe_print_characteristics2(IMAGE_SCN_LNK_INFO);
    pe_print_characteristics2(IMAGE_SCN_LNK_REMOVE);
    pe_print_characteristics2(IMAGE_SCN_LNK_COMDAT);
    pe_print_characteristics2(IMAGE_SCN_GPREL);
    pe_print_characteristics2(IMAGE_SCN_MEM_FARDATA);
    pe_print_characteristics2(IMAGE_SCN_MEM_PURGEABLE);
    pe_print_characteristics2(IMAGE_SCN_MEM_16BIT);
    pe_print_characteristics2(IMAGE_SCN_MEM_LOCKED);
    pe_print_characteristics2(IMAGE_SCN_MEM_PRELOAD);
    /*
    pe_print_characteristics2(IMAGE_SCN_ALIGN_1BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_2BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_4BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_8BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_16BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_32BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_64BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_128BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_256BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_512BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_1024BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_2048BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_4096BYTES);
    pe_print_characteristics2(IMAGE_SCN_ALIGN_8192BYTES);
    */
    pe_print_characteristics2(IMAGE_SCN_LNK_NRELOC_OVFL);
    pe_print_characteristics2(IMAGE_SCN_MEM_DISCARDABLE);
    pe_print_characteristics2(IMAGE_SCN_MEM_NOT_CACHED);
    pe_print_characteristics2(IMAGE_SCN_MEM_NOT_PAGED);
    pe_print_characteristics2(IMAGE_SCN_MEM_SHARED);
    pe_print_characteristics2(IMAGE_SCN_MEM_EXECUTE);
    pe_print_characteristics2(IMAGE_SCN_MEM_READ);
    pe_print_characteristics2(IMAGE_SCN_MEM_WRITE);
    printf("\n");
}



int pe_parse_exe_set_one_section(parse_exe_t *pe, int offset, int filememsz) {
    if(!pe) return -1;

    pe->section = realloc(pe->section, sizeof(pe_section_t));
    if(!pe->section) return(-1);
    pe->section[0].VirtualAddress   = 0;
    pe->section[0].VirtualSize      = filememsz - offset;
    pe->section[0].VirtualSize_off  = -1;
    pe->section[0].PointerToRawData = offset;
    pe->section[0].SizeOfRawData    = filememsz - offset;
    pe->section[0].Characteristics  = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    pe->sections = 1;

    return 0;
}



int pe_parse_exe(parse_exe_t *pe, u8 *filemem, int filememsz, int full_parsing) {
    int     i,
            offset;
    u32     t,
            xsize;

    if(!pe) return -1;
    memset(pe, 0, sizeof(parse_exe_t));

                   offset = pe_parse_PE(pe, filemem, filememsz, full_parsing);
    if(offset < 0) offset = pe_parse_ELF32(pe, filemem, filememsz, full_parsing);

    if(offset < 0) {
        // don't quit, handle the file as a DAT
        // return(-1);

        offset = 0;
    }

    if(full_parsing) {

        if(!pe->sections || !pe->section) { // possible work-around in case of errors
            pe_parse_exe_set_one_section(pe, offset, filememsz);
        }

        // find the lower section
        xsize = -1;
        for(i = 0; i < pe->sections; i++) {
            if(!pe->section[i].PointerToRawData) continue;
            if(pe->section[i].PointerToRawData < xsize) xsize = pe->section[i].PointerToRawData;
        }
        if(xsize == -1) xsize = filememsz;

        pe->image_size = xsize;
        /*
        pe->image      = malloc(pe->image_size);
        if(!pe->image) STD_ERR;
        memcpy(pe->image, filemem, pe->image_size);
        */

        for(i = 0; i < pe->sections; i++) {
            xsize = PARSE_EXE_MAX(pe->section[i].VirtualSize, pe->section[i].SizeOfRawData);
            t = pe->section[i].VirtualAddress + xsize;
            if(t > pe->image_size) {
                /*
                pe->image = realloc(pe->image, t);
                if(!pe->image) STD_ERR;
                memset(pe->image + pe->image_size, 0, t - pe->image_size);
                */
                pe->image_size = t;
            }
            /*
            memset(pe->image + pe->section[i].VirtualAddress, 0, xsize);
            memcpy(pe->image + pe->section[i].VirtualAddress, filemem + pe->section[i].PointerToRawData, pe->section[i].SizeOfRawData);
            */
        }
    }

    return(0);
}


