/* Copyright (C) 2014-2020 Free Software Foundation, Inc.
   Copying and distribution of this script, with or without modification,
   are permitted in any medium without royalty provided the copyright
   notice and this notice are preserved.  */
/* 2022-05-20  Stripped down greatly from output of:
      ld --verbose -m elf_x86_64
   using binutils-2.35.2-6.fc34.x86_64 .
   So that
      multiarch-ld-2.17 -T this.lds -r ...
   will preserve Sections (Elf64_Shdr) and relocations between them.
*/
OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
  . = SIZEOF_HEADERS;
}
