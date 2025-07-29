OUTPUT_FORMAT("elf32-bigarm", "elf32-bigarm", "elf32-littlearm")
OUTPUT_ARCH(arm)

SECTIONS
{
  .text : {
  }
  ELFMAINX : {
    *(ELFMAINX)
    *(.text)
  }
}
