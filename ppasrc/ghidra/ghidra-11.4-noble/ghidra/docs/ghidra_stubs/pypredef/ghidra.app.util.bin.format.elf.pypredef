from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format
import ghidra.app.util.bin.format.elf.extend
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


T = typing.TypeVar("T")


@typing.type_check_only
class AndroidElfRelocationData(ghidra.program.model.data.SignedLeb128DataType):
    """
    ``AndroidElfRelocationData`` provides a dynamic LEB128 data 
    component for packed Android ELF Relocation Table.
    See :obj:`AndroidElfRelocationTableDataType`.
     
    
    Secondary purpose is to retain the relocation offset associated with a 
    component instance.  This functionality relies on the 1:1 relationship
    between this dynamic datatype and the single component which references it.
    """

    class_: typing.ClassVar[java.lang.Class]


class ElfRelocation(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the Elf32_Rel and Elf64_Rel data structure.
     
    
     
    typedef uint32_t Elf32_Addr;
    typedef uint64_t Elf64_Addr;
    typedef uint32_t Elf32_Word;
    typedef uint64_t Elf64_Xword;
     
    REL entry:
     
        typedef struct {
            Elf32_Addr   r_offset;
            Elf32_Word   r_info;
        } Elf32_Rel;
     
        typedef struct {
            Elf64_Addr   r_offset;
            Elf64_Xword  r_info;
        } Elf64_Rel;
     
    RELA entry with addend:
     
        typedef struct {
            Elf32_Addr    r_offset;
            Elf32_Word    r_info;
            Elf32_Sword   r_addend;
        } Elf32_Rela;
     
        typedef struct {
            Elf64_Addr    r_offset;   //Address
            Elf64_Xword   r_info;     //Relocation type and symbol index
            Elf64_Sxword  r_addend;   //Addend 
        } Elf64_Rela;
     
    RELR entry (see SHT_RELR, DT_RELR):
        NOTE: Relocation type is data *relative* and must be specified by appropriate relocation handler
        (see :meth:`AbstractElfRelocationHandler.getRelrRelocationType() <AbstractElfRelocationHandler.getRelrRelocationType>`) since it is not contained within the 
        relocation table which only specifies *r_offset* for each entry.
     
     
     
    NOTE: instantiation relies on the use of a default constructor which must be 
    implemented by any extension.  An extension should implement the methods
    :meth:`initElfRelocation(BinaryReader, ElfHeader, int, boolean) <.initElfRelocation>` and/or
    :meth:`initElfRelocation(ElfHeader, int, boolean, long, long, long) <.initElfRelocation>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Instantiate an uninitialized relocation object.
         
        
        NOTE: This method is intended for use by the various factory methods which should generally
        be used when building-up a relocation table (see :meth:`createElfRelocation(BinaryReader, ElfHeader, int, boolean) <.createElfRelocation>`
        and :meth:`createElfRelocation(ElfHeader, int, boolean, long, long, long) <.createElfRelocation>`).
        """

    def getAddend(self) -> int:
        """
        This member specifies the RELA signed-constant addend used to compute 
        the value to be stored into the relocatable field.  This
        value will be 0 for REL entries which do not supply an addend and may
        rely on an implicit addend stored at the relocation offset.
        See :meth:`hasAddend() <.hasAddend>` which is true for RELA / Elf_Rela and false
        for REL / Elf_Rel relocations.
        
        :return: addend as 64-bit signed constant
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        This member gives the location at which to apply the relocation action. 
         
        For a relocatable file, the value is the byte offset from the 
        beginning of the section to the storage unit affected by the relocation. 
         
        For an executable file or a shared object, the value is the virtual address of
        the storage unit affected by the relocation.
        
        :return: the location at which to apply the relocation
        :rtype: int
        """

    def getRelocationIndex(self) -> int:
        """
        
        
        :return: index of relocation within its corresponding relocation table
        :rtype: int
        """

    def getRelocationInfo(self) -> int:
        """
        Returns the r_info relocation entry field value
        
        :return: r_info value
        :rtype: int
        """

    @staticmethod
    def getStandardRelocationEntrySize(is64bit: typing.Union[jpype.JBoolean, bool], hasAddend: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get the standard relocation size when one has notbeen specified
        
        :param jpype.JBoolean or bool is64bit: true if ELF 64-bit
        :param jpype.JBoolean or bool hasAddend: true if relocation has addend
        :return: size of relocation entry
        :rtype: int
        """

    def getSymbolIndex(self) -> int:
        """
        Returns the symbol index where the relocation must be made.
        A value of 0 is generally returned when no symbol is relavent
        to the relocation.
        
        :return: the symbol index
        :rtype: int
        """

    def getType(self) -> int:
        """
        The type ID value for this relocation
        NOTE 1: Relocation types are processor-specific (see :obj:`AbstractElfRelocationHandler`).
        NOTE 2: A type ID of 0 is returned by default for RELR relocations and must be updated 
        during relocation processing (see :meth:`setType(long) <.setType>`).  The appropriate RELR 
        relocation type can be obtained from the appropriate 
        :meth:`AbstractElfRelocationHandler.getRelrRelocationType() <AbstractElfRelocationHandler.getRelrRelocationType>` or 
        :meth:`ElfRelocationContext.getRelrRelocationType() <ElfRelocationContext.getRelrRelocationType>` if available.
        
        :return: type ID for this relocation
        :rtype: int
        """

    def hasAddend(self) -> bool:
        """
        Returns true if this is a RELA entry with addend
        
        :return: true if this is a RELA entry with addend
        :rtype: bool
        """

    def setType(self, typeId: typing.Union[jpype.JLong, int]):
        """
        Set the relocation type ID associated with this relocation.
        Updating the relocation type is required for RELR relocations.
        
        :param jpype.JLong or int typeId: relocation type ID value for this relocation
        """

    @property
    def relocationInfo(self) -> jpype.JLong:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def symbolIndex(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def relocationIndex(self) -> jpype.JInt:
        ...

    @property
    def addend(self) -> jpype.JLong:
        ...


class ElfCompressedSectionHeader(java.lang.Object):
    """
    Header at the beginning of an ELF compressed section.
     
    
    See https://docs.oracle.com/cd/E53394_01/html/E54813/section_compression.html
     
    typedef struct {
        Elf32_Word      ch_type;
        Elf32_Word      ch_size;
        Elf32_Word      ch_addralign;
    } Elf32_Chdr;
     
    typedef struct {
        Elf64_Word      ch_type;
        Elf64_Word      ch_reserved;
        Elf64_Xword     ch_size;
        Elf64_Xword     ch_addralign;
    } Elf64_Chdr;
    """

    class_: typing.ClassVar[java.lang.Class]
    ELFCOMPRESS_ZLIB: typing.Final = 1

    def getCh_addralign(self) -> int:
        """
        :return: the address alignment value
        :rtype: int
        .
         
        
        See :meth:`ElfSectionHeader.getAddressAlignment() <ElfSectionHeader.getAddressAlignment>`
        """

    def getCh_size(self) -> int:
        """
        :return: the uncompressed size
        :rtype: int
        """

    def getCh_type(self) -> int:
        """
        :return: the compression type, see ELFCOMPRESS_ZLIB
        :rtype: int
        """

    def getHeaderSize(self) -> int:
        """
        :return: the size of this header struct
        :rtype: int
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, elf: ElfHeader) -> ElfCompressedSectionHeader:
        """
        Reads an Elf(32|64)_Chdr from the current position in the supplied stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: stream to read from
        :param ElfHeader elf: ElfHeader that defines the format of the binary
        :return: new :obj:`ElfCompressedSectionHeader` instance, never null
        :rtype: ElfCompressedSectionHeader
        :raises IOException: if error reading the header
        """

    @property
    def headerSize(self) -> jpype.JInt:
        ...

    @property
    def ch_type(self) -> jpype.JInt:
        ...

    @property
    def ch_size(self) -> jpype.JLong:
        ...

    @property
    def ch_addralign(self) -> jpype.JLong:
        ...


class ElfDynamicTable(ElfFileSection):
    """
    If an object file participates in dynamic linking, its program header table 
    will have an element of type PT_DYNAMIC. This "segment" contains the ".dynamic" section. 
    A special symbol, _DYNAMIC, labels the section, which contains an array of the 
    Elf32_Dyn or Elf64_Dyn structures.
     
    
    All address entries contained within this table should adjusted for pre-linking 
    using :meth:`ElfHeader.adjustAddressForPrelink(long) <ElfHeader.adjustAddressForPrelink>`.  If a pre-link adjustment is not applicable, 
    this adjustment will have no affect.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ElfHeader, fileOffset: typing.Union[jpype.JLong, int], addrOffset: typing.Union[jpype.JLong, int]):
        """
        Construct an ELF Dynamic data table
        
        :param ghidra.app.util.bin.BinaryReader reader: byte provider reader (reader is not retained and position is unaffected)
        :param ElfHeader header: elf header
        :param jpype.JLong or int fileOffset: file offset which will be used to temporarily position reader
        :param jpype.JLong or int addrOffset: memory address offset
        :raises IOException: if IO error occurs during parse
        """

    def addDynamic(self, dyn: ElfDynamic, index: typing.Union[jpype.JInt, int]):
        """
        Adds the new dynamic at the specified index.
        
        :param ElfDynamic dyn: the new dynamic
        :param jpype.JInt or int index: the new index
        """

    @typing.overload
    def containsDynamicValue(self, type: ElfDynamicType) -> bool:
        """
        Returns true if the specified dynamic (enum) type has a value.
        
        :param ElfDynamicType type: the dynamic (enum) type
        :return: true if dynamic value exists
        :rtype: bool
        """

    @typing.overload
    def containsDynamicValue(self, type: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the specified dynamic type has a value.
        
        :param jpype.JLong or int type: the dynamic type
        :return: true if dynamic value exists
        :rtype: bool
        """

    @typing.overload
    def getDynamicValue(self, type: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the value of the specified dynamic type.
        
        :param jpype.JLong or int type: the dynamic type
        :return: the dynamic value
        :rtype: int
        :raises NotFoundException: if requested value type not found
        """

    @typing.overload
    def getDynamicValue(self, type: ElfDynamicType) -> int:
        """
        Returns the value of the specified dynamic (enum) type.
        
        :param ElfDynamicType type: the dynamic (enum) type
        :return: the dynamic value
        :rtype: int
        :raises NotFoundException: if requested value type not found
        """

    @typing.overload
    def getDynamics(self) -> jpype.JArray[ElfDynamic]:
        """
        Returns an array of the dynamics defined this dynamic header.
        
        :return: an array of the dynamics defined this dynamic header
        :rtype: jpype.JArray[ElfDynamic]
        """

    @typing.overload
    def getDynamics(self, type: typing.Union[jpype.JLong, int]) -> jpype.JArray[ElfDynamic]:
        """
        Returns an array of the dynamics defined this dynamic header
        with the specified type.
        
        :param jpype.JLong or int type: the desired dynamic type, e.g., DT_NEEDED
        :return: an array of the dynamics defined this dynamic header
        :rtype: jpype.JArray[ElfDynamic]
        """

    @typing.overload
    def getDynamics(self, type: ElfDynamicType) -> jpype.JArray[ElfDynamic]:
        """
        Returns an array of the dynamics defined this dynamic header
        with the specified (enum) type.
        
        :param ElfDynamicType type: the desired dynamic type, e.g., DT_NEEDED
        :return: an array of the dynamics defined this dynamic header
        :rtype: jpype.JArray[ElfDynamic]
        """

    @property
    def dynamics(self) -> jpype.JArray[ElfDynamic]:
        ...

    @property
    def dynamicValue(self) -> jpype.JLong:
        ...


class ElfSymbolTable(ElfFileSection):
    """
    A container class to hold ELF symbols.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ElfHeader, symbolTableSection: ElfSectionHeader, fileOffset: typing.Union[jpype.JLong, int], addrOffset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int], entrySize: typing.Union[jpype.JLong, int], stringTable: ElfStringTable, symbolSectionIndexTable: jpype.JArray[jpype.JInt], isDynamic: typing.Union[jpype.JBoolean, bool]):
        """
        Construct and parse an Elf symbol table
        
        :param ghidra.app.util.bin.BinaryReader reader: byte reader (reader is not retained and position is unaffected)
        :param ElfHeader header: elf header
        :param ElfSectionHeader symbolTableSection: string table section header or null if associated with a dynamic table entry
        :param jpype.JLong or int fileOffset: symbol table file offset
        :param jpype.JLong or int addrOffset: memory address of symbol table (should already be adjusted for prelink)
        :param jpype.JLong or int length: length of symbol table in bytes of -1 if unknown
        :param jpype.JLong or int entrySize: size of each symbol entry in bytes
        :param ElfStringTable stringTable: associated string table
        :param jpype.JArray[jpype.JInt] symbolSectionIndexTable: extended symbol section index table (may be null, used when 
                symbol ``st_shndx == SHN_XINDEX``).  See 
                :meth:`ElfSymbol.getExtendedSectionHeaderIndex() <ElfSymbol.getExtendedSectionHeaderIndex>`).
        :param jpype.JBoolean or bool isDynamic: true if symbol table is the dynamic symbol table
        :raises IOException: if an IO or parse error occurs
        """

    def getExtendedSectionIndex(self, sym: ElfSymbol) -> int:
        """
        Get the extended symbol section index value for the specified ELF symbol which originated
        from this symbol table.   This section index is provided by an associated SHT_SYMTAB_SHNDX 
        section when the symbols st_shndx == SHN_XINDEX.
        
        :param ElfSymbol sym: ELF symbol from this symbol table
        :return: associated extended section index value or 0 if not defined.
        :rtype: int
        """

    def getFormattedSymbolName(self, symbolIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the formatted ELF symbol name which corresponds to the specified index. 
        If the name is blank or can not be resolved due to a missing string table the 
        literal string *<no name>* will be returned.
        
        :param jpype.JInt or int symbolIndex: symbol index
        :return: formatted symbol name which corresponds to symbol index or the 
        literal string *<no name>*
        :rtype: str
        """

    def getGlobalSymbols(self) -> jpype.JArray[ElfSymbol]:
        """
        Returns all of the global symbols.
        
        :return: all of the global symbols
        :rtype: jpype.JArray[ElfSymbol]
        """

    def getSourceFiles(self) -> jpype.JArray[java.lang.String]:
        """
        Returns all of the sources file names.
        
        :return: all of the sources file names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getStringTable(self) -> ElfStringTable:
        """
        Returns the associated string table section.
        
        :return: the associated string table section
        :rtype: ElfStringTable
        """

    def getSymbol(self, symbolIndex: typing.Union[jpype.JInt, int]) -> ElfSymbol:
        """
        Get the Elf symbol which corresponds to the specified index.  Each relocation table
        may correspond to a specific symbol table to which the specified symbolIndex will be
        applied.
        
        :param jpype.JInt or int symbolIndex: symbol index
        :return: Elf symbol which corresponds to symbol index or **null** if out of range
        :rtype: ElfSymbol
        """

    def getSymbolAt(self, addr: typing.Union[jpype.JLong, int]) -> ElfSymbol:
        """
        Returns the symbol at the specified address.
        
        :param jpype.JLong or int addr: the symbol address
        :return: the symbol at the specified address
        :rtype: ElfSymbol
        """

    def getSymbolCount(self) -> int:
        """
        
        
        :return: number of symbols
        :rtype: int
        """

    def getSymbolIndex(self, symbol: ElfSymbol) -> int:
        """
        Returns the index of the specified symbol in this
        symbol table.
        
        :param ElfSymbol symbol: the symbol
        :return: the index of the specified symbol
        :rtype: int
        """

    def getSymbolName(self, symbolIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the ELF symbol name which corresponds to the specified index.
        
        :param jpype.JInt or int symbolIndex: symbol index
        :return: symbol name which corresponds to symbol index or null if out of range
        :rtype: str
        """

    def getSymbols(self) -> jpype.JArray[ElfSymbol]:
        """
        Returns all of the symbols defined in this symbol table.
        
        :return: all of the symbols defined in this symbol table
        :rtype: jpype.JArray[ElfSymbol]
        """

    def getTableSectionHeader(self) -> ElfSectionHeader:
        """
        Get the section header which corresponds to this table, or null
        if only associated with a dynamic table entry
        
        :return: symbol table section header or null
        :rtype: ElfSectionHeader
        """

    def isDynamic(self) -> bool:
        """
        Returns true if this is the dynamic symbol table
        
        :return: true if this is the dynamic symbol table
        :rtype: bool
        """

    @property
    def tableSectionHeader(self) -> ElfSectionHeader:
        ...

    @property
    def symbol(self) -> ElfSymbol:
        ...

    @property
    def formattedSymbolName(self) -> java.lang.String:
        ...

    @property
    def sourceFiles(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def globalSymbols(self) -> jpype.JArray[ElfSymbol]:
        ...

    @property
    def extendedSectionIndex(self) -> jpype.JInt:
        ...

    @property
    def symbolAt(self) -> ElfSymbol:
        ...

    @property
    def dynamic(self) -> jpype.JBoolean:
        ...

    @property
    def symbolName(self) -> java.lang.String:
        ...

    @property
    def symbolIndex(self) -> jpype.JInt:
        ...

    @property
    def symbolCount(self) -> jpype.JInt:
        ...

    @property
    def stringTable(self) -> ElfStringTable:
        ...

    @property
    def symbols(self) -> jpype.JArray[ElfSymbol]:
        ...


class ElfConstants(java.lang.Object):
    """
    A collection of constants used in the ELF header.
    """

    class_: typing.ClassVar[java.lang.Class]
    GOT_SYMBOL_NAME: typing.Final = "_GLOBAL_OFFSET_TABLE_"
    EI_NIDENT: typing.Final = 16
    """
    Length of the File ID
    """

    EI_MAG0: typing.Final = 0
    """
    File ID
    """

    EI_MAG1: typing.Final = 1
    """
    File ID
    """

    EI_MAG2: typing.Final = 2
    """
    File ID
    """

    EI_MAG3: typing.Final = 3
    """
    File ID
    """

    EI_CLASS: typing.Final = 4
    """
    File class
    """

    EI_DATA: typing.Final = 5
    """
    Data encoding
    """

    EI_VERSION: typing.Final = 6
    """
    File version
    """

    EI_OSIABI: typing.Final = 7
    """
    Operating System/ABI Identification
    """

    EI_ABIVERSION: typing.Final = 8
    """
    ABI Version
    """

    EI_PAD: typing.Final = 9
    """
    Start of padding
    """

    MAGIC_NUM: typing.Final = 127
    """
    The ELF magic number
    """

    MAGIC_STR: typing.Final = "ELF"
    """
    The ELF magic string
    """

    MAGIC_BYTES: typing.Final[jpype.JArray[jpype.JByte]]
    """
    The ELF magic number and string as a byte array
    """

    MAGIC_STR_LEN: typing.Final = 3
    """
    The ELF magic string length
    """

    ELF_CLASS_NONE: typing.Final = 0
    """
    Invalid class
    """

    ELF_CLASS_32: typing.Final = 1
    """
    32-bit objects
    """

    ELF_CLASS_64: typing.Final = 2
    """
    64-bit objects
    """

    ELF_CLASS_NUM: typing.Final = 3
    """
    ?
    """

    ELF_DATA_NONE: typing.Final = 0
    """
    invalid byte order
    """

    ELF_DATA_LE: typing.Final = 1
    """
    little-endian byte order
    """

    ELF_DATA_BE: typing.Final = 2
    """
    big-endian byte order
    """

    EV_NONE: typing.Final = 0
    """
    invalid version
    """

    EV_CURRENT: typing.Final = 1
    """
    current version
    """

    ELFOSABI_NONE: typing.Final = 0
    """
    no extension or unspecified
    """

    ELFOSABI_HPUX: typing.Final = 1
    """
    hewlett packard unix
    """

    ELFOSABI_NETBSD: typing.Final = 2
    """
    net bsd
    """

    ELFOSABI_LINUX: typing.Final = 3
    """
    linux
    """

    ELFOSABI_GNU: typing.Final = 3
    """
    GNU LINUX
    """

    ELFOSABI_HURD: typing.Final = 4
    """
    GNU/Hurd
    """

    ELFOSABI_SOLARIS: typing.Final = 6
    """
    sun solaris
    """

    ELFOSABI_AIX: typing.Final = 7
    """
    aix
    """

    ELFOSABI_IRIX: typing.Final = 8
    """
    irix
    """

    ELFOSABI_FREEBSD: typing.Final = 9
    """
    free bsd
    """

    ELFOSABI_TRUE64: typing.Final = 10
    """
    compaq tru64 unix
    """

    ELFOSABI_MODESTO: typing.Final = 11
    """
    novell modesto
    """

    ELFOSABI_OPENBSD: typing.Final = 12
    """
    open bsd
    """

    ELFOSABI_OPENVMS: typing.Final = 13
    """
    OpenVMS
    """

    ELFOSABI_NSK: typing.Final = 14
    """
    Hewlett-Packard Non-Stop Kernel
    """

    ELFOSABI_AROS: typing.Final = 15
    """
    AROS
    """

    ELFOSABI_FENIXOS: typing.Final = 16
    """
    FenixOS
    """

    ELFOSABI_CLOUDABI: typing.Final = 17
    """
    Nuxi CloudABI
    """

    ELFOSABI_C6000_ELFABI: typing.Final = 64
    """
    Bare-metal TMS320C6000
    """

    ELFOSABI_C6000_LINUX: typing.Final = 65
    """
    Linux TMS320C6000
    """

    ELFOSABI_ARM: typing.Final = 97
    """
    ARM
    """

    ELFOSABI_STANDALONE: typing.Final = -1
    """
    Standalone (embedded) application
    """

    ET_NONE: typing.Final = 0
    """
    No file type
    """

    ET_REL: typing.Final = 1
    """
    Relocatable file (suitable for linking)
    """

    ET_EXEC: typing.Final = 2
    """
    Executable file
    """

    ET_DYN: typing.Final = 3
    """
    Shared object file
    """

    ET_CORE: typing.Final = 4
    """
    Core file
    """

    ET_LOPROC: typing.Final = -256
    """
    Processor specific
    """

    ET_HIPROC: typing.Final = -1
    """
    Processor specific
    """

    EM_NONE: typing.Final = 0
    """
    No machine
    """

    EM_M32: typing.Final = 1
    """
    AT&T WE 32100
    """

    EM_SPARC: typing.Final = 2
    """
    SUN SPARC
    """

    EM_386: typing.Final = 3
    """
    Intel 80386
    """

    EM_68K: typing.Final = 4
    """
    Motorola m68k family
    """

    EM_88K: typing.Final = 5
    """
    Motorola m88k family
    """

    EM_486: typing.Final = 6
    """
    Intel 486 (deprecated)
    """

    EM_860: typing.Final = 7
    """
    Intel 80860
    """

    EM_MIPS: typing.Final = 8
    """
    MIPS R3000 big-endian
    """

    EM_S370: typing.Final = 9
    """
    IBM System/370
    """

    EM_MIPS_RS3_LE: typing.Final = 10
    """
    MIPS R3000 little-endian
    """

    EM_PARISC: typing.Final = 15
    """
    HPPA
    """

    EM_VPP500: typing.Final = 17
    """
    Fujitsu VPP500
    """

    EM_SPARC32PLUS: typing.Final = 18
    """
    Sun's "v8plus"
    """

    EM_960: typing.Final = 19
    """
    Intel 80960
    """

    EM_PPC: typing.Final = 20
    """
    PowerPC
    """

    EM_PPC64: typing.Final = 21
    """
    PowerPC 64-bit
    """

    EM_S390: typing.Final = 22
    """
    IBM S390
    """

    EM_SPU: typing.Final = 23
    """
    IBM SPU/SPC
    """

    EM_V800: typing.Final = 36
    """
    NEC V800 series
    """

    EM_FR20: typing.Final = 37
    """
    Fujitsu FR20
    """

    EM_RH32: typing.Final = 38
    """
    TRW RH-32
    """

    EM_RCE: typing.Final = 39
    """
    Motorola RCE
    """

    EM_ARM: typing.Final = 40
    """
    ARM
    """

    EM_FAKE_ALPHA: typing.Final = 41
    """
    Digital Alpha
    """

    EM_SH: typing.Final = 42
    """
    Hitachi SH
    """

    EM_SPARCV9: typing.Final = 43
    """
    SPARC v9 64-bit
    """

    EM_TRICORE: typing.Final = 44
    """
    Siemens Tricore
    """

    EM_ARC: typing.Final = 45
    """
    Argonaut RISC Core
    """

    EM_H8_300: typing.Final = 46
    """
    Hitachi H8/300
    """

    EM_H8_300H: typing.Final = 47
    """
    Hitachi H8/300H
    """

    EM_H8S: typing.Final = 48
    """
    Hitachi H8S
    """

    EM_H8_500: typing.Final = 49
    """
    Hitachi H8/500
    """

    EM_IA_64: typing.Final = 50
    """
    Intel Merced
    """

    EM_MIPS_X: typing.Final = 51
    """
    Stanford MIPS-X
    """

    EM_COLDFIRE: typing.Final = 52
    """
    Motorola Coldfire
    """

    EM_68HC12: typing.Final = 53
    """
    Motorola M68HC12
    """

    EM_MMA: typing.Final = 54
    """
    Fujitsu MMA Multimedia Accelerator
    """

    EM_PCP: typing.Final = 55
    """
    Siemens PCP
    """

    EM_NCPU: typing.Final = 56
    """
    Sony nCPU embedded RISC
    """

    EM_NDR1: typing.Final = 57
    """
    Denso NDR1 microprocessor
    """

    EM_STARCORE: typing.Final = 58
    """
    Motorola Start*Core processor
    """

    EM_ME16: typing.Final = 59
    """
    Toyota ME16 processor
    """

    EM_ST100: typing.Final = 60
    """
    STMicroelectronic ST100 processor
    """

    EM_TINYJ: typing.Final = 61
    """
    Advanced Logic Corp. Tinyj emb.fam
    """

    EM_X86_64: typing.Final = 62
    """
    AMD x86-64 architecture
    """

    EM_PDSP: typing.Final = 63
    """
    Sony DSP Processor
    """

    EM_PDP10: typing.Final = 64
    """
    Digital Equipment Corp. PDP-10
    """

    EM_PDP11: typing.Final = 65
    """
    Digital Equipment Corp. PDP-11
    """

    EM_FX66: typing.Final = 66
    """
    Siemens FX66 microcontroller
    """

    EM_ST9PLUS: typing.Final = 67
    """
    STMicroelectronics ST9+ 8/16 mc
    """

    EM_ST7: typing.Final = 68
    """
    STmicroelectronics ST7 8 bit mc
    """

    EM_68HC16: typing.Final = 69
    """
    Motorola MC68HC16 microcontroller
    """

    EM_68HC11: typing.Final = 70
    """
    Motorola MC68HC11 microcontroller
    """

    EM_68HC08: typing.Final = 71
    """
    Motorola MC68HC08 microcontroller
    """

    EM_68HC05: typing.Final = 72
    """
    Motorola MC68HC05 microcontroller
    """

    EM_SVX: typing.Final = 73
    """
    Silicon Graphics SVx
    """

    EM_ST19: typing.Final = 74
    """
    STMicroelectronics ST19 8 bit mc
    """

    EM_VAX: typing.Final = 75
    """
    Digital VAX
    """

    EM_CRIS: typing.Final = 76
    """
    Axis Communications 32-bit embedded processor
    """

    EM_JAVELIN: typing.Final = 77
    """
    Infineon Technologies 32-bit embedded processor
    """

    EM_FIREPATH: typing.Final = 78
    """
    Element 14 64-bit DSP Processor
    """

    EM_ZSP: typing.Final = 79
    """
    LSI Logic 16-bit DSP Processor
    """

    EM_MMIX: typing.Final = 80
    """
    Donald Knuth's educational 64-bit processor
    """

    EM_HUANY: typing.Final = 81
    """
    Harvard University machine-independent object files
    """

    EM_PRISM: typing.Final = 82
    """
    SiTera Prism
    """

    EM_AVR: typing.Final = 83
    """
    Atmel AVR 8-bit microcontroller
    """

    EM_FR30: typing.Final = 84
    """
    Fujitsu FR30
    """

    EM_D10V: typing.Final = 85
    """
    Mitsubishi D10V
    """

    EM_D30V: typing.Final = 86
    """
    Mitsubishi D30V
    """

    EM_V850: typing.Final = 87
    """
    NEC v850
    """

    EM_M32R: typing.Final = 88
    """
    Mitsubishi M32R
    """

    EM_MN10300: typing.Final = 89
    """
    Matsushita MN10300
    """

    EM_MN10200: typing.Final = 90
    """
    Matsushita MN10200
    """

    EM_PJ: typing.Final = 91
    """
    picoJava
    """

    EM_OPENRISC: typing.Final = 92
    """
    OpenRISC 32-bit embedded processor
    """

    EM_ARC_A5: typing.Final = 93
    """
    ARC Cores Tangent-A5
    """

    EM_XTENSA: typing.Final = 94
    """
    Tensilica Xtensa Architecture
    """

    EM_VIDEOCORE: typing.Final = 95
    """
    Alphamosaic VideoCore processor
    """

    EM_TMM_GPP: typing.Final = 96
    """
    Thompson Multimedia General Purpose Processor
    """

    EM_NS32K: typing.Final = 97
    """
    National Semiconductor 32000 series
    """

    EM_TPC: typing.Final = 98
    """
    Tenor Network TPC processor
    """

    EM_SNP1K: typing.Final = 99
    """
    Trebia SNP 1000 processor
    """

    EM_ST200: typing.Final = 100
    """
    STMicroelectronics (www.st.com) ST200
    """

    EM_IP2K: typing.Final = 101
    """
    Ubicom IP2xxx microcontroller family
    """

    EM_MAX: typing.Final = 102
    """
    MAX Processor
    """

    EM_CR: typing.Final = 103
    """
    National Semiconductor CompactRISC microprocessor
    """

    EM_F2MC16: typing.Final = 104
    """
    Fujitsu F2MC16
    """

    EM_MSP430: typing.Final = 105
    """
    Texas Instruments embedded microcontroller msp430
    """

    EM_BLACKFIN: typing.Final = 106
    """
    Analog Devices Blackfin (DSP) processor
    """

    EM_SE_C33: typing.Final = 107
    """
    S1C33 Family of Seiko Epson processors
    """

    EM_SEP: typing.Final = 108
    """
    Sharp embedded microprocessor
    """

    EM_ARCA: typing.Final = 109
    """
    Arca RISC Microprocessor
    """

    EM_UNICORE: typing.Final = 110
    """
    Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
    """

    EM_EXCESS: typing.Final = 111
    """
    eXcess: 16/32/64-bit configurable embedded CPU
    """

    EM_DXP: typing.Final = 112
    """
    Icera Semiconductor Inc. Deep Execution Processor
    """

    EM_ALTERA_NIOS2: typing.Final = 113
    """
    Altera Nios II soft-core processor
    """

    EM_CRX: typing.Final = 114
    """
    National Semiconductor CompactRISC CRX
    """

    EM_XGATE: typing.Final = 115
    """
    Motorola XGATE embedded processor
    """

    EM_C166: typing.Final = 116
    """
    Infineon C16x/XC16x processor
    """

    EM_M16C: typing.Final = 117
    """
    Renesas M16C series microprocessors
    """

    EM_DSPIC30F: typing.Final = 118
    """
    Microchip Technology dsPIC30F Digital Signal Controller
    """

    EM_CE: typing.Final = 119
    """
    Freescale Communication Engine RISC core
    """

    EM_M32C: typing.Final = 120
    """
    Renesas M32C series microprocessors*
    """

    EM_TSK3000: typing.Final = 131
    """
    Altium TSK3000 core
    """

    EM_RS08: typing.Final = 132
    """
    Freescale RS08 embedded processor
    """

    EM_SHARC: typing.Final = 133
    """
    Analog Devices SHARC family of 32-bit DSP processors
    """

    EM_ECOG2: typing.Final = 134
    """
    Cyan Technology eCOG2 microprocessor
    """

    EM_SCORE7: typing.Final = 135
    """
    Sunplus S+core7 RISC processor
    """

    EM_DSP24: typing.Final = 136
    """
    New Japan Radio (NJR) 24-bit DSP Processor
    """

    EM_VIDEOCORE3: typing.Final = 137
    """
    Broadcom VideoCore III processor
    """

    EM_LATTICEMICO32: typing.Final = 138
    """
    RISC processor for Lattice FPGA architecture
    """

    EM_SE_C17: typing.Final = 139
    """
    Seiko Epson C17 family
    """

    EM_TI_C6000: typing.Final = 140
    """
    The Texas Instruments TMS320C6000 DSP family
    """

    EM_TI_C2000: typing.Final = 141
    """
    The Texas Instruments TMS320C2000 DSP family
    """

    EM_TI_C5500: typing.Final = 142
    """
    The Texas Instruments TMS320C55x DSP family
    """

    EM_TI_PRU: typing.Final = 144
    """
    Texas Instruments Programmable Realtime Unit
    """

    EM_MMDSP_PLUS: typing.Final = 160
    """
    STMicroelectronics 64bit VLIW Data Signal Processor
    """

    EM_CYPRESS_M8C: typing.Final = 161
    """
    Cypress M8C microprocessor
    """

    EM_R32C: typing.Final = 162
    """
    Renesas R32C series microprocessors
    """

    EM_TRIMEDIA: typing.Final = 163
    """
    NXP Semiconductors TriMedia architecture family
    """

    EM_HEXAGON: typing.Final = 164
    """
    Qualcomm Hexagon processor
    """

    EM_8051: typing.Final = 165
    """
    Intel 8051 and variants
    """

    EM_STXP7X: typing.Final = 166
    """
    STMicroelectronics STxP7x family of RISC processors
    """

    EM_NDS32: typing.Final = 167
    """
    Andes Technology compact code size embedded RISC processor family
    """

    EM_ECOG1: typing.Final = 168
    """
    Cyan Technology eCOG1X family
    """

    EM_ECOG1X: typing.Final = 168
    """
    Cyan Technology eCOG1X family
    """

    EM_MAXQ30: typing.Final = 169
    """
    Dallas Semiconductor MAXQ30 Core Micro-controllers
    """

    EM_XIMO16: typing.Final = 170
    """
    New Japan Radio (NJR) 16-bit DSP Processor
    """

    EM_MANIK: typing.Final = 171
    """
    M2000 Reconfigurable RISC Microprocessor
    """

    EM_CRAYNV2: typing.Final = 172
    """
    Cray Inc. NV2 vector architecture
    """

    EM_RX: typing.Final = 173
    """
    Renesas RX family
    """

    EM_METAG: typing.Final = 174
    """
    Imagination Technologies META processor architecture
    """

    EM_MCST_ELBRUS: typing.Final = 175
    """
    MCST Elbrus general purpose hardware architecture
    """

    EM_ECOG16: typing.Final = 176
    """
    Cyan Technology eCOG16 family
    """

    EM_CR16: typing.Final = 177
    """
    National Semiconductor CompactRISC CR16 16-bitmicroprocessor
    """

    EM_ETPU: typing.Final = 178
    """
    Freescale Extended Time Processing Unit
    """

    EM_SLE9X: typing.Final = 179
    """
    Infineon Technologies SLE9X core
    """

    EM_L10M: typing.Final = 180
    """
    Intel L10M
    """

    EM_K10M: typing.Final = 181
    """
    Intel K10M
    """

    EM_AARCH64: typing.Final = 183
    """
    AARCH64 Architecture
    """

    EM_AVR32: typing.Final = 185
    """
    Atmel Corporation 32-bit microprocessor family
    """

    EM_STM8: typing.Final = 186
    """
    STMicroeletronics STM8 8-bit microcontroller
    """

    EM_TILE64: typing.Final = 187
    """
    Tilera TILE64 multicore architecture family
    """

    EM_TILEPRO: typing.Final = 188
    """
    Tilera TILEPro multicore architecture family
    """

    EM_CUDA: typing.Final = 190
    """
    NVIDIA CUDA architecture
    """

    EM_TILEGX: typing.Final = 191
    """
    Tilera TILE-Gx multicore architecture family
    """

    EM_CLOUDSHIELD: typing.Final = 192
    """
    CloudShield architecture family
    """

    EM_COREA_1ST: typing.Final = 193
    """
    KIPO-KAIST Core-A 1st generation processor family
    """

    EM_COREA_2ND: typing.Final = 194
    """
    KIPO-KAIST Core-A 2nd generation processor family
    """

    EM_ARC_COMPACT2: typing.Final = 195
    """
    Synopsys ARCompact V2
    """

    EM_OPEN8: typing.Final = 196
    """
    Open8 8-bit RISC soft processor core
    """

    EM_RL78: typing.Final = 197
    """
    Renesas RL78 family
    """

    EM_VIDEOCORE5: typing.Final = 198
    """
    Broadcom VideoCore V processor
    """

    EM_78KOR: typing.Final = 199
    """
    Renesas 78KOR family
    """

    EM_56800EX: typing.Final = 200
    """
    Freescale 56800EX Digital Signal Controller (DSC)
    """

    EM_BA1: typing.Final = 201
    """
    Beyond BA1 CPU
    """

    EM_BA2: typing.Final = 202
    """
    Beyond BA2 CPU
    """

    EM_XCORE: typing.Final = 203
    """
    XMOS xCORE processor family
    """

    EM_MCHP_PIC: typing.Final = 204
    """
    Microchip 8-bit PIC(r) family
    """

    EM_INTELGT: typing.Final = 205
    """
    Intel Graphics Technology
    """

    EM_KM32: typing.Final = 210
    """
    KM211 KM32 32-bit processor
    """

    EM_KMX32: typing.Final = 211
    """
    KM211 KMX32 32-bit processor
    """

    EM_KMX16: typing.Final = 212
    """
    KM211 KMX16 16-bit processor
    """

    EM_KMX8: typing.Final = 213
    """
    KM211 KMX8 8-bit processor
    """

    EM_KVARC: typing.Final = 214
    """
    KM211 KVARC processor
    """

    EM_CDP: typing.Final = 215
    """
    Paneve CDP architecture family
    """

    EM_COGE: typing.Final = 216
    """
    Cognitive Smart Memory Processor
    """

    EM_COOL: typing.Final = 217
    """
    iCelero CoolEngine
    """

    EM_NORC: typing.Final = 218
    """
    Nanoradio Optimized RISC
    """

    EM_CSR_KALIMBA: typing.Final = 219
    """
    CSR Kalimba architecture family
    """

    EM_Z80: typing.Final = 220
    """
    Zilog Z80
    """

    EM_VISIUM: typing.Final = 221
    """
    Controls and Data Services VISIUMcore processor
    """

    EM_FT32: typing.Final = 222
    """
    FTDI Chip FT32 high performance 32-bit RISC architecture
    """

    EM_MOXIE: typing.Final = 223
    """
    Moxie processor family
    """

    EM_AMDGPU: typing.Final = 224
    """
    AMD GPU architecture
    """

    EM_RISCV: typing.Final = 243
    """
    RISC-V
    """

    EM_LANAI: typing.Final = 244
    """
    Lanai 32-bit processor
    """

    EM_CEVA: typing.Final = 245
    """
    CEVA Processor Architecture Family
    """

    EM_CEVA_X2: typing.Final = 246
    """
    CEVA X2 Processor Family
    """

    EM_BPF: typing.Final = 247
    """
    Linux kernel bpf virtual machine
    """

    EM_GRAPHCORE_IPU: typing.Final = 248
    """
    Graphcore Intelligent Processing Unit
    """

    EM_IMG1: typing.Final = 249
    """
    Imagination Technologies
    """

    EM_NFP: typing.Final = 250
    """
    Netronome Flow Processor.
    """

    EM_VE: typing.Final = 251
    """
    NEC Vector Engine
    """

    EM_CSKY: typing.Final = 252
    """
    C-SKY processor family.
    """

    EM_ARC_COMPACT3_64: typing.Final = 253
    """
    Synopsys ARCv2.3 64-bit
    """

    EM_MCS6502: typing.Final = 254
    """
    MOS Technology MCS 6502 processor
    """

    EM_ARC_COMPACT3: typing.Final = 255
    """
    Synopsys ARCv2.3 32-bit
    """

    EM_KVX: typing.Final = 256
    """
    Kalray VLIW core of the MPPA processor family
    """

    EM_65816: typing.Final = 257
    """
    WDC 65816/65C816
    """

    EM_LOONGARCH: typing.Final = 258
    """
    LoongArch
    """

    EM_KF32: typing.Final = 259
    """
    ChipON KungFu32
    """

    EM_U16_U8CORE: typing.Final = 260
    """
    Linux kernel bpf virtual machine
    """

    EM_TACHYUM: typing.Final = 261
    """
    Tachyum
    """

    EM_56800EF: typing.Final = 262
    """
    NXP 56800EF Digital Signal Controller (DSC)
    """

    EM_AVR32_unofficial: typing.Final = 6317
    """
    used by NetBSD/avr32 - AVR 32-bit
    """

    PN_XNUM: typing.Final = -1
    """
    PN_XNUM: Used by e_phnum field to signal alternate storage of program header count
    within section[0] sh_info field.
    """

    ELF32_INVALID_OFFSET: typing.Final = 4294967295
    """
    32bit "-1", used in 32bit files to signal an invalid offset
    """



class ElfStringTable(ElfFileSection):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ElfHeader, stringTableSection: ElfSectionHeader, fileOffset: typing.Union[jpype.JLong, int], addrOffset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int]):
        """
        Construct and parse an Elf string table
        
        :param ElfHeader header: elf header
        :param ElfSectionHeader stringTableSection: string table section header or null if associated with a dynamic table entry
        :param jpype.JLong or int fileOffset: symbol table file offset
        :param jpype.JLong or int addrOffset: memory address of symbol table (should already be adjusted for prelink)
        :param jpype.JLong or int length: length of symbol table in bytes of -1 if unknown
        """

    def getTableSectionHeader(self) -> ElfSectionHeader:
        """
        Get section header which corresponds to this table, or null
        if only associated with a dynamic table entry
        
        :return: string table section header or null
        :rtype: ElfSectionHeader
        """

    def readString(self, reader: ghidra.app.util.bin.BinaryReader, stringOffset: typing.Union[jpype.JLong, int]) -> str:
        """
        Read string from table at specified relative table offset
        
        :param ghidra.app.util.bin.BinaryReader reader: byte reader (position remains unchanged)
        :param jpype.JLong or int stringOffset: table relative string offset
        :return: string or null on error
        :rtype: str
        """

    @property
    def tableSectionHeader(self) -> ElfSectionHeader:
        ...


class ElfSectionHeaderConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    dot_bss: typing.Final = ".bss"
    dot_comment: typing.Final = ".comment"
    dot_data: typing.Final = ".data"
    dot_data1: typing.Final = ".data1"
    dot_debug: typing.Final = ".debug"
    dot_dynamic: typing.Final = ".dynamic"
    dot_dynstr: typing.Final = ".dynstr"
    dot_dynsym: typing.Final = ".dynsym"
    dot_fini: typing.Final = ".fini"
    dot_got: typing.Final = ".got"
    dot_hash: typing.Final = ".hash"
    dot_init: typing.Final = ".init"
    dot_interp: typing.Final = ".interp"
    dot_line: typing.Final = ".line"
    dot_note: typing.Final = ".note"
    dot_plt: typing.Final = ".plt"
    dot_rodata: typing.Final = ".rodata"
    dot_rodata1: typing.Final = ".rodata1"
    dot_shstrtab: typing.Final = ".shstrtab"
    dot_strtab: typing.Final = ".strtab"
    dot_symtab: typing.Final = ".symtab"
    dot_text: typing.Final = ".text"
    dot_tbss: typing.Final = ".tbss"
    dot_tdata: typing.Final = ".tdata"
    dot_tdata1: typing.Final = ".tdata1"
    SHT_NULL: typing.Final = 0
    """
    Inactive section header
    """

    SHT_PROGBITS: typing.Final = 1
    """
    Program defined
    """

    SHT_SYMTAB: typing.Final = 2
    """
    Symbol table for link editing and dynamic linking
    """

    SHT_STRTAB: typing.Final = 3
    """
    String table
    """

    SHT_RELA: typing.Final = 4
    """
    Relocation entries with explicit addends
    """

    SHT_HASH: typing.Final = 5
    """
    Symbol hash table for dynamic linking
    """

    SHT_DYNAMIC: typing.Final = 6
    """
    Dynamic linking information
    """

    SHT_NOTE: typing.Final = 7
    """
    Section holds information that marks the file
    """

    SHT_NOBITS: typing.Final = 8
    """
    Section contains no bytes
    """

    SHT_REL: typing.Final = 9
    """
    Relocation entries w/o explicit addends
    """

    SHT_SHLIB: typing.Final = 10
    """
    Undefined
    """

    SHT_DYNSYM: typing.Final = 11
    """
    Symbol table for dynamic linking
    """

    SHT_INIT_ARRAY: typing.Final = 14
    """
    Array of constructors
    """

    SHT_FINI_ARRAY: typing.Final = 15
    """
    Array of destructors
    """

    SHT_PREINIT_ARRAY: typing.Final = 16
    """
    Array of pre-constructors
    """

    SHT_GROUP: typing.Final = 17
    """
    Section group
    """

    SHT_SYMTAB_SHNDX: typing.Final = 18
    """
    Extended section index table for linked symbol table
    """

    SHT_RELR: typing.Final = 19
    """
    Relative relocation table section
    (see proposal at https://groups.google.com/forum/#!topic/generic-abi/bX460iggiKg
    """

    SHT_ANDROID_REL: typing.Final = 1610612737
    """
    Android relocation entries w/o explicit addends
    """

    SHT_ANDROID_RELA: typing.Final = 1610612738
    """
    Android relocation entries with explicit addends
    """

    SHT_ANDROID_RELR: typing.Final = 1879047936
    """
    Android's experimental support for SHT_RELR sections (see above)
    """

    SHT_LLVM_ODRTAB: typing.Final = 1879002112
    """
    LLVM-specific section header types
    """

    SHT_LLVM_LINKER_OPTIONS: typing.Final = 1879002113
    SHT_LLVM_ADDRSIG: typing.Final = 1879002115
    SHT_LLVM_DEPENDENT_LIBRARIES: typing.Final = 1879002116
    SHT_LLVM_SYMPART: typing.Final = 1879002117
    SHT_LLVM_PART_EHDR: typing.Final = 1879002118
    SHT_LLVM_PART_PHDR: typing.Final = 1879002119
    SHT_LLVM_BB_ADDR_MAP_V0: typing.Final = 1879002120
    SHT_LLVM_CALL_GRAPH_PROFILE: typing.Final = 1879002121
    SHT_LLVM_BB_ADDR_MAP: typing.Final = 1879002122
    SHT_LLVM_OFFLOADING: typing.Final = 1879002123
    SHT_LLVM_LTO: typing.Final = 1879002124
    SHT_GNU_ATTRIBUTES: typing.Final = 1879048181
    """
    Object attributes
    """

    SHT_GNU_HASH: typing.Final = 1879048182
    """
    GNU-style hash table
    """

    SHT_GNU_LIBLIST: typing.Final = 1879048183
    """
    Prelink library list
    """

    SHT_CHECKSUM: typing.Final = 1879048184
    """
    Checksum for DSO content. +
    """

    SHT_SUNW_move: typing.Final = 1879048186
    SHT_SUNW_COMDAT: typing.Final = 1879048187
    SHT_SUNW_syminfo: typing.Final = 1879048188
    SHT_GNU_verdef: typing.Final = 1879048189
    """
    Version definition section.
    """

    SHT_GNU_verneed: typing.Final = 1879048190
    """
    Version needs section.
    """

    SHT_GNU_versym: typing.Final = 1879048191
    """
    Version symbol table.
    """

    SHF_WRITE: typing.Final = 1
    """
    The section contains data that should be writable during process execution.
    """

    SHF_ALLOC: typing.Final = 2
    """
    The section occupies memory during execution
    """

    SHF_EXECINSTR: typing.Final = 4
    """
    The section contains executable machine instructions.
    """

    SHF_MERGE: typing.Final = 16
    """
    The section might be merged
    """

    SHF_STRINGS: typing.Final = 32
    """
    The section contains null-terminated strings
    """

    SHF_INFO_LINK: typing.Final = 64
    """
    sh_info contains SHT index
    """

    SHF_LINK_ORDER: typing.Final = 128
    """
    Preserve order after combining
    """

    SHF_OS_NONCONFORMING: typing.Final = 256
    """
    Non-standard OS specific handling required
    """

    SHF_GROUP: typing.Final = 512
    """
    The section  is member of a group.
    """

    SHF_TLS: typing.Final = 1024
    """
    The section that holds thread-local data.
    """

    SHF_COMPRESSED: typing.Final = 2048
    """
    The bytes of the section are compressed
    """

    SHF_EXCLUDE: typing.Final = -2147483648
    """
    This section is excluded from the final executable or shared library.
    """

    SHF_MASKOS: typing.Final = 267386880
    """
    The section contains OS-specific data.
    """

    SHF_MASKPROC: typing.Final = -268435456
    """
    Processor-specific
    """

    SHN_UNDEF: typing.Final = 0
    """
    undefined, missing, irrelevant section
    """

    SHN_LORESERVE: typing.Final = -256
    """
    lower bound on range of reserved indexes
    """

    SHN_LOPROC: typing.Final = -256
    """
    lower bound for processor-specific semantics
    """

    SHN_HIPROC: typing.Final = -225
    """
    upper bound for processor-specific semantics
    """

    SHN_LOOS: typing.Final = -224
    """
    Lowest operating system-specific index
    """

    SHN_HIOS: typing.Final = -193
    """
    Highest operating system-specific index
    """

    SHN_ABS: typing.Final = -15
    """
    symbol defined relative to this are absolute, not affected by relocation
    """

    SHN_COMMON: typing.Final = -14
    """
    common symbols, such as Fortran COMMON or unallocated C external vars
    """

    SHN_XINDEX: typing.Final = -1
    """
    Mark that the index is >= SHN_LORESERVE
    """

    SHN_HIRESERVE: typing.Final = -1
    """
    upper bound on range of reserved indexes
    """



class ElfDefaultGotPltMarkup(java.lang.Object):
    """
    ``ElfDefaultGotPltMarkup`` provides the legacy/default implementation of ELF GOT/PLT processing 
    which handles a limited set of cases.  It is intended that over time this default implementation be 
    eliminated although it may form the basis of an abstract implementation for specific processor
    extensions.
    """

    @typing.type_check_only
    class PltGotSymbol(java.lang.Comparable[ElfDefaultGotPltMarkup.PltGotSymbol]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, elfLoadHelper: ElfLoadHelper):
        ...

    @staticmethod
    def isValidPointer(pointerData: ghidra.program.model.listing.Data) -> bool:
        """
        Determine if pointerData refers to a valid memory address or symbol
        
        :param ghidra.program.model.listing.Data pointerData: pointer data
        :return: true if pointer data refers to valid memory address or symbol
        :rtype: bool
        """

    def process(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    def processLinkageTable(self, pltName: typing.Union[java.lang.String, str], minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform disassembly and markup of specified external linkage table which 
        consists of thunks to external functions.  If symbols are defined within the 
        linkage table, these will be transitioned to external functions.
        
        :param java.lang.String or str pltName: name of PLT section for log messages
        :param ghidra.program.model.address.Address minAddress: minimum address of linkage table
        :param ghidra.program.model.address.Address maxAddress: maximum address of linkage table
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: task cancelled
        """

    @staticmethod
    def setConstant(data: ghidra.program.model.listing.Data):
        """
        Set specified data as constant if contained within a writable block.  It can be helpful
        to the decompiler results if constant pointers are marked as such (e.g., GOT entries)
        
        :param ghidra.program.model.listing.Data data: program data
        """


class GnuVerdef(ghidra.app.util.bin.StructConverter):
    """
    Version definition sections.
     
    typedef struct {
    Elf32_Half    vd_version;        //Version revision
    Elf32_Half    vd_flags;        //Version information
    Elf32_Half    vd_ndx;            //Version Index
    Elf32_Half    vd_cnt;            //Number of associated aux entries
    Elf32_Word    vd_hash;        //Version name hash value
    Elf32_Word    vd_aux;            //Offset in bytes to verdaux array
    Elf32_Word    vd_next;        //Offset in bytes to next verdef entry
    } Elf32_Verdef;
     
    typedef struct {
    Elf64_Half    vd_version;        //Version revision
    Elf64_Half    vd_flags;        //Version information
    Elf64_Half    vd_ndx;            //Version Index
    Elf64_Half    vd_cnt;            //Number of associated aux entries
    Elf64_Word    vd_hash;        //Version name hash value
    Elf64_Word    vd_aux;            //Offset in bytes to verdaux array
    Elf64_Word    vd_next;        //Offset in bytes to next verdef entry
    } Elf64_Verdef;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAux(self) -> int:
        ...

    def getCnt(self) -> int:
        ...

    def getFlags(self) -> int:
        ...

    def getHash(self) -> int:
        ...

    def getNdx(self) -> int:
        ...

    def getNext(self) -> int:
        ...

    def getVersion(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.bin.StructConverter.toDataType()`
        """

    @property
    def next(self) -> jpype.JInt:
        ...

    @property
    def ndx(self) -> jpype.JShort:
        ...

    @property
    def aux(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JShort:
        ...

    @property
    def cnt(self) -> jpype.JShort:
        ...

    @property
    def version(self) -> jpype.JShort:
        ...

    @property
    def hash(self) -> jpype.JInt:
        ...


class ElfException(java.lang.Exception):
    """
    An exception class to handle encountering
    invalid ELF Headers.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructs a new exception with the specified detail message.
        
        :param java.lang.String or str message: the detail message.
        """

    @typing.overload
    def __init__(self, cause: java.lang.Exception):
        """
        Constructs a new exception with the specified cause and a detail message.
        
        :param java.lang.Exception cause: the cause (which is saved for later retrieval by the method
        """


class ElfFileSection(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getAddressOffset(self) -> int:
        """
        Preferred memory address offset where data should be loaded.
        The returned offset will already have the prelink adjustment 
        applied, although will not reflect any change in the image base.
        
        :return: default memory address offset where data should be loaded
        :rtype: int
        """

    def getEntrySize(self) -> int:
        """
        Size of each structured entry in bytes
        
        :return: entry size or -1 if variable
        :rtype: int
        """

    def getFileOffset(self) -> int:
        """
        Offset within file where section bytes are specified
        
        :return: offset within file where section bytes are specified
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Length of file section in bytes
        
        :return: length of file section in bytes
        :rtype: int
        """

    @property
    def addressOffset(self) -> jpype.JLong:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def entrySize(self) -> jpype.JInt:
        ...


class GnuVerdaux(ghidra.app.util.bin.StructConverter):
    """
    Auxiliary version information.
     
    typedef struct {
    Elf32_Word    vda_name;        //Version or dependency names
    Elf32_Word    vda_next;        //Offset in bytes to next verdaux entry
    } Elf32_Verdaux;
     
    typedef struct {
    Elf64_Word    vda_name;        //Version or dependency names
    Elf64_Word    vda_next;        //Offset in bytes to next verdaux entry
    } Elf32_Verdaux;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getVda_name(self) -> int:
        ...

    def getVda_next(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.bin.StructConverter.toDataType()`
        """

    @property
    def vda_next(self) -> jpype.JInt:
        ...

    @property
    def vda_name(self) -> jpype.JInt:
        ...


class GnuVernaux(ghidra.app.util.bin.StructConverter):
    """
    Auxiliary needed version information.
     
    typedef struct {
    Elf32_Word    vna_hash;        //Hash value of dependency name
    Elf32_Half    vna_flags;        //Dependency specific information
    Elf32_Half    vna_other;        //Unused
    Elf32_Word    vna_name;        //Dependency name string offset
    Elf32_Word    vna_next;        //Offset in bytes to next vernaux entry
    } Elf32_Vernaux;
    
    typedef struct {
    Elf64_Word    vna_hash;        //Hash value of dependency name
    Elf64_Half    vna_flags;        //Dependency specific information
    Elf64_Half    vna_other;        //Unused
    Elf64_Word    vna_name;        //Dependency name string offset
    Elf64_Word    vna_next;        //Offset in bytes to next vernaux entry
    } Elf64_Vernaux;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFlags(self) -> int:
        ...

    def getHash(self) -> int:
        ...

    def getName(self) -> int:
        ...

    def getNext(self) -> int:
        ...

    def getOther(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.bin.StructConverter.toDataType()`
        """

    @property
    def next(self) -> jpype.JInt:
        ...

    @property
    def other(self) -> jpype.JShort:
        ...

    @property
    def name(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JShort:
        ...

    @property
    def hash(self) -> jpype.JInt:
        ...


@typing.type_check_only
class AndroidElfRelocationOffset(ghidra.program.model.data.AbstractLeb128DataType):
    """
    ``AndroidElfRelocationOffset`` provides a dynamic LEB128 relocation 
    offset adjustment component for packed Android ELF Relocation Table groups.
    See :obj:`AndroidElfRelocationGroup`.  The offset adjustment provided
    by the LEB128 memory data is added to the associated baseOffset to obtain
    the corresponding relocation offset/address.
     
    
    Secondary purpose is to retain the relocation offset associated with a 
    component instance.  This functionality relies on the 1:1 relationship
    between this dynamic datatype and the single component which references it.
    """

    class_: typing.ClassVar[java.lang.Class]


class ElfDynamicType(java.lang.Object):

    class ElfDynamicValueType(java.lang.Enum[ElfDynamicType.ElfDynamicValueType]):

        class_: typing.ClassVar[java.lang.Class]
        VALUE: typing.Final[ElfDynamicType.ElfDynamicValueType]
        ADDRESS: typing.Final[ElfDynamicType.ElfDynamicValueType]
        STRING: typing.Final[ElfDynamicType.ElfDynamicValueType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ElfDynamicType.ElfDynamicValueType:
            ...

        @staticmethod
        def values() -> jpype.JArray[ElfDynamicType.ElfDynamicValueType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DT_NULL: typing.ClassVar[ElfDynamicType]
    DT_NEEDED: typing.ClassVar[ElfDynamicType]
    DT_PLTRELSZ: typing.ClassVar[ElfDynamicType]
    DT_PLTGOT: typing.ClassVar[ElfDynamicType]
    DT_HASH: typing.ClassVar[ElfDynamicType]
    DT_STRTAB: typing.ClassVar[ElfDynamicType]
    DT_SYMTAB: typing.ClassVar[ElfDynamicType]
    DT_RELA: typing.ClassVar[ElfDynamicType]
    DT_RELASZ: typing.ClassVar[ElfDynamicType]
    DT_RELAENT: typing.ClassVar[ElfDynamicType]
    DT_STRSZ: typing.ClassVar[ElfDynamicType]
    DT_SYMENT: typing.ClassVar[ElfDynamicType]
    DT_INIT: typing.ClassVar[ElfDynamicType]
    DT_FINI: typing.ClassVar[ElfDynamicType]
    DT_SONAME: typing.ClassVar[ElfDynamicType]
    DT_RPATH: typing.ClassVar[ElfDynamicType]
    DT_SYMBOLIC: typing.ClassVar[ElfDynamicType]
    DT_REL: typing.ClassVar[ElfDynamicType]
    DT_RELSZ: typing.ClassVar[ElfDynamicType]
    DT_RELENT: typing.ClassVar[ElfDynamicType]
    DT_PLTREL: typing.ClassVar[ElfDynamicType]
    DT_DEBUG: typing.ClassVar[ElfDynamicType]
    DT_TEXTREL: typing.ClassVar[ElfDynamicType]
    DT_JMPREL: typing.ClassVar[ElfDynamicType]
    DT_BIND_NOW: typing.ClassVar[ElfDynamicType]
    DT_INIT_ARRAY: typing.ClassVar[ElfDynamicType]
    DT_FINI_ARRAY: typing.ClassVar[ElfDynamicType]
    DT_INIT_ARRAYSZ: typing.ClassVar[ElfDynamicType]
    DT_FINI_ARRAYSZ: typing.ClassVar[ElfDynamicType]
    DT_RUNPATH: typing.ClassVar[ElfDynamicType]
    DT_FLAGS: typing.ClassVar[ElfDynamicType]
    DT_RELRSZ: typing.ClassVar[ElfDynamicType]
    DT_RELR: typing.ClassVar[ElfDynamicType]
    DT_RELRENT: typing.ClassVar[ElfDynamicType]
    DF_ORIGIN: typing.Final = 1
    DF_SYMBOLIC: typing.Final = 2
    DF_TEXTREL: typing.Final = 4
    DF_BIND_NOW: typing.Final = 8
    DF_STATIC_TLS: typing.Final = 16
    DT_PREINIT_ARRAY: typing.ClassVar[ElfDynamicType]
    DT_PREINIT_ARRAYSZ: typing.ClassVar[ElfDynamicType]
    DT_ANDROID_REL: typing.ClassVar[ElfDynamicType]
    DT_ANDROID_RELSZ: typing.ClassVar[ElfDynamicType]
    DT_ANDROID_RELA: typing.ClassVar[ElfDynamicType]
    DT_ANDROID_RELASZ: typing.ClassVar[ElfDynamicType]
    DT_ANDROID_RELR: typing.ClassVar[ElfDynamicType]
    DT_ANDROID_RELRSZ: typing.ClassVar[ElfDynamicType]
    DT_ANDROID_RELRENT: typing.ClassVar[ElfDynamicType]
    DT_GNU_PRELINKED: typing.ClassVar[ElfDynamicType]
    DT_GNU_CONFLICTSZ: typing.ClassVar[ElfDynamicType]
    DT_GNU_LIBLISTSZ: typing.ClassVar[ElfDynamicType]
    DT_CHECKSUM: typing.ClassVar[ElfDynamicType]
    DT_PLTPADSZ: typing.ClassVar[ElfDynamicType]
    DT_MOVEENT: typing.ClassVar[ElfDynamicType]
    DT_MOVESZ: typing.ClassVar[ElfDynamicType]
    DT_FEATURE_1: typing.ClassVar[ElfDynamicType]
    DT_POSFLAG_1: typing.ClassVar[ElfDynamicType]
    DT_SYMINSZ: typing.ClassVar[ElfDynamicType]
    DT_SYMINENT: typing.ClassVar[ElfDynamicType]
    DT_GNU_XHASH: typing.ClassVar[ElfDynamicType]
    DT_GNU_HASH: typing.ClassVar[ElfDynamicType]
    DT_TLSDESC_PLT: typing.ClassVar[ElfDynamicType]
    DT_TLSDESC_GOT: typing.ClassVar[ElfDynamicType]
    DT_GNU_CONFLICT: typing.ClassVar[ElfDynamicType]
    DT_GNU_LIBLIST: typing.ClassVar[ElfDynamicType]
    DT_CONFIG: typing.ClassVar[ElfDynamicType]
    DT_DEPAUDIT: typing.ClassVar[ElfDynamicType]
    DT_AUDIT: typing.ClassVar[ElfDynamicType]
    DT_PLTPAD: typing.ClassVar[ElfDynamicType]
    DT_MOVETAB: typing.ClassVar[ElfDynamicType]
    DT_SYMINFO: typing.ClassVar[ElfDynamicType]
    DT_VERSYM: typing.ClassVar[ElfDynamicType]
    DT_RELACOUNT: typing.ClassVar[ElfDynamicType]
    DT_RELCOUNT: typing.ClassVar[ElfDynamicType]
    DT_FLAGS_1: typing.ClassVar[ElfDynamicType]
    DF_1_NOW: typing.Final = 1
    DF_1_GLOBAL: typing.Final = 2
    DF_1_GROUP: typing.Final = 4
    DF_1_NODELETE: typing.Final = 8
    DF_1_LOADFLTR: typing.Final = 16
    DF_1_INITFIRST: typing.Final = 32
    DF_1_NOOPEN: typing.Final = 64
    DF_1_ORIGIN: typing.Final = 128
    DF_1_DIRECT: typing.Final = 256
    DF_1_INTERPOSE: typing.Final = 1024
    DF_1_NODEFLIB: typing.Final = 2048
    DT_VERDEF: typing.ClassVar[ElfDynamicType]
    DT_VERDEFNUM: typing.ClassVar[ElfDynamicType]
    DT_VERNEED: typing.ClassVar[ElfDynamicType]
    DT_VERNEEDNUM: typing.ClassVar[ElfDynamicType]
    DT_AUXILIARY: typing.ClassVar[ElfDynamicType]
    DT_FILTER: typing.ClassVar[ElfDynamicType]
    value: typing.Final[jpype.JInt]
    name: typing.Final[java.lang.String]
    description: typing.Final[java.lang.String]
    valueType: typing.Final[ElfDynamicType.ElfDynamicValueType]

    def __init__(self, value: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], valueType: ElfDynamicType.ElfDynamicValueType):
        ...

    @staticmethod
    def addDefaultTypes(dynamicTypeMap: collections.abc.Mapping):
        ...

    @staticmethod
    def addDynamicType(type: ElfDynamicType, dynamicTypeMap: collections.abc.Mapping):
        """
        Add the specified dynamic entry type to the specified map.
        
        :param ElfDynamicType type: dynamic entry type
        :param collections.abc.Mapping dynamicTypeMap: map of dynamic types
        :raises DuplicateNameException: if new type name already defined within
        the specified map
        """


@typing.type_check_only
class ElfRelrRelocationTableDataType(ghidra.program.model.data.FactoryStructureDataType):
    """
    ``ElfRelrRelocationTableDataType`` is a Factory datatype which defines a markup
    structure corresponding to a specified ELF REL relocation table.  The REL entry size and
    total length in bytes is required when interpreting a RELR table.
    """

    class_: typing.ClassVar[java.lang.Class]


class GnuConstants(java.lang.Object):
    """
    GNU Constants.
    """

    class_: typing.ClassVar[java.lang.Class]
    VER_NDX_LOCAL: typing.Final = 0
    """
    Symbol is local.
    """

    VER_NDX_GLOBAL: typing.Final = 1
    """
    Symbol is global.
    """

    VER_NDX_LORESERVE: typing.Final = -256
    """
    Beginning of reserved entries.
    """

    VER_NDX_ELIMINATE: typing.Final = -255
    """
    Symbol is to be eliminated.
    """



class ElfLoadHelper(java.lang.Object):
    """
    ``ElfLoadHelper`` exposes loader methods useful to ElfExtension 
    implementations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addArtificialRelocTableEntry(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> bool:
        """
        Add an artificial relocation table entry if none previously existed for the specified address.
        This is intended to record original file bytes when forced modifications have been
        performed during the ELF import processing.  A relocation type of 0 and a status of 
        :obj:`Status.APPLIED_OTHER` will be applied to the relocation entry.  
        NOTE: The number of recorded original FileBytes currently ignores the specified length.
        However, the length is still used to verify that the intended modification region
        does not intersect another relocation.
        
        :param ghidra.program.model.address.Address address: relocation address
        :param jpype.JInt or int length: number of bytes affected
        :return: true if recorded successfully, or false if conflict with existing relocation 
        entry and memory addressing error occurs
        :rtype: bool
        """

    def allocateLinkageBlock(self, alignment: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], purpose: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.AddressRange:
        """
        
        Get a free aligned address range within the program's memory block structure to facilitate 
        dynamic memory block allocation requirements to support relocation processing (e.g., fake EXTERNAL memory block,
        generated GOT for object modules, etc.).  The range returned for the EXTERNAL memory block may be very large
        but only that portion used should be committed the program's memory map.  The EXTERNAL memory block
        must be committed to the memory map prior to any subsequent invocations of this method
        
         
        
        NOTES: Additional support may be required for spaces with odd word sizes,
        small 16-bit default memory space, or when shared memory regions exist.
         
        
        
        :param jpype.JInt or int alignment: required byte alignment of allocated range
        :param jpype.JInt or int size: size of requested allocation (size <= 0 reserved for EXTERNAL block)
        :param java.lang.String or str purpose: brief descriptive purpose of range.
        :return: address range or null if no unallocated range found
        :rtype: ghidra.program.model.address.AddressRange
        """

    def createData(self, address: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType) -> ghidra.program.model.listing.Data:
        """
        Create a data item using the specified data type
        
        :param ghidra.program.model.address.Address address: location of undefined data to create
        :param ghidra.program.model.data.DataType dt: data type
        :return: :obj:`Data` which was created or null if conflict occurs
        :rtype: ghidra.program.model.listing.Data
        """

    def createExternalFunctionLinkage(self, name: typing.Union[java.lang.String, str], functionAddr: ghidra.program.model.address.Address, indirectPointerAddr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Create an external function within the UNKNOWN space and a corresponding thunk at 
        the internalFunctionAddr.  If the functionAddr and/or indirectPointerAddr has a symbol with
        ``<name>`` it will be removed so as not to replicate the external function name.
        
        :param java.lang.String or str name: external function name
        :param ghidra.program.model.address.Address functionAddr: location of thunk function (memory address only)
        :param ghidra.program.model.address.Address indirectPointerAddr: if not null a pointer to functionAddr will be written (size of pointer
        based 32 or 64 bits based upon ELF size).  Memory must exist and will be converted to initialized
        if needed.
        :return: thunk function or null if failure occurred
        :rtype: ghidra.program.model.listing.Function
        """

    def createOneByteFunction(self, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, isEntry: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.Function:
        """
        Create a one-byte function, so that when the code is analyzed,
        it will be disassembled, and the function created with the correct body.
        
        :param java.lang.String or str name: name of function or null for default (or label already applied)
        :param ghidra.program.model.address.Address address: address of function
        :param jpype.JBoolean or bool isEntry: mark function as entry point if true
        :return: new or existing function.
        :rtype: ghidra.program.model.listing.Function
        """

    def createSymbol(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], isPrimary: typing.Union[jpype.JBoolean, bool], pinAbsolute: typing.Union[jpype.JBoolean, bool], namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Create the specified label symbol within the program.
        
        :param ghidra.program.model.address.Address addr: program address
        :param java.lang.String or str name: symbol/label name
        :param jpype.JBoolean or bool isPrimary: true if is symbol should be made primary (certain name patterns excluded)
        :param jpype.JBoolean or bool pinAbsolute: true if address is absolute and should not change
        :param ghidra.program.model.symbol.Namespace namespace: symbol namespace (should generally be null for global namespace)
        :return: program symbol
        :rtype: ghidra.program.model.symbol.Symbol
        :raises InvalidInputException: if an invalid name is specified
        """

    def createUndefinedData(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Data:
        """
        Create an undefined data item to reserve the location as data, without specifying the type.
        If :meth:`ElfLoaderOptionsFactory.applyUndefinedSymbolData(java.util.List) <ElfLoaderOptionsFactory.applyUndefinedSymbolData>` returns false
        data will not be applied and null will be returned.
        
        :param ghidra.program.model.address.Address address: location of undefined data to create
        :param jpype.JInt or int length: size of the undefined data item
        :return: :obj:`Data` which was created or null if conflict occurs or disabled by option
        :rtype: ghidra.program.model.listing.Data
        """

    def findLoadAddress(self, section: ghidra.app.util.bin.format.MemoryLoadable, byteOffsetWithinSection: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Find the program address at which a specified offset within a section or segment was loaded/resolved.
        
        :param ghidra.app.util.bin.format.MemoryLoadable section: a segment or section header which was loaded to memory
        :param jpype.JLong or int byteOffsetWithinSection: offset within section
        :return: resolved load address or null if not loaded
        :rtype: ghidra.program.model.address.Address
        """

    def getDefaultAddress(self, addressableWordOffset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the program address for an addressableWordOffset within the default address space.  
        This method is responsible for applying any program image base change imposed during 
        the import (see :meth:`getImageBaseWordAdjustmentOffset() <.getImageBaseWordAdjustmentOffset>`.
        
        :param jpype.JLong or int addressableWordOffset: absolute word offset.  The offset should already include
        default image base and pre-link adjustment (see :meth:`ElfHeader.adjustAddressForPrelink(long) <ElfHeader.adjustAddressForPrelink>`).
        :return: memory address in default code space
        :rtype: ghidra.program.model.address.Address
        """

    def getElfHeader(self) -> ElfHeader:
        """
        Get ELF Header object
        
        :return: ELF Header object
        :rtype: ElfHeader
        """

    def getElfSymbolAddress(self, elfSymbol: ElfSymbol) -> ghidra.program.model.address.Address:
        """
        Get the memory address of a previously resolved symbol
        
        :param ElfSymbol elfSymbol: elf symbol
        :return: memory address or null if unknown
        :rtype: ghidra.program.model.address.Address
        """

    def getGOTValue(self) -> int:
        """
        Returns the appropriate .got (Global Offset Table) section address using the
        DT_PLTGOT value defined in the .dynamic section.
        If the dynamic value is not defined, the symbol offset for _GLOBAL_OFFSET_TABLE_
        will be used, otherwise null will be returned.  See :obj:`ElfConstants.GOT_SYMBOL_NAME`.
        
        :return: the .got section address offset
        :rtype: int
        """

    def getImageBaseWordAdjustmentOffset(self) -> int:
        """
        Get the program image base offset adjustment.  The value returned reflects the
        actual program image base minus the default image base (see :meth:`ElfHeader.getImageBase() <ElfHeader.getImageBase>`.
        This will generally be zero (0), unless the program image base differs from the
        default.  It may be necessary to add this value to any pre-linked address values
        such as those contained with the dynamic table. (Applies to default address space only)
        
        :return: image base adjustment value
        :rtype: int
        """

    def getLog(self) -> ghidra.app.util.importer.MessageLog:
        """
        Get the message log
        
        :return: message log
        :rtype: ghidra.app.util.importer.MessageLog
        """

    def getOption(self, optionName: typing.Union[java.lang.String, str], defaultValue: T) -> T:
        """
        Get an import processing option value
        
        :param T: class of option value (e.g., String, Boolean, etc.):param java.lang.String or str optionName: option name
        :param T defaultValue: default option value which also establishes expected value type
        :return: option value
        :rtype: T
        """

    def getOriginalValue(self, addr: ghidra.program.model.address.Address, signExtend: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        
        Get the original memory value at the specified address if a relocation was applied at the
        specified address (not containing).  Current memory value will be returned if no relocation
        has been applied at specified address.  The value size is either 8-bytes if :meth:`ElfHeader.is64Bit() <ElfHeader.is64Bit>`,
        otherwise it will be 4-bytes.  This is primarily intended to inspect original bytes within 
        the GOT which may have had relocations applied to them.
        
        :param ghidra.program.model.address.Address addr: memory address
        :param jpype.JBoolean or bool signExtend: if true sign-extend to long, else treat as unsigned
        :return: original bytes value
        :rtype: int
        :raises MemoryAccessException: if memory read fails
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get program object
        
        :return: program object
        :rtype: ghidra.program.model.listing.Program
        """

    @typing.overload
    def log(self, msg: typing.Union[java.lang.String, str]):
        """
        Output loader log message
        
        :param java.lang.String or str msg: text message
        """

    @typing.overload
    def log(self, t: java.lang.Throwable):
        """
        Output loader log message.
        
        :param java.lang.Throwable t: exception/throwable error
        """

    def markAsCode(self, address: ghidra.program.model.address.Address):
        """
        Mark this location as code in the CodeMap.
        The analyzers will pick this up and disassemble the code.
        
        :param ghidra.program.model.address.Address address: code memory address to be marked
        """

    def setElfSymbolAddress(self, elfSymbol: ElfSymbol, address: ghidra.program.model.address.Address):
        """
        Add specified elfSymbol to the loader symbol map after its program address has been assigned
        
        :param ElfSymbol elfSymbol: elf symbol
        :param ghidra.program.model.address.Address address: program address (may be null if not applicable)
        """

    @property
    def imageBaseWordAdjustmentOffset(self) -> jpype.JLong:
        ...

    @property
    def gOTValue(self) -> jpype.JLong:
        ...

    @property
    def elfHeader(self) -> ElfHeader:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def elfSymbolAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def defaultAddress(self) -> ghidra.program.model.address.Address:
        ...


class GnuVerneed(ghidra.app.util.bin.StructConverter):
    """
    Version dependency section.
     
    typedef struct {
    Elf32_Half    vn_version;        //Version of structure
    Elf32_Half    vn_cnt;            //Number of associated aux entries
    Elf32_Word    vn_file;        //Offset of filename for this dependency
    Elf32_Word    vn_aux;            //Offset in bytes to vernaux array
    Elf32_Word    vn_next;        //Offset in bytes to next verneed entry
    } Elf32_Verneed;
     
    typedef struct {
    Elf64_Half    vn_version;        //Version of structure
    Elf64_Half    vn_cnt;            //Number of associated aux entries
    Elf64_Word    vn_file;        //Offset of filename for this dependency
    Elf64_Word    vn_aux;            //Offset in bytes to vernaux array
    Elf64_Word    vn_next;        //Offset in bytes to next verneed entry
    } Elf64_Verneed;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAux(self) -> int:
        ...

    def getCnt(self) -> int:
        ...

    def getFile(self) -> int:
        ...

    def getNext(self) -> int:
        ...

    def getVersion(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.bin.StructConverter.toDataType()`
        """

    @property
    def next(self) -> jpype.JInt:
        ...

    @property
    def file(self) -> jpype.JInt:
        ...

    @property
    def aux(self) -> jpype.JInt:
        ...

    @property
    def cnt(self) -> jpype.JShort:
        ...

    @property
    def version(self) -> jpype.JShort:
        ...


class ElfSectionHeaderType(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SHT_NULL: typing.ClassVar[ElfSectionHeaderType]
    SHT_PROGBITS: typing.ClassVar[ElfSectionHeaderType]
    SHT_SYMTAB: typing.ClassVar[ElfSectionHeaderType]
    SHT_STRTAB: typing.ClassVar[ElfSectionHeaderType]
    SHT_RELA: typing.ClassVar[ElfSectionHeaderType]
    SHT_HASH: typing.ClassVar[ElfSectionHeaderType]
    SHT_DYNAMIC: typing.ClassVar[ElfSectionHeaderType]
    SHT_NOTE: typing.ClassVar[ElfSectionHeaderType]
    SHT_NOBITS: typing.ClassVar[ElfSectionHeaderType]
    SHT_REL: typing.ClassVar[ElfSectionHeaderType]
    SHT_SHLIB: typing.ClassVar[ElfSectionHeaderType]
    SHT_DYNSYM: typing.ClassVar[ElfSectionHeaderType]
    SHT_INIT_ARRAY: typing.ClassVar[ElfSectionHeaderType]
    SHT_FINI_ARRAY: typing.ClassVar[ElfSectionHeaderType]
    SHT_PREINIT_ARRAY: typing.ClassVar[ElfSectionHeaderType]
    SHT_GROUP: typing.ClassVar[ElfSectionHeaderType]
    SHT_SYMTAB_SHNDX: typing.ClassVar[ElfSectionHeaderType]
    SHT_ANDROID_REL: typing.ClassVar[ElfSectionHeaderType]
    SHT_ANDROID_RELA: typing.ClassVar[ElfSectionHeaderType]
    SHT_GNU_ATTRIBUTES: typing.ClassVar[ElfSectionHeaderType]
    SHT_GNU_HASH: typing.ClassVar[ElfSectionHeaderType]
    SHT_GNU_LIBLIST: typing.ClassVar[ElfSectionHeaderType]
    SHT_CHECKSUM: typing.ClassVar[ElfSectionHeaderType]
    SHT_SUNW_move: typing.ClassVar[ElfSectionHeaderType]
    SHT_SUNW_COMDAT: typing.ClassVar[ElfSectionHeaderType]
    SHT_SUNW_syminfo: typing.ClassVar[ElfSectionHeaderType]
    SHT_GNU_verdef: typing.ClassVar[ElfSectionHeaderType]
    SHT_GNU_verneed: typing.ClassVar[ElfSectionHeaderType]
    SHT_GNU_versym: typing.ClassVar[ElfSectionHeaderType]
    value: typing.Final[jpype.JInt]
    name: typing.Final[java.lang.String]
    description: typing.Final[java.lang.String]

    def __init__(self, value: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def addDefaultTypes(programHeaderTypeMap: collections.abc.Mapping):
        ...

    @staticmethod
    def addSectionHeaderType(type: ElfSectionHeaderType, sectionHeaderTypeMap: collections.abc.Mapping):
        """
        Add the specified section header type to the specified map.
        
        :param ElfSectionHeaderType type: section header type
        :param collections.abc.Mapping sectionHeaderTypeMap: map of section header types
        :raises DuplicateNameException: if new type name already defined within
        the specified map
        """

    @staticmethod
    def getEnumDataType(is32bit: typing.Union[jpype.JBoolean, bool], typeSuffix: typing.Union[java.lang.String, str], dynamicTypeMap: collections.abc.Mapping) -> ghidra.program.model.data.EnumDataType:
        ...


class AndroidElfRelocationTableDataType(ghidra.program.model.data.DynamicDataType):
    """
    ``AndroidElfRelocationTableDataType`` provides an implementation of 
    an Android APS2 packed ELF relocation table.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...

    @staticmethod
    @typing.overload
    def getLEB128Component(leb128: ghidra.app.util.bin.LEB128Info, parent: ghidra.program.model.data.DynamicDataType, ordinal: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], relocOffset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.data.DataTypeComponent:
        ...

    @staticmethod
    @typing.overload
    def getLEB128Component(leb128: ghidra.app.util.bin.LEB128Info, parent: ghidra.program.model.data.DynamicDataType, ordinal: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataTypeComponent:
        ...


class ElfProgramHeaderConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    PT_NULL: typing.Final = 0
    """
    Unused/Undefined segment
    """

    PT_LOAD: typing.Final = 1
    """
    Loadable segment
    """

    PT_DYNAMIC: typing.Final = 2
    """
    Dynamic linking information (.dynamic section)
    """

    PT_INTERP: typing.Final = 3
    """
    Interpreter path name
    """

    PT_NOTE: typing.Final = 4
    """
    Auxiliary information location
    """

    PT_SHLIB: typing.Final = 5
    """
    Unused
    """

    PT_PHDR: typing.Final = 6
    """
    Program header table
    """

    PT_TLS: typing.Final = 7
    """
    Thread-local storage segment
    """

    PT_GNU_EH_FRAME: typing.Final = 1685382480
    """
    GCC .eh_frame_hdr segment
    """

    PT_GNU_STACK: typing.Final = 1685382481
    """
    Indicates stack executability
    """

    PT_GNU_RELRO: typing.Final = 1685382482
    """
    Specifies segments which may be read-only after relocation
    """

    PT_SUNWBSS: typing.Final = 1879048186
    """
    Sun Specific segment
    """

    PT_SUNWSTACK: typing.Final = 1879048187
    """
    Stack segment
    """

    PF_X: typing.Final = 1
    """
    Segment is executable
    """

    PF_W: typing.Final = 2
    """
    Segment is writable
    """

    PF_R: typing.Final = 4
    """
    Segment is readable
    """

    PF_MASKOS: typing.Final = 267386880
    """
    OS-specific
    """

    PF_MASKPROC: typing.Final = -268435456
    """
    Processor-specific
    """



class ElfSymbol(java.lang.Object):
    """
    A class to represent the ELF 32bit and 64bit Symbol data structures.
     
    
     
    typedef struct {
        Elf32_Word      st_name;     //Symbol name (string tbl index)
        Elf32_Addr      st_value;    //Symbol value
        Elf32_Word      st_size;     //Symbol size
        unsigned char   st_info;     //Symbol type and binding
        unsigned char   st_other;    //Symbol visibility
        Elf32_Section   st_shndx;    //Section index
    } Elf32_Sym;
     
    typedef struct {
        Elf64_Word       st_name;    //Symbol name (string tbl index)
        unsigned char    st_info;    //Symbol type and binding
        unsigned char    st_other;   //Symbol visibility
        Elf64_Section    st_shndx;   //Section index
        Elf64_Addr       st_value;   //Symbol value
        Elf64_Xword      st_size;    //Symbol size
    } Elf64_Sym;
    """

    class_: typing.ClassVar[java.lang.Class]
    FORMATTED_NO_NAME: typing.Final = "<no name>"
    STB_LOCAL: typing.Final = 0
    """
    Local symbols are not visible outside the object file containing their definition.
    """

    STB_GLOBAL: typing.Final = 1
    """
    Global symbols are visible to all object files being combined.
    """

    STB_WEAK: typing.Final = 2
    """
    Weak symbols resemble global symbols, but their definitions have lower precedence.
    """

    STB_GNU_UNIQUE: typing.Final = 10
    """
    Symbol is unique in namespace.
    """

    STT_NOTYPE: typing.Final = 0
    """
    The symbol's type is not specified.
    """

    STT_OBJECT: typing.Final = 1
    """
    The symbol is associated with a data object, such as a variable, an array, etc.
    """

    STT_FUNC: typing.Final = 2
    """
    The symbol is associated with a function or other executable code.
    """

    STT_SECTION: typing.Final = 3
    """
    The symbol is associated with a section. (Used for relocation and normally have STB_LOCAL binding.)
    """

    STT_FILE: typing.Final = 4
    """
    The symbol's name gives the name of the source file associated with the object file.
    """

    STT_COMMON: typing.Final = 5
    """
    An uninitialized common block
    """

    STT_TLS: typing.Final = 6
    """
    In object files: st_value contains offset from the beginning of the section
    In DSOs:         st_value contains offset in the TLS initialization image (inside of .tdata)
    """

    STT_RELC: typing.Final = 8
    """
    Symbol is in support of complex relocation.
    """

    STT_SRELC: typing.Final = 9
    """
    Symbol is in support of complex relocation (signed value).
    """

    STV_DEFAULT: typing.Final = 0
    """
    Default symbol visibility rules
    """

    STV_INTERNAL: typing.Final = 1
    """
    Processor specific hidden class
    """

    STV_HIDDEN: typing.Final = 2
    """
    Sym unavailable in other modules
    """

    STV_PROTECTED: typing.Final = 3
    """
    Not preemptible, not exported
    """


    @typing.overload
    def __init__(self):
        """
        Construct a new special null symbol which corresponds to symbol index 0.
        """

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, symbolIndex: typing.Union[jpype.JInt, int], symbolTable: ElfSymbolTable, header: ElfHeader):
        """
        Construct a normal ElfSymbol.
        Warning! the routine initSymbolName() must be called on the symbol later
        to initialize the string name.  This is a performance enhancement.
        
        :param ghidra.app.util.bin.BinaryReader reader: to read symbol entry at current position 
                        (reader is not retained, position is altered)
        :param jpype.JInt or int symbolIndex: index of the symbol to read
        :param ElfSymbolTable symbolTable: symbol table to associate the symbol to
        :param ElfHeader header: ELF header
        :raises IOException: if an IO error occurs during parse
        """

    def getBind(self) -> int:
        """
        Returns the symbol's binding. For example, global.
        
        :return: the symbol's binding
        :rtype: int
        """

    def getExtendedSectionHeaderIndex(self) -> int:
        """
        Get the extended symbol section index value when ``st_shndx``
        (:meth:`getSectionHeaderIndex() <.getSectionHeaderIndex>`) has a value of SHN_XINDEX.  This requires a lookup
        into a table defined by an associated SHT_SYMTAB_SHNDX section.
        
        :return: extended symbol section index value
        :rtype: int
        """

    def getFormattedName(self) -> str:
        """
        Returns the formatted string name for this symbol. If the name is blank or
        can not be resolved due to a missing string table the literal string 
        *<no name>* will be returned.
        the name string is located.
        
        :return: the actual string name for this symbol or the literal string *<no name>*
        :rtype: str
        """

    def getInfo(self) -> int:
        """
        This member specifies the symbol's type and binding attributes.
        
        :return: the symbol's type and binding attributes
        :rtype: int
        """

    def getName(self) -> int:
        """
        This member holds an index into the object file's symbol 
        string table, which holds the character representations 
        of the symbol names. If the value is non-zero, it represents a
        string table index that gives the symbol name.
        Otherwise, the symbol table entry has no name.
        
        :return: the index to the symbol's name
        :rtype: int
        """

    def getNameAsString(self) -> str:
        """
        Returns the actual string name for this symbol. The symbol only
        stores an byte index into the string table where
        the name string is located.
        
        :return: the actual string name for this symbol (may be null or empty string)
        :rtype: str
        """

    def getOther(self) -> int:
        """
        This member currently holds 0 and has no defined meaning.
        
        :return: no defined meaning
        :rtype: int
        """

    def getSectionHeaderIndex(self) -> int:
        """
        Get the raw section index value (``st_shndx``) for this symbol.
        Special values (SHN_LORESERVE and higher) must be treated properly.  The value SHN_XINDEX 
        indicates that the extended value must be used to obtained the actual section index 
        (see :meth:`getExtendedSectionHeaderIndex() <.getExtendedSectionHeaderIndex>`).
        
        :return: the ``st_shndx`` section index value
        :rtype: int
        """

    def getSize(self) -> int:
        """
        Many symbols have associated sizes. For example, a data object's size is the number of
        bytes contained in the object. This member holds 0 if the symbol has no size or an
        unknown size.
        
        :return: the symbol's size
        :rtype: int
        """

    def getSymbolTable(self) -> ElfSymbolTable:
        """
        Get the symbol table containing this symbol
        
        :return: symbol table
        :rtype: ElfSymbolTable
        """

    def getSymbolTableIndex(self) -> int:
        """
        Get the index of this symbol within the corresponding symbol table.
        
        :return: index of this symbol within the corresponding symbol table
        :rtype: int
        """

    def getType(self) -> int:
        """
        Returns the symbol's binding. For example, section.
        
        :return: the symbol's binding
        :rtype: int
        """

    def getValue(self) -> int:
        """
        This member gives the value of the associated symbol.
        Depending on the context, this may be an absolute value, 
        an address, etc.
        
        :return: the symbol's value
        :rtype: int
        """

    def getVisibility(self) -> int:
        """
        Returns the symbol's visibility. For example, default.
        
        :return: the symbol's visibility
        :rtype: int
        """

    def hasProcessorSpecificSymbolSectionIndex(self) -> bool:
        """
        Determine if st_shndx is within the reserved processor-specific index range
        
        :return: true if specified symbol section index corresponds to a processor
        specific value in the range SHN_LOPROC..SHN_HIPROC, else false
        :rtype: bool
        """

    def initSymbolName(self, reader: ghidra.app.util.bin.BinaryReader, stringTable: ElfStringTable):
        """
        Initialize the string name of the symbol.
         
        NOTE: This routine MUST be called for each
        ELFSymbol after the elf symbols have been created.
         
        This is done separately from the initial symbol entry read because
        the string names are in a separate location.  If they are read
        at the same time the reading buffer will jump around and significantly
        degrade reading performance.
        
        :param ghidra.app.util.bin.BinaryReader reader: to read from (position remains unchanged)
        :param ElfStringTable stringTable: stringTable to initialize symbol name
        """

    def isAbsolute(self) -> bool:
        """
        Returns true if the symbol has an absolute 
        value that will not change because of relocation.
        
        :return: true if the symbol value will not change due to relocation
        :rtype: bool
        """

    def isCommon(self) -> bool:
        """
        The symbol labels a common block that has not yet been allocated. The symbol's value
        gives alignment constraints, similar to a section's sh_addralign member. That is, the
        link editor will allocate the storage for the symbol at an address that is a multiple of
        st_value. The symbol's size tells how many bytes are required.
        
        :return: true if this is a common symbol
        :rtype: bool
        """

    def isExternal(self) -> bool:
        """
        Returns true if this is an external symbol.
        A symbol is considered external if it's 
        binding is global and it's size is zero.
        
        :return: true if this is an external symbol
        :rtype: bool
        """

    def isFile(self) -> bool:
        """
        Returns true if this symbol defines a file.
        
        :return: true if this symbol defines a file
        :rtype: bool
        """

    def isFunction(self) -> bool:
        """
        Returns true if this symbol defines a function.
        
        :return: true if this symbol defines a function
        :rtype: bool
        """

    def isGlobal(self) -> bool:
        """
        Returns true if this symbol is global.
        Global symbols are visible to all object files 
        being combined. One object file's definition
        of a global symbol will satisfy another
        file's undefined reference to the same
        global symbol.
        
        :return: true if this symbol is global
        :rtype: bool
        """

    def isLocal(self) -> bool:
        """
        Returns true if this symbol is local.
        Local symbols are not visible outside the object file
        containing their definition. Local symbols of the same
        name may exist in multiple files without colliding.
        
        :return: true if this symbol is local
        :rtype: bool
        """

    def isNoType(self) -> bool:
        """
        Returns true if this symbol's type is not specified.
        
        :return: true if this symbol's type is not specified
        :rtype: bool
        """

    def isObject(self) -> bool:
        """
        Returns true if this symbol defines an object.
        
        :return: true if this symbol defines an object
        :rtype: bool
        """

    def isSection(self) -> bool:
        """
        Returns true if this symbol defines a section.
        
        :return: true if this symbol defines a section
        :rtype: bool
        """

    def isTLS(self) -> bool:
        """
        Returns true if this symbol defines a thread-local symbol.
        
        :return: true if this symbol defines a thread-local symbol
        :rtype: bool
        """

    def isWeak(self) -> bool:
        """
        Returns true if this symbol is weak.
        Weak symbols resemble global symbols,
        but their definitions have lower precedence.
        
        :return: true if this symbol is weak
        :rtype: bool
        """

    @property
    def other(self) -> jpype.JByte:
        ...

    @property
    def formattedName(self) -> java.lang.String:
        ...

    @property
    def section(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> jpype.JByte:
        ...

    @property
    def local(self) -> jpype.JBoolean:
        ...

    @property
    def weak(self) -> jpype.JBoolean:
        ...

    @property
    def file(self) -> jpype.JBoolean:
        ...

    @property
    def bind(self) -> jpype.JByte:
        ...

    @property
    def common(self) -> jpype.JBoolean:
        ...

    @property
    def function(self) -> jpype.JBoolean:
        ...

    @property
    def nameAsString(self) -> java.lang.String:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @property
    def symbolTableIndex(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> jpype.JByte:
        ...

    @property
    def noType(self) -> jpype.JBoolean:
        ...

    @property
    def symbolTable(self) -> ElfSymbolTable:
        ...

    @property
    def visibility(self) -> jpype.JByte:
        ...

    @property
    def sectionHeaderIndex(self) -> jpype.JShort:
        ...

    @property
    def global_(self) -> jpype.JBoolean:
        ...

    @property
    def external(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def extendedSectionHeaderIndex(self) -> jpype.JInt:
        ...

    @property
    def absolute(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> jpype.JInt:
        ...

    @property
    def tLS(self) -> jpype.JBoolean:
        ...

    @property
    def object(self) -> jpype.JBoolean:
        ...


class ElfDynamic(java.lang.Object):
    """
    A class to represent the Elf``32``_Dyn data structure.
     
    ``
    typedef  int32_t  Elf32_Sword;
    typedef uint32_t  Elf32_Word;
    typedef uint32_t  Elf32_Addr;
     
    typedef struct {
        Elf32_Sword     d_tag;
        union {
            Elf32_Word  d_val;
            Elf32_Addr  d_ptr;
        } d_un;
    } Elf32_Dyn;
     
    typedef   int64_t  Elf64_Sxword;
    typedef  uint64_t  Elf64_Xword;
    typedef  uint64_t  Elf64_Addr;
     
    typedef struct {
        Elf64_Sxword       d_tag;     //Dynamic entry type
        union {
            Elf64_Xword d_val;     //Integer value
            Elf64_Addr  d_ptr;     //Address value
        } d_un;
    } Elf64_Dyn;
     
    ``
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, elf: ElfHeader):
        """
        Construct an ELF dynamic table entry
        
        :param ghidra.app.util.bin.BinaryReader reader: to read dynamic entry at current position 
                        (reader is not retained, position moves to next entry)
        :param ElfHeader elf: ELF header
        :raises IOException: if an IO error occurs during parse
        """

    @typing.overload
    def __init__(self, tag: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int], elf: ElfHeader):
        """
        Constructs a new ELF dynamic with the specified tag and value.
        
        :param jpype.JInt or int tag: the tag (or type) of this dynamic
        :param jpype.JLong or int value: the value (or pointer) of this dynamic
        :param ElfHeader elf: the elf header
        """

    @typing.overload
    def __init__(self, tag: ElfDynamicType, value: typing.Union[jpype.JLong, int], elf: ElfHeader):
        """
        Constructs a new ELF dynamic with the specified (enum) tag and value.
        
        :param ElfDynamicType tag: the (enum) tag (or type) of this dynamic
        :param jpype.JLong or int value: the value (or pointer) of this dynamic
        :param ElfHeader elf: the elf header
        """

    def getTag(self) -> int:
        """
        Returns the value that controls the interpretation of the 
        the d_val and/or d_ptr.
        
        :return: the tag (or type) of this dynamic
        :rtype: int
        """

    def getTagAsString(self) -> str:
        """
        A convenience method for getting a string representing the d_tag value.
        For example, if d_tag == DT_SYMTAB, then this method returns "DT_SYMTAB".
        
        :return: a string representing the d_tag value
        :rtype: str
        """

    def getTagType(self) -> ElfDynamicType:
        """
        Returns the enum value that controls the interpretation of the 
        the d_val and/or d_ptr (or null if unknown).
        
        :return: the enum tag (or type) of this dynamic or null if unknown
        :rtype: ElfDynamicType
        """

    def getValue(self) -> int:
        """
        Returns the object whose integer values represent various interpretations.
        For example, if d_tag == DT_SYMTAB, then d_val holds the address of the symbol table.
        But, if d_tag == DT_SYMENT, then d_val holds the size of each symbol entry.
        
        :return: the Elf32_Word object represent integer values with various interpretations
        :rtype: int
        """

    def sizeof(self) -> int:
        """
        
        
        :return: the size in bytes of this object.
        :rtype: int
        """

    @property
    def tagType(self) -> ElfDynamicType:
        ...

    @property
    def tag(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @property
    def tagAsString(self) -> java.lang.String:
        ...


@typing.type_check_only
class AndroidElfRelocationGroup(ghidra.program.model.data.DynamicDataType):
    """
    ``AndroidElfRelocationGroup`` provides a dynamic substructure 
    component for relocation groups within a packed Android ELF Relocation Table.
    See :obj:`AndroidElfRelocationTableDataType`.
    """

    class_: typing.ClassVar[java.lang.Class]


class ElfProgramHeader(ghidra.app.util.bin.StructConverter, java.lang.Comparable[ElfProgramHeader], ghidra.app.util.bin.format.MemoryLoadable):
    """
    An executable or shared object file's program header table is an 
    array of structures, each describing a segment
    or other information the system needs to prepare the program for execution. 
    An object file segment contains one or more sections. 
    Program headers are meaningful only for executable 
    and shared object files. A file specifies its 
    own program header size with the ELF
    header's e_phentsize and e_phnum members.
    Some entries describe process segments; others give supplementary information and do not contribute to
    the process image. Segment entries may appear in any order. Except for PT_LOAD segment 
    entries which must appear in ascending order, sorted on the p_vaddr member.
     
    
     
    typedef struct {
        Elf32_Word   p_type;
        Elf32_Off    p_offset;
        Elf32_Addr   p_vaddr;
        Elf32_Addr   p_paddr;
        Elf32_Word   p_filesz;
        Elf32_Word   p_memsz;
        Elf32_Word   p_flags;
        Elf32_Word   p_align;
    } Elf32_Phdr;
     
    typedef struct {
        Elf64_Word   p_type;         //Segment type
        Elf64_Word   p_flags;        //Segment flags
        Elf64_Off    p_offset;       //Segment file offset
        Elf64_Addr   p_vaddr;        //Segment virtual address
        Elf64_Addr   p_paddr;        //Segment physical address
        Elf64_Xword  p_filesz;       //Segment size in file
        Elf64_Xword  p_memsz;        //Segment size in memory
        Elf64_Xword  p_align;        //Segment alignment
    } Elf64_Phdr;
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ElfHeader):
        """
        Construct :obj:`ElfProgramHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: dedicated reader instance positioned to the start of the program header data.
        (the reader supplied will be retained and altered).
        :param ElfHeader header: ELF header
        :raises IOException: if an IO error occurs during parse
        """

    def getAdjustedLoadSize(self) -> int:
        """
        Get the adjusted file load size (i.e., filtered load size) to be loaded into memory block which relates to 
        this program header; it may be zero if no block should be created.  The returned value reflects any adjustment 
        the ElfExtension may require based upon the specific processor/language implementation which may 
        require filtering of file bytes as loaded into memory.
        
        :return: the number of bytes to be loaded into the resulting memory block
        :rtype: int
        """

    def getAdjustedMemorySize(self) -> int:
        """
        Get the adjusted memory size in bytes of the memory block which relates to this program header; it may be zero
        if no block should be created.  The returned value reflects any adjustment the ElfExtension may require
        based upon the specific processor/language implementation which may require filtering of file bytes
        as loaded into memory.
        
        :return: the number of bytes in the resulting memory block
        :rtype: int
        """

    def getAlign(self) -> int:
        """
        As ''Program Loading'' later in this part describes, loadable process segments must have
        congruent values for p_vaddr and p_offset, modulo the page size. This member
        gives the value to which the segments are aligned in memory and in the file. Values 0
        and 1 mean no alignment is required. Otherwise, p_align should be a positive, integral
        power of 2, and p_vaddr should equal p_offset, modulo p_align.
        
        :return: the segment alignment value
        :rtype: int
        """

    def getComment(self) -> str:
        """
        Get descriptive comment which includes type and description
        
        :return: descriptive comment
        :rtype: str
        """

    def getDescription(self) -> str:
        """
        Get header description
        
        :return: header description
        :rtype: str
        """

    def getElfHeader(self) -> ElfHeader:
        """
        Return ElfHeader associated with this program header
        
        :return: ElfHeader
        :rtype: ElfHeader
        """

    def getFileSize(self) -> int:
        """
        This member gives the number of bytes in the file image of the segment; it may be zero.
        
        :return: the number of bytes in the file image
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        This member gives flags relevant to the segment. Defined flag values appear below.
        
        :return: the segment flags
        :rtype: int
        """

    def getMemorySize(self) -> int:
        """
        Get the unadjusted memory size in bytes specified by this program header; it may be zero.
        
        :return: the unadjusted memory size in bytes specified by this program header
        :rtype: int
        """

    @typing.overload
    def getOffset(self) -> int:
        """
        This member gives the offset from the beginning of the file at which 
        the first byte of the segment resides.
        
        :return: the offset from the beginning of the file
        :rtype: int
        """

    @typing.overload
    def getOffset(self, virtualAddress: typing.Union[jpype.JLong, int]) -> int:
        """
        Compute the file offset associated with the specified loaded virtual address 
        defined by this PT_LOAD program header.  This can be useful when attempting to locate
        addresses defined by the PT_DYNAMIC section.
        
        :param jpype.JLong or int virtualAddress: a memory address which has already had the PRElink adjustment applied
        :return: computed file offset or -1 if virtual address not contained within this header
        :rtype: int
        
        .. seealso::
        
            | :obj:`ElfHeader.getProgramLoadHeaderContaining(long)`for obtaining PT_LOAD segment which contains
            virtualAddress
        """

    def getPhysicalAddress(self) -> int:
        """
        On systems for which physical addressing is relevant, this member is reserved for the
        segment's physical address. Because System V ignores physical addressing for application
        programs, this member has unspecified contents for executable files and shared objects.
        
        :return: the segment's physical address
        :rtype: int
        """

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the binary reader.
        
        :return: the binary reader
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getType(self) -> int:
        """
        This member tells what kind of segment this array element describes or how to interpret
        the array element's information. Type values and their meanings appear below.
        
        :return: the program header type
        :rtype: int
        """

    def getTypeAsString(self) -> str:
        """
        Get header type as string.  ElfProgramHeaderType name will be returned
        if know, otherwise a numeric name of the form "PT_0x12345678" will be returned.
        
        :return: header type as string
        :rtype: str
        """

    def getVirtualAddress(self) -> int:
        """
        This member gives the virtual address at which the first 
        byte of the segment resides in memory.
        
        :return: the virtual address
        :rtype: int
        """

    def isExecute(self) -> bool:
        """
        Returns true if this segment is executable when loaded
        
        :return: true if this segment is executable when loaded
        :rtype: bool
        """

    def isInvalidOffset(self) -> bool:
        """
        Return true if this program header's offset is invalid.
        
        :return: true if this program header's offset is invalid
        :rtype: bool
        """

    def isRead(self) -> bool:
        """
        Returns true if this segment is readable when loaded
        
        :return: true if this segment is readable when loaded
        :rtype: bool
        """

    def isWrite(self) -> bool:
        """
        Returns true if this segment is writable when loaded
        
        :return: true if this segment is writable when loaded
        :rtype: bool
        """

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def adjustedLoadSize(self) -> jpype.JLong:
        ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def virtualAddress(self) -> jpype.JLong:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def align(self) -> jpype.JLong:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @property
    def adjustedMemorySize(self) -> jpype.JLong:
        ...

    @property
    def typeAsString(self) -> java.lang.String:
        ...

    @property
    def memorySize(self) -> jpype.JLong:
        ...

    @property
    def fileSize(self) -> jpype.JLong:
        ...

    @property
    def physicalAddress(self) -> jpype.JLong:
        ...

    @property
    def elfHeader(self) -> ElfHeader:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def invalidOffset(self) -> jpype.JBoolean:
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...


class ElfProgramHeaderType(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    PT_NULL: typing.ClassVar[ElfProgramHeaderType]
    PT_LOAD: typing.ClassVar[ElfProgramHeaderType]
    PT_DYNAMIC: typing.ClassVar[ElfProgramHeaderType]
    PT_INTERP: typing.ClassVar[ElfProgramHeaderType]
    PT_NOTE: typing.ClassVar[ElfProgramHeaderType]
    PT_SHLIB: typing.ClassVar[ElfProgramHeaderType]
    PT_PHDR: typing.ClassVar[ElfProgramHeaderType]
    PT_TLS: typing.ClassVar[ElfProgramHeaderType]
    PT_GNU_EH_FRAME: typing.ClassVar[ElfProgramHeaderType]
    PT_GNU_STACK: typing.ClassVar[ElfProgramHeaderType]
    PT_GNU_RELRO: typing.ClassVar[ElfProgramHeaderType]
    value: typing.Final[jpype.JInt]
    name: typing.Final[java.lang.String]
    description: typing.Final[java.lang.String]

    def __init__(self, value: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def addDefaultTypes(programHeaderTypeMap: collections.abc.Mapping):
        ...

    @staticmethod
    def addProgramHeaderType(type: ElfProgramHeaderType, programHeaderTypeMap: collections.abc.Mapping):
        """
        Add the specified program header type to the specified map.
        
        :param ElfProgramHeaderType type: program header type
        :param collections.abc.Mapping programHeaderTypeMap: map of program header types
        :raises DuplicateNameException: if new type name already defined within
        the specified map
        """

    @staticmethod
    def getEnumDataType(is32bit: typing.Union[jpype.JBoolean, bool], typeSuffix: typing.Union[java.lang.String, str], dynamicTypeMap: collections.abc.Mapping) -> ghidra.program.model.data.EnumDataType:
        ...


class ElfRelocationTable(ElfFileSection):
    """
    A container class to hold ELF relocations.
    """

    class TableFormat(java.lang.Enum[ElfRelocationTable.TableFormat]):

        class_: typing.ClassVar[java.lang.Class]
        DEFAULT: typing.Final[ElfRelocationTable.TableFormat]
        ANDROID: typing.Final[ElfRelocationTable.TableFormat]
        RELR: typing.Final[ElfRelocationTable.TableFormat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ElfRelocationTable.TableFormat:
            ...

        @staticmethod
        def values() -> jpype.JArray[ElfRelocationTable.TableFormat]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ElfHeader, relocTableSection: ElfSectionHeader, fileOffset: typing.Union[jpype.JLong, int], addrOffset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int], entrySize: typing.Union[jpype.JLong, int], addendTypeReloc: typing.Union[jpype.JBoolean, bool], symbolTable: ElfSymbolTable, sectionToBeRelocated: ElfSectionHeader, format: ElfRelocationTable.TableFormat):
        """
        Construct an Elf Relocation Table
        
        :param ghidra.app.util.bin.BinaryReader reader: byte provider reader (reader is not retained and position is unaffected)
        :param ElfHeader header: elf header
        :param ElfSectionHeader relocTableSection: relocation table section header or null if associated with a dynamic table entry
        :param jpype.JLong or int fileOffset: relocation table file offset
        :param jpype.JLong or int addrOffset: memory address of relocation table (should already be adjusted for prelink)
        :param jpype.JLong or int length: length of relocation table in bytes
        :param jpype.JLong or int entrySize: size of each relocation entry in bytes
        :param jpype.JBoolean or bool addendTypeReloc: true if addend type relocation table
        :param ElfSymbolTable symbolTable: associated symbol table (may be null if not applicable)
        :param ElfSectionHeader sectionToBeRelocated: or null for dynamic relocation table
        :param ElfRelocationTable.TableFormat format: table format
        :raises IOException: if an IO or parse error occurs
        """

    def getAssociatedSymbolTable(self) -> ElfSymbolTable:
        """
        Returns the associated symbol table.
        A relocation object contains a symbol index.
        This index is into this symbol table.
        
        :return: the associated symbol table or null if not applicable to this reloc table
        :rtype: ElfSymbolTable
        """

    def getRelocationCount(self) -> int:
        """
        Get number of relocation entries contained within this table
        
        :return: relocation entry count
        :rtype: int
        """

    def getRelocations(self) -> jpype.JArray[ElfRelocation]:
        """
        Returns the relocations defined in this table.
        
        :return: the relocations defined in this table
        :rtype: jpype.JArray[ElfRelocation]
        """

    def getSectionToBeRelocated(self) -> ElfSectionHeader:
        """
        Returns the section where the relocations will be applied.
        For example, this method will return ".plt" for ".rel.plt"
        
        :return: the section where the relocations will be applied
        or null for dynamic relocation table not associated with 
        a section.
        :rtype: ElfSectionHeader
        """

    def getTableSectionHeader(self) -> ElfSectionHeader:
        """
        Get section header which corresponds to this table, or null
        if only associated with a dynamic table entry
        
        :return: relocation table section header or null
        :rtype: ElfSectionHeader
        """

    def hasAddendRelocations(self) -> bool:
        """
        
        
        :return: true if has addend relocations, otherwise addend extraction from
        relocation target may be required
        :rtype: bool
        """

    def isMissingRequiredSymbolTable(self) -> bool:
        """
        Determine if required symbol table is missing.  If so, relocations may not be processed.
        
        :return: true if required symbol table is missing, else false
        :rtype: bool
        """

    def isRelrTable(self) -> bool:
        ...

    @property
    def missingRequiredSymbolTable(self) -> jpype.JBoolean:
        ...

    @property
    def tableSectionHeader(self) -> ElfSectionHeader:
        ...

    @property
    def associatedSymbolTable(self) -> ElfSymbolTable:
        ...

    @property
    def relrTable(self) -> jpype.JBoolean:
        ...

    @property
    def relocationCount(self) -> jpype.JInt:
        ...

    @property
    def sectionToBeRelocated(self) -> ElfSectionHeader:
        ...

    @property
    def relocations(self) -> jpype.JArray[ElfRelocation]:
        ...


class ElfHeader(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the Executable and Linking Format (ELF)
    header and specification.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, errorConsumer: java.util.function.Consumer[java.lang.String]):
        """
        Construct ``ElfHeader`` from byte provider
        
        :param ghidra.app.util.bin.ByteProvider provider: byte provider
        :param java.util.function.Consumer[java.lang.String] errorConsumer: error consumer
        :raises ElfException: if header parse failed
        """

    def adjustAddressForPrelink(self, address: typing.Union[jpype.JLong, int]) -> int:
        """
        Adjust address offset for certain pre-linked binaries which do not adjust certain
        header fields (e.g., dynamic table address entries).  Standard GNU/Linux pre-linked 
        shared libraries have adjusted header entries and this method should have no effect.
        
        :param jpype.JLong or int address: unadjusted address offset
        :return: address with appropriate pre-link adjustment added
        :rtype: int
        """

    def e_ehsize(self) -> int:
        """
        This member holds the ELF header's size in bytes.
        
        :return: the ELF header's size in bytes
        :rtype: int
        """

    def e_entry(self) -> int:
        """
        This member gives the virtual address to which the system first transfers control, thus
        starting the process. If the file has no associated entry point, this member holds zero.
        
        :return: the virtual address to which the system first transfers control
        :rtype: int
        """

    def e_flags(self) -> int:
        """
        This member holds processor-specific flags associated with the file. Flag names take
        the form EF_machine_flag.
        
        :return: the processor-specific flags associated with the file
        :rtype: int
        
        .. seealso::
        
            | :obj:`ElfConstants`for flag definitions
        """

    def e_ident_abiversion(self) -> int:
        """
        This member identifies the target ABI version.
        
        :return: the target ABI version
        :rtype: int
        """

    def e_ident_osabi(self) -> int:
        """
        This member identifies the target operating system and ABI.
        
        :return: the target operating system and ABI
        :rtype: int
        """

    def e_machine(self) -> int:
        """
        This member's value specifies the required architecture for an individual file.
        
        :return: the required architecture for an individual file
        :rtype: int
        
        .. seealso::
        
            | :obj:`ElfConstants`for machine definitions
        """

    def e_phentsize(self) -> int:
        """
        This member holds the size in bytes of one entry in the file's program header table;
        all entries are the same size.
        
        :return: the size in bytes of one program header table entry
        :rtype: int
        """

    def e_phoff(self) -> int:
        """
        This member holds the program header table's file offset in bytes. If the file has no
        program header table, this member holds zero.
        
        :return: the program header table's file offset in bytes
        :rtype: int
        """

    def e_shentsize(self) -> int:
        """
        This member holds the section header's size in bytes. A section header is one entry in
        the section header table; all entries are the same size.
        
        :return: the section header's size in bytes
        :rtype: int
        """

    def e_shoff(self) -> int:
        """
        This member holds the section header table's file offset in bytes. If the file has no section
        header table, this member holds zero.
        
        :return: the section header table's file offset in bytes
        :rtype: int
        """

    def e_shstrndx(self) -> int:
        """
        This member holds the section header table index of the entry associated with the section
        name string table. If the file has no section name string table, this member holds
        the value SHN_UNDEF.
        
        :return: the section header table index of the entry associated with the section name string table
        :rtype: int
        """

    def e_type(self) -> int:
        """
        This member identifies the object file type; executable, shared object, etc.
        
        :return: the object file type
        :rtype: int
        """

    def e_version(self) -> int:
        """
        This member identifies the object file version,
        where "EV_NONE == Invalid Version" and "EV_CURRENT == Current Version"
        The value 1 signifies the original file format; extensions will 
        create new versions with higher numbers. 
        The value of EV_CURRENT, though given as 1 above, will change as
        necessary to reflect the current version number.
        
        :return: the object file version
        :rtype: int
        """

    def findImageBase(self) -> int:
        """
        Inspect the Elf image and determine the default image base prior 
        to any parse method being invoked (i.e., only the main Elf
        header structure has been parsed during initialization.
        The image base is the virtual address of the PT_LOAD program header
        with the smallest address or 0 if no program headers exist.  By default,
        the image base address should be treated as a addressable unit offset.
        
        :return: preferred image base
        :rtype: int
        """

    def getByteProvider(self) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns the byte provider
        
        :return: the byte provider
        :rtype: ghidra.app.util.bin.ByteProvider
        """

    def getDynamicLibraryNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns array of dynamic library names defined by DT_NEEDED
        
        :return: array of dynamic library names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getDynamicStringTable(self) -> ElfStringTable:
        """
        Returns the dynamic string table as defined in this ELF file.
        
        :return: the dynamic string table as defined in this ELF file
        :rtype: ElfStringTable
        """

    def getDynamicSymbolTable(self) -> ElfSymbolTable:
        """
        Returns the dynamic symbol table as defined in this ELF file.
        
        :return: the dynamic symbol table as defined in this ELF file
        :rtype: ElfSymbolTable
        """

    def getDynamicTable(self) -> ElfDynamicTable:
        """
        Returns the dynamic table defined by program header of type PT_DYNAMIC or the .dynamic program section.
        Or, null if one does not exist.
        
        :return: the dynamic table
        :rtype: ElfDynamicTable
        """

    def getDynamicType(self, type: typing.Union[jpype.JInt, int]) -> ElfDynamicType:
        ...

    def getEntryComponentOrdinal(self) -> int:
        """
        Get the Elf header structure component ordinal 
        corresponding to the e_entry element
        
        :return: e_entry component ordinal
        :rtype: int
        """

    def getFlags(self) -> str:
        """
        Returns a string representation of the numeric flags field.
        
        :return: elf flags field value
        :rtype: str
        """

    def getImageBase(self) -> int:
        """
        Returns the image base of this ELF. 
        The image base is the virtual address of the first PT_LOAD
        program header or 0 if no program headers. By default,
        the image base address should be treated as a addressable unit offset.s
        
        :return: the image base of this ELF
        :rtype: int
        """

    def getLoadAdapter(self) -> ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter:
        """
        Get the installed extension provider.  If the parse method has not yet been 
        invoked, the default adapter will be returned.
        
        :return: ELF load adapter
        :rtype: ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter
        """

    def getMachineName(self) -> str:
        """
        Returns a string name of the processor specified in this ELF header.
        For example, if "e_machine==EM_386", then it returns "80386".
        
        :return: a string name of the processor specified in this ELF header
        :rtype: str
        """

    def getPhoffComponentOrdinal(self) -> int:
        """
        Get the Elf header structure component ordinal 
        corresponding to the e_phoff element
        
        :return: e_phoff component ordinal
        :rtype: int
        """

    def getProgramHeaderAt(self, virtualAddr: typing.Union[jpype.JLong, int]) -> ElfProgramHeader:
        """
        Returns the program header at the specified address,
        or null if no program header exists at that address.
        
        :param jpype.JLong or int virtualAddr: the address of the requested program header
        :return: the program header with the specified address
        :rtype: ElfProgramHeader
        """

    def getProgramHeaderCount(self) -> int:
        """
        This member holds the number of entries in the program header table. Thus the product
        of e_phentsize and unsigned e_phnum gives the table's size in bytes. If original 
        e_phnum equals PNXNUM (0xffff) an attempt will be made to obtained the extended size
        from section[0].sh_info field.  If a file has no program header table, e_phnum holds 
        the value zero.
        
        :return: the number of entries in the program header table
        :rtype: int
        """

    def getProgramHeaderProgramHeader(self) -> ElfProgramHeader:
        """
        Returns the program header with type of PT_PHDR.
        Or, null if one does not exist.
        
        :return: the program header with type of PT_PHDR
        :rtype: ElfProgramHeader
        """

    def getProgramHeaderType(self, type: typing.Union[jpype.JInt, int]) -> ElfProgramHeaderType:
        ...

    @typing.overload
    def getProgramHeaders(self) -> jpype.JArray[ElfProgramHeader]:
        """
        Returns the program headers as defined in this ELF file.
        
        :return: the program headers as defined in this ELF file
        :rtype: jpype.JArray[ElfProgramHeader]
        """

    @typing.overload
    def getProgramHeaders(self, type: typing.Union[jpype.JInt, int]) -> jpype.JArray[ElfProgramHeader]:
        """
        Returns the program headers with the specified type.
        The array could be zero-length, but will not be null.
        
        :param jpype.JInt or int type: program header type
        :return: the program headers with the specified type
        :rtype: jpype.JArray[ElfProgramHeader]
        
        .. seealso::
        
            | :obj:`ElfProgramHeader`
        """

    def getProgramLoadHeaderContaining(self, virtualAddr: typing.Union[jpype.JLong, int]) -> ElfProgramHeader:
        """
        Returns the PT_LOAD program header which loads a range containing 
        the specified address, or null if not found.
        
        :param jpype.JLong or int virtualAddr: the address of the requested program header
        :return: the program header with the specified address
        :rtype: ElfProgramHeader
        """

    def getProgramLoadHeaderContainingFileOffset(self, offset: typing.Union[jpype.JLong, int]) -> ElfProgramHeader:
        """
        Returns the PT_LOAD program header which loads a range containing 
        the specified file offset, or null if not found.
        
        :param jpype.JLong or int offset: the file offset to be loaded
        :return: the program header with the specified file offset
        :rtype: ElfProgramHeader
        """

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the unconstrained binary reader (i.e., reads beyond EOF
        will return 0-bytes).
        
        :return: the binary reader
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getRelocationTable(self, relocSection: ElfSectionHeader) -> ElfRelocationTable:
        """
        Returns the relocation table associated to the specified section header,
        or null if one does not exist.
        
        :param ElfSectionHeader relocSection: section header corresponding to relocation table
        :return: the relocation table associated to the specified section header
        :rtype: ElfRelocationTable
        """

    def getRelocationTableAtOffset(self, fileOffset: typing.Union[jpype.JLong, int]) -> ElfRelocationTable:
        """
        Returns the relocation table located at the specified fileOffset,
        or null if one does not exist.
        
        :param jpype.JLong or int fileOffset: file offset corresponding to start of relocation table
        :return: the relocation table located at the specified fileOffset or null
        :rtype: ElfRelocationTable
        """

    def getRelocationTables(self) -> jpype.JArray[ElfRelocationTable]:
        """
        Returns the relocation tables as defined in this ELF file.
        
        :return: the relocation tables as defined in this ELF file
        :rtype: jpype.JArray[ElfRelocationTable]
        """

    def getSection(self, name: typing.Union[java.lang.String, str]) -> ElfSectionHeader:
        """
        Returns the section header with the specified name, or null
        if no section exists with that name.
        
        :param java.lang.String or str name: the name of the requested section
        :return: the section header with the specified name
        :rtype: ElfSectionHeader
        """

    def getSectionAt(self, address: typing.Union[jpype.JLong, int]) -> ElfSectionHeader:
        """
        Returns the section header at the specified address,
        or null if no section exists at that address.
        
        :param jpype.JLong or int address: the address of the requested section
        :return: the section header with the specified address
        :rtype: ElfSectionHeader
        """

    def getSectionHeaderContainingFileRange(self, fileOffset: typing.Union[jpype.JLong, int], fileRangeLength: typing.Union[jpype.JLong, int]) -> ElfSectionHeader:
        """
        Returns the section header which fully contains the specified file offset range.
        
        :param jpype.JLong or int fileOffset: file offset
        :param jpype.JLong or int fileRangeLength: length of file range in bytes
        :return: section or null if not found
        :rtype: ElfSectionHeader
        """

    def getSectionHeaderCount(self) -> int:
        """
        This member holds the number of entries in the section header table. Thus the product
        of e_shentsize and unsigned e_shnum gives the section header table's size in bytes. If a file
        has no section header table, e_shnum holds the value zero.
        
        :return: the number of entries in the section header table
        :rtype: int
        """

    def getSectionHeaderType(self, type: typing.Union[jpype.JInt, int]) -> ElfSectionHeaderType:
        ...

    def getSectionIndex(self, section: ElfSectionHeader) -> int:
        """
        Returns the index of the specified section.
        The index is the order in which the section was
        defined in the section header table.
        
        :param ElfSectionHeader section: the section header
        :return: the index of the specified section header
        :rtype: int
        """

    def getSectionLoadHeaderContaining(self, address: typing.Union[jpype.JLong, int]) -> ElfSectionHeader:
        """
        Returns the section header that loads/contains the specified address,
        or null if no section contains the address.
        
        :param jpype.JLong or int address: the address of the requested section
        :return: the section header that contains the address
        :rtype: ElfSectionHeader
        """

    @typing.overload
    def getSections(self) -> jpype.JArray[ElfSectionHeader]:
        """
        Returns the section headers as defined in this ELF file.
        
        :return: the section headers as defined in this ELF file
        :rtype: jpype.JArray[ElfSectionHeader]
        """

    @typing.overload
    def getSections(self, type: typing.Union[jpype.JInt, int]) -> jpype.JArray[ElfSectionHeader]:
        """
        Returns the section headers with the specified type.
        The array could be zero-length, but will not be null.
        
        :param jpype.JInt or int type: section type
        :return: the section headers with the specified type
        :rtype: jpype.JArray[ElfSectionHeader]
        
        .. seealso::
        
            | :obj:`ElfSectionHeader`
        """

    def getShoffComponentOrdinal(self) -> int:
        """
        Get the Elf header structure component ordinal 
        corresponding to the e_shoff element
        
        :return: e_shoff component ordinal
        :rtype: int
        """

    def getStringTable(self, section: ElfSectionHeader) -> ElfStringTable:
        """
        Returns the string table associated to the specified section header.
        Or, null if one does not exist.
        
        :param ElfSectionHeader section: section whose associated string table is requested
        :return: the string table associated to the specified section header
        :rtype: ElfStringTable
        """

    def getStringTables(self) -> jpype.JArray[ElfStringTable]:
        """
        Returns the string tables as defined in this ELF file.
        
        :return: the string tables as defined in this ELF file
        :rtype: jpype.JArray[ElfStringTable]
        """

    def getSymbolTable(self, symbolTableSection: ElfSectionHeader) -> ElfSymbolTable:
        """
        Returns the symbol table associated to the specified section header.
        Or, null if one does not exist.
        
        :param ElfSectionHeader symbolTableSection: symbol table section header
        :return: the symbol table associated to the specified section header
        :rtype: ElfSymbolTable
        """

    def getSymbolTables(self) -> jpype.JArray[ElfSymbolTable]:
        """
        Returns the symbol tables as defined in this ELF file.
        
        :return: the symbol tables as defined in this ELF file
        :rtype: jpype.JArray[ElfSymbolTable]
        """

    def is32Bit(self) -> bool:
        """
        Returns true if this ELF was created for a 32-bit processor.
        
        :return: true if this ELF was created for a 32-bit processor
        :rtype: bool
        """

    def is64Bit(self) -> bool:
        """
        Returns true if this ELF was created for a 64-bit processor.
        
        :return: true if this ELF was created for a 64-bit processor
        :rtype: bool
        """

    def isBigEndian(self) -> bool:
        """
        Returns true if this ELF was created for a big endian processor.
        
        :return: true if this ELF was created for a big endian processor
        :rtype: bool
        """

    def isExecutable(self) -> bool:
        """
        Returns true if this is an executable file.
         
        
        e_type == NewElfHeaderConstants.ET_EXEC
        
        :return: true if this is a executable file
        :rtype: bool
        """

    def isLittleEndian(self) -> bool:
        """
        Returns true if this ELF was created for a little endian processor.
        
        :return: true if this ELF was created for a little endian processor
        :rtype: bool
        """

    def isPreLinked(self) -> bool:
        """
        Determine if the image has been pre-linked.
        NOTE: Currently has very limited support.  Certain pre-link
        cases can not be detected until after a full parse has been 
        performed.
        
        :return: true if image has been pre-linked
        :rtype: bool
        """

    def isRelocatable(self) -> bool:
        """
        Returns true if this is a relocatable file.
         
        
        e_type == NewElfHeaderConstants.ET_REL
        
        :return: true if this is a relocatable file
        :rtype: bool
        """

    def isSectionLoaded(self, section: ElfSectionHeader) -> bool:
        ...

    def isSharedObject(self) -> bool:
        """
        Returns true if this is a shared object file.
         
        
        e_type == NewElfHeaderConstants.ET_DYN
        
        :return: true if this is a shared object file
        :rtype: bool
        """

    def parse(self):
        """
        Perform parse of all supported headers.
        
        :raises IOException: if file IO error occurs
        """

    def unadjustAddressForPrelink(self, address: typing.Union[jpype.JLong, int]) -> int:
        """
        Unadjust address offset for certain pre-linked binaries which do not adjust certain
        header fields (e.g., dynamic table address entries).  This may be needed when updating
        a header address field which requires pre-link adjustment.
        
        :param jpype.JLong or int address: prelink-adjusted address offset
        :return: address with appropriate pre-link adjustment subtracted
        :rtype: int
        """

    @property
    def sectionHeaderType(self) -> ElfSectionHeaderType:
        ...

    @property
    def dynamicSymbolTable(self) -> ElfSymbolTable:
        ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def byteProvider(self) -> ghidra.app.util.bin.ByteProvider:
        ...

    @property
    def flags(self) -> java.lang.String:
        ...

    @property
    def dynamicStringTable(self) -> ElfStringTable:
        ...

    @property
    def section(self) -> ElfSectionHeader:
        ...

    @property
    def dynamicTable(self) -> ElfDynamicTable:
        ...

    @property
    def relocatable(self) -> jpype.JBoolean:
        ...

    @property
    def sectionLoaded(self) -> jpype.JBoolean:
        ...

    @property
    def dynamicType(self) -> ElfDynamicType:
        ...

    @property
    def programLoadHeaderContainingFileOffset(self) -> ElfProgramHeader:
        ...

    @property
    def machineName(self) -> java.lang.String:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def programLoadHeaderContaining(self) -> ElfProgramHeader:
        ...

    @property
    def imageBase(self) -> jpype.JLong:
        ...

    @property
    def programHeaderType(self) -> ElfProgramHeaderType:
        ...

    @property
    def loadAdapter(self) -> ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter:
        ...

    @property
    def sectionLoadHeaderContaining(self) -> ElfSectionHeader:
        ...

    @property
    def symbolTables(self) -> jpype.JArray[ElfSymbolTable]:
        ...

    @property
    def sectionIndex(self) -> jpype.JInt:
        ...

    @property
    def entryComponentOrdinal(self) -> jpype.JInt:
        ...

    @property
    def symbolTable(self) -> ElfSymbolTable:
        ...

    @property
    def programHeaderCount(self) -> jpype.JInt:
        ...

    @property
    def stringTables(self) -> jpype.JArray[ElfStringTable]:
        ...

    @property
    def relocationTableAtOffset(self) -> ElfRelocationTable:
        ...

    @property
    def littleEndian(self) -> jpype.JBoolean:
        ...

    @property
    def sharedObject(self) -> jpype.JBoolean:
        ...

    @property
    def preLinked(self) -> jpype.JBoolean:
        ...

    @property
    def stringTable(self) -> ElfStringTable:
        ...

    @property
    def relocationTables(self) -> jpype.JArray[ElfRelocationTable]:
        ...

    @property
    def programHeaders(self) -> jpype.JArray[ElfProgramHeader]:
        ...

    @property
    def phoffComponentOrdinal(self) -> jpype.JInt:
        ...

    @property
    def dynamicLibraryNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def sectionHeaderCount(self) -> jpype.JInt:
        ...

    @property
    def executable(self) -> jpype.JBoolean:
        ...

    @property
    def sections(self) -> jpype.JArray[ElfSectionHeader]:
        ...

    @property
    def sectionAt(self) -> ElfSectionHeader:
        ...

    @property
    def programHeaderProgramHeader(self) -> ElfProgramHeader:
        ...

    @property
    def relocationTable(self) -> ElfRelocationTable:
        ...

    @property
    def shoffComponentOrdinal(self) -> jpype.JInt:
        ...

    @property
    def programHeaderAt(self) -> ElfProgramHeader:
        ...


class ElfSectionHeader(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.MemoryLoadable):
    """
    A class to represent the Elf32_Shdr data structure.
     
    
     
    typedef  int32_t  Elf32_Sword;
    typedef uint32_t  Elf32_Word;
    typedef uint32_t  Elf32_Addr;
     
    typedef struct {
        Elf32_Word    sh_name;       //Section name (string tbl index)
        Elf32_Word    sh_type;       //Section type
        Elf32_Word    sh_flags;      //Section flags
        Elf32_Addr    sh_addr;       //Section virtual addr at execution
        Elf32_Off     sh_offset;     //Section file offset
        Elf32_Word    sh_size;       //Section size in bytes
        Elf32_Word    sh_link;       //Link to another section
        Elf32_Word    sh_info;       //Additional section information
        Elf32_Word    sh_addralign;  //Section alignment
        Elf32_Word    sh_entsize;    //Entry size if section holds table *
    } Elf32_Shdr;
     
    typedef  uint32_t  Elf64_Word;
    typedef  uint64_t  Elf64_Xword;
    typedef  uint64_t  Elf64_Addr;
    typedef  uint64_t  Elf64_Off;
     
    typedef struct {
        Elf64_Word    sh_name;       //Section name (string tbl index)
        Elf64_Word    sh_type;       //Section type
        Elf64_Xword   sh_flags;      //Section flags
        Elf64_Addr    sh_addr;       //Section virtual addr at execution
        Elf64_Off     sh_offset;     //Section file offset
        Elf64_Xword   sh_size;       //Section size in bytes
        Elf64_Word    sh_link;       //Link to another section
        Elf64_Word    sh_info;       //Additional section information
        Elf64_Xword   sh_addralign;  //Section alignment
        Elf64_Xword   sh_entsize;    //Entry size if section holds table *
    } Elf64_Shdr;
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ElfHeader):
        """
        Construct :obj:`ElfSectionHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: dedicated reader instance positioned to the start of the program header data.
        (the reader supplied will be retained and altered).
        :param ElfHeader header: ELF header
        :raises IOException: if an IO error occurs during parse
        """

    def getAddress(self) -> int:
        """
        If the section will appear in the memory image of a process, this 
        member gives the address at which the section's first byte 
        should reside. Otherwise, the member contains 0.
        
        :return: the address of the section in memory
        :rtype: int
        """

    def getAddressAlignment(self) -> int:
        """
        Some sections have address alignment constraints. For example, if a section holds a
        doubleword, the system must ensure doubleword alignment for the entire section.
        That is, the value of sh_addr must be congruent to 0, modulo the value of
        sh_addralign. Currently, only 0 and positive integral powers of two are allowed.
        Values 0 and 1 mean the section has no alignment constraints.
        
        :return: the section address alignment constraints
        :rtype: int
        """

    def getElfHeader(self) -> ElfHeader:
        """
        Return ElfHeader associated with this section
        
        :return: ElfHeader
        :rtype: ElfHeader
        """

    def getEntrySize(self) -> int:
        """
        Some sections hold a table of fixed-size entries, such as a symbol table. For such a section,
        this member gives the size in bytes of each entry. The member contains 0 if the
        section does not hold a table of fixed-size entries.
        
        :return: the section entry size
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        Sections support 1-bit flags that describe miscellaneous attributes. Flag definitions
        appear aove.
        
        :return: the section flags
        :rtype: int
        """

    def getInfo(self) -> int:
        """
        This member holds extra information, whose interpretation 
        depends on the section type.
          
        If sh_type is SHT_REL or SHT_RELA, then sh_info holds 
        the section header index of the
        section to which the relocation applies.
         
        If sh_type is SHT_SYMTAB or SHT_DYNSYM, then sh_info
        holds one greater than the symbol table index of the last
        local symbol (binding STB_LOCAL).
        
        :return: the section header info
        :rtype: int
        """

    def getLink(self) -> int:
        """
        This member holds extra information, whose interpretation 
        depends on the section type.
         
        If sh_type is SHT_SYMTAB, SHT_DYNSYM, or SHT_DYNAMIC, 
        then sh_link holds the section header table index of
        its associated string table.
         
        If sh_type is SHT_REL, SHT_RELA, or SHT_HASH
        sh_link holds the section header index of the 
        associated symbol table.
        
        :return: the section header link
        :rtype: int
        """

    def getLogicalSize(self) -> int:
        """
        Returns the logical size of this section, possibly affected by compression.
        
        :return: logical size of this section, see :meth:`getSize() <.getSize>`
        :rtype: int
        """

    def getName(self) -> int:
        """
        An index into the section header string table section, 
        giving the location of a null-terminated string which is the name of this section.
        
        :return: the index of the section name
        :rtype: int
        """

    def getNameAsString(self) -> str:
        """
        Returns the actual string name for this section. The section only
        stores an byte index into the string table where
        the name string is located.
        
        :return: the actual string name for this section
        :rtype: str
        """

    def getOffset(self) -> int:
        """
        The byte offset from the beginning of the file to the first
        byte in the section.
        One section type, SHT_NOBITS described below, occupies no
        space in the file, and its sh_offset member locates the conceptual placement in the
        file.
        
        :return: byte offset from the beginning of the file to the first byte in the section
        :rtype: int
        """

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the binary reader.
        
        :return: the binary reader
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getSize(self) -> int:
        """
        This member gives the section's size in bytes. Unless the section type is
        SHT_NOBITS, the section occupies sh_size bytes in the file. A section of type
        SHT_NOBITS may have a non-zero size, but it occupies no space in the file.
        
        :return: the section's size in bytes
        :rtype: int
        """

    def getType(self) -> int:
        """
        This member categorizes the section's contents and semantics.
        
        :return: the section's contents and semantics
        :rtype: int
        """

    def getTypeAsString(self) -> str:
        """
        Get header type as string.  ElfSectionHeaderType name will be returned
        if know, otherwise a numeric name of the form "SHT_0x12345678" will be returned.
        
        :return: header type as string
        :rtype: str
        """

    def isAlloc(self) -> bool:
        """
        Returns true if this section is allocated (e.g., SHF_ALLOC is set)
        
        :return: true if this section is allocated.
        :rtype: bool
        """

    def isCompressed(self) -> bool:
        """
        Returns true if this section is compressed in a supported manner.  This does NOT include
        sections that carry compressed data, such as ".zdebuginfo" type sections.
        
        :return: true if the section was compressed and needs to be decompressed, false if normal
        section
        :rtype: bool
        """

    def isExecutable(self) -> bool:
        """
        Returns true if this section is executable.
        
        :return: true if this section is executable.
        :rtype: bool
        """

    def isInvalidOffset(self) -> bool:
        """
        Returns true if this section header's offset is invalid.
        
        :return: true if this section header's offset is invalid
        :rtype: bool
        """

    def isWritable(self) -> bool:
        """
        Returns true if this section is writable.
        
        :return: true if this section is writable.
        :rtype: bool
        """

    def setAddress(self, addr: typing.Union[jpype.JLong, int]):
        """
        Sets the start address of this section.
        
        :param jpype.JLong or int addr: the new start address of this section
        """

    @property
    def address(self) -> jpype.JLong:
        ...

    @address.setter
    def address(self, value: jpype.JLong):
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def link(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JLong:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def executable(self) -> jpype.JBoolean:
        ...

    @property
    def writable(self) -> jpype.JBoolean:
        ...

    @property
    def typeAsString(self) -> java.lang.String:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def logicalSize(self) -> jpype.JLong:
        ...

    @property
    def addressAlignment(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> jpype.JInt:
        ...

    @property
    def elfHeader(self) -> ElfHeader:
        ...

    @property
    def compressed(self) -> jpype.JBoolean:
        ...

    @property
    def nameAsString(self) -> java.lang.String:
        ...

    @property
    def invalidOffset(self) -> jpype.JBoolean:
        ...

    @property
    def alloc(self) -> jpype.JBoolean:
        ...

    @property
    def info(self) -> jpype.JInt:
        ...

    @property
    def entrySize(self) -> jpype.JLong:
        ...



__all__ = ["AndroidElfRelocationData", "ElfRelocation", "ElfCompressedSectionHeader", "ElfDynamicTable", "ElfSymbolTable", "ElfConstants", "ElfStringTable", "ElfSectionHeaderConstants", "ElfDefaultGotPltMarkup", "GnuVerdef", "ElfException", "ElfFileSection", "GnuVerdaux", "GnuVernaux", "AndroidElfRelocationOffset", "ElfDynamicType", "ElfRelrRelocationTableDataType", "GnuConstants", "ElfLoadHelper", "GnuVerneed", "ElfSectionHeaderType", "AndroidElfRelocationTableDataType", "ElfProgramHeaderConstants", "ElfSymbol", "ElfDynamic", "AndroidElfRelocationGroup", "ElfProgramHeader", "ElfProgramHeaderType", "ElfRelocationTable", "ElfHeader", "ElfSectionHeader"]
