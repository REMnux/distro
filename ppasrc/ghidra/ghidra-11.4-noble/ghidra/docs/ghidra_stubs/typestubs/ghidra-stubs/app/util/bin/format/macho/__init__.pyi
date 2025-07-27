from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.commands
import ghidra.program.model.lang
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class SectionNames(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    TEXT: typing.Final = "__text"
    """
    the real text part of the text section no headers, and no padding
    """

    TEXT_CSTRING: typing.Final = "__cstring"
    """
    Constant null-terminated C strings
    """

    TEXT_PICSYMBOL_STUB: typing.Final = "__picsymbol_stub"
    """
    Position-independent indirect symbol stubs
    """

    TEXT_SYMBOL_STUB: typing.Final = "__symbol_stub"
    """
    Indirect symbol stubs
    """

    TEXT_CONST: typing.Final = "__const"
    """
    Initialized constant variables
    """

    TEXT_LITERAL4: typing.Final = "__literal4"
    """
    4-byte literal values. single-precision floating pointer constants
    """

    TEXT_LITERAL8: typing.Final = "__literal8"
    """
    8-byte literal values. double-precision floating pointer constants
    """

    TEXT_FVMLIB_INIT0: typing.Final = "__fvmlib_init0"
    """
    the fvmlib initialization section
    """

    TEXT_FVMLIB_INIT1: typing.Final = "__fvmlib_init1"
    """
    the section following the fvmlib initialization section
    """

    DATA: typing.Final = "__data"
    """
    the real initialized data section no padding, no bss overlap
    """

    DATA_LA_SYMBOL_PTR: typing.Final = "__la_symbol_ptr"
    """
    Lazy symbol pointers, which are indirect references to imported functions
    """

    DATA_NL_SYMBOL_PTR: typing.Final = "__nl_symbol_ptr"
    """
    Non-lazy symbol pointers, which are indirect references to imported functions
    """

    DATA_DYLD: typing.Final = "__dyld"
    """
    Place holder section used by dynamic linker
    """

    DATA_CONST: typing.Final = "__const"
    """
    Initialized relocatable constant variables
    """

    DATA_MOD_INIT_FUNC: typing.Final = "__mod_init_func"
    """
    Module initialization functions. C++ places static constructors here.
    """

    DATA_MOD_TERM_FUNC: typing.Final = "__mod_term_func"
    """
    Module termination functions
    """

    SECT_BSS: typing.Final = "__bss"
    """
    the real uninitialized data section no padding
    """

    SECT_COMMON: typing.Final = "__common"
    """
    the section common symbols are allocated in by the link editor
    """

    SECT_GOT: typing.Final = "__got"
    """
    global offset table section
    """

    OBJC_SYMBOLS: typing.Final = "__symbol_table"
    """
    symbol table
    """

    OBJC_MODULES: typing.Final = "__module_info"
    """
    module information
    """

    OBJC_STRINGS: typing.Final = "__selector_strs"
    """
    string table
    """

    OBJC_REFS: typing.Final = "__selector_refs"
    """
    string table
    """

    IMPORT_JUMP_TABLE: typing.Final = "__jump_table"
    """
    Stubs for calls to functions in a dynamic library
    """

    IMPORT_POINTERS: typing.Final = "__pointers"
    """
    Non-lazy symbol pointers
    """

    PROGRAM_VARS: typing.Final = "__program_vars"
    """
    Section dedicated to holding global program variables
    """

    CHAIN_STARTS: typing.Final = "__chain_starts"
    """
    Section containing dyld_chained_starts_offsets structure
    """

    THREAD_STARTS: typing.Final = "__thread_starts"
    """
    Section containing chained fixups
    """


    def __init__(self):
        ...


class MachConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MH_MAGIC: typing.Final = -17958194
    """
    PowerPC 32-bit Magic Number
    """

    MH_MAGIC_64: typing.Final = -17958193
    """
    PowerPC 64-bit Magic Number
    """

    MH_CIGAM: typing.Final = -822415874
    """
    Intel x86 32-bit Magic Number
    """

    MH_CIGAM_64: typing.Final = -805638658
    """
    Intel x86 64-bit Magic Number
    """

    NAME_LENGTH: typing.Final = 16
    DATA_TYPE_CATEGORY: typing.Final = "/MachO"

    def __init__(self):
        ...

    @staticmethod
    def isMagic(magic: typing.Union[jpype.JInt, int]) -> bool:
        """
        Convenience method for matching the magic number
        
        :param jpype.JInt or int magic: the magic number read from the file
        :return: true if the magic number matches
        :rtype: bool
        """


class ObsoleteException(MachException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CpuTypes(java.lang.Object):
    """
    
    
    
    .. seealso::
    
        | `osfmk/mach/machiine.h <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/machine.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    CPU_ARCH_MASK: typing.Final = -16777216
    """
    mask for architecture bits
    """

    CPU_ARCH_ABI64: typing.Final = 16777216
    """
    64 bit ABI
    """

    CPU_ARCH_ABI64_32: typing.Final = 33554432
    """
    ABI for 64-bit hardware with 32-bit types; LP32
    """

    CPU_TYPE_ANY: typing.Final = -1
    CPU_TYPE_VAX: typing.Final = 1
    CPU_TYPE_MC680x0: typing.Final = 6
    CPU_TYPE_X86: typing.Final = 7
    CPU_TYPE_I386: typing.Final = 7
    CPU_TYPE_MC98000: typing.Final = 10
    CPU_TYPE_HPPA: typing.Final = 11
    CPU_TYPE_ARM: typing.Final = 12
    CPU_TYPE_MC88000: typing.Final = 13
    CPU_TYPE_SPARC: typing.Final = 14
    CPU_TYPE_I860: typing.Final = 15
    CPU_TYPE_POWERPC: typing.Final = 18
    CPU_TYPE_POWERPC64: typing.Final = 16777234
    CPU_TYPE_X86_64: typing.Final = 16777223
    CPU_TYPE_ARM_64: typing.Final = 16777228
    CPU_TYPE_ARM64_32: typing.Final = 33554444

    def __init__(self):
        ...

    @staticmethod
    def getMagicString(cpuType: typing.Union[jpype.JInt, int], cpuSubtype: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    def getProcessor(cpuType: typing.Union[jpype.JInt, int], cpuSubtype: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.Processor:
        """
        Returns the processor name of the given CPU type value.
        
        :param jpype.JInt or int cpuType: the CPU type value
        :param jpype.JInt or int cpuSubtype: the CPU subtype value
        :return: the processor name of the given CPU type value
        :rtype: ghidra.program.model.lang.Processor
        """

    @staticmethod
    def getProcessorBitSize(cpuType: typing.Union[jpype.JInt, int]) -> int:
        ...


class MachException(java.lang.Exception):
    """
    An exception class to handle encountering
    invalid Mach-O Headers.
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


class MachHeaderFileTypes(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MH_OBJECT: typing.Final = 1
    """
    relocatable object file
    """

    MH_EXECUTE: typing.Final = 2
    """
    demand paged executable file
    """

    MH_FVMLIB: typing.Final = 3
    """
    fixed VM shared library file
    """

    MH_CORE: typing.Final = 4
    """
    core file
    """

    MH_PRELOAD: typing.Final = 5
    """
    preloaded executable file
    """

    MH_DYLIB: typing.Final = 6
    """
    dynamically bound shared library
    """

    MH_DYLINKER: typing.Final = 7
    """
    dynamic link editor
    """

    MH_BUNDLE: typing.Final = 8
    """
    dynamically bound bundle file
    """

    MH_DYLIB_STUB: typing.Final = 9
    """
    shared library stub for static linking only, no section contents
    """

    MH_DSYM: typing.Final = 10
    """
    linking only, no section contents, companion file with only debug sections
    """

    MH_KEXT_BUNDLE: typing.Final = 11
    """
    x86_64 kexts
    """

    MH_FILESET: typing.Final = 12
    """
    kernel cache fileset
    """


    def __init__(self):
        ...

    @staticmethod
    def getFileTypeDescription(fileType: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    def getFileTypeName(fileType: typing.Union[jpype.JInt, int]) -> str:
        ...


class SectionAttributes(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SECTION_ATTRIBUTES_MASK: typing.Final = -256
    """
    24 section attributes
    """

    SECTION_ATTRIBUTES_USR: typing.Final = -16777216
    """
    Attribute: User setable attributes
    """

    SECTION_ATTRIBUTES_SYS: typing.Final = 16776960
    """
    Attribute: system setable attributes
    """

    S_ATTR_PURE_INSTRUCTIONS: typing.Final = -2147483648
    """
    Attribute: section contains only true machine instructions
    """

    S_ATTR_NO_TOC: typing.Final = 1073741824
    """
    Attribute: section contains coalesced symbols that are not to be in a ranlib table of contents
    """

    S_ATTR_STRIP_STATIC_SYMS: typing.Final = 536870912
    """
    Attribute: ok to strip static symbols in this section in files with the MH_DYLDLINK flag
    """

    S_ATTR_NO_DEAD_STRIP: typing.Final = 268435456
    """
    Attribute: section must not be dead-stripped. (see "linking" in xcode2 user guide)
    """

    S_ATTR_LIVE_SUPPORT: typing.Final = 134217728
    """
    Attribute: section must
    """

    S_ATTR_SELF_MODIFYING_CODE: typing.Final = 67108864
    """
    Attribute: Used with i386 code stubs written on by dyld
    """

    S_ATTR_SOME_INSTRUCTIONS: typing.Final = 1024
    """
    Attribute: section contains some machine instructions
    """

    S_ATTR_EXT_RELOC: typing.Final = 512
    """
    Attribute: section has external relocation entries
    """

    S_ATTR_LOC_RELOC: typing.Final = 256
    """
    Attribute: section has local relocation entries
    """


    def __init__(self):
        ...

    @staticmethod
    def getAttributeNames(attributes: typing.Union[jpype.JInt, int]) -> java.util.List[java.lang.String]:
        ...


class MachHeader(ghidra.app.util.bin.StructConverter):
    """
    Represents a mach_header structure.
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/loader.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        """
        Creates a new :obj:`MachHeader`.  Assumes the MachHeader starts at index 0 in the 
        ByteProvider.
        
        :param ghidra.app.util.bin.ByteProvider provider: the ByteProvider
        :raises IOException: if an I/O error occurs while reading from the ByteProvider
        :raises MachException: if an invalid MachHeader is detected
        """

    @typing.overload
    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, machHeaderStartIndexInProvider: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`MachHeader`. Assumes the MachHeader starts at index 
        *machHeaderStartIndexInProvider* in the ByteProvider.
        
        :param ghidra.app.util.bin.ByteProvider provider: the ByteProvider
        :param jpype.JLong or int machHeaderStartIndexInProvider: the index into the ByteProvider where the MachHeader 
        begins
        :raises IOException: if an I/O error occurs while reading from the ByteProvider
        :raises MachException: if an invalid MachHeader is detected
        """

    @typing.overload
    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, machHeaderStartIndexInProvider: typing.Union[jpype.JLong, int], isRemainingMachoRelativeToStartIndex: typing.Union[jpype.JBoolean, bool]):
        """
        Creatse a new :obj:`MachHeader`.  Assumes the MachHeader starts at index 
        *machHeaderStartIndexInProvider* in the ByteProvider.
        
        :param ghidra.app.util.bin.ByteProvider provider: the ByteProvider
        :param jpype.JLong or int machHeaderStartIndexInProvider: the index into the ByteProvider where the MachHeader 
        begins.
        :param jpype.JBoolean or bool isRemainingMachoRelativeToStartIndex: true if the rest of the macho uses relative 
        indexin (this is common in UBI and kernel cache files); otherwise, false if the rest of the
        file uses absolute indexing from 0 (this is common in DYLD cache files)
        :raises IOException: if an I/O error occurs while reading from the ByteProvider
        :raises MachException: if an invalid MachHeader is detected
        """

    @staticmethod
    def create(magic: typing.Union[jpype.JInt, int], cpuType: typing.Union[jpype.JInt, int], cpuSubType: typing.Union[jpype.JInt, int], fileType: typing.Union[jpype.JInt, int], nCmds: typing.Union[jpype.JInt, int], sizeOfCmds: typing.Union[jpype.JInt, int], flags: typing.Union[jpype.JInt, int], reserved: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Creates a new Mach Header byte array
        
        :param jpype.JInt or int magic: The magic
        :param jpype.JInt or int cpuType: The cpu type
        :param jpype.JInt or int cpuSubType: The cpu subtype
        :param jpype.JInt or int fileType: The file type
        :param jpype.JInt or int nCmds: The number of commands
        :param jpype.JInt or int sizeOfCmds: The size of the commands
        :param jpype.JInt or int flags: The flags
        :param jpype.JInt or int reserved: A reserved value (ignored for 32-bit magic)
        :return: The new header in byte array form
        :rtype: jpype.JArray[jpype.JByte]
        :raises MachException: if an invalid magic value was passed in (see :obj:`MachConstants`)
        """

    def getAddressSize(self) -> int:
        ...

    def getAllSections(self) -> java.util.List[Section]:
        ...

    def getAllSegments(self) -> java.util.List[ghidra.app.util.bin.format.macho.commands.SegmentCommand]:
        ...

    def getCpuSubType(self) -> int:
        ...

    def getCpuType(self) -> int:
        ...

    def getDescription(self) -> str:
        ...

    def getFileType(self) -> int:
        ...

    def getFirstLoadCommand(self, classType: java.lang.Class[T]) -> T:
        ...

    def getFlags(self) -> int:
        ...

    def getImageBase(self) -> int:
        ...

    @typing.overload
    def getLoadCommands(self) -> java.util.List[ghidra.app.util.bin.format.macho.commands.LoadCommand]:
        ...

    @typing.overload
    def getLoadCommands(self, classType: java.lang.Class[T]) -> java.util.List[T]:
        ...

    def getMagic(self) -> int:
        ...

    def getNumberOfCommands(self) -> int:
        ...

    def getReserved(self) -> int:
        ...

    def getSection(self, segmentName: typing.Union[java.lang.String, str], sectionName: typing.Union[java.lang.String, str]) -> Section:
        ...

    def getSegment(self, segmentName: typing.Union[java.lang.String, str]) -> ghidra.app.util.bin.format.macho.commands.SegmentCommand:
        ...

    def getSize(self) -> int:
        """
        Gets the size of this :obj:`MachHeader` in bytes
        
        :return: The size of this :obj:`MachHeader` in bytes
        :rtype: int
        """

    def getSizeOfCommands(self) -> int:
        ...

    def getStartIndex(self) -> int:
        """
        Returns the start index that should be used for calculating offsets.
        This will be 0 for things such as the dyld shared cache where offsets are
        based off the beginning of the file.
        
        :return: the start index that should be used for calculating offsets
        :rtype: int
        """

    def getStartIndexInProvider(self) -> int:
        """
        Returns the offset of the MachHeader in the ByteProvider
        
        :return: the offset of the MachHeader in the ByteProvider
        :rtype: int
        """

    def is32bit(self) -> bool:
        ...

    def isLittleEndian(self) -> bool:
        ...

    @staticmethod
    def isMachHeader(provider: ghidra.app.util.bin.ByteProvider) -> bool:
        """
        Returns true if the specified ByteProvider starts with a Mach header magic signature.
        
        :param ghidra.app.util.bin.ByteProvider provider: :obj:`ByteProvider` to check
        :return: boolean true if byte provider starts with a MachHeader
        :rtype: bool
        """

    @typing.overload
    def parse(self) -> MachHeader:
        """
        Parses this :obj:`MachHeader`'s :obj:`load commands <LoadCommand>`
        
        :return: This :obj:`MachHeader`, for convenience
        :rtype: MachHeader
        :raises IOException: If there was an IO-related error
        :raises MachException: if the load command is invalid
        """

    @typing.overload
    def parse(self, splitDyldCache: ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache) -> MachHeader:
        """
        Parses this :obj:`MachHeader`'s :obj:`load commands <LoadCommand>`
        
        :param ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache splitDyldCache: The :obj:`SplitDyldCache` that this header resides in.  Could be null
        if a split DYLD cache is not being used.
        :return: This :obj:`MachHeader`, for convenience
        :rtype: MachHeader
        :raises IOException: If there was an IO-related error
        :raises MachException: if the load command is invalid
        """

    def parseAndCheck(self, loadCommandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        Parses only this :obj:`MachHeader`'s :obj:`LoadCommand`s to check to see if one of the
        given type exists
        
        :param jpype.JInt or int loadCommandType: The type of :obj:`LoadCommand` to check for
        :return: True if this :obj:`MachHeader` contains the given :obj:`LoadCommand` type
        :rtype: bool
        :raises IOException: If there was an IO-related error
        
        .. seealso::
        
            | :obj:`LoadCommandTypes`
        """

    def parseReexports(self) -> java.util.List[ghidra.app.util.bin.format.macho.commands.DynamicLibraryCommand]:
        """
        Parses only this :obj:`MachHeader`'s :obj:`reexport load commands <DynamicLibraryCommand>`
        
        :return: A :obj:`List` of this :obj:`MachHeader`'s 
        :obj:`reexport load commands <DynamicLibraryCommand>`
        :rtype: java.util.List[ghidra.app.util.bin.format.macho.commands.DynamicLibraryCommand]
        :raises IOException: If there was an IO-related error
        """

    def parseSegments(self) -> java.util.List[ghidra.app.util.bin.format.macho.commands.SegmentCommand]:
        """
        Parses only this :obj:`MachHeader`'s :obj:`segments <SegmentCommand>`
        
        :return: A :obj:`List` of this :obj:`MachHeader`'s :obj:`segments <SegmentCommand>`
        :rtype: java.util.List[ghidra.app.util.bin.format.macho.commands.SegmentCommand]
        :raises IOException: If there was an IO-related error
        """

    @property
    def magic(self) -> jpype.JInt:
        ...

    @property
    def sizeOfCommands(self) -> jpype.JInt:
        ...

    @property
    def cpuType(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def cpuSubType(self) -> jpype.JInt:
        ...

    @property
    def littleEndian(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def allSegments(self) -> java.util.List[ghidra.app.util.bin.format.macho.commands.SegmentCommand]:
        ...

    @property
    def firstLoadCommand(self) -> T:
        ...

    @property
    def numberOfCommands(self) -> jpype.JInt:
        ...

    @property
    def startIndex(self) -> jpype.JLong:
        ...

    @property
    def allSections(self) -> java.util.List[Section]:
        ...

    @property
    def addressSize(self) -> jpype.JInt:
        ...

    @property
    def imageBase(self) -> jpype.JLong:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def loadCommands(self) -> java.util.List[ghidra.app.util.bin.format.macho.commands.LoadCommand]:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def segment(self) -> ghidra.app.util.bin.format.macho.commands.SegmentCommand:
        ...

    @property
    def fileType(self) -> jpype.JInt:
        ...

    @property
    def startIndexInProvider(self) -> jpype.JLong:
        ...


class MachHeaderFlags(java.lang.Object):
    """
    Constants for the flags field of the mach_header
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/loader.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    MH_NOUNDEFS: typing.Final = 1
    """
    the object file has no undefined references
    """

    MH_INCRLINK: typing.Final = 2
    """
    the object file is the output of an incremental link against a base file and
    can't be link edited again.
    """

    MH_DYLDLINK: typing.Final = 4
    """
    the object file is input for the dynamic linker and can't be staticly link
    edited again
    """

    MH_BINDATLOAD: typing.Final = 8
    """
    the object file's undefined references are bound by the dynamic linker when
    loaded
    """

    MH_PREBOUND: typing.Final = 16
    """
    the file has its dynamic undefined references prebound
    """

    MH_SPLIT_SEGS: typing.Final = 32
    """
    the file has its read-only and read-write segments split
    """

    MH_LAZY_INIT: typing.Final = 64
    """
    the shared library init routine is to be run lazily via catching memory faults to its 
    writeable segments (obsolete)
    """

    MH_TWOLEVEL: typing.Final = 128
    """
    the image is using two-level name space bindings
    """

    MH_FORCE_FLAT: typing.Final = 256
    """
    the executable is forcing all images to use flat name space bindings
    """

    MH_NOMULTIDEFS: typing.Final = 512
    """
    this umbrella guarantees no multiple definitions of symbols in its sub-images so the 
    two-level namespace hints can always be used
    """

    MH_NOFIXPREBINDING: typing.Final = 1024
    """
    do not have dyld notify the prebinding agent about this executable
    """

    MH_PREBINDABLE: typing.Final = 2048
    """
    the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is 
    not set
    """

    MH_ALLMODSBOUND: typing.Final = 4096
    """
    indicates that this binary binds to all two-level namespace modules of its dependent 
    libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set.
    """

    MH_SUBSECTIONS_VIA_SYMBOLS: typing.Final = 8192
    """
    safe to divide up the sections into sub-sections via symbols for dead code stripping
    """

    MH_CANONICAL: typing.Final = 16384
    """
    the binary has been canonicalized via the unprebind operation.
    """

    MH_WEAK_DEFINES: typing.Final = 32768
    """
    the final linked image contains external weak symbols.
    """

    MH_BINDS_TO_WEAK: typing.Final = 65536
    """
    the final linked image uses weak symbols.
    """

    MH_ALLOW_STACK_EXECUTION: typing.Final = 131072
    """
    When this bit is set, all stacks in the task will be given stack execution privilege. only 
    used in MH_EXECUTE filetypes.
    """

    MH_ROOT_SAFE: typing.Final = 262144
    """
    When this bit is set, the binary declares it is safe for use in processes with uid zero
    """

    MH_SETUID_SAFE: typing.Final = 524288
    """
    When this bit is set, the binary declares it is safe for use in processes when issetugid() 
    is true
    """

    MH_NO_REEXPORTED_DYLIBS: typing.Final = 1048576
    """
    When this bit is set on a dylib, the static linker does not need to examine dependent dylibs 
    to see if any are re-exported
    """

    MH_PIE: typing.Final = 2097152
    """
    When this bit is set, the OS will load the main executable at a random address. Only used in 
    MH_EXECUTE filetypes.
    """

    MH_DEAD_STRIPPABLE_DYLIB: typing.Final = 4194304
    """
    Only for use on dylibs. When linking against a dylib that has this bit set, the static linker 
    will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are 
    being referenced from the dylib.
    """

    MH_HAS_TLV_DESCRIPTORS: typing.Final = 8388608
    """
    Contains a section of type S_THREAD_LOCAL_VARIABLES.
    """

    MH_NO_HEAP_EXECUTION: typing.Final = 16777216
    """
    When this bit is set, the OS will run the main executable with a non-executable heap even on 
    platforms ( e.g., i386 ) that don't require it. Only used in MH_EXECUTE file types.
    """

    MH_APP_EXTENSION_SAFE: typing.Final = 33554432
    """
    The code was linked for use in an application extension.
    """

    MH_NLIST_OUTOFSYNC_WITH_DYLDINFO: typing.Final = 67108864
    """
    The external symbols listed in the nlist symbol table do not include all the symbols listed 
    in the dyld info.
    """

    MH_SIM_SUPPORT: typing.Final = 134217728
    """
    Allow LC_MIN_VERSION_MACOS and LC_BUILD_VERSION load commands with the platforms macOS, 
    iOSMac, iOSSimulator, tvOSSimulator and watchOSSimulator.
    """

    MH_DYLIB_IN_CACHE: typing.Final = -2147483648
    """
    Only for use on dylibs. When this bit is set, the dylib is part of the dyld shared cache, 
    rather than loose in the filesystem.
    """


    def __init__(self):
        ...

    @staticmethod
    def getFlags(flags: typing.Union[jpype.JInt, int]) -> java.util.List[java.lang.String]:
        """
        Returns string representation of the flag values.
        
        :param jpype.JInt or int flags: the flags value to get the string representation of.
        :return: a string representation of the flag values.
        :rtype: java.util.List[java.lang.String]
        """


class Section(ghidra.app.util.bin.StructConverter):
    """
    Represents a section and section_64 structure.
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/loader.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>`_
    """

    @typing.type_check_only
    class SectionInputStream(java.io.InputStream):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, is32bit: typing.Union[jpype.JBoolean, bool]):
        ...

    def contains(self, address: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the section contains the given address
        
        :param jpype.JLong or int address: The address to check
        :return: True if the section contains the given address; otherwise, false
        :rtype: bool
        """

    def getAddress(self) -> int:
        ...

    def getAlign(self) -> int:
        ...

    def getAttributes(self) -> int:
        ...

    def getDataStream(self, header: MachHeader) -> java.io.InputStream:
        """
        Returns an input stream to underlying bytes of this section.
        
        :param MachHeader header: The Mach-O header
        :return: an input stream to underlying bytes of this section
        :rtype: java.io.InputStream
        :raises IOException: if an i/o error occurs.
        """

    def getFlags(self) -> int:
        ...

    def getNumberOfRelocations(self) -> int:
        ...

    def getOffset(self) -> int:
        ...

    def getRelocationOffset(self) -> int:
        ...

    def getRelocations(self) -> java.util.List[RelocationInfo]:
        ...

    def getReserved1(self) -> int:
        ...

    def getReserved2(self) -> int:
        ...

    def getReserved3(self) -> int:
        ...

    def getSectionName(self) -> str:
        ...

    def getSegmentName(self) -> str:
        ...

    def getSize(self) -> int:
        ...

    def getType(self) -> int:
        ...

    def isExecute(self) -> bool:
        """
        Returns true if this section has EXECUTE permission.
         
        
        NOTE: On a real system, sections don't have their own permissions, only the segments they 
        live in do.  However, Ghidra needs finer-grained control for analysis to work correctly, so 
        we take control over section permissions to fit our needs.
        
        :return: true if this section has EXECUTE permission
        :rtype: bool
        """

    def isRead(self) -> bool:
        """
        Returns true if this section has READ permission.
         
        
        NOTE: On a real system, sections don't have their own permissions, only the segments they 
        live in do.  However, Ghidra needs finer-grained control for analysis to work correctly, so 
        we take control over section permissions to fit our needs.
        
        :return: true if this section has READ permission
        :rtype: bool
        """

    def isWrite(self) -> bool:
        """
        Returns true if this section has WRITE permission.
         
        
        NOTE: On a real system, sections don't have their own permissions, only the segments they 
        live in do.  However, Ghidra needs finer-grained control for analysis to work correctly, so 
        we take control over section permissions to fit our needs.
        
        :return: true if this section has WRITE permission
        :rtype: bool
        """

    def setSectionName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setSegmentName(self, name: typing.Union[java.lang.String, str]):
        ...

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> jpype.JLong:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def align(self) -> jpype.JInt:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @property
    def segmentName(self) -> java.lang.String:
        ...

    @segmentName.setter
    def segmentName(self, value: java.lang.String):
        ...

    @property
    def sectionName(self) -> java.lang.String:
        ...

    @sectionName.setter
    def sectionName(self, value: java.lang.String):
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def dataStream(self) -> java.io.InputStream:
        ...

    @property
    def reserved3(self) -> jpype.JInt:
        ...

    @property
    def reserved2(self) -> jpype.JInt:
        ...

    @property
    def reserved1(self) -> jpype.JInt:
        ...

    @property
    def attributes(self) -> jpype.JInt:
        ...

    @property
    def numberOfRelocations(self) -> jpype.JInt:
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @property
    def relocationOffset(self) -> jpype.JInt:
        ...

    @property
    def relocations(self) -> java.util.List[RelocationInfo]:
        ...


class RelocationInfo(ghidra.app.util.bin.StructConverter):
    """
    Represents a relocation_info and scattered_relocation_info structure.
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/reloc.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/reloc.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getAddress(self) -> int:
        ...

    def getLength(self) -> int:
        ...

    def getType(self) -> int:
        ...

    def getValue(self) -> int:
        ...

    def isExternal(self) -> bool:
        ...

    def isPcRelocated(self) -> bool:
        ...

    def isScattered(self) -> bool:
        ...

    def toValues(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns the values array for storage into the program's relocation table.
        
        :return: the values array for storage into the program's relocation table
        :rtype: jpype.JArray[jpype.JLong]
        """

    @property
    def external(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...

    @property
    def scattered(self) -> jpype.JBoolean:
        ...

    @property
    def pcRelocated(self) -> jpype.JBoolean:
        ...


class CpuSubTypes(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    CPU_SUBTYPE_POWERPC_ALL: typing.Final = 0
    CPU_SUBTYPE_POWERPC_601: typing.Final = 1
    CPU_SUBTYPE_POWERPC_602: typing.Final = 2
    CPU_SUBTYPE_POWERPC_603: typing.Final = 3
    CPU_SUBTYPE_POWERPC_603e: typing.Final = 4
    CPU_SUBTYPE_POWERPC_603ev: typing.Final = 5
    CPU_SUBTYPE_POWERPC_604: typing.Final = 6
    CPU_SUBTYPE_POWERPC_604e: typing.Final = 7
    CPU_SUBTYPE_POWERPC_620: typing.Final = 8
    CPU_SUBTYPE_POWERPC_750: typing.Final = 9
    CPU_SUBTYPE_POWERPC_7400: typing.Final = 10
    CPU_SUBTYPE_POWERPC_7450: typing.Final = 11
    CPU_SUBTYPE_POWERPC_Max: typing.Final = 10
    CPU_SUBTYPE_POWERPC_SCVger: typing.Final = 11
    CPU_SUBTYPE_POWERPC_970: typing.Final = 100
    CPU_SUBTYPE_I386_ALL: typing.Final[jpype.JInt]
    CPU_SUBTYPE_386: typing.Final[jpype.JInt]
    CPU_SUBTYPE_486: typing.Final[jpype.JInt]
    CPU_SUBTYPE_486SX: typing.Final[jpype.JInt]
    CPU_SUBTYPE_586: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENT: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTPRO: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTII_M3: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTII_M5: typing.Final[jpype.JInt]
    CPU_SUBTYPE_CELERON: typing.Final[jpype.JInt]
    CPU_SUBTYPE_CELERON_MOBILE: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTIUM_3: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTIUM_3_M: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTIUM_3_XEON: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTIUM_M: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTIUM_4: typing.Final[jpype.JInt]
    CPU_SUBTYPE_PENTIUM_4_M: typing.Final[jpype.JInt]
    CPU_SUBTYPE_ITANIUM: typing.Final[jpype.JInt]
    CPU_SUBTYPE_ITANIUM_2: typing.Final[jpype.JInt]
    CPU_SUBTYPE_XEON: typing.Final[jpype.JInt]
    CPU_SUBTYPE_XEON_MP: typing.Final[jpype.JInt]
    CPU_SUBTYPE_X86_ALL: typing.Final = 3
    CPU_SUBTYPE_X86_ARCH1: typing.Final = 4
    CPU_THREADTYPE_INTEL_HTT: typing.Final = 1
    CPU_SUBTYPE_MIPS_ALL: typing.Final = 0
    CPU_SUBTYPE_MIPS_R2300: typing.Final = 1
    CPU_SUBTYPE_MIPS_R2600: typing.Final = 2
    CPU_SUBTYPE_MIPS_R2800: typing.Final = 3
    CPU_SUBTYPE_MIPS_R2000a: typing.Final = 4
    CPU_SUBTYPE_MIPS_R2000: typing.Final = 5
    CPU_SUBTYPE_MIPS_R3000a: typing.Final = 6
    CPU_SUBTYPE_MIPS_R3000: typing.Final = 7
    CPU_SUBTYPE_MC98000_ALL: typing.Final = 0
    CPU_SUBTYPE_MC98601: typing.Final = 1
    CPU_SUBTYPE_HPPA_ALL: typing.Final = 0
    CPU_SUBTYPE_HPPA_7100: typing.Final = 0
    CPU_SUBTYPE_HPPA_7100LC: typing.Final = 1
    CPU_SUBTYPE_MC88000_ALL: typing.Final = 0
    CPU_SUBTYPE_MC88100: typing.Final = 1
    CPU_SUBTYPE_MC88110: typing.Final = 2
    CPU_SUBTYPE_SPARC_ALL: typing.Final = 0
    CPU_SUBTYPE_I860_ALL: typing.Final = 0
    CPU_SUBTYPE_I860_860: typing.Final = 1
    CPU_SUBTYPE_VAX_ALL: typing.Final = 0
    CPU_SUBTYPE_VAX780: typing.Final = 1
    CPU_SUBTYPE_VAX785: typing.Final = 2
    CPU_SUBTYPE_VAX750: typing.Final = 3
    CPU_SUBTYPE_VAX730: typing.Final = 4
    CPU_SUBTYPE_UVAXI: typing.Final = 5
    CPU_SUBTYPE_UVAXII: typing.Final = 6
    CPU_SUBTYPE_VAX8200: typing.Final = 7
    CPU_SUBTYPE_VAX8500: typing.Final = 8
    CPU_SUBTYPE_VAX8600: typing.Final = 9
    CPU_SUBTYPE_VAX8650: typing.Final = 10
    CPU_SUBTYPE_VAX8800: typing.Final = 11
    CPU_SUBTYPE_UVAXIII: typing.Final = 12
    CPU_SUBTYPE_MC680x0_ALL: typing.Final = 1
    CPU_SUBTYPE_MC68030: typing.Final = 1
    CPU_SUBTYPE_MC68040: typing.Final = 2
    CPU_SUBTYPE_MC68030_ONLY: typing.Final = 3
    CPU_SUBTYPE_ARM_ALL: typing.Final = 0
    CPU_SUBTYPE_ARM_V4T: typing.Final = 5
    CPU_SUBTYPE_ARM_V6: typing.Final = 6
    CPU_SUBTYPE_ARM_V5: typing.Final = 7
    CPU_SUBTYPE_ARM_V5TEJ: typing.Final = 7
    CPU_SUBTYPE_ARM_XSCALE: typing.Final = 8
    CPU_SUBTYPE_ARM_V7: typing.Final = 9
    CPU_SUBTYPE_ARM_V7F: typing.Final = 10
    CPU_SUBTYPE_ARM_V7S: typing.Final = 11
    CPU_SUBTYPE_ARM_V7K: typing.Final = 12
    CPU_SUBTYPE_ARM_V6M: typing.Final = 14
    CPU_SUBTYPE_ARM_V7M: typing.Final = 15
    CPU_SUBTYPE_ARM_V7EM: typing.Final = 16
    CPU_SUBTYPE_MULTIPLE: typing.Final = -1
    CPU_SUBTYPE_LITTLE_ENDIAN: typing.Final = 0
    CPU_SUBTYPE_BIG_ENDIAN: typing.Final = 1

    def __init__(self):
        ...


class SectionTypes(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SECTION_TYPE_MASK: typing.Final = 255
    """
    256 section types
    """

    S_REGULAR: typing.Final = 0
    """
    Type: regular section
    """

    S_ZEROFILL: typing.Final = 1
    """
    Type: zero fill on demand section
    """

    S_CSTRING_LITERALS: typing.Final = 2
    """
    Type: section with only literal C strings
    """

    S_4BYTE_LITERALS: typing.Final = 3
    """
    Type: section with only 4 byte literals
    """

    S_8BYTE_LITERALS: typing.Final = 4
    """
    Type: section with only 8 byte literals
    """

    S_LITERAL_POINTERS: typing.Final = 5
    """
    Type: section with only pointers to literals
    """

    S_NON_LAZY_SYMBOL_POINTERS: typing.Final = 6
    """
    Type: section with only non-lazy symbol pointers
    """

    S_LAZY_SYMBOL_POINTERS: typing.Final = 7
    """
    Type: section with only lazy symbol pointers
    """

    S_SYMBOL_STUBS: typing.Final = 8
    """
    Type: section with only symbol stubs, byte size of stub in the reserved2 field
    """

    S_MOD_INIT_FUNC_POINTERS: typing.Final = 9
    """
    Type: section with only function pointers for initialization
    """

    S_MOD_TERM_FUNC_POINTERS: typing.Final = 10
    """
    Type: section with only function pointers for termination
    """

    S_COALESCED: typing.Final = 11
    """
    Type: section contains symbols that are to be coalesced
    """

    S_GB_ZEROFILL: typing.Final = 12
    """
    Type: zero fill on demand section (that can be larger than 4 gigabytes)
    """

    S_INTERPOSING: typing.Final = 13
    """
    Type: section with only pairs of function pointers for interposing
    """

    S_16BYTE_LITERALS: typing.Final = 14
    """
    section with only 16 byte literals
    """

    S_DTRACE_DOF: typing.Final = 15
    """
    section contains DTrace Object Format
    """

    S_LAZY_DYLIB_SYMBOL_POINTERS: typing.Final = 16
    """
    section with only lazy symbol pointers to lazy loaded dylibs
    """

    S_THREAD_LOCAL_REGULAR: typing.Final = 17
    """
    Section types to support thread local variables.
    Template of initial values to TLVs.
    """

    S_THREAD_LOCAL_ZEROFILL: typing.Final = 18
    """
    Section types to support thread local variables.
    Template of initial values to TLVs.
    """

    S_THREAD_LOCAL_VARIABLES: typing.Final = 19
    """
    Section types to support thread local variables.
    TLV descriptors.
    """

    S_THREAD_LOCAL_VARIABLE_POINTERS: typing.Final = 20
    """
    Section types to support thread local variables.
    Pointers to TLV descriptors.
    """

    S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: typing.Final = 21
    """
    Section types to support thread local variables.
    Functions to call to initialize TLV values.
    """


    def __init__(self):
        ...

    @staticmethod
    def getTypeName(type: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the string name for the constant define of the section type.
        
        :param jpype.JInt or int type: the section type
        :return: string name for the constant define of the section type
        :rtype: str
        """



__all__ = ["SectionNames", "MachConstants", "ObsoleteException", "CpuTypes", "MachException", "MachHeaderFileTypes", "SectionAttributes", "MachHeader", "MachHeaderFlags", "Section", "RelocationInfo", "CpuSubTypes", "SectionTypes"]
