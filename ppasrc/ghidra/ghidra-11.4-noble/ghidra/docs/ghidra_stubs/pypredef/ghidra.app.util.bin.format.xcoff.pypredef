from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang # type: ignore


class XCoffSectionHeader(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def sizeof(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...


class XCoffSymbol(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SYMSZ: typing.Final = 18
    SYMNMLEN: typing.Final = 8
    N_DEBUG: typing.Final = -2
    N_ABS: typing.Final = -1
    N_UNDEF: typing.Final = 0

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, optionalHeader: XCoffOptionalHeader):
        ...

    def getName(self) -> str:
        ...

    def isFunction(self) -> bool:
        ...

    def isLongName(self) -> bool:
        ...

    def isVariable(self) -> bool:
        ...

    @property
    def function(self) -> jpype.JBoolean:
        ...

    @property
    def variable(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def longName(self) -> jpype.JBoolean:
        ...


class XCoffException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class XCoffArchiveHeader(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        ...

    def fl_freeoff(self) -> int:
        ...

    def fl_gst64off(self) -> int:
        ...

    def fl_gstoff(self) -> int:
        ...

    def fl_magic(self) -> str:
        ...

    def fl_memoff(self) -> int:
        ...

    def fstmoff(self) -> int:
        ...

    def lstmoff(self) -> int:
        ...


class XCoffArchiveMemberHeader(java.lang.Object):
    """
    The ``ARHeader`` class is used to store the per-object file 
    archive headers.  It can also create an XCOFF32 object for inspecting
    the object file data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getDate(self) -> int:
        ...

    def getGroupID(self) -> int:
        ...

    def getMode(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getNameLength(self) -> int:
        ...

    def getNextMemberOffset(self) -> int:
        ...

    def getObjectDataOffset(self) -> int:
        ...

    def getPreviousMemberOffset(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    def getTerminator(self) -> str:
        ...

    def getUserID(self) -> int:
        ...

    @property
    def mode(self) -> jpype.JLong:
        ...

    @property
    def date(self) -> jpype.JLong:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def nameLength(self) -> jpype.JInt:
        ...

    @property
    def previousMemberOffset(self) -> jpype.JLong:
        ...

    @property
    def objectDataOffset(self) -> jpype.JLong:
        ...

    @property
    def groupID(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def terminator(self) -> java.lang.String:
        ...

    @property
    def userID(self) -> jpype.JLong:
        ...

    @property
    def nextMemberOffset(self) -> jpype.JLong:
        ...


class XCoffSymbolStorageClass(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    C_BCOMM: typing.Final = 135
    """
    beginning of the common block
    """

    C_BINCL: typing.Final = 108
    """
    beginning of include file
    """

    C_BLOCK: typing.Final = 100
    """
    beginning or end of inner block
    """

    C_BSTAT: typing.Final = 143
    """
    beginning of static block
    """

    C_DECL: typing.Final = 140
    """
    declaration of object (type)
    """

    C_ECOML: typing.Final = 136
    """
    local member of common block
    """

    C_ECOMM: typing.Final = 127
    """
    end of common block
    """

    C_EINCL: typing.Final = 109
    """
    end of include file
    """

    C_ENTRY: typing.Final = 141
    """
    alternate entry
    """

    C_ESTAT: typing.Final = 144
    """
    end of static block
    """

    C_EXT: typing.Final = 2
    """
    external symbol
    """

    C_FCN: typing.Final = 101
    """
    beginning or end of function
    """

    C_FILE: typing.Final = 103
    """
    source file name and compiler information
    """

    C_FUN: typing.Final = 142
    """
    function or procedure
    """

    C_GSYM: typing.Final = 128
    """
    global variable
    """

    C_HIDEXT: typing.Final = 107
    """
    unnamed external symbol
    """

    C_INFO: typing.Final = 100
    """
    comment section reference
    """

    C_LSYM: typing.Final = 129
    """
    automatic variable allocated on stack
    """

    C_NULL: typing.Final = 0
    """
    symbol table entry marked for deletion
    """

    C_PSYM: typing.Final = 130
    """
    argument to subroutine allocated on stack
    """

    C_RPSYM: typing.Final = 132
    """
    argument to function or procedure stored in register
    """

    C_RSYM: typing.Final = 131
    """
    register variable
    """

    C_STAT: typing.Final = 3
    """
    static symbol (unknown)
    """

    C_STSYM: typing.Final = 133
    """
    statically allocated symbol
    """

    C_TCSYM: typing.Final = 134
    """
    reserved
    """

    C_WEAKEXT: typing.Final = 111
    """
    weak external symbol
    """


    def __init__(self):
        ...


class XCoffFileHeader(ghidra.app.util.bin.StructConverter):
    """
    XCOFF File Header.
    Handles both 32 and 64 bit cases.
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 20

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        ...

    def getFlags(self) -> int:
        ...

    def getMagic(self) -> int:
        ...

    def getOptionalHeader(self) -> XCoffOptionalHeader:
        ...

    def getOptionalHeaderSize(self) -> int:
        ...

    def getSectionCount(self) -> int:
        ...

    def getSymbolTableEntries(self) -> int:
        ...

    def getSymbolTablePointer(self) -> int:
        ...

    def getTimeStamp(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def timeStamp(self) -> jpype.JInt:
        ...

    @property
    def magic(self) -> jpype.JShort:
        ...

    @property
    def sectionCount(self) -> jpype.JShort:
        ...

    @property
    def optionalHeaderSize(self) -> jpype.JShort:
        ...

    @property
    def symbolTableEntries(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JShort:
        ...

    @property
    def optionalHeader(self) -> XCoffOptionalHeader:
        ...

    @property
    def symbolTablePointer(self) -> jpype.JLong:
        ...


class XCoffSymbolStorageClassCSECT(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    XMC_PR: typing.Final = 0
    XMC_RO: typing.Final = 1
    XMC_DB: typing.Final = 2
    XMC_TC: typing.Final = 3
    XMC_UA: typing.Final = 4
    XMC_RW: typing.Final = 5
    XMC_GL: typing.Final = 6
    XMC_XO: typing.Final = 7
    XMC_SV: typing.Final = 8
    XMC_BS: typing.Final = 9
    XMC_DS: typing.Final = 10
    XMC_UC: typing.Final = 11
    XMC_TI: typing.Final = 12
    XMC_TB: typing.Final = 13
    XMC_TC0: typing.Final = 15
    XMC_TD: typing.Final = 16
    XMC_SV64: typing.Final = 17
    XMC_SV3264: typing.Final = 18

    def __init__(self):
        ...


class XCoffOptionalHeader(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    AOUTHDRSZ: typing.Final = 72

    def getCpuFlag(self) -> int:
        """
        Returns the CPU bit flags.
        
        :return: the CPU bit flags
        :rtype: int
        """

    def getCpuType(self) -> int:
        """
        Reserved. Always returns 0.
        
        :return: always returns 0
        :rtype: int
        """

    def getDataStart(self) -> int:
        """
        Returns the virtual address of the .data section.
        
        :return: the virtual address of the .data section
        :rtype: int
        """

    def getDebugger(self) -> int:
        """
        This field should be 0. When the loaded program
        is being debugged, the memory image of this field
        may be modified by the debugger to insert
        a trap instruction.
        
        :return: should return 0
        :rtype: int
        """

    def getEntry(self) -> int:
        """
        Returns the virtual address of the entry point.
        
        :return: the virtual address of the entry point
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        This field consists of 4 1-bit flags and a 4-bit .tdata alignment.
        
        :return: the flags
        :rtype: int
        """

    def getInitializedDataSize(self) -> int:
        """
        Returns the size (in bytes) of the raw data for the .data section.
        
        :return: the size (in bytes) of the raw data for the .data section
        :rtype: int
        """

    def getMagic(self) -> int:
        """
        Returns the magic value. The binder assigns the following value: 0x010b.
        
        :return: the magic value
        :rtype: int
        """

    def getMaxAlignmentForData(self) -> int:
        """
        Returns log (base-2) of the maximum alignment needed for 
        any csect in the .data or .bss section.
        
        :return: the maximum alignment for the .data or .bss section
        :rtype: int
        """

    def getMaxAlignmentForText(self) -> int:
        """
        Returns log (base-2) of the maximum alignment needed for 
        any csect in the .text section.
        
        :return: the maximum alignment for the .text section
        :rtype: int
        """

    def getMaxDataSize(self) -> int:
        """
        Returns the maximum data size allowed for this executable.
        If the value is 0, then the default value is used.
        
        :return: the maximum data size allow for this executable
        :rtype: int
        """

    def getMaxStackSize(self) -> int:
        """
        Returns the maximum stack size allowed for this executable.
        If the value is 0, then the default value is used.
        
        :return: the maximum stack size allow for this executable
        :rtype: int
        """

    def getModuleType(self) -> str:
        """
        Returns the module type.
        Valid module types:
                RO - Specifies a read-only module.
        
        :return: the module type
        :rtype: str
        """

    def getSectionNumberForBss(self) -> int:
        """
        Returns the number of the .bss section.
        
        :return: the number of the .bss section
        :rtype: int
        """

    def getSectionNumberForData(self) -> int:
        """
        Returns the number of the .data section.
        
        :return: the number of the .data section
        :rtype: int
        """

    def getSectionNumberForEntry(self) -> int:
        """
        Returns the number of the section that contains the entry point.
        The entry point must be in the .text or .data section.
        
        :return: the number of the section that contains the entry point
        :rtype: int
        """

    def getSectionNumberForLoader(self) -> int:
        """
        Returns the number of the section that contains the system loader information.
        
        :return: the number of the section that contains the system loader information
        :rtype: int
        """

    def getSectionNumberForTBss(self) -> int:
        ...

    def getSectionNumberForTData(self) -> int:
        ...

    def getSectionNumberForTOC(self) -> int:
        """
        Returns the number of the section that contains the TOC.
        
        :return: the number of the section that contains the TOC
        :rtype: int
        """

    def getSectionNumberForText(self) -> int:
        """
        Returns the number of the .text section.
        
        :return: the number of the .text section
        :rtype: int
        """

    def getTOC(self) -> int:
        """
        Returns the virtual address of the TOC anchor.
        
        :return: the virtual address of the TOC anchor
        :rtype: int
        """

    def getTextSize(self) -> int:
        """
        Returns the size (in bytes) of the raw data for the .text section.
        
        :return: the size (in bytes) of the raw data for the .text section
        :rtype: int
        """

    def getTextStart(self) -> int:
        """
        Returns the virtual address of the .text section.
        
        :return: the virtual address of the .text section
        :rtype: int
        """

    def getUninitializedDataSize(self) -> int:
        """
        Returns the size (in bytes) of the .bss section.
        No raw data exists in the file for the .bss section.
        
        :return: the size (in bytes) of the .bss section
        :rtype: int
        """

    def getVersionStamp(self) -> int:
        """
        Returns the format version for this auxiliary header.
        The only valid value is 1.
        
        :return: the format version for this auxiliary header
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def magic(self) -> jpype.JShort:
        ...

    @property
    def maxStackSize(self) -> jpype.JLong:
        ...

    @property
    def cpuType(self) -> jpype.JByte:
        ...

    @property
    def debugger(self) -> jpype.JLong:
        ...

    @property
    def flags(self) -> jpype.JByte:
        ...

    @property
    def tOC(self) -> jpype.JLong:
        ...

    @property
    def textStart(self) -> jpype.JLong:
        ...

    @property
    def maxDataSize(self) -> jpype.JLong:
        ...

    @property
    def cpuFlag(self) -> jpype.JByte:
        ...

    @property
    def initializedDataSize(self) -> jpype.JLong:
        ...

    @property
    def sectionNumberForEntry(self) -> jpype.JShort:
        ...

    @property
    def maxAlignmentForText(self) -> jpype.JShort:
        ...

    @property
    def sectionNumberForData(self) -> jpype.JShort:
        ...

    @property
    def sectionNumberForText(self) -> jpype.JShort:
        ...

    @property
    def sectionNumberForTBss(self) -> jpype.JShort:
        ...

    @property
    def textSize(self) -> jpype.JLong:
        ...

    @property
    def uninitializedDataSize(self) -> jpype.JLong:
        ...

    @property
    def sectionNumberForTData(self) -> jpype.JShort:
        ...

    @property
    def moduleType(self) -> java.lang.String:
        ...

    @property
    def sectionNumberForLoader(self) -> jpype.JShort:
        ...

    @property
    def maxAlignmentForData(self) -> jpype.JShort:
        ...

    @property
    def versionStamp(self) -> jpype.JShort:
        ...

    @property
    def sectionNumberForBss(self) -> jpype.JShort:
        ...

    @property
    def entry(self) -> jpype.JLong:
        ...

    @property
    def dataStart(self) -> jpype.JLong:
        ...

    @property
    def sectionNumberForTOC(self) -> jpype.JShort:
        ...


class XCoffSectionHeaderNames(java.lang.Object):
    """
    Names of "special" sections.
    """

    class_: typing.ClassVar[java.lang.Class]
    _TEXT: typing.Final = ".text"
    _DATA: typing.Final = ".data"
    _BSS: typing.Final = ".bss"
    _PAD: typing.Final = ".pad"
    _LOADER: typing.Final = ".loader"
    _DEBUG: typing.Final = ".debug"
    _TYPCHK: typing.Final = ".typchk"
    _EXCEPT: typing.Final = ".except"
    _OVRFLO: typing.Final = ".ovrflo"
    _INFO: typing.Final = ".info"

    def __init__(self):
        ...


class XCoffFileHeaderFlags(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    F_RELFLG: typing.Final = 1
    """
    relocation info stripped from file
    """

    F_EXEC: typing.Final = 2
    """
    file is executable (no unresolved external references)
    """

    F_LNNO: typing.Final = 4
    """
    line numbers stripped from file
    """

    F_LSYMS: typing.Final = 8
    """
    local symbols stripped from file
    """

    F_FDPR_PROF: typing.Final = 16
    """
    file was profiled with fdpr command
    """

    F_FDPR_OPTI: typing.Final = 32
    """
    file was reordered with fdpr command
    """

    F_DSA: typing.Final = 64
    """
    file uses Very Large Program Support
    """

    F_AR16WR: typing.Final = 128
    """
    file is 16-bit little-endian
    """

    F_AR32WR: typing.Final = 256
    """
    file is 32-bit little-endian
    """

    F_AR32W: typing.Final = 512
    """
    file is 32-bit big-endian
    """

    F_DYNLOAD: typing.Final = 4096
    """
    rs/6000 aix: dynamically loadable w/imports and exports
    """

    F_SHROBJ: typing.Final = 8192
    """
    rs/6000 aix: file is a shared object
    """

    F_LOADONLY: typing.Final = 16384
    """
    rs/6000 aix: if the object file is a member of an archive
    it can be loaded by the system loader but the member is ignored by the binder.
    """


    def __init__(self):
        ...

    @staticmethod
    def isDebug(header: XCoffFileHeader) -> bool:
        ...

    @staticmethod
    def isExec(header: XCoffFileHeader) -> bool:
        ...

    @staticmethod
    def isStrip(header: XCoffFileHeader) -> bool:
        ...


class XCoffSectionHeaderFlags(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    STYP_PAD: typing.Final = 8
    STYP_TEXT: typing.Final = 32
    STYP_DATA: typing.Final = 64
    STYP_BSS: typing.Final = 128
    STYP_EXCEPT: typing.Final = 128
    STYP_INFO: typing.Final = 512
    STYP_LOADER: typing.Final = 4096
    STYP_DEBUG: typing.Final = 8192
    STYP_TYPCHK: typing.Final = 16384
    STYP_OVRFLO: typing.Final = 32768

    def __init__(self):
        ...


class XCoffArchiveConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MAGIC: typing.Final = "<bigaf>\n"
    MAGIC_LENGTH: typing.Final[jpype.JInt]

    def __init__(self):
        ...


class XCoffFileHeaderMagic(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MAGIC_XCOFF32: typing.Final = 479
    """
    XCOFF32
    """

    MAGIC_XCOFF64_OLD: typing.Final = 495
    """
    XCOFF64 - discontinued AIX
    """

    MAGIC_XCOFF64: typing.Final = 503
    """
    XCOFF64
    """


    def __init__(self):
        ...

    @staticmethod
    def is32bit(header: XCoffFileHeader) -> bool:
        ...

    @staticmethod
    def is64bit(header: XCoffFileHeader) -> bool:
        ...

    @staticmethod
    def isMatch(magic: typing.Union[jpype.JShort, int]) -> bool:
        ...



__all__ = ["XCoffSectionHeader", "XCoffSymbol", "XCoffException", "XCoffArchiveHeader", "XCoffArchiveMemberHeader", "XCoffSymbolStorageClass", "XCoffFileHeader", "XCoffSymbolStorageClassCSECT", "XCoffOptionalHeader", "XCoffSectionHeaderNames", "XCoffFileHeaderFlags", "XCoffSectionHeaderFlags", "XCoffArchiveConstants", "XCoffFileHeaderMagic"]
