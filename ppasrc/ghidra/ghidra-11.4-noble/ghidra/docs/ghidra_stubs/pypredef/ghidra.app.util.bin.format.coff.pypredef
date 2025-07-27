from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class CoffSymbolAuxFilename(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getFilename(self) -> str:
        ...

    def getUnused(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def unused(self) -> jpype.JArray[jpype.JByte]:
        ...


class CoffSymbolSpecial(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DOT_FILE: typing.Final = ".file"
    """
    file name
    """

    DOT_TEXT: typing.Final = ".text"
    """
    address of the .text section
    """

    DOT_DATA: typing.Final = ".data"
    """
    address of the .data section
    """

    DOT_BSS: typing.Final = ".bss"
    """
    address of the .bss section
    """

    DOT_BB: typing.Final = ".bb"
    """
    address of the beginning of a block
    """

    DOT_EB: typing.Final = ".eb"
    """
    address of the end of a block
    """

    DOT_BF: typing.Final = ".bf"
    """
    address of the beginning of a function
    """

    DOT_EF: typing.Final = ".ef"
    """
    address of the end of a function
    """

    DOT_TARGET: typing.Final = ".target"
    """
    Pointer to a structure or union that is returned by a function.
    """

    DOT_NFAKE: typing.Final = ".nfake"
    """
    Dummy tag name for a structure, union, or enumeration.
    """

    DOT_EOS: typing.Final = ".eos"
    """
    End of a structure, union, or enumeration.
    """

    DOT_ETEXT: typing.Final = "etext"
    """
    Next available address after the end of the .text output section.
    """

    DOT_EDATA: typing.Final = "edata"
    """
    Next available address after the end of the .data output section.
    """

    DOT_END: typing.Final = "end"
    """
    Next available address after the end of the .bss output section.
    """


    def __init__(self):
        ...

    def getStorageClass(self, specialSymbol: CoffSymbol) -> int:
        ...

    @staticmethod
    def isSpecial(symbol: CoffSymbol) -> bool:
        ...

    @property
    def storageClass(self) -> jpype.JInt:
        ...


@typing.type_check_only
class CoffSymbolAuxDefault(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...


class CoffSymbolAuxTagName(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getNextEntryIndex(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    def getUnused1(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getUnused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getUnused3(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def size(self) -> jpype.JShort:
        ...

    @property
    def unused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def unused3(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def nextEntryIndex(self) -> jpype.JInt:
        ...

    @property
    def unused1(self) -> jpype.JArray[jpype.JByte]:
        ...


class CoffSymbolAuxArray(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getArraySize(self) -> int:
        ...

    def getFirstDimension(self) -> int:
        ...

    def getFourthDimension(self) -> int:
        ...

    def getLineNumber(self) -> int:
        ...

    def getSecondDimension(self) -> int:
        ...

    def getTagIndex(self) -> int:
        ...

    def getThirdDimension(self) -> int:
        ...

    def getUnused(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def thirdDimension(self) -> jpype.JShort:
        ...

    @property
    def secondDimension(self) -> jpype.JShort:
        ...

    @property
    def fourthDimension(self) -> jpype.JShort:
        ...

    @property
    def tagIndex(self) -> jpype.JInt:
        ...

    @property
    def unused(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def arraySize(self) -> jpype.JShort:
        ...

    @property
    def lineNumber(self) -> jpype.JShort:
        ...

    @property
    def firstDimension(self) -> jpype.JShort:
        ...


class CoffConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME_LENGTH: typing.Final = 8
    """
    Max length (in bytes) of an in-place section name.
    """

    SYMBOL_NAME_LENGTH: typing.Final = 8
    """
    Max length (in bytes) of an in-place symbol name.
    """

    SYMBOL_SIZEOF: typing.Final = 18
    """
    Length (in bytes) of a symbol data structure.
    """

    FILE_NAME_LENGTH: typing.Final = 14
    """
    Max-length (in bytes) of a file name.
    """

    AUXILIARY_ARRAY_DIMENSION: typing.Final = 4
    """
    Number of dimensions of a symbol's auxiliary array.
    """


    def __init__(self):
        ...


class AoutHeaderMIPS(AoutHeader):

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 56

    def getCprMask(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the co-processor register masks.
        
        :return: the co-processor register masks
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getGpValue(self) -> int:
        """
        Returns the GP value.
        
        :return: the GP value
        :rtype: int
        """

    def getGprMask(self) -> int:
        """
        Returns the general purpose register mask.
        
        :return: the general purpose register mask
        :rtype: int
        """

    def getUninitializedDataStart(self) -> int:
        ...

    @property
    def gpValue(self) -> jpype.JInt:
        ...

    @property
    def cprMask(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def uninitializedDataStart(self) -> jpype.JInt:
        ...

    @property
    def gprMask(self) -> jpype.JInt:
        ...


class CoffSectionHeader(ghidra.app.util.bin.StructConverter):
    """
    A 0x28 byte COFF section header
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def getAddress(language: ghidra.program.model.lang.Language, offset: typing.Union[jpype.JLong, int], section: CoffSectionHeader) -> ghidra.program.model.address.Address:
        """
        Convert address offset to an Address object.  The default data space (defined by pspec)
        will be used if section is null or corresponds to a data section.  The language default
        space (defined by slaspec) will be used for all non-data sections.  If pspec does not 
        specify a default data space, the default language space is used.
        
        :param ghidra.program.model.lang.Language language: 
        :param jpype.JLong or int offset: address offset (byte offset assumed if section is null or is not explicitly
        byte aligned, otherwise word offset assumed).
        :param CoffSectionHeader section: section which contains the specified offset or null (data space assumed)
        :return: address object
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    @typing.overload
    def getAddress(language: ghidra.program.model.lang.Language, offset: typing.Union[jpype.JLong, int], space: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.Address:
        """
        Convert address offset to an Address in the specified space (defined by pspec).
        If pspec does not specify a default data space, the default language space is used.
        
        :param ghidra.program.model.lang.Language language: 
        :param jpype.JLong or int offset: address offset (word offset assumed).
        :param ghidra.program.model.address.AddressSpace space: address space
        :return: address object
        :rtype: ghidra.program.model.address.Address
        """

    def getFlags(self) -> int:
        """
        Returns the flags for this section.
        
        :return: the flags for this section
        :rtype: int
        """

    def getLineNumberCount(self) -> int:
        """
        Returns the number of line number entries for this section.
        
        :return: the number of line number entries for this section
        :rtype: int
        """

    def getLineNumbers(self) -> java.util.List[CoffLineNumber]:
        ...

    def getName(self) -> str:
        """
        Returns the section name.
        The section name will never be more than eight characters.
        
        :return: the section name
        :rtype: str
        """

    def getPage(self) -> int:
        ...

    @typing.overload
    def getPhysicalAddress(self) -> int:
        """
        Returns the physical address offset.
        This is the address at which the section 
        should be loaded into memory and reflects a addressable word offset.
        For linked executables, this is the absolute 
        address within the program space.
        For unlinked objects, this address is relative
        to the object's address space (i.e. the first section
        is always at offset zero).
        
        :return: the physical address
        :rtype: int
        """

    @typing.overload
    def getPhysicalAddress(self, language: ghidra.program.model.lang.Language) -> ghidra.program.model.address.Address:
        """
        Returns the physical address.
        This is the address at which the section 
        should be loaded into memory.
        For linked executables, this is the absolute 
        address within the program space.
        For unlinked objects, this address is relative
        to the object's address space (i.e. the first section
        is always at offset zero).
        
        :return: the physical address
        :rtype: ghidra.program.model.address.Address
        """

    def getPointerToLineNumbers(self) -> int:
        """
        Returns the file offset to the line numbers for this section.
        
        :return: the file offset to the line numbers for this section
        :rtype: int
        """

    def getPointerToRawData(self) -> int:
        """
        Returns the file offset to the section data.
        
        :return: the file offset to the section data
        :rtype: int
        """

    def getPointerToRelocations(self) -> int:
        """
        Returns the file offset to the relocations for this section.
        
        :return: the file offset to the relocations for this section
        :rtype: int
        """

    def getRawDataStream(self, provider: ghidra.app.util.bin.ByteProvider, language: ghidra.program.model.lang.Language) -> java.io.InputStream:
        """
        Returns an input stream that will supply the bytes
        for this section.
        
        :return: the input stream
        :rtype: java.io.InputStream
        :raises IOException: if an I/O error occurs
        """

    def getRelocationCount(self) -> int:
        """
        Returns the number of relocations for this section.
        
        :return: the number of relocations for this section
        :rtype: int
        """

    def getRelocations(self) -> java.util.List[CoffRelocation]:
        ...

    def getReserved(self) -> int:
        ...

    def getSize(self, language: ghidra.program.model.lang.Language) -> int:
        """
        Returns the number of bytes of data stored in the file for this section.
        NOTE: This value does not strictly indicate size in bytes.
            For word-oriented machines, this value is represents
            size in words.
        
        :return: the number of bytes of data stored in the file for this section
        :rtype: int
        """

    def getVirtualAddress(self) -> int:
        """
        Returns the virtual address.
        This value is always the same as s_paddr.
        
        :return: the virtual address
        :rtype: int
        """

    def isAllocated(self) -> bool:
        ...

    def isData(self) -> bool:
        ...

    def isExecutable(self) -> bool:
        ...

    def isExplicitlyByteAligned(self) -> bool:
        """
        Returns true if this section is byte oriented and aligned and should assume
        an addressable unit size of 1.
        
        :return: true if byte aligned, false if word aligned
        :rtype: bool
        """

    def isGroup(self) -> bool:
        ...

    def isInitializedData(self) -> bool:
        ...

    def isProcessedBytes(self, language: ghidra.program.model.lang.Language) -> bool:
        ...

    def isReadable(self) -> bool:
        ...

    def isUninitializedData(self) -> bool:
        ...

    def isWritable(self) -> bool:
        ...

    def move(self, offset: typing.Union[jpype.JInt, int]):
        """
        Adds offset to the physical address; this must be performed before
        relocations in order to achieve the proper result.
        
        :param jpype.JInt or int offset: the offset to add to the physical address
        """

    @property
    def readable(self) -> jpype.JBoolean:
        ...

    @property
    def explicitlyByteAligned(self) -> jpype.JBoolean:
        ...

    @property
    def pointerToRelocations(self) -> jpype.JInt:
        ...

    @property
    def lineNumbers(self) -> java.util.List[CoffLineNumber]:
        ...

    @property
    def uninitializedData(self) -> jpype.JBoolean:
        ...

    @property
    def data(self) -> jpype.JBoolean:
        ...

    @property
    def initializedData(self) -> jpype.JBoolean:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def virtualAddress(self) -> jpype.JInt:
        ...

    @property
    def executable(self) -> jpype.JBoolean:
        ...

    @property
    def writable(self) -> jpype.JBoolean:
        ...

    @property
    def pointerToLineNumbers(self) -> jpype.JInt:
        ...

    @property
    def processedBytes(self) -> jpype.JBoolean:
        ...

    @property
    def lineNumberCount(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def relocationCount(self) -> jpype.JInt:
        ...

    @property
    def reserved(self) -> jpype.JShort:
        ...

    @property
    def pointerToRawData(self) -> jpype.JInt:
        ...

    @property
    def physicalAddress(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def page(self) -> jpype.JShort:
        ...

    @property
    def relocations(self) -> java.util.List[CoffRelocation]:
        ...

    @property
    def group(self) -> jpype.JBoolean:
        ...

    @property
    def allocated(self) -> jpype.JBoolean:
        ...


class CoffSymbolAuxEndOfStruct(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getSize(self) -> int:
        ...

    def getTagIndex(self) -> int:
        ...

    def getUnused1(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getUnused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def size(self) -> jpype.JShort:
        ...

    @property
    def unused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def tagIndex(self) -> jpype.JInt:
        ...

    @property
    def unused1(self) -> jpype.JArray[jpype.JByte]:
        ...


class CoffSymbolAux(ghidra.app.util.bin.StructConverter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CoffSectionHeaderFlags(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    STYP_REG: typing.Final = 0
    """
    Regular segment.
    """

    STYP_DSECT: typing.Final = 1
    """
    Dummy section.
    """

    STYP_NOLOAD: typing.Final = 2
    """
    No-load segment.
    """

    STYP_GROUP: typing.Final = 4
    """
    Group segment.
    """

    STYP_PAD: typing.Final = 8
    """
    Pad segment.
    """

    STYP_COPY: typing.Final = 16
    """
    Copy segment.
    """

    STYP_TEXT: typing.Final = 32
    """
    The section contains only executable code.
    """

    STYP_DATA: typing.Final = 64
    """
    The section contains only initialized data.
    """

    STYP_BSS: typing.Final = 128
    """
    The section defines uninitialized data.
    """

    STYP_EXCEPT: typing.Final = 256
    """
    Exception section
    """

    STYP_INFO: typing.Final = 512
    """
    Comment section
    """

    STYP_OVER: typing.Final = 1024
    """
    Overlay section (defines a piece of another named section which has no bytes)
    """

    STYP_LIB: typing.Final = 2048
    """
    Library section
    """

    STYP_LOADER: typing.Final = 4096
    """
    Loader section
    """

    STYP_DEBUG: typing.Final = 8192
    """
    Debug section
    """

    STYP_TYPECHK: typing.Final = 16384
    """
    Type check section
    """

    STYP_OVRFLO: typing.Final = 32768
    """
    RLD and line number overflow sec hdr section
    """


    def __init__(self):
        ...


class CoffException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class CoffSymbolAuxFunction(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getFilePointerToLineNumber(self) -> int:
        ...

    def getNextEntryIndex(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    def getTagIndex(self) -> int:
        ...

    def getUnused(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def tagIndex(self) -> jpype.JInt:
        ...

    @property
    def unused(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def nextEntryIndex(self) -> jpype.JInt:
        ...

    @property
    def filePointerToLineNumber(self) -> jpype.JInt:
        ...


class AoutHeader(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 28

    def getEntry(self) -> int:
        ...

    def getInitializedDataSize(self) -> int:
        ...

    def getInitializedDataStart(self) -> int:
        ...

    def getMagic(self) -> int:
        ...

    def getTextSize(self) -> int:
        ...

    def getTextStart(self) -> int:
        ...

    def getUninitializedDataSize(self) -> int:
        ...

    def getVersionStamp(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def magic(self) -> jpype.JShort:
        ...

    @property
    def versionStamp(self) -> jpype.JShort:
        ...

    @property
    def entry(self) -> jpype.JInt:
        ...

    @property
    def textSize(self) -> jpype.JInt:
        ...

    @property
    def uninitializedDataSize(self) -> jpype.JInt:
        ...

    @property
    def textStart(self) -> jpype.JInt:
        ...

    @property
    def initializedDataStart(self) -> jpype.JInt:
        ...

    @property
    def initializedDataSize(self) -> jpype.JInt:
        ...


@typing.type_check_only
class AoutHeaderFactory(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CoffSymbolAuxEndOfBlock(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getSourceLineNumber(self) -> int:
        ...

    def getUnused1(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getUnused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def unused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def sourceLineNumber(self) -> jpype.JShort:
        ...

    @property
    def unused1(self) -> jpype.JArray[jpype.JByte]:
        ...


class CoffFileHeaderFlag(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    F_RELFLG: typing.Final = 1
    """
    If set, there is not relocation information
    in this file. This is usually clear for objects
    and set for executables.
    """

    F_EXEC: typing.Final = 2
    """
    If set, all unresolved symbols have been resolved 
    and the file may be considered executable.
    """

    F_LNNO: typing.Final = 4
    """
    If set, all line number information has been removed
    from the file (or was never added in the first place).
    """

    F_LSYMS: typing.Final = 8
    """
    If set, all local symbols have been removed from 
    the file (or were never added in the first place).
    """

    F_MINMAL: typing.Final = 16
    """
    Indicates this file is a minimal object file (".m")
    """

    F_UPDATE: typing.Final = 32
    """
    Indicates this file is a fully bound update
    file.
    """

    F_SWABD: typing.Final = 64
    """
    Indicates this file has had its bytes
    swabbed (in names).
    """

    F_AR16WR: typing.Final = 128
    F_AR32WR: typing.Final = 256
    """
    Indicates that the file is 32-bit little endian.
    """

    F_AR32W: typing.Final = 512
    F_PATCH: typing.Final = 1024
    F_NODF: typing.Final = 1024

    def __init__(self):
        ...


class CoffRelocation(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> int:
        """
        Returns the address where the relocation 
        should be performed.
        
        :return: the relocation address
        :rtype: int
        """

    def getExtendedAddress(self) -> int:
        """
        Returns the extended address value.
        This is only used for COFF2.
        
        :return: the extended address value
        :rtype: int
        """

    def getSymbolIndex(self) -> int:
        """
        Returns the symbol being relocated.
        
        :return: the symbol being relocated
        :rtype: int
        """

    def getType(self) -> int:
        """
        Returns the relocation type.
        
        :return: the relocation type
        :rtype: int
        """

    def sizeof(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def address(self) -> jpype.JLong:
        ...

    @property
    def symbolIndex(self) -> jpype.JLong:
        ...

    @property
    def type(self) -> jpype.JShort:
        ...

    @property
    def extendedAddress(self) -> jpype.JShort:
        ...


class CoffSymbolAuxName(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getSize(self) -> int:
        ...

    def getTagIndex(self) -> int:
        ...

    def getUnused1(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getUnused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def size(self) -> jpype.JShort:
        ...

    @property
    def unused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def tagIndex(self) -> jpype.JInt:
        ...

    @property
    def unused1(self) -> jpype.JArray[jpype.JByte]:
        ...


class CoffLineNumber(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 6

    def getAddress(self) -> int:
        ...

    def getFunctionNameSymbolIndex(self) -> int:
        ...

    def getLineNumber(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def address(self) -> jpype.JInt:
        ...

    @property
    def functionNameSymbolIndex(self) -> jpype.JLong:
        ...

    @property
    def lineNumber(self) -> jpype.JShort:
        ...


class AoutHeaderMagic(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    TIC80_AOUTHDR_MAGIC: typing.Final = 264
    TICOFF_AOUTHDR_MAGIC: typing.Final = 264

    def __init__(self):
        ...


@typing.type_check_only
class CoffSectionHeader2(CoffSectionHeader):
    """
    A 0x30 byte COFF section header
    """

    class_: typing.ClassVar[java.lang.Class]


class CoffSymbolAuxSection(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getLineNumberCount(self) -> int:
        ...

    def getRelocationCount(self) -> int:
        ...

    def getSectionLength(self) -> int:
        ...

    def getUnused(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def lineNumberCount(self) -> jpype.JShort:
        ...

    @property
    def sectionLength(self) -> jpype.JInt:
        ...

    @property
    def relocationCount(self) -> jpype.JShort:
        ...

    @property
    def unused(self) -> jpype.JArray[jpype.JByte]:
        ...


class CoffSymbolSectionNumber(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    N_DEBUG: typing.Final = -2
    """
    special symbolic debugging symbol
    """

    N_ABS: typing.Final = -1
    """
    absolute symbols
    """

    N_UNDEF: typing.Final = 0
    """
    undefined external symbol
    """

    N_TEXT: typing.Final = 1
    """
    .text section symbol
    """

    N_DATA: typing.Final = 2
    """
    .data section symbol
    """

    N_BSS: typing.Final = 3
    """
    .bss section symbol
    """


    def __init__(self):
        ...


class CoffSymbol(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getAuxiliaryCount(self) -> int:
        ...

    def getAuxiliarySymbols(self) -> java.util.List[CoffSymbolAux]:
        ...

    def getBasicType(self) -> int:
        ...

    def getDerivedType(self, derivedIndex: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getName(self) -> str:
        ...

    def getSectionNumber(self) -> int:
        ...

    def getStorageClass(self) -> int:
        ...

    def getValue(self) -> int:
        ...

    def isSection(self) -> bool:
        """
        Returns true if this symbol represents a section.
        
        :return: true if this symbol represents a section
        :rtype: bool
        """

    def move(self, offset: typing.Union[jpype.JInt, int]):
        """
        Adds offset to the value; this must be performed before
        relocations in order to achieve the proper result.
        
        :param jpype.JInt or int offset: the offset to add to the value
        """

    @property
    def derivedType(self) -> jpype.JInt:
        ...

    @property
    def basicType(self) -> jpype.JInt:
        ...

    @property
    def storageClass(self) -> jpype.JByte:
        ...

    @property
    def sectionNumber(self) -> jpype.JShort:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def section(self) -> jpype.JBoolean:
        ...

    @property
    def auxiliaryCount(self) -> jpype.JByte:
        ...

    @property
    def auxiliarySymbols(self) -> java.util.List[CoffSymbolAux]:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class CoffMachineType(java.lang.Object):
    """
    The Machine field has one of the following values that specifies its CPU type. 
    An image file can be run only on the specified machine or on a system that emulates
    the specified machine.
    """

    class_: typing.ClassVar[java.lang.Class]
    TICOFF1MAGIC: typing.Final = 193
    TICOFF2MAGIC: typing.Final = 194
    IMAGE_FILE_MACHINE_UNKNOWN: typing.Final = 0
    """
    The contents of this field are assumed to be applicable to any machine type
    """

    IMAGE_FILE_MACHINE_ALPHA: typing.Final = 388
    """
    Alpha
    """

    IMAGE_FILE_MACHINE_ALPHA64: typing.Final = 644
    """
    Alpha 64
    """

    IMAGE_FILE_MACHINE_AM33: typing.Final = 467
    """
    Matsushita AM33
    """

    IMAGE_FILE_MACHINE_AMD64: typing.Final = -31132
    """
    x64
    """

    IMAGE_FILE_MACHINE_AM29KBIGMAGIC: typing.Final = 378
    """
    AMD Am29000 big endian
    """

    IMAGE_FILE_MACHINE_AM29KLITTLEMAGIC: typing.Final = 379
    """
    AMD Am29000 little endian
    """

    IMAGE_FILE_MACHINE_ARM: typing.Final = 448
    """
    ARM little endian
    """

    IMAGE_FILE_MACHINE_ARM64: typing.Final = -21916
    """
    ARM64 little endian
    """

    IMAGE_FILE_MACHINE_ARMNT: typing.Final = 452
    """
    ARM Thumb-2 little endian
    """

    IMAGE_FILE_MACHINE_EBC: typing.Final = 3772
    """
    EFI byte code
    """

    IMAGE_FILE_MACHINE_I386: typing.Final = 332
    """
    Intel 386 or later processors and compatible processors
    """

    IMAGE_FILE_MACHINE_I386_PTX: typing.Final = 340
    """
    Intel 386 or later processors and compatible processors (PTX)
    """

    IMAGE_FILE_MACHINE_I386_AIX: typing.Final = 373
    """
    Intel 386 or later processors and compatible processors (AIX)
    """

    IMAGE_FILE_MACHINE_I960ROMAGIC: typing.Final = 352
    """
    Intel i960 with read-only text segment
    """

    IMAGE_FILE_MACHINE_I960RWMAGIC: typing.Final = 353
    """
    Intel i960 with read-write text segment
    """

    IMAGE_FILE_MACHINE_IA64: typing.Final = 512
    """
    Intel Itanium processor family
    """

    IMAGE_FILE_MACHINE_M32R: typing.Final = -28607
    """
    Mitsubishi M32R little endian
    """

    IMAGE_FILE_MACHINE_MIPS16: typing.Final = 614
    """
    MIPS16
    """

    IMAGE_FILE_MACHINE_MIPSFPU: typing.Final = 870
    """
    MIPS with FPU
    """

    IMAGE_FILE_MACHINE_MIPSFPU16: typing.Final = 1126
    """
    MIPS16 with FPU
    """

    IMAGE_FILE_MACHINE_M68KMAGIC: typing.Final = 616
    """
    Motorola 68000
    """

    IMAGE_FILE_MACHINE_PIC30: typing.Final = 4662
    """
    PIC-30 (dsPIC30F)
    """

    IMAGE_FILE_MACHINE_POWERPC: typing.Final = 496
    """
    Power PC little endian
    """

    IMAGE_FILE_MACHINE_POWERPCFP: typing.Final = 497
    """
    Power PC with floating point support
    """

    IMAGE_FILE_MACHINE_R3000: typing.Final = 354
    """
    MIPS little endian
    """

    IMAGE_FILE_MACHINE_R4000: typing.Final = 358
    """
    MIPS little endian
    """

    IMAGE_FILE_MACHINE_R10000: typing.Final = 360
    """
    MIPS little endian
    """

    IMAGE_FILE_MACHINE_RISCV32: typing.Final = 20530
    """
    RISC-V 32-bit address space
    """

    IMAGE_FILE_MACHINE_RISCV64: typing.Final = 20580
    """
    RISC-V 64-bit address space
    """

    IMAGE_FILE_MACHINE_RISCV128: typing.Final = 20776
    """
    RISC-V 128-bit address space
    """

    IMAGE_FILE_MACHINE_SH3: typing.Final = 418
    """
    Hitachi SH3
    """

    IMAGE_FILE_MACHINE_SH3DSP: typing.Final = 419
    """
    Hitachi SH3 DSP
    """

    IMAGE_FILE_MACHINE_SH4: typing.Final = 422
    """
    Hitachi SH4
    """

    IMAGE_FILE_MACHINE_SH5: typing.Final = 424
    """
    Hitachi SH5
    """

    IMAGE_FILE_MACHINE_TI_TMS320C3x4x: typing.Final = 147
    """
    Texas Instruments TMS320C3x/4x
    """

    IMAGE_FILE_MACHINE_TI_TMS470: typing.Final = 151
    """
    Texas Instruments TMS470
    """

    IMAGE_FILE_MACHINE_TI_TMS320C5400: typing.Final = 152
    """
    Texas Instruments TMS320C5400
    """

    IMAGE_FILE_MACHINE_TI_TMS320C6000: typing.Final = 153
    """
    Texas Instruments TMS320C6000
    """

    IMAGE_FILE_MACHINE_TI_TMS320C5500: typing.Final = 156
    """
    Texas Instruments TMS320C5500
    """

    IMAGE_FILE_MACHINE_TI_TMS320C2800: typing.Final = 157
    """
    Texas Instruments TMS320C2800
    """

    IMAGE_FILE_MACHINE_TI_MSP430: typing.Final = 160
    """
    Texas Instruments MSP430
    """

    IMAGE_FILE_MACHINE_TI_TMS320C5500_PLUS: typing.Final = 161
    """
    Texas Instruments TMS320C5500+
    """

    IMAGE_FILE_MACHINE_THUMB: typing.Final = 450
    """
    Thumb
    """

    IMAGE_FILE_MACHINE_WCEMIPSV2: typing.Final = 361
    """
    MIPS little-endian WCE v2
    """


    def __init__(self):
        ...

    @staticmethod
    def isMachineTypeDefined(type: typing.Union[jpype.JShort, int]) -> bool:
        """
        Checks to see if the given machine type is defined in this file.
        
        :param jpype.JShort or int type: The machine type to check.
        :return: True if the given machine type is defined in this file; otherwise, false.
        :rtype: bool
        """


class CoffSymbolType(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    T_NULL: typing.Final = 0
    T_VOID: typing.Final = 1
    T_CHAR: typing.Final = 2
    T_SHORT: typing.Final = 3
    T_INT: typing.Final = 4
    T_LONG: typing.Final = 5
    T_FLOAT: typing.Final = 6
    T_DOUBLE: typing.Final = 7
    T_STRUCT: typing.Final = 8
    T_UNION: typing.Final = 9
    T_ENUM: typing.Final = 10
    T_MOE: typing.Final = 11
    T_UCHAR: typing.Final = 12
    T_USHORT: typing.Final = 13
    T_UINT: typing.Final = 14
    T_ULONG: typing.Final = 15
    T_LONG_DOUBLE: typing.Final = 16
    DT_NON: typing.Final = 0
    DT_PTR: typing.Final = 1
    DT_FCN: typing.Final = 2
    DT_ARY: typing.Final = 3

    def __init__(self):
        ...

    @staticmethod
    def getBaseType(symbolType: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def getDerivedType(symbolType: typing.Union[jpype.JInt, int]) -> int:
        ...


@typing.type_check_only
class CoffSymbolAuxFactory(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CoffSectionHeader3(CoffSectionHeader):
    """
    A 0x2c byte COFF section header
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CoffSectionHeaderFactory(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CoffSymbolStorageClass(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    C_NULL: typing.Final = 0
    """
    no entry
    """

    C_AUTO: typing.Final = 1
    """
    automatic variable
    """

    C_EXT: typing.Final = 2
    """
    external (public) symbol - globals and externs
    """

    C_STAT: typing.Final = 3
    """
    static (private) symbol
    """

    C_REG: typing.Final = 4
    """
    register variable
    """

    C_EXTDEF: typing.Final = 5
    """
    external definition
    """

    C_LABEL: typing.Final = 6
    """
    label
    """

    C_ULABEL: typing.Final = 7
    """
    undefined label
    """

    C_MOS: typing.Final = 8
    """
    member of structure
    """

    C_ARG: typing.Final = 9
    """
    function argument
    """

    C_STRTAG: typing.Final = 10
    """
    structure tag
    """

    C_MOU: typing.Final = 11
    """
    member of union
    """

    C_UNTAG: typing.Final = 12
    """
    union tag
    """

    C_TPDEF: typing.Final = 13
    """
    type definition
    """

    C_USTATIC: typing.Final = 14
    """
    undefined static
    """

    C_ENTAG: typing.Final = 15
    """
    enumeration tag
    """

    C_MOE: typing.Final = 16
    """
    member of enumeration
    """

    C_REGPARAM: typing.Final = 17
    """
    register parameter
    """

    C_FIELD: typing.Final = 18
    """
    bit field
    """

    C_AUTOARG: typing.Final = 19
    """
    automatic argument
    """

    C_LASTENT: typing.Final = 20
    """
    dummy entry (end of block)
    """

    C_BLOCK: typing.Final = 100
    """
    ".bb" or ".eb" - beginning or end of block
    """

    C_FCN: typing.Final = 101
    """
    ".bf" or ".ef" - beginning or end of function
    """

    C_EOS: typing.Final = 102
    """
    end of structure
    """

    C_FILE: typing.Final = 103
    """
    file name
    """

    C_LINE: typing.Final = 104
    """
    line number, reformatted as symbol
    """

    C_ALIAS: typing.Final = 105
    """
    duplicate tag
    """

    C_HIDDEN: typing.Final = 106
    """
    external symbol in dmert public lib
    """

    C_EFCN: typing.Final = 107
    """
    physical end of function
    """


    def __init__(self):
        ...


class CoffSymbolAuxBeginningOfBlock(CoffSymbolAux):

    class_: typing.ClassVar[java.lang.Class]

    def getNextEntryIndex(self) -> int:
        ...

    def getSourceLineNumber(self) -> int:
        ...

    def getUnused1(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getUnused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getUnused3(self) -> jpype.JArray[jpype.JByte]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def unused2(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def sourceLineNumber(self) -> jpype.JShort:
        ...

    @property
    def unused3(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def nextEntryIndex(self) -> jpype.JInt:
        ...

    @property
    def unused1(self) -> jpype.JArray[jpype.JByte]:
        ...


class CoffFileHeaderTargetID(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    TIC2xx_TARGET_ID: typing.Final = 146
    TIC5X_TARGET_ID: typing.Final = 146
    TIC80_TARGET_ID: typing.Final = 149
    TIC54X_TARGET_ID: typing.Final = 152
    TIC64X_TARGET_ID: typing.Final = 153
    TIC55X_TARGET_ID: typing.Final = 156
    TIC27X_TARGET_ID: typing.Final = 157

    def __init__(self):
        ...


@typing.type_check_only
class CoffSectionHeader1(CoffSectionHeader):
    """
    A 0x28 byte COFF section header
    """

    class_: typing.ClassVar[java.lang.Class]


class CoffSectionHeaderReserved(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    EXPLICITLY_BYTE_ALIGNED: typing.Final = 8
    """
    Assuming the underlying processor is word aligned,
    then this value indicates that a section
    is byte aligned.
    """


    def __init__(self):
        ...


@typing.type_check_only
class BigEndianUnitSizeByteSwapperInputStream(java.io.InputStream):
    """
    All COFF files are stored as little endian.
    However, for COFF binaries targeted for WORD addressable
    big endian processors, the bytes for the section
    must be swapped inside the addressable unit.
    """

    class_: typing.ClassVar[java.lang.Class]


class CoffFileHeader(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        ...

    def getFlags(self) -> int:
        """
        Returns the flags about this COFF.
        
        :return: the flags about this COFF
        :rtype: int
        """

    def getImageBase(self, isWindowsPlatform: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Returns the image base.
        
        :return: the image base
        :rtype: int
        """

    def getMachine(self) -> int:
        ...

    def getMachineName(self) -> str:
        """
        Returns the machine name.
        
        :return: the machine name
        :rtype: str
        """

    def getMagic(self) -> int:
        """
        Returns the magic COFF file identifier.
        
        :return: the magic COFF file identifier
        :rtype: int
        """

    def getOptionalHeader(self) -> AoutHeader:
        """
        Returns the a.out optional header.
        This return value may be null.
        
        :return: the a.out optional header
        :rtype: AoutHeader
        """

    def getOptionalHeaderSize(self) -> int:
        """
        Returns the size in bytes of the optional header.
        The optional header immediately follows the file header
        and immediately proceeds the sections headers.
        
        :return: the size in bytes of the optional header
        :rtype: int
        """

    def getSectionCount(self) -> int:
        """
        Returns the number of sections in this COFF file.
        
        :return: the number of sections in this COFF file
        :rtype: int
        """

    def getSections(self) -> java.util.List[CoffSectionHeader]:
        """
        Returns the sections in this COFF header.
        
        :return: the sections in this COFF header
        :rtype: java.util.List[CoffSectionHeader]
        """

    def getSymbolAtIndex(self, index: typing.Union[jpype.JLong, int]) -> CoffSymbol:
        ...

    def getSymbolTableEntries(self) -> int:
        """
        Returns the number of symbols in the symbol table.
        
        :return: the number of symbols in the symbol table
        :rtype: int
        """

    def getSymbolTablePointer(self) -> int:
        """
        Returns the file offset to the symbol table.
        
        :return: the file offset to the symbol table
        :rtype: int
        """

    def getSymbols(self) -> java.util.List[CoffSymbol]:
        """
        Returns the symbols in this COFF header.
        
        :return: the symbols in this COFF header
        :rtype: java.util.List[CoffSymbol]
        """

    def getTargetID(self) -> int:
        """
        Returns the specific target id
        
        :return: the specific target id
        :rtype: int
        """

    def getTimestamp(self) -> int:
        """
        Returns the time stamp of when this file was created.
        
        :return: the time stamp of when this file was created
        :rtype: int
        """

    @staticmethod
    def isValid(provider: ghidra.app.util.bin.ByteProvider) -> bool:
        """
        Tests if the given :obj:`ByteProvider` is a valid :obj:`CoffFileHeader`.
         
        
        To avoid false positives when the machine type is 
        :obj:`CoffMachineType.IMAGE_FILE_MACHINE_UNKNOWN`, we do an additional check on some extra
        bytes at the beginning of the given :obj:`ByteProvider` to make sure the entire file isn't
        all 0's.
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` to check
        :return: True if this is a is a valid :obj:`CoffFileHeader`; otherwise, false
        :rtype: bool
        :raises IOException: if there was an IO-related issue
        """

    def parse(self, provider: ghidra.app.util.bin.ByteProvider, monitor: ghidra.util.task.TaskMonitor):
        """
        Finishes the parsing of this file header.
        
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if an i/o error occurs
        """

    def parseSectionHeaders(self, provider: ghidra.app.util.bin.ByteProvider):
        """
        Read just the section headers, not including line numbers and relocations
        
        :param ghidra.app.util.bin.ByteProvider provider: 
        :raises IOException:
        """

    def sizeof(self) -> int:
        """
        Returns the size (in bytes) of this COFF file header.
        
        :return: the size (in bytes) of this COFF file header
        :rtype: int
        """

    @property
    def magic(self) -> jpype.JShort:
        ...

    @property
    def targetID(self) -> jpype.JShort:
        ...

    @property
    def symbolTableEntries(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JShort:
        ...

    @property
    def symbols(self) -> java.util.List[CoffSymbol]:
        ...

    @property
    def sections(self) -> java.util.List[CoffSectionHeader]:
        ...

    @property
    def machineName(self) -> java.lang.String:
        ...

    @property
    def sectionCount(self) -> jpype.JShort:
        ...

    @property
    def imageBase(self) -> jpype.JLong:
        ...

    @property
    def optionalHeaderSize(self) -> jpype.JShort:
        ...

    @property
    def machine(self) -> jpype.JShort:
        ...

    @property
    def optionalHeader(self) -> AoutHeader:
        ...

    @property
    def symbolTablePointer(self) -> jpype.JInt:
        ...

    @property
    def symbolAtIndex(self) -> CoffSymbol:
        ...

    @property
    def timestamp(self) -> jpype.JInt:
        ...



__all__ = ["CoffSymbolAuxFilename", "CoffSymbolSpecial", "CoffSymbolAuxDefault", "CoffSymbolAuxTagName", "CoffSymbolAuxArray", "CoffConstants", "AoutHeaderMIPS", "CoffSectionHeader", "CoffSymbolAuxEndOfStruct", "CoffSymbolAux", "CoffSectionHeaderFlags", "CoffException", "CoffSymbolAuxFunction", "AoutHeader", "AoutHeaderFactory", "CoffSymbolAuxEndOfBlock", "CoffFileHeaderFlag", "CoffRelocation", "CoffSymbolAuxName", "CoffLineNumber", "AoutHeaderMagic", "CoffSectionHeader2", "CoffSymbolAuxSection", "CoffSymbolSectionNumber", "CoffSymbol", "CoffMachineType", "CoffSymbolType", "CoffSymbolAuxFactory", "CoffSectionHeader3", "CoffSectionHeaderFactory", "CoffSymbolStorageClass", "CoffSymbolAuxBeginningOfBlock", "CoffFileHeaderTargetID", "CoffSectionHeader1", "CoffSectionHeaderReserved", "BigEndianUnitSizeByteSwapperInputStream", "CoffFileHeader"]
