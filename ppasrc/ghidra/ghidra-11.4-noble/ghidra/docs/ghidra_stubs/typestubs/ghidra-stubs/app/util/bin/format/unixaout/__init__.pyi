from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import java.lang # type: ignore


class UnixAoutRelocation(java.lang.Object):
    """
    Represents the content of a single entry in the relocation table format used
    by the UNIX a.out executable.
    """

    class_: typing.ClassVar[java.lang.Class]
    address: jpype.JLong
    symbolNum: jpype.JInt
    flags: jpype.JByte
    pcRelativeAddressing: jpype.JBoolean
    pointerLength: jpype.JByte
    extern: jpype.JBoolean
    baseRelative: jpype.JBoolean
    jmpTable: jpype.JBoolean
    relative: jpype.JBoolean
    copy: jpype.JBoolean

    def __init__(self, address: typing.Union[jpype.JLong, int], flags: typing.Union[jpype.JLong, int], bigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        :param jpype.JLong or int address: First of the two words in the table entry (a 32-bit address)
        :param jpype.JLong or int flags: Second of the two words in the table entry (containing several bitfields)
        :param jpype.JBoolean or bool bigEndian: True if big endian; otherwise, false
        """

    def getSymbolName(self, symtab: UnixAoutSymbolTable) -> str:
        ...

    @property
    def symbolName(self) -> java.lang.String:
        ...


class UnixAoutStringTable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, fileOffset: typing.Union[jpype.JLong, int], fileSize: typing.Union[jpype.JLong, int]):
        ...

    def markup(self, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock):
        ...

    def readString(self, stringOffset: typing.Union[jpype.JLong, int]) -> str:
        ...


class UnixAoutHeader(ghidra.app.util.bin.StructConverter):

    class AoutType(java.lang.Enum[UnixAoutHeader.AoutType]):

        class_: typing.ClassVar[java.lang.Class]
        OMAGIC: typing.Final[UnixAoutHeader.AoutType]
        NMAGIC: typing.Final[UnixAoutHeader.AoutType]
        ZMAGIC: typing.Final[UnixAoutHeader.AoutType]
        QMAGIC: typing.Final[UnixAoutHeader.AoutType]
        CMAGIC: typing.Final[UnixAoutHeader.AoutType]
        UNKNOWN: typing.Final[UnixAoutHeader.AoutType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> UnixAoutHeader.AoutType:
            ...

        @staticmethod
        def values() -> jpype.JArray[UnixAoutHeader.AoutType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, isLittleEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Interprets binary data as an exec header from a UNIX-style a.out executable, and validates 
        the contained fields.
        
        :param ghidra.app.util.bin.ByteProvider provider: Source of header binary data
        :param jpype.JBoolean or bool isLittleEndian: Flag indicating whether to interpret the data as little-endian.
        :raises IOException: if an IO-related error occurred
        """

    def getBssAddr(self) -> int:
        ...

    def getBssSize(self) -> int:
        ...

    def getCompilerSpec(self) -> str:
        """
        :return: the compiler used by this executable. This is left as 'default' for
        all machine types other than i386, where it is assumed to be gcc.
        :rtype: str
        """

    def getDataAddr(self) -> int:
        ...

    def getDataOffset(self) -> int:
        ...

    def getDataRelocOffset(self) -> int:
        ...

    def getDataRelocSize(self) -> int:
        ...

    def getDataSize(self) -> int:
        ...

    def getEntryPoint(self) -> int:
        ...

    def getExecutableType(self) -> UnixAoutHeader.AoutType:
        """
        :return: the enumerated type of executable contained in this A.out file.
        :rtype: UnixAoutHeader.AoutType
        """

    def getLanguageSpec(self) -> str:
        """
        :return: the processor/language specified by this header.
        :rtype: str
        """

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    def getStrOffset(self) -> int:
        ...

    def getStrSize(self) -> int:
        ...

    def getSymOffset(self) -> int:
        ...

    def getSymSize(self) -> int:
        ...

    def getTextAddr(self) -> int:
        ...

    def getTextOffset(self) -> int:
        ...

    def getTextRelocOffset(self) -> int:
        ...

    def getTextRelocSize(self) -> int:
        ...

    def getTextSize(self) -> int:
        ...

    def isValid(self) -> bool:
        """
        :return: an indication of whether this header's fields are all valid; this
        includes the machine type, executable type, and section offsets.
        :rtype: bool
        """

    def markup(self, program: ghidra.program.model.listing.Program, headerAddress: ghidra.program.model.address.Address):
        ...

    @property
    def bssAddr(self) -> jpype.JLong:
        ...

    @property
    def dataAddr(self) -> jpype.JLong:
        ...

    @property
    def dataOffset(self) -> jpype.JLong:
        ...

    @property
    def textSize(self) -> jpype.JLong:
        ...

    @property
    def textOffset(self) -> jpype.JLong:
        ...

    @property
    def languageSpec(self) -> java.lang.String:
        ...

    @property
    def symSize(self) -> jpype.JLong:
        ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def dataSize(self) -> jpype.JLong:
        ...

    @property
    def textRelocOffset(self) -> jpype.JLong:
        ...

    @property
    def strOffset(self) -> jpype.JLong:
        ...

    @property
    def compilerSpec(self) -> java.lang.String:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def symOffset(self) -> jpype.JLong:
        ...

    @property
    def textRelocSize(self) -> jpype.JLong:
        ...

    @property
    def dataRelocOffset(self) -> jpype.JLong:
        ...

    @property
    def bssSize(self) -> jpype.JLong:
        ...

    @property
    def executableType(self) -> UnixAoutHeader.AoutType:
        ...

    @property
    def textAddr(self) -> jpype.JLong:
        ...

    @property
    def entryPoint(self) -> jpype.JLong:
        ...

    @property
    def strSize(self) -> jpype.JLong:
        ...

    @property
    def dataRelocSize(self) -> jpype.JLong:
        ...


class UnixAoutSymbolTable(java.lang.Iterable[UnixAoutSymbol], ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, fileOffset: typing.Union[jpype.JLong, int], fileSize: typing.Union[jpype.JLong, int], strtab: UnixAoutStringTable, log: ghidra.app.util.importer.MessageLog):
        ...

    def get(self, symbolNum: typing.Union[jpype.JInt, int]) -> UnixAoutSymbol:
        ...

    def markup(self, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock):
        ...

    def size(self) -> int:
        ...


class UnixAoutRelocationTable(java.lang.Iterable[UnixAoutRelocation], ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, fileOffset: typing.Union[jpype.JLong, int], fileSize: typing.Union[jpype.JLong, int], symtab: UnixAoutSymbolTable):
        ...

    def markup(self, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock):
        ...


class UnixAoutSymbol(java.lang.Object):
    """
    Represents the content of a single entry in the symbol table format used by
    the UNIX a.out executable.
    """

    class SymbolType(java.lang.Enum[UnixAoutSymbol.SymbolType]):

        class_: typing.ClassVar[java.lang.Class]
        N_UNDF: typing.Final[UnixAoutSymbol.SymbolType]
        N_ABS: typing.Final[UnixAoutSymbol.SymbolType]
        N_TEXT: typing.Final[UnixAoutSymbol.SymbolType]
        N_DATA: typing.Final[UnixAoutSymbol.SymbolType]
        N_BSS: typing.Final[UnixAoutSymbol.SymbolType]
        N_INDR: typing.Final[UnixAoutSymbol.SymbolType]
        N_FN: typing.Final[UnixAoutSymbol.SymbolType]
        N_STAB: typing.Final[UnixAoutSymbol.SymbolType]
        UNKNOWN: typing.Final[UnixAoutSymbol.SymbolType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> UnixAoutSymbol.SymbolType:
            ...

        @staticmethod
        def values() -> jpype.JArray[UnixAoutSymbol.SymbolType]:
            ...


    class SymbolKind(java.lang.Enum[UnixAoutSymbol.SymbolKind]):

        class_: typing.ClassVar[java.lang.Class]
        AUX_FUNC: typing.Final[UnixAoutSymbol.SymbolKind]
        AUX_OBJECT: typing.Final[UnixAoutSymbol.SymbolKind]
        AUX_LABEL: typing.Final[UnixAoutSymbol.SymbolKind]
        UNKNOWN: typing.Final[UnixAoutSymbol.SymbolKind]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> UnixAoutSymbol.SymbolKind:
            ...

        @staticmethod
        def values() -> jpype.JArray[UnixAoutSymbol.SymbolKind]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    nameStringOffset: jpype.JLong
    name: java.lang.String
    type: UnixAoutSymbol.SymbolType
    kind: UnixAoutSymbol.SymbolKind
    otherByte: jpype.JByte
    desc: jpype.JShort
    value: jpype.JLong
    isExt: jpype.JBoolean

    def __init__(self, nameStringOffset: typing.Union[jpype.JLong, int], typeByte: typing.Union[jpype.JByte, int], otherByte: typing.Union[jpype.JByte, int], desc: typing.Union[jpype.JShort, int], value: typing.Union[jpype.JLong, int]):
        ...


class UnixAoutMachineType(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    M_UNKNOWN: typing.Final = 0
    M_68010: typing.Final = 1
    M_68020: typing.Final = 2
    M_SPARC: typing.Final = 3
    M_R3000: typing.Final = 4
    M_NS32032: typing.Final = 64
    M_NS32532: typing.Final = 69
    M_386: typing.Final = 100
    M_29K: typing.Final = 101
    M_386_DYNIX: typing.Final = 102
    M_ARM: typing.Final = 103
    M_SPARCLET: typing.Final = 131
    M_386_NETBSD: typing.Final = 134
    M_M68K_NETBSD: typing.Final = 135
    M_M68K4K_NETBSD: typing.Final = 136
    M_532_NETBSD: typing.Final = 137
    M_SPARC_NETBSD: typing.Final = 138
    M_PMAX_NETBSD: typing.Final = 139
    M_VAX_NETBSD: typing.Final = 140
    M_ALPHA_NETBSD: typing.Final = 141
    M_MIPS: typing.Final = 142
    M_ARM6_NETBSD: typing.Final = 143
    M_SH3: typing.Final = 145
    M_POWERPC64: typing.Final = 148
    M_POWERPC_NETBSD: typing.Final = 149
    M_VAX4K_NETBSD: typing.Final = 150
    M_MIPS1: typing.Final = 151
    M_MIPS2: typing.Final = 152
    M_88K_OPENBSD: typing.Final = 153
    M_HPPA_OPENBSD: typing.Final = 154
    M_SH5_64: typing.Final = 155
    M_SPARC64_NETBSD: typing.Final = 156
    M_X86_64_NETBSD: typing.Final = 157
    M_SH5_32: typing.Final = 158
    M_IA64: typing.Final = 159
    M_AARCH64: typing.Final = 183
    M_OR1K: typing.Final = 184
    M_RISCV: typing.Final = 185
    M_CRIS: typing.Final = 255

    def __init__(self):
        ...



__all__ = ["UnixAoutRelocation", "UnixAoutStringTable", "UnixAoutHeader", "UnixAoutSymbolTable", "UnixAoutRelocationTable", "UnixAoutSymbol", "UnixAoutMachineType"]
