from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.pdb
import ghidra.app.util.bin.format.pe
import ghidra.program.model.data
import ghidra.util
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class S_GDATA32_NEW(DebugSymbol):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DebugCodeViewConstants(java.lang.Object):
    """
    Constants defined in Code View Debug information.
    """

    class_: typing.ClassVar[java.lang.Class]
    SIGNATURE_DOT_NET: typing.Final = 21075
    SIGNATURE_N1: typing.Final = 20017
    SIGNATURE_NB: typing.Final = 20034
    VERSION_09: typing.Final = 12345
    VERSION_10: typing.Final = 12592
    VERSION_11: typing.Final = 12593
    VERSION_12: typing.Final = 12608
    VERSION_13: typing.Final = 12528
    VERSION_DOT_NET: typing.Final = 17491
    sstModule: typing.Final = 288
    sstTypes: typing.Final = 289
    sstPublic: typing.Final = 290
    sstPublicSym: typing.Final = 291
    """
    publics as symbol (waiting for link)
    """

    sstSymbols: typing.Final = 292
    sstAlignSym: typing.Final = 293
    sstSrcLnSeg: typing.Final = 294
    """
    because link doesn't emit SrcModule
    """

    sstSrcModule: typing.Final = 295
    sstLibraries: typing.Final = 296
    sstGlobalSym: typing.Final = 297
    sstGlobalPub: typing.Final = 298
    sstGlobalTypes: typing.Final = 299
    sstMPC: typing.Final = 300
    sstSegMap: typing.Final = 301
    sstSegName: typing.Final = 302
    sstPreComp: typing.Final = 303
    """
    precompiled types
    """

    sstPreCompMap: typing.Final = 304
    """
    map precompiled types in global types
    """

    sstOffsetMap16: typing.Final = 305
    sstOffsetMap32: typing.Final = 306
    sstFileIndex: typing.Final = 307
    """
    Index of file names
    """

    sstStaticSym: typing.Final = 308
    S_COMPILE: typing.Final = 1
    """
    Compile flags symbol
    """

    S_REGISTER: typing.Final = 2
    """
    Register variable
    """

    S_CONSTANT: typing.Final = 3
    """
    Constant symbol
    """

    S_UDT: typing.Final = 4
    """
    User defined type
    """

    S_SSEARCH: typing.Final = 5
    """
    Start Search
    """

    S_END: typing.Final = 6
    """
    Block, procedure, "with" or thunk end
    """

    S_SKIP: typing.Final = 7
    """
    Reserve symbol space in $$Symbols table
    """

    S_CVRESERVE: typing.Final = 8
    """
    Reserved symbol for CV internal use
    """

    S_OBJNAME: typing.Final = 9
    """
    Path to object file name
    """

    S_ENDARG: typing.Final = 10
    """
    End of argument/return list
    """

    S_COBOLUDT: typing.Final = 11
    """
    SApecial UDT for cobol that does not symbol pack
    """

    S_MANYREG: typing.Final = 12
    """
    multiple register variable
    """

    S_RETURN: typing.Final = 13
    """
    Return description symbol
    """

    S_ENTRYTHIS: typing.Final = 14
    """
    Description of this pointer on entry
    """

    S_BPREL16: typing.Final = 256
    """
    BP-relative
    """

    S_LDATA16: typing.Final = 257
    """
    Module-local symbol
    """

    S_GDATA16: typing.Final = 258
    """
    Global data symbol
    """

    S_PUB16: typing.Final = 259
    """
    a public symbol
    """

    S_LPROC16: typing.Final = 260
    """
    Local procedure start
    """

    S_GPROC16: typing.Final = 261
    """
    Global procedure start
    """

    S_THUNK16: typing.Final = 262
    """
    Thunk Start
    """

    S_BLOCK16: typing.Final = 263
    """
    block start
    """

    S_WITH16: typing.Final = 264
    """
    With start
    """

    S_LABEL16: typing.Final = 265
    """
    Code label
    """

    S_CEXMODEL16: typing.Final = 266
    """
    Change execution model
    """

    S_VFTABLE16: typing.Final = 267
    """
    Address of virtual function table
    """

    S_REGREL16: typing.Final = 268
    """
    Register relative address
    """

    S_BPREL32: typing.Final = 512
    """
    BP-relative
    """

    S_LDATA32: typing.Final = 513
    """
    Module-local symbol
    """

    S_GDATA32: typing.Final = 514
    """
    Global data symbol
    """

    S_PUB32: typing.Final = 515
    """
    a public symbol (CV internal reserved)
    """

    S_LPROC32: typing.Final = 516
    """
    Local procedure start
    """

    S_GPROC32: typing.Final = 517
    """
    Global procedure start
    """

    S_THUNK32: typing.Final = 518
    """
    Thunk Start
    """

    S_BLOCK32: typing.Final = 519
    """
    block start
    """

    S_WITH32: typing.Final = 520
    """
    with start
    """

    S_LABEL32: typing.Final = 521
    """
    code label
    """

    S_CEXMODEL32: typing.Final = 522
    """
    change execution model
    """

    S_VFTABLE32: typing.Final = 523
    """
    address of virtual function table
    """

    S_REGREL32: typing.Final = 524
    """
    register relative address
    """

    S_LTHREAD32: typing.Final = 525
    """
    local thread storage
    """

    S_GTHREAD32: typing.Final = 526
    """
    global thread storage
    """

    S_SLINK32: typing.Final = 527
    """
    static link for MIPS EH implementation
    """

    S_LPROCMIPS: typing.Final = 768
    """
    Local procedure start
    """

    S_GPROCMIPS: typing.Final = 769
    """
    Global procedure start
    """

    S_PROCREF: typing.Final = 1024
    """
    Reference to a procedure
    """

    S_DATAREF: typing.Final = 1025
    """
    Reference to data
    """

    S_ALIGN: typing.Final = 1026
    """
    Used for page alignment of symbol
    """

    S_LPROCREF: typing.Final = 1027
    """
    Maybe reference to a local procedure
    """

    S_REGISTER32: typing.Final = 4097
    """
    Register variable
    """

    S_CONSTANT32: typing.Final = 4098
    """
    Constant symbol
    """

    S_UDT32: typing.Final = 4099
    """
    User defined type
    """

    S_COBOLUDT32: typing.Final = 4100
    """
    special UDT for cobol that does not symbol pack
    """

    S_MANYREG32: typing.Final = 4101
    """
    Multiple register variable
    """

    S_BPREL32_NEW: typing.Final = 4102
    """
    New CV info for BP-relative
    """

    S_LDATA32_NEW: typing.Final = 4103
    """
    New CV info for module-local symbol
    """

    S_GDATA32_NEW: typing.Final = 4104
    """
    New CV info for global data symbol
    """

    S_PUBSYM32_NEW: typing.Final = 4105
    """
    Newer CV info, defined after 1994
    """

    S_LPROC32_NEW: typing.Final = 4106
    """
    New CV info for reference to a local procedure
    """

    S_GPROC32_NEW: typing.Final = 4107
    """
    New CV info for global procedure start
    """

    S_VFTABLE32_NEW: typing.Final = 4108
    """
    New CV info for address of virtual function table
    """

    S_REGREL32_NEW: typing.Final = 4109
    """
    New CV info for register relative address
    """

    S_LTHREAD32_NEW: typing.Final = 4110
    """
    New CV info for local thread storage
    """

    S_GTHREAD32_NEW: typing.Final = 4111
    """
    New CV info for global thread storage
    """



@typing.type_check_only
class OMFDirHeader(java.lang.Object):
    """
    
    typedef struct OMFDirHeader {
        unsigned short cbDirHeader; // length of this structure unsigned           
                short cbDirEntry;  // number of bytes in each directory entry 
        unsigned long  cDir;        // number of directorie entries 
                long lfoNextDir;   // offset from base of next directory 
        unsigned long flags;        // status flags
    } OMFDirHeader;
    """

    class_: typing.ClassVar[java.lang.Class]


class OMFGlobal(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) Global data structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddrHash(self) -> int:
        ...

    def getCbAddrHash(self) -> int:
        ...

    def getCbSymHash(self) -> int:
        ...

    def getCbSymbol(self) -> int:
        ...

    def getSymHash(self) -> int:
        ...

    def getSymbols(self) -> java.util.List[DebugSymbol]:
        """
        Returns the debug symbols in this OMF Global.
        
        :return: the debug symbols in this OMF Global
        :rtype: java.util.List[DebugSymbol]
        """

    @property
    def addrHash(self) -> jpype.JShort:
        ...

    @property
    def cbSymbol(self) -> jpype.JInt:
        ...

    @property
    def symHash(self) -> jpype.JShort:
        ...

    @property
    def cbAddrHash(self) -> jpype.JInt:
        ...

    @property
    def cbSymHash(self) -> jpype.JInt:
        ...

    @property
    def symbols(self) -> java.util.List[DebugSymbol]:
        ...


@typing.type_check_only
class S_UDT32(DebugSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def getChecksum(self) -> int:
        ...

    @property
    def checksum(self) -> jpype.JInt:
        ...


class DebugCOFFLineNumber(java.lang.Object):
    """
    A class to represent the COFF Line number data structure.
     
    
     
    typedef struct _IMAGE_LINENUMBER {
        union {
            DWORD   SymbolTableIndex; // Symbol table index of function name if Linenumber is 0.
            DWORD   VirtualAddress;   // Virtual address of line number.
        } Type;
        WORD    Linenumber;           // Line number.
    } IMAGE_LINENUMBER;
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SIZEOF_LINENUMBER: typing.Final = 6
    """
    The size of the ``IMAGE_LINENUMBER`` structure.
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int]):
        ...

    def getLineNumber(self) -> int:
        """
        Returns the line number.
        
        :return: the line number
        :rtype: int
        """

    def getSymbolTableIndex(self) -> int:
        """
        Returns the symbol table index of function name, if linenumber is 0.
        
        :return: the symbol table index of function name, if linenumber is 0
        :rtype: int
        """

    def getVirtualAddress(self) -> int:
        """
        Returns the virtual address of the line number.
        
        :return: the virtual address of the line number
        :rtype: int
        """

    @property
    def virtualAddress(self) -> jpype.JInt:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def symbolTableIndex(self) -> jpype.JInt:
        ...


class DebugFixup(java.lang.Object):
    """
    A possible implementation of the FIXUP debug directory. 
    It may be inaccurate and/or incomplete.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDebugFixupElements(self) -> jpype.JArray[DebugFixupElement]:
        """
        Returns the array of FIXUP elements associated with this fixup debug directory.
        
        :return: the array of FIXUP elements associated with this fixup debug directory
        :rtype: jpype.JArray[DebugFixupElement]
        """

    @property
    def debugFixupElements(self) -> jpype.JArray[DebugFixupElement]:
        ...


@typing.type_check_only
class S_DATAREF(DebugSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def getChecksum(self) -> int:
        ...

    @property
    def checksum(self) -> jpype.JInt:
        ...


class DebugCodeViewSymbolTable(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the Object Module Format (OMF)
    code view symbol table.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAGIC_NB_09: typing.Final = 1312960569
    MAGIC_NB_11: typing.Final = 1312960817
    MAGIC_N1_12: typing.Final = 1311846720
    MAGIC_N1_13: typing.Final = 1311846640

    def getMagic(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getOMFAlignSym(self) -> java.util.List[OMFAlignSym]:
        """
        Returns the OMF Align Symbols.
        
        :return: the OMF Align Symbols
        :rtype: java.util.List[OMFAlignSym]
        """

    def getOMFDirectoryEntries(self) -> java.util.List[OMFDirEntry]:
        """
        Returns the OMF directory entries.
        
        :return: the OMF directory entries
        :rtype: java.util.List[OMFDirEntry]
        """

    def getOMFFiles(self) -> java.util.List[OMFFileIndex]:
        """
        Returns the OMF Source Files.
        
        :return: the OMF Source Files
        :rtype: java.util.List[OMFFileIndex]
        """

    def getOMFGlobals(self) -> java.util.List[OMFGlobal]:
        """
        Returns the OMF globals.
        
        :return: the OMF globals
        :rtype: java.util.List[OMFGlobal]
        """

    def getOMFLibrary(self) -> OMFLibrary:
        ...

    def getOMFModules(self) -> java.util.List[OMFModule]:
        """
        Returns the OMF modules.
        
        :return: the OMF modules
        :rtype: java.util.List[OMFModule]
        """

    def getOMFSegMaps(self) -> java.util.List[OMFSegMap]:
        """
        Returns the OMF segment maps.
        
        :return: the OMF segment maps
        :rtype: java.util.List[OMFSegMap]
        """

    def getOMFSrcModules(self) -> java.util.List[OMFSrcModule]:
        """
        Returns the OMF Source Modules.
        
        :return: the OMF Source Modules
        :rtype: java.util.List[OMFSrcModule]
        """

    @staticmethod
    def isMatch(reader: ghidra.app.util.bin.BinaryReader, ptr: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.bin.StructConverter.toDataType()`
        """

    @property
    def magic(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def oMFLibrary(self) -> OMFLibrary:
        ...

    @property
    def oMFAlignSym(self) -> java.util.List[OMFAlignSym]:
        ...

    @property
    def oMFGlobals(self) -> java.util.List[OMFGlobal]:
        ...

    @property
    def oMFSegMaps(self) -> java.util.List[OMFSegMap]:
        ...

    @property
    def oMFSrcModules(self) -> java.util.List[OMFSrcModule]:
        ...

    @property
    def oMFModules(self) -> java.util.List[OMFModule]:
        ...

    @property
    def oMFFiles(self) -> java.util.List[OMFFileIndex]:
        ...

    @property
    def oMFDirectoryEntries(self) -> java.util.List[OMFDirEntry]:
        ...


class S_GPROC32_NEW(DebugSymbol):
    """
    A class to represent the S_GPROC32_NEW data structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDebugEnd(self) -> int:
        ...

    def getDebugStart(self) -> int:
        ...

    def getEnd(self) -> int:
        ...

    def getNext(self) -> int:
        ...

    def getParent(self) -> int:
        ...

    def getProcLen(self) -> int:
        """
        Returns the procedure length.
        
        :return: the procedure length
        :rtype: int
        """

    def getProcOffset(self) -> int:
        """
        Returns the procedure offset.
        
        :return: the procedure offset
        :rtype: int
        """

    def getProcType(self) -> int:
        """
        Returns the procedure type.
        
        :return: the procedure type
        :rtype: int
        """

    @property
    def next(self) -> jpype.JInt:
        ...

    @property
    def parent(self) -> jpype.JInt:
        ...

    @property
    def procLen(self) -> jpype.JInt:
        ...

    @property
    def debugStart(self) -> jpype.JInt:
        ...

    @property
    def end(self) -> jpype.JInt:
        ...

    @property
    def procOffset(self) -> jpype.JInt:
        ...

    @property
    def debugEnd(self) -> jpype.JInt:
        ...

    @property
    def procType(self) -> jpype.JShort:
        ...


@typing.type_check_only
class DataSym32_new(DebugSymbol):
    """
    
    typedef struct DATASYM32_NEW {
        unsigned short  reclen;         // Record length
        unsigned short  rectyp;         // S_LDATA32, S_GDATA32 or S_PUB32
        CVTYPEINDEX     typind;
        unsigned long   off;
        unsigned short  seg;
        unsigned char   name[1];        // Length-prefixed name
    } DATASYM32_NEW;
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class S_LABEL32(DebugSymbol):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DebugMisc(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the ``IMAGE_DEBUG_MISC`` struct
    as defined in **``winnt.h``**.
     
    
     
     
    typedef struct _IMAGE_DEBUG_MISC {
        DWORD       DataType;               // type of misc data, see defines
        DWORD       Length;                 // total length of record, rounded to four
                                            // byte multiple.
        BOOLEAN     Unicode;                // TRUE if data is unicode string
        BYTE        Reserved[ 3 ];
        BYTE        Data[ 1 ];              // Actual data
    }
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_DEBUG_MISC"
    """
    The name to use when converting into a structure data type.
    """


    def getActualData(self) -> str:
        """
        Returns a string equivalent of the actual misc debug data.
        
        :return: a string equivalent of the actual misc debug data
        :rtype: str
        """

    def getDataType(self) -> int:
        """
        Returns the data type of this misc debug.
        
        :return: the data type of this misc debug
        :rtype: int
        """

    def getDebugDirectory(self) -> DebugDirectory:
        """
        Returns the debug directory associated with this misc debug.
        
        :return: the debug directory associated with this misc debug
        :rtype: DebugDirectory
        """

    def getLength(self) -> int:
        """
        Returns the length of this misc debug.
        
        :return: the length of this misc debug
        :rtype: int
        """

    def getReserved(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the array of reserved bytes.
        
        :return: the array of reserved bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    def isUnicode(self) -> bool:
        """
        Returns true if this misc debug is unicode.
        
        :return: true if this misc debug is unicode
        :rtype: bool
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.bin.StructConverter.toDataType()`
        """

    @property
    def debugDirectory(self) -> DebugDirectory:
        ...

    @property
    def reserved(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def dataType(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def unicode(self) -> jpype.JBoolean:
        ...

    @property
    def actualData(self) -> java.lang.String:
        ...


@typing.type_check_only
class S_BLOCK32(DebugSymbol):
    ...
    class_: typing.ClassVar[java.lang.Class]


class OMFFileIndex(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) File Index data structure.
     
    
     
    short cMod          - Count or number of modules in the executable.
    short cRef          - Count or number of file name references.
    short [] modStart - array of indices into the nameoffset table for each module.  Each index is the start of the file name references for each module.
    short cRefCnt      - number of file name references per module.
    int [] nameRef      - array of offsets in to the names table.  For each module the offset to the first references file name is at nameRef[modStart] and continues for cRefCnt entries.
    String names      - file names.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCMod(self) -> int:
        """
        Returns the number of modules in the executable.
        
        :return: the number of modules in the executable
        :rtype: int
        """

    def getCRef(self) -> int:
        """
        Returns the number of file name references in the executable.
        
        :return: the number of file name references in the executable
        :rtype: int
        """

    def getCRefCnt(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns the indices into the nameoffset table for each file.
        
        :return: the indices into the nameoffset table for each file
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getModStart(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns the array of indices into the nameoffset table for each module.
        
        :return: the array of indices into the nameoffset table for each module
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getNameRef(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the array of offsets into the names table.
        
        :return: the array of offsets in to the names table
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the file names referenced in the executable.
        
        :return: the file names referenced in the executable
        :rtype: jpype.JArray[java.lang.String]
        """

    @property
    def modStart(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def cMod(self) -> jpype.JShort:
        ...

    @property
    def names(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def nameRef(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def cRefCnt(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def cRef(self) -> jpype.JShort:
        ...


class DebugCOFFSymbolsHeader(java.lang.Object):
    """
    A class to represent the COFF Symbols Header.
     
    
     
    typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
    DWORD   NumberOfSymbols;
    DWORD   LvaToFirstSymbol;
    DWORD   NumberOfLinenumbers;
    DWORD   LvaToFirstLinenumber;
    DWORD   RvaToFirstByteOfCode;
    DWORD   RvaToLastByteOfCode;
    DWORD   RvaToFirstByteOfData;
    DWORD   RvaToLastByteOfData;
    } IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFirstByteOfCodeRVA(self) -> int:
        """
        Returns the RVA of the first code byte.
        
        :return: the RVA of the first code byte
        :rtype: int
        """

    def getFirstByteOfDataRVA(self) -> int:
        """
        Returns the RVA of the first data byte.
        
        :return: the RVA of the first data byte
        :rtype: int
        """

    def getFirstLinenumberLVA(self) -> int:
        """
        Returns the LVA of the first line number.
        
        :return: the LVA of the first line number
        :rtype: int
        """

    def getFirstSymbolLVA(self) -> int:
        """
        Returns the LVA of the first symbol.
        
        :return: the LVA of the first symbol
        :rtype: int
        """

    def getLastByteOfCodeRVA(self) -> int:
        """
        Returns the RVA of the last code byte.
        
        :return: the RVA of the last code byte
        :rtype: int
        """

    def getLastByteOfDataRVA(self) -> int:
        """
        Returns the RVA of the last data byte.
        
        :return: the RVA of the last data byte
        :rtype: int
        """

    def getLineNumbers(self) -> jpype.JArray[DebugCOFFLineNumber]:
        """
        Returns the COFF line numbers.
        
        :return: the COFF line numbers
        :rtype: jpype.JArray[DebugCOFFLineNumber]
        """

    def getNumberOfLinenumbers(self) -> int:
        """
        Returns the number of line numbers in this header.
        
        :return: the number of line numbers in this header
        :rtype: int
        """

    def getNumberOfSymbols(self) -> int:
        """
        Returns the number of symbols in this header.
        
        :return: the number of symbols in this header
        :rtype: int
        """

    def getSymbolTable(self) -> DebugCOFFSymbolTable:
        """
        Returns the COFF symbol table.
        
        :return: the COFF symbol table
        :rtype: DebugCOFFSymbolTable
        """

    @property
    def lastByteOfCodeRVA(self) -> jpype.JInt:
        ...

    @property
    def lineNumbers(self) -> jpype.JArray[DebugCOFFLineNumber]:
        ...

    @property
    def lastByteOfDataRVA(self) -> jpype.JInt:
        ...

    @property
    def symbolTable(self) -> DebugCOFFSymbolTable:
        ...

    @property
    def firstLinenumberLVA(self) -> jpype.JInt:
        ...

    @property
    def firstSymbolLVA(self) -> jpype.JInt:
        ...

    @property
    def numberOfSymbols(self) -> jpype.JInt:
        ...

    @property
    def firstByteOfDataRVA(self) -> jpype.JInt:
        ...

    @property
    def numberOfLinenumbers(self) -> jpype.JInt:
        ...

    @property
    def firstByteOfCodeRVA(self) -> jpype.JInt:
        ...


class OMFSegMapDesc(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) Segment Mapping Descriptor data structure.
     
    
     
    typedef struct OMFSegMapDesc {
        unsigned short  flags;       // descriptor flags bit field
        unsigned short  ovl;         // the logical overlay number
        unsigned short  group;       // group index into the descriptor array
        unsigned short  frame;       // logical segment index - interpreted via flags
        unsigned short  iSegName;    // segment or group name - index into sstSegName
        unsigned short  iClassName;  // class name - index into sstSegName
        unsigned long   offset;      // byte offset of the logical within the physical segment
        unsigned long   cbSeg;       // byte count of the logical segment or group
    } OMFSegMapDesc;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getByteCount(self) -> int:
        """
        Returns the byte count of the logical segment or group.
        
        :return: the byte count of the logical segment or group
        :rtype: int
        """

    def getByteOffset(self) -> int:
        """
        Returns the byte offset of the logical within the physical segment.
        
        :return: the byte offset of the logical within the physical segment
        :rtype: int
        """

    def getClassName(self) -> int:
        """
        Returns the class name - index into sstSegName.
        
        :return: the class name - index into sstSegName
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        Returns the descriptor flags bit field.
        
        :return: the descriptor flags bit field
        :rtype: int
        """

    def getGroupIndex(self) -> int:
        """
        Returns the group index into the descriptor array.
        
        :return: the group index into the descriptor array
        :rtype: int
        """

    def getLogicalOverlayNumber(self) -> int:
        """
        Returns the logical overlay number.
        
        :return: the logical overlay number
        :rtype: int
        """

    def getLogicalSegmentIndex(self) -> int:
        """
        Returns the logical segment index - interpreted via flags.
        
        :return: the logical segment index - interpreted via flags
        :rtype: int
        """

    def getSegmentName(self) -> int:
        """
        Returns the segment or group name - index into sstSegName.
        
        :return: the segment or group name - index into sstSegName
        :rtype: int
        """

    @property
    def logicalSegmentIndex(self) -> jpype.JShort:
        ...

    @property
    def logicalOverlayNumber(self) -> jpype.JShort:
        ...

    @property
    def byteOffset(self) -> jpype.JInt:
        ...

    @property
    def byteCount(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JShort:
        ...

    @property
    def className(self) -> jpype.JShort:
        ...

    @property
    def groupIndex(self) -> jpype.JShort:
        ...

    @property
    def segmentName(self) -> jpype.JShort:
        ...


class DebugDirectoryParser(ghidra.app.util.bin.format.pe.OffsetValidator):
    """
    A helper class to parsing different types of 
    debug information from a debug directory
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_DEBUG_TYPE_UNKNOWN: typing.Final = 0
    """
    Unknown debug type.
    """

    IMAGE_DEBUG_TYPE_COFF: typing.Final = 1
    """
    COFF debug type.
    """

    IMAGE_DEBUG_TYPE_CODEVIEW: typing.Final = 2
    """
    CodeView debug type.
    """

    IMAGE_DEBUG_TYPE_FPO: typing.Final = 3
    """
    FPO debug type.
    """

    IMAGE_DEBUG_TYPE_MISC: typing.Final = 4
    """
    Misc debug type.
    """

    IMAGE_DEBUG_TYPE_EXCEPTION: typing.Final = 5
    """
    Exception debug type.
    """

    IMAGE_DEBUG_TYPE_FIXUP: typing.Final = 6
    """
    Fixup debug type.
    """

    IMAGE_DEBUG_TYPE_OMAP_TO_SRC: typing.Final = 7
    """
    OMAP-To-Source debug type.
    """

    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: typing.Final = 8
    """
    OMAP-From-Source debug type.
    """

    IMAGE_DEBUG_TYPE_BORLAND: typing.Final = 9
    """
    Borland debug type.
    """

    IMAGE_DEBUG_TYPE_RESERVED10: typing.Final = 10
    """
    Reserved debug type.
    """

    IMAGE_DEBUG_TYPE_CLSID: typing.Final = 11
    """
    CLS ID debug type.
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, ptr: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], sizeOfImage: typing.Union[jpype.JLong, int]):
        """
        Constructs a new debug directory parser.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :param jpype.JLong or int ptr: the pointer into the binary reader
        :param jpype.JInt or int size: the size of the directory
        :param jpype.JLong or int sizeOfImage: the size of the image in memory
        :raises IOException: if an I/O error occurs
        """

    def getDebugCOFFSymbolsHeader(self) -> DebugCOFFSymbolsHeader:
        """
        Returns the COFF debug information, or null if it does not exists.
        
        :return: the COFF debug information
        :rtype: DebugCOFFSymbolsHeader
        """

    def getDebugCodeView(self) -> DebugCodeView:
        """
        Returns the CodeView debug information, or null if it does not exists.
        
        :return: the CodeView debug information
        :rtype: DebugCodeView
        """

    def getDebugDirectories(self) -> jpype.JArray[DebugDirectory]:
        ...

    def getDebugFixup(self) -> DebugFixup:
        """
        Returns the Fixup debug information, or null if it does not exists.
        
        :return: the Fixup debug information
        :rtype: DebugFixup
        """

    def getDebugMisc(self) -> DebugMisc:
        """
        Returns the miscellaneous debug information, or null if it does not exists.
        
        :return: the miscellaneous debug information
        :rtype: DebugMisc
        """

    @property
    def debugDirectories(self) -> jpype.JArray[DebugDirectory]:
        ...

    @property
    def debugCOFFSymbolsHeader(self) -> DebugCOFFSymbolsHeader:
        ...

    @property
    def debugMisc(self) -> DebugMisc:
        ...

    @property
    def debugFixup(self) -> DebugFixup:
        ...

    @property
    def debugCodeView(self) -> DebugCodeView:
        ...


class DebugCodeView(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the code view debug information.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDebugDirectory(self) -> DebugDirectory:
        """
        Returns the code view debug directory.
        
        :return: the code view debug directory
        :rtype: DebugDirectory
        """

    def getDotNetPdbInfo(self) -> ghidra.app.util.bin.format.pdb.PdbInfoDotNet:
        ...

    def getPdbInfo(self) -> ghidra.app.util.bin.format.pdb.PdbInfoCodeView:
        """
        Returns the code view .PDB info.
        
        :return: the code view .PDB info
        :rtype: ghidra.app.util.bin.format.pdb.PdbInfoCodeView
        """

    def getSymbolTable(self) -> DebugCodeViewSymbolTable:
        """
        Returns the code view symbol table.
        
        :return: the code view symbol table
        :rtype: DebugCodeViewSymbolTable
        """

    @property
    def debugDirectory(self) -> DebugDirectory:
        ...

    @property
    def symbolTable(self) -> DebugCodeViewSymbolTable:
        ...

    @property
    def dotNetPdbInfo(self) -> ghidra.app.util.bin.format.pdb.PdbInfoDotNet:
        ...

    @property
    def pdbInfo(self) -> ghidra.app.util.bin.format.pdb.PdbInfoCodeView:
        ...


class DebugCOFFSymbolTable(java.lang.Object):
    """
    A class to represent the COFF Symbol Table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, coffHeader: DebugCOFFSymbolsHeader, offset: typing.Union[jpype.JInt, int]):
        ...

    def getSymbols(self) -> java.util.List[DebugCOFFSymbol]:
        """
        :return: the COFF symbols defined in this COFF symbol table
        :rtype: java.util.List[DebugCOFFSymbol]
        """

    @property
    def symbols(self) -> java.util.List[DebugCOFFSymbol]:
        ...


@typing.type_check_only
class S_OBJNAME(DebugSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def getNameLen(self) -> int:
        ...

    def getPadding(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getSignature(self) -> int:
        ...

    @property
    def padding(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def signature(self) -> jpype.JInt:
        ...

    @property
    def nameLen(self) -> jpype.JByte:
        ...


@typing.type_check_only
class S_CONSTANT32(DebugSymbol):
    ...
    class_: typing.ClassVar[java.lang.Class]


class OMFAlignSym(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) alignment symbol.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPad(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the alignment padding bytes.
        
        :return: the alignment padding bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    @property
    def pad(self) -> jpype.JArray[jpype.JByte]:
        ...


class DebugFixupElement(java.lang.Object):
    """
    A possible implementation of the FIXUP debug directory elements. 
    It may be inaccurate and/or incomplete.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress1(self) -> int:
        """
        Returns the first address of this FIXUP element.
        
        :return: the first address of this FIXUP element
        :rtype: int
        """

    def getAddress2(self) -> int:
        """
        Returns the second address of this FIXUP element.
        
        :return: the second address of this FIXUP element
        :rtype: int
        """

    def getType(self) -> int:
        """
        Returns the FIXUP element type.
        
        :return: the FIXUP element type
        :rtype: int
        """

    @property
    def address2(self) -> jpype.JInt:
        ...

    @property
    def address1(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...


class DebugCOFFSymbolAux(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the COFF Auxiliary Symbol data structure.
     
    
     
    typedef union _IMAGE_AUX_SYMBOL {
        struct {
            DWORD    TagIndex;                      // struct, union, or enum tag index
            union {
                struct {
                    WORD    Linenumber;             // declaration line number
                    WORD    Size;                   // size of struct, union, or enum
                } LnSz;
                DWORD    TotalSize;
            }Misc;
            union {
                struct {                            // if ISFCN, tag, or .bb
                    DWORD    PointerToLinenumber;
                    DWORD    PointerToNextFunction;
                } Function;
                struct {                            // if ISARY, up to 4 dimen.
                    WORD     Dimension[4];
                } Array;
            } FcnAry;
            WORD    TvIndex;                        // tv index
        } Sym;
        struct {
            BYTE    Name[IMAGE_SIZEOF_SYMBOL];
        } File;
        struct {
            DWORD   Length;                         // section length
            WORD    NumberOfRelocations;            // number of relocation entries
            WORD    NumberOfLinenumbers;            // number of line numbers
            DWORD   CheckSum;                       // checksum for communal
            SHORT   Number;                         // section number to associate with
            BYTE    Selection;                      // communal selection type
        } Section;
    } IMAGE_AUX_SYMBOL;
    """

    class AuxSym(ghidra.app.util.bin.StructConverter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class AuxFile(ghidra.app.util.bin.StructConverter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class AuxSection(ghidra.app.util.bin.StructConverter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SIZEOF_AUX_SYMBOL: typing.Final = 18


class OMFLibrary(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) Library data structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLibraries(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the array of library names.
        
        :return: the array of library name
        :rtype: jpype.JArray[java.lang.String]
        """

    @property
    def libraries(self) -> jpype.JArray[java.lang.String]:
        ...


@typing.type_check_only
class S_COMPILE(DebugSymbol):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class S_END(DebugSymbol):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class S_LDATA32_NEW(DebugSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def getPadding(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getReserved(self) -> int:
        ...

    @property
    def padding(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...


class OMFSrcModuleFile(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) Source Module File data structure. 
     
    
    This class describes the code segments that receive code from a source file.
     
    
    short cSeg         - Number of segments that receive code from the source file.
     
    
    short pad         - pad field to maintain alignment
     
    
    int [] baseSrcLn - array of offsets for the line or address mapping for each segment that receives code from the source file.
     
    
    int [] starts     - starting addresses within the segment of the first byte of code from the module.
     
    
    int [] ends         - ending addresses of the code from the module.
     
    
    byte cbName         - count or number of bytes in source file name.
     
    
    String name         - name of source file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBaseSrcLn(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns an array of offsets for the line or address mapping for each segment 
        that receives code from the source file.
        
        :return: an array of offsets for the line or address mapping for each segment
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getEnds(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the ending addresses of the code from the module.
        
        :return: the ending addresses of the code from the module
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getName(self) -> str:
        """
        Returns the name of source file.
        
        :return: the name of source file
        :rtype: str
        """

    def getOMFSrcModuleLines(self) -> jpype.JArray[OMFSrcModuleLine]:
        """
        Returns an array of the source module lines.
        
        :return: an array of the source module lines
        :rtype: jpype.JArray[OMFSrcModuleLine]
        """

    def getPad(self) -> int:
        """
        Returns the pad field to maintain alignment.
        
        :return: the pad field to maintain alignment
        :rtype: int
        """

    def getSegmentCount(self) -> int:
        """
        Returns the number of segments that receive code from the source file.
        
        :return: the number of segments that receive code from the source file
        :rtype: int
        """

    def getStarts(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the starting addresses within the segment of the first byte of code from the module.
        
        :return: the starting addresses within the segment of the first byte of code from the module
        :rtype: jpype.JArray[jpype.JInt]
        """

    @property
    def pad(self) -> jpype.JShort:
        ...

    @property
    def baseSrcLn(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def ends(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def starts(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def oMFSrcModuleLines(self) -> jpype.JArray[OMFSrcModuleLine]:
        ...

    @property
    def segmentCount(self) -> jpype.JShort:
        ...


@typing.type_check_only
class DataSym32(DebugSymbol):
    """
    
    typedef struct DATASYM32 {
        unsigned short  reclen;         // Record length
        unsigned short  rectyp;         // S_LDATA32, S_GDATA32 or S_PUB32
        CV_uoff32_t     off;            // (unsigned long)
        unsigned short  seg;
        CV_typ_t        typind;         // Type index (unsigned short)
        unsigned char   name[1];        // Length-prefixed name
    } DATASYM32;
    """

    class_: typing.ClassVar[java.lang.Class]


class OMFSrcModule(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) Source Module data structure.
     
    
    short cFile           - Number of source files contributing code to segments
     
    
    short cSeg          - Number of code segments receiving code from module
     
    
    int [] baseSrcFile -  An array of base offsets
     
    
    int [] starts       - start offset within the segment of the first byte of code from the module
     
    
    int [] ends        - ending address of code from the module
     
    
    short [] segs      - Array of segment indicies that receive code from the module
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBaseSrcFile(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns an array of base offsets.
        
        :return: an array of base offsets
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getEnds(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns an array of ending addresses of code from the module.
        
        :return: an array of ending addresses of code from the module
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getFileCount(self) -> int:
        """
        Returns the number of source files contributing code to segments.
        
        :return: the number of source files contributing code to segments
        :rtype: int
        """

    def getOMFSrcModuleFiles(self) -> jpype.JArray[OMFSrcModuleFile]:
        """
        Returns the array of source files.
        
        :return: the array of source files
        :rtype: jpype.JArray[OMFSrcModuleFile]
        """

    def getSegmentCount(self) -> int:
        """
        Returns the number of code segments receiving code from module.
        
        :return: the number of code segments receiving code from module
        :rtype: int
        """

    def getSegments(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns an array of segment indicies that receive code from the module.
        
        :return: an array of segment indicies that receive code from the module
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getStarts(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns an array of start offsets within the segment of the first byte of code from the module.
        
        :return: an array of start offsets within the segment of the first byte of code from the module
        :rtype: jpype.JArray[jpype.JInt]
        """

    @property
    def ends(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def oMFSrcModuleFiles(self) -> jpype.JArray[OMFSrcModuleFile]:
        ...

    @property
    def baseSrcFile(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def starts(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def fileCount(self) -> jpype.JShort:
        ...

    @property
    def segmentCount(self) -> jpype.JShort:
        ...

    @property
    def segments(self) -> jpype.JArray[jpype.JShort]:
        ...


class OMFSrcModuleLine(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) Source Module Line data structure.
     
    
    short seg            - segment index.
     
    
    short cPair          - Count or number of source line pairs to follow.
     
    
    int [] offsets       - offset within the code segment of the start of the line.
     
    
    short [] linenumbers - line numbers that are in the source file that cause code to be emitted to the code segment.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLinenumbers(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns the line numbers that are in the source file that cause code to be emitted to the code segment.
        
        :return: the line numbers that are in the source file that cause code to be emitted to the code segment
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getOffsets(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the offset within the code segment of the start of the line.
        
        :return: the offset within the code segment of the start of the line
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getPairCount(self) -> int:
        """
        Returns the count or number of source line pairs to follow.
        
        :return: the count or number of source line pairs to follow
        :rtype: int
        """

    def getSegmentIndex(self) -> int:
        """
        Returns the segment index.
        
        :return: the segment index
        :rtype: int
        """

    @property
    def offsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def pairCount(self) -> jpype.JShort:
        ...

    @property
    def segmentIndex(self) -> jpype.JShort:
        ...

    @property
    def linenumbers(self) -> jpype.JArray[jpype.JShort]:
        ...


class OMFSegMap(java.lang.Object):
    """
    
    typedef struct OMFSegMap {
        unsigned short  cSeg;        // total number of segment descriptors
        unsigned short  cSegLog;     // number of logical segment descriptors
        OMFSegMapDesc   rgDesc[0];   // array of segment descriptors
    };
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLogicalSegmentDescriptorCount(self) -> int:
        """
        Returns the number of logical segment descriptors.
        
        :return: the number of logical segment descriptors
        :rtype: int
        """

    def getSegmentDescriptor(self) -> jpype.JArray[OMFSegMapDesc]:
        """
        Returns the array of segment descriptors.
        
        :return: the array of segment descriptors
        :rtype: jpype.JArray[OMFSegMapDesc]
        """

    def getSegmentDescriptorCount(self) -> int:
        """
        Returns the total number of segment descriptors.
        
        :return: the total number of segment descriptors
        :rtype: int
        """

    @property
    def segmentDescriptor(self) -> jpype.JArray[OMFSegMapDesc]:
        ...

    @property
    def logicalSegmentDescriptorCount(self) -> jpype.JShort:
        ...

    @property
    def segmentDescriptorCount(self) -> jpype.JShort:
        ...


class OMFSegDesc(java.lang.Object):
    """
    A class to represent the Object Module Format (OMF) Segment Descriptor data structure.
    Information describing each segment in a module.
     
    
     
    typedef struct OMFSegDesc {
        unsigned short  Seg;            // segment index
        unsigned short  pad;            // pad to maintain alignment
        unsigned long   Off;            // offset of code in segment
        unsigned long   cbSeg;          // number of bytes in segment
    } OMFSegDesc;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAlignmentPad(self) -> int:
        """
        Returns the pad to maintain alignment.
        
        :return: the pad to maintain alignment
        :rtype: int
        """

    def getNumberOfBytes(self) -> int:
        """
        Returns the number of bytes in segment.
        
        :return: the number of bytes in segment
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Returns the offset of code in segment.
        
        :return: the offset of code in segment
        :rtype: int
        """

    def getSegmentIndex(self) -> int:
        """
        Returns the segment index.
        
        :return: the segment index
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def segmentIndex(self) -> jpype.JShort:
        ...

    @property
    def alignmentPad(self) -> jpype.JShort:
        ...

    @property
    def numberOfBytes(self) -> jpype.JInt:
        ...


@typing.type_check_only
class S_PROCREF(DebugSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def getChecksum(self) -> int:
        ...

    def getModule(self) -> int:
        ...

    @property
    def module(self) -> jpype.JInt:
        ...

    @property
    def checksum(self) -> jpype.JInt:
        ...


class DebugSymbol(java.lang.Object):
    """
    A base class for Object Module Format (OMF) symbols.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLength(self) -> int:
        """
        Returns the length of the symbol.
        
        :return: the length of the symbol
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of the symbol.
        
        :return: the name of the symbol
        :rtype: str
        """

    def getOffset(self) -> int:
        """
        Returns the offset.
        
        :return: the offset
        :rtype: int
        """

    def getSection(self) -> int:
        """
        Returns the section number.
        
        :return: the section number
        :rtype: int
        """

    def getType(self) -> int:
        """
        Returns the type of the symbol.
        
        :return: the type of the symbol
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JShort:
        ...

    @property
    def section(self) -> jpype.JShort:
        ...

    @property
    def type(self) -> jpype.JShort:
        ...


@typing.type_check_only
class S_ALIGN(DebugSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def isEOT(self) -> bool:
        ...

    @property
    def eOT(self) -> jpype.JBoolean:
        ...


class DebugCOFFSymbol(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the COFF symbol data structure.
     
    
     
    typedef struct _IMAGE_SYMBOL {
        union {
            BYTE    ShortName[8];
            struct {
                DWORD   Short;     // if 0, use LongName
                DWORD   Long;      // offset into string table
            } Name;
            DWORD   LongName[2];    // PBYTE [2]
        } N;
        DWORD   Value;
        SHORT   SectionNumber;
        WORD    Type;
        BYTE    StorageClass;
        BYTE    NumberOfAuxSymbols;
    } IMAGE_SYMBOL;
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SIZEOF_SYMBOL: typing.Final = 18
    """
    The size of the ``IMAGE_SYMBOL`` structure.
    """

    IMAGE_SYM_UNDEFINED: typing.Final = 0
    IMAGE_SYM_ABSOLUTE: typing.Final = -1
    IMAGE_SYM_DEBUG: typing.Final = -2
    IMAGE_SYM_TYPE_NULL: typing.Final = 0
    IMAGE_SYM_TYPE_VOID: typing.Final = 1
    IMAGE_SYM_TYPE_CHAR: typing.Final = 2
    IMAGE_SYM_TYPE_SHORT: typing.Final = 3
    IMAGE_SYM_TYPE_INT: typing.Final = 4
    IMAGE_SYM_TYPE_LONG: typing.Final = 5
    IMAGE_SYM_TYPE_FLOAT: typing.Final = 6
    IMAGE_SYM_TYPE_DOUBLE: typing.Final = 7
    IMAGE_SYM_TYPE_STRUCT: typing.Final = 8
    IMAGE_SYM_TYPE_UNION: typing.Final = 9
    IMAGE_SYM_TYPE_ENUM: typing.Final = 10
    IMAGE_SYM_TYPE_MOE: typing.Final = 11
    IMAGE_SYM_TYPE_BYTE: typing.Final = 12
    IMAGE_SYM_TYPE_WORD: typing.Final = 13
    IMAGE_SYM_TYPE_UINT: typing.Final = 14
    IMAGE_SYM_TYPE_DWORD: typing.Final = 15
    IMAGE_SYM_TYPE_PCODE: typing.Final = -32768
    IMAGE_SYM_DTYPE_NULL: typing.Final = 0
    IMAGE_SYM_DTYPE_POINTER: typing.Final = 1
    IMAGE_SYM_DTYPE_FUNCTION: typing.Final = 2
    IMAGE_SYM_DTYPE_ARRAY: typing.Final = 3
    IMAGE_SYM_CLASS_END_OF_FUNCTION: typing.Final = -1
    IMAGE_SYM_CLASS_NULL: typing.Final = 0
    IMAGE_SYM_CLASS_AUTOMATIC: typing.Final = 1
    IMAGE_SYM_CLASS_EXTERNAL: typing.Final = 2
    IMAGE_SYM_CLASS_STATIC: typing.Final = 3
    IMAGE_SYM_CLASS_REGISTER: typing.Final = 4
    IMAGE_SYM_CLASS_EXTERNAL_DEF: typing.Final = 5
    IMAGE_SYM_CLASS_LABEL: typing.Final = 6
    IMAGE_SYM_CLASS_UNDEFINED_LABEL: typing.Final = 7
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT: typing.Final = 8
    IMAGE_SYM_CLASS_ARGUMENT: typing.Final = 9
    IMAGE_SYM_CLASS_STRUCT_TAG: typing.Final = 10
    IMAGE_SYM_CLASS_MEMBER_OF_UNION: typing.Final = 11
    IMAGE_SYM_CLASS_UNION_TAG: typing.Final = 12
    IMAGE_SYM_CLASS_TYPE_DEFINITION: typing.Final = 13
    IMAGE_SYM_CLASS_UNDEFINED_STATIC: typing.Final = 14
    IMAGE_SYM_CLASS_ENUM_TAG: typing.Final = 15
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM: typing.Final = 16
    IMAGE_SYM_CLASS_REGISTER_PARAM: typing.Final = 17
    IMAGE_SYM_CLASS_BIT_FIELD: typing.Final = 18
    IMAGE_SYM_CLASS_FAR_EXTERNAL: typing.Final = 68
    IMAGE_SYM_CLASS_BLOCK: typing.Final = 100
    IMAGE_SYM_CLASS_FUNCTION: typing.Final = 101
    IMAGE_SYM_CLASS_END_OF_STRUCT: typing.Final = 102
    IMAGE_SYM_CLASS_FILE: typing.Final = 103
    IMAGE_SYM_CLASS_SECTION: typing.Final = 104
    IMAGE_SYM_CLASS_WEAK_EXTERNAL: typing.Final = 105

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int], symbolTable: DebugCOFFSymbolTable):
        ...

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int], stringTableIndex: typing.Union[jpype.JLong, int]):
        ...

    def getAuxiliarySymbols(self) -> jpype.JArray[DebugCOFFSymbolAux]:
        """
        Returns the auxiliary symbols related to this symbol.
        
        :return: the auxiliary symbols related to this symbol
        :rtype: jpype.JArray[DebugCOFFSymbolAux]
        """

    def getName(self) -> str:
        """
        Returns the name of this symbol.
        
        :return: the name of this symbol
        :rtype: str
        """

    def getNumberOfAuxSymbols(self) -> int:
        """
        Returns the number of auxiliary symbols defined with this symbol.
        
        :return: the number of auxiliary symbols defined with this symbol
        :rtype: int
        """

    def getSectionNumber(self) -> int:
        """
        Returns the section number if this symbol.
        
        :return: the section number if this symbol
        :rtype: int
        """

    def getSectionNumberAsString(self) -> str:
        """
        Returns a string equivalent of the section number of this symbol.
        
        :return: a string equivalent of the section number of this symbol
        :rtype: str
        """

    def getStorageClass(self) -> int:
        """
        Returns the storage class of this symbol.
        
        :return: the storage class of this symbol
        :rtype: int
        """

    def getStorageClassAsString(self) -> str:
        """
        Returns a string equivalent of the storage class of this symbol.
        
        :return: a string equivalent of the storage class of this symbol
        :rtype: str
        """

    def getType(self) -> int:
        """
        Returns the type of this symbol.
        
        :return: the type of this symbol
        :rtype: int
        """

    def getTypeAsString(self) -> str:
        """
        Returns a string equivalent of the type of this symbol.
        
        :return: a string equivalent of the type of this symbol
        :rtype: str
        """

    def getValue(self) -> int:
        """
        Returns the value of this symbol.
        
        :return: the value of this symbol
        :rtype: int
        """

    def getValueAsString(self) -> str:
        """
        Returns a string equivalent of the value of this symbol.
        
        :return: a string equivalent of the value of this symbol
        :rtype: str
        """

    @property
    def typeAsString(self) -> java.lang.String:
        ...

    @property
    def storageClass(self) -> jpype.JInt:
        ...

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def sectionNumber(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def numberOfAuxSymbols(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def auxiliarySymbols(self) -> jpype.JArray[DebugCOFFSymbolAux]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...

    @property
    def sectionNumberAsString(self) -> java.lang.String:
        ...

    @property
    def storageClassAsString(self) -> java.lang.String:
        ...


class OMFModule(java.lang.Object):
    """
    
    typedef struct OMFModule {
        unsigned short  ovlNumber;      // overlay number
        unsigned short  iLib;           // library that the module was linked from
        unsigned short  cSeg;           // count of number of segments in module
        char            Style[2];       // debugging style "CV"
        OMFSegDesc      SegInfo[1];     // describes segments in module
        char            Name[];         // length prefixed module name padded to long word boundary
    } OMFModule;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getILib(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getOMFSegDescs(self) -> jpype.JArray[OMFSegDesc]:
        """
        Returns the OMF segment descriptions in this OMF module.
        
        :return: the OMF segment descriptions in this OMF module
        :rtype: jpype.JArray[OMFSegDesc]
        """

    def getOvlNumber(self) -> int:
        ...

    def getStyle(self) -> int:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def style(self) -> jpype.JShort:
        ...

    @property
    def ovlNumber(self) -> jpype.JShort:
        ...

    @property
    def oMFSegDescs(self) -> jpype.JArray[OMFSegDesc]:
        ...

    @property
    def iLib(self) -> jpype.JShort:
        ...


@typing.type_check_only
class UnknownSymbol(DebugSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def getUnknown(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def unknown(self) -> jpype.JArray[jpype.JByte]:
        ...


class PrimitiveTypeListing(java.lang.Object):
    """
    A class to convert from debug data types into Ghidra data types.
    """

    class_: typing.ClassVar[java.lang.Class]
    T_NOTYPE: typing.Final = 0
    """
    Uncharacterized type (no type)
    """

    T_ABS: typing.Final = 1
    """
    Absolute symbol
    """

    T_SEGMENT: typing.Final = 2
    """
    Segment Type
    """

    T_VOID: typing.Final = 3
    """
    VOID
    """

    T_PVOID: typing.Final = 259
    """
    Near Pointer to a void
    """

    T_PFOID: typing.Final = 515
    """
    Far pointer to a void
    """

    T_PHVOID: typing.Final = 771
    """
    Huge pointer to a VOID
    """

    T_32PVOID: typing.Final = 1027
    """
    32-bit near pointer to a void
    """

    T_32PFVOID: typing.Final = 1283
    """
    32-bit far pointer to a void
    """

    T_CURRENCY: typing.Final = 4
    """
    Basic 8-byte currency value
    """

    T_NBASICSTR: typing.Final = 5
    """
    Near basic string
    """

    T_FBASICSTR: typing.Final = 6
    """
    Far basic string
    """

    T_NOTTRANS: typing.Final = 7
    """
    Untranslated type record from Microsoft symbol format
    """

    T_BIT: typing.Final = 96
    """
    Bit
    """

    T_PASCHAR: typing.Final = 97
    """
    Pascal CHAR
    """

    T_CHAR: typing.Final = 16
    """
    8-bit signed
    """

    T_UCHAR: typing.Final = 32
    """
    8-bit unsigned
    """

    T_PCHAR: typing.Final = 272
    """
    Near pointer to 8-bit signed
    """

    T_PUCHAR: typing.Final = 288
    """
    Near pointer to 8-bit unsigned
    """

    T_PFCHAR: typing.Final = 528
    """
    Far pointer to 8-bit signed
    """

    T_PFUCHAR: typing.Final = 544
    """
    Far pointer to 8-bit unsigned
    """

    T_PHCHAR: typing.Final = 784
    """
    Huge pointer to 8-bit signed
    """

    T_PHUCHAR: typing.Final = 800
    """
    Huge pointer to 8-bit unsigned
    """

    T_32PCHAR: typing.Final = 1040
    """
    16:32 near pointer to 8-bit signed
    """

    T_32PUCHAR: typing.Final = 1056
    """
    16:32 near pointer to 8-bit unsigned
    """

    T_32PFCHAR: typing.Final = 1296
    """
    16:32 far pointer to 8-bit signed
    """

    T_32PFUCHAR: typing.Final = 1312
    """
    16:32 far pointer to 8-bit unsigned
    """

    T_RCHAR: typing.Final = 112
    """
    Real char
    """

    T_PRCHAR: typing.Final = 368
    """
    Near pointer to a real char
    """

    T_PFRCHAR: typing.Final = 624
    """
    Far pointer to a real char
    """

    T_PHRCHAR: typing.Final = 880
    """
    Huge pointer to a real char
    """

    T_32PRCHAR: typing.Final = 1136
    """
    16:32 near pointer to a real char
    """

    T_32PFRCHAR: typing.Final = 1392
    """
    16:32 far pointer to a real char
    """

    T_WCHAR: typing.Final = 113
    """
    wide char
    """

    T_PWCHAR: typing.Final = 369
    """
    Near pointer to a wide char
    """

    T_PFWCHAR: typing.Final = 625
    """
    far pointer to a wide char
    """

    T_PHWCHAR: typing.Final = 881
    """
    Huge pointer to a wide char
    """

    T_32PWCHAR: typing.Final = 1137
    """
    16:32 near pointer to a wide char
    """

    T_32PFWCHAR: typing.Final = 1393
    """
    16:32 far pointer to a wide char
    """

    T_INT2: typing.Final = 114
    """
    Real 16-bit signed short
    """

    T_UINT2: typing.Final = 115
    """
    Real 16-bit unsigned short
    """

    T_PINT2: typing.Final = 370
    """
    Near pointer to 16-bit signed short
    """

    T_PUINT2: typing.Final = 371
    """
    Near pointer to 16-bit unsigned short
    """

    T_PFINT2: typing.Final = 626
    """
    Far pointer to 16-bit signed short
    """

    T_PFUINT2: typing.Final = 627
    """
    Far point to  16-bit unsigned short
    """

    T_PHINT2: typing.Final = 882
    """
    Huge pointer to 16-bit signed short
    """

    T_PHUINT2: typing.Final = 883
    """
    Huge pointer to 16-bit unsigned short
    """

    T_32PINT2: typing.Final = 1138
    """
    16:32 near pointer to 16-bit signed short
    """

    T_32PUINT2: typing.Final = 1139
    """
    16:32 near pointer to 16-bit unsigned short
    """

    T_32PFINT2: typing.Final = 1394
    """
    16:32 far pointer to 16-bit signed short
    """

    T_32PFUINT2: typing.Final = 1395
    """
    16:32 far pointer to 16-bit unsigned short
    """

    T_SHORT: typing.Final = 17
    """
    16-bit signed
    """

    T_USHORT: typing.Final = 33
    """
    16-bit unsigned
    """

    T_PSHORT: typing.Final = 273
    """
    Near pointer to 16-bit signed
    """

    T_PUSHORT: typing.Final = 289
    """
    Near pointer to 16-bit unsigned
    """

    T_PFSHORT: typing.Final = 529
    """
    Far pointer to16-bit signed
    """

    T_PFUSHORT: typing.Final = 545
    """
    Far pointer to 16-bit unsigned
    """

    T_PHSHORT: typing.Final = 785
    """
    Huge pointer to 16-bit signed
    """

    T_PHUSHORT: typing.Final = 801
    """
    Huge pointer 16-bit unsigned
    """

    T_32PSHORT: typing.Final = 1041
    """
    16:32 near pointer to 16-bit signed
    """

    T_32PUSHORT: typing.Final = 1057
    """
    16:32 near pointer to 16-bit unsigned
    """

    T_32PFSHORT: typing.Final = 1297
    """
    16:32 far pointer to 16-bit signed
    """

    T_32PFUSHORT: typing.Final = 1313
    """
    16:32 far pointer to 16-bit unsigned
    """

    T_INT4: typing.Final = 116
    """
    Real 32-bit signed short
    """

    T_UINT4: typing.Final = 117
    """
    Real 32-bit unsigned short
    """

    T_PINT4: typing.Final = 372
    """
    Near pointer to 32-bit signed short
    """

    T_PUINT4: typing.Final = 373
    """
    Near pointer to 32-bit unsigned short
    """

    T_PFINT4: typing.Final = 628
    """
    Far pointer to 32-bit signed short
    """

    T_PFUINT4: typing.Final = 629
    """
    Far pointer to 32-bit unsigned short
    """

    T_PHINT4: typing.Final = 884
    """
    Huge pointer to 32-bit signed short
    """

    T_PHUINT4: typing.Final = 885
    """
    Huge pointer to 32-bit unsigned short
    """

    T_32PINT4: typing.Final = 1140
    """
    16:32 near pointer to 32-bit signed short
    """

    T_32PUINT4: typing.Final = 1141
    """
    16:32 near pointer to 32-bit unsigned short
    """

    T_32PFINT4: typing.Final = 1396
    """
    16:32 far pointer to 32-bit signed short
    """

    T_32PFUINT4: typing.Final = 1397
    """
    16:32 far pointer to 32-bit unsigned short
    """

    T_LONG: typing.Final = 18
    """
    32-bit signed
    """

    T_ULONG: typing.Final = 34
    """
    32-bit unsigned
    """

    T_PLONG: typing.Final = 274
    """
    Near pointer to 32-bit signed
    """

    T_PULONG: typing.Final = 290
    """
    Near Pointer to 32-bit unsigned
    """

    T_PFLONG: typing.Final = 530
    """
    Far pointer to 32-bit signed
    """

    T_PFULONG: typing.Final = 546
    """
    Far pointer to 32-bit unsigned
    """

    T_PHLONG: typing.Final = 786
    """
    Huge pointer to 32-bit signed
    """

    T_PHULONG: typing.Final = 802
    """
    Huge pointer to 32-bit unsigned
    """

    T_32PLONG: typing.Final = 1042
    """
    16:32 near pointer to 32-bit signed
    """

    T_32PULONG: typing.Final = 1058
    """
    16:32 near pointer to 32-bit unsigned
    """

    T_P2PFLONG: typing.Final = 1298
    """
    16:32 far pointer to 32-bit signed
    """

    T_32PFULONG: typing.Final = 1314
    """
    16:32 far pointer to 32-bit unsigned
    """

    T_INT8: typing.Final = 118
    """
    64-bit signed
    """

    T_UINT8: typing.Final = 119
    """
    64-bit unsigned
    """

    T_PINT8: typing.Final = 374
    """
    Near pointer to 64-bit signed
    """

    T_PUINT8: typing.Final = 375
    """
    Near Pointer to 64-bit unsigned
    """

    T_PFINT8: typing.Final = 630
    """
    Far pointer to 64-bit signed
    """

    T_PFUINT8: typing.Final = 631
    """
    Far pointer to 64-bit unsigned
    """

    T_PHINT8: typing.Final = 886
    """
    Huge pointer to 64-bit signed
    """

    T_PHUINT8: typing.Final = 887
    """
    Huge pointer to 64-bit unsigned
    """

    T_32PINT8: typing.Final = 1142
    """
    16:32 near pointer to 64-bit signed
    """

    T_32PUINT8: typing.Final = 1143
    """
    16:32 near pointer to 64-bit unsigned
    """

    T_32PFINT8: typing.Final = 1398
    """
    16:32 far pointer to 64-bit signed
    """

    T_32PFUINT8: typing.Final = 1399
    """
    16:32 far pointer to 64-bit unsigned
    """

    T_QUAD: typing.Final = 19
    """
    64-bit signed
    """

    T_UQUAD: typing.Final = 35
    """
    64-bit unsigned
    """

    T_PQUAD: typing.Final = 275
    """
    Near pointer to 64-bit signed
    """

    T_PUQUAD: typing.Final = 291
    """
    Near pointer to 64-bit unsigned
    """

    T_PFQUAD: typing.Final = 531
    """
    Far pointer to 64-bit signed
    """

    T_PFUQUAD: typing.Final = 547
    """
    Far pointer to 64-bit unsigned
    """

    T_PHQUAD: typing.Final = 787
    """
    Huge pointer to 64-bit signed
    """

    T_PHUQUAD: typing.Final = 803
    """
    Huge pointer to 64-bit unsigned
    """

    T_32PQUAD: typing.Final = 1043
    """
    16:32 near pointer to 64-bit signed
    """

    T_32PUQUAD: typing.Final = 1059
    """
    16:32 near pointer to 64-bit unsigned
    """

    T_32PFQUAD: typing.Final = 1299
    """
    16:32 far pointer to 64-bit signed
    """

    T_32PFUQUAD: typing.Final = 1315
    """
    16:32 far pointer to 64-bit unsigned
    """

    T_REAL32: typing.Final = 64
    """
    32-bit real
    """

    T_PREAL32: typing.Final = 320
    """
    Near pointer to 32-bit real
    """

    T_PFREAL32: typing.Final = 576
    """
    Far pointer to 32-bit real
    """

    T_PHREAL32: typing.Final = 832
    """
    Huge pointer to 32-bit real
    """

    T_32PREAL32: typing.Final = 1088
    """
    16:32 near pointer to 32-bit real
    """

    T_32PFREAL32: typing.Final = 1344
    """
    16:32 far pointer to 32-bit real
    """

    T_REAL64: typing.Final = 65
    """
    64-bit real
    """

    T_PREAL64: typing.Final = 321
    """
    Near pointer to 64-bit real
    """

    T_PFREAL64: typing.Final = 577
    """
    Far pointer to 64-bit real
    """

    T_PHREAL64: typing.Final = 833
    """
    Huge pointer to 64-bit real
    """

    T_32PREAL64: typing.Final = 1089
    """
    16:32 near pointer to 64-bit real
    """

    T_32PFREAL64: typing.Final = 1345
    """
    16:32 far pointer to 64-bit real
    """

    T_CPLX32: typing.Final = 80
    """
    32-bit complex
    """

    T_PCPLX32: typing.Final = 336
    """
    Near pointer to 32-bit complex
    """

    T_PFCPLX32: typing.Final = 592
    """
    Far pointer to 32-bit complex
    """

    T_PHCPLX32: typing.Final = 848
    """
    Huge pointer to 32-bit complex
    """

    T_32PCPLX32: typing.Final = 1104
    """
    16:32 near pointer to 32-bit complex
    """

    T_32PFCPLX32: typing.Final = 1360
    """
    16:32 far pointer to 32-bit complex
    """

    T_CPLX64: typing.Final = 81
    """
    32-bit complex
    """

    T_PCPLX64: typing.Final = 337
    """
    Near pointer to 64-bit complex
    """

    T_PFCPLX64: typing.Final = 593
    """
    Far Pointer to 64-bit complex
    """

    T_PHCPLX64: typing.Final = 849
    """
    Huge pointer to 64-bit complex
    """

    T_32PCPLX64: typing.Final = 1105
    """
    16:32 near pointer to 64-bit complex
    """

    T_32PFCPLX64: typing.Final = 1361
    """
    16:32 far pointer to 64-bit complex
    """

    T_BOOL08: typing.Final = 48
    """
    8-bit boolean
    """

    T_BOOL16: typing.Final = 49
    """
    16-bit boolean
    """

    T_BOOL32: typing.Final = 50
    """
    32-bit boolean
    """

    T_BOOL64: typing.Final = 51
    """
    64-bit boolean
    """

    T_PBOOL08: typing.Final = 304
    """
    Near pointer to 8-bit boolean
    """

    T_PBOOL16: typing.Final = 305
    """
    Near pointer to 16-bit boolean
    """

    T_PBOOL32: typing.Final = 306
    """
    Near pointer to 32-bit boolean
    """

    T_PBOOL64: typing.Final = 307
    """
    Near pointer to 64-bit boolean
    """

    T_PFBOOL08: typing.Final = 560
    """
    Far Pointer to 8-bit boolean
    """

    T_PFBOOL16: typing.Final = 561
    """
    Far Pointer to 16-bit boolean
    """

    T_PFBOOL32: typing.Final = 562
    """
    Far Pointer to 32-bit boolean
    """

    T_PFBOOL64: typing.Final = 563
    """
    Far Pointer to 64-bit boolean
    """

    T_PHBOOL08: typing.Final = 816
    """
    Huge pointer to 8-bit boolean
    """

    T_PHBOOL16: typing.Final = 817
    """
    Huge pointer to 16-bit boolean
    """

    T_PHBOOL32: typing.Final = 818
    """
    Huge pointer to 32-bit boolean
    """

    T_PHBOOL64: typing.Final = 819
    """
    Huge pointer to 64-bit boolean
    """

    T_32PBOOL08: typing.Final = 1072
    """
    16:32 near pointer to 8-bit boolean
    """

    T_32PBOOL16: typing.Final = 1073
    """
    16:32 near pointer to 16-bit boolean
    """

    T_32PBOOL32: typing.Final = 1074
    """
    16:32 near pointer to 32-bit boolean
    """

    T_32PBOOL64: typing.Final = 1075
    """
    16:32 near pointer to 64-bit boolean
    """

    T_32PFBOOL08: typing.Final = 1328
    """
    16:32 far pointer to 8-bit boolean
    """

    T_32PFBOOL16: typing.Final = 1329
    """
    16:32 far pointer to 16-bit boolean
    """

    T_32PFBOOL32: typing.Final = 1330
    """
    16:32 far pointer to 32-bit boolean
    """

    T_32PFBOOL64: typing.Final = 1331
    """
    16:32 far pointer to 64-bit boolean
    """

    T_HINSTANCE: typing.Final = 4349
    """
    HANDLE
    """


    def __init__(self):
        ...

    @staticmethod
    def getDataType(type: typing.Union[jpype.JShort, int]) -> ghidra.program.model.data.DataType:
        ...


class DebugSymbolSelector(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def selectSymbol(reader: ghidra.app.util.bin.BinaryReader, ptr: typing.Union[jpype.JInt, int]) -> DebugSymbol:
        ...


@typing.type_check_only
class OMFDirEntry(java.lang.Object):
    """
    
    typedef struct OMFDirEntry {
        unsigned short  SubSection;     // subsection type (sst...)
        unsigned short  iMod;           // module index
        long            lfo;            // large file offset of subsection
        unsigned long   cb;             // number of bytes in subsection
    };
    """

    class_: typing.ClassVar[java.lang.Class]


class DebugDirectory(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    A class to represent the Debug Directory data structure.
     
    
     
    typedef struct _IMAGE_DEBUG_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Type;
        DWORD   SizeOfData;
        DWORD   AddressOfRawData;
        DWORD   PointerToRawData;
    } IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_DEBUG_DIRECTORY"
    """
    The name to use when converting into a structure data type.
    """

    IMAGE_SIZEOF_DEBUG_DIRECTORY: typing.Final = 28
    """
    The size of the ``IMAGE_DEBUG_DIRECTORY``, in bytes.
    """


    def getAddressOfRawData(self) -> int:
        """
        Returns the address of the debugging information when the image is loaded, relative to the image base.
        
        :return: the address of the debugging information when the image is loaded, relative to the image base
        :rtype: int
        """

    def getCharacteristics(self) -> int:
        """
        Reserved.
        
        :return: reserved value
        :rtype: int
        """

    def getDescription(self) -> str:
        """
        Returns a description of this debug directory.
        
        :return: a description of this debug directory
        :rtype: str
        """

    def getMajorVersion(self) -> int:
        """
        Returns the major version number of the debugging information format.
        
        :return: the major version number of the debugging information format
        :rtype: int
        """

    def getMinorVersion(self) -> int:
        """
        Returns the minor version number of the debugging information format.
        
        :return: the minor version number of the debugging information format
        :rtype: int
        """

    def getPointerToRawData(self) -> int:
        """
        Returns the file pointer to the debugging information.
        
        :return: the file pointer to the debugging information
        :rtype: int
        """

    def getSizeOfData(self) -> int:
        """
        Returns the size of the debugging information, in bytes. 
        This value does not include the debug directory itself.
        
        :return: the size of the debugging information, in bytes
        :rtype: int
        """

    def getTimeDateStamp(self) -> int:
        """
        Returns the time and date the debugging information was created.
        
        :return: the time and date the debugging information was created
        :rtype: int
        """

    def getType(self) -> int:
        """
        Returns the format of the debugging information.
        
        :return: the format of the debugging information
        :rtype: int
        """

    def setDescription(self, desc: typing.Union[java.lang.String, str]):
        """
        Sets the description of this debug directory.
        
        :param java.lang.String or str desc: the description of this debug directory
        """

    def updatePointers(self, offset: typing.Union[jpype.JInt, int], postOffset: typing.Union[jpype.JInt, int]):
        ...

    def writeHeader(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter):
        ...

    @property
    def timeDateStamp(self) -> jpype.JInt:
        ...

    @property
    def sizeOfData(self) -> jpype.JInt:
        ...

    @property
    def characteristics(self) -> jpype.JInt:
        ...

    @property
    def pointerToRawData(self) -> jpype.JInt:
        ...

    @property
    def addressOfRawData(self) -> jpype.JInt:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @description.setter
    def description(self, value: java.lang.String):
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def minorVersion(self) -> jpype.JInt:
        ...

    @property
    def majorVersion(self) -> jpype.JInt:
        ...


class S_BPREL32_NEW(DebugSymbol):
    """
    A class to represent the S_BPREL32_NEW data structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getVariableType(self) -> int:
        """
        Returns the variable type.
        
        :return: the variable type
        :rtype: int
        """

    @property
    def variableType(self) -> jpype.JShort:
        ...


@typing.type_check_only
class S_UDT32_NEW(DebugSymbol):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["S_GDATA32_NEW", "DebugCodeViewConstants", "OMFDirHeader", "OMFGlobal", "S_UDT32", "DebugCOFFLineNumber", "DebugFixup", "S_DATAREF", "DebugCodeViewSymbolTable", "S_GPROC32_NEW", "DataSym32_new", "S_LABEL32", "DebugMisc", "S_BLOCK32", "OMFFileIndex", "DebugCOFFSymbolsHeader", "OMFSegMapDesc", "DebugDirectoryParser", "DebugCodeView", "DebugCOFFSymbolTable", "S_OBJNAME", "S_CONSTANT32", "OMFAlignSym", "DebugFixupElement", "DebugCOFFSymbolAux", "OMFLibrary", "S_COMPILE", "S_END", "S_LDATA32_NEW", "OMFSrcModuleFile", "DataSym32", "OMFSrcModule", "OMFSrcModuleLine", "OMFSegMap", "OMFSegDesc", "S_PROCREF", "DebugSymbol", "S_ALIGN", "DebugCOFFSymbol", "OMFModule", "UnknownSymbol", "PrimitiveTypeListing", "DebugSymbolSelector", "OMFDirEntry", "DebugDirectory", "S_BPREL32_NEW", "S_UDT32_NEW"]
