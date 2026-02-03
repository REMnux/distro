from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class SomAuxHeader(ghidra.app.util.bin.StructConverter):
    """
    Abstract parent class for SOM auxiliary headers
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomAuxHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the auxiliary header
        :raises IOException: if there was an IO-related error
        """

    def getAuxId(self) -> SomAuxId:
        """
        :return: this :obj:`SomAuxHeader`'s :obj:`aux ID <SomAuxId>`
        :rtype: SomAuxId
        """

    def getLength(self) -> int:
        """
        :return: the length in bytes of this :obj:`auxiliary header <SomAuxHeader>` (including the
        size of the aux id)
        :rtype: int
        """

    @property
    def auxId(self) -> SomAuxId:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...


class SomLinkerFootprintAuxHeader(SomAuxHeader):
    """
    Represents a SOM ``linker_footprint`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomLinkerFootprintAuxHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the auxiliary header
        :raises IOException: if there was an IO-related error
        """

    def getHtime(self) -> SomSysClock:
        """
        :return: the htime
        :rtype: SomSysClock
        """

    def getProductId(self) -> str:
        """
        :return: the product ID
        :rtype: str
        """

    def getVersionId(self) -> str:
        """
        :return: the version ID
        :rtype: str
        """

    @property
    def versionId(self) -> java.lang.String:
        ...

    @property
    def productId(self) -> java.lang.String:
        ...

    @property
    def htime(self) -> SomSysClock:
        ...


class SomUnknownAuxHeader(SomAuxHeader):
    """
    Represents an unknown SOM auxiliary header
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomUnknownAuxHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the auxiliary header
        :raises IOException: if there was an IO-related error
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the unknown bytes of this auxiliary header
        :rtype: jpype.JArray[jpype.JByte]
        """

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...


class SomProductSpecificsAuxHeader(SomAuxHeader):
    """
    Represents a SOM "product specifics" structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomProductSpecificsAuxHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the auxiliary header
        :raises IOException: if there was an IO-related error
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the product specific bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...


class SomSubspace(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``subspace_dictionary_record`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 40
    """
    The size in bytes of a :obj:`SomSubspace`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, spaceStringsLocation: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`SomSubspace`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JLong or int spaceStringsLocation: The starting index of the space strings
        :raises IOException: if there was an IO-related error
        """

    def getAccessControlBits(self) -> int:
        """
        :return: the access control bits for PDIR entries
        :rtype: int
        """

    def getAlignment(self) -> int:
        """
        :return: the alignment required for the subspace
        :rtype: int
        """

    def getFileLocInitValue(self) -> int:
        """
        :return: the file location or initialization value
        :rtype: int
        """

    def getFixupRequestIndex(self) -> int:
        """
        :return: the index into fixup array
        :rtype: int
        """

    def getFixupRequestQuantity(self) -> int:
        """
        :return: the number of fixup requests
        :rtype: int
        """

    def getInitializationLength(self) -> int:
        """
        :return: the initialization length
        :rtype: int
        """

    def getName(self) -> str:
        """
        :return: the subspace name
        :rtype: str
        """

    def getQuadrant(self) -> int:
        """
        :return: the quadrant request
        :rtype: int
        """

    def getReserved(self) -> int:
        """
        :return: the first reserved value
        :rtype: int
        """

    def getReserved2(self) -> int:
        """
        :return: the second reserved value
        :rtype: int
        """

    def getSortKey(self) -> int:
        """
        :return: the sort key for the subspace
        :rtype: int
        """

    def getSpaceIndex(self) -> int:
        """
        :return: the space index
        :rtype: int
        """

    def getSubspaceLength(self) -> int:
        """
        :return: the number of bytes defined by this subspace
        :rtype: int
        """

    def getSubspaceStart(self) -> int:
        """
        :return: the starting offset
        :rtype: int
        """

    def isCodeOnly(self) -> bool:
        """
        :return: whether or not the subspace must contain only code
        :rtype: bool
        """

    def isComdat(self) -> bool:
        """
        :return: whether or not this is for COMDAT subspaces
        :rtype: bool
        """

    def isCommon(self) -> bool:
        """
        :return: whether or not the subspace is a common
        :rtype: bool
        """

    def isContinuation(self) -> bool:
        """
        :return: whether or not this subspace is a continuation
        :rtype: bool
        """

    def isDupCommon(self) -> bool:
        """
        :return: whether or not data name clashes are allowed
        :rtype: bool
        """

    def isExecute(self) -> bool:
        """
        :return: whether or not this subspace is executable
        :rtype: bool
        """

    def isFirst(self) -> bool:
        """
        :return: whether or not this must be the first subspace
        :rtype: bool
        """

    def isInitiallyFrozen(self) -> bool:
        """
        :return: whether or not the subspace must be locked into memory when the OS is booted
        :rtype: bool
        """

    def isLoadable(self) -> bool:
        """
        :return: whether or not the subspace is loadable
        :rtype: bool
        """

    def isMemoryResident(self) -> bool:
        """
        :return: whether or not to lock in memory during execution
        :rtype: bool
        """

    def isRead(self) -> bool:
        """
        :return: whether or not this subspace is readable
        :rtype: bool
        """

    def isReplicateInit(self) -> bool:
        """
        :return: whether or not init values are replicated to fill ``subspace_length``
        :rtype: bool
        """

    def isThreadSpecific(self) -> bool:
        """
        :return: whether or not the subspace is thread specific
        :rtype: bool
        """

    def isWrite(self) -> bool:
        """
        :return: whether or not this subspace is writeable
        :rtype: bool
        """

    @property
    def threadSpecific(self) -> jpype.JBoolean:
        ...

    @property
    def fileLocInitValue(self) -> jpype.JInt:
        ...

    @property
    def loadable(self) -> jpype.JBoolean:
        ...

    @property
    def dupCommon(self) -> jpype.JBoolean:
        ...

    @property
    def comdat(self) -> jpype.JBoolean:
        ...

    @property
    def accessControlBits(self) -> jpype.JInt:
        ...

    @property
    def memoryResident(self) -> jpype.JBoolean:
        ...

    @property
    def common(self) -> jpype.JBoolean:
        ...

    @property
    def fixupRequestQuantity(self) -> jpype.JLong:
        ...

    @property
    def initiallyFrozen(self) -> jpype.JBoolean:
        ...

    @property
    def reserved2(self) -> jpype.JInt:
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @property
    def continuation(self) -> jpype.JBoolean:
        ...

    @property
    def fixupRequestIndex(self) -> jpype.JInt:
        ...

    @property
    def subspaceLength(self) -> jpype.JLong:
        ...

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def replicateInit(self) -> jpype.JBoolean:
        ...

    @property
    def quadrant(self) -> jpype.JInt:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @property
    def initializationLength(self) -> jpype.JLong:
        ...

    @property
    def sortKey(self) -> jpype.JInt:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def spaceIndex(self) -> jpype.JInt:
        ...

    @property
    def codeOnly(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @property
    def first(self) -> jpype.JBoolean:
        ...

    @property
    def subspaceStart(self) -> jpype.JLong:
        ...


class SomSysClock(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``sys_clock`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size in bytes of a :obj:`SomSysClock`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomSysClock`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the value
        :raises IOException: if there was an IO-related error
        """

    def getNanoSeconds(self) -> int:
        """
        :return: the nano second of the second (which requires 30 bits to represent)
        :rtype: int
        """

    def getSeconds(self) -> int:
        """
        :return: the number of seconds that have elapsed since January 1, 1970 (at 0:00 GMT)
        :rtype: int
        """

    @property
    def seconds(self) -> jpype.JLong:
        ...

    @property
    def nanoSeconds(self) -> jpype.JLong:
        ...


class SomAuxHeaderFactory(java.lang.Object):
    """
    A class for reading/creating SOM auxiliary headers
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def readNextAuxHeader(reader: ghidra.app.util.bin.BinaryReader) -> SomAuxHeader:
        ...


class SomConstants(java.lang.Object):
    """
    SOM constant values
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SYSTEM_PA_RISC_1_0: typing.Final = 523
    SYSTEM_PA_RISC_1_1: typing.Final = 528
    SYSTEM_PA_RISC_2_0: typing.Final = 532
    MAGIC_LIBRARY: typing.Final = 260
    MAGIC_RELOCATABLE: typing.Final = 262
    MAGIC_NON_SHAREABLE_EXE: typing.Final = 263
    MAGIC_SHAREABLE_EXE: typing.Final = 264
    MAGIC_SHARABLE_DEMAND_LOADABLE_EXE: typing.Final = 267
    MAGIC_DYNAMIC_LOAD_LIBRARY: typing.Final = 269
    MAGIC_SHARED_LIBRARY: typing.Final = 270
    MAGIC_RELOCATABLE_LIBRARY: typing.Final = 1561
    VERSION_OLD: typing.Final = -2063064814
    VERSION_NEW: typing.Final = -2028985326
    TYPE_NULL: typing.Final = 0
    LINKER_FOOTPRINT: typing.Final = 1
    MEP_IX_PROGRAM: typing.Final = 2
    DEBUGGER_FOOTPRINT: typing.Final = 3
    EXEC_AUXILIARY_HEADER: typing.Final = 4
    IPL_AUXILIARY_HEADER: typing.Final = 5
    VERSION_STRIING: typing.Final = 6
    MPE_IX_PROGRAM: typing.Final = 7
    MPE_IX_SOM: typing.Final = 8
    COPYRIGHT: typing.Final = 9
    SHARED_LIBARY_VERSION_INFORMATION: typing.Final = 10
    PRODUCT_SPECIFICS: typing.Final = 11
    NETWARE_LOADABLE_MODULE: typing.Final = 12
    SYMBOL_NULL: typing.Final = 0
    SYMBOL_ABSOLUTE: typing.Final = 1
    SYMBOL_DATA: typing.Final = 2
    SYMBOL_CODE: typing.Final = 3
    SYMBOL_PRI_PROG: typing.Final = 4
    SYMBOL_SEC_PROG: typing.Final = 5
    SYMBOL_ENTRY: typing.Final = 6
    SYMBOL_STORAGE: typing.Final = 7
    SYMBOL_STUB: typing.Final = 8
    SYMBOL_MODULE: typing.Final = 9
    SYMBOL_SYM_EXT: typing.Final = 10
    SYMBOL_ARG_EXT: typing.Final = 11
    SYMBOL_MILLICODE: typing.Final = 12
    SYMBOL_PLABEL: typing.Final = 13
    SYMBOL_OCT_DIS: typing.Final = 14
    SYMBOL_MILLI_EXT: typing.Final = 15
    SYMBOL_TSTORAGE: typing.Final = 16
    SYMBOL_COMDAT: typing.Final = 17
    SYMBOL_SCOPE_UNSAT: typing.Final = 0
    SYMBOL_SCOPE_EXTERNAL: typing.Final = 1
    SYMBOL_SCOPE_LOCAL: typing.Final = 2
    SYMBOL_SCOPE_UNIVERSAL: typing.Final = 3
    DR_PLABEL_EXT: typing.Final = 1
    DR_PLABEL_INT: typing.Final = 2
    DR_DATA_EXT: typing.Final = 3
    DR_DATA_INT: typing.Final = 4
    DR_PROPAGATE: typing.Final = 5
    DR_INVOKE: typing.Final = 6
    DR_TEXT_INT: typing.Final = 7

    def __init__(self):
        ...


class SomDynamicRelocation(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``dreloc_record`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 20
    """
    The size in bytes of a :obj:`SomDynamicRelocation`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomDynamicRelocation`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the dynamic relocation list
        :raises IOException: if there was an IO-related error
        """

    def getLocation(self) -> int:
        """
        :return: the data-relative offset of the data item the dreloc record refers to
        :rtype: int
        """

    def getModuleIndex(self) -> int:
        """
        :return: the module index (currently reserved)
        :rtype: int
        """

    def getReserved(self) -> int:
        """
        :return: the reserved value
        :rtype: int
        """

    def getShlib(self) -> int:
        """
        :return: the shared library name (currently a reserved field)
        :rtype: int
        """

    def getSymbol(self) -> int:
        """
        :return: the index into the import table if the relocation is an external type
        :rtype: int
        """

    def getType(self) -> int:
        """
        :return: the type of dynamic relocation
        :rtype: int
        
        
        
        .. seealso::
        
            | :obj:`SomConstants`
        """

    def getValue(self) -> int:
        """
        :return: the text or data-relative offset to use for a patch if it is an internal fixup type
        :rtype: int
        """

    @property
    def symbol(self) -> jpype.JInt:
        ...

    @property
    def shlib(self) -> jpype.JInt:
        ...

    @property
    def reserved(self) -> jpype.JByte:
        ...

    @property
    def moduleIndex(self) -> jpype.JShort:
        ...

    @property
    def location(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class SomExportEntryExt(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``export_entry_ext`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 20
    """
    The size in bytes of a :obj:`SomExportEntryExt`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomExportEntryExt`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the export extension list
        :raises IOException: if there was an IO-related error
        """

    def getDreloc(self) -> int:
        """
        :return: the start of the dreloc records for the exported symbol
        :rtype: int
        """

    def getReserved2(self) -> int:
        """
        :return: the second reserved value
        :rtype: int
        """

    def getReserved3(self) -> int:
        """
        :return: the third reserved value
        :rtype: int
        """

    def getSameList(self) -> int:
        """
        :return: the circular list of exports that have the same value (physical location) in the
        library
        :rtype: int
        """

    def getSize(self) -> int:
        """
        :return: the size of the export symbol and is only valid for exports of type ``ST_DATA``
        :rtype: int
        """

    @property
    def sameList(self) -> jpype.JInt:
        ...

    @property
    def dreloc(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def reserved3(self) -> jpype.JInt:
        ...

    @property
    def reserved2(self) -> jpype.JInt:
        ...


class SomSymbol(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``symbol_dictionary_record`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 20
    """
    The size in bytes of a :obj:`SomSymbol`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, symbolStringsLocation: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`SomSymbol`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JLong or int symbolStringsLocation: The starting index of the symbol strings
        :raises IOException: if there was an IO-related error
        """

    def getArgReloc(self) -> int:
        """
        :return: the location of the first four words of the parameter list, and the location of the
        function return value to the linker and loader
        :rtype: int
        """

    def getCheckLevel(self) -> int:
        """
        :return: the check level
        :rtype: int
        """

    def getName(self) -> str:
        """
        :return: the symbol name
        :rtype: str
        """

    def getQualifierName(self) -> str:
        """
        :return: the symbol qualifier name
        :rtype: str
        """

    def getReserved(self) -> int:
        """
        :return: the reserved value
        :rtype: int
        """

    def getSymbolInfo(self) -> int:
        """
        :return: the symbol info
        :rtype: int
        """

    def getSymbolScope(self) -> int:
        """
        :return: the symbol scope
        :rtype: int
        
        
        
        .. seealso::
        
            | :obj:`SomConstants`
        """

    def getSymbolType(self) -> int:
        """
        :return: the symbol type
        :rtype: int
        
        
        
        .. seealso::
        
            | :obj:`SomConstants`
        """

    def getSymbolValue(self) -> int:
        """
        :return: the symbol value
        :rtype: int
        """

    def getXleast(self) -> int:
        """
        :return: the execution level that is required to call this entry point
        :rtype: int
        """

    def hasLongReturn(self) -> bool:
        """
        :return: whether or not the called entry point will have a long return sequence
        :rtype: bool
        """

    def hasNoRelocation(self) -> bool:
        """
        :return: whether or not the called entry point will not require any parameter relocation
        :rtype: bool
        """

    def isComdat(self) -> bool:
        """
        :return: whether or not this symbol identifies as the key symbol for a set of COMDAT 
        subspaces
        :rtype: bool
        """

    def isCommon(self) -> bool:
        """
        :return: whether or not this symbol is an initialized common data block
        :rtype: bool
        """

    def isDupCommon(self) -> bool:
        """
        :return: whether or not this symbol name may conflict with another symbol of the same name if 
        both are of type data
        :rtype: bool
        """

    def isHidden(self) -> bool:
        """
        :return: whether or not the symbol is to be hidden from the loader for the purpose of 
        resolving external (inter-SOM) references
        :rtype: bool
        """

    def isInitiallyFrozen(self) -> bool:
        """
        :return: whether or not the code importing or exporting this symbol is to be locked in 
        physical memory when the operating system is being booted
        :rtype: bool
        """

    def isMemoryResident(self) -> bool:
        """
        :return: whether or the the code that is importing or exporting this symbol is frozen in 
        memory
        :rtype: bool
        """

    def isSecondaryDef(self) -> bool:
        """
        :return: whether or not the symbol is a secondary definition and has an additional name
        that is preceded by “_”
        :rtype: bool
        """

    def mustQualify(self) -> bool:
        """
        :return: whether or not the qualifier name must be used to fully qualify the symbol
        :rtype: bool
        """

    @property
    def hidden(self) -> jpype.JBoolean:
        ...

    @property
    def dupCommon(self) -> jpype.JBoolean:
        ...

    @property
    def symbolValue(self) -> jpype.JLong:
        ...

    @property
    def comdat(self) -> jpype.JBoolean:
        ...

    @property
    def symbolType(self) -> jpype.JInt:
        ...

    @property
    def symbolInfo(self) -> jpype.JInt:
        ...

    @property
    def memoryResident(self) -> jpype.JBoolean:
        ...

    @property
    def qualifierName(self) -> java.lang.String:
        ...

    @property
    def common(self) -> jpype.JBoolean:
        ...

    @property
    def symbolScope(self) -> jpype.JInt:
        ...

    @property
    def checkLevel(self) -> jpype.JInt:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def initiallyFrozen(self) -> jpype.JBoolean:
        ...

    @property
    def xleast(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def argReloc(self) -> jpype.JInt:
        ...

    @property
    def secondaryDef(self) -> jpype.JBoolean:
        ...


class SomCompilationUnit(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``compilation_unit`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 36
    """
    The size in bytes of a :obj:`SomCompilationUnit`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, symbolStringsLocation: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`SomCompilationUnit`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JLong or int symbolStringsLocation: The starting index of the symbol strings
        :raises IOException: if there was an IO-related error
        """

    def getChunkFlag(self) -> bool:
        """
        :return: whether or not the compilation unit is not the first SOM in a multiple chunk
        compilation
        :rtype: bool
        """

    def getCompileTime(self) -> SomSysClock:
        """
        :return: the compile time
        :rtype: SomSysClock
        """

    def getLanguageName(self) -> str:
        """
        :return: the language name
        :rtype: str
        """

    def getName(self) -> str:
        """
        :return: the compilation unit name
        :rtype: str
        """

    def getProductId(self) -> str:
        """
        :return: the product ID
        :rtype: str
        """

    def getReserved(self) -> int:
        """
        :return: the reserved value
        :rtype: int
        """

    def getSourceTime(self) -> SomSysClock:
        """
        :return: the source time
        :rtype: SomSysClock
        """

    def getVersionId(self) -> str:
        """
        :return: the version ID
        :rtype: str
        """

    @property
    def compileTime(self) -> SomSysClock:
        ...

    @property
    def versionId(self) -> java.lang.String:
        ...

    @property
    def productId(self) -> java.lang.String:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def sourceTime(self) -> SomSysClock:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def languageName(self) -> java.lang.String:
        ...

    @property
    def chunkFlag(self) -> jpype.JBoolean:
        ...


class SomDynamicLoaderHeader(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``dl_header`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 112
    """
    The size in bytes of a :obj:`SomDynamicLoaderHeader`
    """


    def __init__(self, program: ghidra.program.model.listing.Program, textAddr: ghidra.program.model.address.Address, dataAddr: ghidra.program.model.address.Address):
        """
        Creates a new :obj:`SomDynamicLoaderHeader`
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.Address textAddr: The :obj:`Address` of the "text" space
        :param ghidra.program.model.address.Address dataAddr: The :obj:`Address` of the "data" space
        :raises IOException: if there was an IO-related error
        """

    def getDataAddress(self) -> ghidra.program.model.address.Address:
        """
        :return: the :obj:`Address` of the "data" space
        :rtype: ghidra.program.model.address.Address
        """

    def getDlt(self) -> java.util.List[SomDltEntry]:
        """
        :return: the :obj:`List` of :obj:`DLT entries <SomDltEntry>`
        :rtype: java.util.List[SomDltEntry]
        """

    def getDltCount(self) -> int:
        """
        :return: the number of entries in the DLT
        :rtype: int
        """

    def getDltLoc(self) -> int:
        """
        :return: the offset in the $DATA$ space of the Data Linkage Table
        :rtype: int
        """

    def getDrelocCount(self) -> int:
        """
        :return: the number of dynamic relocation records generated
        :rtype: int
        """

    def getDrelocLoc(self) -> int:
        """
        :return: the text-relative offset of the dynamic relocation records
        :rtype: int
        """

    def getDynamicRelocations(self) -> java.util.List[SomDynamicRelocation]:
        """
        :return: the :obj:`List` of :obj:`dynamic relocation entries <SomDynamicRelocation>`
        :rtype: java.util.List[SomDynamicRelocation]
        """

    def getElaborator(self) -> int:
        """
        :return: the index into the import table if the elab_ref bit in the flags field is set
        :rtype: int
        """

    def getEmbeddedPath(self) -> int:
        """
        :return: the index into the shared library string table
        :rtype: int
        """

    def getExportExtLoc(self) -> int:
        """
        :return: the text-relative offset of the export extension table
        :rtype: int
        """

    def getExportExtensions(self) -> java.util.List[SomExportEntryExt]:
        """
        :return: the :obj:`List` of :obj:`export entry extensions <SomExportEntryExt>`
        :rtype: java.util.List[SomExportEntryExt]
        """

    def getExportListCount(self) -> int:
        """
        :return: the number of export entries
        :rtype: int
        """

    def getExportListLoc(self) -> int:
        """
        :return: the text-relative offset of the export list
        :rtype: int
        """

    def getExports(self) -> java.util.List[SomExportEntry]:
        """
        :return: the :obj:`List` of :obj:`export entries <SomExportEntry>`
        :rtype: java.util.List[SomExportEntry]
        """

    def getFastbindListLoc(self) -> int:
        """
        :return: the text-relative offset of fastbind info
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def getHashTableLoc(self) -> int:
        """
        :return: the text-relative offset of the hash table
        :rtype: int
        """

    def getHashTableSize(self) -> int:
        """
        :return: the number of slots used in the hash table
        :rtype: int
        """

    def getHdrVersion(self) -> int:
        """
        :return: the version of the DL header
        :rtype: int
        """

    def getHighwaterMark(self) -> int:
        """
        :return: the highest version number of any symbol defined in the shared library or in the
        set of highwater marks of the shared libraries in the shared library list
        :rtype: int
        """

    def getImportListCount(self) -> int:
        """
        :return: the number of entries in the import list
        :rtype: int
        """

    def getImportListLoc(self) -> int:
        """
        :return: the text-relative offset of the import list
        :rtype: int
        """

    def getImports(self) -> java.util.List[SomImportEntry]:
        """
        :return: the :obj:`List` of :obj:`import entries <SomImportEntry>`
        :rtype: java.util.List[SomImportEntry]
        """

    def getInitializer(self) -> int:
        """
        :return: the index into the import table if the init_ref bit in the flags field is set and 
        the initializer_count field is set 0
        :rtype: int
        """

    def getInitializerCount(self) -> int:
        """
        :return: the number of initializers declared
        :rtype: int
        """

    def getLtptrValue(self) -> int:
        """
        :return: the data-relative offset of the Linkage Table pointer
        :rtype: int
        """

    def getModuleCount(self) -> int:
        """
        :return: the number of modules in the module table
        :rtype: int
        """

    def getModuleLoc(self) -> int:
        """
        :return: the text-relative offset of the module table
        :rtype: int
        """

    def getModules(self) -> java.util.List[SomModuleEntry]:
        """
        :return: the :obj:`List` of :obj:`module entries <SomModuleEntry>`
        :rtype: java.util.List[SomModuleEntry]
        """

    def getPlt(self) -> java.util.List[SomPltEntry]:
        """
        :return: the :obj:`List` of :obj:`PLT entries <SomPltEntry>`
        :rtype: java.util.List[SomPltEntry]
        """

    def getPltCount(self) -> int:
        """
        :return: the number of entries in the PLT
        :rtype: int
        """

    def getPltLoc(self) -> int:
        """
        :return: the offset in the $DATA$ space of the Procedure Linkage Table
        :rtype: int
        """

    def getShlibListCount(self) -> int:
        """
        :return: the number of entries in the shared library list
        :rtype: int
        """

    def getShlibListLoc(self) -> int:
        """
        :return: the text-relative offset of the shared library list
        :rtype: int
        """

    def getShlibs(self) -> java.util.List[SomShlibListEntry]:
        """
        :return: the :obj:`List` of :obj:`shared library entries <SomShlibListEntry>`
        :rtype: java.util.List[SomShlibListEntry]
        """

    def getStringTableLoc(self) -> int:
        """
        :return: the text-relative offset of the string table
        :rtype: int
        """

    def getStringTableSize(self) -> int:
        """
        :return: the length of the string table
        :rtype: int
        """

    def getTdsize(self) -> int:
        """
        :return: the size of the TSD area
        :rtype: int
        """

    def getTextAddress(self) -> ghidra.program.model.address.Address:
        """
        :return: the :obj:`Address` of the "text" space
        :rtype: ghidra.program.model.address.Address
        """

    def markup(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor):
        """
        Marks up this header
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :raises java.lang.Exception: if there was a problem during markup
        """

    @property
    def textAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def exportListLoc(self) -> jpype.JInt:
        ...

    @property
    def fastbindListLoc(self) -> jpype.JInt:
        ...

    @property
    def importListLoc(self) -> jpype.JInt:
        ...

    @property
    def hashTableSize(self) -> jpype.JInt:
        ...

    @property
    def exports(self) -> java.util.List[SomExportEntry]:
        ...

    @property
    def hdrVersion(self) -> jpype.JInt:
        ...

    @property
    def moduleLoc(self) -> jpype.JInt:
        ...

    @property
    def highwaterMark(self) -> jpype.JShort:
        ...

    @property
    def flags(self) -> jpype.JShort:
        ...

    @property
    def shlibListCount(self) -> jpype.JInt:
        ...

    @property
    def shlibs(self) -> java.util.List[SomShlibListEntry]:
        ...

    @property
    def pltCount(self) -> jpype.JInt:
        ...

    @property
    def exportExtLoc(self) -> jpype.JInt:
        ...

    @property
    def exportListCount(self) -> jpype.JInt:
        ...

    @property
    def shlibListLoc(self) -> jpype.JInt:
        ...

    @property
    def tdsize(self) -> jpype.JInt:
        ...

    @property
    def initializerCount(self) -> jpype.JInt:
        ...

    @property
    def hashTableLoc(self) -> jpype.JInt:
        ...

    @property
    def dynamicRelocations(self) -> java.util.List[SomDynamicRelocation]:
        ...

    @property
    def exportExtensions(self) -> java.util.List[SomExportEntryExt]:
        ...

    @property
    def drelocLoc(self) -> jpype.JInt:
        ...

    @property
    def stringTableSize(self) -> jpype.JInt:
        ...

    @property
    def imports(self) -> java.util.List[SomImportEntry]:
        ...

    @property
    def dataAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def elaborator(self) -> jpype.JInt:
        ...

    @property
    def ltptrValue(self) -> jpype.JInt:
        ...

    @property
    def dlt(self) -> java.util.List[SomDltEntry]:
        ...

    @property
    def pltLoc(self) -> jpype.JInt:
        ...

    @property
    def modules(self) -> java.util.List[SomModuleEntry]:
        ...

    @property
    def dltCount(self) -> jpype.JInt:
        ...

    @property
    def initializer(self) -> jpype.JInt:
        ...

    @property
    def drelocCount(self) -> jpype.JInt:
        ...

    @property
    def embeddedPath(self) -> jpype.JInt:
        ...

    @property
    def stringTableLoc(self) -> jpype.JInt:
        ...

    @property
    def moduleCount(self) -> jpype.JInt:
        ...

    @property
    def dltLoc(self) -> jpype.JInt:
        ...

    @property
    def plt(self) -> java.util.List[SomPltEntry]:
        ...

    @property
    def importListCount(self) -> jpype.JInt:
        ...


class SomModuleEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``module_entry`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 20
    """
    The size in bytes of a :obj:`SomModuleEntry`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomModuleEntry`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the module list
        :raises IOException: if there was an IO-related error
        """

    def getDrelocs(self) -> int:
        """
        :return: the text address into the dynamic relocation table
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def getImportCount(self) -> int:
        """
        :return: the number of symbol entries in the module import table belonging to this module
        :rtype: int
        """

    def getImports(self) -> int:
        """
        :return: the text address into the module import table
        :rtype: int
        """

    def getModuleDependencies(self) -> int:
        """
        :return: the number of modules the current module needs to have bound before all of its own
        import symbols can be found
        :rtype: int
        """

    def getReserved1(self) -> int:
        """
        :return: the first reserved value
        :rtype: int
        """

    def getReserved2(self) -> int:
        """
        :return: the second reserved value
        :rtype: int
        """

    @property
    def imports(self) -> jpype.JInt:
        ...

    @property
    def drelocs(self) -> jpype.JInt:
        ...

    @property
    def importCount(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def reserved2(self) -> jpype.JInt:
        ...

    @property
    def reserved1(self) -> jpype.JInt:
        ...

    @property
    def moduleDependencies(self) -> jpype.JInt:
        ...


class SomImportEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``import_entry`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size in bytes of a :obj:`SomImportEntry`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stringTableLoc: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`SomImportEntry`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the import list
        :param jpype.JLong or int stringTableLoc: The location of the string table
        :raises IOException: if there was an IO-related error
        """

    def getName(self) -> str:
        """
        :return: the name of the import, or ``null`` if it doesn't have one
        :rtype: str
        """

    def getReserved1(self) -> int:
        """
        :return: the first reserved value
        :rtype: int
        """

    def getReserved2(self) -> int:
        """
        :return: the second reserved value
        :rtype: int
        """

    def getType(self) -> int:
        """
        :return: the symbol type (text, data, or bss)
        :rtype: int
        """

    def isBypassable(self) -> bool:
        """
        :return: whether or not code imports do not have their address taken in that shared library
        :rtype: bool
        """

    @property
    def bypassable(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def reserved2(self) -> jpype.JInt:
        ...

    @property
    def reserved1(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...


class SomDltEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``DLT`` value
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size in bytes of a :obj:`SomDltEntry`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomDltEntry`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the DLT
        :raises IOException: if there was an IO-related error
        """

    def getValue(self) -> int:
        """
        :return: the value of the DLT entry
        :rtype: int
        """

    @property
    def value(self) -> jpype.JInt:
        ...


class SomAuxId(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``aux_id`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size in bytes of a :obj:`SomAuxId`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomAuxId`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the auxiliary ID
        :raises IOException: if there was an IO-related error
        """

    def getAppend(self) -> bool:
        """
        :return: whether or not this auxiliary header is to be copied without modification to any new
        SOM created from this SOM, except that multiple entries with the same type and append set of
        “action flags” (i.e., mandatory, copy, append, ignore) should be merged (concatenation of the
        data portion)
        :rtype: bool
        """

    def getCopy(self) -> bool:
        """
        :return: whether or not this auxiliary header is to be copied without modification to any new
        SOM created from this SOM
        :rtype: bool
        """

    def getIgnore(self) -> bool:
        """
        :return: whether or not this auxiliary header should be ignored if its type field is unknown
        (i.e., do not copy, do not merge)
        :rtype: bool
        """

    def getLength(self) -> int:
        """
        :return: the length of the auxiliary header in bytes (this value does NOT include the two
        word identifiers at the front of the header)
        :rtype: int
        """

    def getMandatory(self) -> bool:
        """
        :return: whether or not this auxiliary header contains information that the linker must 
        understand
        :rtype: bool
        """

    def getReserved(self) -> int:
        """
        :return: the reserved value
        :rtype: int
        """

    def getType(self) -> int:
        """
        :return: the type of auxiliary header
        :rtype: int
        
        
        
        .. seealso::
        
            | :obj:`SomConstants`
        """

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def ignore(self) -> jpype.JBoolean:
        ...

    @property
    def copy(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def mandatory(self) -> jpype.JBoolean:
        ...

    @property
    def append(self) -> jpype.JBoolean:
        ...


class SomExportEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``export_entry`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 20
    """
    The size in bytes of a :obj:`SomExportEntry`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stringTableLoc: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`SomExportEntry`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the export list
        :param jpype.JLong or int stringTableLoc: The location of the string table
        :raises IOException: if there was an IO-related error
        """

    def getInfo(self) -> int:
        """
        :return: the size of the storage request if exported symbol is of type ``STORAGE``, or
        the version of the exported symbol along with argument relocation information
        :rtype: int
        """

    def getModuleIndex(self) -> int:
        """
        :return: the index into the module table of the module defining this symbol
        :rtype: int
        """

    def getName(self) -> str:
        """
        :return: the symbol name
        :rtype: str
        """

    def getNext(self) -> int:
        """
        :return: the next export record in the hash chain
        :rtype: int
        """

    def getReserved1(self) -> int:
        """
        :return: the first reserved value
        :rtype: int
        """

    def getType(self) -> int:
        """
        :return: the symbol type
        :rtype: int
        
        
        
        .. seealso::
        
            | :obj:`SomConstants`
        """

    def getValue(self) -> int:
        """
        :return: the symbol address (subject to relocation)
        :rtype: int
        """

    def isTpRelative(self) -> bool:
        """
        :return: whether or not this is a TLS export
        :rtype: bool
        """

    @property
    def next(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def moduleIndex(self) -> jpype.JShort:
        ...

    @property
    def reserved1(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...

    @property
    def tpRelative(self) -> jpype.JBoolean:
        ...

    @property
    def info(self) -> jpype.JInt:
        ...


class SomShlibListEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``shlib_list_entry`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size in bytes of a :obj:`SomShlibListEntry`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stringTableLoc: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`SomShlibListEntry`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the header
        :param jpype.JLong or int stringTableLoc: The location of the string table
        :raises IOException: if there was an IO-related error
        """

    def getBind(self) -> int:
        """
        :return: the binding-time preference
        :rtype: int
        """

    def getDashLReference(self) -> bool:
        """
        :return: whether or not the shared library was specified on the link line with
        the ``-l`` option or not
        :rtype: bool
        """

    def getHighwaterMark(self) -> int:
        """
        :return: the ``highwater_mark`` value
        :rtype: int
        """

    def getReserved1(self) -> int:
        """
        :return: the reserved value
        :rtype: int
        """

    def getShlibName(self) -> str:
        """
        :return: the name of the shared library
        :rtype: str
        """

    def isInternalName(self) -> bool:
        """
        :return: whether or not the shared library entry is an internal name
        :rtype: bool
        """

    @property
    def internalName(self) -> jpype.JBoolean:
        ...

    @property
    def bind(self) -> jpype.JInt:
        ...

    @property
    def shlibName(self) -> java.lang.String:
        ...

    @property
    def highwaterMark(self) -> jpype.JShort:
        ...

    @property
    def dashLReference(self) -> jpype.JBoolean:
        ...

    @property
    def reserved1(self) -> jpype.JInt:
        ...


class SomSpace(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``space_dictionary_record`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 36
    """
    The size in bytes of a :obj:`SomSpace`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, spaceStringsLocation: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`SomSpace`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JLong or int spaceStringsLocation: The starting index of the space strings
        :raises IOException: if there was an IO-related error
        """

    def getInitPointerQuantity(self) -> int:
        """
        :return: the number of data (init) pointers
        :rtype: int
        """

    def getInitPonterIndex(self) -> int:
        """
        :return: the index into data (init) pointer array
        :rtype: int
        """

    def getLoaderFixIndex(self) -> int:
        """
        :return: the load fix index
        :rtype: int
        """

    def getLoaderFixQuantity(self) -> int:
        """
        :return: the load fix quantity
        :rtype: int
        """

    def getName(self) -> str:
        """
        :return: the space name
        :rtype: str
        """

    def getReserved(self) -> int:
        """
        :return: the first reserved value
        :rtype: int
        """

    def getReserved2(self) -> int:
        """
        :return: the second reserved value
        :rtype: int
        """

    def getSortKey(self) -> int:
        """
        :return: the sort key for the space
        :rtype: int
        """

    def getSpaceNumber(self) -> int:
        """
        :return: the space index
        :rtype: int
        """

    def getSubspaceIndex(self) -> int:
        """
        :return: the index into the subspace dictionary
        :rtype: int
        """

    def getSubspaceQuantity(self) -> int:
        """
        :return: the number of subspaces in the space
        :rtype: int
        """

    def hasIntermediateCode(self) -> bool:
        """
        :return: whether or not the space contains intermediate code
        :rtype: bool
        """

    def isDefined(self) -> bool:
        """
        :return: whether or not the space is defined within the file
        :rtype: bool
        """

    def isLoadable(self) -> bool:
        """
        :return: whether or not the space is loadable
        :rtype: bool
        """

    def isPrivate(self) -> bool:
        """
        :return: whether or not the space is not sharable
        :rtype: bool
        """

    def isThreadSpecific(self) -> bool:
        """
        :return: whether or not the space is thread specific
        :rtype: bool
        """

    @property
    def private(self) -> jpype.JBoolean:
        ...

    @property
    def initPointerQuantity(self) -> jpype.JLong:
        ...

    @property
    def threadSpecific(self) -> jpype.JBoolean:
        ...

    @property
    def loadable(self) -> jpype.JBoolean:
        ...

    @property
    def loaderFixIndex(self) -> jpype.JInt:
        ...

    @property
    def subspaceQuantity(self) -> jpype.JLong:
        ...

    @property
    def initPonterIndex(self) -> jpype.JInt:
        ...

    @property
    def sortKey(self) -> jpype.JInt:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def loaderFixQuantity(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def reserved2(self) -> jpype.JInt:
        ...

    @property
    def spaceNumber(self) -> jpype.JInt:
        ...

    @property
    def defined(self) -> jpype.JBoolean:
        ...

    @property
    def subspaceIndex(self) -> jpype.JInt:
        ...


class SomExecAuxHeader(SomAuxHeader):
    """
    Represents a SOM ``som_exec_auxhdr`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomExecAuxHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the auxiliary header
        :raises IOException: if there was an IO-related error
        """

    def getExecBssFill(self) -> int:
        """
        :return: BSS initialization value
        :rtype: int
        """

    def getExecBssSize(self) -> int:
        """
        :return: the uninitialized data (BSS) size in bytes
        :rtype: int
        """

    def getExecDataFile(self) -> int:
        """
        :return: the location of data in file
        :rtype: int
        """

    def getExecDataMem(self) -> int:
        """
        :return: the offset of data in memory
        :rtype: int
        """

    def getExecDataSize(self) -> int:
        """
        :return: the initialized data size in bytes
        :rtype: int
        """

    def getExecEntry(self) -> int:
        """
        :return: the offset of entrypoint
        :rtype: int
        """

    def getExecFlags(self) -> int:
        """
        :return: the loader flags
        :rtype: int
        """

    def getExecTextFile(self) -> int:
        """
        :return: the location of text in file
        :rtype: int
        """

    def getExecTextMem(self) -> int:
        """
        :return: the offset of text in memory
        :rtype: int
        """

    def getExecTextSize(self) -> int:
        """
        :return: the text size in bytes
        :rtype: int
        """

    @property
    def execBssSize(self) -> jpype.JLong:
        ...

    @property
    def execEntry(self) -> jpype.JLong:
        ...

    @property
    def execDataMem(self) -> jpype.JLong:
        ...

    @property
    def execTextMem(self) -> jpype.JLong:
        ...

    @property
    def execTextFile(self) -> jpype.JLong:
        ...

    @property
    def execDataFile(self) -> jpype.JLong:
        ...

    @property
    def execFlags(self) -> jpype.JLong:
        ...

    @property
    def execDataSize(self) -> jpype.JLong:
        ...

    @property
    def execTextSize(self) -> jpype.JLong:
        ...

    @property
    def execBssFill(self) -> jpype.JLong:
        ...


class SomPltEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``PLT_entry`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size in bytes of a :obj:`SomPltEntry`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomPltEntry`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the PLT
        :raises IOException: if there was an IO-related error
        """

    def getLtptrValue(self) -> int:
        """
        :return: the import index of the code symbol (if ``proc_addr`` points to the BOR routine
        :rtype: int
        """

    def getProcAddr(self) -> int:
        """
        :return: the address of the procedure to be branched to
        :rtype: int
        """

    @property
    def procAddr(self) -> jpype.JInt:
        ...

    @property
    def ltptrValue(self) -> jpype.JInt:
        ...


class SomHeader(ghidra.app.util.bin.StructConverter):
    """
    Represents a SOM ``header`` structure
    
    
    .. seealso::
    
        | `The 32-bit PA-RISC Run-time Architecture Document <https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 128
    """
    The size in bytes of a :obj:`SomHeader`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`SomHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the header
        :raises IOException: if there was an IO-related error
        """

    def getAuxHeaderLocation(self) -> int:
        """
        :return: the auxiliary header location
        :rtype: int
        """

    def getAuxHeaderSize(self) -> int:
        """
        :return: the auxiliary header size
        :rtype: int
        """

    @typing.overload
    def getAuxHeaders(self) -> java.util.List[SomAuxHeader]:
        """
        :return: the :obj:`List` of :obj:`auxiliary headers <SomAuxHeader>`
        :rtype: java.util.List[SomAuxHeader]
        """

    @typing.overload
    def getAuxHeaders(self, classType: java.lang.Class[T]) -> java.util.List[T]:
        """
        :return: the :obj:`List` of :obj:`auxiliary headers <SomAuxHeader>`
        :rtype: java.util.List[T]
        of the given type}
        
        :param T: The type of auxiliary header to get:param java.lang.Class[T] classType: The type of auxiliary header to get
        """

    def getChecksum(self) -> int:
        """
        :return: the checksum
        :rtype: int
        """

    def getCompilationUnits(self) -> java.util.List[SomCompilationUnit]:
        """
        :return: the :obj:`List` of :obj:`compilation units <SomCompilationUnit>`
        :rtype: java.util.List[SomCompilationUnit]
        """

    def getCompilerLocation(self) -> int:
        """
        :return: the location in file of module dictionary
        :rtype: int
        """

    def getCompilerTotal(self) -> int:
        """
        :return: the number of modules
        :rtype: int
        """

    def getDataAddress(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        :return: the starting address of the "data" space, or ``null`` if it wasn't found
        :rtype: ghidra.program.model.address.Address
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :raises java.lang.Exception: if there was a problem getting the address
        """

    def getEntryOffset(self) -> int:
        """
        :return: the offset of entry point
        :rtype: int
        """

    def getEntrySpace(self) -> int:
        """
        :return: the index of space containing entry point
        :rtype: int
        """

    def getEntrySubspace(self) -> int:
        """
        :return: the index of subspace for entry point
        :rtype: int
        """

    def getFileType(self) -> SomSysClock:
        """
        :return: the file time
        :rtype: SomSysClock
        """

    def getFirstAuxHeader(self, classType: java.lang.Class[T]) -> T:
        """
        :return: the first found :obj:`auxiliary header <SomAuxHeader>`
        :rtype: T
        of the given type}
        
        :param T: The type of auxiliary header to get:param java.lang.Class[T] classType: The type of auxiliary header to get
        """

    def getFixupRequestLocation(self) -> int:
        """
        :return: the location in file of fixup requests
        :rtype: int
        """

    def getFixupRequestTotal(self) -> int:
        """
        :return: the number of fixup requests
        :rtype: int
        """

    def getInitArrayLocation(self) -> int:
        """
        :return: the init array location
        :rtype: int
        """

    def getInitArrayTotal(self) -> int:
        """
        :return: the init array total
        :rtype: int
        """

    def getLoaderFixupLocation(self) -> int:
        """
        :return: the MPE/iX loader fixup location
        :rtype: int
        """

    def getLoaderFixupTotal(self) -> int:
        """
        :return: the number of loader fixup records
        :rtype: int
        """

    def getMagic(self) -> int:
        """
        :return: the magic
        :rtype: int
        """

    def getPresumedDp(self) -> int:
        """
        :return: the DP value assumed during compilation
        :rtype: int
        """

    def getSomLength(self) -> int:
        """
        :return: the length in bytes of entire som
        :rtype: int
        """

    def getSpaceLocation(self) -> int:
        """
        :return: the location in file of space dictionary
        :rtype: int
        """

    def getSpaceStringsLocation(self) -> int:
        """
        :return: the file location of string area for space and subspace names
        :rtype: int
        """

    def getSpaceStringsSize(self) -> int:
        """
        :return: the size of string area for space and subspace names
        :rtype: int
        """

    def getSpaceTotal(self) -> int:
        """
        :return: the number of space entries
        :rtype: int
        """

    def getSpaces(self) -> java.util.List[SomSpace]:
        """
        :return: the :obj:`List` of :obj:`spaces <SomSpace>`
        :rtype: java.util.List[SomSpace]
        """

    def getSubspaceLocation(self) -> int:
        """
        :return: the location of subspace entries
        :rtype: int
        """

    def getSubspaceTotal(self) -> int:
        """
        :return: the number of subspace entries
        :rtype: int
        """

    def getSubspaces(self) -> java.util.List[SomSubspace]:
        """
        :return: the :obj:`List` of :obj:`subspaces <SomSubspace>`
        :rtype: java.util.List[SomSubspace]
        """

    def getSymbolLocation(self) -> int:
        """
        :return: the location in file of symbol dictionary
        :rtype: int
        """

    def getSymbolStringsLocation(self) -> int:
        """
        :return: the file location of string area for module and symbol names
        :rtype: int
        """

    def getSymbolStringsSize(self) -> int:
        """
        :return: the size of string area for module and symbol names
        :rtype: int
        """

    def getSymbolTotal(self) -> int:
        """
        :return: the number of symbol records
        :rtype: int
        """

    def getSymbols(self) -> java.util.List[SomSymbol]:
        """
        :return: the :obj:`List` of :obj:`symbols <SomSymbol>`
        :rtype: java.util.List[SomSymbol]
        """

    def getSystemId(self) -> int:
        """
        :return: the system ID
        :rtype: int
        """

    def getTextAddress(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        :return: the starting address of the "text" space
        :rtype: ghidra.program.model.address.Address
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :raises java.lang.Exception: if there was a problem getting the address
        """

    def getUnloadableSpLocation(self) -> int:
        """
        :return: the byte offset of first byte of data for unloadable spaces
        :rtype: int
        """

    def getUnloadableSpSize(self) -> int:
        """
        :return: the byte length of data for unloadable spaces
        :rtype: int
        """

    def getVersionId(self) -> int:
        """
        :return: the version ID
        :rtype: int
        """

    def hasValidMagic(self) -> bool:
        """
        :return: true if this :obj:`SomHeader` has a valid magic number; otherwise false
        :rtype: bool
        """

    def hasValidVersionId(self) -> bool:
        """
        :return: true if this :obj:`SomHeader` has a valid version ID; otherwise false
        :rtype: bool
        """

    def markup(self, program: ghidra.program.model.listing.Program, headerAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Marks up this header
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.Address headerAddr: The :obj:`Address` of this header
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :raises java.lang.Exception: if there was a problem during markup
        """

    @property
    def textAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def magic(self) -> jpype.JInt:
        ...

    @property
    def spaceStringsSize(self) -> jpype.JLong:
        ...

    @property
    def symbolStringsLocation(self) -> jpype.JLong:
        ...

    @property
    def entrySpace(self) -> jpype.JLong:
        ...

    @property
    def unloadableSpLocation(self) -> jpype.JLong:
        ...

    @property
    def symbolLocation(self) -> jpype.JLong:
        ...

    @property
    def somLength(self) -> jpype.JLong:
        ...

    @property
    def symbols(self) -> java.util.List[SomSymbol]:
        ...

    @property
    def subspaceTotal(self) -> jpype.JLong:
        ...

    @property
    def compilerTotal(self) -> jpype.JLong:
        ...

    @property
    def loaderFixupTotal(self) -> jpype.JLong:
        ...

    @property
    def spaceLocation(self) -> jpype.JLong:
        ...

    @property
    def checksum(self) -> jpype.JLong:
        ...

    @property
    def subspaceLocation(self) -> jpype.JLong:
        ...

    @property
    def entryOffset(self) -> jpype.JLong:
        ...

    @property
    def initArrayLocation(self) -> jpype.JLong:
        ...

    @property
    def systemId(self) -> jpype.JInt:
        ...

    @property
    def spaceStringsLocation(self) -> jpype.JLong:
        ...

    @property
    def dataAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def auxHeaders(self) -> java.util.List[SomAuxHeader]:
        ...

    @property
    def presumedDp(self) -> jpype.JLong:
        ...

    @property
    def spaceTotal(self) -> jpype.JLong:
        ...

    @property
    def initArrayTotal(self) -> jpype.JLong:
        ...

    @property
    def entrySubspace(self) -> jpype.JLong:
        ...

    @property
    def firstAuxHeader(self) -> T:
        ...

    @property
    def auxHeaderSize(self) -> jpype.JLong:
        ...

    @property
    def loaderFixupLocation(self) -> jpype.JLong:
        ...

    @property
    def fixupRequestTotal(self) -> jpype.JLong:
        ...

    @property
    def compilationUnits(self) -> java.util.List[SomCompilationUnit]:
        ...

    @property
    def symbolStringsSize(self) -> jpype.JLong:
        ...

    @property
    def symbolTotal(self) -> jpype.JLong:
        ...

    @property
    def auxHeaderLocation(self) -> jpype.JLong:
        ...

    @property
    def unloadableSpSize(self) -> jpype.JLong:
        ...

    @property
    def versionId(self) -> jpype.JLong:
        ...

    @property
    def subspaces(self) -> java.util.List[SomSubspace]:
        ...

    @property
    def fixupRequestLocation(self) -> jpype.JLong:
        ...

    @property
    def compilerLocation(self) -> jpype.JLong:
        ...

    @property
    def spaces(self) -> java.util.List[SomSpace]:
        ...

    @property
    def fileType(self) -> SomSysClock:
        ...



__all__ = ["SomAuxHeader", "SomLinkerFootprintAuxHeader", "SomUnknownAuxHeader", "SomProductSpecificsAuxHeader", "SomSubspace", "SomSysClock", "SomAuxHeaderFactory", "SomConstants", "SomDynamicRelocation", "SomExportEntryExt", "SomSymbol", "SomCompilationUnit", "SomDynamicLoaderHeader", "SomModuleEntry", "SomImportEntry", "SomDltEntry", "SomAuxId", "SomExportEntry", "SomShlibListEntry", "SomSpace", "SomExecAuxHeader", "SomPltEntry", "SomHeader"]
