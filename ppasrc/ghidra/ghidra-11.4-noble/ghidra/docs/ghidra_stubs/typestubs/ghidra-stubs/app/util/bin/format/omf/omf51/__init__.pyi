from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.omf
import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore


class Omf51LibraryDictionaryRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`Omf51LibraryDictionaryRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: if an IO-related error occurred
        """

    def getModuleSymbolMap(self) -> java.util.List[java.util.List[ghidra.app.util.bin.format.omf.OmfString]]:
        """
        :return: the symbol names partitioned by module
        :rtype: java.util.List[java.util.List[ghidra.app.util.bin.format.omf.OmfString]]
        """

    @property
    def moduleSymbolMap(self) -> java.util.List[java.util.List[ghidra.app.util.bin.format.omf.OmfString]]:
        ...


class Omf51LibraryModuleLocationsRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`Omf51LibraryModuleLocationsRecord` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: if an IO-related error occurred
        """

    def getLocations(self) -> java.util.List[Omf51LibraryModuleLocation]:
        """
        :return: the list of module locations
        :rtype: java.util.List[Omf51LibraryModuleLocation]
        """

    @property
    def locations(self) -> java.util.List[Omf51LibraryModuleLocation]:
        ...


class Omf51ModuleEnd(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`Omf51ModuleEnd` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: if an IO-related error occurred
        """

    def getRegisterMask(self) -> int:
        """
        :return: the register mask
        :rtype: int
        """

    @property
    def registerMask(self) -> jpype.JByte:
        ...


class Omf51SegmentDefs(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeSegmentId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51SegmentDefs` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JBoolean or bool largeSegmentId: True if the segment ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def getSegments(self) -> java.util.List[Omf51Segment]:
        """
        :return: the list of segments
        :rtype: java.util.List[Omf51Segment]
        """

    @property
    def segments(self) -> java.util.List[Omf51Segment]:
        ...


class Omf51PublicDef(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    CODE: typing.Final = 0
    XDATA: typing.Final = 1
    DATA: typing.Final = 2
    IDATA: typing.Final = 3
    BIT: typing.Final = 4
    NUMBER: typing.Final = 5
    REG_BANK_0: typing.Final = 0
    REG_BANK_1: typing.Final = 1
    REG_BANK_2: typing.Final = 2
    REG_BANK_3: typing.Final = 3

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeSegmentId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51PublicDef`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the public definition
        :param jpype.JBoolean or bool largeSegmentId: True if the segment ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def getInfo(self) -> int:
        """
        :return: the segment info
        :rtype: int
        """

    def getName(self) -> ghidra.app.util.bin.format.omf.OmfString:
        """
        :return: the symbol name
        :rtype: ghidra.app.util.bin.format.omf.OmfString
        """

    def getOffset(self) -> int:
        """
        :return: the offset into the segment
        :rtype: int
        """

    def getRegBank(self) -> int:
        """
        :return: the register bank this procedure is fixed to
        :rtype: int
        """

    def getSegId(self) -> int:
        """
        :return: the segment id
        :rtype: int
        """

    def getUsageType(self) -> int:
        """
        :return: the usage type (CODE, XDATA, etc)
        :rtype: int
        """

    def isFixedReg(self) -> bool:
        """
        :return: whether or not this procedure is fixed to a register bank
        :rtype: bool
        """

    def isIndirectlyCallable(self) -> bool:
        """
        :return: whether or not this procedure is indirectly callable
        :rtype: bool
        """

    def isVariable(self) -> bool:
        """
        :return: whether or not this symbol is a variable or not
        :rtype: bool
        """

    @property
    def segId(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def variable(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> ghidra.app.util.bin.format.omf.OmfString:
        ...

    @property
    def fixedReg(self) -> jpype.JBoolean:
        ...

    @property
    def regBank(self) -> jpype.JInt:
        ...

    @property
    def indirectlyCallable(self) -> jpype.JBoolean:
        ...

    @property
    def usageType(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> jpype.JByte:
        ...


class Omf51Segment(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    CODE: typing.Final = 0
    XDATA: typing.Final = 1
    DATA: typing.Final = 2
    IDATA: typing.Final = 3
    BIT: typing.Final = 4
    ABS: typing.Final = 0
    UNIT: typing.Final = 1
    BITADDRESSABLE: typing.Final = 2
    INPAGE: typing.Final = 3
    INBLOCK: typing.Final = 4
    PAGE: typing.Final = 5

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeSegmentId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51Segment`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the segment definition
        :param jpype.JBoolean or bool largeSegmentId: True if the segment ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def base(self) -> int:
        """
        :return: the segment base address
        :rtype: int
        """

    def getType(self) -> int:
        """
        :return: the segment type (CODE, XDATA, etc)
        :rtype: int
        """

    def id(self) -> int:
        """
        :return: the segment id
        :rtype: int
        """

    def info(self) -> int:
        """
        :return: the segment info
        :rtype: int
        """

    def isAbsolute(self) -> bool:
        """
        :return: whether or not this segment is absolute
        :rtype: bool
        """

    def isCode(self) -> bool:
        """
        :return: whether or not this segment is code
        :rtype: bool
        """

    def name(self) -> ghidra.app.util.bin.format.omf.OmfString:
        """
        :return: the segment name
        :rtype: ghidra.app.util.bin.format.omf.OmfString
        """

    def relType(self) -> int:
        """
        :return: the segment relocation type
        :rtype: int
        """

    def size(self) -> int:
        """
        :return: the segment size
        :rtype: int
        """

    @property
    def code(self) -> jpype.JBoolean:
        ...

    @property
    def absolute(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...


class Omf51FixupRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeBlockId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51FixupRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JBoolean or bool largeBlockId: True if the block ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def getFixups(self) -> java.util.List[Omf51Fixup]:
        """
        Gets a :obj:`List` of fixups
        
        :return: A :obj:`List` of fixups
        :rtype: java.util.List[Omf51Fixup]
        """

    @property
    def fixups(self) -> java.util.List[Omf51Fixup]:
        ...


class Omf51ExternalDefsRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeExtId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51ExternalDefsRecord` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JBoolean or bool largeExtId: True if the external ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def getDefinitions(self) -> java.util.List[Omf51ExternalDef]:
        """
        :return: the list of external definitions
        :rtype: java.util.List[Omf51ExternalDef]
        """

    @property
    def definitions(self) -> java.util.List[Omf51ExternalDef]:
        ...


class Omf51RecordTypes(java.lang.Object):
    """
    OMF-51 record types
    
    
    .. seealso::
    
        | `OMF-51 Object Module Format <https://turbo51.com/documentation/omf-51-object-module-format>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    ModuleHDR: typing.Final = 2
    ModuleEND: typing.Final = 4
    Content: typing.Final = 6
    Fixup: typing.Final = 8
    SegmentDEF: typing.Final = 14
    ScopeDEF: typing.Final = 16
    DebugItem: typing.Final = 18
    PublicDEF: typing.Final = 22
    ExternalDEF: typing.Final = 24
    LibModLocs: typing.Final = 38
    LibModNames: typing.Final = 40
    LibDictionary: typing.Final = 42
    LibHeader: typing.Final = 44
    KeilContent: typing.Final = 7
    KeilFixup: typing.Final = 9
    KeilSegmentDEF: typing.Final = 15
    KeilScopeDEF: typing.Final = 17
    KeilPublicDEF: typing.Final = 23
    KeilExternalDEF: typing.Final = 25
    KeilDebugItemOBJ: typing.Final = 34
    KeilDebugItemSRC: typing.Final = 35
    KeilModuleSourceName: typing.Final = 36
    KeilSourceBrowserFiles: typing.Final = 97
    KeilDebugData62: typing.Final = 98
    KeilDebugData63: typing.Final = 99
    KeilDebugData64: typing.Final = 100

    def __init__(self):
        ...

    @staticmethod
    def getName(type: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets the name of the given record type
        
        :param jpype.JInt or int type: The record type
        :return: The name of the given record type
        :rtype: str
        """


class Omf51Library(java.lang.Object):

    class MemberHeader(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def offset(self) -> int:
            ...

        def size(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: Omf51RecordFactory):
        """
        Creates a new :obj:`Omf51Library`
        
        :param Omf51RecordFactory factory: A :obj:`Omf51RecordFactory`
        :raises IOException: if an IO-related error occurred
        :raises OmfException: if the required OMF-51 records could not be read
        """

    def getMembers(self) -> java.util.List[Omf51Library.MemberHeader]:
        """
        :return: the list of members
        :rtype: java.util.List[Omf51Library.MemberHeader]
        """

    @property
    def members(self) -> java.util.List[Omf51Library.MemberHeader]:
        ...


class Omf51RecordFactory(ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory):
    """
    A class for reading/creating OMF-51 records
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        """
        Creates a new :obj:`Omf51RecordFactory`
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` that contains the records
        """


class Omf51PublicDefsRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeSegmentId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51PublicDefsRecord` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JBoolean or bool largeSegmentId: True if the segment ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def getDefinitions(self) -> java.util.List[Omf51PublicDef]:
        """
        :return: the list of public definitions
        :rtype: java.util.List[Omf51PublicDef]
        """

    @property
    def definitions(self) -> java.util.List[Omf51PublicDef]:
        ...


class Omf51ExternalDef(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    ID_BLOCK_SEGMENT: typing.Final = 0
    ID_BLOCK_RELOCATABLE: typing.Final = 1
    ID_BLOCK_EXTERNAL: typing.Final = 2

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeSegmentId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51ExternalDef`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the external definition
        :param jpype.JBoolean or bool largeSegmentId: True if the external ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def getBlockType(self) -> int:
        """
        :return: the block type (should always be 2 - ID_BLOCK_EXTERNAL
        :rtype: int
        """

    def getExtId(self) -> int:
        """
        :return: the external reference id
        :rtype: int
        """

    def getInfo(self) -> int:
        """
        :return: the symbol info
        :rtype: int
        """

    def getName(self) -> ghidra.app.util.bin.format.omf.OmfString:
        """
        :return: the symbol name
        :rtype: ghidra.app.util.bin.format.omf.OmfString
        """

    def getRegBank(self) -> int:
        """
        :return: the register bank this procedure is fixed to
        :rtype: int
        """

    def getUsageType(self) -> int:
        """
        :return: the usage type (CODE, XDATA, etc)
        :rtype: int
        """

    def isFixedReg(self) -> bool:
        """
        :return: whether or not this procedure is fixed to a register bank
        :rtype: bool
        """

    def isVariable(self) -> bool:
        """
        :return: whether or not this symbol is a variable or not
        :rtype: bool
        """

    @property
    def blockType(self) -> jpype.JByte:
        ...

    @property
    def variable(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> ghidra.app.util.bin.format.omf.OmfString:
        ...

    @property
    def fixedReg(self) -> jpype.JBoolean:
        ...

    @property
    def regBank(self) -> jpype.JInt:
        ...

    @property
    def extId(self) -> jpype.JInt:
        ...

    @property
    def usageType(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> jpype.JByte:
        ...


class Omf51LibraryModuleNamesRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`Omf51LibraryModuleNamesRecord` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: if an IO-related error occurred
        """

    def getNames(self) -> java.util.List[ghidra.app.util.bin.format.omf.OmfString]:
        """
        :return: the list of module names
        :rtype: java.util.List[ghidra.app.util.bin.format.omf.OmfString]
        """

    @property
    def names(self) -> java.util.List[ghidra.app.util.bin.format.omf.OmfString]:
        ...


class Omf51LibraryHeaderRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]
    BLOCK_SIZE: typing.Final = 128

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`Omf51LibraryHeaderRecord` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: if an IO-related error occurred
        """

    def getModNamesBlockNumber(self) -> int:
        """
        :return: the module names block number
        :rtype: int
        """

    def getModNamesByteNumber(self) -> int:
        """
        :return: the module names byte number
        :rtype: int
        """

    def getModNamesOffset(self) -> int:
        """
        :return: the module names file offset
        :rtype: int
        """

    def getModuleCount(self) -> int:
        """
        :return: the module count
        :rtype: int
        """

    @property
    def modNamesOffset(self) -> jpype.JInt:
        ...

    @property
    def modNamesBlockNumber(self) -> jpype.JShort:
        ...

    @property
    def modNamesByteNumber(self) -> jpype.JShort:
        ...

    @property
    def moduleCount(self) -> jpype.JShort:
        ...


class Omf51ModuleHeader(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`Omf51ModuleHeader` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: if an IO-related error occurred
        """

    def getTrnId(self) -> int:
        """
        :return: the TRN ID
        :rtype: int
        """

    @property
    def trnId(self) -> jpype.JByte:
        ...


class Omf51LibraryModuleLocation(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    BLOCK_SIZE: typing.Final = 128

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`Omf51LibraryModuleLocation`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the segment definition
        :raises IOException: if an IO-related error occurred
        """

    def getBlockNumber(self) -> int:
        """
        :return: the block number
        :rtype: int
        """

    def getByteNumber(self) -> int:
        """
        :return: the byte number
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        :return: the offset into the library
        :rtype: int
        """

    @staticmethod
    def toDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def byteNumber(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def blockNumber(self) -> jpype.JInt:
        ...


class Omf51Fixup(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    REF_TYPE_LOW: typing.Final = 0
    REF_TYPE_BYTE: typing.Final = 1
    REF_TYPE_RELATIVE: typing.Final = 2
    REF_TYPE_HIGH: typing.Final = 3
    REF_TYPE_WORD: typing.Final = 4
    REF_TYPE_INBLOCK: typing.Final = 5
    REF_TYPE_BIT: typing.Final = 6
    REF_TYPE_CONV: typing.Final = 7
    ID_BLOCK_SEGMENT: typing.Final = 0
    ID_BLOCK_RELOCATABLE: typing.Final = 1
    ID_BLOCK_EXTERNAL: typing.Final = 2

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeBlockId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51Fixup`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the fixup
        :param jpype.JBoolean or bool largeBlockId: True if the block ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def getBlockId(self) -> int:
        """
        :return: the operand id (segment ID or EXT ID)
        :rtype: int
        """

    def getBlockType(self) -> int:
        """
        :return: the operand block type (ID BLK)
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        :return: the operand offset
        :rtype: int
        """

    def getRefLoc(self) -> int:
        """
        :return: the reference location (REFLOC)
        :rtype: int
        """

    def getRefType(self) -> int:
        """
        :return: the reference type (REF TYP)
        :rtype: int
        """

    @property
    def blockId(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def blockType(self) -> jpype.JInt:
        ...

    @property
    def refType(self) -> jpype.JInt:
        ...

    @property
    def refLoc(self) -> jpype.JInt:
        ...


class Omf51Content(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, largeSegmentId: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`Omf51Content` record
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param jpype.JBoolean or bool largeSegmentId: True if the segment ID is 2 bytes; false if 1 byte
        :raises IOException: if an IO-related error occurred
        """

    def getDataIndex(self) -> int:
        """
        :return: the start of the data in the reader
        :rtype: int
        """

    def getDataSize(self) -> int:
        """
        :return: the data size in bytes
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        :return: the offset
        :rtype: int
        """

    def getSegId(self) -> int:
        """
        :return: the segment ID
        :rtype: int
        """

    @property
    def segId(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def dataIndex(self) -> jpype.JLong:
        ...

    @property
    def dataSize(self) -> jpype.JInt:
        ...



__all__ = ["Omf51LibraryDictionaryRecord", "Omf51LibraryModuleLocationsRecord", "Omf51ModuleEnd", "Omf51SegmentDefs", "Omf51PublicDef", "Omf51Segment", "Omf51FixupRecord", "Omf51ExternalDefsRecord", "Omf51RecordTypes", "Omf51Library", "Omf51RecordFactory", "Omf51PublicDefsRecord", "Omf51ExternalDef", "Omf51LibraryModuleNamesRecord", "Omf51LibraryHeaderRecord", "Omf51ModuleHeader", "Omf51LibraryModuleLocation", "Omf51Fixup", "Omf51Content"]
