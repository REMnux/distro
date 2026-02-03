from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.omf
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class OmfExternalSymbol(ghidra.app.util.bin.format.omf.OmfRecord):

    @typing.type_check_only
    class Reference(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> ghidra.app.util.bin.format.omf.OmfString:
            ...

        def toString(self) -> str:
            ...

        def typeIndex(self) -> ghidra.app.util.bin.format.omf.OmfIndex:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, isStatic: typing.Union[jpype.JBoolean, bool]):
        ...

    def getSymbols(self) -> java.util.List[OmfSymbol]:
        ...

    def isStatic(self) -> bool:
        ...

    @property
    def static(self) -> jpype.JBoolean:
        ...

    @property
    def symbols(self) -> java.util.List[OmfSymbol]:
        ...


class OmfComdefRecord(OmfExternalSymbol):

    @typing.type_check_only
    class Reference(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def communalLength1(self) -> OmfComdefRecord.OmfCommunalLength:
            ...

        def communalLength2(self) -> OmfComdefRecord.OmfCommunalLength:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> ghidra.app.util.bin.format.omf.OmfString:
            ...

        def toString(self) -> str:
            ...

        def typeIndex(self) -> ghidra.app.util.bin.format.omf.OmfIndex:
            ...


    @typing.type_check_only
    class OmfCommunalLength(ghidra.app.util.bin.StructConverter):
        """
        A OMF COMDEF "communal length"
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, isStatic: typing.Union[jpype.JBoolean, bool]):
        ...


class OmfGroupRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class GroupSubrecord(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @staticmethod
        def read(reader: ghidra.app.util.bin.BinaryReader) -> OmfGroupRecord.GroupSubrecord:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getAddress(self, language: ghidra.program.model.lang.Language) -> ghidra.program.model.address.Address:
        ...

    def getFrameDatum(self) -> int:
        """
        This is the segment selector needed for this object
        
        :return: The segment selector
        :rtype: int
        """

    def getName(self) -> str:
        ...

    def getSegmentComponentType(self, i: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getSegmentIndex(self, i: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getStartAddress(self) -> int:
        ...

    def numSegments(self) -> int:
        ...

    def resolveNames(self, nameList: java.util.List[java.lang.String]):
        ...

    def setStartAddress(self, val: typing.Union[jpype.JLong, int]):
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def startAddress(self) -> jpype.JLong:
        ...

    @startAddress.setter
    def startAddress(self, value: jpype.JLong):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def segmentIndex(self) -> jpype.JInt:
        ...

    @property
    def frameDatum(self) -> jpype.JInt:
        ...

    @property
    def segmentComponentType(self) -> jpype.JByte:
        ...


class OmfCommentRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]
    COMMENT_CLASS_TRANSLATOR: typing.Final = 0
    COMMENT_CLASS_LIBMOD: typing.Final = -93
    COMMENT_CLASS_DEFAULT_LIBRARY: typing.Final = -97
    COMMENT_CLASS_WATCOM_SETTINGS: typing.Final = -101
    COMMENT_CLASS_MICROSOFT_SETTINGS: typing.Final = -99

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getCommentClass(self) -> int:
        ...

    def getCommentType(self) -> int:
        ...

    def getValue(self) -> str:
        ...

    @property
    def commentClass(self) -> jpype.JByte:
        ...

    @property
    def commentType(self) -> jpype.JByte:
        ...

    @property
    def value(self) -> java.lang.String:
        ...


class OmfRecordTypes(java.lang.Object):
    """
    Relocatable OMF record types
    
    
    .. seealso::
    
        | `OMF: Relocatable Object Module Format <http://www.azillionmonkeys.com/qed/Omfg.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    RHEADR: typing.Final = 110
    REGINT: typing.Final = 112
    REDATA: typing.Final = 114
    RIDATA: typing.Final = 116
    OVLDEF: typing.Final = 118
    ENDREC: typing.Final = 120
    BLKDEF: typing.Final = 122
    BLKEND: typing.Final = 124
    DEBSYM: typing.Final = 126
    THEADR: typing.Final = 128
    LHEADR: typing.Final = 130
    PEDATA: typing.Final = 132
    PIDATA: typing.Final = 134
    COMENT: typing.Final = 136
    MODEND: typing.Final = 138
    EXTDEF: typing.Final = 140
    TYPDEF: typing.Final = 142
    PUBDEF: typing.Final = 144
    LOCSYM: typing.Final = 146
    LINNUM: typing.Final = 148
    LNAMES: typing.Final = 150
    SEGDEF: typing.Final = 152
    GRPDEF: typing.Final = 154
    FIXUPP: typing.Final = 156
    LEDATA: typing.Final = 160
    LIDATA: typing.Final = 162
    LIBHED: typing.Final = 164
    LIBNAM: typing.Final = 166
    LIBLOC: typing.Final = 168
    LIBDIC: typing.Final = 170
    COMDEF: typing.Final = 176
    BAKPAT: typing.Final = 178
    LEXTDEF: typing.Final = 180
    LPUBDEF: typing.Final = 182
    LCOMDEF: typing.Final = 184
    CEXTDEF: typing.Final = 188
    COMDAT: typing.Final = 194
    LINSYM: typing.Final = 196
    ALIAS: typing.Final = 198
    NBKPAT: typing.Final = 200
    LLNAMES: typing.Final = 202
    VERNUM: typing.Final = 204
    VENDEXT: typing.Final = 206
    START: typing.Final = 240
    END: typing.Final = 241

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


class OmfIteratedData(OmfData):

    class DataBlock(java.lang.Object):
        """
        Contain the definition of one part of a datablock with possible recursion
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def fillBuffer(self, buffer: jpype.JArray[jpype.JByte], pos: typing.Union[jpype.JInt, int]) -> int:
            """
            Fill part of the buffer
            
            :param jpype.JArray[jpype.JByte] buffer: The buffer to fill
            :param jpype.JInt or int pos: The next position to fill
            :return: The position after the block
            :rtype: int
            """

        def getLength(self) -> int:
            """
            
            
            :return: The length of this block
            :rtype: int
            """

        def isAllZeroes(self) -> bool:
            """
            
            
            :return: true if this DataBlock only represents zero bytes
            :rtype: bool
            """

        @staticmethod
        def read(reader: ghidra.app.util.bin.BinaryReader, hasBigFields: typing.Union[jpype.JBoolean, bool]) -> OmfIteratedData.DataBlock:
            ...

        @property
        def allZeroes(self) -> jpype.JBoolean:
            ...

        @property
        def length(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    MAX_ITERATED_FILL: typing.Final = 1048576

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...


class OmfComdatExternalSymbol(OmfExternalSymbol):

    class ExternalLookup(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, nameIndex: typing.Union[jpype.JInt, int], type: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def nameIndex(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> int:
            ...


    @typing.type_check_only
    class Reference(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def nameIndex(self) -> ghidra.app.util.bin.format.omf.OmfIndex:
            ...

        def toString(self) -> str:
            ...

        def typeIndex(self) -> ghidra.app.util.bin.format.omf.OmfIndex:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def loadNames(self, nameList: java.util.List[java.lang.String]):
        ...


class OmfFixupRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class Subrecord(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def getDataRecordOffset(self) -> int:
            ...

        def getFixMethod(self) -> int:
            ...

        def getFixMethodWithSub(self, rec: OmfFixupRecord.Subrecord) -> int:
            ...

        def getFixThreadNum(self) -> int:
            ...

        def getFrameMethod(self) -> int:
            ...

        def getIndex(self) -> int:
            """
            
            
            :return: Get the index for explicit thread or frame
            :rtype: int
            """

        def getLocationType(self) -> int:
            ...

        def getTargetDatum(self) -> int:
            ...

        def getTargetDisplacement(self) -> int:
            ...

        def getThreadMethod(self) -> int:
            """
            
            
            :return: The method value from a Thread subrecord
            :rtype: int
            """

        def getThreadNum(self) -> int:
            """
            
            
            :return: Get the thread index from flag
            :rtype: int
            """

        def isFrameInSubThread(self) -> bool:
            """
            
            
            :return: True if this is a frame reference
            :rtype: bool
            """

        def isFrameThread(self) -> bool:
            ...

        def isSegmentRelative(self) -> bool:
            ...

        def isTargetThread(self) -> bool:
            ...

        def isThreadSubrecord(self) -> bool:
            """
            
            
            :return: True if this is a Thread subrecord type
            :rtype: bool
            """

        @staticmethod
        def readSubrecord(reader: ghidra.app.util.bin.BinaryReader, hasBigFields: typing.Union[jpype.JBoolean, bool]) -> OmfFixupRecord.Subrecord:
            """
            Read the next subrecord from the input reader
            
            :param ghidra.app.util.bin.BinaryReader reader: The input file
            :param jpype.JBoolean or bool hasBigFields: Is this 16 or 32 bit values
            :return: The read subrecord
            :rtype: OmfFixupRecord.Subrecord
            :raises IOException: if there was an IO-related error
            """

        @property
        def fixMethod(self) -> jpype.JInt:
            ...

        @property
        def targetDisplacement(self) -> jpype.JInt:
            ...

        @property
        def targetDatum(self) -> jpype.JInt:
            ...

        @property
        def dataRecordOffset(self) -> jpype.JInt:
            ...

        @property
        def threadSubrecord(self) -> jpype.JBoolean:
            ...

        @property
        def targetThread(self) -> jpype.JBoolean:
            ...

        @property
        def locationType(self) -> jpype.JInt:
            ...

        @property
        def index(self) -> jpype.JInt:
            ...

        @property
        def frameThread(self) -> jpype.JBoolean:
            ...

        @property
        def threadMethod(self) -> jpype.JInt:
            ...

        @property
        def fixMethodWithSub(self) -> jpype.JInt:
            ...

        @property
        def frameMethod(self) -> jpype.JInt:
            ...

        @property
        def fixThreadNum(self) -> jpype.JInt:
            ...

        @property
        def segmentRelative(self) -> jpype.JBoolean:
            ...

        @property
        def frameInSubThread(self) -> jpype.JBoolean:
            ...

        @property
        def threadNum(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Read a Fixup record from the input reader
        
        :param ghidra.app.util.bin.BinaryReader reader: The actual reader
        :raises IOException: if there was an IO-related error
        """

    def getDataBlock(self) -> OmfData:
        """
        
        
        :return: The datablock this fixup record is meant for
        :rtype: OmfData
        """

    def getSubrecords(self) -> jpype.JArray[OmfFixupRecord.Subrecord]:
        """
        
        
        :return: The array of subrecords
        :rtype: jpype.JArray[OmfFixupRecord.Subrecord]
        """

    def setDataBlock(self, last: OmfData):
        """
        
        
        :param OmfData last: The Datablock this fixup record is meant for
        """

    @property
    def dataBlock(self) -> OmfData:
        ...

    @dataBlock.setter
    def dataBlock(self, value: OmfData):
        ...

    @property
    def subrecords(self) -> jpype.JArray[OmfFixupRecord.Subrecord]:
        ...


class OmfSegmentHeader(ghidra.app.util.bin.format.omf.OmfRecord):

    class SectionStream(java.io.InputStream):
        """
        An InputStream that produces the bytes for the dataBlocks in this segment.
        It runs through the ordered :obj:`OmfData` in turn.  It pads with zeroes,
        wherever part of the segment is not covered by a data block.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, log: ghidra.app.util.importer.MessageLog):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getAddress(self, language: ghidra.program.model.lang.Language) -> ghidra.program.model.address.Address:
        """
        
        
        :param ghidra.program.model.lang.Language language: is the Program language for this binary
        :return: the starting Address for this segment
        :rtype: ghidra.program.model.address.Address
        """

    def getAlignment(self) -> int:
        """
        
        
        :return: the alignment required for this segment
        :rtype: int
        """

    def getClassName(self) -> str:
        """
        
        
        :return: the class name of this segment
        :rtype: str
        """

    def getCombine(self) -> int:
        """
        
        
        :return: special combining rules for this segment
        :rtype: int
        """

    def getFrameDatum(self) -> int:
        """
        
        
        :return: the segment selector needed for this object
        :rtype: int
        """

    def getName(self) -> str:
        """
        
        
        :return: the name of this segment
        :rtype: str
        """

    def getOverlayName(self) -> str:
        """
        
        
        :return: the name of the overlay, or the empty string
        :rtype: str
        """

    def getRawDataStream(self, reader: ghidra.app.util.bin.BinaryReader, log: ghidra.app.util.importer.MessageLog) -> java.io.InputStream:
        """
        Get an InputStream that reads in the raw data for this segment
        
        :param ghidra.app.util.bin.BinaryReader reader: is the image file reader
        :param ghidra.app.util.importer.MessageLog log: the log
        :return: the InputStream
        :rtype: java.io.InputStream
        :raises IOException: for problems reading from the image file
        """

    def getSegmentLength(self) -> int:
        """
        
        
        :return: the length of the segment in bytes
        :rtype: int
        """

    def getStartAddress(self) -> int:
        """
        
        
        :return: the load image address for this segment
        :rtype: int
        """

    def hasNonZeroData(self) -> bool:
        """
        
        
        :return: true if this block uses filler other than zero bytes
        :rtype: bool
        """

    def is16Bit(self) -> bool:
        """
        
        
        :return: if 16 or 32 bit segments are used
        :rtype: bool
        """

    def isCode(self) -> bool:
        """
        
        
        :return: true if this is a code segment
        :rtype: bool
        """

    def isExecutable(self) -> bool:
        """
        
        
        :return: true if this segment is executable
        :rtype: bool
        """

    def isReadable(self) -> bool:
        """
        
        
        :return: true if this segment is readable
        :rtype: bool
        """

    def isWritable(self) -> bool:
        """
        
        
        :return: true if this segment is writable
        :rtype: bool
        """

    @property
    def readable(self) -> jpype.JBoolean:
        ...

    @property
    def code(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def overlayName(self) -> java.lang.String:
        ...

    @property
    def startAddress(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def frameDatum(self) -> jpype.JInt:
        ...

    @property
    def className(self) -> java.lang.String:
        ...

    @property
    def segmentLength(self) -> jpype.JLong:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @property
    def executable(self) -> jpype.JBoolean:
        ...

    @property
    def writable(self) -> jpype.JBoolean:
        ...

    @property
    def combine(self) -> jpype.JInt:
        ...


class OmfSymbolRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    @typing.type_check_only
    class Reference(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> ghidra.app.util.bin.format.omf.OmfString:
            ...

        def offset(self) -> ghidra.app.util.bin.format.omf.Omf2or4:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> ghidra.app.util.bin.format.omf.OmfIndex:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, isStatic: typing.Union[jpype.JBoolean, bool]):
        ...

    def getBaseFrame(self) -> int:
        ...

    def getGroupIndex(self) -> int:
        ...

    def getSegmentIndex(self) -> int:
        ...

    def getSymbol(self, i: typing.Union[jpype.JInt, int]) -> OmfSymbol:
        ...

    def getSymbols(self) -> java.util.List[OmfSymbol]:
        ...

    def isStatic(self) -> bool:
        ...

    def numSymbols(self) -> int:
        ...

    @property
    def symbol(self) -> OmfSymbol:
        ...

    @property
    def static(self) -> jpype.JBoolean:
        ...

    @property
    def baseFrame(self) -> jpype.JInt:
        ...

    @property
    def segmentIndex(self) -> jpype.JInt:
        ...

    @property
    def groupIndex(self) -> jpype.JInt:
        ...

    @property
    def symbols(self) -> java.util.List[OmfSymbol]:
        ...


class OmfFileHeader(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    @staticmethod
    def checkMagicNumber(reader: ghidra.app.util.bin.BinaryReader) -> bool:
        """
        Check that the file has the specific OMF magic number
        
        :param ghidra.app.util.bin.BinaryReader reader: accesses the bytes of the file
        :return: true if the magic number matches
        :rtype: bool
        :raises IOException: for problems reading bytes
        """

    @staticmethod
    def doLinking(startAddress: typing.Union[jpype.JLong, int], segments: java.util.List[OmfSegmentHeader], groups: java.util.List[OmfGroupRecord]):
        """
        Assign a load image address to each segment. Follow OMF rules for grouping and ordering
        the segments in memory.
        
        :param jpype.JLong or int startAddress: is the base memory address for the load image
        :param java.util.List[OmfSegmentHeader] segments: is the list of segments
        :param java.util.List[OmfGroupRecord] groups: is the list of specific segments that are grouped together in memory
        :raises OmfException: for malformed index/alignment/combining fields
        """

    def getExternalSymbols(self) -> java.util.List[OmfExternalSymbol]:
        """
        
        
        :return: the list of symbols that are external to this file
        :rtype: java.util.List[OmfExternalSymbol]
        """

    def getExtraSegments(self) -> java.util.List[OmfSegmentHeader]:
        """
        
        
        :return: the list of segments which are Borland extensions
        :rtype: java.util.List[OmfSegmentHeader]
        """

    def getFixups(self) -> java.util.List[OmfFixupRecord]:
        """
        
        
        :return: the list of relocation records for this file
        :rtype: java.util.List[OmfFixupRecord]
        """

    def getGroups(self) -> java.util.List[OmfGroupRecord]:
        """
        
        
        :return: the list of group records for this file
        :rtype: java.util.List[OmfGroupRecord]
        """

    def getLibraryModuleName(self) -> str:
        """
        The name of the object module (within a library)
        
        :return: the name
        :rtype: str
        """

    def getLocalSymbols(self) -> java.util.List[OmfSymbolRecord]:
        """
        
        
        :return: the list of local symbols in this file
        :rtype: java.util.List[OmfSymbolRecord]
        """

    def getMachineName(self) -> str:
        """
        
        
        :return: the string identifying the architecture this object was compiled for
        :rtype: str
        """

    def getName(self) -> str:
        """
        This is usually the original source filename
        
        :return: the name
        :rtype: str
        """

    def getPublicSymbols(self) -> java.util.List[OmfSymbolRecord]:
        """
        
        
        :return: the list of public symbols exported by this file
        :rtype: java.util.List[OmfSymbolRecord]
        """

    def getRecords(self) -> java.util.List[ghidra.app.util.bin.format.omf.OmfRecord]:
        """
        :return: the list of records
        :rtype: java.util.List[ghidra.app.util.bin.format.omf.OmfRecord]
        """

    def getSegments(self) -> java.util.List[OmfSegmentHeader]:
        """
        
        
        :return: the list of segments in this file
        :rtype: java.util.List[OmfSegmentHeader]
        """

    def getTranslator(self) -> str:
        """
        If the OMF file contains a "translator" record, this is usually a string
        indicating the compiler which produced the file.
        
        :return: the translator for this file
        :rtype: str
        """

    def isLittleEndian(self) -> bool:
        """
        
        
        :return: true if the file describes the load image for a little endian architecture
        :rtype: bool
        """

    @staticmethod
    def parse(factory: ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> OmfFileHeader:
        """
        Parse the entire object file
        
        :param ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory factory: the :obj:`AbstractOmfRecordFactory`
        :param ghidra.util.task.TaskMonitor monitor: is checked for cancel button
        :param ghidra.app.util.importer.MessageLog log: the log
        :return: the header record as root of object
        :rtype: OmfFileHeader
        :raises IOException: for problems reading data
        :raises OmfException: for malformed records
        """

    def resolveNames(self):
        """
        Resolve special names associated with each segment: segment, class, overlay names
        and group: group name
        For each segment, the read/write/execute permissions are also determined
        
        :raises OmfException: if any name indices are malformed
        """

    def resolveSegment(self, index: typing.Union[jpype.JInt, int]) -> OmfSegmentHeader:
        """
        Given an index, retrieve the specific segment it refers to. This
        incorporates the special Borland segments, where the index has 
        the bit 0x4000 set.
        
        :param jpype.JInt or int index: identifies the segment
        :return: the corresponding OmfSegmentHeader
        :rtype: OmfSegmentHeader
        :raises OmfException: if the index is malformed
        """

    @staticmethod
    def scan(factory: ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory, monitor: ghidra.util.task.TaskMonitor, fastscan: typing.Union[jpype.JBoolean, bool]) -> OmfFileHeader:
        """
        Scan the object file, for the main header and comment records. Other records are parsed but not saved
        
        :param ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory factory: the :obj:`AbstractOmfRecordFactory`
        :param ghidra.util.task.TaskMonitor monitor: is checked for cancellation
        :param jpype.JBoolean or bool fastscan: is true if we only want to scan the header until first seghead,
        :return: the header record
        :rtype: OmfFileHeader
        :raises IOException: for problems reading program data
        :raises OmfException: for malformed records
        """

    def sortSegmentDataBlocks(self):
        """
        Sort the explicit data-blocks for each segment into address order.
        """

    @property
    def extraSegments(self) -> java.util.List[OmfSegmentHeader]:
        ...

    @property
    def records(self) -> java.util.List[ghidra.app.util.bin.format.omf.OmfRecord]:
        ...

    @property
    def translator(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def littleEndian(self) -> jpype.JBoolean:
        ...

    @property
    def libraryModuleName(self) -> java.lang.String:
        ...

    @property
    def groups(self) -> java.util.List[OmfGroupRecord]:
        ...

    @property
    def localSymbols(self) -> java.util.List[OmfSymbolRecord]:
        ...

    @property
    def publicSymbols(self) -> java.util.List[OmfSymbolRecord]:
        ...

    @property
    def fixups(self) -> java.util.List[OmfFixupRecord]:
        ...

    @property
    def externalSymbols(self) -> java.util.List[OmfExternalSymbol]:
        ...

    @property
    def machineName(self) -> java.lang.String:
        ...

    @property
    def segments(self) -> java.util.List[OmfSegmentHeader]:
        ...


class OmfRecordFactory(ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory):
    """
    A class for reading/creating Relocatable OMF records
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        """
        Creates a new :obj:`OmfRecordFactory`
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` that contains the records
        """


class OmfEnumeratedData(OmfData):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...


class OmfNamesRecord(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def appendNames(self, namelist: java.util.List[java.lang.String]):
        ...


class OmfModuleEnd(ghidra.app.util.bin.format.omf.OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...


class OmfData(ghidra.app.util.bin.format.omf.OmfRecord, java.lang.Comparable[OmfData]):
    """
    Object representing data loaded directly into the final image.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def compareTo(self, o: OmfData) -> int:
        """
        Compare datablocks by data offset
        
        :return: a value less than 0 for lower address, 0 for same address, or greater than 0 for
        higher address
        :rtype: int
        """

    def getByteArray(self, reader: ghidra.app.util.bin.BinaryReader) -> jpype.JArray[jpype.JByte]:
        """
        Create a byte array holding the data represented by this object. The length
        of the byte array should exactly match the value returned by getLength()
        
        :param ghidra.app.util.bin.BinaryReader reader: is for pulling bytes directly from the binary image
        :return: allocated and filled byte array
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: for problems accessing data through the reader
        """

    def getDataOffset(self) -> int:
        """
        
        
        :return: the starting offset, within the loaded image, of this data
        :rtype: int
        """

    def getLength(self) -> int:
        """
        
        
        :return: the length of this data in bytes
        :rtype: int
        """

    def getSegmentIndex(self) -> int:
        """
        
        
        :return: get the segments index for this datablock
        :rtype: int
        """

    def isAllZeroes(self) -> bool:
        """
        
        
        :return: true if this is a block entirely of zeroes
        :rtype: bool
        """

    @property
    def allZeroes(self) -> jpype.JBoolean:
        ...

    @property
    def dataOffset(self) -> jpype.JLong:
        ...

    @property
    def byteArray(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def segmentIndex(self) -> jpype.JInt:
        ...


class OmfLibraryRecord(java.lang.Object):

    class MemberHeader(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        payloadOffset: jpype.JLong
        size: jpype.JLong
        name: java.lang.String
        translator: java.lang.String
        machineName: java.lang.String

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    @staticmethod
    def checkMagicNumber(reader: ghidra.app.util.bin.BinaryReader) -> bool:
        ...

    def getMemberHeaders(self) -> java.util.ArrayList[OmfLibraryRecord.MemberHeader]:
        ...

    def getPageSize(self) -> int:
        ...

    @staticmethod
    def parse(factory: ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory, monitor: ghidra.util.task.TaskMonitor) -> OmfLibraryRecord:
        ...

    @property
    def pageSize(self) -> jpype.JInt:
        ...

    @property
    def memberHeaders(self) -> java.util.ArrayList[OmfLibraryRecord.MemberHeader]:
        ...


class OmfSymbol(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], type: typing.Union[jpype.JInt, int], off: typing.Union[jpype.JLong, int], dT: typing.Union[jpype.JInt, int], bL: typing.Union[jpype.JInt, int]):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getDataType(self) -> int:
        ...

    def getFrameDatum(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getOffset(self) -> int:
        ...

    def getSegmentRef(self) -> int:
        ...

    def isFloatingPointSpecial(self) -> bool:
        ...

    def setAddress(self, addr: ghidra.program.model.address.Address):
        ...

    def setSegmentRef(self, val: typing.Union[jpype.JInt, int]):
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @address.setter
    def address(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def dataType(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def frameDatum(self) -> jpype.JInt:
        ...

    @property
    def floatingPointSpecial(self) -> jpype.JBoolean:
        ...

    @property
    def segmentRef(self) -> jpype.JInt:
        ...

    @segmentRef.setter
    def segmentRef(self, value: jpype.JInt):
        ...



__all__ = ["OmfExternalSymbol", "OmfComdefRecord", "OmfGroupRecord", "OmfCommentRecord", "OmfRecordTypes", "OmfIteratedData", "OmfComdatExternalSymbol", "OmfFixupRecord", "OmfSegmentHeader", "OmfSymbolRecord", "OmfFileHeader", "OmfRecordFactory", "OmfEnumeratedData", "OmfNamesRecord", "OmfModuleEnd", "OmfData", "OmfLibraryRecord", "OmfSymbol"]
