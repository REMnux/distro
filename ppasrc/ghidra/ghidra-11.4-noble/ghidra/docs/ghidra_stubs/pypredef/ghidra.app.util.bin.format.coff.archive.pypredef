from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.program.model.data
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class CoffArchiveMemberHeader(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    SLASH: typing.Final = "/"
    SLASH_SLASH: typing.Final = "//"
    CAMH_MIN_SIZE: typing.Final = 60

    def __init__(self, name: typing.Union[java.lang.String, str], date: typing.Union[jpype.JLong, int], userId: typing.Union[java.lang.String, str], groupId: typing.Union[java.lang.String, str], mode: typing.Union[java.lang.String, str], size: typing.Union[jpype.JLong, int], payloadOffset: typing.Union[jpype.JLong, int], memberOffset: typing.Union[jpype.JLong, int]):
        ...

    def getDate(self) -> int:
        """
        Milliseconds since java Date epoch
        
        :return: 
        :rtype: int
        """

    def getFileOffset(self) -> int:
        ...

    def getGroupId(self) -> str:
        ...

    def getGroupIdInt(self) -> int:
        ...

    def getMode(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getPayloadOffset(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    def getUserId(self) -> str:
        ...

    def getUserIdInt(self) -> int:
        ...

    def isCOFF(self) -> bool:
        """
        Returns true if this header contains a COFF file.
        
        :return: true if this header contains a COFF file
        :rtype: bool
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, longNames: LongNamesMember) -> CoffArchiveMemberHeader:
        """
        Reads a COFF archive member header from the specified :obj:`reader <BinaryReader>`,
        leaving the file position at the start of this member's payload.
         
        
        The archive member's name is fixed up using the specified :obj:`longNames <LongNamesMember>`
        object.
        
        :param ghidra.app.util.bin.BinaryReader reader: stream from which to read the COFF archive member header from
        :param LongNamesMember longNames: optional, string table with long file names (only present in some 
        COFF ar formats)
        :return: a new :obj:`CoffArchiveMemberHeader`
        :rtype: CoffArchiveMemberHeader
        :raises IOException:
        """

    @property
    def mode(self) -> java.lang.String:
        ...

    @property
    def date(self) -> jpype.JLong:
        ...

    @property
    def payloadOffset(self) -> jpype.JLong:
        ...

    @property
    def cOFF(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def userIdInt(self) -> jpype.JInt:
        ...

    @property
    def groupIdInt(self) -> jpype.JInt:
        ...

    @property
    def groupId(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def userId(self) -> java.lang.String:
        ...


class FirstLinkerMember(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: CoffArchiveMemberHeader, skip: typing.Union[jpype.JBoolean, bool]):
        ...

    def getFileOffset(self) -> int:
        ...

    def getNumberOfSymbols(self) -> int:
        ...

    def getOffsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    def getStringTable(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def offsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def numberOfSymbols(self) -> jpype.JInt:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def stringTable(self) -> java.util.List[java.lang.String]:
        ...


class CoffArchiveHeader(ghidra.app.util.bin.StructConverter):
    """
    A class that represents a COFF archive file (ie. MS .lib files, Unix .ar files)
     
    
    COFF archives are very primitive compared to containers like ZIP or even TAR.
     
    
    The name of entries (ie. files) inside the archive is limited to 16 bytes, and to 
    support longer names a couple of different schemes have been invented.  See the
    comments in :meth:`CoffArchiveMemberHeader.read(BinaryReader, LongNamesMember) <CoffArchiveMemberHeader.read>` for
    decoding the name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getArchiveMemberHeaders(self) -> java.util.List[CoffArchiveMemberHeader]:
        ...

    def getFirstLinkerMember(self) -> FirstLinkerMember:
        ...

    def getLongNameMember(self) -> LongNamesMember:
        ...

    def getSecondLinkerMember(self) -> SecondLinkerMember:
        ...

    def isMSFormat(self) -> bool:
        """
        Returns true if this COFF archive seems to be a Microsoft lib file (ie.
        has linker members and other features specific to MS)
        
        :return: 
        :rtype: bool
        """

    @staticmethod
    def isMatch(provider: ghidra.app.util.bin.ByteProvider) -> bool:
        """
        Returns true if the data contained in the :obj:`provider <ByteProvider>` contains
        a COFF Archive file.
        
        :param ghidra.app.util.bin.ByteProvider provider: 
        :return: 
        :rtype: bool
        :raises IOException:
        """

    @staticmethod
    def read(provider: ghidra.app.util.bin.ByteProvider, monitor: ghidra.util.task.TaskMonitor) -> CoffArchiveHeader:
        """
        Reads and parses the headers and meta-data in a COFF Archive file.
         
        
        Returns a :obj:`CoffArchiveHeader` that has a list of the 
        :obj:`members <CoffArchiveMemberHeader>` in the archive.
        
        :param ghidra.app.util.bin.ByteProvider provider: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :return: 
        :rtype: CoffArchiveHeader
        :raises CoffException: 
        :raises IOException:
        """

    @property
    def firstLinkerMember(self) -> FirstLinkerMember:
        ...

    @property
    def archiveMemberHeaders(self) -> java.util.List[CoffArchiveMemberHeader]:
        ...

    @property
    def longNameMember(self) -> LongNamesMember:
        ...

    @property
    def mSFormat(self) -> jpype.JBoolean:
        ...

    @property
    def secondLinkerMember(self) -> SecondLinkerMember:
        ...


class SecondLinkerMember(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: CoffArchiveMemberHeader, skip: typing.Union[jpype.JBoolean, bool]):
        ...

    def getFileOffset(self) -> int:
        ...

    def getIndices(self) -> jpype.JArray[jpype.JShort]:
        ...

    def getNumberOfMembers(self) -> int:
        ...

    def getNumberOfSymbols(self) -> int:
        ...

    def getOffsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    def getStringTable(self) -> java.util.List[java.lang.String]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def indices(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def offsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def numberOfMembers(self) -> jpype.JInt:
        ...

    @property
    def numberOfSymbols(self) -> jpype.JInt:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def stringTable(self) -> java.util.List[java.lang.String]:
        ...


class LongNamesMember(ghidra.app.util.bin.StructConverter):
    """
    A string table that contains the full filenames of COFF archive members who's actual
    filenames can not fit in the fixed-length name 
    :meth:`field <CoffArchiveMemberHeader.getName>`.
     
    
    This string table is held in a special archive member named "//" and is usually one of
    the first members of the archive.
     
    
    With MS libs, this will typically be the 3rd member in the archive, right after 
    the first and second "/" special members.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: CoffArchiveMemberHeader):
        ...

    def findName(self, provider: ghidra.app.util.bin.ByteProvider, archiveMemberHeader: CoffArchiveMemberHeader) -> str:
        ...

    def getFileOffset(self) -> int:
        ...

    def getStringAtOffset(self, provider: ghidra.app.util.bin.ByteProvider, offset: typing.Union[jpype.JLong, int]) -> str:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...


class CoffArchiveConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MAGIC: typing.Final = "!<arch>\n"
    MAGIC_LEN: typing.Final[jpype.JInt]
    MAGIC_BYTES: typing.Final[jpype.JArray[jpype.JByte]]

    def __init__(self):
        ...



__all__ = ["CoffArchiveMemberHeader", "FirstLinkerMember", "CoffArchiveHeader", "SecondLinkerMember", "LongNamesMember", "CoffArchiveConstants"]
