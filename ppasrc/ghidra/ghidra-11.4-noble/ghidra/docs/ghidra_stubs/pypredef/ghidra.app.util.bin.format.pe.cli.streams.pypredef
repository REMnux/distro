from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import ghidra.app.util.bin.format.pe.cli
import ghidra.app.util.bin.format.pe.cli.blobs
import ghidra.app.util.bin.format.pe.cli.tables
import ghidra.app.util.datatype.microsoft
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore


class CliStreamStrings(CliAbstractStream):
    """
    The Strings stream contains null-terminated UTF8 strings.
    When the stream is present, the first entry is always the empty string.
    This stream may contain garbage in its unreachable parts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ghidra.app.util.bin.format.pe.cli.CliStreamHeader, offset: typing.Union[jpype.JLong, int], rva: typing.Union[jpype.JInt, int], reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new Strings stream.
        
        :param ghidra.app.util.bin.format.pe.cli.CliStreamHeader header: The stream header associated with this stream.
        :param jpype.JLong or int offset: The reader offset where this stream starts.
        :param jpype.JInt or int rva: The relative virtual address where this stream starts.
        :param ghidra.app.util.bin.BinaryReader reader: A reader that is used to read the stream.
        :raises IOException: if there is a problem reading the stream.
        """

    @staticmethod
    def getName() -> str:
        """
        Gets the name of this stream.
        
        :return: The name of this stream.
        :rtype: str
        """

    def getString(self, index: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets the string at the given index.
        
        :param jpype.JInt or int index: The index of the string to get.
        :return: The string at the given index.  Could be null if the index was invalid or there was
        a problem reading the string.
        :rtype: str
        """

    @property
    def string(self) -> java.lang.String:
        ...


class CliStreamBlob(CliAbstractStream):
    """
    The Blob stream contains ???.
    When the stream is present, the first entry is always the byte 0x00.
    This stream may contain garbage in its unreachable parts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ghidra.app.util.bin.format.pe.cli.CliStreamHeader, offset: typing.Union[jpype.JLong, int], rva: typing.Union[jpype.JInt, int], reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new Blob stream.
        
        :param ghidra.app.util.bin.format.pe.cli.CliStreamHeader header: The stream header associated with this stream.
        :param jpype.JLong or int offset: The reader offset where this stream starts.
        :param jpype.JInt or int rva: The relative virtual address where this stream starts.
        :param ghidra.app.util.bin.BinaryReader reader: A reader that is used to read the stream.
        :raises IOException: if there is a problem reading the stream.
        """

    def getBlob(self, index: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.format.pe.cli.blobs.CliBlob:
        """
        Gets the blob at the given index.
        
        :param jpype.JInt or int index: The index of the blob to get.
        :return: The blob at the given index.  Could be null if the index was invalid or
        there was a problem reading the blob.
        :rtype: ghidra.app.util.bin.format.pe.cli.blobs.CliBlob
        """

    @staticmethod
    def getName() -> str:
        """
        Gets the name of this stream.
        
        :return: The name of this stream.
        :rtype: str
        """

    def updateBlob(self, updatedBlob: ghidra.app.util.bin.format.pe.cli.blobs.CliBlob, addr: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program) -> bool:
        """
        Updates the blob at the given address with the new blob.
        
        :param ghidra.app.util.bin.format.pe.cli.blobs.CliBlob updatedBlob: The updated blob.
        :param ghidra.program.model.address.Address addr: The address of the blob to update.
        :param ghidra.program.model.listing.Program program: The program that will get the update.
        """

    @property
    def blob(self) -> ghidra.app.util.bin.format.pe.cli.blobs.CliBlob:
        ...


class CliAbstractStream(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    A abstract CLI stream type for convenience.  Streams that we support should subclass 
    this class and override the :obj:`.parse`, :obj:`.markup`, and :obj:`.toDataType` 
    methods appropriately.  
     
    
    When streams are laid down in memory they are referred to as heaps, but we'll just stick 
    with calling them streams because using both terms can get confusing.
    """

    class_: typing.ClassVar[java.lang.Class]
    PATH: typing.Final = "/PE/CLI/Streams"

    def __init__(self, header: ghidra.app.util.bin.format.pe.cli.CliStreamHeader, offset: typing.Union[jpype.JLong, int], rva: typing.Union[jpype.JInt, int], reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new generic CLI stream type.  This is intended to be called by a subclass
        stream during its creation.
        
        :param ghidra.app.util.bin.format.pe.cli.CliStreamHeader header: The stream header associated with this stream.
        :param jpype.JLong or int offset: The reader offset where this stream starts.
        :param jpype.JInt or int rva: The relative virtual address where this stream starts.
        :param ghidra.app.util.bin.BinaryReader reader: A reader that is used to read the stream.
        :raises IOException: if there is a problem reading the stream.
        """

    def getStreamHeader(self) -> ghidra.app.util.bin.format.pe.cli.CliStreamHeader:
        """
        Gets this stream's header.
        
        :return: This stream's header.
        :rtype: ghidra.app.util.bin.format.pe.cli.CliStreamHeader
        """

    @staticmethod
    def getStreamMarkupAddress(program: ghidra.program.model.listing.Program, isBinary: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog, ntHeader: ghidra.app.util.bin.format.pe.NTHeader, stream: CliAbstractStream, streamIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Gets the markup address of an offset in a given stream.
        
        :param ghidra.program.model.listing.Program program: 
        :param jpype.JBoolean or bool isBinary: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :param ghidra.app.util.importer.MessageLog log: 
        :param ghidra.app.util.bin.format.pe.NTHeader ntHeader: 
        :param CliAbstractStream stream: The stream to offset into.
        :param jpype.JInt or int streamIndex: The index into the stream.
        :return: The markup address of the given offset in the provided stream.
        :rtype: ghidra.program.model.address.Address
        """

    def markup(self, program: ghidra.program.model.listing.Program, isBinary: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog, ntHeader: ghidra.app.util.bin.format.pe.NTHeader):
        """
        Does basic markup that all streams will want:
         
        * Set monitor message
        * Validate addresses
        * Add bookmark
        * Add symbol
        * Create data type
        
        Subclass should first call this and then provide any custom markup they need.
        """

    def parse(self) -> bool:
        """
        Parses this stream.
        
        :return: True if parsing completed successfully; otherwise, false.
        :rtype: bool
        :raises IOException: If there was an IO problem while parsing.
        """

    @property
    def streamHeader(self) -> ghidra.app.util.bin.format.pe.cli.CliStreamHeader:
        ...


class CliStreamMetadata(CliAbstractStream):
    """
    The Metadata stream is giant and complicated.  It is made up of :obj:`CliAbstractTable`s.
    
    
    .. seealso::
    
        | :obj:`CliTypeTable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ghidra.app.util.bin.format.pe.cli.CliStreamHeader, guidStream: CliStreamGuid, userStringsStream: CliStreamUserStrings, stringsStream: CliStreamStrings, blobStream: CliStreamBlob, fileOffset: typing.Union[jpype.JLong, int], rva: typing.Union[jpype.JInt, int], reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new Metadata stream.
        
        :param ghidra.app.util.bin.format.pe.cli.CliStreamHeader header: The stream header associated with this stream.
        :param CliStreamGuid guidStream: The GUID stream.
        :param CliStreamUserStrings userStringsStream: The user strings stream.
        :param CliStreamStrings stringsStream: The strings stream.
        :param CliStreamBlob blobStream: The blob stream.
        :param jpype.JLong or int fileOffset: The file offset where this stream starts.
        :param jpype.JInt or int rva: The relative virtual address where this stream starts.
        :param ghidra.app.util.bin.BinaryReader reader: A reader that is set to the start of the stream.
        :raises IOException: if there is a problem reading the stream.
        """

    def getBlobIndexDataType(self) -> ghidra.program.model.data.DataType:
        """
        Gets the data type of the index into the Blob stream.  Will be either
        :obj:`DWordDataType` or :obj:`WordDataType`.
        
        :return: The data type of the index into the string stream.
        :rtype: ghidra.program.model.data.DataType
        """

    def getBlobStream(self) -> CliStreamBlob:
        """
        Gets the blob stream.
        
        :return: The blob stream.  Could be null if one doesn't exist.
        :rtype: CliStreamBlob
        """

    def getGuidIndexDataType(self) -> ghidra.program.model.data.DataType:
        """
        Gets the data type of the index into the GUID stream.  Will be either
        :obj:`DWordDataType` or :obj:`WordDataType`.
        
        :return: The data type of the index into the string stream.
        :rtype: ghidra.program.model.data.DataType
        """

    def getGuidStream(self) -> CliStreamGuid:
        """
        Gets the GUID stream.
        
        :return: The GUID stream.  Could be null if one doesn't exist.
        :rtype: CliStreamGuid
        """

    def getMajorVersion(self) -> int:
        """
        Gets the major version.
        
        :return: The major version.
        :rtype: int
        """

    def getMinorVersion(self) -> int:
        """
        Gets the minor version.
        
        :return: The minor version.
        :rtype: int
        """

    @staticmethod
    def getName() -> str:
        """
        Gets the name of this stream.
        
        :return: The name of this stream.
        :rtype: str
        """

    def getNumberRowsForTable(self, tableType: ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable) -> int:
        """
        Gets the number of rows in the table with the given table type.
        
        :param ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable tableType: The type of table to get the number of rows of.
        :return: The number of rows in the table with the given table type.  Could be 0 if
        the table of the given type was not found.
        :rtype: int
        """

    def getSorted(self) -> int:
        """
        Gets the sorted field.
        
        :return: The sorted field.
        :rtype: int
        """

    def getStringIndexDataType(self) -> ghidra.program.model.data.DataType:
        """
        Gets the data type of the index into the string stream.  Will be either
        :obj:`DWordDataType` or :obj:`WordDataType`.
        
        :return: The data type of the index into the string stream.
        :rtype: ghidra.program.model.data.DataType
        """

    def getStringsStream(self) -> CliStreamStrings:
        """
        Gets the strings stream.
        
        :return: The strings stream.  Could be null if one doesn't exist.
        :rtype: CliStreamStrings
        """

    @typing.overload
    def getTable(self, tableType: ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable) -> ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTable:
        """
        Gets the table with the provided table type from the metadata stream.
        
        :param ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable tableType: The type of table to get.
        :return: The table with the provided table type.  Could be null if it doesn't exist.
        :rtype: ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTable
        """

    @typing.overload
    def getTable(self, tableId: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTable:
        """
        Gets the table with the provided table type id from the metadata stream.
        
        :param jpype.JInt or int tableId: The id of the table type to get.
        :return: The table with the provided table id.  Could be null if it doesn't exist.
        :rtype: ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTable
        """

    def getTableIndexDataType(self, table: ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable) -> ghidra.program.model.data.DataType:
        """
        Gets the data type of the index into a metadata table.  Will be either
        :obj:`DWordDataType` or :obj:`WordDataType`.
        
        :return: The data type of the index into the string stream.
        :rtype: ghidra.program.model.data.DataType
        """

    def getUserStringsStream(self) -> CliStreamUserStrings:
        """
        Gets the user strings stream.
        
        :return: The user strings stream.  Could be null if one doesn't exist.
        :rtype: CliStreamUserStrings
        """

    def getValid(self) -> int:
        """
        Gets the valid field.
        
        :return: The valid field.
        :rtype: int
        """

    @property
    def userStringsStream(self) -> CliStreamUserStrings:
        ...

    @property
    def blobStream(self) -> CliStreamBlob:
        ...

    @property
    def majorVersion(self) -> jpype.JShort:
        ...

    @property
    def valid(self) -> jpype.JLong:
        ...

    @property
    def guidStream(self) -> CliStreamGuid:
        ...

    @property
    def sorted(self) -> jpype.JLong:
        ...

    @property
    def blobIndexDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def numberRowsForTable(self) -> jpype.JInt:
        ...

    @property
    def stringIndexDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def tableIndexDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def stringsStream(self) -> CliStreamStrings:
        ...

    @property
    def guidIndexDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def minorVersion(self) -> jpype.JShort:
        ...

    @property
    def table(self) -> ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTable:
        ...


class CliStreamGuid(CliAbstractStream):
    """
    The GUID stream points to a sequence of 128-bit GUIDs.  There might be unreachable
    GUIDs stored in the stream.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ghidra.app.util.bin.format.pe.cli.CliStreamHeader, offset: typing.Union[jpype.JLong, int], rva: typing.Union[jpype.JInt, int], reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new GUID stream.
        
        :param ghidra.app.util.bin.format.pe.cli.CliStreamHeader header: The stream header associated with this stream.
        :param jpype.JLong or int offset: The reader offset where this stream starts.
        :param jpype.JInt or int rva: The relative virtual address where this stream starts.
        :param ghidra.app.util.bin.BinaryReader reader: A reader that is used to read the stream.
        :raises IOException: if there is a problem reading the stream.
        """

    def getGuid(self, index: typing.Union[jpype.JInt, int]) -> ghidra.app.util.datatype.microsoft.GUID:
        """
        Gets the GUID at the given index.
        
        :param jpype.JInt or int index: The index of the GUID to get.
        :return: The string at the given index.  Could be null if the index was invalid or
        there was a problem reading the GUID.
        :rtype: ghidra.app.util.datatype.microsoft.GUID
        """

    @staticmethod
    def getName() -> str:
        """
        Gets the name of this stream.
        
        :return: The name of this stream.
        :rtype: str
        """

    @property
    def guid(self) -> ghidra.app.util.datatype.microsoft.GUID:
        ...


class CliStreamUserStrings(CliStreamBlob):
    """
    The User Strings stream contains blobs of 16-bit Unicode strings.
    When the stream is present, the first entry is always the byte 0x00.
    This stream may contain garbage in its unreachable parts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ghidra.app.util.bin.format.pe.cli.CliStreamHeader, fileOffset: typing.Union[jpype.JLong, int], rva: typing.Union[jpype.JInt, int], reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`CliStreamUserStrings`.
        
        :param ghidra.app.util.bin.format.pe.cli.CliStreamHeader header: The stream header associated with this stream.
        :param jpype.JLong or int fileOffset: The file offset where this stream starts.
        :param jpype.JInt or int rva: The relative virtual address where this stream starts.
        :param ghidra.app.util.bin.BinaryReader reader: A reader that is set to the start of the stream.
        :raises IOException: if there is a problem reading the stream.
        """

    @staticmethod
    def getName() -> str:
        """
        Gets the name of this stream.
        
        :return: The name of this stream.
        :rtype: str
        """

    def getUserString(self, index: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets the user string at the given index.
        
        :param jpype.JInt or int index: The index of the user string to get.
        :return: The user string at the given index.  Could be null if the index was invalid or
        there was a problem reading the user string.
        :rtype: str
        """

    @property
    def userString(self) -> java.lang.String:
        ...



__all__ = ["CliStreamStrings", "CliStreamBlob", "CliAbstractStream", "CliStreamMetadata", "CliStreamGuid", "CliStreamUserStrings"]
