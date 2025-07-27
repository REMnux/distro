from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.util
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore


@typing.type_check_only
class UninitializedSubMemoryBlock(SubMemoryBlock):
    """
    Implementation of SubMemoryBlock for uninitialized blocks.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ByteMappedSubMemoryBlock(SubMemoryBlock):
    """
    Class for handling byte mapped memory sub blocks
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FileBytesSubMemoryBlock(SubMemoryBlock):
    """
    Class for handling :obj:`FileBytes` memory sub blocks (blocks whose bytes are backed by a FileBytes object
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFileBytes(self) -> FileBytes:
        ...

    def getFileBytesOffset(self) -> int:
        ...

    @property
    def fileBytes(self) -> FileBytes:
        ...

    @property
    def fileBytesOffset(self) -> jpype.JLong:
        ...


@typing.type_check_only
class BufferSubMemoryBlock(SubMemoryBlock):
    """
    Implementation of SubMemoryBlock for blocks that store bytes in their own private database
    buffers
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MemoryMapDBAdapterV2(MemoryMapDBAdapter):
    """
    Adapter for version 2
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MemoryMapDBAdapterV0(MemoryMapDBAdapter):
    """
    Adapter for version 0
    """

    class_: typing.ClassVar[java.lang.Class]


class AddressSourceInfo(java.lang.Object):
    """
    Provides information about the source of a byte value at an address including the file it 
    came from, the offset into that file, and the original value of that byte.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, memory: ghidra.program.model.mem.Memory, address: ghidra.program.model.address.Address, block: ghidra.program.model.mem.MemoryBlock):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address for which this object provides byte source information.
        
        :return: the address for which this object provides byte source information.
        :rtype: ghidra.program.model.address.Address
        """

    def getFileName(self) -> str:
        """
        Returns the filename of the originally imported file that provided the byte value for the
        associated address or null if there is no source information for this location.
        
        :return: the filename of the originally imported file that provided the byte value for the
        associated address or null if there is no source information for this location.
        :rtype: str
        """

    def getFileOffset(self) -> int:
        """
        Returns the offset into the originally imported file that provided the byte value for the
        associated address or -1 if there is no source information for this location.
        
        :return: the offset into the originally imported file that provided the byte value for the
        associated address.
        :rtype: int
        """

    def getMemoryBlockSourceInfo(self) -> ghidra.program.model.mem.MemoryBlockSourceInfo:
        """
        Returns the :obj:`MemoryBlockSourceInfo` for the region surround this info's location.
        
        :return: the :obj:`MemoryBlockSourceInfo` for the region surround this info's location.
        :rtype: ghidra.program.model.mem.MemoryBlockSourceInfo
        """

    def getOriginalValue(self) -> int:
        """
        Returns the original byte value from the imported file that provided the byte value for the
        associated address or 0 if there is no source information for this location.
        
        :return: the original byte value from the imported file that provided the byte value for the
        associated address or 0 if there is no source information for this location.
        :rtype: int
        :raises IOException: if an io error occurs reading the program database.
        """

    @property
    def memoryBlockSourceInfo(self) -> ghidra.program.model.mem.MemoryBlockSourceInfo:
        ...

    @property
    def fileName(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def originalValue(self) -> jpype.JByte:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...


class MemoryMapDB(ghidra.program.model.mem.Memory, ghidra.program.database.ManagerDB):
    """
    The database memory map manager.
    """

    @typing.type_check_only
    class MemoryAddressSetViews(java.lang.Object):
        """
        Address set views into program memory which are iterator safe
        for public API methods.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMapDB, openMode: ghidra.framework.data.OpenMode, isBigEndian: typing.Union[jpype.JBoolean, bool], lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new MemoryMapDB
        
        :param db.DBHandle handle: the open database handle.
        :param ghidra.program.database.map.AddressMapDB addrMap: the address map.
        :param ghidra.framework.data.OpenMode openMode: the open mode for the program.
        :param jpype.JBoolean or bool isBigEndian: endianness flag
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: Task monitor for upgrading
        :raises IOException: if a database io error occurs.
        :raises VersionException: if the database version is different from the expected version
        """

    def setLanguage(self, newLanguage: ghidra.program.model.lang.Language):
        ...

    def setProgram(self, program: ghidra.program.database.ProgramDB):
        """
        Set the program.
        """


class ByteMappingScheme(java.lang.Object):
    """
    ``ByteMappingScheme`` facilitate byte mapping/decimation scheme for a mapped sub-block to
    an underlying source memory region.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, mappedByteCount: typing.Union[jpype.JInt, int], mappedSourceByteCount: typing.Union[jpype.JInt, int]):
        """
        Construct byte mapping scheme specified as a ratio of mapped bytes to source bytes.
        
        :param jpype.JInt or int mappedByteCount: number of mapped bytes per mappedSourcebyteCount (1..127).  This 
        value must be less-than or equal to schemeSrcByteCount.
        :param jpype.JInt or int mappedSourceByteCount: number of source bytes for mapping ratio (1..127)
        :raises IllegalArgumentException: if invalid mapping scheme specified
        """

    @typing.overload
    def __init__(self, mappingScheme: typing.Union[java.lang.String, str]):
        """
        Construct byte mapping scheme specified as a ratio of mapped bytes to source bytes.
        The two integer values in the range 1..127 are seperated by a ':' character.  The number of
        mapped bytes must be less-than or equal to the number of source bytes.
        
        :param java.lang.String or str mappingScheme: mapping scheme in string form (e.g., "2:4").
        :raises IllegalArgumentException: if invalid mapping scheme specified
        """

    def getMappedByteCount(self) -> int:
        """
        Get the mapped-byte-count (left-hand value in mapping ratio)
        
        :return: mapped-byte-count
        :rtype: int
        """

    def getMappedSourceAddress(self, mappedSourceBaseAddress: ghidra.program.model.address.Address, offsetInSubBlock: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Calculate the mapped source address for a specified offset with the mapped sub-block.
        
        :param ghidra.program.model.address.Address mappedSourceBaseAddress: mapped source base address for sub-block
        :param jpype.JLong or int offsetInSubBlock: byte offset within sub-block to be mapped into source
        :return: mapped source address
        :rtype: ghidra.program.model.address.Address
        :raises AddressOverflowException: if offset in sub-block produces a wrap condition in
        the mapped source address space.
        """

    def getMappedSourceByteCount(self) -> int:
        """
        Get the mapped-source-byte-count (right-hand value in mapping ratio)
        
        :return: mapped-source-byte-count
        :rtype: int
        """

    def isOneToOneMapping(self) -> bool:
        """
        Determine this scheme corresponds to a 1:1 byte mapping
        
        :return: true if 1:1 mapping else false
        :rtype: bool
        """

    @property
    def mappedSourceByteCount(self) -> jpype.JInt:
        ...

    @property
    def oneToOneMapping(self) -> jpype.JBoolean:
        ...

    @property
    def mappedByteCount(self) -> jpype.JInt:
        ...


class MemoryBlockDB(ghidra.program.model.mem.MemoryBlock):

    class_: typing.ClassVar[java.lang.Class]

    def getByte(self, offset: typing.Union[jpype.JLong, int]) -> int:
        ...

    def getBytes(self, offset: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        ...

    def invalidate(self):
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...


@typing.type_check_only
class MemoryMapDBAdapterV1(MemoryMapDBAdapterV0):
    """
    Adapter for version 1
    """

    class_: typing.ClassVar[java.lang.Class]


class MemoryMapDBAdapterV3(MemoryMapDBAdapter):
    """
    MemoryMap adapter for version 3.
    This version introduces the concept of sub memory blocks and FileBytes
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, memMap: MemoryMapDB, maxSubBlockSize: typing.Union[jpype.JLong, int], create: typing.Union[jpype.JBoolean, bool]):
        ...


@typing.type_check_only
class MemoryBlockSourceInfoDB(ghidra.program.model.mem.MemoryBlockSourceInfo):
    """
    Class for describing the source of bytes for a memory block.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FileBytesAdapterNoTable(FileBytesAdapter):
    """
    Version of the FileBytesAdapter used to access older databases for read-only and upgrade purposes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        ...


@typing.type_check_only
class FileBytesAdapter(java.lang.Object):
    """
    Database Adapter for storing and retrieving original file bytes.
    """

    class_: typing.ClassVar[java.lang.Class]
    FILENAME_COL: typing.Final = 0
    OFFSET_COL: typing.Final = 1
    SIZE_COL: typing.Final = 2
    BUF_IDS_COL: typing.Final = 3
    LAYERED_BUF_IDS_COL: typing.Final = 4


@typing.type_check_only
class MemoryBlockInputStream(java.io.InputStream):
    """
    Maps a MemoryBlockDB into an InputStream.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SubMemoryBlock(java.lang.Comparable[SubMemoryBlock]):
    """
    Interface for the various types of memory block sections.  They are used by a :obj:`MemoryBlockDB`
    to do the actual storing and fetching of the bytes that make up a MemoryBlock
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, memBlockOffset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the given :obj:`MemoryBlockDB` offset is in this sub block.
        
        :param jpype.JLong or int memBlockOffset: the offset relative to the containing :obj:`MemoryBlockDB`
        :return: true if the offset is valid for this block
        :rtype: bool
        """

    def delete(self):
        """
        Deletes this SumMemoryBlock
        
        :raises IOException: if a database error occurs
        """

    def getByte(self, memBlockOffset: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the byte in this sub block corresponding to the given offset relative to the containing
        :obj:`MemoryBlockDB`.  In other words, the first byte in this sub block can be retrieved
        using an offset equal to this blocks starting offset.
        
        :param jpype.JLong or int memBlockOffset: the offset from the start of the containing :obj:`MemoryBlockDB`
        :return: the byte at the given containing block offset.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if invalid offset is specified
        :raises MemoryAccessException: if the block is uninitialized.
        :raises IOException: if there is a problem reading from the database
        """

    def getBytes(self, memBlockOffset: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Tries to get len bytes from this block at the given offset (relative to the containing
        :obj:`MemoryBlockDB` and put them into the given byte array at the specified offset.  
        May return fewer bytes if the requested length is beyond the end of the block.
        
        :param jpype.JLong or int memBlockOffset: the offset relative to the containing :obj:`MemoryBlockDB`
        :param jpype.JArray[jpype.JByte] b: the byte array to populate.
        :param jpype.JInt or int off: the offset into the byte array.
        :param jpype.JInt or int len: the number of bytes to get.
        :return: the number of bytes actually populated.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if invalid offset is specified
        :raises MemoryAccessException: if any of the requested bytes are
        uninitialized.
        :raises IOException: if there is a problem reading from the database
        :raises IllegalArgumentException: if the offset is not in this block.
        """

    def getLength(self) -> int:
        """
        Returns the length of this sub block
        
        :return: the length of this sub block
        :rtype: int
        """

    def getParentBlockID(self) -> int:
        """
        Returns the id of the MemoryBlockDB object that owns this sub block.
        
        :return: the id of the MemoryBlockDB object that owns this sub block.
        :rtype: int
        """

    def getStartingOffset(self) -> int:
        """
        Returns the starting offset for this sub block.  In other words, the first byte in this sub 
        block is at this starting offset relative to the containing :obj:`MemoryBlockDB`
        
        :return: the starting offset for this sub block.
        :rtype: int
        """

    def isInitialized(self) -> bool:
        """
        Return whether this block has been initialized (has byte values)
        
        :return: true if the block has associated byte values.
        :rtype: bool
        """

    def putByte(self, memBlockOffset: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JByte, int]):
        """
        Stores the byte in this sub block at the given offset relative to the containing
        :obj:`MemoryBlockDB`.  In other words, the first byte in this sub block can be targeted
        using an offset equal to this blocks starting offset.
        
        :param jpype.JLong or int memBlockOffset: the offset from the start of the containing :obj:`MemoryBlockDB`
        :param jpype.JByte or int b: the byte value to store at the given offset.
        :raises java.lang.IndexOutOfBoundsException: if invalid offset is specified
        :raises MemoryAccessException: if the block is uninitialized
        :raises IOException: if there is a problem writing to the database
        :raises IllegalArgumentException: if the offset is not in this block.
        """

    def putBytes(self, memBlockOffset: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Tries to write len bytes to this block at the given offset (relative to the containing
        :obj:`MemoryBlockDB` using the bytes contained in the given byte array at the specified byte
        array offset.  
        May write fewer bytes if the requested length is beyond the end of the block.
        
        :param jpype.JLong or int memBlockOffset: the offset relative to the containing :obj:`MemoryBlockDB`
        :param jpype.JArray[jpype.JByte] b: the byte array with the bytes to store.
        :param jpype.JInt or int off: the offset into the byte array.
        :param jpype.JInt or int len: the number of bytes to write.
        :return: the number of bytes actually written
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if invalid offset is specified
        :raises MemoryAccessException: if this block is uninitialized.
        :raises IOException: if there is a problem writing to the database
        :raises IllegalArgumentException: if the offset is not in this block.
        """

    @property
    def startingOffset(self) -> jpype.JLong:
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def initialized(self) -> jpype.JBoolean:
        ...

    @property
    def parentBlockID(self) -> jpype.JLong:
        ...


@typing.type_check_only
class MemoryMapDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BitMappedSubMemoryBlock(SubMemoryBlock):
    """
    Class for handling bit mapped memory sub blocks
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FileBytesAdapterV0(FileBytesAdapter):
    """
    Initial version of the FileBytesAdapter
    """

    class_: typing.ClassVar[java.lang.Class]
    V0_FILENAME_COL: typing.Final = 0
    V0_OFFSET_COL: typing.Final = 1
    V0_SIZE_COL: typing.Final = 2
    V0_BUF_IDS_COL: typing.Final = 3
    V0_LAYERED_BUF_IDS_COL: typing.Final = 4


class FileBytes(java.lang.Object):
    """
    FileBytes provides access to the all the byte values (both original and modified) from an
    imported file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, adapter: FileBytesAdapter, record: db.DBRecord):
        ...

    def getFileOffset(self) -> int:
        """
        Returns the offset in the original file from where these bytes originated. Normally this will
        be 0, but in the case where the program is actually a piece in some other file (e.g. tar,zip),
        this will be the offset into the file corresponding to the first byte in this FileBytes object.
        
        :return: the offset in the original file from where these bytes originated.
        :rtype: int
        """

    def getFilename(self) -> str:
        """
        Returns the name of the file that supplied the bytes.
        
        :return: the name of the file that supplied the bytes.
        :rtype: str
        """

    def getModifiedByte(self, offset: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the (possibly modified) byte at the given offset for this file bytes object.
        
        :param jpype.JLong or int offset: the offset into the file bytes for the byte to retrieve.
        :return: the (possibly modified) byte at the given offset for this file bytes object.
        :rtype: int
        :raises IOException: if there is a problem reading the database.
        :raises java.lang.IndexOutOfBoundsException: if the given offset is invalid.
        """

    @typing.overload
    def getModifiedBytes(self, offset: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte]) -> int:
        """
        Tries to get b.length (possibly modified) bytes from this FileBytes entry at the given offset into the file
        bytes.  May return fewer bytes if the requested length is beyond the end of the file bytes.
        
        :param jpype.JLong or int offset: the offset into the files bytes to start.
        :param jpype.JArray[jpype.JByte] b: the byte array to populate.
        :return: the number of bytes actually populated.
        :rtype: int
        :raises IOException: if there is an error reading from the database
        :raises java.lang.IndexOutOfBoundsException: if the given offset is invalid.
        """

    @typing.overload
    def getModifiedBytes(self, offset: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> int:
        """
        Tries to get length (possibly modified) bytes from the files starting at the given offset and put them 
        into the given byte array at the specified offset into the byte array.  May return
        fewer bytes if the requested length is beyond the end of the file bytes.
        
        :param jpype.JLong or int offset: the offset into the files bytes to start.
        :param jpype.JArray[jpype.JByte] b: the byte array to populate.
        :param jpype.JInt or int off: the offset into the byte array.
        :param jpype.JInt or int length: the number of bytes to get.
        :return: the number of bytes actually populated.
        :rtype: int
        :raises IOException: if there is an error reading from the database
        :raises java.lang.IndexOutOfBoundsException: if the destination offset and length would exceed the
        size of the buffer b.
        """

    def getOriginalByte(self, offset: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the original byte value at the given offset for this file bytes object.
        
        :param jpype.JLong or int offset: the offset into the file bytes for the byte to retrieve.
        :return: the original byte at the given offset for this file bytes object.
        :rtype: int
        :raises IOException: if there is a problem reading the database.
        :raises java.lang.IndexOutOfBoundsException: if the given offset is invalid.
        """

    @typing.overload
    def getOriginalBytes(self, offset: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte]) -> int:
        """
        Tries to get b.length original bytes from this FileBytes entry at the given offset into the file
        bytes.  May return fewer bytes if the requested length is beyond the end of the file bytes.
        
        :param jpype.JLong or int offset: the offset into the files bytes to start.
        :param jpype.JArray[jpype.JByte] b: the byte array to populate.
        :return: the number of bytes actually populated.
        :rtype: int
        :raises IOException: if there is an error reading from the database
        :raises java.lang.IndexOutOfBoundsException: if the given offset is invalid.
        """

    @typing.overload
    def getOriginalBytes(self, offset: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> int:
        """
        Tries to get length (original) bytes from the files starting at the given offset and put them 
        into the given byte array at the specified offset into the byte array.  May return
        fewer bytes if the requested length is beyond the end of the file bytes.
        
        :param jpype.JLong or int offset: the offset into the files bytes to start.
        :param jpype.JArray[jpype.JByte] b: the byte array to populate.
        :param jpype.JInt or int off: the offset into the byte array.
        :param jpype.JInt or int length: the number of bytes to get.
        :return: the number of bytes actually populated.
        :rtype: int
        :raises IOException: if there is an error reading from the database
        :raises java.lang.IndexOutOfBoundsException: if the destination offset and length would exceed the
        size of the buffer b.
        """

    def getSize(self) -> int:
        """
        Returns the number of bytes from the original source file that are stored in the database.
        
        :return: the number of bytes from the original source file that are stored in the database.
        :rtype: int
        """

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def originalByte(self) -> jpype.JByte:
        ...

    @property
    def modifiedByte(self) -> jpype.JByte:
        ...



__all__ = ["UninitializedSubMemoryBlock", "ByteMappedSubMemoryBlock", "FileBytesSubMemoryBlock", "BufferSubMemoryBlock", "MemoryMapDBAdapterV2", "MemoryMapDBAdapterV0", "AddressSourceInfo", "MemoryMapDB", "ByteMappingScheme", "MemoryBlockDB", "MemoryMapDBAdapterV1", "MemoryMapDBAdapterV3", "MemoryBlockSourceInfoDB", "FileBytesAdapterNoTable", "FileBytesAdapter", "MemoryBlockInputStream", "SubMemoryBlock", "MemoryMapDBAdapter", "BitMappedSubMemoryBlock", "FileBytesAdapterV0", "FileBytes"]
