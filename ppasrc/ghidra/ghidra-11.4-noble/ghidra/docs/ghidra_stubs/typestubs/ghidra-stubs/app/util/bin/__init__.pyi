from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.formats.gfilesystem
import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util
import java.io # type: ignore
import java.lang # type: ignore
import java.nio.file # type: ignore
import java.util.function # type: ignore


T = typing.TypeVar("T")


class ByteProviderWrapper(ByteProvider):
    """
    A :obj:`ByteProvider` constrained to a sub-section of an existing :obj:`ByteProvider`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: ByteProvider, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Creates a wrapper around a :obj:`ByteProvider` that contains the same bytes as the specified
        provider, but with a new :obj:`FSRL` identity.
        
        :param ByteProvider provider: :obj:`ByteProvider` to wrap
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` identity for the instance
        :raises IOException: if error
        """

    @typing.overload
    def __init__(self, provider: ByteProvider, subOffset: typing.Union[jpype.JLong, int], subLength: typing.Union[jpype.JLong, int]):
        """
        Constructs a :obj:`ByteProviderWrapper` around the specified :obj:`ByteProvider`,
        constrained to a subsection of the provider.
        
        :param ByteProvider provider: the :obj:`ByteProvider` to wrap
        :param jpype.JLong or int subOffset: the offset in the :obj:`ByteProvider` of where to start the new
        :obj:`ByteProviderWrapper`
        :param jpype.JLong or int subLength: the length of the new :obj:`ByteProviderWrapper`
        """

    @typing.overload
    def __init__(self, provider: ByteProvider, subOffset: typing.Union[jpype.JLong, int], subLength: typing.Union[jpype.JLong, int], fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Constructs a :obj:`ByteProviderWrapper` around the specified :obj:`ByteProvider`,
        constrained to a subsection of the provider.
        
        :param ByteProvider provider: the :obj:`ByteProvider` to wrap
        :param jpype.JLong or int subOffset: the offset in the :obj:`ByteProvider` of where to start the new
        :obj:`ByteProviderWrapper`
        :param jpype.JLong or int subLength: the length of the new :obj:`ByteProviderWrapper`
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` identity of the file this ByteProvider represents
        """


class FileBytesProvider(ByteProvider):
    """
    ``FileBytesProvider`` provides a :obj:`ByteProvider` implementation 
    for :obj:`FileBytes` object.
    """

    @typing.type_check_only
    class FileBytesProviderInputStream(java.io.InputStream):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fileBytes: ghidra.program.database.mem.FileBytes):
        """
        Construct byte provider from original file bytes
        
        :param ghidra.program.database.mem.FileBytes fileBytes: original file bytes
        """


class ByteArrayConverter(java.lang.Object):
    """
    An interface to convert from a object to a
    byte array.
    """

    class_: typing.ClassVar[java.lang.Class]

    def toBytes(self, dc: ghidra.util.DataConverter) -> jpype.JArray[jpype.JByte]:
        """
        Returns a byte array representing this implementor
        of this interface.
        
        :param ghidra.util.DataConverter dc: the data converter to use
        :return: a byte array representing this object
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if an IO-related error occurs
        """


class InvalidDataException(java.io.IOException):
    """
    An :obj:`IOException` that indicates that the data being transmitted was invalid or bad format.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class ByteProviderPaddedInputStream(java.io.InputStream):
    """
    Wraps a :obj:`ByteProvider` and presents it as an :obj:`InputStream`.
     
    
    This InputStream will be limited to a region of the underlying ByteProvider, and
    has an optional amount of padding at the end of the stream where the stream will appear
    to have bytes with a value of zero.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ByteProvider, startOffset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int], padCount: typing.Union[jpype.JLong, int]):
        """
        Create a new :obj:`ByteProviderInputStream` instance, using the specified
        :obj:`ByteProvider` as the source of the bytes returned from this stream.
         
        
        The source ByteProvider is not closed when this stream is closed.
         
        
        The total number of bytes that can be read from this instance will be length + padCount.
        
        :param ByteProvider provider: the :obj:`ByteProvider` to wrap.
        :param jpype.JLong or int startOffset: the starting offset in the ByteProvider.
        :param jpype.JLong or int length: the number of bytes from the :obj:`ByteProvider` to allow to be read by this InputStream.
        :param jpype.JLong or int padCount: the number of fake zero bytes to add after the real ``length`` bytes.
        """


class MemoryMutableByteProvider(MemoryByteProvider, MutableByteProvider):
    """
    A Byte Provider implementation based on Memory.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, space: ghidra.program.model.address.AddressSpace):
        """
        Constructs a new provider for a specific address space.
        
        :param ghidra.program.model.mem.Memory memory: the memory
        :param ghidra.program.model.address.AddressSpace space: the address space
        """

    @typing.overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, baseAddress: ghidra.program.model.address.Address):
        """
        Constructs a new provider relative to the base address.
        
        :param ghidra.program.model.mem.Memory memory: the memory
        :param ghidra.program.model.address.Address baseAddress: the relative base address
        """


class ByteProvider(java.io.Closeable):
    """
    An interface for a generic random-access byte provider.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_BYTEPROVIDER: typing.Final[ByteProvider]
    """
    A static re-usable empty :obj:`ByteProvider` instance.
    """


    def close(self):
        """
        Releases any resources the :obj:`ByteProvider` may have occupied
        
        :raises IOException: if an I/O error occurs
        """

    def getAbsolutePath(self) -> str:
        """
        Returns the absolute path (similar to, but not a, URI) to the :obj:`ByteProvider`.
        For example, the complete path to the file.
        
        :return: the absolute path to the :obj:`ByteProvider` or null if not associated with a 
        :obj:`File`.
        :rtype: str
        """

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the :obj:`FSRL` of the underlying file for this byte provider,
        or null if this byte provider is not associated with a file.
        
        :return: The :obj:`FSRL` of the underlying :obj:`File`, or null if no associated 
        :obj:`File`.
        :rtype: ghidra.formats.gfilesystem.FSRL
        """

    def getFile(self) -> java.io.File:
        """
        Returns the underlying :obj:`File` for this :obj:`ByteProvider`, or null if this 
        :obj:`ByteProvider` is not associated with a :obj:`File`.
        
        :return: the underlying file for this byte provider
        :rtype: java.io.File
        """

    def getInputStream(self, index: typing.Union[jpype.JLong, int]) -> java.io.InputStream:
        """
        Returns an input stream to the underlying byte provider starting at the specified index.
         
        
        The caller is responsible for closing the returned :obj:`InputStream` instance.
         
        
        If you need to override this default implementation, please document why your inputstream
        is needed.
        
        :param jpype.JLong or int index: where in the :obj:`ByteProvider` to start the :obj:`InputStream`
        :return: the :obj:`InputStream`
        :rtype: java.io.InputStream
        :raises IOException: if an I/O error occurs
        """

    def getName(self) -> str:
        """
        Returns the name of the :obj:`ByteProvider`. For example, the underlying file name.
        
        :return: the name of the :obj:`ByteProvider` or null if there is no name
        :rtype: str
        """

    def isEmpty(self) -> bool:
        """
        Returns true if this ByteProvider does not contain any bytes.
        
        :return: boolean true if this provider is empty, false if contains bytes
        :rtype: bool
        """

    def isValidIndex(self, index: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the specified index is valid.
        
        :param jpype.JLong or int index: the index in the byte provider to check
        :return: true if the specified index is valid
        :rtype: bool
        """

    def length(self) -> int:
        """
        Returns the length of the :obj:`ByteProvider`
        
        :return: the length of the :obj:`ByteProvider`
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readByte(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Reads a byte at the specified index
        
        :param jpype.JLong or int index: the index of the byte to read
        :return: the byte read from the specified index
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readBytes(self, index: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JByte]:
        """
        Reads a byte array at the specified index
        
        :param jpype.JLong or int index: the index of the byte to read
        :param jpype.JLong or int length: the number of bytes to read
        :return: the byte array read from the specified index
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if an I/O error occurs
        """

    @property
    def file(self) -> java.io.File:
        ...

    @property
    def validIndex(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def fSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    @property
    def inputStream(self) -> java.io.InputStream:
        ...

    @property
    def absolutePath(self) -> java.lang.String:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class MemoryByteProvider(ByteProvider):
    """
    A :obj:`ByteProvider` implementation based on :obj:`Memory`.
     
    
    The bytes returned by this provider are indexed relative to the ``baseAddress``
    supplied to the constructor, and are limited to :obj:`memory blocks <MemoryBlock>` of the
    same address space.
     
    
    **Warnings:**
     
    
    Using this ByteProvider with memory block/address spaces that are not simple "ram" initialized 
    memory blocks is fraught with peril.
     
    
    Addresses and address spaces can use all 64 bits of a ``long`` as an offset, which 
    causes a problem when trying to express the correct :meth:`length() <.length>` of this ByteProvider as
    a long. (this is why address ranges deal with inclusive end values instead of exclusive).
     
    * The return value of :meth:`length() <.length>` is constrained to a max of Long.MAX_VALUE
    * :meth:`isValidIndex(long) <.isValidIndex>` treats its argument as an unsigned int64, and works
    for the entire address space range.
    
     
    
    Not all byte provider index locations between 0 and :meth:`length() <.length>` will be valid
    (because gaps between memory blocks), and may generate exceptions when those locations are read.
     
    * To avoid this situation, the caller will need to use information from the program's Memory
    manager to align reads to valid locations.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, space: ghidra.program.model.address.AddressSpace):
        """
        Constructs a new :obj:`MemoryByteProvider` for a specific :obj:`AddressSpace`.  Bytes 
        will be provided relative to the minimum address (typically 0) in the space, and ranges 
        to the highest address in the same address space currently found in the memory map.
        
        :param ghidra.program.model.mem.Memory memory: the :obj:`Memory`
        :param ghidra.program.model.address.AddressSpace space: the :obj:`AddressSpace`
        """

    @typing.overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, baseAddress: ghidra.program.model.address.Address):
        """
        Constructs a new :obj:`MemoryByteProvider` relative to the specified base address,
        containing the address range to the highest address in the same address space currently
        found in the memory map.
        
        :param ghidra.program.model.mem.Memory memory: the :obj:`Memory`
        :param ghidra.program.model.address.Address baseAddress: the base address
        """

    @typing.overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, baseAddress: ghidra.program.model.address.Address, firstBlockOnly: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new :obj:`MemoryByteProvider` relative to the specified base address,
        containing the address range to the end of the first memory block, or the highest address
        in the same address space, currently found in the memory map.
        
        :param ghidra.program.model.mem.Memory memory: the :obj:`Memory`
        :param ghidra.program.model.address.Address baseAddress: the base address
        :param jpype.JBoolean or bool firstBlockOnly: boolean flag, if true, only the first memory block will be accessible,
        if false, all memory blocks of the address space will be accessible
        """

    @typing.overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, baseAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address):
        """
        Constructs a new :obj:`MemoryByteProvider` relative to the specified base address, with
        the specified length.
        
        :param ghidra.program.model.mem.Memory memory: the :obj:`Memory`
        :param ghidra.program.model.address.Address baseAddress: the base address
        :param ghidra.program.model.address.Address maxAddress: the highest address accessible by this provider (inclusive), or null
        if there is no memory
        """

    @staticmethod
    def createDefaultAddressSpaceByteProvider(program: ghidra.program.model.listing.Program, firstBlockOnly: typing.Union[jpype.JBoolean, bool]) -> MemoryByteProvider:
        """
        Create a :obj:`ByteProvider` that starts at the beginning (e.g. 0) of the specified 
        :obj:`program's <Program>` default address space memory, containing either the first memory 
        block, or all memory blocks (of the same address space).
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to read
        :param jpype.JBoolean or bool firstBlockOnly: boolean flag, if true, only the first memory block will be accessible
        via the returned provider, if false, all memory blocks of the address space will be accessible
        :return: new :obj:`MemoryByteProvider`, starting at program's minAddress
        :rtype: MemoryByteProvider
        """

    @staticmethod
    def createMemoryBlockByteProvider(memory: ghidra.program.model.mem.Memory, block: ghidra.program.model.mem.MemoryBlock) -> MemoryByteProvider:
        """
        Create a :obj:`ByteProvider` that is limited to the specified :obj:`MemoryBlock`.
        
        :param ghidra.program.model.mem.Memory memory: :obj:`Memory` of the program
        :param ghidra.program.model.mem.MemoryBlock block: :obj:`MemoryBlock` to read from
        :return: new :obj:`ByteProvider` that contains the bytes of the specified MemoryBlock
        :rtype: MemoryByteProvider
        """

    @staticmethod
    def createProgramHeaderByteProvider(program: ghidra.program.model.listing.Program, firstBlockOnly: typing.Union[jpype.JBoolean, bool]) -> MemoryByteProvider:
        """
        Create a :obj:`ByteProvider` that starts at the beginning of the specified 
        :obj:`program's <Program>` memory, containing either just the first 
        memory block, or all memory blocks (of the same address space).
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to read
        :param jpype.JBoolean or bool firstBlockOnly: boolean flag, if true, only the first memory block will be accessible
        via the returned provider, if false, all memory blocks of the address space will be accessible
        :return: new :obj:`MemoryByteProvider`, starting at program's minAddress
        :rtype: MemoryByteProvider
        """

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the address range of the bytes of this provider.
        
        :return: address range of first byte to last byte of this provider
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the last byte of this provider.
        
        :return: address of the last byte returned by this provider
        :rtype: ghidra.program.model.address.Address
        """

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the first byte of this provider.
        
        :return: address of the first byte returned by this provider (at index 0)
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...


class SynchronizedByteProvider(ByteProvider):
    """
    Creates a thread-safe pass-through :obj:`ByteProvider`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ByteProvider):
        """
        Constructs a :obj:`SynchronizedByteProvider` around the specified :obj:`ByteProvider`
        
        :param ByteProvider provider: the :obj:`ByteProvider` to make thread-safe
        """


@deprecated("See FileByteProvider as replacement ByteProvider.")
class RandomAccessByteProvider(ByteProvider):
    """
    An implementation of ByteProvider where the underlying
    bytes are supplied by a random access file.
     
    
    Note: this implementation is not thread-safe, and using an instance of this
    class from multiple threads will result in reading incorrect data and/or
    :obj:`ArrayIndexOutOfBoundsException`s.
     
    
    See :obj:`SynchronizedByteProvider` as a solution.
    
    
    .. deprecated::
    
    See :obj:`FileByteProvider` as replacement ByteProvider.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Constructs a :obj:`ByteProvider` using the specified :obj:`File`.
        
        :param jpype.protocol.SupportsPath file: the :obj:`File` to open for random access
        :raises IOException: if the :obj:`File` does not exist or other error
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Constructs a :obj:`ByteProvider` using the specified :obj:`File` and :obj:`FSRL`
        
        :param jpype.protocol.SupportsPath file: the :obj:`File` to open for random access
        :param ghidra.formats.gfilesystem.FSRL fsrl: the :obj:`FSRL` to use for the :obj:`File`'s path
        :raises IOException: if the :obj:`File` does not exist or other error
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath, permissions: typing.Union[java.lang.String, str]):
        """
        Constructs a :obj:`ByteProvider` using the specified :obj:`File` and permissions
        
        :param jpype.protocol.SupportsPath file: the :obj:`File` to open for random access
        :param java.lang.String or str permissions: indicating permissions used for open
        :raises IOException: if the :obj:`File` does not exist or other error
        """

    def setFSRL(self, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Sets the :obj:`FSRL` of this :obj:`ByteProvider`
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: the :obj:`FSRL` to assign to this byte provider
        """


class InputStreamByteProvider(ByteProvider):
    """
    A :obj:`ByteProvider` implementation that wraps an :obj:`InputStream`, allowing
    data to be read, as long as there are no operations that request data from a previous
    offset.
     
    
    In other words, this :obj:`ByteProvider` can only be used to read data at ever increasing 
    offsets.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, inputStream: java.io.InputStream, length: typing.Union[jpype.JLong, int]):
        """
        Constructs a :obj:`InputStreamByteProvider` from the specified :obj:`InputStream`
        
        :param java.io.InputStream inputStream: the underlying :obj:`InputStream`
        :param jpype.JLong or int length: the length of the :obj:`InputStreamByteProvider`
        """

    def getUnderlyingInputStream(self) -> java.io.InputStream:
        ...

    @property
    def underlyingInputStream(self) -> java.io.InputStream:
        ...


class GhidraRandomAccessFile(java.lang.AutoCloseable):
    """
    Instances of this class support both reading and writing to a
    random access file. A random access file behaves like a large
    array of bytes stored in the file system. There is a kind of cursor,
    or index into the implied array, called the *file pointer*.
    This implementation relies on java.net.RandomAccessFile,
    but adds buffering to limit the amount.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath, mode: typing.Union[java.lang.String, str]):
        """
        Creates a random access file stream to read from, and optionally to
        write to, the file specified by the :obj:`File` argument.  A new :obj:`FileDescriptor` object is created to represent this file connection.
        
         
        
        This implementation relies on java.net.RandomAccessFile,
        but adds buffering to limit the amount.
        
         
        .. _mode:
        
        
        The ``mode`` argument specifies the access mode
        in which the file is to be opened.  The permitted values and their
        meanings are:
        
             
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            Access mode permitted values and meanings
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            +-------------+-----------------------------------------------------------------------------------------+
            |             |                                                                                         |
            |    Value    |                                         Meaning                                         |
            +=============+=========================================================================================+
            |``"r"``      |Open for reading only.  Invoking any of the ``write``                                    |
            |             |methods of the resulting object will cause an :obj:`java.io.IOException` to be thrown.   |
            +-------------+-----------------------------------------------------------------------------------------+
            |``"rw"``     |Open for reading and writing.  If the file does not already                              |
            |             |exist then an attempt will be made to create it.                                         |
            +-------------+-----------------------------------------------------------------------------------------+
            |``"rws"``    |Open for reading and writing, as with ``"rw"``, and also                                 |
            |             |require that every update to the file's content or metadata be                           |
            |             |written synchronously to the underlying storage device.                                  |
            +-------------+-----------------------------------------------------------------------------------------+
            |``"rwd"  ``  |Open for reading and writing, as with ``"rw"``, and also                                 |
            |             |require that every update to the file's content be written                               |
            |             |synchronously to the underlying storage device.                                          |
            +-------------+-----------------------------------------------------------------------------------------+
        
        
        :param jpype.protocol.SupportsPath file: the file object
        :param java.lang.String or str mode: the access mode, as described
                            `above <mode_>`_
        :raises IllegalArgumentException: if the mode argument is not equal
                    to one of ``"r"``, ``"rw"``, ``"rws"``, or
                    ``"rwd"``
        :raises FileNotFoundException: that name cannot be created, or if some other error occurs
                    while opening or creating the file
        """

    def close(self):
        """
        Closes this random access file stream and releases any system
        resources associated with the stream. A closed random access
        file cannot perform input or output operations and cannot be
        reopened.
         
        
        If this file has an associated channel then the channel is closed as well.
        
        :raises IOException: if an I/O error occurs.
        """

    def length(self) -> int:
        """
        Returns the length of this file.
        
        :return: the length of this file, measured in bytes.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def read(self, b: jpype.JArray[jpype.JByte]) -> int:
        """
        Reads up to ``b.length`` bytes of data from this file
        into an array of bytes. This method blocks until at least one byte
        of input is available.
        
        :param jpype.JArray[jpype.JByte] b: the buffer into which the data is read.
        :return: the total number of bytes read into the buffer, or
                    ``-1`` if there is no more data because the end of
                    this file has been reached.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def read(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> int:
        """
        Reads up to ``length`` bytes of data from this file into an
        array of bytes. This method blocks until at least one byte of input
        is available.
        
        :param jpype.JArray[jpype.JByte] b: the buffer into which the data is read.
        :param jpype.JInt or int offset: the start offset of the data.
        :param jpype.JInt or int length: the maximum number of bytes read.
        :return: the total number of bytes read into the buffer, or
                    ``-1`` if there is no more data because the end of
                    the file has been reached.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    def readByte(self) -> int:
        """
        This method reads a byte from the file, starting from the current file pointer.
         
        
        This method blocks until the byte is read, the end of the stream
        is detected, or an exception is thrown.
        
        :return: the next byte of this file as a signed eight-bit
                    ``byte``.
        :rtype: int
        :raises EOFException: if this file has reached the end.
        :raises IOException: if an I/O error occurs.
        """

    def seek(self, pos: typing.Union[jpype.JLong, int]):
        """
        Sets the file-pointer offset, measured from the beginning of this
        file, at which the next read or write occurs.  The offset may be
        set beyond the end of the file. Setting the offset beyond the end
        of the file does not change the file length.  The file length will
        change only by writing after the offset has been set beyond the end
        of the file.
        
        :param jpype.JLong or int pos: the offset position, measured in bytes from the
                        beginning of the file, at which to set the file
                        pointer.
        :raises IOException: if ``pos`` is less than
                                ``0`` or if an I/O error occurs.
        """

    @typing.overload
    def write(self, b: typing.Union[jpype.JByte, int]):
        """
        Writes a byte to this file, starting at the current file pointer.
        
        :param jpype.JByte or int b: the data.
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte]):
        """
        Writes ``b.length`` bytes from the specified byte array
        to this file, starting at the current file pointer.
        
        :param jpype.JArray[jpype.JByte] b: the data.
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Writes a sub array as a sequence of bytes.
        
        :param jpype.JArray[jpype.JByte] b: the data to be written
        :param jpype.JInt or int offset: the start offset in the data
        :param jpype.JInt or int length: the number of bytes that are written
        :raises IOException: If an I/O error has occurred.
        """


class BinaryReader(java.lang.Object):
    """
    A class for reading data from a
    generic byte provider in either big-endian or little-endian.
    """

    class ReaderFunction(java.lang.Object, typing.Generic[T]):
        """
        Reads and returns an object from the current position in the specified BinaryReader.
         
        
        When reading from the BinaryReader, use "readNext" methods to consume the location where
        the object was located.
         
        
        See :meth:`get(BinaryReader) <.get>`
        """

        class_: typing.ClassVar[java.lang.Class]

        def get(self, reader: BinaryReader) -> T:
            """
            Reads from the specified :obj:`BinaryReader` and returns a new object instance.
             
            
            When reading from the BinaryReader, use "readNext" methods to consume the location where
            the object was located.
             
            
            Implementations of this method should not return ``null``, instead they should
            throw an IOException.
            
            :param BinaryReader reader: :obj:`BinaryReader`
            :return: new object
            :rtype: T
            :raises IOException: if error reading
            """


    class InputStreamReaderFunction(java.lang.Object, typing.Generic[T]):
        """
        Reads and returns an object from the current position in the specified input stream.
        """

        class_: typing.ClassVar[java.lang.Class]

        def get(self, is_: java.io.InputStream) -> T:
            """
            Reads from the specified input stream and returns a new object instance.
             
            
            Implementations of this method should not return ``null``, instead they should
            throw an IOException.
            
            :param java.io.InputStream is: an :obj:`InputStream` view of the BinaryReader
            :return: new object
            :rtype: T
            :raises IOException: if error reading
            """


    @typing.type_check_only
    class BinaryReaderInputStream(java.io.InputStream):
        """
        Adapter between this BinaryReader and a InputStream.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    SIZEOF_BYTE: typing.Final = 1
    """
    The size of a BYTE in Java.
    """

    SIZEOF_SHORT: typing.Final = 2
    """
    The size of a SHORT in Java.
    """

    SIZEOF_INT: typing.Final = 4
    """
    The size of an INTEGER in Java.
    """

    SIZEOF_LONG: typing.Final = 8
    """
    The size of a LONG in Java.
    """


    @typing.overload
    def __init__(self, provider: ByteProvider, isLittleEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a reader using the given ByteProvider and endian-order.
        
        If isLittleEndian is true, then all values read
        from the file will be done so assuming
        little-endian order.
        
        Otherwise, if isLittleEndian
        is false, then all values will be read
        assuming big-endian order.
        
        :param ByteProvider provider: the byte provider
        :param jpype.JBoolean or bool isLittleEndian: the endian-order
        """

    @typing.overload
    def __init__(self, provider: ByteProvider, converter: ghidra.util.DataConverter, initialIndex: typing.Union[jpype.JLong, int]):
        """
        Creates a BinaryReader instance.
        
        :param ByteProvider provider: the ByteProvider to use
        :param ghidra.util.DataConverter converter: the :obj:`DataConverter` to use
        :param jpype.JLong or int initialIndex: the initial offset
        """

    def align(self, alignValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Advances the current index so that it aligns to the specified value (if not already
        aligned).
         
        
        For example, if current index was 123 and align value was 16, then current index would
        be advanced to 128.
        
        :param jpype.JInt or int alignValue: position index alignment
        :return: the number of bytes required to align (0..alignValue-1)
        :rtype: int
        """

    def asBigEndian(self) -> BinaryReader:
        """
        Returns a BinaryReader that is in BigEndian mode.
        
        :return: a new independent BinaryReader, at the same position, in BigEndian mode
        :rtype: BinaryReader
        """

    def asLittleEndian(self) -> BinaryReader:
        """
        Returns a BinaryReader that is in LittleEndian mode.
        
        :return: a new independent instance, at the same position, in LittleEndian mode
        :rtype: BinaryReader
        """

    @typing.overload
    def clone(self, newIndex: typing.Union[jpype.JLong, int]) -> BinaryReader:
        """
        Returns a clone of this reader, with its own independent current position,
        positioned at the new index.
        
        :param jpype.JLong or int newIndex: the new index
        :return: an independent clone of this reader positioned at the new index
        :rtype: BinaryReader
        """

    @typing.overload
    def clone(self) -> BinaryReader:
        """
        Returns an independent clone of this reader positioned at the same index.
        
        :return: a independent clone of this reader positioned at the same index
        :rtype: BinaryReader
        """

    def getByteProvider(self) -> ByteProvider:
        """
        Returns the underlying byte provider.
        
        :return: the underlying byte provider
        :rtype: ByteProvider
        """

    def getInputStream(self) -> java.io.InputStream:
        """
        Returns an InputStream that is a live view of the BinaryReader's position.
         
        
        Any bytes read with the stream will affect the current position of the BinaryReader, and
        any change to the BinaryReader's position will affect the next value the inputstream returns.
        
        :return: :obj:`InputStream`
        :rtype: java.io.InputStream
        """

    def getPointerIndex(self) -> int:
        """
        Returns the current index value.
        
        :return: the current index value
        :rtype: int
        """

    @typing.overload
    def hasNext(self) -> bool:
        """
        Returns true if this stream has data that could be read at the current position.
        
        :return: true if there are more bytes that could be read at the 
        :meth:`current index <.getPointerIndex>`.
        :rtype: bool
        """

    @typing.overload
    def hasNext(self, count: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if this stream has data that could be read at the current position.
        
        :param jpype.JInt or int count: number of bytes to verify
        :return: true if there are at least count more bytes that could be read at the 
        :meth:`current index <.getPointerIndex>`.
        :rtype: bool
        """

    def isBigEndian(self) -> bool:
        """
        Returns true if this reader will extract values in big endian.
        
        :return: true is big endian, false is little endian
        :rtype: bool
        """

    def isLittleEndian(self) -> bool:
        """
        Returns true if this reader will extract values in little endian,
        otherwise in big endian.
        
        :return: true is little endian, false is big endian
        :rtype: bool
        """

    @typing.overload
    def isValidIndex(self, index: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the specified unsigned int32 index into the underlying byte provider is
        valid.
        
        :param jpype.JInt or int index: an integer that is treated as an unsigned int32 index into the byte provider
        :return: returns true if the specified index is valid
        :rtype: bool
        """

    @typing.overload
    def isValidIndex(self, index: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the specified index into the underlying byte provider is valid.
        
        :param jpype.JLong or int index: the index in the byte provider
        :return: returns true if the specified index is valid
        :rtype: bool
        """

    def isValidRange(self, startIndex: typing.Union[jpype.JLong, int], count: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the specified range is valid and does not wrap around the end of the 
        index space.
        
        :param jpype.JLong or int startIndex: the starting index to check, treated as an unsigned int64
        :param jpype.JInt or int count: the number of bytes to check
        :return: boolean true if all bytes between startIndex to startIndex+count (exclusive) are 
        valid (according to the underlying byte provider)
        :rtype: bool
        """

    def length(self) -> int:
        """
        Returns the length of the underlying file.
        
        :return: returns the length of the underlying file
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def peekNextByte(self) -> int:
        """
        Peeks at the next byte without incrementing
        the current index.
        
        :return: the next byte
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def peekNextInt(self) -> int:
        """
        Peeks at the next integer without incrementing
        the current index.
        
        :return: the next int
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def peekNextLong(self) -> int:
        """
        Peeks at the next long without incrementing
        the current index.
        
        :return: the next long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def peekNextShort(self) -> int:
        """
        Peeks at the next short without incrementing
        the current index.
        
        :return: the next short
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readAsciiString(self, index: typing.Union[jpype.JLong, int]) -> str:
        """
        Reads a null terminated US-ASCII string, starting at specified index, stopping at
        the first null character.
         
        
        Note: this method no longer trims() the returned String.
        
        :param jpype.JLong or int index: starting position of the string
        :return: US-ASCII string, excluding the trailing null terminator character
        :rtype: str
        :raises IOException: if error reading bytes
        """

    @typing.overload
    def readAsciiString(self, index: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JInt, int]) -> str:
        """
        Reads an fixed length US-ASCII string starting at ``index``.
         
        
        Trailing null terminator characters will be removed.  (suitable for reading
        a string from a fixed length field that is padded with trailing null chars)
         
        
        Note: this method no longer trims() the returned String.
        
        :param jpype.JLong or int index: where the string begins
        :param jpype.JInt or int length: number of bytes to read
        :return: the US-ASCII string
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    def readByte(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the signed BYTE at ``index``.
        
        :param jpype.JLong or int index: the index where the BYTE begins
        :return: the signed BYTE
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readByteArray(self, index: typing.Union[jpype.JLong, int], nElements: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Returns the BYTE array of ``nElements``
        starting at ``index``.
        
        :param jpype.JLong or int index: the index where the BYTE begins
        :param jpype.JInt or int nElements: the number of array elements
        :return: the BYTE array
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readInt(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the signed INTEGER at ``index``.
        
        :param jpype.JLong or int index: the index where the INTEGER begins
        :return: the signed INTEGER
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readInt(self, dc: ghidra.util.DataConverter, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the signed INTEGER at ``index``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JLong or int index: the index where the INTEGER begins
        :return: the signed INTEGER
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readIntArray(self, index: typing.Union[jpype.JLong, int], nElements: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JInt]:
        """
        Returns the INTEGER array of ``nElements``
        starting at ``index``.
        
        :param jpype.JLong or int index: the index where the INTEGER begins
        :param jpype.JInt or int nElements: the number of array elements
        :return: the INTEGER array
        :rtype: jpype.JArray[jpype.JInt]
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readLong(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the signed LONG at ``index``.
        
        :param jpype.JLong or int index: the index where the LONG begins
        :return: the LONG
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readLong(self, dc: ghidra.util.DataConverter, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the signed LONG at ``index``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JLong or int index: the index where the LONG begins
        :return: the LONG
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readLongArray(self, index: typing.Union[jpype.JLong, int], nElements: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JLong]:
        """
        Returns the LONG array of ``nElements``
        starting at ``index``.
        
        :param jpype.JLong or int index: the index where the LONG begins
        :param jpype.JInt or int nElements: the number of array elements
        :return: the LONG array
        :rtype: jpype.JArray[jpype.JLong]
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNext(self, func: BinaryReader.ReaderFunction[T]) -> T:
        """
        Reads an object from the current position, using the supplied reader function.
        
        :param T: type of the object that will be returned:param BinaryReader.ReaderFunction[T] func: :obj:`ReaderFunction` that will read and return an object
        :return: new object of type T
        :rtype: T
        :raises IOException: if error reading
        """

    @typing.overload
    def readNext(self, func: BinaryReader.InputStreamReaderFunction[T]) -> T:
        """
        Reads an object from the current position, using the supplied reader function.
        
        :param T: type of the object that will be returned:param BinaryReader.InputStreamReaderFunction[T] func: :obj:`InputStreamReaderFunction` that will read and return an object
        :return: new object of type T
        :rtype: T
        :raises IOException: if error reading
        """

    @typing.overload
    def readNextAsciiString(self) -> str:
        """
        Reads a null terminated US-ASCII string starting at the current index,
        advancing the current index by the length of the string that was found.
         
        
        Note: this method no longer trims() the returned String.
        
        :return: the US-ASCII string at the current index
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextAsciiString(self, length: typing.Union[jpype.JInt, int]) -> str:
        """
        Reads a fixed length US-ASCII string starting at the current index,
        advancing the current index by the specified fixed length.
         
        
        Trailing null terminator characters will be removed.  (suitable for reading
        a string from a fixed length field that is padded with trailing null chars)
         
        
        Note: this method no longer trims() the returned String.
        
        :param jpype.JInt or int length: number of bytes to read
        :return: the US-ASCII string at the current index
        :rtype: str
        :raises IOException: if an IO-related error occurred
        """

    def readNextByte(self) -> int:
        """
        Reads the byte at the current index and then increments the current
        index by ``SIZEOF_BYTE``.
        
        :return: the byte at the current index
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readNextByteArray(self, nElements: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Reads a byte array of ``nElements``
        starting at the current index and then increments the current
        index by ``SIZEOF_BYTE * nElements``.
        
        :param jpype.JInt or int nElements: number of elements to read
        :return: the byte array starting at the current index
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextInt(self) -> int:
        """
        Reads the integer at the current index and then increments the current
        index by ``SIZEOF_INT``.
        
        :return: the integer at the current index
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextInt(self, dc: ghidra.util.DataConverter) -> int:
        """
        Reads the integer at the current index and then increments the current
        index by ``SIZEOF_INT``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :return: the integer at the current index
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readNextIntArray(self, nElements: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JInt]:
        """
        Reads an integer array of ``nElements``
        starting at the current index and then increments the current
        index by ``SIZEOF_INT * nElements``.
        
        :param jpype.JInt or int nElements: number of elements to read
        :return: the integer array starting at the current index
        :rtype: jpype.JArray[jpype.JInt]
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextLong(self) -> int:
        """
        Reads the long at the current index and then increments the current
        index by ``SIZEOF_LONG``.
        
        :return: the long at the current index
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextLong(self, dc: ghidra.util.DataConverter) -> int:
        """
        Reads the long at the current index and then increments the current
        index by ``SIZEOF_LONG``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :return: the long at the current index
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readNextLongArray(self, nElements: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JLong]:
        """
        Reads a long array of ``nElements``
        starting at the current index and then increments the current
        index by ``SIZEOF_LONG * nElements``.
        
        :param jpype.JInt or int nElements: number of elements to read
        :return: the long array starting at the current index
        :rtype: jpype.JArray[jpype.JLong]
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextShort(self) -> int:
        """
        Reads the short at the current index and then increments the current
        index by ``SIZEOF_SHORT``.
        
        :return: the short at the current index
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextShort(self, dc: ghidra.util.DataConverter) -> int:
        """
        Reads the short at the current index and then increments the current
        index by ``SIZEOF_SHORT``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :return: the short at the current index
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readNextShortArray(self, nElements: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JShort]:
        """
        Reads a short array of ``nElements``
        starting at the current index and then increments the current
        index by ``SIZEOF_SHORT * nElements``.
        
        :param jpype.JInt or int nElements: number of elements to read
        :return: the short array starting at the current index
        :rtype: jpype.JArray[jpype.JShort]
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnicodeString(self) -> str:
        """
        Reads a null-terminated UTF-16 Unicode string at the current index, 
        advancing the current index by the length of the string that was found.
        
        :return: UTF-16 string at the current index
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnicodeString(self, charCount: typing.Union[jpype.JInt, int]) -> str:
        """
        Reads a fixed length UTF-16 Unicode string at the current index,
        advancing the current index by the length of the string that was found.
        
        :param jpype.JInt or int charCount: number of UTF-16 characters to read (not bytes)
        :return: the UTF-16 Unicode string at the current index
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    def readNextUnsignedByte(self) -> int:
        """
        Reads the unsigned byte at the current index and then increments the current
        index by ``SIZEOF_BYTE``.
        
        :return: the unsigned byte at the current index, as an int
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnsignedInt(self) -> int:
        """
        Reads the unsigned integer at the current index and then increments the current
        index by ``SIZEOF_INT``.
        
        :return: the unsigned integer at the current index, as a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnsignedInt(self, dc: ghidra.util.DataConverter) -> int:
        """
        Reads the unsigned integer at the current index and then increments the current
        index by ``SIZEOF_INT``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :return: the unsigned integer at the current index, as a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnsignedIntExact(self) -> int:
        """
        Reads an unsigned int32 value, and returns it as a java int (instead of a java long).
         
        
        If the value is outside the range of 0..Integer.MAX_VALUE, an InvalidDataException is thrown.
         
        
        Useful for reading uint32 values that are going to be used in java to allocate arrays or
        other similar cases where the value must be a java integer.
        
        :return: the uint32 value read from the stream, if it fits into the range [0..MAX_VALUE] 
        of a java integer
        :rtype: int
        :raises IOException: if there was an error reading
        :raises InvalidDataException: if value can not be held in a java integer
        """

    @typing.overload
    def readNextUnsignedIntExact(self, dc: ghidra.util.DataConverter) -> int:
        """
        Reads an unsigned int32 value, and returns it as a java int (instead of a java long).
         
        
        If the value is outside the range of 0..Integer.MAX_VALUE, an InvalidDataException is thrown.
         
        
        Useful for reading uint32 values that are going to be used in java to allocate arrays or
        other similar cases where the value must be a java integer.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :return: the uint32 value read from the stream, if it fits into the range [0..MAX_VALUE] 
        of a java integer
        :rtype: int
        :raises IOException: if there was an error reading
        :raises InvalidDataException: if value can not be held in a java integer
        """

    @typing.overload
    def readNextUnsignedShort(self) -> int:
        """
        Reads the unsigned short at the current index and then increments the current
        index by ``SIZEOF_SHORT``.
        
        :return: the unsigned short at the current index, as an int
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnsignedShort(self, dc: ghidra.util.DataConverter) -> int:
        """
        Reads the unsigned short at the current index and then increments the current
        index by ``SIZEOF_SHORT``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :return: the unsigned short at the current index, as an int
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnsignedValue(self, len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unsigned value of the integer (of the specified length) at the current index.
        
        :param jpype.JInt or int len: the number of bytes that the integer occupies, 1 to 8
        :return: unsigned value of requested length, in a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnsignedValue(self, dc: ghidra.util.DataConverter, len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unsigned value of the integer (of the specified length) at the current index.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JInt or int len: the number of bytes that the integer occupies, 1 to 8
        :return: unsigned value of requested length, in a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUnsignedVarIntExact(self, func: BinaryReader.ReaderFunction[java.lang.Long]) -> int:
        """
        Reads a variable length / unknown format unsigned integer from the current position, using
        the supplied reader function, returning it (if it fits) as a 32 bit java integer.
        
        :param BinaryReader.ReaderFunction[java.lang.Long] func: :obj:`ReaderFunction`
        :return: unsigned int32
        :rtype: int
        :raises IOException: if error reading data
        :raises InvalidDataException: if value can not be held in a java integer
        """

    @typing.overload
    def readNextUnsignedVarIntExact(self, func: BinaryReader.InputStreamReaderFunction[java.lang.Long]) -> int:
        """
        Reads a variable length / unknown format unsigned integer from the current position, using
        the supplied reader function, returning it (if it fits) as a 32 bit java integer.
        
        :param BinaryReader.InputStreamReaderFunction[java.lang.Long] func: :obj:`InputStreamReaderFunction`
        :return: unsigned int32
        :rtype: int
        :raises IOException: if error reading data
        :raises InvalidDataException: if value can not be held in a java integer
        """

    @typing.overload
    def readNextUtf8String(self) -> str:
        """
        Reads a null-terminated UTF-8 string at the current index, 
        advancing the current index by the length of the string that was found.
        
        :return: UTF-8 string at the current index
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextUtf8String(self, length: typing.Union[jpype.JInt, int]) -> str:
        """
        Reads a fixed length UTF-8 string the current index,
        advancing the current index by the length of the string that was found.
        
        :param jpype.JInt or int length: number of bytes to read
        :return: the UTF-8 string at the current index
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextValue(self, len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the signed value of the integer (of the specified length) at the current index.
        
        :param jpype.JInt or int len: the number of bytes that the integer occupies, 1 to 8
        :return: value of requested length, with sign bit extended, in a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextValue(self, dc: ghidra.util.DataConverter, len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the signed value of the integer (of the specified length) at the current index.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JInt or int len: the number of bytes that the integer occupies, 1 to 8
        :return: value of requested length, with sign bit extended, in a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readNextVarInt(self, func: BinaryReader.ReaderFunction[java.lang.Long]) -> int:
        """
        Reads a variable length / unknown format integer from the current position, using the
        supplied reader function, returning it (if it fits) as a 32 bit java integer.
        
        :param BinaryReader.ReaderFunction[java.lang.Long] func: :obj:`ReaderFunction`
        :return: signed int32
        :rtype: int
        :raises IOException: if error reading or if the value does not fit into a 32 bit java int
        :raises InvalidDataException: if value can not be held in a java integer
        """

    @typing.overload
    def readNextVarInt(self, func: BinaryReader.InputStreamReaderFunction[java.lang.Long]) -> int:
        """
        Reads a variable length / unknown format integer from the current position, using the
        supplied reader function, returning it (if it fits) as a 32 bit java integer.
        
        :param BinaryReader.InputStreamReaderFunction[java.lang.Long] func: :obj:`InputStreamReaderFunction`
        :return: signed int32
        :rtype: int
        :raises IOException: if error reading or if the value does not fit into a 32 bit java int
        :raises InvalidDataException: if value can not be held in a java integer
        """

    @typing.overload
    def readShort(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the signed SHORT at ``index``.
        
        :param jpype.JLong or int index: the index where the SHORT begins
        :return: the signed SHORT
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readShort(self, dc: ghidra.util.DataConverter, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the signed SHORT at ``index``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JLong or int index: the index where the SHORT begins
        :return: the signed SHORT
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def readShortArray(self, index: typing.Union[jpype.JLong, int], nElements: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JShort]:
        """
        Returns the SHORT array of ``nElements``
        starting at ``index``.
        
        :param jpype.JLong or int index: the index where the SHORT begins
        :param jpype.JInt or int nElements: the number of array elements
        :return: the SHORT array
        :rtype: jpype.JArray[jpype.JShort]
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUnicodeString(self, index: typing.Union[jpype.JLong, int]) -> str:
        """
        Reads a null-terminated UTF-16 Unicode string starting at ``index`` and using 
        the pre-specified :meth:`endianness <.setLittleEndian>`.
         
        
        The end of the string is denoted by a two-byte (ie. short) ``null`` character.
        
        :param jpype.JLong or int index: where the UTF-16 Unicode string begins
        :return: the UTF-16 Unicode string
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUnicodeString(self, index: typing.Union[jpype.JLong, int], charCount: typing.Union[jpype.JInt, int]) -> str:
        """
        Reads a fixed length UTF-16 Unicode string of ``length`` characters
        starting at ``index``, using the pre-specified
        :meth:`endianness <.setLittleEndian>`.
         
        
        Trailing null terminator characters will be removed.  (suitable for reading
        a string from a fixed length field that is padded with trailing null chars)
        
        :param jpype.JLong or int index: the index where the UTF-16 Unicode string begins
        :param jpype.JInt or int charCount: the number of UTF-16 character elements to read.
        :return: the UTF-16 Unicode string
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    def readUnsignedByte(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the unsigned BYTE at ``index``.
        
        :param jpype.JLong or int index: the index where the BYTE begins
        :return: the unsigned BYTE as an int
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUnsignedInt(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the unsigned INTEGER at ``index``.
        
        :param jpype.JLong or int index: the index where the INTEGER begins
        :return: the unsigned INTEGER as a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUnsignedInt(self, dc: ghidra.util.DataConverter, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the unsigned INTEGER at ``index``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JLong or int index: the index where the INTEGER begins
        :return: the unsigned INTEGER as a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUnsignedShort(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the unsigned SHORT at ``index``.
        
        :param jpype.JLong or int index: the index where the SHORT begins
        :return: the unsigned SHORT as an int
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUnsignedShort(self, dc: ghidra.util.DataConverter, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the unsigned SHORT at ``index``.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JLong or int index: the index where the SHORT begins
        :return: the unsigned SHORT as an int
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUnsignedValue(self, index: typing.Union[jpype.JLong, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unsigned value of the integer (of the specified length) at the specified offset.
        
        :param jpype.JLong or int index: where the value begins
        :param jpype.JInt or int len: the number of bytes that the integer occupies, 1 to 8
        :return: unsigned value of requested length, in a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUnsignedValue(self, dc: ghidra.util.DataConverter, index: typing.Union[jpype.JLong, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unsigned value of the integer (of the specified length) at the specified offset.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JLong or int index: where the value begins
        :param jpype.JInt or int len: the number of bytes that the integer occupies, 1 to 8
        :return: unsigned value of requested length, in a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUtf8String(self, index: typing.Union[jpype.JLong, int]) -> str:
        """
        Reads a null-terminated UTF-8 string starting at ``index``.
        
        :param jpype.JLong or int index: where the UTF-8 string begins
        :return: the string
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readUtf8String(self, index: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JInt, int]) -> str:
        """
        Reads a fixed length UTF-8 string of ``length`` bytes
        starting at ``index``.
         
        
        Trailing null terminator characters will be removed.  (suitable for reading
        a string from a fixed length field that is padded with trailing null chars)
        
        :param jpype.JLong or int index: the index where the UTF-8 string begins
        :param jpype.JInt or int length: the number of bytes to read
        :return: the string
        :rtype: str
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readValue(self, index: typing.Union[jpype.JLong, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the signed value of the integer (of the specified length) at the specified offset.
        
        :param jpype.JLong or int index: where the value begins
        :param jpype.JInt or int len: the number of bytes that the integer occupies, 1 to 8
        :return: value of requested length, with sign bit extended, in a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    @typing.overload
    def readValue(self, dc: ghidra.util.DataConverter, index: typing.Union[jpype.JLong, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the signed value of the integer (of the specified length) at the specified offset.
        
        :param ghidra.util.DataConverter dc: :obj:`BE <BigEndianDataConverter>` or :obj:`LE <LittleEndianDataConverter>`
        :param jpype.JLong or int index: where the value begins
        :param jpype.JInt or int len: the number of bytes that the integer occupies, 1 to 8
        :return: value of requested length, with sign bit extended, in a long
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def setLittleEndian(self, isLittleEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the endian of this binary reader.
        
        :param jpype.JBoolean or bool isLittleEndian: true for little-endian and false for big-endian
        """

    @typing.overload
    def setPointerIndex(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        A convenience method for setting the index using a 32 bit integer.
        
        :param jpype.JInt or int index: new index, treated as a 32 bit unsigned integer
        :return: previous reader offset for use with :meth:`setPointerIndex(long) <.setPointerIndex>` to restore 
        previous position.
        :rtype: int
        """

    @typing.overload
    def setPointerIndex(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Sets the current index to the specified value.
        The pointer index will allow the reader
        to operate as a pseudo-iterator.
        
        :param jpype.JLong or int index: the byte provider index value
        :return: previous reader offset for use with this method to restore previous position.
        :rtype: int
        """

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def pointerIndex(self) -> jpype.JLong:
        ...

    @property
    def validIndex(self) -> jpype.JBoolean:
        ...

    @property
    def byteProvider(self) -> ByteProvider:
        ...

    @property
    def littleEndian(self) -> jpype.JBoolean:
        ...

    @littleEndian.setter
    def littleEndian(self, value: jpype.JBoolean):
        ...

    @property
    def inputStream(self) -> java.io.InputStream:
        ...


class RandomAccessMutableByteProvider(RandomAccessByteProvider, MutableByteProvider):
    """
    An implementation of ByteProvider where the underlying
    bytes are supplied by a random access file.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Constructs a byte provider using the specified file
        
        :param jpype.protocol.SupportsPath file: the file to open for random access
        :raises FileNotFoundException: if the file does not exist
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath, permissions: typing.Union[java.lang.String, str]):
        """
        Constructs a byte provider using the specified file and permissions string
        
        :param jpype.protocol.SupportsPath file: the file to open for random access
        :param java.lang.String or str permissions: indicating permissions used for open
        :raises FileNotFoundException: if the file does not exist
        """


class ObfuscatedFileByteProvider(FileByteProvider):
    """
    A :obj:`ByteProvider` that reads from an on-disk file, but obfuscates / de-obfuscates the
    contents of the file when reading / writing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath, fsrl: ghidra.formats.gfilesystem.FSRL, accessMode: java.nio.file.AccessMode):
        """
        Creates an instance of :obj:`ObfuscatedFileByteProvider`.
        
        :param jpype.protocol.SupportsPath file: :obj:`File` to read from / write to
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` identity of this file
        :param java.nio.file.AccessMode accessMode: :obj:`AccessMode.READ` or :obj:`AccessMode.WRITE`
        :raises IOException: if error
        """


class StructConverter(java.lang.Object):
    """
    Allows a class to create a structure
    datatype equivalent to its class members.
    """

    class_: typing.ClassVar[java.lang.Class]
    BYTE: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable BYTE datatype.
    """

    WORD: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable WORD datatype.
    """

    DWORD: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable DWORD datatype.
    """

    QWORD: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable QWORD datatype.
    """

    ASCII: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable ASCII datatype.
    """

    STRING: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable STRING datatype.
    """

    UTF8: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable UTF8 string datatype.
    """

    UTF16: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable UTF16 string datatype.
    """

    POINTER: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable POINTER datatype.
    """

    VOID: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable VOID datatype.
    """

    IBO32: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable 32-bit image base offset datatype.
    """

    IBO64: typing.Final[ghidra.program.model.data.DataType]
    """
    Reusable 64-bit image base offset datatype.
    """

    ULEB128: typing.Final[ghidra.program.model.data.UnsignedLeb128DataType]
    """
    Reusable Unsigned LEB128 dynamic length data type
    """

    SLEB128: typing.Final[ghidra.program.model.data.SignedLeb128DataType]
    """
    Reusable Signed LEB128 dynamic length data type
    """


    @staticmethod
    def setEndian(data: ghidra.program.model.listing.Data, bigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Recursively sets the given :obj:`Data` and its components to big/little endian
        
        :param ghidra.program.model.listing.Data data: The :obj:`Data`
        :param jpype.JBoolean or bool bigEndian: True to set to big endian; false to set to little endian
        :raises java.lang.Exception: if there was a problem setting the endianness
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        Returns a structure datatype representing the
        contents of the implementor of this interface.
         
         
        For example, given:
         
        class A {
            int foo;
            double bar;
        }
         
         
        
        The return value should be a structure data type with two 
        data type components; an INT and a DOUBLE. The structure 
        should contain field names and, if possible,
        field comments.
        
        :return: returns a structure datatype representing
                the implementor of this interface
        :rtype: ghidra.program.model.data.DataType
        :raises DuplicateNameException: when a datatype of the same name already exists
        :raises IOException: if an IO-related error occurs
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.StructureDataType`
        """


class ByteArrayProvider(ByteProvider):
    """
    An implementation of :obj:`ByteProvider` where the underlying bytes are supplied by a
    byte array.
     
    
    NOTE: Use of this class is discouraged when the byte array could be large.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte]):
        """
        Constructs a :obj:`ByteArrayProvider` using the specified byte array
        
        :param jpype.JArray[jpype.JByte] bytes: the underlying byte array
        """

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte], fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Constructs a :obj:`ByteArrayProvider` using the specified byte array
        
        :param jpype.JArray[jpype.JByte] bytes: the underlying byte array
        :param ghidra.formats.gfilesystem.FSRL fsrl: FSRL identity of the file
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], bytes: jpype.JArray[jpype.JByte]):
        """
        Constructs a :obj:`ByteArrayProvider` using the specified byte array
        
        :param java.lang.String or str name: the name of the :obj:`ByteProvider`
        :param jpype.JArray[jpype.JByte] bytes: the underlying byte array
        """

    def hardClose(self):
        """
        Releases the byte storage of this instance.
         
        
        This is separate from the normal close() to avoid changing existing
        behavior of this class.
        """


class StructConverterUtil(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @staticmethod
    def parseName(clazz: java.lang.Class[typing.Any]) -> str:
        ...

    @staticmethod
    @typing.overload
    def toDataType(object: java.lang.Object) -> ghidra.program.model.data.DataType:
        """
        This is a convenience method for converting a class into structure.
        The class is reflected to extract the field members.
        Only private non-static fields are considered.
        Any field names that start with underscore ("_") are ignored.
        
        :param java.lang.Object object: the object to reflect
        :return: a structure representing the class fields.
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    @typing.overload
    def toDataType(clazz: java.lang.Class[typing.Any]) -> ghidra.program.model.data.DataType:
        """
        This is a convenience method for converting a class into structure.
        The class is reflected to extract the field members.
        Only private non-static fields are considered.
        Any field names that start with underscore ("_") are ignored.
        
        :param java.lang.Class[typing.Any] clazz: the class to reflect
        :return: a structure representing the class fields.
        :rtype: ghidra.program.model.data.DataType
        """


class MemBufferByteProvider(ByteProvider):
    """
    ``MemBufferByteProvider`` provide a :obj:`ByteProvider` backed by
    a :obj:`MemBuffer`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buffer: ghidra.program.model.mem.MemBuffer):
        """
        Constructor
        
        :param ghidra.program.model.mem.MemBuffer buffer: memory buffer
        """

    def length(self) -> int:
        """
        Return maximum length since actual length is unknown
        
        :return: maximum possible length
        :rtype: int
        """


class LEB128Info(java.lang.Object):
    """
    Class to hold result of reading a :obj:`LEB128` value, along with size and position metadata.
    """

    class_: typing.ClassVar[java.lang.Class]

    def asInt32(self) -> int:
        """
        Returns the value as an signed int32.  If the actual value
        is outside the range of a java int (ie.  :obj:`Integer.MIN_VALUE`.. :obj:`Integer.MAX_VALUE`),
        an exception is thrown.
        
        :return: int in the range of :obj:`Integer.MIN_VALUE` to  :obj:`Integer.MAX_VALUE`
        :rtype: int
        :raises IOException: if value is outside range
        """

    def asLong(self) -> int:
        """
        Returns the value as a 64bit primitive long.  Interpreting the signed-ness of the
        value will depend on the way the value was read (ie. if :meth:`signed(BinaryReader) <.signed>`
        vs. :meth:`unsigned(BinaryReader) <.unsigned>` was used).
        
        :return: long value.
        :rtype: int
        """

    def asUInt32(self) -> int:
        """
        Returns the value as an unsigned int32.  If the actual value
        is outside the positive range of a java int (ie. 0.. :obj:`Integer.MAX_VALUE`),
        an exception is thrown.
        
        :return: int in the range of 0 to  :obj:`Integer.MAX_VALUE`
        :rtype: int
        :raises IOException: if value is outside range
        """

    def getLength(self) -> int:
        """
        Returns the number of bytes that were used to store the LEB128 value in the stream
        it was read from.
        
        :return: number of bytes used to store the read LEB128 value
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Returns the offset of the LEB128 value in the stream it was read from.
        
        :return: stream offset of the LEB128 value
        :rtype: int
        """

    @staticmethod
    def readValue(reader: BinaryReader, isSigned: typing.Union[jpype.JBoolean, bool]) -> LEB128Info:
        """
        Reads a LEB128 value from the BinaryReader and returns a :obj:`LEB128Info` instance
        that contains the value along with size and position metadata.
        
        :param BinaryReader reader: :obj:`BinaryReader` to read bytes from
        :param jpype.JBoolean or bool isSigned: true if the value is signed
        :return: a :obj:`LEB128Info` instance with the read LEB128 value with metadata
        :rtype: LEB128Info
        :raises IOException: if an I/O error occurs or value is outside the range of a java
        64 bit int
        """

    @staticmethod
    def signed(reader: BinaryReader) -> LEB128Info:
        """
        Reads an signed LEB128 value from the BinaryReader and returns a :obj:`LEB128Info` instance
        that contains the value along with size and position metadata.
        
        :param BinaryReader reader: :obj:`BinaryReader` to read bytes from
        :return: a :obj:`LEB128Info` instance with the read LEB128 value with metadata
        :rtype: LEB128Info
        :raises IOException: if an I/O error occurs or value is outside the range of a java
        64 bit int
        """

    @staticmethod
    def unsigned(reader: BinaryReader) -> LEB128Info:
        """
        Reads an unsigned LEB128 value from the BinaryReader and returns a :obj:`LEB128Info` instance
        that contains the value along with size and position metadata.
        
        :param BinaryReader reader: :obj:`BinaryReader` to read bytes from
        :return: a :obj:`LEB128Info` instance with the read LEB128 value with metadata
        :rtype: LEB128Info
        :raises IOException: if an I/O error occurs or value is outside the range of a java
        64 bit int
        """

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class FaultTolerantInputStream(java.io.InputStream):
    """
    An InputStream wrapper that suppresses any :obj:`IOException`s thrown by the wrapped stream
    and starts returning 0 value bytes for all subsequent reads.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: java.io.InputStream, length: typing.Union[jpype.JLong, int], errorConsumer: java.util.function.BiConsumer[java.lang.String, java.lang.Throwable]):
        """
        Creates instance.
        
        :param java.io.InputStream delegate: :obj:`InputStream` to wrap
        :param jpype.JLong or int length: expected length of the stream
        :param java.util.function.BiConsumer[java.lang.String, java.lang.Throwable] errorConsumer: consumer that will accept errors, if null Msg.error() will be used
        """


class RangeMappedByteProvider(ByteProvider):
    """
    A :obj:`ByteProvider` that is a concatenation of sub-ranges of another ByteProvider, also
    allowing for non-initialized (sparse) regions.
     
     
    Not thread-safe when ranges are being added.
     
    
    Does not assume ownership of wrapped ByteProvider.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ByteProvider, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Creates a new :obj:`RangeMappedByteProvider`.
        
        :param ByteProvider provider: :obj:`ByteProvider` to wrap
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` of this new byte provider
        """

    def addRange(self, offset: typing.Union[jpype.JLong, int], rangeLen: typing.Union[jpype.JLong, int]):
        """
        Adds a range to the current end of this instance.
         
        
        If the new range immediately follows the previous range, the new range is merged
        into the previous entry.
        
        :param jpype.JLong or int offset: long byte offset in the delegate ByteProvider, -1 indicates a sparse
        range with no storage
        :param jpype.JLong or int rangeLen: long length of the range in the delegate ByteProvider
        """

    def addSparseRange(self, rangeLen: typing.Union[jpype.JLong, int]):
        """
        Adds a sparse range to the current end of this instance.
        
        :param jpype.JLong or int rangeLen: long length of the sparse range
        """

    def getRangeCount(self) -> int:
        """
        Return the number of ranges.  Adjacent ranges that were merged
        will count as a single range.
        
        :return: number of ranges
        :rtype: int
        """

    def readBytes(self, index: typing.Union[jpype.JLong, int], buffer: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Read bytes at the specified index into the given byte array.
         
        
        See :meth:`InputStream.read(byte[], int, int) <InputStream.read>`.
        
        :param jpype.JLong or int index: file offset to start reading
        :param jpype.JArray[jpype.JByte] buffer: byte array that will receive the bytes
        :param jpype.JInt or int offset: offset inside the byte array to place the bytes
        :param jpype.JInt or int len: number of bytes to read
        :return: number of actual bytes read
        :rtype: int
        :raises IOException: if error
        """

    @property
    def rangeCount(self) -> jpype.JInt:
        ...


class MutableByteProvider(ByteProvider):
    """
    An interface for a generic random-access byte provider, plus mutation methods.
    """

    class_: typing.ClassVar[java.lang.Class]

    def writeByte(self, index: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JByte, int]):
        """
        Writes a byte at the specified index.
        
        :param jpype.JLong or int index: the index to write the byte
        :param jpype.JByte or int value: the value to write at the specified index
        :raises IOException: if an I/O error occurs
        """

    def writeBytes(self, index: typing.Union[jpype.JLong, int], values: jpype.JArray[jpype.JByte]):
        """
        Writes a byte array at the specified index.
        
        :param jpype.JLong or int index: the index to write the byte array
        :param jpype.JArray[jpype.JByte] values: the values to write at the specified index
        :raises IOException: if an I/O error occurs
        """


class ObfuscatedInputStream(java.io.InputStream):
    """
    An :obj:`InputStream` wrapper that de-obfuscates the bytes being read from the underlying
    stream.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: java.io.InputStream):
        """
        Creates instance.
        
        :param java.io.InputStream delegate: :obj:`InputStream` to wrap
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        """
        Entry point to enable command line users to retrieve the contents of an obfuscated
        file.
        
        :param jpype.JArray[java.lang.String] args: either ["--help"], or [ "input_filename", "output_filename" ]
        :raises IOException: if error
        """


class FileByteProvider(MutableByteProvider):
    """
    A :obj:`ByteProvider` that reads its bytes from a file.
    """

    @typing.type_check_only
    class Buffer(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath, fsrl: ghidra.formats.gfilesystem.FSRL, accessMode: java.nio.file.AccessMode):
        """
        Creates a new instance.
        
        :param jpype.protocol.SupportsPath file: :obj:`File` to open
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` identity of the file
        :param java.nio.file.AccessMode accessMode: :obj:`AccessMode.READ` or :obj:`AccessMode.WRITE`
        :raises IOException: if error
        """

    def getAccessMode(self) -> java.nio.file.AccessMode:
        """
        Returns the access mode the file was opened with.
        
        :return: :obj:`AccessMode` used to open file
        :rtype: java.nio.file.AccessMode
        """

    def readBytes(self, index: typing.Union[jpype.JLong, int], buffer: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> int:
        """
        Read bytes at the specified index into the given byte array.
         
        
        See :meth:`InputStream.read(byte[], int, int) <InputStream.read>`.
        
        :param jpype.JLong or int index: file offset to start reading
        :param jpype.JArray[jpype.JByte] buffer: byte array that will receive the bytes
        :param jpype.JInt or int offset: offset inside the byte array to place the bytes
        :param jpype.JInt or int length: number of bytes to read
        :return: number of actual bytes read
        :rtype: int
        :raises IOException: if error
        """

    def writeBytes(self, index: typing.Union[jpype.JLong, int], buffer: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Writes bytes to the specified offset in the file.
        
        :param jpype.JLong or int index: the location in the file to starting writing
        :param jpype.JArray[jpype.JByte] buffer: bytes to write
        :param jpype.JInt or int offset: offset in the buffer byte array to start
        :param jpype.JInt or int length: number of bytes to write
        :raises IOException: if bad :obj:`AccessMode` or other io error
        """

    @property
    def accessMode(self) -> java.nio.file.AccessMode:
        ...


class ByteProviderInputStream(java.io.InputStream):
    """
    An :obj:`InputStream` that reads from a :obj:`ByteProvider`.
     
    
    Does not close the underlying ByteProvider when closed itself.
    """

    class ClosingInputStream(ByteProviderInputStream):
        """
        An :obj:`InputStream` that reads from a :obj:`ByteProvider`, and **DOES**
        :meth:`close() <ByteProvider.close>` the underlying ByteProvider when
        closed itself.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, provider: ByteProvider):
            """
            Creates an :obj:`InputStream` that reads from a :obj:`ByteProvider`, that
            **DOES** :meth:`close() <ByteProvider.close>` the underlying ByteProvider when
            closed itself.
            
            :param ByteProvider provider: the :obj:`ByteProvider` to read from (and close)
            """


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: ByteProvider):
        """
        Creates an InputStream that uses a ByteProvider as its source of bytes.
        
        :param ByteProvider provider: the :obj:`ByteProvider` to wrap
        """

    @typing.overload
    def __init__(self, provider: ByteProvider, startPosition: typing.Union[jpype.JLong, int]):
        """
        Creates an InputStream that uses a ByteProvider as its source of bytes.
        
        :param ByteProvider provider: the :obj:`ByteProvider` to wrap
        :param jpype.JLong or int startPosition: starting position in the provider
        """


class EmptyByteProvider(ByteProvider):
    """
    A :obj:`ByteProvider` that has no contents.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Create an instance with a null identity
        """

    @typing.overload
    def __init__(self, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Create an instance with the specified :obj:`FSRL` identity.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` identity for this instance
        """


class ObfuscatedOutputStream(java.io.OutputStream):
    """
    An :obj:`OutputStream` wrapper that obfuscates the bytes being written to the underlying
    stream.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: java.io.OutputStream):
        """
        Creates instance.
        
        :param java.io.OutputStream delegate: :obj:`OutputStream` to wrap
        """


class UnlimitedByteProviderWrapper(ByteProviderWrapper):
    """
    A :obj:`ByteProvider` constrained to a sub-section of an existing :obj:`ByteProvider`
    although reads beyond the specified sub-section are permitted but will return zero byte
    values.  The methods :meth:`length() <.length>` and :meth:`getInputStream(long) <.getInputStream>` remain
    bounded by the specified sub-section.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: ByteProvider):
        """
        Creates a wrapper around a :obj:`ByteProvider` that contains the same bytes as the specified
        provider.
        
        :param ByteProvider provider: :obj:`ByteProvider` to wrap
        :raises IOException: if error
        """

    @typing.overload
    def __init__(self, provider: ByteProvider, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Creates a wrapper around a :obj:`ByteProvider` that contains the same bytes as the specified
        provider, but with a new :obj:`FSRL` identity.
        
        :param ByteProvider provider: :obj:`ByteProvider` to wrap
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` identity for the instance
        :raises IOException: if error
        """

    @typing.overload
    def __init__(self, provider: ByteProvider, subOffset: typing.Union[jpype.JLong, int], subLength: typing.Union[jpype.JLong, int]):
        """
        Constructs a :obj:`UnlimitedByteProviderWrapper` around the specified :obj:`ByteProvider`,
        constrained to a subsection of the provider.
        
        :param ByteProvider provider: the :obj:`ByteProvider` to wrap
        :param jpype.JLong or int subOffset: the offset in the :obj:`ByteProvider` of where to start the new
        :obj:`UnlimitedByteProviderWrapper`
        :param jpype.JLong or int subLength: the length of the new :obj:`UnlimitedByteProviderWrapper`
        """

    @typing.overload
    def __init__(self, provider: ByteProvider, subOffset: typing.Union[jpype.JLong, int], subLength: typing.Union[jpype.JLong, int], fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Constructs a :obj:`UnlimitedByteProviderWrapper` around the specified :obj:`ByteProvider`,
        constrained to a subsection of the provider.
        
        :param ByteProvider provider: the :obj:`ByteProvider` to wrap
        :param jpype.JLong or int subOffset: the offset in the :obj:`ByteProvider` of where to start the new
        :obj:`UnlimitedByteProviderWrapper`
        :param jpype.JLong or int subLength: the length of the new :obj:`UnlimitedByteProviderWrapper`
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` identity of the file this ByteProvider represents
        """



__all__ = ["ByteProviderWrapper", "FileBytesProvider", "ByteArrayConverter", "InvalidDataException", "ByteProviderPaddedInputStream", "MemoryMutableByteProvider", "ByteProvider", "MemoryByteProvider", "SynchronizedByteProvider", "RandomAccessByteProvider", "InputStreamByteProvider", "GhidraRandomAccessFile", "BinaryReader", "RandomAccessMutableByteProvider", "ObfuscatedFileByteProvider", "StructConverter", "ByteArrayProvider", "StructConverterUtil", "MemBufferByteProvider", "LEB128Info", "FaultTolerantInputStream", "RangeMappedByteProvider", "MutableByteProvider", "ObfuscatedInputStream", "FileByteProvider", "ByteProviderInputStream", "EmptyByteProvider", "ObfuscatedOutputStream", "UnlimitedByteProviderWrapper"]
