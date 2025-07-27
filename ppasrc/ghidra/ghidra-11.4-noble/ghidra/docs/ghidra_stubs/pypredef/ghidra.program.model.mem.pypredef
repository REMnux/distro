from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.exception
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.nio # type: ignore
import java.util # type: ignore


class MemBufferInputStream(java.io.InputStream):
    """
    Adapter between :obj:`membuffers <MemBuffer>` and :obj:`inputstreams <InputStream>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, membuf: MemBuffer):
        """
        Creates a new instance, starting a offset 0 of the membuffer, limited to the first 2Gb
        of the membuffer.
        
        :param MemBuffer membuf: :obj:`MemBuffer` to wrap as an inputstream
        """

    @typing.overload
    def __init__(self, membuf: MemBuffer, initialPosition: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Creates a new instance of :obj:`MemBufferInputStream`, starting at the specified offset,
        limited to the first ``length`` bytes.
        
        :param MemBuffer membuf: :obj:`MemBuffer` to wrap as an inputstream
        :param jpype.JInt or int initialPosition: starting position in the membuffer
        :param jpype.JInt or int length: number of bytes to limit this inputstream to.  The sum of 
        ``initialPosition`` and ``length`` must not exceed :obj:`Integer.MAX_VALUE`+1
        """


class MemoryConstants(java.lang.Object):
    """
    Memory Constants
    """

    class_: typing.ClassVar[java.lang.Class]
    HEAP_BLOCK_NAME: typing.Final = "__HEAP__"


class ByteMemBufferImpl(MemBuffer):
    """
    Simple byte buffer implementation of the memBuffer.  Even if a Memory is
    provided, the available bytes will be limited to the bytes provided during
    construction.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], isBigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a ByteMemBufferImpl object
        
        :param ghidra.program.model.address.Address addr: the address to associate with the bytes
        :param jpype.JArray[jpype.JByte] bytes: the data that normally would be coming from memory.
        :param jpype.JBoolean or bool isBigEndian: true for BigEndian, false for LittleEndian.
        """

    @typing.overload
    def __init__(self, memory: Memory, addr: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], isBigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a ByteMemBufferImpl object
        
        :param Memory memory: the memory in case getMemory() is called to get associated things like address spaces
        :param ghidra.program.model.address.Address addr: the address to associate with the bytes
        :param jpype.JArray[jpype.JByte] bytes: the data that normally would be coming from memory.
        :param jpype.JBoolean or bool isBigEndian: true for BigEndian, false for LittleEndian.
        """

    def getLength(self) -> int:
        """
        Get number of bytes contained within buffer
        
        :return: byte count
        :rtype: int
        """

    @property
    def length(self) -> jpype.JInt:
        ...


class DumbMemBufferImpl(MemoryBufferImpl):
    """
    ``DumbMemBufferImpl`` extends ``MemoryBufferImpl``
    with an internal cache buffer size of 16-bytes but will use the underlying memory
    if needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mem: Memory, addr: ghidra.program.model.address.Address):
        """
        Construct a new DumbMemBufferImpl
        
        :param Memory mem: memory associated with the given address
        :param ghidra.program.model.address.Address addr: starting address
        """


class MutableMemBuffer(MemBuffer):
    """
    The MutableMemBuffer interface facilitates repositioning of a MemBuffer object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def advance(self, displacement: typing.Union[jpype.JInt, int]):
        """
        Advance the Address pointer.
        
        :param jpype.JInt or int displacement: the amount to adjust the pointer by.
        :raises AddressOverflowException: if displacement would cause the buffer position to wrap.
        """

    def clone(self) -> MutableMemBuffer:
        """
        Create a cloned copy of this MutableMemBuffer
        
        :return: new cloned instance of this buffer object
        :rtype: MutableMemBuffer
        """

    def setPosition(self, addr: ghidra.program.model.address.Address):
        """
        Sets the Address to which offset of 0 points to.
        
        :param ghidra.program.model.address.Address addr: the new base Address.
        """


class MemoryBlockListener(java.lang.Object):
    """
    Methods for a listener that is called when changes are made to a
    MemoryBlock.
    """

    class_: typing.ClassVar[java.lang.Class]

    def commentChanged(self, block: MemoryBlock, oldComment: typing.Union[java.lang.String, str], newComment: typing.Union[java.lang.String, str]):
        """
        Notification that the block's comment changed.
        
        :param MemoryBlock block: affected block
        :param java.lang.String or str oldComment: old comment; may be null
        :param java.lang.String or str newComment: new comment; may be null
        """

    def dataChanged(self, block: MemoryBlock, addr: ghidra.program.model.address.Address, oldData: jpype.JArray[jpype.JByte], newData: jpype.JArray[jpype.JByte]):
        """
        Notification that bytes changed in the block.
        
        :param MemoryBlock block: affected block
        :param ghidra.program.model.address.Address addr: starting address of the change
        :param jpype.JArray[jpype.JByte] oldData: old byte values
        :param jpype.JArray[jpype.JByte] newData: new byte values
        """

    def executeStatusChanged(self, block: MemoryBlock, isExecute: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that the block's execute attribute has changed.
        
        :param MemoryBlock block: affected block
        :param jpype.JBoolean or bool isExecute: true means the block is marked as executable
        """

    def nameChanged(self, block: MemoryBlock, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Notification the name changed.
        
        :param MemoryBlock block: affected block
        :param java.lang.String or str oldName: old name
        :param java.lang.String or str newName: new name
        """

    def readStatusChanged(self, block: MemoryBlock, isRead: typing.Union[jpype.JBoolean, bool]):
        """
        Notification the block's read attribute has changed.
        
        :param MemoryBlock block: affected block
        :param jpype.JBoolean or bool isRead: true means the block is marked as readable
        """

    def sourceChanged(self, block: MemoryBlock, oldSource: typing.Union[java.lang.String, str], newSource: typing.Union[java.lang.String, str]):
        """
        Notification that the source of the block has changed.
        
        :param MemoryBlock block: affected block
        :param java.lang.String or str oldSource: old source
        :param java.lang.String or str newSource: new source
        """

    def sourceOffsetChanged(self, block: MemoryBlock, oldOffset: typing.Union[jpype.JLong, int], newOffset: typing.Union[jpype.JLong, int]):
        """
        Notification that the source offset has changed.
        
        :param MemoryBlock block: affected block
        :param jpype.JLong or int oldOffset: old offset
        :param jpype.JLong or int newOffset: new offset
        """

    def writeStatusChanged(self, block: MemoryBlock, isWrite: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that the block's write attribute has changed.
        
        :param MemoryBlock block: affected block
        :param jpype.JBoolean or bool isWrite: true means the block is marked as writable
        """


class MemBufferMixin(MemBuffer):

    class_: typing.ClassVar[java.lang.Class]

    def getBytes(self, buffer: java.nio.ByteBuffer, addressOffset: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getBytesInFull(self, offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> java.nio.ByteBuffer:
        ...


class MemoryAccessException(ghidra.util.exception.UsrException):
    """
    
    An MemoryAccessException indicates that the attempted
    memory access is not permitted.  (i.e. Readable/Writeable)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs an MemoryAccessException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs an MemoryAccessException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Creates a :obj:`MemoryAccessException` with a message and cause.
        
        :param java.lang.String or str msg: message
        :param java.lang.Throwable cause: nested cause
        """


class WrappedMemBuffer(MemBuffer):
    """
    WrappedMemBuffer implements a MemBuffer that provides a zero based index
    on top of an underlying membuffer with at a given address.  It can buffer N bytes
    at time using the constructor that takes a cache size.  However the default
    is to provide no buffering.  Use of the buffer can
    reduce the overall number of calls to Memory, greatly reducing
    the overhead of various error checks.  This implementation will not wrap
    if the end of the memory space is encountered.
     
    The :meth:`getByte(int) <.getByte>`, :meth:`getBytes(byte[], int) <.getBytes>` methods can cause the bytes in the
    buffer cache if the request is outside of the current cached bytes.
     
    WARNING: The underlying MemBuffer should not change its base address. Using a
    mutable MemBuffer can cause problematic behavior if not controlled carefully.
     
    WARNING: Not thread-safe.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, buf: MemBuffer, baseOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a wrapped MemBuffer with an adjustable base offset
        
        :param MemBuffer buf: memory buffer
        :param jpype.JInt or int baseOffset: offset relative to the underlying buffer's start address
                    (addr + baseOffset) will be the 0 index into this buffer
        :raises AddressOutOfBoundsException:
        """

    @typing.overload
    def __init__(self, buf: MemBuffer, bufferSize: typing.Union[jpype.JInt, int], baseOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a wrapped MemBuffer with an adjustable base offset
        
        :param MemBuffer buf: memory buffer
        :param jpype.JInt or int bufferSize: size of cache buffer - specify 0 for no buffering
        :param jpype.JInt or int baseOffset: offset relative to the underlying buffer's start address
                    (addr + baseOffset) will be the 0 index into this buffer
        :raises AddressOutOfBoundsException:
        """


class MemoryBlockType(java.lang.Enum[MemoryBlockType]):

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final[MemoryBlockType]
    BIT_MAPPED: typing.Final[MemoryBlockType]
    BYTE_MAPPED: typing.Final[MemoryBlockType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MemoryBlockType:
        ...

    @staticmethod
    def values() -> jpype.JArray[MemoryBlockType]:
        ...


class MemBuffer(java.lang.Object):
    """
    MemBuffer provides an array like interface into memory at a
    specific address.  Bytes can be retrieved by using a positive
    offset from the current position.  Depending on the implementation,
    the offset may be restricted to a specific positive range.  If the
    implementation does have a restriction, then a MemoryAccessException
    will be thrown, except for the :meth:`getBytes(byte[], int) <.getBytes>`
    method which will return 0.
    
    The purpose of this class is to
    allow an efficient implementation that buffers memory accesses and
    does not have to keep translating addresses.  This was designed to
    be passed to a language parser.  One advantage of MemBuffer over a
    byte array is that if necessary the actual Memory and Address can
    be retrieved in case all of the necessary bytes are not local.
    
    This interface does not provide methods to reposition the memory
    buffer.  This is so that it is clear that methods accepting this
    base class are not to mess which the base Address for this object.
    
    Memory-backed access is an optional implementation dependent
    capability.  In addition, the use of the relative offset is
    implementation dependent, but in general those implementations
    which are backed by memory may choose to wrap the offset
    when computing the corresponding memory address.  The treatment
    of the offset argument should be consistent across the various
    methods for a given implementation.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.mem.MutableMemBuffer`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the Address which corresponds to the offset 0.
        
        :return: the current address of offset 0.
        :rtype: ghidra.program.model.address.Address
        """

    def getBigInteger(self, offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        returns the value at the given offset, taking into account the endianness.
        
        :param jpype.JInt or int offset: the offset from the membuffers origin (the address that it is set at)
        :param jpype.JInt or int size: the number of bytes to include in the value
        :param jpype.JBoolean or bool signed: true if value should be treated as a signed twos-compliment value.
        :return: the value at the given offset, taking into account the endianness.
        :rtype: java.math.BigInteger
        :raises MemoryAccessException: if the request size value cannot be read at the specified offset
        """

    def getByte(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get one byte from memory at the current position plus offset.
        
        :param jpype.JInt or int offset: the displacement from the current position.
        :return: the data at offset from the current position.
        :rtype: int
        :raises MemoryAccessException: if memory cannot be read at the specified offset
        """

    def getBytes(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Reads ``b.length`` bytes from this memory buffer
        starting at the address of this memory buffer plus the given memoryBufferOffset
        from that position.  The actual number of bytes may be fewer
        if bytes can't be read.
        
        :param jpype.JArray[jpype.JByte] b: the buffer into which bytes will be placed
        :param jpype.JInt or int offset: the offset **in this memory buffer** from which to
                start reading bytes.
        :return: the number of bytes read which may be fewer than b.length if
        available bytes are exhausted or no bytes are available at the specified
        offset.
        :rtype: int
        """

    @typing.overload
    def getInputStream(self) -> java.io.InputStream:
        """
        Returns a stream that supplies the bytes of this buffer, starting at offset 0.
         
        
        Note: the default implementation will produce invalid results if the underlying
        MemBuffer instance is mutated to point to different memory.
        
        :return: an InputStream that returns the bytes of this mem buffer
        :rtype: java.io.InputStream
        """

    @typing.overload
    def getInputStream(self, initialPosition: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> java.io.InputStream:
        """
        Returns a stream that supplies the bytes of this buffer, starting at the specified offset.
         
        
        Note: the default implementation will produce invalid results if the underlying
        MemBuffer instance is mutated to point to different memory.
        
        :param jpype.JInt or int initialPosition: location in membuffer where the stream should start
        :param jpype.JInt or int length: number of bytes to limit the stream to
        :return: an InputSTream that returns the bytes of this mem buffer
        :rtype: java.io.InputStream
        """

    def getInt(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        returns the int at the given offset, taking into account the endianness.
        
        :param jpype.JInt or int offset: the offset from the membuffers origin (the address that it is set at)
        :return: the int at the given offset, taking into account the endianness.
        :rtype: int
        :raises MemoryAccessException: if a 4-byte integer value cannot be read at the specified offset
        """

    def getLong(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        returns the long at the given offset, taking into account the endianness.
        
        :param jpype.JInt or int offset: the offset from the membuffers origin (the address that it is set at)
        :return: the long at the given offset, taking into account the endianness.
        :rtype: int
        :raises MemoryAccessException: if a 8-byte long value cannot be read at the specified offset
        """

    def getMemory(self) -> Memory:
        """
        Get the Memory object actually used by the MemBuffer.
        
        :return: the Memory used by this MemBuffer or null if not available.
        :rtype: Memory
        """

    def getShort(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        returns the short at the given offset, taking into account the endianness.
        
        :param jpype.JInt or int offset: the offset from the membuffers origin (the address that it is set at)
        :return: the short at the given offset, taking into account the endianness.
        :rtype: int
        :raises MemoryAccessException: if a 2-byte short value cannot be read at the specified offset
        """

    def getUnsignedByte(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get one unsigned byte from memory at the current position plus offset.
        
        :param jpype.JInt or int offset: the displacement from the current position.
        :return: the byte data at offset from the current position, as a ``int`` value.
        :rtype: int
        :raises MemoryAccessException: if memory cannot be read at the specified offset
        """

    def getUnsignedInt(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unsigned int at the given offset, taking into account the endianness.
        
        :param jpype.JInt or int offset: the offset from the membuffers origin (the address that it is set at)
        :return: the unsigned int at the given offset, as a ``long``, taking into account the endianness.
        :rtype: int
        :raises MemoryAccessException: if a 4-byte integer value cannot be read at the specified offset
        """

    def getUnsignedShort(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unsigned short at the given offset, taking into account the endian-ness.
        
        :param jpype.JInt or int offset: the offset from the membuffers origin (the address that it is set at)
        :return: the unsigned short at the given offset, as a ``int``, taking into account the endianness.
        :rtype: int
        :raises MemoryAccessException: if a 2-byte short value cannot be read at the specified offset
        """

    def getVarLengthInt(self, offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the signed value of the integer (of the specified length) at the specified offset.
        
        :param jpype.JInt or int offset: the offset from the membuffers origin (the address that it is set at)
        :param jpype.JInt or int len: the number of bytes that the integer occupies (ie. 2 bytes == short int, 4
        bytes == 32bit int, etc), valid lens are 1, 2 and 4.
        :return: int integer value
        :rtype: int
        :raises MemoryAccessException:
        """

    def getVarLengthUnsignedInt(self, offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unsigned value of the integer (of the specified length) at the specified offset.
        
        :param jpype.JInt or int offset: the offset from the membuffers origin (the address that it is set at)
        :param jpype.JInt or int len: the number of bytes that the integer occupies (ie. 2 bytes == short int, 4
        bytes == 32bit int, etc), valid lens are 1, 2 and 4.
        :return: long integer value
        :rtype: int
        :raises MemoryAccessException:
        """

    def isBigEndian(self) -> bool:
        """
        Returns true if the underlying bytes are in big-endian order, false if they are little endian.
        
        :return: true if the underlying bytes are in big-endian order, false if they are little endian.
        :rtype: bool
        """

    def isInitializedMemory(self) -> bool:
        """
        Returns true if this buffer's starting address has valid data.
        
        :return: boolean true if first byte of memory buffer can be read
        :rtype: bool
        """

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def memory(self) -> Memory:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def unsignedInt(self) -> jpype.JLong:
        ...

    @property
    def unsignedByte(self) -> jpype.JInt:
        ...

    @property
    def short(self) -> jpype.JShort:
        ...

    @property
    def inputStream(self) -> java.io.InputStream:
        ...

    @property
    def initializedMemory(self) -> jpype.JBoolean:
        ...

    @property
    def unsignedShort(self) -> jpype.JInt:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...


class Memory(ghidra.program.model.address.AddressSetView):
    """
    :obj:`Memory` provides the ability to inspect and manage the memory model for a :obj:`Program`.
    In addition to conventional :obj:`MemoryBlock`s defined within physical memory 
    :obj:`AddressSpace`s other special purpose memory block types may be defined (e.g.,
    byte-mapped, bit-mapped, overlays, etc.).  
     
    
    All memory block manipulations require excusive access (see :meth:`Program.hasExclusiveAccess() <Program.hasExclusiveAccess>`)
    and all memory changes should generally be completed prior to analysis.  In particular, adding 
    additional overlay blocks to an existing overlay space that has already been analyzed should be 
    avoided.  Code references discovered during analysis from an overlay block will give preference 
    to remaining within the corresponding overlay address space provided a block exists at the 
    referenced offset.
     
    
    Block Types
     
    * Initialized - a memory block which defines a memory region with specific data.  
    Data may be initialized from defined:obj:`FileBytes`, an :obj:`InputStream`, or set to all 
    zeros.
    * Uninitialized - a memory block which defines a memory region whose data is unknown.
    * Byte-Mapped - a memory block whose bytes are mapped to another memory region using 
    either a 1:1 byte-mapping or other specified mapping scheme  (see:obj:`ByteMappingScheme`).
    Byte read/write operations are passed-through the mapped region.
    
    * Bit-Mapped - a memory block whose bytes are mapped to a corresponding bit in another
    memory region where a mapped byte has a value of 0 or 1 only.  Byte read/write operations are
    passed-through to the corresponding bit within the mapped region.
    
     
    
    Overlay Blocks
    An overlay memory block provides the ability to define alternate content for a physical memory
    region.  Any of the Block Types above may be created as an overlay block. The use of an overlay 
    block and its corresponding overlay address space can be used to reflect a different execution 
    context.  Use of overlays during analysis has limitations that must be considered.
    
     
    
    Loaded vs. Non-Loaded
    A special purpose :obj:`AddressSpace.OTHER_SPACE` has been established for storing adhoc
    non-loaded data as a memory block.  This is frequently used for storing portions of a file
    that never actually get loaded into memory.  All blocks created using the
    :obj:`AddressSpace.OTHER_SPACE` must be created as an overlay memory block.  All other
    blocks based upon a memory address space, including overlays, are treated as Loaded and
    use offsets into a physical memory space.
    
     
    
    Sub-Blocks
    When a memory block is first created it corresponds to a single sub-block.  When
    a block join operation is performed the resulting block will consist of multiple sub-blocks.
    However, the join operation is restricted to default block types only and does not support
    byte/bit-mapped types.
    """

    class_: typing.ClassVar[java.lang.Class]
    GBYTE_SHIFT_FACTOR: typing.Final = 30
    GBYTE: typing.Final = 1073741824
    MAX_BINARY_SIZE_GB: typing.Final = 16
    """
    Maximum size of all memory blocks, 16-GByte (see :meth:`getAllInitializedAddressSet() <.getAllInitializedAddressSet>`).
    This restriction is somewhat arbitrary but is established to prevent an excessive
    number of memory map segments which can have a negative impact on performance.
    """

    MAX_BINARY_SIZE: typing.Final = 17179869184
    MAX_BLOCK_SIZE_GB: typing.Final = 16
    """
    The current max size of a memory block.
    """

    MAX_BLOCK_SIZE: typing.Final = 17179869184

    def convertToInitialized(self, uninitializedBlock: MemoryBlock, initialValue: typing.Union[jpype.JByte, int]) -> MemoryBlock:
        """
        Convert an existing uninitialized block with an
        initialized block.
        
        :param MemoryBlock uninitializedBlock: uninitialized block to convert
        :param jpype.JByte or int initialValue: initial value for the bytes
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryBlockException: if there is no block in memory
        at the same address as block or if the block lengths are not
        the same.
        """

    def convertToUninitialized(self, itializedBlock: MemoryBlock) -> MemoryBlock:
        ...

    def createBitMappedBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, mappedAddress: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], overlay: typing.Union[jpype.JBoolean, bool]) -> MemoryBlock:
        """
        Create a bit-mapped overlay memory block and add it to this Memory.  Each byte address
        within the resulting memory block will correspond to a single bit location within the mapped
        region specified by ``mappedAddress``.
         
        
        Overlay Blocks: An overlay memory block may be created in two ways:
         
        * Specifying a ``start`` address within an existing overlay address space 
        (``overlay`` parameter is ignored), or
        * Specifying a ``start`` address within a physical memory address space and passing
        ``overlay=true``.  This use case will force the creation of a new unique overlay 
        address space.
        
        
        :param java.lang.String or str name: block name (See :meth:`Memory.isValidMemoryBlockName(String) <Memory.isValidMemoryBlockName>` for
        naming rules)
        :param ghidra.program.model.address.Address start: start of the block
        :param ghidra.program.model.address.Address mappedAddress: start address in the source block for the
        beginning of this block
        :param jpype.JLong or int length: block length
        :param jpype.JBoolean or bool overlay: if true, the block will be created as an OVERLAY block.  If the ``start``
        address is a non-overlay memory address a new overlay address space will be created and the 
        block will have a starting address at the same offset within the new overlay space.  If the
        specified ``start`` address is an overlay address an overlay block will be created at
        that overlay address.
        :return: new Bit Memory Block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if the new block overlaps with a
        previous block
        :raises MemoryConflictException: if the new block overlaps with a
        previous block
        :raises AddressOverflowException: if block specification exceeds bounds of address space
        :raises java.lang.IllegalArgumentException: if invalid block name specified
        """

    def createBlock(self, block: MemoryBlock, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> MemoryBlock:
        """
        Creates a MemoryBlock at the given address with the same properties
        as block, and adds it to this Memory.  Initialized Default blocks will
        have block filled with 0's.  Method will only create physical space blocks
        and will not create an overlay block.
        
        :param MemoryBlock block: source block
        :param java.lang.String or str name: block name (See :meth:`Memory.isValidMemoryBlockName(String) <Memory.isValidMemoryBlockName>` for
        naming rules).
        :param ghidra.program.model.address.Address start: start of the block
        :param jpype.JLong or int length: the size of the new block.
        :return: new block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if block specification conflicts with an existing block
        :raises AddressOverflowException: if block specification exceeds bounds of address space
        :raises java.lang.IllegalArgumentException: if invalid block name specifiede
        """

    @typing.overload
    def createByteMappedBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, mappedAddress: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], byteMappingScheme: ghidra.program.database.mem.ByteMappingScheme, overlay: typing.Union[jpype.JBoolean, bool]) -> MemoryBlock:
        """
        Create a byte-mapped memory block and add it to this memory.  Each byte address
        within the resulting memory block will correspond to a byte within the mapped
        region specified by ``mappedAddress``.  While a 1:1 byte-mapping is the default,
        a specific byte-mapping ratio may be specified.
         
        
        Overlay Blocks: An overlay memory block may be created in two ways:
         
        * Specifying a ``start`` address within an existing overlay address space 
        (``overlay`` parameter is ignored), or
        * Specifying a ``start`` address within a physical memory address space and passing
        ``overlay=true``.  This use case will force the creation of a new unique overlay 
        address space.
        
        
        :param java.lang.String or str name: block name (See :meth:`Memory.isValidMemoryBlockName(String) <Memory.isValidMemoryBlockName>` for
        naming rules)
        :param ghidra.program.model.address.Address start: start of the block
        :param ghidra.program.model.address.Address mappedAddress: start address in the source block for the
        beginning of this block
        :param jpype.JLong or int length: block length
        :param ghidra.program.database.mem.ByteMappingScheme byteMappingScheme: byte mapping scheme (may be null for 1:1 mapping)
        :param jpype.JBoolean or bool overlay: if true, the block will be created as an OVERLAY block.  If the ``start``
        address is a non-overlay memory address a new overlay address space will be created and the 
        block will have a starting address at the same offset within the new overlay space.  If the
        specified ``start`` address is an overlay address an overlay block will be created at
        that overlay address.
        :return: new Bit Memory Block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if the new block overlaps with a previous block
        :raises AddressOverflowException: if block specification exceeds bounds of address space
        :raises java.lang.IllegalArgumentException: if invalid block name
        """

    @typing.overload
    def createByteMappedBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, mappedAddress: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], overlay: typing.Union[jpype.JBoolean, bool]) -> MemoryBlock:
        """
        Create a byte-mapped memory block and add it to this memory.  Each byte address
        within the resulting memory block will correspond to a byte within the mapped
        region specified by ``mappedAddress`` using a 1:1 byte-mapping.
         
        
        Overlay Blocks: An overlay memory block may be created in two ways:
         
        * Specifying a ``start`` address within an existing overlay address space 
        (``overlay`` parameter is ignored), or
        * Specifying a ``start`` address within a physical memory address space and passing
        ``overlay=true``.  This use case will force the creation of a new unique overlay 
        address space.
        
        
        :param java.lang.String or str name: block name (See :meth:`Memory.isValidMemoryBlockName(String) <Memory.isValidMemoryBlockName>` for
        naming rules)
        :param ghidra.program.model.address.Address start: start of the block
        :param ghidra.program.model.address.Address mappedAddress: start address in the source block for the
        beginning of this block
        :param jpype.JLong or int length: block length
        :param jpype.JBoolean or bool overlay: if true, the block will be created as an OVERLAY block.  If the ``start``
        address is a non-overlay memory address a new overlay address space will be created and the 
        block will have a starting address at the same offset within the new overlay space.  If the
        specified ``start`` address is an overlay address an overlay block will be created at
        that overlay address.
        :return: new Bit Memory Block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if the new block overlaps with a previous block
        :raises AddressOverflowException: if block specification exceeds bounds of address space
        :raises java.lang.IllegalArgumentException: if invalid block name
        """

    def createFileBytes(self, filename: typing.Union[java.lang.String, str], offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JLong, int], is_: java.io.InputStream, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.database.mem.FileBytes:
        """
        Stores a sequence of bytes into the program.  Typically, this method is used by importers
        to store the original raw program bytes.
        
        :param java.lang.String or str filename: the name of the file from where the bytes originated
        :param jpype.JLong or int offset: the offset into the file for the first byte in the input stream.
        :param jpype.JLong or int size: the number of bytes to store from the input stream.
        :param java.io.InputStream is: the input stream that will supply the bytes to store in the program.
        Caller is responsible for closing input stream upon return.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: a FileBytes that was created to access the bytes.
        :rtype: ghidra.program.database.mem.FileBytes
        :raises IOException: if there was an IOException saving the bytes to the program database.
        :raises CancelledException: if the user cancelled this operation. Note: the database will
        be stable, but the buffers may contain 0s instead of the actual bytes.
        """

    @typing.overload
    def createInitializedBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, is_: java.io.InputStream, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor, overlay: typing.Union[jpype.JBoolean, bool]) -> MemoryBlock:
        """
        Create an initialized memory block based upon a data :obj:`InputStream` and add it to 
        this Memory.
         
        
        Overlay Blocks: An overlay memory block may be created in two ways:
         
        * Specifying a ``start`` address within an existing overlay address space 
        (``overlay`` parameter is ignored), or
        * Specifying a ``start`` address within a physical memory address space and passing
        ``overlay=true``.  This use case will force the creation of a new unique overlay 
        address space.
        
        
        :param java.lang.String or str name: block name (See :meth:`Memory.isValidMemoryBlockName(String) <Memory.isValidMemoryBlockName>` for
        naming rules)
        :param ghidra.program.model.address.Address start: start address of the block
        :param java.io.InputStream is: source of the data used to fill the block or null for zero initialization.
        :param jpype.JLong or int length: the size of the block
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :param jpype.JBoolean or bool overlay: if true, the block will be created as an OVERLAY block.  If the ``start``
        address is a non-overlay memory address a new overlay address space will be created and the 
        block will have a starting address at the same offset within the new overlay space.  If the
        specified ``start`` address is an overlay address an overlay block will be created at
        that overlay address.
        :return: new Initialized Memory Block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if the new block overlaps with a
        previous block
        :raises AddressOverflowException: if block specification exceeds bounds of address space
        :raises CancelledException: user cancelled operation
        :raises java.lang.IllegalArgumentException: if invalid block name specified
        """

    @typing.overload
    def createInitializedBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, size: typing.Union[jpype.JLong, int], initialValue: typing.Union[jpype.JByte, int], monitor: ghidra.util.task.TaskMonitor, overlay: typing.Union[jpype.JBoolean, bool]) -> MemoryBlock:
        """
        Create an initialized memory block initialized and add it to this Memory.  All bytes
        will be initialized to the specified value (NOTE: use of zero as the initial value
        is encouraged for reduced storage).
         
        
        Overlay Blocks: An overlay memory block may be created in two ways:
         
        * Specifying a ``start`` address within an existing overlay address space 
        (``overlay`` parameter is ignored), or
        * Specifying a ``start`` address within a physical memory address space and passing
        ``overlay=true``.  This use case will force the creation of a new unique overlay 
        address space.
        
        
        :param java.lang.String or str name: block name (See :meth:`Memory.isValidMemoryBlockName(String) <Memory.isValidMemoryBlockName>` for
        naming rules)
        :param ghidra.program.model.address.Address start: start of the block
        :param jpype.JLong or int size: block length (positive non-zero value required)
        :param jpype.JByte or int initialValue: initialization value for every byte in the block.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor, may be null.
        :param jpype.JBoolean or bool overlay: if true, the block will be created as an OVERLAY block.  If the ``start``
        address is a non-overlay memory address a new overlay address space will be created and the 
        block will have a starting address at the same offset within the new overlay space.  If the
        specified ``start`` address is an overlay address an overlay block will be created at
        that overlay address.
        :return: new Initialized Memory Block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if the new block overlaps with a
        previous block
        :raises AddressOverflowException: if block specification exceeds bounds of address space
        :raises java.lang.IllegalArgumentException: if invalid block name specified
        :raises CancelledException: user cancelled operation
        """

    @typing.overload
    def createInitializedBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, fileBytes: ghidra.program.database.mem.FileBytes, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JLong, int], overlay: typing.Union[jpype.JBoolean, bool]) -> MemoryBlock:
        """
        Create an initialized memory block using bytes from a :obj:`FileBytes` object.
         
        
        Overlay Blocks: An overlay memory block may be created in two ways:
         
        * Specifying a ``start`` address within an existing overlay address space 
        (``overlay`` parameter is ignored), or
        * Specifying a ``start`` address within a physical memory address space and passing
        ``overlay=true``.  This use case will force the creation of a new unique overlay 
        address space.
        
        
        :param java.lang.String or str name: block name (See :meth:`Memory.isValidMemoryBlockName(String) <Memory.isValidMemoryBlockName>` for
        naming rules)
        :param ghidra.program.model.address.Address start: starting address of the block
        :param ghidra.program.database.mem.FileBytes fileBytes: the :obj:`FileBytes` object to use as the underlying source of bytes.
        :param jpype.JLong or int offset: the offset into the FileBytes for the first byte of this memory block.
        :param jpype.JLong or int size: block length (positive non-zero value required)
        :param jpype.JBoolean or bool overlay: if true, the block will be created as an OVERLAY block.  If the ``start``
        address is a non-overlay memory address a new overlay address space will be created and the 
        block will have a starting address at the same offset within the new overlay space.  If the
        specified ``start`` address is an overlay address an overlay block will be created at
        that overlay address.
        :return: new Initialized Memory Block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if the new block overlaps with a
        previous block
        :raises AddressOverflowException: if block specification exceeds bounds of address space
        :raises IndexOutOfBoundsException: if file bytes range specified by offset and size 
        is out of bounds for the specified fileBytes.
        :raises java.lang.IllegalArgumentException: if invalid block name specified
        """

    def createUninitializedBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, size: typing.Union[jpype.JLong, int], overlay: typing.Union[jpype.JBoolean, bool]) -> MemoryBlock:
        """
        Create an uninitialized memory block and add it to this Memory.
         
        
        Overlay Blocks: An overlay memory block may be created in two ways:
         
        * Specifying a ``start`` address within an existing overlay address space 
        (``overlay`` parameter is ignored), or
        * Specifying a ``start`` address within a physical memory address space and passing
        ``overlay=true``.  This use case will force the creation of a new unique overlay 
        address space.
        
        
        :param java.lang.String or str name: block name (See :meth:`Memory.isValidMemoryBlockName(String) <Memory.isValidMemoryBlockName>` for
        naming rules)
        :param ghidra.program.model.address.Address start: start of the block
        :param jpype.JLong or int size: block length
        :param jpype.JBoolean or bool overlay: if true, the block will be created as an OVERLAY block.  If the ``start``
        address is a non-overlay memory address a new overlay address space will be created and the 
        block will have a starting address at the same offset within the new overlay space.  If the
        specified ``start`` address is an overlay address an overlay block will be created at
        that overlay address.
        :return: new Uninitialized Memory Block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if the new block overlaps with a
        previous block
        :raises AddressOverflowException: if block specification exceeds bounds of address space
        :raises java.lang.IllegalArgumentException: if invalid block name specified
        """

    def deleteFileBytes(self, fileBytes: ghidra.program.database.mem.FileBytes) -> bool:
        """
        Deletes a stored sequence of file bytes.  The file bytes can only be deleted if there
        are no memory block references to the file bytes.
        
        :param ghidra.program.database.mem.FileBytes fileBytes: the FileBytes for the file bytes to be deleted.
        :return: true if the FileBytes was deleted.  If any memory blocks are referenced by this 
        FileBytes or it is invalid then it will not be deleted and false will be returned.
        :rtype: bool
        :raises IOException: if there was an error updating the database.
        """

    @typing.overload
    def findBytes(self, addr: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], masks: jpype.JArray[jpype.JByte], forward: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        Finds a sequence of contiguous bytes that match the
        given byte array at all bit positions where the mask contains an "on" bit.
        Search is performed over loaded memory only.
        
        :param ghidra.program.model.address.Address addr: The beginning address in memory to search.
        :param jpype.JArray[jpype.JByte] bytes: the array of bytes to search for.
        :param jpype.JArray[jpype.JByte] masks: the array of masks. (One for each byte in the byte array)
                    if all bits of each byte is to be checked (ie: all mask bytes are 0xff),
                    then pass a null for masks.
        :param jpype.JBoolean or bool forward: if true, search in the forward direction.
        :return: The address of where the first match is found. Null is returned
        if there is no match.
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def findBytes(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], masks: jpype.JArray[jpype.JByte], forward: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        Finds a sequence of contiguous bytes that match the
        given byte array at all bit positions where the mask contains an "on" bit.
        Starts at startAddr and ends at endAddr.
        If forward is true, search starts at startAddr and will end if startAddr ">" endAddr.
        If forward is false, search starts at start addr and will end if startAddr "<" endAddr.
        
        :param ghidra.program.model.address.Address startAddr: The beginning address in memory to search.
        :param ghidra.program.model.address.Address endAddr: The ending address in memory to search (inclusive).
        :param jpype.JArray[jpype.JByte] bytes: the array of bytes to search for.
        :param jpype.JArray[jpype.JByte] masks: the array of masks. (One for each byte in the byte array)
                    if all bits of each byte is to be checked (ie: all mask bytes are 0xff),
                    then pass a null for masks.
        :param jpype.JBoolean or bool forward: if true, search in the forward direction.
        :return: The address of where the first match is found. Null is returned
        if there is no match.
        :rtype: ghidra.program.model.address.Address
        """

    def getAddressSourceInfo(self, address: ghidra.program.model.address.Address) -> ghidra.program.database.mem.AddressSourceInfo:
        """
        Returns information (:obj:`AddressSourceInfo`) about the byte source at the given address.
        
        :param ghidra.program.model.address.Address address: the address to query. Returns null if the address is not in memory.
        :return: information (:obj:`AddressSourceInfo`) about the byte source at the given address or
        null if the address is not in memory.
        :rtype: ghidra.program.database.mem.AddressSourceInfo
        """

    def getAllFileBytes(self) -> java.util.List[ghidra.program.database.mem.FileBytes]:
        """
        Returns a list of all the stored original file bytes objects
        
        :return: a list of all the stored original file bytes objects
        :rtype: java.util.List[ghidra.program.database.mem.FileBytes]
        """

    def getAllInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the set of addresses which correspond to all memory blocks that have
        initialized data.  This includes initialized memory blocks that contain data from
        the program's file header that are not actually in the running in memory image,
        such as debug sections.  Use :obj:`.getLoadedAndInitializedAddressSet` if you only want
        the addressed of the loaded in memory blocks.
        """

    @typing.overload
    def getBlock(self, addr: ghidra.program.model.address.Address) -> MemoryBlock:
        """
        Returns the Block which contains addr.
        
        :param ghidra.program.model.address.Address addr: a valid data Address.
        :return: the block containing addr; null if addr is not a valid location.
        :rtype: MemoryBlock
        """

    @typing.overload
    def getBlock(self, blockName: typing.Union[java.lang.String, str]) -> MemoryBlock:
        """
        Returns the Block with the specified blockName
        
        :param java.lang.String or str blockName: the name of the requested block
        :return: the Block with the specified blockName
        :rtype: MemoryBlock
        """

    def getBlocks(self) -> jpype.JArray[MemoryBlock]:
        """
        Returns an array containing all the memory blocks.
        """

    def getByte(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Get byte at addr.
        
        :param ghidra.program.model.address.Address addr: the Address of the byte.
        :return: the byte.
        :rtype: int
        :raises MemoryAccessException: if the address is
        not contained in any memory block.
        """

    @typing.overload
    def getBytes(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JByte]) -> int:
        """
        Get dest.length number of bytes starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JByte] dest: the byte array to populate.
        :return: the number of bytes put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        :rtype: int
        :raises MemoryAccessException: if the starting address is
        not contained in any memory block.
        """

    @typing.overload
    def getBytes(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JByte], destIndex: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Get size number of bytes starting at the given address and populates
        dest starting at dIndex.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JByte] dest: the byte array to populate.
        :param jpype.JInt or int destIndex: the offset into dest to place the bytes.
        :param jpype.JInt or int size: the number of bytes to get.
        :return: the number of bytes put into dest.  May be less than
        size if the requested number extends beyond initialized / available memory.
        :rtype: int
        :raises IndexOutOfBoundsException: if an invalid index is specified
        :raises MemoryAccessException: if the starting address is
        not contained in any memory block or is an uninitialized location.
        """

    def getExecuteSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the set of addresses which correspond to the executable memory.
        """

    @deprecated("")
    def getInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Use :obj:`.getLoadedAndInitializedAddressSet` instead.
        
        
        .. deprecated::
        """

    @typing.overload
    def getInt(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Get the int at addr.
        
        :param ghidra.program.model.address.Address addr: the Address where the int starts.
        :return: the int.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getInt(self, addr: ghidra.program.model.address.Address, bigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get the int at addr using the specified endian order.
        
        :param ghidra.program.model.address.Address addr: the Address where the int starts.
        :param jpype.JBoolean or bool bigEndian: true means to get the int in
        big endian order
        :return: the int.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getInts(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JInt]) -> int:
        """
        Get dest.length number of ints starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JInt] dest: the int array to populate.
        :return: the number of ints put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is not 0 mod 4, the final byte(s) will be discarded.
        :rtype: int
        :raises MemoryAccessException: if the starting address is
        not contained in any memory block.
        """

    @typing.overload
    def getInts(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JInt], dIndex: typing.Union[jpype.JInt, int], nElem: typing.Union[jpype.JInt, int]) -> int:
        """
        Get dest.length number of ints starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JInt] dest: the int array to populate.
        :param jpype.JInt or int dIndex: the offset into dest to place the ints.
        :param jpype.JInt or int nElem: the number of ints to get.
        :return: the number of ints put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is not 0 mod 4, the final byte(s) will be discarded.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getInts(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JInt], dIndex: typing.Union[jpype.JInt, int], nElem: typing.Union[jpype.JInt, int], isBigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get dest.length number of ints starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JInt] dest: the int array to populate.
        :param jpype.JInt or int dIndex: the offset into dest to place the ints.
        :param jpype.JInt or int nElem: the number of ints to get.
        :param jpype.JBoolean or bool isBigEndian: true means to get the ints in
        bigEndian order
        :return: the number of ints put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is not 0 mod 4, the final byte(s) will be discarded.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    def getLoadedAndInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the set of addresses which correspond to all the "loaded" memory blocks that have
        initialized data.  This does not include initialized memory blocks that contain data from
        the program's file header such as debug sections.
        """

    @typing.overload
    def getLong(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Get the long at addr.
        
        :param ghidra.program.model.address.Address addr: the Address where the long starts.
        :return: the long.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getLong(self, addr: ghidra.program.model.address.Address, bigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get the long at addr in the specified endian order.
        
        :param ghidra.program.model.address.Address addr: the Address where the long starts.
        :param jpype.JBoolean or bool bigEndian: true means to get the long in
        big endian order
        :return: the long.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getLongs(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JLong]) -> int:
        """
        Get dest.length number of longs starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JLong] dest: the long array to populate.
        :return: the number of longs put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is not 0 mod 8, the final byte(s) will be discarded.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getLongs(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JLong], dIndex: typing.Union[jpype.JInt, int], nElem: typing.Union[jpype.JInt, int]) -> int:
        """
        Get dest.length number of longs starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JLong] dest: the long array to populate.
        :param jpype.JInt or int dIndex: the offset into dest to place the longs.
        :param jpype.JInt or int nElem: the number of longs to get.
        :return: the number of longs put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is not 0 mod 8, the final byte(s) will be discarded.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getLongs(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JLong], dIndex: typing.Union[jpype.JInt, int], nElem: typing.Union[jpype.JInt, int], isBigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get dest.length number of longs starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JLong] dest: the long array to populate.
        :param jpype.JInt or int dIndex: the offset into dest to place the longs.
        :param jpype.JInt or int nElem: the number of longs to get.
        :param jpype.JBoolean or bool isBigEndian: true means to get the longs in
        bigEndian order
        :return: the number of longs put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is not 0 mod 8, the final byte(s) will be discarded.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program that this memory belongs to.
        """

    @typing.overload
    def getShort(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Get the short at addr.
        
        :param ghidra.program.model.address.Address addr: the Address where the short starts.
        :return: the short.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getShort(self, addr: ghidra.program.model.address.Address, bigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get the short at addr using the specified endian order.
        
        :param ghidra.program.model.address.Address addr: the Address where the short starts.
        :param jpype.JBoolean or bool bigEndian: true means to get the short in
        bigEndian order
        :return: the short.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getShorts(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JShort]) -> int:
        """
        Get dest.length number of shorts starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JShort] dest: the short array to populate.
        :return: the number of shorts put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is odd, the final byte will be discarded.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getShorts(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JShort], dIndex: typing.Union[jpype.JInt, int], nElem: typing.Union[jpype.JInt, int]) -> int:
        """
        Get dest.length number of shorts starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JShort] dest: the short array to populate.
        :param jpype.JInt or int dIndex: the offset into dest to place the shorts.
        :param jpype.JInt or int nElem: the number of shorts to get.
        :return: the number of shorts put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is odd, the final byte will be discarded.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    @typing.overload
    def getShorts(self, addr: ghidra.program.model.address.Address, dest: jpype.JArray[jpype.JShort], dIndex: typing.Union[jpype.JInt, int], nElem: typing.Union[jpype.JInt, int], isBigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get dest.length number of shorts starting at the given address.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JShort] dest: the short array to populate.
        :param jpype.JInt or int dIndex: the offset into dest to place the shorts.
        :param jpype.JInt or int nElem: the number of shorts to get.
        :param jpype.JBoolean or bool isBigEndian: true means to get the shorts in
        bigEndian order
        :return: the number of shorts put into dest.  May be less than
        dest.length if the requested number extends beyond available memory.
        If the number of retrievable bytes is odd, the final byte will be discarded.
        :rtype: int
        :raises MemoryAccessException: if not all needed bytes are contained in initialized memory.
        """

    def getSize(self) -> int:
        """
        Get the memory size in bytes.
        """

    def isBigEndian(self) -> bool:
        """
        Returns true if the memory is bigEndian, false otherwise.
        """

    def isExternalBlockAddress(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Determine if the specified address is contained within the reserved EXTERNAL block
        (see :obj:`MemoryBlock.EXTERNAL_BLOCK_NAME`).  This artificial memory block has certain
        limitations that may require associated addresses to be properly identified.  All
        data access/referencing has the biggest exposure since the importers generally
        allocate a fixed and possibly insufficient amount of memory to corresponding data
        symbols.  Any pointer math performed based upon an EXTERNAL block symbol address
        is likely to produce an unuseable address that may collide with unrelated symbols
        stored within the memory block (e.g., :obj:`OffsetReference` is one such example).
        
        :param ghidra.program.model.address.Address addr: address
        :return: true if address is contained within EXTERNAL memory block, else false.
        :rtype: bool
        """

    @staticmethod
    def isValidMemoryBlockName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Validate the given block name: cannot be null, cannot be an empty string, 
        cannot contain control characters (ASCII 0..0x19).
         
        
        NOTE: When producing an overlay memory space which corresponds to a block, the space
        name will be modified to be consistent with address space name restrictions
        and to ensure uniqueness.
        
        :param java.lang.String or str name: memory block name
        :return: true if name is valid else false
        :rtype: bool
        """

    def join(self, blockOne: MemoryBlock, blockTwo: MemoryBlock) -> MemoryBlock:
        """
        Join the two blocks to create a single memory block.
        IMPORTANT! When done, both blockOne and blockTwo should no longer be used.
        
        :param MemoryBlock blockOne: block to be combined with blockTwo
        :param MemoryBlock blockTwo: block to be combined with blockOne
        :return: new block
        :rtype: MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryBlockException: thrown if the blocks are
        not contiguous in the address space,
        """

    def locateAddressesForFileBytesOffset(self, fileBytes: ghidra.program.database.mem.FileBytes, offset: typing.Union[jpype.JLong, int]) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Gets a list of addresses where the byte at the given offset
        from the given FileBytes was loaded into memory.
        
        :param jpype.JLong or int offset: the file offset in the given FileBytes of the byte that is to be 
        located in memory
        :param ghidra.program.database.mem.FileBytes fileBytes: the FileBytesobject whose byte is to be located in memory
        :return: a list of addresses that are associated with the given
        FileBytes and offset
        :rtype: java.util.List[ghidra.program.model.address.Address]
        """

    def locateAddressesForFileOffset(self, fileOffset: typing.Union[jpype.JLong, int]) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Gets a :obj:`List` of :obj:`addresses <Address>` that correspond to the given file offset.
        
        :param jpype.JLong or int fileOffset: the file offset that will be used to locate the corresponding memory 
        addresses
        :return: a :obj:`List` of :obj:`Address`es that are associated with the provided file offset
        :rtype: java.util.List[ghidra.program.model.address.Address]
        """

    def moveBlock(self, block: MemoryBlock, newStartAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Move the memory block containing source address to the destination
        address.
        
        :param MemoryBlock block: block to be moved
        :param ghidra.program.model.address.Address newStartAddr: new start address for block
        :param ghidra.util.task.TaskMonitor monitor: task monitor so the move block can be canceled
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if move would cause
        blocks to overlap.
        :raises MemoryBlockException: if block movement is not permitted
        :raises AddressOverflowException: if block movement would violate bounds of address space
        :raises NotFoundException: if memoryBlock does not exist in
        this memory.
        """

    def removeBlock(self, block: MemoryBlock, monitor: ghidra.util.task.TaskMonitor):
        """
        Remove the memory block.
        
        :param MemoryBlock block: the block to be removed.
        :param ghidra.util.task.TaskMonitor monitor: monitor that is used to cancel the remove operation
        :raises LockException: if exclusive lock not in place (see haveLock())
        """

    def setByte(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JByte, int]):
        """
        Write byte at addr.
        
        :param ghidra.program.model.address.Address addr: the Address of the byte.
        :param jpype.JByte or int value: the data to write.
        :raises MemoryAccessException: if writing is not allowed.
        """

    @typing.overload
    def setBytes(self, addr: ghidra.program.model.address.Address, source: jpype.JArray[jpype.JByte]):
        """
        Write size bytes from values at addr.
        
        :param ghidra.program.model.address.Address addr: the starting Address.
        :param jpype.JArray[jpype.JByte] source: the bytes to write.
        :raises MemoryAccessException: if writing is not allowed.
        """

    @typing.overload
    def setBytes(self, addr: ghidra.program.model.address.Address, source: jpype.JArray[jpype.JByte], sIndex: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]):
        """
        Write an array of bytes.  This should copy size bytes or fail!
        
        :param ghidra.program.model.address.Address addr: the starting Address of the bytes.
        :param jpype.JArray[jpype.JByte] source: an array to get bytes from.
        :param jpype.JInt or int sIndex: the starting source index.
        :param jpype.JInt or int size: the number of bytes to fill.
        :raises MemoryAccessException: if writing is not allowed.
        """

    @typing.overload
    def setInt(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JInt, int]):
        """
        Write int at addr in the default endian order.
        
        :param ghidra.program.model.address.Address addr: the Address of the int.
        :param jpype.JInt or int value: the data to write.
        :raises MemoryAccessException: if writing is not allowed.
        """

    @typing.overload
    def setInt(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Write int at addr in the specified endian order.
        
        :param ghidra.program.model.address.Address addr: the Address of the int.
        :param jpype.JBoolean or bool bigEndian: true means to write the short in
        bigEndian order
        :param jpype.JInt or int value: the data to write.
        :raises MemoryAccessException: if writing is not allowed.
        """

    @typing.overload
    def setLong(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JLong, int]):
        """
        Write long at addr in the default endian order.
        
        :param ghidra.program.model.address.Address addr: the Address of the long.
        :param jpype.JLong or int value: the data to write.
        :raises MemoryAccessException: if writing is not allowed.
        """

    @typing.overload
    def setLong(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JLong, int], bigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Write long at addr in the specified endian order.
        
        :param ghidra.program.model.address.Address addr: the Address of the long.
        :param jpype.JLong or int value: the data to write.
        :param jpype.JBoolean or bool bigEndian: true means to write the long in
        bigEndian order
        :raises MemoryAccessException: if writing is not allowed.
        """

    @typing.overload
    def setShort(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JShort, int]):
        """
        Write short at addr in default endian order.
        
        :param ghidra.program.model.address.Address addr: the Address of the short.
        :param jpype.JShort or int value: the data to write.
        :raises MemoryAccessException: if writing is not allowed.
        """

    @typing.overload
    def setShort(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JShort, int], bigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Write short at addr in the specified endian order.
        
        :param ghidra.program.model.address.Address addr: the Address of the short.
        :param jpype.JShort or int value: the data to write.
        :param jpype.JBoolean or bool bigEndian: true means to write short in
        big endian order
        :raises MemoryAccessException: if writing is not allowed.
        """

    def split(self, block: MemoryBlock, addr: ghidra.program.model.address.Address):
        """
        Split a block at the given addr and create a new block
        starting at addr.
        
        :param MemoryBlock block: block to be split into two
        :param ghidra.program.model.address.Address addr: address (within block) that will be the
        start of new block
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises NotFoundException: thrown if block does not exist
        in memory
        :raises MemoryBlockException: memory split not permitted
        :raises AddressOutOfBoundsException: thrown if address is not in the block
        """

    @property
    def allFileBytes(self) -> java.util.List[ghidra.program.database.mem.FileBytes]:
        ...

    @property
    def addressSourceInfo(self) -> ghidra.program.database.mem.AddressSourceInfo:
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def blocks(self) -> jpype.JArray[MemoryBlock]:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def executeSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def allInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def loadedAndInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def initializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def short(self) -> jpype.JShort:
        ...

    @property
    def externalBlockAddress(self) -> jpype.JBoolean:
        ...

    @property
    def block(self) -> MemoryBlock:
        ...


class MemoryBlock(java.io.Serializable, java.lang.Comparable[MemoryBlock]):
    """
    Interface that defines a block in memory.
    """

    class_: typing.ClassVar[java.lang.Class]
    EXTERNAL_BLOCK_NAME: typing.Final = "EXTERNAL"
    """
    A special purpose EXTERNAL block may be created by certain program loaders 
    (e.g., Elf) to act as a stand-in for unknown external symbol locations when 
    relocation support is required using a valid memory address.  While the
    EXTERNAL block is created out of neccessity for relocation processing it
    introduces a number of limitations when used to carry data symbols
    where pointer math and offset-references may occur.  
     
    
    The method :meth:`Memory.isExternalBlockAddress(Address) <Memory.isExternalBlockAddress>`
    may be used to determine if a specific address is contained within an EXTERNAL memory block.
     
    
    NOTE: Close proximity to the end of an address space should be avoided
    to allow for :obj:`OffsetReference` use.
    """

    ARTIFICIAL: typing.Final = 16
    VOLATILE: typing.Final = 8
    READ: typing.Final = 4
    WRITE: typing.Final = 2
    EXECUTE: typing.Final = 1

    def contains(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Return whether addr is contained in this block.
        
        :param ghidra.program.model.address.Address addr: address
        """

    def getAddressRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the address range that corresponds to this block.
        
        :return: block address range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getByte(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Returns the byte at the given address in this block.
        
        :param ghidra.program.model.address.Address addr: the address.
        :return: byte value from this block and specified address
        :rtype: int
        :raises MemoryAccessException: if any of the requested bytes are uninitialized.
        :raises IllegalArgumentException: if the Address is not in this block.
        """

    @typing.overload
    def getBytes(self, addr: ghidra.program.model.address.Address, b: jpype.JArray[jpype.JByte]) -> int:
        """
        Tries to get b.length bytes from this block at the given address. May return fewer bytes if
        the requested length is beyond the end of the block.
        
        :param ghidra.program.model.address.Address addr: the address from which to get the bytes.
        :param jpype.JArray[jpype.JByte] b: the byte array to populate.
        :return: the number of bytes actually populated.
        :rtype: int
        :raises MemoryAccessException: if any of the requested bytes are uninitialized.
        :raises IllegalArgumentException: if the Address is not in this block.
        """

    @typing.overload
    def getBytes(self, addr: ghidra.program.model.address.Address, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Tries to get len bytes from this block at the given address and put them into the given byte
        array at the specified offet. May return fewer bytes if the requested length is beyond the
        end of the block.
        
        :param ghidra.program.model.address.Address addr: the address from which to get the bytes.
        :param jpype.JArray[jpype.JByte] b: the byte array to populate.
        :param jpype.JInt or int off: the offset into the byte array.
        :param jpype.JInt or int len: the number of bytes to get.
        :return: the number of bytes actually populated.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if invalid offset is specified
        :raises MemoryAccessException: if any of the requested bytes are uninitialized.
        :raises IllegalArgumentException: if the Address is not in this block.
        """

    def getComment(self) -> str:
        """
        Get the comment associated with this block.
        
        :return: block comment string
        :rtype: str
        """

    def getData(self) -> java.io.InputStream:
        """
        Get memory data in the form of an InputStream. Null is returned for thos memory blocks which
        have no data.
        """

    def getEnd(self) -> ghidra.program.model.address.Address:
        """
        Return the end address of this block.
        
        :return: end address of the block
        :rtype: ghidra.program.model.address.Address
        """

    def getFlags(self) -> int:
        """
        Returns block flags (i.e., permissions and attributes) as a bit mask. 
        These bits defined as :obj:`.READ`, :obj:`.WRITE`, :obj:`.EXECUTE`, :obj:`.VOLATILE`,
        :obj:`.ARTIFICIAL`.
        
        :return: block flag bits
        :rtype: int
        """

    def getName(self) -> str:
        """
        Get the name of this block
        
        :return: block name
        :rtype: str
        """

    def getSize(self) -> int:
        """
        Get the number of bytes in this block.
        
        :return: number of bytes in the block
        :rtype: int
        """

    def getSizeAsBigInteger(self) -> java.math.BigInteger:
        """
        Get the number of bytes in this block.
        
        :return: the number of bytes in this block as a BigInteger
        :rtype: java.math.BigInteger
        """

    def getSourceInfos(self) -> java.util.List[MemoryBlockSourceInfo]:
        """
        Returns a list of :obj:`MemoryBlockSourceInfo` objects for this block. A block may consist
        of multiple sequences of bytes from different sources. Each such source of bytes is described
        by its respective SourceInfo object. Blocks may have multiple sources after two or more
        memory blocks have been joined together and the underlying byte sources can't be joined.
        
        :return: a list of SourceInfo objects, one for each different source of bytes in this block.
        :rtype: java.util.List[MemoryBlockSourceInfo]
        """

    def getSourceName(self) -> str:
        """
        Get the name of the source of this memory block.
        
        :return: source name
        :rtype: str
        """

    def getStart(self) -> ghidra.program.model.address.Address:
        """
        Return the starting address for this block.
        
        :return: block's start address
        :rtype: ghidra.program.model.address.Address
        """

    def getType(self) -> MemoryBlockType:
        """
        Get the type for this block: DEFAULT, BIT_MAPPED, or BYTE_MAPPED
        (see :obj:`MemoryBlockType`).
        
        :return: memory block type
        :rtype: MemoryBlockType
        """

    def isArtificial(self) -> bool:
        """
        Returns the artificial attribute state of this block. This attribute is
        generally associated with blocks which have been fabricated to facilitate 
        analysis but do not exist in the same form within a running/loaded process
        state.
        
        :return: true if enabled else false
        :rtype: bool
        """

    def isExecute(self) -> bool:
        """
        Returns the value of the execute property associated with this block
        
        :return: true if enabled else false
        :rtype: bool
        """

    def isExternalBlock(self) -> bool:
        """
        Returns true if this is a reserved EXTERNAL memory block based upon its name
        (see :obj:`MemoryBlock.EXTERNAL_BLOCK_NAME`).  Checks for individual addresses may be done
        using :meth:`Memory.isExternalBlockAddress(Address) <Memory.isExternalBlockAddress>`.
         
        
        Note that EXTERNAL blocks always resides within a memory space and never within the artifial
        :obj:`AddressSpace.EXTERNAL_SPACE` which is not a memory space.  This can be a source of confusion.
        An EXTERNAL memory block exists to facilitate relocation processing for some external
        symbols which require a real memory address.
        
        :return: true if this is a reserved EXTERNAL memory block
        :rtype: bool
        """

    def isInitialized(self) -> bool:
        """
        Return whether this block has been initialized.
         
        
        WARNING: A mapped memory block may have a mix of intialized, uninitialized, and undefined 
        regions.  The value returned by this method for a mapped memory block is always false 
        even if some regions are initialized.
        
        :return: true if block is fully initialized and not a memory-mapped-block, else false
        :rtype: bool
        """

    def isLoaded(self) -> bool:
        """
        Returns true if this memory block is a real loaded block (i.e. RAM) and not a special block
        containing file header data such as debug sections.
        
        :return: true if this is a loaded block and not a "special" block such as a file header.
        :rtype: bool
        """

    def isMapped(self) -> bool:
        """
        Returns true if this is either a bit-mapped or byte-mapped block
        
        :return: true if this is either a bit-mapped or byte-mapped block
        :rtype: bool
        """

    def isOverlay(self) -> bool:
        """
        Returns true if this is an overlay block (i.e., contained within overlay space).
        
        :return: true if this is an overlay block
        :rtype: bool
        """

    def isRead(self) -> bool:
        """
        Returns the value of the read property associated with this block
        
        :return: true if enabled else false
        :rtype: bool
        """

    def isVolatile(self) -> bool:
        """
        Returns the volatile attribute state of this block. This attribute is
        generally associated with block of I/O regions of memory.
        
        :return: true if enabled else false
        :rtype: bool
        """

    def isWrite(self) -> bool:
        """
        Returns the value of the write property associated with this block
        
        :return: true if enabled else false
        :rtype: bool
        """

    def putByte(self, addr: ghidra.program.model.address.Address, b: typing.Union[jpype.JByte, int]):
        """
        Puts the given byte at the given address in this block.
        
        :param ghidra.program.model.address.Address addr: the address.
        :param jpype.JByte or int b: byte value
        :raises MemoryAccessException: if the block is uninitialized
        :raises IllegalArgumentException: if the Address is not in this block.
        """

    @typing.overload
    def putBytes(self, addr: ghidra.program.model.address.Address, b: jpype.JArray[jpype.JByte]) -> int:
        """
        Tries to put b.length bytes from the specified byte array to this block. All the bytes may
        not be put if the requested length is beyond the end of the block.
        
        :param ghidra.program.model.address.Address addr: the address of where to put the bytes.
        :param jpype.JArray[jpype.JByte] b: the byte array containing the bytes to write.
        :return: the number of bytes actually written.
        :rtype: int
        :raises MemoryAccessException: if the block is uninitialized
        :raises IllegalArgumentException: if the Address is not in this block.
        """

    @typing.overload
    def putBytes(self, addr: ghidra.program.model.address.Address, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Tries to put len bytes from the specified byte array to this block. All the bytes may not be
        written if the requested length is beyond the end of the block.
        
        :param ghidra.program.model.address.Address addr: the address of where to put the bytes.
        :param jpype.JArray[jpype.JByte] b: the byte array containing the bytes to write.
        :param jpype.JInt or int off: the offset into the byte array.
        :param jpype.JInt or int len: the number of bytes to write.
        :return: the number of bytes actually written.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if invalid offset is specified
        :raises MemoryAccessException: if the block is uninitialized
        :raises IllegalArgumentException: if the Address is not in this block.
        """

    def setArtificial(self, a: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the artificial attribute state associated with this block. This attribute is
        generally associated with blocks which have been fabricated to facilitate 
        analysis but do not exist in the same form within a running/loaded process
        state.
        
        :param jpype.JBoolean or bool a: the artificial attribute state.
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment associated with this block.
        
        :param java.lang.String or str comment: the comment to associate with this block.
        """

    def setExecute(self, e: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the execute property associated with this block.
        
        :param jpype.JBoolean or bool e: the value to set the execute property to.
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Set the name for this block (See :meth:`NamingUtilities.isValidName(String) <NamingUtilities.isValidName>` for naming
        rules). Specified name must not conflict with an address space name.
        
        :param java.lang.String or str name: the new name for this block.
        :raises java.lang.IllegalArgumentException: if invalid name specified
        :raises LockException: renaming an Overlay block without exclusive access
        """

    def setPermissions(self, read: typing.Union[jpype.JBoolean, bool], write: typing.Union[jpype.JBoolean, bool], execute: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the read, write, execute permissions on this block
        
        :param jpype.JBoolean or bool read: the read permission
        :param jpype.JBoolean or bool write: the write permission
        :param jpype.JBoolean or bool execute: the execute permission
        """

    def setRead(self, r: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the read property associated with this block.
        
        :param jpype.JBoolean or bool r: the value to set the read property to.
        """

    def setSourceName(self, sourceName: typing.Union[java.lang.String, str]):
        """
        Sets the name of the source file that provided the data.
        
        :param java.lang.String or str sourceName: the name of the source file.
        """

    def setVolatile(self, v: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the volatile attribute state associated of this block.  This attribute is
        generally associated with block of I/O regions of memory.
        
        :param jpype.JBoolean or bool v: the volatile attribute state.
        """

    def setWrite(self, w: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the write property associated with this block.
        
        :param jpype.JBoolean or bool w: the value to set the write property to.
        """

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @read.setter
    def read(self, value: jpype.JBoolean):
        ...

    @property
    def overlay(self) -> jpype.JBoolean:
        ...

    @property
    def data(self) -> java.io.InputStream:
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def start(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def addressRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def volatile(self) -> jpype.JBoolean:
        ...

    @volatile.setter
    def volatile(self, value: jpype.JBoolean):
        ...

    @property
    def externalBlock(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> MemoryBlockType:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @execute.setter
    def execute(self, value: jpype.JBoolean):
        ...

    @property
    def loaded(self) -> jpype.JBoolean:
        ...

    @property
    def sourceInfos(self) -> java.util.List[MemoryBlockSourceInfo]:
        ...

    @property
    def artificial(self) -> jpype.JBoolean:
        ...

    @artificial.setter
    def artificial(self, value: jpype.JBoolean):
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def mapped(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def initialized(self) -> jpype.JBoolean:
        ...

    @property
    def sizeAsBigInteger(self) -> java.math.BigInteger:
        ...

    @property
    def end(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def sourceName(self) -> java.lang.String:
        ...

    @sourceName.setter
    def sourceName(self, value: java.lang.String):
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @write.setter
    def write(self, value: jpype.JBoolean):
        ...


class MemoryBlockSourceInfo(java.lang.Object):
    """
    Describes the source of bytes for a memory block.
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if this SourceInfo object applies to the given address;
        
        :param ghidra.program.model.address.Address address: the address to test if this is its SourceInfo
        :return: true if this SourceInfo object applies to the given address;
        :rtype: bool
        """

    def containsFileOffset(self, fileOffset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Determine if this block source contains the specified file offset.
        
        :param jpype.JLong or int fileOffset: file offset within underlying FileBytes (if applicable) within the loaded 
        range associated with this source info.
        :return: true if file offset is within the loaded range of the corresponding FileBytes, else 
        false if method is not supported by the sub-block type (e.g., bit/byte-mapped sub-block).
        :rtype: bool
        """

    def getByteMappingScheme(self) -> java.util.Optional[ghidra.program.database.mem.ByteMappingScheme]:
        """
        Returns an :obj:`Optional` :obj:`ByteMappingScheme` employed if this is a byte-mapped 
        memory block.  Otherwise, the Optional is empty.
        
        :return: an :obj:`Optional` :obj:`ByteMappingScheme` employed if this is a byte-mapped memory block.
        :rtype: java.util.Optional[ghidra.program.database.mem.ByteMappingScheme]
        """

    def getDescription(self) -> str:
        """
        Returns a description of this SourceInfo object.
        
        :return: a description of this SourceInfo object.
        :rtype: str
        """

    def getFileBytes(self) -> java.util.Optional[ghidra.program.database.mem.FileBytes]:
        """
        Returns an :obj:`Optional` :obj:`FileBytes` object if a FileBytes object is the byte
        source for this SourceInfo.  Otherwise, the Optional will be empty.
        
        :return: the :obj:`FileBytes` object if it is the byte source for this section
        :rtype: java.util.Optional[ghidra.program.database.mem.FileBytes]
        """

    @typing.overload
    def getFileBytesOffset(self) -> int:
        """
        Returns the offset into the underlying :obj:`FileBytes` object where this sub-block 
        starts getting its bytes from or -1 if this sub-block does not have an associated :obj:`FileBytes`
        or a complex bit/byte-mapping is used.
        
        :return: the offset into the :obj:`FileBytes` object where this section starts getting its bytes.
        :rtype: int
        """

    @typing.overload
    def getFileBytesOffset(self, address: ghidra.program.model.address.Address) -> int:
        """
        Returns the offset into the :obj:`FileBytes` object for the given address or
        -1 if this sub-block if address is out of range or this sub-block does not have 
        an associated :obj:`FileBytes`, or a complex bit/byte-mapping is used.
        
        :param ghidra.program.model.address.Address address: the address for which to get an offset into the :obj:`FileBytes` object.
        :return: the offset into the :obj:`FileBytes` object for the given address.
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Returns the length of this block byte source.
        
        :return: the length of this block byte source.
        :rtype: int
        """

    def getMappedRange(self) -> java.util.Optional[ghidra.program.model.address.AddressRange]:
        """
        Returns an :obj:`Optional` :obj:`AddressRange` for the mapped addresses if this is a mapped
        memory block (bit mapped or byte mapped). Otherwise, the Optional is empty.
        
        :return: an :obj:`Optional` :obj:`AddressRange` for the mapped addresses if this is a mapped
        memory block
        :rtype: java.util.Optional[ghidra.program.model.address.AddressRange]
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the end address where this byte source is mapped.
        
        :return: the end address where this byte source is mapped.
        :rtype: ghidra.program.model.address.Address
        """

    def getMemoryBlock(self) -> MemoryBlock:
        """
        Returns the containing Memory Block
        
        :return: the containing Memory Block
        :rtype: MemoryBlock
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the start address where this byte source is mapped.
        
        :return: the start address where this byte source is mapped.
        :rtype: ghidra.program.model.address.Address
        """

    def locateAddressForFileOffset(self, fileOffset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the Address within this sub-block which corresponds to the specified file offset.
        
        :param jpype.JLong or int fileOffset: file offset
        :return: :obj:`Address` within this sub-block or null if file offset is out of range
        or method is not supported by the sub-block type (e.g., bit/byte-mapped sub-block).
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def byteMappingScheme(self) -> java.util.Optional[ghidra.program.database.mem.ByteMappingScheme]:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def memoryBlock(self) -> MemoryBlock:
        ...

    @property
    def mappedRange(self) -> java.util.Optional[ghidra.program.model.address.AddressRange]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def fileBytes(self) -> java.util.Optional[ghidra.program.database.mem.FileBytes]:
        ...

    @property
    def fileBytesOffset(self) -> jpype.JLong:
        ...


class MemoryBlockStub(MemoryBlock):
    """
    MemoryBlockStub can be extended for use by tests. It throws an UnsupportedOperationException for
    all methods in the MemoryBlock interface. Any method that is needed for your test can then be
    overridden so it can provide its own test implementation and return value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        ...


class StubMemory(ghidra.program.model.address.AddressSet, Memory):
    """
    MemoryStub can be extended for use by tests. It throws an UnsupportedOperationException
    for all methods in the Memory interface. Any method that is needed for your test can then
    be overridden so it can provide its own test implementation and return value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte]):
        ...


class InvalidAddressException(ghidra.util.exception.UsrException):
    """
    Exception for invalid address either due to improper format
    or address not defined within target
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new InvalidAddressException
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructs a new InvalidAddressException with a detailed message.
        
        :param java.lang.String or str msg: detailed message
        """


class MemoryConflictException(ghidra.util.exception.UsrException):
    """
    Exception for overlapping memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new MemoryConflictException
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructs a new MemoryConflictException with a detailed message.
        
        :param java.lang.String or str msg: detailed message
        """


class MemoryBlockException(MemoryAccessException):
    """
    Exception thrown for memory block-related problems.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new MemoryBlockException
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructs a new MemoryBlockException with a detailed message.
        
        :param java.lang.String or str msg: detailed message
        """


class MemoryBufferImpl(MutableMemBuffer):
    """
    MemBufferImpl implements the MemBuffer interface.  It buffers up N bytes
    at time, reducing the overall number of calls to Memory, greatly reducing
    the overhead of various error checks.  This implementation will not wrap
    if the end of the memory space is encountered.
     
    The :meth:`getByte(int) <.getByte>` method can cause the buffer cache to adjust if
    outside the current cache range.  This is not the case for other methods which 
    will simply defer to the underlying memory if outside the cache range.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, mem: Memory, addr: ghidra.program.model.address.Address):
        """
        Construct a new MemoryBufferImpl
        
        :param Memory mem: memory associated with the given address
        :param ghidra.program.model.address.Address addr: start address
        """

    @typing.overload
    def __init__(self, mem: Memory, addr: ghidra.program.model.address.Address, bufSize: typing.Union[jpype.JInt, int]):
        """
        Construct a new MemoryBufferImpl
        
        :param Memory mem: memory associated with the given address
        :param ghidra.program.model.address.Address addr: start address
        :param jpype.JInt or int bufSize: the size of the memory buffer.
        """



__all__ = ["MemBufferInputStream", "MemoryConstants", "ByteMemBufferImpl", "DumbMemBufferImpl", "MutableMemBuffer", "MemoryBlockListener", "MemBufferMixin", "MemoryAccessException", "WrappedMemBuffer", "MemoryBlockType", "MemBuffer", "Memory", "MemoryBlock", "MemoryBlockSourceInfo", "MemoryBlockStub", "StubMemory", "InvalidAddressException", "MemoryConflictException", "MemoryBlockException", "MemoryBufferImpl"]
