from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.base.memsearch.bytesource
import ghidra.program.model.address
import java.lang # type: ignore


class ByteSequence(java.lang.Object):
    """
    An interface for accessing bytes from a byte source.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getByte(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the byte at the given index. The index must between 0 and the extended length.
        
        :param jpype.JInt or int index: the index in the byte sequence to retrieve a byte value
        :return: the byte at the given index
        :rtype: int
        """

    def getBytes(self, start: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Returns a byte array containing the bytes from the given range.
        
        :param jpype.JInt or int start: the start index of the range to get bytes
        :param jpype.JInt or int length: the number of bytes to get
        :return: a byte array containing the bytes from the given range
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getLength(self) -> int:
        """
        Returns the length of available bytes.
        
        :return: the length of the sequence of bytes
        :rtype: int
        """

    def hasAvailableBytes(self, index: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> bool:
        """
        A convenience method for checking if this sequence can provide a range of bytes from some
        offset.
        
        :param jpype.JInt or int index: the index of the start of the range to check for available bytes
        :param jpype.JInt or int length: the length of the range to check for available bytes
        :return: true if bytes are available for the given range
        :rtype: bool
        """

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class AddressableByteSequence(ByteSequence):
    """
    This class provides a :obj:`ByteSequence` view into an :obj:`AddressableByteSource`. By 
    specifying an address and length, this class provides a view into the byte source
    as a indexable sequence of bytes. It is mutable and can be reused by setting a new
    address range for this sequence. This was to avoid constantly allocating large byte arrays.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, byteSource: ghidra.features.base.memsearch.bytesource.AddressableByteSource, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param ghidra.features.base.memsearch.bytesource.AddressableByteSource byteSource: the source of the underlying bytes that is a buffer into
        :param jpype.JInt or int capacity: the maximum size range that this object will buffer
        """

    def clear(self):
        """
        Sets this view to an empty byte sequence
        """

    def getAddress(self, index: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Returns the address of the byte represented by the given index into this buffer.
        
        :param jpype.JInt or int index: the index into the buffer to get its associated address
        :return: the Address for the given index
        :rtype: ghidra.program.model.address.Address
        """

    def setRange(self, range: ghidra.program.model.address.AddressRange):
        """
        Sets the range of bytes that this object will buffer. This immediately will read the bytes
        from the byte source into it's internal byte array buffer.
        
        :param ghidra.program.model.address.AddressRange range: the range of bytes to buffer
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class ExtendedByteSequence(ByteSequence):
    """
    A class for accessing a contiguous sequence of bytes from some underlying byte source to 
    be used for searching for a byte pattern within the byte source. This sequence of bytes 
    consists of two parts; the primary sequence and an extended sequence. Search matches
    must begin in the primary sequence, but may extend into the extended sequence.
     
    
    Searching large ranges of memory can be partitioned into searching smaller chunks. But
    to handle search sequences that span chunks, two chunks are presented at a time, with the second
    chunk being the extended bytes. On the next iteration of the search loop, the extended chunk
    will become the primary chunk, with the next chunk after that becoming the extended sequence
    and so on.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, main: ByteSequence, extended: ByteSequence, extendedLimit: typing.Union[jpype.JInt, int]):
        """
        Constructs an extended byte sequence from two :obj:`ByteSequence`s.
        
        :param ByteSequence main: the byte sequence where search matches may start
        :param ByteSequence extended: the byte sequence where search matches may extend into
        :param jpype.JInt or int extendedLimit: specifies how much of the extended byte sequence to allow search
        matches to extend into. (The extended buffer will be the primary buffer next time, so
        it is a full size buffer, but we only need to use a portion of it to support overlap.
        """

    def getExtendedLength(self) -> int:
        """
        Returns the overall length of sequence of available bytes. This will be the length of
        the primary sequence as returned by :meth:`getLength() <.getLength>` plus the length of the available
        extended bytes, if any.
        
        :return: the
        :rtype: int
        """

    @property
    def extendedLength(self) -> jpype.JInt:
        ...



__all__ = ["ByteSequence", "AddressableByteSequence", "ExtendedByteSequence"]
