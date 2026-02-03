from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.math # type: ignore


class MemoryPage(java.lang.Object):
    """
    ``MemoryPage`` is allows the contents/data of a memory page
    to be maintained along with an initializedMask.  Each bit within the
    initializedMask corresponds to a data byte within the page.  A null
    mask indicates that all data within the page is initialized.  A one-bit
    within the mask indicates that the corresponding data byte is initialized.
    """

    class_: typing.ClassVar[java.lang.Class]
    data: typing.Final[jpype.JArray[jpype.JByte]]

    @typing.overload
    def __init__(self, pageSize: typing.Union[jpype.JInt, int]):
        """
        Construct a new fully initialized page containing
        all zero (0) byte data.
        """

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte]):
        """
        Construct a memory page with an existing data bytes buffer
        
        :param jpype.JArray[jpype.JByte] bytes: buffer
        """

    @typing.overload
    def getInitializedByteCount(self, pageOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Get number of leading bytes within page range which have been 
        initialized.
        
        :param jpype.JInt or int pageOffset: 
        :param jpype.JInt or int size: 
        :return: number of leading bytes within page range which have been 
        initialized.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def getInitializedByteCount(initializedMask: jpype.JArray[jpype.JByte], pageOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Determine how many leading bytes of a specified page region is marked as
        initialized.  Valid page region defined by pageOffset and size is assumed.
        
        :param jpype.JArray[jpype.JByte] initializedMask: 
        :param jpype.JInt or int pageOffset: 
        :param jpype.JInt or int size: 
        :return: number of leading bytes at pageOffset (upto size) are initialized.
        :rtype: int
        """

    @typing.overload
    def getInitializedMask(self) -> jpype.JArray[jpype.JByte]:
        ...

    @staticmethod
    @typing.overload
    def getInitializedMask(pageSize: typing.Union[jpype.JInt, int], initialized: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JByte]:
        """
        Generate an initialized mask for the specified page size
        
        :param jpype.JInt or int pageSize: 
        :param jpype.JBoolean or bool initialized: 
        :return: 
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    @typing.overload
    def getInitializedMask(pageSize: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], initialized: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JByte]:
        """
        Generate an initialized mask for the specified page size.
        The region is identified by offset and size.  The remaining portions
        of the mask will be set based upon !initialized.
        
        :param jpype.JInt or int pageSize: 
        :param jpype.JInt or int offset: 
        :param jpype.JInt or int size: 
        :param jpype.JBoolean or bool initialized: 
        :return: 
        :rtype: jpype.JArray[jpype.JByte]
        """

    @typing.overload
    def setInitialized(self):
        """
        Mark entire page as uninitialized
        """

    @typing.overload
    def setInitialized(self, pageOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], maskUpdate: jpype.JArray[jpype.JByte]):
        """
        Update initialization mask
        
        :param jpype.JInt or int pageOffset: 
        :param jpype.JInt or int size: 
        :param jpype.JArray[jpype.JByte] maskUpdate:
        """

    @typing.overload
    def setInitialized(self, pageOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]):
        """
        Mark specified page region as initialized.
        
        :param jpype.JInt or int pageOffset: 
        :param jpype.JInt or int size:
        """

    @staticmethod
    @typing.overload
    def setInitialized(initializedMask: jpype.JArray[jpype.JByte], pageOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]):
        """
        Mark specified page region as initialized.
        
        :param jpype.JArray[jpype.JByte] initializedMask: 
        :param jpype.JInt or int pageOffset: 
        :param jpype.JInt or int size:
        """

    @typing.overload
    def setUninitialized(self):
        """
        Mark entire page as uninitialized
        """

    @typing.overload
    def setUninitialized(self, pageOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]):
        """
        Mark specified page region as uninitialized.
        
        :param jpype.JInt or int pageOffset: 
        :param jpype.JInt or int size:
        """

    @staticmethod
    @typing.overload
    def setUninitialized(initializedMask: jpype.JArray[jpype.JByte], pageOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]):
        """
        Mark specified page region as uninitialized.
        
        :param jpype.JArray[jpype.JByte] initializedMask: 
        :param jpype.JInt or int pageOffset: 
        :param jpype.JInt or int size:
        """

    @property
    def initializedMask(self) -> jpype.JArray[jpype.JByte]:
        ...


class MemoryBank(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ghidra.program.model.address.AddressSpace, isBigEndian: typing.Union[jpype.JBoolean, bool], ps: typing.Union[jpype.JInt, int], faultHandler: MemoryFaultHandler):
        """
        A MemoryBank must be associated with a specific address space, have a preferred or natural
        pagesize.  The pagesize must be a power of 2.
        
        :param ghidra.program.model.address.AddressSpace spc: is the associated address space
        :param jpype.JBoolean or bool isBigEndian: memory endianness
        :param jpype.JInt or int ps: ps is the number of bytes in a page (must be a power of 2)
        :param MemoryFaultHandler faultHandler: memory fault handler
        """

    @staticmethod
    def constructValue(ptr: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], bigendian: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        This is a static convenience routine for decoding a value from a sequence of bytes depending
        on the desired endianness
        
        :param jpype.JArray[jpype.JByte] ptr: is the pointer to the bytes to decode
        :param jpype.JInt or int offset: a fixed offset from ``ptr`` used during decode
        :param jpype.JInt or int size: is the number of bytes
        :param jpype.JBoolean or bool bigendian: is true if the bytes are encoded in big endian form
        :return: the decoded value
        :rtype: int
        """

    @staticmethod
    def deconstructValue(ptr: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], bigendian: typing.Union[jpype.JBoolean, bool]):
        """
        This is a static convenience routine for encoding bytes from a given value, depending on
        the desired endianness
        
        :param jpype.JArray[jpype.JByte] ptr: is a pointer to the location to write the encoded bytes
        :param jpype.JInt or int offset: a fixed offset from ``ptr`` to where to write the bytes
        :param jpype.JLong or int val: is the value to be encoded
        :param jpype.JInt or int size: is the number of bytes to encode
        :param jpype.JBoolean or bool bigendian: is true if a big endian encoding is desired
        """

    def getChunk(self, addrOffset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], res: jpype.JArray[jpype.JByte], stopOnUnintialized: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        This is the most general method for reading a sequence of bytes from the memory bank.
        There is no restriction on the offset or the number of bytes to read, except that the
        range must be contained in the address space.
        
        :param jpype.JLong or int addrOffset: is the start of the byte range to read
        :param jpype.JInt or int size: is the number of bytes to read
        :param jpype.JArray[jpype.JByte] res: is a pointer to where the retrieved bytes should be stored
        :param jpype.JBoolean or bool stopOnUnintialized: if true a partial read is permitted and returned size may be 
                smaller than size requested if uninitialized data is encountered.
        :return: number of bytes actually read
        :rtype: int
        """

    def getInitializedMaskSize(self) -> int:
        """
        
        
        :return: the size of a page initialized mask in bytes.  Each bit within the
        mask corresponds to a data byte within a page.
        :rtype: int
        """

    def getMemoryFaultHandler(self) -> MemoryFaultHandler:
        """
        
        
        :return: memory fault handler (may be null)
        :rtype: MemoryFaultHandler
        """

    def getPageSize(self) -> int:
        """
        A MemoryBank is instantiated with a natural page size. Requests for large chunks of data
        may be broken down into units of this size.
        
        :return: the number of bytes in a page.
        :rtype: int
        """

    def getSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        
        
        :return: the AddressSpace associated with this bank.
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def isBigEndian(self) -> bool:
        """
        
        
        :return: true if memory bank is big endian
        :rtype: bool
        """

    def setChunk(self, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], val: jpype.JArray[jpype.JByte]):
        """
        This the most general method for writing a sequence of bytes into the memory bank.
        The initial offset and page writes will be wrapped within the address space.
        
        :param jpype.JLong or int offset: is the start of the byte range to be written.  This offset will be wrapped
        within the space
        :param jpype.JInt or int size: is the number of bytes to write
        :param jpype.JArray[jpype.JByte] val: is a pointer to the sequence of bytes to be written into the bank
        """

    def setInitialized(self, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], initialized: typing.Union[jpype.JBoolean, bool]):
        """
        This method allows ranges of bytes to marked as initialized or not.
        There is no restriction on the offset to write to or the number of bytes to be written,
        except that the range must be contained in the address space.
        
        :param jpype.JLong or int offset: is the start of the byte range to be written
        :param jpype.JInt or int size: is the number of bytes to write
        :param jpype.JBoolean or bool initialized: indicates if the range should be marked as initialized or not
        """

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def memoryFaultHandler(self) -> MemoryFaultHandler:
        ...

    @property
    def initializedMaskSize(self) -> jpype.JInt:
        ...

    @property
    def pageSize(self) -> jpype.JInt:
        ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...


class DefaultMemoryState(AbstractMemoryState):
    """
    All storage/state for a pcode emulator machine
    
    Every piece of information in a pcode emulator machine is representable as a triple
    (AddressSpace,offset,size). This class allows getting and setting of all state information of
    this form.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        MemoryState constructor for a specified processor language
        
        :param ghidra.program.model.lang.Language language:
        """

    def getChunk(self, res: jpype.JArray[jpype.JByte], spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], stopOnUnintialized: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        This is the main interface for reading a range of bytes from the MemorySate. The MemoryBank
        associated with the address space of the query is looked up and the request is forwarded to
        the getChunk method on the MemoryBank. If there is no registered MemoryBank or some other
        error, an exception is thrown. All getLongValue methods utilize this method to read the bytes
        from the appropriate memory bank.
        
        :param jpype.JArray[jpype.JByte] res: the result buffer for storing retrieved bytes
        :param ghidra.program.model.address.AddressSpace spc: the desired address space
        :param jpype.JLong or int off: the starting offset of the byte range being read
        :param jpype.JInt or int size: the number of bytes being read
        :param jpype.JBoolean or bool stopOnUnintialized: if true a partial read is permitted and returned size may be
                    smaller than size requested
        :return: number of bytes actually read
        :rtype: int
        :raises LowlevelError: if spc has not been mapped within this MemoryState or memory fault
                    handler generated error
        """

    def getMemoryBank(self, spc: ghidra.program.model.address.AddressSpace) -> MemoryBank:
        """
        Any MemoryBank that has been registered with this MemoryState can be retrieved via this
        method if the MemoryBank's associated address space is known.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space of the desired MemoryBank
        :return: the MemoryBank or null if no bank is associated with spc.
        :rtype: MemoryBank
        """

    def setChunk(self, val: jpype.JArray[jpype.JByte], spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
        """
        This is the main interface for setting values for a range of bytes in the MemoryState. The
        MemoryBank associated with the desired address space is looked up and the write is forwarded
        to the setChunk method on the MemoryBank. If there is no registered MemoryBank or some other
        error, an exception is throw. All setValue methods utilize this method to read the bytes from
        the appropriate memory bank.
        
        :param jpype.JArray[jpype.JByte] val: the byte values to be written into the MemoryState
        :param ghidra.program.model.address.AddressSpace spc: the address space being written
        :param jpype.JLong or int off: the starting offset of the range being written
        :param jpype.JInt or int size: the number of bytes to write
        :raises LowlevelError: if spc has not been mapped within this MemoryState
        """

    def setInitialized(self, initialized: typing.Union[jpype.JBoolean, bool], spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
        """
        This is the main interface for setting the initialization status for a range of bytes in the
        MemoryState. The MemoryBank associated with the desired address space is looked up and the
        write is forwarded to the setInitialized method on the MemoryBank. If there is no registered
        MemoryBank or some other error, an exception is throw. All setValue methods utilize this
        method to read the bytes from the appropriate memory bank.
        
        :param jpype.JBoolean or bool initialized: indicates if range should be marked as initialized or not
        :param ghidra.program.model.address.AddressSpace spc: the address space being written
        :param jpype.JLong or int off: the starting offset of the range being written
        :param jpype.JInt or int size: the number of bytes to write
        """

    def setMemoryBank(self, bank: MemoryBank):
        """
        MemoryBanks associated with specific address spaces must be registers with this MemoryState
        via this method. Each address space that will be used during emulation must be registered
        separately. The MemoryState object does not assume responsibility for freeing the MemoryBank.
        
        :param MemoryBank bank: is a pointer to the MemoryBank to be registered
        """

    @property
    def memoryBank(self) -> MemoryBank:
        ...

    @memoryBank.setter
    def memoryBank(self, value: MemoryBank):
        ...


class MemoryPageBank(MemoryBank):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ghidra.program.model.address.AddressSpace, isBigEndian: typing.Union[jpype.JBoolean, bool], ps: typing.Union[jpype.JInt, int], faultHandler: MemoryFaultHandler):
        ...


class MemoryPageOverlay(MemoryPageBank):
    """
    Memory bank that overlays some other memory bank, using a "copy on write" behavior.
     
    
    Pages are copied from the underlying object only when there is
    a write. The underlying access routines are overridden to make optimal use
    of this page implementation.  The underlying memory bank can be a null pointer
    in which case, this memory bank behaves as if it were initially filled with zeros.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ghidra.program.model.address.AddressSpace, ul: MemoryBank, faultHandler: MemoryFaultHandler):
        """
        A page overlay memory bank needs all the parameters for a generic memory bank
        and it needs to know the underlying memory bank being overlayed.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space associated with the memory bank
        :param MemoryBank ul: is the underlying MemoryBank
        :param MemoryFaultHandler faultHandler:
        """


class MemoryState(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getBigInteger(self, vn: ghidra.program.model.pcode.Varnode, signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        A convenience method for reading a value directly from a varnode rather
        than querying for the offset and space
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode location to be read
        :param jpype.JBoolean or bool signed: true if signed value should be returned, false for unsigned value
        :return: the unsigned value read from the varnode location
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def getBigInteger(self, reg: ghidra.program.model.lang.Register) -> java.math.BigInteger:
        """
        A convenience method for reading a value directly from a register rather
        than querying for the offset and space
        
        :param ghidra.program.model.lang.Register reg: the register location to be read
        :return: the unsigned value read from the register location
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def getBigInteger(self, nm: typing.Union[java.lang.String, str]) -> java.math.BigInteger:
        """
        This is a convenience method for reading registers by name.
        any register name known to the language can be used as a read location.
        The associated address space, offset, and size is looked up and automatically
        passed to the main getValue routine.
        
        :param java.lang.String or str nm: is the name of the register
        :return: the unsigned value associated with that register
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def getBigInteger(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        This is the main interface for reading values from the MemoryState.
        If there is no registered MemoryBank for the desired address space, or
        if there is some other error, an exception is thrown.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space being queried
        :param jpype.JLong or int off: is the offset of the value being queried
        :param jpype.JInt or int size: is the number of bytes to query
        :param jpype.JBoolean or bool signed: true if signed value should be returned, false for unsigned value
        :return: the queried unsigned value
        :rtype: java.math.BigInteger
        """

    def getChunk(self, res: jpype.JArray[jpype.JByte], spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], stopOnUnintialized: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        This is the main interface for reading a range of bytes from the MemorySate.
        The MemoryBank associated with the address space of the query is looked up
        and the request is forwarded to the getChunk method on the MemoryBank. If there
        is no registered MemoryBank or some other error, an exception is thrown.
        All getLongValue methods utilize this method to read the bytes from the
        appropriate memory bank.
        
        :param jpype.JArray[jpype.JByte] res: the result buffer for storing retrieved bytes
        :param ghidra.program.model.address.AddressSpace spc: the desired address space
        :param jpype.JLong or int off: the starting offset of the byte range being read
        :param jpype.JInt or int size: the number of bytes being read
        :param jpype.JBoolean or bool stopOnUnintialized: if true a partial read is permitted and returned size may be 
        smaller than size requested
        :return: number of bytes actually read
        :rtype: int
        :raises LowlevelError: if spc has not been mapped within this MemoryState or memory fault
        handler generated error
        """

    def getMemoryBank(self, spc: ghidra.program.model.address.AddressSpace) -> MemoryBank:
        """
        Any MemoryBank that has been registered with this MemoryState can be retrieved via this
        method if the MemoryBank's associated address space is known.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space of the desired MemoryBank
        :return: the MemoryBank or null if no bank is associated with spc.
        :rtype: MemoryBank
        """

    @typing.overload
    def getValue(self, vn: ghidra.program.model.pcode.Varnode) -> int:
        """
        A convenience method for reading a value directly from a varnode rather
        than querying for the offset and space
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode location to be read
        :return: the value read from the varnode location
        :rtype: int
        """

    @typing.overload
    def getValue(self, reg: ghidra.program.model.lang.Register) -> int:
        """
        A convenience method for reading a value directly from a register rather
        than querying for the offset and space
        
        :param ghidra.program.model.lang.Register reg: the register location to be read
        :return: the value read from the register location
        :rtype: int
        """

    @typing.overload
    def getValue(self, nm: typing.Union[java.lang.String, str]) -> int:
        """
        This is a convenience method for reading registers by name.
        any register name known to the language can be used as a read location.
        The associated address space, offset, and size is looked up and automatically
        passed to the main getValue routine.
        
        :param java.lang.String or str nm: is the name of the register
        :return: the value associated with that register
        :rtype: int
        """

    @typing.overload
    def getValue(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        This is the main interface for reading values from the MemoryState.
        If there is no registered MemoryBank for the desired address space, or
        if there is some other error, an exception is thrown.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space being queried
        :param jpype.JLong or int off: is the offset of the value being queried
        :param jpype.JInt or int size: is the number of bytes to query
        :return: the queried value
        :rtype: int
        """

    def setChunk(self, val: jpype.JArray[jpype.JByte], spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
        """
        This is the main interface for setting values for a range of bytes in the MemoryState.
        The MemoryBank associated with the desired address space is looked up and the
        write is forwarded to the setChunk method on the MemoryBank. If there is no
        registered MemoryBank or some other error, an exception  is throw.
        All setValue methods utilize this method to read the bytes from the
        appropriate memory bank.
        
        :param jpype.JArray[jpype.JByte] val: the byte values to be written into the MemoryState
        :param ghidra.program.model.address.AddressSpace spc: the address space being written
        :param jpype.JLong or int off: the starting offset of the range being written
        :param jpype.JInt or int size: the number of bytes to write
        :raises LowlevelError: if spc has not been mapped within this MemoryState
        """

    def setInitialized(self, initialized: typing.Union[jpype.JBoolean, bool], spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
        """
        This is the main interface for setting the initialization status for a range of bytes
        in the MemoryState.
        The MemoryBank associated with the desired address space is looked up and the
        write is forwarded to the setInitialized method on the MemoryBank. If there is no
        registered MemoryBank or some other error, an exception  is throw.
        All setValue methods utilize this method to read the bytes from the
        appropriate memory bank.
        
        :param jpype.JBoolean or bool initialized: indicates if range should be marked as initialized or not
        :param ghidra.program.model.address.AddressSpace spc: the address space being written
        :param jpype.JLong or int off: the starting offset of the range being written
        :param jpype.JInt or int size: the number of bytes to write
        """

    def setMemoryBank(self, bank: MemoryBank):
        """
        MemoryBanks associated with specific address spaces must be registers with this MemoryState
        via this method.  Each address space that will be used during emulation must be registered
        separately.  The MemoryState object does not assume responsibility for freeing the MemoryBank.
        
        :param MemoryBank bank: is a pointer to the MemoryBank to be registered
        """

    @typing.overload
    def setValue(self, vn: ghidra.program.model.pcode.Varnode, cval: typing.Union[jpype.JLong, int]):
        """
        A convenience method for setting a value directly on a varnode rather than
        breaking out the components
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode location to be written
        :param jpype.JLong or int cval: the value to write into the varnode location
        """

    @typing.overload
    def setValue(self, reg: ghidra.program.model.lang.Register, cval: typing.Union[jpype.JLong, int]):
        """
        A convenience method for setting a value directly on a register rather than
        breaking out the components
        
        :param ghidra.program.model.lang.Register reg: the register location to be written
        :param jpype.JLong or int cval: the value to write into the register location
        """

    @typing.overload
    def setValue(self, nm: typing.Union[java.lang.String, str], cval: typing.Union[jpype.JLong, int]):
        """
        This is a convenience method for setting registers by name.
        Any register name known to the language can be used as a write location.
        The associated address space, offset, and size is looked up and automatically
        passed to the main setValue routine.
        
        :param java.lang.String or str nm: is the name of the register
        :param jpype.JLong or int cval: is the value to write to the register
        """

    @typing.overload
    def setValue(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], cval: typing.Union[jpype.JLong, int]):
        """
        This is the main interface for writing values to the MemoryState.
        If there is no registered MemoryBank for the desired address space, or
        if there is some other error, an exception is thrown.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space to write to
        :param jpype.JLong or int off: is the offset where the value should be written
        :param jpype.JInt or int size: is the number of bytes to be written
        :param jpype.JLong or int cval: is the value to be written
        """

    @typing.overload
    def setValue(self, vn: ghidra.program.model.pcode.Varnode, cval: java.math.BigInteger):
        """
        A convenience method for setting a value directly on a varnode rather than
        breaking out the components
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode location to be written
        :param java.math.BigInteger cval: the value to write into the varnode location
        """

    @typing.overload
    def setValue(self, reg: ghidra.program.model.lang.Register, cval: java.math.BigInteger):
        """
        A convenience method for setting a value directly on a register rather than
        breaking out the components
        
        :param ghidra.program.model.lang.Register reg: the register location to be written
        :param java.math.BigInteger cval: the value to write into the register location
        """

    @typing.overload
    def setValue(self, nm: typing.Union[java.lang.String, str], cval: java.math.BigInteger):
        """
        This is a convenience method for setting registers by name.
        Any register name known to the language can be used as a write location.
        The associated address space, offset, and size is looked up and automatically
        passed to the main setValue routine.
        
        :param java.lang.String or str nm: is the name of the register
        :param java.math.BigInteger cval: is the value to write to the register
        """

    @typing.overload
    def setValue(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], cval: java.math.BigInteger):
        """
        This is the main interface for writing values to the MemoryState.
        If there is no registered MemoryBank for the desired address space, or
        if there is some other error, an exception is thrown.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space to write to
        :param jpype.JLong or int off: is the offset where the value should be written
        :param jpype.JInt or int size: is the number of bytes to be written
        :param java.math.BigInteger cval: is the value to be written
        """

    @property
    def memoryBank(self) -> MemoryBank:
        ...

    @memoryBank.setter
    def memoryBank(self, value: MemoryBank):
        ...

    @property
    def bigInteger(self) -> java.math.BigInteger:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class UniqueMemoryBank(MemoryBank):
    """
    An subclass of :obj:`MemoryBank` intended for modeling the "unique" memory
    space.  The space is byte-addressable and paging is not supported.
    """

    class WordInfo(java.lang.Object):
        """
        A simple class representing a byte-addressable word of memory.  Each
        byte can be either initialized to a byte value or uninitialized.
        It is an error to attempt to read an uninitialized byte.
        """

        class_: typing.ClassVar[java.lang.Class]
        initialized: jpype.JByte
        word: jpype.JLong

        def __init__(self):
            """
            Constructs a :obj:`WordInfo` object with all bytes uninitialized.
            """

        def getByte(self, index: typing.Union[jpype.JInt, int]) -> int:
            """
            Returns the byte at the given index
            
            :param jpype.JInt or int index: index
            :return: corresponding byte value
            :rtype: int
            :raises LowlevelError: if the index is invalid or the requested byte
            is not initialized.
            """

        def getWord(self, buffer: jpype.JArray[jpype.JByte]):
            """
            Writes an entire word into ``buffer``
            
            :param jpype.JArray[jpype.JByte] buffer: buffer to write a single word to.  Must have
            length 8.
            :raises LowlevelError: if the entire word is not initialized
            """

        def setByte(self, val: typing.Union[jpype.JByte, int], index: typing.Union[jpype.JInt, int]):
            """
            Initializes the byte at ``index`` and sets its value to 
            ``val``
            
            :param jpype.JByte or int val: new value
            :param jpype.JInt or int index: index
            :raises LowlevelError: if the index is invalid
            """

        @property
        def byte(self) -> jpype.JByte:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ghidra.program.model.address.AddressSpace, isBigEndian: typing.Union[jpype.JBoolean, bool]):
        ...

    def clear(self):
        """
        Clear unique storage at the start of an instruction
        """


class AbstractMemoryState(MemoryState):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        ...

    @typing.overload
    def getBigInteger(self, vn: ghidra.program.model.pcode.Varnode, signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        A convenience method for reading a value directly from a varnode rather than querying for the
        offset and space
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode location to be read
        :param jpype.JBoolean or bool signed: true if signed value should be returned, false for unsigned value
        :return: the unsigned value read from the varnode location
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def getBigInteger(self, reg: ghidra.program.model.lang.Register) -> java.math.BigInteger:
        """
        A convenience method for reading a value directly from a register rather than querying for
        the offset and space
        
        :param ghidra.program.model.lang.Register reg: the register location to be read
        :return: the unsigned value read from the register location
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def getBigInteger(self, nm: typing.Union[java.lang.String, str]) -> java.math.BigInteger:
        """
        This is a convenience method for reading registers by name. any register name known to the
        language can be used as a read location. The associated address space, offset, and size is
        looked up and automatically passed to the main getValue routine.
        
        :param java.lang.String or str nm: is the name of the register
        :return: the unsigned value associated with that register
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def getBigInteger(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        This is the main interface for reading values from the MemoryState. If there is no registered
        MemoryBank for the desired address space, or if there is some other error, an exception is
        thrown.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space being queried
        :param jpype.JLong or int off: is the offset of the value being queried
        :param jpype.JInt or int size: is the number of bytes to query
        :param jpype.JBoolean or bool signed: true if signed value should be returned, false for unsigned value
        :return: the queried unsigned value
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def getValue(self, vn: ghidra.program.model.pcode.Varnode) -> int:
        """
        A convenience method for reading a value directly from a varnode rather than querying for the
        offset and space
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode location to be read
        :return: the value read from the varnode location
        :rtype: int
        """

    @typing.overload
    def getValue(self, reg: ghidra.program.model.lang.Register) -> int:
        """
        A convenience method for reading a value directly from a register rather than querying for
        the offset and space
        
        :param ghidra.program.model.lang.Register reg: the register location to be read
        :return: the value read from the register location
        :rtype: int
        """

    @typing.overload
    def getValue(self, nm: typing.Union[java.lang.String, str]) -> int:
        """
        This is a convenience method for reading registers by name. any register name known to the
        language can be used as a read location. The associated address space, offset, and size is
        looked up and automatically passed to the main getValue routine.
        
        :param java.lang.String or str nm: is the name of the register
        :return: the value associated with that register
        :rtype: int
        """

    @typing.overload
    def getValue(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        This is the main interface for reading values from the MemoryState. If there is no registered
        MemoryBank for the desired address space, or if there is some other error, an exception is
        thrown.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space being queried
        :param jpype.JLong or int off: is the offset of the value being queried
        :param jpype.JInt or int size: is the number of bytes to query
        :return: the queried value
        :rtype: int
        """

    @typing.overload
    def setValue(self, vn: ghidra.program.model.pcode.Varnode, cval: typing.Union[jpype.JLong, int]):
        """
        A convenience method for setting a value directly on a varnode rather than breaking out the
        components
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode location to be written
        :param jpype.JLong or int cval: the value to write into the varnode location
        """

    @typing.overload
    def setValue(self, reg: ghidra.program.model.lang.Register, cval: typing.Union[jpype.JLong, int]):
        """
        A convenience method for setting a value directly on a register rather than breaking out the
        components
        
        :param ghidra.program.model.lang.Register reg: the register location to be written
        :param jpype.JLong or int cval: the value to write into the register location
        """

    @typing.overload
    def setValue(self, nm: typing.Union[java.lang.String, str], cval: typing.Union[jpype.JLong, int]):
        """
        This is a convenience method for setting registers by name. Any register name known to the
        language can be used as a write location. The associated address space, offset, and size is
        looked up and automatically passed to the main setValue routine.
        
        :param java.lang.String or str nm: is the name of the register
        :param jpype.JLong or int cval: is the value to write to the register
        """

    @typing.overload
    def setValue(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], cval: typing.Union[jpype.JLong, int]):
        """
        This is the main interface for writing values to the MemoryState. If there is no registered
        MemoryBank for the desired address space, or if there is some other error, an exception is
        thrown.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space to write to
        :param jpype.JLong or int off: is the offset where the value should be written
        :param jpype.JInt or int size: is the number of bytes to be written
        :param jpype.JLong or int cval: is the value to be written
        """

    @typing.overload
    def setValue(self, vn: ghidra.program.model.pcode.Varnode, cval: java.math.BigInteger):
        """
        A convenience method for setting a value directly on a varnode rather than breaking out the
        components
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode location to be written
        :param java.math.BigInteger cval: the value to write into the varnode location
        """

    @typing.overload
    def setValue(self, reg: ghidra.program.model.lang.Register, cval: java.math.BigInteger):
        """
        A convenience method for setting a value directly on a register rather than breaking out the
        components
        
        :param ghidra.program.model.lang.Register reg: the register location to be written
        :param java.math.BigInteger cval: the value to write into the register location
        """

    @typing.overload
    def setValue(self, nm: typing.Union[java.lang.String, str], cval: java.math.BigInteger):
        """
        This is a convenience method for setting registers by name. Any register name known to the
        language can be used as a write location. The associated address space, offset, and size is
        looked up and automatically passed to the main setValue routine.
        
        :param java.lang.String or str nm: is the name of the register
        :param java.math.BigInteger cval: is the value to write to the register
        """

    @typing.overload
    def setValue(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], cval: java.math.BigInteger):
        """
        This is the main interface for writing values to the MemoryState. If there is no registered
        MemoryBank for the desired address space, or if there is some other error, an exception is
        thrown.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space to write to
        :param jpype.JLong or int off: is the offset where the value should be written
        :param jpype.JInt or int size: is the number of bytes to be written
        :param java.math.BigInteger cval: is the value to be written
        """

    @property
    def bigInteger(self) -> java.math.BigInteger:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class MemoryFaultHandler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def uninitializedRead(self, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], buf: jpype.JArray[jpype.JByte], bufOffset: typing.Union[jpype.JInt, int]) -> bool:
        """
        An attempt has been made to read uninitialized memory at the 
        specified address.
        
        :param ghidra.program.model.address.Address address: uninitialized storage address (memory, register or unique)
        :param jpype.JInt or int size: number of uninitialized bytes
        :param jpype.JArray[jpype.JByte] buf: storage buffer
        :param jpype.JInt or int bufOffset: read offset within buffer
        :return: true if data should be treated as initialized
        :rtype: bool
        """

    def unknownAddress(self, address: ghidra.program.model.address.Address, write: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Unable to translate the specified address
        
        :param ghidra.program.model.address.Address address: address which failed to be translated
        :param jpype.JBoolean or bool write: true if memory operation was a write vs. read
        :return: true if fault was handled
        :rtype: bool
        """



__all__ = ["MemoryPage", "MemoryBank", "DefaultMemoryState", "MemoryPageBank", "MemoryPageOverlay", "MemoryState", "UniqueMemoryBank", "AbstractMemoryState", "MemoryFaultHandler"]
