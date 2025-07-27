from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util.datastruct
import ghidra.util.exception
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.stream # type: ignore


@typing.type_check_only
class Mark(java.io.Serializable):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GlobalNamespace(ghidra.program.model.symbol.Namespace):
    """
    The global namespace implementation class
    """

    class_: typing.ClassVar[java.lang.Class]
    GLOBAL_NAMESPACE_NAME: typing.Final = "Global"
    """
    Global namespace name which may (incorrectly) appear as the first 
    element within a namespace path (e.g., ``Global::Foo::Bar``).  It is 
    preferred that the Global namespace be omitted in favor of ``Foo::Bar``.
    """


    def __init__(self, memory: ghidra.program.model.mem.Memory):
        """
        Constructs a new GlobalNamespace
        
        :param ghidra.program.model.mem.Memory memory: the memory associated with this global namespace
        """


class SingleAddressSetCollection(AddressSetCollection):
    """
    A simple implementation of AddressSetCollection that contains exactly one AddressSet.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, set: AddressSetView):
        ...


class GlobalSymbol(ghidra.program.model.symbol.Symbol):
    """
    The global symbol implementation class
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAssociatedReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    def getSource(self) -> ghidra.program.model.symbol.SourceType:
        """
        This method doesn't apply to the global symbol, since a program always has a global symbol 
        and it can't be renamed. Therefore calling it will throw an UnsupportedOperationException.
        return source the source of this symbol: default, imported, analysis, or user defined.
        
        :raises UnsupportedOperationException: whenever called.
        """

    def isPinned(self) -> bool:
        """
        This returns false, since the global symbol isn't associated with a specific
        program memory address.
        """

    def setPinned(self, pinned: typing.Union[jpype.JBoolean, bool]):
        """
        This method doesn't apply to the global symbol, since it isn't associated with a specific
        program memory address. Therefore calling it will have no effect.
        """

    def setSource(self, source: ghidra.program.model.symbol.SourceType):
        """
        This method doesn't apply to the global symbol, since a program always has a global symbol 
        and it can't be renamed. Therefore calling it will throw an UnsupportedOperationException.
        
        :param ghidra.program.model.symbol.SourceType source: the source of this symbol: Symbol.DEFAULT, Symbol.IMPORTED, Symbol.ANALYSIS, or Symbol.USER_DEFINED.
        :raises UnsupportedOperationException: whenever called.
        """

    @property
    def pinned(self) -> jpype.JBoolean:
        ...

    @pinned.setter
    def pinned(self, value: jpype.JBoolean):
        ...

    @property
    def associatedReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def source(self) -> ghidra.program.model.symbol.SourceType:
        ...

    @source.setter
    def source(self, value: ghidra.program.model.symbol.SourceType):
        ...


class AddressFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getAddress(self, addrString: typing.Union[java.lang.String, str]) -> Address:
        """
        Create an address from String. Attempts to use the "default" address space
        first.  Otherwise loops through each addressSpace, returning the first valid
        address that any addressSpace creates from the string.
        Returns an Address if the string is valid, otherwise null.
        """

    @typing.overload
    def getAddress(self, spaceID: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JLong, int]) -> Address:
        """
        Get an address using the addressSpace with the given id and having the given offset.
        
        :param jpype.JInt or int spaceID: the id of the address space to use to create the new address.
        :param jpype.JLong or int offset: the offset of the new address to be created.
        :return: the new address.
        :rtype: Address
        """

    @typing.overload
    def getAddressSet(self, min: Address, max: Address) -> AddressSet:
        """
        Computes an address set from a start and end address that may span address spaces.  Although 
        in general, it is not meaningful to compare addresses from multiple spaces, but since there 
        is an absolute ordering of address spaces it can be useful for iterating over all addresses
        in a program with multiple address spaces.
        
        :param Address min: the start address
        :param Address max: the end address.
        :return: an addressSet containing ranges that don't span address spaces.
        :rtype: AddressSet
        """

    @typing.overload
    def getAddressSet(self) -> AddressSet:
        """
        Returns an addressSet containing all possible "real" addresses for this address factory.
        """

    @typing.overload
    def getAddressSpace(self, name: typing.Union[java.lang.String, str]) -> AddressSpace:
        """
        Returns the space with the given name or null if no space
        exists with that name.
        """

    @typing.overload
    def getAddressSpace(self, spaceID: typing.Union[jpype.JInt, int]) -> AddressSpace:
        """
        Returns the space with the given spaceID or null if none exists
        """

    def getAddressSpaces(self) -> jpype.JArray[AddressSpace]:
        """
        Get the array of all "physical" AddressSpaces.
        """

    def getAllAddressSpaces(self) -> jpype.JArray[AddressSpace]:
        """
        Returns an array of all address spaces, including analysis spaces.
        
        :return: an array of all the address spaces.
        :rtype: jpype.JArray[AddressSpace]
        """

    @typing.overload
    def getAllAddresses(self, addrString: typing.Union[java.lang.String, str]) -> jpype.JArray[Address]:
        """
        Generates all reasonable addresses that can be interpreted from
        the given string.  Each Address Space is given a change to parse
        the string and all the valid results are return in the array.
        
        :param java.lang.String or str addrString: the address string to parse.
        :return: Address[] The list of addresses generated from the string.
        :rtype: jpype.JArray[Address]
        """

    @typing.overload
    def getAllAddresses(self, addrString: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[Address]:
        """
        Generates all reasonable addresses that can be interpreted from
        the given string.  Each Address Space is given a change to parse
        the string and all the valid results are return in the array.
        
        :param java.lang.String or str addrString: the address string to parse.
        :param jpype.JBoolean or bool caseSensitive: determines if addressSpace names must be case sensitive to match.
        :return: Address[] The list of addresses generated from the string.
        :rtype: jpype.JArray[Address]
        """

    def getConstantAddress(self, offset: typing.Union[jpype.JLong, int]) -> Address:
        """
        Returns an address in "constant" space with the given offset.
        
        :param jpype.JLong or int offset: the offset in "constant" space for the new address.
        :return: a new address in the "constant" space with the given offset.
        :rtype: Address
        """

    def getConstantSpace(self) -> AddressSpace:
        """
        Returns the "constant" address space.
        """

    def getDefaultAddressSpace(self) -> AddressSpace:
        """
        Returns the default AddressSpace
        """

    def getIndex(self, addr: Address) -> int:
        """
        Returns the index (old encoding) for the given address.
        
        :param Address addr: the address to encode.
        """

    def getNumAddressSpaces(self) -> int:
        """
        Returns the number of physical AddressSpaces.
        """

    def getPhysicalSpace(self, space: AddressSpace) -> AddressSpace:
        """
        Gets the physical address space associated with the given address space. If 
        the given space is physical, then it will be returned.
        
        :param AddressSpace space: the addressSpace for which the physical space is requested.
        :return: the physical address space associated with the given address space.
        :rtype: AddressSpace
        """

    def getPhysicalSpaces(self) -> jpype.JArray[AddressSpace]:
        """
        Returns an array of all the physical address spaces.
        
        :return: an array of all the physical address spaces.
        :rtype: jpype.JArray[AddressSpace]
        """

    def getRegisterSpace(self) -> AddressSpace:
        """
        Returns the "register" address space.
        """

    def getStackSpace(self) -> AddressSpace:
        """
        Returns the "stack" address space.
        """

    def getUniqueSpace(self) -> AddressSpace:
        """
        Returns the "unique" address space.
        """

    def hasMultipleMemorySpaces(self) -> bool:
        """
        Returns true if there is more than one memory address space
        """

    def hasStaleOverlayCondition(self) -> bool:
        """
        Determine if this address factory contains a stale overlay address space
        whose name was recently changed.  When this condition occurs, issues may arise when
        comparing :obj:`Address` and :obj:`AddressSpace`-related objects when overlay 
        address spaces are involved.  A common case for this is a Diff type operation.
        
        :return: true if this factory contains one or more stale overlay address space instances.
        :rtype: bool
        """

    def isValidAddress(self, addr: Address) -> bool:
        """
        Tests if the given address is valid for at least one of the 
        Address Spaces in this factory
        
        :param Address addr: The address to test
        :return: boolean true if the address valid, false otherwise
        :rtype: bool
        """

    def oldGetAddressFromLong(self, value: typing.Union[jpype.JLong, int]) -> Address:
        """
        Returns the address using the old encoding format.
        
        :param jpype.JLong or int value: to decode into an address.
        """

    @property
    def addressSpaces(self) -> jpype.JArray[AddressSpace]:
        ...

    @property
    def addressSet(self) -> AddressSet:
        ...

    @property
    def constantAddress(self) -> Address:
        ...

    @property
    def address(self) -> Address:
        ...

    @property
    def validAddress(self) -> jpype.JBoolean:
        ...

    @property
    def physicalSpace(self) -> AddressSpace:
        ...

    @property
    def addressSpace(self) -> AddressSpace:
        ...

    @property
    def allAddressSpaces(self) -> jpype.JArray[AddressSpace]:
        ...

    @property
    def stackSpace(self) -> AddressSpace:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def constantSpace(self) -> AddressSpace:
        ...

    @property
    def uniqueSpace(self) -> AddressSpace:
        ...

    @property
    def allAddresses(self) -> jpype.JArray[Address]:
        ...

    @property
    def defaultAddressSpace(self) -> AddressSpace:
        ...

    @property
    def physicalSpaces(self) -> jpype.JArray[AddressSpace]:
        ...

    @property
    def registerSpace(self) -> AddressSpace:
        ...

    @property
    def numAddressSpaces(self) -> jpype.JInt:
        ...


class EmptyAddressIterator(AddressIterator):
    """
    Implementation for an AddressIterator that is empty.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OverlayAddressSpace(AbstractAddressSpace):

    class_: typing.ClassVar[java.lang.Class]
    OV_SEPARATER: typing.Final = ":"

    def __init__(self, baseSpace: AddressSpace, unique: typing.Union[jpype.JInt, int], orderedKey: typing.Union[java.lang.String, str]):
        """
        Construction an overlay address space instance.
        
        :param AddressSpace baseSpace: base overlayed address space
        :param jpype.JInt or int unique: unique index/sequence number
        :param java.lang.String or str orderedKey: unique ordered key which should generally match overlay name unless 
        already used (e.g., on a renamed overlay space).  This associated value should not be
        changed for a given address factory instance.
        """

    def contains(self, offset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Determine if the specified offset is contained within a defined region of this overlay space.
        
        :param jpype.JLong or int offset: unsigned address offset
        :return: true if contained within defined region otherwise false
        :rtype: bool
        """

    def getBaseSpaceID(self) -> int:
        """
        
        
        :return: the ID of the address space underlying this space
        :rtype: int
        """

    def getOrderedKey(self) -> str:
        """
        Get the ordered key assigned to this overlay address space instance  This value is used
        when performing :meth:`equals(Object) <.equals>` and :meth:`compareTo(AddressSpace) <.compareTo>`
        operations.
         
        
        If this value does not have its optimal value (i.e., same as address space name), the 
        associated :obj:`AddressFactory` should report a 
        :meth:`stale overlay condition <AddressFactory.hasStaleOverlayCondition>`.
        
        :return: instance ordered key
        :rtype: str
        """

    def getOverlayAddressSet(self) -> AddressSetView:
        """
        Get the :obj:`AddressSet` which corresponds to overlayed physical region which 
        corresponds to the defined overlay regions within the overlay (i.e., overlay blocks).
        
        :return: defined regions within the overlay.  All addresses are overlay addresses.
        :rtype: AddressSetView
        """

    def getOverlayedSpace(self) -> AddressSpace:
        """
        Get the overlayed (i.e., underlying) base space associated with this overlay space.
        
        :return: overlayed base space.
        :rtype: AddressSpace
        """

    @typing.overload
    def translateAddress(self, addr: Address) -> Address:
        """
        If the given address is outside the overlay block, then the address is tranlated to an
        address in the base space with the same offset, otherwise (if the address exists in the
        overlay block), it is returned
        
        :param Address addr: the address to translate to the base space if it is outside the overlay block
        :return: either the given address if it is contained in the overlay memory block or an address
                in the base space with the same offset as the given address.
        :rtype: Address
        """

    @typing.overload
    def translateAddress(self, addr: Address, forceTranslation: typing.Union[jpype.JBoolean, bool]) -> Address:
        """
        Tranlated an overlay-space address (addr, which may exceed the bounds of the overlay space)
        to an address in the base space with the same offset. If forceTranslation is false and addr
        is contained within the overlay-space the original addr is returned.
        
        :param Address addr: the address to translate to the base space
        :param jpype.JBoolean or bool forceTranslation: if true addr will be translated even if addr falls within the bounds
                    of this overlay-space.
        :return: either the given address if it is contained in the overlay memory block or an address
                in the base space with the same offset as the given address.
        :rtype: Address
        """

    @property
    def orderedKey(self) -> java.lang.String:
        ...

    @property
    def overlayedSpace(self) -> AddressSpace:
        ...

    @property
    def overlayAddressSet(self) -> AddressSetView:
        ...

    @property
    def baseSpaceID(self) -> jpype.JInt:
        ...


class Address(java.lang.Comparable[Address]):
    """
    An address represents a location in a program.  Conceptually, addresses consist of an 
    "address space" and an offset within that space.  Many processors have only one "real" address 
    space, but some have several spaces. Also, there are "artificial" address spaces used for 
    analysis and representing other non-memory locations such as a register or an offset on the 
    stack relative to a functions frame pointer.
    """

    class_: typing.ClassVar[java.lang.Class]
    NO_ADDRESS: typing.Final[Address]
    """
    Address object representing an invalid address.
    """

    EXT_FROM_ADDRESS: typing.Final[Address]
    """
    Address object representing an external entry address.
    """

    SEPARATOR_CHAR: typing.Final = ':'
    """
    Character used to separate space names from offsets.
    """

    SEPARATOR: typing.Final = ":"

    def add(self, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address (possibly in a new space) by adding the displacement to this address.
        
        :param jpype.JLong or int displacement: the amount to add to this offset.
        :return: The new address.
        :rtype: Address
        :raises AddressOutOfBoundsException: if wrapping is not supported by the corresponding 
        address space and the addition causes an out-of-bounds error
        """

    @typing.overload
    def addNoWrap(self, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new Address with a displacement relative to this Address.  The Address will not
        wrap around!  An exception will be throw if the result is not within this address space.
        
        :param jpype.JLong or int displacement: the displacement to add.
        :return: the new address.
        :rtype: Address
        :raises AddressOverflowException: if the offset in this Address would overflow (wrap around)
        due to this operation.
        """

    @typing.overload
    def addNoWrap(self, displacement: java.math.BigInteger) -> Address:
        ...

    def addWrap(self, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by adding the displacement to the current address. The new address
        will wrap in a manner that depends on the address space. For a generic address space this
        will wrap at the extents of the address space. For a segmented address space it will wrap at
        the extents of the segment.
        
        :param jpype.JLong or int displacement: the displacement to add.
        :return: The new Address formed by adding the displacement to this address's offset.
        :rtype: Address
        """

    def addWrapSpace(self, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by adding the displacement to the current address. If the offset is 
        greater than the max offset of the address space, the high order bits are masked off, making
        the address wrap.  For non-segmented addresses this will be the same as addWrap().  For 
        segmented addresses, the address will wrap when the 20 bit (oxfffff) offset is exceeded, as
        opposed to when the segment offset is exceeded.
        
        :param jpype.JLong or int displacement: the displacement to add.
        :return: The new Address formed by adding the displacement to this address's offset.
        :rtype: Address
        """

    def equals(self, o: java.lang.Object) -> bool:
        """
        Compares this Address to the specified object. The result is ``true`` if and only 
        if the argument is not ``null`` and is a ``Address`` object that 
        represents the same address as this object.
        
        :param java.lang.Object o: the object to compare this ``String`` against.
        :return: ``true`` if the ``Addresses``are equal; ``false`` 
        otherwise.
        :rtype: bool
        """

    def getAddress(self, addrString: typing.Union[java.lang.String, str]) -> Address:
        """
        Creates a new Address by parsing a String representation of an address. The string may be 
        either a simple number (just the offset part of an address) or take the form 
        "addressSpaceName:offset".  If the latter form is used, the "addressSpaceName" must match 
        the name of the space for this address.
        
        :param java.lang.String or str addrString: the String to parse.
        :return: the new Address if the string is a legally formed address or null if the string 
        contains an address space name that does not match this address's space.
        :rtype: Address
        :raises AddressFormatException: if the string cannot be parsed or the
        parsed offset is larger than the size for this address' space.
        """

    def getAddressSpace(self) -> AddressSpace:
        """
        Returns the address space associated with this address.
        
        :return: the address space
        :rtype: AddressSpace
        """

    def getAddressableWordOffset(self) -> int:
        """
        Get the addressable memory word offset which corresponds to this address.
        
        :return: addressable memory word offset
        :rtype: int
        """

    @typing.overload
    def getNewAddress(self, byteOffset: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new Address in this address's space with the given byte offset.
        
        :param jpype.JLong or int byteOffset: the byte offset for the new address.
        :return: the new Address.
        :rtype: Address
        :raises AddressOutOfBoundsException: if the offset is less than the minimum offset or 
        greater than the max offset allowed for this space.
        """

    @typing.overload
    def getNewAddress(self, offset: typing.Union[jpype.JLong, int], isAddressableWordOffset: typing.Union[jpype.JBoolean, bool]) -> Address:
        """
        Returns a new address in this address's space with the given offset.  
         
        NOTE: for those spaces with an addressable unit size other than 1, the address returned 
        may not correspond to an addressable unit/word boundary if a byte-offset is specified.
        
        :param jpype.JLong or int offset: the offset for the new address.
        :param jpype.JBoolean or bool isAddressableWordOffset: if true the specified offset is an addressable unit/word 
        offset, otherwise offset is a byte offset.  See 
        :meth:`AddressSpace#getAddressableUnitSize() <ghidra.program.model.address.AddressSpace.getAddressableUnitSize>` to understand the distinction
        (i.e., wordOffset = byteOffset * addressableUnitSize).
        :return: address with given offset
        :rtype: Address
        :raises AddressOutOfBoundsException: if the offset is less than 0 or greater than the max 
        offset allowed for this space.
        """

    def getNewTruncatedAddress(self, offset: typing.Union[jpype.JLong, int], isAddressableWordOffset: typing.Union[jpype.JBoolean, bool]) -> Address:
        """
        Returns a new address in this address's space with the given offset.  The specified offset 
        will be truncated within the space and will not throw an exception.
         
        NOTE: for those spaces with an addressable unit size other than 1, the address returned 
        may not correspond to a word boundary (addressable unit) if a byte-offset is specified.
        
        :param jpype.JLong or int offset: the offset for the new address.
        :param jpype.JBoolean or bool isAddressableWordOffset: if true the specified offset is an addressable unit/word 
        offset, otherwise offset is a byte offset.  See 
        :meth:`AddressSpace#getAddressableUnitSize() <ghidra.program.model.address.AddressSpace.getAddressableUnitSize>` to understand the distinction
        (i.e., wordOffset = byteOffset * addressableUnitSize).
        :return: address with given byte offset truncated to the physical space size
        :rtype: Address
        """

    def getOffset(self) -> int:
        """
        Get the offset of this Address.
        
        :return: the offset of this Address.
        :rtype: int
        """

    def getOffsetAsBigInteger(self) -> java.math.BigInteger:
        """
        Get the offset of this Address as a BigInteger.
        
        :return: the offset of this Address.
        :rtype: java.math.BigInteger
        """

    def getPhysicalAddress(self) -> Address:
        """
        Returns the physical Address that corresponds to this Address.
        
        :return: address in a physical space corresponding to this address.
        :rtype: Address
        """

    def getPointerSize(self) -> int:
        """
        Returns the number of bytes needed to form a pointer to this address.  The result will be 
        one of {1,2,4,8}.
        
        :return: the pointer size
        :rtype: int
        
        .. seealso::
        
            | :obj:`DataOrganization.getPointerSize()`for compiler-specific size of pointers stored in 
            memory.
        """

    def getSize(self) -> int:
        """
        Returns the number of bits that are used to form the address.  Thus the maximum offset for 
        this address space will be 2^size-1.
        
        :return: the size
        :rtype: int
        """

    def getUnsignedOffset(self) -> int:
        """
        Get the address offset as an unsigned number.
        This may be useful when dealing with signed spaces (e.g. stack)
        
        :return: unsigned address offset
        :rtype: int
        """

    def hasSameAddressSpace(self, addr: Address) -> bool:
        """
        Return true if this address' address space is equal to the address space for addr.
        
        :param Address addr: the address to check
        :return: true if the same space
        :rtype: bool
        """

    def hashCode(self) -> int:
        """
        Returns a hash code for this Address. The hash code for an ``Address`` should be a 
        value such that two Address objects which are equal will return the same hash code. This 
        method should generally return the same value as getLong().
        
        :return: a hash code value for this object.
        :rtype: int
        """

    def isConstantAddress(self) -> bool:
        """
        Returns true if this address represents a location in constant space.
        
        :return: true if this address represents a location in constant space.
        :rtype: bool
        """

    def isExternalAddress(self) -> bool:
        """
        Returns true if this address represents an external location in the external address space.
        
        :return: true if this address represents an external location in the external address space.
        :rtype: bool
        """

    def isHashAddress(self) -> bool:
        """
        Returns true if this address represents a location in the HASH space.
        
        :return: true if this address represents a location in the HASH space.
        :rtype: bool
        """

    def isLoadedMemoryAddress(self) -> bool:
        """
        Returns true if this address represents an address in a loaded memory block.
        
        :return: true if this address represents an address in a loaded memory block.
        :rtype: bool
        """

    def isMemoryAddress(self) -> bool:
        """
        Returns true if this address represents a location in memory.
        
        :return: true if this address represents a location in memory.
        :rtype: bool
        """

    def isNonLoadedMemoryAddress(self) -> bool:
        """
        Returns true if this address represents an address not loaded in real memory (i.e. OTHER).
        
        :return: true if this address represents an address not loaded in real memory (i.e. OTHER).
        :rtype: bool
        """

    def isRegisterAddress(self) -> bool:
        """
        Returns true if this address represents a location in the register space.
         
        NOTE: It is important to note that a :obj:`Register` could reside within a memory space
        and not the register space in which case this method would return false for its address.
        
        :return: true if a register address
        :rtype: bool
        """

    def isStackAddress(self) -> bool:
        """
        Returns true if this address represents a location in stack space.
        
        :return: true if this address represents a location in stack space.
        :rtype: bool
        """

    def isSuccessor(self, addr: Address) -> bool:
        """
        Tests whether the given address immediately follows this address.
        
        :param Address addr: the address to test.
        :return: true if the address follows this address.
        :rtype: bool
        """

    def isUniqueAddress(self) -> bool:
        """
        Returns true if this address represents a location in unique space.
        
        :return: true if this address represents a location in unique space.
        :rtype: bool
        """

    def isVariableAddress(self) -> bool:
        """
        Returns true if this address represents a location in variable space.
        
        :return: true if this address represents a location in variable space.
        :rtype: bool
        """

    @staticmethod
    def max(a: Address, b: Address) -> Address:
        """
        Return the maximum of two addresses using Address.compareTo
        
        :param Address a: first address
        :param Address b: second address
        :return: maximum of two addresses
        :rtype: Address
        """

    @staticmethod
    def min(a: Address, b: Address) -> Address:
        """
        Return the minimum of two addresses using Address.compareTo
        
        :param Address a: first address
        :param Address b: second address
        :return: minimum of two addresses
        :rtype: Address
        """

    def next(self) -> Address:
        """
        Returns the address's successor.  In most cases, this is equivalent to addr.add(1), but 
        segmented addresses could span segments.  The result of calling this on the highest address
        will result in a null return value.
        
        :return: the next higher address, or null if already at the highest address.
        :rtype: Address
        """

    def previous(self) -> Address:
        """
        Returns the address's predecessor.  In most cases, this is equivalent to addr.subtract(1), 
        but segmented addresses could span segments.  The result of calling this on the lowest 
        address will result in a null return value.
        
        :return: the next lower address, or null if already at the lowest address.
        :rtype: Address
        """

    @typing.overload
    def subtract(self, addr: Address) -> int:
        """
        Calculates the displacement between two addresses (``this - addr``)
        
        :param Address addr: the Address to subtract from ``this`` address
        :return: the difference (thisAddress.offset - thatAddress.offset)
        :rtype: int
        :raises IllegalArgumentException: if the two addresses are not in the same address space
        """

    @typing.overload
    def subtract(self, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address (possibly in a new space) by subtracting the displacement to this 
        address.
        
        :param jpype.JLong or int displacement: the amount to subtract from this offset.
        :return: The address using the subtracted offset.
        :rtype: Address
        """

    def subtractNoWrap(self, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new Address by subtracting displacement from the Address.  The Address will not 
        wrap within the space and in fact will throw an exception if the result is less than the min
        address in this space or greater than the max address in this space.
        
        :param jpype.JLong or int displacement: the displacement to subtract.
        :return: The new Address
        :rtype: Address
        :raises AddressOverflowException: if the offset in this Address would overflow due to this
        operation.
        """

    def subtractWrap(self, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by subtracting the displacement from the current address. The new 
        address will wrap in a manner that depends on the address space. For a generic address space
        this will wrap at the extents of the address space. For a segmented address space it will 
        wrap at the extents of the segment.
        
        :param jpype.JLong or int displacement: the displacement to subtract.
        :return: The new Address formed by subtracting the displacement for the offset.
        :rtype: Address
        """

    def subtractWrapSpace(self, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by subtracting the displacement from the current address. If the 
        offset is greater than the max offset of the address space, the high order bits are masked 
        off, making the address wrap.  For non-segmented addresses this will be the same as 
        subtractWrap().  For segmented addresses, the address will wrap when the 20 bit (oxfffff) 
        offset is exceeded, as opposed to when the segment offset is exceeded.
        
        :param jpype.JLong or int displacement: the displacement to add.
        :return: The new Address formed by subtracting the displacement from this address's offset.
        :rtype: Address
        """

    @typing.overload
    def toString(self) -> str:
        """
        Returns a String representation of the address in hex and padded to the appropriate size.
        
        :return: the string
        :rtype: str
        """

    @typing.overload
    def toString(self, prefix: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a String representation of the address using the given string as a prefix.  
        Equivalent of prefix + ":" + toString(false)
        
        :param java.lang.String or str prefix: the string to prepend to the address string.
        :return: the string
        :rtype: str
        """

    @typing.overload
    def toString(self, showAddressSpace: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a String representation that may include the address space name
        
        :param jpype.JBoolean or bool showAddressSpace: true if the address space should be included in resulting string.
        :return: String the string representation of the address
        :rtype: str
        """

    @typing.overload
    def toString(self, showAddressSpace: typing.Union[jpype.JBoolean, bool], pad: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a String representation that may include the address space name and may or may not 
        pad the address with leading zeros.
        
        :param jpype.JBoolean or bool showAddressSpace: if true, the addressSpace name will be prepended to the address 
        string.
        :param jpype.JBoolean or bool pad: if true, the address will be prepended with leading zeros to completely fill out
        the max digits the address could contain.  If false, the address will be prepended only to 
        make the number of hex digits at least 4.
        :return: the address as a String.
        :rtype: str
        """

    @typing.overload
    def toString(self, showAddressSpace: typing.Union[jpype.JBoolean, bool], minNumDigits: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns a String representation that may include the address space name and may or may not 
        pad the address with leading zeros.
        
        :param jpype.JBoolean or bool showAddressSpace: if true, the addressSpace name will be prepended to the address 
        string.
        :param jpype.JInt or int minNumDigits: specifies the minimum number of digits to use.  If the address space 
        size is less that minNumDigits, the address will be padded to the address space size.  If 
        the address space size is larger that minNumDigits, the address will be displayed with as 
        many digits as necessary, but will contain leading zeros to make the address string have at 
        least minNumDigits.
        :return: the address as a String.
        :rtype: str
        """

    @property
    def nonLoadedMemoryAddress(self) -> jpype.JBoolean:
        ...

    @property
    def hashAddress(self) -> jpype.JBoolean:
        ...

    @property
    def successor(self) -> jpype.JBoolean:
        ...

    @property
    def memoryAddress(self) -> jpype.JBoolean:
        ...

    @property
    def constantAddress(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> Address:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def addressSpace(self) -> AddressSpace:
        ...

    @property
    def externalAddress(self) -> jpype.JBoolean:
        ...

    @property
    def stackAddress(self) -> jpype.JBoolean:
        ...

    @property
    def pointerSize(self) -> jpype.JInt:
        ...

    @property
    def registerAddress(self) -> jpype.JBoolean:
        ...

    @property
    def loadedMemoryAddress(self) -> jpype.JBoolean:
        ...

    @property
    def unsignedOffset(self) -> jpype.JLong:
        ...

    @property
    def variableAddress(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def addressableWordOffset(self) -> jpype.JLong:
        ...

    @property
    def physicalAddress(self) -> Address:
        ...

    @property
    def offsetAsBigInteger(self) -> java.math.BigInteger:
        ...

    @property
    def newAddress(self) -> Address:
        ...

    @property
    def uniqueAddress(self) -> jpype.JBoolean:
        ...


class AddressSetMapping(java.lang.Object):
    """
    Class that provides random access to :obj:`Address`es in an :obj:`AddressSet`, based on the 
    index of the address in the set, not the :meth:`address offset value <Address.getOffset>`.
     
    
    For instance, a :obj:`AddressSet` containing addresses [0,1,2,3,4,90,91,92,93,94], 
    :meth:`getAddress(1) <.getAddress>` will return an :obj:`Address` with an
    offset value of 1, but :meth:`getAddress(5) <.getAddress>` will return an :obj:`Address` 
    instance with an offset value of 90.
     
    
    This collapses a sparse address space with holes into a contiguous list of addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, set: AddressSetView):
        ...

    def getAddress(self, index: typing.Union[jpype.JInt, int]) -> Address:
        """
        Returns the Address at the specified position in the AddressSet.
        
        :param jpype.JInt or int index: the index into the ordered list of addresses within an AddressSet.
        :return: the Address at the specified position.
        :rtype: Address
        """

    @property
    def address(self) -> Address:
        ...


class AddressOverflowException(ghidra.util.exception.UsrException):
    """
    
    An AddressOverflowException occurs when an attempt to
    add or subtract a displacement would result in a value which
    is outside the address space.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs an AddressOverflowException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs an AddressOverflowException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class AddressRangeImpl(AddressRange, java.io.Serializable):
    """
    Implementation of an AddressRange.  An AddressRange is a contiguous
    inclusive set of addresses from some minimum to a maximum address.  Once created
    it is immutable.
    
    
    .. versionadded:: 2000-2-16
    """

    @typing.type_check_only
    class MyAddressIterator(java.util.Iterator[Address]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, range: AddressRange):
        """
        Construct a new AddressRangeImpl from the given range.
        
        :param AddressRange range: the address range to copy.
        """

    @typing.overload
    def __init__(self, start: Address, end: Address):
        """
        Construct an AddressRange with the given start and end address.
        If the start address is before the end address,
        they are swapped to be in order.
        
        :param Address start: start address in the range
        :param Address end: end address in the range
        :raises IllegalArgumentException: thrown if the minimum and
        maximum addresses are not comparable.
        """

    @typing.overload
    def __init__(self, start: Address, length: typing.Union[jpype.JLong, int]):
        """
        Construct an AddressRange with the given start address and length.
        
        :param Address start: start address in the range
        :param jpype.JLong or int length: the length of the range.
        :raises AddressOverflowException: if the length would wrap.
        """


class EmptyAddressRangeIterator(AddressRangeIterator):
    """
    Implementation for an AddressIterator that is empty.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.address.AddressIterator.hasNext()`
        """

    def next(self) -> AddressRange:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.address.AddressIterator.next()`
        """

    def remove(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`java.util.Iterator.remove()`
        """


class AddressRangeToAddressComparator(java.util.Comparator[java.lang.Object]):
    """
    Compares an address against an AddressRange.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def compare(self, obj1: java.lang.Object, obj2: java.lang.Object) -> int:
        """
        Compares an address against an AddressRange.
        
        :param java.lang.Object obj1: the first object to compare. Must be an address or an address range.
        :param java.lang.Object obj2: the second object to compare. Must be an address or an address range.
        :return: a negative integer, zero, or a positive integer
        if the first argument is less than, equal to, or greater than the second.
        :rtype: int
        """


class AddressSetView(java.lang.Iterable[AddressRange]):
    """
    Defines a read-only interface for an address set.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def contains(self, addr: Address) -> bool:
        """
        Test if the address is contained within this set.
        
        :param Address addr: address to test.
        :return: true if addr exists in the set, false otherwise.
        :rtype: bool
        """

    @typing.overload
    def contains(self, start: Address, end: Address) -> bool:
        """
        Test if the given address range is contained in this set.
         
        
        The specified start and end addresses must form a valid range within a single
        :obj:`AddressSpace`.
        
        :param Address start: the first address in the range.
        :param Address end: the last address in the range.
        :return: true if entire range is contained within the set, false otherwise.
        :rtype: bool
        """

    @typing.overload
    def contains(self, rangeSet: AddressSetView) -> bool:
        """
        Test if the given address set is a subset of this set.
        
        :param AddressSetView rangeSet: the set to test.
        :return: true if the entire set is contained within this set, false otherwise.
        :rtype: bool
        """

    def findFirstAddressInCommon(self, set: AddressSetView) -> Address:
        """
        Finds the first address in this collection that is also in the given addressSet.
        
        :param AddressSetView set: the addressSet to search for the first (lowest) common address.
        :return: the first address that is contained in this set and the given set.
        :rtype: Address
        """

    def getAddressCountBefore(self, address: Address) -> int:
        """
        Returns the number of address in this address set before the given address.
        
        :param Address address: the address after the last address to be counted
        :return: the number of address in this address set before the given address
        :rtype: int
        """

    @typing.overload
    def getAddressRanges(self) -> AddressRangeIterator:
        """
        
        
        :return: an iterator over the address ranges in this address set.
        :rtype: AddressRangeIterator
        """

    @typing.overload
    def getAddressRanges(self, forward: typing.Union[jpype.JBoolean, bool]) -> AddressRangeIterator:
        """
        Returns an iterator over the ranges in the specified order
        
        :param jpype.JBoolean or bool forward: the ranges are returned from lowest to highest, otherwise from highest to
                    lowest
        :return: an iterator over all the addresse ranges in the set.
        :rtype: AddressRangeIterator
        """

    @typing.overload
    def getAddressRanges(self, start: Address, forward: typing.Union[jpype.JBoolean, bool]) -> AddressRangeIterator:
        """
        Returns an iterator of address ranges starting with the range that contains the given
        address.
         
        
        If there is no range containing the start address, then the first range will be the next
        range greater than the start address if going forward, otherwise the range less than the
        start address
        
        :param Address start: the address the first range should contain.
        :param jpype.JBoolean or bool forward: true iterators forward, false backwards
        :return: the AddressRange iterator
        :rtype: AddressRangeIterator
        """

    @typing.overload
    def getAddresses(self, forward: typing.Union[jpype.JBoolean, bool]) -> AddressIterator:
        """
        Returns an iterator over all addresses in this set.
        
        :param jpype.JBoolean or bool forward: if true the address are return in increasing order, otherwise in decreasing
                    order.
        :return: an iterator over all addresses in this set.
        :rtype: AddressIterator
        """

    @typing.overload
    def getAddresses(self, start: Address, forward: typing.Union[jpype.JBoolean, bool]) -> AddressIterator:
        """
        Returns an iterator over the addresses in this address set starting at the start address
        
        :param Address start: address to start iterating at in the address set
        :param jpype.JBoolean or bool forward: if true address are return from lowest to highest, else from highest to lowest
        :return: an iterator over the addresses in this address set starting at the start address
        :rtype: AddressIterator
        """

    def getFirstRange(self) -> AddressRange:
        """
        Returns the first range in this set or null if the set is empty
        
        :return: the first range in this set or null if the set is empty
        :rtype: AddressRange
        """

    def getLastRange(self) -> AddressRange:
        """
        Returns the last range in this set or null if the set is empty
        
        :return: the last range in this set or null if the set is empty
        :rtype: AddressRange
        """

    def getMaxAddress(self) -> Address:
        """
        Get the maximum address for this address set.
         
        
        NOTE: An :obj:`AddressRange` should generally not be formed using this address and
        :meth:`getMaxAddress() <.getMaxAddress>` since it may span multiple :obj:`AddressSpace`s.
        
        :return: the maximum address for this set. Returns null if the set is empty.
        :rtype: Address
        """

    def getMinAddress(self) -> Address:
        """
        Get the minimum address for this address set.
         
        
        NOTE: An :obj:`AddressRange` should generally not be formed using this address and
        :meth:`getMaxAddress() <.getMaxAddress>` since it may span multiple :obj:`AddressSpace`s.
        
        :return: the minimum address for this set. Returns null if the set is empty.
        :rtype: Address
        """

    def getNumAddressRanges(self) -> int:
        """
        
        
        :return: the number of address ranges in this set.
        :rtype: int
        """

    def getNumAddresses(self) -> int:
        """
        
        
        :return: the number of addresses in this set.
        :rtype: int
        """

    def getRangeContaining(self, address: Address) -> AddressRange:
        """
        Returns the range that contains the given address
        
        :param Address address: the address for which to find a range.
        :return: the range that contains the given address.
        :rtype: AddressRange
        """

    def hasSameAddresses(self, view: AddressSetView) -> bool:
        """
        Returns true if the given address set contains the same set of addresses as this set.
        
        :param AddressSetView view: the address set to compare.
        :return: true if the given set contains the same addresses as this set.
        :rtype: bool
        """

    def intersect(self, view: AddressSetView) -> AddressSet:
        """
        Computes the intersection of this address set with the given address set.
         
        
        This method does not modify this address set.
        
        :param AddressSetView view: the address set to intersect with.
        :return: AddressSet a new address set that contains all addresses that are contained in both
                this set and the given set.
        :rtype: AddressSet
        """

    def intersectRange(self, start: Address, end: Address) -> AddressSet:
        """
        Computes the intersection of this address set with the given address range.
         
        
        This method does not modify this address set. The specified start and end addresses must form
        a valid range within a single :obj:`AddressSpace`.
        
        :param Address start: start of range
        :param Address end: end of range
        :return: AddressSet a new address set that contains all addresses that are contained in both
                this set and the given range.
        :rtype: AddressSet
        """

    @typing.overload
    def intersects(self, addrSet: AddressSetView) -> bool:
        """
        Determine if this address set intersects with the specified address set.
        
        :param AddressSetView addrSet: address set to check intersection with.
        :return: true if this set intersects the specified addrSet else false
        :rtype: bool
        """

    @typing.overload
    def intersects(self, start: Address, end: Address) -> bool:
        """
        Determine if the start and end range intersects with the specified address set.
         
        
        The specified start and end addresses must form a valid range within a single
        :obj:`AddressSpace`.
        
        :param Address start: start of range
        :param Address end: end of range
        :return: true if the given range intersects this address set.
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        
        
        :return: true if this set is empty.
        :rtype: bool
        """

    @typing.overload
    def iterator(self) -> java.util.Iterator[AddressRange]:
        """
        Returns an iterator over the address ranges in this address set.
        """

    @typing.overload
    def iterator(self, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Iterator[AddressRange]:
        """
        Returns an iterator over the ranges in the specified order
        
        :param jpype.JBoolean or bool forward: the ranges are returned from lowest to highest, otherwise from highest to
                    lowest
        :return: an iterator over all the address ranges in the set.
        :rtype: java.util.Iterator[AddressRange]
        """

    @typing.overload
    def iterator(self, start: Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Iterator[AddressRange]:
        """
        Returns an iterator of address ranges starting with the range that contains the given
        address.
         
        
        If there is no range containing the start address, then the first range will be the next
        range greater than the start address if going forward, otherwise the range less than the
        start address
        
        :param Address start: the address that the first range should contain.
        :param jpype.JBoolean or bool forward: true iterators forward, false backwards
        :return: the AddressRange iterator
        :rtype: java.util.Iterator[AddressRange]
        """

    @typing.overload
    def spliterator(self, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Spliterator[AddressRange]:
        """
        Create a spliterator over the ranges, as in :meth:`iterator(boolean) <.iterator>`
        
        :param jpype.JBoolean or bool forward: true to traverse lowest to highest, false for reverse
        :return: a spliterator over all the address ranges in the set.
        :rtype: java.util.Spliterator[AddressRange]
        """

    @typing.overload
    def spliterator(self, start: Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Spliterator[AddressRange]:
        """
        Create a spliterator over the ranges, as in :meth:`iterator(boolean) <.iterator>`
        
        :param Address start: the address that the first range should contain.
        :param jpype.JBoolean or bool forward: true to traverse lowest to highest, false for reverse
        :return: a spliterator over the address ranges.
        :rtype: java.util.Spliterator[AddressRange]
        """

    @typing.overload
    def stream(self) -> java.util.stream.Stream[AddressRange]:
        """
        Stream the ranges in this set
        
        :return: the stream
        :rtype: java.util.stream.Stream[AddressRange]
        """

    @typing.overload
    def stream(self, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[AddressRange]:
        """
        Stream the ranges in the set forward or backward
        
        :param jpype.JBoolean or bool forward: true to stream lowest to highest, false for reverse
        :return: a stream over all the address ranges in the set.
        :rtype: java.util.stream.Stream[AddressRange]
        """

    @typing.overload
    def stream(self, start: Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[AddressRange]:
        """
        Stream the ranges in the set as in :meth:`iterator(Address, boolean) <.iterator>`
        
        :param Address start: the address that the first range should contain.
        :param jpype.JBoolean or bool forward: true to stream lowest to highest, false for reverse
        :return: a stream over the address ranges.
        :rtype: java.util.stream.Stream[AddressRange]
        """

    def subtract(self, addrSet: AddressSetView) -> AddressSet:
        """
        Computes the difference of this address set with the given address set (this - set).
         
        
        Note that this is not the same as (set - this). This method does not change this address set.
        
        :param AddressSetView addrSet: the set to subtract from this set.
        :return: AddressSet a new address set which contains all the addresses that are in this set,
                but not in the given set.
        :rtype: AddressSet
        """

    @staticmethod
    def trimEnd(set: AddressSetView, addr: Address) -> AddressSetView:
        """
        Trim address set removing all addresses greater-than-or-equal to specified address based upon
        :obj:`Address` comparison.
         
        
        The address set may contain address ranges from multiple address spaces.
        
        :param AddressSetView set: address set to be trimmed
        :param Address addr: trim point. Only addresses less than this address will be returned.
        :return: trimmed address set view
        :rtype: AddressSetView
        """

    @staticmethod
    def trimStart(set: AddressSetView, addr: Address) -> AddressSetView:
        """
        Trim address set removing all addresses less-than-or-equal to specified address based upon
        :obj:`Address` comparison.
         
        
        The address set may contain address ranges from multiple address spaces.
        
        :param AddressSetView set: address set to be trimmed
        :param Address addr: trim point. Only addresses greater than this address will be returned.
        :return: trimmed address set view
        :rtype: AddressSetView
        """

    def union(self, addrSet: AddressSetView) -> AddressSet:
        """
        Computes the union of this address set with the given address set.
         
        
        This method does not change this address set.
        
        :param AddressSetView addrSet: The address set to be unioned with this address set.
        :return: AddressSet A new address set which contains all the addresses from both this set and
                the given set.
        :rtype: AddressSet
        """

    def xor(self, addrSet: AddressSetView) -> AddressSet:
        """
        Computes the exclusive-or of this address set with the given set.
         
        
        This method does not modify this address set.
        
        :param AddressSetView addrSet: address set to exclusive-or with.
        :return: AddressSet a new address set containing all addresses that are in either this set or
                the given set, but not in both sets
        :rtype: AddressSet
        """

    @property
    def maxAddress(self) -> Address:
        ...

    @property
    def rangeContaining(self) -> AddressRange:
        ...

    @property
    def addresses(self) -> AddressIterator:
        ...

    @property
    def addressCountBefore(self) -> jpype.JLong:
        ...

    @property
    def addressRanges(self) -> AddressRangeIterator:
        ...

    @property
    def numAddressRanges(self) -> jpype.JInt:
        ...

    @property
    def lastRange(self) -> AddressRange:
        ...

    @property
    def firstRange(self) -> AddressRange:
        ...

    @property
    def minAddress(self) -> Address:
        ...

    @property
    def numAddresses(self) -> jpype.JLong:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class AddressSetCollection(java.lang.Object):
    """
    This interface represents a collection of AddressSets (actually AddressSetViews). 
    It defines a set of methods that can efficiently be performed on a collection
    of one or more AddressSets.
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, address: Address) -> bool:
        """
        Test if the address is contained within any of the addressSets in this collection.
        
        :param Address address: address to test.
        :return: true if addr exists in the set, false otherwise.
        :rtype: bool
        """

    def findFirstAddressInCommon(self, set: AddressSetView) -> Address:
        """
        Finds the first address in this collection that is also in the given addressSet.
        
        :param AddressSetView set: the addressSet to search for the first (lowest) common address.
        :return: the first address that is contained in this set and the given set.
        :rtype: Address
        """

    def getCombinedAddressSet(self) -> AddressSet:
        """
        Returns a single AddressSet containing the union of all the addressSetViews in the collection.
        """

    def getMaxAddress(self) -> Address:
        """
        Returns the largest address in this collection or null if the collection is empty.
        
        :return: the largest address in this collection or null if the collection is empty.
        :rtype: Address
        """

    def getMinAddress(self) -> Address:
        """
        Returns the smallest address in this collection or null if the collection is empty.
        
        :return: the smallest address in this collection or null if the collection is empty.
        :rtype: Address
        """

    def hasFewerRangesThan(self, rangeThreshold: typing.Union[jpype.JInt, int]) -> bool:
        """
        Tests whether this collection of addressSets has approximately fewer ranges than
        the given threshold. This is probably estimated by adding up the number of ranges
        in each AddressSet in this collections. Returns true if the total is less than the 
        given threshold.
        
        :param jpype.JInt or int rangeThreshold: the number of ranges to test against.
        :return: true if the max possible ranges is less than the given threshold.
        :rtype: bool
        """

    @typing.overload
    def intersects(self, addrSet: AddressSetView) -> bool:
        """
        Determine if any AddressSet in this collection intersects with the specified address set.
        
        :param AddressSetView addrSet: address set to check intersection with.
        """

    @typing.overload
    def intersects(self, start: Address, end: Address) -> bool:
        """
        Determine if range specified by start and end intersects with any of the AddressSets
        in this collection.
        
        :param Address start: start of range
        :param Address end: end of range
        :return: true if the given range intersects this address set collection.
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        Returns true if all the AddressSets in this collection are empty.
        
        :return: true if all the AddressSets in this collection are empty.
        :rtype: bool
        """

    @property
    def maxAddress(self) -> Address:
        ...

    @property
    def minAddress(self) -> Address:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def combinedAddressSet(self) -> AddressSet:
        ...


class DefaultAddressFactory(AddressFactory):
    """
    Keeps track of all the Address spaces in the program and provides
    methods for parsing address strings.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addrSpaces: jpype.JArray[AddressSpace]):
        """
        Constructs a new DefaultAddressFactory.  The default space is assumed to be the first space
        in the array.
        
        :param jpype.JArray[AddressSpace] addrSpaces: array of address spaces for the Program
        """

    @typing.overload
    def __init__(self, addrSpaces: jpype.JArray[AddressSpace], defaultSpace: AddressSpace):
        """
        Constructs a new DefaultAddressFactory with the given spaces and default space.
        
        :param jpype.JArray[AddressSpace] addrSpaces: the set of addressSpaces to manage
        :param AddressSpace defaultSpace: the space to use as the default space. The default space should
        be one of the spaces provided in the addrSpaces array.
        """


class AddressCollectors(java.lang.Object):
    """
    Utilities for using addresses and ranges in streams
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def toAddressSet() -> java.util.stream.Collector[AddressRange, AddressSet, AddressSet]:
        """
        Union a stream of address ranges into a single mutable address set
        
        :return: the address set
        :rtype: java.util.stream.Collector[AddressRange, AddressSet, AddressSet]
        """


@typing.type_check_only
class AbstractAddressSpace(AddressSpace):

    class_: typing.ClassVar[java.lang.Class]

    def getOverlayAddress(self, addr: Address) -> Address:
        """
        No overlay translation necessary, this is a base addressSpace.
         
        (non-Javadoc)
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.address.AddressSpace.getOverlayAddress(ghidra.program.model.address.Address)`
        """

    def getUnique(self) -> int:
        """
        Returns the unique id value for this space.
        """

    def setHasMappedRegisters(self, hasRegisters: typing.Union[jpype.JBoolean, bool]):
        """
        Tag this memory space as having memory mapped registers
        
        :param jpype.JBoolean or bool hasRegisters: true if it has registers, false otherwise
        """

    def setShowSpaceName(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def overlayAddress(self) -> Address:
        ...

    @property
    def unique(self) -> jpype.JInt:
        ...


class ImmutableAddressSet(AddressSetView):
    """
    Immutable implementation of the :obj:`AddressSetView` interface;
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_SET: typing.Final[ImmutableAddressSet]

    def __init__(self, addresses: AddressSetView):
        ...

    @staticmethod
    def asImmutable(view: AddressSetView) -> ImmutableAddressSet:
        ...


class SegmentedAddress(GenericAddress):
    """
    Address class for dealing with (intel) segmented addresses.  The class itself is agnostic
    about the mapping from segmented encoding to flat address offset, it uses the
    SegmentedAddressSpace to perform this mapping. So the same class can be used to represent
    either a real-mode address or a protected-mode address.  The class uses the underlying
    offset field to hold the flat encoding.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getNewAddress(self, byteOffset: typing.Union[jpype.JLong, int]) -> Address:
        """
        Return a new segmented address. An attempt is made to normalize to this addresses segment.
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.address.Address.getNewAddress(long)`
        """

    def getSegment(self) -> int:
        """
        Returns the segment value
        
        :return: int the segment value
        :rtype: int
        """

    def getSegmentOffset(self) -> int:
        """
        Returns the offset within the segment.
        
        :return: the offset value
        :rtype: int
        """

    def normalize(self, seg: typing.Union[jpype.JInt, int]) -> SegmentedAddress:
        """
        Returns a new address that is equivalent to this address using
        the given segment number.
        
        :param jpype.JInt or int seg: the seqment value to normalize to.
        :return: the new address
        :rtype: SegmentedAddress
        """

    @property
    def segment(self) -> jpype.JInt:
        ...

    @property
    def segmentOffset(self) -> jpype.JInt:
        ...

    @property
    def newAddress(self) -> Address:
        ...


class AddressRangeSplitter(AddressRangeIterator):
    """
    :obj:`AddressRangeIterator` that takes a single address range and breaks it down into smaller
    address ranges of a specified maximum size. This is useful for clients that want to break
    down the processing of large address ranges into manageable chunks. For example, searching the
    bytes in memory can be broken so that chunks can be read into reasonably sized buffers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, range: AddressRange, splitSize: typing.Union[jpype.JInt, int], forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param AddressRange range: the address range to split apart
        :param jpype.JInt or int splitSize: the max size of each sub range
        :param jpype.JBoolean or bool forward: if true, the sub ranges will be returned in address order; otherwise they
        will be returned in reverse address order.
        """


class AddressOutOfBoundsException(java.lang.RuntimeException):
    """
    
    An AddressOutOfBoundsException indicates that the Address is
    being used to address Memory which does not exist.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs an AddressOutOfBoundsException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs an AddressOutOfBoundsException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class KeyRange(java.lang.Object):
    """
    Class for holding a range of database keys (long values)
    """

    class_: typing.ClassVar[java.lang.Class]
    minKey: jpype.JLong
    maxKey: jpype.JLong

    def __init__(self, minKey: typing.Union[jpype.JLong, int], maxKey: typing.Union[jpype.JLong, int]):
        """
        Constructs a new key range.  Keys must be ordered and unsigned.
        
        :param jpype.JLong or int minKey: the min key (inclusive)
        :param jpype.JLong or int maxKey: the max key (inclusive)
        """

    def contains(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Tests if the given key is in the range.
        
        :param jpype.JLong or int key: the key to test
        :return: true if the key is in the range, false otherwise
        :rtype: bool
        """

    def length(self) -> int:
        """
        Return the number of keys contained within range.
        
        :return: number of keys contained within range
        :rtype: int
        """


class AddressIteratorAdapter(AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iterator: java.util.Iterator[Address]):
        ...


class SegmentMismatchException(ghidra.util.exception.UsrException):
    """
    ``SegmentMismatchException`` is thrown when two
    addresses with different segments are used in an operation
    that requires the same segment.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs a SegmentMismatchException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs a SegmentMismatchException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class GenericAddress(Address):
    """
    Generic implementation of the Address interface.  Consists of an
    Address Space, an offset, and a namespace id.
    """

    class_: typing.ClassVar[java.lang.Class]


class AddressRange(java.lang.Comparable[AddressRange], java.lang.Iterable[Address]):
    """
    The AddressRange interface is used by any object
    that represents a contiguous inclusive range of
    addresses from a minimum address to a maximum
    address.  The entire range must fall within a 
    single address space.
    
    
    .. versionadded:: 2000-02-16
    
    .. seealso::
    
        | :obj:`AddressRangeImpl`
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def checkValidRange(start: Address, end: Address):
        """
        Change the specified start and end addresses to see if they form a valid
        range within the same :obj:`AddressSpace`.
        
        :param Address start: range start address
        :param Address end: range end address
        """

    def compareTo(self, addr: Address) -> int:
        """
        Compares the given address to this address range.
        
        :param Address addr: the address to compare.
        :return: a negative integer if the address is greater than the maximum range address,
                zero if the address is in the range, and
                a positive integer if the address is less than minimum range address.
        :rtype: int
        """

    def contains(self, addr: Address) -> bool:
        """
        Returns true if the given address is contained in the range.
        """

    def getAddressSpace(self) -> AddressSpace:
        """
        
        
        :return: address space this range resides within
        :rtype: AddressSpace
        """

    def getBigLength(self) -> java.math.BigInteger:
        """
        Returns the number of addresses as a BigInteger.
        
        :return: the number of addresses as a BigInteger.
        :rtype: java.math.BigInteger
        """

    def getLength(self) -> int:
        """
        Returns the number of addresses in the range.
        """

    def getMaxAddress(self) -> Address:
        """
        
        
        :return: the maximum address in the range.
        :rtype: Address
        """

    def getMinAddress(self) -> Address:
        """
        
        
        :return: the minimum address in the range.
        :rtype: Address
        """

    def intersect(self, range: AddressRange) -> AddressRange:
        """
        Computes the intersection of this range with another.
        
        :param AddressRange range: the range to intersect this range with
        :return: AddressRange the intersection or null if the ranges
        do not intersect.
        :rtype: AddressRange
        """

    def intersectRange(self, start: Address, end: Address) -> AddressRange:
        """
        Computes the intersection of this range with another.
        
        :param Address start: of range
        :param Address end: end of range
        :return: AddressRange the intersection or null if the ranges
        do not intersect.
        :rtype: AddressRange
        """

    @typing.overload
    def intersects(self, range: AddressRange) -> bool:
        """
        Returns true if the given range intersects this range.
        
        :param AddressRange range: the range to test for intersection with.
        """

    @typing.overload
    def intersects(self, start: Address, end: Address) -> bool:
        """
        Returns true if the given range intersects this range.
        
        :param Address start: the first address in the range to test for intersection.
        :param Address end: the last address in the range to test for intersection.
        """

    @property
    def maxAddress(self) -> Address:
        ...

    @property
    def bigLength(self) -> java.math.BigInteger:
        ...

    @property
    def addressSpace(self) -> AddressSpace:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def minAddress(self) -> Address:
        ...


class GenericAddressSpace(AbstractAddressSpace):
    """
    Generic implementation of the AddressSpace interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], type: typing.Union[jpype.JInt, int], unique: typing.Union[jpype.JInt, int]):
        """
        Constructs a new GenericAddress space with the given name, bit size, type
        and unique value.
        
        :param java.lang.String or str name: the name of the space.
        :param jpype.JInt or int size: the number of bits required to represent the largest address
                    the space.
        :param jpype.JInt or int type: the type of the space
        :param jpype.JInt or int unique: the unique id for this space.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], type: typing.Union[jpype.JInt, int], unique: typing.Union[jpype.JInt, int], showSpaceName: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new GenericAddress space with the given name, bit size, type
        and unique value.
        
        :param java.lang.String or str name: the name of the space.
        :param jpype.JInt or int size: the number of bits required to represent the largest address
                    the space.
        :param jpype.JInt or int type: the type of the space
        :param jpype.JInt or int unique: the unique id for this space.
        :param jpype.JBoolean or bool showSpaceName: whether to show the space name in toString()
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], unitSize: typing.Union[jpype.JInt, int], type: typing.Union[jpype.JInt, int], unique: typing.Union[jpype.JInt, int]):
        """
        Constructs a new GenericAddress space with the given name, bit size, type
        and unique value.
        
        :param java.lang.String or str name: the name of the space.
        :param jpype.JInt or int size: the number of bits required to represent the largest address
                    the space.
        :param jpype.JInt or int unitSize: number of bytes contained at each addressable location (1, 2,
                    4 or 8)
        :param jpype.JInt or int type: the type of the space
        :param jpype.JInt or int unique: the unique id for this space.
        """


class ProtectedAddressSpace(SegmentedAddressSpace):
    """
    Address Space for (intel) 16-bit protected mode programs. This space produces
    SegmentedAddress objects whose underlying (flat) offset encodes both the
    segment and the segment offset without losing information. There is no possibility
    of alternate encodings for a single address as with real-mode.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], unique: typing.Union[jpype.JInt, int]):
        ...


class AddressObjectMap(java.lang.Object):
    """
    ``AddressObjectMap`` maintains a mapping between addresses in the program
    and Objects that have been discovered.
     
    
    AddressObjectMap uses an ObjectPropertySet to track which addresses belong to
    which Objects. If a range ``[addr1,addr2]`` is assigned to a Object
    with id ``ID`` then ``-ID`` will be placed as the property value at
    ``addr1`` and ``ID`` will be placed at ``addr2``.
    In other words AddressObjectMap marks the beginning of a range belonging to an
    Object with its id (a positive number) and the end with its
    id (a negative number). A single address "range" will just have one entry
    which will contain ``-objID``.
    
    It is important to realize that the current implementation of this cache,
    an address can only belong in one Object.  This could have bad effects
    for BlockModels where code can exist in more than one Object.  If this
    is to be used in that case, one must not just clear an area before adding in
    a range of addresses.  You would need to check if there is anything already
    defined and store a new index in those places that would represent a multi-block
    location.
    
    An AddressObjectMap instance should only be used to map to addresses contained within
    a single program.  The map should be discard if any changes 
    are made to that programs address map (e.g., removing or renaming overlay spaces).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new ``AddressObjectMap`` object.
        """

    @typing.overload
    def addObject(self, obj: java.lang.Object, set: AddressSetView):
        """
        Associates the given object with the given set of addresses
        
        :param java.lang.Object obj: the object to associate
        :param AddressSetView set: the set of address to be associated with the object.
        """

    @typing.overload
    def addObject(self, obj: java.lang.Object, startAddr: Address, endAddr: Address):
        """
        Associates the given object with the given range of addresses
        
        :param java.lang.Object obj: the object to associate
        :param Address startAddr: the first address in the range
        :param Address endAddr: the last address in the range
        """

    def getObjects(self, addr: Address) -> jpype.JArray[java.lang.Object]:
        """
        Get the objs associated with the given address.
        
        :param Address addr: the address at which to get objects.
        :return: an array of objects at the given address.
        :rtype: jpype.JArray[java.lang.Object]
        """

    @typing.overload
    def removeObject(self, obj: java.lang.Object, set: AddressSetView):
        """
        Removes any association with the object and the addresses in the given address set.
        
        :param java.lang.Object obj: the object to remove
        :param AddressSetView set: the set of address from which to remove the object.
        """

    @typing.overload
    def removeObject(self, obj: java.lang.Object, startAddr: Address, endAddr: Address):
        """
        Removes any association with the given object and the given range of addresses.
        
        :param java.lang.Object obj: the object to remove from associations in the given range.
        :param Address startAddr: the first address in the range.
        :param Address endAddr: the last address in the range.
        """

    @property
    def objects(self) -> jpype.JArray[java.lang.Object]:
        ...


class SpecialAddress(GenericAddress):
    """
    Class used to represent "special addresses"
    """

    class_: typing.ClassVar[java.lang.Class]


class AddressSetViewAdapter(AddressSetView):
    """
    This class wraps an address set and provides read-only access to that set.  This class
    is used to ensure that users can not violate the read-only access by casting the object
    to an address set.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, set: AddressSetView):
        """
        Construct an AddressSetViewAdapter for an address set.
        
        :param AddressSetView set: the address set to wrap as a read-only object.
        """

    @typing.overload
    def __init__(self):
        """
        Construct an empty AddressSetViewAdapter.
        """


class AddressRangeChunker(java.lang.Iterable[AddressRange]):
    """
    A class to break a range of addresses into 'chunks' of a give size. This is useful to break-up
    processing of large swaths of addresses, such as when performing work in a background thread.
    Doing this allows the client to iterator over the range, pausing enough to allow the UI to
    update.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, range: AddressRange, chunkSize: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, start: Address, end: Address, chunkSize: typing.Union[jpype.JInt, int]):
        ...

    def stream(self) -> java.util.stream.Stream[AddressRange]:
        """
        Stream the chunks
        
        :return: the stream
        :rtype: java.util.stream.Stream[AddressRange]
        """


class AddressSpace(java.lang.Comparable[AddressSpace]):
    """
    The AddressSpace class is used to represent a unique context for addresses.  Programs can
    have multiple address spaces and address 0 in one space is not the same as address 0 in
    another space.
    """

    class_: typing.ClassVar[java.lang.Class]
    TYPE_CONSTANT: typing.Final = 0
    TYPE_RAM: typing.Final = 1
    TYPE_CODE: typing.Final = 2
    TYPE_UNIQUE: typing.Final = 3
    TYPE_REGISTER: typing.Final = 4
    TYPE_STACK: typing.Final = 5
    TYPE_JOIN: typing.Final = 6
    TYPE_OTHER: typing.Final = 7
    TYPE_SYMBOL: typing.Final = 9
    TYPE_EXTERNAL: typing.Final = 10
    TYPE_VARIABLE: typing.Final = 11
    TYPE_DELETED: typing.Final = 13
    TYPE_UNKNOWN: typing.Final = 14
    TYPE_NONE: typing.Final = 15
    TYPE_IPTR_CONSTANT: typing.Final = 0
    """
    
    
    
    .. seealso::
    
        | :obj:`.TYPE_CONSTANT`
    """

    TYPE_IPTR_INTERNAL: typing.Final = 3
    """
    
    
    
    .. seealso::
    
        | :obj:`.TYPE_UNIQUE`
    """

    TYPE_IPTR_SPACEBASE: typing.Final = 5
    """
    
    
    
    .. seealso::
    
        | :obj:`.TYPE_STACK`
    """

    ID_SIZE_MASK: typing.Final = 112
    ID_SIZE_SHIFT: typing.Final = 4
    ID_TYPE_MASK: typing.Final = 15
    ID_UNIQUE_SHIFT: typing.Final = 7
    OTHER_SPACE: typing.Final[AddressSpace]
    """
    The ``OTHER_SPACE`` is used to store data from the original program file that doesn't
    get loaded into the final memory image and for user-defined spaces.
    """

    EXTERNAL_SPACE: typing.Final[AddressSpace]
    """
    The ``EXTERNAL_SPACE`` is used to contain all external locations (i.e., data and functions) 
    defined within a given library namespace.  All external locations within a program
    are given a unique offset within the EXTERNAL space.
    """

    VARIABLE_SPACE: typing.Final[AddressSpace]
    """
    The ``VARIABLE_SPACE`` is used to contain all variables and parameters 
    defined within a given namespace (i.e., function).  All variables within a program
    are given a unique offset within the VARIABLE space.
    """

    HASH_SPACE: typing.Final[AddressSpace]
    """
    The ``HASH_SPACE`` provides a 60-bit space for encoding of unique hashcodes.
    """

    DEFAULT_REGISTER_SPACE: typing.Final[AddressSpace]
    """
    A language may only define a single REGISTER space.  If one is not defined, this 
    DEFAULT_REGISTER_SPACE definition will be used.
    """


    def add(self, addr: Address, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address (possibly in a new space) by adding the given 
        displacement from the given address.
        
        :param Address addr: original address being subtracted from
        :param jpype.JLong or int displacement: amount to subtract
        :return: the new address
        :rtype: Address
        :raises AddressOutOfBoundsException: if the result does not correspond to any address.
        """

    @typing.overload
    def addNoWrap(self, addr: Address, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by adding displacement to the given address. The
        new address will NOT wrap!
        
        :param Address addr: the original address.
        :param jpype.JLong or int displacement: the displacement to add.
        :return: The new address created by adding displacement to addr.offset.
        :rtype: Address
        :raises AddressOverflowException: if the addition would cause a wrap,
        """

    @typing.overload
    def addNoWrap(self, addr: GenericAddress, displacement: java.math.BigInteger) -> Address:
        """
        Creates a new address by adding displacement to the given address. The
        new address will NOT wrap!
        
        :param GenericAddress addr: the original address.
        :param java.math.BigInteger displacement: the displacement to add.
        :return: The new address created by adding displacement to addr.offset.
        :rtype: Address
        :raises AddressOverflowException: if the addition would cause a wrap,
        """

    def addWrap(self, addr: Address, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by adding displacement to the given address. The
        resulting address may wrap. The new address will wrap in a manner that
        depends on the address space. For a generic address space this will wrap
        at the extents of the address space. For a segmented address space it
        will wrap at the extents of the segment.
        
        :param Address addr: the original address.
        :param jpype.JLong or int displacement: the displacement to add.
        :return: the new address created by adding displacement to addr.offset.
        :rtype: Address
        """

    def addWrapSpace(self, addr: Address, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by adding the displacement to the given 
        address. If the offset is greater than the max offset of the address space, the high
        order bits are masked off, making the address wrap.  For non-segmented addresses this
        will be the same as addWrap().  For segmented addresses, the address will wrap when
        the 20 bit (oxfffff) offset is exceeded, as opposed to when the segment offset is exceeded.
        
        :param Address addr: the address to add the displacement to.
        :param jpype.JLong or int displacement: the displacement to add.
        :return: The new Address formed by adding the displacement to the specified addresst.
        :rtype: Address
        """

    @typing.overload
    def getAddress(self, addrString: typing.Union[java.lang.String, str]) -> Address:
        """
        Parses the String into an address within this address space.
        
        :param java.lang.String or str addrString: the string to parse as an address.
        :return: an address if the string parsed successfully or null if the
        AddressSpace specified in the addrString is not this space.
        :rtype: Address
        :raises AddressFormatException: if the string cannot be parsed or the
        parsed offset is larger than the size for this space.
        """

    @typing.overload
    def getAddress(self, addrString: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> Address:
        """
        Parses the String into an address within this address space.
        
        :param java.lang.String or str addrString: the string to parse as an address.
        :param jpype.JBoolean or bool caseSensitive: specifies if addressSpace names must match case.
        :return: an address if the string parsed successfully or null if the
        AddressSpace specified in the addrString is not this space.
        :rtype: Address
        :raises AddressFormatException: if the string cannot be parsed or the
        parsed offset is larger than the size for this space.
        """

    @typing.overload
    def getAddress(self, byteOffset: typing.Union[jpype.JLong, int]) -> Address:
        """
        Returns a new address in this space with the given byte offset.
        NOTE: This method is the same as invoking getAddress(long byteOffset, false).
        
        :param jpype.JLong or int byteOffset: the byte offset for the new address.
        :return: address with given byte offset
        :rtype: Address
        :raises AddressOutOfBoundsException: if the offset is less than 0 or greater
        than the max offset allowed for this space.
        """

    @typing.overload
    def getAddress(self, offset: typing.Union[jpype.JLong, int], isAddressableWordOffset: typing.Union[jpype.JBoolean, bool]) -> Address:
        """
        Returns a new address in this space with the given offset.  
        NOTE: for those spaces with an addressable unit size other than 1, the address
        returned may not correspond to an addressable unit/word boundary if a byte-offset 
        is specified.
        
        :param jpype.JLong or int offset: the offset for the new address.
        :param jpype.JBoolean or bool isAddressableWordOffset: if true the specified offset is an addressable unit/word offset,
        otherwise offset is a byte offset.  See :meth:`getAddressableUnitSize() <.getAddressableUnitSize>`
        to understand the distinction (i.e., wordOffset = byteOffset * addressableUnitSize).
        :return: address with given offset
        :rtype: Address
        :raises AddressOutOfBoundsException: if the offset is less than 0 or greater
        than the max offset allowed for this space.
        """

    def getAddressInThisSpaceOnly(self, byteOffset: typing.Union[jpype.JLong, int]) -> Address:
        """
        Get a byte address from this address space.  Don't allow overlay spaces
        to remap the address into a base space when the address is not
        contained in the bounds of the overlay region.
        
        :param jpype.JLong or int byteOffset: the byte offset for the new address.
        :return: an address if the offset is valid.
        :rtype: Address
        :raises AddressOutOfBoundsException: if the offset is less than 0 or greater
        than the max offset allowed for this space.
        """

    def getAddressableUnitSize(self) -> int:
        """
        Returns the number of data bytes which correspond to each addressable 
        location within this space (i.e., word-size in bytes).
        NOTE: When transforming a byte-offset to an addressable word
        offset the method :meth:`getAddressableWordOffset(long) <.getAddressableWordOffset>` should
        be used instead of simple division.  When transforming an addressable word-offset
        to a byte-offset simple multiplication may be used.  Neither of these
        transformations perform address space bounds checking.
         
        byteOffset = wordOffset * addressUnitSize
        wordOffset = getAddressableWordOffset(byteOffset)
        """

    def getAddressableWordOffset(self, byteOffset: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the addressable memory word offset which corresponds to the specified 
        memory byte offset.  This method handles some of the issues of unsigned 
        math when stuck using Java's signed long primitives. No space bounds
        checking is performed.
        
        :param jpype.JLong or int byteOffset: memory byte offset
        :return: addressable memory word offset
        :rtype: int
        """

    def getMaxAddress(self) -> Address:
        """
        Get the maximum address allowed for this AddressSpace.
         
        NOTE: Use of this method to identify the region associated with an overlay memory block
        within its overlay address space is no longer supported.  Defined regions of an overlay space
        may now be determined using :meth:`OverlayAddressSpace.getOverlayAddressSet() <OverlayAddressSpace.getOverlayAddressSet>`.
        
        :return: maximum address of this address space.
        :rtype: Address
        """

    def getMinAddress(self) -> Address:
        """
        Get the minimum address allowed for this AddressSpace.
        For a memory space the returned address will have an offset of 0 within this address space.
         
        NOTE: Use of this method to identify the region associated with an overlay memory block
        within its overlay address space is no longer supported.  Defined regions of an overlay space
        may now be determined using :meth:`OverlayAddressSpace.getOverlayAddressSet() <OverlayAddressSpace.getOverlayAddressSet>`.
        
        :return: minimum address of this address space.
        :rtype: Address
        """

    def getName(self) -> str:
        """
        Returns the name of this address space.
        With the exception of :obj:`OverlayAddressSpace`, the name of an address space may not change.
        """

    def getOverlayAddress(self, addr: Address) -> Address:
        """
        Get an address that is relative to this address space.
        If this is an overlay space and the address falls within
        this space, return an address based in this space.
        
        :param Address addr: address possibly falling within this overlay space.
        :return: an address relative to this overlay
        :rtype: Address
        """

    def getPhysicalSpace(self) -> AddressSpace:
        """
        Returns the physical space associated with an address space.  There
        is always exactly one physical space associated with an address
        space (it may be its own physical space).
        
        :return: the associated physical space.
        :rtype: AddressSpace
        """

    def getPointerSize(self) -> int:
        """
        Returns the absolute size of a pointer into this space (in bytes).
        
        
        .. seealso::
        
            | :obj:`Program.getDefaultPointerSize()`for a user adjustable pointer size which is derived from the
            CompilerSpec store pointer size.
        """

    def getSize(self) -> int:
        """
        Returns the number of bits that are used to form the address.  Thus
        the maximum offset for this address space will be 2^size-1.
        """

    def getSpaceID(self) -> int:
        """
        Get the ID for this space
        
        :return: space ID
        :rtype: int
        """

    def getTruncatedAddress(self, offset: typing.Union[jpype.JLong, int], isAddressableWordOffset: typing.Union[jpype.JBoolean, bool]) -> Address:
        """
        Returns a new address in this space with the given offset.  The specified 
        offset will be truncated within the space and will not throw an exception.
        NOTE: for those spaces with an addressable unit size other than 1, the address
        returned may not correspond to a word boundary (addressable unit) if a byte-offset 
        is specified.
        
        :param jpype.JLong or int offset: the offset for the new address.
        :param jpype.JBoolean or bool isAddressableWordOffset: if true the specified offset is an addressable unit/word offset,
        otherwise offset is a byte offset.  See :meth:`getAddressableUnitSize() <.getAddressableUnitSize>`
        to understand the distinction (i.e., wordOffset = byteOffset * addressableUnitSize).
        :return: address with given byte offset truncated to the physical space size
        :rtype: Address
        """

    def getType(self) -> int:
        """
        Returns the type of this address space
        """

    def getUnique(self) -> int:
        """
        Returns the unique index for this address space
        """

    def hasMappedRegisters(self) -> bool:
        """
        Returns true if this space has registers that are mapped into it.
        This means that registers could actually have pointers to them.
        
        :return: true if this space has any registers mapped in it.
        :rtype: bool
        """

    def hasSignedOffset(self) -> bool:
        """
        Returns true if space uses signed offset
        """

    def isConstantSpace(self) -> bool:
        """
        Returns true if this space in the constant space
        """

    def isExternalSpace(self) -> bool:
        """
        Returns true if this space in the EXTERNAL_SPACE
        """

    def isHashSpace(self) -> bool:
        """
        Returns true if this space represents a location in the HASH space.
        """

    def isLoadedMemorySpace(self) -> bool:
        """
        Returns true if this space represents a Loaded Memory
        region (e.g., processor RAM).
        """

    def isMemorySpace(self) -> bool:
        """
        Returns true if this space represents a memory address.  NOTE: It is important to 
        make the distinction between Loaded and Non-Loaded memory addresses.  Program importers
        may create memory blocks associated with Non-Loaded file content which are not associated
        with processor defined memory regions.  While Loaded file content is placed into
        memory blocks which are associated with specific memory address spaces defined
        by the processor language specification.
        
        
        .. seealso::
        
            | :obj:`.isLoadedMemorySpace()`
        
            | :obj:`.isNonLoadedMemorySpace()`
        """

    def isNonLoadedMemorySpace(self) -> bool:
        """
        Returns true if this space represents a Non-Loaded storage region
        for retaining non-loaded file data (e.g., OTHER)
        """

    def isOverlaySpace(self) -> bool:
        """
        Returns true if this addressSpace is an OverlayAddressSpace
        """

    def isRegisterSpace(self) -> bool:
        """
        Returns true if this space represents a register location
        """

    def isStackSpace(self) -> bool:
        """
        Returns true if this space represents a stack location
        """

    def isSuccessor(self, addr1: Address, addr2: Address) -> bool:
        """
        Tests whether addr2 immediately follows addr1.
        
        :param Address addr1: the first address.
        :param Address addr2: the second address.
        """

    def isUniqueSpace(self) -> bool:
        """
        Returns true if this space in the unique space
        """

    @staticmethod
    def isValidName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the specific name is a valid address space name (e.g., allowed
        overlay space name).  NOTE: This does not perform any duplicate name checks.
        
        :param java.lang.String or str name: name
        :return: true if name is a valid space name.
        :rtype: bool
        """

    def isValidRange(self, byteOffset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check the specified address range for validity within this space.
        Segmented spaces will restrict a range to a single segment.
        
        :param jpype.JLong or int byteOffset: 
        :param jpype.JLong or int length: 
        :return: true if range is valid for this space
        :rtype: bool
        """

    def isVariableSpace(self) -> bool:
        """
        Returns true if this space represents a variable location
        """

    def makeValidOffset(self, offset: typing.Union[jpype.JLong, int]) -> int:
        """
        Tests if the offset if valid. If the space is signed, then it sign extends
        the offset.
        
        :param jpype.JLong or int offset: the offset to test and/or sign extend
        :return: the valid positive offset or appropriate sign extended offset.
        :rtype: int
        :raises AddressOutOfBoundsException: if offset is invalid
        """

    def showSpaceName(self) -> bool:
        """
        Returns true if the address should display its addressSpace name.
        """

    @typing.overload
    def subtract(self, addr1: Address, addr2: Address) -> int:
        """
        Calculates the displacement between addr1 and addr2 (addr1 - addr2)
        
        :param Address addr1: the address to subtract from.
        :param Address addr2: the address to subtract.
        :return: the difference. (``addr1.offset - addr2.offset``).
        :rtype: int
        :raises IllegalArgumentException: if the two addresses are not in the
        same address space.
        """

    @typing.overload
    def subtract(self, addr: Address, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address (possibly in a new space) by subtracting the given 
        displacement from the given address.
        
        :param Address addr: original address being subtracted from
        :param jpype.JLong or int displacement: amount to subtract
        :return: the new address
        :rtype: Address
        :raises AddressOutOfBoundsException: if the result does not correspond to any address.
        """

    def subtractNoWrap(self, addr: Address, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by subtracting displacement from addr's offset.
        The new offset will NOT wrap!
        
        :param Address addr: the original address
        :param jpype.JLong or int displacement: the displacement to subtract.
        :return: The new address created by subtracting displacement from addr.offset.
        :rtype: Address
        :raises AddressOverflowException: if the subtraction would cause a wrap,
        """

    def subtractWrap(self, addr: Address, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by subtracting displacement from addr's offset.
        
        :param Address addr: the original address. The new address will wrap in a manner
        that depends on the address space. For a generic address space this will
        wrap at the extents of the address space. For a segmented address space
        it will wrap at the extents of the segment.
        :param jpype.JLong or int displacement: the displacement to subtract.
        :return: a new address created by subtracting the displacement from addr.offset.
        :rtype: Address
        """

    def subtractWrapSpace(self, addr: Address, displacement: typing.Union[jpype.JLong, int]) -> Address:
        """
        Creates a new address by subtracting the displacement from the given 
        address. If the offset is greater than the max offset of the address space, the high
        order bits are masked off, making the address wrap.  For non-segmented addresses this
        will be the same as subtractWrap().  For segmented addresses, the address will wrap when
        the 20 bit (oxfffff) offset is exceeded, as opposed to when the segment offset is exceeded.
        
        :param Address addr: the address to subtract the displacement from.
        :param jpype.JLong or int displacement: the displacement to subtract.
        :return: The new Address formed by subtracting the displacement from the specified address.
        :rtype: Address
        """

    def truncateAddressableWordOffset(self, wordOffset: typing.Union[jpype.JLong, int]) -> int:
        """
        Truncate the specified addressable unit/word offset within this space to produce a 
        valid offset.
        
        :param jpype.JLong or int wordOffset: any addressable unit/word offset
        :return: truncated word offset
        :rtype: int
        """

    def truncateOffset(self, byteOffset: typing.Union[jpype.JLong, int]) -> int:
        """
        Truncate the specified byte offset within this space to produce a valid offset.
        
        :param jpype.JLong or int byteOffset: any byte offset
        :return: truncated byte offset
        :rtype: int
        """

    @property
    def maxAddress(self) -> Address:
        ...

    @property
    def nonLoadedMemorySpace(self) -> jpype.JBoolean:
        ...

    @property
    def externalSpace(self) -> jpype.JBoolean:
        ...

    @property
    def overlayAddress(self) -> Address:
        ...

    @property
    def memorySpace(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> Address:
        ...

    @property
    def variableSpace(self) -> jpype.JBoolean:
        ...

    @property
    def physicalSpace(self) -> AddressSpace:
        ...

    @property
    def stackSpace(self) -> jpype.JBoolean:
        ...

    @property
    def overlaySpace(self) -> jpype.JBoolean:
        ...

    @property
    def minAddress(self) -> Address:
        ...

    @property
    def constantSpace(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def pointerSize(self) -> jpype.JInt:
        ...

    @property
    def hashSpace(self) -> jpype.JBoolean:
        ...

    @property
    def spaceID(self) -> jpype.JInt:
        ...

    @property
    def loadedMemorySpace(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def addressableWordOffset(self) -> jpype.JLong:
        ...

    @property
    def uniqueSpace(self) -> jpype.JBoolean:
        ...

    @property
    def addressInThisSpaceOnly(self) -> Address:
        ...

    @property
    def unique(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def addressableUnitSize(self) -> jpype.JInt:
        ...

    @property
    def registerSpace(self) -> jpype.JBoolean:
        ...


class AddressSet(AddressSetView):
    """
    Class for storing sets of addresses.  This implementation uses a red-black tree where each
    entry node in the tree stores an address range.  The key for an entry node is the minimum address
    of the range and the value is the maximum address of the range.
    """

    @typing.type_check_only
    class RangeCompare(java.lang.Enum[AddressSet.RangeCompare]):

        class_: typing.ClassVar[java.lang.Class]
        RANGE1_COMPLETELY_BEFORE_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END: typing.Final[AddressSet.RangeCompare]
        RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_EQUALS_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2: typing.Final[AddressSet.RangeCompare]
        RANGE1_COMPLETELY_AFTER_RANGE2: typing.Final[AddressSet.RangeCompare]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AddressSet.RangeCompare:
            ...

        @staticmethod
        def values() -> jpype.JArray[AddressSet.RangeCompare]:
            ...


    @typing.type_check_only
    class AddressRangeIteratorAdapter(AddressRangeIterator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, iterator: java.util.Iterator[ghidra.util.datastruct.RedBlackEntry[Address, Address]]):
            ...


    @typing.type_check_only
    class MyAddressIterator(AddressIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Create a new empty Address Set.
        """

    @typing.overload
    def __init__(self, range: AddressRange):
        """
        Create a new Address Set from an address range.
        
        :param AddressRange range: the range of addresses to include in this set.
        """

    @typing.overload
    def __init__(self, start: Address, end: Address):
        """
        Creates a new Address set containing a single range
        The specified start and end addresses must form a valid range within
        a single :obj:`AddressSpace`.
        
        :param Address start: the start address of the range
        :param Address end: the end address of the range
        :raises IllegalArgumentException: if the start and end addresses are in different spaces.  To
        avoid this, use the constructor  :meth:`AddressSet(Program, Address, Address) <.AddressSet>`
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, start: Address, end: Address):
        """
        Creates a new Address set containing a single range.
        Use of this method is generally discouraged since the set of addresses between a start and
        end address not contained within the same :obj:`AddressSpace` may be contain unexpected 
        memory regions.
        
        :param Address start: the start address of the range
        :param Address end: the end address of the range
        :param ghidra.program.model.listing.Program program: the program whose AddressFactory is used to resolve address ranges where the
        start and end are in different address spaces. If you use the constructor with just the
        start and end address and the addresses are in different spaces, you would get an
        IllegalArgumentException.
        """

    @typing.overload
    def __init__(self, set: AddressSetView):
        """
        Create a new Address Set from an existing Address Set.
        
        :param AddressSetView set: Existing Address Set to clone.
        """

    @typing.overload
    def __init__(self, addr: Address):
        """
        Create a new Address containing a single address.
        
        :param Address addr: the address to be included in this address set.
        """

    @typing.overload
    def add(self, address: Address):
        """
        Adds the given address to this set.
        
        :param Address address: the address to add
        """

    @typing.overload
    def add(self, range: AddressRange):
        """
        Add an address range to this set.
        
        :param AddressRange range: the range to add.
        """

    @typing.overload
    def add(self, start: Address, end: Address):
        """
        Adds the range to this set
        
        :param Address start: the start address of the range to add
        :param Address end: the end address of the range to add
        """

    @typing.overload
    def add(self, addressSet: AddressSetView):
        """
        Add all addresses of the given AddressSet to this set.
        
        :param AddressSetView addressSet: set of addresses to add.
        """

    @typing.overload
    def addRange(self, start: Address, end: Address):
        """
        Adds the range to this set
        
        :param Address start: the start address of the range to add
        :param Address end: the end address of the range to add
        :raises IllegalArgumentException: if the start and end addresses are in different spaces.  To
        avoid this, use the constructor  :meth:`addRange(Program, Address, Address) <.addRange>`
        """

    @typing.overload
    def addRange(self, program: ghidra.program.model.listing.Program, start: Address, end: Address):
        """
        Adds a range of addresses to this set.
        
        :param ghidra.program.model.listing.Program program: program whose AddressFactory is used to resolve address ranges that span
        multiple address spaces.
        :param Address start: the start address of the range to add
        :param Address end: the end address of the range to add
        """

    def clear(self):
        """
        Removes all addresses from the set.
        """

    @typing.overload
    def delete(self, range: AddressRange):
        """
        Deletes an address range from this set.
        
        :param AddressRange range: AddressRange to remove from this set
        """

    @typing.overload
    def delete(self, start: Address, end: Address):
        """
        Deletes a range of addresses from this set
        
        :param Address start: the starting address of the range to be removed
        :param Address end: the ending address of the range to be removed (inclusive)
        """

    @typing.overload
    def delete(self, addressSet: AddressSetView):
        """
        Delete all addresses in the given AddressSet from this set.
        
        :param AddressSetView addressSet: set of addresses to remove from this set.
        """

    def deleteFromMin(self, toAddr: Address):
        """
        Delete all addresses from the minimum address in the set up to and including toAddr.
        Addresses less-than-or-equal to specified 
        address based upon :obj:`Address` comparison.
        
        :param Address toAddr: only addresses greater than toAddr will be left in the set.
        """

    def deleteRange(self, start: Address, end: Address):
        """
        Deletes a range of addresses from this set
        
        :param Address start: the starting address of the range to be removed
        :param Address end: the ending address of the range to be removed
        """

    def deleteToMax(self, fromAddr: Address):
        """
        Delete all addresses starting at the fromAddr to the maximum address in the set.
        Addresses greater-than-or-equal to specified 
        address based upon :obj:`Address` comparison.
        
        :param Address fromAddr: only addresses less than fromAddr will be left in the set.
        """

    def printRanges(self) -> str:
        """
        Returns a string displaying the ranges in this set.
        
        :return: a string displaying the ranges in this set.
        :rtype: str
        """

    def toList(self) -> java.util.List[AddressRange]:
        """
        Returns a list of the AddressRanges in this set.
        
        :return: a list of the AddressRanges in this set.
        :rtype: java.util.List[AddressRange]
        """


class AddressMapImpl(java.lang.Object):
    """
    ``AddressMapImpl`` provides a stand-alone AddressMap.
    An AddressMapImpl instance should only be used to decode keys which it has generated.
    If this map is used for a specific program instance, the map should be discard if any changes 
    are made to that programs address map (e.g., removing or renaming overlay spaces).
    """

    @typing.type_check_only
    class ObsoleteOverlaySpace(OverlayAddressSpace):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a new AddressMapImpl with a mapID of 0.
        """

    @typing.overload
    def __init__(self, mapID: typing.Union[jpype.JByte, int], addrFactory: AddressFactory):
        """
        Creates a new AddressMapImpl with the specified mapID
        
        :param jpype.JByte or int mapID: the 8-bit value is placed in the upper 8 bits of every address encoding.
        """

    def decodeAddress(self, value: typing.Union[jpype.JLong, int]) -> Address:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.map.AddressMap.decodeAddress(long)`
        """

    def findKeyRange(self, keyRangeList: java.util.List[KeyRange], addr: Address) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.map.AddressMap.findKeyRange(List, Address)`
        """

    def getKey(self, addr: Address) -> int:
        """
        Generate a unique key for the specified addr.  Only addresses from a single address space or 
        single program should be passed to this method. Only limited checking is not performed in order to 
        improve performance.
        
        :param Address addr: address
        
        .. seealso::
        
            | :obj:`ghidra.program.database.map.AddressMap.getKey(Address, boolean)`
        """

    @typing.overload
    def getKeyRanges(self, start: Address, end: Address) -> java.util.List[KeyRange]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.map.AddressMap.getKeyRanges(Address, Address, boolean)`
        """

    @typing.overload
    def getKeyRanges(self, set: AddressSetView) -> java.util.List[KeyRange]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.map.AddressMap.getKeyRanges(AddressSetView, boolean)`
        """

    def reconcile(self):
        """
        Reconcile address space changes using associated address factory.
        This method should be invoked following an undo/redo (if the
        associated address factory may have changed) or removal of an
        overlay memory block.
        """

    @property
    def key(self) -> jpype.JLong:
        ...

    @property
    def keyRanges(self) -> java.util.List[KeyRange]:
        ...


class SegmentedAddressSpace(GenericAddressSpace):
    """
    Address Space for dealing with (intel) segmented address spaces.
    It understands the mapping between the segmented encoding (seg:offset) and
    the flat address encoding necessary to produce an Address object that can be
    used by other analyses.  This mapping is inherent in protected methods:
    - getDefaultOffsetFromFlat
    - getDefaultSegmentFromFlat
    - getFlatOffset
    - getOffsetFromFlat
    - getAddressInSegment
     
    These 5 methods can be overridden to get a different mapping. This base class is
    set up to map as for x86 16-bit real-mode.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], unique: typing.Union[jpype.JInt, int]):
        """
        Constructs a new Segmented AddressSpace for x86 real-mode, with 21-bit addresses.
        
        :param java.lang.String or str name: is the name of the space
        :param jpype.JInt or int unique: is the unique id for the space.
        """

    def getAddress(self, segment: typing.Union[jpype.JInt, int], segmentOffset: typing.Union[jpype.JInt, int]) -> SegmentedAddress:
        """
        Generates a segmented address with the given segment, offset, and overlay id.
        
        :param jpype.JInt or int segment: the segment
        :param jpype.JInt or int segmentOffset: the offset in the segment
        :return: SegmentedAddress the newly created segmented address.
        :rtype: SegmentedAddress
        """

    def getNextOpenSegment(self, addr: Address) -> int:
        """
        Get the segment index for the first segment whose start address
        comes after the given address
        
        :param Address addr: is the given address
        :return: the segment index
        :rtype: int
        """

    @property
    def nextOpenSegment(self) -> jpype.JInt:
        ...


class AddressRangeIterator(java.util.Iterator[AddressRange], java.lang.Iterable[AddressRange]):
    """
    AddressRangeIterator is used to iterate over some set of addresses.
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]


class AddressFormatException(ghidra.util.exception.UsrException):
    """
    
    An AddressFormatException is thrown when a string that is
    supposed to be an address representation cannot be parsed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs an AddressFormatException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs an AddressFormatException with the specified
        detail message.
        
        :param java.lang.String or str message: A user message.
        """


class OldGenericNamespaceAddress(GenericAddress):
    """
    ``OldGenericNamespaceAddress`` provides a means of instantiating namespace 
    oriented addresses which were previously used for External, Stack and Register addresses.
    This class is needed to facilitate an upgrade since this concept is no longer supported by Address.
    """

    class_: typing.ClassVar[java.lang.Class]
    OLD_MIN_NAMESPACE_ID: typing.Final = 1
    """
    OLD_MIN_NAMESPACE_ID provides the minimum non-global namespace-ID supported by the
    old namespace address.
    """

    OLD_MAX_NAMESPACE_ID: typing.Final = 268435455
    """
    OLD_MAX_NAMESPACE_ID provides the maximum non-global namespace-ID supported by the
    old namespace address.  This was a function of the old 28-bit encoded address
    field used to store this value.
    """


    def __init__(self, addrSpace: AddressSpace, offset: typing.Union[jpype.JLong, int], namespaceID: typing.Union[jpype.JLong, int]):
        ...

    def getGlobalAddress(self) -> Address:
        """
        Returns global address (i.e., GenericAddress) for this address.
        """

    @staticmethod
    def getMaxAddress(addrSpace: AddressSpace, namespaceID: typing.Union[jpype.JLong, int]) -> Address:
        """
        Returns maximum namespace address within the specified address space for upgrade iterators.
        For a signed stack space, the negative region is treated as positive for the purpose of 
        identifying the maximum address key encoding.
        
        :param AddressSpace addrSpace: address space
        :param jpype.JLong or int namespaceID: 
        :return: maximum address
        :rtype: Address
        """

    @staticmethod
    def getMinAddress(addrSpace: AddressSpace, namespaceID: typing.Union[jpype.JLong, int]) -> Address:
        """
        Returns minimum namespace address within the specified address space for upgrade iterators.
        A minimum offset of 0x0 is always assumed.
        
        :param AddressSpace addrSpace: address space
        :param jpype.JLong or int namespaceID: 
        :return: minimum address
        :rtype: Address
        """

    def getNamespaceID(self) -> int:
        """
        Returns the namespace ID assigned to this address.
        This namespace ID generally corresponds to a Function.
        """

    @property
    def namespaceID(self) -> jpype.JLong:
        ...

    @property
    def globalAddress(self) -> Address:
        ...


class AddressIterator(java.util.Iterator[Address], java.lang.Iterable[Address]):
    """
    
    AddressIterator is used to iterate over some set of addresses.
    
     
    Note: The next and previous methods return *Address*s.
     
    
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_ITERATOR: typing.Final[AddressIterator]

    def hasNext(self) -> bool:
        """
        Checks if there is a next address in the iteration.
        
        :return: true if there is a next address.
        :rtype: bool
        """

    def next(self) -> Address:
        """
        Get the next address.
         
        NOTE: This deviates from the standard :obj:`Iterator` interface
        by returning null instead of throwing an exception.
        
        :return: the next address in the iteration.
        :rtype: Address
        """



__all__ = ["Mark", "GlobalNamespace", "SingleAddressSetCollection", "GlobalSymbol", "AddressFactory", "EmptyAddressIterator", "OverlayAddressSpace", "Address", "AddressSetMapping", "AddressOverflowException", "AddressRangeImpl", "EmptyAddressRangeIterator", "AddressRangeToAddressComparator", "AddressSetView", "AddressSetCollection", "DefaultAddressFactory", "AddressCollectors", "AbstractAddressSpace", "ImmutableAddressSet", "SegmentedAddress", "AddressRangeSplitter", "AddressOutOfBoundsException", "KeyRange", "AddressIteratorAdapter", "SegmentMismatchException", "GenericAddress", "AddressRange", "GenericAddressSpace", "ProtectedAddressSpace", "AddressObjectMap", "SpecialAddress", "AddressSetViewAdapter", "AddressRangeChunker", "AddressSpace", "AddressSet", "AddressMapImpl", "SegmentedAddressSpace", "AddressRangeIterator", "AddressFormatException", "OldGenericNamespaceAddress", "AddressIterator"]
