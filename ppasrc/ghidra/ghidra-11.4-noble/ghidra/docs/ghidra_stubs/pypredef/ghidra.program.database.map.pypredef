from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.database.mem
import ghidra.program.database.util
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class AddressMapDBAdapterV0(AddressMapDBAdapter):
    """
    Adapter version 0 (the first real adapter)
    """

    class_: typing.ClassVar[java.lang.Class]


class AddressKeyAddressIterator(ghidra.program.model.address.AddressIterator):
    """
    Converts an AddressKeyIterator or an addressKeyAddressIterator into an AddressIterator
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, keyIter: db.DBLongIterator, forward: typing.Union[jpype.JBoolean, bool], addrMap: AddressMap, errHandler: db.util.ErrorHandler):
        """
        Constructor.
        
        :param db.DBLongIterator keyIter: address key iterator, may be null.  All long values must decode properly with the specified addrMap.
        :param jpype.JBoolean or bool forward: true to iterate in the direction of increasing addresses.
        :param AddressMap addrMap: address map
        :param db.util.ErrorHandler errHandler: IO error handler (may be null)
        """


@typing.type_check_only
class AddressMapDBAdapterNoTable(AddressMapDBAdapter):
    """
    Adapter for when no addr map database existed.
    """

    @typing.type_check_only
    class FactoryBasedAddressMap(AddressMap):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class AddressIndexKeyIterator(db.DBLongIterator):
    """
    Iterator of indexed fields that are addresses. The longs returned are the address longs.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Empty iterator.
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, atStart: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexKeyIterator.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param jpype.JBoolean or bool atStart: if true, iterates forward, otherwise iterates backwards.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, minAddr: ghidra.program.model.address.Address, maxAddr: ghidra.program.model.address.Address, atStart: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexKeyIterator for a range of addresses.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address minAddr: the first address in the range to iterate over.
        :param ghidra.program.model.address.Address maxAddr: the last address in the range to iterator over.
        :param jpype.JBoolean or bool atStart: if true, iterates forward, otherwise iterates backwards.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, set: ghidra.program.model.address.AddressSetView, atStart: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexKeyIterator for a set of addresses.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.AddressSetView set: the set of addresses to iterator over.
        :param jpype.JBoolean or bool atStart: if true, iterates forward, otherwise iterates backwards.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, absolute: typing.Union[jpype.JBoolean, bool], set: ghidra.program.model.address.AddressSetView, atStart: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexKeyIterator for a set of addresses
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param jpype.JBoolean or bool absolute: if true, only absolute memory address encodings are considered, otherwise 
        only standard/relocatable address encodings are considered.
        :param ghidra.program.model.address.AddressSetView set: the set of addresses to iterator over or null for all addresses.
        :param jpype.JBoolean or bool atStart: if true, iterates forward, otherwise iterates backwards.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, start: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexKeyIterator starting at a given address.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address start: the starting address for the iterator.
        :param jpype.JBoolean or bool before: if true, positions the iterator before start, otherwise positions it after start.
        :raises IOException: if a database io error occurs.
        """


@typing.type_check_only
class AddressMapDBAdapter(java.lang.Object):
    """
    Database adapter for address map
    """

    @typing.type_check_only
    class AddressMapEntry(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, index: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], segment: typing.Union[jpype.JInt, int], deleted: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]


class AddressRecordDeleter(java.lang.Object):
    """
    Static methods to delete records from a table. Handles subtle issues with image base causing
    address to "wrap".
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def deleteRecords(table: db.Table, addrMap: AddressMap, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Deletes the records the fall within the given range. Uses the address map to convert the
        address range into 1 or more key ranges. (Address ranges may not be continuous after
        converting to long space).
        NOTE: Absolute key encodings are not handled currently !!
        
        :param db.Table table: the database table to delete records from.
        :param AddressMap addrMap: the address map used to convert addresses into long keys.
        :param ghidra.program.model.address.Address start: the start address in the range.
        :param ghidra.program.model.address.Address end: the end address in the range.
        :raises IOException: if a database io error occurs.
        """

    @staticmethod
    @typing.overload
    def deleteRecords(table: db.Table, colIx: typing.Union[jpype.JInt, int], addrMap: AddressMap, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, filter: ghidra.program.database.util.RecordFilter) -> bool:
        """
        Deletes the records that have indexed address fields that fall within the given range.
        Uses the address map to convert the
        address range into 1 or more key ranges. (Address ranges may not be continuous after
        converting to long space).
        NOTE: Absolute key encodings are not handled currently !!
        
        :param db.Table table: the database table to delete records from.
        :param jpype.JInt or int colIx: the column that has indexed addresses.
        :param AddressMap addrMap: the address map used to convert addresses into long keys.
        :param ghidra.program.model.address.Address start: the start address in the range.
        :param ghidra.program.model.address.Address end: the end address in the range.
        :raises IOException: if a database io error occurs.
        """


class AddressMapDB(AddressMap):
    """
    Class used to map addresses to longs and longs to addresses. Several different encodings
    are depending on the nature of the address to be converted.
    The upper 4 bits in the long are used to specify the encoding used. Currently the encoding are:
    0 - use the original ghidra encoding - used for backwards compatibility.
    1 - absolute encoding - ignores the image base - used only by the memory map.
    2 - relocatable - most common encoding - allows address to move with the image base.
    3 - register - used to encode register addresses
    4 - stack - used to encode stack addresses (includes namespace information to make them unique between functions)
    5 - external - used to encode addresses in another program
    15 - no address - used to represent the null address or a meaningless address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, openMode: ghidra.framework.data.OpenMode, factory: ghidra.program.model.address.AddressFactory, baseImageOffset: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new AddressMapDB object
        
        :param db.DBHandle handle: the handle to the database
        :param ghidra.framework.data.OpenMode openMode: the mode that program was opened.
        :param ghidra.program.model.address.AddressFactory factory: the address factory containing all the address spaces for the program.
        :param jpype.JLong or int baseImageOffset: the current image base offset.
        :param ghidra.util.task.TaskMonitor monitor: the progress monitory used for upgrading.
        :raises IOException: thrown if a dabase io error occurs.
        :raises VersionException: if the database version does not match the expected version.
        """

    def decodeAddress(self, value: typing.Union[jpype.JLong, int], useMemorySegmentation: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        """
        Returns the address that was used to generate the given long key. (If the image base was
        moved, then a different address is returned unless the value was encoded using the
        "absoluteEncoding" method
        
        :param jpype.JLong or int value: the long value to convert to an address.
        :param jpype.JBoolean or bool useMemorySegmentation: if true and the program's default address space is segmented (i.e., SegmentedAddressSpace).
        the address returned will be normalized to defined segmented memory blocks if possible.  This parameter should 
        generally always be true except when used by the Memory map objects to avoid recursion problems.
        :return: decoded address
        :rtype: ghidra.program.model.address.Address
        """

    def deleteOverlaySpace(self, name: typing.Union[java.lang.String, str]):
        """
        Delete the specified overlay space from this address map.
        
        :param java.lang.String or str name: overlay space name (must be unique among all space names within this map)
        :raises IOException: if IO error occurs
        """

    def getOldAddressMap(self) -> AddressMap:
        """
        Returns an address map which may be used during the upgrade of old address
        encodings.  If the address map is up-to-date, then this method will return
        this instance of AddressMapDB.
        """

    def invalidateCache(self):
        """
        Clears any cached values.
        
        :raises IOException: if an IO error occurs
        """

    def memoryMapChanged(self, mem: ghidra.program.database.mem.MemoryMapDB):
        """
        Notification when the memory map changes.  If we are segemented, we need to update our
        list of address ranges used for address normalization.
        
        :param ghidra.program.database.mem.MemoryMapDB mem: the changed memory map.
        """

    def renameOverlaySpace(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Rename an existing overlay space.
        
        :param java.lang.String or str oldName: old overlay name
        :param java.lang.String or str newName: new overlay name (must be unique among all space names within this map)
        :raises IOException: if IO error occurs
        """

    def setImageBase(self, base: ghidra.program.model.address.Address):
        """
        Sets the image base, effectively changing the mapping between addresses and longs.
        
        :param ghidra.program.model.address.Address base: the new base address.
        """

    def setLanguage(self, newLanguage: ghidra.program.model.lang.Language, addrFactory: ghidra.program.database.ProgramAddressFactory, translator: ghidra.program.util.LanguageTranslator):
        """
        Converts the current base addresses to addresses compatible with the new language.
        
        :param ghidra.program.model.lang.Language newLanguage: the new language to use.
        :param ghidra.program.database.ProgramAddressFactory addrFactory: the new AddressFactory.
        :param ghidra.program.util.LanguageTranslator translator: translates address spaces from the old language to the new language.
        :raises IOException: if IO error occurs
        """

    @property
    def oldAddressMap(self) -> AddressMap:
        ...


@typing.type_check_only
class AddressMapDBAdapterV1(AddressMapDBAdapter):
    """
    Adapter version 0 (the first real adapter)
    """

    class_: typing.ClassVar[java.lang.Class]


class AddressKeyRecordIterator(db.RecordIterator):
    """
    Returns a RecordIterator over records that are address keyed.  Various constructors allow
    the iterator to be restricted to an address range or address set and optionally to be
    positioned at some starting address.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, table: db.Table, addrMap: AddressMap):
        """
        Construcs a new AddressKeyRecordIterator that iterates over all records in ascending order.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the table to iterate.
        :param AddressMap addrMap: the address map
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, addrMap: AddressMap, startAddr: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]):
        """
        Construcs a new AddressKeyRecordIterator that iterates over records starting at given 
        start address.  Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the table to iterate.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address startAddr: the address at which to position the iterator.  The iterator will be positioned 
        either before or after the start address depending on the before parameter.
        :param jpype.JBoolean or bool before: if true, the iterator will be positioned before the start address, otherwise
        it will be positioned after the start address.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, addrMap: AddressMap, minAddr: ghidra.program.model.address.Address, maxAddr: ghidra.program.model.address.Address, startAddr: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressKeyRecordIterator that iterates over records that are within an
        address range with an optional start address within that range.  
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the table to iterate.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address minAddr: the minimum address in the range.
        :param ghidra.program.model.address.Address maxAddr: tha maximum address in the range.
        :param ghidra.program.model.address.Address startAddr: the address at which to position the iterator.  The iterator will be positioned 
        either before or after the start address depending on the before parameter. If this parameter
        is null, then the iterator will start either before the min address or after the max address 
        depending on the before parameter.
        :param jpype.JBoolean or bool before: if true, the iterator will be positioned before the start address, otherwise
        it will be positioned after the start address. If the start address is null, then if the before
        parameter is true, the iterator is positioned before the min. Otherwise the iterator is 
        positioned after the max address.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, addrMap: AddressMap, set: ghidra.program.model.address.AddressSetView, startAddr: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]):
        """
        Construcs a new AddressKeyRecordIterator that iterates over records that are contained in
        an address set with an optional start address within that set.  
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the table to iterate.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.AddressSetView set: the address set to iterate over.
        :param ghidra.program.model.address.Address startAddr: the address at which to position the iterator.  The iterator will be positioned 
        either before or after the start address depending on the before parameter. If this parameter
        is null, then the iterator will start either before the min address or after the max address 
        depending on the before parameter.
        :param jpype.JBoolean or bool before: if true, the iterator will be positioned before the start address, otherwise
        it will be positioned after the start address. If the start address is null, then if the before
        parameter is true, the iterator is positioned before the min. Otherwise the iterator is 
        postioned after the max address.
        :raises IOException: if a database io error occurs.
        """

    def iterator(self) -> java.util.Iterator[db.DBRecord]:
        ...


class AddressIndexPrimaryKeyIterator(db.DBFieldIterator):
    """
    Long iterator over indexed addresses. The longs are primary keys returned ordered and restrained
    by the address field they contain
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Empty iterator constructor
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, atStart: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexPrimaryKeyIterator.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param jpype.JBoolean or bool atStart: if true, iterates forward, otherwise iterates backwards.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, minAddr: ghidra.program.model.address.Address, maxAddr: ghidra.program.model.address.Address, atStart: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexPrimaryKeyIterator for a range of addresses.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address minAddr: the first address in the range to iterate over.
        :param ghidra.program.model.address.Address maxAddr: the last address in the range to iterator over.
        :param jpype.JBoolean or bool atStart: if true, iterates forward, otherwise iterates backwards.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, set: ghidra.program.model.address.AddressSetView, atStart: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexPrimaryKeyIterator for a set of addresses.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.AddressSetView set: the set of addresses to iterator over.
        :param jpype.JBoolean or bool atStart: if true, iterates forward, otherwise iterates backwards.
        :raises IOException: if a database io error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, indexCol: typing.Union[jpype.JInt, int], addrMap: AddressMap, start: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new AddressIndexPrimaryKeyIterator starting at a given address.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table containing indexed addresses.
        :param jpype.JInt or int indexCol: the column that contains indexed addresses.
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address start: the starting address for the iterator.
        :param jpype.JBoolean or bool before: if true, positions the iterator before start, otherwise positions it after start.
        :raises IOException: if a database io error occurs.
        """


class AddressMap(java.lang.Object):
    """
    Address map interface add methods need by the program database implementation to manage its address map.
    NOTE: Objects implementing this interface are not intended for use outside of the
    ``ghidra.program.database`` packages.
    """

    class_: typing.ClassVar[java.lang.Class]
    INVALID_ADDRESS_KEY: typing.Final = -1
    """
    Reserved key for an invalid key.
    """


    def decodeAddress(self, value: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Returns the address that was used to generate the given long key. (If the image base was
        moved, then a different address is returned unless the value was encoded using the
        "absoluteEncoding" method.  If the program's default address space is segmented (i.e., SegmentedAddressSpace).
        the address returned will be always be normalized to defined segmented memory blocks if possible.
        
        :param jpype.JLong or int value: the long value to convert to an address.
        :return: address decoded from long
        :rtype: ghidra.program.model.address.Address
        """

    def findKeyRange(self, keyRangeList: java.util.List[ghidra.program.model.address.KeyRange], addr: ghidra.program.model.address.Address) -> int:
        """
        Search for addr within the "sorted" keyRangeList and return the index of the
        keyRange which contains the specified addr.
        
        :param java.util.List[ghidra.program.model.address.KeyRange] keyRangeList: key range list to search
        :param ghidra.program.model.address.Address addr: address or null
        :return: index of the keyRange within the keyRangeList which contains addr 
        if it is contained in the list; otherwise, ``(-(*insertion point*) - 1)``. 
        The *insertion point* is defined as the point at which the
        addr would be inserted into the list: the index of the first keyRange
        greater than addr, or ``keyRangeList.size()``, if all
        keyRanges in the list are less than the specified addr.  Note
        that this guarantees that the return value will be >= 0 if
        and only if the addr is found within a keyRange.  
        An addr of null will always result in a returned index of -1.
        :rtype: int
        """

    def getAbsoluteEncoding(self, addr: ghidra.program.model.address.Address, create: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get the database key associated with the given absolute address.
        This key uniquely identifies an absolute location within the program.
        If the requested key does not exist and create is false, INVALID_ADDRESS_KEY
        will be returned.  Note that nothing should ever be stored using the returned key unless
        create is true.
        
        :param ghidra.program.model.address.Address addr: the address for which to get a database key.
        :param jpype.JBoolean or bool create: true if a new key may be generated
        :return: the database key for the given address or INVALID_ADDRESS_KEY if 
        create is false and one does not exist for the specified addr.
        :rtype: int
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Returns the address factory associated with this map.
        Null may be returned if map not associated with a specific address factory.
        
        :return: associated :obj:`AddressFactory` or null
        :rtype: ghidra.program.model.address.AddressFactory
        """

    def getImageBase(self) -> ghidra.program.model.address.Address:
        """
        Returns the current image base setting.
        """

    def getKey(self, addr: ghidra.program.model.address.Address, create: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get the database key associated with the given relative address.
        This key uniquely identifies a relative location within the program.
        If the program's image base is moved to another address, this key will map to a new
        address that is the same distance to the new base as the old address was to the old base.
        If the requested key does not exist and create is false, INVALID_ADDRESS_KEY
        will be returned.  Note that nothing should ever be stored using the returned key unless
        create is true.
        
        :param ghidra.program.model.address.Address addr: the address for which to get a database key.
        :param jpype.JBoolean or bool create: true if a new key may be generated
        :return: the database key for the given address or INVALID_ADDRESS_KEY if 
        create is false and one does not exist for the specified addr.
        :rtype: int
        """

    @typing.overload
    def getKeyRanges(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, create: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.address.KeyRange]:
        """
        Generates a properly ordered list of database key ranges for a
        a specified address range.  If absolute encodings are requested, 
        only memory addresses will be included.  Returned key ranges are 
        generally intended for read-only operations since new keys will 
        never be generated.  The returned key ranges will correspond 
        to those key ranges which have previously been created within 
        the specified address range and may represent a much smaller subset 
        of addresses within the specified range. 
        NOTE: if the create parameter is true, the given range must not extend in the upper 32 bits 
        by more than 1 segment. For example, range(0x0000000000000000 - 0x0000000100000000) 
        is acceptable, but the range (0x0000000000000000 - 0x0000000200000000) is not because the
        upper 32 bits differ by 2.
        
        :param ghidra.program.model.address.Address start: the start address of the range
        :param ghidra.program.model.address.Address end: maximum address of range
        :param jpype.JBoolean or bool create: true if a new keys may be generated, otherwise returned 
        key-ranges will be limited to those already defined. And if true, the range will be limited
        to a size of 2^32 so that at most it creates two new address bases
        :return: "sorted" list of KeyRange objects
        :rtype: java.util.List[ghidra.program.model.address.KeyRange]
        :raises UnsupportedOperationException: if the given range is so large that the upper 32 bit
        segments differ by more than 1.
        """

    @typing.overload
    def getKeyRanges(self, set: ghidra.program.model.address.AddressSetView, create: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.address.KeyRange]:
        """
        Generates a properly ordered list of database key ranges for a
        a specified address set.  If absolute encodings are requested, 
        only memory addresses will be included.
        
        :param ghidra.program.model.address.AddressSetView set: address set or null for all addresses.  May not be null if ``create`` is true.
        :param jpype.JBoolean or bool create: true if a new keys may be generated, otherwise returned 
        key-ranges will be limited to those already defined.
        :return: "sorted" list of KeyRange objects
        :rtype: java.util.List[ghidra.program.model.address.KeyRange]
        """

    @typing.overload
    def getKeyRanges(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, absolute: typing.Union[jpype.JBoolean, bool], create: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.address.KeyRange]:
        """
        Generates a properly ordered list of database key ranges for a
        a specified address range.  If absolute encodings are requested, 
        only memory addresses will be included.
        
        :param ghidra.program.model.address.Address start: minimum address of range
        :param ghidra.program.model.address.Address end: maximum address of range
        :param jpype.JBoolean or bool absolute: if true, absolute key encodings are returned, otherwise 
        standard/relocatable address key encodings are returned.
        :param jpype.JBoolean or bool create: true if a new keys may be generated, otherwise returned 
        key-ranges will be limited to those already defined.
        :return: "sorted" list of KeyRange objects
        :rtype: java.util.List[ghidra.program.model.address.KeyRange]
        """

    @typing.overload
    def getKeyRanges(self, set: ghidra.program.model.address.AddressSetView, absolute: typing.Union[jpype.JBoolean, bool], create: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.address.KeyRange]:
        """
        Generates a properly ordered list of database key ranges for a
        a specified address set.  If absolute encodings are requested, 
        only memory addresses will be included.
        
        :param ghidra.program.model.address.AddressSetView set: address set or null for all addresses.  May not be null if ``create`` is true.
        :param jpype.JBoolean or bool absolute: if true, absolute key encodings are returned, otherwise 
        standard/relocatable address key encodings are returned.
        :param jpype.JBoolean or bool create: true if a new keys may be generated, otherwise returned 
        key-ranges will be limited to those already defined.
        :return: "sorted" list of KeyRange objects
        :rtype: java.util.List[ghidra.program.model.address.KeyRange]
        """

    def getOldAddressMap(self) -> AddressMap:
        """
        Returns an address map capable of decoding old address encodings.
        """

    def isUpgraded(self) -> bool:
        """
        Returns true if this address map has been upgraded.
        """

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def upgraded(self) -> jpype.JBoolean:
        ...

    @property
    def imageBase(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def oldAddressMap(self) -> AddressMap:
        ...


class AddressKeyIterator(db.DBLongIterator):
    """
    Iterator of primary keys that are addresses. The longs returned are the address longs.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_ITERATOR: typing.Final[AddressKeyIterator]

    @typing.overload
    def __init__(self, table: db.Table, addrMap: AddressMap, before: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs  new AddressKeyIterator that iterates over all addresses.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table key by addresses
        :param AddressMap addrMap: the address map
        :param jpype.JBoolean or bool before: positions the iterator before the min value,otherwise after the max value.
        :raises IOException: if a database error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, addrMap: AddressMap, startAddr: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs  new AddressKeyIterator that iterates overal all addresses and is initially
        positioned at startAddr.  Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table key by addresses
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address startAddr: the address at which to position the iterator.
        :param jpype.JBoolean or bool before: positions the iterator before the start address,otherwise after
        the start address. If the start address is null, then before positions the iterator before
        the lowest address, !before positions the iterater after the largest address.
        :raises IOException: if a database error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, addrMap: AddressMap, minAddr: ghidra.program.model.address.Address, maxAddr: ghidra.program.model.address.Address, startAddr: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs  new AddressKeyIterator that iterates over an address range.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table key by addresses
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address minAddr: the first address in the range.
        :param ghidra.program.model.address.Address maxAddr: the last address in the range.
        :param ghidra.program.model.address.Address startAddr: the address at which to position the iterator, can be null. The exact
        position of the iterator depends on the before parameter.
        :param jpype.JBoolean or bool before: positions the iterator before the start address,otherwise after
        the start address. If the start address is null, then before positions the iterator before
        the lowest address, !before positions the iterater after the largest address.
        :raises IOException: if a database error occurs.
        """

    @typing.overload
    def __init__(self, table: db.Table, addrMap: AddressMap, set: ghidra.program.model.address.AddressSetView, startAddr: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs  new AddressKeyIterator to iterate over an address set.
        Memory addresses encoded as Absolute are not included.
        
        :param db.Table table: the database table key by addresses
        :param AddressMap addrMap: the address map
        :param ghidra.program.model.address.AddressSetView set: the address set to iterator over (may be null for all defined memory)
        :param ghidra.program.model.address.Address startAddr: the address at which to position the iterator, can be null. The exact
        position of the iterator depends on the before parameter.
        :param jpype.JBoolean or bool before: positions the iterator before the start address,otherwise after
        the start address. If the start address is null, then before positions the iterator before
        the lowest address, !before positions the iterater after the largest address.
        :raises IOException: if a database error occurs.
        """


class NormalizedAddressSet(ghidra.program.model.address.AddressSetView):
    """
    AddressSetView implementation that handles image base changes. NOTE: THIS IMPLEMENTATION
    ASSUMES THAT ONLY ADDRESS RANGES THAT ARE PART OF THE MEMORY MAP WILL BE ADDED TO THIS
    ADDRESS SET. IT IS INTENDED FOR USE BY THE CHANGE SET.
    """

    @typing.type_check_only
    class MyAddressIterator(ghidra.program.model.address.AddressIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyAddressRangeIterator(ghidra.program.model.address.AddressRangeIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addrMap: AddressMap):
        """
        Constructs a NormalizedAddressSet
        
        :param AddressMap addrMap: the address map
        """

    @typing.overload
    def add(self, addr: ghidra.program.model.address.Address):
        """
        Adds the address to the set.
        
        :param ghidra.program.model.address.Address addr: the address to add
        """

    @typing.overload
    def add(self, set: ghidra.program.model.address.AddressSetView):
        """
        Adds the addressSet to this set.
        
        :param ghidra.program.model.address.AddressSetView set: the set of addresses to add/
        """

    @typing.overload
    def add(self, range: ghidra.program.model.address.AddressRange):
        """
        Adds the address range to this set.
        
        :param ghidra.program.model.address.AddressRange range: the range to add.
        """

    def addRange(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address):
        """
        Adds the address range to this set.
        
        :param ghidra.program.model.address.Address startAddr: the first address in the range to add.
        :param ghidra.program.model.address.Address endAddr: the last address in the range to add.
        """

    def clear(self):
        """
        Removes all addresses from this set.
        """

    def delete(self, view: ghidra.program.model.address.AddressSetView):
        """
        REmoves all the addresses in the given address set from this set.
        
        :param ghidra.program.model.address.AddressSetView view: the set of addresses to remove.
        """



__all__ = ["AddressMapDBAdapterV0", "AddressKeyAddressIterator", "AddressMapDBAdapterNoTable", "AddressIndexKeyIterator", "AddressMapDBAdapter", "AddressRecordDeleter", "AddressMapDB", "AddressMapDBAdapterV1", "AddressKeyRecordIterator", "AddressIndexPrimaryKeyIterator", "AddressMap", "AddressKeyIterator", "NormalizedAddressSet"]
