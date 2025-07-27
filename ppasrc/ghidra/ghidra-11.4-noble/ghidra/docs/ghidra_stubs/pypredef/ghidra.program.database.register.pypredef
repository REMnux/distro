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
import ghidra.program.database.code
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util
import ghidra.util.datastruct
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class InMemoryRangeMapAdapter(ghidra.program.util.RangeMapAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IndexToAddressRangeIteratorAdapter(ghidra.program.model.address.AddressRangeIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addressMap: ghidra.program.database.map.AddressMap, it: ghidra.util.datastruct.IndexRangeIterator):
        """
        Constructs a new IndexToAddressRangeIteratorAdapter given an AddressMap and 
        IndexRangeIterator
        
        :param ghidra.program.database.map.AddressMap addressMap: the address map
        :param ghidra.util.datastruct.IndexRangeIterator it: the IndexRangeIterator
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.address.AddressRangeIterator.hasNext()`
        """

    def iterator(self) -> java.util.Iterator[ghidra.program.model.address.AddressRange]:
        ...

    def next(self) -> ghidra.program.model.address.AddressRange:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.address.AddressRangeIterator.next()`
        """

    def remove(self):
        ...


@typing.type_check_only
class AddressValueRange(java.lang.Comparable[AddressValueRange[T]], typing.Generic[T]):
    """
    Associates an integer value with a numeric range.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, value: T):
        """
        Constructor for numeric range with an associated value.
        
        :param ghidra.program.model.address.Address start: beginning of the range
        :param ghidra.program.model.address.Address end: end of the range
        :param T value: the value to associate with the range.
        """

    def contains(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Determines whether or not the indicated index is in the range.
        
        :param ghidra.program.model.address.Address address: the index to check
        :return: true if the index is in this range.
        :rtype: bool
        """

    def getEnd(self) -> ghidra.program.model.address.Address:
        """
        Returns the end of the range.
        """

    def getStart(self) -> ghidra.program.model.address.Address:
        """
        Returns the beginning of the range.
        """

    def getValue(self) -> T:
        """
        Returns the value associated with the range.
        """

    @property
    def start(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def end(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def value(self) -> T:
        ...


@typing.type_check_only
class RegisterValueRange(java.lang.Object):
    """
    Represents a register value over a range of addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, value: ghidra.program.model.lang.RegisterValue):
        """
        Constructor for RegisterValueRange.
        
        :param ghidra.program.model.address.Address startAddr: the first address in the range
        :param ghidra.program.model.address.Address endAddr: the last address in the range
        :param ghidra.program.model.lang.RegisterValue value: the value of the register over the range.
        """

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the end address of the range.
        """

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the start address of the range.
        """

    def getValue(self) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the register value.
        """

    def setEndAddress(self, addr: ghidra.program.model.address.Address):
        """
        Set the end address of the range.
        
        :param ghidra.program.model.address.Address addr: the new end address.
        """

    def setStartAddress(self, addr: ghidra.program.model.address.Address):
        """
        Set the end address of the range.
        
        :param ghidra.program.model.address.Address addr: the new start address.
        """

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @startAddress.setter
    def startAddress(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def value(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...

    @endAddress.setter
    def endAddress(self, value: ghidra.program.model.address.Address):
        ...


class DatabaseRangeMapAdapter(ghidra.program.util.RangeMapAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, register: ghidra.program.model.lang.Register, dbHandle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock, errorHandler: db.util.ErrorHandler):
        ...


class AddressRangeObjectMap(java.lang.Object, typing.Generic[T]):
    """
    Associates objects with address ranges.
    """

    @typing.type_check_only
    class SimpleAddressRangeIterator(ghidra.program.model.address.AddressRangeIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RestrictedIndexRangeIterator(ghidra.program.model.address.AddressRangeIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new ObjectRangeMap
        """

    def clearAll(self):
        """
        Clears all objects from map
        """

    def clearCache(self):
        ...

    def clearRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Clears any object associations within the given range.
        
        :param ghidra.program.model.address.Address start: the first index in the range to be cleared.
        :param ghidra.program.model.address.Address end: the last index in the range to be cleared.
        """

    def contains(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the associated address has an associated object even if the assocated object
        is null.
        
        :param ghidra.program.model.address.Address address: the index to check for an association.
        :return: true if the associated index has an associated object even if the assocated object
        is null.
        :rtype: bool
        """

    def getAddressRangeContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Get the value or hole range containing the specified address
        
        :param ghidra.program.model.address.Address addr:
        """

    @typing.overload
    def getAddressRangeIterator(self) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an :obj:`AddressRangeIterator` over all ranges that have associated objects.
        
        :return: an :obj:`AddressRangeIterator` over all ranges that have associated objects.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    @typing.overload
    def getAddressRangeIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an :obj:`AddressRangeIterator` over all ranges that have associated objects within
        the given range.  Object Ranges that overlap the beginning or end of the given range are
        included, but have thier start or end index adjusted to be in the given range.
        
        :param ghidra.program.model.address.Address start: the first Address in the range to find all index ranges that have associated values.
        :param ghidra.program.model.address.Address end: the last Address(inclusive) in the range to find all index ranges that have associated
        values.
        :return: an :obj:`AddressRangeIterator` over all ranges that have associated objects within the
        given range.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    def getObject(self, address: ghidra.program.model.address.Address) -> T:
        """
        Returns the object associated with the given index or null if no object is associated with
        the given index.  Note that null is a valid association so a null result could be either
        no association or an actual association of the index to null.  Use the contains() method
        first if the distinction is important.  If the contains() method returns true, the result
        is cached so the next call to getObject() will be fast.
        
        :param ghidra.program.model.address.Address address: the index at which to retrieve an assocated object.
        :return: the object (which can be null) associated with the given index or null if no such
        association exists.
        :rtype: T
        """

    def isEmpty(self) -> bool:
        ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move all values within an address range to a new range.
        
        :param ghidra.program.model.address.Address fromAddr: the first address of the range to be moved.
        :param ghidra.program.model.address.Address toAddr: the address where to the range is to be moved.
        :param jpype.JLong or int length: the number of addresses to move.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :raises CancelledException: if the user canceled the operation via the task monitor.
        """

    def setObject(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, object: T):
        """
        Associates the given object with all indices in the given range. The object may be null,
        but an association is still established.  Use the clearRange() method to remove associations.
        
        :param ghidra.program.model.address.Address start: the start of the range.
        :param ghidra.program.model.address.Address end: the end (inclusive) of the range.
        :param T object: the object to associate with the given range.
        """

    @property
    def addressRangeContaining(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def addressRangeIterator(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def object(self) -> T:
        ...


@typing.type_check_only
class SimpleAddressRangeIterator(ghidra.program.model.address.AddressRangeIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, valueRanges: jpype.JArray[RegisterValueRange]):
        ...


class ProgramRegisterContextDB(ghidra.program.util.AbstractStoredProgramContext, ghidra.program.database.ManagerDB):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, errHandler: db.util.ErrorHandler, lang: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, addrMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock, openMode: ghidra.framework.data.OpenMode, codeMgr: ghidra.program.database.code.CodeManager, monitor: ghidra.util.task.TaskMonitor):
        ...

    def initializeDefaultValues(self, lang: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec):
        """
        Intialize context with default values defined by pspec and cspec.
        NOTE: cspec values take precedence
        
        :param ghidra.program.model.lang.Language lang: processor language
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: compiler specification
        """

    def setLanguage(self, translator: ghidra.program.util.LanguageTranslator, newCompilerSpec: ghidra.program.model.lang.CompilerSpec, programMemory: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform context upgrade due to a language change
        
        :param ghidra.program.util.LanguageTranslator translator: language translator required by major upgrades (may be null)
        :param ghidra.program.model.lang.CompilerSpec newCompilerSpec: new compiler specification
        :param ghidra.program.model.address.AddressSetView programMemory: program memory
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: thrown if monitor cancelled
        """


class OldProgramContextDB(ghidra.program.model.listing.ProgramContext, ghidra.program.model.listing.DefaultProgramContext, ghidra.program.database.ManagerDB):
    """
    ``ProgramContextDB`` defines a processor context over an address 
    space using database range maps for storage.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, errHandler: db.util.ErrorHandler, language: ghidra.program.model.lang.Language, addrMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock):
        """
        Constructs a new ProgramContextDB object
        
        :param db.DBHandle dbHandle: the handle to the database.
        :param db.util.ErrorHandler errHandler: the error handler
        :param ghidra.program.model.lang.Language language: the processor language
        :param ghidra.program.database.map.AddressMap addrMap: the address map.
        :param ghidra.util.Lock lock: the program synchronization lock
        """

    def get(self, addr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register) -> int:
        ...

    def getRegisterValues(self, reg: ghidra.program.model.lang.Register, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> jpype.JArray[RegisterValueRange]:
        ...

    def getSigned(self, addr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register) -> int:
        ...

    def set(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register, value: typing.Union[jpype.JLong, int]):
        ...



__all__ = ["InMemoryRangeMapAdapter", "IndexToAddressRangeIteratorAdapter", "AddressValueRange", "RegisterValueRange", "DatabaseRangeMapAdapter", "AddressRangeObjectMap", "SimpleAddressRangeIterator", "ProgramRegisterContextDB", "OldProgramContextDB"]
