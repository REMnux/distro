from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.docking.settings
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util
import ghidra.util.exception
import ghidra.util.graph
import ghidra.util.map
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class DataTypeInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataTypeHandle: java.lang.Object, dataTypeLength: typing.Union[jpype.JInt, int], dataTypeAlignment: typing.Union[jpype.JInt, int]):
        """
        Constructor for DataTypeInfo.
        
        :param java.lang.Object dataTypeHandle: any Object providing identity for this data type
        :param jpype.JInt or int dataTypeLength: the length of the data type
        :param jpype.JInt or int dataTypeAlignment: the alignment of the data type
        """

    def getDataTypeAlignment(self) -> int:
        ...

    def getDataTypeHandle(self) -> java.lang.Object:
        ...

    def getDataTypeLength(self) -> int:
        ...

    @property
    def dataTypeLength(self) -> jpype.JInt:
        ...

    @property
    def dataTypeAlignment(self) -> jpype.JInt:
        ...

    @property
    def dataTypeHandle(self) -> java.lang.Object:
        ...


class PropertyMap(java.lang.Object, typing.Generic[T]):
    """
    Interface to define a map containing properties over a set of addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, addr: ghidra.program.model.address.Address, value: java.lang.Object):
        """
        Add a map-specific value type to the specified address
        
        :param ghidra.program.model.address.Address addr: property address
        :param java.lang.Object value: property value or null (null remove value at address)
        :raises IllegalArgumentException: if property value type is inappropriate for this map
        """

    def get(self, addr: ghidra.program.model.address.Address) -> T:
        """
        Returns the property value stored at the specified 
        address or null if no property found.
        
        :param ghidra.program.model.address.Address addr: property address
        :return: property value
        :rtype: T
        """

    def getFirstPropertyAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the first Address where a property value exists.
        
        :return: first property value location or null if none found
        :rtype: ghidra.program.model.address.Address
        """

    def getLastPropertyAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the last Address where a property value exists.
        
        :return: last property value location or null if none found
        :rtype: ghidra.program.model.address.Address
        """

    def getName(self) -> str:
        """
        Get the name for this property map.
        
        :return: map name
        :rtype: str
        """

    def getNextPropertyAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Get the next address where the property value exists.
        
        :param ghidra.program.model.address.Address addr: the address from which to begin the search (exclusive).
        :return: property value location after specified ``addr`` or null if none found
        :rtype: ghidra.program.model.address.Address
        """

    def getPreviousPropertyAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Get the previous Address where a property value exists.
        
        :param ghidra.program.model.address.Address addr: the address from which to begin the search (exclusive).
        :return: property value location after specified ``addr`` or null if none found
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the indices having a property value.
        
        :param ghidra.program.model.address.Address start: minimum address
        :param ghidra.program.model.address.Address end: maximum address
        :return: forward property address iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over addresses that have a property value.
        
        :param ghidra.program.model.address.Address start: minimum address
        :param ghidra.program.model.address.Address end: maximum address
        :param jpype.JBoolean or bool forward: if true will iterate in increasing address order, otherwise it will start at
        the end and iterate in decreasing address order
        :return: property address iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getPropertyIterator(self) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the addresses that a property value.
        
        :return: forward property address iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getPropertyIterator(self, asv: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the addresses that have a property value and
        are in the given address set.
        
        :param ghidra.program.model.address.AddressSetView asv: the set of addresses to iterate over.
        :return: forward property address iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getPropertyIterator(self, asv: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the addresses that have a property value and
        are in the given address set.
        
        :param ghidra.program.model.address.AddressSetView asv: the set of addresses to iterate over.
        :param jpype.JBoolean or bool forward: if true will iterate in increasing address order, otherwise it will start at
        the end and iterate in decreasing address order
        :return: property address iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the address having a property value.
        
        :param ghidra.program.model.address.Address start: the starting address
        :param jpype.JBoolean or bool forward: if true will iterate in increasing address order, otherwise it will start at
        the end and iterate in decreasing address order
        :return: property address iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    def getSize(self) -> int:
        """
        Get the number of properties in the map.
        
        :return: number of stored property values
        :rtype: int
        """

    def getValueClass(self) -> java.lang.Class[T]:
        """
        Returns property value class.
        
        :return: property value class or null for an unsupported map type
        :rtype: java.lang.Class[T]
        """

    def hasProperty(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        returns whether there is a property value at addr.
        
        :param ghidra.program.model.address.Address addr: the address in question
        :return: true if map has value at specified address
        :rtype: bool
        """

    @typing.overload
    def intersects(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Given two addresses, indicate whether there is an address in
        that range (inclusive) having the property.
        
        :param ghidra.program.model.address.Address start: the start of the range.
        :param ghidra.program.model.address.Address end: the end of the range.
        :return: boolean true if at least one address in the range
        has the property, false otherwise.
        :rtype: bool
        """

    @typing.overload
    def intersects(self, set: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Indicate whether there is an address within
        the set which exists within this map.
        
        :param ghidra.program.model.address.AddressSetView set: set of addresses
        :return: boolean true if at least one address in the set
        has the property, false otherwise.
        :rtype: bool
        """

    def moveRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, newStart: ghidra.program.model.address.Address):
        """
        Moves the properties defined in the range from the start address thru the 
        end address to now be located beginning at the newStart address. 
        The moved properties will be located at the same relative location to 
        the newStart address as they were previously to the start address.
        
        :param ghidra.program.model.address.Address start: the start of the range to move.
        :param ghidra.program.model.address.Address end: the end of the range to move.
        :param ghidra.program.model.address.Address newStart: the new start location of the range of properties 
        after the move.
        """

    def remove(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Remove the property value at the given address.
        
        :return: true if the property value was removed, false
        otherwise.
        :rtype: bool
        :param ghidra.program.model.address.Address addr: the address where the property should be removed
        """

    def removeRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Removes all property values within a given range.
        
        :param ghidra.program.model.address.Address start: begin range
        :param ghidra.program.model.address.Address end: end range, inclusive
        :return: true if any property value was removed; return
                false otherwise.
        :rtype: bool
        """

    @property
    def previousPropertyAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def lastPropertyAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def propertyIterator(self) -> ghidra.program.model.address.AddressIterator:
        ...

    @property
    def nextPropertyAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def firstPropertyAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def valueClass(self) -> java.lang.Class[T]:
        ...


class PropertySet(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getIntProperty(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Get the int property for name.
        
        :param java.lang.String or str name: the name of the property
        :return: integer property value property has been set
        :rtype: int
        :raises NoValueException: if there is not name property
        for this code unit
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an IntPropertyMap.
        """

    def getObjectProperty(self, name: typing.Union[java.lang.String, str]) -> ghidra.util.Saveable:
        """
        Get the object property for name; returns null if
        there is no name property for this code unit.
        
        :param java.lang.String or str name: the name of the property
        :return: :obj:`Saveable` property value, with map-specific implementation class, or null.
        :rtype: ghidra.util.Saveable
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an ObjectPropertyMap.
        """

    def getStringProperty(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Get the string property for name; returns null if
        there is no name property for this code unit.
        
        :param java.lang.String or str name: the name of the property
        :return: string property value or null
        :rtype: str
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an StringPropertyMap.
        """

    def getVoidProperty(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns whether this code unit is marked as having the
        name property.
        
        :param java.lang.String or str name: the name of the property
        :return: true if property has been set, else false
        :rtype: bool
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an VoidPropertyMap.
        """

    def hasProperty(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the codeunit has the given property defined.
        This method works for all property map types.
        
        :param java.lang.String or str name: the name of the property
        :return: true if property has been set, else false
        :rtype: bool
        """

    def propertyNames(self) -> java.util.Iterator[java.lang.String]:
        """
        Get an iterator over the property names which have values applied.
        
        :return: iterator of all property map names which have values applied
        :rtype: java.util.Iterator[java.lang.String]
        """

    def removeProperty(self, name: typing.Union[java.lang.String, str]):
        """
        Remove the property value associated with the given name .
        
        :param java.lang.String or str name: the name of the property
        """

    @typing.overload
    def setProperty(self, name: typing.Union[java.lang.String, str], value: T):
        """
        Set the named property with the given :obj:`Saveable` value.
        
        :param java.lang.String or str name: the name of the property.
        :param T value: value to be stored.
        :param T: :obj:`Saveable` implementation:raises java.lang.IllegalArgumentException: if value type is inconsistent with named map
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an ObjectPropertyMap.
        """

    @typing.overload
    def setProperty(self, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Set the named string property with the given value.
        
        :param java.lang.String or str name: the name of the property.
        :param java.lang.String or str value: value to be stored.
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not a StringPropertyMap.
        """

    @typing.overload
    def setProperty(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Set the named integer property with the given value.
        
        :param java.lang.String or str name: the name of the property.
        :param jpype.JInt or int value: value to be stored.
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an IntPropertyMap.
        """

    @typing.overload
    def setProperty(self, name: typing.Union[java.lang.String, str]):
        """
        Set the named property.  This method is used for "void" properites. The
        property is either set or not set - there is no value
        
        :param java.lang.String or str name: the name of the property.
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not a VoidPropertyMap.
        """

    @property
    def intProperty(self) -> jpype.JInt:
        ...

    @property
    def voidProperty(self) -> jpype.JBoolean:
        ...

    @property
    def objectProperty(self) -> ghidra.util.Saveable:
        ...

    @property
    def stringProperty(self) -> java.lang.String:
        ...


class DeletedException(java.lang.Exception):
    """
    Exception thrown when program object being accessed has been deleted.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new DeletedException with a default message.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructs a new DeletedException with a given message.
        
        :param java.lang.String or str msg: the message for the exception.
        """


class CompositeDataTypeElementInfo(DataTypeInfo):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataTypeHandle: java.lang.Object, dataTypeOffset: typing.Union[jpype.JInt, int], dataTypeLength: typing.Union[jpype.JInt, int], dataTypeAlignment: typing.Union[jpype.JInt, int]):
        """
        Constructor for CompositeDataTypeElementInfo.
        
        :param java.lang.Object dataTypeHandle: any Object providing identity for this data type
        :param jpype.JInt or int dataTypeOffset: the offset of the element within the outer composite data type
        :param jpype.JInt or int dataTypeLength: the length of the data type
        :param jpype.JInt or int dataTypeAlignment: the alignment of the data type
        """

    @typing.overload
    def __init__(self, dataTypeInfo: DataTypeInfo, dataTypeOffset: typing.Union[jpype.JInt, int]):
        """
        Constructor for CompositeDataTypeElementInfo (copy-ish).
        
        :param DataTypeInfo dataTypeInfo: the dataType this CompositeDataTypeElementInfo is based upon
        :param jpype.JInt or int dataTypeOffset: the offset of the element within the outer composite data type
        """

    def getDataTypeOffset(self) -> int:
        ...

    @property
    def dataTypeOffset(self) -> jpype.JInt:
        ...


class ObjectPropertyMap(PropertyMap[T], typing.Generic[T]):
    """
    Property manager that deals with properties that are of
    Object type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, addr: ghidra.program.model.address.Address, value: T):
        """
        Add an object value at the specified address.
        
        :param ghidra.program.model.address.Address addr: address for the property
        :param T value: value of the property
        :raises java.lang.IllegalArgumentException: if value is type is inconsistent with map
        """


class ProcessorSymbolType(java.lang.Enum[ProcessorSymbolType]):

    class_: typing.ClassVar[java.lang.Class]
    CODE: typing.Final[ProcessorSymbolType]
    CODE_PTR: typing.Final[ProcessorSymbolType]

    @staticmethod
    def getType(string: typing.Union[java.lang.String, str]) -> ProcessorSymbolType:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ProcessorSymbolType:
        ...

    @staticmethod
    def values() -> jpype.JArray[ProcessorSymbolType]:
        ...


class VoidPropertyMap(PropertyMap[java.lang.Boolean]):
    """
    Property manager that deals with properties that are of
    "void" type, which is a marker for whether a property exists.
    Object values returned are either :obj:`Boolean.TRUE` or null.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def add(self, addr: ghidra.program.model.address.Address):
        """
        Mark the specified address as having a property
        
        :param ghidra.program.model.address.Address addr: address for the property
        """

    @typing.overload
    def add(self, addr: ghidra.program.model.address.Address, value: java.lang.Object):
        """
        Apply property value to specified address.
        
        :param ghidra.program.model.address.Address addr: property address
        :param java.lang.Object value: boolean value (null or false will remove property value)
        :raises IllegalArgumentException: if value specified is not a Boolean or null
        """


class StringPropertyMap(PropertyMap[java.lang.String]):
    """
    Property manager that deals with properties that are of
    String type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, addr: ghidra.program.model.address.Address, value: typing.Union[java.lang.String, str]):
        """
        Add a String value at the specified address.
        
        :param ghidra.program.model.address.Address addr: address for the property
        :param java.lang.String or str value: value of the property
        :raises TypeMismatchException: thrown if the
        property does not have String values.
        """

    def getString(self, addr: ghidra.program.model.address.Address) -> str:
        """
        Get the String value at the given address.
        
        :param ghidra.program.model.address.Address addr: the address from where to get the String value
        :return: String or null if property not found at addr.
        :rtype: str
        """

    @property
    def string(self) -> java.lang.String:
        ...


class SettingsPropertyMap(PropertyMap[ghidra.docking.settings.Settings]):
    """
    Property map interface for storing Settings objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, addr: ghidra.program.model.address.Address, value: ghidra.docking.settings.Settings):
        """
        Add an Settings object value at the specified address.
        
        :param ghidra.program.model.address.Address addr: address for the property
        :param ghidra.docking.settings.Settings value: value of the property
        """

    def getSettings(self, addr: ghidra.program.model.address.Address) -> ghidra.docking.settings.Settings:
        """
        Get the Settings object value at the given address.
        
        :param ghidra.program.model.address.Address addr: the address from where to get the int value
        :return: Settings object or null if property not found at addr.
        :rtype: ghidra.docking.settings.Settings
        """

    @property
    def settings(self) -> ghidra.docking.settings.Settings:
        ...


class MemoryByteIterator(java.lang.Object):
    """
    Class to iterate over the bytes in memory for an address set.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mem: ghidra.program.model.mem.Memory, set: ghidra.program.model.address.AddressSetView):
        """
        Construct a memoryIterator
        
        :param ghidra.program.model.mem.Memory mem: the memory providing the bytes
        :param ghidra.program.model.address.AddressSetView set: the set of addresses for which to iterate bytes
        """

    def hasNext(self) -> bool:
        """
        Returns true if there are more bytes to iterate over
        """

    def next(self) -> int:
        """
        Returns the next byte.
        
        :raises MemoryAccessException: if the next byte could not be read
        """


class LongPropertyMap(PropertyMap[java.lang.Long]):
    """
    Property manager that deals with properties that are of
    long type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JLong, int]):
        """
        Add a long value at the specified address.
        
        :param ghidra.program.model.address.Address addr: address for the property
        :param jpype.JLong or int value: value of the property
        """

    def getLong(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Get the long value at the given address.
        
        :param ghidra.program.model.address.Address addr: the address from where to get the long value
        :return: long property value
        :rtype: int
        :raises NoValueException: if there is no property value at addr.
        """

    @property
    def long(self) -> jpype.JLong:
        ...


class PropertyMapManager(java.lang.Object):
    """
    Interface for managing a set of PropertyManagers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createIntPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> IntPropertyMap:
        """
        Creates a new IntPropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name for the new property.
        :return: newly created integer object map
        :rtype: IntPropertyMap
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def createLongPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> LongPropertyMap:
        """
        Creates a new LongPropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name for the new property.
        :return: newly created long object map
        :rtype: LongPropertyMap
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def createObjectPropertyMap(self, propertyName: typing.Union[java.lang.String, str], objectClass: java.lang.Class[T]) -> ObjectPropertyMap[T]:
        """
        Creates a new ObjectPropertyMap with the given name.
        
        :param T: :obj:`Saveable` property value type:param java.lang.String or str propertyName: the name for the new property.
        :param java.lang.Class[T] objectClass: :obj:`Saveable` implementation class
        :return: newly created :obj:`Saveable` object map
        :rtype: ObjectPropertyMap[T]
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def createStringPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> StringPropertyMap:
        """
        Creates a new StringPropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name for the new property.
        :return: newly created string object map
        :rtype: StringPropertyMap
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def createVoidPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> VoidPropertyMap:
        """
        Creates a new VoidPropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name for the new property.
        :return: newly created void map
        :rtype: VoidPropertyMap
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def getIntPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> IntPropertyMap:
        """
        Returns the IntPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :return: existing map or null if not found
        :rtype: IntPropertyMap
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an IntPropertyMap.
        """

    def getLongPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> LongPropertyMap:
        """
        Returns the LongPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :return: existing map or null if not found
        :rtype: LongPropertyMap
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an LongPropertyMap.
        """

    def getObjectPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ObjectPropertyMap[ghidra.util.Saveable]:
        """
        Returns the ObjectPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :return: existing map or null if not found
        :rtype: ObjectPropertyMap[ghidra.util.Saveable]
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an ObjectPropertyMap.
        """

    def getPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> PropertyMap[typing.Any]:
        """
        Returns the PropertyMap with the given name or null if no PropertyMap
        exists with that name.
        
        :return: existing map or null if not found
        :rtype: PropertyMap[typing.Any]
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        """

    def getStringPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> StringPropertyMap:
        """
        Returns the StringPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :return: existing map or null if not found
        :rtype: StringPropertyMap
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not a StringPropertyMap.
        """

    def getVoidPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> VoidPropertyMap:
        """
        Returns the VoidPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :return: existing map or null if not found
        :rtype: VoidPropertyMap
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not a VoidPropertyMap.
        """

    def propertyManagers(self) -> java.util.Iterator[java.lang.String]:
        """
        Returns an iterator over the names of all existing PropertyMaps sorted by name.
        """

    @typing.overload
    def removeAll(self, addr: ghidra.program.model.address.Address):
        """
        Removes any property at the given address from all defined 
        PropertyMaps.
        
        :param ghidra.program.model.address.Address addr: the address at which to remove all property values.
        """

    @typing.overload
    def removeAll(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Removes all properties in the given range from all user 
        defined PropertyMaps. 
        The specified start and end addresses must form a valid range within
        a single :obj:`AddressSpace`.
        
        :param ghidra.program.model.address.Address startAddr: the first address in the range of addresses where 
        propertie values are to be removed.
        :param ghidra.program.model.address.Address endAddr: the last address in the range of addresses where 
        propertie values are to be removed.
        :param ghidra.util.task.TaskMonitor monitor: monitors progress
        :raises CancelledException: if the user cancelled the operation.
        """

    def removePropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> bool:
        """
        Removes the PropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to remove.
        :return: true if a PropertyMap with that name was found (and removed)
        :rtype: bool
        """

    @property
    def intPropertyMap(self) -> IntPropertyMap:
        ...

    @property
    def voidPropertyMap(self) -> VoidPropertyMap:
        ...

    @property
    def stringPropertyMap(self) -> StringPropertyMap:
        ...

    @property
    def propertyMap(self) -> PropertyMap[typing.Any]:
        ...

    @property
    def longPropertyMap(self) -> LongPropertyMap:
        ...

    @property
    def objectPropertyMap(self) -> ObjectPropertyMap[ghidra.util.Saveable]:
        ...


class IntPropertyMap(PropertyMap[java.lang.Integer]):
    """
    Property manager that deals with properties that are of
    int type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, addr: ghidra.program.model.address.Address, value: typing.Union[jpype.JInt, int]):
        """
        Add an int value at the specified address.
        
        :param ghidra.program.model.address.Address addr: address for the property
        :param jpype.JInt or int value: value of the property
        """

    def getInt(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Get the integer value at the given address.
        
        :param ghidra.program.model.address.Address addr: the address from where to get the int value
        :return: integer property value
        :rtype: int
        :raises NoValueException: if there is no property value at addr.
        """

    @property
    def int(self) -> jpype.JInt:
        ...


class CodeUnitInsertionException(ghidra.util.exception.UsrException):
    """
    Exception thrown when a code unit cannot be created.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """


class DefaultPropertyMap(PropertyMap[T], typing.Generic[T]):
    """
    PropertyMap is used to store values for a fixed property at
    address locations given as longs. The values for the property
    must be homogeneous, i.e. all have the same type, and are
    determined by which subclass of PropertyMap is instantiated.
    For any long the property
    manager can be used to tell if the property exists there and
    what its value is. It also maintains information that allows it
    to efficiently search for the next and previous occurrence of the
    property relative to a given address.
    The subclass provides the createPage() method that dictates
    the type of PropertyPage that will be managed.
    """

    @typing.type_check_only
    class AddressPropertyIterator(ghidra.program.model.address.AddressIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AddressSetPropertyIterator(ghidra.program.model.address.AddressIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, propertyMgr: ghidra.util.map.ValueMap[T]):
        """
        Construct a PropertyMap
        
        :param ghidra.util.map.ValueMap[T] propertyMgr: property manager that manages storage of
        properties
        """

    def getDescription(self) -> str:
        """
        Return the property description.
        
        :return: the property description
        :rtype: str
        """

    def restoreProperties(self, ois: java.io.ObjectInputStream):
        """
        Restore properties from the given input stream.
        
        :param java.io.ObjectInputStream ois: input stream
        :raises IOException: if there is a problem reading from the stream
        :raises java.lang.ClassNotFoundException: if the class for the object being
        read is not in the class path
        """

    def saveProperties(self, oos: java.io.ObjectOutputStream, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Save the properties in the given range to output stream.
        
        :param java.io.ObjectOutputStream oos: output stream to write to
        :param ghidra.program.model.address.Address start: start address in the range
        :param ghidra.program.model.address.Address end: end address in the range
        :raises IOException: if there a problem doing the write
        """

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        """
        Set the description for this property.
        
        :param java.lang.String or str description: property description
        """

    @property
    def description(self) -> java.lang.String:
        ...

    @description.setter
    def description(self, value: java.lang.String):
        ...


class AcyclicCallGraphBuilder(java.lang.Object):
    """
    Class to build an DependencyGraph base on a acyclic function call graph.  This is useful when
    you want to process functions "bottom up".
    """

    @typing.type_check_only
    class StackNode(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        address: ghidra.program.model.address.Address
        children: jpype.JArray[ghidra.program.model.address.Address]
        nextchild: jpype.JInt


    @typing.type_check_only
    class VisitStack(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, functionEntry: ghidra.program.model.address.Address):
            ...

        def contains(self, address: ghidra.program.model.address.Address) -> bool:
            ...

        def isEmpty(self) -> bool:
            ...

        def peek(self) -> AcyclicCallGraphBuilder.StackNode:
            ...

        def pop(self):
            ...

        def push(self, address: ghidra.program.model.address.Address):
            ...

        @property
        def empty(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, killThunks: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a DependencyGraph of all functions in a program based on the call graph.
        
        :param ghidra.program.model.listing.Program program: the program to create an acyclic call graph
        :param jpype.JBoolean or bool killThunks: true if thunked functions should be eliminated from the graph
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, killThunks: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a DependencyGraph of all functions in the given addressSet based on the call graph.
        Calls to or from functions outside the given address set are ignored.
        
        :param ghidra.program.model.listing.Program program: the program to create an acyclic call graph
        :param ghidra.program.model.address.AddressSetView set: the address to restrict the call graph.
        :param jpype.JBoolean or bool killThunks: true if thunked functions should be eliminated from the graph
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, functions: collections.abc.Sequence, killThunks: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a DependencyGraph of all functions in the given set of functions based on the call graph.
        Calls to or from functions not in the given set are ignored.
        
        :param ghidra.program.model.listing.Program program: the program to create an acyclic call graph
        :param collections.abc.Sequence functions: the set of functions to include in the call graph.
        :param jpype.JBoolean or bool killThunks: true if thunked functions should be eliminated from the graph
        """

    def getDependencyGraph(self, monitor: ghidra.util.task.TaskMonitor) -> ghidra.util.graph.AbstractDependencyGraph[ghidra.program.model.address.Address]:
        """
        Builds the DependencyGraph for the acyclic call graph represented by this object.
        
        :param ghidra.util.task.TaskMonitor monitor: the taskMonitor to use for reporting progress or cancelling.
        :return: the DependencyGraph for the acyclic call graph represented by this object.
        :rtype: ghidra.util.graph.AbstractDependencyGraph[ghidra.program.model.address.Address]
        :raises CancelledException: if the monitor was cancelled.
        """

    @property
    def dependencyGraph(self) -> ghidra.util.graph.AbstractDependencyGraph[ghidra.program.model.address.Address]:
        ...


class DefaultIntPropertyMap(DefaultPropertyMap[java.lang.Integer], IntPropertyMap):
    """
    Property manager that deals with properties that are of
    int type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Construct a new IntPropertyMap
        
        :param java.lang.String or str name: name of property
        """


class AddressSetPropertyMap(java.lang.Object):
    """
    Defines methods to mark ranges in a property map.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def add(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Add the address range to the property map.
        
        :param ghidra.program.model.address.Address start: start of the range
        :param ghidra.program.model.address.Address end: end of the range
        """

    @typing.overload
    def add(self, addressSet: ghidra.program.model.address.AddressSetView):
        """
        Add the address set to the property map.
        
        :param ghidra.program.model.address.AddressSetView addressSet: address set to add
        """

    def clear(self):
        """
        Clear the property map.
        """

    def contains(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Return whether the property map contains the given address.
        
        :param ghidra.program.model.address.Address addr: address to check
        """

    def getAddressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Return an address range iterator over the property map.
        """

    def getAddressSet(self) -> ghidra.program.model.address.AddressSet:
        """
        Return the address set for the property map.
        """

    def getAddresses(self) -> ghidra.program.model.address.AddressIterator:
        """
        Return an address iterator over the property map.
        """

    @typing.overload
    def remove(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Remove the address range from the property map.
        
        :param ghidra.program.model.address.Address start: start of the range
        :param ghidra.program.model.address.Address end: end of the range
        """

    @typing.overload
    def remove(self, addressSet: ghidra.program.model.address.AddressSetView):
        """
        Remove the address set from the property map.
        
        :param ghidra.program.model.address.AddressSetView addressSet: address set to remove
        """

    def set(self, addressSet: ghidra.program.model.address.AddressSetView):
        """
        Clear the property map and set it with the given address set.
        
        :param ghidra.program.model.address.AddressSetView addressSet: address set to use
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def addresses(self) -> ghidra.program.model.address.AddressIterator:
        ...

    @property
    def addressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...



__all__ = ["DataTypeInfo", "PropertyMap", "PropertySet", "DeletedException", "CompositeDataTypeElementInfo", "ObjectPropertyMap", "ProcessorSymbolType", "VoidPropertyMap", "StringPropertyMap", "SettingsPropertyMap", "MemoryByteIterator", "LongPropertyMap", "PropertyMapManager", "IntPropertyMap", "CodeUnitInsertionException", "DefaultPropertyMap", "AcyclicCallGraphBuilder", "DefaultIntPropertyMap", "AddressSetPropertyMap"]
