from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.stack
import ghidra.trace.model.thread
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class TracePropertyMapOperations(java.lang.Object, typing.Generic[T]):
    """
    A map from address-snap pairs to user-defined values in a :obj:`Trace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def clear(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> bool:
        """
        Remove or truncate entries so that the given box contains no entries
         
         
        
        This applies the same truncation rule as in :meth:`set(Lifespan, AddressRange, Object) <.set>`,
        except that no replacement entry is created.
        
        :param ghidra.trace.model.Lifespan span: the range of snaps
        :param ghidra.program.model.address.AddressRange range: the address range
        :return: true if any entry was affected
        :rtype: bool
        """

    def get(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        Get the value at the given address-snap pair
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the value
        :rtype: T
        """

    def getAddressSetView(self, span: ghidra.trace.model.Lifespan) -> ghidra.program.model.address.AddressSetView:
        """
        Get the union of address ranges for entries which intersect the given span
        
        :param ghidra.trace.model.Lifespan span: the range of snaps
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getEntries(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]]:
        """
        Get the entries intersecting the given bounds
        
        :param ghidra.trace.model.Lifespan lifespan: the range of snaps
        :param ghidra.program.model.address.AddressRange range: the range of addresses
        :return: the entries
        :rtype: java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]]
        """

    def getEntry(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]:
        """
        Get the entry at the given address-snap pair
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the entry, which includes the ranges and the value
        :rtype: java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]
        """

    def getValueClass(self) -> java.lang.Class[T]:
        """
        Get the class for values of the map
        
        :return: the value class
        :rtype: java.lang.Class[T]
        """

    @typing.overload
    def set(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, value: T):
        """
        Set a value at the given address over the given lifespan
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan
        :param ghidra.program.model.address.Address address: the address
        :param T value: the value
        
        .. seealso::
        
            | :obj:`.set(Lifespan, AddressRange, Object)`
        """

    @typing.overload
    def set(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, value: T):
        """
        Set a value over the given ranges
         
         
        
        Setting a value of null still creates an entry, so that Void-typed maps function.
         
         
        
        When setting an overlapping value, existing entries are deleted or truncated to make space
        for the new entry. If an existing entry overlaps and its starting snap is contained in the
        new entry's span, the existing entry is deleted, regardless of whether or not its ending snap
        is also contained in the new entry's span. If the starting snap of the existing entry
        precedes the span of the new entry, the existing entry is truncated -- its ending snap is set
        to one less than the new entry's starting snap. Address ranges are never truncated.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan
        :param ghidra.program.model.address.AddressRange range: the address range
        :param T value: the value
        """

    @property
    def valueClass(self) -> java.lang.Class[T]:
        ...

    @property
    def addressSetView(self) -> ghidra.program.model.address.AddressSetView:
        ...


class TraceAddressPropertyManager(java.lang.Object):
    """
    The manager for user properties of a trace
     
     
    
    Clients may create property maps of various value types. Each map is named, also considered the
    "property name," and can be retrieve by that name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createPropertyMap(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[T]) -> TracePropertyMap[T]:
        """
        Create a property map with the given name having the given type
         
         
        
        The following types are supported for valueClass:
         
        * :obj:`Integer`
        * :obj:`Long`
        * :obj:`String`
        * :obj:`Void`: presence or absence of entry satisfies "boolean" use case
        * ``? extends``:obj:`Saveable`
        
         
         
        
        Note that for maps of user-defined :obj:`Saveable` type, only the specified type is accepted
        by the map. Attempting to save an extension of that type may lead to undefined behavior,
        esp., if it attempts to save additional fields. When the value is restored, it will have the
        type given in ``valueClass``, not the extended type.
        
        :param java.lang.String or str name: the name
        :param java.lang.Class[T] valueClass: the type of values
        :return: the new property map
        :rtype: TracePropertyMap[T]
        :raises DuplicateNameException: if a map of the given name already exists
        """

    def getAllProperties(self) -> java.util.Map[java.lang.String, TracePropertyMap[typing.Any]]:
        """
        Get a copy of all the defined properties
        
        :return: the set of names
        :rtype: java.util.Map[java.lang.String, TracePropertyMap[typing.Any]]
        """

    def getOrCreatePropertyMap(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[T]) -> TracePropertyMap[T]:
        """
        Get the property map with the given name, creating it if necessary, of the given type
        
        :param java.lang.String or str name: the name
        :param java.lang.Class[T] valueClass: the expected type of values
        :return: the (possibly new) property map
        :rtype: TracePropertyMap[T]
        
        .. seealso::
        
            | :obj:`.createPropertyMap(String, Class)`
        """

    def getOrCreatePropertyMapSuper(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[T]) -> TracePropertyMap[T]:
        """
        Get the property map with the given name, creating it if necessary, of the given type
         
         
        
        If the map already exists, then its values' type must be a super type of that given.
        
        :param java.lang.String or str name: the name
        :param java.lang.Class[T] valueClass: the expected type of values
        :return: the (possibly new) property map
        :rtype: TracePropertyMap[T]
        
        .. seealso::
        
            | :obj:`.getOrCreatePropertyMap(String, Class)`
        """

    @typing.overload
    def getPropertyMap(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[T]) -> TracePropertyMap[T]:
        """
        Get the property map with the given name, if it has the given type
        
        :param java.lang.String or str name: the name
        :param java.lang.Class[T] valueClass: the expected type of values
        :return: the property map, or null if it does not exist
        :rtype: TracePropertyMap[T]
        :raises TypeMismatchException: if it exists but does not have the expected type
        """

    @typing.overload
    def getPropertyMap(self, name: typing.Union[java.lang.String, str]) -> TracePropertyMap[typing.Any]:
        """
        Get the property map with the given name.
         
         
        
        Note that no type checking is performed (there is no ``valueClass`` parameter). Thus, the
        returned map is suitable only for clearing and querying where the property is present. The
        caller may perform run-time type checking via the
        :meth:`TracePropertyMapOperations.getValueClass() <TracePropertyMapOperations.getValueClass>` method.
        
        :param java.lang.String or str name: the name
        :return: the property map
        :rtype: TracePropertyMap[typing.Any]
        """

    def getPropertyMapExtends(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[T]) -> TracePropertyMap[T]:
        """
        Get the property map with the given name, if its values extend the given type
        
        :param java.lang.String or str name: the name
        :param java.lang.Class[T] valueClass: the expected type of values
        :return: the property map, or null if it does not exist
        :rtype: TracePropertyMap[T]
        :raises TypeMismatchException: if it exists but does not have the expected type
        """

    @property
    def allProperties(self) -> java.util.Map[java.lang.String, TracePropertyMap[typing.Any]]:
        ...

    @property
    def propertyMap(self) -> TracePropertyMap[typing.Any]:
        ...


class TracePropertyMap(TracePropertyMapOperations[T], typing.Generic[T]):
    """
    A range map for storing properties in a trace
    
     
    
    Technically, each range is actually a "box" in two dimensions: time and space. Time is
    represented by the span of snapshots covered, and space is represented by the range of addresses
    covered. Currently, no effort is made to optimize coverage for entries having the same value. For
    operations on entries, see :obj:`TracePropertyMapOperations`.
     
     
    
    This interface is the root of a multi-space property map. For memory spaces, clients can
    generally use the operations inherited on this interface. For register spaces, clients must use
    :meth:`getPropertyMapRegisterSpace(TraceThread, int, boolean) <.getPropertyMapRegisterSpace>` or similar.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        """
        Delete this property and remove all of its maps
         
         
        
        The property can be re-created with the same or different value type.
        """

    @typing.overload
    def getPropertyMapRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, frameLevel: typing.Union[jpype.JInt, int], createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TracePropertyMapSpace[T]:
        """
        Get the map space for the registers of a given thread and frame
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JInt or int frameLevel: the frame level, 0 being the innermost
        :param jpype.JBoolean or bool createIfAbsent: true to create the map space if it doesn't already exist
        :return: the space, or null
        :rtype: TracePropertyMapSpace[T]
        """

    @typing.overload
    def getPropertyMapRegisterSpace(self, frame: ghidra.trace.model.stack.TraceStackFrame, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TracePropertyMapSpace[T]:
        """
        Get the map space for the registers of a given frame (which knows its thread)
        
        :param ghidra.trace.model.stack.TraceStackFrame frame: the frame
        :param jpype.JBoolean or bool createIfAbsent: true to create the map space if it doesn't already exist
        :return: the space, or null
        :rtype: TracePropertyMapSpace[T]
        """

    def getPropertyMapSpace(self, space: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TracePropertyMapSpace[T]:
        """
        Get the map space for the given address space
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param jpype.JBoolean or bool createIfAbsent: true to create the map space if it doesn't already exist
        :return: the space, or null
        :rtype: TracePropertyMapSpace[T]
        """


class TracePropertyMapSpace(TracePropertyMapOperations[T], typing.Generic[T]):
    """
    A property map space for a memory space
    """

    class_: typing.ClassVar[java.lang.Class]

    def clear(self, span: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register):
        """
        Remove or truncate entries so that the given box (register and lifespan) contains no entries
        
        :param ghidra.trace.model.Lifespan span: the range of snaps
        :param ghidra.program.model.lang.Register register: the register
        """

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the address space for this space
        
        :return: the address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    @typing.overload
    def getEntries(self, platform: ghidra.trace.model.guest.TracePlatform, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register) -> java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]]:
        """
        Get all entries intersecting the given register and lifespan
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform defining the register
        :param ghidra.trace.model.Lifespan lifespan: the range of snaps
        :param ghidra.program.model.lang.Register register: the register
        :return: the entries
        :rtype: java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]]
        """

    @typing.overload
    def getEntries(self, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register) -> java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]]:
        """
        Get all entries intersecting the given register and lifespan
        
        :param ghidra.trace.model.Lifespan lifespan: the range of snaps
        :param ghidra.program.model.lang.Register register: the register
        :return: the entries
        :rtype: java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]]
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    @typing.overload
    def set(self, platform: ghidra.trace.model.guest.TracePlatform, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register, value: T):
        """
        Set a property on the given register for the given lifespan
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform defining the register
        :param ghidra.trace.model.Lifespan lifespan: the range of snaps
        :param ghidra.program.model.lang.Register register: the register
        :param T value: the value to set
        """

    @typing.overload
    def set(self, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register, value: T):
        """
        Set a property on the given register for the given lifespan
        
        :param ghidra.trace.model.Lifespan lifespan: the range of snaps
        :param ghidra.program.model.lang.Register register: the register
        :param T value: the value to set
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...



__all__ = ["TracePropertyMapOperations", "TraceAddressPropertyManager", "TracePropertyMap", "TracePropertyMapSpace"]
