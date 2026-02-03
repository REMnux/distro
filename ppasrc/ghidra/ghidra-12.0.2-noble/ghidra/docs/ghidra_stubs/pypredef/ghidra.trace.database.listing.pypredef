from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.trace.database
import ghidra.trace.database.address
import ghidra.trace.database.data
import ghidra.trace.database.guest
import ghidra.trace.database.map
import ghidra.trace.database.space
import ghidra.trace.database.symbol
import ghidra.trace.database.thread
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.thread
import ghidra.trace.util
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore


M = typing.TypeVar("M")
P = typing.TypeVar("P")
T = typing.TypeVar("T")


class DBTraceDataMemoryView(AbstractWithUndefinedDBTraceCodeUnitsMemoryView[DBTraceDataAdapter, DBTraceDataView], ghidra.trace.model.listing.TraceDataView, InternalBaseCodeUnitsView[ghidra.trace.model.listing.TraceData]):
    """
    The implementation of :meth:`TraceCodeManager.data() <TraceCodeManager.data>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager):
        """
        Construct the view
        
        :param DBTraceCodeManager manager: the manager
        """


class DBTraceCodeUnitsMemoryView(AbstractWithUndefinedDBTraceCodeUnitsMemoryView[DBTraceCodeUnitAdapter, DBTraceCodeUnitsView], ghidra.trace.model.listing.TraceCodeUnitsView, InternalBaseCodeUnitsView[ghidra.trace.model.listing.TraceCodeUnit]):
    """
    The implementation of :meth:`TraceCodeManager.codeUnits() <TraceCodeManager.codeUnits>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager):
        """
        Construct the view
        
        :param DBTraceCodeManager manager: the manager
        """


class DBTraceCodeManager(ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager[DBTraceCodeSpace], ghidra.trace.model.listing.TraceCodeManager, ghidra.trace.database.space.DBTraceDelegatingManager[DBTraceCodeSpace]):
    """
    The implementation of :obj:`TraceCodeManager` for :obj:`DBTrace`
     
     
    
    The "fluent" interfaces actually create quite a burden to implement here; however, we have some
    opportunity to extract common code among the various views. There are a few concepts and nuances
    to consider in order to handle all the fluent cases. The manager implements
    :obj:`TraceCodeOperations` directly, which means it must provide a version of each
    :obj:`TraceCodeUnitsView` that composes all memory address spaces. These are named with the
    suffix ``MemoryView`` and extend :obj:`AbstractBaseDBTraceCodeUnitsMemoryView`.
     
     
    
    In addition, in order to support :meth:`getCodeSpace(AddressSpace, boolean) <.getCodeSpace>`, it must provide a
    version of each that can be bound to a single memory address space. Same for
    :meth:`getCodeRegisterSpace(TraceThread, int, boolean) <.getCodeRegisterSpace>`. These are named with the suffix
    ``View`` and extend :obj:`AbstractBaseDBTraceCodeUnitsView`.
     
     
    
    Furthermore, there are three types of views:
     
     
    1. Those defined by a table, i.e., defined data and instructions. These extend
    :obj:`AbstractBaseDBTraceDefinedUnitsView`.
    2. Those defined implicitly, but may have a support table, i.e., undefined units. This is
    implemented by:obj:`DBTraceUndefinedDataView`.
    3. Those defined as the composition of others, i.e., data and defined units. These extend
    :obj:`AbstractComposedDBTraceCodeUnitsView`.
    
     
     
    
    The first two types represent a view of a single code unit type, so they both extend
    :obj:`AbstractSingleDBTraceCodeUnitsView`.
     
     
    
    The abstract classes do not nominally implement the trace manager's
    :obj:`TraceBaseCodeUnitsView` nor :obj:`TraceBaseDefinedUnitsView` interfaces, because Java
    prevents the (nominal) implementation of the same interface with different type parameters by the
    same class. E.g., :obj:`DBTraceDataView` would inherit
    ``TraceBaseCodeUnitsView<DBTraceData>`` via :obj:`AbstractBaseDBTraceCodeUnitsView`, but
    also ``TraceBaseCodeUnitsView<TraceDataUnit>`` via :obj:`TraceDataView`. Instead, the
    abstract classes *structurally* implement those interfaces, meaning they implement the
    methods required by the interface, but without naming the interface in their `implements` clause.
    The realizations, e.g., :obj:`DBTraceDataView`, *nominally* implement their corresponding
    interfaces, meaning they do name the interface. Each realization will inherit the structural
    implementation from the abstract classes, satisfying the requirements imposed by nominally
    implementing the interface.
     
     
    
    Note, as a result, navigating from declarations in the interfaces to implementations in abstract
    classes using your IDE may not work as expected :/ . The best way is probably to display the type
    hierarchy of the interface declaring the desired method. Open one of the classes implementing it,
    then display all its methods, including those inherited, and search for desired method.
     
     
    
    Here is the type hierarchy presented with notes regarding structural interface implementations:
     
    * :obj:`AbstractBaseDBTraceCodeUnitsView` structurally implements
    :obj:`TraceBaseCodeUnitsView`    
        * :obj:`AbstractComposedDBTraceCodeUnitsView`    
            * :obj:`DBTraceCodeUnitsView` nominally implements :obj:`TraceCodeUnitsView`
            * :obj:`DBTraceDataView` nominally implements :obj:`TraceDataView`
            * :obj:`DBTraceDefinedUnitsView` nominally implements :obj:`TraceDefinedUnitsView`
        
        * :obj:`AbstractSingleDBTraceCodeUnitsView`    
            * :obj:`AbstractBaseDBTraceDefinedUnitsView` structurally implements
            :obj:`TraceBaseDefinedUnitsView`    
                * :obj:`DBTraceDefinedDataView` nominally implements :obj:`TraceDefinedDataView`
                * :obj:`DBTraceInstructionsView` nominally implements :obj:`TraceInstructionsView`
            
            * :obj:`DBTraceUndefinedDataView` nominally implements :obj:`TraceUndefinedDataView`
        
    
    
     
     
    
    The view composition is not hierarchical, as each may represent a different combination, and one
    type may appear in several compositions. The single-type views are named first, then the composed
    views:
     
     
    * Instructions - single-type view
    * Defined Data - single-type view
    * Undefined Data - single-type view
    
     
     
    
    Note that while the API presents separate views for defined data and undefined units, both are
    represented by the type :obj:`TraceData`. Meaning, a client with a data unit in hand cannot
    determine whether it is defined or undefined from its type alone. It must invoke
    :meth:`Data.isDefined() <Data.isDefined>` instead. While the implementation provides a separate type, which we see
    mirrors the hierarchy of the views' implementation, the client interfaces do not.
     
     
    * Code Units - Instructions, Defined Data, Undefined Data
    * Data - Defined Data, Undefined Data
    * Defined Units - Instructions, Defined Data
    
     
     
    
    The ``MemoryView`` classes compose the memory address spaces into a single view. These need
    not mirror the same implementation hierarchy as the views they compose. Other than special
    handling for compositions including undefined units, each memory view need not know anything
    about the views it composes. There are two abstract classes:
    :obj:`AbstractBaseDBTraceCodeUnitsMemoryView`, which is suitable for composing views without
    undefined units, and :obj:`AbstractWithUndefinedDBTraceCodeUnitsMemoryView`, which extends the
    base making it suitable for composing views with undefined units. The realizations each extend
    from the appropriate abstract class. Again, the abstract classes do not nominally implement
    :obj:`TraceBaseCodeUnitsView`. They structurally implement it, partly satisfying the
    requirements on the realizations, which nominally implement their appropriate interfaces.
    """

    class DBTraceCodePrototypeEntry(ghidra.util.database.DBAnnotatedObject, ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses):
        """
        A prototype entry
        
         
        
        Version history:
         
        * 1: Change :obj:`.address` to 10-byte fixed encoding
        * 0: Initial version and previous unversioned implementation
        """

        class_: typing.ClassVar[java.lang.Class]
        TABLE_NAME: typing.Final = "Prototypes"

        def __init__(self, manager: DBTraceCodeManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...

        def getPrototype(self) -> ghidra.program.model.lang.InstructionPrototype:
            ...

        @property
        def prototype(self) -> ghidra.program.model.lang.InstructionPrototype:
            ...


    @typing.type_check_only
    class ProtoProcessorContext(ghidra.program.model.lang.ProcessorContext):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, baseContextValue: ghidra.program.model.lang.RegisterValue):
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Code"

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, platformManager: ghidra.trace.database.guest.DBTracePlatformManager, dataTypeManager: ghidra.trace.database.data.DBTraceDataTypeManager, overlayAdapter: ghidra.trace.database.address.DBTraceOverlaySpaceAdapter, referenceManager: ghidra.trace.database.symbol.DBTraceReferenceManager):
        ...

    def clearData(self, deletedDataTypeIds: java.util.Set[java.lang.Long], monitor: ghidra.util.task.TaskMonitor):
        ...

    def clearPlatform(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, guest: ghidra.trace.database.guest.DBTraceGuestPlatform, monitor: ghidra.util.task.TaskMonitor):
        ...

    def deleteLangauge(self, guest: ghidra.trace.database.guest.DBTraceGuestPlatform.DBTraceGuestLanguage, monitor: ghidra.util.task.TaskMonitor):
        ...

    def deletePlatform(self, guest: ghidra.trace.database.guest.DBTraceGuestPlatform, monitor: ghidra.util.task.TaskMonitor):
        ...

    def doCreateUndefinedUnit(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, thread: ghidra.trace.model.thread.TraceThread, frameLevel: typing.Union[jpype.JInt, int]) -> UndefinedDBTraceData:
        ...

    def replaceDataTypes(self, dataTypeReplacementMap: collections.abc.Mapping):
        ...


class DBTraceData(AbstractDBTraceCodeUnit[DBTraceData], DBTraceDefinedDataAdapter):
    """
    The implementation for a defined :obj:`TraceData` for :obj:`DBTrace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceData, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        """
        Construct a data unit
        
        :param DBTraceCodeSpace space: the space
        :param ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceData, typing.Any] tree: the storage R*-Tree
        :param ghidra.util.database.DBCachedObjectStore[typing.Any] store: the object store
        :param db.DBRecord record: the record
        """

    @staticmethod
    def getBaseDataType(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Get the base data type of the given data type, following typedefs recursively
        
        :param ghidra.program.model.data.DataType dt: the data type
        :return: the base data type
        :rtype: ghidra.program.model.data.DataType
        """


class AbstractDBTraceCodeUnit(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[T], DBTraceCodeUnitAdapter, typing.Generic[T]):
    """
    An abstract implementation of a table-backed code unit
    
     
    
    This is implemented as a data entry in an address-snap-range property map. This is not suitable
    for data components, nor for undefined units.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[T, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        """
        Construct a code unit
        
        :param DBTraceCodeSpace space: the space
        :param ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[T, typing.Any] tree: the storage R*-Tree
        :param ghidra.util.database.DBCachedObjectStore[typing.Any] store: the object store
        :param db.DBRecord record: the record
        """


class DBTraceInstructionsView(AbstractBaseDBTraceDefinedUnitsView[DBTraceInstruction], ghidra.trace.model.listing.TraceInstructionsView, InternalTraceBaseDefinedUnitsView[ghidra.trace.model.listing.TraceInstruction]):
    """
    The implementation of :meth:`TraceCodeSpace.instructions() <TraceCodeSpace.instructions>`
    """

    @typing.type_check_only
    class InstructionBlockAdder(java.lang.Object):
        """
        A mechanism for adding a block of instructions
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace):
        """
        Construct the view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        """


class AbstractBaseDBTraceCodeUnitsMemoryView(ghidra.trace.database.space.DBTraceDelegatingManager[M], typing.Generic[T, M]):
    """
    An abstract implementation of :obj:`TraceBaseCodeUnitsView` for composing views of many address
    spaces
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager):
        """
        Construct a composite view
        
        :param DBTraceCodeManager manager: the code manager, from which individual views are retrieved
        """

    def containsAddress(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> bool:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: true if contained
        :rtype: bool
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.containsAddress(long, Address)`
        """

    @typing.overload
    def coversRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> bool:
        """
        
        
        :param ghidra.trace.model.Lifespan span: the span
        :param ghidra.program.model.address.AddressRange range: the range
        :return: true if covered
        :rtype: bool
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.coversRange(Lifespan, AddressRange)`
        """

    @typing.overload
    def coversRange(self, range: ghidra.trace.model.TraceAddressSnapRange) -> bool:
        """
        
        
        :param ghidra.trace.model.TraceAddressSnapRange range: the range in space and time
        :return: true if covered
        :rtype: bool
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.coversRange(TraceAddressSnapRange)`
        """

    @typing.overload
    def emptyOrFullIterableUndefined(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        The result of iteration when there is no view or space for the given range's space
         
         
        
        Views composing undefiend units should return an iterable that generates (possibly caching)
        undefined units. Others should leave this empty.
        
        :param jpype.JLong or int snap: the snap the client requested
        :param ghidra.program.model.address.AddressRange range: the range of iteration
        :param jpype.JBoolean or bool forward: true to iterate forward (min to max), false for backward (max to min)
        :return: an iterable of units
        :rtype: java.lang.Iterable[T]
        """

    @typing.overload
    def emptyOrFullIterableUndefined(self, tasr: ghidra.trace.model.TraceAddressSnapRange) -> java.lang.Iterable[T]:
        """
        
        
        :param ghidra.trace.model.TraceAddressSnapRange tasr: the range of space and time to cover
        :return: the iterable
        :rtype: java.lang.Iterable[T]
        
        .. seealso::
        
            | :obj:`.emptyOrFullIterableUndefined(long, AddressRange, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address min: the min address
        :param ghidra.program.model.address.Address max: the max address
        :param jpype.JBoolean or bool forward: true to iterate forward
        :return: an iterable of units
        :rtype: java.lang.Iterable[T]
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, Address, Address, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.AddressSetView set: the address set
        :param jpype.JBoolean or bool forward: true to iterate forward
        :return: an iterable of units
        :rtype: java.lang.Iterable[T]
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, AddressSetView, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.AddressRange range: the address range
        :param jpype.JBoolean or bool forward: true to iterate forward
        :return: an iterable of units
        :rtype: java.lang.Iterable[T]
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, AddressRange, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address start: the start address
        :param jpype.JBoolean or bool forward: true to iterate forward
        :return: an iterable of units
        :rtype: java.lang.Iterable[T]
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, Address, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JBoolean or bool forward: true to iterate forward
        :return: an iterable of units
        :rtype: java.lang.Iterable[T]
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, boolean)`
        """

    @typing.overload
    def getAddressSetView(self, snap: typing.Union[jpype.JLong, int], within: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.AddressRange within: the range to consider
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getAddressSetView(long, AddressRange)`
        """

    @typing.overload
    def getAddressSetView(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getAddressSetView(long)`
        """

    def getAfter(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the unit or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getAfter(long, Address)`
        """

    def getAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the unit or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getAt(long, Address)`
        """

    def getBefore(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the unit or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getBefore(long, Address)`
        """

    def getCeiling(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the unit or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getCeiling(long, Address)`
        """

    def getContaining(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the unit or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getContaining(long, Address)`
        """

    def getFloor(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the unit or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getFloor(long, Address)`
        """

    def getIntersecting(self, tasr: ghidra.trace.model.TraceAddressSnapRange) -> java.lang.Iterable[T]:
        """
        
        
        :param ghidra.trace.model.TraceAddressSnapRange tasr: the range in space and time to cover
        :return: an iterable of units
        :rtype: java.lang.Iterable[T]
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getIntersecting(TraceAddressSnapRange)`
        """

    def getSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getTrace()`
        """

    @typing.overload
    def intersectsRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> bool:
        """
        
        
        :param ghidra.trace.model.Lifespan span: the span
        :param ghidra.program.model.address.AddressRange range: the range
        :return: true if intersected
        :rtype: bool
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.intersectsRange(Lifespan, AddressRange)`
        """

    @typing.overload
    def intersectsRange(self, range: ghidra.trace.model.TraceAddressSnapRange) -> bool:
        """
        
        
        :param ghidra.trace.model.TraceAddressSnapRange range: the range in space and time
        :return: true if intersected
        :rtype: bool
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.intersectsRange(TraceAddressSnapRange)`
        """

    def size(self) -> int:
        """
        
        
        :return: the number of defined units
        :rtype: int
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.size()`
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def intersecting(self) -> java.lang.Iterable[T]:
        ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addressSetView(self) -> ghidra.program.model.address.AddressSetView:
        ...


class DBTraceInstruction(AbstractDBTraceCodeUnit[DBTraceInstruction], ghidra.trace.model.listing.TraceInstruction, ghidra.trace.util.InstructionAdapterFromPrototype, ghidra.program.model.lang.InstructionContext):
    """
    The implementation of :obj:`TraceInstruction` for :obj:`DBTrace`
    """

    @typing.type_check_only
    class GuestInstructionContext(ghidra.program.model.lang.InstructionContext):
        """
        A context for guest instructions that maps addresses appropriately
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GuestMemBuffer(ghidra.program.model.mem.MemBufferMixin):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceInstruction, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        """
        Construct an instruction unit
        
        :param DBTraceCodeSpace space: the space
        :param ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceInstruction, typing.Any] tree: the storage R*-Tree
        :param ghidra.util.database.DBCachedObjectStore[typing.Any] store: the object store
        :param db.DBRecord record: the record
        """


class DBTraceDefinedUnitsMemoryView(AbstractBaseDBTraceCodeUnitsMemoryView[AbstractDBTraceCodeUnit[typing.Any], DBTraceDefinedUnitsView], ghidra.trace.model.listing.TraceDefinedUnitsView, InternalTraceBaseDefinedUnitsView[ghidra.trace.model.listing.TraceCodeUnit]):
    """
    The implementation of :meth:`TraceCodeManager.definedUnits() <TraceCodeManager.definedUnits>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager):
        """
        Construct the view
        
        :param DBTraceCodeManager manager: the manager
        """


class AbstractDBTraceDataComponent(DBTraceDefinedDataAdapter):
    """
    An abstract implementation of a :obj:`TraceData` for a data component, i.e., field of a struct
    or element of an array
    
     
    
    These are not backed directly by a table. The root data unit, along with its type, is stored in
    the table. If the type is composite, then these are generated, possibly recursively, for the
    components therein.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, root: DBTraceData, parent: DBTraceDefinedDataAdapter, index: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]):
        """
        Create a data component
        
        :param DBTraceData root: the root data unit
        :param DBTraceDefinedDataAdapter parent: the parent component, possibly the root
        :param jpype.JInt or int index: the index of this component in its parent
        :param ghidra.program.model.address.Address address: the minimum address of this component
        :param ghidra.program.model.data.DataType dataType: the data type of this component
        :param jpype.JInt or int length: the length of this component
        """

    def getFieldSyntax(self) -> str:
        ...

    @property
    def fieldSyntax(self) -> java.lang.String:
        ...


class DBTraceCommentAdapter(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap[DBTraceCommentAdapter.DBTraceCommentEntry, DBTraceCommentAdapter.DBTraceCommentEntry]):
    """
    A property map for storing code unit comments
    """

    class DBTraceCommentEntry(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[DBTraceCommentAdapter.DBTraceCommentEntry]):
        """
        A comment entry
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceCommentAdapter.DBTraceCommentEntry, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...

        def getType(self) -> int:
            ...

        @property
        def type(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
        ...

    @staticmethod
    def arrayFromComment(comment: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        """
        Split a comment into an array of lines
        
        :param java.lang.String or str comment: the comment text or null
        :return: the array of lines or null
        :rtype: jpype.JArray[java.lang.String]
        """

    def clearComments(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, commentType: ghidra.program.model.listing.CommentType):
        """
        Clear all comments in the given box of the given type
        
        :param ghidra.trace.model.Lifespan span: the lifespan fo the box
        :param ghidra.program.model.address.AddressRange range: the address range of the box
        :param ghidra.program.model.listing.CommentType commentType: a comment type to clear, or null to clear all.
        """

    @staticmethod
    def commentFromArray(comment: jpype.JArray[java.lang.String]) -> str:
        """
        Construct a comment from an array of lines
        
        :param jpype.JArray[java.lang.String] comment: the lines or null
        :return: the comment text or null
        :rtype: str
        """

    def getComment(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, commentType: ghidra.program.model.listing.CommentType) -> str:
        """
        Get the comment at the given point
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :param ghidra.program.model.listing.CommentType commentType: the type of comment
        :return: the comment text
        :rtype: str
        """

    def setComment(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, commentType: ghidra.program.model.listing.CommentType, comment: typing.Union[java.lang.String, str]):
        """
        Set a comment at the given address for the given lifespan
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan
        :param ghidra.program.model.address.Address address: the address
        :param ghidra.program.model.listing.CommentType commentType: the type of comment as in
                    :meth:`Listing.setComment(Address, CommentType, String) <Listing.setComment>`
        :param java.lang.String or str comment: the comment
        """


class DBTraceDefinedUnitsView(AbstractComposedDBTraceCodeUnitsView[AbstractDBTraceCodeUnit[typing.Any], AbstractBaseDBTraceDefinedUnitsView[AbstractDBTraceCodeUnit[typing.Any]]], ghidra.trace.model.listing.TraceDefinedUnitsView, InternalTraceBaseDefinedUnitsView[ghidra.trace.model.listing.TraceCodeUnit]):
    """
    The implementation of :meth:`TraceCodeSpace.data() <TraceCodeSpace.data>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace):
        """
        Construct the view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        """


class DBTraceCodeSpace(ghidra.trace.model.listing.TraceCodeSpace, ghidra.trace.database.space.DBTraceSpaceBased):
    """
    A space managed by the :obj:`DBTraceCodeManager`
     
     
    
    This implements :meth:`TraceCodeManager.getCodeSpace(AddressSpace, boolean) <TraceCodeManager.getCodeSpace>` and
    :meth:`TraceCodeManager.getCodeRegisterSpace(TraceThread, int, boolean) <TraceCodeManager.getCodeRegisterSpace>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager, dbh: db.DBHandle, space: ghidra.program.model.address.AddressSpace, ent: ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry):
        """
        Construct a space
        
        :param DBTraceCodeManager manager: the manager
        :param db.DBHandle dbh: the database handle
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry ent: an entry describing this space
        :raises VersionException: if there is already a table of a different version
        :raises IOException: if there is trouble accessing the database
        """

    def bytesChanged(self, changed: java.util.Set[ghidra.trace.model.TraceAddressSnapRange], snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, oldBytes: jpype.JArray[jpype.JByte], newBytes: jpype.JArray[jpype.JByte]):
        """
        Notify this space that some bytes have changed
         
         
        
        If any unit(s) contained the changed bytes, they may need to be truncated, deleted, and/or
        replaced. Instructions are generally truncated or deleted without replacement. A data unit
        may be replaced if its length would match that of the original.
        
        :param java.util.Set[ghidra.trace.model.TraceAddressSnapRange] changed: the boxes whose bytes changed
        :param jpype.JLong or int snap: the snap where the client requested the change
        :param ghidra.program.model.address.Address start: the starting address where the client requested the change
        :param jpype.JArray[jpype.JByte] oldBytes: the old bytes
        :param jpype.JArray[jpype.JByte] newBytes: the new bytes
        """


class UndefinedDBTraceData(DBTraceDataAdapter, ghidra.trace.util.TraceSpaceMixin):
    """
    The implementation for an undefined :obj:`TraceData` for :obj:`DBTrace`
     
     
    
    These are not backed by a table. They are generated ephemerally. Each is exactly one unit in size
    in both time and space.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.database.DBTrace, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, thread: ghidra.trace.model.thread.TraceThread, frameLevel: typing.Union[jpype.JInt, int]):
        """
        Construct an undefined unit
        
        :param ghidra.trace.database.DBTrace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :param ghidra.trace.model.thread.TraceThread thread: the thread, if in a per-thread space
        :param jpype.JInt or int frameLevel: the frame, if in a per-frame space
        """


class DBTraceUndefinedDataMemoryView(AbstractWithUndefinedDBTraceCodeUnitsMemoryView[UndefinedDBTraceData, DBTraceUndefinedDataView], ghidra.trace.model.listing.TraceUndefinedDataView, InternalBaseCodeUnitsView[ghidra.trace.model.listing.TraceData]):
    """
    The implementation of :meth:`TraceCodeManager.undefinedData() <TraceCodeManager.undefinedData>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager):
        """
        Construct the view
        
        :param DBTraceCodeManager manager: the manager
        """


class DBTraceDataArrayElementComponent(AbstractDBTraceDataComponent):
    """
    The implementation of an array-element data component in a :obj:`DBTrace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, root: DBTraceData, parent: DBTraceDefinedDataAdapter, index: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]):
        """
        Create an array element
        
        :param DBTraceData root: the root data unit
        :param DBTraceDefinedDataAdapter parent: the parent component, possibly the root
        :param jpype.JInt or int index: the index of this component in its parent
        :param ghidra.program.model.address.Address address: the minimum address of this component
        :param ghidra.program.model.data.DataType dataType: the data type of this component
        :param jpype.JInt or int length: the length of this component
        """


class InternalTraceBaseDefinedUnitsView(ghidra.trace.model.listing.TraceBaseDefinedUnitsView[T], InternalBaseCodeUnitsView[T], typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AbstractBaseDBTraceDefinedUnitsView(AbstractSingleDBTraceCodeUnitsView[T], typing.Generic[T]):
    """
    An abstract implementation of a single-type view for a defined unit type
    
     
    
    This is *note* a base class of :obj:`DBTraceDefinedUnitsView`. This class supports the
    implementation of one or the other: Instruction or Defined data. :obj:`DBTraceDefinedUnitsView`
    is the implementation of the composition of both.
    """

    @typing.type_check_only
    class CacheForGetUnitContainingQueries(ghidra.trace.database.DBTraceCacheForContainingQueries[ghidra.trace.database.DBTraceCacheForContainingQueries.GetKey, T, T]):
        """
        Cache for optimizing :meth:`AbstractBaseDBTraceDefinedUnitsView.getAt(long, Address) <AbstractBaseDBTraceDefinedUnitsView.getAt>`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class CacheForGetUnitSequenceQueries(ghidra.trace.database.DBTraceCacheForSequenceQueries[T]):
        """
        Cache for optimizing :meth:`AbstractBaseDBTraceDefinedUnitsView.getFloor(long, Address) <AbstractBaseDBTraceDefinedUnitsView.getFloor>` and
        similar.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace, mapSpace: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace[T, T]):
        """
        Construct the view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        :param ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace[T, T] mapSpace: the map storing the actual code unit entries
        """

    def clear(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, clearContext: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseDefinedUnitsView.clear(Lifespan, AddressRange, boolean, TaskMonitor)`
        """

    def invalidateCache(self):
        """
        Invalidate the query-optimizing caches for this view
        """


class DBTraceDefinedDataAdapter(DBTraceDataAdapter):
    """
    A base interface for implementations of :obj:`TraceData`
     
     
    
    This behaves somewhat like a mixin, allowing it to be used on defined data units as well as data
    components, e.g., fields of a struct data unit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def doGetComponent(self, componentPath: jpype.JArray[jpype.JInt], level: typing.Union[jpype.JInt, int]) -> DBTraceDefinedDataAdapter:
        ...

    def doGetComponentCache(self) -> jpype.JArray[AbstractDBTraceDataComponent]:
        """
        TODO: Document me
         
        Note this will always be called with the write lock
        
        :return: the new or existing component cache
        :rtype: jpype.JArray[AbstractDBTraceDataComponent]
        """

    def getPathName(self, builder: java.lang.StringBuilder, includeRootSymbol: typing.Union[jpype.JBoolean, bool]) -> java.lang.StringBuilder:
        ...


class AbstractBaseDBTraceCodeUnitsView(java.lang.Object, typing.Generic[T]):
    """
    An abstract implementation of a :obj:`TraceBaseCodeUnitsView` for a specific address space
    
     
    
    Note that this class does not declare :obj:`TraceBaseCodeUnitsView` as an implemented interface,
    thought it does implement it structurally. If it were implemented nominally, the realizations
    would inherit the same interface twice, with different type parameters, which is not allowed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace):
        """
        Construct a view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        """

    def containsAddress(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.containsAddress(long, Address)`
        """

    @typing.overload
    def coversRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.coversRange(Lifespan, AddressRange)`
        """

    @typing.overload
    def coversRange(self, range: ghidra.trace.model.TraceAddressSnapRange) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.coversRange(TraceAddressSnapRange)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, Address, Address, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, AddressSetView, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, AddressRange, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, Address, boolean)`
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.get(long, boolean)`
        """

    @typing.overload
    def getAddressSetView(self, snap: typing.Union[jpype.JLong, int], within: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getAddressSetView(long, AddressRange)`
        """

    @typing.overload
    def getAddressSetView(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getAddressSetView(long)`
        """

    def getAfter(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getAfter(long, Address)`
        """

    def getAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getAt(long, Address)`
        """

    def getBefore(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getBefore(long, Address)`
        """

    def getCeiling(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getCeiling(long, Address)`
        """

    def getContaining(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getContaining(long, Address)`
        """

    def getFloor(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getFloor(long, Address)`
        """

    def getIntersecting(self, tasr: ghidra.trace.model.TraceAddressSnapRange) -> java.lang.Iterable[T]:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getIntersecting(TraceAddressSnapRange)`
        """

    def getSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.getTrace()`
        """

    @typing.overload
    def intersectsRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.intersectsRange(Lifespan, AddressRange)`
        """

    @typing.overload
    def intersectsRange(self, range: ghidra.trace.model.TraceAddressSnapRange) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.intersectsRange(TraceAddressSnapRange)`
        """

    def size(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`TraceBaseCodeUnitsView.size()`
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def intersecting(self) -> java.lang.Iterable[T]:
        ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addressSetView(self) -> ghidra.program.model.address.AddressSetView:
        ...


class DBTraceDefinedDataView(AbstractBaseDBTraceDefinedUnitsView[DBTraceData], InternalTraceDefinedDataView):
    """
    The implementation of :meth:`TraceCodeSpace.definedData() <TraceCodeSpace.definedData>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace):
        """
        Construct the view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        """


class AbstractComposedDBTraceCodeUnitsView(AbstractBaseDBTraceCodeUnitsView[T], typing.Generic[T, P]):
    """
    An abstract implementation of a multi-type view, by composing other single-type views
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace, parts: collections.abc.Sequence):
        """
        Construct a view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        :param collections.abc.Sequence parts: the single-type views composed
        """


class DBTraceCodeUnitAdapter(ghidra.trace.model.listing.TraceCodeUnit, ghidra.program.model.mem.MemBufferMixin):
    """
    A base interface for implementations of :obj:`TraceCodeUnit`
     
     
    
    This behaves somewhat like a mixin, allowing it to be used on code units as well as data
    components, e.g., fields of a struct data unit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class DBTraceDefinedDataMemoryView(AbstractBaseDBTraceCodeUnitsMemoryView[DBTraceData, DBTraceDefinedDataView], InternalTraceDefinedDataView):
    """
    The implementation of :meth:`TraceCodeManager.definedData() <TraceCodeManager.definedData>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager):
        """
        Construct the view
        
        :param DBTraceCodeManager manager: the manager
        """


class DBTraceCodeUnitsView(AbstractComposedDBTraceCodeUnitsView[DBTraceCodeUnitAdapter, AbstractSingleDBTraceCodeUnitsView[DBTraceCodeUnitAdapter]], ghidra.trace.model.listing.TraceCodeUnitsView, InternalBaseCodeUnitsView[ghidra.trace.model.listing.TraceCodeUnit]):
    """
    The implementation of :meth:`TraceCodeSpace.codeUnits() <TraceCodeSpace.codeUnits>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace):
        """
        Construct the view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        """


class DBTraceUndefinedDataView(AbstractSingleDBTraceCodeUnitsView[UndefinedDBTraceData], ghidra.trace.model.listing.TraceUndefinedDataView, InternalBaseCodeUnitsView[ghidra.trace.model.listing.TraceData]):
    """
    The implementation of :meth:`TraceCodeSpace.undefinedData() <TraceCodeSpace.undefinedData>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace):
        """
        Construct the view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        """

    def invalidateCache(self):
        """
        Invalidate the cache of generated undefined units
        """


class InternalBaseCodeUnitsView(ghidra.trace.model.listing.TraceBaseCodeUnitsView[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def getSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...


class InternalTraceDefinedDataView(ghidra.trace.model.listing.TraceDefinedDataView, InternalTraceBaseDefinedUnitsView[ghidra.trace.model.listing.TraceData]):

    class_: typing.ClassVar[java.lang.Class]

    def getPlatformOf(self, type: ghidra.program.model.data.DataType) -> ghidra.trace.model.guest.TracePlatform:
        ...

    @property
    def platformOf(self) -> ghidra.trace.model.guest.TracePlatform:
        ...


class AbstractSingleDBTraceCodeUnitsView(AbstractBaseDBTraceCodeUnitsView[T], typing.Generic[T]):
    """
    An abstract implementation of a single-type view
    
    
    .. admonition:: Implementation Note
    
        This class cannot be removed. Despite it appearing not to do anything, this class
        serves as an upper bound on the views composed by
        :obj:`AbstractComposedDBTraceCodeUnitsView`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace):
        """
        Construct a view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        """


class AbstractWithUndefinedDBTraceCodeUnitsMemoryView(AbstractBaseDBTraceCodeUnitsMemoryView[T, M], typing.Generic[T, M]):
    """
    An abstract implementation of :obj:`TraceBaseCodeUnitsView` for composing views of many address
    spaces, where the views include undefined units
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager):
        """
        Construct a composite view
        
        :param DBTraceCodeManager manager: the code manager, from which individual views are retrieved
        """


class DBTraceDataAdapter(DBTraceCodeUnitAdapter, ghidra.trace.util.DataAdapterMinimal, ghidra.trace.util.DataAdapterFromDataType, ghidra.trace.util.DataAdapterFromSettings, ghidra.trace.model.listing.TraceData):
    """
    A base interface for implementations of :obj:`TraceData`
     
     
    
    This behaves somewhat like a mixin, allowing it to be used on data units as well as data
    components, e.g., fields of a struct data unit.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_STRING_ARRAY: typing.Final[jpype.JArray[java.lang.String]]

    def getSettingsSpace(self, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> ghidra.trace.database.data.DBTraceDataSettingsOperations:
        """
        Get the same space from the internal settings adapter
        
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if its not already present
        :return: the space or null
        :rtype: ghidra.trace.database.data.DBTraceDataSettingsOperations
        """

    @property
    def settingsSpace(self) -> ghidra.trace.database.data.DBTraceDataSettingsOperations:
        ...


class DBTraceDataView(AbstractComposedDBTraceCodeUnitsView[DBTraceDataAdapter, AbstractSingleDBTraceCodeUnitsView[DBTraceDataAdapter]], ghidra.trace.model.listing.TraceDataView, InternalBaseCodeUnitsView[ghidra.trace.model.listing.TraceData]):
    """
    The implementation of :meth:`TraceCodeSpace.data() <TraceCodeSpace.data>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceCodeSpace):
        """
        Construct the view
        
        :param DBTraceCodeSpace space: the space, bound to an address space
        """


class DBTraceDataCompositeFieldComponent(AbstractDBTraceDataComponent):
    """
    The implementation of a field data component in a :obj:`DBTrace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, root: DBTraceData, parent: DBTraceDefinedDataAdapter, address: ghidra.program.model.address.Address, dtc: ghidra.program.model.data.DataTypeComponent):
        """
        Create a field
        
        :param DBTraceData root: the root data unit
        :param DBTraceDefinedDataAdapter parent: the parent component, possibly the root
        :param ghidra.program.model.address.Address address: the minimum address of this component
        :param ghidra.program.model.data.DataTypeComponent dtc: the data type component, giving the index, data type, and length
        """


class DBTraceInstructionsMemoryView(AbstractBaseDBTraceCodeUnitsMemoryView[DBTraceInstruction, DBTraceInstructionsView], ghidra.trace.model.listing.TraceInstructionsView, InternalTraceBaseDefinedUnitsView[ghidra.trace.model.listing.TraceInstruction]):
    """
    The implementation of :meth:`TraceCodeManager.definedData() <TraceCodeManager.definedData>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceCodeManager):
        """
        Construct the view
        
        :param DBTraceCodeManager manager: the manager
        """



__all__ = ["DBTraceDataMemoryView", "DBTraceCodeUnitsMemoryView", "DBTraceCodeManager", "DBTraceData", "AbstractDBTraceCodeUnit", "DBTraceInstructionsView", "AbstractBaseDBTraceCodeUnitsMemoryView", "DBTraceInstruction", "DBTraceDefinedUnitsMemoryView", "AbstractDBTraceDataComponent", "DBTraceCommentAdapter", "DBTraceDefinedUnitsView", "DBTraceCodeSpace", "UndefinedDBTraceData", "DBTraceUndefinedDataMemoryView", "DBTraceDataArrayElementComponent", "InternalTraceBaseDefinedUnitsView", "AbstractBaseDBTraceDefinedUnitsView", "DBTraceDefinedDataAdapter", "AbstractBaseDBTraceCodeUnitsView", "DBTraceDefinedDataView", "AbstractComposedDBTraceCodeUnitsView", "DBTraceCodeUnitAdapter", "DBTraceDefinedDataMemoryView", "DBTraceCodeUnitsView", "DBTraceUndefinedDataView", "InternalBaseCodeUnitsView", "InternalTraceDefinedDataView", "AbstractSingleDBTraceCodeUnitsView", "AbstractWithUndefinedDBTraceCodeUnitsMemoryView", "DBTraceDataAdapter", "DBTraceDataView", "DBTraceDataCompositeFieldComponent", "DBTraceInstructionsMemoryView"]
