from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.util
import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.trace.model
import ghidra.trace.model.bookmark
import ghidra.trace.model.breakpoint
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.memory
import ghidra.trace.model.modules
import ghidra.trace.model.stack
import ghidra.trace.model.symbol
import ghidra.trace.model.target
import ghidra.trace.model.thread
import ghidra.trace.model.time
import ghidra.util
import ghidra.util.datastruct
import java.lang # type: ignore
import java.nio # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import org.apache.commons.lang3.tuple # type: ignore


E = typing.TypeVar("E")
K = typing.TypeVar("K")
L = typing.TypeVar("L")
R = typing.TypeVar("R")
T = typing.TypeVar("T")
U = typing.TypeVar("U")
V = typing.TypeVar("V")


class TypedEventDispatcher(java.lang.Object):

    class EventRecordHandler(java.lang.Object, typing.Generic[T, U]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self, record: TraceChangeRecord[T, U]):
            ...


    class FullEventRecordHandler(TypedEventDispatcher.EventRecordHandler[T, U], typing.Generic[T, U]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self, space: ghidra.program.model.address.AddressSpace, affectedObject: T, oldValue: U, newValue: U):
            ...


    class AffectedObjectHandler(TypedEventDispatcher.EventRecordHandler[T, java.lang.Void], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self, space: ghidra.program.model.address.AddressSpace, affectedObject: T):
            ...


    class AffectedObjectOnlyHandler(TypedEventDispatcher.EventRecordHandler[T, java.lang.Void], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self, affectedObject: T):
            ...


    class AffectedAndValuesOnlyHandler(TypedEventDispatcher.EventRecordHandler[T, U], typing.Generic[T, U]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self, affectedObject: T, oldValue: U, newValue: U):
            ...


    class SpaceValuesHandler(TypedEventDispatcher.EventRecordHandler[java.lang.Void, U], typing.Generic[U]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self, space: ghidra.program.model.address.AddressSpace, oldValue: U, newValue: U):
            ...


    class ValuesOnlyHandler(TypedEventDispatcher.EventRecordHandler[java.lang.Void, U], typing.Generic[U]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self, oldValue: U, newValue: U):
            ...


    class IgnoreValuesHandler(TypedEventDispatcher.EventRecordHandler[java.lang.Object, java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self, space: ghidra.program.model.address.AddressSpace):
            ...


    class IgnoreAllHandler(TypedEventDispatcher.EventRecordHandler[java.lang.Object, java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]

        def handle(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def handleChangeRecord(self, rec: ghidra.framework.model.DomainObjectChangeRecord):
        ...

    def handleTraceChangeRecord(self, rec: TraceChangeRecord[typing.Any, typing.Any]):
        ...


class DataAdapterFromSettings(ghidra.program.model.listing.Data):

    class_: typing.ClassVar[java.lang.Class]

    def getSettingsDefinition(self, settingsDefinitionClass: java.lang.Class[T]) -> T:
        ...

    def hasMutability(self, mutabilityType: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @property
    def settingsDefinition(self) -> T:
        ...


class CopyOnWrite(java.lang.Object):

    class AbstractCowMap(java.util.Map[K, V], typing.Generic[K, V]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class HashCowMap(CopyOnWrite.AbstractCowMap[K, V], typing.Generic[K, V]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class WeakValueAbstractCowMap(ghidra.util.datastruct.AbstractWeakValueMap[K, V], typing.Generic[K, V]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class WeakValueHashCowMap(CopyOnWrite.WeakValueAbstractCowMap[K, V], typing.Generic[K, V]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class WeakAbstractCowSet(java.util.AbstractSet[E], typing.Generic[E]):
        """
        Assumes elements use system hash equality, i.e., :meth:`E.equals(Object) <E.equals>` is ignored
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class WeakHashCowSet(CopyOnWrite.WeakAbstractCowSet[E], typing.Generic[E]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]


class EnumeratingIterator(java.util.Iterator[T], typing.Generic[T]):

    class WrappingEnumeratingIterator(EnumeratingIterator[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, it: java.util.Iterator[T]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def castOrWrap(it: java.util.Iterator[T]) -> EnumeratingIterator[T]:
        ...

    def getIndex(self) -> int:
        """
        Get the index of the last element returned by :meth:`next() <.next>`.
        
        :return: the index of the last iterated element.
        :rtype: int
        """

    @property
    def index(self) -> jpype.JInt:
        ...


class TraceSpaceMixin(java.lang.Object):
    """
    Add conveniences for getting the thread and frame level, if applicable, from an object's address
    space.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the object's address space
        
        :return: the address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getFrameLevel(self) -> int:
        """
        Get the frame level denoted by the object's address space
         
         
        
        Note this will return 0 if the frame level is not applicable. This is the same as the
        innermost frame level when it is applicable. To distinguish whether or not a 0 return value
        is applicable, you must examine the path or schema.
        
        :return: the level or 0
        :rtype: int
        """

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the thread denoted by the object's address space
        
        :return: the thread
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing the object
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def frameLevel(self) -> jpype.JInt:
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...


class WrappingInstructionIterator(ghidra.program.model.listing.InstructionIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: java.util.Iterator[ghidra.program.model.listing.Instruction]):
        ...


class OverlappingObjectIterator(generic.util.AbstractPeekableIterator[org.apache.commons.lang3.tuple.Pair[L, R]], typing.Generic[L, R]):
    """
    An iterator of overlapping objects return from two given iterators.
     
     
    
    The given iterators, named left and right, must return objects each having a range attribute.
    Each iterator must return objects having disjoint ranges, i.e., no two objects from the
    *same* iterator may intersect. Each iterator must also return the objects sorted by min
    address. This iterator will then discover every case where an object from the left iterator
    overlaps an object from the right iterator, and return a pair for each such instance, in order of
    min address.
     
     
    
    **WARNING:** To avoid heap pollution, this iterator re-uses the same :obj:`Pair` on each call
    to :meth:`next() <.next>`. If you need to save an overlapping pair, you must copy it.
    """

    class Ranger(java.lang.Object, typing.Generic[T]):
        """
        A means of obtaining the range attribute from each object
        """

        class_: typing.ClassVar[java.lang.Class]

        def getMaxAddress(self, t: T) -> ghidra.program.model.address.Address:
            ...

        def getMinAddress(self, t: T) -> ghidra.program.model.address.Address:
            ...

        @property
        def maxAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def minAddress(self) -> ghidra.program.model.address.Address:
            ...


    class AddressRangeRanger(OverlappingObjectIterator.Ranger[ghidra.program.model.address.AddressRange]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class SnapRangeKeyRanger(OverlappingObjectIterator.Ranger[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, typing.Any]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class CodeUnitRanger(OverlappingObjectIterator.Ranger[ghidra.program.model.listing.CodeUnit]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class MyPair(org.apache.commons.lang3.tuple.Pair[L, R]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ADDRESS_RANGE: typing.Final[OverlappingObjectIterator.AddressRangeRanger]
    SNAP_RANGE_KEY: typing.Final[OverlappingObjectIterator.SnapRangeKeyRanger]
    CODE_UNIT: typing.Final[OverlappingObjectIterator.CodeUnitRanger]

    def __init__(self, left: java.util.Iterator[L], leftRanger: OverlappingObjectIterator.Ranger[L], right: java.util.Iterator[R], rightRanger: OverlappingObjectIterator.Ranger[R]):
        ...


class WrappingDataIterator(ghidra.program.model.listing.DataIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: java.util.Iterator[ghidra.program.model.listing.Data]):
        ...


class InstructionAdapterFromPrototype(ghidra.trace.model.listing.TraceInstruction):

    class_: typing.ClassVar[java.lang.Class]

    def getFullString(self) -> str:
        ...

    @property
    def fullString(self) -> java.lang.String:
        ...


class WrappingCodeUnitIterator(ghidra.program.model.listing.CodeUnitIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: java.util.Iterator[ghidra.program.model.listing.CodeUnit]):
        ...


class TraceChangeRecord(ghidra.framework.model.DomainObjectChangeRecord, typing.Generic[T, U]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, type: TraceEvent[T, U], space: ghidra.program.model.address.AddressSpace, affectedObject: T, oldValue: U, newValue: U):
        ...

    @typing.overload
    def __init__(self, type: TraceEvent[T, U], space: ghidra.program.model.address.AddressSpace, affectedObject: T, newValue: U):
        ...

    @typing.overload
    def __init__(self, type: TraceEvent[T, U], space: ghidra.program.model.address.AddressSpace, affectedObject: T):
        ...

    @typing.overload
    def __init__(self, type: TraceEvent[T, U], space: ghidra.program.model.address.AddressSpace):
        ...

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getAffectedObject(self) -> T:
        ...

    def isOldKnown(self) -> bool:
        ...

    @property
    def oldKnown(self) -> jpype.JBoolean:
        ...

    @property
    def affectedObject(self) -> T:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceChangeManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def setChanged(self, event: TraceChangeRecord[typing.Any, typing.Any]):
        ...


class TraceEvent(ghidra.framework.model.EventType, typing.Generic[T, U]):
    """
    A sub-type for event specific to traces.
     
     
    
    For the various defined events, see :obj:`TraceEvents`.
     
     
    
    This interface introduces two type parameters, which are provided by each trace event enum. They
    describe the type of the effected object, e.g., a thread, as well as the type of the changed
    value, e.g., its lifespan. These are can be enforced by using :obj:`TraceChangeRecord`. Its
    constructors will ensure that the affected object and values actually match the types for the
    given trace event. Conversely, by using :obj:`TraceDomainObjectListener` and registering
    handlers for each event type, it will ensure each handler method accepts arguments of the correct
    types. See, e.g., :meth:`TypedEventDispatcher.listenFor(TraceEvent, FullEventRecordHandler) <TypedEventDispatcher.listenFor>`.
    """

    class TraceObjectEvent(java.lang.Enum[TraceEvent.TraceObjectEvent], TraceEvent[ghidra.trace.model.target.TraceObject, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        OBJECT_CREATED: typing.Final[TraceEvent.TraceObjectEvent]
        OBJECT_LIFE_CHANGED: typing.Final[TraceEvent.TraceObjectEvent]
        OBJECT_DELETED: typing.Final[TraceEvent.TraceObjectEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceObjectEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceObjectEvent]:
            ...


    class TraceObjectValueEvent(java.lang.Enum[TraceEvent.TraceObjectValueEvent], TraceEvent[ghidra.trace.model.target.TraceObjectValue, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        VALUE_CREATED: typing.Final[TraceEvent.TraceObjectValueEvent]
        VALUE_DELETED: typing.Final[TraceEvent.TraceObjectValueEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceObjectValueEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceObjectValueEvent]:
            ...


    class TraceObjectValueLifespanEvent(java.lang.Enum[TraceEvent.TraceObjectValueLifespanEvent], TraceEvent[ghidra.trace.model.target.TraceObjectValue, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        VALUE_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceObjectValueLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceObjectValueLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceObjectValueLifespanEvent]:
            ...


    class TraceBookmarkTypeEvent(java.lang.Enum[TraceEvent.TraceBookmarkTypeEvent], TraceEvent[ghidra.trace.model.bookmark.TraceBookmarkType, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        BOOKMARK_TYPE_ADDED: typing.Final[TraceEvent.TraceBookmarkTypeEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceBookmarkTypeEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceBookmarkTypeEvent]:
            ...


    class TraceBookmarkEvent(java.lang.Enum[TraceEvent.TraceBookmarkEvent], TraceEvent[ghidra.trace.model.bookmark.TraceBookmark, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        BOOKMARK_ADDED: typing.Final[TraceEvent.TraceBookmarkEvent]
        BOOKMARK_CHANGED: typing.Final[TraceEvent.TraceBookmarkEvent]
        BOOKMARK_DELETED: typing.Final[TraceEvent.TraceBookmarkEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceBookmarkEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceBookmarkEvent]:
            ...


    class TraceBookmarkLifespanEvent(java.lang.Enum[TraceEvent.TraceBookmarkLifespanEvent], TraceEvent[ghidra.trace.model.bookmark.TraceBookmark, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        BOOKMARK_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceBookmarkLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceBookmarkLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceBookmarkLifespanEvent]:
            ...


    class TraceBreakpointEvent(java.lang.Enum[TraceEvent.TraceBreakpointEvent], TraceEvent[ghidra.trace.model.breakpoint.TraceBreakpointLocation, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        BREAKPOINT_ADDED: typing.Final[TraceEvent.TraceBreakpointEvent]
        BREAKPOINT_CHANGED: typing.Final[TraceEvent.TraceBreakpointEvent]
        BREAKPOINT_DELETED: typing.Final[TraceEvent.TraceBreakpointEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceBreakpointEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceBreakpointEvent]:
            ...


    class TraceBreakpointLifespanEvent(java.lang.Enum[TraceEvent.TraceBreakpointLifespanEvent], TraceEvent[ghidra.trace.model.breakpoint.TraceBreakpointLocation, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        BREAKPOINT_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceBreakpointLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceBreakpointLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceBreakpointLifespanEvent]:
            ...


    class TraceTypeCategoryEvent(java.lang.Enum[TraceEvent.TraceTypeCategoryEvent], TraceEvent[java.lang.Long, ghidra.program.model.data.Category]):

        class_: typing.ClassVar[java.lang.Class]
        TYPE_CATEGORY_ADDED: typing.Final[TraceEvent.TraceTypeCategoryEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceTypeCategoryEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceTypeCategoryEvent]:
            ...


    class TraceTypeCategoryPathEvent(java.lang.Enum[TraceEvent.TraceTypeCategoryPathEvent], TraceEvent[java.lang.Long, ghidra.program.model.data.CategoryPath]):

        class_: typing.ClassVar[java.lang.Class]
        TYPE_CATEGORY_MOVED: typing.Final[TraceEvent.TraceTypeCategoryPathEvent]
        TYPE_CATEGORY_DELETED: typing.Final[TraceEvent.TraceTypeCategoryPathEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceTypeCategoryPathEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceTypeCategoryPathEvent]:
            ...


    class TraceTypeCategoryStringEvent(java.lang.Enum[TraceEvent.TraceTypeCategoryStringEvent], TraceEvent[java.lang.Long, java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]
        TYPE_CATEGORY_RENAMED: typing.Final[TraceEvent.TraceTypeCategoryStringEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceTypeCategoryStringEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceTypeCategoryStringEvent]:
            ...


    class TraceCodeEvent(java.lang.Enum[TraceEvent.TraceCodeEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, ghidra.trace.model.listing.TraceCodeUnit]):

        class_: typing.ClassVar[java.lang.Class]
        CODE_ADDED: typing.Final[TraceEvent.TraceCodeEvent]
        CODE_REMOVED: typing.Final[TraceEvent.TraceCodeEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceCodeEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceCodeEvent]:
            ...


    class TraceCodeLifespanEvent(java.lang.Enum[TraceEvent.TraceCodeLifespanEvent], TraceEvent[ghidra.trace.model.listing.TraceCodeUnit, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        CODE_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceCodeLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceCodeLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceCodeLifespanEvent]:
            ...


    class TraceCodeFragmentEvent(java.lang.Enum[TraceEvent.TraceCodeFragmentEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, ghidra.program.model.listing.ProgramFragment]):

        class_: typing.ClassVar[java.lang.Class]
        CODE_FRAGMENT_CHANGED: typing.Final[TraceEvent.TraceCodeFragmentEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceCodeFragmentEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceCodeFragmentEvent]:
            ...


    class TraceCodeDataTypeEvent(java.lang.Enum[TraceEvent.TraceCodeDataTypeEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, java.lang.Long]):

        class_: typing.ClassVar[java.lang.Class]
        CODE_DATA_TYPE_REPLACED: typing.Final[TraceEvent.TraceCodeDataTypeEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceCodeDataTypeEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceCodeDataTypeEvent]:
            ...


    class TraceCodeDataSettingsEvent(java.lang.Enum[TraceEvent.TraceCodeDataSettingsEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        CODE_DATA_SETTINGS_CHANGED: typing.Final[TraceEvent.TraceCodeDataSettingsEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceCodeDataSettingsEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceCodeDataSettingsEvent]:
            ...


    class TraceCommentEvent(java.lang.Enum[TraceEvent.TraceCommentEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]
        PLATE_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
        PRE_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
        POST_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
        EOL_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
        REPEATABLE_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceCommentEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceCommentEvent]:
            ...


    class TraceCompositeDataEvent(java.lang.Enum[TraceEvent.TraceCompositeDataEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, ghidra.trace.model.listing.TraceData]):

        class_: typing.ClassVar[java.lang.Class]
        COMPOSITE_DATA_ADDED: typing.Final[TraceEvent.TraceCompositeDataEvent]
        COMPOSITE_DATA_REMOVED: typing.Final[TraceEvent.TraceCompositeDataEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceCompositeDataEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceCompositeDataEvent]:
            ...


    class TraceCompositeDataLifespanEvent(java.lang.Enum[TraceEvent.TraceCompositeDataLifespanEvent], TraceEvent[ghidra.trace.model.listing.TraceData, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        COMPOSITE_DATA_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceCompositeDataLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceCompositeDataLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceCompositeDataLifespanEvent]:
            ...


    class TraceDataTypeEvent(java.lang.Enum[TraceEvent.TraceDataTypeEvent], TraceEvent[java.lang.Long, ghidra.program.model.data.DataType]):

        class_: typing.ClassVar[java.lang.Class]
        DATA_TYPE_ADDED: typing.Final[TraceEvent.TraceDataTypeEvent]
        DATA_TYPE_CHANGED: typing.Final[TraceEvent.TraceDataTypeEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceDataTypeEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceDataTypeEvent]:
            ...


    class TraceDataTypePathEvent(java.lang.Enum[TraceEvent.TraceDataTypePathEvent], TraceEvent[java.lang.Long, ghidra.program.model.data.DataTypePath]):

        class_: typing.ClassVar[java.lang.Class]
        DATA_TYPE_REPLACED: typing.Final[TraceEvent.TraceDataTypePathEvent]
        DATA_TYPE_MOVED: typing.Final[TraceEvent.TraceDataTypePathEvent]
        DATA_TYPE_DELETED: typing.Final[TraceEvent.TraceDataTypePathEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceDataTypePathEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceDataTypePathEvent]:
            ...


    class TraceDataTypeStringEvent(java.lang.Enum[TraceEvent.TraceDataTypeStringEvent], TraceEvent[java.lang.Long, java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]
        DATA_TYPE_RENAMED: typing.Final[TraceEvent.TraceDataTypeStringEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceDataTypeStringEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceDataTypeStringEvent]:
            ...


    class TraceInstructionFlowEvent(java.lang.Enum[TraceEvent.TraceInstructionFlowEvent], TraceEvent[ghidra.trace.model.listing.TraceInstruction, ghidra.program.model.listing.FlowOverride]):

        class_: typing.ClassVar[java.lang.Class]
        INSTRUCTION_FLOW_OVERRIDE_CHANGED: typing.Final[TraceEvent.TraceInstructionFlowEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceInstructionFlowEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceInstructionFlowEvent]:
            ...


    class TraceInstructionBoolEvent(java.lang.Enum[TraceEvent.TraceInstructionBoolEvent], TraceEvent[ghidra.trace.model.listing.TraceInstruction, java.lang.Boolean]):

        class_: typing.ClassVar[java.lang.Class]
        INSTRUCTION_FALL_THROUGH_OVERRIDE_CHANGED: typing.Final[TraceEvent.TraceInstructionBoolEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceInstructionBoolEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceInstructionBoolEvent]:
            ...


    class TraceInstructionIntEvent(java.lang.Enum[TraceEvent.TraceInstructionIntEvent], TraceEvent[ghidra.trace.model.listing.TraceInstruction, java.lang.Integer]):

        class_: typing.ClassVar[java.lang.Class]
        INSTRUCTION_LENGTH_OVERRIDE_CHANGED: typing.Final[TraceEvent.TraceInstructionIntEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceInstructionIntEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceInstructionIntEvent]:
            ...


    class TraceBytesEvent(java.lang.Enum[TraceEvent.TraceBytesEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, jpype.JArray[jpype.JByte]]):

        class_: typing.ClassVar[java.lang.Class]
        BYTES_CHANGED: typing.Final[TraceEvent.TraceBytesEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceBytesEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceBytesEvent]:
            ...


    class TraceMemoryRegionEvent(java.lang.Enum[TraceEvent.TraceMemoryRegionEvent], TraceEvent[ghidra.trace.model.memory.TraceMemoryRegion, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        REGION_ADDED: typing.Final[TraceEvent.TraceMemoryRegionEvent]
        REGION_CHANGED: typing.Final[TraceEvent.TraceMemoryRegionEvent]
        REGION_DELETED: typing.Final[TraceEvent.TraceMemoryRegionEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceMemoryRegionEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceMemoryRegionEvent]:
            ...


    class TraceMemoryRegionLifespanEvent(java.lang.Enum[TraceEvent.TraceMemoryRegionLifespanEvent], TraceEvent[ghidra.trace.model.memory.TraceMemoryRegion, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        REGION_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceMemoryRegionLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceMemoryRegionLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceMemoryRegionLifespanEvent]:
            ...


    class TraceOverlaySpaceEvent(java.lang.Enum[TraceEvent.TraceOverlaySpaceEvent], TraceEvent[ghidra.trace.model.Trace, ghidra.program.model.address.AddressSpace]):

        class_: typing.ClassVar[java.lang.Class]
        OVERLAY_ADDED: typing.Final[TraceEvent.TraceOverlaySpaceEvent]
        OVERLAY_DELETED: typing.Final[TraceEvent.TraceOverlaySpaceEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceOverlaySpaceEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceOverlaySpaceEvent]:
            ...


    class TraceMemoryStateEvent(java.lang.Enum[TraceEvent.TraceMemoryStateEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, ghidra.trace.model.memory.TraceMemoryState]):

        class_: typing.ClassVar[java.lang.Class]
        BYTES_STATE_CHANGED: typing.Final[TraceEvent.TraceMemoryStateEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceMemoryStateEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceMemoryStateEvent]:
            ...


    class TraceModuleEvent(java.lang.Enum[TraceEvent.TraceModuleEvent], TraceEvent[ghidra.trace.model.modules.TraceModule, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        MODULE_ADDED: typing.Final[TraceEvent.TraceModuleEvent]
        MODULE_CHANGED: typing.Final[TraceEvent.TraceModuleEvent]
        MODULE_DELETED: typing.Final[TraceEvent.TraceModuleEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceModuleEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceModuleEvent]:
            ...


    class TraceModuleLifespanEvent(java.lang.Enum[TraceEvent.TraceModuleLifespanEvent], TraceEvent[ghidra.trace.model.modules.TraceModule, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        MODULE_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceModuleLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceModuleLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceModuleLifespanEvent]:
            ...


    class TraceSectionEvent(java.lang.Enum[TraceEvent.TraceSectionEvent], TraceEvent[ghidra.trace.model.modules.TraceSection, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        SECTION_ADDED: typing.Final[TraceEvent.TraceSectionEvent]
        SECTION_CHANGED: typing.Final[TraceEvent.TraceSectionEvent]
        SECTION_DELETED: typing.Final[TraceEvent.TraceSectionEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSectionEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSectionEvent]:
            ...


    class TraceReferenceEvent(java.lang.Enum[TraceEvent.TraceReferenceEvent], TraceEvent[ghidra.trace.model.TraceAddressSnapRange, ghidra.trace.model.symbol.TraceReference]):

        class_: typing.ClassVar[java.lang.Class]
        REFERENCE_ADDED: typing.Final[TraceEvent.TraceReferenceEvent]
        REFERENCE_DELETED: typing.Final[TraceEvent.TraceReferenceEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceReferenceEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceReferenceEvent]:
            ...


    class TraceReferenceLifespanEvent(java.lang.Enum[TraceEvent.TraceReferenceLifespanEvent], TraceEvent[ghidra.trace.model.symbol.TraceReference, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        REFERENCE_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceReferenceLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceReferenceLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceReferenceLifespanEvent]:
            ...


    class TraceReferenceBoolEvent(java.lang.Enum[TraceEvent.TraceReferenceBoolEvent], TraceEvent[ghidra.trace.model.symbol.TraceReference, java.lang.Boolean]):

        class_: typing.ClassVar[java.lang.Class]
        REFERENCE_PRIMARY_CHANGED: typing.Final[TraceEvent.TraceReferenceBoolEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceReferenceBoolEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceReferenceBoolEvent]:
            ...


    class TraceStackEvent(java.lang.Enum[TraceEvent.TraceStackEvent], TraceEvent[ghidra.trace.model.stack.TraceStack, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        STACK_ADDED: typing.Final[TraceEvent.TraceStackEvent]
        STACK_DELETED: typing.Final[TraceEvent.TraceStackEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceStackEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceStackEvent]:
            ...


    class TraceStackLongEvent(java.lang.Enum[TraceEvent.TraceStackLongEvent], TraceEvent[ghidra.trace.model.stack.TraceStack, java.lang.Long]):

        class_: typing.ClassVar[java.lang.Class]
        STACK_CHANGED: typing.Final[TraceEvent.TraceStackLongEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceStackLongEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceStackLongEvent]:
            ...


    class TraceMappingEvent(java.lang.Enum[TraceEvent.TraceMappingEvent], TraceEvent[ghidra.trace.model.modules.TraceStaticMapping, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        MAPPING_ADDED: typing.Final[TraceEvent.TraceMappingEvent]
        MAPPING_DELETED: typing.Final[TraceEvent.TraceMappingEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceMappingEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceMappingEvent]:
            ...


    class TraceTypeArchiveEvent(java.lang.Enum[TraceEvent.TraceTypeArchiveEvent], TraceEvent[ghidra.util.UniversalID, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        SOURCE_TYPE_ARCHIVE_ADDED: typing.Final[TraceEvent.TraceTypeArchiveEvent]
        SOURCE_TYPE_ARCHIVE_CHANGED: typing.Final[TraceEvent.TraceTypeArchiveEvent]
        SOURCE_TYPE_ARCHIVE_DELETED: typing.Final[TraceEvent.TraceTypeArchiveEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceTypeArchiveEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceTypeArchiveEvent]:
            ...


    class TraceSymbolEvent(java.lang.Enum[TraceEvent.TraceSymbolEvent], TraceEvent[ghidra.trace.model.symbol.TraceSymbol, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        SYMBOL_ADDED: typing.Final[TraceEvent.TraceSymbolEvent]
        SYMBOL_CHANGED: typing.Final[TraceEvent.TraceSymbolEvent]
        SYMBOL_DELETED: typing.Final[TraceEvent.TraceSymbolEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSymbolEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSymbolEvent]:
            ...


    class TraceSymbolSourceEvent(java.lang.Enum[TraceEvent.TraceSymbolSourceEvent], TraceEvent[ghidra.trace.model.symbol.TraceSymbol, ghidra.program.model.symbol.SourceType]):

        class_: typing.ClassVar[java.lang.Class]
        SYMBOL_SOURCE_CHANGED: typing.Final[TraceEvent.TraceSymbolSourceEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSymbolSourceEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSymbolSourceEvent]:
            ...


    class TraceSymbolSymEvent(java.lang.Enum[TraceEvent.TraceSymbolSymEvent], TraceEvent[ghidra.trace.model.symbol.TraceSymbol, ghidra.trace.model.symbol.TraceSymbol]):

        class_: typing.ClassVar[java.lang.Class]
        SYMBOL_PRIMARY_CHANGED: typing.Final[TraceEvent.TraceSymbolSymEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSymbolSymEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSymbolSymEvent]:
            ...


    class TraceSymbolStringEvent(java.lang.Enum[TraceEvent.TraceSymbolStringEvent], TraceEvent[ghidra.trace.model.symbol.TraceSymbol, java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]
        SYMBOL_RENAMED: typing.Final[TraceEvent.TraceSymbolStringEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSymbolStringEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSymbolStringEvent]:
            ...


    class TraceSymbolNamespaceEvent(java.lang.Enum[TraceEvent.TraceSymbolNamespaceEvent], TraceEvent[ghidra.trace.model.symbol.TraceSymbol, ghidra.trace.model.symbol.TraceNamespaceSymbol]):

        class_: typing.ClassVar[java.lang.Class]
        SYMBOL_PARENT_CHANGED: typing.Final[TraceEvent.TraceSymbolNamespaceEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSymbolNamespaceEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSymbolNamespaceEvent]:
            ...


    class TraceSymbolRefEvent(java.lang.Enum[TraceEvent.TraceSymbolRefEvent], TraceEvent[ghidra.trace.model.symbol.TraceSymbol, ghidra.trace.model.symbol.TraceReference]):

        class_: typing.ClassVar[java.lang.Class]
        SYMBOL_ASSOCIATION_ADDED: typing.Final[TraceEvent.TraceSymbolRefEvent]
        SYMBOL_ASSOCIATION_REMOVED: typing.Final[TraceEvent.TraceSymbolRefEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSymbolRefEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSymbolRefEvent]:
            ...


    class TraceSymbolAddressEvent(java.lang.Enum[TraceEvent.TraceSymbolAddressEvent], TraceEvent[ghidra.trace.model.symbol.TraceSymbol, ghidra.program.model.address.Address]):

        class_: typing.ClassVar[java.lang.Class]
        SYMBOL_ADDRESS_CHANGED: typing.Final[TraceEvent.TraceSymbolAddressEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSymbolAddressEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSymbolAddressEvent]:
            ...


    class TraceSymbolLifespanEvent(java.lang.Enum[TraceEvent.TraceSymbolLifespanEvent], TraceEvent[ghidra.trace.model.symbol.TraceSymbolWithLifespan, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        SYMBOL_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceSymbolLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSymbolLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSymbolLifespanEvent]:
            ...


    class TraceThreadEvent(java.lang.Enum[TraceEvent.TraceThreadEvent], TraceEvent[ghidra.trace.model.thread.TraceThread, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        THREAD_ADDED: typing.Final[TraceEvent.TraceThreadEvent]
        THREAD_CHANGED: typing.Final[TraceEvent.TraceThreadEvent]
        THREAD_DELETED: typing.Final[TraceEvent.TraceThreadEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceThreadEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceThreadEvent]:
            ...


    class TraceThreadLifespanEvent(java.lang.Enum[TraceEvent.TraceThreadLifespanEvent], TraceEvent[ghidra.trace.model.thread.TraceThread, ghidra.trace.model.Lifespan]):

        class_: typing.ClassVar[java.lang.Class]
        THREAD_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceThreadLifespanEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceThreadLifespanEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceThreadLifespanEvent]:
            ...


    class TraceSnapshotEvent(java.lang.Enum[TraceEvent.TraceSnapshotEvent], TraceEvent[ghidra.trace.model.time.TraceSnapshot, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        SNAPSHOT_ADDED: typing.Final[TraceEvent.TraceSnapshotEvent]
        SNAPSHOT_CHANGED: typing.Final[TraceEvent.TraceSnapshotEvent]
        SNAPSHOT_DELETED: typing.Final[TraceEvent.TraceSnapshotEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TraceSnapshotEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TraceSnapshotEvent]:
            ...


    class TracePlatformEvent(java.lang.Enum[TraceEvent.TracePlatformEvent], TraceEvent[ghidra.trace.model.guest.TraceGuestPlatform, java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]
        PLATFORM_ADDED: typing.Final[TraceEvent.TracePlatformEvent]
        PLATFORM_DELETED: typing.Final[TraceEvent.TracePlatformEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TracePlatformEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TracePlatformEvent]:
            ...


    class TracePlatformMappingEvent(java.lang.Enum[TraceEvent.TracePlatformMappingEvent], TraceEvent[ghidra.trace.model.guest.TraceGuestPlatform, ghidra.trace.model.guest.TraceGuestPlatformMappedRange]):

        class_: typing.ClassVar[java.lang.Class]
        PLATFORM_MAPPING_ADDED: typing.Final[TraceEvent.TracePlatformMappingEvent]
        PLATFORM_MAPPING_DELETED: typing.Final[TraceEvent.TracePlatformMappingEvent]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEvent.TracePlatformMappingEvent:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEvent.TracePlatformMappingEvent]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def cast(self, rec: ghidra.framework.model.DomainObjectChangeRecord) -> TraceChangeRecord[T, U]:
        """
        Cast a change record to one with object/affected value types for this event
        
        :param ghidra.framework.model.DomainObjectChangeRecord rec: the untyped record
        :return: the typed record
        :rtype: TraceChangeRecord[T, U]
        """


class TraceViewportSpanIterator(generic.util.AbstractPeekableIterator[ghidra.trace.model.Lifespan]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]):
        ...


class TraceEvents(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    OBJECT_CREATED: typing.Final[TraceEvent.TraceObjectEvent]
    """
    A :obj:`TraceObject` was created, but not yet inserted.
     
     
    
    Between the :obj:`.OBJECT_CREATED` event and the first :obj:`.OBJECT_LIFE_CHANGED` event,
    an object is considered "incomplete," because it is likely missing its attributes. Thus, a
    trace client must take care to ensure all attributes, especially fixed attributes, are added
    to the object before it is inserted at its canonical path. Listeners may use
    :meth:`TraceObject.getCanonicalParent(long) <TraceObject.getCanonicalParent>` to check if an object is complete for a given
    snapshot.
    """

    OBJECT_LIFE_CHANGED: typing.Final[TraceEvent.TraceObjectEvent]
    """
    An object's life changed.
     
     
    
    One of its canonical parents was created, deleted, or had its lifespan change.
    """

    OBJECT_DELETED: typing.Final[TraceEvent.TraceObjectEvent]
    """
    A :obj:`TraceObject` was deleted
    """

    VALUE_CREATED: typing.Final[TraceEvent.TraceObjectValueEvent]
    """
    A :obj:`TraceObjectValue` was created
    """

    VALUE_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceObjectValueLifespanEvent]
    """
    A :obj:`TraceObjectValue`'s lifespan changed
    """

    VALUE_DELETED: typing.Final[TraceEvent.TraceObjectValueEvent]
    """
    A :obj:`TraceObjectValue` was deleted
    """

    BOOKMARK_TYPE_ADDED: typing.Final[TraceEvent.TraceBookmarkTypeEvent]
    """
    A :obj:`TraceBookmarkType` was added
    """

    BOOKMARK_ADDED: typing.Final[TraceEvent.TraceBookmarkEvent]
    """
    A :obj:`TraceBookmark` was added
    """

    BOOKMARK_CHANGED: typing.Final[TraceEvent.TraceBookmarkEvent]
    """
    A :obj:`TraceBookmark` was changed
    """

    BOOKMARK_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceBookmarkLifespanEvent]
    """
    A :obj:`TraceBookmark`'s lifespan was changed
    """

    BOOKMARK_DELETED: typing.Final[TraceEvent.TraceBookmarkEvent]
    """
    A :obj:`TraceBookmark` was deleted
    """

    BREAKPOINT_ADDED: typing.Final[TraceEvent.TraceBreakpointEvent]
    """
    A :obj:`TraceBreakpointLocation` was added
    """

    BREAKPOINT_CHANGED: typing.Final[TraceEvent.TraceBreakpointEvent]
    """
    A :obj:`TraceBreakpointLocation` was changed
    """

    BREAKPOINT_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceBreakpointLifespanEvent]
    """
    A :obj:`TraceBreakpointLocation`'s lifespan was changed
    """

    BREAKPOINT_DELETED: typing.Final[TraceEvent.TraceBreakpointEvent]
    """
    A :obj:`TraceBreakpointLocation` was deleted
    """

    TYPE_CATEGORY_ADDED: typing.Final[TraceEvent.TraceTypeCategoryEvent]
    """
    A :obj:`Category` was added. The ``long`` is the category id.
    """

    TYPE_CATEGORY_MOVED: typing.Final[TraceEvent.TraceTypeCategoryPathEvent]
    """
    A :obj:`Category` was moved. The ``long`` is the category id.
    """

    TYPE_CATEGORY_RENAMED: typing.Final[TraceEvent.TraceTypeCategoryStringEvent]
    """
    A :obj:`Category` was renamed. The ``long`` is the category id.
    """

    TYPE_CATEGORY_DELETED: typing.Final[TraceEvent.TraceTypeCategoryPathEvent]
    """
    A :obj:`Category` was deleted. The ``long`` is the category id.
    """

    CODE_ADDED: typing.Final[TraceEvent.TraceCodeEvent]
    """
    One or more :obj:`TraceCodeUnit`s were added.
     
     
    
    This may be a single unit or a whole block. Only the first unit in the block is given in the
    record.
    """

    CODE_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceCodeLifespanEvent]
    """
    A :obj:`TraceCodeUnit`'s lifspan changed.
    """

    CODE_REMOVED: typing.Final[TraceEvent.TraceCodeEvent]
    """
    One or more :obj:`TraceCodeUnit`'s were removed.
     
     
    
    This may be a single unit or a whole block. Only the first unit in the block is given, if it
    is given at all.
    """

    CODE_FRAGMENT_CHANGED: typing.Final[TraceEvent.TraceCodeFragmentEvent]
    """
    A :obj:`ProgramFragment` was changed.
    """

    CODE_DATA_TYPE_REPLACED: typing.Final[TraceEvent.TraceCodeDataTypeEvent]
    """
    One or more :obj:`TraceData`s' :obj:`DataType` was replaced.
     
     
    
    The type's id is given in the record.
    """

    CODE_DATA_SETTINGS_CHANGED: typing.Final[TraceEvent.TraceCodeDataSettingsEvent]
    """
    One or more :obj:`TraceData`s' :obj:`Settings` was changed.
    """

    PLATE_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
    """
    A plate comment was changed.
    """

    PRE_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
    """
    A pre comment was changed.
    """

    POST_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
    """
    A post comment was changed.
    """

    EOL_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
    """
    An end-of-line comment was changed.
    """

    REPEATABLE_COMMENT_CHANGED: typing.Final[TraceEvent.TraceCommentEvent]
    """
    A repeatable comment was changed.
    """

    COMPOSITE_DATA_ADDED: typing.Final[TraceEvent.TraceCompositeDataEvent]
    """
    A :obj:`TraceData` of :obj:`Composite` type was added.
    """

    COMPOSITE_DATA_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceCompositeDataLifespanEvent]
    """
    The lifespan of a :obj:`TraceData` of :obj:`Composite` type was changed.
    """

    COMPOSITE_DATA_REMOVED: typing.Final[TraceEvent.TraceCompositeDataEvent]
    """
    A :obj:`TraceData` of :obj:`Composite` type was removed.
    """

    DATA_TYPE_ADDED: typing.Final[TraceEvent.TraceDataTypeEvent]
    """
    A :obj:`DataType` was added.
    """

    DATA_TYPE_REPLACED: typing.Final[TraceEvent.TraceDataTypePathEvent]
    """
    A :obj:`DataType` was replaced.
    """

    DATA_TYPE_CHANGED: typing.Final[TraceEvent.TraceDataTypeEvent]
    """
    A :obj:`DataType` was changed.
    """

    DATA_TYPE_MOVED: typing.Final[TraceEvent.TraceDataTypePathEvent]
    """
    A :obj:`DataType` was moved.
    """

    DATA_TYPE_RENAMED: typing.Final[TraceEvent.TraceDataTypeStringEvent]
    """
    A :obj:`DataType` was renamed.
    """

    DATA_TYPE_DELETED: typing.Final[TraceEvent.TraceDataTypePathEvent]
    """
    A :obj:`DataType` was deleted.
    """

    INSTRUCTION_FLOW_OVERRIDE_CHANGED: typing.Final[TraceEvent.TraceInstructionFlowEvent]
    """
    A :obj:`TraceInstruction`'s flow override was changed.
    """

    INSTRUCTION_FALL_THROUGH_OVERRIDE_CHANGED: typing.Final[TraceEvent.TraceInstructionBoolEvent]
    """
    A :obj:`TraceInstruction`'s fall-through override was changed.
    """

    INSTRUCTION_LENGTH_OVERRIDE_CHANGED: typing.Final[TraceEvent.TraceInstructionIntEvent]
    """
    A :obj:`TraceInstruction`'s length override was changed.
    """

    BYTES_CHANGED: typing.Final[TraceEvent.TraceBytesEvent]
    """
    The :obj:`Trace`'s memory or register values were changed.
     
     
    
    Note the given byte arrays may be larger than the actual change.
    """

    REGION_ADDED: typing.Final[TraceEvent.TraceMemoryRegionEvent]
    """
    A :obj:`TraceMemoryRegion` was added.
    """

    REGION_CHANGED: typing.Final[TraceEvent.TraceMemoryRegionEvent]
    """
    A :obj:`TraceMemoryRegion` was changed.
    """

    REGION_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceMemoryRegionLifespanEvent]
    """
    A :obj:`TraceMemoryRegion`'s lifespan was changed.
    """

    REGION_DELETED: typing.Final[TraceEvent.TraceMemoryRegionEvent]
    """
    A :obj:`TraceMemoryRegion` was deleted.
    """

    OVERLAY_ADDED: typing.Final[TraceEvent.TraceOverlaySpaceEvent]
    """
    An overlay :obj:`AddressSpace` was added.
    """

    OVERLAY_DELETED: typing.Final[TraceEvent.TraceOverlaySpaceEvent]
    """
    An overlay :obj:`AddressSpace` was deleted.
    """

    BYTES_STATE_CHANGED: typing.Final[TraceEvent.TraceMemoryStateEvent]
    """
    The cache state of memory or register values was changed.
    """

    MODULE_ADDED: typing.Final[TraceEvent.TraceModuleEvent]
    """
    A :obj:`TraceModule` was added.
    """

    MODULE_CHANGED: typing.Final[TraceEvent.TraceModuleEvent]
    """
    A :obj:`TraceModule` was changed.
    """

    MODULE_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceModuleLifespanEvent]
    """
    A :obj:`TraceModule`'s lifespan was changed.
    """

    MODULE_DELETED: typing.Final[TraceEvent.TraceModuleEvent]
    """
    A :obj:`TraceModule` was deleted.
    """

    SECTION_ADDED: typing.Final[TraceEvent.TraceSectionEvent]
    """
    A :obj:`TraceSection` was added.
    """

    SECTION_CHANGED: typing.Final[TraceEvent.TraceSectionEvent]
    """
    A :obj:`TraceSection` was changed.
    """

    SECTION_DELETED: typing.Final[TraceEvent.TraceSectionEvent]
    """
    A :obj:`TraceSection` was deleted.
    """

    REFERENCE_ADDED: typing.Final[TraceEvent.TraceReferenceEvent]
    """
    A :obj:`TraceReference` was added.
    """

    REFERENCE_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceReferenceLifespanEvent]
    """
    A :obj:`TraceReference`'s lifespan was changed.
    """

    REFERENCE_PRIMARY_CHANGED: typing.Final[TraceEvent.TraceReferenceBoolEvent]
    """
    A :obj:`TraceReference` was promoted to or demoted from primary.
    """

    REFERENCE_DELETED: typing.Final[TraceEvent.TraceReferenceEvent]
    """
    A :obj:`TraceReference` was deleted.
    """

    STACK_ADDED: typing.Final[TraceEvent.TraceStackEvent]
    """
    A :obj:`TraceStack` was added.
    """

    STACK_CHANGED: typing.Final[TraceEvent.TraceStackLongEvent]
    """
    A :obj:`TraceStack` was changed.
     
     
    
    The "new value" in the record is the min snap of the change. The "old value" is always 0.
    """

    STACK_DELETED: typing.Final[TraceEvent.TraceStackEvent]
    """
    A :obj:`TraceStack` was deleted.
    """

    MAPPING_ADDED: typing.Final[TraceEvent.TraceMappingEvent]
    """
    A :obj:`TraceStaticMapping` was added.
    """

    MAPPING_DELETED: typing.Final[TraceEvent.TraceMappingEvent]
    """
    A :obj:`TraceStaticMapping` was deleted.
    """

    SOURCE_TYPE_ARCHIVE_ADDED: typing.Final[TraceEvent.TraceTypeArchiveEvent]
    """
    A source data type archive was added.
    """

    SOURCE_TYPE_ARCHIVE_CHANGED: typing.Final[TraceEvent.TraceTypeArchiveEvent]
    """
    A source data type archive was changed.
    """

    SOURCE_TYPE_ARCHIVE_DELETED: typing.Final[TraceEvent.TraceTypeArchiveEvent]
    """
    A source data type archive was deleted.
    """

    SYMBOL_ADDED: typing.Final[TraceEvent.TraceSymbolEvent]
    """
    A :obj:`TraceSymbol` was added.
    """

    SYMBOL_SOURCE_CHANGED: typing.Final[TraceEvent.TraceSymbolSourceEvent]
    """
    A :obj:`TraceSymbol`'s source type changed.
    """

    SYMBOL_PRIMARY_CHANGED: typing.Final[TraceEvent.TraceSymbolSymEvent]
    """
    A :obj:`TraceSymbol` was promoted to or demoted from primary.
    """

    SYMBOL_RENAMED: typing.Final[TraceEvent.TraceSymbolStringEvent]
    """
    A :obj:`TraceSymbol` was renamed.
    """

    SYMBOL_PARENT_CHANGED: typing.Final[TraceEvent.TraceSymbolNamespaceEvent]
    """
    A :obj:`TraceSymbol`'s parent namespace changed.
    """

    SYMBOL_ASSOCIATION_ADDED: typing.Final[TraceEvent.TraceSymbolRefEvent]
    """
    A :obj:`TraceSymbol` was associated with a :obj:`TraceReference`.
    """

    SYMBOL_ASSOCIATION_REMOVED: typing.Final[TraceEvent.TraceSymbolRefEvent]
    """
    A :obj:`TraceSymbol` was dissociated from a :obj:`TraceReference`.
    """

    SYMBOL_ADDRESS_CHANGED: typing.Final[TraceEvent.TraceSymbolAddressEvent]
    """
    A :obj:`TraceSymbol`'s address changed.
    """

    SYMBOL_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceSymbolLifespanEvent]
    """
    A :obj:`TraceSymbol`'s lifespan changed.
    """

    SYMBOL_CHANGED: typing.Final[TraceEvent.TraceSymbolEvent]
    """
    A :obj:`TraceSymbol` was changed in a way not captured by the other ``SYMBOL_`` events.
    """

    SYMBOL_DELETED: typing.Final[TraceEvent.TraceSymbolEvent]
    """
    A :obj:`TraceSymbol` was deleted.
    """

    THREAD_ADDED: typing.Final[TraceEvent.TraceThreadEvent]
    """
    A :obj:`TraceThread` was added.
    """

    THREAD_CHANGED: typing.Final[TraceEvent.TraceThreadEvent]
    """
    A :obj:`TraceThread` was changed.
    """

    THREAD_LIFESPAN_CHANGED: typing.Final[TraceEvent.TraceThreadLifespanEvent]
    """
    A :obj:`TraceThread`'s lifespan was changed.
    """

    THREAD_DELETED: typing.Final[TraceEvent.TraceThreadEvent]
    """
    A :obj:`TraceThread` was deleted.
    """

    SNAPSHOT_ADDED: typing.Final[TraceEvent.TraceSnapshotEvent]
    """
    A :obj:`TraceSnapshot` was added.
    """

    SNAPSHOT_CHANGED: typing.Final[TraceEvent.TraceSnapshotEvent]
    """
    A :obj:`TraceSnapshot` was changed.
    """

    SNAPSHOT_DELETED: typing.Final[TraceEvent.TraceSnapshotEvent]
    """
    A :obj:`TraceSnapshot` was deleted.
    """

    PLATFORM_ADDED: typing.Final[TraceEvent.TracePlatformEvent]
    """
    A :obj:`TraceGuestPlatform` was added.
    """

    PLATFORM_DELETED: typing.Final[TraceEvent.TracePlatformEvent]
    """
    A :obj:`TraceGuestPlatform` was deleted.
    """

    PLATFORM_MAPPING_ADDED: typing.Final[TraceEvent.TracePlatformMappingEvent]
    """
    A :obj:`TraceGuestPlatformMappedRange` was added.
    """

    PLATFORM_MAPPING_DELETED: typing.Final[TraceEvent.TracePlatformMappingEvent]
    """
    A :obj:`TraceGuestPlatformMappedRange` was deleted.
    """


    @staticmethod
    def byCommentType(commentType: ghidra.program.model.listing.CommentType) -> TraceEvent.TraceCommentEvent:
        """
        Get the comment change event for the given comment type
        
        :param ghidra.program.model.listing.CommentType commentType: the comment type
        :return: the event type
        :rtype: TraceEvent.TraceCommentEvent
        """


class DataAdapterMinimal(ghidra.program.model.listing.Data):

    class_: typing.ClassVar[java.lang.Class]
    DATA_OP_INDEX: typing.Final = 0
    """
    Operand index for data. Will always be zero
    """

    EMPTY_INT_ARRAY: typing.Final[jpype.JArray[jpype.JInt]]

    def getPrimarySymbolOrDynamicName(self) -> str:
        ...

    @property
    def primarySymbolOrDynamicName(self) -> java.lang.String:
        ...


class TraceRegisterUtils(java.lang.Enum[TraceRegisterUtils]):

    @typing.type_check_only
    class RegisterIndex(java.lang.Object):

        @typing.type_check_only
        class RegEntry(java.lang.Record):

            class_: typing.ClassVar[java.lang.Class]

            def base(self) -> ghidra.program.model.address.AddressRange:
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def regs(self) -> java.util.Set[ghidra.program.model.lang.Register]:
                ...

            def toString(self) -> str:
                ...


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def bufferForValue(register: ghidra.program.model.lang.Register, value: ghidra.program.model.lang.RegisterValue) -> java.nio.ByteBuffer:
        ...

    @staticmethod
    def combineWithTraceBaseRegisterValue(rv: ghidra.program.model.lang.RegisterValue, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], regs: ghidra.trace.model.memory.TraceMemorySpace, requireKnown: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.lang.RegisterValue:
        ...

    @staticmethod
    def combineWithTraceParentRegisterValue(parent: ghidra.program.model.lang.Register, rv: ghidra.program.model.lang.RegisterValue, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], regs: ghidra.trace.model.memory.TraceMemorySpace, requireKnown: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.lang.RegisterValue:
        ...

    @staticmethod
    @typing.overload
    def computeMaskOffset(reg: ghidra.program.model.lang.Register) -> int:
        ...

    @staticmethod
    @typing.overload
    def computeMaskOffset(value: ghidra.program.model.lang.RegisterValue) -> int:
        ...

    @staticmethod
    def encodeValueRepresentationHackPointer(register: ghidra.program.model.lang.Register, data: ghidra.trace.model.listing.TraceData, representation: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.RegisterValue:
        ...

    @staticmethod
    def finishBuffer(buf: java.nio.ByteBuffer, register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        ...

    @staticmethod
    def getFrameLevel(trace: ghidra.trace.model.Trace, space: ghidra.program.model.address.AddressSpace) -> int:
        ...

    @staticmethod
    def getOverlayRange(space: ghidra.program.model.address.AddressSpace, range: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        ...

    @staticmethod
    def getOverlaySet(space: ghidra.program.model.address.AddressSpace, set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView:
        ...

    @staticmethod
    def getPhysicalRange(range: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        ...

    @staticmethod
    def getPhysicalSet(set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView:
        """
        Convert a set in an overlay space to the corresponding set in its physical space
        
        :param ghidra.program.model.address.AddressSetView set: a set contained entirely in one space
        :return: the physical set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    @typing.overload
    def getRegisterAddressSpace(cont: ghidra.trace.model.memory.TraceRegisterContainer, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSpace:
        ...

    @staticmethod
    @typing.overload
    def getRegisterAddressSpace(thread: ghidra.trace.model.thread.TraceThread, frameLevel: typing.Union[jpype.JInt, int], createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSpace:
        ...

    @staticmethod
    @typing.overload
    def getRegisterAddressSpace(frame: ghidra.trace.model.stack.TraceStackFrame, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSpace:
        ...

    @staticmethod
    @typing.overload
    def getRegisterContainer(thread: ghidra.trace.model.thread.TraceThread, frameLevel: typing.Union[jpype.JInt, int]) -> ghidra.trace.model.memory.TraceRegisterContainer:
        ...

    @staticmethod
    @typing.overload
    def getRegisterContainer(frame: ghidra.trace.model.stack.TraceStackFrame) -> ghidra.trace.model.memory.TraceRegisterContainer:
        ...

    @staticmethod
    @typing.overload
    def getRegisterContainer(object: ghidra.trace.model.target.TraceObject, frameLevel: typing.Union[jpype.JInt, int]) -> ghidra.trace.model.memory.TraceRegisterContainer:
        ...

    @staticmethod
    def getThread(trace: ghidra.trace.model.Trace, space: ghidra.program.model.address.AddressSpace) -> ghidra.trace.model.thread.TraceThread:
        ...

    @staticmethod
    def isByteBound(register: ghidra.program.model.lang.Register) -> bool:
        ...

    @staticmethod
    def padOrTruncate(arr: jpype.JArray[jpype.JByte], length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        ...

    @staticmethod
    def prepareBuffer(register: ghidra.program.model.lang.Register) -> java.nio.ByteBuffer:
        ...

    @staticmethod
    def rangeForRegister(register: ghidra.program.model.lang.Register) -> ghidra.program.model.address.AddressRange:
        ...

    @staticmethod
    def registersIntersecting(language: ghidra.program.model.lang.Language, set: ghidra.program.model.address.AddressSetView) -> java.util.Set[ghidra.program.model.lang.Register]:
        ...

    @staticmethod
    def requireByteBound(register: ghidra.program.model.lang.Register):
        ...

    @staticmethod
    @typing.overload
    def seekComponent(data: ghidra.trace.model.listing.TraceData, range: ghidra.program.model.address.AddressRange) -> ghidra.trace.model.listing.TraceData:
        ...

    @staticmethod
    @typing.overload
    def seekComponent(data: ghidra.trace.model.listing.TraceData, reg: ghidra.program.model.lang.Register) -> ghidra.trace.model.listing.TraceData:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceRegisterUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceRegisterUtils]:
        ...


class ByteArrayUtils(java.lang.Enum[ByteArrayUtils]):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def computeDiffsAddressSet(start: ghidra.program.model.address.Address, a: jpype.JArray[jpype.JByte], b: jpype.JArray[jpype.JByte]) -> ghidra.program.model.address.AddressSet:
        """
        Compute the address set where two byte arrays differ, given a start address
        
        :param ghidra.program.model.address.Address start: the address of the first byte in each array
        :param jpype.JArray[jpype.JByte] a: the first array
        :param jpype.JArray[jpype.JByte] b: the second array
        :return: the address set where the arrays differ
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ByteArrayUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[ByteArrayUtils]:
        ...


class MethodProtector(java.lang.Object):

    class TemperamentalCallable(java.lang.Object, typing.Generic[E]):

        class_: typing.ClassVar[java.lang.Class]

        def run(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def avoid(self, callable: MethodProtector.TemperamentalCallable[E]):
        ...

    def take(self, callable: MethodProtector.TemperamentalCallable[E]):
        ...


class MemoryAdapter(ghidra.program.model.mem.Memory):

    class_: typing.ClassVar[java.lang.Class]

    def mustRead(self, addr: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool]) -> java.nio.ByteBuffer:
        ...


class DataAdapterFromDataType(ghidra.program.model.listing.Data):

    class_: typing.ClassVar[java.lang.Class]

    def doToString(self) -> str:
        ...


class WrappingFunctionIterator(ghidra.program.model.listing.FunctionIterator):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, it: java.util.Iterator[ghidra.program.model.listing.Function]):
        ...

    @typing.overload
    def __init__(self, it: java.util.Iterator[T], filter: java.util.function.Predicate[T]):
        ...


class EmptyFunctionIterator(java.lang.Enum[EmptyFunctionIterator], ghidra.program.model.listing.FunctionIterator):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[EmptyFunctionIterator]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EmptyFunctionIterator:
        ...

    @staticmethod
    def values() -> jpype.JArray[EmptyFunctionIterator]:
        ...



__all__ = ["TypedEventDispatcher", "DataAdapterFromSettings", "CopyOnWrite", "EnumeratingIterator", "TraceSpaceMixin", "WrappingInstructionIterator", "OverlappingObjectIterator", "WrappingDataIterator", "InstructionAdapterFromPrototype", "WrappingCodeUnitIterator", "TraceChangeRecord", "TraceChangeManager", "TraceEvent", "TraceViewportSpanIterator", "TraceEvents", "DataAdapterMinimal", "TraceRegisterUtils", "ByteArrayUtils", "MethodProtector", "MemoryAdapter", "DataAdapterFromDataType", "WrappingFunctionIterator", "EmptyFunctionIterator"]
