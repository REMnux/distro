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
import ghidra.program.model.lang
import ghidra.trace.database
import ghidra.trace.model
import ghidra.trace.model.breakpoint
import ghidra.trace.model.memory
import ghidra.trace.model.modules
import ghidra.trace.model.stack
import ghidra.trace.model.target
import ghidra.trace.model.target.iface
import ghidra.trace.model.target.path
import ghidra.trace.model.thread
import ghidra.trace.util
import ghidra.util
import ghidra.util.database
import ghidra.util.database.spatial
import ghidra.util.database.spatial.hyper
import ghidra.util.task
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore
import java.util.function # type: ignore
import java.util.stream # type: ignore


I = typing.TypeVar("I")
K = typing.TypeVar("K")
OV = typing.TypeVar("OV")
T = typing.TypeVar("T")


@typing.type_check_only
class ValueTriple(java.lang.Record, ghidra.util.database.spatial.hyper.HyperPoint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parentKey: typing.Union[jpype.JLong, int], childKey: typing.Union[jpype.JLong, int], entryKey: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], address: ghidra.util.database.DBCachedObjectStoreFactory.RecAddress):
        ...

    def address(self) -> ghidra.util.database.DBCachedObjectStoreFactory.RecAddress:
        ...

    def childKey(self) -> int:
        ...

    def entryKey(self) -> str:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def parentKey(self) -> int:
        ...

    def snap(self) -> int:
        ...

    def toString(self) -> str:
        ...


class DBTraceObjectInterface(ghidra.trace.model.target.iface.TraceObjectInterface, ghidra.trace.model.TraceUniqueObject):

    class Translator(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, spaceValueKey: typing.Union[java.lang.String, str], object: DBTraceObject, iface: T):
            ...

        def translate(self, rec: ghidra.trace.util.TraceChangeRecord[typing.Any, typing.Any]) -> ghidra.trace.util.TraceChangeRecord[typing.Any, typing.Any]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def spaceForValue(object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.AddressSpace:
        ...

    @typing.overload
    def spaceForValue(self, snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.AddressSpace:
        ...

    def translateEvent(self, rec: ghidra.trace.util.TraceChangeRecord[typing.Any, typing.Any]) -> ghidra.trace.util.TraceChangeRecord[typing.Any, typing.Any]:
        """
        Translate an object event into the interface-specific event
         
         
        
        Both the object event and the interface-specific event, if applicable, will be emitted. If
        multiple events need to be emitted, then this method may emit them directly via its object's
        trace. If exactly one event needs to be emitted, then this method should return the
        translated record. If no translation applies, or if the translated event(s) were emitted
        directly, this method returns ``null``.
        
        :param ghidra.trace.util.TraceChangeRecord[typing.Any, typing.Any] rec: the object event
        :return: the interface-specific event to emit, or ``null``
        :rtype: ghidra.trace.util.TraceChangeRecord[typing.Any, typing.Any]
        """


class DBTraceObjectDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[DBTraceObject, OV, db.LongField], typing.Generic[OV]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, objectType: java.lang.Class[OV], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
        ...


class ValueBox(ghidra.util.database.spatial.hyper.HyperBox[ValueTriple, ValueBox]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ImmutableValueShape(java.lang.Record, ValueShape):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, parent: DBTraceObject, value: java.lang.Object, entryKey: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan):
        ...

    @typing.overload
    def __init__(self, shape: ValueShape):
        ...

    @typing.overload
    def __init__(self, parent: DBTraceObject, child: DBTraceObject, entryKey: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, addressSpaceId: typing.Union[jpype.JInt, int], minAddressOffset: typing.Union[jpype.JLong, int], maxAddressOffset: typing.Union[jpype.JLong, int]):
        ...

    def addressSpaceId(self) -> int:
        ...

    def child(self) -> DBTraceObject:
        ...

    def entryKey(self) -> str:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    @staticmethod
    def getAddressSpaceId(value: java.lang.Object) -> int:
        ...

    @staticmethod
    def getMaxAddressOffset(value: java.lang.Object) -> int:
        ...

    @staticmethod
    def getMinAddressOffset(value: java.lang.Object) -> int:
        ...

    def hashCode(self) -> int:
        ...

    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def maxAddressOffset(self) -> int:
        ...

    def minAddressOffset(self) -> int:
        ...

    def parent(self) -> DBTraceObject:
        ...

    def toString(self) -> str:
        ...


@typing.type_check_only
class ValueSpace(java.lang.Enum[ValueSpace], ghidra.util.database.spatial.hyper.EuclideanHyperSpace[ValueTriple, ValueBox]):

    @typing.type_check_only
    class ParentKeyDimension(java.lang.Enum[ValueSpace.ParentKeyDimension], ghidra.util.database.spatial.hyper.ULongDimension[ValueTriple, ValueBox]):

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[ValueSpace.ParentKeyDimension]
        FORWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]
        BACKWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ValueSpace.ParentKeyDimension:
            ...

        @staticmethod
        def values() -> jpype.JArray[ValueSpace.ParentKeyDimension]:
            ...


    @typing.type_check_only
    class ChildKeyDimension(java.lang.Enum[ValueSpace.ChildKeyDimension], ghidra.util.database.spatial.hyper.ULongDimension[ValueTriple, ValueBox]):

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[ValueSpace.ChildKeyDimension]
        FORWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]
        BACKWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ValueSpace.ChildKeyDimension:
            ...

        @staticmethod
        def values() -> jpype.JArray[ValueSpace.ChildKeyDimension]:
            ...


    @typing.type_check_only
    class EntryKeyDimension(java.lang.Enum[ValueSpace.EntryKeyDimension], ghidra.util.database.spatial.hyper.StringDimension[ValueTriple, ValueBox]):

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[ValueSpace.EntryKeyDimension]
        FORWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]
        BACKWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ValueSpace.EntryKeyDimension:
            ...

        @staticmethod
        def values() -> jpype.JArray[ValueSpace.EntryKeyDimension]:
            ...


    @typing.type_check_only
    class SnapDimension(java.lang.Enum[ValueSpace.SnapDimension], ghidra.util.database.spatial.hyper.LongDimension[ValueTriple, ValueBox]):

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[ValueSpace.SnapDimension]
        FORWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]
        BACKWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ValueSpace.SnapDimension:
            ...

        @staticmethod
        def values() -> jpype.JArray[ValueSpace.SnapDimension]:
            ...


    @typing.type_check_only
    class AddressDimension(java.lang.Enum[ValueSpace.AddressDimension], ghidra.util.database.spatial.hyper.Dimension[ghidra.util.database.DBCachedObjectStoreFactory.RecAddress, ValueTriple, ValueBox]):

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[ValueSpace.AddressDimension]
        FORWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]
        BACKWARD: typing.Final[ghidra.util.database.spatial.hyper.HyperDirection]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ValueSpace.AddressDimension:
            ...

        @staticmethod
        def values() -> jpype.JArray[ValueSpace.AddressDimension]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[ValueSpace]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ValueSpace:
        ...

    @staticmethod
    def values() -> jpype.JArray[ValueSpace]:
        ...


@typing.type_check_only
class TraceObjectValueStorage(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def doDelete(self):
        ...

    def doSetLifespan(self, lifespan: ghidra.trace.model.Lifespan):
        """
        Just set the lifespan, no notifications
         
         
        
        The wrapper will notify the parent and child, if necessary.
        
        :param ghidra.trace.model.Lifespan lifespan: the new lifespan
        """

    def getChildOrNull(self) -> DBTraceObject:
        ...

    def getEntryKey(self) -> str:
        ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def getManager(self) -> DBTraceObjectManager:
        ...

    def getParent(self) -> DBTraceObject:
        ...

    def getValue(self) -> java.lang.Object:
        ...

    def getWrapper(self) -> DBTraceObjectValue:
        ...

    def isDeleted(self) -> bool:
        ...

    @property
    def parent(self) -> DBTraceObject:
        ...

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def manager(self) -> DBTraceObjectManager:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def childOrNull(self) -> DBTraceObject:
        ...

    @property
    def entryKey(self) -> java.lang.String:
        ...

    @property
    def wrapper(self) -> DBTraceObjectValue:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...


class DBTraceObjectValueRStarTree(ghidra.util.database.spatial.hyper.AbstractHyperRStarTree[ValueTriple, ValueShape, DBTraceObjectValueData, ValueBox, DBTraceObjectValueNode, DBTraceObjectValueData, TraceObjectValueQuery]):

    class DBTraceObjectValueMap(ghidra.util.database.spatial.hyper.AbstractHyperRStarTree.AsSpatialMap[ValueShape, DBTraceObjectValueData, ValueBox, DBTraceObjectValueData, TraceObjectValueQuery]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: ghidra.util.database.spatial.AbstractConstraintsTree[ValueShape, DBTraceObjectValueData, ValueBox, typing.Any, DBTraceObjectValueData, TraceObjectValueQuery], query: TraceObjectValueQuery, factory: ghidra.program.model.address.AddressFactory, lock: java.util.concurrent.locks.ReadWriteLock):
            ...

        def getAddressSetView(self, at: ghidra.trace.model.Lifespan, predicate: java.util.function.Predicate[DBTraceObjectValueData]) -> ghidra.program.model.address.AddressSetView:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceObjectManager, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, tableName: typing.Union[java.lang.String, str], space: ghidra.util.database.spatial.hyper.EuclideanHyperSpace[ValueTriple, ValueBox], dataType: java.lang.Class[DBTraceObjectValueData], nodeType: java.lang.Class[DBTraceObjectValueNode], upgradeable: typing.Union[jpype.JBoolean, bool], maxChildren: typing.Union[jpype.JInt, int]):
        ...


class DBTraceObjectValPath(ghidra.trace.model.target.TraceObjectValPath):

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[DBTraceObjectValPath]

    @staticmethod
    @typing.overload
    def of() -> DBTraceObjectValPath:
        ...

    @staticmethod
    @typing.overload
    def of(entryList: collections.abc.Sequence) -> DBTraceObjectValPath:
        ...

    @staticmethod
    @typing.overload
    def of(*entries: DBTraceObjectValue) -> DBTraceObjectValPath:
        ...


class DBTraceObjectValueData(ghidra.util.database.spatial.DBTreeDataRecord[ValueShape, ValueBox, DBTraceObjectValueData], TraceObjectValueStorage, ValueShape):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceObjectManager, tree: DBTraceObjectValueRStarTree, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class CachePerDBTraceObject(java.lang.Object):

    @typing.type_check_only
    class SnapKey(java.lang.Record, java.lang.Comparable[CachePerDBTraceObject.SnapKey]):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def forValue(value: DBTraceObjectValue) -> CachePerDBTraceObject.SnapKey:
            ...

        def hashCode(self) -> int:
            ...

        def key(self) -> str:
            ...

        def snap(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class Cached(java.lang.Record, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, isMiss: typing.Union[jpype.JBoolean, bool], value: T):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def isMiss(self) -> bool:
            ...

        @staticmethod
        def miss() -> CachePerDBTraceObject.Cached[T]:
            ...

        def toString(self) -> str:
            ...

        def value(self) -> T:
            ...


    @typing.type_check_only
    class CachedLifespanValues(java.lang.Record, typing.Generic[K]):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def span(self) -> ghidra.trace.model.Lifespan:
            ...

        def toString(self) -> str:
            ...

        def values(self) -> java.util.NavigableMap[K, DBTraceObjectValue]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def expandLifespan(self, lifespan: ghidra.trace.model.Lifespan) -> ghidra.trace.model.Lifespan:
        ...

    def getValue(self, snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str]) -> CachePerDBTraceObject.Cached[DBTraceObjectValue]:
        ...

    def notifyValueCreated(self, value: DBTraceObjectValue):
        ...

    def notifyValueDeleted(self, value: DBTraceObjectValue):
        ...

    def offerGetValue(self, expanded: ghidra.trace.model.Lifespan, values: java.util.stream.Stream[DBTraceObjectValue], snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str]) -> DBTraceObjectValue:
        ...

    def offerStreamAnyKey(self, expanded: ghidra.trace.model.Lifespan, values: java.util.stream.Stream[DBTraceObjectValue], lifespan: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[DBTraceObjectValue]:
        ...

    def offerStreamPerKey(self, expanded: ghidra.trace.model.Lifespan, values: java.util.stream.Stream[DBTraceObjectValue], lifespan: ghidra.trace.model.Lifespan, key: typing.Union[java.lang.String, str], forward: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[DBTraceObjectValue]:
        ...

    @typing.overload
    def streamValues(self, lifespan: ghidra.trace.model.Lifespan) -> CachePerDBTraceObject.Cached[java.util.stream.Stream[DBTraceObjectValue]]:
        ...

    @typing.overload
    def streamValues(self, lifespan: ghidra.trace.model.Lifespan, key: typing.Union[java.lang.String, str], forward: typing.Union[jpype.JBoolean, bool]) -> CachePerDBTraceObject.Cached[java.util.stream.Stream[DBTraceObjectValue]]:
        ...


class DBTraceObjectValue(ghidra.trace.model.target.TraceObjectValue):

    @typing.type_check_only
    class ValueLifespanSetter(ghidra.trace.database.DBTraceUtils.LifespanMapSetter[DBTraceObjectValue, java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, range: ghidra.trace.model.Lifespan, value: java.lang.Object):
            ...

        @typing.overload
        def __init__(self, range: ghidra.trace.model.Lifespan, value: java.lang.Object, keep: DBTraceObjectValue):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceObjectManager, wrapped: TraceObjectValueStorage):
        ...

    def getWrapped(self) -> TraceObjectValueStorage:
        ...

    @property
    def wrapped(self) -> TraceObjectValueStorage:
        ...


@typing.type_check_only
class DBTraceObjectValueWriteBehindCache(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    INITIAL_CACHE_SIZE: typing.Final = 1000
    BATCH_SIZE: typing.Final = 100
    DELAY_MS: typing.Final = 10000

    def __init__(self, manager: DBTraceObjectManager):
        ...

    def clear(self):
        ...

    def doCreateValue(self, lifespan: ghidra.trace.model.Lifespan, parent: DBTraceObject, key: typing.Union[java.lang.String, str], value: java.lang.Object) -> DBTraceObjectValueBehind:
        ...

    def flush(self):
        ...

    def get(self, parent: DBTraceObject, key: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int]) -> DBTraceObjectValueBehind:
        ...

    def getObjectsAddressSet(self, snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str], ifaceCls: java.lang.Class[I], predicate: java.util.function.Predicate[I]) -> ghidra.program.model.address.AddressSetView:
        ...

    def remove(self, value: DBTraceObjectValueBehind):
        ...

    def streamAllValues(self) -> java.util.stream.Stream[DBTraceObjectValueBehind]:
        ...

    def streamCanonicalParents(self, child: DBTraceObject, lifespan: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[DBTraceObjectValueBehind]:
        ...

    def streamParents(self, child: DBTraceObject, lifespan: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[DBTraceObjectValueBehind]:
        ...

    @typing.overload
    def streamValues(self, parent: DBTraceObject, lifespan: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[DBTraceObjectValueBehind]:
        ...

    @typing.overload
    def streamValues(self, parent: DBTraceObject, key: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[DBTraceObjectValueBehind]:
        ...

    def streamValuesAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, entryKey: typing.Union[java.lang.String, str]) -> java.util.stream.Stream[DBTraceObjectValueBehind]:
        ...

    def streamValuesIntersecting(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, entryKey: typing.Union[java.lang.String, str]) -> java.util.stream.Stream[DBTraceObjectValueBehind]:
        ...

    def waitWorkers(self):
        ...


class DBTraceObject(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.target.TraceObject):

    @typing.type_check_only
    class ObjectPathDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[ghidra.trace.model.target.path.KeyPath, ghidra.util.database.DBAnnotatedObject, db.StringField]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[ghidra.util.database.DBAnnotatedObject], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceObjectManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...

    def findOrCreateCanonicalAncestorInterface(self, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> ghidra.trace.model.target.TraceObject:
        ...

    def getManager(self) -> DBTraceObjectManager:
        ...

    def queryOrCreateCanonicalAncestorInterface(self, iface: java.lang.Class[I]) -> I:
        ...

    @property
    def manager(self) -> DBTraceObjectManager:
        ...


class DBTraceObjectManager(ghidra.trace.model.target.TraceObjectManager, ghidra.trace.database.DBTraceManager):

    class DBTraceObjectSchemaDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[ghidra.trace.model.target.schema.SchemaContext, DBTraceObjectManager.DBTraceObjectSchemaEntry, db.StringField]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[DBTraceObjectManager.DBTraceObjectSchemaEntry], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class DBTraceObjectSchemaEntry(ghidra.util.database.DBAnnotatedObject):

        class_: typing.ClassVar[java.lang.Class]
        TABLE_NAME: typing.Final = "ObjectSchema"

        def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    @typing.type_check_only
    class ObjectsContainingKey(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def address(self) -> ghidra.program.model.address.Address:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def iface(self) -> java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]:
            ...

        def key(self) -> str:
            ...

        def snap(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace):
        ...

    def addBreakpoint(self, path: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, threads: collections.abc.Sequence, kinds: collections.abc.Sequence, enabled: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str]) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    def addMemoryRegion(self, path: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, flags: collections.abc.Sequence) -> ghidra.trace.model.memory.TraceMemoryRegion:
        ...

    def addModule(self, path: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> ghidra.trace.model.modules.TraceModule:
        ...

    def addSection(self, path: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> ghidra.trace.model.modules.TraceSection:
        ...

    def addStack(self, path: ghidra.trace.model.target.path.KeyPath, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.stack.TraceStack:
        ...

    def addStackFrame(self, path: ghidra.trace.model.target.path.KeyPath, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.stack.TraceStackFrame:
        ...

    def addThread(self, path: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan) -> ghidra.trace.model.thread.TraceThread:
        ...

    def assertMyThread(self, thread: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.thread.TraceThread:
        ...

    def flushWbCaches(self):
        ...

    def getAllObjects(self, iface: java.lang.Class[I]) -> java.util.Collection[I]:
        ...

    def getLatestSuccessor(self, seed: ghidra.trace.model.target.TraceObject, path: ghidra.trace.model.target.path.KeyPath, snap: typing.Union[jpype.JLong, int], iface: java.lang.Class[I]) -> I:
        ...

    def getObjectByPath(self, snap: typing.Union[jpype.JLong, int], path: typing.Union[java.lang.String, str], iface: java.lang.Class[I]) -> I:
        ...

    def getObjectContaining(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, key: typing.Union[java.lang.String, str], iface: java.lang.Class[I]) -> I:
        ...

    def getObjectsAddressSet(self, snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str], ifaceCls: java.lang.Class[I], predicate: java.util.function.Predicate[I]) -> ghidra.program.model.address.AddressSetView:
        ...

    def getObjectsAtSnap(self, snap: typing.Union[jpype.JLong, int], iface: java.lang.Class[I]) -> java.util.Collection[I]:
        ...

    def getObjectsByPath(self, path: typing.Union[java.lang.String, str], iface: java.lang.Class[I]) -> java.util.Collection[I]:
        ...

    def getObjectsContaining(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, key: typing.Union[java.lang.String, str], iface: java.lang.Class[I]) -> java.util.Collection[I]:
        ...

    def getObjectsIntersecting(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, key: typing.Union[java.lang.String, str], iface: java.lang.Class[I]) -> java.util.Collection[I]:
        ...

    def getRootValue(self) -> DBTraceObjectValue:
        ...

    def getSuccessor(self, seed: ghidra.trace.model.target.TraceObject, filter: ghidra.trace.model.target.path.PathFilter, snap: typing.Union[jpype.JLong, int], iface: java.lang.Class[I]) -> I:
        ...

    def getValuesAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, entryKey: typing.Union[java.lang.String, str]) -> java.util.Collection[ghidra.trace.model.target.TraceObjectValue]:
        ...

    def waitWbWorkers(self):
        ...

    @property
    def rootValue(self) -> DBTraceObjectValue:
        ...

    @property
    def allObjects(self) -> java.util.Collection[I]:
        ...


class TraceObjectValueQuery(ghidra.util.database.spatial.hyper.AbstractHyperBoxQuery[ValueTriple, ValueShape, ValueBox, TraceObjectValueQuery]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ls: ValueBox, us: ValueBox, direction: ghidra.util.database.spatial.hyper.HyperDirection):
        ...

    @staticmethod
    def all() -> TraceObjectValueQuery:
        ...

    @staticmethod
    def at(entryKey: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> TraceObjectValueQuery:
        ...

    @staticmethod
    def canonicalParents(child: DBTraceObject, lifespan: ghidra.trace.model.Lifespan) -> TraceObjectValueQuery:
        ...

    @staticmethod
    @typing.overload
    def intersecting(minKey: typing.Union[java.lang.String, str], maxKey: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, minAddress: ghidra.util.database.DBCachedObjectStoreFactory.RecAddress, maxAddress: ghidra.util.database.DBCachedObjectStoreFactory.RecAddress) -> TraceObjectValueQuery:
        ...

    @staticmethod
    @typing.overload
    def intersecting(minKey: typing.Union[java.lang.String, str], maxKey: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> TraceObjectValueQuery:
        ...

    @staticmethod
    @typing.overload
    def intersecting(lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> TraceObjectValueQuery:
        ...

    @staticmethod
    def parents(child: DBTraceObject, lifespan: ghidra.trace.model.Lifespan) -> TraceObjectValueQuery:
        ...

    @staticmethod
    @typing.overload
    def values(parent: DBTraceObject, lifespan: ghidra.trace.model.Lifespan) -> TraceObjectValueQuery:
        ...

    @staticmethod
    @typing.overload
    def values(parent: DBTraceObject, minKey: typing.Union[java.lang.String, str], maxKey: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan) -> TraceObjectValueQuery:
        ...


class DBTraceObjectValueMapAddressSetView(ghidra.util.AbstractAddressSetView):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: ghidra.program.model.address.AddressFactory, lock: java.util.concurrent.locks.ReadWriteLock, map: ghidra.util.database.spatial.SpatialMap[ValueShape, DBTraceObjectValueData, TraceObjectValueQuery], predicate: java.util.function.Predicate[DBTraceObjectValueData]):
        """
        An address set view that unions all addresses where an entry satisfying the given predicate
        exists.
         
         
        
        The caller may reduce the map given to this view. Reduction is preferable to using a
        predicate, where possible, because reduction benefits from the index.
        
        :param ghidra.program.model.address.AddressFactory factory: the trace's address factory
        :param java.util.concurrent.locks.ReadWriteLock lock: the lock on the database
        :param ghidra.util.database.spatial.SpatialMap[ValueShape, DBTraceObjectValueData, TraceObjectValueQuery] map: the map
        :param java.util.function.Predicate[DBTraceObjectValueData] predicate: a predicate to further filter entries
        """


class DBTraceObjectValueNode(ghidra.util.database.spatial.DBTreeNodeRecord[ValueBox], ValueBox):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: DBTraceObjectValueRStarTree, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class DBTraceObjectValueBehind(TraceObjectValueStorage):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceObjectManager, parent: DBTraceObject, entryKey: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, value: java.lang.Object):
        ...


class ValueShape(ghidra.util.database.spatial.BoundedShape[ValueBox]):

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpaceId(self) -> int:
        """
        If the value is an address or range, the id of the address space
        
        :return: the space id, or -1 for non-address value
        :rtype: int
        """

    def getChild(self) -> DBTraceObject:
        ...

    def getChildOrNull(self) -> DBTraceObject:
        ...

    def getEntryKey(self) -> str:
        ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def getMaxAddress(self, factory: ghidra.program.model.address.AddressFactory) -> ghidra.program.model.address.Address:
        ...

    def getMaxAddressOffset(self) -> int:
        ...

    def getMinAddress(self, factory: ghidra.program.model.address.AddressFactory) -> ghidra.program.model.address.Address:
        ...

    def getMinAddressOffset(self) -> int:
        ...

    def getParent(self) -> DBTraceObject:
        ...

    def getRange(self, factory: ghidra.program.model.address.AddressFactory) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def parent(self) -> DBTraceObject:
        ...

    @property
    def addressSpaceId(self) -> jpype.JInt:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def childOrNull(self) -> DBTraceObject:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def entryKey(self) -> java.lang.String:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def maxAddressOffset(self) -> jpype.JLong:
        ...

    @property
    def minAddressOffset(self) -> jpype.JLong:
        ...

    @property
    def child(self) -> DBTraceObject:
        ...


@typing.type_check_only
class ImmutableValueBox(java.lang.Record, ValueBox):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, box: ValueBox):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def lCorner(self) -> ValueTriple:
        ...

    def toString(self) -> str:
        ...

    def uCorner(self) -> ValueTriple:
        ...



__all__ = ["ValueTriple", "DBTraceObjectInterface", "DBTraceObjectDBFieldCodec", "ValueBox", "ImmutableValueShape", "ValueSpace", "TraceObjectValueStorage", "DBTraceObjectValueRStarTree", "DBTraceObjectValPath", "DBTraceObjectValueData", "CachePerDBTraceObject", "DBTraceObjectValue", "DBTraceObjectValueWriteBehindCache", "DBTraceObject", "DBTraceObjectManager", "TraceObjectValueQuery", "DBTraceObjectValueMapAddressSetView", "DBTraceObjectValueNode", "DBTraceObjectValueBehind", "ValueShape", "ImmutableValueBox"]
