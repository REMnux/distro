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
import ghidra.trace.database.space
import ghidra.trace.database.thread
import ghidra.trace.model
import ghidra.trace.model.map
import ghidra.trace.model.property
import ghidra.util
import ghidra.util.database
import ghidra.util.database.spatial
import ghidra.util.database.spatial.rect
import ghidra.util.task
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util.concurrent.locks # type: ignore
import java.util.function # type: ignore


DR = typing.TypeVar("DR")
K = typing.TypeVar("K")
T = typing.TypeVar("T")


class DBTraceAddressSnapRangePropertyMap(ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager[DBTraceAddressSnapRangePropertyMapSpace[T, DR]], ghidra.trace.model.map.TraceAddressSnapRangePropertyMap[T], ghidra.trace.database.space.DBTraceDelegatingManager[DBTraceAddressSnapRangePropertyMapSpace[T, DR]], typing.Generic[T, DR]):

    class DBTraceAddressSnapRangePropertyMapDataFactory(java.lang.Object, typing.Generic[T, DR]):

        class_: typing.ClassVar[java.lang.Class]

        def create(self, tree: DBTraceAddressSnapRangePropertyMapTree[T, DR], store: ghidra.util.database.DBCachedObjectStore[DR], record: db.DBRecord) -> DR:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, dataType: java.lang.Class[DR], dataFactory: DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory[T, DR]):
        ...

    def deleteData(self, data: DR):
        ...


class DBTraceAddressSnapRangePropertyMapSpace(ghidra.trace.database.space.DBTraceSpaceBased, ghidra.util.database.spatial.SpatialMap[ghidra.trace.model.TraceAddressSnapRange, T, DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery], ghidra.trace.model.map.TraceAddressSnapRangePropertyMapSpace[T], typing.Generic[T, DR]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tableName: typing.Union[java.lang.String, str], trace: ghidra.trace.database.DBTrace, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, lock: java.util.concurrent.locks.ReadWriteLock, space: ghidra.program.model.address.AddressSpace, dataType: java.lang.Class[DR], dataFactory: DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory[T, DR]):
        ...

    def checkIntegrity(self):
        """
        For developers and testers.
        """

    def deleteData(self, data: DR):
        ...

    def getDataByKey(self, key: typing.Union[jpype.JLong, int]) -> DR:
        ...

    def getUserIndex(self, fieldClass: java.lang.Class[K], column: ghidra.util.database.DBObjectColumn) -> ghidra.util.database.DBCachedObjectIndex[K, DR]:
        ...

    @property
    def dataByKey(self) -> DR:
        ...


class AbstractDBTracePropertyMap(DBTraceAddressSnapRangePropertyMap[T, DR], ghidra.trace.model.property.TracePropertyMap[T], typing.Generic[T, DR]):

    class DBTracePropertyMapSpace(DBTraceAddressSnapRangePropertyMapSpace[T, DR], ghidra.trace.model.property.TracePropertyMapSpace[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tableName: typing.Union[java.lang.String, str], trace: ghidra.trace.database.DBTrace, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, lock: java.util.concurrent.locks.ReadWriteLock, space: ghidra.program.model.address.AddressSpace, dataType: java.lang.Class[DR], dataFactory: DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory[T, DR]):
            ...


    class DBTraceIntPropertyMap(AbstractDBTracePropertyMap[java.lang.Integer, AbstractDBTracePropertyMap.DBTraceIntPropertyMapEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
            ...


    class DBTraceIntPropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[java.lang.Integer]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: DBTraceAddressSnapRangePropertyMapTree[java.lang.Integer, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class DBTraceLongPropertyMap(AbstractDBTracePropertyMap[java.lang.Long, AbstractDBTracePropertyMap.DBTraceLongPropertyMapEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
            ...


    class DBTraceLongPropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[java.lang.Long]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: DBTraceAddressSnapRangePropertyMapTree[java.lang.Long, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class DBTraceSaveablePropertyMap(AbstractDBTracePropertyMap[T, AbstractDBTracePropertyMap.DBTraceSaveablePropertyMapEntry[T]], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, valueClass: java.lang.Class[T]):
            ...


    class DBTraceSaveablePropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: DBTraceAddressSnapRangePropertyMapTree[T, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord, valueClass: java.lang.Class[T]):
            ...


    class SaveableDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[ghidra.util.Saveable, AbstractDBTracePropertyMap.DBTraceSaveablePropertyMapEntry[typing.Any], db.BinaryField]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[AbstractDBTracePropertyMap.DBTraceSaveablePropertyMapEntry[typing.Any]], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class DBTraceStringPropertyMap(AbstractDBTracePropertyMap[java.lang.String, AbstractDBTracePropertyMap.DBTraceStringPropertyMapEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
            ...


    class DBTraceStringPropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: DBTraceAddressSnapRangePropertyMapTree[java.lang.String, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class DBTraceVoidPropertyMap(AbstractDBTracePropertyMap[java.lang.Void, AbstractDBTracePropertyMap.DBTraceVoidPropertyMapEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
            ...


    class DBTraceVoidPropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[java.lang.Void]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: DBTraceAddressSnapRangePropertyMapTree[java.lang.Void, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, dataType: java.lang.Class[DR], dataFactory: DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory[T, DR]):
        ...


class DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable(AbstractDBTraceAddressSnapRangePropertyMapOcclusionIterable[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceAddressSnapRangePropertyMapSpace[T, typing.Any], within: ghidra.trace.model.TraceAddressSnapRange):
        ...


class DBTraceAddressSnapRangePropertyMapTree(ghidra.util.database.spatial.rect.Abstract2DRStarTree[ghidra.program.model.address.Address, java.lang.Long, ghidra.trace.model.TraceAddressSnapRange, DR, ghidra.trace.model.TraceAddressSnapRange, DBTraceAddressSnapRangePropertyMapTree.DBTraceAddressSnapRangePropertyMapNode, T, DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery], typing.Generic[T, DR]):

    class DBTraceAddressSnapRangePropertyMapNode(ghidra.util.database.spatial.DBTreeNodeRecord[ghidra.trace.model.TraceAddressSnapRange], ghidra.trace.model.TraceAddressSnapRange):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: DBTraceAddressSnapRangePropertyMapTree[typing.Any, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class AbstractDBTraceAddressSnapRangePropertyMapData(ghidra.util.database.spatial.DBTreeDataRecord[ghidra.trace.model.TraceAddressSnapRange, ghidra.trace.model.TraceAddressSnapRange, T], ghidra.trace.model.TraceAddressSnapRange, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: DBTraceAddressSnapRangePropertyMapTree[T, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class TraceAddressSnapRangeQuery(ghidra.util.database.spatial.rect.AbstractRectangle2DQuery[ghidra.program.model.address.Address, java.lang.Long, ghidra.trace.model.TraceAddressSnapRange, ghidra.trace.model.TraceAddressSnapRange, DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, r1: ghidra.trace.model.TraceAddressSnapRange, r2: ghidra.trace.model.TraceAddressSnapRange, direction: ghidra.util.database.spatial.rect.Rectangle2DDirection):
            ...

        @staticmethod
        def added(from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int], space: ghidra.program.model.address.AddressSpace) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            """
            Find entries which do not exist at the from snap, but do exist at the to snap
             
             
            
            Note that entries created and then destroyed within the given span are not selected.
            
            :param jpype.JLong or int from: the first snap to "compare"
            :param jpype.JLong or int to: the second snap to "compare"
            :param ghidra.program.model.address.AddressSpace space: the address space
            :return: a query which can compare the two snaps, searching for entries added
            :rtype: DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery
            """

        @staticmethod
        def at(address: ghidra.program.model.address.Address, snap: typing.Union[jpype.JLong, int]) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        def atSnap(snap: typing.Union[jpype.JLong, int], space: ghidra.program.model.address.AddressSpace) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def enclosed(range: ghidra.trace.model.TraceAddressSnapRange) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def enclosed(range: ghidra.program.model.address.AddressRange, lifespan: ghidra.trace.model.Lifespan) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def enclosed(minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, minSnap: typing.Union[jpype.JLong, int], maxSnap: typing.Union[jpype.JLong, int]) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        def equalTo(shape: ghidra.trace.model.TraceAddressSnapRange) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
            ...

        @staticmethod
        @typing.overload
        def intersecting(range: ghidra.trace.model.TraceAddressSnapRange) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def intersecting(range: ghidra.program.model.address.AddressRange, lifespan: ghidra.trace.model.Lifespan) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def intersecting(minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, minSnap: typing.Union[jpype.JLong, int], maxSnap: typing.Union[jpype.JLong, int]) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def intersecting(lifespan: ghidra.trace.model.Lifespan, space: ghidra.program.model.address.AddressSpace) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        def leftLower(address: ghidra.program.model.address.Address) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def mostRecent(address: ghidra.program.model.address.Address, snap: typing.Union[jpype.JLong, int]) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def mostRecent(address: ghidra.program.model.address.Address, span: ghidra.trace.model.Lifespan) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        @typing.overload
        def mostRecent(range: ghidra.program.model.address.AddressRange, span: ghidra.trace.model.Lifespan) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @staticmethod
        def removed(from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int], space: ghidra.program.model.address.AddressSpace) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            """
            Find entries which exist at the from snap, but do not exist at the to snap
             
             
            
            Note that entries created and then destroyed within the given span are not selected.
            
            :param jpype.JLong or int from: the first snap to "compare"
            :param jpype.JLong or int to: the second snap to "compare"
            :param ghidra.program.model.address.AddressSpace space: the address space
            :return: a query which can compare the two snaps, searching for entries removed
            :rtype: DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery
            """

        @staticmethod
        def rightHigher(address: ghidra.program.model.address.Address) -> DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery:
            ...

        @property
        def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, tableName: typing.Union[java.lang.String, str], space: DBTraceAddressSnapRangePropertyMapSpace[T, DR], dataType: java.lang.Class[DR], dataFactory: DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory[T, DR], upgradable: typing.Union[jpype.JBoolean, bool]):
        ...

    def getMapSpace(self) -> DBTraceAddressSnapRangePropertyMapSpace[T, DR]:
        ...

    @property
    def mapSpace(self) -> DBTraceAddressSnapRangePropertyMapSpace[T, DR]:
        ...


class DBTraceAddressSnapRangePropertyMapOcclusionIntoPastIterable(AbstractDBTraceAddressSnapRangePropertyMapOcclusionIterable[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceAddressSnapRangePropertyMapSpace[T, typing.Any], within: ghidra.trace.model.TraceAddressSnapRange):
        ...


class DBTraceAddressSnapRangePropertyMapAddressSetView(ghidra.util.AbstractAddressSetView, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: ghidra.program.model.address.AddressSpace, lock: java.util.concurrent.locks.ReadWriteLock, map: ghidra.util.database.spatial.SpatialMap[ghidra.trace.model.TraceAddressSnapRange, T, DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery], predicate: java.util.function.Predicate[T]):
        """
        Construct an :obj:`AddressSetView` based on the given map of entries and predicate.
         
         
        
        The spatial map is a 2-dimensional collection of entries, but only the address dimension is
        considered. This set behaves as the union of address ranges for all entries whose values pass
        the predicate. Typically, the caller reduces the map first.
        
        :param ghidra.program.model.address.AddressSpace space: the address space of the given map
        :param java.util.concurrent.locks.ReadWriteLock lock: a lock to ensure access to the underlying database is synchronized
        :param ghidra.util.database.spatial.SpatialMap[ghidra.trace.model.TraceAddressSnapRange, T, DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery] map: the map whose entries to test
        :param java.util.function.Predicate[T] predicate: the predicate for testing entry values
        """


class AbstractDBTraceAddressSnapRangePropertyMapOcclusionIterable(java.lang.Iterable[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceAddressSnapRangePropertyMapSpace[T, typing.Any], within: ghidra.trace.model.TraceAddressSnapRange):
        ...



__all__ = ["DBTraceAddressSnapRangePropertyMap", "DBTraceAddressSnapRangePropertyMapSpace", "AbstractDBTracePropertyMap", "DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable", "DBTraceAddressSnapRangePropertyMapTree", "DBTraceAddressSnapRangePropertyMapOcclusionIntoPastIterable", "DBTraceAddressSnapRangePropertyMapAddressSetView", "AbstractDBTraceAddressSnapRangePropertyMapOcclusionIterable"]
