from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import generic
import ghidra.framework.data
import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.trace.database.address
import ghidra.trace.database.data
import ghidra.trace.database.listing
import ghidra.trace.database.property
import ghidra.trace.model
import ghidra.trace.model.memory
import ghidra.trace.model.time
import ghidra.trace.util
import ghidra.util
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


DR = typing.TypeVar("DR")
E = typing.TypeVar("E")
K = typing.TypeVar("K")
OT = typing.TypeVar("OT")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class DBTraceDirectChangeListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def changed(self, rec: ghidra.framework.model.DomainObjectChangeRecord):
        ...


class DBTrace(ghidra.util.database.DBCachedDomainObjectAdapter, ghidra.trace.model.Trace, ghidra.trace.util.TraceChangeManager):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], baseCompilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object):
        ...

    @typing.overload
    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, monitor: ghidra.util.task.TaskMonitor, consumer: java.lang.Object):
        ...

    def addDirectChangeListener(self, listener: DBTraceDirectChangeListener):
        ...

    def assertValidAddress(self, pc: ghidra.program.model.address.Address):
        ...

    def assertValidSpace(self, as_: ghidra.program.model.address.AddressSpace):
        ...

    def categoryAdded(self, addedID: typing.Union[jpype.JLong, int], addedCategory: ghidra.program.model.data.Category):
        ...

    def categoryDeleted(self, deletedID: typing.Union[jpype.JLong, int], deletedPath: ghidra.program.model.data.CategoryPath):
        ...

    def categoryMoved(self, movedID: typing.Union[jpype.JLong, int], oldPath: ghidra.program.model.data.CategoryPath, newPath: ghidra.program.model.data.CategoryPath):
        ...

    def categoryRenamed(self, renamedID: typing.Union[jpype.JLong, int], oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        ...

    def dataTypeAdded(self, addedID: typing.Union[jpype.JLong, int], addedType: ghidra.program.model.data.DataType):
        ...

    def dataTypeChanged(self, changedID: typing.Union[jpype.JLong, int], changedType: ghidra.program.model.data.DataType):
        ...

    def dataTypeDeleted(self, deletedID: typing.Union[jpype.JLong, int], deletedPath: ghidra.program.model.data.DataTypePath):
        ...

    def dataTypeMoved(self, movedID: typing.Union[jpype.JLong, int], oldPath: ghidra.program.model.data.DataTypePath, newPath: ghidra.program.model.data.DataTypePath):
        ...

    def dataTypeNameChanged(self, renamedID: typing.Union[jpype.JLong, int], oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        ...

    def dataTypeReplaced(self, replacedID: typing.Union[jpype.JLong, int], replacedPath: ghidra.program.model.data.DataTypePath, newPath: ghidra.program.model.data.DataTypePath):
        ...

    def getCommentAdapter(self) -> ghidra.trace.database.listing.DBTraceCommentAdapter:
        ...

    def getCreationDate(self) -> java.util.Date:
        ...

    def getDataSettingsAdapter(self) -> ghidra.trace.database.data.DBTraceDataSettingsAdapter:
        ...

    def getExecutablePath(self) -> str:
        ...

    def getInternalAddressFactory(self) -> ghidra.trace.database.address.TraceAddressFactory:
        ...

    def getInternalAddressPropertyManager(self) -> ghidra.trace.database.property.DBTraceAddressPropertyManager:
        ...

    def getOverlaySpaceAdapter(self) -> ghidra.trace.database.address.DBTraceOverlaySpaceAdapter:
        ...

    def getStoreFactory(self) -> ghidra.util.database.DBCachedObjectStoreFactory:
        ...

    def isClosing(self) -> bool:
        ...

    def removeDirectChangeListener(self, listener: DBTraceDirectChangeListener):
        ...

    def setExecutablePath(self, path: typing.Union[java.lang.String, str]):
        ...

    def sourceArchiveAdded(self, sourceArchiveID: ghidra.util.UniversalID):
        ...

    def sourceArchiveChanged(self, sourceArchiveID: ghidra.util.UniversalID):
        ...

    def updateViewportsSnapshotAdded(self, snapshot: ghidra.trace.model.time.TraceSnapshot):
        ...

    def updateViewportsSnapshotChanged(self, snapshot: ghidra.trace.model.time.TraceSnapshot):
        ...

    def updateViewportsSnapshotDeleted(self, snapshot: ghidra.trace.model.time.TraceSnapshot):
        ...

    def updateViewsAddRegionBlock(self, region: ghidra.trace.model.memory.TraceMemoryRegion):
        ...

    def updateViewsAddSpaceBlock(self, space: ghidra.program.model.address.AddressSpace):
        ...

    def updateViewsBytesChanged(self, range: ghidra.program.model.address.AddressRange):
        ...

    def updateViewsChangeRegionBlockFlags(self, region: ghidra.trace.model.memory.TraceMemoryRegion, lifespan: ghidra.trace.model.Lifespan):
        ...

    def updateViewsChangeRegionBlockLifespan(self, region: ghidra.trace.model.memory.TraceMemoryRegion, oldLifespan: ghidra.trace.model.Lifespan, newLifespan: ghidra.trace.model.Lifespan):
        ...

    def updateViewsChangeRegionBlockName(self, region: ghidra.trace.model.memory.TraceMemoryRegion):
        ...

    def updateViewsChangeRegionBlockRange(self, region: ghidra.trace.model.memory.TraceMemoryRegion, oldRange: ghidra.program.model.address.AddressRange, newRange: ghidra.program.model.address.AddressRange):
        ...

    def updateViewsDeleteRegionBlock(self, region: ghidra.trace.model.memory.TraceMemoryRegion):
        ...

    def updateViewsDeleteSpaceBlock(self, space: ghidra.program.model.address.AddressSpace):
        ...

    def updateViewsRefreshBlocks(self):
        ...

    @property
    def closing(self) -> jpype.JBoolean:
        ...

    @property
    def storeFactory(self) -> ghidra.util.database.DBCachedObjectStoreFactory:
        ...

    @property
    def internalAddressPropertyManager(self) -> ghidra.trace.database.property.DBTraceAddressPropertyManager:
        ...

    @property
    def overlaySpaceAdapter(self) -> ghidra.trace.database.address.DBTraceOverlaySpaceAdapter:
        ...

    @property
    def executablePath(self) -> java.lang.String:
        ...

    @executablePath.setter
    def executablePath(self, value: java.lang.String):
        ...

    @property
    def dataSettingsAdapter(self) -> ghidra.trace.database.data.DBTraceDataSettingsAdapter:
        ...

    @property
    def commentAdapter(self) -> ghidra.trace.database.listing.DBTraceCommentAdapter:
        ...

    @property
    def internalAddressFactory(self) -> ghidra.trace.database.address.TraceAddressFactory:
        ...

    @property
    def creationDate(self) -> java.util.Date:
        ...


class DBTraceUtils(java.lang.Enum[DBTraceUtils]):
    """
    Various utilities used for implementing the trace database
    
     
    
    Some of these are also useful from the API perspective. TODO: We should probably separate trace
    API utilities into another class.
    """

    class OffsetSnap(java.lang.Object):
        """
        A tuple used to index/locate a block in the trace's byte stores (memory manager)
        """

        class_: typing.ClassVar[java.lang.Class]
        offset: typing.Final[jpype.JLong]
        snap: typing.Final[jpype.JLong]

        def __init__(self, offset: typing.Union[jpype.JLong, int], snap: typing.Union[jpype.JLong, int]):
            ...

        def isScratch(self) -> bool:
            ...

        @property
        def scratch(self) -> jpype.JBoolean:
            ...


    class URLDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[java.net.URL, OT, db.StringField], typing.Generic[OT]):
        """
        A codec for URLs
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class LanguageIDDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[ghidra.program.model.lang.LanguageID, OT, db.StringField], typing.Generic[OT]):
        """
        A codec for language IDs
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class CompilerSpecIDDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[ghidra.program.model.lang.CompilerSpecID, OT, db.StringField], typing.Generic[OT]):
        """
        A codec for compiler spec IDs
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class AbstractOffsetSnapDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[DBTraceUtils.OffsetSnap, OT, db.BinaryField], typing.Generic[OT]):
        """
        A (abstract) codec for the offset-snap tuple
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class OffsetThenSnapDBFieldCodec(DBTraceUtils.AbstractOffsetSnapDBFieldCodec[OT], typing.Generic[OT]):
        """
        Codec for storing :obj:`OffsetSnap`s as :obj:`BinaryField`s.
         
         
        
        Encodes the address space ID followed by the address then the snap.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class RefTypeDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[ghidra.program.model.symbol.RefType, OT, db.ByteField], typing.Generic[OT]):
        """
        A codec for reference types
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class AddressRangeMapSetter(generic.RangeMapSetter[E, ghidra.program.model.address.Address, ghidra.program.model.address.AddressRange, V], typing.Generic[E, V]):
        """
        A setter which works on ranges of addresses
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class LifespanMapSetter(generic.RangeMapSetter[E, java.lang.Long, ghidra.trace.model.Lifespan, V], typing.Generic[E, V]):
        """
        A setter which operates on spans of snapshot keys
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def covariantIterator(it: java.util.Iterator[T]) -> java.util.Iterator[T]:
        """
        Cast an iterator to a less-specific type, given that it cannot insert elements
        
        :param T: the desired type:param java.util.Iterator[T] it: the iterator of more specific type
        :return: the same iterator
        :rtype: java.util.Iterator[T]
        """

    @staticmethod
    def getAddressSet(factory: ghidra.program.model.address.AddressFactory, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSetView:
        """
        Get all the addresses in a factory, starting at the given place
         
         
        
        If backward, this yields all addresses coming before start
        
        :param ghidra.program.model.address.AddressFactory factory: the factory
        :param ghidra.program.model.address.Address start: the start (or end) address
        :param jpype.JBoolean or bool forward: true for all after, false for all before
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    def makeWay(data: DR, span: ghidra.trace.model.Lifespan, lifespanSetter: java.util.function.BiConsumer[DR, ghidra.trace.model.Lifespan], deleter: java.util.function.Consumer[DR]):
        """
        Truncate or delete an entry to make room
         
         
        
        Only call this method for entries which definitely intersect the given span. This does not
        verify intersection. If the data's start snap is contained in the span to clear, the entry is
        deleted. Otherwise, it's end snap is set to one less than the span's start snap.
        
        :param DR data: the entry subject to truncation or deletion
        :param ghidra.trace.model.Lifespan span: the span to clear up
        :param java.util.function.BiConsumer[DR, ghidra.trace.model.Lifespan] lifespanSetter: the method used to truncate the entry
        :param java.util.function.Consumer[DR] deleter: the method used to delete the entry
        """

    @staticmethod
    def tableName(baseName: typing.Union[java.lang.String, str], space: ghidra.program.model.address.AddressSpace) -> str:
        """
        Derive the table name for a given addres/register space
        
        :param java.lang.String or str baseName: the base name of the table group
        :param ghidra.program.model.address.AddressSpace space: the address space
        :return: the table name
        :rtype: str
        """

    @staticmethod
    def toRange(min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Create an address range, checking the endpoints
        
        :param ghidra.program.model.address.Address min: the min address, which must be less than or equal to max
        :param ghidra.program.model.address.Address max: the max address, which must be greater than or equal to min
        :return: the range
        :rtype: ghidra.program.model.address.AddressRange
        :raises IllegalArgumentException: if max is less than min
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DBTraceUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[DBTraceUtils]:
        ...


class DBTraceContentHandler(ghidra.framework.data.DBWithUserDataContentHandler[DBTrace]):

    class_: typing.ClassVar[java.lang.Class]
    TRACE_CONTENT_TYPE: typing.Final = "Trace"
    TRACE_ICON: typing.Final[javax.swing.Icon]

    def __init__(self):
        ...


class DBTraceTimeViewport(ghidra.trace.model.TraceTimeViewport):
    """
    Computes and tracks the "viewport" resulting from forking patterns encoded in snapshot schedules
     
     
    
    This is used primarily by the :obj:`TraceProgramView` implementation to resolve most-recent
    objects according to a layering or forking structure given in snapshot schedules. This listens on
    the given trace for changes in snapshot schedules and keeps an up-to-date set of visible (or
    potentially-visible) ranges from the given snap.
     
     
    
    TODO: Because complicated forking structures are not anticipated, some minimal effort is given to
    cull meaningless changes, but in general, changes cause a complete re-computation of the
    viewport. If complex, deep forking structures prove to be desirable, then this is an area for
    optimization.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOrderedSpans(self, snap: typing.Union[jpype.JLong, int]) -> java.util.List[ghidra.trace.model.Lifespan]:
        ...

    @property
    def orderedSpans(self) -> java.util.List[ghidra.trace.model.Lifespan]:
        ...


class DBTraceCacheForSequenceQueries(java.lang.Object, typing.Generic[T]):

    @typing.type_check_only
    class CachedRegion(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        snap: jpype.JLong
        min: ghidra.program.model.address.Address
        max: ghidra.program.model.address.Address

        def __init__(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange):
            ...

        def getCeiling(self, address: ghidra.program.model.address.Address) -> T:
            ...

        def getFloor(self, address: ghidra.program.model.address.Address) -> T:
            ...

        def load(self, entries: java.util.ArrayList[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, T]]):
            ...

        @property
        def ceiling(self) -> T:
            ...

        @property
        def floor(self) -> T:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, maxRegions: typing.Union[jpype.JInt, int], addressBreadth: typing.Union[jpype.JInt, int]):
        ...

    def getCeiling(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        ...

    def getFloor(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        ...

    def invalidate(self):
        ...

    def notifyEntryRemoved(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, item: T):
        ...

    def notifyEntryShapeChanged(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, item: T):
        ...

    def notifyNewEntry(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRangeImpl, item: T):
        ...


class DBTraceUserData(ghidra.framework.data.DomainObjectAdapterDB, ghidra.trace.model.TraceUserData):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, trace: DBTrace, monitor: ghidra.util.task.TaskMonitor):
        ...


class DBTraceLinkContentHandler(ghidra.framework.data.LinkHandler[DBTrace]):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.ClassVar[DBTraceLinkContentHandler]
    TRACE_LINK_CONTENT_TYPE: typing.Final = "TraceLink"

    def __init__(self):
        ...


class DBTraceCacheForContainingQueries(java.lang.Object, typing.Generic[K, V, T]):

    class GetKey(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        snap: typing.Final[jpype.JLong]
        addr: typing.Final[ghidra.program.model.address.Address]

        def __init__(self, snap: typing.Union[jpype.JLong, int], addr: ghidra.program.model.address.Address):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, snapBreadth: typing.Union[jpype.JInt, int], addressBreadth: typing.Union[jpype.JInt, int], maxPoints: typing.Union[jpype.JInt, int]):
        ...

    def getContaining(self, key: K) -> V:
        ...

    def invalidate(self):
        ...

    def notifyEntryRemoved(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, item: T):
        ...

    def notifyEntryShapeChanged(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, item: T):
        ...

    def notifyNewEntries(self, lifespan: ghidra.trace.model.Lifespan, addresses: ghidra.program.model.address.AddressSetView, item: T):
        ...

    @typing.overload
    def notifyNewEntry(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, item: T):
        ...

    @typing.overload
    def notifyNewEntry(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, item: T):
        ...

    @property
    def containing(self) -> V:
        ...


class DBTraceChangeSet(ghidra.trace.model.TraceChangeSet, ghidra.framework.data.DomainObjectDBChangeSet):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DBTraceManager(db.util.ErrorHandler):

    class_: typing.ClassVar[java.lang.Class]

    def invalidateCache(self, all: typing.Union[jpype.JBoolean, bool]):
        """
        Invalidate this manager's caches
        
        :param jpype.JBoolean or bool all: probably nothing. Check out implementations of
                    :meth:`ManagerDB.invalidateCache(boolean) <ManagerDB.invalidateCache>`.
        """



__all__ = ["DBTraceDirectChangeListener", "DBTrace", "DBTraceUtils", "DBTraceContentHandler", "DBTraceTimeViewport", "DBTraceCacheForSequenceQueries", "DBTraceUserData", "DBTraceLinkContentHandler", "DBTraceCacheForContainingQueries", "DBTraceChangeSet", "DBTraceManager"]
