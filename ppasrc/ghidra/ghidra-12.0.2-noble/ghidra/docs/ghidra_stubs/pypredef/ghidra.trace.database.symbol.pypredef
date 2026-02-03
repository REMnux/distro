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
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.trace.database
import ghidra.trace.database.address
import ghidra.trace.database.data
import ghidra.trace.database.map
import ghidra.trace.database.space
import ghidra.trace.database.thread
import ghidra.trace.model
import ghidra.trace.model.symbol
import ghidra.trace.model.thread
import ghidra.trace.util
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore


T = typing.TypeVar("T")


class DBTraceReferenceManager(ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager[DBTraceReferenceSpace], ghidra.trace.model.symbol.TraceReferenceManager, ghidra.trace.database.space.DBTraceDelegatingManager[DBTraceReferenceSpace]):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Reference"

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, overlayAdapter: ghidra.trace.database.address.DBTraceOverlaySpaceAdapter):
        ...

    def assertIsMine(self, ref: ghidra.program.model.symbol.Reference) -> DBTraceReference:
        ...

    def checkIsInMemory(self, space: ghidra.program.model.address.AddressSpace):
        """
        Ensures that a "from" address is in memory
         
         
        
        NOTE: To manage references from registers, you must use
        :meth:`getReferenceRegisterSpace(TraceThread, boolean) <.getReferenceRegisterSpace>`, which requires a thread.
        
        :param ghidra.program.model.address.AddressSpace space: the space of the address to check
        """


class DBTraceOffsetReference(DBTraceReference, ghidra.trace.model.symbol.TraceOffsetReference):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ent: DBTraceReferenceSpace.DBTraceReferenceEntry, isExternalBlockReference: typing.Union[jpype.JBoolean, bool]):
        ...


class DBTraceReference(ghidra.trace.model.symbol.TraceReference):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ent: DBTraceReferenceSpace.DBTraceReferenceEntry):
        ...


class DBTraceNamespaceSymbol(AbstractDBTraceSymbol, ghidra.trace.model.symbol.TraceNamespaceSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class AbstractDBTraceSymbolSingleTypeWithAddressView(AbstractDBTraceSymbolSingleTypeView[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager, typeID: typing.Union[jpype.JByte, int], store: ghidra.util.database.DBCachedObjectStore[T]):
        ...

    def getAt(self, address: ghidra.program.model.address.Address, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        ...

    def getChildWithNameAt(self, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, parent: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> T:
        ...

    def getGlobalWithNameAt(self, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address) -> T:
        ...

    def getIntersecting(self, range: ghidra.program.model.address.AddressRange, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        ...


class AbstractDBTraceSymbolSingleTypeView(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager, typeID: typing.Union[jpype.JByte, int], store: ghidra.util.database.DBCachedObjectStore[T]):
        ...

    def getAll(self, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        ...

    def getByKey(self, key: typing.Union[jpype.JLong, int]) -> T:
        ...

    def getChildren(self, parent: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> java.util.Collection[T]:
        ...

    def getChildrenNamed(self, name: typing.Union[java.lang.String, str], parent: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> java.util.Collection[T]:
        ...

    def getManager(self) -> DBTraceSymbolManager:
        ...

    def getNamed(self, name: typing.Union[java.lang.String, str]) -> java.util.Collection[T]:
        ...

    def getWithMatchingName(self, glob: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        ...

    def invalidateCache(self):
        ...

    def scanByName(self, startName: typing.Union[java.lang.String, str]) -> java.util.Iterator[T]:
        ...

    @property
    def all(self) -> java.util.Collection[T]:
        ...

    @property
    def named(self) -> java.util.Collection[T]:
        ...

    @property
    def manager(self) -> DBTraceSymbolManager:
        ...

    @property
    def children(self) -> java.util.Collection[T]:
        ...

    @property
    def byKey(self) -> T:
        ...


class DBTraceEquateManager(ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager[DBTraceEquateSpace], ghidra.trace.model.symbol.TraceEquateManager, ghidra.trace.database.space.DBTraceDelegatingManager[DBTraceEquateSpace]):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Equate"

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
        ...


class DBTraceClassSymbol(DBTraceNamespaceSymbol, ghidra.trace.model.symbol.TraceClassSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class DBTraceSnapSelectedReferenceSpace(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DBTraceSymbolManager(ghidra.trace.model.symbol.TraceSymbolManager, ghidra.trace.database.DBTraceManager):

    class DBTraceSymbolIDEntry(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[java.lang.Long]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[java.lang.Long, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class VariableStorageDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[ghidra.program.model.listing.VariableStorage, DBTraceSymbolManager.DBTraceVariableStorageEntry, db.StringField]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[DBTraceSymbolManager.DBTraceVariableStorageEntry], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class DBTraceVariableStorageEntry(ghidra.util.database.DBAnnotatedObject):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, manager: DBTraceSymbolManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...

        def getProgram(self) -> ghidra.program.model.listing.Program:
            ...

        def getStorage(self) -> ghidra.program.model.listing.VariableStorage:
            ...

        @property
        def storage(self) -> ghidra.program.model.listing.VariableStorage:
            ...

        @property
        def program(self) -> ghidra.program.model.listing.Program:
            ...


    class MySymbolTypes(java.lang.Enum[DBTraceSymbolManager.MySymbolTypes]):

        class_: typing.ClassVar[java.lang.Class]
        LABEL: typing.Final[DBTraceSymbolManager.MySymbolTypes]
        NO_LIBRARY: typing.Final[DBTraceSymbolManager.MySymbolTypes]
        NO_NULL: typing.Final[DBTraceSymbolManager.MySymbolTypes]
        NAMESPACE: typing.Final[DBTraceSymbolManager.MySymbolTypes]
        CLASS: typing.Final[DBTraceSymbolManager.MySymbolTypes]
        GLOBAL_VAR: typing.Final[DBTraceSymbolManager.MySymbolTypes]
        VALUES: typing.Final[java.util.List[DBTraceSymbolManager.MySymbolTypes]]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DBTraceSymbolManager.MySymbolTypes:
            ...

        @staticmethod
        def values() -> jpype.JArray[DBTraceSymbolManager.MySymbolTypes]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, dataTypeManager: ghidra.trace.database.data.DBTraceDataTypeManager, overlayAdapter: ghidra.trace.database.address.DBTraceOverlaySpaceAdapter):
        ...

    @typing.overload
    def assertIsMine(self, ns: ghidra.program.model.symbol.Namespace) -> DBTraceNamespaceSymbol:
        ...

    @typing.overload
    def assertIsMine(self, symbol: ghidra.program.model.symbol.Symbol) -> AbstractDBTraceSymbol:
        ...

    @typing.overload
    def checkIsMine(self, ns: ghidra.program.model.symbol.Namespace) -> DBTraceNamespaceSymbol:
        ...

    @typing.overload
    def checkIsMine(self, symbol: ghidra.program.model.symbol.Symbol) -> AbstractDBTraceSymbol:
        ...

    def replaceDataTypes(self, dataTypeReplacementMap: collections.abc.Mapping):
        ...

    def uniqueNamespaces(self) -> ghidra.trace.model.symbol.TraceSymbolNoDuplicatesView[DBTraceNamespaceSymbol]:
        ...


class DBTraceSymbolMultipleTypesWithLocationView(DBTraceSymbolMultipleTypesView[T], ghidra.trace.model.symbol.TraceSymbolWithLocationView[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, parts: collections.abc.Sequence):
        ...

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, *parts: AbstractDBTraceSymbolSingleTypeWithLocationView[T]):
        ...


class AbstractDBTraceSymbolSingleTypeWithLocationView(AbstractDBTraceSymbolSingleTypeView[T], typing.Generic[T]):

    @typing.type_check_only
    class GetSymbolsKey(ghidra.trace.database.DBTraceCacheForContainingQueries.GetKey):

        class_: typing.ClassVar[java.lang.Class]
        thread: typing.Final[ghidra.trace.model.thread.TraceThread]

        def __init__(self, thread: ghidra.trace.model.thread.TraceThread, snap: typing.Union[jpype.JLong, int], addr: ghidra.program.model.address.Address, includeDynamic: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class CacheForGetSymbolsAtQueries(ghidra.trace.database.DBTraceCacheForContainingQueries[AbstractDBTraceSymbolSingleTypeWithLocationView.GetSymbolsKey, java.util.Collection[T], T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager, typeID: typing.Union[jpype.JByte, int], store: ghidra.util.database.DBCachedObjectStore[T]):
        ...

    def getAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get the symbols at the given snap and address, starting with the primary
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address address: the address
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamic symbols
        :return: the collection
        :rtype: java.util.Collection[T]
        """

    def getChildWithNameAt(self, name: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, parent: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> T:
        ...

    @typing.overload
    def getIntersecting(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get intersecting things in no particular order
        
        :param ghidra.trace.model.Lifespan span: the span of snapshots
        :param ghidra.program.model.address.AddressRange range: the range of addresses
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamic symbols
        :return: the collection
        :rtype: java.util.Collection[T]
        """

    @typing.overload
    def getIntersecting(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool], forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        ...


class DBTraceLabelSymbolView(AbstractDBTraceSymbolSingleTypeWithLocationView[DBTraceLabelSymbol], ghidra.trace.model.symbol.TraceLabelSymbolView):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager):
        ...


class DBTraceSymbolMultipleTypesWithAddressNoDuplicatesView(DBTraceSymbolMultipleTypesWithAddressView[T], ghidra.trace.model.symbol.TraceSymbolWithAddressNoDuplicatesView[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, parts: collections.abc.Sequence):
        ...

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, *parts: AbstractDBTraceSymbolSingleTypeWithAddressView[T]):
        ...


class DBTraceEquate(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.symbol.TraceEquate):

    class_: typing.ClassVar[java.lang.Class]
    TABLE_NAME: typing.Final = "Equates"

    def __init__(self, manager: DBTraceEquateManager, store: ghidra.util.database.DBCachedObjectStore[DBTraceEquate], record: db.DBRecord):
        ...

    def getReferences(self, refAddr: ghidra.program.model.address.Address) -> java.util.List[ghidra.program.model.symbol.EquateReference]:
        ...

    @property
    def references(self) -> java.util.List[ghidra.program.model.symbol.EquateReference]:
        ...


class DBTraceShiftedReference(DBTraceReference, ghidra.trace.model.symbol.TraceShiftedReference):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ent: DBTraceReferenceSpace.DBTraceReferenceEntry):
        ...


class DBTraceClassSymbolView(AbstractDBTraceSymbolSingleTypeView[DBTraceClassSymbol], ghidra.trace.model.symbol.TraceClassSymbolView):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager):
        ...


class DBTraceReferenceSpace(ghidra.trace.database.space.DBTraceSpaceBased, ghidra.trace.model.symbol.TraceReferenceSpace):

    @typing.type_check_only
    class TypeEnum(java.lang.Enum[DBTraceReferenceSpace.TypeEnum]):

        class_: typing.ClassVar[java.lang.Class]
        MEMORY: typing.Final[DBTraceReferenceSpace.TypeEnum]
        OFFSET: typing.Final[DBTraceReferenceSpace.TypeEnum]
        SHIFT: typing.Final[DBTraceReferenceSpace.TypeEnum]
        OFFSET_EXTERNAL: typing.Final[DBTraceReferenceSpace.TypeEnum]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DBTraceReferenceSpace.TypeEnum:
            ...

        @staticmethod
        def values() -> jpype.JArray[DBTraceReferenceSpace.TypeEnum]:
            ...


    @typing.type_check_only
    class DBTraceReferenceEntry(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[DBTraceReferenceSpace.DBTraceReferenceEntry], ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses):
        """
        A reference entry
         
         
        
        Version history:
         
        * 1: Change :obj:`.toAddress` to 10-byte fixed encoding
        * 0: Initial version and previous unversioned implementation
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, space: DBTraceReferenceSpace, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceReferenceSpace.DBTraceReferenceEntry, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...

        def getRefType(self) -> ghidra.program.model.symbol.RefType:
            ...

        def getSourceType(self) -> ghidra.program.model.symbol.SourceType:
            ...

        def getSymbolId(self) -> int:
            ...

        def isPrimary(self) -> bool:
            ...

        def setEndSnap(self, endSnap: typing.Union[jpype.JLong, int]):
            ...

        def setPrimary(self, b: typing.Union[jpype.JBoolean, bool]):
            ...

        def setRefType(self, refType: ghidra.program.model.symbol.RefType):
            ...

        def setSymbolId(self, symbolId: typing.Union[jpype.JLong, int]):
            ...

        @staticmethod
        def tableName(space: ghidra.program.model.address.AddressSpace) -> str:
            ...

        @property
        def symbolId(self) -> jpype.JLong:
            ...

        @symbolId.setter
        def symbolId(self, value: jpype.JLong):
            ...

        @property
        def sourceType(self) -> ghidra.program.model.symbol.SourceType:
            ...

        @property
        def refType(self) -> ghidra.program.model.symbol.RefType:
            ...

        @refType.setter
        def refType(self, value: ghidra.program.model.symbol.RefType):
            ...

        @property
        def primary(self) -> jpype.JBoolean:
            ...

        @primary.setter
        def primary(self, value: jpype.JBoolean):
            ...


    @typing.type_check_only
    class DBTraceXRefEntry(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[DBTraceReferenceSpace.DBTraceXRefEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, space: DBTraceReferenceSpace, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceReferenceSpace.DBTraceXRefEntry, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...

        @staticmethod
        def tableName(space: ghidra.program.model.address.AddressSpace) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceReferenceManager, dbh: db.DBHandle, space: ghidra.program.model.address.AddressSpace, ent: ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry):
        ...


class DBTraceEquateSpace(ghidra.trace.database.space.DBTraceSpaceBased, ghidra.trace.model.symbol.TraceEquateSpace):

    @typing.type_check_only
    class EquateRefType(java.lang.Enum[DBTraceEquateSpace.EquateRefType]):

        class_: typing.ClassVar[java.lang.Class]
        OP: typing.Final[DBTraceEquateSpace.EquateRefType]
        HASH: typing.Final[DBTraceEquateSpace.EquateRefType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DBTraceEquateSpace.EquateRefType:
            ...

        @staticmethod
        def values() -> jpype.JArray[DBTraceEquateSpace.EquateRefType]:
            ...


    @typing.type_check_only
    class DBTraceEquateReference(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[DBTraceEquateSpace.DBTraceEquateReference]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, space: DBTraceEquateSpace, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceEquateSpace.DBTraceEquateReference, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...

        @staticmethod
        def tableName(space: ghidra.program.model.address.AddressSpace) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceEquateManager, dbh: db.DBHandle, space: ghidra.program.model.address.AddressSpace, ent: ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry):
        ...


class DBTraceLabelSymbol(AbstractDBTraceSymbol, ghidra.trace.model.symbol.TraceLabelSymbol, ghidra.trace.util.TraceSpaceMixin, ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses):
    """
    The implementation of a label symbol, directly via a database object
     
     
    
    Version history:
     
    * 1: Change :obj:`.address` to 10-byte fixed encoding
    * 0: Initial version and previous unversioned implementation
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class DBTraceSymbolMultipleTypesNoDuplicatesView(DBTraceSymbolMultipleTypesView[T], ghidra.trace.model.symbol.TraceSymbolNoDuplicatesView[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, parts: collections.abc.Sequence):
        ...

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, *parts: AbstractDBTraceSymbolSingleTypeView[T]):
        ...


class DBTraceSymbolMultipleTypesView(ghidra.trace.model.symbol.TraceSymbolView[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, parts: collections.abc.Sequence):
        ...

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, *parts: AbstractDBTraceSymbolSingleTypeView[T]):
        ...


class AbstractDBTraceSymbol(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.symbol.TraceSymbol, ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...

    def getAddressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...


class DBTraceSymbolMultipleTypesWithAddressView(DBTraceSymbolMultipleTypesView[T], ghidra.trace.model.symbol.TraceSymbolWithAddressView[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, parts: collections.abc.Sequence):
        ...

    @typing.overload
    def __init__(self, manager: DBTraceSymbolManager, *parts: AbstractDBTraceSymbolSingleTypeWithAddressView[T]):
        ...


class DBTraceStackReference(DBTraceReference, ghidra.trace.model.symbol.TraceStackReference):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ent: DBTraceReferenceSpace.DBTraceReferenceEntry):
        ...


class DBTraceNamespaceSymbolView(AbstractDBTraceSymbolSingleTypeView[DBTraceNamespaceSymbol], ghidra.trace.model.symbol.TraceNamespaceSymbolView):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceSymbolManager):
        ...



__all__ = ["DBTraceReferenceManager", "DBTraceOffsetReference", "DBTraceReference", "DBTraceNamespaceSymbol", "AbstractDBTraceSymbolSingleTypeWithAddressView", "AbstractDBTraceSymbolSingleTypeView", "DBTraceEquateManager", "DBTraceClassSymbol", "DBTraceSnapSelectedReferenceSpace", "DBTraceSymbolManager", "DBTraceSymbolMultipleTypesWithLocationView", "AbstractDBTraceSymbolSingleTypeWithLocationView", "DBTraceLabelSymbolView", "DBTraceSymbolMultipleTypesWithAddressNoDuplicatesView", "DBTraceEquate", "DBTraceShiftedReference", "DBTraceClassSymbolView", "DBTraceReferenceSpace", "DBTraceEquateSpace", "DBTraceLabelSymbol", "DBTraceSymbolMultipleTypesNoDuplicatesView", "DBTraceSymbolMultipleTypesView", "AbstractDBTraceSymbol", "DBTraceSymbolMultipleTypesWithAddressView", "DBTraceStackReference", "DBTraceNamespaceSymbolView"]
