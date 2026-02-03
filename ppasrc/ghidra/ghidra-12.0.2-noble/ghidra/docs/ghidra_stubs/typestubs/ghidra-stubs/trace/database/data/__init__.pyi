from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.database.data
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.database
import ghidra.trace.database.guest
import ghidra.trace.database.map
import ghidra.trace.database.thread
import ghidra.trace.model
import ghidra.trace.model.data
import ghidra.trace.model.map
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceDataTypeManager(ghidra.program.database.data.ProgramBasedDataTypeManagerDB, ghidra.trace.model.data.TraceBasedDataTypeManager, ghidra.trace.database.DBTraceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, trace: ghidra.trace.database.DBTrace, platform: ghidra.trace.database.guest.InternalTracePlatform):
        ...


class DBTraceDataSettingsAdapter(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap[DBTraceDataSettingsAdapter.DBTraceSettingsEntry, DBTraceDataSettingsAdapter.DBTraceSettingsEntry], DBTraceDataSettingsOperations):

    @typing.type_check_only
    class DBTraceSettingsEntry(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[DBTraceDataSettingsAdapter.DBTraceSettingsEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceDataSettingsAdapter.DBTraceSettingsEntry, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class DBTraceDataSettingsSpace(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace[DBTraceDataSettingsAdapter.DBTraceSettingsEntry, DBTraceDataSettingsAdapter.DBTraceSettingsEntry], DBTraceDataSettingsOperations):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tableName: typing.Union[java.lang.String, str], trace: ghidra.trace.database.DBTrace, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, lock: java.util.concurrent.locks.ReadWriteLock, space: ghidra.program.model.address.AddressSpace, dataType: java.lang.Class[DBTraceDataSettingsAdapter.DBTraceSettingsEntry], dataFactory: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory[DBTraceDataSettingsAdapter.DBTraceSettingsEntry, DBTraceDataSettingsAdapter.DBTraceSettingsEntry]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "DataSettings"

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
        ...


class DBTraceDataSettingsOperations(ghidra.trace.model.map.TraceAddressSnapRangePropertyMapOperations[DBTraceDataSettingsAdapter.DBTraceSettingsEntry]):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def assertKnownType(obj: java.lang.Object):
        ...

    def clear(self, span: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]):
        ...

    def doExactOrNew(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> DBTraceDataSettingsAdapter.DBTraceSettingsEntry:
        ...

    def doGetEntry(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> DBTraceDataSettingsAdapter.DBTraceSettingsEntry:
        ...

    def doGetExactEntry(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> DBTraceDataSettingsAdapter.DBTraceSettingsEntry:
        ...

    def doMakeWay(self, span: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]):
        ...

    def getLock(self) -> java.util.concurrent.locks.ReadWriteLock:
        ...

    def getLong(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> int:
        ...

    def getSettingNames(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address) -> java.util.Collection[java.lang.String]:
        ...

    def getString(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> str:
        ...

    def getValue(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> java.lang.Object:
        ...

    def isEmpty(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address) -> bool:
        ...

    def makeWay(self, entry: DBTraceDataSettingsAdapter.DBTraceSettingsEntry, span: ghidra.trace.model.Lifespan):
        ...

    def setLong(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        ...

    def setString(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    def setValue(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], value: java.lang.Object):
        ...

    @property
    def lock(self) -> java.util.concurrent.locks.ReadWriteLock:
        ...



__all__ = ["DBTraceDataTypeManager", "DBTraceDataSettingsAdapter", "DBTraceDataSettingsOperations"]
