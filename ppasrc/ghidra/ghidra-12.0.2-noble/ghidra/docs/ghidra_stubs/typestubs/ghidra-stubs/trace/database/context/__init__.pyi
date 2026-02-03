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
import ghidra.trace.database
import ghidra.trace.database.guest
import ghidra.trace.database.map
import ghidra.trace.database.space
import ghidra.trace.database.thread
import ghidra.trace.model.context
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceRegisterContextManager(ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager[DBTraceRegisterContextSpace], ghidra.trace.model.context.TraceRegisterContextManager, ghidra.trace.database.space.DBTraceDelegatingManager[DBTraceRegisterContextSpace]):

    @typing.type_check_only
    class DBTraceRegisterContextEntry(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[jpype.JArray[jpype.JByte]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[jpype.JArray[jpype.JByte], typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "RegisterContext"

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, languageManager: ghidra.trace.database.guest.DBTracePlatformManager):
        ...

    def getDefaultContext(self, language: ghidra.program.model.lang.Language) -> ghidra.program.model.listing.ProgramContext:
        ...

    @property
    def defaultContext(self) -> ghidra.program.model.listing.ProgramContext:
        ...


class DBTraceRegisterContextSpace(ghidra.trace.model.context.TraceRegisterContextSpace, ghidra.trace.database.space.DBTraceSpaceBased):

    class DBTraceRegisterEntry(ghidra.util.database.DBAnnotatedObject):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceRegisterContextManager, dbh: db.DBHandle, space: ghidra.program.model.address.AddressSpace, ent: ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry):
        ...



__all__ = ["DBTraceRegisterContextManager", "DBTraceRegisterContextSpace"]
