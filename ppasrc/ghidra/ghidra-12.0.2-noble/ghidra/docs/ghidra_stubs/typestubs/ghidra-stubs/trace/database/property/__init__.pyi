from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.model.lang
import ghidra.trace.database
import ghidra.trace.database.thread
import ghidra.trace.model.property
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceAddressPropertyManager(ghidra.trace.model.property.TraceAddressPropertyManager, ghidra.trace.database.DBTraceManager):
    """
    TODO: Document me
     
    TODO: This is public for user properties, i.e., :obj:`ProgramUserData`, but encapsulated for
    trace properties
    """

    @typing.type_check_only
    class DBTraceAddressPropertyEntry(ghidra.util.database.DBAnnotatedObject):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
        ...

    def getApiPropertyManager(self) -> ghidra.trace.model.property.TraceAddressPropertyManager:
        ...

    @property
    def apiPropertyManager(self) -> ghidra.trace.model.property.TraceAddressPropertyManager:
        ...


@typing.type_check_only
class DBTraceAddressPropertyManagerApiView(ghidra.trace.model.property.TraceAddressPropertyManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, internalView: DBTraceAddressPropertyManager):
        ...



__all__ = ["DBTraceAddressPropertyManager", "DBTraceAddressPropertyManagerApiView"]
