from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.trace.database
import ghidra.trace.database.thread
import ghidra.trace.model.time
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceTimeManager(ghidra.trace.model.time.TraceTimeManager, ghidra.trace.database.DBTraceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
        ...

    def deleteSnapshot(self, snapshot: DBTraceSnapshot):
        ...


class DBTraceSnapshot(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.time.TraceSnapshot):

    class_: typing.ClassVar[java.lang.Class]
    manager: typing.Final[DBTraceTimeManager]

    def __init__(self, manager: DBTraceTimeManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...



__all__ = ["DBTraceTimeManager", "DBTraceSnapshot"]
