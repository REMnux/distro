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
import ghidra.trace.database.target
import ghidra.trace.model.thread
import ghidra.util.task
import java.lang # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceThreadManager(ghidra.trace.model.thread.TraceThreadManager, ghidra.trace.database.DBTraceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, trace: ghidra.trace.database.DBTrace, objectManager: ghidra.trace.database.target.DBTraceObjectManager):
        ...

    def assertIsMine(self, thread: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.thread.TraceThread:
        ...


class DBTraceObjectProcess(ghidra.trace.model.thread.TraceProcess, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceThread(ghidra.trace.model.thread.TraceThread, ghidra.trace.database.target.DBTraceObjectInterface):

    @typing.type_check_only
    class ThreadChangeTranslator(ghidra.trace.database.target.DBTraceObjectInterface.Translator[ghidra.trace.model.thread.TraceThread]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...



__all__ = ["DBTraceThreadManager", "DBTraceObjectProcess", "DBTraceThread"]
