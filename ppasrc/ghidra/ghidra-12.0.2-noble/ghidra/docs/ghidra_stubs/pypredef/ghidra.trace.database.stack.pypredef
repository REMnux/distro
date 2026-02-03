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
import ghidra.trace.database.address
import ghidra.trace.database.target
import ghidra.trace.database.thread
import ghidra.trace.model.stack
import ghidra.trace.model.target
import ghidra.trace.model.target.iface
import ghidra.trace.model.target.path
import ghidra.util.task
import java.lang # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceStackFrame(ghidra.trace.model.stack.TraceStackFrame, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceStack(ghidra.trace.model.stack.TraceStack, ghidra.trace.database.target.DBTraceObjectInterface):

    @typing.type_check_only
    class StackChangeTranslator(ghidra.trace.database.target.DBTraceObjectInterface.Translator[ghidra.trace.model.stack.TraceStack]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceStackManager(ghidra.trace.model.stack.TraceStackManager, ghidra.trace.database.DBTraceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, overlayAdapter: ghidra.trace.database.address.DBTraceOverlaySpaceAdapter):
        ...

    @staticmethod
    def single(seed: ghidra.trace.model.target.TraceObject, targetIf: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> ghidra.trace.model.target.path.PathFilter:
        ...



__all__ = ["DBTraceStackFrame", "DBTraceStack", "DBTraceStackManager"]
