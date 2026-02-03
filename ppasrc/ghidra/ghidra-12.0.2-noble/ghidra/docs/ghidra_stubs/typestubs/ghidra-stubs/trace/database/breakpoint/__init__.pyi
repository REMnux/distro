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
import ghidra.trace.database
import ghidra.trace.database.target
import ghidra.trace.model.breakpoint
import ghidra.util.task
import java.lang # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceBreakpointLocation(ghidra.trace.model.breakpoint.TraceBreakpointLocation, ghidra.trace.database.target.DBTraceObjectInterface):

    @typing.type_check_only
    class BreakpointChangeTranslator(ghidra.trace.database.target.DBTraceObjectInterface.Translator[ghidra.trace.model.breakpoint.TraceBreakpointLocation]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...

    def getAddressSpace(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSpace:
        ...

    def getOrCreateSpecification(self) -> ghidra.trace.model.breakpoint.TraceBreakpointSpec:
        ...

    @property
    def orCreateSpecification(self) -> ghidra.trace.model.breakpoint.TraceBreakpointSpec:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class DBTraceBreakpointManager(ghidra.trace.model.breakpoint.TraceBreakpointManager, ghidra.trace.database.DBTraceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, trace: ghidra.trace.database.DBTrace, objectManager: ghidra.trace.database.target.DBTraceObjectManager):
        ...


class DBTraceBreakpointSpec(ghidra.trace.model.breakpoint.TraceBreakpointSpec, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...



__all__ = ["DBTraceBreakpointLocation", "DBTraceBreakpointManager", "DBTraceBreakpointSpec"]
