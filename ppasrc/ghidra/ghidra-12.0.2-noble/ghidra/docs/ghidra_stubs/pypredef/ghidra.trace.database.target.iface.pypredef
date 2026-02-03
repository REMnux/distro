from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.trace.database.target
import ghidra.trace.model.target.iface
import java.lang # type: ignore


class DBTraceObjectMethod(ghidra.trace.model.target.iface.TraceMethod, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceObjectEventScope(ghidra.trace.model.target.iface.TraceEventScope, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceObjectFocusScope(ghidra.trace.model.target.iface.TraceFocusScope, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceObjectActivatable(ghidra.trace.model.target.iface.TraceActivatable, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceObjectTogglable(ghidra.trace.model.target.iface.TraceTogglable, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceObjectEnvironment(ghidra.trace.model.target.iface.TraceEnvironment, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceObjectExecutionStateful(ghidra.trace.model.target.iface.TraceExecutionStateful, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceObjectAggregate(ghidra.trace.model.target.iface.TraceAggregate, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...



__all__ = ["DBTraceObjectMethod", "DBTraceObjectEventScope", "DBTraceObjectFocusScope", "DBTraceObjectActivatable", "DBTraceObjectTogglable", "DBTraceObjectEnvironment", "DBTraceObjectExecutionStateful", "DBTraceObjectAggregate"]
