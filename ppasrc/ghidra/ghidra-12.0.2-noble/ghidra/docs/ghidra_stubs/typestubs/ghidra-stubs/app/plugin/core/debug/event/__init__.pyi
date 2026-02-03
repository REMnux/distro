from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.events
import ghidra.debug.api.action
import ghidra.debug.api.platform
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.program
import java.lang # type: ignore


class TraceInactiveCoordinatesPluginEvent(ghidra.framework.plugintool.PluginEvent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def getCoordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    @property
    def coordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...


class DebuggerPlatformPluginEvent(ghidra.framework.plugintool.PluginEvent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceName: typing.Union[java.lang.String, str], trace: ghidra.trace.model.Trace, mapper: ghidra.debug.api.platform.DebuggerPlatformMapper):
        ...

    def getMapper(self) -> ghidra.debug.api.platform.DebuggerPlatformMapper:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def mapper(self) -> ghidra.debug.api.platform.DebuggerPlatformMapper:
        ...


class TraceSelectionPluginEvent(ghidra.app.events.AbstractSelectionPluginEvent):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "TraceSelection"

    def __init__(self, src: typing.Union[java.lang.String, str], selection: ghidra.program.util.ProgramSelection, view: ghidra.trace.model.program.TraceProgramView):
        ...

    def getTraceProgramView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...

    @property
    def traceProgramView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...


class TraceHighlightPluginEvent(ghidra.app.events.AbstractHighlightPluginEvent):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "TraceHighlight"

    def __init__(self, src: typing.Union[java.lang.String, str], highlight: ghidra.program.util.ProgramSelection, view: ghidra.trace.model.program.TraceProgramView):
        ...

    def getTraceProgramView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...

    @property
    def traceProgramView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...


class TraceOpenedPluginEvent(ghidra.framework.plugintool.PluginEvent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], trace: ghidra.trace.model.Trace):
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...


class TraceClosedPluginEvent(ghidra.framework.plugintool.PluginEvent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], trace: ghidra.trace.model.Trace):
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...


class TrackingChangedPluginEvent(ghidra.framework.plugintool.PluginEvent):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "TrackingChanged"

    def __init__(self, sourceName: typing.Union[java.lang.String, str], spec: ghidra.debug.api.action.LocationTrackingSpec):
        ...

    def getLocationTrackingSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...

    @property
    def locationTrackingSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...


class TraceLocationPluginEvent(ghidra.app.events.AbstractLocationPluginEvent):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "TraceLocation"

    def __init__(self, src: typing.Union[java.lang.String, str], loc: ghidra.program.util.ProgramLocation):
        ...

    def getTraceProgramView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...

    @property
    def traceProgramView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...


class TraceActivatedPluginEvent(ghidra.framework.plugintool.PluginEvent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, cause: ghidra.app.services.DebuggerTraceManagerService.ActivationCause):
        ...

    def getActiveCoordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    def getCause(self) -> ghidra.app.services.DebuggerTraceManagerService.ActivationCause:
        ...

    @property
    def activeCoordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    @property
    def cause(self) -> ghidra.app.services.DebuggerTraceManagerService.ActivationCause:
        ...



__all__ = ["TraceInactiveCoordinatesPluginEvent", "DebuggerPlatformPluginEvent", "TraceSelectionPluginEvent", "TraceHighlightPluginEvent", "TraceOpenedPluginEvent", "TraceClosedPluginEvent", "TrackingChangedPluginEvent", "TraceLocationPluginEvent", "TraceActivatedPluginEvent"]
