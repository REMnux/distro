from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui.model
import ghidra.app.plugin.core.debug.gui.model.columns
import ghidra.app.services
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.trace.model


class DebuggerThreadsProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class ForSnapsListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerThreadsPlugin):
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def setEmulationService(self, emulationService: ghidra.app.services.DebuggerEmulationService):
        ...


class DebuggerTraceFileActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.model.Trace):
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...


class DebuggerThreadsPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerThreadsPanel(ghidra.app.plugin.core.debug.gui.model.AbstractObjectsTableBasedPanel[ghidra.trace.model.thread.TraceThread]):

    @typing.type_check_only
    class ThreadPathColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ThreadNameColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueValColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ThreadPcColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn[ghidra.program.model.address.Address]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ThreadFunctionColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn[ghidra.program.model.listing.Function]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ThreadModuleColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ThreadSpColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn[ghidra.program.model.address.Address]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ThreadStateColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectAttributeColumn[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ThreadCommentColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectEditableAttributeColumn[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ThreadPlotColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueLifePlotColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ThreadTableModel(ghidra.app.plugin.core.debug.gui.model.ObjectTableModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerThreadsProvider):
        ...



__all__ = ["DebuggerThreadsProvider", "DebuggerTraceFileActionContext", "DebuggerThreadsPlugin", "DebuggerThreadsPanel"]
