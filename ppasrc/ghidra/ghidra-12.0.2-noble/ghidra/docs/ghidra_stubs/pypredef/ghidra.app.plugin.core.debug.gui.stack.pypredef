from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action.builder
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui.model
import ghidra.app.plugin.core.debug.gui.model.columns
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.trace.model
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


class DebuggerStackPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerStackProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class UnwindStackAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Unwind from frame 0"
        DESCRIPTION: typing.Final = "Unwind the stack, placing frames in the dynamic listing"
        HELP_ANCHOR: typing.Final = "unwind_stack"
        KEY_STROKE: typing.Final[javax.swing.KeyStroke]

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerStackPlugin):
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def traceClosed(self, trace: ghidra.trace.model.Trace):
        ...


class DebuggerStackPanel(ghidra.app.plugin.core.debug.gui.model.AbstractObjectsTableBasedPanel[ghidra.trace.model.stack.TraceStackFrame], javax.swing.event.ListSelectionListener):

    @typing.type_check_only
    class FrameLevelColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FramePcColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectAttributeColumn[ghidra.program.model.address.Address]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class FrameFunctionColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn[ghidra.program.model.listing.Function]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class FrameModuleColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class StackTableModel(ghidra.app.plugin.core.debug.gui.model.ObjectTableModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerStackProvider):
        ...



__all__ = ["DebuggerStackPlugin", "DebuggerStackProvider", "DebuggerStackPanel"]
