from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action.builder
import docking.widgets.table
import ghidra.app.plugin.core.debug
import ghidra.debug.api.tracemgr
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.trace.model
import ghidra.trace.model.time
import ghidra.trace.model.time.schedule
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class DebuggerTimeSelectionDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    def promptTime(self, trace: ghidra.trace.model.Trace, defaultTime: ghidra.trace.model.time.schedule.TraceSchedule) -> ghidra.trace.model.time.schedule.TraceSchedule:
        """
        Prompts the user to select a snapshot and optionally specify a full schedule
        
        :param ghidra.trace.model.Trace trace: the trace from whose snapshots to select
        :param ghidra.trace.model.time.schedule.TraceSchedule defaultTime: optionally the time to select initially
        :return: the schedule, likely specifying just the snapshot selection
        :rtype: ghidra.trace.model.time.schedule.TraceSchedule
        """

    def setScheduleText(self, text: typing.Union[java.lang.String, str]):
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...


class SnapshotRow(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, snapshot: ghidra.trace.model.time.TraceSnapshot, serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        ...

    def getDescription(self) -> str:
        ...

    def getEventThreadName(self) -> str:
        ...

    def getFunction(self) -> ghidra.program.model.listing.Function:
        ...

    def getModuleName(self) -> str:
        ...

    def getProgramCounter(self) -> ghidra.program.model.address.Address:
        ...

    def getSchedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        ...

    def getSnap(self) -> int:
        ...

    def getSnapshot(self) -> ghidra.trace.model.time.TraceSnapshot:
        ...

    def getTime(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        ...

    def getTimeStamp(self) -> java.util.Date:
        ...

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        ...

    @property
    def timeStamp(self) -> java.util.Date:
        ...

    @property
    def schedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        ...

    @property
    def programCounter(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def moduleName(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @description.setter
    def description(self, value: java.lang.String):
        ...

    @property
    def time(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        ...

    @property
    def snapshot(self) -> ghidra.trace.model.time.TraceSnapshot:
        ...

    @property
    def eventThreadName(self) -> java.lang.String:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class DebuggerTimeProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class GoToTimeAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Go To Time"
        DESCRIPTION: typing.Final = "Go to a specific time, optionally using emulation"
        GROUP: typing.Final = "Dbg7. Trace"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "goto_time"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class SetTimeRadixAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Set Time Radix"
        DESCRIPTION: typing.Final = "Change the time radix for this trace / target"
        GROUP: typing.Final = "Dbg7. Trace"
        HELP_ANCHOR: typing.Final = "radix"

        @staticmethod
        def builder(title: typing.Union[java.lang.String, str], owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class ForRadixTraceListener(ghidra.trace.model.TraceDomainObjectListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerTimePlugin):
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...


class DebuggerTimePlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerSnapshotTablePanel(javax.swing.JPanel):

    @typing.type_check_only
    class SnapshotTableColumns(java.lang.Enum[DebuggerSnapshotTablePanel.SnapshotTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerSnapshotTablePanel.SnapshotTableColumns, SnapshotRow]):

        class_: typing.ClassVar[java.lang.Class]
        SNAP: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]
        TIME: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]
        EVENT_THREAD: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]
        PC: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]
        MODULE: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]
        FUNCTION: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]
        TIMESTAMP: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]
        SCHEDULE: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]
        DESCRIPTION: typing.Final[DebuggerSnapshotTablePanel.SnapshotTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerSnapshotTablePanel.SnapshotTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerSnapshotTablePanel.SnapshotTableColumns]:
            ...


    @typing.type_check_only
    class SnapshotTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerSnapshotTablePanel.SnapshotTableColumns, SnapshotRow]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    @typing.type_check_only
    class SnapshotListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getSelectedSnapshot(self) -> int:
        ...

    def getSelectionModel(self) -> javax.swing.ListSelectionModel:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    def setCurrent(self, coords: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def setHideScratchSnapshots(self, hideScratch: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSelectedSnapshot(self, snap: typing.Union[java.lang.Long, int]):
        ...

    def setTrace(self, trace: ghidra.trace.model.Trace):
        ...

    @property
    def selectionModel(self) -> javax.swing.ListSelectionModel:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @trace.setter
    def trace(self, value: ghidra.trace.model.Trace):
        ...

    @property
    def selectedSnapshot(self) -> jpype.JLong:
        ...

    @selectedSnapshot.setter
    def selectedSnapshot(self, value: jpype.JLong):
        ...



__all__ = ["DebuggerTimeSelectionDialog", "SnapshotRow", "DebuggerTimeProvider", "DebuggerTimePlugin", "DebuggerSnapshotTablePanel"]
