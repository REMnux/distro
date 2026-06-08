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
import ghidra.app.plugin.core.data
import ghidra.app.plugin.core.debug
import ghidra.app.services
import ghidra.base.widgets.table
import ghidra.debug.api.tracemgr
import ghidra.debug.api.watch
import ghidra.docking.settings
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.memory
import ghidra.trace.model.time.schedule
import ghidra.util.table.column
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class DefaultWatchRow(ghidra.debug.api.watch.WatchRow):

    class_: typing.ClassVar[java.lang.Class]
    TRUNCATE_BYTES_LENGTH: typing.Final = 64

    def __init__(self, provider: DebuggerWatchesProvider, expression: typing.Union[java.lang.String, str]) -> None:
        ...

    def getReads(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the memory read by the watch, from the host platform perspective
        
        :return: the reads
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getSettings(self) -> ghidra.docking.settings.Settings:
        """
        Get the row's (mutable) data type settings
         
         
        
        After mutating these settings, the client must call :meth:`settingsChanged() <.settingsChanged>` to update the
        row's display and save state.
        
        :return: the settings
        :rtype: ghidra.docking.settings.Settings
        """

    def getState(self) -> ghidra.trace.model.memory.TraceMemoryState:
        ...

    def getTypePath(self) -> str:
        ...

    def setRawValueBytes(self, bytes: jpype.JArray[jpype.JByte]) -> None:
        ...

    def setRawValueBytesString(self, bytesString: typing.Union[java.lang.String, str]) -> None:
        ...

    def setRawValueIntString(self, intString: typing.Union[java.lang.String, str]) -> None:
        ...

    def setTypePath(self, typePath: typing.Union[java.lang.String, str]) -> None:
        ...

    @property
    def typePath(self) -> java.lang.String:
        ...

    @typePath.setter
    def typePath(self, value: java.lang.String):
        ...

    @property
    def settings(self) -> ghidra.docking.settings.Settings:
        ...

    @property
    def reads(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def state(self) -> ghidra.trace.model.memory.TraceMemoryState:
        ...


class DebuggerWatchesProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.app.services.DebuggerWatchesService):

    @typing.type_check_only
    class WatchTypeSettings(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Watch Type Settings"
        DESCRIPTION: typing.Final = "Set the watch\'s data type settings"
        HELP_ANCHOR: typing.Final = "type_settings"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class WatchDataSettingsDialog(ghidra.app.plugin.core.data.AbstractSettingsDialog):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, row: ghidra.debug.api.watch.WatchRow) -> None:
            ...


    @typing.type_check_only
    class WatchTableColumns(java.lang.Enum[DebuggerWatchesProvider.WatchTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerWatchesProvider.WatchTableColumns, DefaultWatchRow]):

        class_: typing.ClassVar[java.lang.Class]
        EXPRESSION: typing.Final[DebuggerWatchesProvider.WatchTableColumns]
        COMMENT: typing.Final[DebuggerWatchesProvider.WatchTableColumns]
        ADDRESS: typing.Final[DebuggerWatchesProvider.WatchTableColumns]
        SYMBOL: typing.Final[DebuggerWatchesProvider.WatchTableColumns]
        VALUE: typing.Final[DebuggerWatchesProvider.WatchTableColumns]
        TYPE: typing.Final[DebuggerWatchesProvider.WatchTableColumns]
        REPR: typing.Final[DebuggerWatchesProvider.WatchTableColumns]
        ERROR: typing.Final[DebuggerWatchesProvider.WatchTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerWatchesProvider.WatchTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerWatchesProvider.WatchTableColumns]:
            ...


    @typing.type_check_only
    class WatchTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerWatchesProvider.WatchTableColumns, DefaultWatchRow]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
            ...


    @typing.type_check_only
    class ForDepsListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self) -> None:
            ...


    @typing.type_check_only
    class WatchDataTypeEditor(ghidra.base.widgets.table.DataTypeTableCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self) -> None:
            ...


    @typing.type_check_only
    class WatchValueCellRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerWatchesPlugin) -> None:
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> None:
        ...

    def doCheckDepsAndReevaluate(self) -> None:
        ...

    def goToTime(self, time: ghidra.trace.model.time.schedule.TraceSchedule) -> None:
        ...

    def isEditsEnabled(self) -> bool:
        ...

    def readConfigState(self, saveState: ghidra.framework.options.SaveState) -> None:
        ...

    def reevaluate(self) -> None:
        ...

    def traceClosed(self, trace: ghidra.trace.model.Trace) -> None:
        ...

    def waitEvaluate(self, timeoutMs: typing.Union[jpype.JInt, int]) -> None:
        ...

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState) -> None:
        ...

    @property
    def editsEnabled(self) -> jpype.JBoolean:
        ...


class DebuggerWatchesPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


class SavedSettings(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, settings: ghidra.docking.settings.Settings) -> None:
        ...

    def getState(self) -> ghidra.framework.options.SaveState:
        ...

    def read(self, definitions: jpype.JArray[ghidra.docking.settings.SettingsDefinition], defaultSettings: ghidra.docking.settings.Settings) -> None:
        ...

    def setState(self, state: ghidra.framework.options.SaveState) -> None:
        ...

    def write(self, definitions: jpype.JArray[ghidra.docking.settings.SettingsDefinition], defaultSettings: ghidra.docking.settings.Settings) -> None:
        ...

    @property
    def state(self) -> ghidra.framework.options.SaveState:
        ...

    @state.setter
    def state(self, value: ghidra.framework.options.SaveState):
        ...


class DebuggerWatchActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerWatchesProvider, sel: collections.abc.Sequence, sourceComponent: java.awt.Component) -> None:
        ...

    def getWatchRow(self) -> ghidra.debug.api.watch.WatchRow:
        ...

    def getWatchRows(self) -> java.util.Set[ghidra.debug.api.watch.WatchRow]:
        ...

    @property
    def watchRow(self) -> ghidra.debug.api.watch.WatchRow:
        ...

    @property
    def watchRows(self) -> java.util.Set[ghidra.debug.api.watch.WatchRow]:
        ...



__all__ = ["DefaultWatchRow", "DebuggerWatchesProvider", "DebuggerWatchesPlugin", "SavedSettings", "DebuggerWatchActionContext"]
