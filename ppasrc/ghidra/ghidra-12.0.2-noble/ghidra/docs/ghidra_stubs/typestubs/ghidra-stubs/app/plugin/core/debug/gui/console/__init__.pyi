from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.actions
import ghidra.app.plugin.core.debug.utils
import ghidra.app.services
import ghidra.debug.api.progress
import ghidra.framework.plugintool
import ghidra.util.table
import ghidra.util.table.column
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore
import org.apache.logging.log4j.core.appender # type: ignore


T = typing.TypeVar("T")


class ConsoleActionsCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor, java.awt.event.ActionListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class HtmlOrProgressCellRenderer(java.lang.Enum[HtmlOrProgressCellRenderer], ghidra.util.table.column.GColumnRenderer[java.lang.Object]):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[HtmlOrProgressCellRenderer]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> HtmlOrProgressCellRenderer:
        ...

    @staticmethod
    def values() -> jpype.JArray[HtmlOrProgressCellRenderer]:
        ...


class DebuggerConsoleProvider(ghidra.framework.plugintool.ComponentProviderAdapter, docking.actions.PopupActionProvider):

    @typing.type_check_only
    class LogTableColumns(java.lang.Enum[DebuggerConsoleProvider.LogTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerConsoleProvider.LogTableColumns, DebuggerConsoleProvider.LogRow[typing.Any]]):

        class_: typing.ClassVar[java.lang.Class]
        ICON: typing.Final[DebuggerConsoleProvider.LogTableColumns]
        MESSAGE: typing.Final[DebuggerConsoleProvider.LogTableColumns]
        ACTIONS: typing.Final[DebuggerConsoleProvider.LogTableColumns]
        TIME: typing.Final[DebuggerConsoleProvider.LogTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerConsoleProvider.LogTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerConsoleProvider.LogTableColumns]:
            ...


    class BoundAction(java.lang.Object):
        """
        An action bound to a context
         
         
        
        This class is public for access by test cases only.
        """

        class_: typing.ClassVar[java.lang.Class]
        action: typing.Final[docking.action.DockingActionIf]
        context: typing.Final[docking.ActionContext]

        def __init__(self, action: docking.action.DockingActionIf, context: docking.ActionContext):
            ...

        def getIcon(self) -> javax.swing.Icon:
            ...

        def getName(self) -> str:
            ...

        def getTooltipText(self) -> str:
            ...

        def isEnabled(self) -> bool:
            ...

        def perform(self):
            ...

        @property
        def tooltipText(self) -> java.lang.String:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def icon(self) -> javax.swing.Icon:
            ...

        @property
        def enabled(self) -> jpype.JBoolean:
            ...


    class ActionList(java.util.ArrayList[DebuggerConsoleProvider.BoundAction]):
        """
        A list of bound actions
         
         
        
        This class is public for access by test cases only.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class LogRow(java.lang.Object, typing.Generic[T]):
        """
        An entry in the console's log
         
         
        
        This class is public for access by test cases only.
        """

        class_: typing.ClassVar[java.lang.Class]

        def actionContext(self) -> docking.ActionContext:
            ...

        def actions(self) -> DebuggerConsoleProvider.ActionList:
            ...

        def activated(self) -> bool:
            ...

        def date(self) -> java.util.Date:
            ...

        def icon(self) -> javax.swing.Icon:
            ...

        def message(self) -> T:
            ...


    @typing.type_check_only
    class MessageLogRow(java.lang.Record, DebuggerConsoleProvider.LogRow[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, icon: javax.swing.Icon, message: typing.Union[java.lang.String, str], date: java.util.Date, error: java.lang.Throwable, actionContext: docking.ActionContext, actions: DebuggerConsoleProvider.ActionList):
            ...

        def actionContext(self) -> docking.ActionContext:
            ...

        def actions(self) -> DebuggerConsoleProvider.ActionList:
            ...

        def date(self) -> java.util.Date:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def error(self) -> java.lang.Throwable:
            ...

        def hashCode(self) -> int:
            ...

        def icon(self) -> javax.swing.Icon:
            ...

        def message(self) -> str:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class MonitorLogRow(java.lang.Record, DebuggerConsoleProvider.LogRow[ghidra.debug.api.progress.MonitorReceiver]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, message: ghidra.debug.api.progress.MonitorReceiver, date: java.util.Date, actionContext: docking.ActionContext, actions: DebuggerConsoleProvider.ActionList):
            ...

        def actionContext(self) -> docking.ActionContext:
            ...

        def actions(self) -> DebuggerConsoleProvider.ActionList:
            ...

        def date(self) -> java.util.Date:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def message(self) -> ghidra.debug.api.progress.MonitorReceiver:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ListenerForProgress(ghidra.debug.api.progress.ProgressListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CancelAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    @typing.type_check_only
    class LogTableModel(ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel[DebuggerConsoleProvider.LogTableColumns, docking.ActionContext, DebuggerConsoleProvider.LogRow[typing.Any], DebuggerConsoleProvider.LogRow[typing.Any]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    @typing.type_check_only
    class LogTable(ghidra.util.table.GhidraTable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: DebuggerConsoleProvider.LogTableModel):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerConsolePlugin):
        ...

    def clear(self):
        ...

    def getLogRow(self, ctx: docking.ActionContext) -> DebuggerConsoleProvider.LogRow[typing.Any]:
        ...

    @property
    def logRow(self) -> DebuggerConsoleProvider.LogRow[typing.Any]:
        ...


class MonitorRowConsoleActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.debug.api.progress.MonitorReceiver):
        ...

    def getMonitor(self) -> ghidra.debug.api.progress.MonitorReceiver:
        ...

    @property
    def monitor(self) -> ghidra.debug.api.progress.MonitorReceiver:
        ...


class DebuggerConsolePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DebuggerConsoleService):

    @typing.type_check_only
    class ConsolePluginAppender(org.apache.logging.log4j.core.appender.AbstractAppender):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def clear(self):
        """
        Clear the console
        """

    def getLogRow(self, ctx: docking.ActionContext) -> DebuggerConsoleProvider.LogRow[typing.Any]:
        """
        For testing: to verify the contents of a message delivered to the console log
        
        :param docking.ActionContext ctx: the context
        :return: the log entry
        :rtype: DebuggerConsoleProvider.LogRow[typing.Any]
        """

    def getRowCount(self, ctxCls: java.lang.Class[docking.ActionContext]) -> int:
        """
        For testing: get the number of rows having a given class of action context
        
        :param java.lang.Class[docking.ActionContext] ctxCls: the context class
        :return: the number of rows
        :rtype: int
        """

    @property
    def logRow(self) -> DebuggerConsoleProvider.LogRow[typing.Any]:
        ...

    @property
    def rowCount(self) -> jpype.JLong:
        ...


class MonitorCellRenderer(javax.swing.JPanel, ghidra.util.table.column.GColumnRenderer[ghidra.debug.api.progress.MonitorReceiver]):

    @typing.type_check_only
    class CachedColor(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LogRowConsoleActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ConsoleActionsCellRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[DebuggerConsoleProvider.ActionList]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ConsoleActionsCellEditor", "HtmlOrProgressCellRenderer", "DebuggerConsoleProvider", "MonitorRowConsoleActionContext", "DebuggerConsolePlugin", "MonitorCellRenderer", "LogRowConsoleActionContext", "ConsoleActionsCellRenderer"]
