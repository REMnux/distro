from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.action.builder
import docking.menu
import docking.widgets.fieldpanel.listener
import docking.widgets.table
import ghidra.app.decompiler.component.margin
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui
import ghidra.app.plugin.core.marker
import ghidra.app.services
import ghidra.app.util.viewer.listingpanel
import ghidra.debug.api.breakpoint
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.breakpoint
import ghidra.util.table.column
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore
import javax.swing.text # type: ignore


T = typing.TypeVar("T")


class DebuggerBreakpointsPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerBreakpointMarkerPlugin(ghidra.framework.plugintool.Plugin):

    @typing.type_check_only
    class DualMarkerSet(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, service: ghidra.app.services.MarkerService, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, priority: typing.Union[jpype.JInt, int], showMarks: typing.Union[jpype.JBoolean, bool], showNavigation: typing.Union[jpype.JBoolean, bool], colorBackground: typing.Union[jpype.JBoolean, bool], color: java.awt.Color, icon: javax.swing.Icon, preferred: typing.Union[jpype.JBoolean, bool]):
            ...

        def add(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
            ...

        def clearAll(self):
            ...

        def remove(self, service: ghidra.app.services.MarkerService, program: ghidra.program.model.listing.Program):
            ...

        def setColoringBackground(self, coloringBackground: typing.Union[jpype.JBoolean, bool]):
            ...

        def setMarkerColor(self, color: java.awt.Color):
            ...


    @typing.type_check_only
    class BreakpointMarkerSets(java.lang.Object):
        """
        A variety of marker sets (one for each logical state) attached to a program or trace view
        """

        class_: typing.ClassVar[java.lang.Class]

        def clear(self):
            ...

        def dispose(self):
            ...

        def setDisabledColoringBackground(self, coloringBackground: typing.Union[jpype.JBoolean, bool]):
            ...

        def setEnabledColoringBackground(self, coloringBackground: typing.Union[jpype.JBoolean, bool]):
            ...

        def setIneffectiveDisabledColoringBackground(self, coloringBackground: typing.Union[jpype.JBoolean, bool]):
            ...

        def setIneffectiveEnabledColoringBackground(self, coloringBackground: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class UpdateMarksBreakpointRecordChangeListener(ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToggleBreakpointsMarkerClickedListener(ghidra.app.util.viewer.listingpanel.MarkerClickedListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DefaultMarginProviderSupplier(ghidra.app.plugin.core.marker.MarginProviderSupplier):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class AbstractToggleBreakpointAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Toggle Breakpoint"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "toggle_breakpoint"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    @typing.type_check_only
    class ToggleBreakpointAction(DebuggerBreakpointMarkerPlugin.AbstractToggleBreakpointAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class SetBreakpointAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSetBreakpointAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self, kinds: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]):
            ...


    @typing.type_check_only
    class EnableBreakpointAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractEnableBreakpointAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class DisableBreakpointAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractDisableBreakpointAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class ClearBreakpointAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractClearBreakpointAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerBreakpointStateTableCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor, java.awt.event.ActionListener, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterPanel: docking.widgets.table.GTableFilterPanel[T]):
        ...


class DebuggerMakeBreakpointsEffectiveActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DebuggerLogicalBreakpointsActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, selection: collections.abc.Sequence):
        ...

    def getBreakpoints(self) -> java.util.Collection[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        ...

    def getSelection(self) -> java.util.Collection[LogicalBreakpointRow]:
        ...

    @property
    def selection(self) -> java.util.Collection[LogicalBreakpointRow]:
        ...

    @property
    def breakpoints(self) -> java.util.Collection[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        ...


class DebuggerSleighSemanticInputDialog(AbstractDebuggerSleighInputDialog):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[DebuggerSleighSemanticInputDialog]


class DebuggerBreakpointsProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener, ghidra.app.services.DebuggerControlService.ControlModeChangeListener):

    @typing.type_check_only
    class LogicalBreakpointTableColumns(java.lang.Enum[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns, LogicalBreakpointRow]):

        class_: typing.ClassVar[java.lang.Class]
        STATE: typing.Final[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]
        NAME: typing.Final[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]
        ADDRESS: typing.Final[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]
        IMAGE: typing.Final[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]
        LENGTH: typing.Final[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]
        KINDS: typing.Final[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]
        LOCATIONS: typing.Final[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]
        SLEIGH: typing.Final[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerBreakpointsProvider.LogicalBreakpointTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns]:
            ...


    @typing.type_check_only
    class LogicalBreakpointTableModel(docking.widgets.table.RowWrappedEnumeratedColumnTableModel[DebuggerBreakpointsProvider.LogicalBreakpointTableColumns, ghidra.debug.api.breakpoint.LogicalBreakpoint, LogicalBreakpointRow, ghidra.debug.api.breakpoint.LogicalBreakpoint]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, provider: DebuggerBreakpointsProvider):
            ...


    @typing.type_check_only
    class BreakpointLocationTableColumns(java.lang.Enum[DebuggerBreakpointsProvider.BreakpointLocationTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerBreakpointsProvider.BreakpointLocationTableColumns, BreakpointLocationRow]):

        class_: typing.ClassVar[java.lang.Class]
        STATE: typing.Final[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]
        NAME: typing.Final[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]
        ADDRESS: typing.Final[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]
        TRACE: typing.Final[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]
        THREADS: typing.Final[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]
        COMMENT: typing.Final[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]
        EXPRESSION: typing.Final[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]
        SLEIGH: typing.Final[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerBreakpointsProvider.BreakpointLocationTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerBreakpointsProvider.BreakpointLocationTableColumns]:
            ...


    @typing.type_check_only
    class BreakpointLocationTableModel(docking.widgets.table.RowWrappedEnumeratedColumnTableModel[DebuggerBreakpointsProvider.BreakpointLocationTableColumns, ghidra.util.database.ObjectKey, BreakpointLocationRow, ghidra.trace.model.breakpoint.TraceBreakpointLocation]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, provider: DebuggerBreakpointsProvider):
            ...


    @typing.type_check_only
    class GenericSetBreakpointAction(ghidra.app.plugin.core.debug.gui.InvokeActionEntryAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, entry: ghidra.debug.api.target.Target.ActionEntry):
            ...


    @typing.type_check_only
    class StubSetBreakpointAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class SetBreakpointAction(docking.menu.MultiActionDockingAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class EnableSelectedBreakpointsAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractEnableSelectedBreakpointsAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class EnableAllBreakpointsAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractEnableAllBreakpointsAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class DisableSelectedBreakpointsAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractDisableSelectedBreakpointsAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class DisableAllBreakpointsAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractDisableAllBreakpointsAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class ClearSelectedBreakpointsAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractClearSelectedBreakpointsAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. BreakpointsClear"

        def __init__(self):
            ...


    @typing.type_check_only
    class ClearAllBreakpointsAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractClearAllBreakpointsAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. BreakpointsClear"

        def __init__(self):
            ...


    @typing.type_check_only
    class CommonMakeBreakpointsEffectiveAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractMakeBreakpointsEffectiveAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg6. Breakpoints"

        def __init__(self):
            ...


    @typing.type_check_only
    class MakeBreakpointsEffectiveAction(DebuggerBreakpointsProvider.CommonMakeBreakpointsEffectiveAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class MakeBreakpointsEffectiveResolutionAction(DebuggerBreakpointsProvider.CommonMakeBreakpointsEffectiveAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SetEmulatedBreakpointConditionAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Set Condition (Emulator)"
        DESCRIPTION: typing.Final = "Set a Sleigh condition for this emulated breakpoint"
        GROUP: typing.Final = "Dbg6. Breakpoints"
        HELP_ANCHOR: typing.Final = "set_condition"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class SetEmulatedBreakpointInjectionAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Set Injection (Emulator)"
        DESCRIPTION: typing.Final = "Set a Sleigh injection for this emulated breakpoint"
        GROUP: typing.Final = "Dbg6. Breakpoints"
        HELP_ANCHOR: typing.Final = "set_injection"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class LocationsBySelectedBreakpointsTableFilter(docking.widgets.table.TableFilter[BreakpointLocationRow]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ForBreakpointLocationsTraceListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, trace: ghidra.trace.model.Trace):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerBreakpointsPlugin):
        ...

    def isFilterByCurrentTrace(self) -> bool:
        ...

    def isFilterLocationsByBreakpoints(self) -> bool:
        ...

    def setSelectedBreakpoints(self, sel: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]):
        ...

    def setSelectedLocations(self, sel: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]):
        ...

    def setTrace(self, trace: ghidra.trace.model.Trace):
        ...

    @property
    def filterByCurrentTrace(self) -> jpype.JBoolean:
        ...

    @property
    def filterLocationsByBreakpoints(self) -> jpype.JBoolean:
        ...


class AbstractDebuggerSleighInputDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class SleighTextPane(javax.swing.JTextPane):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, document: javax.swing.text.StyledDocument):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getInput(self) -> str:
        ...

    def prompt(self, tool: ghidra.framework.plugintool.PluginTool, defaultInput: typing.Union[java.lang.String, str]) -> str:
        ...

    @property
    def input(self) -> java.lang.String:
        ...


class DebuggerSleighExpressionInputDialog(AbstractDebuggerSleighInputDialog):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[DebuggerSleighExpressionInputDialog]


class DebuggerPlaceBreakpointDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def prompt(self, tool: ghidra.framework.plugintool.PluginTool, service: ghidra.app.services.DebuggerLogicalBreakpointService, title: typing.Union[java.lang.String, str], loc: ghidra.program.util.ProgramLocation, length: typing.Union[jpype.JLong, int], kinds: collections.abc.Sequence, name: typing.Union[java.lang.String, str]):
        ...


class DebuggerBreakpointStateTableCellRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ghidra.debug.api.breakpoint.LogicalBreakpoint.State]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BreakpointsDecompilerMarginProvider(javax.swing.JPanel, ghidra.app.decompiler.component.margin.DecompilerMarginProvider, docking.widgets.fieldpanel.listener.LayoutModelListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerBreakpointMarkerPlugin):
        ...


class DebuggerBreakpointLocationsActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, selection: collections.abc.Sequence):
        ...

    def getLocations(self) -> java.util.Collection[ghidra.trace.model.breakpoint.TraceBreakpointLocation]:
        ...

    def getSelection(self) -> java.util.Collection[BreakpointLocationRow]:
        ...

    @property
    def selection(self) -> java.util.Collection[BreakpointLocationRow]:
        ...

    @property
    def locations(self) -> java.util.Collection[ghidra.trace.model.breakpoint.TraceBreakpointLocation]:
        ...


class LogicalBreakpointRow(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerBreakpointsProvider, lb: ghidra.debug.api.breakpoint.LogicalBreakpoint):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getDomainObject(self) -> ghidra.framework.model.DomainObject:
        ...

    def getImageName(self) -> str:
        ...

    def getKinds(self) -> str:
        ...

    def getLength(self) -> int:
        ...

    def getLocationCount(self) -> int:
        """
        Count the number of locations, enabled and disabled, among live traces
        
        :return: the count
        :rtype: int
        """

    def getLogicalBreakpoint(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint:
        ...

    def getMode(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.Mode:
        ...

    def getName(self) -> str:
        ...

    def getState(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        ...

    def hasSleigh(self) -> bool:
        ...

    def isMapped(self) -> bool:
        """
        Check if it has mapped locations, regardless of whether those locations are present
        
        :return: true if mapped (or mappable), false if not.
        :rtype: bool
        """

    def isNamable(self) -> bool:
        ...

    def setEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setState(self, state: ghidra.debug.api.breakpoint.LogicalBreakpoint.State):
        ...

    @property
    def imageName(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def locationCount(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def kinds(self) -> java.lang.String:
        ...

    @property
    def domainObject(self) -> ghidra.framework.model.DomainObject:
        ...

    @property
    def mode(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.Mode:
        ...

    @property
    def namable(self) -> jpype.JBoolean:
        ...

    @property
    def logicalBreakpoint(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint:
        ...

    @property
    def mapped(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def state(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        ...

    @state.setter
    def state(self, value: ghidra.debug.api.breakpoint.LogicalBreakpoint.State):
        ...


class BreakpointLocationRow(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerBreakpointsProvider, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getComment(self) -> str:
        ...

    def getExpression(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getState(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        ...

    def getThreads(self) -> str:
        ...

    def getTraceBreakpoint(self) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    def getTraceName(self) -> str:
        ...

    def hasSleigh(self) -> bool:
        ...

    def isEnabled(self) -> bool:
        ...

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        ...

    def setEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setState(self, state: ghidra.debug.api.breakpoint.LogicalBreakpoint.State):
        ...

    @property
    def expression(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def traceBreakpoint(self) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    @property
    def traceName(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def threads(self) -> java.lang.String:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def state(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        ...

    @state.setter
    def state(self, value: ghidra.debug.api.breakpoint.LogicalBreakpoint.State):
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...



__all__ = ["DebuggerBreakpointsPlugin", "DebuggerBreakpointMarkerPlugin", "DebuggerBreakpointStateTableCellEditor", "DebuggerMakeBreakpointsEffectiveActionContext", "DebuggerLogicalBreakpointsActionContext", "DebuggerSleighSemanticInputDialog", "DebuggerBreakpointsProvider", "AbstractDebuggerSleighInputDialog", "DebuggerSleighExpressionInputDialog", "DebuggerPlaceBreakpointDialog", "DebuggerBreakpointStateTableCellRenderer", "BreakpointsDecompilerMarginProvider", "DebuggerBreakpointLocationsActionContext", "LogicalBreakpointRow", "BreakpointLocationRow"]
