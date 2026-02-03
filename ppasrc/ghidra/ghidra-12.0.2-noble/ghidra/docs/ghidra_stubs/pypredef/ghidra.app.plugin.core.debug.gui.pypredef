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
import docking.widgets.table
import docking.widgets.tree
import generic.theme
import ghidra.app.plugin.core.debug.gui.action
import ghidra.app.services
import ghidra.debug.api
import ghidra.debug.api.target
import ghidra.debug.api.tracemgr
import ghidra.features.base.memsearch.bytesource
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.memory
import ghidra.trace.model.modules
import ghidra.trace.model.program
import ghidra.util
import ghidra.util.table
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


P = typing.TypeVar("P")
R = typing.TypeVar("R")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class DebuggerSearchRegionFactory(java.lang.Enum[DebuggerSearchRegionFactory]):

    @typing.type_check_only
    class DebuggerSearchRegion(java.lang.Record, ghidra.features.base.memsearch.bytesource.SearchRegion):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def factory(self) -> DebuggerSearchRegionFactory:
            ...

        def hashCode(self) -> int:
            ...

        def spaces(self) -> ghidra.program.model.address.AddressSpace:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    FULL_SPACE: typing.Final[DebuggerSearchRegionFactory]
    VALID: typing.Final[DebuggerSearchRegionFactory]
    WRITABLE: typing.Final[DebuggerSearchRegionFactory]
    ALL: typing.Final[java.util.List[DebuggerSearchRegionFactory]]

    def createRegion(self, space: ghidra.program.model.address.AddressSpace) -> ghidra.features.base.memsearch.bytesource.SearchRegion:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerSearchRegionFactory:
        ...

    @staticmethod
    def values() -> jpype.JArray[DebuggerSearchRegionFactory]:
        ...


class DebuggerLocationLabel(javax.swing.JLabel):

    @typing.type_check_only
    class ForLocationLabelTraceListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getActionContext(self, provider: docking.ComponentProvider, event: java.awt.event.MouseEvent) -> docking.ActionContext:
        ...

    def goToAddress(self, address: ghidra.program.model.address.Address):
        ...

    def goToCoordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def updateLabel(self):
        ...


class AbstractDebuggerParameterDialog(docking.DialogComponentProvider, java.beans.PropertyChangeListener, typing.Generic[P]):

    class BigIntEditor(java.beans.PropertyEditorSupport):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def setValueNoAsText(self, value: java.lang.Object):
            ...


    class FileChooserPanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, propertyChange: java.lang.Runnable):
            ...

        def setValue(self, file: jpype.protocol.SupportsPath):
            ...


    class PathEditor(java.beans.PropertyEditorSupport):
        """
        Compared to :obj:`FileChooserEditor`, this does not require the user to enter a full path.
        Nor will it resolve file names against the working directory. It's just a text box with a
        file browser assist.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class PathIsDirEditor(AbstractDebuggerParameterDialog.PathEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class PathIsFileEditor(AbstractDebuggerParameterDialog.PathEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ChoicesPropertyEditor(java.beans.PropertyEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, choices: collections.abc.Sequence):
            ...


    @typing.type_check_only
    class NameTypePair(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def encodeString(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromString(name: typing.Union[java.lang.String, str]) -> AbstractDebuggerParameterDialog.NameTypePair:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> java.lang.Class[typing.Any]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], buttonText: typing.Union[java.lang.String, str], buttonIcon: javax.swing.Icon):
        ...

    def forgetMemorizedArguments(self):
        ...

    def getArguments(self) -> java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]:
        ...

    def promptArguments(self, parameterMap: collections.abc.Mapping, initial: collections.abc.Mapping, defaults: collections.abc.Mapping) -> java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]:
        """
        Prompt the user for the given arguments, all at once
         
         
        
        This displays a single dialog with each option listed. The parameter map contains the
        description of each parameter to be displayed. The ``initial`` values are the values to
        pre-populate the options with, e.g., because they are saved from a previous session, or
        because they are the suggested values. If the user clicks the "Reset" button, the values are
        revered to the defaults given in each parameter's description, unless that value is
        overridden in ``defaults``. This may be appropriate if a value is suggested for a
        (perhaps required) option that otherwise has no default.
        
        :param collections.abc.Mapping parameterMap: the map of parameters, keyed by :meth:`parameterName(Object) <.parameterName>`. This map
                    may be ordered to control the order of options displayed.
        :param collections.abc.Mapping initial: the initial values of the options. If a key is not provided, the initial value
                    is its default value. Extraneous keys are ignored.
        :param collections.abc.Mapping defaults: the default values to use upon reset. If a key is not provided, the default
                    is taken from the parameter description. Extraneous keys are ignored.
        :return: the arguments provided by the user
        :rtype: java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]
        """

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def setDescription(self, htmlDescription: typing.Union[java.lang.String, str]):
        ...

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def arguments(self) -> java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]:
        ...


class DebuggerByteSource(ghidra.features.base.memsearch.bytesource.AddressableByteSource):
    """
    A byte source for searching the memory of a possibly-live target in the debugger.
     
     
    
    Because we'd like the search to preserve its state over the lifetime of the target, and the
    target "changes" by navigating snapshots, we need to allow the view to move without requiring a
    new byte source to be constructed. We *cannot*, however, just blindly follow the
    :obj:`Navigatable` wherever it goes. This is roughly the equivalent of a :obj:`Program`, but
    with knowledge of the target to cause a refresh of actual target memory when necessary.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, view: ghidra.trace.model.program.TraceProgramView, target: ghidra.debug.api.target.Target, readsMem: ghidra.app.plugin.core.debug.gui.action.DebuggerReadsMemoryTrait):
        ...


class DebuggerProvider(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addLocalAction(self, action: docking.action.DockingActionIf):
        ...

    def getActionContext(self, event: java.awt.event.MouseEvent) -> docking.ActionContext:
        ...

    @property
    def actionContext(self) -> docking.ActionContext:
        ...


class DebuggerSnapActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]):
        ...

    def getSnap(self) -> int:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class MultiProviderSaveBehavior(java.lang.Object, typing.Generic[P]):

    class SaveableProvider(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def readConfigState(self, saveState: ghidra.framework.options.SaveState):
            ...

        def readDataState(self, saveState: ghidra.framework.options.SaveState):
            ...

        def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
            ...

        def writeDataState(self, saveState: ghidra.framework.options.SaveState):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def readDataState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def writeDataState(self, saveState: ghidra.framework.options.SaveState):
        ...


class InvokeActionEntryAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, entry: ghidra.debug.api.target.Target.ActionEntry):
        ...


class DebuggerResources(java.lang.Object):

    class AbstractFlushCachesAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Flush Caches"
        HELP_ANCHOR: typing.Final = "flush_caches"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class SaveTraceAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME_PREFIX: typing.Final = "Save "
        DESCRIPTION: typing.Final = "Save the selected trace"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg7. Trace"
        HELP_ANCHOR: typing.Final = "save_trace"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class AbstractConnectAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Connect"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "connect"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def styleButton(button: javax.swing.JButton):
            ...


    class AbstractConsoleAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Console"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "console"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractLaunchAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Launch"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "launch"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...

        @staticmethod
        def styleButton(button: javax.swing.JButton):
            ...


    class DebugProgramAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Debug Program"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "debug_program"


    class AbstractQuickLaunchAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Quick Launch"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "quick_launch"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractAttachAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Attach"
        ICON: typing.Final[javax.swing.Icon]
        DESCRIPTION: typing.Final = "Attach to an existing target accessible to the agent"
        HELP_ANCHOR: typing.Final = "attach"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...

        @staticmethod
        def styleButton(button: javax.swing.JButton):
            ...


    class AbstractResumeAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Resume"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "resume"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractStepIntoAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Step Into"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "step_into"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractStepOverAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Step Over"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "step_over"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractStepFinishAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Step Finish"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "step_finish"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractStepLastAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Step Last"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "step_last"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractInterruptAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Interrupt"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "interrupt"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractKillAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Kill"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "kill"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractDetachAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Detach"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "detach"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractDisconnectAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Disconnect"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "disconnect"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class DisconnectAllAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Disconnect All"
        DESCRIPTION: typing.Final = "Close and Debugger Model Connections"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "disconnect_all"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin, helpOwner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class PinInterpreterAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Pin Interpreter"
        DESCRIPTION: typing.Final = "Prevent this Interpreter from closing automatically"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "pin"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    class InterpreterInterruptAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Interpreter Interrupt"
        DESCRIPTION: typing.Final = "Send an interrupt through this Interpreter"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "interrupt"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class ChoosePlatformAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Choose Platform"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        DESCRIPTION: typing.Final = "Manually select the target platform"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "choose_platform"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class AbstractRecordAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Record"
        ICON: typing.Final[javax.swing.Icon]

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractRefreshSelectedMemoryAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Read Selected Memory"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "read_memory"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class TrackLocationAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Track Location"
        DESCRIPTION: typing.Final = "Follow a location in this view"
        HELP_ANCHOR: typing.Final = "track_location"
        NAME_PC: typing.Final = "Track Program Counter"
        NAME_PC_BY_REGISTER: typing.Final = "Track Program Counter (by Register)"
        NAME_PC_BY_STACK: typing.Final = "Track Program Counter (by Stack)"
        NAME_SP: typing.Final = "Track Stack Pointer"
        NAME_NONE: typing.Final = "Do Not Track"
        NAME_PREFIX_WATCH: typing.Final = "Track address of watch: "
        ICON_PC: typing.Final[javax.swing.Icon]
        ICON_PC_BY_REGISTER: typing.Final[javax.swing.Icon]
        ICON_PC_BY_STACK: typing.Final[javax.swing.Icon]
        ICON_SP: typing.Final[javax.swing.Icon]
        ICON_NONE: typing.Final[javax.swing.Icon]

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.MultiStateActionBuilder[T]:
            ...


    class GoToAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Go To"
        DESCRIPTION: typing.Final = "Seek this listing to an arbitrary expression"
        HELP_ANCHOR: typing.Final = "go_to"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class FollowsCurrentThreadAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Follows Selected Thread"
        DESCRIPTION: typing.Final = "Register tracking follows selected thread (and contents follow selected trace)"
        HELP_ANCHOR: typing.Final = "follows_thread"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    class AutoReadMemoryAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Auto-Read Target Memory"
        DESCRIPTION: typing.Final = "Automatically read and record visible memory from the live target"
        HELP_ANCHOR: typing.Final = "auto_memory"
        NAME_VIS_RO_ONCE: typing.Final = "Read Visible Memory, RO Once"
        NAME_VISIBLE: typing.Final = "Read Visible Memory"
        NAME_NONE: typing.Final = "Do Not Read Memory"
        ICON_VIS_RO_ONCE: typing.Final[javax.swing.Icon]
        ICON_VISIBLE: typing.Final[javax.swing.Icon]
        ICON_NONE: typing.Final[javax.swing.Icon]

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.MultiStateActionBuilder[T]:
            ...


    class AbstractRefreshAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Refresh"
        ICON: typing.Final[javax.swing.Icon]

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class SelectRegistersAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Select Registers"
        DESCRIPTION: typing.Final = "Select registers to display/modify"
        GROUP: typing.Final = "aa"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "select_registers"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class CloneWindowAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Clone Window"
        DESCRIPTION: typing.Final = "Create a disconnected copy of this window"
        GROUP: typing.Final = "zzzz"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "clone_window"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class EnableEditsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Enable Edits"
        DESCRIPTION: typing.Final = "Enable editing of recorded or live values"
        GROUP: typing.Final = "yyyy2"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "enable_edits"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    class DisassembleAsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Disassemble as"
        DESCRIPTION: typing.Final = "Disassemble using an alternative language"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "disassemble_as"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class AddAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Add"
        GROUP: typing.Final = "yyyy"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "add"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class RemoveAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Remove"
        GROUP: typing.Final = "yyyy"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "remove"

        @staticmethod
        @typing.overload
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        @typing.overload
        def builder(ownerName: typing.Union[java.lang.String, str]) -> docking.action.builder.ActionBuilder:
            ...


    class ClearAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Clear"
        GROUP: typing.Final = "yyyy"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "clear"

        @staticmethod
        @typing.overload
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        @typing.overload
        def builder(ownerName: typing.Union[java.lang.String, str]) -> docking.action.builder.ActionBuilder:
            ...


    class FilterAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Filter"
        GROUP: typing.Final = "yyyy"
        ICON: typing.Final[javax.swing.Icon]

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    class SelectNoneAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Select None"
        GROUP: typing.Final = "Select"
        HELP_ANCHOR: typing.Final = "select_none"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class SelectRowsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Select Rows"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "select_rows"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class ExportTraceViewAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Export Trace View"
        DESCRIPTION: typing.Final = "Export the current view as if a Ghidra program"
        GROUP: typing.Final = "Dbg8. Maintenance"
        HELP_ANCHOR: typing.Final = "export_view"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class CopyIntoProgramAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME_PAT: typing.Final = "Copy Into %s Program"
        DESC_PAT: typing.Final = "Copy the current selection into %s program"
        GROUP: typing.Final = "Dbg8. Maintenance"


    class CopyIntoCurrentProgramAction(DebuggerResources.CopyIntoProgramAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final[java.lang.String]
        DESCRIPTION: typing.Final[java.lang.String]
        HELP_ANCHOR: typing.Final = "copy_into_current"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class CopyIntoNewProgramAction(DebuggerResources.CopyIntoProgramAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final[java.lang.String]
        DESCRIPTION: typing.Final[java.lang.String]
        HELP_ANCHOR: typing.Final = "copy_into_new"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class AbstractSetBreakpointAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Set Breakpoint"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "set_breakpoint"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...

        @staticmethod
        def styleButton(button: javax.swing.JButton):
            ...


    class AbstractEnableBreakpointAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Enable Breakpoint"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "enable_breakpoint"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractEnableSelectedBreakpointsAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Enable"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "enable_breakpoints"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractEnableAllBreakpointsAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Enable All Breakpoints"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "enable_all_breakpoints"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractDisableBreakpointAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Disable Breakpoint"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "disable_breakpoint"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractDisableSelectedBreakpointsAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Disable"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "disable_breakpoints"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractDisableAllBreakpointsAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Disable All Breakpoints"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "disable_all_breakpoints"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractClearBreakpointAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Clear Breakpoint"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "clear_breakpoint"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractClearSelectedBreakpointsAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Clear"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "clear_breakpoints"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractClearAllBreakpointsAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Clear All Breakpoints"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "clear_all_breakpoints"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractMakeBreakpointsEffectiveAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Make Breakpoints Effective"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "make_breakpoints_effective"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractToggleAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Toggle"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "toggle_option"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...

        @staticmethod
        def help(owner: ghidra.framework.plugintool.Plugin) -> ghidra.util.HelpLocation:
            ...


    class AbstractSelectAddressesAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Select Addresses"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "select_addresses"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractImportFromFileSystemAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Import From File System"
        HELP_ANCHOR: typing.Final = "import_from_fs"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class AbstractNewListingAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "New Dynamic Listing"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "new_listing"

        def __init__(self, owner: ghidra.framework.plugintool.Plugin):
            ...


    class NewMemoryAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "New Memory View"
        DESCRIPTION: typing.Final = "Open a new memory bytes view"
        GROUP: typing.Final = "Dbg3a. Transient Views"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "new_memory"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class StepSnapBackwardAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Step Trace Snap Backward"
        DESCRIPTION: typing.Final = "Navigate the recording backward one snap"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg4. Control"
        ORDER: typing.Final = "1"
        HELP_ANCHOR: typing.Final = "step_trace_snap_backward"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class StepSnapForwardAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Step Trace Snap Forward"
        DESCRIPTION: typing.Final = "Navigate the recording forward one snap"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg4. Control"
        ORDER: typing.Final = "5"
        HELP_ANCHOR: typing.Final = "step_trace_snap_forward"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class EmulateTickBackwardAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Emulate Trace Tick Backward"
        DESCRIPTION: typing.Final = "Emulate the recording backward one tick"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg4. Control"
        ORDER: typing.Final = "2"
        HELP_ANCHOR: typing.Final = "emu_trace_tick_backward"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class EmulateTickForwardAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Emulate Trace Tick Forward"
        DESCRIPTION: typing.Final = "Emulate the recording forward one instruction"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg4. Control"
        ORDER: typing.Final = "3"
        HELP_ANCHOR: typing.Final = "emu_trace_tick_forward"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class EmulateSkipTickForwardAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Emulate Trace Skip Tick Forward"
        DESCRIPTION: typing.Final = "Emulate the recording forward by skipping one instruction"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg4. Control"
        ORDER: typing.Final = "4"
        HELP_ANCHOR: typing.Final = "emu_trace_skip_tick_forward"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class EmulatePcodeBackwardAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Emulate Trace p-code Backward"
        DESCRIPTION: typing.Final = "Navigate the recording backward one p-code tick"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg4. Control"
        ORDER: typing.Final = "2"
        HELP_ANCHOR: typing.Final = "emu_trace_pcode_backward"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class EmulatePcodeForwardAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Emulate Trace p-code Forward"
        DESCRIPTION: typing.Final = "Emulate the recording forward one p-code tick"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg4. Control"
        ORDER: typing.Final = "3"
        HELP_ANCHOR: typing.Final = "emu_trace_pcode_forward"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class EmulateSkipPcodeForwardAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Emulate Trace Skip P-code Forward"
        DESCRIPTION: typing.Final = "Emulate the recording forward by skipping one p-code op"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg4. Control"
        ORDER: typing.Final = "4"
        HELP_ANCHOR: typing.Final = "emu_trace_skip_pcode_forward"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class RenameSnapshotAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Rename Current Snapshot"
        DESCRIPTION: typing.Final = "Modify the description of the snapshot (event) in the current view"
        GROUP: typing.Final = "Dbg7. Trace"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "rename_snapshot"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class SaveByDefaultAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Save Traces By Default"
        DESCRIPTION: typing.Final = "Automatically save traces to the project"
        GROUP: typing.Final = "Dbg7.a. Trace Toggles"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "save_by_default"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    class CloseOnTerminateAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Close Traces Upon Termination"
        DESCRIPTION: typing.Final = "Close any live trace whose recording terminates"
        GROUP: typing.Final = "Dbg7.a. Trace Toggles"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "auto_close_terminated"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    class OpenTraceAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Open Trace"
        DESCRIPTION: typing.Final = "Open a trace from the project"
        GROUP: typing.Final = "Dbg7. Trace"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "open_trace"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class CloseTraceAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME_PREFIX: typing.Final = "Close "
        DESCRIPTION: typing.Final = "Close the current or selected trace"
        GROUP: typing.Final = "Dbg7.b. Trace Close"
        SUB_GROUP: typing.Final = "a"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "close_trace"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        def builderCommon(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        def builderPopup(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class CloseAllTracesAction(DebuggerResources.CloseTraceAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Close All Traces"
        DESCRIPTION: typing.Final = "Close all traces"
        HELP_ANCHOR: typing.Final = "close_all_traces"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        def builderCommon(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        def builderPopup(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class CloseOtherTracesAction(DebuggerResources.CloseTraceAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Close Other Traces"
        DESCRIPTION: typing.Final = "Close all traces except the current one"
        HELP_ANCHOR: typing.Final = "close_other_traces"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        def builderCommon(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        def builderPopup(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class CloseDeadTracesAction(DebuggerResources.CloseTraceAction):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Close Dead Traces"
        DESCRIPTION: typing.Final = "Close all traces not being recorded"
        HELP_ANCHOR: typing.Final = "close_dead_traces"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        def builderCommon(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...

        @staticmethod
        def builderPopup(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class ApplyDataTypeAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Apply Data to Listing "
        DESCRIPTION: typing.Final = "Apply the selected data type at the address of this value in the listing"
        GROUP: typing.Final = "Dbg1. General"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "apply_data_type"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class SelectWatchRangeAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Select Range"
        DESCRIPTION: typing.Final = "For memory watches, select the range comprising the value"
        GROUP: typing.Final = "Dbg1. General"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "select_addresses"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class SelectWatchReadsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Select Reads"
        DESCRIPTION: typing.Final = "Select every memory range read evaluating this watch"
        GROUP: typing.Final = "Dbg1. General"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "select_reads"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class WatchAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Watch"
        DESCRIPTION: typing.Final = "Watch the selected item"
        GROUP: typing.Final = "DbgA. Watches"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "watch"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class HideScratchSnapshotsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Hide Scratch"
        DESCRIPTION: typing.Final = "Hide negative snaps, typically used as emulation scratch space"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "hide_scratch"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    class CompareTimesAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Compare"
        DESCRIPTION: typing.Final = "Compare this point in time to another"
        GROUP: typing.Final = "zzz"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "compare"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    class PrevDifferenceAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Previous Difference"
        DESCRIPTION: typing.Final = "Go to the previous highlighted difference"
        GROUP: typing.Final = "DiffNavigate"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "prev_diff"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class NextDifferenceAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Next Difference"
        DESCRIPTION: typing.Final = "Go to the next highlighted difference"
        GROUP: typing.Final = "DiffNavigate"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "next_diff"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class AbstractDebuggerConnectionsNode(docking.widgets.tree.GTreeNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class AbstractDebuggerModelNode(docking.widgets.tree.GTreeNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ToToggleSelectionListener(ghidra.app.services.DebuggerTraceManagerService.BooleanChangeAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, action: docking.action.ToggleDockingAction):
            ...


    class_: typing.ClassVar[java.lang.Class]
    OPTIONS_CATEGORY_DEBUGGER: typing.Final = "Debugger"
    OPTIONS_CATEGORY_WORKFLOW: typing.Final = "Workflow"
    ICON_DEBUGGER: typing.Final[javax.swing.Icon]
    ICON_CONNECTION: typing.Final[javax.swing.Icon]
    ICON_CONNECT_ACCEPT: typing.Final[javax.swing.Icon]
    ICON_CONNECT_OUTBOUND: typing.Final[javax.swing.Icon]
    ICON_DISCONNECT: typing.Final[javax.swing.Icon]
    ICON_PROCESS: typing.Final[javax.swing.Icon]
    ICON_TRACE: typing.Final[javax.swing.Icon]
    ICON_THREAD: typing.Final[javax.swing.Icon]
    ICON_PROGRAM: typing.Final[javax.swing.Icon]
    ICON_PROCESSOR: typing.Final[javax.swing.Icon]
    ICON_LAUNCH: typing.Final[javax.swing.Icon]
    ICON_ATTACH: typing.Final[javax.swing.Icon]
    ICON_RESUME: typing.Final[javax.swing.Icon]
    ICON_INTERRUPT: typing.Final[javax.swing.Icon]
    ICON_KILL: typing.Final[javax.swing.Icon]
    ICON_DETACH: typing.Final[javax.swing.Icon]
    ICON_RECORD: typing.Final[javax.swing.Icon]
    ICON_STEP_INTO: typing.Final[javax.swing.Icon]
    ICON_STEP_OVER: typing.Final[javax.swing.Icon]
    ICON_SKIP_OVER: typing.Final[javax.swing.Icon]
    ICON_STEP_FINISH: typing.Final[javax.swing.Icon]
    ICON_STEP_BACK: typing.Final[javax.swing.Icon]
    ICON_STEP_LAST: typing.Final[javax.swing.Icon]
    ICON_SNAP_FORWARD: typing.Final[javax.swing.Icon]
    ICON_SNAP_BACKWARD: typing.Final[javax.swing.Icon]
    ICON_SEEK_PRESENT: typing.Final[javax.swing.Icon]
    ICON_SET_BREAKPOINT: typing.Final[javax.swing.Icon]
    ICON_CLEAR_BREAKPOINT: typing.Final[javax.swing.Icon]
    ICON_ENABLE_BREAKPOINT: typing.Final[javax.swing.Icon]
    ICON_ENABLE_ALL_BREAKPOINTS: typing.Final[javax.swing.Icon]
    ICON_DISABLE_BREAKPOINT: typing.Final[javax.swing.Icon]
    ICON_DISABLE_ALL_BREAKPOINTS: typing.Final[javax.swing.Icon]
    ICON_CLEAR_ALL_BREAKPOINTS: typing.Final[javax.swing.Icon]
    ICON_MAKE_BREAKPOINTS_EFFECTIVE: typing.Final[javax.swing.Icon]
    ICON_LISTING: typing.Final[javax.swing.Icon]
    ICON_MEMORY_BYTES: typing.Final[javax.swing.Icon]
    ICON_CONSOLE: typing.Final[javax.swing.Icon]
    ICON_REGISTERS: typing.Final[javax.swing.Icon]
    ICON_STACK: typing.Final[javax.swing.Icon]
    ICON_BREAKPOINTS: typing.Final[javax.swing.Icon]
    ICON_MODULES: typing.Final[javax.swing.Icon]
    ICON_MAPPINGS: typing.Final[javax.swing.Icon]
    ICON_PCODE: typing.Final[javax.swing.Icon]
    ICON_REGIONS: typing.Final[javax.swing.Icon]
    ICON_TIME: typing.Final[javax.swing.Icon]
    ICON_OBJECTS: typing.Final[javax.swing.Icon]
    ICON_SAVE: typing.Final[javax.swing.Icon]
    ICON_CLOSE: typing.Final[javax.swing.Icon]
    ICON_ADD: typing.Final[javax.swing.Icon]
    ICON_DELETE: typing.Final[javax.swing.Icon]
    ICON_CLEAR: typing.Final[javax.swing.Icon]
    ICON_REFRESH: typing.Final[javax.swing.Icon]
    ICON_FILTER: typing.Final[javax.swing.Icon]
    ICON_SELECT_ROWS: typing.Final[javax.swing.Icon]
    ICON_AUTOREAD: typing.Final[javax.swing.Icon]
    ICON_OBJECT_POPULATED: typing.Final[javax.swing.Icon]
    ICON_OBJECT_UNPOPULATED: typing.Final[javax.swing.Icon]
    ICON_REFRESH_MEMORY: typing.Final[javax.swing.Icon]
    ICON_RENAME_SNAPSHOT: typing.Final[javax.swing.Icon]
    ICON_MAP_IDENTICALLY: typing.Final[javax.swing.Icon]
    ICON_MAP_MODULES: typing.Final[javax.swing.Icon]
    ICON_MAP_SECTIONS: typing.Final[javax.swing.Icon]
    ICON_MAP_REGIONS: typing.Final[javax.swing.Icon]
    ICON_MAP_AUTO: typing.Final[javax.swing.Icon]
    ICON_MAP_MANUALLY: typing.Final[javax.swing.Icon]
    ICON_BLOCK: typing.Final[javax.swing.Icon]
    ICON_SELECT_ADDRESSES: typing.Final[javax.swing.Icon]
    ICON_DATA_TYPES: typing.Final[javax.swing.Icon]
    ICON_CAPTURE_SYMBOLS: typing.Final[javax.swing.Icon]
    ICON_LOG_FATAL: typing.Final[javax.swing.Icon]
    ICON_LOG_ERROR: typing.Final[javax.swing.Icon]
    ICON_LOG_WARN: typing.Final[javax.swing.Icon]
    ICON_SYNC: typing.Final[javax.swing.Icon]
    ICON_VISIBILITY: typing.Final[javax.swing.Icon]
    ICON_PIN: typing.Final[javax.swing.Icon]
    ICON_IMPORT: typing.Final[javax.swing.Icon]
    ICON_BLANK: typing.Final[javax.swing.Icon]
    ICON_PACKAGE: typing.Final[javax.swing.Icon]
    ICON_EMULATE: typing.Final[javax.swing.Icon]
    ICON_CONFIG: typing.Final[javax.swing.Icon]
    ICON_TOGGLE: typing.Final[javax.swing.Icon]
    ICON_DIFF: typing.Final[javax.swing.Icon]
    ICON_DIFF_PREV: typing.Final[javax.swing.Icon]
    ICON_DIFF_NEXT: typing.Final[javax.swing.Icon]
    HELP_PACKAGE: typing.Final[ghidra.util.HelpLocation]
    HELP_ANCHOR_PLUGIN: typing.Final = "plugin"
    TITLE_PROVIDER_BREAKPOINTS: typing.Final = "Breakpoints"
    ICON_PROVIDER_BREAKPOINTS: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_BREAKPOINTS: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_CONSOLE: typing.Final = "Debug Console"
    ICON_PROVIDER_CONSOLE: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_CONSOLE: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_LISTING: typing.Final = "Dynamic"
    ICON_PROVIDER_LISTING: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_LISTING: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_MAPPINGS: typing.Final = "Static Mappings"
    ICON_PROVIDER_MAPPINGS: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_MAPPINGS: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_MEMORY_BYTES: typing.Final = "Memory"
    ICON_PROVIDER_MEMORY_BYTES: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_MEMORY_BYTES: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_MODULES: typing.Final = "Modules"
    ICON_PROVIDER_MODULES: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_MODULES: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_PCODE: typing.Final = "Pcode Stepper"
    ICON_PROVIDER_PCODE: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_PCODE: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_REGIONS: typing.Final = "Regions"
    ICON_PROVIDER_REGIONS: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_REGIONS: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_REGISTERS: typing.Final = "Registers"
    ICON_PROVIDER_REGISTERS: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_REGISTERS: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_STACK: typing.Final = "Stack"
    ICON_PROVIDER_STACK: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_STACK: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_THREADS: typing.Final = "Threads"
    ICON_PROVIDER_THREADS: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_THREADS: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_TIME: typing.Final = "Time"
    ICON_PROVIDER_TIME: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_TIME: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_MODEL: typing.Final = "Model"
    ICON_PROVIDER_MODEL: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_MODEL: typing.Final[ghidra.util.HelpLocation]
    TITLE_PROVIDER_WATCHES: typing.Final = "Watches"
    ICON_PROVIDER_WATCHES: typing.Final[javax.swing.Icon]
    HELP_PROVIDER_WATCHES: typing.Final[ghidra.util.HelpLocation]
    BOOKMARK_CATEGORY_MEMORY_READ_ERROR: typing.Final = "Debugger Memory Read Error"
    COLOR_BACKGROUND_STALE: typing.Final[generic.theme.GColor]
    COLOR_BACKGROUND_ERROR: typing.Final[java.awt.Color]
    PRIORITY_REGISTER_MARKER: typing.Final = 10
    COLOR_REGISTER_MARKERS: typing.Final[java.awt.Color]
    ICON_REGISTER_MARKER: typing.Final[javax.swing.Icon]
    ICON_EVENT_MARKER: typing.Final[javax.swing.Icon]
    COLOR_VALUE_CHANGED: typing.Final[java.awt.Color]
    COLOR_VALUE_CHANGED_SEL: typing.Final[java.awt.Color]
    ICON_UNIQUE_REF_READ: typing.Final[javax.swing.Icon]
    ICON_UNIQUE_REF_WRITE: typing.Final[javax.swing.Icon]
    ICON_UNIQUE_REF_RW: typing.Final[javax.swing.Icon]
    OPTION_NAME_COLORS_ENABLED_BREAKPOINT_COLORING_BACKGROUND: typing.Final = "Colors.Enabled Breakpoint Markers Have Background"
    DEFAULT_COLOR_ENABLED_BREAKPOINT_COLORING_BACKGROUND: typing.Final = True
    OPTION_NAME_COLORS_DISABLED_BREAKPOINT_COLORING_BACKGROUND: typing.Final = "Colors.Disabled Breakpoint Markers Have Background"
    DEFAULT_COLOR_DISABLED_BREAKPOINT_COLORING_BACKGROUND: typing.Final = False
    OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_COLORING_BACKGROUND: typing.Final = "Colors.Ineffective Enabled Breakpoint Markers Have Background"
    DEFAULT_COLOR_INEFF_EN_BREAKPOINT_COLORING_BACKGROUND: typing.Final = True
    OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_COLORING_BACKGROUND: typing.Final = "Colors.Ineffective Disabled Breakpoint Markers Have Background"
    DEFAULT_COLOR_INEFF_DIS_BREAKPOINT_COLORING_BACKGROUND: typing.Final = False
    OPTION_NAME_LOG_BUFFER_LIMIT: typing.Final = "Log Buffer Size"
    DEFAULT_LOG_BUFFER_LIMIT: typing.Final = 20
    GROUP_GENERAL: typing.Final = "Dbg1. General"
    GROUP_CONNECTION: typing.Final = "Dbg2. Connection"
    GROUP_VIEWS: typing.Final = "Dbg3. Views"
    GROUP_TRANSIENT_VIEWS: typing.Final = "Dbg3a. Transient Views"
    GROUP_CONTROL: typing.Final = "Dbg4. Control"
    GROUP_TARGET: typing.Final = "Dbg5. Target"
    GROUP_BREAKPOINTS: typing.Final = "Dbg6. Breakpoints"
    GROUP_TRACE: typing.Final = "Dbg7. Trace"
    GROUP_TRACE_TOGGLES: typing.Final = "Dbg7.a. Trace Toggles"
    GROUP_TRACE_CLOSE: typing.Final = "Dbg7.b. Trace Close"
    GROUP_MAINTENANCE: typing.Final = "Dbg8. Maintenance"
    GROUP_MAPPING: typing.Final = "Dbg9. Map Modules/Sections"
    GROUP_WATCHES: typing.Final = "DbgA. Watches"
    GROUP_DIFF_NAV: typing.Final = "DiffNavigate"
    NAME_MAP_IDENTICALLY: typing.Final = "Map Identically"
    DESCRIPTION_MAP_IDENTICALLY: typing.Final = "Map the current trace to the current program using identical addresses"
    NAME_MAP_MANUALLY: typing.Final = "Map Manually"
    DESCRIPTION_MAP_MANUALLY: typing.Final = "Map the current trace to various programs manually"
    NAME_MAP_MODULES: typing.Final = "Map Modules"
    DESCRIPTION_MAP_MODULES: typing.Final = "Map selected modules to program images"
    NAME_PREFIX_MAP_MODULE_TO: typing.Final = "Map Module to "
    DESCRIPTION_MAP_MODULE_TO: typing.Final = "Map the selected module to the current program"
    NAME_MAP_SECTIONS: typing.Final = "Map Sections"
    DESCRIPTION_MAP_SECTIONS: typing.Final = "Map selected sections to program memory blocks"
    NAME_PREFIX_MAP_SECTION_TO: typing.Final = "Map Section to "
    DESCRIPTION_MAP_SECTION_TO: typing.Final = "Map the selected section to the current program"
    NAME_PREFIX_MAP_SECTIONS_TO: typing.Final = "Map Sections to "
    DESCRIPTION_MAP_SECTIONS_TO: typing.Final = "Map the selected module sections to the current program"
    NAME_MAP_REGIONS: typing.Final = "Map Regions"
    DESCRIPTION_MAP_REGIONS: typing.Final = "Map selected regions to program memory blocks"
    NAME_PREFIX_MAP_REGION_TO: typing.Final = "Map Region to "
    DESCRIPTION_MAP_REGION_TO: typing.Final = "Map the selected region to the current program"
    NAME_PREFIX_MAP_REGIONS_TO: typing.Final = "Map Regions to "
    DESCRIPTION_MAP_REGIONS_TO: typing.Final = "Map the selected (module) regions to the current program"
    NAME_CHOOSE_PLATFORM: typing.Final = "Choose Platform"
    DESCRIPTION_CHOOSE_PLATFORM: typing.Final = "Choose a platform to use with the current trace"
    NAME_CHOOSE_MORE_PLATFORMS: typing.Final = "Choose More Platforms"
    TITLE_CHOOSE_MORE_PLATFORMS: typing.Final = "More..."
    DESCRIPTION_CHOOSE_MORE_PLATFORMS: typing.Final = "Choose from more platforms to use with the current trace"
    NAME_CLEAR_REGISTER_TYPE: typing.Final = "Clear Register Type"
    DESCRIPTION_CLEAR_REGISTER_TYPE: typing.Final = "Clear the register\'s data type"
    NAME_REGISTER_TYPE_SETTINGS: typing.Final = "Register Type Settings"
    DESCRIPTION_REGISTER_TYPE_SETTINGS: typing.Final = "Set the register\'s data type settings"
    NAME_WATCH_TYPE_SETTINGS: typing.Final = "Watch Type Settings"
    DESCRIPTION_WATCH_TYPE_SETTINGS: typing.Final = "Set the watch\'s data type settings"

    @staticmethod
    @typing.overload
    def setSelectedRows(sel: java.util.Set[V], rowMapper: java.util.function.Function[V, R], table: docking.widgets.table.GTable, model: docking.widgets.table.RowObjectTableModel[R], filterPanel: docking.widgets.table.GTableFilterPanel[R]):
        ...

    @staticmethod
    @typing.overload
    def setSelectedRows(sel: java.util.Set[V], getter: java.util.function.Function[R, V], table: docking.widgets.table.GTable, filterPanel: docking.widgets.table.GTableFilterPanel[R]):
        ...

    @staticmethod
    def showError(parent: java.awt.Component, message: typing.Union[java.lang.String, str]) -> java.util.function.Function[java.lang.Throwable, T]:
        ...

    @staticmethod
    def tableRowActivationAction(table: docking.widgets.table.GTable, runnable: java.lang.Runnable):
        ...


class AbstractDebuggerMapProposalDialog(docking.ReusableDialogComponentProvider, typing.Generic[R]):

    class_: typing.ClassVar[java.lang.Class]

    def adjustCollection(self, tool: ghidra.framework.plugintool.PluginTool, collection: collections.abc.Sequence) -> java.util.Collection[R]:
        ...

    def getAdjusted(self) -> java.util.Collection[R]:
        ...

    def getTable(self) -> docking.widgets.table.GTable:
        ...

    def getTableModel(self) -> docking.widgets.table.EnumeratedColumnTableModel[R]:
        ...

    @property
    def adjusted(self) -> java.util.Collection[R]:
        ...

    @property
    def tableModel(self) -> docking.widgets.table.EnumeratedColumnTableModel[R]:
        ...

    @property
    def table(self) -> docking.widgets.table.GTable:
        ...


class PasteIntoTargetMixin(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def doHasEnoughSpace(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, byteCount: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def doPasteBytes(self, tool: ghidra.framework.plugintool.PluginTool, controlService: ghidra.app.services.DebuggerControlService, consoleService: ghidra.app.services.DebuggerConsoleService, current: ghidra.debug.api.tracemgr.DebuggerCoordinates, location: ghidra.program.util.ProgramLocation, bytes: jpype.JArray[jpype.JByte]) -> bool:
        ...


class DebuggerBlockChooserDialog(docking.ReusableDialogComponentProvider):

    class MemoryBlockRow(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getBlock(self) -> ghidra.program.model.mem.MemoryBlock:
            ...

        def getBlockName(self) -> str:
            ...

        def getLength(self) -> int:
            ...

        def getMaxAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getMinAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getProgram(self) -> ghidra.program.model.listing.Program:
            ...

        def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
            ...

        def getProgramName(self) -> str:
            ...

        def getScore(self) -> float:
            ...

        @typing.overload
        def score(self, section: ghidra.trace.model.modules.TraceSection, snap: typing.Union[jpype.JLong, int], service: ghidra.app.services.DebuggerStaticMappingService) -> float:
            ...

        @typing.overload
        def score(self, region: ghidra.trace.model.memory.TraceMemoryRegion, snap: typing.Union[jpype.JLong, int], service: ghidra.app.services.DebuggerStaticMappingService) -> float:
            ...

        @property
        def maxAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def blockName(self) -> java.lang.String:
            ...

        @property
        def programName(self) -> java.lang.String:
            ...

        @property
        def length(self) -> jpype.JLong:
            ...

        @property
        def minAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def block(self) -> ghidra.program.model.mem.MemoryBlock:
            ...

        @property
        def program(self) -> ghidra.program.model.listing.Program:
            ...

        @property
        def programLocation(self) -> ghidra.program.util.ProgramLocation:
            ...


    @typing.type_check_only
    class MemoryBlockTableColumns(java.lang.Enum[DebuggerBlockChooserDialog.MemoryBlockTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerBlockChooserDialog.MemoryBlockTableColumns, DebuggerBlockChooserDialog.MemoryBlockRow]):

        class_: typing.ClassVar[java.lang.Class]
        SCORE: typing.Final[DebuggerBlockChooserDialog.MemoryBlockTableColumns]
        PROGRAM: typing.Final[DebuggerBlockChooserDialog.MemoryBlockTableColumns]
        BLOCK: typing.Final[DebuggerBlockChooserDialog.MemoryBlockTableColumns]
        START: typing.Final[DebuggerBlockChooserDialog.MemoryBlockTableColumns]
        END: typing.Final[DebuggerBlockChooserDialog.MemoryBlockTableColumns]
        LENGTH: typing.Final[DebuggerBlockChooserDialog.MemoryBlockTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerBlockChooserDialog.MemoryBlockTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerBlockChooserDialog.MemoryBlockTableColumns]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @typing.overload
    def chooseBlock(self, tool: ghidra.framework.plugintool.PluginTool, section: ghidra.trace.model.modules.TraceSection, snap: typing.Union[jpype.JLong, int], programs: collections.abc.Sequence) -> java.util.Map.Entry[ghidra.program.model.listing.Program, ghidra.program.model.mem.MemoryBlock]:
        ...

    @typing.overload
    def chooseBlock(self, tool: ghidra.framework.plugintool.PluginTool, region: ghidra.trace.model.memory.TraceMemoryRegion, snap: typing.Union[jpype.JLong, int], programs: collections.abc.Sequence) -> java.util.Map.Entry[ghidra.program.model.listing.Program, ghidra.program.model.mem.MemoryBlock]:
        ...

    def getChosen(self) -> java.util.Map.Entry[ghidra.program.model.listing.Program, ghidra.program.model.mem.MemoryBlock]:
        ...

    def getTableFilterPanel(self) -> ghidra.util.table.GhidraTableFilterPanel[DebuggerBlockChooserDialog.MemoryBlockRow]:
        ...

    def getTableModel(self) -> docking.widgets.table.EnumeratedColumnTableModel[DebuggerBlockChooserDialog.MemoryBlockRow]:
        ...

    @property
    def tableModel(self) -> docking.widgets.table.EnumeratedColumnTableModel[DebuggerBlockChooserDialog.MemoryBlockRow]:
        ...

    @property
    def tableFilterPanel(self) -> ghidra.util.table.GhidraTableFilterPanel[DebuggerBlockChooserDialog.MemoryBlockRow]:
        ...

    @property
    def chosen(self) -> java.util.Map.Entry[ghidra.program.model.listing.Program, ghidra.program.model.mem.MemoryBlock]:
        ...



__all__ = ["DebuggerSearchRegionFactory", "DebuggerLocationLabel", "AbstractDebuggerParameterDialog", "DebuggerByteSource", "DebuggerProvider", "DebuggerSnapActionContext", "MultiProviderSaveBehavior", "InvokeActionEntryAction", "DebuggerResources", "AbstractDebuggerMapProposalDialog", "PasteIntoTargetMixin", "DebuggerBlockChooserDialog"]
