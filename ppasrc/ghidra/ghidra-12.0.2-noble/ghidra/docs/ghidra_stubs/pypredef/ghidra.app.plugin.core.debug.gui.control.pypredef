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
import docking.actions
import docking.menu
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui
import ghidra.debug.api.target
import ghidra.framework.plugintool
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


@typing.type_check_only
class TargetStepOutAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Step Out"
    DESCRIPTION: typing.Final = "Step the target out"
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "target_step_out"
    SUB_GROUP: typing.Final = 8
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(owner: DebuggerControlPlugin) -> TargetActionBuilder:
        ...


@typing.type_check_only
class TargetStepExtAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "target_step_ext"
    SUB_GROUP: typing.Final = 9
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(name: typing.Union[java.lang.String, str], owner: DebuggerControlPlugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class TargetKillAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Kill"
    DESCRIPTION: typing.Final = "Kill the target"
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "target_kill"
    SUB_GROUP: typing.Final = 2
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(owner: DebuggerControlPlugin) -> TargetActionBuilder:
        ...


@typing.type_check_only
class InterruptAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    ICON: typing.Final[javax.swing.Icon]
    SUB_GROUP: typing.Final = 1
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]


@typing.type_check_only
class ControlAction(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    GROUP: typing.Final = "Dbg4. Control"

    @staticmethod
    def intSubGroup(subGroup: typing.Union[jpype.JInt, int]) -> str:
        ...


@typing.type_check_only
class DisconnectAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Disconnect"
    DESCRIPTION: typing.Final = "Close the connection to the debugging agent"
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "target_disconnect"
    SUB_GROUP: typing.Final = 3
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class StepIntoAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    ICON: typing.Final[javax.swing.Icon]
    SUB_GROUP: typing.Final = 5
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]


@typing.type_check_only
class TargetActionBuilder(docking.action.builder.AbstractActionBuilder[TargetDockingAction, docking.ActionContext, TargetActionBuilder]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: ghidra.framework.plugintool.Plugin):
        ...

    def action(self, action: ghidra.debug.api.target.ActionName) -> TargetActionBuilder:
        ...

    def defaultDescription(self, defaultDescription: typing.Union[java.lang.String, str]) -> TargetActionBuilder:
        ...


class DebuggerMethodActionsPlugin(ghidra.framework.plugintool.Plugin, docking.actions.PopupActionProvider):

    @typing.type_check_only
    class MethodAction(ghidra.app.plugin.core.debug.gui.InvokeActionEntryAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, entry: ghidra.debug.api.target.Target.ActionEntry):
            ...


    class_: typing.ClassVar[java.lang.Class]
    GROUP_METHODS: typing.Final = "Debugger Methods"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class TargetDockingAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], keyBindingType: docking.action.KeyBindingType, tool: ghidra.framework.plugintool.PluginTool, action: ghidra.debug.api.target.ActionName, defaultDescription: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class EmulateStepIntoAction(StepIntoAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Step Emulator Into"
    DESCRIPTION: typing.Final = "Step the integrated emulator a single instruction, descending into calls"
    HELP_ANCHOR: typing.Final = "emu_step_into"

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class TargetResumeAction(ResumeAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Resume"
    DESCRIPTION: typing.Final = "Resume the target"
    HELP_ANCHOR: typing.Final = "target_resume"

    @staticmethod
    def builder(owner: DebuggerControlPlugin) -> TargetActionBuilder:
        ...


@typing.type_check_only
class ResumeAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    ICON: typing.Final[javax.swing.Icon]
    SUB_GROUP: typing.Final = 0
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]


@typing.type_check_only
class TraceSnapBackwardAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Trace Snapshot Backward"
    DESCRIPTION: typing.Final = "Navigate the trace recording backward one snapshot"
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "trace_snap_backward"
    SUB_GROUP: typing.Final = 10
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class TargetInterruptAction(InterruptAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Interrupt"
    DESCRIPTION: typing.Final = "Interrupt the target"
    HELP_ANCHOR: typing.Final = "target_interrupt"

    @staticmethod
    def builder(owner: DebuggerControlPlugin) -> TargetActionBuilder:
        ...


@typing.type_check_only
class EmulateStepBackAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Step Emulator Back"
    DESCRIPTION: typing.Final = "Step the integrated emulator a single instruction backward"
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "emu_step_back"
    SUB_GROUP: typing.Final = 4
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class ControlModeAction(docking.menu.MultiStateDockingAction[ghidra.debug.api.control.ControlMode]):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Control Mode"
    DESCRIPTION: typing.Final = "Choose what to control and edit in dynamic views"
    GROUP: typing.Final = "Dbg4. Control"
    HELP_ANCHOR: typing.Final = "control_mode"

    def __init__(self, plugin: DebuggerControlPlugin):
        ...


@typing.type_check_only
class EmulateSkipOverAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Skip Emulator"
    DESCRIPTION: typing.Final = "Skip the integrated emulator a single instruction, ignoring its effects"
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "emu_skip_over"
    SUB_GROUP: typing.Final = 7
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class EmulateInterruptAction(InterruptAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Interrupt Emulator"
    DESCRIPTION: typing.Final = "Interrupt, i.e., suspend, the integrated emulator"
    HELP_ANCHOR: typing.Final = "emu_interrupt"

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class TraceSnapForwardAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Trace Snapshot Forward"
    DESCRIPTION: typing.Final = "Navigate the trace recording forward one snapshot"
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "trace_snap_backward"
    SUB_GROUP: typing.Final = 11
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class EmulateResumeAction(ResumeAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Resume Emulator"
    DESCRIPTION: typing.Final = "Resume, i.e., go or continue execution of the integrated emulator"
    HELP_ANCHOR: typing.Final = "emu_resume"

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
        ...


@typing.type_check_only
class TargetStepOverAction(ControlAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Step Over"
    DESCRIPTION: typing.Final = "Step the target over"
    ICON: typing.Final[javax.swing.Icon]
    HELP_ANCHOR: typing.Final = "target_step_over"
    SUB_GROUP: typing.Final = 6
    KEY_BINDING: typing.Final[javax.swing.KeyStroke]

    @staticmethod
    def builder(owner: DebuggerControlPlugin) -> TargetActionBuilder:
        ...


class DisconnectTask(ghidra.util.task.Task):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, targets: collections.abc.Sequence):
        ...


@typing.type_check_only
class TargetStepIntoAction(StepIntoAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Step Into"
    DESCRIPTION: typing.Final = "Step the target into"
    HELP_ANCHOR: typing.Final = "target_step_into"

    @staticmethod
    def builder(owner: DebuggerControlPlugin) -> TargetActionBuilder:
        ...


class TargetActionTask(ghidra.util.task.Task):
    """
    A task for executing a target :obj:`ActionEntry`.
     
     
    
    This also has some static convenience methods for scheduling this and other types of tasks in the
    Debugger tool.
    """

    @typing.type_check_only
    class FutureTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, delegate: ghidra.util.task.Task):
            ...


    @typing.type_check_only
    class FutureAsTask(ghidra.util.task.Task, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, title: typing.Union[java.lang.String, str], canCancel: typing.Union[jpype.JBoolean, bool], hasProgress: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool], futureSupplier: java.util.function.Function[ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[T]]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], entry: ghidra.debug.api.target.Target.ActionEntry, timeout: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a task fore the given action
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        :param java.lang.String or str title: the title, often :meth:`ActionEntry.display() <ActionEntry.display>`
        :param ghidra.debug.api.target.Target.ActionEntry entry: the action to execute
        :param jpype.JBoolean or bool timeout: whether or not to enforce the timeout
        """

    @staticmethod
    @typing.overload
    def executeTask(tool: ghidra.framework.plugintool.PluginTool, task: ghidra.util.task.Task) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Execute a task
         
         
        
        If available, this simply delegates to :meth:`ProgressService.execute(Task) <ProgressService.execute>`. If not, then
        this falls back to :meth:`PluginTool.execute(Task) <PluginTool.execute>`.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool in which to execute
        :param ghidra.util.task.Task task: the task to execute
        :return: a future that completes (perhaps exceptionally) when the task is finished or
                cancelled
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @staticmethod
    @typing.overload
    def executeTask(tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], canCancel: typing.Union[jpype.JBoolean, bool], hasProgress: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool], futureSupplier: java.util.function.Function[ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[T]]) -> java.util.concurrent.CompletableFuture[T]:
        """
        Execute an asynchronous task
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool in which to execute
        :param java.lang.String or str title: the title of the task
        :param jpype.JBoolean or bool canCancel: if the task can be cancelled
        :param jpype.JBoolean or bool hasProgress: if the task displays progress
        :param jpype.JBoolean or bool isModal: if the task is modal
        :param java.util.function.Function[ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[T]] futureSupplier: the task, a function of the monitor returning the future
        :return: a future which completes in the same way as the one returned by the supplier
        :rtype: java.util.concurrent.CompletableFuture[T]
        """

    @staticmethod
    def runAction(tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], entry: ghidra.debug.api.target.Target.ActionEntry) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Execute an :obj:`ActionEntry`
         
         
        
        If the :obj:`ProgressService` is available, we will not enforce a timeout, because it should
        be relatively easy for the user to manage the pending tasks. Otherwise, we'll enforce the
        timeout. The rationale here is that some tasks do actually take a good bit of time. For
        example, some targets just have a large module list. Often a GUI component is asking for a
        reason, and if we time it out, that thing doesn't get what it needs. Furthermore, the entry
        disappears from the task list, even though the back-end is likely still working on it. That's
        not good, actually. Since we have a cancel button, let the user decide when it's had enough
        time.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool in which to execute
        :param java.lang.String or str title: the title, often :meth:`ActionEntry.display() <ActionEntry.display>`
        :param ghidra.debug.api.target.Target.ActionEntry entry: the action to execute
        :return: a future that completes (perhaps exceptionally) when the task is finished or
                cancelled
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """


class DebuggerControlPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin, docking.DockingContextListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["TargetStepOutAction", "TargetStepExtAction", "TargetKillAction", "InterruptAction", "ControlAction", "DisconnectAction", "StepIntoAction", "TargetActionBuilder", "DebuggerMethodActionsPlugin", "TargetDockingAction", "EmulateStepIntoAction", "TargetResumeAction", "ResumeAction", "TraceSnapBackwardAction", "TargetInterruptAction", "EmulateStepBackAction", "ControlModeAction", "EmulateSkipOverAction", "EmulateInterruptAction", "TraceSnapForwardAction", "EmulateResumeAction", "TargetStepOverAction", "DisconnectTask", "TargetStepIntoAction", "TargetActionTask", "DebuggerControlPlugin"]
