from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.importer
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util.classfinder
import ghidra.util.task
import java.lang # type: ignore


T = typing.TypeVar("T")


class BinaryAnalysisCommand(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL BinaryAnalysisCommand CLASSES MUST END IN "BinaryAnalysisCommand".  If not,
    the ClassSearcher will not find them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def applyTo(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Applies the command to the given domain object.
        
        :param ghidra.program.model.listing.Program program: domain object that this command is to be applied.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if the command applied successfully
        :rtype: bool
        """

    def canApply(self, program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns TRUE if this command can be applied
        to the given domain object.
        
        :param ghidra.program.model.listing.Program program: the domain object to inspect.
        :return: TRUE if this command can be applied
        :rtype: bool
        """

    def getMessages(self) -> ghidra.app.util.importer.MessageLog:
        """
        Returns the status message indicating the status of the command.
        
        :return: reason for failure, or null if the status of the command 
                was successful
        :rtype: ghidra.app.util.importer.MessageLog
        """

    def getName(self) -> str:
        """
        Returns the name of this command.
        
        :return: the name of this command
        :rtype: str
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def messages(self) -> ghidra.app.util.importer.MessageLog:
        ...


class CompoundBackgroundCommand(BackgroundCommand[T], typing.Generic[T]):
    """
    Compound command to handle multiple background commands.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], modal: typing.Union[jpype.JBoolean, bool], canCancel: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param java.lang.String or str name: name of the command
        :param jpype.JBoolean or bool modal: true means the monitor dialog is modal and the command has to
                complete or be canceled before any other action can occur
        :param jpype.JBoolean or bool canCancel: true means the command can be canceled
        """

    def add(self, cmd: Command[T]):
        """
        Add a command to this compound background command.
        
        :param Command[T] cmd: command to be added
        """

    def isEmpty(self) -> bool:
        """
        
        
        :return: true if no sub-commands have been added
        :rtype: bool
        """

    def size(self) -> int:
        """
        Get the number of background commands in this compound background
        command.
        
        :return: the number of commands
        :rtype: int
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class Command(java.lang.Object, typing.Generic[T]):
    """
    Interface to define a change made to a domain object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def applyTo(self, obj: T) -> bool:
        """
        Applies the command to the given domain object.
        
        :param T obj: domain object that this command is to be applied.
        :return: true if the command applied successfully
        :rtype: bool
        """

    def getName(self) -> str:
        """
        Returns the name of this command.
        
        :return: the name of this command
        :rtype: str
        """

    def getStatusMsg(self) -> str:
        """
        Returns the status message indicating the status of the command.
        
        :return: reason for failure, or null if the status of the command 
                was successful
        :rtype: str
        """

    @property
    def statusMsg(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class CompoundCmd(Command[T], typing.Generic[T]):
    """
    Implementation for multiple commands that are done as a unit.
     
    Multiple commands may be added to this one so that multiple changes can be
    applied to the domain object as unit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructor for CompoundCmd.
        
        :param java.lang.String or str name: the name of the command
        """

    def add(self, cmd: Command[T]):
        """
        Add the given command to this command.
        
        :param Command[T] cmd: command to add to this command
        """

    def size(self) -> int:
        """
        Return the number of commands that are part of this compound command.
        
        :return: the number of commands that have been added to this one.
        :rtype: int
        """


class MergeableBackgroundCommand(BackgroundCommand[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], hasProgress: typing.Union[jpype.JBoolean, bool], canCancel: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool]):
        ...

    def mergeCommands(self, command: MergeableBackgroundCommand[T]) -> MergeableBackgroundCommand[T]:
        """
        Merges the properties of the two commands
        
        :param MergeableBackgroundCommand[T] command: command to be merged with this one
        :return: resulting merged command
        :rtype: MergeableBackgroundCommand[T]
        """


class BackgroundCommand(Command[T], typing.Generic[T]):
    """
    Abstract command that will be run in a thread (in the background) other than the AWT(GUI)
    thread.  Use this to apply a long running command that is cancellable.
     
     
    The monitor allows the command to display status information as it executes.
     
     
    This allows commands to make changes in the background so that the GUI is not frozen and the
    user can still interact with the GUI.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], hasProgress: typing.Union[jpype.JBoolean, bool], canCancel: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool]):
        ...

    def applyTo(self, obj: T, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Method called when this command is to apply changes to the given domain object.  A monitor
        is provided to display status information about the command as it executes in the background.
        
        :param T obj: domain object that will be affected by the command
        :param ghidra.util.task.TaskMonitor monitor: monitor to show progress of the command
        :return: true if the command applied successfully
        :rtype: bool
        """

    def canCancel(self) -> bool:
        """
        Check if the command can be canceled.
        
        :return: true if this command can be canceled
        :rtype: bool
        """

    def dispose(self):
        """
        Called when this command is going to be removed/canceled without
        running it.  This gives the command the opportunity to free any
        temporary resources it has hold of.
        """

    def hasProgress(self) -> bool:
        """
        Check if the command provides progress information.
        
        :return: true if the command shows progress information
        :rtype: bool
        """

    def isModal(self) -> bool:
        """
        Check if the command requires the monitor to be modal.  No other
        command should be allowed, and the GUI will be locked.
        
        :return: true if no other operation should be going on while this
        command is in progress.
        :rtype: bool
        """

    def run(self, tool: ghidra.framework.plugintool.PluginTool, obj: T):
        ...

    def taskCompleted(self):
        """
        Called when the task monitor is completely done with indicating progress.
        """

    @property
    def modal(self) -> jpype.JBoolean:
        ...



__all__ = ["BinaryAnalysisCommand", "CompoundBackgroundCommand", "Command", "CompoundCmd", "MergeableBackgroundCommand", "BackgroundCommand"]
