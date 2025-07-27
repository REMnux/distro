from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.options
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import org.jdom # type: ignore


T = typing.TypeVar("T")


class EventManager(java.lang.Object):
    """
    Helper class to manage the events that plugins consume and produce. This class keeps track of the
    last events that went out so that when a plugin is added, it receives those events.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Construct a new EventManager.
        
        :param ghidra.framework.plugintool.PluginTool tool: plugin tool associated with this EventManager
        """

    def addAllEventListener(self, listener: ghidra.framework.plugintool.util.PluginEventListener):
        ...

    def addEventListener(self, eventClass: java.lang.Class[ghidra.framework.plugintool.PluginEvent], listener: ghidra.framework.plugintool.util.PluginEventListener):
        """
        Add a plugin event listener that will be notified when an event of the given event class is
        generated.
        
        :param java.lang.Class[ghidra.framework.plugintool.PluginEvent] eventClass: class of the event of interest
        :param ghidra.framework.plugintool.util.PluginEventListener listener: listener to notify
        """

    def addEventProducer(self, eventClass: java.lang.Class[ghidra.framework.plugintool.PluginEvent]):
        """
        Add the class for the PluginEvent that a plugin will produce
        
        :param java.lang.Class[ghidra.framework.plugintool.PluginEvent] eventClass: class for the PluginEvent
        """

    def addToolListener(self, listener: ghidra.framework.model.ToolListener):
        """
        Add the given tool listener to be notified when tool events are generated
        
        :param ghidra.framework.model.ToolListener listener: listener to add
        """

    def clear(self):
        """
        Clear last plugin events fired, current event, listeners, etc.
        """

    def clearLastEvents(self):
        """
        Clear the list of last plugin events fired
        """

    def fireEvent(self, event: ghidra.framework.plugintool.PluginEvent):
        """
        Notify all plugin listeners that are registered to consume the given event. Events are fired
        in the SwingThread.
        
        :param ghidra.framework.plugintool.PluginEvent event: event to fire
        """

    def getEventsConsumed(self) -> jpype.JArray[java.lang.String]:
        """
        Get the names of all events consumed by plugins in the tool.
        
        :return: array of PluginEvent names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getEventsProduced(self) -> jpype.JArray[java.lang.String]:
        """
        Get the names of all events produced by plugins in the tool.
        
        :return: array of PluginEvent names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getLastEvents(self) -> jpype.JArray[ghidra.framework.plugintool.PluginEvent]:
        """
        Return an array of the last plugin events fired. EventManager maps the event class to the
        last event fired.
        
        :return: array of plugin events
        :rtype: jpype.JArray[ghidra.framework.plugintool.PluginEvent]
        """

    def hasToolListeners(self) -> bool:
        """
        Return whether there are any registered tool listeners for the tool associated with class
        
        :return: true if there are any listeners
        :rtype: bool
        """

    def processToolEvent(self, event: ghidra.framework.plugintool.PluginEvent):
        """
        Convert the given tool event to a plugin event; notify the appropriate plugin listeners. This
        method allows one tool's event manager to send events to another connected tool.
        
        :param ghidra.framework.plugintool.PluginEvent event: tool event
        """

    def removeAllEventListener(self, listener: ghidra.framework.plugintool.util.PluginEventListener):
        ...

    @typing.overload
    def removeEventListener(self, eventClass: java.lang.Class[ghidra.framework.plugintool.PluginEvent], listener: ghidra.framework.plugintool.util.PluginEventListener):
        """
        Remove the plugin event listener from the list of listeners notified when an event of the
        given event class is generated.
        
        :param java.lang.Class[ghidra.framework.plugintool.PluginEvent] eventClass: class of the event of interest
        :param ghidra.framework.plugintool.util.PluginEventListener listener: listener to remove
        """

    @typing.overload
    def removeEventListener(self, className: typing.Union[java.lang.String, str]):
        """
        Remove the event listener by className; the plugin registered for events, but the
        construction failed.
        
        :param java.lang.String or str className: class name of the plugin (event listener)
        """

    def removeEventProducer(self, eventClass: java.lang.Class[ghidra.framework.plugintool.PluginEvent]):
        """
        Remove the class of a PluginEvent that a plugin produces.
        
        :param java.lang.Class[ghidra.framework.plugintool.PluginEvent] eventClass: class for the PluginEvent
        """

    def removeToolListener(self, listener: ghidra.framework.model.ToolListener):
        """
        Remove the given tool listener from the list of tool listeners
        
        :param ghidra.framework.model.ToolListener listener: listener to remove
        """

    @property
    def eventsProduced(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def eventsConsumed(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def lastEvents(self) -> jpype.JArray[ghidra.framework.plugintool.PluginEvent]:
        ...


class DialogManager(java.lang.Object):
    """
    Helper class to manage actions for saving and exporting the tool
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def exportDefaultTool(self):
        """
        Exports a version of our tool without any config settings.  This is useful for making a
        new 'default' tool to be shared with others, which will not contain any user settings.
        """

    def exportTool(self):
        """
        Write our tool to a filename; the user is prompted for a filename
        """

    def saveToolAs(self) -> bool:
        """
        Show the "Save Tool" dialog.  Returns true if the user performed a 'save as'; returns false
        if the user cancelled.
        
        :return: false if the user cancelled
        :rtype: bool
        """


@typing.type_check_only
class BackgroundCommandTask(ghidra.util.task.Task, ghidra.framework.model.AbortedTransactionListener, typing.Generic[T]):
    """
    A task that executes a command in separate thread, not in the Swing Thread
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, taskMgr: ToolTaskManager, obj: T, cmd: ghidra.framework.cmd.BackgroundCommand[T]):
        """
        Constructor
        
        :param ToolTaskManager taskMgr: manager for this background task.
        :param T obj: the domain object to be modified by this task.
        :param ghidra.framework.cmd.BackgroundCommand[T] cmd: the background command to invoke.
        """

    def getCommand(self) -> ghidra.framework.cmd.BackgroundCommand[T]:
        """
        Returns command associated with this task
        
        :return: background command
        :rtype: ghidra.framework.cmd.BackgroundCommand[T]
        """

    def getDomainObject(self) -> T:
        """
        Returns the Domain Object associated with this Task
        
        :return: the object
        :rtype: T
        """

    @property
    def domainObject(self) -> T:
        ...

    @property
    def command(self) -> ghidra.framework.cmd.BackgroundCommand[T]:
        ...


class ToolTaskManager(java.lang.Runnable):
    """
    Manages a queue of background tasks that execute commands.
    """

    @typing.type_check_only
    class EmptyBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class SimpleCommand(ghidra.framework.cmd.Command[T], typing.Generic[T]):
        """
        :obj:`SimpleCommand` provides a convenience command for wrapping a lambda function
        into a foreground :obj:`Command` for execution by the task manager.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Construct a new ToolTaskManager.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool associated with this ToolTaskManager
        """

    def cancelCurrentTask(self):
        """
        Cancel the current task.
        """

    def clearQueuedCommands(self, obj: ghidra.framework.model.DomainObject):
        """
        Clear the queue of scheduled commands.
        
        :param ghidra.framework.model.DomainObject obj: domain object
        """

    @typing.overload
    def clearTasks(self, obj: ghidra.framework.model.DomainObject):
        """
        Clear all tasks associated with specified domain object.
        
        :param ghidra.framework.model.DomainObject obj: domain object
        """

    @typing.overload
    def clearTasks(self):
        """
        Clear the list of tasks.
        """

    def dispose(self):
        """
        Clear list of tasks and queue of scheduled commands.
        """

    @typing.overload
    def execute(self, commandName: typing.Union[java.lang.String, str], domainObject: T, f: java.util.function.Function[T, java.lang.Boolean]) -> bool:
        """
        Execute the given command in the foreground.  Required domain object transaction will be
        started with delayed end to ensure that any follow-on analysis starts prior to transaction 
        end.
        
        :param T: :obj:`DomainObject` implementation interface:param java.lang.String or str commandName: command name to be associated with transaction
        :param T domainObject: domain object to be modified
        :param java.util.function.Function[T, java.lang.Boolean] f: command function callback which should return true on success or false on failure.
        :return: result from command function callback
        :rtype: bool
        """

    @typing.overload
    def execute(self, cmd: ghidra.framework.cmd.Command[T], obj: T) -> bool:
        """
        Execute the given command in the foreground.  Required domain object transaction will be
        started with delayed end to ensure that any follow-on analysis starts prior to transaction 
        end.
        
        :param ghidra.framework.cmd.Command[T] cmd: command to execute
        :param T obj: domain object to which the command will be applied
        :return: the completion status of the command
        :rtype: bool
        
        .. seealso::
        
            | :obj:`Command.applyTo(DomainObject)`
        """

    def executeCommand(self, cmd: ghidra.framework.cmd.BackgroundCommand[T], obj: T):
        """
        Execute the given command in the background
        
        :param ghidra.framework.cmd.BackgroundCommand[T] cmd: background command
        :param T obj: domain object that supports undo/redo
        """

    def getMonitorComponent(self) -> javax.swing.JComponent:
        """
        Get the monitor component that shows progress and has a cancel button.
        
        :return: the monitor component
        :rtype: javax.swing.JComponent
        """

    def getTaskThreadGroup(self) -> java.lang.ThreadGroup:
        """
        Returns the thread group associated with all background tasks run by this
        manager and their instantiated threads.
        
        :return: task thread group
        :rtype: java.lang.ThreadGroup
        """

    def hasTasksForDomainObject(self, domainObject: ghidra.framework.model.DomainObject) -> bool:
        ...

    def isBusy(self) -> bool:
        """
        Return true if a task is executing
        
        :return: true if a task is executing
        :rtype: bool
        """

    def scheduleFollowOnCommand(self, cmd: ghidra.framework.cmd.BackgroundCommand[T], obj: T):
        """
        Schedule the given background command when the current command completes.
        
        :param ghidra.framework.cmd.BackgroundCommand[T] cmd: background command to be scheduled
        :param T obj: domain object that supports undo/redo
        """

    def stop(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Cancel the currently running task and clear all commands that are scheduled to run. Block
        until the currently running task ends.
        
        :param ghidra.util.task.TaskMonitor monitor: a monitor to cancel waiting for the task to finish
        """

    def taskCompleted(self, obj: T, task: BackgroundCommandTask[T], monitor: ghidra.util.task.TaskMonitor):
        """
        Notification from the BackgroundCommandTask that it has completed; queued
        or scheduled commands are executed.
        
        :param T obj: domain object that supports undo/redo
        :param BackgroundCommandTask[T] task: background command task that has completed
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        """

    def taskFailed(self, obj: T, taskCmd: ghidra.framework.cmd.BackgroundCommand[T], monitor: ghidra.util.task.TaskMonitor):
        """
        Notification from the BackgroundCommandTask that the given command
        failed. Any scheduled commands are cleared from the queue.
        
        :param T obj: domain object that supports undo/redo
        :param ghidra.framework.cmd.BackgroundCommand[T] taskCmd: background command that failed
        :param ghidra.util.task.TaskMonitor monitor: task monitor for the background task
        """

    @property
    def taskThreadGroup(self) -> java.lang.ThreadGroup:
        ...

    @property
    def monitorComponent(self) -> javax.swing.JComponent:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...


class ServiceManager(java.lang.Object):
    """
    Class for managing plugin services. A plugin may provide a service, or
    it may depend on a service. The ServiceManager maintains a list of
    service names and plugins that provide those services. A plugin may
    dynamically add and remove services from the service registry. As services
    are added and removed, all the plugins (ServiceListener)
    in the tool are notified.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Construct a new Service Registry.
        """

    def addService(self, interfaceClass: java.lang.Class[T], service: T):
        """
        Add the service to the tool. Notify the service listeners if the
        notification indicator is true; otherwise, add the service to a list
        that will be used to notify listeners when notifications are
        turned on again.
        
        :param java.lang.Class[T] interfaceClass: class of the service interface being added
        :param T service: implementation of the service; it may be a plugin or
        may be some object created by the plugin
        
        .. seealso::
        
            | :obj:`.setServiceAddedNotificationsOn(boolean)`
        """

    def addServiceListener(self, listener: ghidra.framework.plugintool.util.ServiceListener):
        """
        Add listener that is notified when services are added or removed.
        
        :param ghidra.framework.plugintool.util.ServiceListener listener: listener to notify
        """

    def getAllServices(self) -> java.util.List[ghidra.framework.plugintool.ServiceInterfaceImplementationPair]:
        """
        Returns a array of all service implementors.
        
        :return: a array of all service implementors
        :rtype: java.util.List[ghidra.framework.plugintool.ServiceInterfaceImplementationPair]
        """

    def getService(self, interfaceClass: java.lang.Class[T]) -> T:
        """
        Return the first implementation found for the given service class.
        
        :param java.lang.Class[T] interfaceClass: interface class for the service
        :return: null if the interfaceClass was not registered
        :rtype: T
        """

    def getServices(self, interfaceClass: java.lang.Class[T]) -> jpype.JArray[T]:
        """
        Get an array of objects that implement the given interfaceClass.
        
        :param java.lang.Class[T] interfaceClass: interface class for the service
        :return: zero length array if the interfaceClass was not registered
        :rtype: jpype.JArray[T]
        """

    def isService(self, serviceInterface: java.lang.Class[typing.Any]) -> bool:
        """
        Returns true if the specified ``serviceInterface``
        is a valid service that exists in this service manager.
        
        :param java.lang.Class[typing.Any] serviceInterface: the service interface
        :return: true if the specified ``serviceInterface``
        :rtype: bool
        """

    def removeService(self, interfaceClass: java.lang.Class[typing.Any], service: java.lang.Object):
        """
        Remove the service from the tool.
        
        :param java.lang.Class[typing.Any] interfaceClass: the service interface
        :param java.lang.Object service: the service implementation
        """

    def removeServiceListener(self, listener: ghidra.framework.plugintool.util.ServiceListener):
        """
        Remove the given listener from list of listeners notified when
        services are added or removed.
        
        :param ghidra.framework.plugintool.util.ServiceListener listener: listener to remove
        """

    def setServiceAddedNotificationsOn(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Set the indicator for whether service listeners should be notified.
        While plugins are being restored from a tool state, this indicator
        is false, as a plugin may not be in the proper state to handle the
        notification.
        
        :param jpype.JBoolean or bool b: true means to notify listeners of the services added to
        the tool
        """

    @property
    def service(self) -> T:
        ...

    @property
    def services(self) -> jpype.JArray[T]:
        ...

    @property
    def allServices(self) -> java.util.List[ghidra.framework.plugintool.ServiceInterfaceImplementationPair]:
        ...


@typing.type_check_only
class Counter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ToolTaskMonitor(ghidra.util.task.TaskMonitorComponent, ghidra.util.task.TaskListener):

    class_: typing.ClassVar[java.lang.Class]

    def updateTaskCmd(self, cmd: ghidra.framework.cmd.BackgroundCommand[typing.Any]):
        ...


class OptionsManager(docking.options.OptionsService, ghidra.framework.options.OptionsChangeListener):
    """
    Created by PluginTool to manage the set of Options for each category.
    """

    @typing.type_check_only
    class OptionsComparator(java.util.Comparator[ghidra.framework.options.ToolOptions]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyBindingOptionsEditor(ghidra.framework.options.OptionsEditor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: associated with this OptionsManager
        """

    def deregisterOwner(self, ownerPlugin: ghidra.framework.plugintool.Plugin):
        """
        Deregister the owner from the options; if options are empty, then
        remove the options from the map.
        
        :param ghidra.framework.plugintool.Plugin ownerPlugin: the owner plugin
        """

    def dispose(self):
        ...

    def editOptions(self):
        ...

    def getConfigState(self) -> org.jdom.Element:
        """
        Write this object out; first remove any unused options so they
        do not hang around.
        
        :return: XML element containing the state of all the options
        :rtype: org.jdom.Element
        """

    def registerOptionNameChanged(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Updates saved options from an old name to a new name.  NOTE: this must be called before
        any calls to register or get options.
        
        :param java.lang.String or str oldName: the old name of the options.
        :param java.lang.String or str newName: the new name of the options.
        """

    def removeUnusedOptions(self):
        ...

    def setConfigState(self, root: org.jdom.Element):
        """
        Restore Options objects using the given XML Element.
        
        :param org.jdom.Element root: element to use to restore the Options objects
        """

    def validateOptions(self):
        ...

    @property
    def configState(self) -> org.jdom.Element:
        ...

    @configState.setter
    def configState(self, value: org.jdom.Element):
        ...



__all__ = ["EventManager", "DialogManager", "BackgroundCommandTask", "ToolTaskManager", "ServiceManager", "Counter", "ToolTaskMonitor", "OptionsManager"]
