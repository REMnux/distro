from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.concurrent
import ghidra.framework.model
import ghidra.framework.task.gui
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class GTaskListenerAdapter(GTaskListener):
    """
    A Dummy implementation to that listeners can subclass this and not have to fill in methods they
    don't need.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GTaskMonitor(ghidra.util.task.TaskMonitor, ghidra.util.task.CancelledListener):
    """
    Implementation of a TaskMontor that can be "attached" to a GProgressBar.
    
    The GTaskMonitor is a non-gui object for tracking the progress of a GTaskGroup or GTask.  It
    is created by the GTaskManager as tasks are scheduled.  GUIs that wish to display the progress
    of the groups and tasks can set a GProgressBar into a GTaskMonitor and it will display the
    progress.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def isInderminate(self) -> bool:
        ...

    def isShowingProgressValue(self) -> bool:
        ...

    def setProgressBar(self, gProgressBar: ghidra.framework.task.gui.GProgressBar):
        """
        Set the GProgressBar to use to display the progress.
        
        :param ghidra.framework.task.gui.GProgressBar gProgressBar: the GProgressBar to use.
        """

    @property
    def inderminate(self) -> jpype.JBoolean:
        ...

    @property
    def showingProgressValue(self) -> jpype.JBoolean:
        ...


class GTask(java.lang.Object):
    """
    Interface for tasks to be run by :obj:`GTaskManager`.
    
    
    .. seealso::
    
        | :obj:`GTaskGroup`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getName(self) -> str:
        """
        Returns the name of this task.
        
        :return: the name of this task.
        :rtype: str
        """

    def run(self, domainObject: ghidra.framework.model.DomainObject, monitor: ghidra.util.task.TaskMonitor):
        """
        the run method where work can be performed on the given domain object.
        
        :param ghidra.framework.model.DomainObject domainObject: the object to affect.
        :param ghidra.util.task.TaskMonitor monitor: the taskMonitor to be used to cancel and report progress.
        :raises CancelledException: if the user cancelled the task.
        """

    @property
    def name(self) -> java.lang.String:
        ...


class GTaskManagerPanel(javax.swing.JPanel):
    """
    Main component for managing and viewing the state of a GTaskManager.
     
    
    This component consists of three sub-components: the TaskViewer, The GTaskResultPanel, and a
    button control panel.
     
    
    The TaskViewer:
    
    The TaskViewer shows the state of the scheduled and currently running tasks.  It consists of 
    group objects and task objects arranged in a linear list.  
     
    
    The currently running group has a
    progress bar that indicates the percentage of completed tasks within that group and has a cancel
    button that can be used to cancel all tasks within that group.
     
    
    The currently running task has a progress bar the indicates just the progress of that task.  It
    also has a cancel button that can be used to cancel that task.
     
    
    As groups and tasks are completed, they are removed from the TaskViewer and their results will
    show up in the result panel (if showing)
     
    
    The GTaskResultPanel
    
    The result panel shows the last N tasks that were completed.  It indicates if the task completed
    successfully, or was cancelled or had an exception.
     
    
    The Button Panel
    
    There are buttons to pause and resume the TaskManager, step (run one task when paused), and 
    cancel all scheduled tasks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, taskMgr: GTaskManager):
        ...

    def setUseAnimations(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Turns on or off animations.
        
        :param jpype.JBoolean or bool b: if true, the component will use animation.
        """

    def showResultPanel(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Turns on or off the display of the task results panel.
        
        :param jpype.JBoolean or bool b: if true, displays the task results panel.
        """


class GTaskListener(java.lang.Object):
    """
    Interface used to track the state of a GTaskManager
    """

    class_: typing.ClassVar[java.lang.Class]

    def initialize(self):
        """
        Called when a task listener is added so that the listener can get all the initial state of
        the taskManger while the taskManager is in a locked state where nothing will change.
        """

    def suspendedStateChanged(self, suspended: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that the GTaskManager has been suspended or resumed.
        
        :param jpype.JBoolean or bool suspended: true if the GTaskManger has been suspended, or false if it has been resumed.
        """

    def taskCompleted(self, task: GScheduledTask, result: GTaskResult):
        """
        Notification that a task is no longer running regardless of whether it completed normally,
        was cancelled, or threw an unhandled exception.
        
        :param GScheduledTask task: the ScheduledTask that was running.
        :param GTaskResult result: the result state for the task.
        """

    def taskGroupCompleted(self, taskGroup: GTaskGroup):
        """
        Notification that the GTaskGroup has completed running.
        
        :param GTaskGroup taskGroup: the GTaskGroup that has completed running.
        """

    def taskGroupScheduled(self, group: GTaskGroup):
        """
        Notification that a GTaskGroup has been scheduled.
        
        :param GTaskGroup group: the GTaskGroup that has been scheduled to run.
        """

    def taskGroupStarted(self, taskGroup: GTaskGroup):
        """
        Notification that a new GTaskGroup has started to run.
        
        :param GTaskGroup taskGroup: the new GTaskGroup that is running.
        """

    def taskScheduled(self, scheduledTask: GScheduledTask):
        """
        Notification that a new GTask has been scheduled to run.
        
        :param GScheduledTask scheduledTask: the GScheduledTask that wraps the GTask with scheduling information.
        """

    def taskStarted(self, task: GScheduledTask):
        """
        Notification that a task is starting to run
        
        :param GScheduledTask task: the GTask that is starting to run
        """


class GTaskResult(java.lang.Object):
    """
    Class to represent the result state of a GTask, such as whether it was cancelled or an exception
    happened.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, group: GTaskGroup, task: GScheduledTask, e: java.lang.Exception, transactionID: typing.Union[java.lang.Integer, int]):
        """
        Constructs a GTaskResult for a completed GTask with an optional exception.
        
        :param GTaskGroup group: The GTaskGroup that the completed GTask belonged to.
        :param GScheduledTask task: the GScheduledTask which contains the actual GTask that has completed.
        :param java.lang.Exception e: optional exception recorded if an exception occurred while processing the task.  If
        the task was cancelled, there should be a CancelledException passed in here.
        :param java.lang.Integer or int transactionID: The transaction id for the transaction that was open when the task was
        executed.  Used by the results GUI to indicate when transactions are opened and closed between
        tasks.
        """

    def getDescription(self) -> str:
        """
        Returns a description of the task that was run.
        
        :return: a description of the task that was run.
        :rtype: str
        """

    def getException(self) -> java.lang.Exception:
        """
        Returns the exception generated by the task, or null if no exception was generated.  If 
        the task was cancelled, this will return a CancelledException.
        
        :return: the exception generated by this task or null.
        :rtype: java.lang.Exception
        """

    def getGroupDescription(self) -> str:
        """
        Returns the description for the group for which this task belonged.
        
        :return: the description for the group for which this task belonged.
        :rtype: str
        """

    def getPriority(self) -> int:
        """
        Returns the priority at which the task was run within its group.
        
        :return: the priority at which the task was run within its group.
        :rtype: int
        """

    def hasSameTransaction(self, result: GTaskResult) -> bool:
        """
        Returns true if the task represented by this result was executed in the same transaction
        as the task represented by the given GTaskResult.
        
        :param GTaskResult result: the result to check if it was executed in the same transaction as this task
        result.
        :return: true if same transaction.
        :rtype: bool
        """

    def wasCancelled(self) -> bool:
        """
        Returns true if the task for this result was cancelled.
        
        :return: true if the task for this result was cancelled.
        :rtype: bool
        """

    @property
    def exception(self) -> java.lang.Exception:
        ...

    @property
    def groupDescription(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...


class GScheduledTask(java.lang.Comparable[GScheduledTask]):
    """
    Class for tracking scheduled GTasks.  When tasks are scheduled, they are assigned to a GTaskGroup,
    given a priority, assigned a one-up ID, given a GTaskMonitor.  This class is used to keep all
    that information together.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, group: GTaskGroup, task: GTask, priority: typing.Union[jpype.JInt, int]):
        """
        Create a new GScheduledTask when a task is scheduled with the GTaskManager.
        
        :param GTaskGroup group: the group that this task belongs to.
        :param GTask task: the task being scheduled.
        :param jpype.JInt or int priority: the priority at which this task is to be executed relative to other 
        scheduled tasks.  Lower numbers are run before higher numbers.
        """

    def getDescription(self) -> str:
        """
        Returns the description for the scheduled GTask.
        
        :return: the description for the scheduled GTask.
        :rtype: str
        """

    def getGroup(self) -> GTaskGroup:
        """
        Return GTaskGroup for this task.
        
        :return: the GTaskGroup
        :rtype: GTaskGroup
        """

    def getPriority(self) -> int:
        """
        Returns the priority at which the task was scheduled. Lower numbers have higher priority.
        
        :return: the priority at which the task was scheduled.
        :rtype: int
        """

    def getTask(self) -> GTask:
        """
        Returns the GTask that is scheduled.
        
        :return: the GTask that is scheduled.
        :rtype: GTask
        """

    def getTaskMonitor(self) -> GTaskMonitor:
        """
        Returns the GTaskMonitor that will be used for this task.
        
        :return: the GTaskMonitor that will be used for this task.
        :rtype: GTaskMonitor
        """

    @property
    def task(self) -> GTask:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def taskMonitor(self) -> GTaskMonitor:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...

    @property
    def group(self) -> GTaskGroup:
        ...


class GTaskManager(java.lang.Object):
    """
    Class for managing a queue of tasks to be executed, one at a time, in priority order.  All the
    tasks pertain to an DomainObject and transactions are created on the DomainObject
    so that tasks can operate on them.
     
    
    Tasks are organized into groups such that all tasks in a group will be completed before the
    tasks in the next group, regardless of priority.  Within a group, task are ordered first by
    priority and then by the order in which they were added to the group. Groups are executed 
    in the order that they are scheduled.
     
    
    All tasks within the same group are executed within the same transaction on the
    DomainObject.  When all the tasks within a group are completed, the transaction is closed
    unless there is another group scheduled and that group does not specify that it should run in its
    own transaction.
     
    
    Suspending:
    
    The GTaskManager can be suspended.  When suspended, any currently running task will continue to
    run, but no new or currently scheduled tasks will be executed until the GTaskManager is resumed.
    There is a special method, :meth:`runNextTaskEvenWhenSuspended() <.runNextTaskEvenWhenSuspended>`, that will run the next scheduled task
    even if the GTaskManager is suspended.
     
    
    Yielding to Other Tasks:
    
    While running, a GTask can call the method :meth:`waitForHigherPriorityTasks() <.waitForHigherPriorityTasks>` on the GTaskManager, 
    which will cause the GTaskManager to run scheduled tasks (within the same group) that are 
    a higher priority than the running task, effectively allowing the running task to yield until all
    higher priority tasks are executed.
    
    
    .. seealso::
    
        | :obj:`GTask`
    
        | :obj:`GTaskGroup`
    """

    @typing.type_check_only
    class GTaskRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, domainObject: ghidra.framework.model.DomainObject, threadPool: generic.concurrent.GThreadPool):
        """
        Creates a new GTaskManager for an DomainObject
        
        :param ghidra.framework.model.DomainObject domainObject: the domainObject that tasks scheduled in this GTaskManager will
        operate upon.
        :param generic.concurrent.GThreadPool threadPool: the GThreadPool that will provide the threads that will be used to run 
        tasks in this GTaskManager.
        """

    def addTaskListener(self, listener: GTaskListener):
        """
        Adds a GTaskListener to be notified as tasks are completed.
        
        :param GTaskListener listener: the listener to add
        """

    def cancelAll(self):
        """
        Cancels all scheduled groups and tasks. The TaskMonitor for
        the currently running task will be cancelled, but the task will continue to run until it
        checks the monitor.
        """

    def cancelRunningGroup(self, group: GTaskGroup):
        """
        Cancels all tasks in the currently running group.  Tasks in the group that have not yet started
        will never run and will immediately be put into the TaskResults list.  The TaskMonitor for
        the currently running task will be cancelled, but the task will continue to run until it
        checks the monitor.
        
        :param GTaskGroup group: the group to be cancelled.  It must match the currently running group or nothing
        will happen.
        """

    def getCurrentGroup(self) -> GTaskGroup:
        """
        Returns the currently running group, or null if no group is running.
        
        :return: the currently running group, or null if no group is running.
        :rtype: GTaskGroup
        """

    def getDelayedTasks(self) -> java.util.List[GScheduledTask]:
        """
        Returns a list of Tasks that are currently waiting for higher priority tasks.
        
        :return: a list of Tasks that are currently waiting for higher priority tasks.
        :rtype: java.util.List[GScheduledTask]
        """

    def getRunningTask(self) -> GScheduledTask:
        """
        Returns the currently running task, or null if no task is running.
        
        :return: the currently running task;
        :rtype: GScheduledTask
        """

    def getScheduledGroups(self) -> java.util.List[GTaskGroup]:
        """
        Returns a list of Groups that are waiting to run.
        
        :return: a list of Groups that are waiting to run.
        :rtype: java.util.List[GTaskGroup]
        """

    def getScheduledTasks(self) -> java.util.List[GScheduledTask]:
        """
        Returns a list of scheduled tasks for the currently running group.
        
        :return: a list of scheduled tasks for the currently running group.
        :rtype: java.util.List[GScheduledTask]
        """

    def getTaskResults(self) -> java.util.List[GTaskResult]:
        """
        Returns a list of the most recent GTaskResults.  The TaskManager only keeps the most recent
        N GTaskResults.
        
        :return: the list of the most recent GTaskResults.
        :rtype: java.util.List[GTaskResult]
        """

    def isBusy(self) -> bool:
        """
        Returns true if this manager is running a task, or if suspended has additional tasks queued.
        
        :return: true if this manager is running a task, or if suspended has additional tasks queued.
        :rtype: bool
        """

    def isRunning(self) -> bool:
        """
        Returns true if this manager is currently running a task. If not suspended, a GTaskManager
        will always be executing a task as long as there are tasks to execute.  If suspended, a
        GTaskManager may have tasks scheduled, but may not be currently executing one.
        
        :return: true if this manager is currently running a task.
        :rtype: bool
        """

    def isSuspended(self) -> bool:
        """
        Returns true if this GTaskManager is currently suspended.
        
        :return: true if this GTaskManager is currently suspended.
        :rtype: bool
        """

    def removeTaskListener(self, listener: GTaskListener):
        """
        Removes the given GTaskListener from this queue.
        
        :param GTaskListener listener: the listener to remove.
        """

    def runNextTaskEvenWhenSuspended(self):
        """
        This method will cause the next scheduled task to run even though the task manager is
        suspended.  Calling this method while the queue is not suspended has no effect because
        if not suspended, it will be busy (or have nothing to do)
        """

    @typing.overload
    def scheduleTask(self, task: GTask, priority: typing.Union[jpype.JInt, int], useCurrentGroup: typing.Union[jpype.JBoolean, bool]) -> GScheduledTask:
        """
        Schedules a task to be run by this TaskManager. Tasks are run one at a time.
        
        :param GTask task: the task to be run.
        :param jpype.JInt or int priority: the priority of the task.  Lower numbers are run before higher numbers.
        :param jpype.JBoolean or bool useCurrentGroup: If true, this task will be rolled into the current transaction group
                                    if one exists.  If false, any open transaction 
                                    will be closed and a new transaction will be opened before 
                                    this task is run.
        :return: scheduled task
        :rtype: GScheduledTask
        """

    @typing.overload
    def scheduleTask(self, task: GTask, priority: typing.Union[jpype.JInt, int], groupName: typing.Union[java.lang.String, str]):
        """
        Schedules a task to be run by this TaskManager within the group with the given group name.
        If a group already exists with the given name(either currently running or waiting), the task
        will be added to that group. Otherwise, a new group will be created with the given group name
        and the task will be placed in that group.
        
        :param GTask task: the task to be run.
        :param jpype.JInt or int priority: the priority of the task.  Lower numbers are run before higher numbers.
        :param java.lang.String or str groupName: The name of the group that the task will be added to.
        """

    def scheduleTaskGroup(self, group: GTaskGroup):
        """
        Schedules a task group to run.  Task groups are run in the order they are scheduled. They 
        have the option of being executed in the current transaction (if it exists) or starting
        a new transaction.
        
        :param GTaskGroup group: the TaskGroup to be scheduled.
        """

    def setSuspended(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the suspended state of this task queue.  While suspended, this task manager will not
        start any new tasks in its queue.  Any currently running task will continue to run.
        
        :param jpype.JBoolean or bool b: true to suspend this manager, false to resume executing new tasks.
        """

    def waitForHigherPriorityTasks(self):
        """
        This methods is for currently running tasks to suspend and allow higher priority tasks 
        (within the same task group) to complete before continuing.  If called by any thread other
        than the thread that is currently executing a task for this queue, an exception will be 
        thrown.
        
        :raises IllegalStateException: if this method is called from any thread not currently 
        executing the current task for this queue.
        """

    def waitUntilBusy(self, timeoutMillis: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def waitWhileBusy(self, timeoutMillis: typing.Union[jpype.JLong, int]) -> bool:
        ...

    @property
    def running(self) -> jpype.JBoolean:
        ...

    @property
    def scheduledTasks(self) -> java.util.List[GScheduledTask]:
        ...

    @property
    def delayedTasks(self) -> java.util.List[GScheduledTask]:
        ...

    @property
    def runningTask(self) -> GScheduledTask:
        ...

    @property
    def taskResults(self) -> java.util.List[GTaskResult]:
        ...

    @property
    def scheduledGroups(self) -> java.util.List[GTaskGroup]:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def currentGroup(self) -> GTaskGroup:
        ...

    @property
    def suspended(self) -> jpype.JBoolean:
        ...

    @suspended.setter
    def suspended(self, value: jpype.JBoolean):
        ...


class GTaskManagerFactory(java.lang.Object):
    """
    Factory class managing a single GTaskManager for an DomainObject.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getTaskManager(domainObject: ghidra.framework.model.DomainObject) -> GTaskManager:
        """
        Returns the one GTaskManager for the domainObject. A new GTaskManager will be created if
        one does not already exist for the domainObject.
        
        :param ghidra.framework.model.DomainObject domainObject: the domainObject for which to get a GTaskManager.
        :return: the GTaskManager for the given domainObject.
        :rtype: GTaskManager
        """


class GTaskGroup(java.lang.Object):
    """
    Class for grouping several :obj:`GTask`s that all should be 
    executed before any new group of tasks are
    executed, regardless of priority.
    
    
    .. seealso::
    
        | :obj:`GTaskManager`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, description: typing.Union[java.lang.String, str], startNewTransaction: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new named GTaskGroup.
        
        :param java.lang.String or str description: the display name for the group.
        :param jpype.JBoolean or bool startNewTransaction: if true, any existing transaction (if there is one) will be closed
        and a new transaction will be created.  Otherwise, the tasks in this group will be executed
        in the same transaction as the previous group. Note that this can only happen if there was
        a previous group executing at the time this group is scheduled.
        """

    def addTask(self, task: GTask, priority: typing.Union[jpype.JInt, int]) -> GScheduledTask:
        """
        Add a task to this group with the given priority.  Tasks can only be added to this group
        before the group is added to the GTaskManager.  After that, an IllegalStateException will
        be thrown.
        
        :param GTask task: the task being added to this group.
        :param jpype.JInt or int priority: the priority for the task within the group.
        :return: the GScheduledTask created to schedule this task within the group.
        :rtype: GScheduledTask
        :raises IllegalStateException: if this method is called after the group has been added to
        the GTaskManager.
        """

    def compareTo(self, group: GTaskGroup) -> int:
        ...

    def getDescription(self) -> str:
        """
        Returns a description for the group.
        
        :return: a description for this group.
        :rtype: str
        """

    def getTaskMonitor(self) -> GTaskMonitor:
        """
        Returns the TaskMonitor that will be used to track the overall progress of tasks within this 
        group.
        
        :return: the TaskMonitor that will be used to track the overall progress of tasks within this 
        group.
        :rtype: GTaskMonitor
        """

    def getTasks(self) -> java.util.List[GScheduledTask]:
        """
        Returns a list scheduled tasks in the group.
        
        :return: a list scheduled tasks in the group.
        :rtype: java.util.List[GScheduledTask]
        """

    def setCancelled(self):
        """
        Cancels the group.  Any tasks that haven't yet started will never run.
        """

    def setScheduled(self):
        ...

    def taskCompleted(self):
        """
        Notification that a task in the group has been completed.  The group keeps track of the overall
        progress of the tasks completed in this group.  This call is used to notify the group that
        another one of its tasks was completed.
        """

    def wantsNewTransaction(self) -> bool:
        """
        Returns true if this group wants to start a new transaction when it runs.  Otherwise, the
        group will add-on to any existing transaction from the previous group.
        
        :return: true if a new transaction should be started for this group.
        :rtype: bool
        """

    def wasCancelled(self) -> bool:
        """
        Returns true if this group was cancelled.
        
        :return: true if this group was cancelled.
        :rtype: bool
        """

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def taskMonitor(self) -> GTaskMonitor:
        ...

    @property
    def tasks(self) -> java.util.List[GScheduledTask]:
        ...


@typing.type_check_only
class MulticastTaskListener(GTaskListener):
    """
    Used by the GTaskManager to efficiently manage multiple GTaskListeners.  
     
    
    When an GTaskManager has multiple listeners, instead of having a list of listeners, listeners
    are chained together using MulticastTaskListeners. It avoids the creation of
    an iterator every time a listener method needs to be called.
     
    
    For example, the GTaskManager has a single TaskListener variable that it notifies when its state
    changes.  If someone adds a listener, and the current listener is null, then it becomes the 
    listener.  If it already has a listener, it will create a new MulticaseTaskListener taking in the
    old listener and the new listener.  When a TaskListener method is called, it simply calls the same
    method on those two listeners.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, a: GTaskListener, b: GTaskListener):
        ...

    def removeListener(self, listener: GTaskListener) -> GTaskListener:
        ...



__all__ = ["GTaskListenerAdapter", "GTaskMonitor", "GTask", "GTaskManagerPanel", "GTaskListener", "GTaskResult", "GScheduledTask", "GTaskManager", "GTaskManagerFactory", "GTaskGroup", "MulticastTaskListener"]
