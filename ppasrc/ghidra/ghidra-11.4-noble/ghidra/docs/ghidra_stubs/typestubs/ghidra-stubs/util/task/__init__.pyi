from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.util
import ghidra.util.worker
import java.awt # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import javax.swing # type: ignore
import utility.function


T = typing.TypeVar("T")


@typing.type_check_only
class TaskRunner(java.lang.Object):
    """
    Helper class to launch the given task in a background thread, showing a task dialog if
    this task takes to long. See :obj:`TaskLauncher`.
    """

    class_: typing.ClassVar[java.lang.Class]


class TaskMonitorComponent(javax.swing.JPanel, TaskMonitor):
    """
    Component that contains a progress bar, a progress icon, and a cancel
    button to cancel the task that is associated with this task monitor.
     
    
    By default the progress bar and progress icon (spinning globe) are visible.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, includeTextField: typing.Union[jpype.JBoolean, bool], includeCancelButton: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param jpype.JBoolean or bool includeTextField: if true, the dialog can display a status progressMessage with progress details
        :param jpype.JBoolean or bool includeCancelButton: if true, a cancel button will be displayed
        """

    def isIndeterminate(self) -> bool:
        """
        Returns true if :meth:`setIndeterminate(boolean) <.setIndeterminate>` with a value of ``true`` has
        been called.
        
        :return: true if :meth:`setIndeterminate(boolean) <.setIndeterminate>` with a value of ``true`` has
        been called.
        :rtype: bool
        """

    def reset(self):
        """
        Reset this monitor so that it can be reused
        """

    def setCancelButtonVisibility(self, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Set the visibility of the cancel button
        
        :param jpype.JBoolean or bool visible: if true, show the cancel button; false otherwise
        """

    def setIndeterminate(self, indeterminate: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the ``indeterminate`` property of the progress bar,
        which determines whether the progress bar is in determinate
        or indeterminate mode.
         
        
        An indeterminate progress bar continuously displays animation
        indicating that an operation of unknown length is occurring.
        By default, this property is ``false``.
        Some look and feels might not support indeterminate progress bars;
        they will ignore this property.
        
        
        .. seealso::
        
            | :obj:`JProgressBar`
        """

    def setTaskName(self, name: typing.Union[java.lang.String, str]):
        """
        Set the name of the task; the name shows up in the tool tip for
        the cancel button.
        
        :param java.lang.String or str name: the name of the task
        """

    def showProgress(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether the progress bar should be visible
        
        :param jpype.JBoolean or bool show: true if the progress bar should be visible
        """

    def showProgressIcon(self, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the visibility of the progress icon
        
        :param jpype.JBoolean or bool visible: if true, display the progress icon
        """

    @property
    def indeterminate(self) -> jpype.JBoolean:
        ...

    @indeterminate.setter
    def indeterminate(self, value: jpype.JBoolean):
        ...


@typing.type_check_only
class BasicTaskMonitor(TaskMonitor):
    """
    A task monitor that tracks all monitor state, but is not attached to any UI component
     
     
    **Synchronization Policy**:
    
    We wish for this class to be performant.    Thus, we do not synchronize the methods of this
    class, nor do we make the values thread visible via ``volatile`` or by any of 
    the Java concurrent structures (e.g., :obj:`AtomicBoolean`).   In order to keep the values of
    this class's fields update-to-date, we have chosen to synchronize the package-level client of
    this class.  **If this class is ever made public, then most of the methods herein need to 
    be synchronized to prevent race conditions and to provide visibility.**
    """

    class_: typing.ClassVar[java.lang.Class]


class CachingLoader(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def clear(self):
        ...

    def get(self, monitor: TaskMonitor) -> T:
        ...


class ChompingBitsAnimationPanel(javax.swing.JPanel):
    """
    Panel that displays an animation of the Ghidra dragon eating bits.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RunManager(java.lang.Object):
    """
    Helper class to execute a Runnable in a separate thread and provides a
    progress monitor component that is shown as needed. This class can support several
    different scheduling models described below.
     
    
    1) Only allow one runnable at any given time.  In this model, a new runnable will cause any running
    runnable to be cancelled and the new runnable will begin running. Because of this, there will
    never be any runnables waiting in the queue. Use the :meth:`runNow(MonitoredRunnable, String) <.runNow>` 
    method to get this behavior.
     
    
    2) Allow one running runnable and one pending runnable.  In this mode, any running runnable will be
    allowed to complete, but any currently pending runnable will be replaced by the new runnable. Use
    the :meth:`runNext(MonitoredRunnable, String) <.runNext>` method to get this behavior.
     
    
    3) Run all scheduled runnables in the order they are scheduled.  Use the 
    :meth:`runLater(MonitoredRunnable, String, int) <.runLater>` for this behavior.
     
    
    If the given runnable has Swing work to perform after the main Runnable.run() method completes
    (e.g., updating Swing components),
    the runnable should implement the :obj:`SwingRunnable` interface and perform this work in
    :meth:`SwingRunnable.swingRun(boolean) <SwingRunnable.swingRun>`.
     
    
    The progress monitor component, retrieved via :meth:`getMonitorComponent() <.getMonitorComponent>`, can be placed
    into a Swing widget.  This RunManager will show and hide this progress component as necessary
    when runnables are being run.
    
    
    .. seealso::
    
        | :obj:`SwingRunnable`
    """

    @typing.type_check_only
    class RunnerJob(ghidra.util.worker.Job):

        @typing.type_check_only
        class SwingRunner(java.lang.Runnable):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, cancelledWhileRunning: typing.Union[jpype.JBoolean, bool]):
                ...


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, listener: TaskListener):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultComponent: java.awt.Component):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultComponent: java.awt.Component, listener: TaskListener):
        ...

    def cancelAllRunnables(self):
        """
        A convenience method to cancel the any currently running job and any scheduled jobs.  Note:
        this method does not block or wait for the currently running job to finish.
        """

    def dispose(self):
        ...

    def getMonitorComponent(self) -> javax.swing.JComponent:
        ...

    def isInProgress(self) -> bool:
        ...

    def runLater(self, runnable: MonitoredRunnable, taskName: typing.Union[java.lang.String, str], showProgressDelay: typing.Union[jpype.JInt, int]):
        """
        Schedules this runnable to be run after all runnables currently queued.
         
        
        This method differs from the :meth:`runNow(MonitoredRunnable, String, int) <.runNow>` methods in that it will
        not cancel any currently running jobs.  This allows you to add new jobs to this run
        manager, which lets them queue up. See header docs for details.
        
        :param MonitoredRunnable runnable: The runnable to run
        :param java.lang.String or str taskName: The name of the task to run
        :param jpype.JInt or int showProgressDelay: The amount of time to wait before showing a progress monitor.
        """

    @typing.overload
    def runNext(self, runnable: MonitoredRunnable, taskName: typing.Union[java.lang.String, str]):
        """
        Allows any currently running runnable to finish, clears any queued runnables,
        and then queues the given runnable to be run after the current runnable finishes.
         
        
        This call will use the default :obj:`delay <.SHOW_PROGRESS_DELAY>` of
        500.
         
        
        See the class header for more info.
        
        :param MonitoredRunnable runnable: Runnable to execute
        :param java.lang.String or str taskName: name of runnable; may be null (this will appear in the progress panel)
        """

    @typing.overload
    def runNext(self, runnable: MonitoredRunnable, taskName: typing.Union[java.lang.String, str], showProgressDelay: typing.Union[jpype.JInt, int]):
        """
        Allows any currently running runnable to finish, clears any queued runnables,
        and then queues the given runnable to be run after the current runnable finishes.
         
        
        See the class header for more info.
        
        :param MonitoredRunnable runnable: Runnable to execute
        :param java.lang.String or str taskName: name of runnable; may be null (this will appear in the progress panel)
        :param jpype.JInt or int showProgressDelay: the amount of time (in milliseconds) before showing the progress
                panel
        """

    @typing.overload
    def runNow(self, runnable: MonitoredRunnable, taskName: typing.Union[java.lang.String, str]):
        """
        Cancels any currently running runnable, clears any queued runnables, and then runs the given
        runnable.
         
        
        See the class header for more info.
        
        :param MonitoredRunnable runnable: Runnable to execute
        :param java.lang.String or str taskName: name of runnable; may be null (this will appear in the progress panel)
        """

    @typing.overload
    def runNow(self, runnable: MonitoredRunnable, taskName: typing.Union[java.lang.String, str], showProgressDelay: typing.Union[jpype.JInt, int]):
        """
        Cancels any currently running runnable, clears any queued runnables, and then runs the given
        runnable.
         
        
        See the class header for more info.
        
        :param MonitoredRunnable runnable: Runnable to execute
        :param java.lang.String or str taskName: name of runnable; may be null (this will appear in the progress panel)
        :param jpype.JInt or int showProgressDelay: the amount of time (in milliseconds) before showing the progress
                panel
        """

    def showCancelButton(self, showCancel: typing.Union[jpype.JBoolean, bool]):
        """
        Show the cancel button according to the showCancel parameter.
        
        :param jpype.JBoolean or bool showCancel: true means to show the cancel button
        """

    def showProgressBar(self, showProgress: typing.Union[jpype.JBoolean, bool]):
        """
        Show the progress bar according to the showProgress parameter.
        
        :param jpype.JBoolean or bool showProgress: true means to show the progress bar
        """

    def showProgressIcon(self, showIcon: typing.Union[jpype.JBoolean, bool]):
        """
        Show the progress icon according to the showIcon parameter.
        
        :param jpype.JBoolean or bool showIcon: true means to show the progress icon
        """

    def waitForNotBusy(self, maxWaitMillis: typing.Union[jpype.JInt, int]):
        ...

    @property
    def inProgress(self) -> jpype.JBoolean:
        ...

    @property
    def monitorComponent(self) -> javax.swing.JComponent:
        ...


class TaskDialog(docking.DialogComponentProvider, TaskMonitor):
    """
    Dialog that is displayed to show activity for a Task that is running outside of the
    Swing Thread.   This dialog uses a delay before showing in order to give the background task
    thread a chance to finish.  This prevents a flashing dialog for tasks that finish before the
    delay time period.
    
     
    Implementation note:
    if this class is constructed with a ``hasProgress`` value of ``false``,
    then an activity component will be shown, not a progress monitor.   Any calls to update
    progress will not affect the display.   However, the display can be converted to use progress
    by first calling :meth:`setIndeterminate(boolean) <.setIndeterminate>` with a ``false`` value and then calling
    :meth:`initialize(long) <.initialize>`.    Once this has happened, this dialog will no longer use the
    activity display--the progress bar is in effect for the duration of this dialog's usage.
    
     
    This dialog can be toggled between indeterminate mode and progress mode via calls to
    :meth:`setIndeterminate(boolean) <.setIndeterminate>`.
     
     
    **API Usage Note: **If this dialog is used outside of the task API, then the client must
    be sure to call :meth:`taskProcessed() <.taskProcessed>`** from the background thread performing the work**.
    Otherwise, this dialog will always wait for the ``delay`` amount of time for the background
    thread to finish.  This happens since the default completed notification mechanism is performed
    on the Swing thread.   If a client has triggered blocking on the Swing thread, then the
    notification on the Swing thread must wait, causing the full delay to take place.   Calling
    :meth:`taskProcessed() <.taskProcessed>` from the background thread allows the dialog to get notified before the
    ``delay`` period has expired.  The blocking issue only exists with a non-0 ``delay``
    value.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_WIDTH: typing.Final = 275

    @typing.overload
    def __init__(self, task: Task):
        """
        Constructor
        
        :param Task task: the Task that this dialog will be associated with
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], canCancel: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool], hasProgress: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param java.lang.String or str title: title for the dialog
        :param jpype.JBoolean or bool canCancel: true if the task can be canceled
        :param jpype.JBoolean or bool isModal: true if the dialog should be modal
        :param jpype.JBoolean or bool hasProgress: true if the dialog should show a progress bar
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], canCancel: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool], hasProgress: typing.Union[jpype.JBoolean, bool], finished: java.util.concurrent.CountDownLatch):
        """
        Constructor
        
        :param java.lang.String or str title: title for the dialog
        :param jpype.JBoolean or bool canCancel: true if the task can be canceled
        :param jpype.JBoolean or bool isModal: true if the dialog should be modal
        :param jpype.JBoolean or bool hasProgress: true if the dialog should show a progress bar
        :param java.util.concurrent.CountDownLatch finished: the finished latch used by the background thread to notify of completion
        """

    def isCompleted(self) -> bool:
        """
        Returns true if this dialog's task has completed normally or been cancelled
        
        :return: true if this dialog's task has completed normally or been cancelled
        :rtype: bool
        """

    def show(self, delay: typing.Union[jpype.JInt, int]):
        """
        Shows the dialog window centered on the parent window. Dialog display is delayed if delay
        greater than zero.
        
        :param jpype.JInt or int delay: number of milliseconds to delay displaying of the task dialog.  If the delay is
        greater than :obj:`.MAX_DELAY`, then the delay will be :obj:`.MAX_DELAY`;
        :raises IllegalArgumentException: if ``delay`` is negative
        """

    def taskProcessed(self):
        """
        Called after the task has been executed or when the task is cancelled
        """

    def wasShown(self) -> bool:
        """
        Returns true if this dialog was ever made visible
        
        :return: true if shown
        :rtype: bool
        """

    @property
    def completed(self) -> jpype.JBoolean:
        ...


class TaskLauncher(java.lang.Object):
    """
    Class to initiate a Task in a new Thread, and to show a progress dialog that indicates
    activity **if the task takes too long**.  The progress dialog will show an 
    animation in the event that the task of this class cannot show progress.
    
     
    For complete control of how this class functions, use
    :meth:`TaskLauncher(Task, Component, int, int) <.TaskLauncher>`.  Alternatively, for simpler uses,
    see one of the many static convenience methods.
     
     
    
    .. _modal_usage:
    
    **Modal Usage**
    
    Most clients of this class should not be concerned with where 
    the dialog used by this class will appear.  By default, it will be shown over 
    the active window, which is the desired
    behavior for most uses.  If you should need a dialog to appear over a non-active window,
    then either specify that window, or a child component of that window, by calling a
    constructor that takes in a :obj:`Component`.  Further, if you task is modal, then the
    progress dialog should always be shown over the active window so that users understand that
    their UI is blocked.  In this case, there is no need to specify a component over which to
    show the dialog.
    
     
    An alternative to using this class is to use the :obj:`TaskBuilder`, which offers a
    more *Fluent API* approach for your tasking needs.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, task: Task):
        """
        Constructor for TaskLauncher
        
         
        This constructor assumes that if a progress dialog is needed, then it should appear
        over the active window.  If you should need a dialog to appear over a non-active window,
        then either specify that window or a component within that window by calling a
        constructor that takes in a :obj:`Component`.
        
        :param Task task: task to run in another thread (other than the Swing Thread)
        """

    @typing.overload
    def __init__(self, task: Task, parent: java.awt.Component):
        """
        Constructor for TaskLauncher
        
         
        See `notes on modal usage <modal_usage_>`_
        
        :param Task task: task to run in another thread (other than the Swing Thread)
        :param java.awt.Component parent: component whose window to use to parent the dialog.
        """

    @typing.overload
    def __init__(self, task: Task, parent: java.awt.Component, delayMs: typing.Union[jpype.JInt, int]):
        """
        Construct a new TaskLauncher
        
         
        See `notes on modal usage <modal_usage_>`_
        
        :param Task task: task to run in another thread (other than the Swing Thread)
        :param java.awt.Component parent: component whose window to use to parent the dialog; null centers the task
                dialog over the current window
        :param jpype.JInt or int delayMs: number of milliseconds to delay until the task monitor is displayed
        """

    @typing.overload
    def __init__(self, task: Task, parent: java.awt.Component, delayMs: typing.Union[jpype.JInt, int], dialogWidth: typing.Union[jpype.JInt, int]):
        """
        Construct a new TaskLauncher
        
         
        See `notes on modal usage <modal_usage_>`_
        
        :param Task task: task to run in another thread (other than the Swing Thread)
        :param java.awt.Component parent: component whose window to use to parent the dialog; null centers the task
                dialog over the current window
        :param jpype.JInt or int delayMs: number of milliseconds to delay until the task monitor is displayed
        :param jpype.JInt or int dialogWidth: The preferred width of the dialog (this allows clients to make a wider
                dialog, which better shows long messages).
        """

    @staticmethod
    def launch(task: T) -> T:
        """
        Directly launches a :obj:`Task` via a new :obj:`TaskLauncher` instance, with
        a progress dialog.
         
        
        See also :meth:`TaskLauncher.TaskLauncher(Task, Component) <TaskLauncher.TaskLauncher>`
        
        :param T task: :obj:`Task` to run in another thread
        :return: the original :obj:`Task` (for chaining)
        :rtype: T
        """

    @staticmethod
    @typing.overload
    def launchModal(title: typing.Union[java.lang.String, str], runnable: MonitoredRunnable):
        """
        A convenience method to directly run a :obj:`MonitoredRunnable` in a separate
        thread as a :obj:`Task`, displaying a **modal** progress dialog.
        ``TaskLauncher.launchModal("My task",   null, // parent   monitor -> { while (!monitor.isCanceled()) { longRunningWork(); } });``
        
         
        Note: the task created by this call will be both cancellable and have progress.  If
        you task cannot be cancelled or does not have progress, then do not use this
        convenience method, but rather call one of the constructors of this class or
        :meth:`launchModal(String, MonitoredRunnable) <.launchModal>`.
        
        :param java.lang.String or str title: name of the task thread that will be executing this task.
        :param MonitoredRunnable runnable: :obj:`MonitoredRunnable` that takes a :obj:`TaskMonitor`.
        """

    @staticmethod
    @typing.overload
    def launchModal(title: typing.Union[java.lang.String, str], runnable: java.lang.Runnable):
        """
        A convenience method to directly run a :obj:`Runnable` in a separate
        thread as a :obj:`Task`, displaying a non-modal progress dialog.
        
         
        This modal will be launched immediately, without delay.  Typically the launcher will
        delay showing the modal dialog in order to prevent the dialog from being shown, just
        to have it immediately go away.  If you desire this default behavior, then do not use
        this convenience method.
        
        ``TaskLauncher.launchModal("My task",  monitor -> { foo(); });``
        
         
        Note: the task created by this call will not be cancellable nor have progress.  If
        you need either of these behaviors, the do not use this
        convenience method, but rather call one of the constructors of this class.
        
        :param java.lang.String or str title: name of the task thread that will be executing this task.
        :param java.lang.Runnable runnable: :obj:`Runnable` to be called in a background thread
        """

    @staticmethod
    def launchNonModal(title: typing.Union[java.lang.String, str], runnable: MonitoredRunnable):
        """
        A convenience method to directly run a :obj:`MonitoredRunnable` in a separate
        thread as a :obj:`Task`, displaying a non-modal progress dialog.
        ``TaskLauncher.launchNonModal("My task",  null, // parent  monitor -> { while (!monitor.isCanceled()) { longRunningWork(); } });``
        
         
        Note: the task created by this call will be both cancellable and have progress.  If
        you task cannot be cancelled or does not have progress, then do not use this
        convenience method, but rather call one of the constructors of this class.
        
         
        See `notes on non-modal usage <modal_usage_>`_
        
        :param java.lang.String or str title: name of the task thread that will be executing this task.
        :param MonitoredRunnable runnable: :obj:`MonitoredRunnable` that takes a :obj:`TaskMonitor`.
        """


class HourglassAnimationPanel(javax.swing.JPanel):
    """
    Panel that displays an animation of a spinning hourglass
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CachingSwingWorker(CachingLoader[T], typing.Generic[T]):
    """
    Class for managing the creation of some slow loading object that may be used by multiple threads,
    including the Swing thread.  Further, repeated calls to this object will used the
    cached value.
     
    
    The basic uses cases are:
     
    1. 
    Call:meth:`get(TaskMonitor) <.get>`from the Swing thread - this will block the Swing thread,
        showing a modal dialog, as needed.
    
    2. 
    Call:meth:`get(TaskMonitor) <.get>`from a non-Swing thread - this will block the calling
        thread, with no effect on the UI.
    
    3. Call :meth:`startLoading() <.startLoading>` - this will trigger this worker to load in the background
        without blocking the calling thread.
    
    4. 
    Call:meth:`getCachedValue() <.getCachedValue>` - this is a way to see if the value has been loaded
        without blocking the current thread.
    
    5. 
    Override:meth:`done() <.done>` - this method will be called when the initial loading
        is finished.
    """

    @typing.type_check_only
    class SwingWorkerTaskDialog(TaskDialog):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SwingWorkerImpl(javax.swing.SwingWorker[T, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class WorkerTaskMonitor(TaskMonitorAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def add(self, monitor: TaskMonitor):
            ...

        def clear(self):
            ...

        def setBlockingMonitor(self, monitor: TaskMonitor):
            ...


    @typing.type_check_only
    class SwingWorkerCompletionWaiter(java.beans.PropertyChangeListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dialog: docking.DialogComponentProvider):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], hasProgress: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new CachingSwingWorker
        
        :param java.lang.String or str name: the name of worker. (Displayed in the progress dialog)
        :param jpype.JBoolean or bool hasProgress: true if the dialog should show progress or be indeterminate.
        """

    def cancel(self):
        """
        Cancels this swing worker
        """

    def clear(self):
        """
        Clears the cached value for the object causing it to be recreated on the next call to get()
        """

    def done(self):
        """
        A method for clients to use as a callback for completion.  This method will be called in
        the Swing thread, after the value has been set.
        """

    def get(self, monitor: TaskMonitor) -> T:
        """
        Returns the object that this class is managing/caching.  It will return the object if it is
        already created or it will block until the object can be created.  If called from the Swing
        thread, it will also launch a modal progress dialog while waiting for the object to be
        created.
        
        :param TaskMonitor monitor: the monitor (may be null)
        :return: the object that this class is managing/caching
        :rtype: T
        
        .. seealso::
        
            | :obj:`.getCachedValue()`
        """

    def getCachedValue(self) -> T:
        """
        Returns the value only if it is cached, otherwise return null.
        
        :return: the value only if it is cached, otherwise return null.
        :rtype: T
        """

    def setTaskDialogDelay(self, delay: typing.Union[jpype.JInt, int]):
        """
        Sets the initial delay before showing a progress dialog.  The default is 100ms.
        
        :param jpype.JInt or int delay: the delay to wait before displaying a progress dialog.
        """

    def startLoading(self):
        """
        Allows clients to start this worker loading without blocking.
        """

    @property
    def cachedValue(self) -> T:
        ...


@typing.type_check_only
class BackgroundThreadTaskLauncher(java.lang.Object):
    """
    Helper class to launch the given task in a background thread  This helper will not 
    show a task dialog. 
     
     
    This class is useful when you want to run the task and use a monitor that is embedded 
    in some other component.
     
     
    See :obj:`TaskLauncher`.
    """

    class_: typing.ClassVar[java.lang.Class]


class TaskBuilder(java.lang.Object):
    """
    A builder object that allows clients to launch tasks in the background, with a progress
    dialog representing the task.
    
     
    Using this class obviates the need for clients to create full class objects to implement
    the :obj:`Task` interface, which means less boiler-plate code.
    
     
    An example of usage:
     
    MonitoredRunnable r =    monitor -> doWork(parameter, monitor);new TaskBuilder("Task Title", r)   .setHasProgress(true)   .setCanCancel(true)   .setStatusTextAlignment(SwingConstants.LEADING)   .launchModal();
    
    Or,
    
     
    TaskBuilder.withRunnable(monitor -> doWork(parameter, monitor))    .setTitle("Task Title")    .setHasProgress(true)    .setCanCancel(true)    .setStatusTextAlignment(SwingConstants.LEADING)    .launchModal();
    
    Or,
    
     
    TaskBuilder.withTask(new AwesomeTask(awesomeStuff)).launchModal();
     
    
    Or,
    
     
    :meth:`TaskLauncher.launch <TaskLauncher.launch>`(new AwesomeTask(awesomeStuff));
     
    
    
     
    Note: this class will check to see if it is in a headless environment before launching
    its task.  This makes it safe to use this class in headed or headless environments.
    """

    @typing.type_check_only
    class TaskBuilderTask(Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], runnable: MonitoredRunnable):
        """
        Constructor
        
        :param java.lang.String or str title: the required title for your task.  This will appear as the title of the
                task dialog
        :param MonitoredRunnable runnable: the runnable that will be called when the task is run
        """

    def launchInBackground(self, monitor: TaskMonitor):
        """
        Runs the task in a background thread with the given monitor that cannot be null.  This
        is a special case for clients that already have a task monitor widget in their UI and
        they wish to let it show the progress of the given task while not blocking the Swing
        thread.
        
        :param TaskMonitor monitor: the task monitor; may not be null
        """

    def launchModal(self):
        """
        Launches the task built by this builder, using a blocking modal dialog.  The task will
        be run in the current thread if in a headless environment.
        """

    def launchNonModal(self):
        """
        Launches the task built by this builder, using a non-blocking dialog.  The task will
        be run in the current thread if in a headless environment.
        """

    def setCanCancel(self, canCancel: typing.Union[jpype.JBoolean, bool]) -> TaskBuilder:
        """
        Sets whether the task can be cancelled.  The default is ``true``.
        
        :param jpype.JBoolean or bool canCancel: true if the task can be cancelled.
        :return: this builder
        :rtype: TaskBuilder
        """

    def setDialogWidth(self, width: typing.Union[jpype.JInt, int]) -> TaskBuilder:
        """
        The desired width of the dialog.  The default is :obj:`TaskDialog.DEFAULT_WIDTH`.
        
        :param jpype.JInt or int width: the width
        :return: this builder
        :rtype: TaskBuilder
        """

    def setHasProgress(self, hasProgress: typing.Union[jpype.JBoolean, bool]) -> TaskBuilder:
        """
        Sets whether this task reports progress.   The default is ``true``.
        
        :param jpype.JBoolean or bool hasProgress: true if the task reports progress
        :return: this builder
        :rtype: TaskBuilder
        """

    def setLaunchDelay(self, delay: typing.Union[jpype.JInt, int]) -> TaskBuilder:
        """
        Sets the amount of time that will pass before showing the dialog.  The default is
        :obj:`TaskLauncher.INITIAL_DELAY_MS` for non-modal tasks and
        :obj:`TaskLauncher.INITIAL_MODAL_DELAY_MS` for modal tasks.
        
        :param jpype.JInt or int delay: the delay time
        :return: this builder
        :rtype: TaskBuilder
        """

    def setParent(self, parent: java.awt.Component) -> TaskBuilder:
        """
        Sets the component over which the task dialog will be shown.  The default is ``null``,
        which shows the dialog over the active window.
        
        :param java.awt.Component parent: the parent
        :return: this builder
        :rtype: TaskBuilder
        """

    def setStatusTextAlignment(self, alignment: typing.Union[jpype.JInt, int]) -> TaskBuilder:
        """
        Sets the horizontal text alignment of messages shown in the task dialog.  The
        default is :obj:`SwingConstants.CENTER`.  Valid values are :obj:`SwingConstants`
        LEADING, CENTER and TRAILING.
        
        :param jpype.JInt or int alignment: the alignment
        :return: this builder
        :rtype: TaskBuilder
        """

    def setTitle(self, title: typing.Union[java.lang.String, str]) -> TaskBuilder:
        """
        Sets the title of this task.  The title must be set before calling any of the
        ``launch`` methods.
        
        :param java.lang.String or str title: the title
        :return: this builder
        :rtype: TaskBuilder
        """

    @staticmethod
    def withRunnable(r: MonitoredRunnable) -> TaskBuilder:
        """
        A convenience method to start a builder using the given runnable.  After calling this
        method you are still required to call :meth:`setTitle(String) <.setTitle>`.
        
         
        This method allows for a more attractive fluent API usage than does the constructor
        (see the javadoc header).
        
        :param MonitoredRunnable r: the runnable
        :return: this builder
        :rtype: TaskBuilder
        """

    @staticmethod
    def withTask(t: Task) -> TaskBuilder:
        """
        A convenience method to start a builder using the given task.  The
        :meth:`title <.setTitle>` of the task will be the value of
        :meth:`Task.getTaskTitle() <Task.getTaskTitle>`.
        
         
        This method allows for a more attractive fluent API usage than does the constructor
        (see the javadoc header).
        
        :param Task t: the task
        :return: this builder
        :rtype: TaskBuilder
        """


class DummyCancellableTaskMonitor(TaskMonitorAdapter):
    """
    A :obj:`TaskMonitorAdapter` that is cancellable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SwingRunnable(MonitoredRunnable):
    """
    Runnable that has a method that may need to be run in the Swing AWT thread. 
    Pass a SwingRunnable to the RunManager if follow on work needs to be done
    after the ``run()`` method completes.
    
    
    .. seealso::
    
        | :obj:`RunManager.runNext(MonitoredRunnable, String)`
    
        | :obj:`RunManager.runNext(MonitoredRunnable, String, int)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def swingRun(self, isCancelled: typing.Union[jpype.JBoolean, bool]):
        """
        Callback on the swing thread.
        """


class CompoundTask(Task):
    """
    Combines multiple Tasks into a single task.  All tasks should have the same cancel, progress, and modality.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tasks: jpype.JArray[Task], title: typing.Union[java.lang.String, str]):
        """
        Create a CompoundTask from an array of tasks.
        
        :param jpype.JArray[Task] tasks: the array of tasks.
        :param java.lang.String or str title: the title for this task.
        """

    def run(self, monitor: TaskMonitor):
        """
        The task run method
        
        :raises CancelledException: if any task is cancelled
        """


class SwingUpdateManager(AbstractSwingUpdateManager):
    """
    A class to allow clients to buffer events.  UI components may receive numbers events to make
    changes to their underlying data model.  Further, for many of these clients, it is sufficient
    to perform one update to capture all of the changes.  In this scenario, the client can use this
    class to keep pushing off internal updates until: 1) the flurry of events has settled down, or
    2) some specified amount of time has expired.
     
    
    The various methods dictate when the client will get a callback:
     
    * :meth:`update() <.update>` - if this is the first call to update, then do the work
    immediately; otherwise, buffer the update request until the
    timeout has expired.
    * :meth:`updateNow() <.updateNow>` - perform the callback now.
    * :meth:`updateLater() <.updateLater>` - buffer the update request until the timeout has expired.
    * Non-blocking update now - this is a conceptual use-case, where the client wishes to perform an
    immediate update, but not during the current Swing event.  To achieve
    this, you could call something like:
        SwingUtilities.invokeLater(() -> updateManager.updateNow());
    
    
     
    This class is safe to use in a multi-threaded environment.   State variables are guarded
    via synchronization on this object.   The Swing thread is used to perform updates, which
    guarantees that only one update will happen at a time.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, r: java.lang.Runnable):
        """
        Constructs a new SwingUpdateManager with default values for min and max delay.  See
        :obj:`.DEFAULT_MIN_DELAY` and 30000.
        
        :param java.lang.Runnable r: the runnable that performs the client work.
        """

    @typing.overload
    def __init__(self, minDelay: typing.Union[jpype.JInt, int], r: java.lang.Runnable):
        """
        Constructs a new SwingUpdateManager
         
        
        **Note: **The ``minDelay`` will always be at least :obj:`.MIN_DELAY_FLOOR`, 
        regardless of the given value.
        
        :param jpype.JInt or int minDelay: the minimum number of milliseconds to wait once the event stream stops
                        coming in before actually updating the screen.
        :param java.lang.Runnable r: the runnable that performs the client work.
        """

    @typing.overload
    def __init__(self, minDelay: typing.Union[jpype.JInt, int], maxDelay: typing.Union[jpype.JInt, int], r: java.lang.Runnable):
        """
        Constructs a new SwingUpdateManager
         
        
        **Note: **The ``minDelay`` will always be at least :obj:`.MIN_DELAY_FLOOR`, 
        regardless of the given value.
        
        :param jpype.JInt or int minDelay: the minimum number of milliseconds to wait once the event stream stops
                        coming in before actually updating the screen.
        :param jpype.JInt or int maxDelay: the maximum amount of time to wait between gui updates.
        :param java.lang.Runnable r: the runnable that performs the client work.
        """

    @typing.overload
    def __init__(self, minDelay: typing.Union[jpype.JInt, int], maxDelay: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], r: java.lang.Runnable):
        """
        Constructs a new SwingUpdateManager
         
        
        **Note: **The ``minDelay`` will always be at least :obj:`.MIN_DELAY_FLOOR`, regardless of
        the given value.
        
        :param jpype.JInt or int minDelay: the minimum number of milliseconds to wait once the event stream stops
                        coming in before actually updating the screen.
        :param jpype.JInt or int maxDelay: the maximum amount of time to wait between gui updates.
        :param java.lang.String or str name: The name of this update manager; this allows for selective trace logging
        :param java.lang.Runnable r: the runnable that performs the client work.
        """

    def update(self):
        """
        Signals to perform an update.  See the class header for the usage of the various
        update methods.
        """

    def updateLater(self):
        """
        Signals to perform an update.  See the class header for the usage of the various
        update methods.
        """

    def updateNow(self):
        """
        Signals to perform an update.  See the class header for the usage of the various
        update methods.
        """


class TaskListener(java.lang.Object):
    """
    Listener that is notified when a thread completes its task.
    """

    class_: typing.ClassVar[java.lang.Class]

    def taskCancelled(self, task: Task):
        """
        Notification that the task was canceled.
        
        :param Task task: the task that was running and was canceled
        """

    def taskCompleted(self, task: Task):
        """
        Notification that the task completed.
        
        :param Task task: the task that was running and is now completed
        """


class Task(MonitoredRunnable):
    """
    Base class for Tasks to be run in separate threads
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str]):
        """
        Creates new Task.
        
        :param java.lang.String or str title: the title associated with the task
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], canCancel: typing.Union[jpype.JBoolean, bool], hasProgress: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new Task.
        
        :param java.lang.String or str title: title the title associated with the task
        :param jpype.JBoolean or bool canCancel: true means that the user can cancel the task
        :param jpype.JBoolean or bool hasProgress: true means that the dialog should show a
        progress indicator
        :param jpype.JBoolean or bool isModal: true means that the dialog is modal and the task has to
        complete or be canceled before any other action can occur
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], canCancel: typing.Union[jpype.JBoolean, bool], hasProgress: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool], waitForTaskCompleted: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new Task.
        
        :param java.lang.String or str title: title the title associated with the task
        :param jpype.JBoolean or bool canCancel: true means that the user can cancel the task
        :param jpype.JBoolean or bool hasProgress: true means that the dialog should show a
        progress indicator
        :param jpype.JBoolean or bool isModal: true means that the dialog is modal and the task has to
        complete or be canceled before any other action can occur
        :param jpype.JBoolean or bool waitForTaskCompleted: true causes the running thread to block until the finish or
                cancelled callback has completed on the swing thread.  Note: passing true
                only makes sense if the task is modal.
        """

    def addTaskListener(self, listener: TaskListener):
        """
        Sets the task listener on this task.  It is a programming error to call this method more
        than once or to call this method if a listener was passed into the constructor of this class.
        
        :param TaskListener listener: the listener
        """

    def canCancel(self) -> bool:
        """
        Returns true if the task can be canceled.
        
        :return: boolean true if the user can cancel the task
        :rtype: bool
        """

    def cancel(self):
        ...

    def getStatusTextAlignment(self) -> int:
        """
        Returns the alignment of the text displayed in the modal dialog.  The default is
        :obj:`SwingConstants.CENTER`.   For status updates where the initial portion of the
        text does not change, :obj:`SwingConstants.LEADING` is recommended.  To change the
        default value, simply override this method and return one of :obj:`SwingConstants`
        CENTER, LEADING or TRAILING.
        
        :return: the alignment of the text displayed
        :rtype: int
        """

    def getTaskTitle(self) -> str:
        """
        Get the title associated with the task
        
        :return: String title shown in the dialog
        :rtype: str
        """

    def getWaitForTaskCompleted(self) -> bool:
        """
        Returns the value of the 'wait for completed task' boolean that was passed into this class
        
        :return: the value
        :rtype: bool
        """

    def hasProgress(self) -> bool:
        """
        Return true if the task has a progress indicator.
        
        :return: boolean true if the task shows progress
        :rtype: bool
        """

    def isCancelled(self) -> bool:
        ...

    def isModal(self) -> bool:
        """
        Returns true if the dialog associated with the task is modal.
        
        :return: boolean true if the associated dialog is modal
        :rtype: bool
        """

    def monitoredRun(self, monitor: TaskMonitor):
        """
        When an object implementing interface ``Runnable`` is used to create a thread,
        starting the thread causes the object's ``run`` method to be called in that
        separately executing thread.
        
        :param TaskMonitor monitor: the task monitor
        """

    def run(self, monitor: TaskMonitor):
        """
        This is the method that will be called to do the work
        
         
        Note: The run(TaskMonitor) method should not make any calls directly
        on Swing components, as these calls are not thread safe. Place Swing
        calls in a Runnable, then call :meth:`Swing.runLater(Runnable) <Swing.runLater>` or
        :meth:`Swing.runNow(Runnable) <Swing.runNow>`to schedule the Runnable inside of
        the AWT Event Thread.
        
        :param TaskMonitor monitor: The TaskMonitor that will monitor the executing Task
        :raises CancelledException: if the task is cancelled.  Subclasses can trigger this exception
                                    by calling :meth:`TaskMonitor.checkCancelled() <TaskMonitor.checkCancelled>`.  This allows
                                    them to break out of the current work stack.
        """

    def setHasProgress(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this task to have progress or not.  Note: changing this value after launching the
        task will have no effect.
        
        :param jpype.JBoolean or bool b: true to show progress, false otherwise.
        """

    @property
    def statusTextAlignment(self) -> jpype.JInt:
        ...

    @property
    def waitForTaskCompleted(self) -> jpype.JBoolean:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def taskTitle(self) -> java.lang.String:
        ...

    @property
    def modal(self) -> jpype.JBoolean:
        ...


class AbstractSwingUpdateManager(java.lang.Object):
    """
    A base class to allow clients to buffer events.  UI components may receive numbers events to make
    changes to their underlying data model.  Further, for many of these clients, it is sufficient
    to perform one update to capture all of the changes.  In this scenario, the client can use this
    class to keep pushing off internal updates until: 1) the flurry of events has settled down, or
    2) some specified amount of time has expired.
     
    
    The various methods dictate when the client will get a callback:
     
    * :meth:`update() <.update>` - if this is the first call to update, then do the work
    immediately; otherwise, buffer the update request until the
    timeout has expired.
    * :meth:`updateNow() <.updateNow>` - perform the callback now.
    * :meth:`updateLater() <.updateLater>` - buffer the update request until the timeout has expired.
    * Non-blocking update now - this is a conceptual use-case, where the client wishes to perform an
    immediate update, but not during the current Swing event.  To achieve
    this, you could call something like:
        SwingUtilities.invokeLater(() -> updateManager.updateNow());
    
    
     
    This class is safe to use in a multi-threaded environment.   State variables are guarded
    via synchronization on this object.   The Swing thread is used to perform updates, which
    guarantees that only one update will happen at a time.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_MAX_DELAY: typing.Final = 30000
    DEFAULT_MIN_DELAY: typing.Final = 250

    def dispose(self):
        ...

    def flush(self):
        """
        Causes this run manager to run if it has a pending update
        """

    def hasPendingUpdates(self) -> bool:
        """
        Returns true if there is a pending request that hasn't started yet.  Any currently
        executing requests will not affect this call.
        
        :return: true if there is a pending request that hasn't started yet.
        :rtype: bool
        """

    def isBusy(self) -> bool:
        """
        Returns true if any work is being performed or if there is buffered work
        
        :return: true if any work is being performed or if there is buffered work
        :rtype: bool
        """

    def isDisposed(self) -> bool:
        ...

    def stop(self):
        """
        Signals to stop any buffered work.   This will not stop any in-progress work.
        """

    def toStringDebug(self) -> str:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...


class BufferedSwingRunner(AbstractSwingUpdateManager):
    """
    A class that run the client's runnable on the Swing thread.  Repeated requests will get buffered
    until the max delay is reached.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, minDelay: typing.Union[jpype.JInt, int], maxDelay: typing.Union[jpype.JInt, int]):
        """
        Constructs a new SwingUpdateManager
         
        
        **Note: **The ``minDelay`` will always be at least :obj:`.MIN_DELAY_FLOOR`, 
        regardless of the given value.
        
        :param jpype.JInt or int minDelay: the minimum number of milliseconds to wait once the event stream stops
                        coming in before actually updating the screen.
        :param jpype.JInt or int maxDelay: the maximum amount of time to wait between gui updates.
        """

    @typing.overload
    def __init__(self):
        ...

    def run(self, r: java.lang.Runnable):
        """
        Runs the given runnable.  If this is the first call to ``run``, then do the work
        immediately; otherwise, buffer the request until the timeout has expired.
         
         
        See the header of :obj:`AbstractSwingUpdateManager` for details on the update process.
        
        :param java.lang.Runnable r: the task to run on the Swing thread
        """

    def runLater(self, r: java.lang.Runnable):
        """
        Runs the given runnable later, buffering the request until the timeout has expired.
         
         
        See the header of :obj:`AbstractSwingUpdateManager` for details on the update process.
        
        :param java.lang.Runnable r: the task to run on the Swing thread
        """


class UnknownProgressWrappingTaskMonitor(WrappingTaskMonitor):
    """
    A class that is meant to wrap a :obj:`TaskMonitor` when you do not know the maximum value
    of the progress.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, delegate: TaskMonitor):
        ...

    @typing.overload
    def __init__(self, delegate: TaskMonitor, startMaximum: typing.Union[jpype.JLong, int]):
        ...


class TaskMonitorAdapter(TaskMonitor):
    """
    Implementation of :obj:`TaskMonitor` with most features stubbed out.
     
    
    This class supports cancelling and cancel listener notification.  Cancelling must be enabled
    via :meth:`setCancelEnabled(boolean) <.setCancelEnabled>`.
     
    
    Use :obj:`WrappingTaskMonitor` if you need to override an existing TaskMonitor 
    instance's behavior.
    """

    class_: typing.ClassVar[java.lang.Class]
    DUMMY_MONITOR: typing.Final[TaskMonitor]
    """
    Provides a static instance of ``TaskMonitorAdapter``
    which is a non-cancellable task monitor with no visual components.
    
    
    .. deprecated::
    
    use :obj:`TaskMonitor.DUMMY` instead
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, cancelEnabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def getMinimum(self) -> int:
        ...

    def setMinimum(self, min: typing.Union[jpype.JInt, int]):
        ...

    @property
    def minimum(self) -> jpype.JInt:
        ...

    @minimum.setter
    def minimum(self, value: jpype.JInt):
        ...


class WrappingTaskMonitor(TaskMonitor):
    """
    An implementation of the :obj:`TaskMonitor` interface that simply wraps a delegate task
    monitor.   This is useful for classes that wish to wrap a task monitor, changing behavior
    as needed by overriding a subset of methods.
     
     
    **Synchronization Policy**:
    
    We wish for this class to be performant.    Thus, we do not synchronize the methods of this
    class. The :meth:`setDelegate(TaskMonitor) <.setDelegate>` is synchronized to ensure thread visibility
    for the state of the delegate monitor. 
     
     
    When calling :meth:`setDelegate(TaskMonitor) <.setDelegate>` there is the potential for the values being
    transferred to become inconsistent with any new values being set.  We have decided that this
    does not much matter for the overall progress or the messages on the monitor.  However, most
    of the other setter methods could lead to bad behavior if they are inconsistent.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: TaskMonitor):
        """
        Constructor
        
        :param TaskMonitor delegate: the delegate task monitor
        """

    def setDelegate(self, newDelegate: TaskMonitor):
        """
        Sets the delegate of this wrapper to be the new value.  The new delegate will be 
        initialized with the current values of the existing delegate.
        
        :param TaskMonitor newDelegate: the new delegate
        """


class ConsoleTaskMonitor(TaskMonitorAdapter):
    """
    Handles monitor output to console
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TimeoutTaskMonitor(TaskMonitor):
    """
    A task monitor that allows clients the ability to specify a timeout after which this monitor
    will be cancelled.
     
     
    This monitor can wrap an existing monitor.
     
     
    You can call :meth:`setTimeoutListener(Callback) <.setTimeoutListener>` to get a notification that the monitor
    timed-out.  In order to prevent this from firing after your work is finished normally, call
    :meth:`finished() <.finished>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def didTimeout(self) -> bool:
        """
        Returns true if this monitor has timed-out
        
        :return: true if this monitor has timed-out
        :rtype: bool
        """

    def finished(self):
        ...

    def setTimeoutListener(self, timeoutCallback: utility.function.Callback):
        """
        Sets a callback function that will be called if the timeout is reached.
        
        :param utility.function.Callback timeoutCallback: the callback to call
        """

    @staticmethod
    @typing.overload
    def timeoutIn(timeout: typing.Union[jpype.JLong, int], timeUnit: java.util.concurrent.TimeUnit) -> TimeoutTaskMonitor:
        """
        Creates a timeout task monitor that will be cancelled after the specified timeout.
        
        :param jpype.JLong or int timeout: the timeout value
        :param java.util.concurrent.TimeUnit timeUnit: the timeout time unit
        :return: the newly created monitor
        :rtype: TimeoutTaskMonitor
        """

    @staticmethod
    @typing.overload
    def timeoutIn(timeout: typing.Union[jpype.JLong, int], timeUnit: java.util.concurrent.TimeUnit, monitor: TaskMonitor) -> TimeoutTaskMonitor:
        """
        Creates a timeout task monitor that will be cancelled after the specified timeout.  The
        created monitor wraps the given monitor, calling cancel on the given monitor when the
        timeout is reached.  This method allows you to use an existing monitor while adding
        the timeout feature.
        
        :param jpype.JLong or int timeout: the timeout value
        :param java.util.concurrent.TimeUnit timeUnit: the timeout time unit
        :param TaskMonitor monitor: the monitor to wrap
        :return: the newly created monitor
        :rtype: TimeoutTaskMonitor
        """


class CancelOnlyWrappingTaskMonitor(WrappingTaskMonitor):
    """
    A monitor that is designed for sub-tasks, where the outer task handles reporting messages and
    progress.  This class is really just for checking cancelled.
     
     
    This class wants the following methods related to cancelling to work normally:
     
    * isCancelled()
    * checkCancelled()
    * cancel()
    * addCancelledListener(CancelledListener)
    * removeCancelledListener(CancelledListener)
    * addIssueListener(IssueListener)
    * removeIssueListener(IssueListener)
    * isCancelEnabled()
            
    
        
    The rest of TaskMonitor should be stubbed out.  This means that if any methods are 
        added to the TaskMonitor interface, and subsequently implemented in this class's parent,
        then this class needs to override them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: TaskMonitor):
        ...


class BusyListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def setBusy(self, busy: typing.Union[jpype.JBoolean, bool]):
        ...


class TaskMonitorSplitter(java.lang.Object):

    @typing.type_check_only
    class SubTaskMonitor(TaskMonitor, CancelledListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, parent: TaskMonitor, subSize: typing.Union[jpype.JDouble, float], notDoneYetSet: java.util.Set[TaskMonitorSplitter.SubTaskMonitor]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    MONITOR_SIZE: typing.ClassVar[jpype.JInt]

    def __init__(self):
        ...

    @staticmethod
    def splitTaskMonitor(monitor: TaskMonitor, n: typing.Union[jpype.JInt, int]) -> jpype.JArray[TaskMonitor]:
        ...


class MonitoredRunnable(java.lang.Object):
    """
    Similar to a :obj:`Runnable` except the :meth:`run <.monitoredRun>` method is given a
    monitor to report progress and check for cancellation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def monitoredRun(self, monitor: TaskMonitor):
        """
        Runs this runnable, given a monitor to report progress and check for cancellation.
        
        :param TaskMonitor monitor: the monitor.
        """


class PreserveStateWrappingTaskMonitor(WrappingTaskMonitor, java.io.Closeable):
    """
    A :obj:`TaskMonitor` wrapper that restores all changed values of the wrapped TaskMonitor when
    the wrapper is :meth:`closed <.close>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: TaskMonitor):
        ...


class TaskMonitor(java.lang.Object):
    """
    ``TaskMonitor`` provides an interface that allows potentially long running tasks to show
    progress and check for user has cancellation.
     
    
    Tasks that support a task monitor should periodically check to see if the operation has been
    cancelled and abort. If possible, the task should also provide periodic progress information. If
    your task can estimate the amount of work done, then it should use the :meth:`setProgress(long) <.setProgress>`
    method, otherwise it should call :meth:`setMessage(String) <.setMessage>` method to provide status updates.
    """

    class_: typing.ClassVar[java.lang.Class]
    DUMMY: typing.Final[TaskMonitor]
    """
    A 'do nothing' task monitor that can be passed to APIs when the client has not progress to
    report.
    """

    NO_PROGRESS_VALUE: typing.Final = -1
    """
    A value to indicate that this monitor has no progress value set
    """


    def addCancelledListener(self, listener: CancelledListener):
        """
        Add cancelled listener
        
        :param CancelledListener listener: the cancel listener
        """

    def cancel(self):
        """
        Cancel the task
        """

    @deprecated("Use checkCancelled() instead")
    def checkCanceled(self):
        """
        Check to see if this monitor has been cancelled
        
        :raises CancelledException: if monitor has been cancelled
        
        .. deprecated::
        
        Use :meth:`checkCancelled() <.checkCancelled>` instead
        """

    def checkCancelled(self):
        """
        Check to see if this monitor has been cancelled
        
        :raises CancelledException: if monitor has been cancelled
        """

    @deprecated("Use clearCancelled() instead")
    def clearCanceled(self):
        """
        Clear the cancellation so that this TaskMonitor may be reused
        
        
        .. deprecated::
        
        Use :meth:`clearCancelled() <.clearCancelled>` instead
        """

    def clearCancelled(self):
        """
        Clear the cancellation so that this TaskMonitor may be reused
        """

    @staticmethod
    def dummyIfNull(tm: TaskMonitor) -> TaskMonitor:
        """
        Returns the given task monitor if it is not ``null``.  Otherwise, a :obj:`.DUMMY`
        monitor is returned.
        
        :param TaskMonitor tm: the monitor to check for ``null``
        :return: a non-null task monitor
        :rtype: TaskMonitor
        """

    def getMaximum(self) -> int:
        """
        Returns the current maximum value for progress
        
        :return: the maximum progress value
        :rtype: int
        """

    def getMessage(self) -> str:
        """
        Gets the last set message of this monitor
        
        :return: the message
        :rtype: str
        """

    def getProgress(self) -> int:
        """
        Returns the current progress value or :obj:`.NO_PROGRESS_VALUE` if there is no value set
        
        :return: the current progress value or :obj:`.NO_PROGRESS_VALUE` if there is no value set
        :rtype: int
        """

    @typing.overload
    def increment(self):
        """
        Increases the progress value by 1, and checks if this monitor has been cancelled.
        
        :raises CancelledException: if monitor has been cancelled
        """

    @typing.overload
    def increment(self, incrementAmount: typing.Union[jpype.JLong, int]):
        """
        Changes the progress value by the specified amount, and checks if this monitor has 
        been cancelled.
        
        :param jpype.JLong or int incrementAmount: The amount by which to increment the progress
        :raises CancelledException: if monitor has been cancelled
        """

    @typing.overload
    def incrementProgress(self):
        """
        Increases the progress value by 1.
        """

    @typing.overload
    def incrementProgress(self, incrementAmount: typing.Union[jpype.JLong, int]):
        """
        Changes the progress value by the specified amount.
        
        :param jpype.JLong or int incrementAmount: The amount by which to increment the progress
        """

    @typing.overload
    def initialize(self, max: typing.Union[jpype.JLong, int]):
        """
        Initialized this TaskMonitor to the given max values.  The current value of this monitor
        will be set to zero.
        
        :param jpype.JLong or int max: maximum value for progress
        """

    @typing.overload
    def initialize(self, max: typing.Union[jpype.JLong, int], message: typing.Union[java.lang.String, str]):
        """
        Initializes the progress value to 0, sets the max value and message of this monitor.
        
        :param jpype.JLong or int max: maximum value for progress
        :param java.lang.String or str message: the message to display
        """

    def isCancelEnabled(self) -> bool:
        """
        Returns true if cancel ability is enabled
        
        :return: true if cancel ability is enabled
        :rtype: bool
        """

    def isCancelled(self) -> bool:
        """
        Returns true if the user has cancelled the operation
        
        :return: true if the user has cancelled the operation
        :rtype: bool
        """

    def isIndeterminate(self) -> bool:
        """
        Returns true if this monitor shows no progress
        
        :return: true if this monitor shows no progress
        :rtype: bool
        """

    def removeCancelledListener(self, listener: CancelledListener):
        """
        Remove cancelled listener
        
        :param CancelledListener listener: the cancel listener
        """

    def setCancelEnabled(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Set the enablement of the Cancel button
        
        :param jpype.JBoolean or bool enable: true means to enable the cancel button
        """

    def setIndeterminate(self, indeterminate: typing.Union[jpype.JBoolean, bool]):
        """
        An indeterminate task monitor may choose to show an animation instead of updating progress
        
        :param jpype.JBoolean or bool indeterminate: true if indeterminate
        """

    def setMaximum(self, max: typing.Union[jpype.JLong, int]):
        """
        Set the progress maximum value
         
        **
        Note: setting this value will reset the progress to be the max if the progress is currently
        greater than the new max value.**
        
        :param jpype.JLong or int max: maximum value for progress
        """

    def setMessage(self, message: typing.Union[java.lang.String, str]):
        """
        Sets the message displayed on the task monitor
        
        :param java.lang.String or str message: the message to display
        """

    def setProgress(self, value: typing.Union[jpype.JLong, int]):
        """
        Sets the current progress value
        
        :param jpype.JLong or int value: progress value
        """

    def setShowProgressValue(self, showProgressValue: typing.Union[jpype.JBoolean, bool]):
        """
        True (the default) signals to paint the progress information inside of the progress bar
        
        :param jpype.JBoolean or bool showProgressValue: true to paint the progress value; false to not
        """

    @property
    def indeterminate(self) -> jpype.JBoolean:
        ...

    @indeterminate.setter
    def indeterminate(self, value: jpype.JBoolean):
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def progress(self) -> jpype.JLong:
        ...

    @progress.setter
    def progress(self, value: jpype.JLong):
        ...

    @property
    def maximum(self) -> jpype.JLong:
        ...

    @maximum.setter
    def maximum(self, value: jpype.JLong):
        ...

    @property
    def cancelEnabled(self) -> jpype.JBoolean:
        ...

    @cancelEnabled.setter
    def cancelEnabled(self, value: jpype.JBoolean):
        ...

    @property
    def message(self) -> java.lang.String:
        ...

    @message.setter
    def message(self, value: java.lang.String):
        ...


class IssueListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def issueReported(self, issue: ghidra.util.Issue):
        ...


@typing.type_check_only
class StubTaskMonitor(TaskMonitor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CancelledListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def cancelled(self):
        """
        Provides notification when a task is cancelled.
        """


class CancellableIterator(java.util.Iterator[T], typing.Generic[T]):
    """
    An :obj:`Iterator` wrapper that allows clients to use a task monitor to cancel iteration
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: java.util.Iterator[T], monitor: TaskMonitor):
        ...



__all__ = ["TaskRunner", "TaskMonitorComponent", "BasicTaskMonitor", "CachingLoader", "ChompingBitsAnimationPanel", "RunManager", "TaskDialog", "TaskLauncher", "HourglassAnimationPanel", "CachingSwingWorker", "BackgroundThreadTaskLauncher", "TaskBuilder", "DummyCancellableTaskMonitor", "SwingRunnable", "CompoundTask", "SwingUpdateManager", "TaskListener", "Task", "AbstractSwingUpdateManager", "BufferedSwingRunner", "UnknownProgressWrappingTaskMonitor", "TaskMonitorAdapter", "WrappingTaskMonitor", "ConsoleTaskMonitor", "TimeoutTaskMonitor", "CancelOnlyWrappingTaskMonitor", "BusyListener", "TaskMonitorSplitter", "MonitoredRunnable", "PreserveStateWrappingTaskMonitor", "TaskMonitor", "IssueListener", "StubTaskMonitor", "CancelledListener", "CancellableIterator"]
