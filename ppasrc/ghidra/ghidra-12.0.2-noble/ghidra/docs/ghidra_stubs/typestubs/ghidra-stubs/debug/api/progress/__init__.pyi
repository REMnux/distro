from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.task
import java.lang # type: ignore


class CloseableTaskMonitor(ghidra.util.task.TaskMonitor, java.lang.AutoCloseable):
    """
    A task monitor that can be used in a try-with-resources block.
    """

    class_: typing.ClassVar[java.lang.Class]

    def reportError(self, error: java.lang.Throwable):
        """
        Report an error while working on this task
        
        :param java.lang.Throwable error: the error
        """


class MonitorReceiver(java.lang.Object):
    """
    The subscriber side of a published :obj:`TaskMonitor`
     
     
    
    This only gives a subset of the expected task monitor interface. This is the subset a
    *user* would need to monitor and/or cancel the task. All the mechanisms for updating the
    monitor are only available to the publishing client.
    """

    class_: typing.ClassVar[java.lang.Class]

    def cancel(self):
        """
        Request the task be cancelled
         
         
        
        Note it is up to the client publishing the task to adhere to this request. In general, the
        computation should occasionally call :meth:`TaskMonitor.checkCancelled() <TaskMonitor.checkCancelled>`. In particular, the
        subscribing client *cannot* presume the task is cancelled purely by virtue of calling
        this method successfully. Instead, it should listen for
        :meth:`ProgressListener.monitorDisposed(MonitorReceiver, Disposal) <ProgressListener.monitorDisposed>`.
        """

    def getMaximum(self) -> int:
        """
        Get the maximum value of progress
         
         
        
        The implication is that when :meth:`getProgress() <.getProgress>` returns the maximum, the task is
        complete.
        
        :return: the maximum progress
        :rtype: int
        """

    def getMessage(self) -> str:
        """
        Get the current message for the monitor
        
        :return: the message
        :rtype: str
        """

    def getProgress(self) -> int:
        """
        Get the progress value, if applicable
        
        :return: the progress, or :obj:`TaskMonitor.NO_PROGRESS_VALUE` if un-set or not applicable
        :rtype: int
        """

    def isCancelEnabled(self) -> bool:
        """
        Check if the task can be cancelled
        
        :return: true if cancel is enabled, false if not
        :rtype: bool
        """

    def isCancelled(self) -> bool:
        """
        Check if the task is cancelled
        
        :return: true if cancelled, false if not
        :rtype: bool
        """

    def isIndeterminate(self) -> bool:
        """
        Check if the monitor indicates progress at all
         
         
        
        If the task is indeterminate, then its :meth:`getMaximum() <.getMaximum>` and :meth:`getProgress() <.getProgress>`
        methods are meaningless.
        
        :return: true if indeterminate (no progress shown), false if determinate (progress shown)
        :rtype: bool
        """

    def isShowProgressValue(self) -> bool:
        """
        Check if the monitor should be rendered with the progress value
         
         
        
        Regardless of this value, the monitor will render a progress bar and a numeric percentage. If
        this is set to true (the default), the it will also display "{progress} of {maximum}" in
        text.
        
        :return: true to render the actual progress value, false for only a percentage.
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        Check if the monitor is still valid
         
         
        
        A monitor becomes invalid when it is closed or cleaned.
        
        :return: true if still valid, false if invalid
        :rtype: bool
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def showProgressValue(self) -> jpype.JBoolean:
        ...

    @property
    def indeterminate(self) -> jpype.JBoolean:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def progress(self) -> jpype.JLong:
        ...

    @property
    def maximum(self) -> jpype.JLong:
        ...

    @property
    def cancelEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def message(self) -> java.lang.String:
        ...


class ProgressListener(java.lang.Object):
    """
    A listener for events on the progress service, including updates to task progress
    """

    class Disposal(java.lang.Enum[ProgressListener.Disposal]):
        """
        Describes how or why a task monitor was disposed
        """

        class_: typing.ClassVar[java.lang.Class]
        CLOSED: typing.Final[ProgressListener.Disposal]
        """
        The monitor was properly closed
        """

        CLEANED: typing.Final[ProgressListener.Disposal]
        """
        The monitor was *not* closed. Instead, it was cleaned by the garbage collector.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ProgressListener.Disposal:
            ...

        @staticmethod
        def values() -> jpype.JArray[ProgressListener.Disposal]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def attributeUpdated(self, monitor: MonitorReceiver):
        """
        Some other attribute has been updated
         
         
        * cancelled
        * cancel enabled
        * indeterminate
        * maximum
        * show progress value in percent string
        
        
        :param MonitorReceiver monitor: the receiver whose monitor's attribute(s) changed
        """

    def errorReported(self, monitor: MonitorReceiver, error: java.lang.Throwable):
        """
        A task has reported an error
        
        :param MonitorReceiver monitor: the receiver for the task reporting the error
        :param java.lang.Throwable error: the exception representing the error
        """

    def messageUpdated(self, monitor: MonitorReceiver, message: typing.Union[java.lang.String, str]):
        """
        A task has updated a monitor's message
        
        :param MonitorReceiver monitor: the receiver whose monitor's message changed
        :param java.lang.String or str message: the new message
        """

    def monitorCreated(self, monitor: MonitorReceiver):
        """
        A new task monitor has been created
         
         
        
        The subscriber ought to display the monitor as soon as is reasonable. Optionally, a
        subscriber may apply a grace period, e.g., half a second, before displaying it, in case it is
        quickly disposed.
        
        :param MonitorReceiver monitor: a means of retrieving messages and progress about the task
        """

    def monitorDisposed(self, monitor: MonitorReceiver, disposal: ProgressListener.Disposal):
        """
        A task monitor has been disposed
        
        :param MonitorReceiver monitor: the receiver for the disposed monitor
        :param ProgressListener.Disposal disposal: why it was disposed
        """

    def progressUpdated(self, monitor: MonitorReceiver, progress: typing.Union[jpype.JLong, int]):
        """
        A task's progress has updated
         
         
        
        Note the subscriber may need to use :meth:`MonitorReceiver.getMaximum() <MonitorReceiver.getMaximum>` to properly update
        the display.
        
        :param MonitorReceiver monitor: the receiver whose monitor's progress changed
        :param jpype.JLong or int progress: the new progress value
        """



__all__ = ["CloseableTaskMonitor", "MonitorReceiver", "ProgressListener"]
