from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.list
import ghidra.framework.task
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class GTaskResultPanel(javax.swing.JPanel):

    @typing.type_check_only
    class GTaskResultCellRenderer(docking.widgets.list.GListCellRenderer[GTaskResultInfo]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, taskMgr: ghidra.framework.task.GTaskManager):
        ...


@typing.type_check_only
class GTaskResultInfo(java.lang.Object):
    """
    An item that wraps :obj:`GTaskResult`s that are to be put into JLists in order to add more
    information.
    """

    class_: typing.ClassVar[java.lang.Class]


class CompletedTaskListModel(GTaskListModel[GTaskResultInfo]):

    @typing.type_check_only
    class CompletedTaskRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InitializeRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CompletedPanelTaskListener(ghidra.framework.task.GTaskListenerAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        ...


class GProgressBar(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cancelledListener: ghidra.util.task.CancelledListener, includeTextField: typing.Union[jpype.JBoolean, bool], includeCancelButton: typing.Union[jpype.JBoolean, bool], includeAnimatedIcon: typing.Union[jpype.JBoolean, bool]):
        ...

    def cancel(self):
        ...

    def getMax(self) -> int:
        ...

    def getMessage(self) -> str:
        ...

    def getProgress(self) -> int:
        ...

    def incrementProgress(self, incrementAmount: typing.Union[jpype.JLong, int]):
        ...

    def initialize(self, maximum: typing.Union[jpype.JLong, int]):
        ...

    def setBackgroundColor(self, bg: java.awt.Color):
        ...

    def setCancelledListener(self, listener: ghidra.util.task.CancelledListener):
        ...

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
        
        :param jpype.JBoolean or bool indeterminate: true if indeterminate
        
        .. seealso::
        
            | :obj:`JProgressBar`
        """

    def setMaximum(self, max: typing.Union[jpype.JLong, int]):
        ...

    def setMessage(self, message: typing.Union[java.lang.String, str]):
        ...

    def setProgress(self, progress: typing.Union[jpype.JLong, int]):
        ...

    def setShowProgressValue(self, showProgressValue: typing.Union[jpype.JBoolean, bool]):
        """
        True (the default) signals to paint the progress information inside of the progress bar.
        
        :param jpype.JBoolean or bool showProgressValue: true to paint the progress value; false to not
        """

    def showProgressIcon(self, showIcon: typing.Union[jpype.JBoolean, bool]):
        """
        Show or not show the progress icon (spinning globe) according to
        the showIcon param.
        
        :param jpype.JBoolean or bool showIcon: true to show the icon
        """

    @property
    def max(self) -> jpype.JLong:
        ...

    @property
    def progress(self) -> jpype.JLong:
        ...

    @progress.setter
    def progress(self, value: jpype.JLong):
        ...

    @property
    def message(self) -> java.lang.String:
        ...

    @message.setter
    def message(self, value: java.lang.String):
        ...


class GTaskListModel(javax.swing.AbstractListModel[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["GTaskResultPanel", "GTaskResultInfo", "CompletedTaskListModel", "GProgressBar", "GTaskListModel"]
