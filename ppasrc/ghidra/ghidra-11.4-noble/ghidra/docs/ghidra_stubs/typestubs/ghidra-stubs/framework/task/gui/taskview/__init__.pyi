from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.task
import ghidra.framework.task.gui
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class ScheduledTaskPanel(javax.swing.JPanel):

    @typing.type_check_only
    class ScheduledElementLayout(java.awt.LayoutManager):

        class_: typing.ClassVar[java.lang.Class]

        def clearPreferredSize(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, labelText: typing.Union[java.lang.String, str], indention: typing.Union[jpype.JInt, int]):
        ...

    def getProgressBar(self) -> ghidra.framework.task.gui.GProgressBar:
        ...

    def setHiddenViewAmount(self, fraction: typing.Union[jpype.JFloat, float]):
        """
        Sets the amount of the view that is hidden, i.e., "scrolled off".  The animation framework
        will cause this method to be called with a sequence of values from 0 to 1 which will be
        used to scroll the component off the view.
        
        :param jpype.JFloat or float fraction: the amount of the component to hide.
        """

    @property
    def progressBar(self) -> ghidra.framework.task.gui.GProgressBar:
        ...


class AbstractTaskInfo(java.lang.Comparable[AbstractTaskInfo]):

    class_: typing.ClassVar[java.lang.Class]

    def getComponent(self) -> ScheduledTaskPanel:
        ...

    def getGroup(self) -> ghidra.framework.task.GTaskGroup:
        ...

    def setBackground(self, c: java.awt.Color):
        """
        sets the background of the component being managed by this info.  It is used by the animation 
        framework.
        
        :param java.awt.Color c: the color
        """

    def setRunning(self) -> ghidra.framework.task.gui.GProgressBar:
        ...

    def setScrollFraction(self, fraction: typing.Union[jpype.JFloat, float]):
        ...

    @property
    def component(self) -> ScheduledTaskPanel:
        ...

    @property
    def group(self) -> ghidra.framework.task.GTaskGroup:
        ...


class TaskViewerComponent(javax.swing.JPanel, javax.swing.Scrollable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GroupInfo(AbstractTaskInfo):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TaskViewer(java.lang.Object):

    @typing.type_check_only
    class CustomLayoutManager(java.awt.LayoutManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MessageCanvas(javax.swing.JComponent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TaskViewerTaskListener(ghidra.framework.task.GTaskListenerAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InitializeRunnable(java.lang.Runnable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class TaskStartedRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TaskCompletedRunnable(java.lang.Runnable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, task: ghidra.framework.task.GScheduledTask):
            ...


    @typing.type_check_only
    class TaskGroupScheduledRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TaskScheduledRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TaskGroupStartedRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TaskGroupCompletedRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GroupCancelledListener(ghidra.util.task.CancelledListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, taskManager: ghidra.framework.task.GTaskManager):
        ...

    def getComponent(self) -> javax.swing.JComponent:
        ...

    def setUseAnimations(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...


class TaskInfo(AbstractTaskInfo):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, task: ghidra.framework.task.GScheduledTask, useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...

    def getScheduledTask(self) -> ghidra.framework.task.GScheduledTask:
        ...

    @property
    def scheduledTask(self) -> ghidra.framework.task.GScheduledTask:
        ...



__all__ = ["ScheduledTaskPanel", "AbstractTaskInfo", "TaskViewerComponent", "GroupInfo", "TaskViewer", "TaskInfo"]
