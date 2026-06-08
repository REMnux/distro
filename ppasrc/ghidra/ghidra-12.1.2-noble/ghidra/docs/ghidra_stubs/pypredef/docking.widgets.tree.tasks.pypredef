from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.tree
import ghidra.util.task
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.tree # type: ignore


class GTreeSelectNodeByNameTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: docking.widgets.tree.GTree, jTree: javax.swing.JTree, names: jpype.JArray[java.lang.String], origin: docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin) -> None:
        ...


class GTreeExpandNodeToDepthTask(docking.widgets.tree.GTreeTask):
    """
    A GTree task to fully expand a tree node to a maximal depth.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: docking.widgets.tree.GTree, node: docking.widgets.tree.GTreeNode, depth: typing.Union[jpype.JInt, int]) -> None:
        ...


class GTreeSelectPathsTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gtree: docking.widgets.tree.GTree, tree: javax.swing.JTree, paths: java.util.List[javax.swing.tree.TreePath], origin: docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin) -> None:
        ...

    def setExpandingDisabled(self, disabled: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Tells the JTree to not expand paths for each selection that is set upon it.  Doing this
        will speed-up performance.   However, only call this when some other task is going to
        ensure that paths are properly expanded.
        
        :param jpype.JBoolean or bool disabled: true to disable
        """


class GTreeClearTreeFilterTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree) -> None:
        ...


class GTreeLoadChildrenTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree, node: docking.widgets.tree.GTreeSlowLoadingNode) -> None:
        ...


class GTreeStartEditingTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: docking.widgets.tree.GTree, jTree: javax.swing.JTree, editNode: docking.widgets.tree.GTreeNode) -> None:
        ...


class GTreeExpandAllTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree, node: docking.widgets.tree.GTreeNode) -> None:
        ...


class GTreeCollapseAllTask(docking.widgets.tree.GTreeTask):
    """
    A GTree task to fully collapse a tree
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree, node: docking.widgets.tree.GTreeNode) -> None:
        ...


class GTreeClearSelectionTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree, jTree: javax.swing.JTree) -> None:
        ...


class GTreeBulkTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def runBulk(self, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Perform bulk operations here.
        
        :param ghidra.util.task.TaskMonitor monitor: the monitor used to report progress and check for cancelled
        :raises CancelledException: if the user cancelled and :meth:`TaskMonitor.checkCancelled() <TaskMonitor.checkCancelled>`
                gets called
        """


class GTreeExpandPathsTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: docking.widgets.tree.GTree, paths: java.util.List[javax.swing.tree.TreePath]) -> None:
        ...



__all__ = ["GTreeSelectNodeByNameTask", "GTreeExpandNodeToDepthTask", "GTreeSelectPathsTask", "GTreeClearTreeFilterTask", "GTreeLoadChildrenTask", "GTreeStartEditingTask", "GTreeExpandAllTask", "GTreeCollapseAllTask", "GTreeClearSelectionTask", "GTreeBulkTask", "GTreeExpandPathsTask"]
