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

    def __init__(self, gTree: docking.widgets.tree.GTree, jTree: javax.swing.JTree, names: jpype.JArray[java.lang.String], origin: docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin):
        ...


class GTreeExpandNodeToDepthTask(docking.widgets.tree.GTreeTask):
    """
    A GTree task to fully expand a tree node to a maximal depth.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: docking.widgets.tree.GTree, jTree: javax.swing.JTree, node: docking.widgets.tree.GTreeNode, depth: typing.Union[jpype.JInt, int]):
        ...


class GTreeSelectPathsTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gtree: docking.widgets.tree.GTree, tree: javax.swing.JTree, paths: java.util.List[javax.swing.tree.TreePath], origin: docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin):
        ...

    def setExpandingDisabled(self, disabled: typing.Union[jpype.JBoolean, bool]):
        """
        Tells the JTree to not expand paths for each selection that is set upon it.  Doing this
        will speed-up performance.   However, only call this when some other task is going to
        ensure that paths are properly expanded.
        
        :param jpype.JBoolean or bool disabled: true to disable
        """


class GTreeClearTreeFilterTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree):
        ...


class GTreeLoadChildrenTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree, node: docking.widgets.tree.GTreeSlowLoadingNode):
        ...


class GTreeStartEditingTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: docking.widgets.tree.GTree, jTree: javax.swing.JTree, editNode: docking.widgets.tree.GTreeNode):
        ...


class GTreeExpandAllTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree, node: docking.widgets.tree.GTreeNode):
        ...


class GTreeCollapseAllTask(docking.widgets.tree.GTreeTask):
    """
    A GTree task to fully collapse a tree
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree, node: docking.widgets.tree.GTreeNode):
        ...


class GTreeClearSelectionTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree, jTree: javax.swing.JTree):
        ...


class GTreeBulkTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def runBulk(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform bulk operations here.
        
        :param ghidra.util.task.TaskMonitor monitor: the monitor used to report progress and check for cancelled
        :raises CancelledException: if the user cancelled and :meth:`TaskMonitor.checkCancelled() <TaskMonitor.checkCancelled>`
                gets called
        """


class GTreeExpandPathsTask(docking.widgets.tree.GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: docking.widgets.tree.GTree, paths: java.util.List[javax.swing.tree.TreePath]):
        ...



__all__ = ["GTreeSelectNodeByNameTask", "GTreeExpandNodeToDepthTask", "GTreeSelectPathsTask", "GTreeClearTreeFilterTask", "GTreeLoadChildrenTask", "GTreeStartEditingTask", "GTreeExpandAllTask", "GTreeCollapseAllTask", "GTreeClearSelectionTask", "GTreeBulkTask", "GTreeExpandPathsTask"]
