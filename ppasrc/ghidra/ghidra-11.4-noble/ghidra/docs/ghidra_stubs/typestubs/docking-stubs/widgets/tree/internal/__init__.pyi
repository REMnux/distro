from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.tree
import docking.widgets.tree.support
import ghidra.util
import java.awt.dnd # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.tree # type: ignore


class GTreeSelectionModel(javax.swing.tree.DefaultTreeSelectionModel):
    """
    This class was created so that GTree users can know the origin of tree selections.  This is 
    useful in determining if the tree selection event occurred because the user clicked in the
    tree, or if an API method was called (or by an event internal to, or trigged by the GTree).
     
    
     
    As an example usage, imagine an event cycle, where a change in the tree selection causes a 
    change in some other GUI component and changes in the other GUI component cause a change 
    in the tree selection.  
    In this scenario, to avoid bouncing back and forth, the TreeSelectionListener can check 
    if the tree selection change was caused by the user or by an API call responding to the 
    change in the other GUI component, thereby breaking the cycle.
     
    
     
    With this selection model the user can check the origin of the event with a call to:
     
            public void valueChanged(GTreeSelectionEvent e) {
                if ( e.getEventOrigin() == EventOrigin.USER_GENERATED ) {
                    // respond to user selection
                }
            }
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addGTreeSelectionListener(self, listener: docking.widgets.tree.support.GTreeSelectionListener):
        ...

    def removeGTreeSelectionListener(self, listener: docking.widgets.tree.support.GTreeSelectionListener):
        ...

    def setSelectionPaths(self, paths: jpype.JArray[javax.swing.tree.TreePath], origin: docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin):
        ...

    def userRemovedSelectionPath(self, path: javax.swing.tree.TreePath):
        """
        This method allows the GTree's JTree to tell this selection model when a selection has
        been removed due to the user clicking.
         
        
        Implementation Note: this method is needed because :meth:`removeSelectionPaths(TreePath[]) <.removeSelectionPaths>`
        marks all events as :obj:`EventOrigin.INTERNAL_GENERATED`.  Our intention is to mark any
        tree housekeeping as internal, with user operations being marked appropriately.
        
        :param javax.swing.tree.TreePath path: the path that is to be removed
        """


class InProgressGTreeNode(docking.widgets.tree.GTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GTreeNodeListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def nodeAdded(self, parentNode: docking.widgets.tree.GTreeNode, newNode: docking.widgets.tree.GTreeNode):
        ...

    def nodeChanged(self, parentNode: docking.widgets.tree.GTreeNode, changedNode: docking.widgets.tree.GTreeNode):
        ...

    def nodeRemoved(self, parentNode: docking.widgets.tree.GTreeNode, removedNode: docking.widgets.tree.GTreeNode, oldIndexInParent: typing.Union[jpype.JInt, int]):
        ...

    def nodeStructureChanged(self, node: docking.widgets.tree.GTreeNode):
        ...


class GTreeDragNDropAdapter(java.awt.dnd.DragSourceListener, java.awt.dnd.DragGestureListener, java.awt.dnd.DropTargetListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: docking.widgets.tree.GTree, tree: javax.swing.JTree, dragNDropHandler: docking.widgets.tree.support.GTreeDragNDropHandler):
        ...


class GTreeModel(javax.swing.tree.TreeModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, root: docking.widgets.tree.GTreeNode):
        """
        Constructs a GTreeModel with the given root node.
        
        :param docking.widgets.tree.GTreeNode root: The root of the tree.
        """

    def dispose(self):
        ...

    def fireNodeAdded(self, parentNode: docking.widgets.tree.GTreeNode, newNode: docking.widgets.tree.GTreeNode):
        ...

    def fireNodeDataChanged(self, changedNode: docking.widgets.tree.GTreeNode):
        ...

    def fireNodeRemoved(self, parentNode: docking.widgets.tree.GTreeNode, removedNode: docking.widgets.tree.GTreeNode, index: typing.Union[jpype.JInt, int]):
        ...

    def fireNodeStructureChanged(self, changedNode: docking.widgets.tree.GTreeNode):
        ...

    def getModelRoot(self) -> docking.widgets.tree.GTreeNode:
        ...

    def privateSwingSetRootNode(self, newRoot: docking.widgets.tree.GTreeNode):
        """
        Sets the models root node. NOTE: this is intended to only be called from the :obj:`GTree`
        
        :param docking.widgets.tree.GTreeNode newRoot: the new tree model root.  It will either be the actual root or a root
        of a filtered sub-tree
        """

    def setEventsEnabled(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def modelRoot(self) -> docking.widgets.tree.GTreeNode:
        ...


class DefaultGTreeDataTransformer(ghidra.util.FilterTransformer[docking.widgets.tree.GTreeNode]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class InProgressGTreeRootNode(docking.widgets.tree.GTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["GTreeSelectionModel", "InProgressGTreeNode", "GTreeNodeListener", "GTreeDragNDropAdapter", "GTreeModel", "DefaultGTreeDataTransformer", "InProgressGTreeRootNode"]
