from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.actions
import docking.widgets
import docking.widgets.filter
import docking.widgets.tree.internal
import docking.widgets.tree.support
import docking.widgets.tree.tasks
import ghidra.util
import ghidra.util.task
import ghidra.util.worker
import java.awt # type: ignore
import java.awt.dnd # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import java.util.stream # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore


@typing.type_check_only
class CoreGTreeNode(java.lang.Cloneable):
    """
    This class exists to help prevent threading errors in :obj:`GTreeNode` and subclasses,
    by privately maintaining synchronous access to the parent and children of a node. 
     
    
    This implementation uses a :obj:`CopyOnWriteArrayList` to store its children. The theory is
    that this will allow direct thread-safe access to the children without having to worry about
    :obj:`ConcurrentModificationException`s while iterating the children.  Also, the assumption
    is that accessing the children will occur much more frequently than modifying the children.  
    This should only be a problem if a direct descendant of GTreeNode creates its children by calling
    addNode many times. But in that case, the tree should be using Lazy or 
    SlowLoading nodes which always load into another list first and all the children will be set 
    on a node in a single operation.
     
    
    Subclasses that need access to the children can call the :meth:`children() <.children>` method which will
    ensure that the children are loaded (not null). Since this class uses a
    :obj:`CopyOnWriteArrayList`, subclasses that call the :meth:`children() <.children>` method can safely
    iterate the list without having to worry about getting a :obj:`ConcurrentModificationException`.  
     
    
    This class uses synchronization to assure that the parent/children relationship is stable across
    threads.  To avoid deadlocks, the sychronization strategy is that if you have the lock on
    a parent node, you can safely acquire the lock on any of its descendants, but never its 
    ancestors.  To facilitate this strategy, the :meth:`getParent() <.getParent>` is not synchronized, but it
    is made volatile to assure the current value is always used.
     
    
    Except for the :meth:`doSetChildren(List) <.doSetChildren>` method, all other calls that mutate the
    children must be called on the swing thread.  The idea is that bulk operations can work efficiently
    by avoiding constantly switching to the swing thread to mutate the tree. This works because
    the bulk setting of the children generates a coarse "node structure changed" event, which causes the
    underlying :obj:`JTree` to rebuild its internal cache of the tree.  Individual add/remove operations
    have to be done very carefully such that the :obj:`JTree` is always updated on one change before any
    additional changes are done.  This is why those operations are required to be done on the swing
    thread, which combined with the fact that all mutate operations are synchronized, keeps the JTree
    happy.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clone(self) -> GTreeNode:
        """
        Creates a clone of this node.  The clone should contain a shallow copy of all the node's
        attributes except that the parent and children are null.
        
        :return: the clone of this object.
        :rtype: GTreeNode
        :raises java.lang.CloneNotSupportedException: if some implementation prevents itself from being cloned.
        """

    def dispose(self):
        ...

    def getParent(self) -> GTreeNode:
        """
        Returns the parent of this node.
         
        Note: this method is deliberately not synchronized (See comments above)
        
        :return: the parent of this node.
        :rtype: GTreeNode
        """

    def getTree(self) -> GTree:
        """
        Returns the GTree that this node is attached to
        
        :return: the GTree that this node is attached to
        :rtype: GTree
        """

    def isInProgress(self) -> bool:
        """
        Returns true if the node is in the process of loading its children. 
        See :obj:`GTreeSlowLoadingNode`
        
        :return: true if the node is in the process of loading its children.
        :rtype: bool
        """

    def isLoaded(self) -> bool:
        """
        True if the children for this node have been loaded yet.  Some GTree nodes are lazy in that they
        don't load their children until needed. Nodes that have the IN_PROGRESS node as it child
        is considered loaded if in the swing thread, otherwise they are considered not loaded.
        
        :return: true if the children for this node have been loaded.
        :rtype: bool
        """

    def isRoot(self) -> bool:
        """
        Returns true if this is a root node of a GTree
        
        :return: true if this is a root node of a GTree
        :rtype: bool
        """

    @property
    def loaded(self) -> jpype.JBoolean:
        ...

    @property
    def parent(self) -> GTreeNode:
        ...

    @property
    def inProgress(self) -> jpype.JBoolean:
        ...

    @property
    def root(self) -> jpype.JBoolean:
        ...

    @property
    def tree(self) -> GTree:
        ...


class InvertedTreeFilter(docking.widgets.tree.support.GTreeFilter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeFilter: docking.widgets.tree.support.GTreeFilter):
        ...


class GTreeNode(CoreGTreeNode, java.lang.Comparable[GTreeNode]):
    """
    Base implementation for GTree nodes. Direct subclasses of this class are expected to have all
    their children in hand when initially constructed (either in their constructor or externally
    using :meth:`addNode(GTreeNode) <.addNode>` or :meth:`setChildren(List) <.setChildren>`. For large trees, subclasses
    should instead extend :obj:`GTreeLazyNode` or :obj:`GTreeSlowLoadingNode`
     
    
    All methods in this class that mutate the children node must perform that operation in the swing
    thread.
     
    
    To create a simple GTreeNode where nodes will be added immediately using the addNode() methods,
    simply extend this class and implement the following methods:
     
    * getName()
    * getToolTip()
    * isLeaf()
    * getIcon()
    
    
     
    .. _usage:
    
    Usage Notes:
     
    * The ``equals()`` method: The GTree has the ability to remember
    expanded and selected states. This will only work if the nodes in the saved state can be matched
    with the nodes in theGTree. Java will do this by using the equals()
    method. There is a potential problem with this usage. If nodes within theGTree get
    rebuilt ( i.e., new nodes are created), then, by default, the expanded and selected state feature
    will be unable to find the correct nodes, since the defaultequals() method on
    GTreeNode performs a comparison based upon instances. To fix this problem, the
    :meth:`equals(Object) <.equals>` method has been implemented such that nodes are considered equal if they
    have the same name (see:meth:`getName() <.getName>`). The :meth:`hashCode() <.hashCode>` method will return the hash
    of the name. The name attribute was chosen because it should be the most unique and descriptive
    piece of information available in a generic GTreeNode.
    
    There are two situations where the:meth:`equals(Object) <.equals>` and :meth:`hashCode() <.hashCode>` using the name
    are insufficient. One is if your tree implementation allows nodes with the same name with the
    same parent. The other possible situation is if your nodes can change their name, which may
    confuse the tree. If either of these situations apply, just override the:meth:`equals(Object) <.equals>`
    and:meth:`hashCode() <.hashCode>` methods to make them more robust.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def addNode(self, node: GTreeNode):
        """
        Adds the given node as a child to this node. Note: this method may be inefficient so if you
        have many nodes to add, you should use either :meth:`addNodes(List) <.addNodes>` or
        :meth:`setChildren(List) <.setChildren>`
        
        :param GTreeNode node: the node to add as a child
        """

    @typing.overload
    def addNode(self, index: typing.Union[jpype.JInt, int], node: GTreeNode):
        """
        Adds the given node at the given index as a child to this node
        
        :param jpype.JInt or int index: the index to place the node
        :param GTreeNode node: the node to add as a child of this node
        """

    def addNodes(self, nodes: java.util.List[GTreeNode]):
        """
        Adds the given nodes as children to this node
        
        :param java.util.List[GTreeNode] nodes: the nodes to add
        """

    def collapse(self):
        """
        Convenience method for collapsing (closing) this node in the tree. If this node is not
        currently attached to a visible tree, then this call does nothing
        """

    def expand(self):
        """
        Convenience method for expanding (opening) this node in the tree. If this node is not
        currently attached to a visible tree, then this call does nothing
        """

    def filter(self, filter: docking.widgets.tree.support.GTreeFilter, monitor: ghidra.util.task.TaskMonitor) -> GTreeNode:
        """
        Generates a filtered copy of this node and its children.
         
        
        A node will be included if it or any of its descendants are accepted by the filter. NOTE: the
        filter will only be applied to a nodes children if they are loaded. So to perform a filter on
        all the nodes in the tree, the :meth:`loadAll(TaskMonitor) <.loadAll>` should be called before the
        filter call.
        
        :param docking.widgets.tree.support.GTreeFilter filter: the filter being applied
        :param ghidra.util.task.TaskMonitor monitor: a TaskMonitor for tracking the progress and cancelling
        :return: A copy of this node and its children that matches the filter or null if this node and
                none of its children match the filter.
        :rtype: GTreeNode
        :raises CancelledException: if the operation is cancelled via the TaskMonitor
        :raises java.lang.CloneNotSupportedException: if any nodes in the tree explicitly prevents cloning
        """

    def fireNodeChanged(self):
        """
        Notifies the tree that a node has changed, excluding its children. If it has gained or lost
        children, then use :meth:`fireNodeStructureChanged() <.fireNodeStructureChanged>` instead.
        """

    def fireNodeStructureChanged(self):
        """
        Notifies the tree that the node has different children.
        """

    @typing.overload
    def getChild(self, name: typing.Union[java.lang.String, str]) -> GTreeNode:
        """
        Returns the child node of this node with the given name.
         
        
        WARNING: If this node supports duplicate named children, then the node returned by this 
        method is arbitrary, depending upon how the nodes are arranged in the parent's list.  If you
        know duplicates are not allowed, then calling this method is safe.  Otherwise, you should 
        instead use :meth:`getChildren(String) <.getChildren>`.
        
        :param java.lang.String or str name: the name of the child to be returned
        :return: the child with the given name
        :rtype: GTreeNode
        
        .. seealso::
        
            | :obj:`.getChildren(String)`
        """

    @typing.overload
    def getChild(self, name: typing.Union[java.lang.String, str], filter: java.util.function.Predicate[GTreeNode]) -> GTreeNode:
        """
        Returns the child node of this node with the given name which satisfies predicate filter.
        
        :param java.lang.String or str name: the name of the child to be returned
        :param java.util.function.Predicate[GTreeNode] filter: predicate filter
        :return: the child with the given name
        :rtype: GTreeNode
        
        .. seealso::
        
            | :obj:`.getChildren(String)`
        """

    @typing.overload
    def getChild(self, index: typing.Union[jpype.JInt, int]) -> GTreeNode:
        """
        Returns the child node at the given index. Returns null if the index is out of bounds.
        
        :param jpype.JInt or int index: the index of the child to be returned
        :return: the child at the given index
        :rtype: GTreeNode
        """

    def getChildCount(self) -> int:
        """
        Returns the number of **visible** children of this node. Does not include nodes that are
        current filtered out
        
        :return: the number of **visible** children of this node
        :rtype: int
        """

    @typing.overload
    def getChildren(self) -> java.util.List[GTreeNode]:
        """
        Returns all of the **visible** children of this node. If there are filtered nodes, then
        they will not be returned.
        
        :return: all of the **visible** children of this node. If there are filtered nodes, then
                they will not be returned.
        :rtype: java.util.List[GTreeNode]
        """

    @typing.overload
    def getChildren(self, name: typing.Union[java.lang.String, str]) -> java.util.List[GTreeNode]:
        """
        Gets any children under this parent with the given name.
         
        
        Note: if you know this parent node does not allow duplicates, then you can use 
        :meth:`getChild(String) <.getChild>` instead of this method.
        
        :param java.lang.String or str name: the name of the children to be returned
        :return: the matching children
        :rtype: java.util.List[GTreeNode]
        """

    def getDisplayText(self) -> str:
        """
        Returns the display text for the node. By default, this is the same as the name of the node.
        The name of the node usually serves two purposes: 1) to uniquely identify the node (the
        identity) and 2) the display text (what you see in the tree). Sometimes, it is useful to
        display more information in the tree without affecting the nodes identity. In this case, you
        can override this method to return the "display" name, while :meth:`getName() <.getName>` will still
        return the name used to identify the node.
        
        :return: the display text for the node.
        :rtype: str
        """

    def getIcon(self, expanded: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the Icon to be displayed for this node in the tree
        
        :param jpype.JBoolean or bool expanded: true if the node is expanded
        :return: the icon to be displayed for this node in the tree
        :rtype: javax.swing.Icon
        """

    def getIndexInParent(self) -> int:
        """
        Returns the index of this node within its parent node
        
        :return: the index of this node within its parent node
        :rtype: int
        """

    def getIndexOfChild(self, node: GTreeNode) -> int:
        """
        Returns the index of the given node within this node. -1 is returned if the node is not a
        child of this node.
        
        :param GTreeNode node: whose index we want
        :return: the index of the given node within this node
        :rtype: int
        """

    def getLeafCount(self) -> int:
        """
        Returns the total number of leaf nodes in the subtree from this node. Note that if any nodes
        are "lazy" (see :obj:`GTreeLazyNode`) and not currently loaded, then it will be considered
        as a leaf and return 1.
        
        :return: the total number of leaf nodes in the subtree from this node
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of the node. If :meth:`getDisplayText() <.getDisplayText>` is not overridden, then this is
        also the text that will be displayed in the tree for that node. In general, the name of a
        node should not change. If the text displayed in the tree changes over time, override
        :meth:`getDisplayText() <.getDisplayText>`.
        
        :return: the name of the node
        :rtype: str
        """

    def getNodeCount(self) -> int:
        """
        Returns the total number of nodes in the subtree rooted at this node. Leaf nodes return 1.
        
        :return: the number of nodes from this node downward
        :rtype: int
        """

    def getRoot(self) -> GTreeNode:
        """
        Returns the rootNode for this tree or null if there is no parent path to a root node.
        
        :return: the rootNode for a tree of nodes in a :obj:`GTree`
        :rtype: GTreeNode
        """

    def getToolTip(self) -> str:
        """
        Returns the string to be displayed as a tooltip when the user hovers the mouse on this node
        in the tree
        
        :return: the tooltip to be displayed
        :rtype: str
        """

    def getTreePath(self) -> javax.swing.tree.TreePath:
        """
        Returns the TreePath for this node
        
        :return: the TreePath for this node
        :rtype: javax.swing.tree.TreePath
        """

    def isAncestor(self, node: GTreeNode) -> bool:
        """
        Returns true if the given node is a child of this node or one of its children.
        
        :param GTreeNode node: the potential descendant node to check
        :return: true if the given node is a child of this node or one of its children
        :rtype: bool
        """

    def isAutoExpandPermitted(self) -> bool:
        """
        Determine if this node may be auto-expanded.  Some special node cases may need to prevent
        or limit auto-expansion due to tree depth or other special conditions.
        
        :return: true if this node allows auto-expansion, else false.
        :rtype: bool
        """

    def isEditable(self) -> bool:
        """
        Returns true if this node is allowed to be edited in the tree. You must override this method
        to allow a node to be edited. You must also override :meth:`valueChanged(Object) <.valueChanged>` to handle
        the result of the edit.
        
        :return: true if this node is allowed to be edited in the tree
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.valueChanged(Object)`
        """

    def isExpanded(self) -> bool:
        """
        Convenience method determining if this node is expanded in a tree. If the node is not
        currently attached to a visible tree, then this call returns false
        
        :return: true if the node is expanded in a currently visible tree.
        :rtype: bool
        """

    def isLeaf(self) -> bool:
        """
        Returns true if this node never has children
        
        :return: true if this node is a leaf
        :rtype: bool
        """

    def iterator(self, depthFirst: typing.Union[jpype.JBoolean, bool]) -> java.util.Iterator[GTreeNode]:
        """
        Returns an iterator of the GTree nodes in the subtree of this node
        
        :param jpype.JBoolean or bool depthFirst: if true, the nodes will be returned in depth-first order, otherwise
                    breadth-first order
        :return: an iterator of the GTree nodes in the subtree of this node
        :rtype: java.util.Iterator[GTreeNode]
        """

    def loadAll(self, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Causes any lazy or slow loading nodes in the tree to load their children so that the tree is
        fully loaded. Nodes that are already loaded (including normal nodes which are always loaded)
        do nothing except recursively call :meth:`loadAll(TaskMonitor) <.loadAll>` on their children.
        
        :param ghidra.util.task.TaskMonitor monitor: the TaskMonitor to monitor progress and provide cancel checking
        :return: the total number of nodes in the subtree of this node
        :rtype: int
        :raises CancelledException: if the operation is cancelled using the monitor
        """

    def removeAll(self):
        """
        Removes all children from this node. The children nodes will be disposed.
        """

    def removeNode(self, node: GTreeNode):
        """
        Remove the given node from this node
        
        :param GTreeNode node: the to be removed
        """

    def setChildren(self, childList: java.util.List[GTreeNode]):
        """
        Sets the children on this node. Any existing current children will be dispose.
        
        :param java.util.List[GTreeNode] childList: this list of nodes to be set as children of this node
        """

    def stream(self, depthFirst: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[GTreeNode]:
        """
        Returns a stream of the GTree nodes in the subtree of this node
        
        :param jpype.JBoolean or bool depthFirst: if true, the nodes will be streamed in depth-first order, otherwise
                    breadth-first order
        :return: a stream of the GTree nodes in the subtree of this node
        :rtype: java.util.stream.Stream[GTreeNode]
        """

    def valueChanged(self, newValue: java.lang.Object):
        """
        Notification method called when a cell editor completes editing to notify this node that its
        value has changed. If you override this method you must also override :meth:`isEditable() <.isEditable>`.
        
        :param java.lang.Object newValue: the new value provided by the cell editor
        
        .. seealso::
        
            | :obj:`.isEditable()`
        """

    @property
    def displayText(self) -> java.lang.String:
        ...

    @property
    def editable(self) -> jpype.JBoolean:
        ...

    @property
    def ancestor(self) -> jpype.JBoolean:
        ...

    @property
    def toolTip(self) -> java.lang.String:
        ...

    @property
    def indexInParent(self) -> jpype.JInt:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def indexOfChild(self) -> jpype.JInt:
        ...

    @property
    def childCount(self) -> jpype.JInt:
        ...

    @property
    def leaf(self) -> jpype.JBoolean:
        ...

    @property
    def autoExpandPermitted(self) -> jpype.JBoolean:
        ...

    @property
    def expanded(self) -> jpype.JBoolean:
        ...

    @property
    def leafCount(self) -> jpype.JInt:
        ...

    @property
    def children(self) -> java.util.List[GTreeNode]:
        ...

    @children.setter
    def children(self, value: java.util.List[GTreeNode]):
        ...

    @property
    def root(self) -> GTreeNode:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def nodeCount(self) -> jpype.JInt:
        ...

    @property
    def treePath(self) -> javax.swing.tree.TreePath:
        ...

    @property
    def child(self) -> GTreeNode:
        ...


class TreeTextFilter(docking.widgets.tree.support.GTreeFilter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, textFilter: docking.widgets.filter.TextFilter, transformer: ghidra.util.FilterTransformer[GTreeNode]):
        ...


class DefaultGTreeFilterProvider(GTreeFilterProvider):

    @typing.type_check_only
    class FilterDocumentListener(docking.widgets.filter.FilterListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: GTree):
        ...

    def getFilterOptions(self) -> docking.widgets.filter.FilterOptions:
        ...

    def setFilterOptions(self, filterOptions: docking.widgets.filter.FilterOptions):
        """
        Sets the options for this filter provider.
        
        :param docking.widgets.filter.FilterOptions filterOptions: the new filter options
        """

    def setPreferredFilterOptions(self, filterOptions: docking.widgets.filter.FilterOptions):
        """
        A method to allow clients to change the current filter settings to something they would like
        for their particular use case.  This differs from :meth:`setFilterOptions(FilterOptions) <.setFilterOptions>` in
        that this method will also disable saving any changes the user makes to the filter.  If you
        do not need to disable preference saving, then call the other method.
         
        
        This method disables preference saving with the assumption that some clients always wish the
        filter to start in the same preferred state instead of where the user last left it.
        It is not clear  why we do that, but it is probably based on the assumption that the API 
        client wants the filter to always start in the preferred state.  The prevents filter from 
        being restored with a previous user filter that does not make sense for the general case.
        
        :param docking.widgets.filter.FilterOptions filterOptions: the options
        
        .. seealso::
        
            | :obj:`.setFilterOptions(FilterOptions)`
        """

    @property
    def filterOptions(self) -> docking.widgets.filter.FilterOptions:
        ...

    @filterOptions.setter
    def filterOptions(self, value: docking.widgets.filter.FilterOptions):
        ...


class GTreeTask(ghidra.util.worker.PriorityJob):

    @typing.type_check_only
    class CheckCancelledRunnable(java.lang.Runnable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, runnable: java.lang.Runnable):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def runOnSwingThread(self, runnable: java.lang.Runnable):
        ...


class GTreeFilterFactory(java.lang.Object):

    @typing.type_check_only
    class PrependPathWrappingTransformer(ghidra.util.FilterTransformer[GTreeNode]):
        """
        A class that takes in a client node filter transformer and wraps it so that any text returned
        by the client will have the node path prepended.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, filterOptions: docking.widgets.filter.FilterOptions):
        ...

    def getFilterOptions(self) -> docking.widgets.filter.FilterOptions:
        ...

    def getFilterStateIcon(self) -> javax.swing.Icon:
        ...

    def getTreeFilter(self, text: typing.Union[java.lang.String, str], transformer: ghidra.util.FilterTransformer[GTreeNode]) -> docking.widgets.tree.support.GTreeFilter:
        ...

    def isDefault(self) -> bool:
        ...

    @property
    def default(self) -> jpype.JBoolean:
        ...

    @property
    def filterStateIcon(self) -> javax.swing.Icon:
        ...

    @property
    def filterOptions(self) -> docking.widgets.filter.FilterOptions:
        ...


class GTreeSlowLoadingNode(GTreeLazyNode):
    """
    Base class for nodes that generate their children on demand, but because generating their
    children is slow, that operation is moved to a background thread. While the children are being
    generated, an :obj:`InProgressGTreeNode` will appear in the tree until the
    :obj:`LoadChildrenTask` has completed.
    """

    @typing.type_check_only
    class LoadChildrenTask(GTreeTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def generateChildren(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[GTreeNode]:
        """
        Subclass must implement this method to generate their children. This operation will always be
        performed in a background thread (i.e. Not the swing thread)
        
        :param ghidra.util.task.TaskMonitor monitor: a TaskMonitor for reporting progress and cancel notification.
        :return: the list of children for this node.
        :rtype: java.util.List[GTreeNode]
        :raises CancelledException: if the monitor is cancelled
        """


class TreeTaskMonitor(ghidra.util.task.TaskMonitor):
    """
    TaskMonitor implementation that is useful for monitor work when traversing trees.  
     
    It works by subdividing the distance of the top-most progress bar (represented by the top-most
    monitor) into equal size chunks depending on how many children have to be visited.  For example, 
    assume the root node has 5 children, then the task bar for that node would increment 20% of
    the bar as it completed work on each of its children. Now, assume each child of the root node 
    has 10 children. The task monitor for each root child will operate entirely with its 20% as 
    mentioned above.  So the first child of the first child will increment the progress bar 
    2% (10% of 20%) when it is complete.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, max: typing.Union[jpype.JLong, int]):
        ...


class GTree(javax.swing.JPanel, ghidra.util.task.BusyListener):
    """
    Class for creating a JTree that supports filtering, threading, and a progress bar.
     
    
    Note: when calling methods on this class to select nodes, if those nodes are threaded, or extend
    from :obj:`GTreeSlowLoadingNode`, then you must first expand the paths you wish to select.  You
    can do this by calling :meth:`expandAndSelectPaths(List) <.expandAndSelectPaths>`.  The various select methods of this 
    class will not expand nodes, but they will trigger children to be loaded.  If those nodes are not
    threaded, then the tree will add and expand the children by default.  When using threaded nodes, 
    the delay in loading prevents the tree from correctly expanding the paths.
    """

    @typing.type_check_only
    class AutoScrollTree(javax.swing.JTree, java.awt.dnd.Autoscroll):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: javax.swing.tree.TreeModel):
            ...

        def addMouseListener(self, l: java.awt.event.MouseListener):
            """
            Need to override the addMouseListener method of the JTree to defer to the delegate mouse
            listener. The GTree uses a mouse listener delegate for itself and the JTree it wraps.
            When the delegate was installed, it moved all the existing mouse listeners from the JTree
            to the delegate. Any additional listeners should also be moved to the delegate.
            Otherwise, some Ghidra components that use a convention/pattern to avoid listener
            duplication by first removing a listener before adding it, don't work and duplicates get
            added.
            """

        def getDefaultToolTipText(self, event: java.awt.event.MouseEvent) -> str:
            ...

        def isRootAllowedToCollapse(self) -> bool:
            ...

        def removeMouseListener(self, l: java.awt.event.MouseListener):
            """
            Need to override the removeMouseListener method of the JTree to defer to the delegate
            mouse listener. The GTree uses a mouse listener delegate for itself and the JTree it
            wraps. When the delegate was installed, it moved all the existing mouse listeners from
            the JTree to the delegate. All listener remove calls should also be moved to the
            delegate. Otherwise, some Ghidra components that use a convention/pattern to avoid
            listener duplication by first removing a listener before adding it, don't work and
            duplicates get added.
            """

        def setPaintHandlesForLeafNodes(self, enable: typing.Union[jpype.JBoolean, bool]):
            ...

        def setRootNodeAllowedToCollapse(self, allowed: typing.Union[jpype.JBoolean, bool]):
            ...

        def setScrollableUnitIncrement(self, increment: typing.Union[jpype.JInt, int]):
            ...

        @property
        def defaultToolTipText(self) -> java.lang.String:
            ...

        @property
        def rootAllowedToCollapse(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class GTreeMouseListenerDelegate(docking.widgets.JTreeMouseListenerDelegate):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GTreeAction(docking.action.DockingAction, docking.action.ComponentBasedDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, root: GTreeNode):
        """
        Creates a GTree with the given root node. The created GTree will use a threaded model for
        performing tasks, which allows the GUI to be responsive for reaaaaaaaaly big trees.
        
        :param GTreeNode root: The root node of the tree.
        """

    def addGTModelListener(self, listener: javax.swing.event.TreeModelListener):
        ...

    def addGTreeSelectionListener(self, listener: docking.widgets.tree.support.GTreeSelectionListener):
        ...

    def addSelectionPath(self, path: javax.swing.tree.TreePath):
        ...

    def addTreeExpansionListener(self, listener: javax.swing.event.TreeExpansionListener):
        ...

    def cancelEditing(self):
        ...

    def cancelWork(self):
        """
        Signals that any multithreaded work should be cancelled.
        """

    def clearFilter(self):
        ...

    def clearSelectionPaths(self):
        ...

    def clearSizeCache(self):
        ...

    def collapseAll(self, node: GTreeNode):
        ...

    @staticmethod
    def createSharedActions(tool: docking.Tool, toolActions: docking.actions.ToolActions, owner: typing.Union[java.lang.String, str]):
        ...

    def dispose(self):
        ...

    def expandAll(self):
        ...

    def expandAndSelectPaths(self, paths: java.util.List[javax.swing.tree.TreePath]):
        """
        Expands and then selects the given paths.  You must use this method if your tree is using
        :obj:`GTreeSlowLoadingNode`s.  Otherwise, if the given paths are not expanded, then the 
        select will not work.  More info at the class javadoc.
        
        :param java.util.List[javax.swing.tree.TreePath] paths: the paths
        """

    @typing.overload
    def expandPath(self, node: GTreeNode):
        ...

    @typing.overload
    def expandPath(self, path: javax.swing.tree.TreePath):
        ...

    @typing.overload
    def expandPaths(self, paths: jpype.JArray[javax.swing.tree.TreePath]):
        ...

    @typing.overload
    def expandPaths(self, paths: java.util.List[javax.swing.tree.TreePath]):
        ...

    def expandTree(self, node: GTreeNode):
        ...

    def expandedStateRestored(self, taskMonitor: ghidra.util.task.TaskMonitor):
        """
        A method that subclasses can use to be notified when tree state has been restored. This
        method is called after a major structural tree change has happened **and** the paths that
        should be opened have been opened. Thus any other nodes are closed and can be disposed, if
        desired.
        
        :param ghidra.util.task.TaskMonitor taskMonitor: the TaskMonitor
        """

    def filterChanged(self):
        ...

    def getCellEditor(self) -> javax.swing.CellEditor:
        ...

    def getCellRenderer(self) -> docking.widgets.tree.support.GTreeRenderer:
        ...

    def getDragNDropHandler(self) -> docking.widgets.tree.support.GTreeDragNDropHandler:
        ...

    @typing.overload
    def getExpandedPaths(self) -> java.util.List[javax.swing.tree.TreePath]:
        ...

    @typing.overload
    def getExpandedPaths(self, node: GTreeNode) -> java.util.List[javax.swing.tree.TreePath]:
        ...

    def getFilter(self) -> docking.widgets.tree.support.GTreeFilter:
        ...

    def getFilterField(self) -> java.awt.Component:
        """
        Returns the filter text field in this tree.
        
        :return: the filter text field in this tree.
        :rtype: java.awt.Component
        """

    def getFilterProvider(self) -> GTreeFilterProvider:
        ...

    def getFilterText(self) -> str:
        ...

    def getGTSelectionModel(self) -> docking.widgets.tree.internal.GTreeSelectionModel:
        ...

    def getModel(self) -> docking.widgets.tree.internal.GTreeModel:
        """
        Returns the model for this tree
        
        :return: the model for this tree
        :rtype: docking.widgets.tree.internal.GTreeModel
        """

    def getModelNode(self, node: GTreeNode) -> GTreeNode:
        """
        Gets the model node for the given node. This is useful if the node that is in the path has
        been replaced by a new node that is equal, but a different instance. One way this happens is
        if the tree is filtered and therefor the displayed nodes are clones of the model nodes. This
        can also happen if the tree nodes are rebuilt for some reason.
        
        :param GTreeNode node: the node
        :return: the corresponding model node in the tree. If the tree is filtered the viewed node
                will be a clone of the corresponding model node.
        :rtype: GTreeNode
        """

    def getModelNodeForPath(self, path: javax.swing.tree.TreePath) -> GTreeNode:
        """
        Gets the model node for the given path. This is useful if the node that is in the path has
        been replaced by a new node that is equal, but a different instance. One way this happens is
        if the tree is filtered and therefor the displayed nodes are clones of the model nodes. This
        can also happen if the tree nodes are rebuilt for some reason.
        
        :param javax.swing.tree.TreePath path: the path of the node
        :return: the corresponding model node in the tree. If the tree is filtered the viewed node
                will be a clone of the corresponding model node.
        :rtype: GTreeNode
        """

    def getModelRoot(self) -> GTreeNode:
        """
        This method returns the root node that was provided to the tree by the client, whether from
        the constructor or from :meth:`setRootNode(GTreeNode) <.setRootNode>`. This node represents the data model
        and always contains all the nodes regardless of any filter being applied. If a filter is
        applied to the tree, then this is not the actual root node being displayed by the
        :obj:`JTree`.
        
        :return: the root node as provided by the client.
        :rtype: GTreeNode
        """

    def getNodeForLocation(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> GTreeNode:
        ...

    def getPathBounds(self, path: javax.swing.tree.TreePath) -> java.awt.Rectangle:
        ...

    def getPathForLocation(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> javax.swing.tree.TreePath:
        ...

    def getPathForRow(self, row: typing.Union[jpype.JInt, int]) -> javax.swing.tree.TreePath:
        ...

    def getPreferenceKey(self) -> str:
        """
        Returns the key that this tree uses to store preferences.
        
        :return: the key that this tree uses to store preferences.
        :rtype: str
        """

    def getRowCount(self) -> int:
        ...

    def getRowForPath(self, treePath: javax.swing.tree.TreePath) -> int:
        ...

    def getSelectedNodes(self) -> java.util.List[GTreeNode]:
        ...

    def getSelectionModel(self) -> javax.swing.tree.TreeSelectionModel:
        ...

    def getSelectionPath(self) -> javax.swing.tree.TreePath:
        ...

    def getSelectionPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    @typing.overload
    def getTreeState(self) -> GTreeState:
        """
        Returns a state object that allows this tree to later restore its expanded and selected
        state.
         
        
        **Note: **See the usage note at the header of this class concerning how tree state is used
        relative to the ``equals()`` method.
        
        :return: the saved state
        :rtype: GTreeState
        """

    @typing.overload
    def getTreeState(self, node: GTreeNode) -> GTreeState:
        ...

    def getViewNode(self, node: GTreeNode) -> GTreeNode:
        """
        Gets the view node for the given node. This is useful to translate to a tree path that is
        valid for the currently displayed tree. (Remember that if the tree is filtered, then the
        displayed nodes are clones of the model nodes.)
        
        :param GTreeNode node: the node
        :return: the current node in the displayed (possibly filtered) tree
        :rtype: GTreeNode
        """

    def getViewNodeForPath(self, path: javax.swing.tree.TreePath) -> GTreeNode:
        """
        Gets the view node for the given path. This is useful to translate to a tree path that is
        valid for the currently displayed tree. (Remember that if the tree is filtered, then the
        displayed nodes are clones of the model nodes.)
        
        :param javax.swing.tree.TreePath path: the path of the node
        :return: the current node in the displayed (possibly filtered) tree
        :rtype: GTreeNode
        """

    def getViewPosition(self) -> java.awt.Point:
        """
        Returns the current viewport position of the scrollable tree.
        
        :return: the current viewport position of the scrollable tree.
        :rtype: java.awt.Point
        """

    def getViewRect(self) -> java.awt.Rectangle:
        ...

    def getViewRoot(self) -> GTreeNode:
        """
        This method returns the root node currently being displayed by the :obj:`JTree`. If there
        are no filters applied, then this will be the same as the model root (See
        :meth:`getModelRoot() <.getModelRoot>`). If a filter is applied, then this will be a clone of the model root
        that contains clones of all nodes matching the filter.
        
        :return: the root node currently being display by the :obj:`JTree`
        :rtype: GTreeNode
        """

    def hasFilterText(self) -> bool:
        ...

    def isBusy(self) -> bool:
        ...

    def isCollapsed(self, path: javax.swing.tree.TreePath) -> bool:
        ...

    def isDisposed(self) -> bool:
        ...

    def isEditing(self) -> bool:
        ...

    def isExpanded(self, treePath: javax.swing.tree.TreePath) -> bool:
        ...

    def isFiltered(self) -> bool:
        ...

    def isFilteringEnabled(self) -> bool:
        ...

    def isMyJTree(self, jTree: javax.swing.JTree) -> bool:
        """
        Returns true if the given JTree is the actual JTree used by this GTree.
        
        :param javax.swing.JTree jTree: the tree to test
        :return: true if the given JTree is the actual JTree used by this GTree.
        :rtype: bool
        """

    def isPathEditable(self, path: javax.swing.tree.TreePath) -> bool:
        ...

    def isPathSelected(self, treePath: javax.swing.tree.TreePath) -> bool:
        ...

    def isRootAllowedToCollapse(self) -> bool:
        ...

    def isRootVisible(self) -> bool:
        ...

    @staticmethod
    def printEvent(out: java.io.PrintWriter, name: typing.Union[java.lang.String, str], e: javax.swing.event.TreeModelEvent):
        """
        This method is useful for debugging tree problems. Don't know where else to put it.
        
        :param java.io.PrintWriter out: the output writer
        :param java.lang.String or str name: use this to indicate what tree event occurred ("node inserted" "node removed",
                    etc.)
        :param javax.swing.event.TreeModelEvent e: the TreeModelEvent;
        """

    @typing.overload
    def refilterLater(self):
        """
        Causes the tree to refilter some time later
        """

    @typing.overload
    def refilterLater(self, newNode: GTreeNode):
        """
        Re-filters the tree if the newNode should be included in the current filter results. If the
        new node doesn't match the filter, there is no need to refilter the tree.
        
        :param GTreeNode newNode: the node that may cause the tree to refilter.
        """

    def refilterNow(self):
        """
        Causes the tree to refilter immediately (before this method returns)
        """

    def removeGTModelListener(self, listener: javax.swing.event.TreeModelListener):
        ...

    def removeGTreeSelectionListener(self, listener: docking.widgets.tree.support.GTreeSelectionListener):
        ...

    def removeTreeExpansionListener(self, listener: javax.swing.event.TreeExpansionListener):
        ...

    def restoreTreeState(self, state: GTreeState):
        """
        Restores the expanded and selected state of this tree to that contained in the given state
        object.
         
        
        **Note: **See the usage note at the header of this class concerning how tree state is used
        relative to the ``equals()`` method.
        
        :param GTreeState state: the state to restore
        
        .. seealso::
        
            | :obj:`.getTreeState()`
        
            | :obj:`.getTreeState(GTreeNode)`
        """

    def runBulkTask(self, task: docking.widgets.tree.tasks.GTreeBulkTask):
        ...

    @typing.overload
    def runTask(self, task: GTreeTask):
        """
        Used to run tree tasks. This method is not meant for general clients of this tree, but rather
        for tasks to tell the tree to perform subtasks.
        
        :param GTreeTask task: the task to run
        """

    @typing.overload
    def runTask(self, runnableTask: ghidra.util.task.MonitoredRunnable):
        """
        Used to run simple GTree tasks that can be expressed as a :obj:`MonitoredRunnable` (or a
        lambda taking a :obj:`TaskMonitor`).
        
        :param ghidra.util.task.MonitoredRunnable runnableTask: :obj:`TaskMonitor` to watch and update with progress.
        """

    def scrollPathToVisible(self, treePath: javax.swing.tree.TreePath):
        ...

    def setAccessibleNamePrefix(self, namePrefix: typing.Union[java.lang.String, str]):
        """
        Sets an accessible name on the GTree. This prefix will be used to assign
        meaningful accessible names to the tree, filter text field and the filter options button such
        that screen readers will properly describe them.
         
        
        This prefix should be the base name that describes the type of items in the tree.
        This method will then append the necessary information to name the text field and the button.
        
        :param java.lang.String or str namePrefix: the accessible name prefix to assign to the filter component. For
        example if the tree contains fruits, then "Fruits" would be an appropriate prefix name.
        """

    def setActiveDropTargetNode(self, node: GTreeNode):
        ...

    def setCellEditor(self, editor: javax.swing.tree.TreeCellEditor):
        ...

    def setCellRenderer(self, renderer: docking.widgets.tree.support.GTreeRenderer):
        ...

    def setDataTransformer(self, transformer: ghidra.util.FilterTransformer[GTreeNode]):
        """
        Sets a transformer object used to perform filtering. This object is responsible for turning
        the tree's nodes into a list of strings that can be searched when filtering.
        
        :param ghidra.util.FilterTransformer[GTreeNode] transformer: the transformer to set
        """

    def setDoubleClickExpansionEnabled(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Enable or disable using double-click to open and close tree nodes.  The default is true.
        
        :param jpype.JBoolean or bool b: true to enable
        """

    def setDragNDropHandler(self, dragNDropHandler: docking.widgets.tree.support.GTreeDragNDropHandler):
        ...

    def setEditable(self, editable: typing.Union[jpype.JBoolean, bool]):
        ...

    def setEventsEnabled(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Turns tree event notifications on/off
        
        :param jpype.JBoolean or bool b: true to enable events, false to disable events
        """

    def setFilterFieldEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Disabled the filter text field, but allows the tree to still filter. This is useful if you
        want to allow programmatic filtering, but to not allow the user to filter.
        
        :param jpype.JBoolean or bool enabled: True makes the filter field editable; false makes it uneditable
        
        .. seealso::
        
            | :obj:`.setFilteringEnabled(boolean)`
        """

    def setFilterProvider(self, filterProvider: GTreeFilterProvider):
        ...

    def setFilterText(self, text: typing.Union[java.lang.String, str]):
        ...

    def setFilterVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Hides the filter field. Filtering will still take place, as defined by the
        :obj:`GTreeFilterProvider`.
        
        :param jpype.JBoolean or bool visible: true to show the filter; false to hide it.
        
        .. seealso::
        
            | :obj:`.setFilteringEnabled(boolean)`
        """

    def setFilteringEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Disables all filtering performed by this tree. Also, the filter field of the tree will be
        disabled.
         
        
        Use this method to temporarily disable filtering.
        
        :param jpype.JBoolean or bool enabled: True to allow normal filtering; false to disable all filtering
        
        .. seealso::
        
            | :obj:`.setFilterFieldEnabled(boolean)`
        """

    def setHorizontalScrollPolicy(self, policy: typing.Union[jpype.JInt, int]):
        ...

    def setNodeEditable(self, child: GTreeNode):
        ...

    def setPaintHandlesForLeafNodes(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Passing a value of ``false`` signals to disable the :obj:`JTree`'s default behavior
        of showing handles for leaf nodes until they are opened.
        
        :param jpype.JBoolean or bool enable: False to disable the default JTree behavior
        """

    def setRootNode(self, rootNode: GTreeNode):
        """
        Sets the root node for this tree.
         
        
        NOTE: if this method is not called from the Swing thread, then the root node will be set
        later on the Swing thread. That is, this method will return before the work has been done.
        
        :param GTreeNode rootNode: The node to set as the new root.
        """

    def setRootNodeAllowedToCollapse(self, allowed: typing.Union[jpype.JBoolean, bool]):
        ...

    def setRootVisible(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setRowHeight(self, rowHeight: typing.Union[jpype.JInt, int]):
        ...

    def setScrollableUnitIncrement(self, increment: typing.Union[jpype.JInt, int]):
        """
        Sets the size of the scroll when mouse scrolling or pressing the scroll up/down buttons. Most
        clients will not need this method, as the default behavior of the tree is correct, which is
        to scroll based upon the size of the nodes (which is usually uniform and a single row in
        size). However, some clients that have variable row height, with potentially large rows, may
        wish to change the scrolling behavior so that it is not too fast.
        
        :param jpype.JInt or int increment: the new (uniform) scroll increment.
        """

    def setSelectedNode(self, node: GTreeNode):
        ...

    def setSelectedNodeByNamePath(self, namePath: jpype.JArray[java.lang.String]):
        """
        A convenience method to select a node by a path, starting with the tree root name, down each
        level until the desired node name.
        
        :param jpype.JArray[java.lang.String] namePath: The path to select
        """

    def setSelectedNodeByPathName(self, treePath: javax.swing.tree.TreePath):
        """
        Selects the node that matches the each name in the given tree path. It is worth noting that
        the items in the tree path themselves are not used to identify nodes, but the
        :meth:`toString() <.toString>` of those items will be used.
        
        :param javax.swing.tree.TreePath treePath: The path containing the names of the path of the node to select
        """

    @typing.overload
    def setSelectedNodes(self, *nodes: GTreeNode):
        ...

    @typing.overload
    def setSelectedNodes(self, nodes: collections.abc.Sequence):
        ...

    def setSelectionModel(self, selectionModel: docking.widgets.tree.internal.GTreeSelectionModel):
        ...

    def setSelectionPath(self, path: javax.swing.tree.TreePath):
        ...

    @typing.overload
    def setSelectionPaths(self, paths: jpype.JArray[javax.swing.tree.TreePath]):
        ...

    @typing.overload
    def setSelectionPaths(self, pathsList: java.util.List[javax.swing.tree.TreePath]):
        ...

    @typing.overload
    def setSelectionPaths(self, paths: jpype.JArray[javax.swing.tree.TreePath], origin: docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin):
        ...

    @typing.overload
    def setSelectionPaths(self, paths: java.util.List[javax.swing.tree.TreePath], expandPaths: typing.Union[jpype.JBoolean, bool], origin: docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin):
        """
        Selects the given paths, expanding them first if requested.
        
        :param java.util.List[javax.swing.tree.TreePath] paths: the paths to select
        :param jpype.JBoolean or bool expandPaths: true to expand the paths first; this is only needed for multi-threaded 
        nodes.  Non-threaded nodes should use false, as it increase performance.
        :param docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin origin: the event type; use :obj:`EventOrigin.API_GENERATED` if unsure
        """

    def setSeletedNodeByName(self, parentNode: GTreeNode, childName: typing.Union[java.lang.String, str]):
        """
        A convenience method that allows clients that have created a new child node to select that
        node in the tree, without having to lookup the actual GTreeNode implementation.
        
        :param GTreeNode parentNode: The parent containing a child by the given name
        :param java.lang.String or str childName: The name of the child to select
        """

    def setShowsRootHandles(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setViewPosition(self, p: java.awt.Point):
        ...

    @typing.overload
    def startEditing(self, parent: GTreeNode, childName: typing.Union[java.lang.String, str]):
        """
        Requests that the node with the given name, in the given parent, be edited. This operation is
        asynchronous. This request will be buffered as needed to wait for the given node to be added
        to the parent, up to a timeout period.
         
        
        Note: if there are multiple nodes by the given name under the given parent, then no editing
        will take place.  In that case, you can instead use :meth:`startEditing(GTreeNode) <.startEditing>`, if you
        have the node.  If you have duplicates and do not yet have the node, then you will need to 
        create your own mechanism for waiting for the desired node and then starting the edit.
        
        :param GTreeNode parent: the parent node
        :param java.lang.String or str childName: the name of the child to edit
        """

    @typing.overload
    def startEditing(self, node: GTreeNode):
        """
        Requests that the node be edited. This operation is asynchronous.
        
        :param GTreeNode node: the node to edit
        """

    def stopEditing(self):
        ...

    @typing.overload
    def whenNodeIsReady(self, parent: GTreeNode, matches: java.util.function.Predicate[GTreeNode], consumer: java.util.function.Consumer[GTreeNode]):
        """
        A specialized method that will get the child node from the given parent node when it becomes
        available to the model. This method will ensure that the matching child passes any current
        filter in order for the child to appear in the tree. This effect is temporary and will be
        undone when next the filter changes.
        
         
        
        This method is intended to be used by clients using an asynchronous node model, where new
        nodes will get created by application-level events. Such clients may wish to perform work
        when newly created nodes become available. This method simplifies the concurrent nature of
        the GTree, asynchronous nodes and the processing of asynchronous application-level events by
        providing a callback mechanism for clients. **This method is non-blocking.**
        
         
        
        Note: this method assumes that the given parent node is in the view and not filtered out of
        the view. This method makes no attempt to ensure the given parent node passes any existing
        filter.
        
         
        
        Note: this method will not wait forever for the given node to appear. It will eventually give
        up if the node never arrives.
        
        :param GTreeNode parent: the model's parent node. If the view's parent node is passed, it will be
                    translated to the model node.
        :param java.util.function.Predicate[GTreeNode] matches: the predicate that returns true when the given node is the desired node
        :param java.util.function.Consumer[GTreeNode] consumer: the consumer callback to which the child node will be given when available
        """

    @typing.overload
    def whenNodeIsReady(self, parent: GTreeNode, childName: typing.Union[java.lang.String, str], consumer: java.util.function.Consumer[GTreeNode]):
        """
        A specialized method that will get the child node from the given parent node when it becomes
        available to the model. This method will ensure that the named child passes any current
        filter in order for the child to appear in the tree. This effect is temporary and will be
        undone when next the filter changes.
        
         
        
        This method is intended to be used by clients using an asynchronous node model, where new
        nodes will get created by application-level events. Such clients may wish to perform work
        when newly created nodes become available. This method simplifies the concurrent nature of
        the GTree, asynchronous nodes and the processing of asynchronous application-level events by
        providing a callback mechanism for clients. **This method is non-blocking.**
        
         
        
        Note: this method assumes that the given parent node is in the view and not filtered out of
        the view. This method makes no attempt to ensure the given parent node passes any existing
        filter.
        
         
        
        Note: this method will not wait forever for the given node to appear. It will eventually give
        up if the node never arrives.
         
         
        
        Note: if your parent node allows duplicate nodes then this method may not match the correct
        node.  If that is the case, then use 
        :meth:`whenNodeIsReady(GTreeNode, Predicate, Consumer) <.whenNodeIsReady>`.
        
        :param GTreeNode parent: the model's parent node. If the view's parent node is passed, it will be
                    translated to the model node.
        :param java.lang.String or str childName: the name of the desired child
        :param java.util.function.Consumer[GTreeNode] consumer: the consumer callback to which the child node will be given when available
        """

    @property
    def rowForPath(self) -> jpype.JInt:
        ...

    @property
    def viewNode(self) -> GTreeNode:
        ...

    @property
    def viewNodeForPath(self) -> GTreeNode:
        ...

    @property
    def selectedNodes(self) -> java.util.List[GTreeNode]:
        ...

    @property
    def viewPosition(self) -> java.awt.Point:
        ...

    @viewPosition.setter
    def viewPosition(self, value: java.awt.Point):
        ...

    @property
    def modelRoot(self) -> GTreeNode:
        ...

    @property
    def filteringEnabled(self) -> jpype.JBoolean:
        ...

    @filteringEnabled.setter
    def filteringEnabled(self, value: jpype.JBoolean):
        ...

    @property
    def filtered(self) -> jpype.JBoolean:
        ...

    @property
    def cellEditor(self) -> javax.swing.CellEditor:
        ...

    @property
    def gTSelectionModel(self) -> docking.widgets.tree.internal.GTreeSelectionModel:
        ...

    @property
    def model(self) -> docking.widgets.tree.internal.GTreeModel:
        ...

    @property
    def selectionPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    @selectionPaths.setter
    def selectionPaths(self, value: jpype.JArray[javax.swing.tree.TreePath]):
        ...

    @property
    def selectionPath(self) -> javax.swing.tree.TreePath:
        ...

    @selectionPath.setter
    def selectionPath(self, value: javax.swing.tree.TreePath):
        ...

    @property
    def modelNodeForPath(self) -> GTreeNode:
        ...

    @property
    def pathBounds(self) -> java.awt.Rectangle:
        ...

    @property
    def filterProvider(self) -> GTreeFilterProvider:
        ...

    @filterProvider.setter
    def filterProvider(self, value: GTreeFilterProvider):
        ...

    @property
    def filterText(self) -> java.lang.String:
        ...

    @filterText.setter
    def filterText(self, value: java.lang.String):
        ...

    @property
    def treeState(self) -> GTreeState:
        ...

    @property
    def pathForRow(self) -> javax.swing.tree.TreePath:
        ...

    @property
    def pathSelected(self) -> jpype.JBoolean:
        ...

    @property
    def rootAllowedToCollapse(self) -> jpype.JBoolean:
        ...

    @property
    def selectionModel(self) -> javax.swing.tree.TreeSelectionModel:
        ...

    @property
    def collapsed(self) -> jpype.JBoolean:
        ...

    @property
    def expanded(self) -> jpype.JBoolean:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def dragNDropHandler(self) -> docking.widgets.tree.support.GTreeDragNDropHandler:
        ...

    @dragNDropHandler.setter
    def dragNDropHandler(self, value: docking.widgets.tree.support.GTreeDragNDropHandler):
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...

    @property
    def preferenceKey(self) -> java.lang.String:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def rootVisible(self) -> jpype.JBoolean:
        ...

    @rootVisible.setter
    def rootVisible(self, value: jpype.JBoolean):
        ...

    @property
    def myJTree(self) -> jpype.JBoolean:
        ...

    @property
    def viewRoot(self) -> GTreeNode:
        ...

    @property
    def cellRenderer(self) -> docking.widgets.tree.support.GTreeRenderer:
        ...

    @cellRenderer.setter
    def cellRenderer(self, value: docking.widgets.tree.support.GTreeRenderer):
        ...

    @property
    def filterField(self) -> java.awt.Component:
        ...

    @property
    def modelNode(self) -> GTreeNode:
        ...

    @property
    def editing(self) -> jpype.JBoolean:
        ...

    @property
    def viewRect(self) -> java.awt.Rectangle:
        ...

    @property
    def filter(self) -> docking.widgets.tree.support.GTreeFilter:
        ...

    @property
    def expandedPaths(self) -> java.util.List[javax.swing.tree.TreePath]:
        ...

    @property
    def pathEditable(self) -> jpype.JBoolean:
        ...


class GTreeRestoreTreeStateTask(GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gTree: GTree, state: GTreeState):
        ...


class MultiTextFilterTreeFilter(docking.widgets.tree.support.GTreeFilter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filters: java.util.List[docking.widgets.filter.TextFilter], transformer: ghidra.util.FilterTransformer[GTreeNode], evalMode: docking.widgets.filter.MultitermEvaluationMode):
        ...


@typing.type_check_only
class GTreeRootParentNode(GTreeNode):
    """
    Artificial node used by the GTree to set as a parent on the real root node of a GTree.  It allows
    nodes to access the GTree because it overrides getTree to return the GTree. This eliminates the
    need for clients to create special root nodes that have getTree/setTree
    """

    class_: typing.ClassVar[java.lang.Class]


class GTreeFilterTask(GTreeTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: GTree, filter: docking.widgets.tree.support.GTreeFilter):
        ...


class GTreeState(java.lang.Object):
    """
    A class to remember the current state of the tree, for things like expanded paths, 
    selected paths and the view location.
     
     
    This class is used to restore state for uses so that updates to the tree do not cause the
    user to lose their spot.   
     
     
    Issues:
     
    * If the number of expanded items is too large, then the tree will spend a large 
    amount of time restoring, thus we limit the size of the expanded paths
    * If we have to trim the number of items we remember, we need to do so intelligently so
    that the user experience seems natural (for example, when trimming what to keep,
    be sure to first keep what is visible to the user, versus expanded/selected items
    that are scrolled off the top of the view.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tree: GTree):
        ...

    @typing.overload
    def __init__(self, tree: GTree, node: GTreeNode):
        ...

    def getExpandedPaths(self) -> java.util.List[javax.swing.tree.TreePath]:
        ...

    def getSelectedPaths(self) -> java.util.List[javax.swing.tree.TreePath]:
        ...

    def getViewPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        """
        Returns the top few paths that are visible in the view.
        
        :return: the top few paths that are visible in the view.
        :rtype: jpype.JArray[javax.swing.tree.TreePath]
        """

    def isEmpty(self) -> bool:
        ...

    def updateStateForMovedNodes(self):
        ...

    @property
    def expandedPaths(self) -> java.util.List[javax.swing.tree.TreePath]:
        ...

    @property
    def selectedPaths(self) -> java.util.List[javax.swing.tree.TreePath]:
        ...

    @property
    def viewPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class GTreeTextFilterFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getFilterOptions(self) -> docking.widgets.filter.FilterOptions:
        ...

    def getTreeFilter(self, filterText: typing.Union[java.lang.String, str], transformer: ghidra.util.FilterTransformer[GTreeNode]) -> docking.widgets.tree.support.GTreeFilter:
        ...

    def setFilterOptions(self, options: docking.widgets.filter.FilterOptions):
        ...

    @property
    def filterOptions(self) -> docking.widgets.filter.FilterOptions:
        ...

    @filterOptions.setter
    def filterOptions(self, value: docking.widgets.filter.FilterOptions):
        ...


class GTreeLazyNode(GTreeNode):
    """
    Base class for GTreeNodes that populate their children on demand (typically when expanded). 
    Also, children of this node can be unloaded by calling :meth:`unloadChildren() <.unloadChildren>`.  This
    can be used by nodes in large trees to save memory by unloading children that are no longer
    in the current tree view (collapsed).  Of course, that decision would need to be balanced
    against the extra time to reload the nodes in the event that a filter is applied. Also, if
    some external event occurs that changes the set of children for a GTreeLazyNode, you can call
    :meth:`unloadChildren() <.unloadChildren>` to clear any previously loaded children.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def unloadChildren(self):
        """
        Sets this lazy node back to the "unloaded" state such that if
        its children are accessed, it will reload its children as needed.
        """


class GTreeFilterProvider(java.lang.Object):
    """
    Interface for providing a filter for GTrees.
    """

    class_: typing.ClassVar[java.lang.Class]

    def activate(self):
        """
        Activates this filter by showing it, if not visible, and then requesting focus in the filter
        text field.
        """

    def copy(self, gTree: GTree) -> GTreeFilterProvider:
        """
        Creates a copy of this filter with all current filter settings.
         
        
        This is meant to be used for GTrees that support creating a new copy.  
         
        
        Note: Filter providers that do not support copying will return null from this method.
        
        :param GTree gTree: the new tree for the new filter
        :return: the copy
        :rtype: GTreeFilterProvider
        """

    def dispose(self):
        """
        A method for subclasses to do any optional cleanup
        """

    def getFilter(self) -> docking.widgets.tree.support.GTreeFilter:
        """
        returns the :obj:`GTreeFilter` object to apply to the GTree whenever the filter component
        is manipulated
        
        :return: the GTreeFilter to apply to the tree
        :rtype: docking.widgets.tree.support.GTreeFilter
        """

    def getFilterComponent(self) -> javax.swing.JComponent:
        """
        Returns the component to place at the bottom of a GTree to provider filtering capabilities.
        
        :return: the filter component
        :rtype: javax.swing.JComponent
        """

    def getFilterText(self) -> str:
        """
        Returns the current filter text.
        
        :return: the current filter text
        :rtype: str
        """

    def loadFilterPreference(self, windowManager: docking.DockingWindowManager):
        """
        Loads any filter preferences that have been saved.  
         
        
        This is called when the tree is first made visible in the tool.  This is the chance for the
        filter to load any preferences and to add a preference supplier to the window manager.
        
        :param docking.DockingWindowManager windowManager: the :obj:`DockingWindowManager` to load preferences from
        """

    def setAccessibleNamePrefix(self, namePrefix: typing.Union[java.lang.String, str]):
        """
        Sets an accessible name on the filter component. This prefix will be used to assign
        meaningful accessible names to the filter text field and the filter options button such
        that screen readers will properly describe them.
         
        
        This prefix should be the base name that describes the type of items in the tree. 
        This method will then append the necessary information to name the text field and the button.
        
        :param java.lang.String or str namePrefix: the accessible name prefix to assign to the filter component. For
        example if the tree contains fruits, then "Fruits" would be an appropriate prefix name.
        """

    def setDataTransformer(self, transformer: ghidra.util.FilterTransformer[GTreeNode]):
        """
        Sets a :obj:`FilterTransformer` for preparing tree data to be filtered.
        
        :param ghidra.util.FilterTransformer[GTreeNode] transformer: the transform for preparing tree data to be filtered
        """

    def setEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the active state for the filter component.
        
        :param jpype.JBoolean or bool enabled: true, the filter component is enabled
        """

    def setFilterText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the filter text for the filter.
        
        :param java.lang.String or str text: the text to filter on
        """

    def toggleVisibility(self):
        """
        Changes the visibility of the filter, make it not visible it if showing, showing it if
        not visible.
        """

    @property
    def filter(self) -> docking.widgets.tree.support.GTreeFilter:
        ...

    @property
    def filterText(self) -> java.lang.String:
        ...

    @filterText.setter
    def filterText(self, value: java.lang.String):
        ...

    @property
    def filterComponent(self) -> javax.swing.JComponent:
        ...



__all__ = ["CoreGTreeNode", "InvertedTreeFilter", "GTreeNode", "TreeTextFilter", "DefaultGTreeFilterProvider", "GTreeTask", "GTreeFilterFactory", "GTreeSlowLoadingNode", "TreeTaskMonitor", "GTree", "GTreeRestoreTreeStateTask", "MultiTextFilterTreeFilter", "GTreeRootParentNode", "GTreeFilterTask", "GTreeState", "GTreeTextFilterFactory", "GTreeLazyNode", "GTreeFilterProvider"]
