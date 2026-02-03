from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.dnd
import docking.widgets.tree
import ghidra.app.plugin.core.symboltree
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.awt.datatransfer # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class ParameterSymbolNode(SymbolNode):

    class_: typing.ClassVar[java.lang.Class]
    PARAMETER_ICON: typing.Final[javax.swing.Icon]


@typing.type_check_only
class ExportsCategoryNode(SymbolCategoryNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


class SearchKeySymbolNode(SymbolNode):
    """
    A special version of :obj:`SymbolNode` that is used as a key when searching for other 
    symbol nodes.  This class allows us to search for another symbol node using whatever 
    name is desired.
    """

    class_: typing.ClassVar[java.lang.Class]


class LocalVariableSymbolNode(SymbolNode):

    class_: typing.ClassVar[java.lang.Class]
    LOCAL_VARIABLE_ICON: typing.Final[javax.swing.Icon]


class CodeSymbolNode(SymbolNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, symbol: ghidra.program.model.symbol.Symbol):
        ...


class LibrarySymbolNode(SymbolNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class NamespaceCategoryNode(SymbolCategoryNode):

    class_: typing.ClassVar[java.lang.Class]
    OPEN_FOLDER_NAMESPACES_ICON: typing.Final[javax.swing.Icon]
    CLOSED_FOLDER_NAMESPACES_ICON: typing.Final[javax.swing.Icon]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    def isSupportedLocalFlavor(self, flavor: java.awt.datatransfer.DataFlavor) -> bool:
        ...

    @property
    def supportedLocalFlavor(self) -> jpype.JBoolean:
        ...


class SymbolTreeRootNode(docking.widgets.tree.GTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, groupThreshold: typing.Union[jpype.JInt, int]):
        ...

    def findSymbolTreeNode(self, key: SymbolNode, loadChildren: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> docking.widgets.tree.GTreeNode:
        ...

    def getNodeGroupThreshold(self) -> int:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getReorganizeLimit(self) -> int:
        ...

    def rebuild(self):
        ...

    def symbolAdded(self, symbol: ghidra.program.model.symbol.Symbol, monitor: ghidra.util.task.TaskMonitor) -> SymbolNode:
        ...

    @typing.overload
    def symbolRemoved(self, symbol: ghidra.program.model.symbol.Symbol, oldName: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def symbolRemoved(self, symbol: ghidra.program.model.symbol.Symbol, oldNamespace: ghidra.program.model.symbol.Namespace, monitor: ghidra.util.task.TaskMonitor):
        ...

    @property
    def nodeGroupThreshold(self) -> jpype.JInt:
        ...

    @property
    def reorganizeLimit(self) -> jpype.JInt:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class OrganizationNode(SymbolTreeNode):
    """
    These nodes are used to organize large lists of nodes into a hierarchical structure based on 
    the node names. See :meth:`organize(List, int, TaskMonitor) <.organize>` for details on 
    how this class works.
    """

    @typing.type_check_only
    class OrganizationNodeComparator(java.util.Comparator[docking.widgets.tree.GTreeNode]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MAX_SAME_NAME: typing.Final = 10

    def insertNode(self, newNode: docking.widgets.tree.GTreeNode):
        """
        Inserts the given node into this organization node which is different than calling the
        :meth:`addNode(GTreeNode) <.addNode>` method, which is used during construction.  This method knows
        how to recursively find the correct :obj:`OrganizationNode` node into which the given
        node should be inserted.
        
        :param docking.widgets.tree.GTreeNode newNode: the node to insert.
        """

    @staticmethod
    def organize(list: java.util.List[docking.widgets.tree.GTreeNode], maxGroupSize: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[docking.widgets.tree.GTreeNode]:
        """
        Subdivide the given list of nodes recursively such that there are generally not more
        than maxGroupSize number of nodes at any level. Also, if there are ever many
        nodes of the same name, a group for them will be created and only a few will be shown with
        an "xx more..." node to indicate there are additional nodes that are not shown.
         
        
        This algorithm uses the node names to group nodes based upon common prefixes.  For example,
        if a parent node contained more than ``maxNodes`` children then a possible grouping
        would be:
         
        -abc...
        --abca
        --abcb
        --abcc
        -g
         
        where the nodes given contained:
         
        abca
        abcb
        abcc
        g
         
        
        :param java.util.List[docking.widgets.tree.GTreeNode] list: list of child nodes of to breakup into smaller groups
        :param jpype.JInt or int maxGroupSize: the max number of nodes to allow before trying to organize into
        smaller groups
        :param ghidra.util.task.TaskMonitor monitor: the TaskMonitor to be checked for canceling this operation
        :return: the given ``list`` sub-grouped as outlined above
        :rtype: java.util.List[docking.widgets.tree.GTreeNode]
        :raises CancelledException: if the operation is cancelled
        """


class ClassCategoryNode(SymbolCategoryNode):

    class_: typing.ClassVar[java.lang.Class]
    OPEN_FOLDER_CLASSES_ICON: typing.Final[javax.swing.Icon]
    CLOSED_FOLDER_CLASSES_ICON: typing.Final[javax.swing.Icon]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


class NamespaceSymbolNode(SymbolNode):

    class_: typing.ClassVar[java.lang.Class]
    NAMESPACE_ICON: typing.Final[javax.swing.Icon]
    DISABLED_NAMESPACE_ICON: typing.Final[javax.swing.Icon]


class SymbolNode(SymbolTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createKeyNode(symbol: ghidra.program.model.symbol.Symbol, searchSymbolName: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> SymbolNode:
        ...

    @staticmethod
    def createNode(symbol: ghidra.program.model.symbol.Symbol, program: ghidra.program.model.listing.Program) -> SymbolNode:
        ...

    def getSymbolID(self) -> int:
        ...

    @property
    def symbolID(self) -> jpype.JLong:
        ...


class SymbolTreeNode(docking.widgets.tree.GTreeSlowLoadingNode):
    """
    Base class for all nodes that live in the :obj:`Symbol Tree <SymbolTreeProvider>`.  
     
     
    All nodes will provide a way to search for the node that represents a given symbol.  The
    'find' logic lives in this class so all nodes have this capability.  Some subclasses
    of this interface, those with the potential for thousands of children, will break their 
    children up into subgroups by name.  The search algorithm in this class will uses each 
    node's :meth:`getChildrenComparator() <.getChildrenComparator>` method in order to be able to find the correct
    symbol node whether or not the grouping nodes are used.   This allows each :obj:`GTreeNode`
    to keep its default :meth:`GTreeNode.compareTo(GTreeNode) <GTreeNode.compareTo>` method, while allow each 
    parent node to sort its children differently.
    """

    class_: typing.ClassVar[java.lang.Class]
    SYMBOL_COMPARATOR: typing.Final[java.util.Comparator[ghidra.program.model.symbol.Symbol]]

    def __init__(self):
        ...

    def canCut(self) -> bool:
        """
        Returns true if this node can be cut and moved to a different location.
        
        :return: true if this node can be cut and moved to a different location.
        :rtype: bool
        """

    def canPaste(self, pastedNodes: java.util.List[docking.widgets.tree.GTreeNode]) -> bool:
        """
        Returns true if this nodes handles paste operations
        
        :param java.util.List[docking.widgets.tree.GTreeNode] pastedNodes: the nodes to be pasted
        :return: true if this nodes handles paste operations
        :rtype: bool
        """

    def findSymbolTreeNode(self, key: SymbolNode, loadChildren: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> docking.widgets.tree.GTreeNode:
        """
        Locates the node that contains the given symbol.
         
         
        **Note: **This can degenerate into a brute-force search algorithm, but works in 
        all normal cases using a binary search.
        
        :param SymbolNode key: the node used to find an existing node.  This node is a node created that is
                used by the Comparators to perform binary searches.  These can be fabricated 
                by using :meth:`SymbolNode.createNode(Symbol, Program) <SymbolNode.createNode>`
        :param jpype.JBoolean or bool loadChildren: if true then children should be loaded, else quit early if 
                children are not loaded.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the node that contains the given symbol.
        :rtype: docking.widgets.tree.GTreeNode
        """

    def getChildrenComparator(self) -> java.util.Comparator[docking.widgets.tree.GTreeNode]:
        """
        Returns the comparator used to sort the children of this node.  This node will still 
        be sorted according to its own ``compareTo`` method, unless its parent has
        overridden this method.
        
        :return: the comparator used to sort this node's children
        :rtype: java.util.Comparator[docking.widgets.tree.GTreeNode]
        """

    def getNamespace(self) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the namespace for this symbol tree node.  Not all implementations contain symbols,
        but all category implementations represent a namespace and some symbol nodes represent a
        namespace.
        
        :return: the namespace for this symbol tree node.
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getNodeDataFlavor(self) -> java.awt.datatransfer.DataFlavor:
        """
        Gets the data flavor that this node supports for dragging.
        
        :return: the data flavor that this node supports for dragging.
        :rtype: java.awt.datatransfer.DataFlavor
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the symbol for this node, if it has one.
        
        :return: the symbol for this node; null if it not associated with a symbol
        :rtype: ghidra.program.model.symbol.Symbol
        """

    def isCut(self) -> bool:
        """
        Return true if the node has been cut.
        
        :return: true if the node has been cut.
        :rtype: bool
        """

    def setNodeCut(self, isCut: typing.Union[jpype.JBoolean, bool]):
        """
        Signals to this node that it has been cut during a cut operation, for example, like during
        a cut/paste operation.
        
        :param jpype.JBoolean or bool isCut: true signals that the node has been cut; false that it is not cut.
        """

    def supportsDataFlavors(self, dataFlavors: jpype.JArray[java.awt.datatransfer.DataFlavor]) -> bool:
        """
        Returns true if this node can accept any of the given data flavors for dropping.
        
        :param jpype.JArray[java.awt.datatransfer.DataFlavor] dataFlavors: the data flavors of an object being dragged.
        :return: true if this node can accept any of the given data flavors for dropping.
        :rtype: bool
        """

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def cut(self) -> jpype.JBoolean:
        ...

    @property
    def childrenComparator(self) -> java.util.Comparator[docking.widgets.tree.GTreeNode]:
        ...

    @property
    def namespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def nodeDataFlavor(self) -> java.awt.datatransfer.DataFlavor:
        ...


class ImportsCategoryNode(SymbolCategoryNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


@typing.type_check_only
class FunctionCategoryNode(SymbolCategoryNode):

    class_: typing.ClassVar[java.lang.Class]
    OPEN_FOLDER_FUNCTIONS_ICON: typing.Final[javax.swing.Icon]
    CLOSED_FOLDER_FUNCTIONS_ICON: typing.Final[javax.swing.Icon]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


class MoreNode(SymbolTreeNode):
    """
    Node to represent nodes that are not shown. After showing a handful of symbol nodes
    with the same name, this node will be used in place of the rest of the nodes and
    will display "xx more..." where xx is the number of nodes that are not being shown.
    """

    class_: typing.ClassVar[java.lang.Class]


class SymbolCategoryNode(SymbolTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbolCategory: ghidra.app.plugin.core.symboltree.SymbolCategory, p: ghidra.program.model.listing.Program):
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getSymbolCategory(self) -> ghidra.app.plugin.core.symboltree.SymbolCategory:
        ...

    def isEnabled(self) -> bool:
        ...

    def isModifiable(self) -> bool:
        ...

    def setEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def symbolAdded(self, symbol: ghidra.program.model.symbol.Symbol, monitor: ghidra.util.task.TaskMonitor) -> SymbolNode:
        ...

    @typing.overload
    def symbolRemoved(self, symbol: ghidra.program.model.symbol.Symbol, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def symbolRemoved(self, symbol: ghidra.program.model.symbol.Symbol, oldName: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def symbolRemoved(self, symbol: ghidra.program.model.symbol.Symbol, oldNamespace: ghidra.program.model.symbol.Namespace, monitor: ghidra.util.task.TaskMonitor):
        ...

    @property
    def symbolCategory(self) -> ghidra.app.plugin.core.symboltree.SymbolCategory:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def modifiable(self) -> jpype.JBoolean:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...


class ConfigurableSymbolTreeRootNode(SymbolTreeRootNode):
    """
    A version of the Symbol Tree's root node that allows users to disable categories.  The categories
    themselves track their enabled state.  This class supports the cloning of a 
    :obj:`DisconnectedSymbolTreeProvider` by copying the categories' enable state.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, groupThreshold: typing.Union[jpype.JInt, int]):
        ...

    def transferSettings(self, otherRoot: ConfigurableSymbolTreeRootNode):
        ...


class LabelCategoryNode(SymbolCategoryNode):

    class_: typing.ClassVar[java.lang.Class]
    OPEN_FOLDER_LABELS_ICON: typing.Final[javax.swing.Icon]
    CLOSED_FOLDER_LABELS_ICON: typing.Final[javax.swing.Icon]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


class ClassSymbolNode(SymbolNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SymbolTreeDataFlavor(docking.dnd.GenericDataFlavor):

    class_: typing.ClassVar[java.lang.Class]
    DATA_FLAVOR: typing.Final[java.awt.datatransfer.DataFlavor]

    def __init__(self, displayText: typing.Union[java.lang.String, str]):
        ...


class FunctionSymbolNode(SymbolNode):

    @typing.type_check_only
    class FunctionVariableComparator(java.util.Comparator[docking.widgets.tree.GTreeNode]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FUNCTION_ICON: typing.Final[javax.swing.Icon]
    THUNK_ICON: typing.Final[javax.swing.Icon]
    EXTERNAL_ICON: typing.Final[javax.swing.Icon]
    DISABLED_FUNCTION_ICON: typing.Final[javax.swing.Icon]
    DISABLED_THUNK_ICON: typing.Final[javax.swing.Icon]
    DISABLED_EXTERNAL_ICON: typing.Final[javax.swing.Icon]



__all__ = ["ParameterSymbolNode", "ExportsCategoryNode", "SearchKeySymbolNode", "LocalVariableSymbolNode", "CodeSymbolNode", "LibrarySymbolNode", "NamespaceCategoryNode", "SymbolTreeRootNode", "OrganizationNode", "ClassCategoryNode", "NamespaceSymbolNode", "SymbolNode", "SymbolTreeNode", "ImportsCategoryNode", "FunctionCategoryNode", "MoreNode", "SymbolCategoryNode", "ConfigurableSymbolTreeRootNode", "LabelCategoryNode", "ClassSymbolNode", "SymbolTreeDataFlavor", "FunctionSymbolNode"]
