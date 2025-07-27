from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import docking.widgets.tree
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore


class BreadthFirstIterator(java.util.Iterator[docking.widgets.tree.GTreeNode]):
    """
    Implements an iterator over all GTreeNodes in some gTree (or subtree).  The nodes are
    return in breadth first order.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, node: docking.widgets.tree.GTreeNode):
        ...


class GTreeFilter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def acceptsNode(self, node: docking.widgets.tree.GTreeNode) -> bool:
        ...

    def showFilterMatches(self) -> bool:
        """
        True signals that the matching nodes should be made visible, expanding the tree as 
        necessary.
        
        :return: True if the matching nodes should be made visible.
        :rtype: bool
        """


@typing.type_check_only
class DragNDropHandler(GTreeDragNDropHandler):

    class_: typing.ClassVar[java.lang.Class]
    supportedFlavors: typing.ClassVar[jpype.JArray[java.awt.datatransfer.DataFlavor]]


@typing.type_check_only
class DirectoryNode(docking.widgets.tree.GTreeLazyNode, FileData):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FileData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getFile(self) -> java.io.File:
        ...

    @property
    def file(self) -> java.io.File:
        ...


class GTreeSelectionEvent(java.lang.Object):

    class EventOrigin(java.lang.Enum[GTreeSelectionEvent.EventOrigin]):
        """
        An enum that contains the origin of the GTreeSelectionEvent (see each enum for more 
        details).
        """

        class_: typing.ClassVar[java.lang.Class]
        API_GENERATED: typing.Final[GTreeSelectionEvent.EventOrigin]
        """
        This event was triggered by an API on the GTree interface
        """

        INTERNAL_GENERATED: typing.Final[GTreeSelectionEvent.EventOrigin]
        """
        This event was triggered by an internal GTree selection change (e.g., filter change)
        """

        USER_GENERATED: typing.Final[GTreeSelectionEvent.EventOrigin]
        """
        This event was triggered by the **user** changing the selection via the GUI
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GTreeSelectionEvent.EventOrigin:
            ...

        @staticmethod
        def values() -> jpype.JArray[GTreeSelectionEvent.EventOrigin]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, event: javax.swing.event.TreeSelectionEvent, origin: GTreeSelectionEvent.EventOrigin):
        ...

    def getEventOrigin(self) -> GTreeSelectionEvent.EventOrigin:
        ...

    def getNewLeadSelectionPath(self) -> javax.swing.tree.TreePath:
        ...

    def getOldLeadSelectionPath(self) -> javax.swing.tree.TreePath:
        ...

    def getPath(self) -> javax.swing.tree.TreePath:
        ...

    def getPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    def getSource(self) -> java.lang.Object:
        ...

    @typing.overload
    def isAddedPath(self) -> bool:
        ...

    @typing.overload
    def isAddedPath(self, index: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @typing.overload
    def isAddedPath(self, path: javax.swing.tree.TreePath) -> bool:
        ...

    @property
    def newLeadSelectionPath(self) -> javax.swing.tree.TreePath:
        ...

    @property
    def path(self) -> javax.swing.tree.TreePath:
        ...

    @property
    def oldLeadSelectionPath(self) -> javax.swing.tree.TreePath:
        ...

    @property
    def addedPath(self) -> jpype.JBoolean:
        ...

    @property
    def paths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    @property
    def source(self) -> java.lang.Object:
        ...

    @property
    def eventOrigin(self) -> GTreeSelectionEvent.EventOrigin:
        ...


class GTreeNodeTransferable(java.awt.datatransfer.Transferable):
    """
    A transferable for sharing data via drag/drop and clipboard operations for GTrees
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handler: GTreeTransferHandler, selectedData: java.util.List[docking.widgets.tree.GTreeNode]):
        """
        Creates this transferable based upon the selected data and uses the given transfer
        handler to perform :obj:`Transferable` operations
        
        :param GTreeTransferHandler handler: the handler used to perform transfer operations
        :param java.util.List[docking.widgets.tree.GTreeNode] selectedData: The selected tree nodes
        """

    def getAllData(self) -> java.util.List[docking.widgets.tree.GTreeNode]:
        """
        Returns all of the original selected data contained by this transferable.
        
        :return: all of the original selected data contained by this transferable
        :rtype: java.util.List[docking.widgets.tree.GTreeNode]
        """

    def getTransferData(self, flavor: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        """
        Gets the transfer data from the selection based upon the given flavor
        
        :param java.awt.datatransfer.DataFlavor flavor: The flavor of data to retrieve from the given selection.
        :return: the transfer data from the selection based upon the given flavor.
        :rtype: java.lang.Object
        :raises UnsupportedFlavorException: if the given flavor is not one of the supported flavors
        returned by :meth:`getTransferDataFlavors() <.getTransferDataFlavors>`
        """

    def getTransferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Returns the DataFlavors for the types of data that this transferable supports, based upon
        the given selection
        
        :return: the DataFlavors for the types of data that this transferable supports, based upon
        the given selection
        :rtype: jpype.JArray[java.awt.datatransfer.DataFlavor]
        """

    def isDataFlavorSupported(self, flavor: java.awt.datatransfer.DataFlavor) -> bool:
        """
        A convenience method to determine if this transferable supports the given flavor
        
        :return: true if this transferable supports the given flavor
        :rtype: bool
        """

    @property
    def transferData(self) -> java.lang.Object:
        ...

    @property
    def allData(self) -> java.util.List[docking.widgets.tree.GTreeNode]:
        ...

    @property
    def transferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def dataFlavorSupported(self) -> jpype.JBoolean:
        ...


class CombinedGTreeFilter(GTreeFilter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter1: GTreeFilter, filter2: GTreeFilter):
        ...


class NewTestApp(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getMemoryUsage() -> int:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class DepthFirstIterator(java.util.Iterator[docking.widgets.tree.GTreeNode]):
    """
    Implements an iterator over all GTreeNodes in some gTree (or subtree).  The nodes are
    return in depth first order.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, node: docking.widgets.tree.GTreeNode):
        ...


@typing.type_check_only
class RootNode(DirectoryNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GTreeRenderer(javax.swing.tree.DefaultTreeCellRenderer, docking.widgets.GComponent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMinIconWidth(self) -> int:
        ...

    def setBackgroundNonSelectionColor(self, newColor: java.awt.Color):
        """
        Overrides this method to ensure that the new background non-selection color is not
        a :obj:`GColorUIResource`. Some Look and Feels will ignore color values that extend
        :obj:`UIResource`, choosing instead their own custom painting behavior. By not using a 
        UIResource, we prevent the Look and Feel from overriding this renderer's color value.
        
        :param java.awt.Color newColor: the new background non-selection color
        """

    def setBackgroundSelectionColor(self, newColor: java.awt.Color):
        """
        Overrides this method to ensure that the new background selection color is not
        a :obj:`GColorUIResource`. Some Look and Feels will ignore color values that extend
        :obj:`UIResource`, choosing instead their own custom painting behavior. By not using a 
        UIResource, we prevent the Look and Feel from overriding this renderer's color value.
        
        :param java.awt.Color newColor: the new background selection color
        """

    def setMinIconWidth(self, minIconWidth: typing.Union[jpype.JInt, int]):
        ...

    def setRendererDropTarget(self, target: java.lang.Object):
        ...

    @property
    def minIconWidth(self) -> jpype.JInt:
        ...

    @minIconWidth.setter
    def minIconWidth(self, value: jpype.JInt):
        ...


class GTreeCellEditor(javax.swing.tree.DefaultTreeCellEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: javax.swing.JTree, renderer: javax.swing.tree.DefaultTreeCellRenderer):
        ...


class GTreeDragNDropHandler(GTreeTransferHandler):

    class_: typing.ClassVar[java.lang.Class]

    def drop(self, destUserData: docking.widgets.tree.GTreeNode, transferable: java.awt.datatransfer.Transferable, dropAction: typing.Union[jpype.JInt, int]):
        """
        Add the given transferable's data to the destination user data.
        
        :param docking.widgets.tree.GTreeNode destUserData: destination node for the data.
        :param java.awt.datatransfer.Transferable transferable: the transferable being dragged whose data will be dropped.
        :param jpype.JInt or int dropAction: user action for drop operation
        """

    def getSupportedDragActions(self) -> int:
        """
        Returns the supported Drag actions for this tree.  For available actions see
        :obj:`DnDConstants`.
        
        :return: the supported Drag actions.
        :rtype: int
        """

    def isDropSiteOk(self, destUserData: docking.widgets.tree.GTreeNode, flavors: jpype.JArray[java.awt.datatransfer.DataFlavor], dropAction: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return true if the drop site is valid for the given target.
        
        :param docking.widgets.tree.GTreeNode destUserData: destination for node being dragged
        :param jpype.JArray[java.awt.datatransfer.DataFlavor] flavors: flavor(s) being dragged
        :param jpype.JInt or int dropAction: user action for drop operation
        :return: true if the drop site is valid for the given target
        :rtype: bool
        """

    def isStartDragOk(self, dragUserData: java.util.List[docking.widgets.tree.GTreeNode], dragAction: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return true if the dragUserData can be dragged.
        
        :param java.util.List[docking.widgets.tree.GTreeNode] dragUserData: data where user is initiating the drag operation
        :param jpype.JInt or int dragAction: user action for the drag operation
        :return: true if the dragUserData can be dragged
        :rtype: bool
        """

    @property
    def supportedDragActions(self) -> jpype.JInt:
        ...


class GTreeSelectionListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def valueChanged(self, e: GTreeSelectionEvent):
        """
        Called whenever the value of the selection changes.
        
        :param GTreeSelectionEvent e: the event that characterizes the change.
        """


class IgnoredNodesGtreeFilter(GTreeFilter):
    """
    GTreeFilter that allows for some nodes that are never filtered out.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter: GTreeFilter, ignoredNodes: java.util.Set[docking.widgets.tree.GTreeNode]):
        ...


@typing.type_check_only
class FileNode(docking.widgets.tree.GTreeNode, FileData):

    class_: typing.ClassVar[java.lang.Class]
    tempName: java.lang.String


class GTreeTransferHandler(java.lang.Object):
    """
    A generic transfer handler used by GTrees to handle transferring drag/drop data and clipboard
    data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getSupportedDataFlavors(self, transferNodes: java.util.List[docking.widgets.tree.GTreeNode]) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Returns the DataFlavors for the types of data that this transferable supports, based upon
        the given selection.
        
        :param java.util.List[docking.widgets.tree.GTreeNode] transferNodes: The nodes to base the DataFlavor selection upon.
        :return: the DataFlavors for the types of data that this transferable supports, based upon
        the given selection.
        :rtype: jpype.JArray[java.awt.datatransfer.DataFlavor]
        """

    def getTransferData(self, transferNodes: java.util.List[docking.widgets.tree.GTreeNode], flavor: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        """
        Gets the transfer data from the selection based upon the given flavor.
        
        :param java.util.List[docking.widgets.tree.GTreeNode] transferNodes: The nodes from which to get the data.
        :param java.awt.datatransfer.DataFlavor flavor: The flavor of data to retrieve from the given selection.
        :return: the transfer data from the selection based upon the given flavor.
        :rtype: java.lang.Object
        :raises UnsupportedFlavorException: if the given flavor is not one of the supported flavors
        returned by :meth:`getSupportedDataFlavors(List) <.getSupportedDataFlavors>`.
        """

    @property
    def supportedDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...



__all__ = ["BreadthFirstIterator", "GTreeFilter", "DragNDropHandler", "DirectoryNode", "FileData", "GTreeSelectionEvent", "GTreeNodeTransferable", "CombinedGTreeFilter", "NewTestApp", "DepthFirstIterator", "RootNode", "GTreeRenderer", "GTreeCellEditor", "GTreeDragNDropHandler", "GTreeSelectionListener", "IgnoredNodesGtreeFilter", "FileNode", "GTreeTransferHandler"]
