from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.dnd
import ghidra.app.context
import ghidra.app.plugin
import ghidra.app.services
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.task
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.dnd # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore


class TreeListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def goTo(self, addr: ghidra.program.model.address.Address):
        """
        Notification for going to the given address.
        """

    def treeViewChanged(self, e: javax.swing.event.ChangeEvent):
        """
        Called when the view changes.
        """


@typing.type_check_only
class ViewPanel(javax.swing.JPanel, javax.swing.event.ChangeListener):
    """
    Panel that has a tabbed pane to switch between the views.
    """

    class_: typing.ClassVar[java.lang.Class]

    def isEmpty(self) -> bool:
        ...

    def stateChanged(self, e: javax.swing.event.ChangeEvent):
        """
        Invoked when the target of the listener has changed its state. In this
        case, the method is called when the user switches to another tab in the
        tabbed pane.
        
        :param javax.swing.event.ChangeEvent e: the event
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ProgramDnDTree(DragNDropTree):
    """
    Class that presents a Program in a tree structure; ProgramDnDTree
    provides Drag and Drop capability, and menu options and actions
    to support cut, copy, paste, and rename operations.
    """

    @typing.type_check_only
    class NodeComparator(java.util.Comparator[javax.swing.tree.TreePath]):
        """
        Class to compare two objects.
        """

        class_: typing.ClassVar[java.lang.Class]

        def compare(self, p1: javax.swing.tree.TreePath, p2: javax.swing.tree.TreePath) -> int:
            """
            Return negative, 0, or positive number if p1 is less than
            equal to, or greater than p2.
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeName: typing.Union[java.lang.String, str], model: javax.swing.tree.DefaultTreeModel, plugin: ProgramTreePlugin):
        """
        Construct a ProgramDnDTree with the given model.
        
        :param java.lang.String or str treeName: The name of the tree to show in the tab
        :param javax.swing.tree.DefaultTreeModel model: the tree model
        :param ProgramTreePlugin plugin: the program tree plugin
        """

    def expandPaths(self, list: java.util.List[javax.swing.tree.TreePath]):
        """
        Expand all paths in the list.
        
        :param java.util.List[javax.swing.tree.TreePath] list: list of TreePaths.
        """

    def fireTreeExpanded(self, path: javax.swing.tree.TreePath):
        """
        Fire tree expansion event; if node has not been visited,
        then populate the node with its children.
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program.
        """

    def isDropOk(self, e: java.awt.dnd.DropTargetDragEvent) -> bool:
        """
        Droppable interface method called to know when the drop site is
        valid.
        """

    @property
    def dropOk(self) -> jpype.JBoolean:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class DragNDropTree(javax.swing.JTree, docking.dnd.Draggable, docking.dnd.Droppable, java.awt.dnd.Autoscroll):
    """
    Class to support Drag and Drop; it is also responsible for
    rendering the icons, and  for editing a node name.
     
    The nodes that are used in this class are ProgramNode objects.
    """

    @typing.type_check_only
    class ProgramTreeCellEditor(javax.swing.tree.DefaultTreeCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: javax.swing.tree.DefaultTreeModel):
        ...


@typing.type_check_only
class ProgramTreeActionManager(java.awt.datatransfer.ClipboardOwner):
    """
    Class to manage actions and popup menus for the program tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def lostOwnership(self, clipboard: java.awt.datatransfer.Clipboard, contents: java.awt.datatransfer.Transferable):
        """
        Notifies tree object that it is no longer the owner of
        the contents of the clipboard.
        
        :param java.awt.datatransfer.Clipboard clipboard: the clipboard that is no longer owned
        :param java.awt.datatransfer.Transferable contents: the contents which tree owner had placed on the clipboard
        """


@typing.type_check_only
class ProgramTreeModelListener(javax.swing.event.TreeModelListener):
    """
    Class that is a listener on the TreeModel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def treeNodesChanged(self, e: javax.swing.event.TreeModelEvent):
        """
        Called when a node changes; update the Group name for the node being changed.
        """

    def treeNodesInserted(self, e: javax.swing.event.TreeModelEvent):
        """
        Method called when nodes are being inserted into the tree; update the treePath and the 
        group path fields in the ProgramNode object.
        """


class GroupTransferable(java.awt.datatransfer.Transferable):
    """
    A test implementation of data that could be dragged onto the ProgramTree.
    """

    class_: typing.ClassVar[java.lang.Class]
    localGroupFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]

    @typing.overload
    def __init__(self, g: ghidra.program.model.listing.Group):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    def getTransferData(self, f: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        """
        Return the transfer data with the given data flavor.
        """

    def getTransferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Return all data flavors that this class supports.
        """

    def isDataFlavorSupported(self, f: java.awt.datatransfer.DataFlavor) -> bool:
        """
        Return whether the specified data flavor is supported.
        """

    @property
    def transferData(self) -> java.lang.Object:
        ...

    @property
    def transferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def dataFlavorSupported(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class PasteManager(java.lang.Object):
    """
    Manage paste operations for the Program Tree.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class TreeDragSrcAdapter(docking.dnd.DragSrcAdapter):
    """
    Drag source adapter on tree to set the custom cursors for the drag under feedback.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dragComponent: docking.dnd.Draggable):
        ...


@typing.type_check_only
class ReorderManager(java.lang.Object):
    """
    Manage the drop operation for reordering modules and fragments.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ProgramListener(ghidra.framework.model.DomainObjectListener):
    """
    Listener for the Program domain object; updates the appropriate ProgramDnDTree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def domainObjectChanged(self, ev: ghidra.framework.model.DomainObjectChangedEvent):
        """
        Interface method called when the program changes.
        """


@typing.type_check_only
class ProgramTreeTransferable(java.awt.datatransfer.Transferable, java.awt.datatransfer.ClipboardOwner):
    """
    Defines data that is available for drag/drop and clipboard transfers.
    The data is an ArrayList of ProgramNode objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    localTreeNodeFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]


class ProgramTreeActionContext(ghidra.app.context.ProgramActionContext):
    """
    A context object for the :obj:`ProgramTreePlugin`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ViewManagerComponentProvider, program: ghidra.program.model.listing.Program, viewPanel: ViewPanel, contextObject: java.lang.Object):
        ...

    def getLeadSelectedNode(self) -> ProgramNode:
        ...

    def getSelectionPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    def getSingleSelectedNode(self) -> ProgramNode:
        ...

    def getTree(self) -> ProgramDnDTree:
        ...

    def hasFullNodeMultiSelection(self) -> bool:
        """
        Returns true if the selected paths: 1) do not contain the root node and 2) for each folder,
        either all children are selected or no children are selected.
        
        :return: true if the criteria above are met
        :rtype: bool
        """

    def hasSingleNodeSelection(self) -> bool:
        ...

    def isOnlyRootNodeSelected(self) -> bool:
        ...

    @property
    def leadSelectedNode(self) -> ProgramNode:
        ...

    @property
    def selectionPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    @property
    def singleSelectedNode(self) -> ProgramNode:
        ...

    @property
    def tree(self) -> ProgramDnDTree:
        ...

    @property
    def onlyRootNodeSelected(self) -> jpype.JBoolean:
        ...


class ProgramTreeModularizationPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class DnDTreeCellRenderer(javax.swing.tree.DefaultTreeCellRenderer):
    """
    Cell renderer for the drag and drop tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getTreeCellRendererComponent(self, tree: javax.swing.JTree, value: java.lang.Object, sel: typing.Union[jpype.JBoolean, bool], expanded: typing.Union[jpype.JBoolean, bool], leaf: typing.Union[jpype.JBoolean, bool], row: typing.Union[jpype.JInt, int], isFocused: typing.Union[jpype.JBoolean, bool]) -> java.awt.Component:
        """
        Configures the renderer based on the passed in components.
        The icon is set according to value, expanded, and leaf
        parameters.
        """

    def setHTMLRenderingEnabled(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Enables and disables the rendering of HTML content in this renderer.  If enabled, this
        renderer will interpret HTML content when the text this renderer is showing begins with
        ``<html>``
        
        :param jpype.JBoolean or bool enable: true to enable HTML rendering; false to disable it
        """


class ProgramNode(javax.swing.tree.DefaultMutableTreeNode):
    """
    Class to define a node in a DragNDropTree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Returns whether some other object is "equal to" this one.
        """

    def getAllowsChildren(self) -> bool:
        """
        Returns true if this node is allowed to have children.
        """

    def getFragment(self) -> ghidra.program.model.listing.ProgramFragment:
        """
        Returns the fragment if this node represents a Fragment.
        
        :return: null if this node does not represent a Fragment.
        :rtype: ghidra.program.model.listing.ProgramFragment
        """

    def getGroup(self) -> ghidra.program.model.listing.Group:
        """
        Get the group for this node.
        
        :return: the group for this node.
        :rtype: ghidra.program.model.listing.Group
        """

    def getGroupPath(self) -> ghidra.program.util.GroupPath:
        """
        Get the group path for this node.
        
        :return: the group path for this node.
        :rtype: ghidra.program.util.GroupPath
        """

    def getModule(self) -> ghidra.program.model.listing.ProgramModule:
        """
        Returns the module if this node represents a Module.
        
        :return: null if this node does not represent a Module.
        :rtype: ghidra.program.model.listing.ProgramModule
        """

    def getName(self) -> str:
        """
        Get the name for this node.
        
        :return: he name for this node.
        :rtype: str
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program for this node.
        
        :return: the program for this node.
        :rtype: ghidra.program.model.listing.Program
        """

    def getTree(self) -> javax.swing.JTree:
        ...

    def isFragment(self) -> bool:
        """
        Returns true if this node represents a Fragment.
        
        :return: true if this node represents a Fragment.
        :rtype: bool
        """

    def isInView(self) -> bool:
        """
        Return true if the node is in the view.
        
        :return: true if the node is in the view.
        :rtype: bool
        """

    def isLeaf(self) -> bool:
        """
        Returns true if this node has no children.
        """

    def isModule(self) -> bool:
        """
        Returns true if this node represents a Module.
        
        :return: true if this node represents a Module.
        :rtype: bool
        """

    @property
    def fragment(self) -> ghidra.program.model.listing.ProgramFragment:
        ...

    @property
    def module(self) -> ghidra.program.model.listing.ProgramModule:
        ...

    @property
    def tree(self) -> javax.swing.JTree:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def allowsChildren(self) -> jpype.JBoolean:
        ...

    @property
    def inView(self) -> jpype.JBoolean:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def leaf(self) -> jpype.JBoolean:
        ...

    @property
    def groupPath(self) -> ghidra.program.util.GroupPath:
        ...

    @property
    def group(self) -> ghidra.program.model.listing.Group:
        ...


class ViewManagerComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.app.services.ViewManagerService, ViewChangeListener):

    class_: typing.ClassVar[java.lang.Class]
    CURRENT_VIEW: typing.Final = "Current Viewname"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]):
        ...

    def addViewChangeListener(self, l: ViewChangeListener):
        ...

    def dispose(self):
        ...

    def removeViewChangeListener(self, l: ViewChangeListener):
        ...

    def setCurrentProgram(self, program: ghidra.program.model.listing.Program):
        ...

    def setCurrentViewProvider(self, vps: ViewProviderService):
        ...


class ViewChangeListener(java.lang.Object):
    """
    Define a method that will be called when the view changes either because
    the user made a new selection, or the user switched to a different view.
    """

    class_: typing.ClassVar[java.lang.Class]

    def viewChanged(self, addrSet: ghidra.program.model.address.AddressSetView):
        """
        Notification that the view changed.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the new AddressSet for the current view.
        """


class ViewProviderService(ghidra.app.services.ViewService):
    """
    Define methods for notification of which service becomes active;
    the service is managed by the ViewManagerService.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getActionContext(self, event: java.awt.event.MouseEvent) -> docking.ActionContext:
        """
        Returns the current action context for this view service
        
        :param java.awt.event.MouseEvent event: the mouse event
        :return: the context
        :rtype: docking.ActionContext
        """

    def getActiveObject(self) -> java.lang.Object:
        """
        Returns the context for the current selection.
        """

    def getActivePopupObject(self, event: java.awt.event.MouseEvent) -> java.lang.Object:
        """
        Return the object under the mouse location for the popup
        
        :param java.awt.event.MouseEvent event: mouse event generated when the right mouse button is pressed
        """

    def getToolBarActions(self) -> jpype.JArray[docking.action.DockingAction]:
        """
        Get the actions that would go on a tool bar.
        """

    def getViewComponent(self) -> javax.swing.JComponent:
        """
        Get the viewer component.
        """

    def getViewName(self) -> str:
        """
        Get the name of this view.
        """

    def setHasFocus(self, hasFocus: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether or not the component that is showing has focus.
        
        :param jpype.JBoolean or bool hasFocus: true if the component has focus
        """

    def viewClosed(self) -> bool:
        """
        Notification that this view is closed.
        
        :return: true if the view can be closed
        :rtype: bool
        """

    def viewDeleted(self) -> bool:
        """
        Notification that this view should be deleted
        
        :return: true if the view can be deleted
        :rtype: bool
        """

    def viewRenamed(self, newName: typing.Union[java.lang.String, str]) -> bool:
        """
        Notification that this view should be renamed to newName.
        
        :return: true if the rename is allowed
        :rtype: bool
        """

    @property
    def viewName(self) -> java.lang.String:
        ...

    @property
    def viewComponent(self) -> javax.swing.JComponent:
        ...

    @property
    def activeObject(self) -> java.lang.Object:
        ...

    @property
    def activePopupObject(self) -> java.lang.Object:
        ...

    @property
    def toolBarActions(self) -> jpype.JArray[docking.action.DockingAction]:
        ...

    @property
    def actionContext(self) -> docking.ActionContext:
        ...


@typing.type_check_only
class ProgramTreeAction(docking.action.DockingAction):
    """
    Class for program tree actions; ensures that actions are put on a popup
    only if the popup is over something that implements the ProgramTreeService.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProgramTreePlugin(ghidra.app.plugin.ProgramPlugin, ghidra.app.services.ProgramTreeService, ghidra.framework.options.OptionsChangeListener):
    """
    Plugin that creates view provider services to show the trees in a program.
    Notifies the view manager service when the view changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def dispose(self):
        """
        Tells a plugin that it is no longer needed. The plugin should remove
        itself from anything that it is registered to and release any resources.
        """

    def readDataState(self, saveState: ghidra.framework.options.SaveState):
        """
        Read the data for the plugin upon deserialization; reads what should be
        the current selection in the tree.
        """

    def serviceRemoved(self, interfaceClass: java.lang.Class[typing.Any], service: java.lang.Object):
        """
        Notifies this plugin that service has been removed from the plugin tool.
        """

    def writeDataState(self, saveState: ghidra.framework.options.SaveState):
        """
        Write data for plugin; writes the current selection.
        """


@typing.type_check_only
class TreeViewProvider(ViewProviderService):
    """
    Provides a view of the program tree.
    """

    @typing.type_check_only
    class SelectPathsRunnable(ghidra.util.task.SwingRunnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeName: typing.Union[java.lang.String, str], plugin: ProgramTreePlugin):
        ...


@typing.type_check_only
class ProgramTreePanel(javax.swing.JPanel, javax.swing.event.ChangeListener):
    """
    Wrapper for a ProgramDnDTree that supports drag and drop and
    option menus and actions for cut, paste, rename, delete, and
    merge operations. This class generates ProgramTreeSelection events.
    """

    class_: typing.ClassVar[java.lang.Class]

    def stateChanged(self, e: javax.swing.event.ChangeEvent):
        """
        Invoked when the target of the listener has changed its state.
        
        :param javax.swing.event.ChangeEvent e: a ChangeEvent object
        """


@typing.type_check_only
class DnDMoveManager(java.lang.Object):
    """
    Helper class to interpret the drop operation as a Move/Copy
    operation versus the reorder.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["TreeListener", "ViewPanel", "ProgramDnDTree", "DragNDropTree", "ProgramTreeActionManager", "ProgramTreeModelListener", "GroupTransferable", "PasteManager", "TreeDragSrcAdapter", "ReorderManager", "ProgramListener", "ProgramTreeTransferable", "ProgramTreeActionContext", "ProgramTreeModularizationPlugin", "DnDTreeCellRenderer", "ProgramNode", "ViewManagerComponentProvider", "ViewChangeListener", "ViewProviderService", "ProgramTreeAction", "ProgramTreePlugin", "TreeViewProvider", "ProgramTreePanel", "DnDMoveManager"]
