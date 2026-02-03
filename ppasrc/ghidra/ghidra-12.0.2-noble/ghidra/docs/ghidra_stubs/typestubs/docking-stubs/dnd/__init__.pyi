from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.dnd # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.tree # type: ignore


ROW_OBJECT = typing.TypeVar("ROW_OBJECT")


class DragDropNode(javax.swing.tree.DefaultMutableTreeNode):
    """
    Defines a node that is in the DragDropTree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructs a new DragDropNode with the given name.
        
        :param java.lang.String or str name: the name to associate with this node.
        """

    def getIcon(self, expanded: typing.Union[jpype.JBoolean, bool], leaf: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Get the appropriate icon for this node's state; called
        by the tree cell renderer.
        
        :param jpype.JBoolean or bool expanded: true if the node is expanded
        :param jpype.JBoolean or bool leaf: true if the node is a leaf node
        """

    def getName(self) -> str:
        """
        Get the name of this node.
        """

    def getToolTipText(self) -> str:
        """
        Get the tool tip for this node.
        """

    def getTreePath(self) -> javax.swing.tree.TreePath:
        """
        Get the tree path for this node.
        
        :return: TreePath
        :rtype: javax.swing.tree.TreePath
        """

    def isDropAllowed(self, dropNode: DragDropNode, dropAction: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return true if this node can be a drop target.
        
        :param DragDropNode dropNode: node being dragged and dropped;
        could be null if the drag was initiated outside of the tree
        :param jpype.JInt or int dropAction: DnDConstants value for copy or move
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Set the name for this node.
        
        :param java.lang.String or str name: the name to set on this node.
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def treePath(self) -> javax.swing.tree.TreePath:
        ...

    @property
    def toolTipText(self) -> java.lang.String:
        ...


class DropTgtAdapter(java.awt.dnd.DropTargetListener):
    """
    Class to handle notifications of drag and drop operations that occur on the DropTarget 
    object. The DropTarget is the component that accepts drops during a drag and drop operation. 
    The ``drop`` method actually transfers the data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dropComponent: Droppable, acceptableDropActions: typing.Union[jpype.JInt, int], acceptableDropFlavors: jpype.JArray[java.awt.datatransfer.DataFlavor]):
        """
        Constructor
        
        :param Droppable dropComponent: the drop target
        :param jpype.JInt or int acceptableDropActions: a DnDConstants variable that defines dnd actions
        :param jpype.JArray[java.awt.datatransfer.DataFlavor] acceptableDropFlavors: acceptable data formats that the drop target can handle
        """

    @staticmethod
    def getFirstMatchingFlavor(e: java.awt.dnd.DropTargetDragEvent, acceptableFlavors: jpype.JArray[java.awt.datatransfer.DataFlavor]) -> java.awt.datatransfer.DataFlavor:
        ...

    def setAcceptableDropFlavors(self, dropFlavors: jpype.JArray[java.awt.datatransfer.DataFlavor]):
        """
        Set the data flavors acceptable to the associated drop target
        
        :param jpype.JArray[java.awt.datatransfer.DataFlavor] dropFlavors: the flavors
        """


class StringTransferable(java.awt.datatransfer.Transferable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: typing.Union[java.lang.String, str]):
        ...

    def removeOuterQuotesAndStandardStringPrefix(self):
        """
        Removes quotes and standard string literal prefixes from the string. In order for this 
        method to do anything, the string must start with one of the standard string literals
        prefixes and end with a quote character"
        """


class DragSrcAdapter(java.awt.dnd.DragSourceListener):
    """
    Adapter class that receives notifications in order to provide drag over effects.
     
     
    When the operation ends, this class receives a ``dragDropEnd`` message, and is 
    responsible for checking the success of the operation. If the operation was successful, and if it
    was a Move, then this class will remove the source data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dragComponent: Draggable):
        """
        Constructor
        
        :param Draggable dragComponent: component that can be dragged.
        """


class Droppable(java.lang.Object):
    """
    Methods called by the DropTargetAdapter that implements the DropTargetListener interface
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, obj: java.lang.Object, e: java.awt.dnd.DropTargetDropEvent, f: java.awt.datatransfer.DataFlavor):
        """
        Add the object to the droppable component. The DropTargetAdapter
        calls this method from its drop() method.
        
        :param java.lang.Object obj: Transferable object that is to be dropped.
        :param java.awt.dnd.DropTargetDropEvent e: has current state of drop operation
        :param java.awt.datatransfer.DataFlavor f: represents the opaque concept of a data format as 
        would appear on a clipboard, during drag and drop.
        """

    def dragUnderFeedback(self, ok: typing.Union[jpype.JBoolean, bool], e: java.awt.dnd.DropTargetDragEvent):
        """
        Set drag feedback according to the ok parameter
        
        :param jpype.JBoolean or bool ok: true means the drop action is OK
        :param java.awt.dnd.DropTargetDragEvent e: event that has current state of drag and drop operation
        """

    def isDropOk(self, e: java.awt.dnd.DropTargetDragEvent) -> bool:
        """
        Return true if is OK to drop the transferable at the location specified the event
        
        :param java.awt.dnd.DropTargetDragEvent e: event that has current state of drag and drop operation
        :return: true if OK
        :rtype: bool
        """

    def undoDragUnderFeedback(self):
        """
        Revert back to normal if any drag feedback was set
        """

    @property
    def dropOk(self) -> jpype.JBoolean:
        ...


class GTableDragProvider(java.awt.dnd.DragSourceListener, java.awt.dnd.DragGestureListener, typing.Generic[ROW_OBJECT]):
    """
    A class to allow GTables to support drag operations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: docking.widgets.table.GTable, model: docking.widgets.table.RowObjectTableModel[ROW_OBJECT]):
        ...


class DragDropTableSelectionMouseListener(java.awt.event.MouseAdapter):
    """
    A listener for tables that support drag and drop operations.  This listener allows the user to
    make a multi-selection in the table and drag that selection.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: docking.widgets.table.GTable):
        ...


class Draggable(java.lang.Object):
    """
    Interface to define a drag source.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dragFinished(self, cancelled: typing.Union[jpype.JBoolean, bool]):
        """
        Called when the drag and drop operation completes.  
         
         
        Clients can use this callback to reset visual state.
        
        :param jpype.JBoolean or bool cancelled: true if the drag operation was cancelled
        
        .. seealso::
        
            | :obj:`docking.dnd.DragSrcAdapter.dragDropEnd(DragSourceDropEvent)`
        """

    def getDragAction(self) -> int:
        """
        Get the drag actions supported by this drag source:
         
        * DnDConstants.ACTION_MOVE
        * DnDConstants.ACTION_COPY
        * DnDConstants.ACTION_COPY_OR_MOVE
        
        
        :return: the drag actions
        :rtype: int
        """

    def getDragSourceListener(self) -> java.awt.dnd.DragSourceListener:
        """
        Called by the DragGestureAdapter when the drag is started.
        
        :return: the listener
        :rtype: java.awt.dnd.DragSourceListener
        
        .. seealso::
        
            | :obj:`DragGestureEvent.startDrag(Cursor, Image, Point, Transferable, DragSourceListener)`
        """

    def getTransferable(self, p: java.awt.Point) -> java.awt.datatransfer.Transferable:
        """
        Get the object to transfer.
        
        :param java.awt.Point p: location of object to transfer
        :return: object to transfer
        :rtype: java.awt.datatransfer.Transferable
        """

    def isStartDragOk(self, e: java.awt.dnd.DragGestureEvent) -> bool:
        """
        Return true if the object at the location in the DragGesture event is draggable.
        
        :param java.awt.dnd.DragGestureEvent e: event passed to a DragGestureListener via its 
        dragGestureRecognized() method when a particular DragGestureRecognizer 
        detects a platform dependent Drag and Drop action initiating 
        gesture has occurred on the Component it is tracking.
        :return: true if a drag can be starts
        :rtype: bool
        
        .. seealso::
        
            | :obj:`docking.dnd.DragGestureAdapter`
        """

    @property
    def transferable(self) -> java.awt.datatransfer.Transferable:
        ...

    @property
    def startDragOk(self) -> jpype.JBoolean:
        ...

    @property
    def dragAction(self) -> jpype.JInt:
        ...

    @property
    def dragSourceListener(self) -> java.awt.dnd.DragSourceListener:
        ...


class ImageTransferable(java.awt.datatransfer.Transferable):
    """
    Provides drag-n-drop support for Images
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, img: java.awt.Image):
        ...


class GClipboard(java.lang.Object):
    """
    Provides a place for clients to retrieve the Clipboard they should be using.  This class
    provides a level of indirection that allows us to inject clipboards as needed.
     
     
    Note: if a test needs to check the contents of the native clipboard, such as after 
    executing a native Java action that uses the system clipboard, then that test must use some 
    other mechanism to know that the native action was executed.   This is due to the fact that 
    the system clipboard is potentially used by multiple Java test processes at once.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getSystemClipboard() -> java.awt.datatransfer.Clipboard:
        """
        Returns the clipboard that should be used by the current JVM
        
        :return: the clipboard
        :rtype: java.awt.datatransfer.Clipboard
        """


class DragGestureAdapter(java.awt.dnd.DragGestureListener):
    """
    This class receives notification when the user initiates a drag and drop operation; it is 
    responsible for getting the ``Transferable`` and telling the ``DragSource`` to 
    start the drag.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dragComponent: Draggable):
        """
        Construct a new DragGestureAdapter
        
        :param Draggable dragComponent: Component that can support drag operations
        """


class GenericDataFlavor(java.awt.datatransfer.DataFlavor):
    """
    Generic data flavor class to override the equals(DataFlavor) method
    in order to have data flavors support the same general class types
    such as an ArrayList.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a new GenericDataFlavor.
        """

    @typing.overload
    def __init__(self, representationClass: java.lang.Class[typing.Any], humanPresentableName: typing.Union[java.lang.String, str]):
        """
        Construct a GenericDataFlavor that represents a Java class
        
        :param java.lang.Class[typing.Any] representationClass: the class used to transfer data in this flavor
        :param java.lang.String or str humanPresentableName: the human-readable string used to 
        identify this flavor. If this parameter is null then the value of 
        the MIME Content Type is used.
        """

    @typing.overload
    def __init__(self, mimeType: typing.Union[java.lang.String, str]):
        """
        construct a GenericDataFlavor from a Mime Type string.
        
        :param java.lang.String or str mimeType: he string used to identify the MIME type for this flavor
        The string must specify a "class="
        parameter in order to succeed in constructing a DataFlavor.
        :raises java.lang.ClassNotFoundException: if the class could not be loaded
        :raises IllegalArgumentException: thrown if mimeType does not
        specify a "class=" parameter
        """

    @typing.overload
    def __init__(self, mimeType: typing.Union[java.lang.String, str], humanPresentableName: typing.Union[java.lang.String, str]):
        """
        Construct a GenericDataFlavor that represents a MimeType 
        If the mimeType is 
        ``"application/x-java-serialized-object; class=<representation class>", the result is the same as calling new GenericDataFlavor(Class:forName(<representation class>)``
        
        :param java.lang.String or str mimeType: the string used to identify the MIME type for 
        this flavor
        :param java.lang.String or str humanPresentableName: the human-readable string used to 
        identify this flavor
        :raises IllegalArgumentException: thrown if the mimeType does not 
        specify a "class=" parameter, or if the class is not
        successfully loaded
        """

    @typing.overload
    def __init__(self, mimeType: typing.Union[java.lang.String, str], humanPresentableName: typing.Union[java.lang.String, str], classLoader: java.lang.ClassLoader):
        """
        Construct a GenericDataFlavor that represents a MimeType 
        If the mimeType is 
        ``"application/x-java-serialized-object; class=<representation class>", the result is the same as calling new GenericDataFlavor(Class:forName(<representation class>).``
        
        :param java.lang.String or str mimeType: the string used to identify the MIME type for this flavor
        :param java.lang.String or str humanPresentableName: the human-readable string used to 
        identify this flavor.
        :param java.lang.ClassLoader classLoader: class loader to load the class
        :raises java.lang.ClassNotFoundException: is thrown if class could not be loaded
        """

    @typing.overload
    def equals(self, dataFlavor: java.awt.datatransfer.DataFlavor) -> bool:
        """
        Return true if dataFlavor equals this generic data flavor.
        """

    @typing.overload
    def equals(self, obj: java.lang.Object) -> bool:
        """
        Return true if obj is equal this generic data flavor.
        """


class DragDropManager(java.lang.Object):
    """
    Interface used by the DragDropTree to know how to handle the
    drag and drop operations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, destNode: DragDropNode, data: java.lang.Object, chosen: java.awt.datatransfer.DataFlavor, dropAction: typing.Union[jpype.JInt, int]):
        """
        Add the given data to the destination node.
        
        :param DragDropNode destNode: destination node for the data.
        :param java.lang.Object data: data to add
        :param java.awt.datatransfer.DataFlavor chosen: data flavor for the data being added
        :param jpype.JInt or int dropAction: user action for drop operation
        """

    def getAcceptableFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Return the data flavors that can be dragged and dropped.
        """

    def getTransferable(self, p: java.awt.Point) -> java.awt.datatransfer.Transferable:
        """
        Get the transferable at the given point.
        
        :param java.awt.Point p: point where the mouse pointer is when the drag begins
        """

    def isDropSiteOk(self, destNode: DragDropNode, e: java.awt.dnd.DropTargetDragEvent) -> bool:
        """
        Return true if the drop site is valid for the given target and drag event.
        
        :param DragDropNode destNode: destination for node being dragged
        :param java.awt.dnd.DropTargetDragEvent e: the drag event
        """

    def isStartDragOk(self, dragNode: DragDropNode, dragAction: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return true if the dragNode can be dragged.
        
        :param DragDropNode dragNode: node where user is initiating the drag operation
        :param jpype.JInt or int dragAction: user action for the drag operation
        """

    def move(self, sourceNodes: jpype.JArray[DragDropNode]):
        """
        Remove the given sourceNodes. (It got moved, so remove it at the source)
        
        :param jpype.JArray[DragDropNode] sourceNodes: nodes to remove.
        """

    @property
    def transferable(self) -> java.awt.datatransfer.Transferable:
        ...

    @property
    def acceptableFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...


class DragDropTreeTransferable(java.awt.datatransfer.Transferable, java.awt.datatransfer.ClipboardOwner):
    """
    Defines data that is available for drag/drop and clipboard transfers.
    The data is an ArrayList of DragDropNode objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    localTreeNodeFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    """
    A static instance of the local tree node flavor that is an
    ArrayList of DragDropNode objects.
    """


    def __init__(self, nodes: jpype.JArray[DragDropNode]):
        """
        Constructs a new Transferable from the array of DragDropNodes
        
        :param jpype.JArray[DragDropNode] nodes: the array of DragDropNodes being transfered.
        """

    def getTransferData(self, f: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        """
        Return the transfer data with the given data flavor.
        
        :param java.awt.datatransfer.DataFlavor f: the DataFlavor for which to get a Transferable.
        """

    def getTransferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Return all data flavors that this class supports.
        """

    def isDataFlavorSupported(self, f: java.awt.datatransfer.DataFlavor) -> bool:
        """
        Return whether the specifed data flavor is supported.
        
        :param java.awt.datatransfer.DataFlavor f: the DataFlavor to check if supported.
        """

    def lostOwnership(self, clipboard: java.awt.datatransfer.Clipboard, contents: java.awt.datatransfer.Transferable):
        """
        Notification we have lost ownership of the clipboard because 
        something else was put on the clipboard.
        
        :param java.awt.datatransfer.Clipboard clipboard: the system clipboard.
        :param java.awt.datatransfer.Transferable contents: the Transferable lost in the clipboard.
        """

    def toString(self) -> str:
        """
        Get the string representation for this transferable.
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



__all__ = ["DragDropNode", "DropTgtAdapter", "StringTransferable", "DragSrcAdapter", "Droppable", "GTableDragProvider", "DragDropTableSelectionMouseListener", "Draggable", "ImageTransferable", "GClipboard", "DragGestureAdapter", "GenericDataFlavor", "DragDropManager", "DragDropTreeTransferable"]
