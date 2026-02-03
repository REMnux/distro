from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action.builder
import docking.widgets.table
import docking.widgets.table.threaded
import docking.widgets.tree
import docking.widgets.tree.support
import generic.theme
import ghidra.app.plugin.core.debug.gui
import ghidra.app.plugin.core.debug.gui.model.columns
import ghidra.app.services
import ghidra.debug.api.model
import ghidra.debug.api.tracemgr
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.target
import ghidra.trace.model.target.path
import ghidra.trace.model.target.schema
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.stream # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore


M = typing.TypeVar("M")
P = typing.TypeVar("P")
T = typing.TypeVar("T")
U = typing.TypeVar("U")


class AbstractObjectsTableBasedPanel(ObjectsTablePanel, javax.swing.event.ListSelectionListener, AbstractQueryTablePanel.CellActivationListener, ObjectDefaultActionsMixin, typing.Generic[U]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, provider: docking.ComponentProvider, objType: java.lang.Class[U]):
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def getActionContext(self) -> ghidra.debug.api.model.DebuggerObjectActionContext:
        ...

    def getSelected(self, ctx: ghidra.debug.api.model.DebuggerObjectActionContext) -> java.util.stream.Stream[U]:
        ...

    def isContextNonEmpty(self, ctx: ghidra.debug.api.model.DebuggerObjectActionContext) -> bool:
        ...

    @property
    def contextNonEmpty(self) -> jpype.JBoolean:
        ...

    @property
    def selected(self) -> java.util.stream.Stream[U]:
        ...

    @property
    def actionContext(self) -> ghidra.debug.api.model.DebuggerObjectActionContext:
        ...


class KeepTreeState(java.lang.AutoCloseable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: docking.widgets.tree.GTree):
        ...

    @staticmethod
    def ifNotNull(tree: docking.widgets.tree.GTree) -> KeepTreeState:
        ...


class ColorsModified(java.lang.Object, typing.Generic[P]):

    class InTable(ColorsModified[javax.swing.JTable]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class InTree(ColorsModified[javax.swing.JTree], javax.swing.tree.TreeCellRenderer):

        class_: typing.ClassVar[java.lang.Class]

        def getTextNonSelectionColor(self) -> java.awt.Color:
            ...

        def getTextSelectionColor(self) -> java.awt.Color:
            ...

        @property
        def textSelectionColor(self) -> java.awt.Color:
            ...

        @property
        def textNonSelectionColor(self) -> java.awt.Color:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getDiffForeground(self, p: P) -> java.awt.Color:
        ...

    def getDiffSelForeground(self, p: P) -> java.awt.Color:
        ...

    def getForeground(self, p: P) -> java.awt.Color:
        ...

    def getForegroundFor(self, p: P, isModified: typing.Union[jpype.JBoolean, bool], isSelected: typing.Union[jpype.JBoolean, bool]) -> java.awt.Color:
        ...

    def getSelForeground(self, p: P) -> java.awt.Color:
        ...

    @property
    def diffSelForeground(self) -> java.awt.Color:
        ...

    @property
    def diffForeground(self) -> java.awt.Color:
        ...

    @property
    def selForeground(self) -> java.awt.Color:
        ...

    @property
    def foreground(self) -> java.awt.Color:
        ...


class DisplaysObjectValues(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getBoolsDisplay(self, bools: jpype.JArray[jpype.JBoolean]) -> str:
        ...

    def getBytesDisplay(self, bytes: jpype.JArray[jpype.JByte]) -> str:
        ...

    def getCharsDisplay(self, chars: jpype.JArray[jpype.JChar]) -> str:
        ...

    def getEdgeDisplay(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getEdgeHtmlDisplay(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        """
        Get an HTML string representing how the edge's value should be displayed
        
        :return: the display string
        :rtype: str
        """

    def getEdgeToolTip(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getIntsDisplay(self, ints: jpype.JArray[jpype.JInt]) -> str:
        ...

    def getLongsDisplay(self, longs: jpype.JArray[jpype.JLong]) -> str:
        ...

    def getNullDisplay(self) -> str:
        ...

    def getObjectDisplay(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getObjectLinkDisplay(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getObjectLinkToolTip(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getObjectToolTip(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getObjectType(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getPrimitiveEdgeToolTip(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getPrimitiveEdgeType(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getPrimitiveValueDisplay(self, value: java.lang.Object) -> str:
        ...

    def getRawObjectDisplay(self, edge: ghidra.trace.model.target.TraceObjectValue) -> str:
        ...

    def getShortsDisplay(self, shorts: jpype.JArray[jpype.JShort]) -> str:
        ...

    def getSnap(self) -> int:
        ...

    def getStringsDisplay(self, strings: jpype.JArray[java.lang.String]) -> str:
        ...

    @property
    def primitiveValueDisplay(self) -> java.lang.String:
        ...

    @property
    def edgeHtmlDisplay(self) -> java.lang.String:
        ...

    @property
    def edgeDisplay(self) -> java.lang.String:
        ...

    @property
    def objectLinkDisplay(self) -> java.lang.String:
        ...

    @property
    def stringsDisplay(self) -> java.lang.String:
        ...

    @property
    def shortsDisplay(self) -> java.lang.String:
        ...

    @property
    def edgeToolTip(self) -> java.lang.String:
        ...

    @property
    def charsDisplay(self) -> java.lang.String:
        ...

    @property
    def nullDisplay(self) -> java.lang.String:
        ...

    @property
    def primitiveEdgeType(self) -> java.lang.String:
        ...

    @property
    def objectType(self) -> java.lang.String:
        ...

    @property
    def rawObjectDisplay(self) -> java.lang.String:
        ...

    @property
    def bytesDisplay(self) -> java.lang.String:
        ...

    @property
    def objectDisplay(self) -> java.lang.String:
        ...

    @property
    def objectToolTip(self) -> java.lang.String:
        ...

    @property
    def objectLinkToolTip(self) -> java.lang.String:
        ...

    @property
    def longsDisplay(self) -> java.lang.String:
        ...

    @property
    def intsDisplay(self) -> java.lang.String:
        ...

    @property
    def primitiveEdgeToolTip(self) -> java.lang.String:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...

    @property
    def boolsDisplay(self) -> java.lang.String:
        ...


class DisplaysModified(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getDiffSnap(self) -> int:
        """
        Get the snap for comparison
        
        :return: the snap
        :rtype: int
        """

    def getDiffTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace for comparison, which may be the same as the current trace
        
        :return: the trace, or null to disable comparison
        :rtype: ghidra.trace.model.Trace
        """

    def getSnap(self) -> int:
        """
        Get the current snap
        
        :return: the snap
        :rtype: int
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the current trace
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def isEdgesDiffer(self, newEdge: ghidra.trace.model.target.TraceObjectValue, oldEdge: ghidra.trace.model.target.TraceObjectValue) -> bool:
        """
        Determine whether two object values (edges) differ
         
         
        
        By default, this behaves as in :meth:`Objects.equals(Object) <Objects.equals>`, deferring to
        :meth:`isValuesDiffer(Object, Object) <.isValuesDiffer>`. Note that newEdge can be null because span may
        include more than the current snap. It will be null for edges that are displayed but do not
        contains the current snap.
        
        :param ghidra.trace.model.target.TraceObjectValue newEdge: the current edge, possibly null
        :param ghidra.trace.model.target.TraceObjectValue oldEdge: the previous edge, possibly null
        :return: true if the edges' values differ
        :rtype: bool
        """

    def isObjectsDiffer(self, newObject: ghidra.trace.model.target.TraceObject, oldObject: ghidra.trace.model.target.TraceObject) -> bool:
        """
        Determine whether two objects differ
         
         
        
        By default the objects are considered equal if their canonical paths agree, without regard to
        the source trace or child values. To compare child values would likely recurse all the way to
        the leaves, which is costly and not exactly informative. This method should only be called
        for objects at the same path, meaning the two objects have at least one path in common. If
        this path is the canonical path, then the two objects (by default) cannot differ. This will
        detect changes in object links, though.
        
        :param ghidra.trace.model.target.TraceObject newObject: the current object
        :param ghidra.trace.model.target.TraceObject oldObject: the previous object
        :return: true if the objects differ, i.e., should be displayed in red
        :rtype: bool
        """

    def isValueModified(self, value: ghidra.trace.model.target.TraceObjectValue) -> bool:
        ...

    def isValuesDiffer(self, newValue: java.lang.Object, oldValue: java.lang.Object) -> bool:
        """
        Determine whether two values differ
         
         
        
        By default this defers to the values' Object:meth:`equals(Object) <.equals>` methods, or in case both
        are of type :obj:`TraceObject`, to :meth:`isObjectsDiffer(TraceObject, TraceObject) <.isObjectsDiffer>`. This
        method should only be called for values at the same path.
        
        :param java.lang.Object newValue: the current value
        :param java.lang.Object oldValue: the previous value
        :return: true if the values differ, i.e., should be displayed in red
        :rtype: bool
        """

    @property
    def valueModified(self) -> jpype.JBoolean:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def diffTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def diffSnap(self) -> jpype.JLong:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class AbstractQueryTableModel(docking.widgets.table.threaded.ThreadedTableModel[T, ghidra.trace.model.Trace], DisplaysModified, typing.Generic[T]):

    @typing.type_check_only
    class ListenerForChanges(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class TableDisplaysObjectValues(DisplaysObjectValues):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DiffTableDisplaysObjectValues(DisplaysObjectValues):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def addSeekListener(self, listener: docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener):
        ...

    def findTraceObject(self, object: ghidra.trace.model.target.TraceObject) -> T:
        ...

    def getCurrentObject(self) -> ghidra.trace.model.target.TraceObject:
        ...

    def getQuery(self) -> ModelQuery:
        ...

    def getSpan(self) -> ghidra.trace.model.Lifespan:
        ...

    def isShowHidden(self) -> bool:
        ...

    def setCurrentObject(self, curObject: ghidra.trace.model.target.TraceObject):
        ...

    def setDiffColor(self, diffColor: java.awt.Color):
        ...

    def setDiffColorSel(self, diffColorSel: java.awt.Color):
        ...

    def setDiffSnap(self, diffSnap: typing.Union[jpype.JLong, int]):
        """
        Set alternative snap to colorize values that differ
         
         
        
        The diff trace must be set, even if it's the same as the trace being displayed. See
        :meth:`setDiffTrace(Trace) <.setDiffTrace>`.
        
        :param jpype.JLong or int diffSnap: the alternative snap
        """

    def setDiffTrace(self, diffTrace: ghidra.trace.model.Trace):
        """
        Set alternative trace to colorize values that differ
         
         
        
        The same trace can be used, but with an alternative snap, if desired. See
        :meth:`setDiffSnap(long) <.setDiffSnap>`. One common use is to compare with the previous snap of the same
        trace. Another common use is to compare with the previous navigation.
        
        :param ghidra.trace.model.Trace diffTrace: the alternative trace
        """

    def setQuery(self, query: ModelQuery):
        ...

    def setShowHidden(self, showHidden: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSnap(self, snap: typing.Union[jpype.JLong, int]):
        ...

    def setSpan(self, span: ghidra.trace.model.Lifespan):
        ...

    def setTrace(self, trace: ghidra.trace.model.Trace):
        ...

    @property
    def showHidden(self) -> jpype.JBoolean:
        ...

    @showHidden.setter
    def showHidden(self, value: jpype.JBoolean):
        ...

    @property
    def query(self) -> ModelQuery:
        ...

    @query.setter
    def query(self, value: ModelQuery):
        ...

    @property
    def currentObject(self) -> ghidra.trace.model.target.TraceObject:
        ...

    @currentObject.setter
    def currentObject(self, value: ghidra.trace.model.target.TraceObject):
        ...

    @property
    def span(self) -> ghidra.trace.model.Lifespan:
        ...

    @span.setter
    def span(self, value: ghidra.trace.model.Lifespan):
        ...


class AbstractQueryTablePanel(javax.swing.JPanel, typing.Generic[T, M]):

    class CellActivationListener(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def cellActivated(self, table: javax.swing.JTable):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...

    def addCellActivationListener(self, listener: AbstractQueryTablePanel.CellActivationListener):
        ...

    def addSeekListener(self, listener: docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener):
        ...

    def addSelectionListener(self, listener: javax.swing.event.ListSelectionListener):
        ...

    def getAllItems(self) -> java.util.List[T]:
        ...

    def getQuery(self) -> ModelQuery:
        ...

    def getSelectedItem(self) -> T:
        ...

    def getSelectedItems(self) -> java.util.List[T]:
        ...

    def getSelectionMode(self) -> int:
        ...

    def goToCoordinates(self, coords: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def isLimitToSnap(self) -> bool:
        ...

    def isShowHidden(self) -> bool:
        ...

    def reload(self):
        ...

    def removeCellActivationListener(self, listener: AbstractQueryTablePanel.CellActivationListener):
        ...

    def removeSelectionListener(self, listener: javax.swing.event.ListSelectionListener):
        ...

    def setDiffColor(self, diffColor: java.awt.Color):
        ...

    def setDiffColorSel(self, diffColorSel: java.awt.Color):
        ...

    def setLimitToSnap(self, limitToSnap: typing.Union[jpype.JBoolean, bool]):
        ...

    def setQuery(self, query: ModelQuery):
        ...

    def setSelectedItem(self, item: T):
        ...

    def setSelectedItems(self, items: collections.abc.Sequence):
        ...

    def setSelectionMode(self, selectionMode: typing.Union[jpype.JInt, int]):
        ...

    def setShowHidden(self, showHidden: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def trySelect(self, object: ghidra.trace.model.target.TraceObject) -> bool:
        ...

    @typing.overload
    def trySelect(self, objects: collections.abc.Sequence):
        ...

    @property
    def showHidden(self) -> jpype.JBoolean:
        ...

    @showHidden.setter
    def showHidden(self, value: jpype.JBoolean):
        ...

    @property
    def limitToSnap(self) -> jpype.JBoolean:
        ...

    @limitToSnap.setter
    def limitToSnap(self, value: jpype.JBoolean):
        ...

    @property
    def selectedItem(self) -> T:
        ...

    @selectedItem.setter
    def selectedItem(self, value: T):
        ...

    @property
    def allItems(self) -> java.util.List[T]:
        ...

    @property
    def query(self) -> ModelQuery:
        ...

    @query.setter
    def query(self, value: ModelQuery):
        ...

    @property
    def selectionMode(self) -> jpype.JInt:
        ...

    @selectionMode.setter
    def selectionMode(self, value: jpype.JInt):
        ...

    @property
    def selectedItems(self) -> java.util.List[T]:
        ...


class PathsTablePanel(AbstractQueryTablePanel[PathTableModel.PathRow, PathTableModel]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...


class ObjectsTreePanel(javax.swing.JPanel):

    @typing.type_check_only
    class ObjectsTreeRenderer(docking.widgets.tree.support.GTreeRenderer, ColorsModified.InTree):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ObjectGTree(docking.widgets.tree.GTree):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, root: docking.widgets.tree.GTreeNode):
            ...


    @typing.type_check_only
    class DelayedSwingHack(java.lang.Runnable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, delay: typing.Union[jpype.JInt, int], runnable: java.lang.Runnable):
            ...

        @staticmethod
        def runWayLater(delay: typing.Union[jpype.JInt, int], runnable: java.lang.Runnable):
            ...


    @typing.type_check_only
    class ListenerForShowing(javax.swing.event.AncestorListener):

        class_: typing.ClassVar[java.lang.Class]

        def updateShowing(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addTreeSelectionListener(self, listener: docking.widgets.tree.support.GTreeSelectionListener):
        ...

    def expandCurrent(self):
        ...

    def getNode(self, path: ghidra.trace.model.target.path.KeyPath) -> ObjectTreeModel.AbstractNode:
        ...

    def getSelectedItem(self) -> ObjectTreeModel.AbstractNode:
        ...

    def getSelectedItems(self) -> java.util.List[ObjectTreeModel.AbstractNode]:
        ...

    def getSelectedKeyPaths(self) -> java.util.Set[ghidra.trace.model.target.path.KeyPath]:
        ...

    def getSelectionMode(self) -> int:
        ...

    def goToCoordinates(self, coords: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def isLimitToSnap(self) -> bool:
        ...

    def isShowHidden(self) -> bool:
        ...

    def isShowMethods(self) -> bool:
        ...

    def isShowPrimitives(self) -> bool:
        ...

    def removeTreeSelectionListener(self, listener: docking.widgets.tree.support.GTreeSelectionListener):
        ...

    def selectCurrent(self):
        ...

    def setDiffColor(self, diffColor: java.awt.Color):
        ...

    def setDiffColorSel(self, diffColorSel: java.awt.Color):
        ...

    def setLimitToSnap(self, limitToSnap: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def setSelectedKeyPaths(self, keyPaths: collections.abc.Sequence, origin: docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin):
        ...

    @typing.overload
    def setSelectedKeyPaths(self, keyPaths: collections.abc.Sequence):
        ...

    def setSelectedObject(self, object: ghidra.trace.model.target.TraceObject):
        ...

    def setSelectionMode(self, selectionMode: typing.Union[jpype.JInt, int]):
        ...

    def setShowHidden(self, showHidden: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowMethods(self, showMethods: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowPrimitives(self, showPrimitives: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def showHidden(self) -> jpype.JBoolean:
        ...

    @showHidden.setter
    def showHidden(self, value: jpype.JBoolean):
        ...

    @property
    def node(self) -> ObjectTreeModel.AbstractNode:
        ...

    @property
    def showMethods(self) -> jpype.JBoolean:
        ...

    @showMethods.setter
    def showMethods(self, value: jpype.JBoolean):
        ...

    @property
    def limitToSnap(self) -> jpype.JBoolean:
        ...

    @limitToSnap.setter
    def limitToSnap(self, value: jpype.JBoolean):
        ...

    @property
    def selectedItem(self) -> ObjectTreeModel.AbstractNode:
        ...

    @property
    def selectedKeyPaths(self) -> java.util.Set[ghidra.trace.model.target.path.KeyPath]:
        ...

    @property
    def showPrimitives(self) -> jpype.JBoolean:
        ...

    @showPrimitives.setter
    def showPrimitives(self, value: jpype.JBoolean):
        ...

    @property
    def selectionMode(self) -> jpype.JInt:
        ...

    @selectionMode.setter
    def selectionMode(self, value: jpype.JInt):
        ...

    @property
    def selectedItems(self) -> java.util.List[ObjectTreeModel.AbstractNode]:
        ...


class DebuggerModelPlugin(ghidra.framework.plugintool.Plugin):

    @typing.type_check_only
    class ForModelMultiProviderSaveBehavior(ghidra.app.plugin.core.debug.gui.MultiProviderSaveBehavior[DebuggerModelProvider]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getConnectedProvider(self) -> DebuggerModelProvider:
        ...

    def getDisconnectedProviders(self) -> java.util.List[DebuggerModelProvider]:
        ...

    @property
    def disconnectedProviders(self) -> java.util.List[DebuggerModelProvider]:
        ...

    @property
    def connectedProvider(self) -> DebuggerModelProvider:
        ...


class ObjectDefaultActionsMixin(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def activatePath(self, path: ghidra.trace.model.target.path.KeyPath):
        ...

    def getCurrent(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    @typing.overload
    def goToAddress(self, listingService: ghidra.app.services.DebuggerListingService, address: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def goToAddress(self, address: ghidra.program.model.address.Address):
        ...

    def goToRange(self, range: ghidra.program.model.address.AddressRange):
        ...

    @typing.overload
    def performDefaultAction(self, value: ghidra.trace.model.target.TraceObjectValue) -> bool:
        ...

    @typing.overload
    def performDefaultAction(self, object: ghidra.trace.model.target.TraceObject) -> bool:
        ...

    @typing.overload
    def performDefaultAction(self, value: java.lang.Object) -> bool:
        ...

    def performElementCellDefaultAction(self, table: javax.swing.JTable) -> bool:
        ...

    def performPathRowDefaultAction(self, row: PathTableModel.PathRow) -> bool:
        ...

    def performValueRowDefaultAction(self, row: ObjectTableModel.ValueRow) -> bool:
        ...

    def toggleObject(self, object: ghidra.trace.model.target.TraceObject):
        ...

    @property
    def current(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...


class Adapters(java.lang.Object):

    class FocusListener(java.awt.event.FocusListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class KeyListener(java.awt.event.KeyListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class MouseListener(java.awt.event.MouseListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class TreeExpansionListener(javax.swing.event.TreeExpansionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ObjectTableModel(AbstractQueryTableModel[ObjectTableModel.ValueRow]):

    class ValueProperty(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def getDisplay(self) -> str:
            ...

        def getHtmlDisplay(self) -> str:
            ...

        def getRow(self) -> ObjectTableModel.ValueRow:
            ...

        def getToolTip(self) -> str:
            ...

        def getType(self) -> java.lang.Class[T]:
            ...

        def getValue(self) -> T:
            ...

        def isModified(self) -> bool:
            ...

        @property
        def display(self) -> java.lang.String:
            ...

        @property
        def toolTip(self) -> java.lang.String:
            ...

        @property
        def htmlDisplay(self) -> java.lang.String:
            ...

        @property
        def modified(self) -> jpype.JBoolean:
            ...

        @property
        def row(self) -> ObjectTableModel.ValueRow:
            ...

        @property
        def type(self) -> java.lang.Class[T]:
            ...

        @property
        def value(self) -> T:
            ...


    class ValueFixedProperty(ObjectTableModel.ValueProperty[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: T):
            ...


    class ValueDerivedProperty(ObjectTableModel.ValueProperty[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, row: ObjectTableModel.ValueRow, type: java.lang.Class[T]):
            ...


    class ValueAddressProperty(ObjectTableModel.ValueDerivedProperty[ghidra.program.model.address.Address]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, row: ObjectTableModel.ValueRow):
            ...


    class ValueAttribute(java.lang.Record, ObjectTableModel.ValueProperty[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, row: ObjectTableModel.ValueRow, name: typing.Union[java.lang.String, str], type: java.lang.Class[T]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def getEntry(self) -> ghidra.trace.model.target.TraceObjectValue:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def row(self) -> ObjectTableModel.ValueRow:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> java.lang.Class[T]:
            ...

        @property
        def entry(self) -> ghidra.trace.model.target.TraceObjectValue:
            ...


    class ValueRow(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def currentObject(self) -> ghidra.trace.model.target.TraceObject:
            ...

        def currentSnap(self) -> int:
            ...

        def getAttribute(self, attributeName: typing.Union[java.lang.String, str], type: java.lang.Class[T]) -> ObjectTableModel.ValueAttribute[T]:
            ...

        def getAttributeDisplay(self, attributeName: typing.Union[java.lang.String, str]) -> str:
            ...

        def getAttributeEntry(self, attributeName: typing.Union[java.lang.String, str]) -> ghidra.trace.model.target.TraceObjectValue:
            ...

        def getAttributeHtmlDisplay(self, attributeName: typing.Union[java.lang.String, str]) -> str:
            ...

        def getAttributeToolTip(self, attributeName: typing.Union[java.lang.String, str]) -> str:
            ...

        def getDisplay(self) -> str:
            """
            Get a non-HTML string representing how this row's value should be sorted, filtered, etc.
            
            :return: the display string
            :rtype: str
            """

        def getHtmlDisplay(self) -> str:
            """
            Get an HTML string representing how this row's value should be displayed
            
            :return: the display string
            :rtype: str
            """

        def getKey(self) -> str:
            ...

        def getLife(self) -> ghidra.trace.model.Lifespan.LifeSet:
            ...

        def getToolTip(self) -> str:
            ...

        def getValue(self) -> ghidra.trace.model.target.TraceObjectValue:
            ...

        def isAttributeModified(self, attributeName: typing.Union[java.lang.String, str]) -> bool:
            ...

        def isCurrent(self) -> bool:
            ...

        def isModified(self) -> bool:
            """
            Determine whether the value in the row has changed since the diff coordinates
            
            :return: true if they differ, i.e., should be rendered in red
            :rtype: bool
            """

        def previousSnap(self) -> int:
            ...

        @property
        def attributeEntry(self) -> ghidra.trace.model.target.TraceObjectValue:
            ...

        @property
        def current(self) -> jpype.JBoolean:
            ...

        @property
        def display(self) -> java.lang.String:
            ...

        @property
        def attributeToolTip(self) -> java.lang.String:
            ...

        @property
        def toolTip(self) -> java.lang.String:
            ...

        @property
        def htmlDisplay(self) -> java.lang.String:
            ...

        @property
        def modified(self) -> jpype.JBoolean:
            ...

        @property
        def attributeDisplay(self) -> java.lang.String:
            ...

        @property
        def value(self) -> ghidra.trace.model.target.TraceObjectValue:
            ...

        @property
        def attributeModified(self) -> jpype.JBoolean:
            ...

        @property
        def life(self) -> ghidra.trace.model.Lifespan.LifeSet:
            ...

        @property
        def key(self) -> java.lang.String:
            ...

        @property
        def attributeHtmlDisplay(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class AbstractValueRow(ObjectTableModel.ValueRow):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: ghidra.trace.model.target.TraceObjectValue):
            ...


    @typing.type_check_only
    class PrimitiveRow(ObjectTableModel.AbstractValueRow):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: ghidra.trace.model.target.TraceObjectValue):
            ...


    @typing.type_check_only
    class ObjectRow(ObjectTableModel.AbstractValueRow):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: ghidra.trace.model.target.TraceObjectValue):
            ...

        def getTraceObject(self) -> ghidra.trace.model.target.TraceObject:
            ...

        @property
        def traceObject(self) -> ghidra.trace.model.target.TraceObject:
            ...


    @typing.type_check_only
    class ColKey(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromSchema(ctx: ghidra.trace.model.target.schema.SchemaContext, attributeSchema: ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema) -> ObjectTableModel.ColKey:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> java.lang.Class[typing.Any]:
            ...


    @typing.type_check_only
    class AutoAttributeColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectAttributeColumn[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, attributeName: typing.Union[java.lang.String, str], attributeType: java.lang.Class[T], hidden: typing.Union[jpype.JBoolean, bool]):
            ...

        @staticmethod
        def fromSchema(ctx: ghidra.trace.model.target.schema.SchemaContext, attributeSchema: ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema) -> ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectAttributeColumn[typing.Any]:
            ...

        def isHidden(self) -> bool:
            ...

        @property
        def hidden(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def findTraceObjectAncestor(self, successor: ghidra.trace.model.target.TraceObject) -> ObjectTableModel.ValueRow:
        """
        Find the row whose object is the canonical ancestor to the given object
        
        :param ghidra.trace.model.target.TraceObject successor: the given object
        :return: the row or null
        :rtype: ObjectTableModel.ValueRow
        """

    def isColumnEditableForRow(self, t: ObjectTableModel.ValueRow, columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def setColumnValueForRow(self, t: ObjectTableModel.ValueRow, aValue: java.lang.Object, columnIndex: typing.Union[jpype.JInt, int]):
        ...


class DebuggerModelProvider(docking.ComponentProvider, ghidra.app.plugin.core.debug.gui.MultiProviderSaveBehavior.SaveableProvider):

    @typing.type_check_only
    class ShowObjectsTreeAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Show Objects Tree"
        ICON: typing.Final[javax.swing.Icon]
        DESCRIPTION: typing.Final = "Toggle display of the Objects Tree pane"
        GROUP: typing.Final = "Dbg3. Views"
        ORDER: typing.Final = "1"
        HELP_ANCHOR: typing.Final = "show_objects_tree"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class ShowElementsTableAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Show Elements Table"
        ICON: typing.Final[javax.swing.Icon]
        DESCRIPTION: typing.Final = "Toggle display of the Elements Table pane"
        GROUP: typing.Final = "Dbg3. Views"
        ORDER: typing.Final = "2"
        HELP_ANCHOR: typing.Final = "show_elements_table"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class ShowAttributesTableAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Show Attributes Table"
        ICON: typing.Final[javax.swing.Icon]
        DESCRIPTION: typing.Final = "Toggle display of the Attributes Table pane"
        GROUP: typing.Final = "Dbg3. Views"
        ORDER: typing.Final = "3"
        HELP_ANCHOR: typing.Final = "show_attributes_table"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class LimitToCurrentSnapAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Limit to Current Snap"
        DESCRIPTION: typing.Final = "Choose whether displayed objects must be alive at the current snap"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "limit_to_current_snap"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class ShowHiddenAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Show Hidden"
        DESCRIPTION: typing.Final = "Choose whether to display hidden children"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "show_hidden"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class ShowPrimitivesInTreeAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Show Primitives in Tree"
        DESCRIPTION: typing.Final = "Choose whether to display primitive values in the tree"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "show_primitives"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class ShowMethodsInTreeAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Show Methods in Tree"
        DESCRIPTION: typing.Final = "Choose whether to display methods in the tree"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "show_methods"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class FollowLinkAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Follow Link"
        DESCRIPTION: typing.Final = "Navigate to the link target"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "follow_link"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MyTextField(javax.swing.JTextField):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyMixin(ObjectDefaultActionsMixin):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ObjectsTreeListener(DebuggerModelProvider.MyMixin, Adapters.FocusListener, Adapters.TreeExpansionListener, Adapters.MouseListener, Adapters.KeyListener):

        class_: typing.ClassVar[java.lang.Class]

        def selectionChanged(self, evt: docking.widgets.tree.support.GTreeSelectionEvent):
            ...


    @typing.type_check_only
    class ElementsTableListener(DebuggerModelProvider.MyMixin, Adapters.FocusListener, AbstractQueryTablePanel.CellActivationListener):

        class_: typing.ClassVar[java.lang.Class]

        def selectionChanged(self, evt: javax.swing.event.ListSelectionEvent):
            ...


    @typing.type_check_only
    class AttributesTableListener(DebuggerModelProvider.MyMixin, Adapters.FocusListener, AbstractQueryTablePanel.CellActivationListener):

        class_: typing.ClassVar[java.lang.Class]

        def selectionChanged(self, evt: javax.swing.event.ListSelectionEvent):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerModelPlugin, isClone: typing.Union[jpype.JBoolean, bool]):
        ...

    def coordinatesActivated(self, coords: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def getPath(self) -> ghidra.trace.model.target.path.KeyPath:
        ...

    def isLimitToCurrentSnap(self) -> bool:
        ...

    def isShowHidden(self) -> bool:
        ...

    def isShowMethodsInTree(self) -> bool:
        ...

    def isShowPrimitivesInTree(self) -> bool:
        ...

    def setLimitToCurrentSnap(self, limitToSnap: typing.Union[jpype.JBoolean, bool]):
        ...

    def setPath(self, path: ghidra.trace.model.target.path.KeyPath):
        ...

    def setShowAttributesTable(self, showAttributesTable: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowElementsTable(self, showElementsTable: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowHidden(self, showHidden: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowMethodsInTree(self, showMethodsInTree: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowObjectsTree(self, showObjectsTree: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowPrimitivesInTree(self, showPrimitivesInTree: typing.Union[jpype.JBoolean, bool]):
        ...

    def traceClosed(self, trace: ghidra.trace.model.Trace):
        ...

    @property
    def showMethodsInTree(self) -> jpype.JBoolean:
        ...

    @showMethodsInTree.setter
    def showMethodsInTree(self, value: jpype.JBoolean):
        ...

    @property
    def showHidden(self) -> jpype.JBoolean:
        ...

    @showHidden.setter
    def showHidden(self, value: jpype.JBoolean):
        ...

    @property
    def path(self) -> ghidra.trace.model.target.path.KeyPath:
        ...

    @path.setter
    def path(self, value: ghidra.trace.model.target.path.KeyPath):
        ...

    @property
    def limitToCurrentSnap(self) -> jpype.JBoolean:
        ...

    @limitToCurrentSnap.setter
    def limitToCurrentSnap(self, value: jpype.JBoolean):
        ...

    @property
    def showPrimitivesInTree(self) -> jpype.JBoolean:
        ...

    @showPrimitivesInTree.setter
    def showPrimitivesInTree(self, value: jpype.JBoolean):
        ...


class ModelQuery(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[ModelQuery]

    def __init__(self, filter: ghidra.trace.model.target.path.PathFilter):
        """
        TODO: This should probably be more capable, but for now, just support simple path patterns
        
        :param ghidra.trace.model.target.path.PathFilter filter: the filter
        """

    @staticmethod
    def attributesOf(path: ghidra.trace.model.target.path.KeyPath) -> ModelQuery:
        ...

    def computeAttributes(self, trace: ghidra.trace.model.Trace) -> java.util.stream.Stream[ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema]:
        """
        Compute the named attributes for resulting objects, according to the schema
         
         
        
        This does not include the "default attribute schema."
        
        :param ghidra.trace.model.Trace trace: the data source
        :return: the list of attributes
        :rtype: java.util.stream.Stream[ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema]
        """

    def computeSchemas(self, trace: ghidra.trace.model.Trace) -> java.util.List[ghidra.trace.model.target.schema.TraceObjectSchema]:
        ...

    def computeSingleSchema(self, trace: ghidra.trace.model.Trace) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    @staticmethod
    def elementsOf(path: ghidra.trace.model.target.path.KeyPath) -> ModelQuery:
        ...

    def includes(self, span: ghidra.trace.model.Lifespan, value: ghidra.trace.model.target.TraceObjectValue) -> bool:
        """
        Determine whether this query would include the given value in its result
         
         
        
        More precisely, determine whether it would traverse the given value, accept it, and include
        its child in the result. It's possible the child could be included via another value, but
        this only considers the given value.
        
        :param ghidra.trace.model.Lifespan span: the span to consider
        :param ghidra.trace.model.target.TraceObjectValue value: the value to examine
        :return: true if the value would be accepted
        :rtype: bool
        """

    def involves(self, span: ghidra.trace.model.Lifespan, value: ghidra.trace.model.target.TraceObjectValue) -> bool:
        """
        Determine whether the query results could depend on the given value
        
        :param ghidra.trace.model.Lifespan span: the lifespan of interest, e.g., the span being displayed
        :param ghidra.trace.model.target.TraceObjectValue value: the value that has changed
        :return: true if the query results depend on the given value
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        ...

    @staticmethod
    def parse(queryString: typing.Union[java.lang.String, str]) -> ModelQuery:
        ...

    def streamObjects(self, trace: ghidra.trace.model.Trace, span: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[ghidra.trace.model.target.TraceObject]:
        """
        Execute the query
        
        :param ghidra.trace.model.Trace trace: the data source
        :param ghidra.trace.model.Lifespan span: the span of snapshots to search, usually all or a singleton
        :return: the stream of resulting objects
        :rtype: java.util.stream.Stream[ghidra.trace.model.target.TraceObject]
        """

    def streamPaths(self, trace: ghidra.trace.model.Trace, span: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[ghidra.trace.model.target.TraceObjectValPath]:
        ...

    def streamValues(self, trace: ghidra.trace.model.Trace, span: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[ghidra.trace.model.target.TraceObjectValue]:
        ...

    def toQueryString(self) -> str:
        """
        Render the query as a string as in :meth:`parse(String) <.parse>`
        
        :return: the string
        :rtype: str
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ObjectTreeModel(DisplaysModified):

    @typing.type_check_only
    class ListenerForChanges(ghidra.trace.model.TraceDomainObjectListener, ghidra.framework.model.DomainObjectClosedListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def domainObjectRestored(self, rec: ghidra.framework.model.DomainObjectChangeRecord):
            ...


    @typing.type_check_only
    class NodeCache(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def invalidate(self):
            ...


    class PendingNode(docking.widgets.tree.GTreeLazyNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class AbstractNode(docking.widgets.tree.GTreeLazyNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def addNodeSorted(self, node: ObjectTreeModel.AbstractNode):
            ...

        def getNode(self, p: ghidra.trace.model.target.path.KeyPath) -> ObjectTreeModel.AbstractNode:
            ...

        def getValue(self) -> ghidra.trace.model.target.TraceObjectValue:
            ...

        @property
        def node(self) -> ObjectTreeModel.AbstractNode:
            ...

        @property
        def value(self) -> ghidra.trace.model.target.TraceObjectValue:
            ...


    class RootNode(ObjectTreeModel.AbstractNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class PrimitiveNode(ObjectTreeModel.AbstractNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: ghidra.trace.model.target.TraceObjectValue):
            ...


    class AbstractObjectNode(ObjectTreeModel.AbstractNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: ghidra.trace.model.target.TraceObjectValue):
            ...


    class LinkNode(ObjectTreeModel.AbstractObjectNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: ghidra.trace.model.target.TraceObjectValue):
            ...


    class CanonicalNode(ObjectTreeModel.AbstractObjectNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: ghidra.trace.model.target.TraceObjectValue):
            ...


    @typing.type_check_only
    class LastKeyDisplaysObjectValues(DisplaysObjectValues):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TreeDisplaysObjectValues(ObjectTreeModel.LastKeyDisplaysObjectValues):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DiffTreeDisplaysObjectValues(ObjectTreeModel.LastKeyDisplaysObjectValues):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ICON_PENDING: typing.Final[generic.theme.GIcon]

    def __init__(self):
        ...

    def getNode(self, p: ghidra.trace.model.target.path.KeyPath) -> ObjectTreeModel.AbstractNode:
        ...

    def getRoot(self) -> docking.widgets.tree.GTreeLazyNode:
        ...

    def getSpan(self) -> ghidra.trace.model.Lifespan:
        ...

    def isShowHidden(self) -> bool:
        ...

    def isShowMethods(self) -> bool:
        ...

    def isShowPrimitives(self) -> bool:
        ...

    def setDiffSnap(self, diffSnap: typing.Union[jpype.JLong, int]):
        """
        Set alternative snap to colorize values that differ
         
         
        
        The diff trace must be set, even if it's the same as the trace being displayed. See
        :meth:`setDiffTrace(Trace) <.setDiffTrace>`.
        
        :param jpype.JLong or int diffSnap: the alternative snap
        """

    def setDiffTrace(self, diffTrace: ghidra.trace.model.Trace):
        """
        Set alternative trace to colorize values that differ
         
         
        
        The same trace can be used, but with an alternative snap, if desired. See
        :meth:`setDiffSnap(long) <.setDiffSnap>`. One common use is to compare with the previous snap of the same
        trace. Another common use is to compare with the previous navigation.
        
        :param ghidra.trace.model.Trace diffTrace: the alternative trace
        """

    def setShowHidden(self, showHidden: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowMethods(self, showMethods: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowPrimitives(self, showPrimitives: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSnap(self, snap: typing.Union[jpype.JLong, int]):
        ...

    def setSpan(self, span: ghidra.trace.model.Lifespan):
        ...

    def setTrace(self, trace: ghidra.trace.model.Trace):
        ...

    @property
    def showHidden(self) -> jpype.JBoolean:
        ...

    @showHidden.setter
    def showHidden(self, value: jpype.JBoolean):
        ...

    @property
    def node(self) -> ObjectTreeModel.AbstractNode:
        ...

    @property
    def showMethods(self) -> jpype.JBoolean:
        ...

    @showMethods.setter
    def showMethods(self, value: jpype.JBoolean):
        ...

    @property
    def root(self) -> docking.widgets.tree.GTreeLazyNode:
        ...

    @property
    def showPrimitives(self) -> jpype.JBoolean:
        ...

    @showPrimitives.setter
    def showPrimitives(self, value: jpype.JBoolean):
        ...

    @property
    def span(self) -> ghidra.trace.model.Lifespan:
        ...

    @span.setter
    def span(self, value: ghidra.trace.model.Lifespan):
        ...


class PathTableModel(AbstractQueryTableModel[PathTableModel.PathRow]):

    @typing.type_check_only
    class Seen(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def minSnap(self) -> int:
            ...

        def path(self) -> ghidra.trace.model.target.path.KeyPath:
            ...

        def toString(self) -> str:
            ...


    class PathRow(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, path: ghidra.trace.model.target.TraceObjectValPath):
            ...

        def computeValue(self) -> java.lang.Object:
            ...

        def getDisplay(self) -> str:
            """
            Get a non-HTML string representing how this row's value should be sorted, filtered, etc.
            
            :return: the display string
            :rtype: str
            """

        def getHtmlDisplay(self) -> str:
            """
            Get an HTML string representing how this row's value should be displayed
            
            :return: the display string
            :rtype: str
            """

        def getPath(self) -> ghidra.trace.model.target.TraceObjectValPath:
            ...

        def getToolTip(self) -> str:
            ...

        def getValue(self) -> java.lang.Object:
            ...

        def isCurrent(self) -> bool:
            ...

        def isLastCanonical(self) -> bool:
            ...

        def isModified(self) -> bool:
            ...

        @property
        def path(self) -> ghidra.trace.model.target.TraceObjectValPath:
            ...

        @property
        def current(self) -> jpype.JBoolean:
            ...

        @property
        def lastCanonical(self) -> jpype.JBoolean:
            ...

        @property
        def display(self) -> java.lang.String:
            ...

        @property
        def toolTip(self) -> java.lang.String:
            ...

        @property
        def htmlDisplay(self) -> java.lang.String:
            ...

        @property
        def modified(self) -> jpype.JBoolean:
            ...

        @property
        def value(self) -> java.lang.Object:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...


class ObjectsTablePanel(AbstractQueryTablePanel[ObjectTableModel.ValueRow, ObjectTableModel]):

    @typing.type_check_only
    class PropertyEditor(docking.widgets.table.GTableTextCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...

    def trySelectAncestor(self, successor: ghidra.trace.model.target.TraceObject) -> bool:
        ...



__all__ = ["AbstractObjectsTableBasedPanel", "KeepTreeState", "ColorsModified", "DisplaysObjectValues", "DisplaysModified", "AbstractQueryTableModel", "AbstractQueryTablePanel", "PathsTablePanel", "ObjectsTreePanel", "DebuggerModelPlugin", "ObjectDefaultActionsMixin", "Adapters", "ObjectTableModel", "DebuggerModelProvider", "ModelQuery", "ObjectTreeModel", "PathTableModel", "ObjectsTablePanel"]
