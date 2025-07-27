from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.google.common.base # type: ignore
import docking.widgets
import edu.uci.ics.jung.algorithms.layout # type: ignore
import edu.uci.ics.jung.graph # type: ignore
import edu.uci.ics.jung.visualization # type: ignore
import edu.uci.ics.jung.visualization.control # type: ignore
import ghidra.framework.options
import ghidra.graph
import ghidra.graph.event
import ghidra.graph.job
import ghidra.graph.viewer.actions
import ghidra.graph.viewer.edge
import ghidra.graph.viewer.event.mouse
import ghidra.graph.viewer.event.picking
import ghidra.graph.viewer.layout
import ghidra.graph.viewer.options
import ghidra.graph.viewer.popup
import ghidra.graph.viewer.vertex
import ghidra.util.task
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.awt.geom # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import utility.function


E = typing.TypeVar("E")
G = typing.TypeVar("G")
V = typing.TypeVar("V")


class GraphViewer(edu.uci.ics.jung.visualization.VisualizationViewer[V, E], typing.Generic[V, E]):
    """
    The base viewer for the Graph module.   This viewer provides methods for manipulating
    the graph using the mouse.
     
     
    The viewer is currently an extension of the :obj:`VisualizationViewer` and as such it 
    is accessed by much of the event handling subsystem, such as the mouse plugins, as well as 
    the rendering system.
     
     
    Also, tooltips/popups for edges and vertices are handled by this class.
     
     
    This class creates a :obj:`VisualGraphViewUpdater` that perform graph transformations, 
    such as panning the graph, with and without animation, as requested.
    """

    @typing.type_check_only
    class GraphViewerPopupSource(ghidra.graph.viewer.popup.PopupSource[V, E]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VertexToolTipInfo(ghidra.graph.viewer.popup.ToolTipInfo[V]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EdgeToolTipInfo(ghidra.graph.viewer.popup.ToolTipInfo[E]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DummyTooltipProvider(ghidra.graph.viewer.event.mouse.VertexTooltipProvider[V, E]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, layout: ghidra.graph.viewer.layout.VisualGraphLayout[V, E], size: java.awt.Dimension):
        ...

    def add(self, comp: java.awt.Component) -> java.awt.Component:
        """
        !!Super Hacky Override!!
        The code we are overriding blindly calls add(), without first checking to see if it has
        already been added.  Java 6 added a method, removeNotify(), that is called when components
        are removed.  When add is called in the overridden method, it triggers a call to remove, 
        which triggers removeNotify().  This call is made during the painting process.  The problem
        therein is that out buttons borders get reset (see AbstractButton.removeNotify()) when
        we repaint, which means that mouse hovers do not work correctly (SCR 6819).
        """

    def createVertexMouseInfo(self, e: java.awt.event.MouseEvent, v: V, vertexBasedClickPoint: java.awt.geom.Point2D) -> ghidra.graph.viewer.event.mouse.VertexMouseInfo[V, E]:
        ...

    def dispose(self):
        ...

    def getGPickedVertexState(self) -> ghidra.graph.viewer.event.picking.GPickedState[V]:
        ...

    def getOptions(self) -> ghidra.graph.viewer.options.VisualGraphOptions:
        ...

    def getPathHighlighter(self) -> ghidra.graph.viewer.edge.VisualGraphPathHighlighter[V, E]:
        ...

    def getVertexFocusPathHighlightMode(self) -> PathHighlightMode:
        ...

    def getVertexHoverPathHighlightMode(self) -> PathHighlightMode:
        ...

    def getViewUpdater(self) -> VisualGraphViewUpdater[V, E]:
        ...

    def getVisualGraph(self) -> ghidra.graph.VisualGraph[V, E]:
        ...

    def getVisualGraphLayout(self) -> ghidra.graph.viewer.layout.VisualGraphLayout[V, E]:
        ...

    def optionsChanged(self):
        ...

    def setGraphOptions(self, options: ghidra.graph.viewer.options.VisualGraphOptions):
        ...

    def setPopupsVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    def setVertexFocusPathHighlightMode(self, focusMode: PathHighlightMode):
        ...

    def setVertexHoverPathHighlightMode(self, hoverMode: PathHighlightMode):
        ...

    def setVertexTooltipProvider(self, vertexTooltipProvider: ghidra.graph.viewer.event.mouse.VertexTooltipProvider[V, E]):
        ...

    def setViewerInitializedListener(self, listener: java.util.function.Consumer[GraphViewer[V, E]]):
        ...

    def useMouseRelativeZoom(self) -> bool:
        """
        When true (the default), the zoom will center wherever the mouse is positioned.  False 
        will zoom at the center of the view.
        
        :return: true if using mouse-relative zoom
        :rtype: bool
        """

    @property
    def viewUpdater(self) -> VisualGraphViewUpdater[V, E]:
        ...

    @property
    def vertexHoverPathHighlightMode(self) -> PathHighlightMode:
        ...

    @vertexHoverPathHighlightMode.setter
    def vertexHoverPathHighlightMode(self, value: PathHighlightMode):
        ...

    @property
    def vertexFocusPathHighlightMode(self) -> PathHighlightMode:
        ...

    @vertexFocusPathHighlightMode.setter
    def vertexFocusPathHighlightMode(self, value: PathHighlightMode):
        ...

    @property
    def gPickedVertexState(self) -> ghidra.graph.viewer.event.picking.GPickedState[V]:
        ...

    @property
    def visualGraph(self) -> ghidra.graph.VisualGraph[V, E]:
        ...

    @property
    def options(self) -> ghidra.graph.viewer.options.VisualGraphOptions:
        ...

    @property
    def visualGraphLayout(self) -> ghidra.graph.viewer.layout.VisualGraphLayout[V, E]:
        ...

    @property
    def pathHighlighter(self) -> ghidra.graph.viewer.edge.VisualGraphPathHighlighter[V, E]:
        ...


class VisualGraphViewUpdater(java.lang.Object, typing.Generic[V, E]):
    """
    This is the class through which operations travel that manipulate the view and graph **while
    plugged-in to the UI**.   (Setup and tear down operations performed before the view 
    or graph are visible need not pass through this class.)  This class is responsible for 
    controlling how to display view and graph changes, including whether to animate.
     
     
    The animations are categorized into those that mutate the graph and those that are just
    display animations (like hover animations).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, primaryViewer: GraphViewer[V, E], graph: ghidra.graph.VisualGraph[V, E]):
        ...

    def addJobScheduledListener(self, c: utility.function.Callback):
        """
        Add a listener to be notified when a job is started.  Jobs often, but not always, mutate
        the underlying graph.  For this reason, other tasks that use the graph may want to not 
        do their work while a job is running.
        
        :param utility.function.Callback c: the listener
        """

    def animateEdgeHover(self):
        ...

    def centerLayoutSpacePointWithoutAnimation(self, point: java.awt.Point):
        ...

    def centerViewSpacePointWithAnimation(self, point: java.awt.Point):
        ...

    def centerViewSpacePointWithoutAnimation(self, point: java.awt.Point):
        ...

    def dispose(self):
        ...

    def ensureVertexAreaVisible(self, vertex: V, area: java.awt.Rectangle, callbackListener: ghidra.util.task.BusyListener):
        ...

    def ensureVertexVisible(self, vertex: V, area: java.awt.Rectangle):
        ...

    def fitAllGraphsToViewsNow(self):
        """
        Fits the graph into both the primary and satellite views
        """

    @typing.overload
    def fitGraphToViewerLater(self):
        """
        Will schedule the fitting work to happen now if now work is being done, or later otherwis
        """

    @typing.overload
    def fitGraphToViewerLater(self, theViewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]):
        ...

    @typing.overload
    def fitGraphToViewerNow(self):
        ...

    @typing.overload
    def fitGraphToViewerNow(self, theViewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]):
        ...

    def isAnimationEnabled(self) -> bool:
        ...

    def isBusy(self) -> bool:
        """
        Returns true if this updater is performing any animations or running any jobs that can
        mutate the graph or view
        
        :return: true if busy
        :rtype: bool
        """

    def isMutatingGraph(self) -> bool:
        """
        Returns true if this updater is running any jobs that can mutate the graph or view
        
        :return: true if busy
        :rtype: bool
        """

    @typing.overload
    def moveVertexToCenterTopWithAnimation(self, vertex: V):
        ...

    @typing.overload
    def moveVertexToCenterTopWithAnimation(self, vertex: V, callbackListener: ghidra.util.task.BusyListener):
        ...

    def moveVertexToCenterTopWithoutAnimation(self, vertex: V):
        ...

    @typing.overload
    def moveVertexToCenterWithAnimation(self, vertex: V):
        ...

    @typing.overload
    def moveVertexToCenterWithAnimation(self, vertex: V, callbackListener: ghidra.util.task.BusyListener):
        ...

    def moveVertexToCenterWithoutAnimation(self, vertex: V):
        ...

    def moveViewerLocationWithoutAnimation(self, translation: java.awt.Point):
        ...

    def relayoutGraph(self):
        ...

    def scheduleViewChangeJob(self, job: ghidra.graph.job.GraphJob):
        ...

    def setGraphPerspective(self, graphInfo: GraphPerspectiveInfo[V, E]):
        ...

    def setGraphScale(self, scale: typing.Union[jpype.JDouble, float]):
        ...

    def setLayoutSpacePointWithAnimation(self, point: java.awt.Point):
        ...

    def setLayoutSpacePointWithoutAnimation(self, point: java.awt.geom.Point2D):
        ...

    def stopAllAnimation(self):
        ...

    def stopEdgeHoverAnimation(self):
        ...

    def twinkeVertex(self, vertex: V):
        ...

    def updateEdgeShapes(self, edges: collections.abc.Sequence):
        ...

    @typing.overload
    def zoomInCompletely(self):
        ...

    @typing.overload
    def zoomInCompletely(self, centerOnVertex: V):
        ...

    @property
    def mutatingGraph(self) -> jpype.JBoolean:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def animationEnabled(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class VisualGraphLayeredPaneButton(docking.widgets.EmptyBorderButton, ghidra.graph.viewer.actions.VisualGraphContextMarker):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SatelliteGraphViewer(edu.uci.ics.jung.visualization.control.SatelliteVisualizationViewer[V, E], typing.Generic[V, E]):
    """
    A graph viewer that shows a scaled, complete rendering of the graph with which it is 
    associated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, master: GraphViewer[V, E], preferredSize: java.awt.Dimension):
        ...

    def getPreferredVertexRenderer(self) -> edu.uci.ics.jung.visualization.renderers.Renderer.Vertex[V, E]:
        """
        Gets the renderer to use with this satellite viewer.
        
        :return: the renderer
        :rtype: edu.uci.ics.jung.visualization.renderers.Renderer.Vertex[V, E]
        """

    def isDocked(self) -> bool:
        """
        Returns true if this satellite viewer is docked
        
        :return: true if this satellite viewer is docked
        :rtype: bool
        """

    def optionsChanged(self):
        """
        Called to signal that the options used by this viewer have changed
        """

    def setDocked(self, docked: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the docked state of this viewer.  An undocked satellite viewer will be in its 
        own window.
        
        :param jpype.JBoolean or bool docked: true if this viewer is docked; false if it is undocked
        """

    def setGraphOptions(self, options: ghidra.graph.viewer.options.VisualGraphOptions):
        """
        The options for this viewer
        
        :param ghidra.graph.viewer.options.VisualGraphOptions options: the options
        """

    @property
    def preferredVertexRenderer(self) -> edu.uci.ics.jung.visualization.renderers.Renderer.Vertex[V, E]:
        ...

    @property
    def docked(self) -> jpype.JBoolean:
        ...

    @docked.setter
    def docked(self, value: jpype.JBoolean):
        ...


class VisualGraphView(java.lang.Object, typing.Generic[V, E, G]):
    """
    A view object, where 'view' is used in the sense of the Model-View-Controller (MVC) pattern.
    This class will contain all UI widgets need to display and interact with a graph.
    
     
    **Implementation Note:**
     
    1. The graph of this component can be null, changing to non-null values over the
    lifetime of this view.  This allows this view to be installed in a UI component, with the
    contents changing as needed.
    
    2. 
    When the graph is:meth:`set <.setGraph>`, the view portion of the class is
    recreated.
    
    3. 
    At any given point in time there may not be a:obj:`.graphComponent`.  This means that
    this class must maintain settings state that it will apply when the component is created.
    This state is atypical and makes this class a bit harder to understand.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def arePopupsEnabled(self) -> bool:
        ...

    def cleanup(self):
        """
        Effectively clears this display.  This method is not called dispose, as that implies
        the end of an object's lifecycle.  This object can be re-used after this method is
        called.
        """

    def generateGraphPerspective(self) -> GraphPerspectiveInfo[V, E]:
        ...

    def getFocusedVertex(self) -> V:
        ...

    def getGraphComponent(self) -> GraphComponent[V, E, G]:
        ...

    def getLayoutProvider(self) -> ghidra.graph.viewer.layout.LayoutProvider[V, E, G]:
        ...

    def getPrimaryGraphViewer(self) -> GraphViewer[V, E]:
        """
        Returns the primary viewer of the graph (as opposed to the satellite viewer).   The
        viewer returned is responsible for maintaining view information for a given graph.
        
        :return: the primary viewer
        :rtype: GraphViewer[V, E]
        """

    def getSatellitePosition(self) -> GraphComponent.SatellitePosition:
        ...

    def getSatelliteViewer(self) -> SatelliteGraphViewer[V, E]:
        ...

    def getSelectedVertices(self) -> java.util.Set[V]:
        ...

    def getUndockedSatelliteComponent(self) -> javax.swing.JComponent:
        ...

    def getVertexFocusPathHighlightMode(self) -> PathHighlightMode:
        ...

    def getVertexHoverPathHighlightMode(self) -> PathHighlightMode:
        ...

    def getVertexPointInViewSpace(self, v: V) -> java.awt.Point:
        ...

    def getViewComponent(self) -> javax.swing.JComponent:
        ...

    def getViewUpdater(self) -> VisualGraphViewUpdater[V, E]:
        ...

    def getVisualGraph(self) -> G:
        ...

    def isSatelliteComponent(self, c: java.awt.Component) -> bool:
        ...

    def isSatelliteDocked(self) -> bool:
        """
        Returns whether the satellite intended to be docked.  If this component is built, then
        a result of true means that the satellite is docked.  If the component is not yet
        built, then a result of true means that the satellite will be made docked when the
        component is built.
        
        :return: true if visible
        :rtype: bool
        """

    def isSatelliteVisible(self) -> bool:
        """
        Returns whether the satellite intended to be visible.  If this component is built, then
        a result of true means that the satellite is showing.  If the component is not yet
        built, then a result of true means that the satellite will be made visible when the
        component is built.
        
        :return: true if visible
        :rtype: bool
        """

    def isScaledPastInteractionThreshold(self) -> bool:
        ...

    def optionsChanged(self):
        """
        Called when the options used by this graph view have changed
        """

    def repaint(self):
        ...

    def requestFocus(self):
        ...

    def setGraph(self, graph: G):
        ...

    def setGraphPerspective(self, newPerspective: GraphPerspectiveInfo[V, E]):
        """
        Sets the perspective for this view
        
        :param GraphPerspectiveInfo[V, E] newPerspective: the new perspective
        """

    def setLayoutProvider(self, newLayoutProvider: ghidra.graph.viewer.layout.LayoutProvider[V, E, G]):
        """
        Sets the given layout provider, **but does not actually perform a layout**.
        
        :param ghidra.graph.viewer.layout.LayoutProvider[V, E, G] newLayoutProvider: the new provider
        """

    def setPopupsVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSatelliteDocked(self, docked: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSatelliteListener(self, l: GraphSatelliteListener):
        ...

    def setSatellitePosition(self, position: GraphComponent.SatellitePosition):
        ...

    def setSatelliteVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    def setStatusMessage(self, message: typing.Union[java.lang.String, str]):
        """
        Sets a message to be painted on the viewer.  This is useful to show a text message to the
        user.  Passing null will clear the message.
        
        :param java.lang.String or str message: the status message
        """

    def setTooltipProvider(self, provider: ghidra.graph.viewer.event.mouse.VertexTooltipProvider[V, E]):
        ...

    def setVertexClickListener(self, l: ghidra.graph.viewer.vertex.VertexClickListener[V, E]):
        """
        Sets a listener that allows clients to be notified of vertex double-clicks.  Normal
        mouse processing is handled by the :obj:`VisualGraphMousePlugin` class.  This is a
        convenience method so that clients do not have to deal with the mouse plugin.
        
        :param ghidra.graph.viewer.vertex.VertexClickListener[V, E] l: the listener
        """

    def setVertexFocusListener(self, l: ghidra.graph.viewer.vertex.VertexFocusListener[V]):
        ...

    def setVertexFocusPathHighlightMode(self, mode: PathHighlightMode):
        ...

    def setVertexHoverPathHighlightMode(self, mode: PathHighlightMode):
        ...

    def showErrorView(self, errorMessage: typing.Union[java.lang.String, str]):
        ...

    def translateMouseEventFromVertexToViewSpace(self, v: V, e: java.awt.event.MouseEvent) -> java.awt.event.MouseEvent:
        ...

    def translatePointFromVertexToViewSpace(self, v: V, p: java.awt.Point) -> java.awt.Point:
        ...

    def translateRectangleFromVertexToViewSpace(self, v: V, r: java.awt.Rectangle) -> java.awt.Rectangle:
        ...

    def zoomInGraph(self):
        ...

    def zoomOutGraph(self):
        ...

    def zoomToVertex(self, v: V):
        ...

    def zoomToWindow(self):
        ...

    @property
    def satelliteViewer(self) -> SatelliteGraphViewer[V, E]:
        ...

    @property
    def graphComponent(self) -> GraphComponent[V, E, G]:
        ...

    @property
    def selectedVertices(self) -> java.util.Set[V]:
        ...

    @property
    def viewUpdater(self) -> VisualGraphViewUpdater[V, E]:
        ...

    @property
    def layoutProvider(self) -> ghidra.graph.viewer.layout.LayoutProvider[V, E, G]:
        ...

    @layoutProvider.setter
    def layoutProvider(self, value: ghidra.graph.viewer.layout.LayoutProvider[V, E, G]):
        ...

    @property
    def vertexFocusPathHighlightMode(self) -> PathHighlightMode:
        ...

    @vertexFocusPathHighlightMode.setter
    def vertexFocusPathHighlightMode(self, value: PathHighlightMode):
        ...

    @property
    def satelliteComponent(self) -> jpype.JBoolean:
        ...

    @property
    def vertexHoverPathHighlightMode(self) -> PathHighlightMode:
        ...

    @vertexHoverPathHighlightMode.setter
    def vertexHoverPathHighlightMode(self, value: PathHighlightMode):
        ...

    @property
    def scaledPastInteractionThreshold(self) -> jpype.JBoolean:
        ...

    @property
    def satelliteDocked(self) -> jpype.JBoolean:
        ...

    @satelliteDocked.setter
    def satelliteDocked(self, value: jpype.JBoolean):
        ...

    @property
    def vertexPointInViewSpace(self) -> java.awt.Point:
        ...

    @property
    def undockedSatelliteComponent(self) -> javax.swing.JComponent:
        ...

    @property
    def visualGraph(self) -> G:
        ...

    @property
    def viewComponent(self) -> javax.swing.JComponent:
        ...

    @property
    def primaryGraphViewer(self) -> GraphViewer[V, E]:
        ...

    @property
    def satelliteVisible(self) -> jpype.JBoolean:
        ...

    @satelliteVisible.setter
    def satelliteVisible(self, value: jpype.JBoolean):
        ...

    @property
    def focusedVertex(self) -> V:
        ...

    @property
    def satellitePosition(self) -> GraphComponent.SatellitePosition:
        ...

    @satellitePosition.setter
    def satellitePosition(self, value: GraphComponent.SatellitePosition):
        ...


class PathHighlightMode(java.lang.Enum[PathHighlightMode]):
    """
    An enum that lists possible states for highlighting paths between vertices in a graph.
    
    
    .. seealso::
    
        | :obj:`VisualGraphPathHighlighter`
    """

    class_: typing.ClassVar[java.lang.Class]
    ALLCYCLE: typing.Final[PathHighlightMode]
    """
    Shows all cycles in the graph
    """

    CYCLE: typing.Final[PathHighlightMode]
    """
    Shows all cycles for a given vertex
    """

    IN: typing.Final[PathHighlightMode]
    """
    Shows all paths that can reach the given vertex
    """

    INOUT: typing.Final[PathHighlightMode]
    """
    Shows all paths coming into and out of a vertex
    """

    OFF: typing.Final[PathHighlightMode]
    """
    Shows no paths
    """

    OUT: typing.Final[PathHighlightMode]
    """
    Shows all paths reachable from the current vertex
    """

    PATH: typing.Final[PathHighlightMode]
    """
    Shows all paths between two vertices
    """

    SCOPED_FORWARD: typing.Final[PathHighlightMode]
    """
    Shows all paths that must have been traveled to reach the current vertex
    """

    SCOPED_REVERSE: typing.Final[PathHighlightMode]
    """
    Shows all paths that will be traveled after leaving the current vertex
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PathHighlightMode:
        ...

    @staticmethod
    def values() -> jpype.JArray[PathHighlightMode]:
        ...


class GraphPerspectiveInfo(java.lang.Object, typing.Generic[V, E]):
    """
    An object that allows for storing and restoring of graph perspective data, like the zoom 
    level and the position of the graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, renderContext: edu.uci.ics.jung.visualization.RenderContext[V, E], zoom: typing.Union[jpype.JDouble, float]):
        ...

    @typing.overload
    def __init__(self, saveState: ghidra.framework.options.SaveState):
        ...

    @staticmethod
    def createInvalidGraphPerspectiveInfo() -> GraphPerspectiveInfo[V, E]:
        ...

    def getLayoutTranslateCoordinates(self) -> java.awt.Point:
        """
        The offset of the transform from the world origin (which at the time of writing is
        the (0,0) at the upper left-hand corner of the GUI.  This is for the layout transformer.
        """

    def getViewTranslateCoordinates(self) -> java.awt.Point:
        """
        The offset of the transform from the world origin (which at the time of writing is
        the (0,0) at the upper left-hand corner of the GUI.  This is for the view transformer, 
        which also potentially has a scale applied to the transform.
        """

    def getZoom(self) -> float:
        ...

    def isInvalid(self) -> bool:
        ...

    def isRestoreZoom(self) -> bool:
        ...

    def saveState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def invalid(self) -> jpype.JBoolean:
        ...

    @property
    def zoom(self) -> jpype.JDouble:
        ...

    @property
    def restoreZoom(self) -> jpype.JBoolean:
        ...

    @property
    def viewTranslateCoordinates(self) -> java.awt.Point:
        ...

    @property
    def layoutTranslateCoordinates(self) -> java.awt.Point:
        ...


class VisualEdge(ghidra.graph.GEdge[V], typing.Generic[V]):
    """
    An edge that contains properties and state related to a user interface.
     
     
    An edge can be selected, which means that it has been clicked by the user.  Also, an 
    edge can be part of an active path.  This allows the UI to paint the edge differently if it
    is in the active path.   The active path concept applies to both hovered and focused vertices
    separately.  A hovered vertex is one that the user moves the mouse over; a focused vertex is
    one that is selected.
     
     
    .. _articulations:
    
    
     
    Articulations - The start and end points are always part of the
    edge.  Any additional points on the edge are considered articulation points.  Thus, an edge
    without articulations will be drawn as a straight line.  An edge with articulations will
    be drawn as a series of straight lines from point-to-point, allowing the layout algorithm
    to add points to the edge to avoid line crossings; these points are used to make the 
    drawing of the edge cleaner.
    
     
    equals() and hashCode() - The graph API allows for cloning of layouts.  For this 
    to correctly copy layout locations, each edge must override ``equals`` and
    ``hashCode`` in order to properly find edges across graphs.
    """

    class_: typing.ClassVar[java.lang.Class]

    def cloneEdge(self, start: V, end: V) -> E:
        """
        Creates a new edge of this type using the given vertices.
         
         
        Implementation Note: the odd type 'E' below is there so that subclasses can return
        the type of their implementation.   Basically, the decision was made to have each subclass
        suppress the warning that appears, since they know the type is safe.  Alternatively, 
        each client would have to cast the return type, which seems less desirable.
        
        :param V start: the start vertex
        :param V end: the end vertex
        :return: the new edge
        :rtype: E
        """

    def getAlpha(self) -> float:
        """
        Get the alpha, which determines how much of the edge is visible/see through.  0 is 
        completely transparent.  This attribute allows transitional for animations.
        
        :return: the alpha value
        :rtype: float
        """

    def getArticulationPoints(self) -> java.util.List[java.awt.geom.Point2D]:
        """
        Returns the points (in :obj:`GraphViewerUtils` View Space) of the articulation
         
         
        `What are articulations? <articulations_>`_
        
        :return: the points (in View Space space) of the articulation.
        :rtype: java.util.List[java.awt.geom.Point2D]
        """

    def getEmphasis(self) -> float:
        """
        Returns the emphasis value of this edge.  0 if not emphasized.
        
        :return: the emphasis value of this edge.
        :rtype: float
        """

    def isInFocusedVertexPath(self) -> bool:
        """
        Returns true if this edge is part of an active path for a currently focused/selected 
        vertex (this allows the edge to be differently rendered)
        
        :return: true if this edge is part of the active path
        :rtype: bool
        """

    def isInHoveredVertexPath(self) -> bool:
        """
        Returns true if this edge is part of an active path for a currently hovered 
        vertex (this allows the edge to be differently rendered)
        
        :return: true if this edge is part of the active path
        :rtype: bool
        """

    def isSelected(self) -> bool:
        """
        Returns true if this edge is selected
        
        :return: true if this edge is selected
        :rtype: bool
        """

    def setAlpha(self, alpha: typing.Union[jpype.JDouble, float]):
        """
        Set the alpha, which determines how much of the edge is visible/see through.  0 is 
        completely transparent.  This attribute allows transitional for animations.
        
        :param jpype.JDouble or float alpha: the alpha value
        """

    def setArticulationPoints(self, points: java.util.List[java.awt.geom.Point2D]):
        """
        Sets the articulation points for the given edge
         
         
        `What are articulations? <articulations_>`_
        
        :param java.util.List[java.awt.geom.Point2D] points: the points
        """

    def setEmphasis(self, emphasisLevel: typing.Union[jpype.JDouble, float]):
        """
        Sets the emphasis value for this edge.  A value of 0 indicates no emphasis.
        
        :param jpype.JDouble or float emphasisLevel: the emphasis
        """

    def setInFocusedVertexPath(self, inPath: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this edge to be marked as in the active path of a currently focused/selected vertex
        
        :param jpype.JBoolean or bool inPath: true to be marked as in the active path; false to be marked as not 
                in the active path
        """

    def setInHoveredVertexPath(self, inPath: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this edge to be marked as in the active path of a currently hovered vertex
        
        :param jpype.JBoolean or bool inPath: true to be marked as in the active path; false to be marked as not 
                in the active path
        """

    def setSelected(self, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this edge selected.  This is usually in response to the user selecting the edge.
        
        :param jpype.JBoolean or bool selected: true to select this edge; false to de-select this vertex
        """

    @property
    def inHoveredVertexPath(self) -> jpype.JBoolean:
        ...

    @inHoveredVertexPath.setter
    def inHoveredVertexPath(self, value: jpype.JBoolean):
        ...

    @property
    def alpha(self) -> jpype.JDouble:
        ...

    @alpha.setter
    def alpha(self, value: jpype.JDouble):
        ...

    @property
    def emphasis(self) -> jpype.JDouble:
        ...

    @emphasis.setter
    def emphasis(self, value: jpype.JDouble):
        ...

    @property
    def articulationPoints(self) -> java.util.List[java.awt.geom.Point2D]:
        ...

    @articulationPoints.setter
    def articulationPoints(self, value: java.util.List[java.awt.geom.Point2D]):
        ...

    @property
    def inFocusedVertexPath(self) -> jpype.JBoolean:
        ...

    @inFocusedVertexPath.setter
    def inFocusedVertexPath(self, value: jpype.JBoolean):
        ...

    @property
    def selected(self) -> jpype.JBoolean:
        ...

    @selected.setter
    def selected(self, value: jpype.JBoolean):
        ...


class VisualGraphScalingControl(edu.uci.ics.jung.visualization.control.ScalingControl):
    """
    An implementation of :obj:`ScalingControl` that allows us to zoom in and out of the view.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GraphSatelliteListener(java.lang.Object):
    """
    A listener to get notified of changes to the :obj:`SatelliteGraphViewer`
    """

    class_: typing.ClassVar[java.lang.Class]

    def satelliteVisibilityChanged(self, docked: typing.Union[jpype.JBoolean, bool], visible: typing.Union[jpype.JBoolean, bool]):
        """
        Called when the visibility and/or docked state of the watched satellite changes
        
        :param jpype.JBoolean or bool docked: true if the satellite is now docked
        :param jpype.JBoolean or bool visible: true if the satellite is now visible
        """


class VisualVertex(ghidra.graph.GVertex):
    """
    A vertex that contains properties and state related to a user interface.
     
     
    equals() and hashCode() - The graph API allows for cloning of layouts.  For this 
    to correctly copy layout locations, each edge must override ``equals`` and
    ``hashCode`` in order to properly find edges across graphs.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        A dispose method that should be called when a vertex is reclaimed, never again to be 
        used in a graph or display
        """

    def getAlpha(self) -> float:
        """
        Get the alpha, which determines how much of the vertex is visible/see through.  0 is 
        completely transparent.  This attribute allows transitional for animations.
        
        :return: the alpha value
        :rtype: float
        """

    def getComponent(self) -> javax.swing.JComponent:
        """
        Returns the component of this vertex.  This is used for rendering and interaction 
        with the user.
        
        :return: the component of this vertex
        :rtype: javax.swing.JComponent
        """

    def getEmphasis(self) -> float:
        """
        Returns the emphasis value of this vertex.  0 if not emphasized.
        
        :return: the emphasis value of this vertex.
        :rtype: float
        """

    def getLocation(self) -> java.awt.geom.Point2D:
        """
        Returns the location of this vertex in the view
        
        :return: the location of this vertex in the view
        :rtype: java.awt.geom.Point2D
        """

    def isFocused(self) -> bool:
        """
        Returns true if this vertex is focused (see :meth:`setFocused(boolean) <.setFocused>`
        
        :return: true if focused
        :rtype: bool
        """

    def isGrabbable(self, c: java.awt.Component) -> bool:
        """
        Returns true if the given component of this vertex is grabbable, which means that 
        mouse drags on that component will move the vertex.   
         
         
        This is used to differentiate components within a vertex that should receive mouse 
        events versus those components that will not be given mouse events.
        
        :param java.awt.Component c: the component
        :return: true if the component is grabbable
        :rtype: bool
        """

    def isHovered(self) -> bool:
        """
        Returns true if this vertex is being hovered by the mouse
        
        :return: true if this vertex is being hovered by the mouse
        :rtype: bool
        """

    def isSelected(self) -> bool:
        """
        Returns true if this vertex is selected
        
        :return: true if this vertex is selected
        :rtype: bool
        """

    def setAlpha(self, alpha: typing.Union[jpype.JDouble, float]):
        """
        Set the alpha, which determines how much of the vertex is visible/see through.  0 is 
        completely transparent.  This attribute allows transitional for animations.
        
        :param jpype.JDouble or float alpha: the alpha value
        """

    def setEmphasis(self, emphasisLevel: typing.Union[jpype.JDouble, float]):
        """
        Sets the emphasis value for this vertex.  A value of 0 indicates no emphasis.
        
        :param jpype.JDouble or float emphasisLevel: the emphasis
        """

    def setFocused(self, focused: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this vertex to be focused.   This differs from being selected in that multiple
        vertices in a graph can be selected, but only one can be the focused vertex.
        
        :param jpype.JBoolean or bool focused: true to focus; false to be marked as not focused
        """

    def setHovered(self, hovered: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this vertex to be hovered
        
        :param jpype.JBoolean or bool hovered: true to be marked as hovered; false to be marked as not hovered
        """

    def setLocation(self, p: java.awt.geom.Point2D):
        """
        Sets the location of this vertex in the view
        
        :param java.awt.geom.Point2D p: the location of this vertex in the view
        """

    def setSelected(self, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this vertex selected
        
        :param jpype.JBoolean or bool selected: true to select this vertex; false to de-select this vertex
        """

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def alpha(self) -> jpype.JDouble:
        ...

    @alpha.setter
    def alpha(self, value: jpype.JDouble):
        ...

    @property
    def grabbable(self) -> jpype.JBoolean:
        ...

    @property
    def focused(self) -> jpype.JBoolean:
        ...

    @focused.setter
    def focused(self, value: jpype.JBoolean):
        ...

    @property
    def emphasis(self) -> jpype.JDouble:
        ...

    @emphasis.setter
    def emphasis(self, value: jpype.JDouble):
        ...

    @property
    def location(self) -> java.awt.geom.Point2D:
        ...

    @location.setter
    def location(self, value: java.awt.geom.Point2D):
        ...

    @property
    def hovered(self) -> jpype.JBoolean:
        ...

    @hovered.setter
    def hovered(self, value: jpype.JBoolean):
        ...

    @property
    def selected(self) -> jpype.JBoolean:
        ...

    @selected.setter
    def selected(self, value: jpype.JBoolean):
        ...


class GraphViewerUtils(java.lang.Object):
    """
    This class houses various methods for translating location and size data from the various
    graph coordinate spaces.
     
     
    .. _graph_spaces:
    
    Graph Spaces
    Size and location information is represented in multiple coordinate spaces, as listed below.
    To translate from one to the other, use :obj:`GraphViewerUtils`; for example, to see if a 
    mouse click is on a given vertex.
     
     
    * Layout Space - the layout contains Point2D objects that represent positions of the
    vertices.
    * Graph Space - the space where the Layout points are transformed as the view is moved 
    around the screen (e.g., as the user pans)
    * View Space - the coordinate system of Java 2D rendering; scaling (zooming) transformations
    are applied at this layer
    
     
     
    Note: vertex relative means that the value is from inside the vertex, or the vertex's
        coordinate space (like a component that is inside the vertex), where it's 
        coordinate values are relative to the component's parent.
    """

    class_: typing.ClassVar[java.lang.Class]
    GRAPH_DECORATOR_THREAD_POOL_NAME: typing.Final = "Graph Decorator"
    GRAPH_BUILDER_THREAD_POOL_NAME: typing.Final = "Graph Builder"
    INTERACTION_ZOOM_THRESHOLD: typing.Final = 0.2
    PAINT_ZOOM_THRESHOLD: typing.Final = 0.1
    EDGE_ROW_SPACING: typing.Final = 25
    EDGE_COLUMN_SPACING: typing.Final = 25
    EXTRA_LAYOUT_ROW_SPACING: typing.Final = 50
    EXTRA_LAYOUT_ROW_SPACING_CONDENSED: typing.Final = 25
    EXTRA_LAYOUT_COLUMN_SPACING: typing.Final = 50
    EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED: typing.Final = 10

    def __init__(self):
        ...

    @staticmethod
    def addPaddingToRectangle(padding: typing.Union[jpype.JInt, int], rectangle: java.awt.Rectangle):
        ...

    @staticmethod
    def adjustEdgePickSizeForZoom(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]):
        ...

    @staticmethod
    def convertMouseEventToVertexMouseEvent(viewer: GraphViewer[V, E], mouseEvent: java.awt.event.MouseEvent) -> ghidra.graph.viewer.event.mouse.VertexMouseInfo[V, E]:
        ...

    @staticmethod
    def createCollectionWithZOrderBySelection(vertices: collections.abc.Sequence) -> java.util.List[V]:
        """
        Moves the selected vertices to the end of the list of vertices so that when picked (or 
        painted), we will prefer the selected vertices, since we have configured the algorithms for
        the graph stuff to prefer the last accessed vertex (like when picking and painting).
        
        :param collections.abc.Sequence vertices: the vertices to order
        :return: the given vertices, ordered by selected/emphasized state
        :rtype: java.util.List[V]
        """

    @staticmethod
    @typing.overload
    def createEgdeLoopInGraphSpace(vertexShape: java.awt.Shape, x: typing.Union[jpype.JDouble, float], y: typing.Union[jpype.JDouble, float]) -> java.awt.Shape:
        """
        Creates a loop shape for a vertex that calls itself.  The loop is transformed to graph space,
        which includes updating the size and location of the loop to be relative to
        the vertex.
        
        :param java.awt.Shape vertexShape: The shape of the vertex for which the edge is being created.
        :param jpype.JDouble or float x: The x coordinate of the vertex
        :param jpype.JDouble or float y: The y coordinate of the vertex
        :return: a loop shape for a vertex that calls itself.
        :rtype: java.awt.Shape
        """

    @staticmethod
    @typing.overload
    def createEgdeLoopInGraphSpace(edgeLoopShape: java.awt.Shape, vertexShape: java.awt.Shape, x: typing.Union[jpype.JDouble, float], y: typing.Union[jpype.JDouble, float]) -> java.awt.Shape:
        """
        Transforms the given edge loop shape to graph space, which includes updating
        the size and location of the loop to be relative to the vertex.
        
        :param java.awt.Shape edgeLoopShape: The shape to transform
        :param java.awt.Shape vertexShape: The shape of the vertex for which the edge is being created
        :param jpype.JDouble or float x: The x coordinate of the vertex
        :param jpype.JDouble or float y: The y coordinate of the vertex
        :return: the transformed edge loop shape
        :rtype: java.awt.Shape
        """

    @staticmethod
    def createHollowEgdeLoop() -> java.awt.Shape:
        ...

    @staticmethod
    def createHollowEgdeLoopInGraphSpace(vertexShape: java.awt.Shape, x: typing.Union[jpype.JDouble, float], y: typing.Union[jpype.JDouble, float]) -> java.awt.Shape:
        """
        Creates a self-loop edge to be used with a vertex that calls itself.  The returned shape
        is hollow (not a filled loop) so that mouse hit detection does not occur in the middle of
        the circle.
        
        :param java.awt.Shape vertexShape: The shape of the vertex for which the edge is being created.
        :param jpype.JDouble or float x: The x coordinate of the vertex
        :param jpype.JDouble or float y: The y coordinate of the vertex
        :return: a self-loop edge to be used with a vertex that calls itself.
        :rtype: java.awt.Shape
        """

    @staticmethod
    @typing.overload
    def getBoundsForVerticesInLayoutSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertices: collections.abc.Sequence) -> java.awt.Rectangle:
        """
        Returns a rectangle that contains all give vertices
        
        :param edu.uci.ics.jung.visualization.VisualizationServer[V, E] viewer: the viewer containing the UI
        :param collections.abc.Sequence vertices: the vertices
        :return: a rectangle that contains all give vertices
        :rtype: java.awt.Rectangle
        """

    @staticmethod
    @typing.overload
    def getBoundsForVerticesInLayoutSpace(vertices: collections.abc.Sequence, vertexToBounds: com.google.common.base.Function[V, java.awt.Rectangle]) -> java.awt.Rectangle:
        """
        Returns a rectangle that contains all vertices, in the layout space
        
        :param collections.abc.Sequence vertices: the vertices for which to calculate the bounds
        :param com.google.common.base.Function[V, java.awt.Rectangle] vertexToBounds: a function that can turn a single vertex into a rectangle
        :return: the bounds
        :rtype: java.awt.Rectangle
        """

    @staticmethod
    def getEdgeFromPointInViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], point: java.awt.Point) -> E:
        ...

    @staticmethod
    def getEdgeShapeInGraphSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], e: E) -> java.awt.Shape:
        ...

    @staticmethod
    def getGraphCenterInLayoutSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Point:
        ...

    @staticmethod
    def getGraphScale(vv: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> float:
        ...

    @staticmethod
    def getOffsetFromCenterForPointInViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], point: java.awt.geom.Point2D) -> java.awt.geom.Point2D.Double:
        ...

    @staticmethod
    def getOffsetFromCenterInLayoutSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], pointInLayoutSpace: java.awt.Point) -> java.awt.geom.Point2D.Double:
        ...

    @staticmethod
    def getPointInViewSpaceForVertex(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.Point:
        """
        Get the upper-left point of vertex in the view space (Java component space)
        
        :param edu.uci.ics.jung.visualization.VisualizationServer[V, E] viewer: the viewer containing the UI
        :param V vertex: the vertex
        :return: the upper-left point of the vertex
        :rtype: java.awt.Point
        """

    @staticmethod
    def getScaleRatioToFitInDimension(currentSize: java.awt.Dimension, targetSize: java.awt.Dimension) -> float:
        ...

    @staticmethod
    @typing.overload
    def getTotalGraphSizeInLayoutSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Rectangle:
        ...

    @staticmethod
    @typing.overload
    def getTotalGraphSizeInLayoutSpace(vertices: collections.abc.Sequence, edges: collections.abc.Sequence, vertexToBounds: com.google.common.base.Function[V, java.awt.Rectangle], edgeToArticulations: com.google.common.base.Function[E, java.util.List[java.awt.geom.Point2D]]) -> java.awt.Rectangle:
        ...

    @staticmethod
    def getVertexBoundsInGraphSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.Rectangle:
        ...

    @staticmethod
    def getVertexBoundsInLayoutSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.Rectangle:
        ...

    @staticmethod
    def getVertexBoundsInViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.Rectangle:
        ...

    @staticmethod
    def getVertexCenterPointInViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], v: V) -> java.awt.geom.Point2D:
        ...

    @staticmethod
    def getVertexFromPointInViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], point: java.awt.Point) -> V:
        ...

    @staticmethod
    def getVertexOffsetFromLayoutCenter(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.geom.Point2D.Double:
        ...

    @staticmethod
    def getVertexOffsetFromLayoutCenterTop(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.geom.Point2D.Double:
        ...

    @staticmethod
    def getVertexUpperLeftCornerInGraphSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.Point:
        ...

    @staticmethod
    def getVertexUpperLeftCornerInLayoutSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.Point:
        ...

    @staticmethod
    def getVertexUpperLeftCornerInViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V) -> java.awt.Point:
        ...

    @staticmethod
    def getVerticesOfHoveredEdges(graph: edu.uci.ics.jung.graph.Graph[V, E]) -> java.util.Collection[V]:
        ...

    @staticmethod
    def getVerticesOfSelectedEdges(graph: edu.uci.ics.jung.graph.Graph[V, E]) -> java.util.Collection[V]:
        """
        Returns a collection of vertices that are incident to selected edges.
        
        :param edu.uci.ics.jung.graph.Graph[V, E] graph: the graph from which to retrieve vertices
        :return: a collection of vertices that are incident to selected edges.
        :rtype: java.util.Collection[V]
        """

    @staticmethod
    def getVisualGraphLayout(graphLayout: edu.uci.ics.jung.algorithms.layout.Layout[V, E]) -> ghidra.graph.viewer.layout.VisualGraphLayout[V, E]:
        ...

    @staticmethod
    def isScaledPastVertexInteractionThreshold(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> bool:
        ...

    @staticmethod
    def layoutUsesEdgeArticulations(graphLayout: edu.uci.ics.jung.algorithms.layout.Layout[V, E]) -> bool:
        ...

    @staticmethod
    def setGraphScale(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], scale: typing.Union[jpype.JDouble, float]):
        ...

    @staticmethod
    def translatePointFromGraphSpaceToLayoutSpace(pointInGraphSpace: java.awt.geom.Point2D, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Point:
        ...

    @staticmethod
    def translatePointFromGraphSpaceToViewSpace(pointInGraphSpace: java.awt.geom.Point2D, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Point:
        ...

    @staticmethod
    def translatePointFromLayoutSpaceToGraphSpace(pointInLayoutSpace: java.awt.geom.Point2D, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Point:
        ...

    @staticmethod
    def translatePointFromLayoutSpaceToViewSpace(pointInLayoutSpace: java.awt.geom.Point2D, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Point:
        ...

    @staticmethod
    def translatePointFromVertexRelativeSpaceToViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V, startPoint: java.awt.Point) -> java.awt.Point:
        ...

    @staticmethod
    def translatePointFromViewSpaceToGraphSpace(pointInViewSpace: java.awt.geom.Point2D, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Point:
        ...

    @staticmethod
    def translatePointFromViewSpaceToLayoutSpace(pointInViewSpace: java.awt.geom.Point2D, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Point:
        ...

    @staticmethod
    @typing.overload
    def translatePointFromViewSpaceToVertexRelativeSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], startPoint: java.awt.Point) -> java.awt.Point:
        ...

    @staticmethod
    @typing.overload
    def translatePointFromViewSpaceToVertexRelativeSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], startPoint: java.awt.Point, vertex: V) -> java.awt.Point:
        ...

    @staticmethod
    def translateRectangleFromLayoutSpaceToViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], rectangle: java.awt.Rectangle) -> java.awt.Rectangle:
        ...

    @staticmethod
    def translateRectangleFromVertexRelativeSpaceToViewSpace(viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V, rectangle: java.awt.Rectangle) -> java.awt.Rectangle:
        ...

    @staticmethod
    def translateShapeFromLayoutSpaceToGraphSpace(shape: java.awt.Shape, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Shape:
        ...

    @staticmethod
    def translateShapeFromLayoutSpaceToViewSpace(shape: java.awt.Shape, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Shape:
        ...

    @staticmethod
    def translateShapeFromViewSpaceToLayoutSpace(shape: java.awt.Shape, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]) -> java.awt.Shape:
        ...


class GraphComponent(java.lang.Object, typing.Generic[V, E, G]):
    """
    A component that contains primary and satellite graph views.  This viewer provides
    methods for manipulating the graph using the mouse.
    
     
    To gain the full functionality offered by this class, clients will need to subclass
    this class and override :meth:`createPrimaryGraphViewer(VisualGraphLayout, Dimension) <.createPrimaryGraphViewer>`
    and :meth:`createSatelliteGraphViewer(GraphViewer, Dimension) <.createSatelliteGraphViewer>` as needed.   This allows
    them to customize renderers and other viewer attributes.  To use the subclass, see the
    :obj:`VisualGraphView` and its ``installGraphViewer()`` method.
    
    
    .. seealso::
    
        | :obj:`GraphViewer`
    """

    class SatellitePosition(java.lang.Enum[GraphComponent.SatellitePosition]):

        class_: typing.ClassVar[java.lang.Class]
        UPPER_LEFT: typing.Final[GraphComponent.SatellitePosition]
        UPPER_RIGHT: typing.Final[GraphComponent.SatellitePosition]
        LOWER_LEFT: typing.Final[GraphComponent.SatellitePosition]
        LOWER_RIGHT: typing.Final[GraphComponent.SatellitePosition]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GraphComponent.SatellitePosition:
            ...

        @staticmethod
        def values() -> jpype.JArray[GraphComponent.SatellitePosition]:
            ...


    @typing.type_check_only
    class PrimaryLayoutListener(ghidra.graph.viewer.layout.LayoutListener[V, E]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MessagePaintable(edu.uci.ics.jung.visualization.VisualizationServer.Paintable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyForwardingKeyAdapter(java.awt.event.KeyAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, g: ghidra.graph.VisualGraph[V, E], viewer: edu.uci.ics.jung.visualization.VisualizationViewer[V, E]):
            ...


    @typing.type_check_only
    class VertexPickingListener(ghidra.graph.viewer.event.picking.PickListener[V]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, g: ghidra.graph.VisualGraph[V, E]):
            ...


    @typing.type_check_only
    class EdgePickingListener(java.awt.event.ItemListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GraphChangeListener(ghidra.graph.event.VisualGraphChangeListener[V, E]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VertexClickMousePlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseListener, ghidra.graph.viewer.event.mouse.VisualGraphMousePlugin[V, E]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graph: G):
        ...

    def dispose(self):
        ...

    def getComponent(self) -> javax.swing.JComponent:
        ...

    def getGraph(self) -> G:
        ...

    def getGraphOptions(self) -> ghidra.graph.viewer.options.VisualGraphOptions:
        ...

    def getPathHighlighter(self) -> ghidra.graph.viewer.edge.VisualGraphPathHighlighter[V, E]:
        ...

    def getPrimaryViewer(self) -> GraphViewer[V, E]:
        ...

    def getRenderContext(self) -> edu.uci.ics.jung.visualization.RenderContext[V, E]:
        ...

    def getSatelliteBounds(self) -> java.awt.Rectangle:
        """
        Returns an empty rectangle if the satellite is not visible
        
        :return: the bounds
        :rtype: java.awt.Rectangle
        """

    def getSatellitePosition(self) -> GraphComponent.SatellitePosition:
        ...

    def getSatelliteViewer(self) -> SatelliteGraphViewer[V, E]:
        ...

    def getVertexFocusPathHighlightMode(self) -> PathHighlightMode:
        ...

    def getVertexHoverPathHighlightMode(self) -> PathHighlightMode:
        ...

    def getViewUpdater(self) -> VisualGraphViewUpdater[V, E]:
        ...

    def isGraphViewStale(self) -> bool:
        ...

    def isSatelliteComponent(self, c: java.awt.Component) -> bool:
        ...

    def isSatelliteDocked(self) -> bool:
        ...

    def isSatelliteShowing(self) -> bool:
        ...

    def isSatelliteUnDocked(self) -> bool:
        ...

    def isUninitialized(self) -> bool:
        ...

    def optionsChanged(self):
        ...

    def repaint(self):
        ...

    def setGraphOptions(self, options: ghidra.graph.viewer.options.VisualGraphOptions):
        ...

    def setGraphPerspective(self, info: GraphPerspectiveInfo[V, E]):
        ...

    def setGraphViewStale(self, isStale: typing.Union[jpype.JBoolean, bool]):
        ...

    def setPopupsVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSatelliteDocked(self, docked: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSatellitePosition(self, position: GraphComponent.SatellitePosition):
        ...

    def setSatelliteVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    def setStatusMessage(self, message: typing.Union[java.lang.String, str]):
        """
        Sets a message to be painted on the viewer.  This is useful to show a text message to the
        user.  Passing null will clear the message.
        
        :param java.lang.String or str message: the message
        """

    def setVertexClickListener(self, l: ghidra.graph.viewer.vertex.VertexClickListener[V, E]):
        ...

    def setVertexFocusListener(self, l: ghidra.graph.viewer.vertex.VertexFocusListener[V]):
        ...

    def setVertexFocusPathHighlightMode(self, mode: PathHighlightMode):
        ...

    def setVertexFocused(self, vertex: V):
        """
        Sets the given vertex to be the focused vertex.  This will be the only focused vertex.
        
        :param V vertex: the vertex
        """

    def setVertexHoverPathHighlightMode(self, mode: PathHighlightMode):
        ...

    def setVerticesSelected(self, vertices: collections.abc.Sequence):
        ...

    def twinkleVertex(self, twinkleVertex: V):
        ...

    @property
    def satelliteViewer(self) -> SatelliteGraphViewer[V, E]:
        ...

    @property
    def graphViewStale(self) -> jpype.JBoolean:
        ...

    @graphViewStale.setter
    def graphViewStale(self, value: jpype.JBoolean):
        ...

    @property
    def primaryViewer(self) -> GraphViewer[V, E]:
        ...

    @property
    def pathHighlighter(self) -> ghidra.graph.viewer.edge.VisualGraphPathHighlighter[V, E]:
        ...

    @property
    def viewUpdater(self) -> VisualGraphViewUpdater[V, E]:
        ...

    @property
    def vertexFocusPathHighlightMode(self) -> PathHighlightMode:
        ...

    @vertexFocusPathHighlightMode.setter
    def vertexFocusPathHighlightMode(self, value: PathHighlightMode):
        ...

    @property
    def satelliteComponent(self) -> jpype.JBoolean:
        ...

    @property
    def uninitialized(self) -> jpype.JBoolean:
        ...

    @property
    def renderContext(self) -> edu.uci.ics.jung.visualization.RenderContext[V, E]:
        ...

    @property
    def vertexHoverPathHighlightMode(self) -> PathHighlightMode:
        ...

    @vertexHoverPathHighlightMode.setter
    def vertexHoverPathHighlightMode(self, value: PathHighlightMode):
        ...

    @property
    def satelliteDocked(self) -> jpype.JBoolean:
        ...

    @satelliteDocked.setter
    def satelliteDocked(self, value: jpype.JBoolean):
        ...

    @property
    def graph(self) -> G:
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def satelliteUnDocked(self) -> jpype.JBoolean:
        ...

    @property
    def satelliteBounds(self) -> java.awt.Rectangle:
        ...

    @property
    def satelliteShowing(self) -> jpype.JBoolean:
        ...

    @property
    def satellitePosition(self) -> GraphComponent.SatellitePosition:
        ...

    @satellitePosition.setter
    def satellitePosition(self, value: GraphComponent.SatellitePosition):
        ...

    @property
    def graphOptions(self) -> ghidra.graph.viewer.options.VisualGraphOptions:
        ...

    @graphOptions.setter
    def graphOptions(self, value: ghidra.graph.viewer.options.VisualGraphOptions):
        ...



__all__ = ["GraphViewer", "VisualGraphViewUpdater", "VisualGraphLayeredPaneButton", "SatelliteGraphViewer", "VisualGraphView", "PathHighlightMode", "GraphPerspectiveInfo", "VisualEdge", "VisualGraphScalingControl", "GraphSatelliteListener", "VisualVertex", "GraphViewerUtils", "GraphComponent"]
