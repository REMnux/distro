from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import edu.uci.ics.jung.visualization # type: ignore
import edu.uci.ics.jung.visualization.control # type: ignore
import ghidra.graph.viewer
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.awt.geom # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class VisualGraphSatelliteNavigationGraphMousePlugin(VisualGraphSatelliteAbstractGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphSatelliteAbstractGraphMousePlugin(VisualGraphAbstractGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, selectionModifiers: typing.Union[jpype.JInt, int]):
        ...


class VisualGraphMousePlugin(java.lang.Object, typing.Generic[V, E]):
    """
    An interface to provide a common set of methods for classes that could not otherwise 
    extend an abstract class.  This interface signals that the implementer is a :obj:`VisualGraph`
    mouse plugin.
     
     
    Note: The implementors of this interface still use the deprecated 
    :meth:`MouseEvent.getModifiers() <MouseEvent.getModifiers>` method, since many of those classes extends from 
    3rd-party classes that still use them, such as :obj:`PickingGraphMousePlugin`.   We will need
    to update the library (if/when possible), or rewrite our code so that it does not use the 
    old 3rd-party algorithms.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Signals to perform any cleanup when this plugin is going away
        """

    def getGraphViewer(self, e: java.awt.event.MouseEvent) -> ghidra.graph.viewer.GraphViewer[V, E]:
        """
        Returns the **primary/master** graph viewer.
        
        :param java.awt.event.MouseEvent e: the mouse event from which to get the viewer
        :return: the viewer
        :rtype: ghidra.graph.viewer.GraphViewer[V, E]
        """

    def getSatelliteGraphViewer(self, e: java.awt.event.MouseEvent) -> ghidra.graph.viewer.SatelliteGraphViewer[V, E]:
        """
        Returns the satellite graph viewer.  This assumes that the mouse event originated from 
        the satellite viewer.
        
        :param java.awt.event.MouseEvent e: the mouse event from which to get the viewer
        :return: the viewer
        :rtype: ghidra.graph.viewer.SatelliteGraphViewer[V, E]
        """

    @typing.overload
    def getViewUpdater(self, e: java.awt.event.MouseEvent) -> ghidra.graph.viewer.VisualGraphViewUpdater[V, E]:
        """
        Returns the updater that is used to modify the primary graph viewer.
        
        :param java.awt.event.MouseEvent e: the mouse event from which to get the viewer
        :return: the updater
        :rtype: ghidra.graph.viewer.VisualGraphViewUpdater[V, E]
        """

    @typing.overload
    def getViewUpdater(self, viewer: ghidra.graph.viewer.GraphViewer[V, E]) -> ghidra.graph.viewer.VisualGraphViewUpdater[V, E]:
        """
        Returns the updater that is used to modify the primary graph viewer.
        
        :param ghidra.graph.viewer.GraphViewer[V, E] viewer: the viewer
        :return: the updater
        :rtype: ghidra.graph.viewer.VisualGraphViewUpdater[V, E]
        """

    def getViewer(self, e: java.awt.event.MouseEvent) -> edu.uci.ics.jung.visualization.VisualizationViewer[V, E]:
        ...

    @property
    def viewUpdater(self) -> ghidra.graph.viewer.VisualGraphViewUpdater[V, E]:
        ...

    @property
    def viewer(self) -> edu.uci.ics.jung.visualization.VisualizationViewer[V, E]:
        ...

    @property
    def satelliteGraphViewer(self) -> ghidra.graph.viewer.SatelliteGraphViewer[V, E]:
        ...

    @property
    def graphViewer(self) -> ghidra.graph.viewer.GraphViewer[V, E]:
        ...


class VisualGraphScreenPositioningPlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseWheelListener, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VertexTooltipProvider(java.lang.Object, typing.Generic[V, E]):
    """
    Creates tooltips for a given vertex.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getTooltip(self, v: V) -> javax.swing.JComponent:
        """
        Returns a tooltip component for the given vertex
         
         
        This is used when the vertex is scaled too far for the user to see individual 
        vertex subcomponents.
        
        :param V v: the vertex
        :return: a tooltip component
        :rtype: javax.swing.JComponent
        """

    @typing.overload
    def getTooltip(self, v: V, e: E) -> javax.swing.JComponent:
        """
        Returns a tooltip component for the given vertex and edge.  This is used to create
        an edge tooltip, allowing for vertex data to appear in the tip.
        
        :param V v: the vertex
        :param E e: the edge for
        :return: a tooltip component
        :rtype: javax.swing.JComponent
        """

    def getTooltipText(self, v: V, e: java.awt.event.MouseEvent) -> str:
        """
        Returns a tooltip string for the given vertex and mouse event
        
        :param V v: the vertex
        :param java.awt.event.MouseEvent e: the mouse event
        :return: the tooltip text
        :rtype: str
        """

    @property
    def tooltip(self) -> javax.swing.JComponent:
        ...


class VisualGraphTranslatingGraphMousePlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseListener, java.awt.event.MouseMotionListener, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):
    """
    Note: this class is based on :obj:`TranslatingGraphMousePlugin`.
     
    
    TranslatingGraphMousePlugin uses a MouseButtonOne press and drag gesture to translate 
    the graph display in the x and y direction. The default MouseButtonOne modifier can be overridden
    to cause a different mouse gesture to translate the display.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, modifiers: typing.Union[jpype.JInt, int]):
        ...


class VisualGraphAbstractGraphMousePlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseListener, java.awt.event.MouseMotionListener, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):
    """
    Usage Notes:
     
    * We clear state on mouseReleased() and mouseExited(), since we will get 
    at least one of those calls
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, selectionModifiers: typing.Union[jpype.JInt, int]):
        ...


class VisualGraphSatelliteGraphMouse(VisualGraphPluggableGraphMouse[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphHoverMousePlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseMotionListener, java.awt.event.MouseListener, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):
    """
    A mouse plugin to handle vertex hovers, to include animating paths in the graph, based 
    upon the current :obj:`PathHighlightMode`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graphComponent: ghidra.graph.viewer.GraphComponent[V, E, typing.Any], viewer: edu.uci.ics.jung.visualization.VisualizationViewer[V, E], otherViewer: edu.uci.ics.jung.visualization.VisualizationViewer[V, E]):
        ...


class VisualGraphPickingGraphMousePlugin(JungPickingGraphMousePlugin[V, E], VisualGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphSatelliteTranslatingGraphMousePlugin(VisualGraphSatelliteAbstractGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphMouseTrackingGraphMousePlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseListener, java.awt.event.MouseMotionListener, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):
    """
    A simple plugin that allows clients to be notified of mouse events before any of the other
    mouse plugins.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: ghidra.graph.viewer.GraphViewer[V, E]):
        ...


class VisualGraphZoomingPickingGraphMousePlugin(VisualGraphAbstractGraphMousePlugin[V, E], typing.Generic[V, E]):
    """
    A handler to zoom nodes when double-clicked.  If the vertex is zoomed out, then we will zoom
    in and center.  If the vertex is zoomed to full size, then we will zoom out and center.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphCursorRestoringGraphMousePlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseMotionListener, typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VertexMouseInfo(java.lang.Object, typing.Generic[V, E]):
    """
    A class that knows how and where a given vertex was clicked.  Further, this class knows how 
    to get clicked components within a given vertex.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, originalMouseEvent: java.awt.event.MouseEvent, vertex: V, vertexBasedClickPoint: java.awt.geom.Point2D, viewer: ghidra.graph.viewer.GraphViewer[V, E]):
        ...

    def forwardEvent(self):
        ...

    def getClickedComponent(self) -> java.awt.Component:
        ...

    def getCursorForClickedComponent(self) -> java.awt.Cursor:
        ...

    def getDeepestComponentBasedClickPoint(self) -> java.awt.Point:
        ...

    def getEventSource(self) -> java.lang.Object:
        ...

    def getOriginalMouseEvent(self) -> java.awt.event.MouseEvent:
        ...

    def getTranslatedMouseEvent(self) -> java.awt.event.MouseEvent:
        ...

    def getVertex(self) -> V:
        ...

    def getViewer(self) -> ghidra.graph.viewer.GraphViewer[V, E]:
        ...

    def isButtonClick(self) -> bool:
        ...

    def isGrabArea(self) -> bool:
        ...

    def isPopupClick(self) -> bool:
        ...

    def isScaledPastInteractionThreshold(self) -> bool:
        ...

    def isVertexSelected(self) -> bool:
        ...

    def selectVertex(self, addToSelection: typing.Union[jpype.JBoolean, bool]):
        """
        Selects, or 'pick's the given vertex.
        
        :param jpype.JBoolean or bool addToSelection: true signals to add the given vertex to the set of selected vertices;
                            false signals to clear the existing selected vertices before selecting
                            the given vertex
        """

    def setClickedComponent(self, clickedComponent: java.awt.Component, vertexBasedPoint: java.awt.geom.Point2D):
        """
        You can use this method to override which Java component will get the forwarded event.  By
        default, the mouse info will forward the event to the component that is under the point in
        the event.
        
        :param java.awt.Component clickedComponent: the component that was clicked
        :param java.awt.geom.Point2D vertexBasedPoint: the point, relative to the vertex's coordinates
        """

    def simulateMouseEnteredEvent(self):
        ...

    def simulateMouseExitedEvent(self):
        ...

    @property
    def grabArea(self) -> jpype.JBoolean:
        ...

    @property
    def viewer(self) -> ghidra.graph.viewer.GraphViewer[V, E]:
        ...

    @property
    def translatedMouseEvent(self) -> java.awt.event.MouseEvent:
        ...

    @property
    def originalMouseEvent(self) -> java.awt.event.MouseEvent:
        ...

    @property
    def cursorForClickedComponent(self) -> java.awt.Cursor:
        ...

    @property
    def vertex(self) -> V:
        ...

    @property
    def buttonClick(self) -> jpype.JBoolean:
        ...

    @property
    def scaledPastInteractionThreshold(self) -> jpype.JBoolean:
        ...

    @property
    def popupClick(self) -> jpype.JBoolean:
        ...

    @property
    def vertexSelected(self) -> jpype.JBoolean:
        ...

    @property
    def eventSource(self) -> java.lang.Object:
        ...

    @property
    def deepestComponentBasedClickPoint(self) -> java.awt.Point:
        ...

    @property
    def clickedComponent(self) -> java.awt.Component:
        ...


class VisualGraphScalingGraphMousePlugin(edu.uci.ics.jung.visualization.control.ScalingGraphMousePlugin, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):
    """
    Overridden implementation that allows us to change scaling behavior through options.  This 
    class works on the opposite modifier setup as FunctionGraphScrollWheelPanningPlugin.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphPluggableGraphMouse(edu.uci.ics.jung.visualization.VisualizationViewer.GraphMouse, typing.Generic[V, E]):
    """
    This is the class that controls which mouse plugins get installed into the graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, p: edu.uci.ics.jung.visualization.control.GraphMousePlugin):
        ...

    def dispose(self):
        ...

    def prepend(self, p: edu.uci.ics.jung.visualization.control.GraphMousePlugin):
        """
        Places the given plugin at the front of the list
        
        :param edu.uci.ics.jung.visualization.control.GraphMousePlugin p: the mouse plugin to prepend
        """

    def remove(self, p: edu.uci.ics.jung.visualization.control.GraphMousePlugin):
        ...


class JungPickingGraphMousePlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseListener, java.awt.event.MouseMotionListener, typing.Generic[V, E]):
    """
    PickingGraphMousePlugin supports the picking of graph elements
    with the mouse. MouseButtonOne picks a single vertex
    or edge, and MouseButtonTwo adds to the set of selected Vertices
    or EdgeType. If a Vertex is selected and the mouse is dragged while
    on the selected Vertex, then that Vertex will be repositioned to
    follow the mouse until the button is released.
    
    
    .. codeauthor:: Tom Nelson
     
     
    Note: this class was copied completely from Jung 2.   Minimal changes were applied to get
    correct mouse behavior by using :meth:`MouseEvent.getModifiersEx() <MouseEvent.getModifiersEx>`.
    """

    @typing.type_check_only
    class LensPaintable(edu.uci.ics.jung.visualization.VisualizationServer.Paintable):
        """
        a Paintable to draw the rectangle used to pick multiple
        Vertices
        
        
        .. codeauthor:: Tom Nelson
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        create an instance with default settings
        """

    @typing.overload
    def __init__(self, selectionModifiers: typing.Union[jpype.JInt, int], addToSelectionModifiers: typing.Union[jpype.JInt, int]):
        """
        create an instance with overrides
        
        :param jpype.JInt or int selectionModifiers: for primary selection
        :param jpype.JInt or int addToSelectionModifiers: for additional selection
        """

    def getLensColor(self) -> java.awt.Color:
        """
        
        
        :return: Returns the lensColor.
        :rtype: java.awt.Color
        """

    def isLocked(self) -> bool:
        """
        
        
        :return: Returns the locked.
        :rtype: bool
        """

    def mouseDragged(self, e: java.awt.event.MouseEvent):
        """
        If the mouse is over a picked vertex, drag all picked
        vertices with the mouse.
        If the mouse is not over a Vertex, draw the rectangle
        to select multiple Vertices
        """

    def mousePressed(self, e: java.awt.event.MouseEvent):
        """
        For primary modifiers (default, MouseButton1):
        pick a single Vertex or Edge that
        is under the mouse pointer. If no Vertex or edge is under
        the pointer, unselect all picked Vertices and edges, and
        set up to draw a rectangle for multiple selection
        of contained Vertices.
        For additional selection (default Shift+MouseButton1):
        Add to the selection, a single Vertex or Edge that is
        under the mouse pointer. If a previously picked Vertex
        or Edge is under the pointer, it is un-picked.
        If no vertex or Edge is under the pointer, set up
        to draw a multiple selection rectangle (as above)
        but do not unpick previously picked elements.
        
        :param java.awt.event.MouseEvent e: the event
        """

    def mouseReleased(self, e: java.awt.event.MouseEvent):
        """
        If the mouse is dragging a rectangle, pick the
        Vertices contained in that rectangle
         
        clean up settings from mousePressed
        """

    def setLensColor(self, lensColor: java.awt.Color):
        """
        
        
        :param java.awt.Color lensColor: The lensColor to set.
        """

    def setLocked(self, locked: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        :param jpype.JBoolean or bool locked: The locked to set.
        """

    @property
    def lensColor(self) -> java.awt.Color:
        ...

    @lensColor.setter
    def lensColor(self, value: java.awt.Color):
        ...

    @property
    def locked(self) -> jpype.JBoolean:
        ...

    @locked.setter
    def locked(self, value: jpype.JBoolean):
        ...


class VisualGraphEventForwardingGraphMousePlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseListener, java.awt.event.MouseMotionListener, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, modifiers: typing.Union[jpype.JInt, int]):
        ...


class VisualGraphAnimatedPickingGraphMousePlugin(edu.uci.ics.jung.visualization.control.AnimatedPickingGraphMousePlugin[V, E], VisualGraphMousePlugin[V, E], typing.Generic[V, E]):
    """
    A mouse handler to center a vertex when the header is double-clicked
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphScrollWheelPanningPlugin(edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin, java.awt.event.MouseWheelListener, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphPopupMousePlugin(edu.uci.ics.jung.visualization.control.AbstractPopupGraphMousePlugin, typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphEdgeSelectionGraphMousePlugin(VisualGraphAbstractGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphSatelliteScalingGraphMousePlugin(edu.uci.ics.jung.visualization.control.SatelliteScalingGraphMousePlugin, VisualGraphMousePlugin[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["VisualGraphSatelliteNavigationGraphMousePlugin", "VisualGraphSatelliteAbstractGraphMousePlugin", "VisualGraphMousePlugin", "VisualGraphScreenPositioningPlugin", "VertexTooltipProvider", "VisualGraphTranslatingGraphMousePlugin", "VisualGraphAbstractGraphMousePlugin", "VisualGraphSatelliteGraphMouse", "VisualGraphHoverMousePlugin", "VisualGraphPickingGraphMousePlugin", "VisualGraphSatelliteTranslatingGraphMousePlugin", "VisualGraphMouseTrackingGraphMousePlugin", "VisualGraphZoomingPickingGraphMousePlugin", "VisualGraphCursorRestoringGraphMousePlugin", "VertexMouseInfo", "VisualGraphScalingGraphMousePlugin", "VisualGraphPluggableGraphMouse", "JungPickingGraphMousePlugin", "VisualGraphEventForwardingGraphMousePlugin", "VisualGraphAnimatedPickingGraphMousePlugin", "VisualGraphScrollWheelPanningPlugin", "VisualGraphPopupMousePlugin", "VisualGraphEdgeSelectionGraphMousePlugin", "VisualGraphSatelliteScalingGraphMousePlugin"]
