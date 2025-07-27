from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.google.common.base # type: ignore
import edu.uci.ics.jung.algorithms.layout # type: ignore
import edu.uci.ics.jung.graph # type: ignore
import edu.uci.ics.jung.visualization # type: ignore
import edu.uci.ics.jung.visualization.picking # type: ignore
import edu.uci.ics.jung.visualization.renderers # type: ignore
import ghidra.graph
import ghidra.graph.viewer
import ghidra.util.task
import java.awt # type: ignore
import java.awt.geom # type: ignore
import java.lang # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class AbstractVisualEdge(ghidra.graph.viewer.VisualEdge[V], typing.Generic[V]):
    """
    An implementation of :obj:`VisualEdge` that implements the base interface so subclasses 
    do not have to.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: V, end: V):
        ...


class PathHighlighterWorkPauser(java.lang.Object):
    """
    A simple boolean supplier that signals if path highlighting work should not take place
    """

    class_: typing.ClassVar[java.lang.Class]

    def isPaused(self) -> bool:
        """
        True if work should not happen; false for normal path highlighting operations
        
        :return: if work should not happen
        :rtype: bool
        """

    @property
    def paused(self) -> jpype.JBoolean:
        ...


class VisualGraphEdgeStrokeTransformer(com.google.common.base.Function[E, java.awt.Stroke], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pickedInfo: edu.uci.ics.jung.visualization.picking.PickedInfo[E], pickedStrokeSize: typing.Union[jpype.JInt, int]):
        ...


class VisualEdgeRenderer(edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer[V, E], typing.Generic[V, E]):
    """
    Edge render for the :obj:`VisualGraph` system
     
     
    ********************
    Implementation Notes
    ********************
    
     
     
    ==========================
    Jung Vertex/Edge Rendering
    ==========================
    
     
    Jung creates shapes for vertices (see :obj:`VertexShapeFactory`) that are centered.  They
    do this by getting the width/height of the shape and then creating an x/y value that is 
    half of the width and height, respectively.  This has the effect of the vertex appearing 
    centered over its connected edge.  We mimic that with our 
    :obj:`VisualGraphVertexShapeTransformer` so that our edge rendering code is similar to 
    Jung's.
     
    If we ever decide instead to not center our shapes, then this renderer would have to be
    updated to itself center the edge shape created herein, like this:
            Rectangle b1 = s1.getBounds();    Rectangle b2 = s2.getBounds();    // translate the edge to be centered in the vertex    int w1 = b1.width >> 1;    int h1 = b1.height >> 1;    int w2 = b2.width >> 1;    int h2 = b2.height >> 1;    float tx1 = x1 + w1;    float ty1 = y1 + h1;    float tx2 = x2 + w2;    float ty2 = y2 + h2;        Shape edgeShape = getEdgeShape(rc, graph, e, tx1, ty1, tx2, ty2, isLoop, xs1);
     
    Also, there are other spots in the system where we account for this center that would 
    have to be changed, such as the :obj:`AbstractVisualGraphLayout`, which needs the centering
    offsets to handle vertex clipping.
    
     
    When painting edges this renderer will paint colors based on the following states: default, 
    emphasized, hovered, focused and selected.   A focused edge is one that is part of the path 
    between focused vertices(such as when the vertex is hovered), whereas a selected edge is one 
    that has been selected by the user (see :obj:`VisualEdge` for details).   An edge is 
    'emphasized' when the user mouses over the edge (which is when the edge is hovered, not when the 
    vertex is hovered.  Each of these states may have a different color that can be changed by 
    calling the various setter methods on this renderer.  When painting, these colors are used along 
    with various different strokes to paint in an overlay fashion.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getDrawColor(self, g: edu.uci.ics.jung.graph.Graph[V, E], e: E) -> java.awt.Color:
        """
        Returns the current draw color.  This is also the color used to paint an 'emphasized' edge.
        
        :param edu.uci.ics.jung.graph.Graph[V, E] g: the graph
        :param E e: the edge
        :return: the color
        :rtype: java.awt.Color
        """

    def getEdgeShape(self, rc: edu.uci.ics.jung.visualization.RenderContext[V, E], graph: edu.uci.ics.jung.graph.Graph[V, E], e: E, x1: typing.Union[jpype.JFloat, float], y1: typing.Union[jpype.JFloat, float], x2: typing.Union[jpype.JFloat, float], y2: typing.Union[jpype.JFloat, float], isLoop: typing.Union[jpype.JBoolean, bool], vertexShape: java.awt.Shape) -> java.awt.Shape:
        """
        Returns the edge shape for the given points
        
        :param edu.uci.ics.jung.visualization.RenderContext[V, E] rc: the render context for the graph
        :param edu.uci.ics.jung.graph.Graph[V, E] graph: the graph
        :param E e: the edge to shape
        :param jpype.JFloat or float x1: the start vertex point x; layout space
        :param jpype.JFloat or float y1: the start vertex point y; layout space
        :param jpype.JFloat or float x2: the end vertex point x; layout space
        :param jpype.JFloat or float y2: the end vertex point y; layout space
        :param jpype.JBoolean or bool isLoop: true if the start == end, which is a self-loop
        :param java.awt.Shape vertexShape: the vertex shape (used in the case of a loop to draw a circle from the 
                shape to itself)
        :return: the edge shape
        :rtype: java.awt.Shape
        """

    def getFocusedColor(self, g: edu.uci.ics.jung.graph.Graph[V, E], e: E) -> java.awt.Color:
        """
        Returns the current color to use when the edge is focused.
        
        :param edu.uci.ics.jung.graph.Graph[V, E] g: the graph
        :param E e: the edge
        :return: the color
        :rtype: java.awt.Color
        """

    def getFullShape(self, rc: edu.uci.ics.jung.visualization.RenderContext[V, E], layout: edu.uci.ics.jung.algorithms.layout.Layout[V, E], vertex: V) -> java.awt.Shape:
        """
        Uses the render context to create a compact shape for the given vertex
        
        :param edu.uci.ics.jung.visualization.RenderContext[V, E] rc: the render context
        :param edu.uci.ics.jung.algorithms.layout.Layout[V, E] layout: the layout
        :param V vertex: the vertex
        :return: the vertex shape
        :rtype: java.awt.Shape
        
        .. seealso::
        
            | :obj:`VertexShapeProvider.getFullShape()`
        """

    def getHoveredColor(self, g: edu.uci.ics.jung.graph.Graph[V, E], e: E) -> java.awt.Color:
        """
        Returns the current color to use when the edge is in the hovered path.
        
        :param edu.uci.ics.jung.graph.Graph[V, E] g: the graph
        :param E e: the edge
        :return: the color
        :rtype: java.awt.Color
        """

    def getSelectedColor(self, g: edu.uci.ics.jung.graph.Graph[V, E], e: E) -> java.awt.Color:
        """
        Returns the current color to use when the edge is selected.
        
        :param edu.uci.ics.jung.graph.Graph[V, E] g: the graph
        :param E e: the edge
        :return: the color
        :rtype: java.awt.Color
        """

    def setDashingPatternOffset(self, dashingPatterOffset: typing.Union[jpype.JFloat, float]):
        """
        Sets the offset value for painting dashed lines.  This allows clients to animate the 
        lines being drawn for edges in the edge direction.
        
        :param jpype.JFloat or float dashingPatterOffset: the offset value
        """

    def setDrawColorTransformer(self, transformer: com.google.common.base.Function[E, java.awt.Color]):
        """
        Sets the color provider to use when drawing this edge.  This is also the color used to paint 
        an 'emphasized' edge.
        
        :param com.google.common.base.Function[E, java.awt.Color] transformer: the color provider
        """

    def setFocusedColorTransformer(self, transformer: com.google.common.base.Function[E, java.awt.Color]):
        """
        Sets the color provider to use when drawing this edge when the edge is focused.
        
        :param com.google.common.base.Function[E, java.awt.Color] transformer: the color provider
        """

    def setHoveredColorTransformer(self, transformer: com.google.common.base.Function[E, java.awt.Color]):
        """
        Sets the color provider to use when drawing this edge when the edge is in the hovered path.
        
        :param com.google.common.base.Function[E, java.awt.Color] transformer: the color provider
        """

    def setSelectedColorTransformer(self, transformer: com.google.common.base.Function[E, java.awt.Color]):
        """
        Sets the color provider to use when drawing this edge when the edge is selected.
        
        :param com.google.common.base.Function[E, java.awt.Color] transformer: the color provider
        """


class PathHighlightListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def pathHighlightChanged(self, hoverChange: typing.Union[jpype.JBoolean, bool]):
        """
        Called when the a path is highlighted.
        
        :param jpype.JBoolean or bool hoverChange: true if the change path is hover change; false if the changed path 
                is a selection change
        """


class VisualGraphEdgeSatelliteRenderer(VisualEdgeRenderer[V, E], typing.Generic[V, E]):
    """
    A renderer designed to override default edge rendering to NOT paint emphasizing effects.  We
    do this because space is limited in the satellite and because this rendering can take excess
    processing time.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: VisualEdgeRenderer[V, E]):
        ...


class BasicEdgeLabelRenderer(edu.uci.ics.jung.visualization.renderers.BasicEdgeLabelRenderer[V, E], typing.Generic[V, E]):
    """
    A class to override the default edge label placement.   This class is called a renderer because
    the parent class is.  However, it is not a renderer in the sense that it's job is to paint
    the contents, like in Java when you provide a cell rendering component, but rather, it uses
    such a component.  Further, the job of this class is to position said component and then to 
    have it paint its contents.
     
    
    Normally we would just set our custom renderer on the :obj:`RenderContext` at construction 
    time, like we do with the other rendering classes, but not such method is provided.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphPathHighlighter(java.lang.Object, typing.Generic[V, E]):
    """
    A class that calculates flow between vertices and then triggers that flow to be painted
    in the UI.
     
     
    **Threading Policy:**  Some operations use algorithms that slow down, depending
    upon the graph size.  Further, some of these algorithms may not even complete.  To keep the
    graph responsive, this class will perform its work *in the future*.   The work we 
    wish to do is further complicated by these requirements:
     
    * Some data should be calculated only as needed, to avoid excessive work
    * Many tasks depend on data to be calculated before they can perform their algorithm
    * Results must be cached for speed, but may cleared as the graph is mutated
    * Algorithms must not block the UI thread
    * Related actions (i.e., hover vs. selection) should cancel any pending action, but not 
    unrelated actions (e.g., a new hover request should cancel a pending hover update)
    
     
    Based on these requirements, we need to use multi-threading.  Further complicating the need
    for multi-threading is that some operations depending on lazy-loaded data.  Finally, we 
    have different types of actions, hovering vs. selecting a vertex, which should override 
    previous related requests.   To accomplish this we use:
     
    * :obj:`CompletableFuture` - to lazy-load and cache required algorithm data
    * :obj:`RunManager`s - to queue requests so that new requests cancel old ones.  A 
    different Run Manager is used for each type of request.
    
             
     
    **Naming Conventions:**  There are many methods in this class, called from 
    different threads.   For simplicity, we use the following conventions: 
     
    * fooAsync - methods ending in Async indicate that they are to be 
    called from a background thread.
    * fooSwing - methods ending in Swing indicate that they are to be 
    called from the Swing thread.
    * *All public methods are assumed to be called on the Swing thread
    """

    @typing.type_check_only
    class Circuits(java.lang.Object):
        """
        A simple class to hold loops and success status
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SetHoveredEdgesRunnable(ghidra.util.task.SwingRunnable):
        """
        A class to handle off-loading the calculation of edges to be hovered.   The results will
        then be used to update the UI.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SetFocusedEdgesRunnable(ghidra.util.task.SwingRunnable):
        """
        A class to handle off-loading the calculation of edges to be focused.  
        The results will then be used to update the UI.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SlowSetHoveredEdgesRunnable(ghidra.util.task.MonitoredRunnable):
        """
        A class meant to run in the hover RunManager that is slow or open-ended.  Work will
        be performed as long as possible, updating results along the way.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graph: ghidra.graph.VisualGraph[V, E], listener: PathHighlightListener):
        ...

    def clearEdgeCache(self):
        ...

    def dispose(self):
        ...

    def getVertexFocusPathHighlightMode(self) -> ghidra.graph.viewer.PathHighlightMode:
        ...

    def getVertexHoverPathHighlightMode(self) -> ghidra.graph.viewer.PathHighlightMode:
        ...

    def isBusy(self) -> bool:
        ...

    def setFocusedVertex(self, focusedVertex: V):
        ...

    def setHoveredVertex(self, hoveredVertex: V):
        ...

    def setVertexFocusMode(self, mode: ghidra.graph.viewer.PathHighlightMode):
        ...

    def setVertexHoverMode(self, mode: ghidra.graph.viewer.PathHighlightMode):
        ...

    def setWorkPauser(self, pauser: PathHighlighterWorkPauser):
        """
        Sets the callback that signals when this path highlighter should not be performing any
        work
        
        :param PathHighlighterWorkPauser pauser: the callback that returns a boolean of true when this class should pause
                its work.
        """

    def stop(self):
        """
        Signals to this path highlighter that it should stop all background jobs
        """

    @property
    def vertexHoverPathHighlightMode(self) -> ghidra.graph.viewer.PathHighlightMode:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def vertexFocusPathHighlightMode(self) -> ghidra.graph.viewer.PathHighlightMode:
        ...


class VisualEdgeArrowRenderingSupport(java.lang.Object, typing.Generic[V, E]):
    """
    Basic class to calculate the position of an edge arrow
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def createArrowTransform(self, rc: edu.uci.ics.jung.visualization.RenderContext[V, E], edgeShape: java.awt.Shape, vertexShape: java.awt.Shape) -> java.awt.geom.AffineTransform:
        ...



__all__ = ["AbstractVisualEdge", "PathHighlighterWorkPauser", "VisualGraphEdgeStrokeTransformer", "VisualEdgeRenderer", "PathHighlightListener", "VisualGraphEdgeSatelliteRenderer", "BasicEdgeLabelRenderer", "VisualGraphPathHighlighter", "VisualEdgeArrowRenderingSupport"]
