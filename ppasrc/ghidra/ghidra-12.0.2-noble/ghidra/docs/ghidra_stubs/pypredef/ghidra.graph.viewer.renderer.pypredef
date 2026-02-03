from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import edu.uci.ics.jung.algorithms.layout # type: ignore
import edu.uci.ics.jung.visualization # type: ignore
import edu.uci.ics.jung.visualization.renderers # type: ignore
import edu.uci.ics.jung.visualization.transform.shape # type: ignore
import ghidra.graph.viewer
import ghidra.graph.viewer.edge
import ghidra.graph.viewer.layout
import ghidra.graph.viewer.vertex
import java.awt # type: ignore
import java.lang # type: ignore
import java.util.concurrent.atomic # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class ArticulatedEdgeRenderer(ghidra.graph.viewer.edge.VisualEdgeRenderer[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VisualGraphRenderer(edu.uci.ics.jung.visualization.renderers.BasicRenderer[V, E], typing.Generic[V, E]):
    """
    This was created to add the ability to paint selected vertices above other vertices.  We need
    this since the Jung Graph has no notion of Z-order and thus does not let us specify that any
    particular vertex should be above another one.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, edgeLabelRenderer: edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel[V, E]):
        ...

    @staticmethod
    def setGridPainter(gridPainter: GridPainter):
        """
        Sets a painter to show an underlying grid. (To see a layout's associated grid, search
        for calls to this method and un-comment them)
        
        :param GridPainter gridPainter: A painter that paints the grid that a layout was based on.
        """


class VisualVertexSatelliteRenderer(ghidra.graph.viewer.vertex.AbstractVisualVertexRenderer[V, E], typing.Generic[V, E]):
    """
    A renderer for vertices for the satellite view.  This is really just a basic renderer
    that adds emphasis capability, as seen in the primary function graph renderer.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MouseClickedPaintableShape(PaintableShape):
    """
    A debugging shape painter that allows the user to see where a mouse clicked happened.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, p: java.awt.Point, tx: typing.Union[jpype.JDouble, float], ty: typing.Union[jpype.JDouble, float]):
        ...

    @typing.overload
    def __init__(self, p: java.awt.Point, tx: typing.Union[jpype.JDouble, float], ty: typing.Union[jpype.JDouble, float], color: java.awt.Color):
        ...


class MouseDebugPaintable(edu.uci.ics.jung.visualization.VisualizationServer.Paintable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addShape(self, shape: PaintableShape, graphViewer: ghidra.graph.viewer.GraphViewer[typing.Any, typing.Any]):
        ...

    def clear(self):
        ...


class VisualGraphEdgeLabelRenderer(edu.uci.ics.jung.visualization.renderers.DefaultEdgeLabelRenderer):
    """
    Overrides the :obj:`DefaultEdgeLabelRenderer` so that the client can set the non-picked
    foreground color.  See :meth:`setNonPickedForegroundColor(Color) <.setNonPickedForegroundColor>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pickedColor: java.awt.Color):
        ...

    def setNonPickedForegroundColor(self, color: java.awt.Color):
        """
        Sets the foreground color for this renderer when the edge is not picked/selected
        
        :param java.awt.Color color: the color
        """


class MouseDraggedPaintableShape(PaintableShape):
    """
    Paints a rectangle showing the start and end points of a drag.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: java.awt.Point, end: java.awt.Point, tx: typing.Union[jpype.JDouble, float], ty: typing.Union[jpype.JDouble, float]):
        ...

    def setPoints(self, start: java.awt.Point, end: java.awt.Point):
        ...


class MouseDraggedLinePaintableShape(PaintableShape):
    """
    Paints a line showing the start and end points of a drag operation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: java.awt.Point, end: java.awt.Point, tx: typing.Union[jpype.JDouble, float], ty: typing.Union[jpype.JDouble, float]):
        ...

    def addPoint(self, p: java.awt.Point):
        ...


class GridPainter(java.lang.Object):
    """
    Class for painting the underlying grid used to layout a graph. Used as a visual aid when 
    debugging grid based graph layouts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gridCoordinates: ghidra.graph.viewer.layout.GridCoordinates):
        ...

    def paintLayoutGridCells(self, renderContext: edu.uci.ics.jung.visualization.RenderContext[typing.Any, typing.Any], layout: edu.uci.ics.jung.algorithms.layout.Layout[typing.Any, typing.Any]):
        ...


class PaintableShape(java.lang.Object):
    """
    A base class for shapes that can be painted on the graph.  See :obj:`MouseDebugPaintable`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, s: java.awt.Shape):
        ...

    @typing.overload
    def __init__(self, s: java.awt.Shape, c: java.awt.Color):
        ...

    @typing.overload
    def __init__(self, s: java.awt.Shape, c: java.awt.Color, stroke: java.awt.Stroke):
        ...

    def getColor(self) -> java.awt.Color:
        ...

    def getShape(self) -> java.awt.Shape:
        ...

    def getStroke(self) -> java.awt.Stroke:
        ...

    def getTx(self) -> float:
        ...

    def getTy(self) -> float:
        ...

    def isShapeFinished(self) -> bool:
        ...

    def paint(self, g: java.awt.Graphics2D):
        ...

    def shapeFinished(self):
        ...

    @property
    def tx(self) -> jpype.JDouble:
        ...

    @property
    def shape(self) -> java.awt.Shape:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def ty(self) -> jpype.JDouble:
        ...

    @property
    def stroke(self) -> java.awt.Stroke:
        ...


class DebugShape(edu.uci.ics.jung.visualization.VisualizationServer.Paintable, typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], drawingIterationCounter: java.util.concurrent.atomic.AtomicInteger, text: typing.Union[java.lang.String, str], shape: java.awt.Shape, color: java.awt.Color):
        ...

    def getColor(self) -> java.awt.Color:
        ...

    def getShape(self) -> java.awt.Shape:
        ...

    def paint(self, g: edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator):
        ...

    @property
    def shape(self) -> java.awt.Shape:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...



__all__ = ["ArticulatedEdgeRenderer", "VisualGraphRenderer", "VisualVertexSatelliteRenderer", "MouseClickedPaintableShape", "MouseDebugPaintable", "VisualGraphEdgeLabelRenderer", "MouseDraggedPaintableShape", "MouseDraggedLinePaintableShape", "GridPainter", "PaintableShape", "DebugShape"]
