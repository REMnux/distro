from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.google.common.base # type: ignore
import edu.uci.ics.jung.algorithms.layout # type: ignore
import edu.uci.ics.jung.visualization # type: ignore
import edu.uci.ics.jung.visualization.picking # type: ignore
import java.awt # type: ignore
import java.lang # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class GraphLoopShape(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, shape: java.awt.Shape, radius: typing.Union[jpype.JFloat, float]):
        ...

    def getRadius(self) -> float:
        ...

    def getShape(self) -> java.awt.Shape:
        ...

    @property
    def shape(self) -> java.awt.Shape:
        ...

    @property
    def radius(self) -> jpype.JFloat:
        ...


class ArticulatedEdgeTransformer(com.google.common.base.Function[E, java.awt.Shape], typing.Generic[V, E]):
    """
    An edge shape that renders as a series of straight lines between articulation points.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def apply(self, e: E) -> java.awt.Shape:
        """
        Get the shape for this edge
        
        :param E e: the edge
        :return: the edge shape
        :rtype: java.awt.Shape
        """


class VisualGraphShapePickSupport(edu.uci.ics.jung.visualization.picking.ShapePickSupport[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E]):
        ...

    def getEdge(self, layout: edu.uci.ics.jung.algorithms.layout.Layout[V, E], viewSpaceX: typing.Union[jpype.JDouble, float], viewSpaceY: typing.Union[jpype.JDouble, float]) -> E:
        """
        Overridden to handle edge picking with our custom edge placement.  The painting and picking
        algorithms in Jung are all hard-coded to transform loop edges to above the vertex--there
        is no way to plug our own transformation into Jung :(
        
        :param edu.uci.ics.jung.algorithms.layout.Layout[V, E] layout: 
        :param jpype.JDouble or float viewSpaceX: The x under which to look for an edge (view coordinates)
        :param jpype.JDouble or float viewSpaceY: The y under which to look for an edge (view coordinates)
        :return: The closest edge to the given point; null if no edge near the point
        :rtype: E
        """



__all__ = ["GraphLoopShape", "ArticulatedEdgeTransformer", "VisualGraphShapePickSupport"]
