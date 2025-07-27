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
import edu.uci.ics.jung.visualization.renderers # type: ignore
import ghidra.graph.viewer
import ghidra.graph.viewer.event.mouse
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class VertexClickListener(java.lang.Object, typing.Generic[V, E]):
    """
    A listener that allows clients to be notified of vertex clicks.  Normal 
    mouse processing is handled by the :obj:`VisualGraphMousePlugin` class.  This is a
    convenience method so that clients do not have to deal with the mouse plugin.
    
    
    .. seealso::
    
        | :obj:`VertexFocusListener`
    """

    class_: typing.ClassVar[java.lang.Class]

    def vertexDoubleClicked(self, v: V, mouseInfo: ghidra.graph.viewer.event.mouse.VertexMouseInfo[V, E]) -> bool:
        """
        Called when a vertex is double-clicked
        
        :param V v: the clicked vertex
        :param ghidra.graph.viewer.event.mouse.VertexMouseInfo[V, E] mouseInfo: the info object that contains mouse information for the graph and 
                the low-level vertex's clicked component
        :return: true if this call wants to stop all further mouse event processing
        :rtype: bool
        """


class AbstractVisualVertex(ghidra.graph.viewer.VisualVertex):
    """
    A :obj:`VisualVertex` implementation that implements most of the methods on the interface
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def isFocused(self) -> bool:
        ...

    @property
    def focused(self) -> jpype.JBoolean:
        ...


class VisualVertexRenderer(AbstractVisualVertexRenderer[V, E], typing.Generic[V, E]):
    """
    A renderer for the :obj:`VisualGraph` system.
     
     
    Rendering in the graph system is a bit different than other Java rendering systems.  For
    example, when a JTable renders itself, it uses a single renderer to stamp the data.  The 
    table's renderer has no state and is updated for each cell's data that is to be rendered.
    The graph renderer system is different due to the possibility of complex vertex UIs.  Some
    vertices have sophisticated UI elements that have state.  For these vertices, it makes sense
    for the vertex to build and maintain that state; having that state repeatedly built by the
    renderer would be extremely inefficient and difficult to implement.  Considering that we 
    expect the vertex to build and maintain its UI, this renderer is really just a tool to:
     
    1. Determine if the vertex needs to be painted (by clipping or filtering)
    
    2. Setup the geometry for the vertex (convert the model's location to the view location,
        accounting for panning and zooming)
    
    3. Paint any added effects (such as drop-shadows or highlighting)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VertexShapeProvider(java.lang.Object):
    """
    An interface that can be implemented to provide vertex shapes to the UI.  These are used
    for rendering and mouse interaction.  Typically, these shapes are the same.   Clients that
    wish to allow for complicated shapes can use this interface to control mouse hit detection
    while providing simpler shape painting.
     
     
    The only time a client would need this separation of shapes is if they create complex 
    renderings with odd shapes (a shape that is not a rectangle).   With such a complex 
    shape, those graph views that paint only shapes, like the satellite viewer, will look 
    peculiar.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCompactShape(self) -> java.awt.Shape:
        """
        Returns the compact shape that the user will see when full, detailed rendering is 
        not being performed for a vertex, such as in the satellite viewer or when fully-zoomed-out
        
        :return: the shape
        :rtype: java.awt.Shape
        """

    def getFullShape(self) -> java.awt.Shape:
        """
        Returns the full (the actual) shape of a vertex.  This can be used to determine if a 
        mouse point intersects a vertex or to get the real bounding-box of a vertex.
        
        :return: the shape
        :rtype: java.awt.Shape
        """

    @property
    def fullShape(self) -> java.awt.Shape:
        ...

    @property
    def compactShape(self) -> java.awt.Shape:
        ...


class AbstractVisualVertexRenderer(edu.uci.ics.jung.visualization.renderers.BasicVertexRenderer[V, E], typing.Generic[V, E]):
    """
    A base renderer class to define shared logic needed to render a vertex
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

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

    def getVertexFillPaintTransformer(self) -> com.google.common.base.Function[V, java.awt.Paint]:
        ...

    def setVertexFillPaintTransformer(self, transformer: com.google.common.base.Function[V, java.awt.Paint]):
        """
        Sets the optional transformer used to convert a vertex into a color
        
        :param com.google.common.base.Function[V, java.awt.Paint] transformer: the transformer
        """

    @property
    def vertexFillPaintTransformer(self) -> com.google.common.base.Function[V, java.awt.Paint]:
        ...

    @vertexFillPaintTransformer.setter
    def vertexFillPaintTransformer(self, value: com.google.common.base.Function[V, java.awt.Paint]):
        ...


class DockingVisualVertex(AbstractVisualVertex):
    """
    A :obj:`VisualVertex` implementation that provides a component with a docking header that 
    is clickable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    def getName(self) -> str:
        ...

    def getText(self) -> str:
        ...

    def getTextArea(self) -> javax.swing.JTextArea:
        ...

    def setMaxWidth(self, width: typing.Union[jpype.JInt, int]):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def textArea(self) -> javax.swing.JTextArea:
        ...


class VisualGraphVertexShapeTransformer(com.google.common.base.Function[V, java.awt.Shape], typing.Generic[V]):
    """
    The default :obj:`VisualGraph` renderer.  By default, the shape returned by this class is
    a :obj:`Rectangle` of the given vertex's :meth:`component <VisualVertex.getComponent>`.
     
     
    This class is aware of :obj:`VertexShapeProvider`s, which allows vertex creators to 
    provide vertex shapes that differ for rendering and clicking.  See that class for more info.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def transformToCompactShape(self, v: V) -> java.awt.Shape:
        """
        Returns the compact shape that the user will see when full, detailed rendering is 
        not being performed for a vertex, such as in the satellite viewer or when fully-zoomed-out
        
        :param V v: the vertex
        :return: the shape
        :rtype: java.awt.Shape
        """

    def transformToFullShape(self, v: V) -> java.awt.Shape:
        """
        Returns the full (the actual) shape of a vertex.  This can be used to determine if a 
        mouse point intersects a vertex or to get the real bounding-box of a vertex.
        
        :param V v: the vertex
        :return: the shape
        :rtype: java.awt.Shape
        """


class VertexFocusListener(java.lang.Object, typing.Generic[V]):
    """
    A listener called when a vertex is focused.
    """

    class_: typing.ClassVar[java.lang.Class]

    def vertexFocused(self, v: V):
        ...



__all__ = ["VertexClickListener", "AbstractVisualVertex", "VisualVertexRenderer", "VertexShapeProvider", "AbstractVisualVertexRenderer", "DockingVisualVertex", "VisualGraphVertexShapeTransformer", "VertexFocusListener"]
