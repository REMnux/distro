from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.graph.viewer
import ghidra.graph.viewer.vertex
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class VertexExpansionListener(java.lang.Object):
    """
    A listener to know when a vertex has been told to expand
    """

    class_: typing.ClassVar[java.lang.Class]

    def toggleIncomingVertices(self, v: ghidra.graph.viewer.VisualVertex):
        """
        Show or hide those vertices that are on incoming edges to v
        
        :param ghidra.graph.viewer.VisualVertex v: the vertex
        """

    def toggleOutgoingVertices(self, v: ghidra.graph.viewer.VisualVertex):
        """
        Show or hide those vertices that are on outgoing edges to v
        
        :param ghidra.graph.viewer.VisualVertex v: the vertex
        """


class CircleWithLabelVertexShapeProvider(ghidra.graph.viewer.vertex.VertexShapeProvider):

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_VERTEX_SHAPE_COLOR: typing.Final[java.awt.Color]

    @typing.overload
    def __init__(self, label: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, label: typing.Union[java.lang.String, str], expansionListener: VertexExpansionListener):
        ...

    def canExpand(self) -> bool:
        """
        Returns true if this node can be expanded
        
        :return: true if this node can be expanded
        :rtype: bool
        """

    def getCircleCenterYOffset(self) -> int:
        ...

    def getComponent(self) -> javax.swing.JComponent:
        ...

    def getIncomingToggleButton(self) -> javax.swing.JButton:
        ...

    def getName(self) -> str:
        ...

    def getOutgoingToggleButton(self) -> javax.swing.JButton:
        ...

    def isExpanded(self) -> bool:
        """
        Returns whether this vertex is fully expanded in its current direction
        
        :return: whether this vertex is fully expanded in its current direction
        :rtype: bool
        """

    def isIncomingExpanded(self) -> bool:
        """
        Returns true if this vertex is showing all edges in the incoming direction
        
        :return: true if this vertex is showing all edges in the incoming direction
        :rtype: bool
        """

    def isOutgoingExpanded(self) -> bool:
        """
        Returns true if this vertex is showing all edges in the outgoing direction
        
        :return: true if this vertex is showing all edges in the outgoing direction
        :rtype: bool
        """

    def setIncomingExpanded(self, setExpanded: typing.Union[jpype.JBoolean, bool]):
        """
        Sets to true if this vertex is showing all edges in the incoming direction
        
        :param jpype.JBoolean or bool setExpanded: true if this vertex is showing all edges in the incoming direction
        """

    def setOutgoingExpanded(self, setExpanded: typing.Union[jpype.JBoolean, bool]):
        """
        Sets to true if this vertex is showing all edges in the outgoing direction
        
        :param jpype.JBoolean or bool setExpanded: true if this vertex is showing all edges in the outgoing direction
        """

    def setTogglesVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def incomingExpanded(self) -> jpype.JBoolean:
        ...

    @incomingExpanded.setter
    def incomingExpanded(self, value: jpype.JBoolean):
        ...

    @property
    def outgoingToggleButton(self) -> javax.swing.JButton:
        ...

    @property
    def expanded(self) -> jpype.JBoolean:
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def circleCenterYOffset(self) -> jpype.JInt:
        ...

    @property
    def incomingToggleButton(self) -> javax.swing.JButton:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def outgoingExpanded(self) -> jpype.JBoolean:
        ...

    @outgoingExpanded.setter
    def outgoingExpanded(self, value: jpype.JBoolean):
        ...


class CircleWithLabelVertex(ghidra.graph.viewer.vertex.AbstractVisualVertex, ghidra.graph.viewer.vertex.VertexShapeProvider):
    """
    A vertex that is a circle shape with a label below the circle to show the given text.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, label: typing.Union[java.lang.String, str]):
        ...

    def getName(self) -> str:
        ...

    @property
    def name(self) -> java.lang.String:
        ...



__all__ = ["VertexExpansionListener", "CircleWithLabelVertexShapeProvider", "CircleWithLabelVertex"]
