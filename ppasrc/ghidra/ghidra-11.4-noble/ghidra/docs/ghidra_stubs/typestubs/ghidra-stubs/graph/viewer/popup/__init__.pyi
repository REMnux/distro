from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore


E = typing.TypeVar("E")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class PopupSource(java.lang.Object, typing.Generic[V, E]):
    """
    An interface that provides graph and component information to the :obj:`PopupRegulator`
    """

    class_: typing.ClassVar[java.lang.Class]

    def addMouseMotionListener(self, l: java.awt.event.MouseMotionListener):
        """
        Adds the given mouse motion listener to the graph component.  This allows the popup 
        regulator to decided when to show and hide popups.
        
        :param java.awt.event.MouseMotionListener l: the listener
        """

    def getEdge(self, event: java.awt.event.MouseEvent) -> E:
        """
        Returns an edge for the given event
        
        :param java.awt.event.MouseEvent event: the event
        :return: the edge or null
        :rtype: E
        """

    def getPopupParent(self) -> java.awt.Window:
        """
        Returns a suitable window parent for the popup window
        
        :return: the window parent
        :rtype: java.awt.Window
        """

    def getToolTipInfo(self, event: java.awt.event.MouseEvent) -> ToolTipInfo[typing.Any]:
        """
        Returns the tool tip info object for the given mouse event.  Implementations will use the
        event to determine whether a popup should be created for a vertex, edge, the graph or 
        not at all.
        
        :param java.awt.event.MouseEvent event: the event
        :return: the info; null for no popup
        :rtype: ToolTipInfo[typing.Any]
        """

    def getVertex(self, event: java.awt.event.MouseEvent) -> V:
        """
        Returns a vertex for the given event
        
        :param java.awt.event.MouseEvent event: the event
        :return: the vertex or null
        :rtype: V
        """

    def repaint(self):
        """
        Signals that the graph needs to repaint
        """

    @property
    def edge(self) -> E:
        ...

    @property
    def vertex(self) -> V:
        ...

    @property
    def toolTipInfo(self) -> ToolTipInfo[typing.Any]:
        ...

    @property
    def popupParent(self) -> java.awt.Window:
        ...


class ToolTipInfo(java.lang.Object, typing.Generic[T]):
    """
    Basic container object that knows how to generate tooltips
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, event: java.awt.event.MouseEvent, t: T):
        ...


class PopupRegulator(java.lang.Object, typing.Generic[V, E]):
    """
    A class to control popups for graph clients, bypassing Java's default tool tip mechanism
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, popupSupplier: PopupSource[V, E]):
        ...

    def isPopupShowing(self) -> bool:
        """
        Returns true if this class's popup is showing
        
        :return: true if this class's popup is showing
        :rtype: bool
        """

    def setPopupDelay(self, delayMs: typing.Union[jpype.JInt, int]):
        """
        Sets the time between mouse movements to wait before showing this class's popup
        
        :param jpype.JInt or int delayMs: the delay
        """

    def setPopupsVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the enablement of this class's popup
        
        :param jpype.JBoolean or bool visible: true to have popups enabled
        """

    @property
    def popupShowing(self) -> jpype.JBoolean:
        ...



__all__ = ["PopupSource", "ToolTipInfo", "PopupRegulator"]
