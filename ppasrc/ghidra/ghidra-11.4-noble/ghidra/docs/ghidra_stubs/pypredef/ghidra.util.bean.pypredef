from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import javax.swing # type: ignore


class GGlassPanePainter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def paint(self, glassPane: GGlassPane, graphics: java.awt.Graphics):
        ...


class GGlassPane(javax.swing.JComponent):
    """
    A component that acts as the general purpose glass pane for Java windows.  This component allows
    Ghidra to easily change
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default constructor.
         
        
        **NOTE: **You must call :meth:`setVisible(true) <.setVisible>` on this component **after adding it
        to the component**.  This is because the component will set the visibility to that of
        the previous glass pane, which is false by default.
        """

    def addPainter(self, painter: GGlassPanePainter):
        """
        Adds a painter that will be called when this pane's :meth:`paintComponent(Graphics) <.paintComponent>` 
        method is called.
        
        :param GGlassPanePainter painter: the painter to add
        """

    @staticmethod
    def getGlassPane(component: java.awt.Component) -> GGlassPane:
        ...

    def isBusy(self) -> bool:
        """
        Returns true if this glass pane is blocking user input.
        
        :return: true if this glass pane is blocking user input.
        :rtype: bool
        """

    def removePainter(self, painter: GGlassPanePainter):
        ...

    @staticmethod
    def setAllGlassPanesBusy(isBusy: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the busy state of all glass panes created in the VM.
        
        :param jpype.JBoolean or bool isBusy: the busy state of all glass panes created in the VM.
        """

    def setBusy(self, isBusy: typing.Union[jpype.JBoolean, bool]):
        """
        When set busy is called, a busy cursor will be displayed **and** all user mouse and 
        keyboard events will be blocked.
        
        :param jpype.JBoolean or bool isBusy: True to block events and show the busy cursor; false to restore events and
                    to restore the default cursor.
        """

    def showBusyCursor(self, showBusyCursor: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @busy.setter
    def busy(self, value: jpype.JBoolean):
        ...



__all__ = ["GGlassPanePainter", "GGlassPane"]
