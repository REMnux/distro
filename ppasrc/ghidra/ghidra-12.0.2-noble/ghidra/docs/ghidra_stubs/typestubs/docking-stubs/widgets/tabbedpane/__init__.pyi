from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class DockingTabRenderer(javax.swing.JPanel):
    """
    A widget that can be used to render an icon, title and close button for JTabbedPane.  You would 
    use this class with the tabbed pane by calling :meth:`JTabbedPane.setTabComponentAt(int, Component) <JTabbedPane.setTabComponentAt>`
    """

    @typing.type_check_only
    class ForwardingMouseListener(java.awt.event.MouseListener, java.awt.event.MouseMotionListener):
        """
        A class designed to listen for mouse events on this renderer component which it will then
        forward on to the given component.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TabContainerForwardingMouseListener(java.awt.event.MouseAdapter):
        """
        A class to handle mouse events specifically for BasicTabbedPaneUI$TabContainer, which does
        not forward mouse events on to the tabbed pane.  When using custom tab renderers, which 
        we are, tabbed panes that are larger than the renderer will not get mouse events that
        are over the tab, but not the renderer.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tabbedPane: javax.swing.JTabbedPane, fullTitle: typing.Union[java.lang.String, str], tabTitle: typing.Union[java.lang.String, str], closeListener: java.awt.event.ActionListener):
        ...

    def getTabText(self) -> str:
        ...

    def installRenameAction(self, listener: java.awt.event.MouseListener):
        ...

    def setIcon(self, icon: javax.swing.Icon):
        ...

    def setTitle(self, tabTitle: typing.Union[java.lang.String, str], fullTitle: typing.Union[java.lang.String, str]):
        ...

    @property
    def tabText(self) -> java.lang.String:
        ...



__all__ = ["DockingTabRenderer"]
