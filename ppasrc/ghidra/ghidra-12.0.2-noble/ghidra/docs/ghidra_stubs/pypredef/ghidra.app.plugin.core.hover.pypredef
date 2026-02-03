from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel.support
import docking.widgets.shapes
import ghidra.app.services
import ghidra.app.util.viewer.listingpanel
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util
import java.lang # type: ignore
import javax.swing # type: ignore


class AbstractHover(ghidra.app.services.HoverService):
    """
    Base class for listing hover extensions.
    """

    class_: typing.ClassVar[java.lang.Class]


class AbstractHoverProvider(docking.widgets.fieldpanel.support.HoverProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, windowName: typing.Union[java.lang.String, str]):
        ...

    def dispose(self):
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def initializeListingHoverHandler(self, otherHandler: AbstractHoverProvider):
        ...

    def isForcePopups(self) -> bool:
        ...

    def setHoverEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setPopupPlacer(self, popupWindowPlacer: docking.widgets.shapes.PopupWindowPlacer):
        """
        Sets the object that decides where to place the popup window.
        
        :param docking.widgets.shapes.PopupWindowPlacer popupWindowPlacer: the placer
        """

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @program.setter
    def program(self, value: ghidra.program.model.listing.Program):
        ...

    @property
    def forcePopups(self) -> jpype.JBoolean:
        ...


class AbstractScalarOperandHover(AbstractConfigurableHover):
    """
    A hover service to show tool tip text for hovering over scalar values.
    The tooltip shows the scalar in different bases.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, priority: typing.Union[jpype.JInt, int]):
        ...


class AbstractConfigurableHover(AbstractHover, ghidra.util.Disposable, ghidra.framework.options.OptionsChangeListener):
    """
    A listing or decompiler hover that employs some degree of configurability.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, priority: typing.Union[jpype.JInt, int]):
        ...

    def initializeOptions(self):
        ...

    def setOptions(self, options: ghidra.framework.options.Options, optionName: typing.Union[java.lang.String, str]):
        ...


class AbstractReferenceHover(AbstractConfigurableHover):
    """
    A hover service to show tool tip text for hovering over a reference.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, priority: typing.Union[jpype.JInt, int]):
        ...

    def getPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    def getToolTip(self) -> javax.swing.JToolTip:
        ...

    def programClosed(self, program: ghidra.program.model.listing.Program):
        ...

    @property
    def toolTip(self) -> javax.swing.JToolTip:
        ...

    @property
    def panel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...



__all__ = ["AbstractHover", "AbstractHoverProvider", "AbstractScalarOperandHover", "AbstractConfigurableHover", "AbstractReferenceHover"]
