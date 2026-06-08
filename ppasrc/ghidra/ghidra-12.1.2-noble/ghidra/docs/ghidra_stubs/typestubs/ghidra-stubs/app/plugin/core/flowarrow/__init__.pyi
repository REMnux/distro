from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.util
import ghidra.app.services
import ghidra.app.util.viewer.listingpanel
import ghidra.framework.plugintool
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class FlowArrowPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.ListingMarginProviderService):
    """
    Plugin that has a margin provider to show the program flow.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


@typing.type_check_only
class ConditionalFlowArrow(FlowArrow):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FlowArrowShapeFactory(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FlowArrowPanel(javax.swing.JPanel):

    @typing.type_check_only
    class ScrollingCallback(docking.util.SwingAnimationCallback):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FlowArrowCursorMouseListener(java.awt.event.MouseMotionListener, java.awt.event.MouseListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FlowArrowPanelMouseWheelListener(java.awt.event.MouseWheelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def resetCursor(self) -> None:
        ...

    def updateCursor(self, point: java.awt.Point) -> None:
        ...


@typing.type_check_only
class FallthroughFlowArrow(FlowArrow):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FlowArrow(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getDisplayString(self) -> str:
        ...

    @property
    def displayString(self) -> java.lang.String:
        ...


@typing.type_check_only
class DefaultFlowArrow(FlowArrow):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FlowArrowMarginProvider(ghidra.app.util.viewer.listingpanel.ListingMarginProvider):

    @typing.type_check_only
    class ArrowGroup(java.lang.Object):
        """
        An arrow group is all arrows that will be in the same column.  The column for an arrow
        will be based on the first group to assign a column.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OffscreenArrowsFlow(java.lang.Object):
        """
        A cache of all arrows that start at a given address.  This is only used while building the 
        set of arrows.  This tracks arrow usage from the start address to limit the number of arrows
        that go offscreen.   We allow 1 offscreen arrow above and below for each of the three flow
        types: conditional, fallthrough and other.   This is used to prevent too many arrows from 
        cluttering the screen when there are many references starting at the same address.
        """

        @typing.type_check_only
        class OffScreenFlow(java.lang.Object):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def forwardMouseEventToListing(self, e: java.awt.event.MouseWheelEvent) -> None:
        ...



__all__ = ["FlowArrowPlugin", "ConditionalFlowArrow", "FlowArrowShapeFactory", "FlowArrowPanel", "FallthroughFlowArrow", "FlowArrow", "DefaultFlowArrow", "FlowArrowMarginProvider"]
