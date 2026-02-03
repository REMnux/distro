from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.util
import ghidra.app.util.viewer.listingpanel
import ghidra.framework.options
import ghidra.framework.plugintool
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class FlowArrowPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.util.viewer.listingpanel.MarginProvider, ghidra.framework.options.OptionsChangeListener):
    """
    Plugin that has a margin provider to show the program flow.
    """

    @typing.type_check_only
    class ArrowCache(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def forwardMouseEventToListing(self, e: java.awt.event.MouseWheelEvent):
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

    def resetCursor(self):
        ...

    def updateCursor(self, point: java.awt.Point):
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



__all__ = ["FlowArrowPlugin", "ConditionalFlowArrow", "FlowArrowShapeFactory", "FlowArrowPanel", "FallthroughFlowArrow", "FlowArrow", "DefaultFlowArrow"]
