from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.theme
import ghidra.framework.options
import ghidra.util
import java.awt # type: ignore
import java.lang # type: ignore


class ViewRestoreOption(java.lang.Enum[ViewRestoreOption]):

    class_: typing.ClassVar[java.lang.Class]
    START_FULLY_ZOOMED_OUT: typing.Final[ViewRestoreOption]
    START_FULLY_ZOOMED_IN: typing.Final[ViewRestoreOption]
    REMEMBER_SETTINGS: typing.Final[ViewRestoreOption]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ViewRestoreOption:
        ...

    @staticmethod
    def values() -> jpype.JArray[ViewRestoreOption]:
        ...


class RelayoutOption(java.lang.Enum[RelayoutOption]):

    class_: typing.ClassVar[java.lang.Class]
    ALWAYS: typing.Final[RelayoutOption]
    BLOCK_MODEL_CHANGES: typing.Final[RelayoutOption]
    VERTEX_GROUPING_CHANGES: typing.Final[RelayoutOption]
    NEVER: typing.Final[RelayoutOption]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> RelayoutOption:
        ...

    @staticmethod
    def values() -> jpype.JArray[RelayoutOption]:
        ...


class VisualGraphOptions(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    GRAPH_BACKGROUND_COLOR_KEY: typing.Final = "Graph Background Color"
    GRAPH_BACKGROUND_COLOR_DESCRPTION: typing.Final = "The graph display background color"
    SHOW_ANIMATION_OPTIONS_KEY: typing.Final = "Use Animation"
    SHOW_ANIMATION_DESCRIPTION: typing.Final = "Signals to the Function Graph to use animated transitions for certain operations, like navigation."
    USE_MOUSE_RELATIVE_ZOOM_KEY: typing.Final = "Use Mouse-relative Zoom"
    USE_MOUSE_RELATIVE_ZOOM_DESCRIPTION: typing.Final = "When true the Function Graph will perform zoom operations relative to the mouse point."
    USE_CONDENSED_LAYOUT_KEY: typing.Final = "Use Condensed Layout"
    USE_CONDENSED_LAYOUT_DESCRIPTION: typing.Final = "Place vertices as close together as possible.  For example, when true, the graph will use little spacing between vertices.  Each layout will handle this option differently."
    SCROLL_WHEEL_PANS_KEY: typing.Final = "Scroll Wheel Pans"
    SCROLL_WHEEL_PANS_DESCRIPTION: typing.Final[java.lang.String]
    USE_STICKY_SELECTION_KEY: typing.Final = "Use Sticky Selection"
    USE_STICKY_SELECTION_DESCRIPTION: typing.Final = "When enabled Selecting code units in one vertex will not clear the selection in another.  When disabled, every new selection clears the previous selection <b>unless the Control</b>key is pressed."
    VIEW_RESTORE_OPTIONS_KEY: typing.Final = "View Settings"
    VIEW_RESTORE_OPTIONS_DESCRIPTION: typing.Final = "Dictates how the view of new graphs and already rendered graphs are zoomed and positioned.  See the help for more details."
    DEFAULT_GRAPH_BACKGROUND_COLOR: typing.Final[generic.theme.GColor]

    def __init__(self):
        ...

    def getGraphBackgroundColor(self) -> java.awt.Color:
        ...

    def getScrollWheelPans(self) -> bool:
        ...

    def getViewRestoreOption(self) -> ViewRestoreOption:
        ...

    def isDefaultBackgroundColor(self, c: java.awt.Color) -> bool:
        ...

    def loadOptions(self, options: ghidra.framework.options.Options):
        ...

    def registerOptions(self, options: ghidra.framework.options.Options, help: ghidra.util.HelpLocation):
        ...

    def setUseAnimation(self, useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...

    def useAnimation(self) -> bool:
        ...

    def useCondensedLayout(self) -> bool:
        ...

    def useMouseRelativeZoom(self) -> bool:
        ...

    @property
    def graphBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def scrollWheelPans(self) -> jpype.JBoolean:
        ...

    @property
    def viewRestoreOption(self) -> ViewRestoreOption:
        ...

    @property
    def defaultBackgroundColor(self) -> jpype.JBoolean:
        ...



__all__ = ["ViewRestoreOption", "RelayoutOption", "VisualGraphOptions"]
