from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug.gui.timeoverview
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class TimeTypeOverviewLegendPanel(javax.swing.JPanel):
    """
    A component for displaying the color legend for the :obj:`TimeTypeOverviewColorService`
    """

    @typing.type_check_only
    class ColorPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, colorService: TimeTypeOverviewColorService):
        ...

    def updateColors(self):
        """
        Kick to repaint when the colors have changed.
        """


class TimeSelectionOverviewColorService(TimeTypeOverviewColorService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TimeTypeOverviewColorService(ghidra.app.plugin.core.debug.gui.timeoverview.TimeOverviewColorService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getColor(self, timeType: TimeType) -> java.awt.Color:
        """
        Returns the color associated with the given :obj:`TimeType`
        
        :param TimeType timeType: the span type for which to get a color.
        :return: the color associated with the given :obj:`TimeType`
        :rtype: java.awt.Color
        """

    def setColor(self, type: TimeType, newColor: java.awt.Color):
        """
        Sets the color to be associated with a given :obj:`TimeType`
        
        :param TimeType type: the LifespanType for which to assign the color.
        :param java.awt.Color newColor: the new color for the given :obj:`TimeType`
        """

    @property
    def color(self) -> java.awt.Color:
        ...


class TimeType(java.lang.Enum[TimeType]):
    """
    An enum for the different types that are represented by unique colors by the
    :obj:`TimeTypeOverviewColorService`
    """

    class_: typing.ClassVar[java.lang.Class]
    THREAD_ADDED: typing.Final[TimeType]
    THREAD_REMOVED: typing.Final[TimeType]
    THREAD_CHANGED: typing.Final[TimeType]
    MODULE_ADDED: typing.Final[TimeType]
    MODULE_REMOVED: typing.Final[TimeType]
    MODULE_CHANGED: typing.Final[TimeType]
    REGION_ADDED: typing.Final[TimeType]
    REGION_REMOVED: typing.Final[TimeType]
    REGION_CHANGED: typing.Final[TimeType]
    BPT_ADDED: typing.Final[TimeType]
    BPT_REMOVED: typing.Final[TimeType]
    BPT_CHANGED: typing.Final[TimeType]
    BPT_HIT: typing.Final[TimeType]
    BOOKMARK_ADDED: typing.Final[TimeType]
    BOOKMARK_REMOVED: typing.Final[TimeType]
    BOOKMARK_CHANGED: typing.Final[TimeType]
    UNDEFINED: typing.Final[TimeType]

    def getDefaultColor(self) -> java.awt.Color:
        """
        Returns a color of this enum value.
        
        :return: a color of this enum value.
        :rtype: java.awt.Color
        """

    def getDescription(self) -> str:
        """
        Returns a description of this enum value.
        
        :return: a description of this enum value.
        :rtype: str
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TimeType:
        ...

    @staticmethod
    def values() -> jpype.JArray[TimeType]:
        ...

    @property
    def defaultColor(self) -> java.awt.Color:
        ...

    @property
    def description(self) -> java.lang.String:
        ...



__all__ = ["TimeTypeOverviewLegendPanel", "TimeSelectionOverviewColorService", "TimeTypeOverviewColorService", "TimeType"]
