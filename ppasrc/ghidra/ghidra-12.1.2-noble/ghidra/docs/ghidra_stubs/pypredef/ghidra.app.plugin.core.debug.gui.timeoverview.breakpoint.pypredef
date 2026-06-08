from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug.gui.timeoverview
import ghidra.trace.model
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class CellType(java.lang.Enum[CellType]):
    """
    An enum for the different types that are represented by unique colors by the
    :obj:`BreakpointTimeOverviewColorService`
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTRUCTION_EXECUTED: typing.Final[CellType]
    MEMORY_READ: typing.Final[CellType]
    MEMORY_WRITTEN: typing.Final[CellType]
    CURRENT_LOCATION: typing.Final[CellType]

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
    def valueOf(name: typing.Union[java.lang.String, str]) -> CellType:
        ...

    @staticmethod
    def values() -> jpype.JArray[CellType]:
        ...

    @property
    def defaultColor(self) -> java.awt.Color:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class BreakpointTimeOverviewColorService(ghidra.app.plugin.core.debug.gui.timeoverview.TimeOverviewColorService):

    @typing.type_check_only
    class BreakpointTimeOverviewEventListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def getColor(self, breakType: CellType) -> java.awt.Color:
        """
        Returns the color associated with the given :obj:`CellType`
        
        :param CellType breakType: the span type for which to get a color.
        :return: the color associated with the given :obj:`CellType`
        :rtype: java.awt.Color
        """

    def setColor(self, type: CellType, newColor: java.awt.Color) -> None:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...


@typing.type_check_only
class BreakpointEvent(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]

    def breakType(self) -> CellType:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def snap(self) -> int:
        ...

    def toString(self) -> str:
        ...


class BreakTypeOverviewLegendPanel(javax.swing.JPanel):

    @typing.type_check_only
    class ColorPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, colorService: BreakpointTimeOverviewColorService) -> None:
        ...

    def updateColors(self) -> None:
        """
        Kick to repaint when the colors have changed.
        """



__all__ = ["CellType", "BreakpointTimeOverviewColorService", "BreakpointEvent", "BreakTypeOverviewLegendPanel"]
