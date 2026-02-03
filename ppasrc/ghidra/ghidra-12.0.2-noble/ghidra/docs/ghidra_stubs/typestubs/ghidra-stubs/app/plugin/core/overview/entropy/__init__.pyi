from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.overview
import ghidra.framework.options
import ghidra.framework.plugintool
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class EntropyOverviewColorService(ghidra.app.plugin.core.overview.OverviewColorService):
    """
    Service for associating colors with a programs address's based on an Entropy computation for
    the bytes in a chunk around the given address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def paletteChanged(self):
        """
        Kick when the colors have been changed.
        """


class EntropyKnot(java.lang.Enum[EntropyKnot]):
    """
    Enum for defining known entropy ranges
    """

    class_: typing.ClassVar[java.lang.Class]
    NONE: typing.Final[EntropyKnot]
    X86: typing.Final[EntropyKnot]
    ARM: typing.Final[EntropyKnot]
    THUMB: typing.Final[EntropyKnot]
    POWER_PC: typing.Final[EntropyKnot]
    ASCII: typing.Final[EntropyKnot]
    COMPRESSED: typing.Final[EntropyKnot]
    UTF16: typing.Final[EntropyKnot]

    def getRecord(self) -> EntropyRecord:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EntropyKnot:
        ...

    @staticmethod
    def values() -> jpype.JArray[EntropyKnot]:
        ...

    @property
    def record(self) -> EntropyRecord:
        ...


class KnotRecord(java.lang.Object):
    """
    Entropy information for the Entropy color legend panel. A KnotRecord records a "known" entropy
    range for a specific type of data in a program.  For example, if you compute the entropy for
    a range of bytes containing ASCII characters, you will get an entropy score close to 4.7.
    """

    class_: typing.ClassVar[java.lang.Class]
    name: java.lang.String
    color: java.awt.Color
    start: jpype.JInt
    end: jpype.JInt
    point: jpype.JInt

    def __init__(self, name: typing.Union[java.lang.String, str], color: java.awt.Color, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int], point: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param java.lang.String or str name: a name for what this range represents. (ASCII, X86 code, etc.)
        :param java.awt.Color color: the color to associate with this type.
        :param jpype.JInt or int start: the minimum entropy for this range.
        :param jpype.JInt or int end: the maximum entropy for this range.
        :param jpype.JInt or int point: the x coordinate in the legend for this knot.
        """

    def contains(self, entropy: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def getName(self) -> str:
        ...


class LegendPanel(javax.swing.JPanel):
    """
    Panel for display the Entropy color legend.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setPalette(self, pal: OverviewPalette):
        ...


class EntropyOverviewOptionsManager(ghidra.framework.options.OptionsChangeListener):
    """
    Helper class for the :obj:`EntropyOverviewColorService` to manage the options and create
    the color Palette for that service.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, service: EntropyOverviewColorService):
        ...

    def getChunkSize(self) -> int:
        """
        Returns the current chunk size option value.
        
        :return: the current chunk size option value.
        :rtype: int
        """

    def getPalette(self) -> OverviewPalette:
        """
        Returns the palette computed after reading the options.
        
        :return: the color palette for the :obj:`EntropyOverviewColorService`
        :rtype: OverviewPalette
        """

    @property
    def chunkSize(self) -> jpype.JInt:
        ...

    @property
    def palette(self) -> OverviewPalette:
        ...


class PalettePanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def setPalette(self, palette: OverviewPalette):
        ...


class EntropyChunkSize(java.lang.Enum[EntropyChunkSize]):
    """
    Enum for the various supported entropy chunk sizes.
    """

    class_: typing.ClassVar[java.lang.Class]
    SMALL: typing.Final[EntropyChunkSize]
    MEDIUM: typing.Final[EntropyChunkSize]
    LARGE: typing.Final[EntropyChunkSize]

    def getChunkSize(self) -> int:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EntropyChunkSize:
        ...

    @staticmethod
    def values() -> jpype.JArray[EntropyChunkSize]:
        ...

    @property
    def chunkSize(self) -> jpype.JInt:
        ...


class OverviewPalette(java.lang.Object):
    """
    Manages the colors used by the entropy overview bar.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sz: typing.Union[jpype.JInt, int], uninit: java.awt.Color):
        ...

    def addKnot(self, name: typing.Union[java.lang.String, str], knot: java.awt.Color, start: typing.Union[jpype.JInt, int], point: typing.Union[jpype.JInt, int]):
        ...

    def getColor(self, i: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    def getKnots(self) -> java.util.ArrayList[KnotRecord]:
        ...

    def getSize(self) -> int:
        ...

    def setBase(self, lo: java.awt.Color, hi: java.awt.Color):
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def knots(self) -> java.util.ArrayList[KnotRecord]:
        ...


class KnotLabelPanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, topBottomMargin: typing.Union[jpype.JInt, int]):
        ...

    def setPalette(self, palette: OverviewPalette):
        ...


class EntropyRecord(java.lang.Object):
    """
    Class for storing entropy information for various types found in program such
    """

    class_: typing.ClassVar[java.lang.Class]
    name: java.lang.String
    center: jpype.JDouble
    width: jpype.JDouble

    def __init__(self, name: typing.Union[java.lang.String, str], center: typing.Union[jpype.JDouble, float], width: typing.Union[jpype.JDouble, float]):
        """
        Constructor
        
        :param java.lang.String or str name: the name
        :param jpype.JDouble or float center: the center point of the entropy range
        :param jpype.JDouble or float width: the width of the entropy range
        """



__all__ = ["EntropyOverviewColorService", "EntropyKnot", "KnotRecord", "LegendPanel", "EntropyOverviewOptionsManager", "PalettePanel", "EntropyChunkSize", "OverviewPalette", "KnotLabelPanel", "EntropyRecord"]
