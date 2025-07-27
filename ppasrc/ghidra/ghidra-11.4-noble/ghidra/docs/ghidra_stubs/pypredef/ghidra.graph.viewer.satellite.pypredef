from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.graph.viewer
import java.awt # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class CachingSatelliteGraphViewer(ghidra.graph.viewer.SatelliteGraphViewer[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, masterViewer: ghidra.graph.viewer.GraphViewer[V, E], preferredSize: java.awt.Dimension):
        ...



__all__ = ["CachingSatelliteGraphViewer"]
