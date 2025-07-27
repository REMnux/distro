from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import edu.uci.ics.jung.visualization # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class BasicEdgeRouter(java.lang.Object, typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], edges: collections.abc.Sequence):
        ...

    def route(self):
        ...


@typing.type_check_only
class ArticulatedEdgeRouter(BasicEdgeRouter[V, E], typing.Generic[V, E]):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["BasicEdgeRouter", "ArticulatedEdgeRouter"]
