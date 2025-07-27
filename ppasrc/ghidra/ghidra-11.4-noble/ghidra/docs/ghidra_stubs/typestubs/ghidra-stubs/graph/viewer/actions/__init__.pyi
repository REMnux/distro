from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import java.lang # type: ignore


V = typing.TypeVar("V")


class VisualGraphActionContext(java.lang.Object):
    """
    Action context for :obj:`VisualGraph`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def shouldShowSatelliteActions(self) -> bool:
        """
        Returns true actions that manipulate the satellite viewer should be enabled for this context
        
        :return: true actions that manipulate the satellite viewer should be enabled for this context
        :rtype: bool
        """


class VgVertexContext(VgActionContext, VisualGraphVertexActionContext[V], typing.Generic[V]):
    """
    Context for a :obj:`VisualGraph` when a vertex is selected
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, v: V):
        ...


class VisualGraphContextMarker(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class VgActionContext(docking.DefaultActionContext, VisualGraphActionContext):
    """
    Context for :obj:`VisualGraph`s
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider):
        ...

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, contextObject: java.lang.Object):
        ...

    def shouldShowSatelliteActions(self) -> bool:
        """
        Returns true actions that manipulate the satellite viewer should be enabled for this context
        
        :return: true actions that manipulate the satellite viewer should be enabled for this context
        :rtype: bool
        """


class VisualGraphVertexActionContext(VisualGraphActionContext, typing.Generic[V]):
    """
    Context for a :obj:`VisualGraph` when a vertex is selected
    """

    class_: typing.ClassVar[java.lang.Class]

    def getVertex(self) -> V:
        ...

    def shouldShowSatelliteActions(self) -> bool:
        """
        Returns true actions that manipulate the satellite viewer should be enabled for this context
        
        :return: true actions that manipulate the satellite viewer should be enabled for this context
        :rtype: bool
        """

    @property
    def vertex(self) -> V:
        ...


class VisualGraphSatelliteActionContext(VisualGraphActionContext):
    ...
    class_: typing.ClassVar[java.lang.Class]


class VgSatelliteContext(VgActionContext):
    """
    Context for :obj:`VisualGraph`'s satellite viewer
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider):
        ...



__all__ = ["VisualGraphActionContext", "VgVertexContext", "VisualGraphContextMarker", "VgActionContext", "VisualGraphVertexActionContext", "VisualGraphSatelliteActionContext", "VgSatelliteContext"]
