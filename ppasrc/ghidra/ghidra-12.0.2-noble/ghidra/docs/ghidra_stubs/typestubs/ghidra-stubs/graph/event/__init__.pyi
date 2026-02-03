from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class VisualGraphChangeListener(java.lang.Object, typing.Generic[V, E]):
    """
    A listener to get notified of graph changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def edgesAdded(self, edges: collections.abc.Sequence):
        """
        Called when the given edges have been added from the graph
        
        :param collections.abc.Sequence edges: the added edges
        """

    def edgesRemoved(self, edges: collections.abc.Sequence):
        """
        Called when the given edges have been removed from the graph
        
        :param collections.abc.Sequence edges: the removed edges
        """

    def verticesAdded(self, vertices: collections.abc.Sequence):
        """
        Called when the given vertices have been added from the graph
        
        :param collections.abc.Sequence vertices: the added vertices
        """

    def verticesRemoved(self, vertices: collections.abc.Sequence):
        """
        Called when the given vertices have been removed from the graph
        
        :param collections.abc.Sequence vertices: the removed vertices
        """



__all__ = ["VisualGraphChangeListener"]
