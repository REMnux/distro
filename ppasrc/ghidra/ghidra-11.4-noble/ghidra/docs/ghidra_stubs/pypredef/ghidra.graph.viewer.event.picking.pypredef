from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import edu.uci.ics.jung.visualization.picking # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


V = typing.TypeVar("V")


class PickListener(java.lang.Object, typing.Generic[V]):

    class EventSource(java.lang.Enum[PickListener.EventSource]):

        class_: typing.ClassVar[java.lang.Class]
        EXTERNAL: typing.Final[PickListener.EventSource]
        """
        Originated from outside of the graph API (e.g., an external location change)
        """

        INTERNAL: typing.Final[PickListener.EventSource]
        """
        Originated from the graph API (e.g., a user click, a graph grouping)
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PickListener.EventSource:
            ...

        @staticmethod
        def values() -> jpype.JArray[PickListener.EventSource]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def verticesPicked(self, vertices: java.util.Set[V], source: PickListener.EventSource):
        ...


class GPickedState(edu.uci.ics.jung.visualization.picking.PickedState[V], typing.Generic[V]):
    """
    This picked-state is a wrapper for :obj:`PickedState` that allows us to broadcast events
    with the trigger of that event.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pickedState: edu.uci.ics.jung.visualization.picking.MultiPickedState[V]):
        ...

    def addPickingListener(self, pickListener: PickListener[V]):
        ...

    def pickToActivate(self, vertex: V):
        """
        A convenience method to clear the current selected vertices and select the given vertex
        
        :param V vertex: the vertex to pick
        """

    @typing.overload
    def pickToSync(self, vertex: V):
        """
        Picks the given vertex, but signals that the pick is really just to make sure that the 
        vertex is picked in order to match the graph's notion of the current location.  To pick a 
        vertex and signal that the location has changed, call :meth:`pick(Object, boolean) <.pick>`. 
        Calling this method is the same as calling 
        pickToSync(vertex, false);
        
        :param V vertex: the vertex to pick
        """

    @typing.overload
    def pickToSync(self, vertex: V, addToSelection: typing.Union[jpype.JBoolean, bool]):
        """
        Picks the given vertex, but signals that the pick is really just to make sure that the 
        vertex is picked in order to match the graph's notion of the current location.  To pick a 
        vertex and signal that the location has changed, call :meth:`pick(Object, boolean) <.pick>`
        
        :param V vertex: the vertex to pick
        :param jpype.JBoolean or bool addToSelection: true signals that the given vertex should be picked, but not to 
                            remove any other picked vertices; false signals to pick the given
                            vertex and to clear any other picked vertices
        """

    def removePickingListener(self, pickListener: PickListener[V]):
        ...



__all__ = ["PickListener", "GPickedState"]
