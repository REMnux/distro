from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import edu.uci.ics.jung.graph # type: ignore
import edu.uci.ics.jung.graph.util # type: ignore
import ghidra.graph
import java.lang # type: ignore
import java.util # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class JungToGDirectedGraphAdapter(ghidra.graph.GDirectedGraph[V, E], typing.Generic[V, E]):
    """
    A class that turns a :obj:`Graph` into a :obj:`GDirectedGraph`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: edu.uci.ics.jung.graph.Graph[V, E]):
        ...

    @typing.overload
    def addEdge(self, edge: E, vertices: collections.abc.Sequence) -> bool:
        ...

    @typing.overload
    def addEdge(self, e: E, v1: V, v2: V) -> bool:
        ...

    @typing.overload
    def addEdge(self, edge: E, vertices: collections.abc.Sequence, edge_type: edu.uci.ics.jung.graph.util.EdgeType) -> bool:
        ...

    @typing.overload
    def addEdge(self, e: E, v1: V, v2: V, edgeType: edu.uci.ics.jung.graph.util.EdgeType) -> bool:
        ...

    def degree(self, vertex: V) -> int:
        ...

    def findEdgeSet(self, v1: V, v2: V) -> java.util.Collection[E]:
        ...

    def getDefaultEdgeType(self) -> edu.uci.ics.jung.graph.util.EdgeType:
        ...

    def getDest(self, directed_edge: E) -> V:
        ...

    def getEdgeCount(self, edge_type: edu.uci.ics.jung.graph.util.EdgeType) -> int:
        ...

    def getEdgeType(self, edge: E) -> edu.uci.ics.jung.graph.util.EdgeType:
        ...

    def getEdges(self, edge_type: edu.uci.ics.jung.graph.util.EdgeType) -> java.util.Collection[E]:
        ...

    def getEndpoints(self, edge: E) -> edu.uci.ics.jung.graph.util.Pair[V]:
        ...

    def getIncidentCount(self, edge: E) -> int:
        ...

    def getIncidentVertices(self, edge: E) -> java.util.Collection[V]:
        ...

    def getNeighborCount(self, vertex: V) -> int:
        ...

    def getNeighbors(self, vertex: V) -> java.util.Collection[V]:
        ...

    def getOpposite(self, vertex: V, edge: E) -> V:
        ...

    def getPredecessorCount(self, vertex: V) -> int:
        ...

    def getSource(self, directed_edge: E) -> V:
        ...

    def getSuccessorCount(self, vertex: V) -> int:
        ...

    def inDegree(self, vertex: V) -> int:
        ...

    def isDest(self, vertex: V, edge: E) -> bool:
        ...

    def isIncident(self, vertex: V, edge: E) -> bool:
        ...

    def isNeighbor(self, v1: V, v2: V) -> bool:
        ...

    def isPredecessor(self, v1: V, v2: V) -> bool:
        ...

    def isSource(self, vertex: V, edge: E) -> bool:
        ...

    def isSuccessor(self, v1: V, v2: V) -> bool:
        ...

    def outDegree(self, vertex: V) -> int:
        ...

    @property
    def neighborCount(self) -> jpype.JInt:
        ...

    @property
    def defaultEdgeType(self) -> edu.uci.ics.jung.graph.util.EdgeType:
        ...

    @property
    def endpoints(self) -> edu.uci.ics.jung.graph.util.Pair[V]:
        ...

    @property
    def incidentCount(self) -> jpype.JInt:
        ...

    @property
    def neighbors(self) -> java.util.Collection[V]:
        ...

    @property
    def edgeType(self) -> edu.uci.ics.jung.graph.util.EdgeType:
        ...

    @property
    def edgeCount(self) -> jpype.JInt:
        ...

    @property
    def edges(self) -> java.util.Collection[E]:
        ...

    @property
    def predecessorCount(self) -> jpype.JInt:
        ...

    @property
    def source(self) -> V:
        ...

    @property
    def dest(self) -> V:
        ...

    @property
    def incidentVertices(self) -> java.util.Collection[V]:
        ...

    @property
    def successorCount(self) -> jpype.JInt:
        ...


class JungDirectedGraph(edu.uci.ics.jung.graph.DirectedSparseGraph[V, E], ghidra.graph.GDirectedGraph[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["JungToGDirectedGraphAdapter", "JungDirectedGraph"]
