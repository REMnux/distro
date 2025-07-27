from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.graph
import ghidra.util.datastruct
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class SorterException(java.lang.Exception):
    """
    Occurs when a graph cannot be sorted
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, desc: typing.Union[java.lang.String, str], v1: java.lang.Object, v2: java.lang.Object):
        ...

    @typing.overload
    def __init__(self, desc: typing.Union[java.lang.String, str], vs: collections.abc.Sequence):
        ...


class TarjanStronglyConnectedAlgorthm(java.lang.Object, typing.Generic[V, E]):

    @typing.type_check_only
    class TarjanVertexInfo(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        index: jpype.JInt
        lowLink: jpype.JInt

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, g: ghidra.graph.GDirectedGraph[V, E]):
        ...

    def getConnectedComponents(self) -> java.util.Set[java.util.Set[V]]:
        ...

    @property
    def connectedComponents(self) -> java.util.Set[java.util.Set[V]]:
        ...


class DijkstraShortestPathsAlgorithm(java.lang.Object, typing.Generic[V, E]):
    """
    Dijkstra's shortest-path algorithm
     
     
    
    This implementation computes the shortest paths between two vertices using Dijkstra's
    single-source shortest path finding algorithm. Any time a new source is given, it explores all
    destinations in the graph up to a maximum distance from the source. Thus, this implementation is
    best applied when many queries are anticipated from relatively few sources.
    """

    @typing.type_check_only
    class OneSourceToAll(java.lang.Object):
        """
        A class representing all optimal paths from a given source to every other (reachable) vertex
        in the graph
         
         
        
        This is the workhorse of path computation, and implements Dijkstra's Shortest Path algorithm
        from one source to all destinations. We considered using JUNG to store the graph and compute
        the paths, but we could not, because we would like to find all paths having the optimal
        distance. If there are ties, JUNG's implementation chooses one arbitrarily; we would like all
        tied paths.
        """

        class_: typing.ClassVar[java.lang.Class]

        def computeOptimalPathsTo(self, dst: V) -> java.util.Collection[java.util.Deque[E]]:
            """
            Recover the shortest paths from the source to the given destination, if it is reachable
            
            :param V dst: the destination
            :return: a collection of the shortest paths from source to destination, or the empty set
            :rtype: java.util.Collection[java.util.Deque[E]]
            """


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, graph: ghidra.graph.GImplicitDirectedGraph[V, E]):
        """
        Use Dijkstra's algorithm on the given graph
         
         
        
        This constructor assumes the graph's edges are :obj:`GWeightedEdge`s. If not, you will
        likely encounter a :obj:`ClassCastException`.
        
        :param ghidra.graph.GImplicitDirectedGraph[V, E] graph: the graph
        """

    @typing.overload
    def __init__(self, graph: ghidra.graph.GImplicitDirectedGraph[V, E], maxDistance: typing.Union[jpype.JDouble, float]):
        """
        Use Dijkstra's algorithm on the given graph with the given maximum distance
         
         
        
        This constructor assumes the graph's edges are :obj:`GWeightedEdge`s. If not, you will
        likely encounter a :obj:`ClassCastException`.
        
        :param ghidra.graph.GImplicitDirectedGraph[V, E] graph: the graph
        :param jpype.JDouble or float maxDistance: the maximum distance, or null for no maximum
        """

    @typing.overload
    def __init__(self, graph: ghidra.graph.GImplicitDirectedGraph[V, E], metric: ghidra.graph.GEdgeWeightMetric[E]):
        """
        Use Dijstra's algorithm on the given graph with a custom edge weight metric
        
        :param ghidra.graph.GImplicitDirectedGraph[V, E] graph: the graph
        :param ghidra.graph.GEdgeWeightMetric[E] metric: the function to compute the weight of an edge
        """

    @typing.overload
    def __init__(self, graph: ghidra.graph.GImplicitDirectedGraph[V, E], maxDistance: typing.Union[jpype.JDouble, float], metric: ghidra.graph.GEdgeWeightMetric[E]):
        """
        Use Dijstra's algorithm on the given graph with the given maximum distance and a custom edge
        weight metric
        
        :param ghidra.graph.GImplicitDirectedGraph[V, E] graph: the graph
        :param jpype.JDouble or float maxDistance: the maximum distance, or null for no maximum
        :param ghidra.graph.GEdgeWeightMetric[E] metric: the function to compute the weight of an edge
        """

    def computeOptimalPaths(self, src: V, dst: V) -> java.util.Collection[java.util.Deque[E]]:
        """
        Compute the shortest paths from the given source to the given destination
         
         
        
        This implementation differs from typical implementations in that paths tied for the shortest
        distance are all returned. Others tend to choose one arbitrarily.
        
        :param V src: the source
        :param V dst: the destination
        :return: a collection of paths of shortest distance from source to destination
        :rtype: java.util.Collection[java.util.Deque[E]]
        """

    def getDistancesFromSource(self, v: V) -> java.util.Map[V, java.lang.Double]:
        """
        Compute the shortest distance to all reachable vertices from the given source
        
        :param V v: the source vertex
        :return: a map of destinations to distances from the given source
        :rtype: java.util.Map[V, java.lang.Double]
        """

    @property
    def distancesFromSource(self) -> java.util.Map[V, java.lang.Double]:
        ...


class ChkDominanceAlgorithm(AbstractDominanceAlgorithm[V, E], typing.Generic[V, E]):
    """
    This algorithm is an implementation of the Cooper, Harvey, Kennedy algorithm.  
     
     
    The algorithm processes the graph in reverse post-order.  The runtime of 
    this algorithm is approximately ``O(V+E*D)`` per iteration of the loop, where 
    D is the size of the largest dominator set.  The number of iterations is 
    bound at ``d(G) + 3``, where d(G) is the "loop 
    connectedness" of the graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, g: ghidra.graph.GDirectedGraph[V, E], monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor.
        
        :param ghidra.graph.GDirectedGraph[V, E] g: the graph
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :raises CancelledException: if the algorithm is cancelled
        :raises IllegalArgumentException: if there are no source vertices in the graph
        """

    def clear(self):
        """
        Releases cached values used by internal data structures
        """

    def getDominanceTree(self) -> ghidra.graph.GDirectedGraph[V, ghidra.graph.GEdge[V]]:
        """
        Returns the dominance tree for the given graph, which is tree where each 
        node's children are those nodes it *immediately* dominates (a idom b).
        
        :return: the dominance tree
        :rtype: ghidra.graph.GDirectedGraph[V, ghidra.graph.GEdge[V]]
        """

    def getDominated(self, a: V) -> java.util.Set[V]:
        """
        Returns all nodes dominated by the given vertex.  A node 'a' dominates node 'b' if 
        all paths from start to 'b' contain 'a'.
        
        :param V a: the vertex
        :return: the dominated vertices
        :rtype: java.util.Set[V]
        """

    def getDominators(self, a: V) -> java.util.Set[V]:
        """
        Returns all nodes that dominate the given vertex.  A node 'a' dominates node 'b' if 
        all paths from start to 'b' contain 'a'.
        
        :param V a: the vertex
        :return: the dominating vertices
        :rtype: java.util.Set[V]
        """

    @property
    def dominated(self) -> java.util.Set[V]:
        ...

    @property
    def dominanceTree(self) -> ghidra.graph.GDirectedGraph[V, ghidra.graph.GEdge[V]]:
        ...

    @property
    def dominators(self) -> java.util.Set[V]:
        ...


class FindPathsAlgorithm(java.lang.Object, typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def findPaths(self, g: ghidra.graph.GDirectedGraph[V, E], start: V, end: V, accumulator: ghidra.util.datastruct.Accumulator[java.util.List[V]], monitor: ghidra.util.task.TaskMonitor):
        ...

    def setStatusListener(self, listener: GraphAlgorithmStatusListener[V]):
        ...


class RecursiveFindPathsAlgorithm(FindPathsAlgorithm[V, E], typing.Generic[V, E]):
    """
    Finds all paths between two vertices for a given graph.
     
     
    **Warning:** This is a recursive algorithm.  As such, it is limited in how deep 
    it can recurse.   Any path that exceeds the :obj:`.JAVA_STACK_DEPTH_LIMIT` will not be found.
     
     
    Note: this algorithm is based entirely on the :obj:`JohnsonCircuitsAlgorithm`.
    """

    class_: typing.ClassVar[java.lang.Class]
    JAVA_STACK_DEPTH_LIMIT: typing.Final = 2700

    def __init__(self):
        ...


class JohnsonCircuitsAlgorithm(java.lang.Object, typing.Generic[V, E]):
    """
    Finds all circuits (loops) in the given graph.
     
     
    **Warning:** This is a recursive algorithm.  As such, it is limited in how deep 
    it can recurse.   Any path that exceeds the :obj:`.JAVA_STACK_DEPTH_LIMIT` will not be found.
    """

    class_: typing.ClassVar[java.lang.Class]
    JAVA_STACK_DEPTH_LIMIT: typing.Final = 2700

    def __init__(self, g: ghidra.graph.GDirectedGraph[V, E], accumulator: ghidra.util.datastruct.Accumulator[java.util.List[V]]):
        ...

    def compute(self, uniqueCircuits: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Finds the circuits in the graph passed at construction time.
        
        :param jpype.JBoolean or bool uniqueCircuits: true signals to return only unique circuits, where no two 
                circuits will contain the same vertex
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises CancelledException: if the monitor is cancelled
        """


@typing.type_check_only
class AbstractDominanceAlgorithm(java.lang.Object, typing.Generic[V, E]):
    """
    A general base class for sharing code between graph algorithm implementations.
    """

    class_: typing.ClassVar[java.lang.Class]


class GraphAlgorithmStatusListener(java.lang.Object, typing.Generic[V]):
    """
    An interface and state values used to follow the state of vertices as they are processed by 
    algorithms
    """

    class STATUS(java.lang.Enum[GraphAlgorithmStatusListener.STATUS]):

        class_: typing.ClassVar[java.lang.Class]
        WAITING: typing.Final[GraphAlgorithmStatusListener.STATUS]
        SCHEDULED: typing.Final[GraphAlgorithmStatusListener.STATUS]
        EXPLORING: typing.Final[GraphAlgorithmStatusListener.STATUS]
        BLOCKED: typing.Final[GraphAlgorithmStatusListener.STATUS]
        IN_PATH: typing.Final[GraphAlgorithmStatusListener.STATUS]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GraphAlgorithmStatusListener.STATUS:
            ...

        @staticmethod
        def values() -> jpype.JArray[GraphAlgorithmStatusListener.STATUS]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def finished(self):
        ...

    def getTotalStatusChanges(self) -> int:
        ...

    def statusChanged(self, v: V, s: GraphAlgorithmStatusListener.STATUS):
        ...

    @property
    def totalStatusChanges(self) -> jpype.JInt:
        ...


class IterativeFindPathsAlgorithm(FindPathsAlgorithm[V, E], typing.Generic[V, E]):
    """
    Finds all paths between two vertices for a given graph.
     
     
    Note: this algorithm is based on the :obj:`JohnsonCircuitsAlgorithm`, modified to be
    iterative instead of recursive.
    """

    @typing.type_check_only
    class Node(java.lang.Object):
        """
        Simple class to maintain a relationship between a given node and its children that need
        processing.  It also knows if it has been found in a path from start to end.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GraphNavigator(java.lang.Object, typing.Generic[V, E]):
    """
    The methods on this interface are meant to enable graph traversal in a way that allows 
    the underlying graph to be walked from top-down or bottom-up.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def bottomUpNavigator() -> GraphNavigator[V, E]:
        """
        Creates a bottom-down navigator, which is one that traverses the graph from the sink 
        to the source.
        
        :return: the navigator
        :rtype: GraphNavigator[V, E]
        """

    def getEdges(self, graph: ghidra.graph.GDirectedGraph[V, E], v: V) -> java.util.Collection[E]:
        """
        Gets all edges leaving the given vertex, depending upon the direction of this navigator.
        
        :param ghidra.graph.GDirectedGraph[V, E] graph: the graph
        :param V v: the vertex
        :return: the edges
        :rtype: java.util.Collection[E]
        """

    def getEnd(self, e: E) -> V:
        """
        Gets the vertex at the end of the given edge, where the 'end' of the edge depends on the
        start vertex.
        
        :param E e: the edge
        :return: the vertex
        :rtype: V
        """

    def getPredecessors(self, graph: ghidra.graph.GDirectedGraph[V, E], v: V) -> java.util.Collection[V]:
        """
        Gets all parent vertices of the given vertex, depending upon the direction of the 
        navigator.
        
        :param ghidra.graph.GDirectedGraph[V, E] graph: the graph
        :param V v: the vertex
        :return: the vertices
        :rtype: java.util.Collection[V]
        """

    def getSinks(self, graph: ghidra.graph.GDirectedGraph[V, E]) -> java.util.Set[V]:
        """
        Gets the exit vertices of the given graph.  If this is a top-down navigator, then the
        sinks are returned; otherwise, the sources are returned.
        
        :param ghidra.graph.GDirectedGraph[V, E] graph: the graph
        :return: the exits
        :rtype: java.util.Set[V]
        """

    def getSources(self, graph: ghidra.graph.GDirectedGraph[V, E]) -> java.util.Set[V]:
        """
        Gets the root vertices of the given graph.  If this is a top-down navigator, then the
        sources are returned; otherwise, the sinks are returned.
        
        :param ghidra.graph.GDirectedGraph[V, E] graph: the graph
        :return: the roots
        :rtype: java.util.Set[V]
        """

    def getSuccessors(self, graph: ghidra.graph.GDirectedGraph[V, E], v: V) -> java.util.Collection[V]:
        """
        Gets all child vertices of the given vertex, depending upon the direction of the 
        navigator.
        
        :param ghidra.graph.GDirectedGraph[V, E] graph: the graph
        :param V v: the vertex
        :return: the vertices
        :rtype: java.util.Collection[V]
        """

    def getVerticesInPostOrder(self, graph: ghidra.graph.GDirectedGraph[V, E]) -> java.util.List[V]:
        """
        Returns all vertices in the given graph in the depth-first order.   The order will 
        be post-order for a top-down navigator and pre-order for a bottom-up navigator.
        
        :param ghidra.graph.GDirectedGraph[V, E] graph: the graph
        :return: the ordered vertices
        :rtype: java.util.List[V]
        """

    def isTopDown(self) -> bool:
        """
        Returns true if this navigator processes nodes from the top down; false if nodes are
        processed from the bottom up.
        
        :return: true if this navigator processes nodes from the top down; false if nodes are
                    processed from the bottom up.
        :rtype: bool
        """

    @staticmethod
    def topDownNavigator() -> GraphNavigator[V, E]:
        """
        Creates a top-down navigator, which is one that traverses the graph from the source
        to the sink.
        
        :return: the navigator
        :rtype: GraphNavigator[V, E]
        """

    @property
    def topDown(self) -> jpype.JBoolean:
        ...

    @property
    def sources(self) -> java.util.Set[V]:
        ...

    @property
    def sinks(self) -> java.util.Set[V]:
        ...

    @property
    def end(self) -> V:
        ...

    @property
    def verticesInPostOrder(self) -> java.util.List[V]:
        ...


class DepthFirstSorter(java.lang.Object, typing.Generic[V, E]):
    """
    Processes the given graph depth first and records that order of the vertices.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def postOrder(g: ghidra.graph.GDirectedGraph[V, E]) -> java.util.List[V]:
        """
        Returns the vertices of the given graph in post-order, which is the order the vertices
        are last visited when performing a depth-first traversal.
        
        :param ghidra.graph.GDirectedGraph[V, E] g: the graph
        :return: the vertices in post-order
        :rtype: java.util.List[V]
        """

    @staticmethod
    @typing.overload
    def postOrder(g: ghidra.graph.GDirectedGraph[V, E], navigator: GraphNavigator[V, E]) -> java.util.List[V]:
        """
        Returns the vertices of the given graph in post-order, which is the order the vertices
        are last visited when performing a depth-first traversal.
        
        :param ghidra.graph.GDirectedGraph[V, E] g: the graph
        :param GraphNavigator[V, E] navigator: the knower of the direction the graph should be traversed
        :return: the vertices in post-order
        :rtype: java.util.List[V]
        """

    @staticmethod
    @typing.overload
    def preOrder(g: ghidra.graph.GDirectedGraph[V, E]) -> java.util.List[V]:
        """
        Returns the vertices of the given graph in pre-order, which is the order the vertices
        are encountered when performing a depth-first traversal.
        
        :param ghidra.graph.GDirectedGraph[V, E] g: the graph
        :return: the vertices in pre-order
        :rtype: java.util.List[V]
        """

    @staticmethod
    @typing.overload
    def preOrder(g: ghidra.graph.GDirectedGraph[V, E], navigator: GraphNavigator[V, E]) -> java.util.List[V]:
        """
        Returns the vertices of the given graph in pre-order, which is the order the vertices
        are encountered when performing a depth-first traversal.
        
        :param ghidra.graph.GDirectedGraph[V, E] g: the graph
        :param GraphNavigator[V, E] navigator: the knower of the direction the graph should be traversed
        :return: the vertices in pre-order
        :rtype: java.util.List[V]
        """


class ChkPostDominanceAlgorithm(ChkDominanceAlgorithm[V, E], typing.Generic[V, E]):
    """
    This is :obj:`ChkDominanceAlgorithm` with reverse graph traversal, which allows the
    algorithm to calculate post dominance.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, g: ghidra.graph.GDirectedGraph[V, E], monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor.
        
        :param ghidra.graph.GDirectedGraph[V, E] g: the graph
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :raises CancelledException: if the algorithm is cancelled
        """



__all__ = ["SorterException", "TarjanStronglyConnectedAlgorthm", "DijkstraShortestPathsAlgorithm", "ChkDominanceAlgorithm", "FindPathsAlgorithm", "RecursiveFindPathsAlgorithm", "JohnsonCircuitsAlgorithm", "AbstractDominanceAlgorithm", "GraphAlgorithmStatusListener", "IterativeFindPathsAlgorithm", "GraphNavigator", "DepthFirstSorter", "ChkPostDominanceAlgorithm"]
