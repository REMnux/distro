from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.graph.algo
import ghidra.graph.event
import ghidra.graph.viewer
import ghidra.graph.viewer.layout
import ghidra.program.model.symbol
import ghidra.service.graph
import ghidra.util.datastruct
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


E = typing.TypeVar("E")
G = typing.TypeVar("G")
V = typing.TypeVar("V")


class ProgramGraphType(ghidra.service.graph.GraphType):
    """
    Defines a common set of vertex and edge types :obj:`GraphType` for program code and data flow
    graphs. Each specific type of program graph will use a subclass to specifically identify the
    graph type.
    """

    class_: typing.ClassVar[java.lang.Class]
    BODY: typing.Final[java.lang.String]
    ENTRY: typing.Final[java.lang.String]
    EXIT: typing.Final[java.lang.String]
    SWITCH: typing.Final[java.lang.String]
    EXTERNAL: typing.Final[java.lang.String]
    BAD: typing.Final[java.lang.String]
    INSTRUCTION: typing.Final[java.lang.String]
    DATA: typing.Final[java.lang.String]
    ENTRY_NEXUS: typing.Final[java.lang.String]
    STACK: typing.Final[java.lang.String]
    ENTRY_EDGE: typing.Final[java.lang.String]
    FALL_THROUGH: typing.Final[java.lang.String]
    UNCONDITIONAL_JUMP: typing.Final[java.lang.String]
    UNCONDITIONAL_CALL: typing.Final[java.lang.String]
    TERMINATOR: typing.Final[java.lang.String]
    JUMP_TERMINATOR: typing.Final[java.lang.String]
    INDIRECTION: typing.Final[java.lang.String]
    CONDITIONAL_JUMP: typing.Final[java.lang.String]
    CONDITIONAL_CALL: typing.Final[java.lang.String]
    CONDITIONAL_TERMINATOR: typing.Final[java.lang.String]
    CONDITIONAL_CALL_TERMINATOR: typing.Final[java.lang.String]
    COMPUTED_JUMP: typing.Final[java.lang.String]
    COMPUTED_CALL: typing.Final[java.lang.String]
    COMPUTED_CALL_TERMINATOR: typing.Final[java.lang.String]
    CONDITIONAL_COMPUTED_CALL: typing.Final[java.lang.String]
    CONDITIONAL_COMPUTED_JUMP: typing.Final[java.lang.String]
    CALL_OVERRIDE_UNCONDITIONAL: typing.Final[java.lang.String]
    JUMP_OVERRIDE_UNCONDITIONAL: typing.Final[java.lang.String]
    CALLOTHER_OVERRIDE_CALL: typing.Final[java.lang.String]
    CALLOTHER_OVERRIDE_JUMP: typing.Final[java.lang.String]
    READ: typing.Final[java.lang.String]
    WRITE: typing.Final[java.lang.String]
    READ_WRITE: typing.Final[java.lang.String]
    UNKNOWN_DATA: typing.Final[java.lang.String]
    EXTERNAL_REF: typing.Final[java.lang.String]
    READ_INDIRECT: typing.Final[java.lang.String]
    WRITE_INDIRECT: typing.Final[java.lang.String]
    READ_WRITE_INDIRECT: typing.Final[java.lang.String]
    DATA_INDIRECT: typing.Final[java.lang.String]
    PARAM: typing.Final[java.lang.String]
    THUNK: typing.Final[java.lang.String]

    @staticmethod
    def getEdgeType(refType: ghidra.program.model.symbol.RefType) -> str:
        ...


class ProgramGraphDisplayOptions(ghidra.service.graph.GraphDisplayOptions):
    """
    :obj:`GraphDisplayOptions` for :obj:`ProgramGraphType`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graphType: ProgramGraphType, tool: ghidra.framework.plugintool.PluginTool):
        """
        constructor
        
        :param ProgramGraphType graphType: the specific ProgramGraphType subclass for these options
        :param ghidra.framework.plugintool.PluginTool tool: if non-null, will load values from tool options
        """


class CallGraphType(ProgramGraphType):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CodeFlowGraphType(ProgramGraphType):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DataFlowGraphType(ProgramGraphType):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BlockFlowGraphType(ProgramGraphType):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GWeightedEdge(GEdge[V], typing.Generic[V]):
    """
    An edge having a natural weight
    """

    class_: typing.ClassVar[java.lang.Class]

    def getWeight(self) -> float:
        """
        The natural weight of the edge
        
        :return: the weight
        :rtype: float
        """

    @property
    def weight(self) -> jpype.JDouble:
        ...


class GraphToTreeAlgorithm(java.lang.Object, typing.Generic[V, E]):
    """
    This class provides an algorithm for topological graph sorting and an algorithm for using
    that topological sort to create a tree structure from the graph using that topological sort.
     
    
    In general topological sorting and converting to a tree, require an acyclic graph. However,
    by supplying a root vertex, the graph can be made to be acyclic by traversing the graph from 
    that root and discarding any edges the return to a "visited" vertex. This has a side effect of
    ignoring any nodes that are not reachable from the root node. Also, this algorithm class is 
    constructed with an edge comparator which can also determine the order nodes are traversed,
    thereby affecting the final ordering or tree structure. Higher priority edges will be processed
    first, making those edges least likely to be removed as "back" edges.
     
    
    To convert a general graph to a tree, some subset of the graphs original edges are used to
    form the tree. There are many possible different trees that can be created in this way. This
    algorimth's goal is to create a tree such that if all the original "forward" edges are added 
    back to the tree, they only flow down the tree. This is useful for creating a nicely organized
    layout of vertices and edges when drawn.
    """

    @typing.type_check_only
    class Depth(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VertexChildIterator(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def hasNext(self) -> bool:
            ...

        def next(self) -> V:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graph: GDirectedGraph[V, E], edgeComparator: java.util.Comparator[E]):
        """
        Constructor.
        
        :param GDirectedGraph[V, E] graph: the graph from with to create a tree
        :param java.util.Comparator[E] edgeComparator: provides a priority ordering of edges with higher priority edges 
        getting first shot at claiming children for its sub-tree.
        """

    def toTree(self, root: V) -> GDirectedGraph[V, E]:
        """
        Creates a tree graph with the given vertex as the root from this object's graph.
        
        :param V root: the vertex to be used as the root
        getting first shot at claiming children for its sub-tree.
        :return: a graph with edges removed such that the graph is a tree.
        :rtype: GDirectedGraph[V, E]
        """

    def topolocigalSort(self, root: V) -> java.util.List[V]:
        """
        Sorts the vertices in this graph topologically.
        
        :param V root: the start node for traversing the graph (will always be the first node in the
        resulting list)
        :return: a list of vertices reachable from the given root vertex, sorted topologically
        :rtype: java.util.List[V]
        """


class DefaultGEdge(GEdge[V], typing.Generic[V]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: V, end: V):
        ...


class MutableGDirectedGraphWrapper(GDirectedGraph[V, E], typing.Generic[V, E]):
    """
    A class that can wrap a :obj:`GDirectedGraph` and allows for vertex and edge additions 
    without changing the underlying graph.
    
     
    **Warning: **As mentioned above, this graph is meant for additive operations.  In its
    current form, removal operations will not work.  To facilitate removals, this class will 
    have to be updated to track removed vertices and edges, using them to correctly report
    the state of the graph for methods like :meth:`containsVertex(Object) <.containsVertex>` and 
    :meth:`containsEdge(GEdge) <.containsEdge>`.
    
     
    Implementation Note: there is some 'magic' in this class to add 'dummy' vertices to the
    graph.  To facilitate this, the mutated graph in this class does not have the ``V``
    type, but rather is typed on Object.   This means that this class can only be used 
    generically, with templated types (like by algorithms and such).  Any usage of this class
    that expects concrete implementations to be returned can trigger ClassCastExceptions.
    """

    @typing.type_check_only
    class DummyVertex(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...


    class DummyEdge(DefaultGEdge[java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, start: java.lang.Object, end: java.lang.Object):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: GDirectedGraph[V, E]):
        ...

    def addDummyEdge(self, start: V, end: V) -> E:
        ...

    def addDummyVertex(self, name: typing.Union[java.lang.String, str]) -> V:
        ...

    @typing.overload
    def isDummy(self, v: V) -> bool:
        ...

    @typing.overload
    def isDummy(self, e: E) -> bool:
        ...

    @property
    def dummy(self) -> jpype.JBoolean:
        ...


class GImplicitDirectedGraph(java.lang.Object, typing.Generic[V, E]):
    """
    A directed graph that need not be constructed explicitly
     
     
    Instead, the graph is constructed (and usually cached) as it is explored. For instance, if
    a path searching algorithm is being applied, incident edges and neighboring nodes need not
    be computed if they're never visited. This allows conceptually large (even infinite) graphs to
    be represented. A graph algorithm can be applied so long as it supports this interface, and
    does not attempt to exhaust an infinite graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    def copy(self) -> GDirectedGraph[V, E]:
        """
        Copy some portion of the implicit graph to an explicit graph
         
        Usually, this returns the cached (explored) portion of the graph
        
        :return: a "copy" of this implicit graph
        :rtype: GDirectedGraph[V, E]
        """

    def getInEdges(self, v: V) -> java.util.Collection[E]:
        """
        Compute the incident edges that end at the given vertex
         
        (Optional operation)
         
        NOTE: This method ought to return cached results if available
        NOTE: As part of computing in-edges, this method will also provide predecessors
        
        :param V v: the destination vertex
        :return: the in-edges to the given vertex
        :rtype: java.util.Collection[E]
        """

    def getOutEdges(self, v: V) -> java.util.Collection[E]:
        """
        Compute the incident edges that start at the given vertex
         
        NOTE: This method ought to return cached results if available
        NOTE: As part of computing out-edges, this method will also provide successors
        
        :param V v: the source vertex
        :return: the out-edges from the given vertex
        :rtype: java.util.Collection[E]
        """

    def getPredecessors(self, v: V) -> java.util.Collection[V]:
        """
        Compute a vertex's predecessors
         
        The default implementation computes this from the in-edges
         
        NOTE: If a non-default implementation is provided, it ought to return cached results if
        available
        
        :param V v: the destination vertex
        :return: the predecessors
        :rtype: java.util.Collection[V]
        """

    def getSuccessors(self, v: V) -> java.util.Collection[V]:
        """
        Compute a vertex's successors
         
        The default implementation compute this from the out-edges
         
        NOTE: If a non-default implementation is provided, it ought to return cached results if
        available
        
        :param V v: the source vertex
        :return: the successors
        :rtype: java.util.Collection[V]
        """

    @property
    def outEdges(self) -> java.util.Collection[E]:
        ...

    @property
    def predecessors(self) -> java.util.Collection[V]:
        ...

    @property
    def successors(self) -> java.util.Collection[V]:
        ...

    @property
    def inEdges(self) -> java.util.Collection[E]:
        ...


class GraphPath(java.lang.Object, typing.Generic[V]):
    """
    Class for storing paths with fast "contains" method.
    
     
    Note: a path can only contain a vertex once.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor.
        """

    @typing.overload
    def __init__(self, v: V):
        """
        Constructor with a vertex.
        
        :param V v: the first vertex of the newly initialized GraphPath object
        """

    def add(self, v: V):
        """
        Add a vertex to the GraphPath.
        
        :param V v: the new vertex
        """

    def contains(self, v: V) -> bool:
        """
        Check if vertex v is in the GraphPath.
        
        :param V v: the vertex
        :return: true if vertex v is in this GraphPath
        :rtype: bool
        """

    def copy(self) -> GraphPath[V]:
        """
        Creates a new GraphPath object by performing a shallow copy on another GraphPath object.
        
        :return: the new shallow copy of the original GraphPath object
        :rtype: GraphPath[V]
        """

    def depth(self, v: V) -> int:
        """
        Get the depth of the vertex that is specified by the parameter.
        
        :param V v: the vertex for which we get the depth
        :return: the depth of the vertex
        :rtype: int
        """

    def get(self, depth: typing.Union[jpype.JInt, int]) -> V:
        """
        Get vertex that is specified by the parameter.
        
        :param jpype.JInt or int depth: of the vertex to retrieve
        :return: the vertex
        :rtype: V
        """

    def getCommonStartPath(self, other: GraphPath[V]) -> GraphPath[V]:
        """
        Return all vertices that two GraphPaths have in common. For example if you have
        a-b-c-d-e-f and a-b-c-d-k-l-z, the common start path will be a-b-c-d. If there is no common
        start path, an empty GraphPath object is returned.
        
        :param GraphPath[V] other: the other GraphPath to get the common start path of
        :return: a new GraphPath object containing the common start path vertices
        :rtype: GraphPath[V]
        """

    def getLast(self) -> V:
        """
        Get last vertex of GraphPath.
        
        :return: last vertex of GraphPath
        :rtype: V
        """

    def getPredecessors(self, v: V) -> java.util.Set[V]:
        """
        Return a set with all of the predecessors of the vertex in the GraphPath.
        
        :param V v: the vertex we want to get the predecessors of
        :return: the predecessors of the vertex as a set, return empty set if there are none
        :rtype: java.util.Set[V]
        """

    def getSuccessors(self, v: V) -> java.util.Set[V]:
        """
        Return a set with all of the successors of the vertex in the GraphPath.
        
        :param V v: the vertex we want to get the successors of
        :return: the successors of the vertex as a set, return empty set if there are none
        :rtype: java.util.Set[V]
        """

    def removeLast(self) -> V:
        """
        Remove the last vertex of the GraphPath.
        
        :return: the removed vertex
        :rtype: V
        """

    def size(self) -> int:
        """
        Return the size of the GraphPath.
        
        :return: size of the GraphPath
        :rtype: int
        """

    def startsWith(self, otherPath: GraphPath[V]) -> bool:
        """
        Check if a GraphPath starts with another GraphPath.
        
        :param GraphPath[V] otherPath: the other GraphPath we are checking
        :return: true if the current GraphPath starts with otherPath, false otherwise
        :rtype: bool
        """

    def subPath(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]) -> GraphPath[V]:
        """
        Get a part of the whole GraphPath, similar to substring with strings.
        
        :param jpype.JInt or int start: the start of the sub-path of the GraphPath
        :param jpype.JInt or int end: the end of the sub-path of the GraphPath
        :return: a new GraphPath which is a sub-path of the original GraphPath from start to end
        :rtype: GraphPath[V]
        """

    @property
    def predecessors(self) -> java.util.Set[V]:
        ...

    @property
    def commonStartPath(self) -> GraphPath[V]:
        ...

    @property
    def last(self) -> V:
        ...

    @property
    def successors(self) -> java.util.Set[V]:
        ...


class GDirectedGraph(GImplicitDirectedGraph[V, E], typing.Generic[V, E]):
    """
    A directed graph
     
    Unlike :obj:`GImplicitDirectedGraph`, this graph is constructed explicitly
    in memory. Edges and vertices are added and removed like any other
    collection, and these elements represent the entirety of the graph at any
    given time.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addEdge(self, e: E):
        """
        Add an edge
        
        :param E e: the edge
        """

    def addVertex(self, v: V) -> bool:
        """
        Add a vertex
        
        :param V v: the vertex
        :return: true if the add was successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def containsEdge(self, e: E) -> bool:
        """
        Test if the graph contains a given edge
        
        :param E e: the ege
        :return: true if the edge is in the graph, or false
        :rtype: bool
        """

    @typing.overload
    def containsEdge(self, from_: V, to: V) -> bool:
        """
        Test if the graph contains an edge from one given vertex to another
        
        :param V from: the source vertex
        :param V to: the destination vertex
        :return: true if such an edge exists, or false
        :rtype: bool
        """

    def containsVertex(self, v: V) -> bool:
        """
        Test if the graph contains a given vertex
        
        :param V v: the vertex
        :return: true if the vertex is in the graph, or false
        :rtype: bool
        """

    def copy(self) -> GDirectedGraph[V, E]:
        """
        Copy this graph.
         
         
        
        Note: the vertices and edges in the copy may be the same instances in the
        new graph and not themselves copies.
        
        :return: the new copy
        :rtype: GDirectedGraph[V, E]
        """

    def emptyCopy(self) -> GDirectedGraph[V, E]:
        """
        Creates a new instance of this graph with no vertices or edges. This is
        useful when you wish to build a new graph using the same type as this
        graph.
        
        :return: the new copy
        :rtype: GDirectedGraph[V, E]
        """

    def findEdge(self, start: V, end: V) -> E:
        """
        Locates the edge object for the two vertices
        
        :param V start: the start vertex
        :param V end: the end vertex
        :return: the edge
        :rtype: E
        """

    def getEdgeCount(self) -> int:
        """
        Count the number of edges in the graph
        
        :return: the count
        :rtype: int
        """

    def getEdges(self) -> java.util.Collection[E]:
        """
        Retrieve all the edges
        
        :return: the edges
        :rtype: java.util.Collection[E]
        """

    def getInEdges(self, v: V) -> java.util.Collection[E]:
        """
        Compute the incident edges that end at the given vertex
        
        :param V v: the destination vertex
        :return: the in-edges to the given vertex
        :rtype: java.util.Collection[E]
        """

    def getIncidentEdges(self, v: V) -> java.util.Collection[E]:
        """
        Returns all edges connected to the given vertex
        
        :param V v: the vertex
        :return: the edges
        :rtype: java.util.Collection[E]
        """

    def getOutEdges(self, v: V) -> java.util.Collection[E]:
        """
        Compute the incident edges that start at the given vertex
        
        :param V v: the source vertex
        :return: the out-edges from the given vertex
        :rtype: java.util.Collection[E]
        """

    def getPredecessors(self, v: V) -> java.util.Collection[V]:
        """
        Compute a vertex's predecessors
         
         
        
        The default implementation computes this from the in-edges
        
        :param V v: the destination vertex
        :return: the predecessors
        :rtype: java.util.Collection[V]
        """

    def getSuccessors(self, v: V) -> java.util.Collection[V]:
        """
        Compute a vertex's successors
         
         
        
        The default implementation compute this from the out-edges
        
        :param V v: the source vertex
        :return: the successors
        :rtype: java.util.Collection[V]
        """

    def getVertexCount(self) -> int:
        """
        Count the number of vertices in the graph
        
        :return: the count
        :rtype: int
        """

    def getVertices(self) -> java.util.Collection[V]:
        """
        Retrieve all the vertices
        
        :return: the vertices
        :rtype: java.util.Collection[V]
        """

    def isEmpty(self) -> bool:
        """
        Test if the graph is empty, i.e., contains no vertices or edges
        
        :return: true if the graph is empty, or false
        :rtype: bool
        """

    def removeEdge(self, e: E) -> bool:
        """
        Removes an edge
        
        :param E e: the edge
        :return: true if the graph contained the given edge
        :rtype: bool
        """

    def removeEdges(self, edges: collections.abc.Sequence):
        """
        Removes the given edges from the graph
        
        :param collections.abc.Sequence edges: the edges to remove
        """

    def removeVertex(self, v: V) -> bool:
        """
        Remove a vertex
        
        :param V v: the vertex
        :return: true
        :rtype: bool
        """

    def removeVertices(self, vertices: collections.abc.Sequence):
        """
        Removes the given vertices from the graph
        
        :param collections.abc.Sequence vertices: the vertices to remove
        """

    @property
    def outEdges(self) -> java.util.Collection[E]:
        ...

    @property
    def predecessors(self) -> java.util.Collection[V]:
        ...

    @property
    def incidentEdges(self) -> java.util.Collection[E]:
        ...

    @property
    def vertices(self) -> java.util.Collection[V]:
        ...

    @property
    def edgeCount(self) -> jpype.JInt:
        ...

    @property
    def successors(self) -> java.util.Collection[V]:
        ...

    @property
    def edges(self) -> java.util.Collection[E]:
        ...

    @property
    def vertexCount(self) -> jpype.JInt:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def inEdges(self) -> java.util.Collection[E]:
        ...


class GEdgeWeightMetric(java.lang.Object, typing.Generic[E]):
    """
    A callback to get the weight of an edge
     
    Analogous to Java's :obj:`Comparator`, this provides a means to override the weight of an edge
    in a graph, or provide a weight in the absence of a natural weight, when executing various graph
    algorithms, e.g., shortest path.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNIT_METRIC: typing.Final[GEdgeWeightMetric[typing.Any]]
    NATURAL_METRIC: typing.Final[GEdgeWeightMetric[typing.Any]]

    def computeWeight(self, e: E) -> float:
        """
        Compute or retrieve the weight of the given edge
        
        :param E e: the edge
        :return: the weight
        :rtype: float
        """

    @staticmethod
    def naturalMetric() -> GEdgeWeightMetric[E]:
        """
        Use the natural weight of each edge
         
        The metric assumes every edge is a :obj:`GWeightedEdge`. If not, you will likely encounter
        a :obj:`ClassCastException`.
        
        :return: the metric
        :rtype: GEdgeWeightMetric[E]
        """

    @staticmethod
    def unitMetric() -> GEdgeWeightMetric[E]:
        """
        Measure every edge as having a weight of 1
        
        :return: the metric
        :rtype: GEdgeWeightMetric[E]
        """


class VisualGraphComponentProvider(docking.ComponentProvider, typing.Generic[V, E, G]):
    """
    A base component provider for displaying :obj:`VisualGraph`s
     
     
    This class will provide many optional sub-features, enabled as desired by calling the
    various ``addXyzFeature()`` methods.
     
     
    Implementation Notes:   to get full functionality, you must:
     
    * Have your plugin call :meth:`readConfigState(SaveState) <.readConfigState>` and
    :meth:`writeConfigState(SaveState) <.writeConfigState>` to save user settings.
    
    * Enable features you desire after calling your :meth:`addToTool() <.addToTool>` method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        To be called at the end of this provider's lifecycle
        """

    def getSelectedVertices(self) -> java.util.Set[V]:
        ...

    def getView(self) -> ghidra.graph.viewer.VisualGraphView[V, E, G]:
        """
        You must return your graph view from this method
        
        :return: your graph view
        :rtype: ghidra.graph.viewer.VisualGraphView[V, E, G]
        """

    def isSatelliteDocked(self) -> bool:
        """
        Returns true if the satellite is embedded in the graph view, whether it is showing or not
        
        :return: true if the satellite is embedded in the graph view, whether it is showing or not
        :rtype: bool
        """

    def isSatelliteShowing(self) -> bool:
        """
        Returns true if the satellite is showing, whether in the graph or undocked
        
        :return: true if the satellite is showing, whether in the graph or undocked
        :rtype: bool
        """

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        """
        Reads previously saved state from the given state object
        
        :param ghidra.framework.options.SaveState saveState: the state object that may contain state information for this provider
        """

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        """
        Writes this providers saveable state to the given state object
        
        :param ghidra.framework.options.SaveState saveState: the state object into which state is to be written
        """

    @property
    def view(self) -> ghidra.graph.viewer.VisualGraphView[V, E, G]:
        ...

    @property
    def satelliteDocked(self) -> jpype.JBoolean:
        ...

    @property
    def satelliteShowing(self) -> jpype.JBoolean:
        ...

    @property
    def selectedVertices(self) -> java.util.Set[V]:
        ...


class GraphFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createDirectedGraph() -> GDirectedGraph[V, E]:
        ...


class GraphPathSet(java.lang.Object, typing.Generic[V]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, path: GraphPath[V]):
        ...

    def containSomePathStartingWith(self, otherPath: GraphPath[V]) -> bool:
        ...

    def getPathsContaining(self, v: V) -> java.util.Set[GraphPath[V]]:
        ...

    def size(self) -> int:
        ...

    @property
    def pathsContaining(self) -> java.util.Set[GraphPath[V]]:
        ...


class GVertex(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class VisualGraph(GDirectedGraph[V, E], typing.Generic[V, E]):
    """
    The primary interface for graphs that are to be rendered.  This class defines methods 
    commonly used in the GUI while extending the primary non-visual graph interface.
     
     
    The Visual Graph API will typically provide services for taking a Visual Graph and 
    creating a UI that handles basic user interaction elements (similar to how complex Java
    widgets handle user interaction for the developer).  The Visual Graph is the model of the
    UI components.  A typical Visual Graph UI will render developer-defined components, 
    handling mouse event translations for the developer. 
      
     
    Some features found in Visual Graphs:
     
    * Mouse event translation - the JComponent being rendered in the graph will be handed 
        mouse events that are relative to its coordinate space, not that of the graph.
    
    * Hover and Selection - vertex hover and selection events are handled by the API
    
    * Zooming - zoom level and related events (when zoomed too far, mouse events are 
        not passed-through to the component) and handled by the API
    """

    class_: typing.ClassVar[java.lang.Class]

    def addGraphChangeListener(self, l: ghidra.graph.event.VisualGraphChangeListener[V, E]):
        """
        Adds the given listener to this graph
        
        :param ghidra.graph.event.VisualGraphChangeListener[V, E] l: the listener
        """

    def clearSelectedVertices(self):
        """
        Clears any selected vertices as well as the focused vertex
        """

    def getFocusedVertex(self) -> V:
        """
        Returns the focused vertex; null if no vertex has focus.  Focus is equivalent to 
        being selected, but further distinguishes the vertex as being the only selected 
        vertex.  This is useful for key event processing.
        
        :return: the focused vertex
        :rtype: V
        """

    def getLayout(self) -> ghidra.graph.viewer.layout.VisualGraphLayout[V, E]:
        """
        Returns the layout that has been applied to the graph.  The graph does not need its 
        layout to function, but rather it is convenient for the visual graph system to be able
        to get the layout from the graph, rather than passing the layout everywhere it is 
        needed.
        
        :return: the layout applied to the graph
        :rtype: ghidra.graph.viewer.layout.VisualGraphLayout[V, E]
        """

    def getSelectedVertices(self) -> java.util.Set[V]:
        """
        Returns the selected vertices.
        
        :return: the selected vertices
        :rtype: java.util.Set[V]
        """

    def removeGraphChangeListener(self, l: ghidra.graph.event.VisualGraphChangeListener[V, E]):
        """
        Removes the given listener from this graph
        
        :param ghidra.graph.event.VisualGraphChangeListener[V, E] l: the listener
        """

    def setSelectedVertices(self, vertices: java.util.Set[V]):
        """
        Selects the given vertices
         
         
        Note: this method is called by other APIs to ensure that the graph's notion of the 
        focused vertex matches what is happening externally (e.g., from the user clicking the
        screen).  If you wish to programmatically select a vertex, then you should not be calling
        this API directly, but you should instead be using the :obj:`GPickedState` or one
        of the APIs that uses that, such as the :obj:`GraphComponent`.
        
        :param java.util.Set[V] vertices: the vertices
        """

    def setVertexFocused(self, v: V, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the given vertex to be focused or not
         
         
        Note: this method is called by other APIs to ensure that the graph's notion of the 
        focused vertex matches what is happening externally (e.g., from the user clicking the
        screen).  If you wish to programmatically focus a vertex, then you should not be calling
        this API directly, but you should instead be using the :obj:`GPickedState` or one
        of the APIs that uses that, such as the :obj:`GraphComponent`.
        
        :param V v: the focused vertex
        :param jpype.JBoolean or bool b: true for focused; false for not focused
        """

    def vertexLocationChanged(self, v: V, point: java.awt.Point, changeType: ghidra.graph.viewer.layout.LayoutListener.ChangeType):
        """
        A callback notifying this graph that the given vertex's location has changed
        
        :param V v: the vertex
        :param java.awt.Point point: the new location
        :param ghidra.graph.viewer.layout.LayoutListener.ChangeType changeType: the type of change
        """

    @property
    def layout(self) -> ghidra.graph.viewer.layout.VisualGraphLayout[V, E]:
        ...

    @property
    def selectedVertices(self) -> java.util.Set[V]:
        ...

    @selectedVertices.setter
    def selectedVertices(self, value: java.util.Set[V]):
        ...

    @property
    def focusedVertex(self) -> V:
        ...


class GraphAlgorithms(java.lang.Object):
    """
    A set of convenience methods for performing graph algorithms on a graph.
     
     
    Some definitions:
     
    1. dominance: 
            a node 'a' dominates node 'b' if all paths from start to 'b' contain 'a';
            a node always dominates itself (except in 'strict dominance', which is all
            dominators except for itself)
    
    2. post-dominance: 
        A node 'b' is said to post-dominate node 'a' if all paths from 'a'
            to END contain 'b'
    
    3. immediate dominator: 
        the closest dominator of a node
    
    4. dominance tree:  
        A dominator tree is a tree where each node's children are those nodes
        it *immediately* dominates (a idom b)
    
    5. dominance frontier: 
                    the immediate successors of the nodes dominated by 'a'; it is the set of
                    nodes where d's dominance stops.
    
    6. strongly connected components: 
                    a graph is said to be strongly connected if every vertex is reachable
                    from every other vertex. The strongly connected components
                    of an arbitrary directed graph form a partition into
                    subgraphs that are themselves strongly connected.
    
    7. graph density:
                            E
            Density =  --------
                        V(V-1)
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createSubGraph(g: GDirectedGraph[V, E], vertices: collections.abc.Sequence) -> GDirectedGraph[V, E]:
        """
        Creates a subgraph of the given graph for each edge of the given graph that is 
        contained in the list of vertices.
        
        :param GDirectedGraph[V, E] g: the existing graph
        :param collections.abc.Sequence vertices: the vertices to be in the new graph
        :return: the new subgraph
        :rtype: GDirectedGraph[V, E]
        """

    @staticmethod
    @typing.overload
    def findCircuits(g: GDirectedGraph[V, E], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[java.util.List[V]]:
        """
        Finds all the circuits, or cycles, in the given graph.
        
        :param GDirectedGraph[V, E] g: the graph
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the circuits
        :rtype: java.util.List[java.util.List[V]]
        :raises CancelledException: if the monitor is cancelled
        """

    @staticmethod
    @typing.overload
    def findCircuits(g: GDirectedGraph[V, E], uniqueCircuits: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[java.util.List[V]]:
        """
        Finds all the circuits, or cycles, in the given graph.
        
        :param GDirectedGraph[V, E] g: the graph
        :param jpype.JBoolean or bool uniqueCircuits: true signals to return only unique circuits, where no two 
                circuits will contain the same vertex
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the circuits
        :rtype: java.util.List[java.util.List[V]]
        :raises CancelledException: if the monitor is cancelled
        """

    @staticmethod
    @typing.overload
    def findCircuits(g: GDirectedGraph[V, E], uniqueCircuits: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TimeoutTaskMonitor) -> java.util.List[java.util.List[V]]:
        """
        Finds all the circuits, or cycles, in the given graph.  **This version
        of ``findCircuits()`` takes a :obj:`TimeoutTaskMonitor`, which allows for the 
        client to control the duration of work.**   This is useful for finding paths on very
        large, dense graphs.
        
        :param GDirectedGraph[V, E] g: the graph
        :param jpype.JBoolean or bool uniqueCircuits: true signals to return only unique circuits, where no two 
                circuits will contain the same vertex
        :param ghidra.util.task.TimeoutTaskMonitor monitor: the timeout task monitor
        :return: the circuits
        :rtype: java.util.List[java.util.List[V]]
        :raises CancelledException: if the monitor is cancelled
        :raises TimeoutException: if the algorithm times-out, as defined by the monitor
        """

    @staticmethod
    def findDominance(g: GDirectedGraph[V, E], from_: V, monitor: ghidra.util.task.TaskMonitor) -> java.util.Set[V]:
        """
        Returns a set of all vertices that are dominated by the given vertex.  A node 'a' 
        dominates node 'b' if all paths from start to 'b' contain 'a';
        a node always dominates itself (except in 'strict dominance', which is all
        dominators except for itself)
        
        :param GDirectedGraph[V, E] g: the graph
        :param V from: the vertex for which to find dominated vertices
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :return: the set of dominated vertices
        :rtype: java.util.Set[V]
        :raises CancelledException: if the monitor is cancelled
        """

    @staticmethod
    def findDominanceTree(g: GDirectedGraph[V, E], monitor: ghidra.util.task.TaskMonitor) -> GDirectedGraph[V, GEdge[V]]:
        """
        Returns the dominance tree of the given graph.  A dominator tree of the vertices where each 
        node's children are those nodes it *immediately* dominates (a idom b)
        
        :param GDirectedGraph[V, E] g: the graph
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the tree
        :rtype: GDirectedGraph[V, GEdge[V]]
        :raises CancelledException: if the monitor is cancelled
        """

    @staticmethod
    @typing.overload
    def findPaths(g: GDirectedGraph[V, E], start: V, end: V, accumulator: ghidra.util.datastruct.Accumulator[java.util.List[V]], monitor: ghidra.util.task.TaskMonitor):
        """
        Finds all paths from ``start`` to ``end`` in the given graph.
         
         
        **Warning:** for large, dense graphs (those with many interconnected 
        vertices) this algorithm could run indeterminately, possibly causing the JVM to 
        run out of memory.
         
         
        You are encouraged to call this method with a monitor that will limit the work to 
        be done, such as the :obj:`TimeoutTaskMonitor`.
        
        :param GDirectedGraph[V, E] g: the graph
        :param V start: the start vertex
        :param V end: the end vertex
        :param ghidra.util.datastruct.Accumulator[java.util.List[V]] accumulator: the accumulator into which results will be placed
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises CancelledException: if the operation is cancelled
        """

    @staticmethod
    @typing.overload
    def findPaths(g: GDirectedGraph[V, E], start: V, end: V, accumulator: ghidra.util.datastruct.Accumulator[java.util.List[V]], monitor: ghidra.util.task.TimeoutTaskMonitor):
        """
        Finds all paths from ``start`` to ``end`` in the given graph.  **This version
        of ``findPaths()`` takes a :obj:`TimeoutTaskMonitor`, which allows for the 
        client to control the duration of work.**   This is useful for finding paths on very
        large, dense graphs.
         
         
        **Warning:** for large, dense graphs (those with many interconnected 
        vertices) this algorithm could run indeterminately, possibly causing the JVM to 
        run out of memory.
        
        :param GDirectedGraph[V, E] g: the graph
        :param V start: the start vertex
        :param V end: the end vertex
        :param ghidra.util.datastruct.Accumulator[java.util.List[V]] accumulator: the accumulator into which results will be placed
        :param ghidra.util.task.TimeoutTaskMonitor monitor: the timeout task monitor
        :raises CancelledException: if the operation is cancelled
        :raises TimeoutException: if the operation passes the timeout period
        """

    @staticmethod
    def findPostDominance(g: GDirectedGraph[V, E], from_: V, monitor: ghidra.util.task.TaskMonitor) -> java.util.Set[V]:
        """
        Returns a set of all vertices that are post-dominated by the given vertex.  A node 'b' 
        is said to post-dominate node 'a' if all paths from 'a' to END contain 'b'.
        
        :param GDirectedGraph[V, E] g: the graph
        :param V from: the vertex for which to get post-dominated vertices
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :return: the post-dominated vertices
        :rtype: java.util.Set[V]
        :raises CancelledException: if the monitor is cancelled
        """

    @staticmethod
    def getAncestors(g: GDirectedGraph[V, E], vertices: collections.abc.Sequence) -> java.util.Set[V]:
        """
        Returns all ancestors for the given vertices in the given graph.  Ancestors for a given
        vertex are all nodes at the incoming side of an edge, as well as their incoming 
        vertices, etc.
        
        :param GDirectedGraph[V, E] g: the graph
        :param collections.abc.Sequence vertices: the vertices for which to find descendants
        :return: the ancestors
        :rtype: java.util.Set[V]
        """

    @staticmethod
    def getComplexityDepth(g: GDirectedGraph[V, E]) -> java.util.Map[V, java.lang.Integer]:
        """
        Calculates 'complexity depth', which is, for each vertex, the deepest/longest path 
        from that vertex for a depth-first traversal.   So, for a vertex with a single 
        successor that has no children, the depth would be 1.
        
        :param GDirectedGraph[V, E] g: the graph
        :return: the map of each vertex to its complexity depth
        :rtype: java.util.Map[V, java.lang.Integer]
        """

    @staticmethod
    def getDescendants(g: GDirectedGraph[V, E], vertices: collections.abc.Sequence) -> java.util.Set[V]:
        """
        Returns all descendants for the given vertices in the given graph.  Descendants for a given
        vertex are all nodes at the outgoing side of an edge, as well as their outgoing 
        vertices, etc.
        
        :param GDirectedGraph[V, E] g: the graph
        :param collections.abc.Sequence vertices: the vertices for which to find descendants
        :return: the descendants
        :rtype: java.util.Set[V]
        """

    @staticmethod
    @typing.overload
    def getEdgesFrom(g: GDirectedGraph[V, E], v: V, topDown: typing.Union[jpype.JBoolean, bool]) -> java.util.Set[E]:
        """
        Returns a set of all edges that are reachable from the given vertex.
        
        :param GDirectedGraph[V, E] g: the graph
        :param V v: the vertex for which to get edges
        :param jpype.JBoolean or bool topDown: true for outgoing edges; false for incoming edges
        :return: the set of edges
        :rtype: java.util.Set[E]
        """

    @staticmethod
    @typing.overload
    def getEdgesFrom(g: GDirectedGraph[V, E], vertices: collections.abc.Sequence, topDown: typing.Union[jpype.JBoolean, bool]) -> java.util.Set[E]:
        """
        Returns a set of all edges that are reachable from the given collection of vertices.
        
        :param GDirectedGraph[V, E] g: the graph
        :param collections.abc.Sequence vertices: the vertices for which to get edges
        :param jpype.JBoolean or bool topDown: true for outgoing edges; false for incoming edges
        :return: the set of edges
        :rtype: java.util.Set[E]
        """

    @staticmethod
    def getEntryPoints(g: GDirectedGraph[V, E]) -> java.util.Set[V]:
        """
        Returns all entry points in the given graph.  This includes sources, vertices which 
        have no incoming edges, as well as strongly connected sub-graphs.  The latter being a 
        group vertices where each vertex is reachable from every other vertex.  In the case of
        strongly connected components, we pick one of them arbitrarily to be the entry point.
        
        :param GDirectedGraph[V, E] g: the graph
        :return: the entry points into the graph
        :rtype: java.util.Set[V]
        """

    @staticmethod
    def getSinks(g: GDirectedGraph[V, E]) -> java.util.Set[V]:
        """
        Returns all sink vertices (those with no outgoing edges) in the graph.
        
        :param GDirectedGraph[V, E] g: the graph
        :return: sink vertices
        :rtype: java.util.Set[V]
        """

    @staticmethod
    def getSources(g: GDirectedGraph[V, E]) -> java.util.Set[V]:
        """
        Returns all source vertices (those with no incoming edges) in the graph.
        
        :param GDirectedGraph[V, E] g: the graph
        :return: source vertices
        :rtype: java.util.Set[V]
        """

    @staticmethod
    def getStronglyConnectedComponents(g: GDirectedGraph[V, E]) -> java.util.Set[java.util.Set[V]]:
        """
        Returns a list where each set therein is a strongly connected component of the given 
        graph.  Each strongly connected component is that in which each vertex is reachable from
        any other vertex in that set.
         
         
        This method can be used to determine reachability of a set of vertices.  
         
         
        This can also be useful for cycle detection, as a multi-vertex strong component 
        is by definition a cycle.  This method differs from 
        :meth:`findCircuits(GDirectedGraph, boolean, TaskMonitor) <.findCircuits>` in that the latter will 
        return cycles within the strong components, or sub-cycles.
        
        :param GDirectedGraph[V, E] g: the graph
        :return: the list of strongly connected components
        :rtype: java.util.Set[java.util.Set[V]]
        """

    @staticmethod
    def getVerticesInPostOrder(g: GDirectedGraph[V, E], navigator: ghidra.graph.algo.GraphNavigator[V, E]) -> java.util.List[V]:
        """
        Returns the vertices of the graph in post-order.   Pre-order is the order the vertices
        are last visited when performing a depth-first traversal.
        
        :param GDirectedGraph[V, E] g: the graph
        :param ghidra.graph.algo.GraphNavigator[V, E] navigator: the knower of the direction the graph should be traversed
        :return: the vertices
        :rtype: java.util.List[V]
        """

    @staticmethod
    def getVerticesInPreOrder(g: GDirectedGraph[V, E], navigator: ghidra.graph.algo.GraphNavigator[V, E]) -> java.util.List[V]:
        """
        Returns the vertices of the graph in pre-order.   Pre-order is the order the vertices
        are encountered when performing a depth-first traversal.
        
        :param GDirectedGraph[V, E] g: the graph
        :param ghidra.graph.algo.GraphNavigator[V, E] navigator: the knower of the direction the graph should be traversed
        :return: the vertices
        :rtype: java.util.List[V]
        """

    @staticmethod
    def printGraph(g: GDirectedGraph[V, E], ps: java.io.PrintStream):
        """
        A method to debug the given graph by printing it.
        
        :param GDirectedGraph[V, E] g: the graph to print
        :param java.io.PrintStream ps: the output stream
        """

    @staticmethod
    def retainEdges(graph: GDirectedGraph[V, E], vertices: java.util.Set[V]) -> java.util.Set[E]:
        """
        Retain all edges in the graph where each edge's endpoints are in the given set of 
        vertices.
        
        :param GDirectedGraph[V, E] graph: the graph
        :param java.util.Set[V] vertices: the vertices of the edges to keep
        :return: the set of edges
        :rtype: java.util.Set[E]
        """

    @staticmethod
    def toTree(g: GDirectedGraph[V, E], root: V, edgeComparator: java.util.Comparator[E]) -> GDirectedGraph[V, E]:
        """
        Converts a general directed graph into a tree graph with the given vertex as the root. It
        does this by first doing a topological sort (which ignores back edges) and greedily accepting
        the first incoming edge based on the sorted vertex order.
        
        :param V: the vertex type:param E: the edge type:param GDirectedGraph[V, E] g: the graph to be converted into a tree
        :param V root: the vertex to be used as the root
        :param java.util.Comparator[E] edgeComparator: provides a priority ordering of edges with higher priority edges 
        getting first shot at claiming children for its sub-tree.
        :return: a graph with edges removed such that the graph is a tree.
        :rtype: GDirectedGraph[V, E]
        """

    @staticmethod
    def toVertices(edges: collections.abc.Sequence) -> java.util.Set[V]:
        """
        Returns the set of vertices contained within the given edges.
        
        :param collections.abc.Sequence edges: the edges
        :return: the vertices
        :rtype: java.util.Set[V]
        """

    @staticmethod
    def topologicalSort(g: GDirectedGraph[V, E], root: V, edgeComparator: java.util.Comparator[E]) -> java.util.List[V]:
        """
        Returns a list of list of vertices sorted topologically such that for every edge 
        V1 -> V2, the V1 vertex will appear in the resulting list before the V2 vertex. Normally,
        this is only defined for acyclic graphs. For purposes of this implementation, a root vertex 
        is given as a start point and any edge encountered by following edges from the root that
        results in a "back" edge (i.e any edge that points to a previously visited vertex) is 
        ignored, effectively making the graph acyclic (somewhat arbitrarily depending the order in
        which vertexes are visited which is determined by the given edge comparator). Also, note
        that any vertex in the graph that is not reachable from the given root will not appear in
        the resulting list of sorted vertices.
        
        :param V: the vertex type:param E: the edge type:param GDirectedGraph[V, E] g: the graph
        :param V root: the start node for traversing the graph (will always be the first node in the
        resulting list)
        :param java.util.Comparator[E] edgeComparator: provides an ordering for traversing the graph which can impact which
        edges are ignored as "back" edges and ultimately affect the final ordering
        :return: a list of vertices reachable from the given root vertex, sorted topologically
        :rtype: java.util.List[V]
        """


class GEdge(java.lang.Object, typing.Generic[V]):
    """
    An edge in a (usually directed) graph
    """

    class_: typing.ClassVar[java.lang.Class]

    def getEnd(self) -> V:
        """
        Get the end, or head, of the edge
         
         
        In the edge x -> y, y is the end
        
        :return: the end
        :rtype: V
        """

    def getStart(self) -> V:
        """
        Get the start, or tail, of the edge
         
         
        In the edge x -> y, x is the start
        
        :return: the start
        :rtype: V
        """

    @property
    def start(self) -> V:
        ...

    @property
    def end(self) -> V:
        ...



__all__ = ["ProgramGraphType", "ProgramGraphDisplayOptions", "CallGraphType", "CodeFlowGraphType", "DataFlowGraphType", "BlockFlowGraphType", "GWeightedEdge", "GraphToTreeAlgorithm", "DefaultGEdge", "MutableGDirectedGraphWrapper", "GImplicitDirectedGraph", "GraphPath", "GDirectedGraph", "GEdgeWeightMetric", "VisualGraphComponentProvider", "GraphFactory", "GraphPathSet", "GVertex", "VisualGraph", "GraphAlgorithms", "GEdge"]
