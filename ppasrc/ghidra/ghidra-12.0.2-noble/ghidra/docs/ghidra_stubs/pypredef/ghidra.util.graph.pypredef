from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.datastruct
import ghidra.util.graph.attributes
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class WeightedDigraph(DirectedGraph):
    """
    DirectedGraph with edge weights. Weights are assumed to be 0.0 by default.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, vertexCapacity: typing.Union[jpype.JInt, int], edgeCapacity: typing.Union[jpype.JInt, int]):
        """
        Create weighted directed graph with default edge weight of 0.0
        and room for vertexCapicity vertices and edgeCapacity edges.
        """

    @typing.overload
    def __init__(self, vertexCapacity: typing.Union[jpype.JInt, int], edgeCapacity: typing.Union[jpype.JInt, int], defaultEdgeWeight: typing.Union[jpype.JDouble, float]):
        """
        Create a weighted directed graph. Use the defaultEdgeWeight for any edges whose
        weights have not been set.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    @typing.overload
    def add(self, e: Edge) -> bool:
        """
        Add an edge. If successful (i.e. that edge does not already appear
        in the graph), set the weight to the default value
        
        :return: true if edge added succesfuly.
        :rtype: bool
        """

    @typing.overload
    def add(self, e: Edge, weight: typing.Union[jpype.JDouble, float]) -> bool:
        """
        Add an edge. If successful (i.e. that edge does not appear in the graph),
        then set the weight to the specified value.
        
        :return: true if edge added succesfuly.
        :rtype: bool
        """

    def degree(self, v: Vertex) -> float:
        """
        Returns the weighted degree of this vertex. The degree is the
        sum of weights of all edges entering and leaving this vertex.
        """

    def getDefaultEdgeWeight(self) -> float:
        """
        Gets the defaultEdgeWeight of this graph specified at creation
        time.
        """

    def getEdgeWeights(self) -> ghidra.util.graph.attributes.DoubleAttribute[Edge]:
        """
        Get the edge weights for this graph.
        """

    def getWeight(self, e: Edge) -> float:
        """
        Returns the weight of the specified edge.
        """

    def inDegree(self, v: Vertex) -> float:
        """
        Returns the weighted in-degree of this vertex. The in-degree is the
        sum of weights of all enges entering this vertex.
        """

    def intersectionWith(self, otherGraph: DirectedGraph):
        """
        Creates intersection of graphs in place by adding all vertices and edges of
        other graph to this graph. This method used to return a different graph
        as the intersection but now does not.
        """

    def outDegree(self, v: Vertex) -> float:
        """
        Returns the weighted out-degree of this vertex. The out-degree is the
        sum of weights of all enges entering this vertex.
        """

    def selfDegree(self, v: Vertex) -> float:
        """
        Returns the weighted self-degree of this vertex. The self-degree is the
        sum of weights of all loops at this vertex.
        """

    def setWeight(self, e: Edge, value: typing.Union[jpype.JDouble, float]) -> bool:
        """
        Sets the weight of the specified edge.
        """

    def unionWith(self, otherGraph: DirectedGraph):
        """
        Creates union of graphs in place by adding all vertices and edges of
        other graph to this graph. This method used to return a different graph
        as the union but now does not.
        """

    @property
    def edgeWeights(self) -> ghidra.util.graph.attributes.DoubleAttribute[Edge]:
        ...

    @property
    def weight(self) -> jpype.JDouble:
        ...

    @property
    def defaultEdgeWeight(self) -> jpype.JDouble:
        ...


class Dominator(DirectedGraph):
    """
    Title: Dominator
    Description: This class contains the functions necessary to build the
    dominance graph of a FlowGraph, ShrinkWrap or Modularized Graph.
    A more complete explanation of my algorithm can be found in my paper
    titled "Building a Dominance Graph"
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, vertexCapacity: typing.Union[jpype.JInt, int], edgeCapacity: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, cg: DirectedGraph):
        ...

    def addToPaths(self, v: Vertex, singlePath: java.util.Vector) -> Vertex:
        """
        This function originally did not return anything.  It returns a vertex
        for the purpose of keeping track of which vertex we left off on.  So if we
        backtrack, we can copy the portion of the previous path that is contained
        in the path we are currently construction.  I tried to do this without
        passing v as a parameter and it did not work.  Something funny happened I
        suppose with JAVA and pointers.
        This  function simply adds to singlePath until there are no more white
        children which means we've either reached a sink, or the only vertices
        left are repeated meaning we have a loop.
        """

    def allPathsContain(self, pathSet: java.util.Vector, v: Vertex, path: java.util.Vector) -> Vertex:
        """
        This takes the longest path that contains vertex v and looks to see
        if any of v's ancestors from that path are contained in all other
        paths that contain v.
        """

    def allPathsContaining(self, v: Vertex) -> java.util.Vector:
        """
        this returns all paths that contain v which we need to consider when
        looking for the dominator of v.  It places the longest path as the
        first element in the vector pathSet.
        """

    def backTrack(self, v: Vertex) -> Vertex:
        """
        this aids in going back to the parent from which a vertex was accessed in
        the depth first search
        """

    def getCallingParent(self, v: Vertex) -> Vertex:
        ...

    def getColor(self, v: Vertex) -> int:
        ...

    def getDominanceGraph(self) -> DirectedGraph:
        """
        This iterates through the vertices of our graph and gets the dominator
        for each.  In a new graph - dom - it adds each vertex and an edge between the
        vertex and its dominator.  It returns dom, the dominance graph.
        """

    def getDominator(self, v: Vertex) -> Vertex:
        """
        this returns the vertex that is the dominator
        """

    def getType(self, o: KeyedObject) -> str:
        ...

    @typing.overload
    def getWeight(self, v: Vertex) -> float:
        ...

    @typing.overload
    def getWeight(self, e: Edge) -> float:
        ...

    def goToNextWhiteChild(self, v: Vertex) -> Vertex:
        """
        Goes to the next child of v that has not been visited and sets the
        calling parent to be v so that we can backtrack.
        """

    def setCallingParent(self, v: Vertex, parent: Vertex):
        ...

    def setColor(self, v: Vertex, color: typing.Union[jpype.JInt, int]):
        ...

    def setDominance(self) -> DirectedGraph:
        """
        This makes a list of all the paths that are in a graph that terminate
        either because of a repeated vertex or hitting a sink. It then calls
        getDominanceGraph which gets the dominator for every vertex and builds a
        dominance graph.
        """

    def setType(self, v: Vertex, type: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def setWeight(self, v: Vertex, weight: typing.Union[jpype.JDouble, float]):
        ...

    @typing.overload
    def setWeight(self, e: Edge, weight: typing.Union[jpype.JDouble, float]):
        ...

    def whitenChildren(self, v: Vertex):
        """
        Whitens the children of v.  It is only called after v has no more
        children left and we have backtracked to the calling parent of
        v.  This is to ensure that we don't miss out on any paths that
        contain a child of v which has other parents.
        """

    @property
    def dominator(self) -> Vertex:
        ...

    @property
    def color(self) -> jpype.JInt:
        ...

    @property
    def callingParent(self) -> Vertex:
        ...

    @property
    def weight(self) -> jpype.JDouble:
        ...

    @property
    def dominanceGraph(self) -> DirectedGraph:
        ...

    @property
    def type(self) -> java.lang.String:
        ...


@typing.type_check_only
class VertexSet(KeyIndexableSet[Vertex]):
    """
    VertexSet is a container class for objects of type Vertex. It is
    designed to be used in conjunction with EdgeSet as part of DirectedGraph.
    """

    @typing.type_check_only
    class VertexSetIterator(GraphIterator[Vertex]):
        """
        Implements an Iterator for this VertexSet.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            """
            Constructor
            """

        def hasNext(self) -> bool:
            """
            Return true if there is another vertex in this iteration.
            
            :raises ConcurrentModificationException: if the VertexSet is 
            modified by methods outside this iterator.
            """

        def next(self) -> Vertex:
            """
            Return the next Vertex in the iteration
            """

        def remove(self) -> bool:
            """
            Remove the vertex returned by the most recent call to next().
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: DirectedGraph, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param DirectedGraph parent: The DirectedGraph this is a VertexSet of.
        :param jpype.JInt or int capacity: number of vertices that may be held without invoking grow()
        """

    def add(self, v: Vertex) -> bool:
        """
        Adds the given vertex to the vertex set, if it does not already contain
        it.
        
        :return: true if and only if the vertex was sucessfully added.
        :rtype: bool
        """

    def capacity(self) -> int:
        """
        Return the number of vertices this VertexSet may hold without growing.
        """

    def contains(self, v: Vertex) -> bool:
        """
        Return true iff the specified KeyedObject is contained in
        this VertexSet.
        """

    def getModificationNumber(self) -> int:
        """
        Get the number of times this VertexSet has changed
        """

    def iterator(self) -> GraphIterator[Vertex]:
        """
        Return an iterator over all of the vertices in this VertexSet.
        The iterator becomes invalid and throws a ConcurrentModificationException
        if any changes are made to the VertexSet after the iterator is created.
        """

    def numSinks(self) -> int:
        """
        Return the number of sinks.  
        This equals the number of vertices with no outgoing
        edges in the VertexSet.
        """

    def numSources(self) -> int:
        """
        Return the number of sources.
        This equals the number of vertices with no incoming
        edges in the VertexSet.
        """

    def remove(self, v: Vertex) -> bool:
        """
        Removes the given vertex from this vertex set if it contains it.
        
        :return: true if and only if the vertex was sucessfully removed.
        :rtype: bool
        """

    def size(self) -> int:
        """
        Return The number of vertices in this VertexSet.
        """

    def toArray(self) -> jpype.JArray[Vertex]:
        """
        Return the elements of this VertexSet as an Vertex[].
        """

    def toSet(self) -> java.util.Set[Vertex]:
        """
        Return the elements of this VertexSet as a java.util.Set.
        """

    @property
    def modificationNumber(self) -> jpype.JLong:
        ...


class DepthFirstSearch(java.lang.Object):
    """
    Provides a depth first search service to directed graphs. 
    Once a search has finished information about the search 
    can be obtained.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graph: DirectedGraph, initialSeeds: jpype.JArray[Vertex], getAdditionalSeedsIfNeeded: typing.Union[jpype.JBoolean, bool], goForward: typing.Union[jpype.JBoolean, bool], goBackward: typing.Union[jpype.JBoolean, bool]):
        """
        Upon creation a depth first search of the given graph is performed.
        
        :param DirectedGraph graph: The graph to search
        :param jpype.JArray[Vertex] initialSeeds: The vertices used to start the search
        :param jpype.JBoolean or bool getAdditionalSeedsIfNeeded: If true, when searching from the initial
        seeds does not find all vertices in the graph, additional start vertices will
        be selected until every vertex is the graph has been found.
        :param jpype.JBoolean or bool goForward: Follow edges in their specifed direction
        :param jpype.JBoolean or bool goBackward: Follow edges in the opposite of their specified direction.
        """

    def backEdges(self) -> jpype.JArray[Edge]:
        """
        Return the back edges found in this depth first search.
        """

    def isAcyclic(self) -> bool:
        """
        Return true iff no back edges were found. 
         
        Note that if the graph
        is not completely explored the answer is only for the portion
        of the graph expored.
        """

    def isCompleted(self, v: Vertex) -> bool:
        """
        Return true if the vertex has completed its role in the depth first
        search.
        """

    def isTree(self) -> bool:
        """
        Return true iff the every edge is a tree edge. Will always be false
        if the entire graph is not explored.
        """

    def isUnseen(self, v: Vertex) -> bool:
        """
        Return true if the vertex has not yet been discovered in the depth first
        search.
        """

    def spanningTree(self) -> DirectedGraph:
        """
        Returns a spanning tree (in the form of a DirectedGraph). 
        No claims that the spanning tree returned has any special 
        properties.
        """

    def topologicalSort(self) -> jpype.JArray[Vertex]:
        """
        Returns a topological sort of the directed graph. 
        Return the vertices in the explored 
        portion of the graph with the following
        property:
         
        1. If the graph is acyclic then v[i] -> v[j] => i < j .
        2. If the graph contains cycles, then the above is true except when
        (v[i],v[j]) is a back edge.
        """

    def treeEdges(self) -> jpype.JArray[Edge]:
        """
        Return the tree edges in this depth first search.
        """

    @property
    def tree(self) -> jpype.JBoolean:
        ...

    @property
    def acyclic(self) -> jpype.JBoolean:
        ...

    @property
    def completed(self) -> jpype.JBoolean:
        ...

    @property
    def unseen(self) -> jpype.JBoolean:
        ...


class Edge(KeyedObject, java.lang.Comparable[Edge]):
    """
    An Edge joins a pair of vertices. 
    The from and to vertex of an edge can not be changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, from_: Vertex, to: Vertex):
        """
        
        
        :param Vertex from: The from or parent vertex.
        :param Vertex to: The to or child vertex.
        """

    def compareTo(self, edge: Edge) -> int:
        """
        Compare one edge to another. Based on time of creation.
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Overides equals method by comparing keys.
        """

    def from_(self) -> Vertex:
        """
        Returns from vertex.
        """

    def key(self) -> int:
        """
        Returns the key of this edge.
        """

    def to(self) -> Vertex:
        """
        Returns to vertex.
        """


class KeyedObjectFactory(java.lang.Object):
    """
    The KeyedObjectFactory class is responsible for ensuring that no two
        vertices or edges have the same keys. One and only one instance of the 
        KeyedObjectFactory may exist. In addition to ensuring that all vertices 
        and edges contained within any graph have distinct keys, KeyedObjectFactory
        provides methods for obtaining the Object that a KeyedObject refers to. More 
        than one vertex may refer to the same object. The object a Vertex refers 
        to can not be changed. There is no method to return the vertex referring 
        to a specific object since in theory there can be a one-to-many 
        correspondence.
    """

    class_: typing.ClassVar[java.lang.Class]
    instance_: typing.ClassVar[KeyedObjectFactory]
    """
    The singleton instance of KeyedObjectFactory.
    """


    @staticmethod
    def getInstance() -> KeyedObjectFactory:
        """
        Returns singleton instance of KeyedObjectFactory.
        """


class SimpleWeightedDigraph(WeightedDigraph):
    """
    A simple graph is a graph with no parallel edges or loops. This class models
    a simple digraph -- edges are directed and a single edge may go from any vertex
    to any other vertex. It is possible to have edges A-->B and B-->A however.
    Attempting to add an edge from A to B when an edge from A to B already exists
    causes the edge weight to be increased by the defaultEdgeWeight or the weight
    specified. 
     
    This class may be used when simple unweighted graphs are desired. (Simply ignore
    edge weights.)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, vertexCapacity: typing.Union[jpype.JInt, int], edgeCapacity: typing.Union[jpype.JInt, int], defaultEdgeWeight: typing.Union[jpype.JDouble, float], loopsAllowed: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for SimpleWeightedDigraph.
        
        :param jpype.JInt or int vertexCapacity: initially allocate space for this many vertices.
        :param jpype.JInt or int edgeCapacity: initially allocate space for this many edges.
        :param jpype.JDouble or float defaultEdgeWeight: edges are given this weight at creation time by default. 
        the default is 1.0 for constructors where not specified.
        :param jpype.JBoolean or bool loopsAllowed: Loops are allowed in the graph if this value set true
        in constructor. Default value is false.
         
        If vertex weights are desired, the class can either be extended or a vertex 
        attribute can be defined using the code
        DoubleAttribute vertexWeights = 
                (DoubleAttribute)this.vertexAttributes().createAttribute("weight", AttributeManager.DOUBLE_TYPE);
        """

    @typing.overload
    def __init__(self, vertexCapacity: typing.Union[jpype.JInt, int], edgeCapacity: typing.Union[jpype.JInt, int], defaultEdgeWeight: typing.Union[jpype.JDouble, float]):
        """
        Constructor for SimpleWeightedDigraph. 
         
        AllowLoops is false by default.
        
        :param jpype.JInt or int vertexCapacity: 
        :param jpype.JInt or int edgeCapacity: 
        :param jpype.JDouble or float defaultEdgeWeight:
        """

    @typing.overload
    def __init__(self, vertexCapacity: typing.Union[jpype.JInt, int], edgeCapacity: typing.Union[jpype.JInt, int]):
        """
        Constructor for SimpleWeightedDigraph. 
         
        AllowLoops is false by default.
        The defaultEdgeWeight is 1.0.
        
        :param jpype.JInt or int vertexCapacity: 
        :param jpype.JInt or int edgeCapacity:
        """

    @typing.overload
    def add(self, e: Edge) -> bool:
        """
        Add an edge with the default edge weight. 
         
        If an edge from and to the vertices
        specified by the edge already exists in the graph, 
        then the edge weight in increased by the default value.
        
        :param Edge e: the edge to add.
        :return: true if the edge was added sucessfully.
        :rtype: bool
        """

    @typing.overload
    def add(self, e: Edge, weight: typing.Union[jpype.JDouble, float]) -> bool:
        """
        Add an edge with the specified edge weight. 
         
        If an edge from and to the vertices
        specified by the edge already exists in the graph,
        then the edge weight in increased
        by the specified value.
        
        :return: true if the edge was added sucessfully.
        :rtype: bool
        """


class DependencyGraph(AbstractDependencyGraph[T], typing.Generic[T]):
    """
    Original Dependency Graph implementation that uses :obj:`HashMap`s and :obj:`HashSet`s.
    Side affect of these is that data pulled from the graph (:meth:`pop() <.pop>`) is not performed
    in a deterministic order.  However, load time for the graph is O(1).
    
    
    .. seealso::
    
        | :obj:`AbstractDependencyGraph`
    
        | :obj:`DeterministicDependencyGraph`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, other: DependencyGraph[T]):
        """
        Copy constructor
        
        :param DependencyGraph[T] other: the other DependencyGraph to copy
        """


class AddableLongIntHashtable(ghidra.util.datastruct.LongIntHashtable):
    """
    This class modifies the behavior of LongIntHashtable. May add
    to the value stored with the key rather than replacing the value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        ...

    def add(self, key: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JInt, int]):
        """
        Adds value associated with the stored key
        """


class AbstractDependencyGraph(java.lang.Object, typing.Generic[T]):
    """
    Class for managing the visiting (processing)  of a set of values where some values depend
    on other values being process before them.  In other words, an acyclic directed graph will
    be formed where the vertexes are the values and the edges represent dependencies.  Values can
    only be removed if they have no dependencies.  Since the graph is acyclic, as values are removed
    that have no dependencies, other nodes that depend on those nodes will become eligible for 
    processing and removal.  If cycles are introduced, they will eventually cause an IllegalState
    exception to occur when removing and processing values.  There is also a hasCycles() method
    that can be called before processing to find cycle problems up front without wasting time 
    processing values.
    
    
    .. seealso::
    
        | :obj:`DependencyGraph`
    
        | :obj:`DeterministicDependencyGraph`
    """

    @typing.type_check_only
    class DependencyNode(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def addNodeThatDependsOnMe(self, node: AbstractDependencyGraph.DependencyNode):
            ...

        def getNumberOfNodesThatIDependOn(self) -> int:
            ...

        def getSetOfNodesThatDependOnMe(self) -> java.util.Set[AbstractDependencyGraph.DependencyNode]:
            ...

        def getValue(self) -> T:
            ...

        def releaseDependencies(self):
            ...

        @property
        def setOfNodesThatDependOnMe(self) -> java.util.Set[AbstractDependencyGraph.DependencyNode]:
            ...

        @property
        def numberOfNodesThatIDependOn(self) -> jpype.JInt:
            ...

        @property
        def value(self) -> T:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addDependency(self, value1: T, value2: T):
        """
        Add a dependency such that value1 depends on value2.  Both value1 and value2 will be
        added to the graph if they are not already in the graph.
        
        :param T value1: the value that depends on value2
        :param T value2: the value that value1 is depending on
        """

    def addValue(self, value: T):
        """
        Adds the value to this graph.
        
        :param T value: the value to add
        """

    def contains(self, value: T) -> bool:
        """
        Returns true if this graph has the given key.
        
        :param T value: the value to check if its in this graph
        :return: true if this graph has the given key.
        :rtype: bool
        """

    def copy(self) -> AbstractDependencyGraph[T]:
        """
        Returns a copy of this graph.
        
        :return: a copy of this graph.
        :rtype: AbstractDependencyGraph[T]
        """

    def getAllIndependentValues(self) -> java.util.Set[T]:
        """
        Returns the set of all values that have no dependencies regardless of whether or not
        they have been "visited" (by the getUnvisitedIndependentValues() method.
        
        :return: return the set of all values that have no dependencies.
        :rtype: java.util.Set[T]
        """

    def getDependentValues(self, value: T) -> java.util.Set[T]:
        """
        Returns a set of values that depend on the given value.
        
        :param T value: the value that other values may depend on.
        :return: a set of values that depend on the given value.
        :rtype: java.util.Set[T]
        """

    def getNodeMap(self) -> java.util.Map[T, AbstractDependencyGraph.DependencyNode]:
        ...

    def getNodeMapValues(self) -> java.util.Set[T]:
        """
        Returns the set of values in this graph.
        
        :return: the set of values in this graph.
        :rtype: java.util.Set[T]
        """

    def getUnvisitedIndependentValues(self) -> java.util.Set[T]:
        """
        Returns a set of all values that have no dependencies.  As values are removed from the
        graph, dependencies will be removed and additional values will be eligible to be returned
        by this method.  Once a value has been retrieved using this method, it will be considered
        "visited" and future calls to this method will not include those values.  To continue
        processing the values in the graph, all values return from this method should eventually
        be deleted from the graph to "free up" other values.  NOTE: values retrieved by this method
        will no longer be eligible for return by the pop() method.
        
        :return: the set of values without dependencies that have never been returned by this method 
        before.
        :rtype: java.util.Set[T]
        """

    def getValues(self) -> java.util.Set[T]:
        """
        Returns the set of values in this graph.
        
        :return: the set of values in this graph.
        :rtype: java.util.Set[T]
        """

    def hasCycles(self) -> bool:
        """
        Checks if this graph has cycles.  Normal processing of this graph will eventually reveal
        a cycle and throw an exception at the time it is detected.  This method allows for a 
        "fail fast" way to detect cycles.
        
        :return: true if cycles exist in the graph.
        :rtype: bool
        """

    def hasUnVisitedIndependentValues(self) -> bool:
        """
        Returns true if there are unvisited values ready (no dependencies) for processing.
        
        :return: true if there are unvisited values ready for processing.
        :rtype: bool
        :raises IllegalStateException: is thrown if the graph is not empty and there are no nodes
        without dependency which indicates there is a cycle in the graph.
        """

    def isEmpty(self) -> bool:
        """
        Returns true if the graph has no values;
        
        :return: true if the graph has no values;
        :rtype: bool
        """

    def pop(self) -> T:
        """
        Removes and returns a value that has no dependencies from the graph.  If the graph is empty
        or all the nodes without dependencies are currently visited, then null will be returned.
        NOTE: If the getUnvisitedIndependentValues() method has been called(), this method may
        return null until all those "visited" nodes are removed from the graph.
        
        :return: return an arbitrary value that has no dependencies and hasn't been visited or null.
        :rtype: T
        """

    def remove(self, value: T):
        """
        Removes the value from the graph.  Any dependency from this node to another will be removed,
        possible allowing nodes that depend on this node to be eligible for processing.
        
        :param T value: the value to remove from the graph.
        """

    def size(self) -> int:
        """
        Returns the number of values in this graph.
        
        :return: the number of values in this graph.
        :rtype: int
        """

    @property
    def nodeMapValues(self) -> java.util.Set[T]:
        ...

    @property
    def dependentValues(self) -> java.util.Set[T]:
        ...

    @property
    def allIndependentValues(self) -> java.util.Set[T]:
        ...

    @property
    def unvisitedIndependentValues(self) -> java.util.Set[T]:
        ...

    @property
    def values(self) -> java.util.Set[T]:
        ...

    @property
    def nodeMap(self) -> java.util.Map[T, AbstractDependencyGraph.DependencyNode]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class KeyedObject(java.lang.Object):
    """
    The KeyedObject class is used as a base class for objects which have keys.
    Some specific examples of KeyedObject are Vertex and Edge.
    """

    class_: typing.ClassVar[java.lang.Class]

    def key(self) -> int:
        """
        Returns the key for this KeyedObject.
        """


class AddableLongDoubleHashtable(ghidra.util.datastruct.LongDoubleHashtable):
    """
    This class modifies the behavior of LongDoubleHashtable. May add
    to the value stored with the key rather than replacing the value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        """

    def add(self, key: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JDouble, float]):
        """
        Adds the value to the stored value rather than replacing it.
        """


class Path(java.util.Vector):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def containsInSomeElement(self, otherVector: java.util.Vector) -> bool:
        ...


class KeyIndexableSet(java.lang.Object, typing.Generic[T]):
    """
    Interface for sets of graph objects which have keys such as vertices
    and edges.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, o: T) -> bool:
        """
        Adds a KeyedObject to this KeyIndexableSet. The set will increase
        in capacity if needed.
        
        :return: true if the KeyedObject was successfully added. Returns false
        if the KeyedObject is null or already in the KeyIndexableSet or addition
        fails for some other reason.
        :rtype: bool
        """

    def capacity(self) -> int:
        """
        Returns the number of KeyedObjects this KeyIndexableSet can
        hold without growing.
        """

    def contains(self, o: T) -> bool:
        """
        Returns true if this KeyIndexableSet contains the specified KeyedObject.
        """

    def getKeyedObject(self, key: typing.Union[jpype.JLong, int]) -> T:
        """
        Returns the KeyedObject with the specified key in this KeyIndexableSet.
        Returns null if the Set contains no object with that key.
        """

    def getModificationNumber(self) -> int:
        """
        The modification number is a counter for the number of changes
        the KeyIndexableSet has undergone since its creation.
        """

    def iterator(self) -> GraphIterator[T]:
        """
        Returns an iterator for this KeyIndexableSet which uses the
        hasNext()/next() style. See GraphIterator.
        """

    def remove(self, o: T) -> bool:
        """
        Remove a KeyedObject from this KeyIndexableSet.
        
        :return: true if the KeyedObject was sucessfully removed. Returns false
        if the KeyedObject was not in the KeyIndexablrSet.
        :rtype: bool
        """

    def size(self) -> int:
        """
        Returns the number of KeyedObjects in this KeyIndexableSet
        """

    def toArray(self) -> jpype.JArray[T]:
        """
        Returns the elements of this KeyIndexableSet as an array of
        KeyedObjects.
        """

    @property
    def keyedObject(self) -> T:
        ...

    @property
    def modificationNumber(self) -> jpype.JLong:
        ...


class DirectedGraph(java.lang.Object):
    """
    Base implementation of a directed graph. A directed graph consists
    of a set of vertices (implemented as a VertexSet) and a set of edges
    (implemented as an EdgeSet) joining ordered pairs of vertices in the
    graph. Both vertices and edges can belong to more than one DirectedGraph.
    Attributes for both vertices and edges may be defined for a DirectedGraph.
    Parallel edges (more than one edge with the same from and to vertices)
    are allowed in DirectedGraph. Loops are also allowed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, vertexCapacity: typing.Union[jpype.JInt, int], edgeCapacity: typing.Union[jpype.JInt, int]):
        """
        Creates an empty DirectedGraph with room for 
        vertexCapacity vertices and edgeCapacity edges.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    @typing.overload
    def add(self, v: Vertex) -> bool:
        """
        Adds the specified vertex to the graph.
        """

    @typing.overload
    def add(self, e: Edge) -> bool:
        """
        Adds the specified edge to the graph. If either endpoint of the
        edge is not in the graph that vertex is also added to the graph.
        """

    def areRelatedAs(self, parent: Vertex, child: Vertex) -> bool:
        """
        Returns true iff the graph contains and edge from the parent vertex
        to the child vertex.
        """

    def assignVerticesToStrongComponents(self) -> jpype.JArray[java.util.Set[Vertex]]:
        """
        Returns an array of Sets (HashSet). Each set contains the vertices
        within a single strongly connected component of the DirectedGraph.
         
        A strongly connected component of a directed graph is a subgraph 
        in which it is possible to find a directed path from any vertex to any 
        other vertex in the graph. A cycle is a simple example of strongly 
        connected graph.
        """

    def clear(self):
        """
        Removes all vertices and edges from the graph without changing 
        the space allocated.
        """

    def complexityDepth(self) -> ghidra.util.graph.attributes.IntegerAttribute[Vertex]:
        """
        Assigns levels to the graph in a bottom up fashion. All sinks have the
        same level.
        """

    @typing.overload
    def contains(self, v: Vertex) -> bool:
        """
        Returns true iff the vertex is in the graph.
        """

    @typing.overload
    def contains(self, e: Edge) -> bool:
        """
        Returns true iff the graph contains the edge e.
        """

    def containsAsSubgraph(self, g: DirectedGraph) -> bool:
        """
        Returns true iff all nodes and edges of the given graph are in the current graph
        """

    def copy(self) -> DirectedGraph:
        """
        
        
        :return: A directed graph with the same vertices, edges, and attributes.
        :rtype: DirectedGraph
        """

    def degree(self, v: Vertex) -> float:
        """
        Returns valence as a double. Should be overridden extending classes.
        """

    def descendantsGraph(self, seeds: jpype.JArray[Vertex]) -> DirectedGraph:
        """
        Get the graph induced by the seed vertices and their descendants
        """

    def edgeAttributes(self) -> ghidra.util.graph.attributes.AttributeManager[Edge]:
        """
        Returns the AttributeManager for the edges of this graph.
        """

    def edgeIterator(self) -> GraphIterator[Edge]:
        """
        Returns an iterator for the EdgeSet of this graph.
        """

    def edges(self) -> EdgeSet:
        """
        Returns the EdgeSet of this graph.
        """

    def getAncestors(self, v: Vertex) -> java.util.Set[Vertex]:
        """
        Returns a set of all the vertices which are ancestors of the given vertex.
        Note: By definition a vertex is one of its own ancestors.
        """

    @typing.overload
    def getChildren(self, v: Vertex) -> java.util.Set[Vertex]:
        """
        Returns a Set (HashSet) containing all vertices that are the tos
        of outgoing edges of the given vertex. Note in the case of multiple
        edges, the number of children and outvalence need not be the same.
        """

    @typing.overload
    def getChildren(self, vs: java.util.Set[Vertex]) -> java.util.Set[Vertex]:
        """
        Returns all children of the vertices in the given set.
        """

    def getComponentContaining(self, v: Vertex) -> DirectedGraph:
        """
        Returns the subgraph of this graph which is the component containing v.
        """

    def getComponents(self) -> jpype.JArray[DirectedGraph]:
        """
        Returns an array of directed graphs. Each array element is a 
        DirectedGraph consisting of a single
        connected component of this graph.
        """

    @typing.overload
    def getDescendants(self, v: Vertex) -> java.util.Set[Vertex]:
        """
        Returns a Set (HashSet) containing all descendants of the given vertex.
        Note: The vertex is defined to be a descendant of itself.
        """

    @typing.overload
    def getDescendants(self, seedVertices: jpype.JArray[Vertex]) -> java.util.Set[Vertex]:
        """
        Returns a Set (HashSet) of all vertices descended from a vertex in the
        given array.
        """

    def getEdgeArray(self) -> jpype.JArray[Edge]:
        """
        returns an array containing the edges in the graph
        """

    def getEdgeWithKey(self, key: typing.Union[jpype.JLong, int]) -> Edge:
        """
        
        
        :param jpype.JLong or int key: 
        :return: the edge in the graph with the specified key or null
        if the graph does not contain an edge with the key.
        :rtype: Edge
        """

    @typing.overload
    def getEdges(self) -> java.util.Set[Edge]:
        """
        returns a java.util.Set containing the edges in this graph.
        """

    @typing.overload
    def getEdges(self, from_: Vertex, to: Vertex) -> jpype.JArray[Edge]:
        """
        Returns all edges joing the from and to vertices. Recall DirectedGraph
        uses a multigraph model where parallel edges are allowed.
        """

    def getEntryPoints(self) -> java.util.Vector[Vertex]:
        """
        Returns a vector containing the entry points to a directed graph. An entry
        point is either a source (in valence zero) or the least vertex in a strongly
        connected component unreachable from any vertex outside the strongly
        connected component. Least is defined here to be the vertex with the smallest
        key.
        """

    def getIncomingEdges(self, v: Vertex) -> java.util.Set[Edge]:
        """
        Returns a Set containing all of the edges to the given vertex.
        """

    def getLevels(self) -> ghidra.util.graph.attributes.IntegerAttribute[Vertex]:
        """
        This method assigns levels in a top-down manner. Sources are on level 0.
        """

    @typing.overload
    def getNeighborhood(self, v: Vertex) -> java.util.Set[Vertex]:
        """
        Returns a java.util.Set containing the vertex v and its neighbors.
        """

    @typing.overload
    def getNeighborhood(self, vs: java.util.Set[Vertex]) -> java.util.Set[Vertex]:
        """
        Returns a java.util.Set containing the vertices in the given Set and their
        neighbors.
        """

    def getOutgoingEdges(self, v: Vertex) -> java.util.Set[Edge]:
        """
        Returns the outgoing edges from the given vertex.
        """

    @typing.overload
    def getParents(self, v: Vertex) -> java.util.Set[Vertex]:
        """
        Returns a Set containg all of the vertices from which an edge comes
        into the given vertex.
        """

    @typing.overload
    def getParents(self, vs: java.util.Set[Vertex]) -> java.util.Set[Vertex]:
        """
        Returns all parents of the vertices in the given set.
        """

    def getReferent(self, v: Vertex) -> java.lang.Object:
        """
        Returns the referent of the object used to create v if it exists. If the
        vertex was created with a null referent this method returns null.
        """

    def getSinks(self) -> jpype.JArray[Vertex]:
        """
        Returns a Vertex[] containing the sinks. A vertex is a sink if it 
        has no outgoing edges.
        """

    def getSources(self) -> jpype.JArray[Vertex]:
        """
        Returns a Vertex[] containing the sources. A vertex is a source if
        it has no incoming edges.
        """

    def getVertexArray(self) -> jpype.JArray[Vertex]:
        """
        returns an array containing the vertices in the graph
        """

    def getVertexWithKey(self, key: typing.Union[jpype.JLong, int]) -> Vertex:
        """
        
        
        :param jpype.JLong or int key: 
        :return: the vertex in the graph with the specified key or null
        if the graph does not contain an vertex with the key.
        :rtype: Vertex
        """

    def getVertices(self) -> java.util.Set[Vertex]:
        """
        returns a java.util.Set containing the vertices in this graph.
        """

    def getVerticesHavingReferent(self, o: java.lang.Object) -> jpype.JArray[Vertex]:
        """
        Returns Vertex[] containing all vertices having the given object as
        a referent. Any number of vertices in the graph may refer back to 
        the same object.
        """

    def getVerticesInContainingComponent(self, v: Vertex) -> java.util.Set[Vertex]:
        """
        Returns a java.util.Set containing all of the vertices within the
        same component a the given vertex.
        """

    def inDegree(self, v: Vertex) -> float:
        """
        Returns inValence as a double. Should be overridden extending classes.
        """

    def inValence(self, v: Vertex) -> int:
        """
        The number of edges having v as their terminal or
        "to" vertex.
        """

    def incomingEdges(self, v: Vertex) -> jpype.JArray[Edge]:
        """
        Returns an array of all incoming edges.
        """

    def inducedSubgraph(self, vertexSet: jpype.JArray[Vertex]) -> DirectedGraph:
        """
        Returns the directed graph which is subgraph induced by the given
        set of vertices. The vertex set of the returned graph contains the
        given vertices which belong to this graph. An edge of this graph
        is in the returned graph iff both endpoints belong to the given vertices.
        """

    def intersectionWith(self, otherGraph: DirectedGraph):
        """
        Creates intersection of graphs in place by adding all vertices and edges of
        other graph to this graph. This method used to return a different graph
        as the intersection but now does not.
        """

    def join(self, other: DirectedGraph) -> DirectedGraph:
        """
        This method joins nodes from a directed graph into this.  This 
        allows DirectedGraph subclasses to copy nodes and attributes, 
        a shortcomings with the unionWith method.
        
        :param DirectedGraph other: the other directed graph that is to be joined into this one.
        :return: this directed graph
        :rtype: DirectedGraph
        """

    def loopDegree(self, v: Vertex) -> float:
        """
        Returns numLoops as a double. Should be overridden extending classes.
        """

    def numEdges(self) -> int:
        """
        Returns the number of edges in the graph
        """

    def numLoops(self, v: Vertex) -> int:
        """
        The number of edges having v as both their terminal and
        terminal vertex.
        """

    def numSinks(self) -> int:
        """
        returns the number of vertices with outValence zero.
        """

    def numSources(self) -> int:
        """
        returns the number of vertices with inValence zero.
        """

    def numVertices(self) -> int:
        """
        Returns the number of vertices in the graph
        """

    def outDegree(self, v: Vertex) -> float:
        """
        Returns outValence as a double. Should be overridden extending classes.
        """

    def outValence(self, v: Vertex) -> int:
        """
        The number of edges having v as their initial or
        "from" vertex.
        """

    def outgoingEdges(self, v: Vertex) -> jpype.JArray[Edge]:
        """
        Returns an array of all outgoing edges.
        """

    @typing.overload
    def remove(self, v: Vertex) -> bool:
        """
        Removes the vertex v from the graph. Also removes all edges incident with
        v. Does nothing if the vertex is not in the graph.
        """

    @typing.overload
    def remove(self, e: Edge) -> bool:
        """
        Removes Edge e from the graph. No effect if the edge is not in the graph.
        """

    def selfEdges(self, v: Vertex) -> jpype.JArray[Edge]:
        """
        Returns an array of all edges with the given vertex as both the from
        and to.
        """

    def unionWith(self, otherGraph: DirectedGraph):
        """
        Creates union of graphs in place by adding all vertices and edges of
        other graph to this graph. This method used to return a different graph
        as the union but now does not.
        """

    def valence(self, v: Vertex) -> int:
        """
        The number of edges incident with v. For unweighted
        graphs valence and degree are the same, except valence is an int
        while degree is a double.
        """

    def vertexAttributes(self) -> ghidra.util.graph.attributes.AttributeManager[Vertex]:
        """
        Returns the AttributeManager for the vertices of this graph.
        """

    def vertexIterator(self) -> GraphIterator[Vertex]:
        """
        Returns an iterator for the VertexSet of this graph.
        """

    def vertices(self) -> VertexSet:
        """
        Returns the VertexSet of this graph.
        """

    def verticesUnreachableFromSources(self) -> jpype.JArray[Vertex]:
        """
        Returns array of all vertices unreachable from a source. These are the
        vertices descending only from a non-trivial strongly connected component.
        """

    @staticmethod
    def verts2referentSet(verts: collections.abc.Sequence) -> java.util.Set[typing.Any]:
        """
        This method converts a collection of verticies into a set of its
        referent objects.  It is up to the methods using the created set 
        to properly type cast the set's elements.
        
        :param collections.abc.Sequence verts: the vertices
        :return: the set of referent objects
        :rtype: java.util.Set[typing.Any]
        """

    @property
    def entryPoints(self) -> java.util.Vector[Vertex]:
        ...

    @property
    def components(self) -> jpype.JArray[DirectedGraph]:
        ...

    @property
    def sources(self) -> jpype.JArray[Vertex]:
        ...

    @property
    def sinks(self) -> jpype.JArray[Vertex]:
        ...

    @property
    def referent(self) -> java.lang.Object:
        ...

    @property
    def edgeArray(self) -> jpype.JArray[Edge]:
        ...

    @property
    def verticesInContainingComponent(self) -> java.util.Set[Vertex]:
        ...

    @property
    def descendants(self) -> java.util.Set[Vertex]:
        ...

    @property
    def vertexWithKey(self) -> Vertex:
        ...

    @property
    def componentContaining(self) -> DirectedGraph:
        ...

    @property
    def edgeWithKey(self) -> Edge:
        ...

    @property
    def verticesHavingReferent(self) -> jpype.JArray[Vertex]:
        ...

    @property
    def children(self) -> java.util.Set[Vertex]:
        ...

    @property
    def neighborhood(self) -> java.util.Set[Vertex]:
        ...

    @property
    def ancestors(self) -> java.util.Set[Vertex]:
        ...

    @property
    def levels(self) -> ghidra.util.graph.attributes.IntegerAttribute[Vertex]:
        ...

    @property
    def vertexArray(self) -> jpype.JArray[Vertex]:
        ...

    @property
    def parents(self) -> java.util.Set[Vertex]:
        ...


class Vertex(KeyedObject, java.lang.Comparable[Vertex]):
    """
    An implementation of vertices for use in ghidra.util.graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, referent: java.lang.Object):
        """
        Creates a vertex tied to a referent object. The object the key refers
        to can be obtained from the vertex factory using the key of the vertex.
        If there is already a vertex having the same key as returned by
        KeyedObjectFactory.getInstance().getKeyForThisObject( Object o ), then a
        DuplicateKeyException is thrown and no vertex is created.
        """

    def compareTo(self, v: Vertex) -> int:
        """
        Compares two vertices by keys. If the specified object o is not a Vertex a
        ClassCastException will be thrown.
        """

    def name(self) -> str:
        """
        Return the name of this vertex. If the Vertex has a referent, the 
        referent's toString() method will be used to create the name. If
        the Vertex has a null referent, then the key will be used to determine
        the name.
        """

    def referent(self) -> java.lang.Object:
        """
        
        
        :return: The Object this vertex refers to specified at creation time.
        :rtype: java.lang.Object
        """


@typing.type_check_only
class EdgeSet(KeyIndexableSet[Edge]):
    """
    Container class for a set of edges (ghidra.util.graph.Edge).
    """

    @typing.type_check_only
    class EdgeSetIterator(GraphIterator[Edge]):
        """
        EdgeSetIterator uses the hasNext()/next() paradigm. Throws
            a ConcurrentModificationException if any addition or deletions to
            the backing EdgeSet are made except through the iterator's own methods.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            """
            Constructor
            """

        def remove(self) -> bool:
            """
            Removes the edge returned by the most recent call to next().
            """


    class_: typing.ClassVar[java.lang.Class]

    def add(self, e: Edge) -> bool:
        """
        Adds an edge to the graph. If either endpoint is not in the graph add it.
        If the edge is already in the graph return false and do nothing.
        
        :return: true if and only if the edge was sucessfully added.
        :rtype: bool
        """

    def capacity(self) -> int:
        """
        Returns the number of edges this edge set can hold without growing.
        """

    def clear(self):
        """
        Empties out the edge set while leaving the capacity alone. Much faster
            than removing the edges one by one.
        """

    def contains(self, edge: Edge) -> bool:
        """
        Return true if and only if the edge is contained in this EdgeSet.
        """

    def getModificationNumber(self) -> int:
        """
        Used to test if edges have been added or removed from this edge set.
        """

    def iterator(self) -> GraphIterator[Edge]:
        """
        Returns an iterator for this EdgeSet.
        """

    def remove(self, e: Edge) -> bool:
        """
        Removes an edge from this EdgeSet. Returns true if and only if the
        edge was in the EdgeSet and was sucessfully removed.
        """

    def size(self) -> int:
        """
        Returns the current number of edges within this edge set.
        """

    def toSet(self) -> java.util.Set[Edge]:
        """
        Get the edges in this EdgeSet as a java.util.Set.
        """

    @property
    def modificationNumber(self) -> jpype.JLong:
        ...


class DeterministicDependencyGraph(AbstractDependencyGraph[T], typing.Generic[T]):
    """
    Dependency Graph that uses :obj:`TreeMap`s and :obj:`ListOrderedSet`s to provide
    determinism in pulling (:meth:`pop() <.pop>`) from the graph.  This class seems to consume more
    memory than :obj:`DependencyGraph`, and if memory is not an issue, it also seems to be
    slightly faster as well.
     
    
    This class was implemented to provide determinism while doing
    developmental debugging.
    
    
    .. seealso::
    
        | :obj:`AbstractDependencyGraph`
    
        | :obj:`DependencyGraph`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, other: DeterministicDependencyGraph[T]):
        """
        Copy constructor
        
        :param DeterministicDependencyGraph[T] other: the other DependencyGraph to copy
        """


class GraphIterator(java.lang.Object, typing.Generic[T]):
    """
    Interface for VertexSet and EdgeSet iterators.
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        """
        Return true if the iterator has more elements
        """

    def next(self) -> T:
        """
        Returns next element in the iteration.
        
        :raises ConcurrentModificationException: if the backing set
        has been modified since the iterator was created.
        """

    def remove(self) -> bool:
        """
        Removes the object from the backing set safely
        """



__all__ = ["WeightedDigraph", "Dominator", "VertexSet", "DepthFirstSearch", "Edge", "KeyedObjectFactory", "SimpleWeightedDigraph", "DependencyGraph", "AddableLongIntHashtable", "AbstractDependencyGraph", "KeyedObject", "AddableLongDoubleHashtable", "Path", "KeyIndexableSet", "DirectedGraph", "Vertex", "EdgeSet", "DeterministicDependencyGraph", "GraphIterator"]
