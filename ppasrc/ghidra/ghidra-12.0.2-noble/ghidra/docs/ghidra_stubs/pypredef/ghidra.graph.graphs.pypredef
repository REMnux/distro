from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.graph
import ghidra.graph.jung
import java.lang # type: ignore
import java.util # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class DefaultVisualGraph(JungDirectedVisualGraph[V, E], typing.Generic[V, E]):
    """
    A default :obj:`VisualGraph` that implements basic setup for things like event processing.
     
     
    Notes:
     
    * Selected Vertices and the Focused Vertex - 
    there can be multiple selected vertices, but only a single focused vertex.
    :meth:`getSelectedVertices() <.getSelectedVertices>` will return both 
        the selected vertices or    the focused vertex if there are no vertices selected.
    * Clicking a single vertex will focus it.  Control-clicking multiple vertices will
            cause them all to be selected, with no focused vertex.
    
    * Rendering Edges - edges are rendered with or without articulations if 
        they have them.  This is built-in to the default graphing edge renderer.
        Some layouts require custom edge rendering and will provide their own
        renderer as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def dispose(self):
        ...

    def getAllEdges(self, v: V) -> java.lang.Iterable[E]:
        """
        A convenience method to combine retrieval of in and out edges for the given vertex
        
        :param V v: the vertex
        :return: the edges
        :rtype: java.lang.Iterable[E]
        """

    def getEdges(self, start: V, end: V) -> java.lang.Iterable[E]:
        """
        Returns all edges shared between the two given vertices
        
        :param V start: the start vertex
        :param V end: the end vertex
        :return: the edges
        :rtype: java.lang.Iterable[E]
        """

    @property
    def allEdges(self) -> java.lang.Iterable[E]:
        ...


class GroupingVisualGraph(DefaultVisualGraph[V, E], typing.Generic[V, E]):
    """
    A visual graph with methods needed to facilitate grouping of vertices.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def findMatchingVertex(self, v: V) -> V:
        """
        Finds a vertex that matches the given vertex.  
         
         
        Grouping can trigger vertex adds and removals.  This method is a way for subclasses
        to search for a vertex that matches the given vertex, but may or may not be the same 
        instance.
        
        :param V v: the vertex
        :return: the matching vertex or null
        :rtype: V
        """

    @typing.overload
    def findMatchingVertex(self, v: V, ignore: collections.abc.Sequence) -> V:
        """
        The same as :meth:`findMatchingVertex(VisualVertex) <.findMatchingVertex>`, except that you can provide a
        collection of vertices to be ignored.
         
         
        This is useful during graph transformations when duplicate vertices may be in the 
        graph at the same time.
        
        :param V v: the vertex
        :param collections.abc.Sequence ignore: vertices to ignore when searching
        :return: the matching vertex or null
        :rtype: V
        """


class FilteringVisualGraph(DefaultVisualGraph[V, E], typing.Generic[V, E]):
    """
    A graph implementation that allows clients to mark vertices and edges as filtered.  When
    filtered, a vertex is removed from this graph, but kept around for later unfiltering. Things
    of note:
     
    * As vertices are filtered, so to will be their edges
    
    * If additions are made to the graph while it is filtered, the new additions will
        not be added to the current graph, but will be kept in the background for later
        restoring
    
    * 
    
    
     
    Implementation Note: this class engages in some odd behavior when removals and additions
    are need to this graph.  A distinction is made between events that are generated from 
    external clients and those that happen due to filtering and restoring.  This distinction
    allows this class to know when to update this graph, based upon whether or not data has
    been filtered.   Implementation of this is achieved by using a flag.  Currently, this flag
    is thread-safe.  If this graph is to be multi-threaded (such as if changes are to be 
    made by multiple threads, then this update flag will have to be revisited to ensure thread
    visibility.
    """

    @typing.type_check_only
    class UnfilteredGraph(DefaultVisualGraph[V, E]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def clearFilter(self):
        ...

    def filterEdges(self, toFilter: collections.abc.Sequence):
        ...

    def filterVertices(self, toFilter: collections.abc.Sequence):
        ...

    @typing.overload
    def getAllEdges(self) -> java.util.Iterator[E]:
        ...

    @typing.overload
    def getAllEdges(self, sourceVertices: java.util.Set[V]) -> java.util.Set[E]:
        """
        Returns all edges connected to the given vertices.
         
         
        This method is needed if you wish to find relationships that have been filtered 
        out.
        
        :param java.util.Set[V] sourceVertices: the vertices for which to get the edges
        :return: the reachable edges
        :rtype: java.util.Set[E]
        """

    def getAllReachableVertices(self, sourceVertices: java.util.Set[V]) -> java.util.Set[V]:
        """
        Returns all vertices that are reachable by the given vertices.
         
         
        This method is needed if you wish to find relationships that have been filtered 
        out.
        
        :param java.util.Set[V] sourceVertices: the vertices for which to find the other reachable vertices
        :return: the reachable vertices
        :rtype: java.util.Set[V]
        """

    def getAllVertices(self) -> java.util.Iterator[V]:
        ...

    def getFilteredEdges(self) -> java.util.Iterator[E]:
        ...

    def getFilteredVertices(self) -> java.util.Iterator[V]:
        ...

    def getUnfilteredEdges(self) -> java.util.Iterator[E]:
        ...

    def getUnfilteredVertices(self) -> java.util.Iterator[V]:
        ...

    def isFiltered(self) -> bool:
        ...

    def unfilterEdges(self, toUnfilter: collections.abc.Sequence):
        """
        Restores the given filtered edges into the graph.  This will only happen if both
        endpoints are in the graph.
        
        :param collections.abc.Sequence toUnfilter: the edges to restore
        """

    def unfilterVertices(self, toUnfilter: collections.abc.Sequence):
        """
        Restores the given filtered vertices into the graph.  This will only happen if both
        endpoints are in the graph.
        
        :param collections.abc.Sequence toUnfilter: the edges to restore
        """

    @property
    def filteredEdges(self) -> java.util.Iterator[E]:
        ...

    @property
    def allReachableVertices(self) -> java.util.Set[V]:
        ...

    @property
    def allVertices(self) -> java.util.Iterator[V]:
        ...

    @property
    def filtered(self) -> jpype.JBoolean:
        ...

    @property
    def unfilteredEdges(self) -> java.util.Iterator[E]:
        ...

    @property
    def filteredVertices(self) -> java.util.Iterator[V]:
        ...

    @property
    def unfilteredVertices(self) -> java.util.Iterator[V]:
        ...

    @property
    def allEdges(self) -> java.util.Iterator[E]:
        ...


class JungDirectedVisualGraph(ghidra.graph.jung.JungDirectedGraph[V, E], ghidra.graph.VisualGraph[V, E], typing.Generic[V, E]):
    """
    A class to combine the :obj:`JungDirectedGraph` and the :obj:`VisualGraph` 
    interfaces
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["DefaultVisualGraph", "GroupingVisualGraph", "FilteringVisualGraph", "JungDirectedVisualGraph"]
