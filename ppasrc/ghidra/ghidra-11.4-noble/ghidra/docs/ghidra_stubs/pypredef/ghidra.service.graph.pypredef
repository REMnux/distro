from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing.event # type: ignore
import org.jgrapht.graph # type: ignore


class GraphActionContext(docking.DefaultActionContext):
    """
    The base ActionContext for the GraphDisplay instances.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, componentProvider: docking.ComponentProvider, graph: AttributedGraph, selectedVertices: java.util.Set[AttributedVertex], locatedVertex: AttributedVertex):
        ...

    def getFocusedVertex(self) -> AttributedVertex:
        """
        Returns the focused vertex (similar concept to the cursor in a text document)
        
        :return: the focused vertex
        :rtype: AttributedVertex
        """

    def getGraph(self) -> AttributedGraph:
        """
        Returns the graph
        
        :return: the graph
        :rtype: AttributedGraph
        """

    def getSelectedVertices(self) -> java.util.Set[AttributedVertex]:
        """
        Returns the set of selectedVertices in the graph
        
        :return: the set of selectedVertices in the graph
        :rtype: java.util.Set[AttributedVertex]
        """

    @property
    def selectedVertices(self) -> java.util.Set[AttributedVertex]:
        ...

    @property
    def focusedVertex(self) -> AttributedVertex:
        ...

    @property
    def graph(self) -> AttributedGraph:
        ...


class GraphDisplayListener(java.lang.Object):
    """
    Interface for being notified when the user interacts with a visual graph display
    """

    class_: typing.ClassVar[java.lang.Class]

    def cloneWith(self, graphDisplay: GraphDisplay) -> GraphDisplayListener:
        """
        Makes a new GraphDisplayListener of the same type as the specific
        instance of this GraphDisplayListener
        
        :param GraphDisplay graphDisplay: the new :obj:`GraphDisplay` the new listener will support
        :return: A new instance of a GraphDisplayListener that is the same type as the instance
        on which it is called
        :rtype: GraphDisplayListener
        """

    def dispose(self):
        """
        Tells the listener that it is no longer needed and it can release any listeners/resources.
        This will be called when a :obj:`GraphDisplay` is disposed or if this listener is replaced.
        """

    def locationFocusChanged(self, vertex: AttributedVertex):
        """
        Notification that the "focused" (active) vertex has changed
        
        :param AttributedVertex vertex: the vertex that is currently "focused"
        """

    def selectionChanged(self, vertices: java.util.Set[AttributedVertex]):
        """
        Notification that the set of selected vertices has changed
        
        :param java.util.Set[AttributedVertex] vertices: the set of currently selected vertices
        """


class EdgeGraphActionContext(GraphActionContext):
    """
    GraphActionContext for when user invokes a popup action on a graph edge.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, componentProvider: docking.ComponentProvider, graph: AttributedGraph, selectedVertices: java.util.Set[AttributedVertex], locatedVertex: AttributedVertex, clickedEdge: AttributedEdge):
        ...

    def getClickedEdge(self) -> AttributedEdge:
        """
        Returns the edge from where the popup menu was launched
        
        :return: the edge from where the popup menu was launched
        :rtype: AttributedEdge
        """

    @property
    def clickedEdge(self) -> AttributedEdge:
        ...


class GraphDisplay(java.lang.Object):
    """
    Interface for objects that display (or consume) graphs.  Normally, a graph display represents
    a visual component for displaying and interacting with a graph.  Some implementation may not
    be a visual component, but instead consumes/processes the graph (i.e. graph exporter). In this
    case, there is no interactive element and once the graph has been set on the display, it is
    closed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addAction(self, action: docking.action.DockingActionIf):
        """
        Adds the action to the graph display. Not all GraphDisplays support adding custom
        actions, so this may have no effect.
        
        :param docking.action.DockingActionIf action: the action to add
        """

    def clear(self):
        """
        Clears all graph vertices and edges from this graph display
        """

    def close(self):
        """
        Closes this graph display window.
        """

    def getActions(self) -> java.util.Collection[docking.action.DockingActionIf]:
        """
        Gets all actions that have been added to this graph display.  If this display does not
        support actions, then an empty collection will be returned.
        
        :return: the actions
        :rtype: java.util.Collection[docking.action.DockingActionIf]
        """

    def getFocusedVertex(self) -> AttributedVertex:
        """
        Returns the currently focused vertex or null if no vertex is focused
        
        :return: the currently focused vertex or null if no vertex is focused
        :rtype: AttributedVertex
        """

    def getGraph(self) -> AttributedGraph:
        """
        Returns the graph for this display
        
        :return: the graph for this display
        :rtype: AttributedGraph
        """

    def getGraphTitle(self) -> str:
        """
        Returns the title of the current graph
        
        :return: the title of the current graph
        :rtype: str
        """

    def getSelectedVertices(self) -> java.util.Set[AttributedVertex]:
        """
        Returns a set of vertex ids for all the currently selected vertices
        
        :return: a set of vertex ids for all the currently selected vertices
        :rtype: java.util.Set[AttributedVertex]
        """

    def selectVertices(self, vertexSet: java.util.Set[AttributedVertex], eventTrigger: docking.widgets.EventTrigger):
        """
        Tells the graph display window to select the vertices with the given ids
        
        :param java.util.Set[AttributedVertex] vertexSet: the set of vertices to select
        :param docking.widgets.EventTrigger eventTrigger: Provides a hint to the GraphDisplay as to why we are updating the
        graph location so that the GraphDisplay can decide if it should send out a notification via
        the :meth:`GraphDisplayListener.selectionChanged(Set) <GraphDisplayListener.selectionChanged>`. For example, if we are updating
        the location due to an event from the main application, we don't want to notify the
        application the graph changed to avoid event cycles. See :obj:`EventTrigger` for more
        information.
        """

    def setFocusedVertex(self, vertex: AttributedVertex, eventTrigger: docking.widgets.EventTrigger):
        """
        Tells the graph display window to focus the vertex with the given id
        
        :param AttributedVertex vertex: the vertex to focus
        :param docking.widgets.EventTrigger eventTrigger: Provides a hint to the GraphDisplay as to why we are updating the
        graph location so that the GraphDisplay can decide if it should send out a notification via
        the :meth:`GraphDisplayListener.locationFocusChanged(AttributedVertex) <GraphDisplayListener.locationFocusChanged>`. For example, if we
        are updating the location due to an event from the main application, we don't want to
        notify the application the graph changed to avoid event cycles. See :obj:`EventTrigger` for
        more information.
        """

    @typing.overload
    @deprecated("You should now use the form that takes in a GraphDisplayOptions")
    def setGraph(self, graph: AttributedGraph, title: typing.Union[java.lang.String, str], append: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Sets the graph to be displayed or consumed by this graph display
        
        :param AttributedGraph graph: the graph to display or consume
        :param java.lang.String or str title: a title for the graph
        :param ghidra.util.task.TaskMonitor monitor: a :obj:`TaskMonitor` which can be used to cancel the graphing operation
        :param jpype.JBoolean or bool append: if true, append the new graph to any existing graph
        :raises CancelledException: thrown if the graphing operation was cancelled
        
        .. deprecated::
        
        You should now use the form that takes in a :obj:`GraphDisplayOptions`
        """

    @typing.overload
    def setGraph(self, graph: AttributedGraph, options: GraphDisplayOptions, title: typing.Union[java.lang.String, str], append: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Sets the graph to be displayed or consumed by this graph display
        
        :param AttributedGraph graph: the graph to display or consume
        :param GraphDisplayOptions options: :obj:`GraphDisplayOptions` for configuring how the display will
        render vertices and edges based on there vertex type and edge type respectively.
        :param java.lang.String or str title: a title for the graph
        :param ghidra.util.task.TaskMonitor monitor: a :obj:`TaskMonitor` which can be used to cancel the graphing operation
        :param jpype.JBoolean or bool append: if true, append the new graph to any existing graph
        :raises CancelledException: thrown if the graphing operation was cancelled
        """

    def setGraphDisplayListener(self, listener: GraphDisplayListener):
        """
        Sets a :obj:`GraphDisplayListener` to be notified when the user changes the vertex focus
        or selects one or more nodes in a graph window
        
        :param GraphDisplayListener listener: the listener to be notified
        """

    def updateVertexName(self, vertex: AttributedVertex, newName: typing.Union[java.lang.String, str]):
        """
        Updates a vertex to a new name
        
        :param AttributedVertex vertex: the vertex to rename
        :param java.lang.String or str newName: the new name for the vertex
        """

    @property
    def graphTitle(self) -> java.lang.String:
        ...

    @property
    def selectedVertices(self) -> java.util.Set[AttributedVertex]:
        ...

    @property
    def focusedVertex(self) -> AttributedVertex:
        ...

    @property
    def actions(self) -> java.util.Collection[docking.action.DockingActionIf]:
        ...

    @property
    def graph(self) -> AttributedGraph:
        ...


class VertexGraphActionContext(GraphActionContext):
    """
    GraphActionContext for when user invokes a popup action on a graph vertex.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, componentProvider: docking.ComponentProvider, graph: AttributedGraph, selectedVertices: java.util.Set[AttributedVertex], locatedVertex: AttributedVertex, clickedVertex: AttributedVertex):
        ...

    def getClickedVertex(self) -> AttributedVertex:
        """
        Returns the vertex from where the popup menu was launched
        
        :return: the vertex from where the popup menu was launched
        :rtype: AttributedVertex
        """

    @property
    def clickedVertex(self) -> AttributedVertex:
        ...


class AttributedGraphExporter(ghidra.util.classfinder.ExtensionPoint):
    """
    Interface for exporting AttributedGraphs
    """

    class_: typing.ClassVar[java.lang.Class]

    def exportGraph(self, graph: AttributedGraph, file: jpype.protocol.SupportsPath):
        """
        Exports the given graph to the given writer
        
        :param AttributedGraph graph: the :obj:`AttributedGraph` to export
        :param jpype.protocol.SupportsPath file: the file to export to
        :raises IOException: if there is an error exporting the graph
        """

    def getDesciption(self) -> str:
        """
        Returns a description of the exporter
        
        :return: a description of the exporter
        :rtype: str
        """

    def getFileExtension(self) -> str:
        """
        Returns the suggested file extension to use for this exporter
        
        :return: the suggested file extension to use for this exporter
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of this exporter
        
        :return: the name of this exporter
        :rtype: str
        """

    @property
    def desciption(self) -> java.lang.String:
        ...

    @property
    def fileExtension(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class DummyGraphDisplayListener(GraphDisplayListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GraphDisplayProvider(ghidra.util.classfinder.ExtensionPoint):
    """
    Basic interface for objects that can display or otherwise consume a generic graph
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Disposes this GraphDisplayProvider
        """

    def getActiveGraphDisplay(self) -> GraphDisplay:
        """
        Returns the active graph display or null if there is no active graph display.  If only one
        graph is displayed, then that graph will be returned.  If multiple graphs are being
        displayed, then the most recently shown graph will be displayed, regardless of whether that
        is the active graph in terms of user interaction.
        
        :return: the active graph display or null if there is no active graph display.
        :rtype: GraphDisplay
        """

    def getAllGraphDisplays(self) -> java.util.List[GraphDisplay]:
        """
        Returns all known graph displays.  Typically they will be ordered by use, most recently
        first.
        
        :return: the displays
        :rtype: java.util.List[GraphDisplay]
        """

    def getGraphDisplay(self, reuseGraph: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> GraphDisplay:
        """
        Returns a GraphDisplay that can be used to "display" a graph
        
        :param jpype.JBoolean or bool reuseGraph: if true, this provider will attempt to re-use an existing GraphDisplay
        :param ghidra.util.task.TaskMonitor monitor: the :obj:`TaskMonitor` that can be used to monitor and cancel the operation
        :return: an object that can be used to display or otherwise consume (e.g., export) the graph
        :rtype: GraphDisplay
        :raises GraphException: thrown if there is a problem creating a GraphDisplay
        """

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Gets the help location for this GraphDisplayProvider
        
        :return: help location for this GraphDisplayProvider
        :rtype: ghidra.util.HelpLocation
        """

    def getName(self) -> str:
        """
        The name of this provider (for displaying as menu option when graphing)
        
        :return: the name of this provider.
        :rtype: str
        """

    def initialize(self, tool: ghidra.framework.plugintool.PluginTool, options: ghidra.framework.options.Options):
        """
        Provides an opportunity for this provider to register and read tool options
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool hosting this display
        :param ghidra.framework.options.Options options: the tool options for graphing
        """

    def optionsChanged(self, options: ghidra.framework.options.Options):
        """
        Called if the graph options change
        
        :param ghidra.framework.options.Options options: the current tool options
        """

    @property
    def allGraphDisplays(self) -> java.util.List[GraphDisplay]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def activeGraphDisplay(self) -> GraphDisplay:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...


class DefaultGraphDisplayOptions(GraphDisplayOptions):
    """
    Empty implementation of GraphDiaplayOptions. Used as an initial default to avoid null
    checks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AttributedGraph(org.jgrapht.graph.AbstractBaseGraph[AttributedVertex, AttributedEdge]):
    """
    Basic graph implementation for a directed graph whose vertices and edges support attributes.
     
    
    The graph can be configured as to how to handle multiple edges with the same source and destination
    vertices. One option is to simply allow multiple edges.  The second option is to collapse
    duplicate edges such that there is only ever one edge with the same
    source and destination.  In this case, each additional duplicate edge added will cause the
    edge to have a "Weight" attribute that will be the total number of edges that were added
    to the same source/destination vertex pair.
    """

    @typing.type_check_only
    class VertexSupplier(java.util.function.Supplier[AttributedVertex]):
        """
        Default VertexSupplier that uses a simple one up number for default vertex ids
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EdgeSupplier(java.util.function.Supplier[AttributedEdge]):
        """
        Default EdgeSupplier that uses a simple one up number for default edge ids
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    WEIGHT: typing.Final = "Weight"

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], type: GraphType):
        """
        Create a new empty AttributedGraph that automatically collapses duplicate edges
        
        :param java.lang.String or str name: the name of the graph
        :param GraphType type: the :obj:`GraphType` which defines valid vertex and edge types.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], type: GraphType, description: typing.Union[java.lang.String, str]):
        """
        Create a new empty AttributedGraph that automatically collapses duplicate edges
        
        :param java.lang.String or str name: the name of the graph
        :param GraphType type: the :obj:`GraphType` which defines valid vertex and edge types.
        :param java.lang.String or str description: a description of the graph
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], type: GraphType, description: typing.Union[java.lang.String, str], collapseDuplicateEdges: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new empty AttributedGraph.
        
        :param java.lang.String or str name: the name of the graph
        :param GraphType type: the :obj:`GraphType` which defines valid vertex and edge types.
        :param java.lang.String or str description: a description of the graph
        :param jpype.JBoolean or bool collapseDuplicateEdges: if true, duplicate edges will be collapsed into a single
        edge with a "Weight" attribute whose value is the number of edges between those vertices.
        """

    @typing.overload
    def addEdge(self, source: AttributedVertex, target: AttributedVertex, edgeId: typing.Union[java.lang.String, str]) -> AttributedEdge:
        """
        Creates and adds a new directed edge with the given id between the given source and
        target vertices. If the graph is set to collapse duplicate edges and an edge for that
        source and target exists, then the existing edge will be return with its "Weight" attribute
        set to the total number of edges that have been added between the source and target vertices.
        
        :param AttributedVertex source: the source vertex of the directed edge to be created.
        :param AttributedVertex target: the target vertex of the directed edge to be created.
        :param java.lang.String or str edgeId: the id to use for the new edge.  Note: if this is a duplicate and edges
        are being collapsed, then this edgeId will not be used.
        :return: a new edge between the source and target if it is the first one or the graph is
        not collapsing edges.  Otherwise, an existing edge with its "Weight" attribute set accordingly.
        :rtype: AttributedEdge
        """

    @typing.overload
    def addEdge(self, source: AttributedVertex, target: AttributedVertex, edge: AttributedEdge) -> bool:
        """
        Creates and adds a new directed edge with the given edge object. If the graph is set to
        collapse duplicate edges and an edge for that
        source and target exists, then the existing edge will be return with its "Weight" attribute
        set to the total number of edges that have been added between the source and target vertices.
        
        :param AttributedVertex source: the source vertex of the directed edge to be created.
        :param AttributedVertex target: the target vertex of the directed edge to be created.
        :param AttributedEdge edge: the BasicEdge object to use for the new edge.  Note: if this is a duplicate and
        edges are being collapsed, then this edge object will not be used.
        :return: true if the edge was added. Note that if this graph is collapsing duplicate edges, then
        it will always return true.
        :rtype: bool
        """

    @typing.overload
    def addEdge(self, source: AttributedVertex, target: AttributedVertex) -> AttributedEdge:
        """
        Creates and adds a new directed edge between the given source and
        target vertices. If the graph is set to collapse duplicate edges and an edge for that
        source and target exists, then the existing edge will be return with its "Weight" attribute
        set to the total number of edges that have been added between the source and target vertices.
        
        :param AttributedVertex source: the source vertex of the directed edge to be created.
        :param AttributedVertex target: the target vertex of the directed edge to be created.
        :return: a new edge between the source and target if it is the first one or the graph is
        not collapsing edges.  Otherwise, an existing edge with its "Weight" attribute set accordingly.
        :rtype: AttributedEdge
        """

    @typing.overload
    def addVertex(self, id: typing.Union[java.lang.String, str]) -> AttributedVertex:
        """
        Adds a new vertex with the given id.  The vertex's name will be the same as the id.
        If a vertex already exists with that id,
        then that vertex will be returned.
        
        :param java.lang.String or str id: the unique vertex id that the graph should have a vertex for.
        :return: either an existing vertex with that id, or a newly added vertex with that id
        :rtype: AttributedVertex
        """

    @typing.overload
    def addVertex(self, id: typing.Union[java.lang.String, str], vertexName: typing.Union[java.lang.String, str]) -> AttributedVertex:
        """
        Adds a new vertex with the given id and name.  If a vertex already exists with that id,
        then that vertex will be returned, but with its name changed to the given name.
        
        :param java.lang.String or str id: the unique vertex id that the graph should have a vertex for.
        :param java.lang.String or str vertexName: the name to associate with this vertex
        :return: either an existing vertex with that id, or a newly added vertex with that id
        :rtype: AttributedVertex
        """

    def getDescription(self) -> str:
        """
        Returns a description of the graph
        
        :return: a description of the graph
        :rtype: str
        """

    def getEdgeCount(self) -> int:
        """
        Returns the total number of edges in the graph
        
        :return: the total number of edges in the graph
        :rtype: int
        """

    def getGraphType(self) -> GraphType:
        """
        Returns the :obj:`GraphType` for this graph
        
        :return: the :obj:`GraphType` for this graph
        :rtype: GraphType
        """

    def getName(self) -> str:
        """
        Returns the name of the graph
        
        :return: the name of the graph
        :rtype: str
        """

    def getVertex(self, vertexId: typing.Union[java.lang.String, str]) -> AttributedVertex:
        """
        Returns the vertex with the given vertex id
        
        :param java.lang.String or str vertexId: the id of the vertex to retrieve
        :return: the vertex with the given vertex id or null if none found
        :rtype: AttributedVertex
        """

    def getVertexCount(self) -> int:
        """
        Returns the total number of vertices in the graph
        
        :return: the total number of vertices in the graph
        :rtype: int
        """

    @property
    def graphType(self) -> GraphType:
        ...

    @property
    def vertex(self) -> AttributedVertex:
        ...

    @property
    def edgeCount(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def vertexCount(self) -> jpype.JInt:
        ...


class GraphType(java.lang.Object):
    """
    Class that defines a new graph type. It defines the set of valid vertex and edge types
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], vertexTypes: java.util.List[java.lang.String], edgeTypes: java.util.List[java.lang.String]):
        """
        Constructs a new GraphType
        
        :param java.lang.String or str name: the name of this GraphType instance
        :param java.lang.String or str description: a brief description for graphs of this type
        :param java.util.List[java.lang.String] vertexTypes: a list of all valid vertex types for graphs of this type
        :param java.util.List[java.lang.String] edgeTypes: a list of all valid edge types for graphs of this type
        """

    def containsEdgeType(self, edgeType: typing.Union[java.lang.String, str]) -> bool:
        """
        Test if the given string is a valid edge type
        
        :param java.lang.String or str edgeType: the string to test for being a valid edge type
        :return: true if the given string is a valid edge type
        :rtype: bool
        """

    def containsVertexType(self, vertexType: typing.Union[java.lang.String, str]) -> bool:
        """
        Test if the given string is a valid vertex type
        
        :param java.lang.String or str vertexType: the string to test for being a valid vertex type
        :return: true if the given string is a valid vertex type
        :rtype: bool
        """

    def getDescription(self) -> str:
        """
        Returns a description for this type of graph
        
        :return: a description for this type of graph
        :rtype: str
        """

    def getEdgeTypes(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of valid edge types for graphs of this type
        
        :return: a list of valid edge types for graphs of this type
        :rtype: java.util.List[java.lang.String]
        """

    def getName(self) -> str:
        """
        Returns a name for this type of graph
        
        :return: a name of this type of graph
        :rtype: str
        """

    def getOptionsName(self) -> str:
        ...

    def getVertexTypes(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of valid vertex types for graphs of this type
        
        :return: a list of valid vertex types for graphs of this type
        :rtype: java.util.List[java.lang.String]
        """

    @property
    def optionsName(self) -> java.lang.String:
        ...

    @property
    def edgeTypes(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def vertexTypes(self) -> java.util.List[java.lang.String]:
        ...


class GraphDisplayOptionsBuilder(java.lang.Object):
    """
    Builder for building :obj:`GraphDisplayOptions`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graphType: GraphType):
        """
        Create a new GraphDisplayOptionsBuilder
        
        :param GraphType graphType: the :obj:`GraphType` of graphs that this instance configures.
        """

    def arrowLength(self, length: typing.Union[jpype.JInt, int]) -> GraphDisplayOptionsBuilder:
        """
        Sets the length of the arrows to display in the graph. The width will be sized proportionately.
        
        :param jpype.JInt or int length: the length the arrows to display in the graph
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def build(self) -> GraphDisplayOptions:
        """
        Returns a GraphTypeDisplayOptions as configured by this builder
        
        :return: a GraphTypeDisplayOptions as configured by this builder
        :rtype: GraphDisplayOptions
        """

    def defaultEdgeColor(self, c: java.awt.Color) -> GraphDisplayOptionsBuilder:
        """
        Sets the default edge color for edges that don't have a registered edge type
        
        :param java.awt.Color c: the default edge color
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def defaultLayoutAlgorithm(self, string: typing.Union[java.lang.String, str]) -> GraphDisplayOptionsBuilder:
        """
        Sets the name of the layout algorithm that will be used to initially layout the graph
        
        :param java.lang.String or str string: the name of the layout algoritm to use to initially layout the graph
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def defaultVertexColor(self, c: java.awt.Color) -> GraphDisplayOptionsBuilder:
        """
        Sets the default vertex color for vertexes that don't have a registered vertex type
        
        :param java.awt.Color c: the default vertex color
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def defaultVertexShape(self, vertexShape: VertexShape) -> GraphDisplayOptionsBuilder:
        """
        Sets the default vertex shape for vertices that don't have a registered vertex type
        
        :param VertexShape vertexShape: the :obj:`VertexShape` to use as a default
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def edge(self, edgeType: typing.Union[java.lang.String, str], color: java.awt.Color) -> GraphDisplayOptionsBuilder:
        """
        Sets the color for edges of the given type
        
        :param java.lang.String or str edgeType: the edge type to assign color
        :param java.awt.Color color: the color to use for the named edge type
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def edgeColorOverrideAttribute(self, colorAttributeKey: typing.Union[java.lang.String, str]) -> GraphDisplayOptionsBuilder:
        """
        Sets the attribute used to override the color for a edge
        
        :param java.lang.String or str colorAttributeKey: the attribute key to use for overriding an edge color
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def edgeSelectionColor(self, color: java.awt.Color) -> GraphDisplayOptionsBuilder:
        """
        Sets the edge selection color
        
        :param java.awt.Color color: the edge selection color
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def labelPosition(self, labelPosition: GraphLabelPosition) -> GraphDisplayOptionsBuilder:
        """
        Sets the vertex label position relative to vertex shape. This is only applicable if the
        :meth:`useIcons(boolean) <.useIcons>` is set to false.
        
        :param GraphLabelPosition labelPosition: the relative position to place the vertex label
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def maxNodeCount(self, maxNodeCount: typing.Union[jpype.JInt, int]) -> GraphDisplayOptionsBuilder:
        """
        Sets the maximum number of nodes a graph can have and still be displayed.
        
        :param jpype.JInt or int maxNodeCount: the maximum number of nodes
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def shapeOverrideAttribute(self, shapeAttributeKey: typing.Union[java.lang.String, str]) -> GraphDisplayOptionsBuilder:
        """
        Sets the attribute used to override the shape for a vertex
        
        :param java.lang.String or str shapeAttributeKey: the attribute key to use of shape override
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def useIcons(self, b: typing.Union[jpype.JBoolean, bool]) -> GraphDisplayOptionsBuilder:
        """
        Sets drawing "mode" for the graph display. If true, vertices are drawn as scaled
        cached images with the label inside the shapes. If false, vertices are drawn as smaller
        shapes with labels drawn near the shapes.
        
        :param jpype.JBoolean or bool b: true to use pre-rendered icon images
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def vertex(self, vertexType: typing.Union[java.lang.String, str], vertexShape: VertexShape, color: java.awt.Color) -> GraphDisplayOptionsBuilder:
        """
        Sets the shape and color for vertices of the given type
        
        :param java.lang.String or str vertexType: the vertex type to assign shape and color
        :param VertexShape vertexShape: the shape to use for the named vertex type
        :param java.awt.Color color: the color to use for the named vertex type
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def vertexColorOverrideAttribute(self, colorAttributeKey: typing.Union[java.lang.String, str]) -> GraphDisplayOptionsBuilder:
        """
        Sets the attribute used to override the color for a vertex
        
        :param java.lang.String or str colorAttributeKey: the attribute key to use for overriding a vertex color
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """

    def vertexSelectionColor(self, color: java.awt.Color) -> GraphDisplayOptionsBuilder:
        """
        Sets the vertex selection color
        
        :param java.awt.Color color: the vertex selection color
        :return: this GraphDisplayOptionsBuilder
        :rtype: GraphDisplayOptionsBuilder
        """


class VertexShape(java.lang.Object):
    """
    Class for defining shapes to use for rendering vertices in a graph
    """

    @typing.type_check_only
    class RectangleVertexShape(VertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EllipseVertexShape(VertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TriangleUpVertexShape(VertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TriangleDownVertexShape(VertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StarVertexShape(VertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DiamondVertexShape(VertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EquilateralPolygonVertexShape(VertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PentagonVertexShape(VertexShape.EquilateralPolygonVertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HexagonVertexShape(VertexShape.EquilateralPolygonVertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OctagonVertexShape(VertexShape.EquilateralPolygonVertexShape):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    RECTANGLE: typing.ClassVar[VertexShape]
    ELLIPSE: typing.ClassVar[VertexShape]
    TRIANGLE_UP: typing.ClassVar[VertexShape]
    TRIANGLE_DOWN: typing.ClassVar[VertexShape]
    STAR: typing.ClassVar[VertexShape]
    DIAMOND: typing.ClassVar[VertexShape]
    PENTAGON: typing.ClassVar[VertexShape]
    HEXAGON: typing.ClassVar[VertexShape]
    OCTAGON: typing.ClassVar[VertexShape]

    def getLabelPosition(self) -> float:
        """
        Gets the relative amount of margin space to allocate above the label. The default is
        0.5 which will center the label in the associated shape. A value closer to 0 will move
        the label closer to the top and a value closer to 1 will move the label closer to the 
        bottom.
        
        :return: the relative amount of margin space to allocate obove the label.s
        :rtype: float
        """

    def getMaxWidthToHeightRatio(self) -> int:
        """
        This is a factor to keep some shapes from being so distorted by very long labels that they
        effectively lose their shape when seen by the user
        
        :return: the max width to height ratio
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of the shape
        
        :return: the name of the shape
        :rtype: str
        """

    @typing.overload
    def getShape(self) -> java.awt.Shape:
        """
        Returns the :obj:`Shape` for this :obj:`VertexShape` instance
        
        :return: the :obj:`Shape` for this :obj:`VertexShape` instance
        :rtype: java.awt.Shape
        """

    @staticmethod
    @typing.overload
    def getShape(shapeName: typing.Union[java.lang.String, str]) -> VertexShape:
        """
        Returns the :obj:`VertexShape` for the given shape name
        
        :param java.lang.String or str shapeName: the name of the shape for which to get the :obj:`VertexShape`
        :return: the :obj:`VertexShape` for the given shape name
        :rtype: VertexShape
        """

    @staticmethod
    def getShapeNames() -> java.util.List[java.lang.String]:
        """
        Returns a list of names for all the supported :obj:`VertexShape`s
        
        :return: a list of names for all the supported :obj:`VertexShape`s
        :rtype: java.util.List[java.lang.String]
        """

    def getShapeToLabelRatio(self) -> float:
        """
        Returns the size factor for a shape relative to its label. Shapes are sized based on the
        label of a vertex so that the label can fit inside the shape (mostly). Some subclasses
        will need to override this value to some value > 1 to fit the label in the shape. For 
        example, a rectangle shape does not need to be extended because text naturally fits. But
        for a shape like a triangle, its bounding box needs to be bigger so that text doesn't
        "stick out" in the narrow part of the triangle.
        
        :return: the size factor for a shape relatvie to its label
        :rtype: float
        """

    @property
    def shapeToLabelRatio(self) -> jpype.JDouble:
        ...

    @property
    def shape(self) -> java.awt.Shape:
        ...

    @property
    def labelPosition(self) -> jpype.JDouble:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def maxWidthToHeightRatio(self) -> jpype.JInt:
        ...


class GraphLabelPosition(java.lang.Enum[GraphLabelPosition]):
    """
    Specification for the vertex label position relative to the vertex shape.
    """

    class_: typing.ClassVar[java.lang.Class]
    NORTH: typing.Final[GraphLabelPosition]
    NORTHEAST: typing.Final[GraphLabelPosition]
    EAST: typing.Final[GraphLabelPosition]
    SOUTHEAST: typing.Final[GraphLabelPosition]
    SOUTH: typing.Final[GraphLabelPosition]
    SOUTHWEST: typing.Final[GraphLabelPosition]
    WEST: typing.Final[GraphLabelPosition]
    NORTHWEST: typing.Final[GraphLabelPosition]
    CENTER: typing.Final[GraphLabelPosition]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GraphLabelPosition:
        ...

    @staticmethod
    def values() -> jpype.JArray[GraphLabelPosition]:
        ...


class LayoutAlgorithmNames(java.lang.Object):
    """
    Just a static list of graph layout algorithm names
    """

    class_: typing.ClassVar[java.lang.Class]
    FORCED_BALANCED: typing.Final = "Force Balanced"
    FORCE_DIRECTED: typing.Final = "Force Directed"
    CIRCLE: typing.Final = "Circle"
    COMPACT_HIERARCHICAL: typing.Final = "Compact Hierarchical"
    COMPACT_RADIAL: typing.Final = "Compact Radial"
    MIN_CROSS_TOP_DOWN: typing.Final = "Hierarchical MinCross Top Down"
    MIN_CROSS_LONGEST_PATH: typing.Final = "Hierarchical MinCross Longest Path"
    MIN_CROSS_NETWORK_SIMPLEX: typing.Final = "Hierarchical MinCross Network Simplex"
    MIN_CROSS_COFFMAN_GRAHAM: typing.Final = "Hierarchical MinCross Coffman Graham"
    VERT_MIN_CROSS_TOP_DOWN: typing.Final = "Vertical Hierarchical MinCross Top Down"
    VERT_MIN_CROSS_LONGEST_PATH: typing.Final = "Vertical Hierarchical MinCross Longest Path"
    VERT_MIN_CROSS_NETWORK_SIMPLEX: typing.Final = "Vertical Hierarchical MinCross Network Simplex"
    VERT_MIN_CROSS_COFFMAN_GRAHAM: typing.Final = "Vertical Hierarchical MinCross Coffman Graham"
    HIERACHICAL: typing.Final = "Hierarchical"
    RADIAL: typing.Final = "Radial"
    BALLOON: typing.Final = "Balloon"
    GEM: typing.Final = "GEM"

    def __init__(self):
        ...

    @staticmethod
    def getLayoutAlgorithmNames() -> java.util.List[java.lang.String]:
        ...


class GraphDisplayOptions(ghidra.framework.options.OptionsChangeListener):
    """
    Class for managing graph display options. This includes color options for each vertex
    and edge type and shapes for vertex types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graphType: GraphType):
        """
        Constructs a new GraphTypeDisplayOptions for the given :obj:`GraphType`
        
        :param GraphType graphType: The :obj:`GraphType` for which to define display options
        """

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Adds a ChangeListener to be notified when display options change
        
        :param javax.swing.event.ChangeListener listener: the listener to be notified.
        """

    def displayEditor(self, tool: docking.Tool, help: ghidra.util.HelpLocation):
        """
        Pop up a dialog for editing these graph display options. If the options
        are registered with tool options, show the tool options with the appropriate
        graph options selected. Otherwise, show an editor for locally editing these
        options.
        
        :param docking.Tool tool: the tool
        :param ghidra.util.HelpLocation help: the help location to use if the options are edited locally
        """

    def getArrowLength(self) -> int:
        """
        Returns the length of the arrow. The width will be proportional to the length.
        Note: this option is not exposed in the Options because it is too specific to a graph
        instance and wouldn't be appropriate to apply to shared options.
        
        :return: the size if the arrow
        :rtype: int
        """

    def getDefaultEdgeColor(self) -> java.awt.Color:
        """
        Returns the default color for edges that don't have an edge type set
        
        :return: the default color for edges that don't have an edge type set
        :rtype: java.awt.Color
        """

    def getDefaultLayoutAlgorithmNameLayout(self) -> str:
        """
        Returns the name of the default graph layout algorithm
        
        :return: the name of the default graph layout algorithms
        :rtype: str
        """

    def getDefaultVertexColor(self) -> java.awt.Color:
        """
        Returns the default color for vertices that don't have an vertex type set
        
        :return: the default color for vertices that don't have an vertex type set
        :rtype: java.awt.Color
        """

    def getDefaultVertexShape(self) -> VertexShape:
        """
        returns the :obj:`VertexShape` for any vertex that has not vertex type defined
        
        :return: the :obj:`VertexShape` for any vertex that has not vertex type defined
        :rtype: VertexShape
        """

    @typing.overload
    def getEdgeColor(self, edge: AttributedEdge) -> java.awt.Color:
        """
        Returns the color that will be used to draw the edge
        
        :param AttributedEdge edge: the edge for which to get the color
        :return: the color that will be used to draw the edge
        :rtype: java.awt.Color
        """

    @typing.overload
    def getEdgeColor(self, edgeType: typing.Union[java.lang.String, str]) -> java.awt.Color:
        """
        Returns the color for the given edge type
        
        :param java.lang.String or str edgeType: the edge type whose color is to be determined.
        :return: the color for the given edge type.
        :rtype: java.awt.Color
        """

    def getEdgeColorOverrideAttributeKey(self) -> str:
        """
        Returns the attribute key that can be used to override the color of an edge
        
        :return: the attribute key that can be used to override the color of an edge
        :rtype: str
        """

    def getEdgePriority(self, edgeType: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the priority for the given edge type. This is used by layout algorithms to
        determine which edges should have more influence on the layout.
        
        :param java.lang.String or str edgeType: the edge type for which to get it's priority
        :return: the priority for the given edge type
        :rtype: int
        """

    def getEdgeSelectionColor(self) -> java.awt.Color:
        """
        Returns the color for edge selections
        
        :return: the color fore edge selections
        :rtype: java.awt.Color
        """

    def getFavoredEdgeType(self) -> str:
        """
        Returns the edge type that is the preferred edge for layout purposes
        
        :return: the edge type that is the preferred edge for layout purposes
        :rtype: str
        """

    def getFont(self) -> java.awt.Font:
        """
        Returns the font being used to render vertex labels
        
        :return: the font being used to render vertex labels
        :rtype: java.awt.Font
        """

    def getGraphType(self) -> GraphType:
        """
        Returns the :obj:`GraphType` that this object provides display options for
        
        :return: the :obj:`GraphType` that this object provides display options for
        :rtype: GraphType
        """

    def getLabelPosition(self) -> GraphLabelPosition:
        """
        Returns the label position relative to the vertex. Note this is only relevant
        if :meth:`usesIcons() <.usesIcons>` is false
        
        :return: the label position relative to the vertex
        :rtype: GraphLabelPosition
        """

    def getMaxNodeCount(self) -> int:
        """
        Returns the maximum number of nodes that can be in a displayed graph
        
        :return: the maximum number of nodes that can be in a displayed graph
        :rtype: int
        """

    def getRootOptionsName(self) -> str:
        """
        Returns the name for the root Options name for this :obj:`GraphDisplayOptions`
        
        :return: the name for the root Options name for this :obj:`GraphDisplayOptions`
        :rtype: str
        """

    @typing.overload
    def getVertexColor(self, vertex: AttributedVertex) -> java.awt.Color:
        """
        Returns the color that will be used to draw the vertex
        
        :param AttributedVertex vertex: the vertex for which to get the color
        :return: the color that will be used to draw the vertex
        :rtype: java.awt.Color
        """

    @typing.overload
    def getVertexColor(self, vertexType: typing.Union[java.lang.String, str]) -> java.awt.Color:
        """
        Returns the color for the given vertex type
        
        :param java.lang.String or str vertexType: the vertex type to get the color for
        :return: the color for the given vertex type
        :rtype: java.awt.Color
        """

    def getVertexColorOverrideAttributeKey(self) -> str:
        """
        Returns the attribute key that can be used to override the color of a vertex. Normally,
        a vertex is colored based on its vertex type. However, if this value is non-null, a vertex
        can override its color by setting an attribute using this key name.
        
        :return: the attribute key that can be used to override the color of a vertex
        :rtype: str
        """

    def getVertexLabel(self, vertex: AttributedVertex) -> str:
        """
        Returns the text that will be displayed as the label for the given vertex
        
        :param AttributedVertex vertex: the vertex for which to get label text
        :return: the text that will be displayed as the label for the given vertex
        :rtype: str
        """

    def getVertexLabelOverride(self) -> str:
        """
        Returns the attribute key that can override the vertices label text
        
        :return: the attribute key that can override the vertices label text
        :rtype: str
        """

    def getVertexSelectionColor(self) -> java.awt.Color:
        """
        Returns the vertex selection color
        
        :return: the vertex selection color
        :rtype: java.awt.Color
        """

    @typing.overload
    def getVertexShape(self, vertex: AttributedVertex) -> VertexShape:
        """
        Returns the :obj:`VertexShape` that will be used to draw the vertex's shape
        
        :param AttributedVertex vertex: the vertex for which to get the shape
        :return: the :obj:`VertexShape` that will be used to draw the vertex's shape
        :rtype: VertexShape
        """

    @typing.overload
    def getVertexShape(self, vertexType: typing.Union[java.lang.String, str]) -> VertexShape:
        """
        Returns the :obj:`VertexShape` for vertices that have the given vertex type
        
        :param java.lang.String or str vertexType: the vertex type for which to get its asigned shape
        :return: the :obj:`VertexShape` for vertices that have the given vertex type
        :rtype: VertexShape
        """

    def getVertexShapeOverrideAttributeKey(self) -> str:
        """
        Returns the attribute key that can be used to override the shape of a vertex. Normally,
        a vertex has a shape based on its vertex type. However, if this value is non-null, a vertex
        can override its shape by setting an attribute using this key name.
        
        :return: the attribute key that can be used to override the shape of a vertex
        :rtype: str
        """

    def initializeFromOptions(self, tool: docking.Tool):
        """
        Loads values from tool options
        
        :param docking.Tool tool: the tool from which to update values.
        """

    def isRegisteredWithTool(self) -> bool:
        """
        Returns true if this :obj:`GraphDisplayOptions` instance has been constructed with
        a tool for getting/saving option values in the tool options
        
        :return: true if this :obj:`GraphDisplayOptions` instance is connected to tool options
        :rtype: bool
        """

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Removes the listener so that it won't be notified of changes any longer
        
        :param javax.swing.event.ChangeListener listener: the listener to be removed
        """

    def setArrowLength(self, length: typing.Union[jpype.JInt, int]):
        """
        Sets the length of the arrow. The width will be proportional to the length.
        Note: this option is not exposed in the Options because it is too specific to a graph
        instance and wouldn't be appropriate to apply to shared options.
        
        :param jpype.JInt or int length: the size of the arrow
        """

    @typing.overload
    def setDefaultEdgeColor(self, color: java.awt.Color):
        """
        Sets the default color to be used by edges that don't have a edge type set
        
        :param java.awt.Color color: the default edge shape
        """

    @typing.overload
    def setDefaultEdgeColor(self, themeColorId: typing.Union[java.lang.String, str]):
        """
        Sets the default color to be used by vertices that don't have a vertex type set. The
        color is set via a themeColorId, which means the client defined a theme color for this.
        
        :param java.lang.String or str themeColorId: the theme color id to use for the default vertex color
        """

    def setDefaultLayoutAlgorithmName(self, defaultLayout: typing.Union[java.lang.String, str]):
        """
        Sets the name of the default layout algorithm
        
        :param java.lang.String or str defaultLayout: the name of the layout algorithm to use by default
        """

    @typing.overload
    def setDefaultVertexColor(self, color: java.awt.Color):
        """
        Sets the default color to be used by vertices that don't have a vertex type set
        
        :param java.awt.Color color: the default vertex shape
        """

    @typing.overload
    def setDefaultVertexColor(self, themeColorId: typing.Union[java.lang.String, str]):
        """
        Sets the default color to be used by vertices that don't have a vertex type set. The
        color is set via a themeColorId, which means the client defined a theme color for this.
        
        :param java.lang.String or str themeColorId: the theme color id to use for the default vertex color
        """

    def setDefaultVertexShape(self, shape: VertexShape):
        """
        Sets the default shape to be used by vertices that don't have a vertex type set
        
        :param VertexShape shape: the default vertex shape
        """

    @typing.overload
    def setEdgeColor(self, edgeType: typing.Union[java.lang.String, str], themeColorId: typing.Union[java.lang.String, str]):
        """
        Sets the edge color using a theme color id. By using a theme color id, this property
        is eligible to be registered as a tool option.
        
        :param java.lang.String or str edgeType: the edge type for which to set its color
        :param java.lang.String or str themeColorId: the theme color id of the color for this edge type
        """

    @typing.overload
    def setEdgeColor(self, edgeType: typing.Union[java.lang.String, str], color: java.awt.Color):
        """
        Sets the color for edges with the given edge type
        
        :param java.lang.String or str edgeType: the edge type for which to set its color
        :param java.awt.Color color: the new color for edges with the given edge type
        """

    def setEdgeColorOverrideAttributeKey(self, attributeKey: typing.Union[java.lang.String, str]):
        """
        Sets the attribute key that can be used to override the color for an edge. Normally, the
        color is determined by the edge type, which will be mapped to a color
        
        :param java.lang.String or str attributeKey: the attribute key that, if set, will be used to define the edge's color
        """

    @typing.overload
    def setEdgeSelectionColor(self, edgeSelectionColor: java.awt.Color):
        """
        Sets the edge selection color. Using the method means the color will not appear in the
        tool options.
        
        :param java.awt.Color edgeSelectionColor: color to use for highlighting selected edges
        """

    @typing.overload
    def setEdgeSelectionColor(self, themeColorId: typing.Union[java.lang.String, str]):
        """
        Sets the edge selection color using the theme color defined by the given color id. This
        method will allow the property to be registered to the tool options.
        
        :param java.lang.String or str themeColorId: the color id to use for highlighting edges.
        """

    def setFavoredEdgeType(self, favoredEdgeType: typing.Union[java.lang.String, str]):
        """
        Sets the favored edge type. The favored edge type is used to influence layout algorithms
        
        :param java.lang.String or str favoredEdgeType: the edge type that is to be favored by layout algorithms
        """

    @typing.overload
    def setFont(self, font: java.awt.Font):
        """
        Sets the font to use for drawing vertex labels
        
        :param java.awt.Font font: the font to use for drawing vertex labels
        """

    @typing.overload
    def setFont(self, themeFontId: typing.Union[java.lang.String, str]):
        ...

    def setLabelPosition(self, labelPosition: GraphLabelPosition):
        """
        Sets the label position relative to the vertex. Note this is only relevant
        if :meth:`usesIcons() <.usesIcons>` is false.
        
        :param GraphLabelPosition labelPosition: the :obj:`GraphLabelPosition` to use for rendering vertex labels
        """

    def setMaxNodeCount(self, maxNodeCount: typing.Union[jpype.JInt, int]):
        """
        Sets the maximum number of nodes a graph can have and still be displayed. Be careful,
        setting this value too high can result in Ghidra running out of memory and/or
        making the system very sluggish.
        
        :param jpype.JInt or int maxNodeCount: the maximum number of nodes a graph can have and still be displayed.
        """

    def setUsesIcons(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether the graph rendering mode is to use icons or not. If using icons, the label and
        shape are drawn together into a cached icon. Otherwise, the shapes are drawn on the fly and
        labeled separately.
        
        :param jpype.JBoolean or bool b: true to render in icon mode.
        """

    @typing.overload
    def setVertexColor(self, vertexType: typing.Union[java.lang.String, str], color: java.awt.Color):
        """
        Sets the color for vertices with the given vertex type. Note that this method does not
        allow the vertex color to be registered in tool options.
        See :meth:`setVertexColor(String, String) <.setVertexColor>`.
        
        :param java.lang.String or str vertexType: the vertex type for which to set its color
        :param java.awt.Color color: the color to use for vertices with the given vertex type
        """

    @typing.overload
    def setVertexColor(self, vertexType: typing.Union[java.lang.String, str], themeColorId: typing.Union[java.lang.String, str]):
        """
        Sets the vertex color using a theme color id. By using a theme color id, this property
        is eligible to be registered as a tool option.
        
        :param java.lang.String or str vertexType: the vertex type for which to set its color
        :param java.lang.String or str themeColorId: the theme color id of the color for this vertex type
        """

    def setVertexColorOverrideAttributeKey(self, attributeKey: typing.Union[java.lang.String, str]):
        """
        Sets the attribute key that can be used to override the color for a vertex. Normally, the
        color is determined by the vertex type, which will be mapped to a color
        
        :param java.lang.String or str attributeKey: the attribute key that, if set, will be used to define the vertice's color
        """

    def setVertexLabelOverrideAttributeKey(self, attributeKey: typing.Union[java.lang.String, str]):
        """
        Sets the attribute key that can be used to override the label text shown for the vertex.
        Normally, the vertex's name is shown as the label.
        
        :param java.lang.String or str attributeKey: the attribute key that, if set, will be used to define the vertice's label
        """

    @typing.overload
    def setVertexSelectionColor(self, vertexSelectionColor: java.awt.Color):
        """
        Sets the vertex selection color. Use this method only if this color does not appear in
        the tool options.
        
        :param java.awt.Color vertexSelectionColor: the color to use for highlighting selected vertices
        """

    @typing.overload
    def setVertexSelectionColor(self, themeColorId: typing.Union[java.lang.String, str]):
        """
        Sets the vertex selection color using the theme color defined by the given color id. This
        method will allow the property to be registered to the tool options.
        
        :param java.lang.String or str themeColorId: the color id to use for highlighting vertices.
        """

    def setVertexShape(self, vertexType: typing.Union[java.lang.String, str], vertexShape: VertexShape):
        """
        Sets the :obj:`VertexShape` to use for vertices with the given vertex type
        
        :param java.lang.String or str vertexType: the vertex type for which to set its shape
        :param VertexShape vertexShape: the :obj:`VertexShape` to use for vertices with the given vertex type
        """

    def setVertexShapeOverrideAttributeKey(self, attributeKey: typing.Union[java.lang.String, str]):
        """
        Sets the attribute key that can be used to override the shape for a vertex. Normally, the
        shape is determined by the vertex type, which will be mapped to a shape
        
        :param java.lang.String or str attributeKey: the attribute key that, if set, will be used to define the vertice's shape
        """

    def usesIcons(self) -> bool:
        """
        Returns true if the rendering mode is to use icons for the vertices. If using
        icons, the label is drawn inside the shape.
        
        :return: true if the rendering mode is to use icons.
        :rtype: bool
        """

    @property
    def rootOptionsName(self) -> java.lang.String:
        ...

    @property
    def maxNodeCount(self) -> jpype.JInt:
        ...

    @maxNodeCount.setter
    def maxNodeCount(self, value: jpype.JInt):
        ...

    @property
    def defaultLayoutAlgorithmNameLayout(self) -> java.lang.String:
        ...

    @property
    def defaultVertexShape(self) -> VertexShape:
        ...

    @defaultVertexShape.setter
    def defaultVertexShape(self, value: VertexShape):
        ...

    @property
    def edgeColorOverrideAttributeKey(self) -> java.lang.String:
        ...

    @edgeColorOverrideAttributeKey.setter
    def edgeColorOverrideAttributeKey(self, value: java.lang.String):
        ...

    @property
    def labelPosition(self) -> GraphLabelPosition:
        ...

    @labelPosition.setter
    def labelPosition(self, value: GraphLabelPosition):
        ...

    @property
    def edgePriority(self) -> jpype.JInt:
        ...

    @property
    def favoredEdgeType(self) -> java.lang.String:
        ...

    @favoredEdgeType.setter
    def favoredEdgeType(self, value: java.lang.String):
        ...

    @property
    def vertexShape(self) -> VertexShape:
        ...

    @property
    def vertexColorOverrideAttributeKey(self) -> java.lang.String:
        ...

    @vertexColorOverrideAttributeKey.setter
    def vertexColorOverrideAttributeKey(self, value: java.lang.String):
        ...

    @property
    def graphType(self) -> GraphType:
        ...

    @property
    def vertexSelectionColor(self) -> java.awt.Color:
        ...

    @vertexSelectionColor.setter
    def vertexSelectionColor(self, value: java.awt.Color):
        ...

    @property
    def vertexShapeOverrideAttributeKey(self) -> java.lang.String:
        ...

    @vertexShapeOverrideAttributeKey.setter
    def vertexShapeOverrideAttributeKey(self, value: java.lang.String):
        ...

    @property
    def defaultVertexColor(self) -> java.awt.Color:
        ...

    @defaultVertexColor.setter
    def defaultVertexColor(self, value: java.awt.Color):
        ...

    @property
    def defaultEdgeColor(self) -> java.awt.Color:
        ...

    @defaultEdgeColor.setter
    def defaultEdgeColor(self, value: java.awt.Color):
        ...

    @property
    def vertexLabel(self) -> java.lang.String:
        ...

    @property
    def edgeColor(self) -> java.awt.Color:
        ...

    @property
    def vertexLabelOverride(self) -> java.lang.String:
        ...

    @property
    def registeredWithTool(self) -> jpype.JBoolean:
        ...

    @property
    def edgeSelectionColor(self) -> java.awt.Color:
        ...

    @edgeSelectionColor.setter
    def edgeSelectionColor(self, value: java.awt.Color):
        ...

    @property
    def vertexColor(self) -> java.awt.Color:
        ...

    @property
    def font(self) -> java.awt.Font:
        ...

    @font.setter
    def font(self, value: java.awt.Font):
        ...

    @property
    def arrowLength(self) -> jpype.JInt:
        ...

    @arrowLength.setter
    def arrowLength(self, value: jpype.JInt):
        ...


class EmptyGraphType(GraphType):
    """
    Default GraphType implementation that has no vertex or edge types defined
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Attributed(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def clear(self):
        """
        removes all key/value mappings
        """

    def entrySet(self) -> java.util.Set[java.util.Map.Entry[java.lang.String, java.lang.String]]:
        """
        Returns a :obj:`Set` containing the key/value entry associations
        
        :return: a :obj:`Set` containing the key/value entry associations
        :rtype: java.util.Set[java.util.Map.Entry[java.lang.String, java.lang.String]]
        """

    def getAttribute(self, key: typing.Union[java.lang.String, str]) -> str:
        """
        gets the value of the given attribute name
        
        :param java.lang.String or str key: attribute name
        :return: the mapped value for the supplied key
        :rtype: str
        """

    def getAttributes(self) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Returns an unmodifiable view of the attribute map
        
        :return: an unmodifiable view of the attribute map
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def getDescription(self) -> str:
        """
        gets the description of this Attributed object.
        
        :return: the description of this Attributed object.
        :rtype: str
        """

    def hasAttribute(self, key: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if there is an attribute with that name
        
        :param java.lang.String or str key: attribute key
        :return: true if there is an attribute with that name
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        Return true if there are no attributes
        
        :return: true if there are no mapped attributes
        :rtype: bool
        """

    def keys(self) -> java.util.Set[java.lang.String]:
        """
        Returns the keys for the attributes
        
        :return: the keys for the attributes
        :rtype: java.util.Set[java.lang.String]
        """

    def putAttributes(self, map: collections.abc.Mapping):
        """
        Adds all the key/value pairs from the given map as attributes
        
        :param collections.abc.Mapping map: a map of key/values to add as attributes
        """

    def removeAttribute(self, key: typing.Union[java.lang.String, str]) -> str:
        """
        Removes the attribute with the given key
        
        :param java.lang.String or str key: attribute key
        :return: the value of the removed attribute
        :rtype: str
        """

    def setAttribute(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> str:
        """
        Sets the attribute with the given key and value
        
        :param java.lang.String or str key: attribute key
        :param java.lang.String or str value: attribute value
        :return: the previous value of the attribute
        :rtype: str
        """

    def setDescription(self, value: typing.Union[java.lang.String, str]) -> str:
        """
        Sets a description for this Attributed object
        
        :param java.lang.String or str value: text that provides a description for this Attributed object. 
        The text can be either a plain string or an HTML string.
        :return: the previously set description
        :rtype: str
        """

    def size(self) -> int:
        """
        Returns the number of attributes defined
        
        :return: the number of attributes defined
        :rtype: int
        """

    def values(self) -> java.util.Collection[java.lang.String]:
        """
        Returns the attribute values
        
        :return: the attribute values
        :rtype: java.util.Collection[java.lang.String]
        """

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def attributes(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def attribute(self) -> java.lang.String:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class AttributedEdge(Attributed):
    """
    Generic directed graph edge implementation
    """

    class_: typing.ClassVar[java.lang.Class]
    EDGE_TYPE_KEY: typing.Final = "EdgeType"

    def __init__(self, id: typing.Union[java.lang.String, str]):
        """
        Constructs a new GhidraEdge
        
        :param java.lang.String or str id: the unique id for the edge
        """

    def getEdgeType(self) -> str:
        """
        Returns the edge type for this edge
        
        :return: the edge type for this edge
        :rtype: str
        """

    def getId(self) -> str:
        """
        Returns the id for this edge
        
        :return: the id for this edge
        :rtype: str
        """

    def setEdgeType(self, edgeType: typing.Union[java.lang.String, str]):
        """
        Sets the edge type for this edge. Should be a value defined by the :obj:`GraphType` for
        this graph, but there is no enforcement for this. If the value is not defined in GraphType,
        it will be rendered using the default edge color for :obj:`GraphType`
        
        :param java.lang.String or str edgeType: the edge type for this edge
        """

    @property
    def edgeType(self) -> java.lang.String:
        ...

    @edgeType.setter
    def edgeType(self, value: java.lang.String):
        ...

    @property
    def id(self) -> java.lang.String:
        ...


class AttributedVertex(Attributed):
    """
    Graph vertex with attributes
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME_KEY: typing.Final = "Name"
    VERTEX_TYPE_KEY: typing.Final = "VertexType"

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Constructs a new GhidraVertex with the given id and name
        
        :param java.lang.String or str id: the unique id for the vertex
        :param java.lang.String or str name: the name for the vertex
        """

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str]):
        ...

    def getId(self) -> str:
        """
        Returns the id for this vertex
        
        :return: the id for this vertex
        :rtype: str
        """

    def getName(self) -> str:
        """
        returns the name of the vertex
        
        :return: the name of the vertex
        :rtype: str
        """

    def getVertexType(self) -> str:
        """
        Returns the vertex type for this vertex
        
        :return: the vertex type for this vertex
        :rtype: str
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name on the vertex
        
        :param java.lang.String or str name: the new name for the vertex
        """

    def setVertexType(self, vertexType: typing.Union[java.lang.String, str]):
        """
        Sets the vertex type for this vertex. Should be a value defined by the :obj:`GraphType` for
        this graph, but there is no enforcement for this. If the value is not defined in GraphType,
        it will be rendered using the default vertex shape and color for the :obj:`GraphType`
        
        :param java.lang.String or str vertexType: the vertex type for this vertex
        """

    @property
    def vertexType(self) -> java.lang.String:
        ...

    @vertexType.setter
    def vertexType(self, value: java.lang.String):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def id(self) -> java.lang.String:
        ...


class GraphTypeBuilder(java.lang.Object):
    """
    Builder class for building new :obj:`GraphType`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Create a new builder
        
        :param java.lang.String or str name: the name of the new :obj:`GraphType`
        """

    def build(self) -> GraphType:
        """
        Builds a new GraphType
        
        :return: a new GraphType
        :rtype: GraphType
        """

    def description(self, text: typing.Union[java.lang.String, str]) -> GraphTypeBuilder:
        """
        Sets the description for the :obj:`GraphType`
        
        :param java.lang.String or str text: the description
        :return: this GraphTypeBuilder
        :rtype: GraphTypeBuilder
        """

    def edgeType(self, type: typing.Union[java.lang.String, str]) -> GraphTypeBuilder:
        """
        Defines a new edge type
        
        :param java.lang.String or str type: a string that names a new edge type
        :return: this GraphTypeBuilder
        :rtype: GraphTypeBuilder
        """

    def vertexType(self, type: typing.Union[java.lang.String, str]) -> GraphTypeBuilder:
        """
        Defines a new vertex type
        
        :param java.lang.String or str type: a string that names a new vertex type
        :return: this GraphTypeBuilder
        :rtype: GraphTypeBuilder
        """



__all__ = ["GraphActionContext", "GraphDisplayListener", "EdgeGraphActionContext", "GraphDisplay", "VertexGraphActionContext", "AttributedGraphExporter", "DummyGraphDisplayListener", "GraphDisplayProvider", "DefaultGraphDisplayOptions", "AttributedGraph", "GraphType", "GraphDisplayOptionsBuilder", "VertexShape", "GraphLabelPosition", "LayoutAlgorithmNames", "GraphDisplayOptions", "EmptyGraphType", "Attributed", "AttributedEdge", "AttributedVertex", "GraphTypeBuilder"]
