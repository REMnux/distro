from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.google.common.base # type: ignore
import edu.uci.ics.jung.algorithms.layout # type: ignore
import edu.uci.ics.jung.visualization.renderers # type: ignore
import ghidra.graph
import ghidra.util.classfinder
import ghidra.util.task
import java.awt # type: ignore
import java.awt.geom # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


E = typing.TypeVar("E")
G = typing.TypeVar("G")
V = typing.TypeVar("V")


class LayoutProvider(java.lang.Object, typing.Generic[V, E, G]):
    """
    A layout provider creates :obj:`VisualGraphLayout` instances.  This class provides a name
    and icon for use in a UI.  These features can be used to create a menu of layouts that may 
    be applied. 
     
     
    The pattern of usage for this class is for it to create the layout that it represents and
    then to apply the locations of that layout to the vertices (and edges, in the case of
    articulating edges) of the graph before returning the new layout.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getActionIcon(self) -> javax.swing.Icon:
        """
        Returns an icon that can be used to show the provider a menu or toolbar.  This may 
        return null, as an icon is not a requirement.
        
        :return: an icon that can be used to show the provider a menu or toolbar
        :rtype: javax.swing.Icon
        """

    def getLayout(self, graph: G, monitor: ghidra.util.task.TaskMonitor) -> VisualGraphLayout[V, E]:
        """
        Returns a new instance of the layout that this class provides
        
        :param G graph: the graph
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :return: the new layout
        :rtype: VisualGraphLayout[V, E]
        :raises CancelledException: if the monitor was cancelled
        """

    def getLayoutName(self) -> str:
        """
        Returns the name of this layout
        
        :return: the name of this layout
        :rtype: str
        """

    def getPriorityLevel(self) -> int:
        """
        Returns an arbitrary value that is relative to other LayoutProviders.  The higher the 
        value the more preferred the provider will be over other providers.
        
        :return: the priority
        :rtype: int
        """

    @property
    def actionIcon(self) -> javax.swing.Icon:
        ...

    @property
    def priorityLevel(self) -> jpype.JInt:
        ...

    @property
    def layoutName(self) -> java.lang.String:
        ...


class JungLayout(JungWrappingVisualGraphLayoutAdapter[V, E], typing.Generic[V, E]):
    """
    A class that defines a simple Jung :obj:`Layout` interface for 
    :obj:`Visual Vertices <VisualVertex>` and :obj:`VisualEdge`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, jungLayout: edu.uci.ics.jung.algorithms.layout.Layout[V, E]):
        ...


class GridCoordinates(java.lang.Object):
    """
    Tracks the mapping of grid coordinates (rows, columns) to space coordinates (x, y)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rowCoordinates: jpype.JArray[jpype.JInt], columnCoordinates: jpype.JArray[jpype.JInt]):
        """
        Constructor
        
        :param jpype.JArray[jpype.JInt] rowCoordinates: an array containing the y locations for all rows in a grid
        :param jpype.JArray[jpype.JInt] columnCoordinates: an array containing the x locations for all columns in a grid
        """

    def columnCount(self) -> int:
        """
        returns the number of columns in the grid.
        
        :return: the number of columns in the grid
        :rtype: int
        """

    def getBounds(self) -> java.awt.Rectangle:
        """
        Returns the total bounds for the grid
        
        :return: the total bounds for the grid
        :rtype: java.awt.Rectangle
        """

    def rowCount(self) -> int:
        """
        returns the number of rows in the grid.
        
        :return: the number of rows in the grid
        :rtype: int
        """

    def x(self, col: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the x value for a given column.
        
        :param jpype.JInt or int col: the column index in the grid
        :return: the x coordinate assigned to the given column index
        :rtype: int
        """

    def y(self, row: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the y value for a given row.
        
        :param jpype.JInt or int row: the row index in the grid
        :return: the y coordinate assigned to the given row index
        :rtype: int
        """

    @property
    def bounds(self) -> java.awt.Rectangle:
        ...


class VisualGraphLayout(edu.uci.ics.jung.algorithms.layout.Layout[V, E], typing.Generic[V, E]):
    """
    The interface for defining functions provided that are additional to that of :obj:`Layout`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addLayoutListener(self, listener: LayoutListener[V, E]):
        """
        Adds a layout listener
        
        :param LayoutListener[V, E] listener: the listener
        """

    def calculateLocations(self, graph: ghidra.graph.VisualGraph[V, E], monitor: ghidra.util.task.TaskMonitor) -> LayoutPositions[V, E]:
        """
        Signals to again layout the current graph.  The locations generated by the layout will
        be returned, but not actually applied to the graph.  This allows clients to generate new
        locations and then apply them in a delayed fashion, like for animation.
        
        :param ghidra.graph.VisualGraph[V, E] graph: the graph that contains the vertices to layout
        :param ghidra.util.task.TaskMonitor monitor: the task monitor used to report progress or to cancel
        :return: the layout locations
        :rtype: LayoutPositions[V, E]
        """

    def cloneLayout(self, newGraph: ghidra.graph.VisualGraph[V, E]) -> VisualGraphLayout[V, E]:
        """
        Creates a new version of this layout using the given graph.  Also, the new layout will
        have the same state as this layout (i.e., vertex positions (and edge articulations, 
        if applicable)).
        
        :param ghidra.graph.VisualGraph[V, E] newGraph: the new graph for the new layout
        :return: the new layout
        :rtype: VisualGraphLayout[V, E]
        """

    def dispose(self):
        """
        Cleanup any resource being managed by this layout.
        """

    def getEdgeLabelRenderer(self) -> edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel[V, E]:
        """
        Returns an optional custom edge label renderer.  This is used to add labels to the edges.
        
        :return: an optional renderer
        :rtype: edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel[V, E]
        """

    def getEdgeRenderer(self) -> edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer[V, E]:
        """
        Returns an optional edge renderer.  This is used to render each edge.
        
        :return: an optional edge renderer
        :rtype: edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer[V, E]
        """

    def getEdgeShapeTransformer(self) -> com.google.common.base.Function[E, java.awt.Shape]:
        """
        Returns an optional edge shape transformer.  This is used to create shapes for each edge.
        
        :return: an optional edge shape transformer
        :rtype: com.google.common.base.Function[E, java.awt.Shape]
        """

    def getVisualGraph(self) -> ghidra.graph.VisualGraph[V, E]:
        """
        Returns the graph of this layout
        
        :return: the graph of this layout
        :rtype: ghidra.graph.VisualGraph[V, E]
        """

    def removeLayoutListener(self, listener: LayoutListener[V, E]):
        """
        Removes a layout listener
        
        :param LayoutListener[V, E] listener: the listener
        """

    def setLocation(self, v: V, location: java.awt.geom.Point2D, changeType: LayoutListener.ChangeType):
        """
        Allows the client to change the location while specifying the type of change
        
        :param V v: the vertex
        :param java.awt.geom.Point2D location: the new location
        :param LayoutListener.ChangeType changeType: the type of change
        """

    def usesEdgeArticulations(self) -> bool:
        """
        Returns true if this layout uses articulated edges.  All :obj:`VisualEdge`s have the
        ability to articulate.  This method servers as a shortcut for algorithms so that they 
        need not loop over all edges to determine if they have articulations.  (Looping over
        large graphs is time intensive.)
         
         
        `What are articulations? <../VisualEdge.html#articulations>`_
        
        :return: true if this layout uses articulated edges.
        :rtype: bool
        """

    @property
    def edgeRenderer(self) -> edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer[V, E]:
        ...

    @property
    def edgeLabelRenderer(self) -> edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel[V, E]:
        ...

    @property
    def visualGraph(self) -> ghidra.graph.VisualGraph[V, E]:
        ...

    @property
    def edgeShapeTransformer(self) -> com.google.common.base.Function[E, java.awt.Shape]:
        ...


class GridPoint(java.lang.Object):
    """
    Row and column information for points in a :obj:`GridLocationMap`. Using these instead
    of java Points, makes the code that translates from grid space to layout space much less
    confusing.
    """

    class_: typing.ClassVar[java.lang.Class]
    row: jpype.JInt
    col: jpype.JInt

    @typing.overload
    def __init__(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, point: GridPoint):
        ...


class LayoutLocationMap(java.lang.Object, typing.Generic[V, E]):
    """
    A class that holds row and column data for each vertex and edge.  
     
     
    This class will take in a :obj:`GridLocationMap`, which is comprised of grid index 
    values, not layout space points.  Then, the grid values will be used to calculate 
    offsets and size for each row and column. Each row has a y location and a height; each 
    column has an x location and a width. The height and width are uniform in size across 
    all rows and columns, based upon the tallest and widest vertex in the graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gridLocations: GridLocationMap[V, E], transformer: com.google.common.base.Function[V, java.awt.Shape], isCondensed: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        ...

    def articulations(self, e: E) -> java.util.List[GridPoint]:
        ...

    @typing.overload
    def col(self, v: V) -> Column[V]:
        ...

    @typing.overload
    def col(self, gridX: typing.Union[jpype.JInt, int]) -> Column[V]:
        ...

    def columns(self) -> java.util.Collection[Column[V]]:
        """
        Returns the columns in this location map, sorted from lowest index to highest
        
        :return: the columns in this location map, sorted from lowest index to highest
        :rtype: java.util.Collection[Column[V]]
        """

    def dispose(self):
        ...

    def getColOffsets(self) -> java.util.List[java.lang.Integer]:
        ...

    def getColumnContaining(self, x: typing.Union[jpype.JInt, int]) -> Column[V]:
        ...

    def getColumnCount(self) -> int:
        ...

    def getGridCoordinates(self) -> GridCoordinates:
        ...

    def getRowCount(self) -> int:
        ...

    def getRowOffsets(self) -> java.util.List[java.lang.Integer]:
        ...

    def gridX(self, col: Column) -> int:
        ...

    def gridY(self, row: Row[V]) -> int:
        ...

    def isCondensed(self) -> bool:
        ...

    def lastColumn(self) -> Column[V]:
        ...

    def lastRow(self) -> Row[V]:
        ...

    def nextColumn(self, column: Column[V]) -> Column[V]:
        ...

    @typing.overload
    def row(self, v: V) -> Row[V]:
        ...

    @typing.overload
    def row(self, gridY: typing.Union[jpype.JInt, int]) -> Row[V]:
        ...

    def rows(self) -> java.util.Collection[Row[V]]:
        """
        Returns the rows in this location map, sorted from lowest index to highest
        
        :return: the rows in this location map, sorted from lowest index to highest
        :rtype: java.util.Collection[Row[V]]
        """

    @property
    def columnContaining(self) -> Column[V]:
        ...

    @property
    def condensed(self) -> jpype.JBoolean:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def columnCount(self) -> jpype.JInt:
        ...

    @property
    def rowOffsets(self) -> java.util.List[java.lang.Integer]:
        ...

    @property
    def gridCoordinates(self) -> GridCoordinates:
        ...

    @property
    def colOffsets(self) -> java.util.List[java.lang.Integer]:
        ...


class JungLayoutProviderFactory(java.lang.Object):
    """
    A factory to produce :obj:`JungLayoutProvider`s that can be used to layout 
    :obj:`VisualGraph`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def create(name: typing.Union[java.lang.String, str], layoutClass: java.lang.Class[edu.uci.ics.jung.algorithms.layout.Layout]) -> JungLayoutProvider[V, E, G]:
        ...

    @staticmethod
    def createLayouts() -> java.util.Set[JungLayoutProvider[V, E, G]]:
        ...


class LayoutPositions(java.lang.Object, typing.Generic[V, E]):
    """
    Simple container class to hold vertex locations (points) and edge articulation locations 
    (points).  The only complicated code in this class is the use of transformers to create 
    copies of the given points as they are accessed so that the original points remain unmodified.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createEmptyPositions() -> LayoutPositions[V, E]:
        ...

    @staticmethod
    def createNewPositions(vertexLocations: collections.abc.Mapping, edgeArticulations: collections.abc.Mapping) -> LayoutPositions[V, E]:
        ...

    def dispose(self):
        ...

    @staticmethod
    def getCurrentPositions(graph: ghidra.graph.VisualGraph[V, E], graphLayout: edu.uci.ics.jung.algorithms.layout.Layout[V, E]) -> LayoutPositions[V, E]:
        ...

    def getEdgeArticulations(self) -> java.util.Map[E, java.util.List[java.awt.geom.Point2D]]:
        ...

    def getVertexLocations(self) -> java.util.Map[V, java.awt.geom.Point2D]:
        ...

    @property
    def vertexLocations(self) -> java.util.Map[V, java.awt.geom.Point2D]:
        ...

    @property
    def edgeArticulations(self) -> java.util.Map[E, java.util.List[java.awt.geom.Point2D]]:
        ...


class JungLayoutProvider(AbstractLayoutProvider[V, E, G], typing.Generic[V, E, G]):
    """
    A layout provider that works on :obj:`JungDirectedVisualGraph`s.  This class allows the 
    Jung layouts to be used where :obj:`VisualGraph`s are used.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractVisualGraphLayout(edu.uci.ics.jung.algorithms.layout.AbstractLayout[V, E], VisualGraphLayout[V, E], typing.Generic[V, E]):
    """
    A base layout that marries the Visual Graph and Jung layout interfaces.   This class allows
    you to create new layouts while stubbing the Jung layout methods.
    
     
    This class essentially takes in client-produced grid row and column indices and
    produces layout locations for those values.
    
     
    This an implementation the Jung :obj:`Layout` interface that handles most of the
    layout implementation for you.  Things to know:
     
    * You should call initialize() inside of your constructor
    * You must implement :meth:`performInitialGridLayout(VisualGraph) <.performInitialGridLayout>` - this is where
    you align your vertices (and optionally edge articulations) on a grid.  This grid
    will be translated into layout space points for you.
    * If you wish to use articulation points in your edges, you must override
    :meth:`usesEdgeArticulations() <.usesEdgeArticulations>` to return true.
    
    
     
    
    .. _column_centering:
    
    By default, this class will create x-position values that
    are aligned with the column's x-position.   You can override
    :meth:`getVertexLocation(VisualVertex, Column, Row, Rectangle) <.getVertexLocation>` in order to center the
    vertex within its column
    :meth:`getCenteredVertexLocation(VisualVertex, Column, Row, Rectangle) <.getCenteredVertexLocation>`.  Also note though
    that if your layout returns true for :meth:`isCondensedLayout() <.isCondensedLayout>`,
    then the centering will be condensed and slightly off.
    
    
    .. seealso::
    
        | :obj:`GridLocationMap`
    
        | :obj:`LayoutPositions`
    """

    class_: typing.ClassVar[java.lang.Class]

    def createClonedLayout(self, newGraph: ghidra.graph.VisualGraph[V, E]) -> AbstractVisualGraphLayout[V, E]:
        """
        This class has implemented :meth:`cloneLayout(VisualGraph) <.cloneLayout>` in order to properly
        initialize location information in the layout so that subclasses do not have to.  Each
        subclass still needs to create the new instance of the layout that is being cloned, as
        this class does not know how to do so.
        
        :param ghidra.graph.VisualGraph[V, E] newGraph: the new graph for the new layout
        :return: the new layout
        :rtype: AbstractVisualGraphLayout[V, E]
        """

    def getLayoutName(self) -> str:
        """
        Returns the name of this layout
        
        :return: the name of this layout
        :rtype: str
        """

    def setTaskMonitor(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    @property
    def layoutName(self) -> java.lang.String:
        ...


class Column(java.lang.Object, typing.Generic[V]):
    """
    A column in a grid.   This class stores its column index, its x offset and its width.  The
    x value is the layout space x value of a :obj:`Point2D` object.   That is, unlike the
    :obj:`GridLocationMap`, the x value of this object is in layout space and not indexes 
    of a grid.
     
     
    This class maintains a collection of vertices on this column, organized by column index.  You
    can get the column of a vertex from :meth:`getRow(Object) <.getRow>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    x: jpype.JInt
    """
    The **layout** x coordinate of the column
    """

    width: jpype.JInt
    index: jpype.JInt
    """
    The grid index of this column (0, 1...n) for the number of columns
    """


    def __init__(self, index: typing.Union[jpype.JInt, int]):
        ...

    def getPaddedWidth(self, isCondensed: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getRow(self, v: V) -> int:
        ...

    def isInitialized(self) -> bool:
        ...

    def isOpenBetween(self, startRow: typing.Union[jpype.JInt, int], endRow: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def setRow(self, v: V, row: typing.Union[jpype.JInt, int]):
        ...

    @property
    def initialized(self) -> jpype.JBoolean:
        ...

    @property
    def row(self) -> jpype.JInt:
        ...

    @property
    def paddedWidth(self) -> jpype.JInt:
        ...


class LayoutListener(java.lang.Object, typing.Generic[V, E]):
    """
    A listener for layout changes.
    """

    class ChangeType(java.lang.Enum[LayoutListener.ChangeType]):

        class_: typing.ClassVar[java.lang.Class]
        USER: typing.Final[LayoutListener.ChangeType]
        TRANSIENT: typing.Final[LayoutListener.ChangeType]
        RESTORE: typing.Final[LayoutListener.ChangeType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LayoutListener.ChangeType:
            ...

        @staticmethod
        def values() -> jpype.JArray[LayoutListener.ChangeType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def vertexLocationChanged(self, v: V, point: java.awt.geom.Point2D, changeType: LayoutListener.ChangeType):
        """
        Called when a vertex location has changed.
        
        :param V v: the vertex
        :param java.awt.geom.Point2D point: the new vertex location
        :param LayoutListener.ChangeType changeType: the type of the change
        """


class CalculateLayoutLocationsTask(ghidra.util.task.Task, typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, graph: ghidra.graph.VisualGraph[V, E], layout: VisualGraphLayout[V, E]):
        ...

    def getLocations(self) -> LayoutPositions[V, E]:
        ...

    @property
    def locations(self) -> LayoutPositions[V, E]:
        ...


class GridBounds(java.lang.Object):
    """
    Tracks the minimum and maximum indexes for both rows and columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def contains(self, p: GridPoint) -> bool:
        ...

    def maxCol(self) -> int:
        ...

    def maxRow(self) -> int:
        ...

    def minCol(self) -> int:
        ...

    def minRow(self) -> int:
        ...

    def shift(self, rowShift: typing.Union[jpype.JInt, int], colShift: typing.Union[jpype.JInt, int]):
        """
        Shifts the columns bounds by the given amount
        
        :param jpype.JInt or int rowShift: the amount to shift the row bounds.
        :param jpype.JInt or int colShift: the amount to shift the column bounds.
        :raises IllegalArgumentException: if the shift would make the minimum column negative
        """

    def update(self, p: GridPoint):
        """
        Updates the bounds for the given GridPoint.
        
        :param GridPoint p: the gridPoint used to update the minimums and maximums
        """


class JungWrappingVisualGraphLayoutAdapter(VisualGraphLayout[V, E], typing.Generic[V, E]):
    """
    A wrapper that allows for existing Jung layouts to be used inside of the Visual Graph system.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, jungLayout: edu.uci.ics.jung.algorithms.layout.Layout[V, E]):
        ...


class LayoutProviderExtensionPoint(LayoutProvider[V, E, G], ghidra.util.classfinder.ExtensionPoint, typing.Generic[V, E, G]):
    """
    A version of :obj:`LayoutProvider` that is discoverable at runtime.   Layouts that do not wish 
    to be discoverable should implement :obj:`LayoutProvider` directly, not this interface.
    """

    class_: typing.ClassVar[java.lang.Class]


class Row(java.lang.Object, typing.Generic[V]):
    """
    A row in a grid.   This class stores its row index, its y offset and its height.   The
    y value is the layout space y value of a :obj:`Point2D` object.   That is, unlike the
    :obj:`GridLocationMap`, the y value of this object is in layout space and not indexes 
    of a grid.
     
     
    This class maintains a collection of vertices on this row, organized by column index.  You
    can get the column of a vertex from :meth:`getColumn(Object) <.getColumn>`
    """

    class_: typing.ClassVar[java.lang.Class]
    y: jpype.JInt
    """
    The **layout** y coordinate of the column
    """

    height: jpype.JInt
    index: jpype.JInt
    """
    The grid index of this row (0, 1...n) for the number of rows
    """


    def getColumn(self, v: V) -> int:
        """
        Returns the column index for the given vertex
        
        :param V v: the vertex
        :return: the column index for the given vertex
        :rtype: int
        """

    def getColumnCount(self) -> int:
        """
        Represents the range of columns in this row.  For this given row in a grid:
         
            0 1 2 3 4 5 6
            - - v - v - - 
         
        the column count is 3--where the column range is 2-4, inclusive.   
         
         
        Note: this differs from then number of vertices in this row, as the column count
        includes columns that have no vertex.
        
        :return: the number of columns in this row, including empty columns between start and end
        :rtype: int
        """

    def getEndColumn(self) -> int:
        """
        Returns the largest column index in this row
        
        :return: the largest column index in this row
        :rtype: int
        """

    def getPaddedHeight(self, isCondensed: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getStartColumn(self) -> int:
        """
        Returns the smallest column index in this row
        
        :return: the smallest column index in this row
        :rtype: int
        """

    def getVertex(self, column: typing.Union[jpype.JInt, int]) -> V:
        """
        Returns the vertex at the given column index or null if there is no vertex at that column
        
        :param jpype.JInt or int column: the column index
        :return: the vertex
        :rtype: V
        """

    def getVertices(self) -> java.util.List[V]:
        """
        Returns all vertices in this row, sorted by column index (min to max).   
         
         
        Note: the index of a vertex in the list does not match the column index.  To get the
        column index for a vertex, call :meth:`getColumn(V) <.getColumn>`.
        
        :return: all vertices in this row
        :rtype: java.util.List[V]
        """

    def isInitialized(self) -> bool:
        ...

    def setColumn(self, v: V, col: typing.Union[jpype.JInt, int]):
        """
        Sets the column index in this row for the given vertex
        
        :param V v: the vertex
        :param jpype.JInt or int col: the column index
        """

    @property
    def endColumn(self) -> jpype.JInt:
        ...

    @property
    def vertex(self) -> V:
        ...

    @property
    def vertices(self) -> java.util.List[V]:
        ...

    @property
    def startColumn(self) -> jpype.JInt:
        ...

    @property
    def column(self) -> jpype.JInt:
        ...

    @property
    def initialized(self) -> jpype.JBoolean:
        ...

    @property
    def paddedHeight(self) -> jpype.JInt:
        ...

    @property
    def columnCount(self) -> jpype.JInt:
        ...


class GridRange(java.lang.Object):
    """
    Class for reporting the min/max columns in a row or the min/max rows in a column
    """

    class_: typing.ClassVar[java.lang.Class]
    min: jpype.JInt
    max: jpype.JInt

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        ...

    def add(self, value: typing.Union[jpype.JInt, int]):
        ...

    def contains(self, value: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def isEmpty(self) -> bool:
        ...

    def width(self) -> int:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class GridLocationMap(java.lang.Object, typing.Generic[V, E]):
    """
    An object that maps vertices and edge articulation points to rows and columns in a grid. This
    class is essentially a container that allows layout algorithms to store results as it lays
    out vertices and edges in a virtual grid. Later, this information can be used in conjunction 
    with vertex size information and padding information to transform these grid coordinates to
    layout space coordinates.
     
    
    This object also has methods for manipulating the grid such as shifting it up, down, left, right,
    and merging in other GridLocationMaps
     
    
    After building the grid using this class, clients can call :meth:`rows() <.rows>`, :meth:`rowsMap() <.rowsMap>`,
    or :meth:`columnsMap() <.columnsMap>` to get high-order objects that represent rows or columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, root: V, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        """
        Constructor that includes an initial "root" vertex.
        
        :param V root: the initial vertex
        :param jpype.JInt or int row: the row for the initial vertex
        :param jpype.JInt or int col: the column for the initial vertex.
        """

    def add(self, other: GridLocationMap[V, E], rowShift: typing.Union[jpype.JInt, int], colShift: typing.Union[jpype.JInt, int]):
        """
        Adds in the vertices and edges from another GridLocationMap with each point in the other
        grid map shifted by the given row and column amounts.
        
        :param GridLocationMap[V, E] other: the other GridLocationMap to add to this one.
        :param jpype.JInt or int rowShift: the amount to shift the rows in the grid points from the other grid before
        adding them to this grid
        :param jpype.JInt or int colShift: the amount to shift the columns in the grid points from the other grid before
        adding them to this grid
        """

    def centerRows(self):
        """
        Updates each row within the grid such that it's column values are set to center the row in
        the grid.  Each row will be updated so that all its columns start at zero.  After that, 
        each column will be centered in the grid.
        """

    @typing.overload
    def col(self, vertex: V, col: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def col(self, vertex: V) -> int:
        ...

    def columnsMap(self) -> java.util.Map[java.lang.Integer, Column[V]]:
        """
        Returns a mapping or column indexes to Column objects in this grid
        
        :return: the columns in this grid
        :rtype: java.util.Map[java.lang.Integer, Column[V]]
        """

    def containsEdge(self, e: E) -> bool:
        ...

    def containsPoint(self, p: GridPoint) -> bool:
        ...

    def containsVertex(self, v: V) -> bool:
        ...

    def dispose(self):
        ...

    def edges(self) -> java.util.Set[E]:
        ...

    def getArticulations(self, edge: E) -> java.util.List[GridPoint]:
        ...

    def getRootColumn(self) -> int:
        """
        Returns the column of the initial vertex in this grid.
        
        :return: the column of the initial vertex in this grid
        :rtype: int
        """

    def getVertexColumnRanges(self) -> jpype.JArray[GridRange]:
        """
        Returns the minimum/max column for all rows in the grid. This method is only defined for
        grids that have no negative rows. This is because the array returned will be 0 based, with
        the entry at index 0 containing the column bounds for row 0 and so on.
        
        :return: the minimum/max column for all rows in the grid
        :rtype: jpype.JArray[GridRange]
        :raises IllegalStateException: if this method is called on a grid with negative rows.
        """

    def getVertexPoints(self) -> java.util.Map[V, GridPoint]:
        ...

    def gridPoint(self, vertex: V) -> GridPoint:
        ...

    def height(self) -> int:
        """
        Returns the number of rows in this grid map. Note that this includes empty rows
        starting at the 0 row.
        
        :return: the number of rows in this grid map
        :rtype: int
        """

    @typing.overload
    def row(self, vertex: V, row: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def row(self, vertex: V) -> int:
        ...

    def rows(self) -> java.util.List[Row[V]]:
        """
        Returns the rows in this grid, sorted by index (index can be negative)
        
        :return: the rows in this grid
        :rtype: java.util.List[Row[V]]
        """

    def rowsMap(self) -> java.util.Map[java.lang.Integer, Row[V]]:
        """
        Returns a mapping or row indexes to Row objects in this grid
        
        :return: the rows in this grid
        :rtype: java.util.Map[java.lang.Integer, Row[V]]
        """

    @typing.overload
    def set(self, v: V, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def set(self, v: V, gridPoint: GridPoint):
        ...

    def setArticulations(self, edge: E, articulations: java.util.List[GridPoint]):
        ...

    def shift(self, rowShift: typing.Union[jpype.JInt, int], colShift: typing.Union[jpype.JInt, int]):
        """
        Shifts the rows and columns for all points in this map by the given amount.
        
        :param jpype.JInt or int rowShift: the amount to shift the rows of each point
        :param jpype.JInt or int colShift: the amount to shift the columns of each point
        """

    def toStringGrid(self) -> str:
        """
        Creates a string representation of this grid
        
        :return: a string representation of this grid
        :rtype: str
        """

    def vertices(self) -> java.util.Set[V]:
        ...

    def width(self) -> int:
        """
        Returns the number of columns in this grid map. Note that this includes empty columns 
        starting at the 0 column.
        
        :return: the number of columns in this grid map
        :rtype: int
        """

    def zeroAlignGrid(self):
        """
        Shifts the grid so that its first row and column are at 0.
        """

    @property
    def vertexPoints(self) -> java.util.Map[V, GridPoint]:
        ...

    @property
    def rootColumn(self) -> jpype.JInt:
        ...

    @property
    def vertexColumnRanges(self) -> jpype.JArray[GridRange]:
        ...

    @property
    def articulations(self) -> java.util.List[GridPoint]:
        ...


class AbstractLayoutProvider(LayoutProviderExtensionPoint[V, E, G], typing.Generic[V, E, G]):
    """
    A base implementation of :obj:`LayoutProvider` that stubs some default methods.
    
     
    Some clients extends this class and adapt their graph to use one of the provided Jung
    layouts.  Other clients will implement the interface of this class to create a custom layout.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["LayoutProvider", "JungLayout", "GridCoordinates", "VisualGraphLayout", "GridPoint", "LayoutLocationMap", "JungLayoutProviderFactory", "LayoutPositions", "JungLayoutProvider", "AbstractVisualGraphLayout", "Column", "LayoutListener", "CalculateLayoutLocationsTask", "GridBounds", "JungWrappingVisualGraphLayoutAdapter", "LayoutProviderExtensionPoint", "Row", "GridRange", "GridLocationMap", "AbstractLayoutProvider"]
