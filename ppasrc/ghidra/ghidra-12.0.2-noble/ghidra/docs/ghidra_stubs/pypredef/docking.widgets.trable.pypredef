from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.datastruct
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore


C = typing.TypeVar("C")
R = typing.TypeVar("R")
T = typing.TypeVar("T")


class GTrableRow(java.lang.Object, typing.Generic[T]):
    """
    Abstract base class for :obj:`GTrable` row objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getIndentLevel(self) -> int:
        """
        :return: the indent level for this row
        :rtype: int
        """

    def isExpandable(self) -> bool:
        """
        :return: true if this row is expandable
        :rtype: bool
        """

    def isExpanded(self) -> bool:
        """
        :return: true if this node is expanded.
        :rtype: bool
        """

    @property
    def expanded(self) -> jpype.JBoolean:
        ...

    @property
    def indentLevel(self) -> jpype.JInt:
        ...

    @property
    def expandable(self) -> jpype.JBoolean:
        ...


class GTrableModeRowlListener(java.lang.Object):
    """
    The listener interface for when the row model changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def trableChanged(self):
        """
        Notification that the row model changed
        """


class GTrableCellRenderer(java.lang.Object, typing.Generic[C]):
    """
    Interface for :obj:`GTrable` cell renderers
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCellRenderer(self, trable: GTrable[typing.Any], value: C, isSelected: typing.Union[jpype.JBoolean, bool], hasFocus: typing.Union[jpype.JBoolean, bool], row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]) -> java.awt.Component:
        """
        Gets and prepares the renderer component for the given column value
        
        :param GTrable[typing.Any] trable: the GTrable
        :param C value: the column value
        :param jpype.JBoolean or bool isSelected: true if the row is selected
        :param jpype.JBoolean or bool hasFocus: true if the cell has focus
        :param jpype.JInt or int row: the row of the cell being painted
        :param jpype.JInt or int column: the column of the cell being painted
        :return: the component to use to paint the cell value
        :rtype: java.awt.Component
        """


class OpenCloseIcon(javax.swing.Icon):
    """
    Icon used for the expand/collapse control in a :obj:`GTrable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, isOpen: typing.Union[jpype.JBoolean, bool], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param jpype.JBoolean or bool isOpen: if true, draws an icon that indicates the row is open, otherwise draws an
        icon that the icon indicates the row is closed
        :param jpype.JInt or int width: the width to draw the icon
        :param jpype.JInt or int height: the height to draw the icon
        """

    def setColor(self, color: java.awt.Color):
        ...


class GTrableCellClickedListener(java.lang.Object):
    """
    Listener for :obj:`GTrable` cell clicked
    """

    class_: typing.ClassVar[java.lang.Class]

    def cellClicked(self, row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int], event: java.awt.event.MouseEvent):
        """
        Notification the a GTrable cell was clicked.
        
        :param jpype.JInt or int row: the row index of the cell that was clicked
        :param jpype.JInt or int column: the column index of the cell that was clicked
        :param java.awt.event.MouseEvent event: the mouse event of the click
        """


class GTrableRowModel(java.lang.Object, typing.Generic[T]):
    """
    Row model for a :obj:`GTrable`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addListener(self, l: GTrableModeRowlListener):
        """
        Adds a listener to the list that is notified each time a change
        to the data model occurs.
        
        :param GTrableModeRowlListener l: the listener to be notified
        """

    def collapseRow(self, rowIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Collapse the row at the given row index.
        
        :param jpype.JInt or int rowIndex: the index of the row to collapse
        :return: the total number of rows removed due to collapsing the row
        :rtype: int
        """

    def expandRow(self, rowIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Expand the row at the given row index.
        
        :param jpype.JInt or int rowIndex: the index of the row to expand
        :return: the total number of rows added due to the expand
        :rtype: int
        """

    def getIndentLevel(self, rowIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        :return: the indent level of the row at the given index.
        :rtype: int
        
        
        :param jpype.JInt or int rowIndex: the index of the row to get its indent level
        """

    def getRow(self, rowIndex: typing.Union[jpype.JInt, int]) -> T:
        """
        :return: the row object for the given index.
        :rtype: T
        
        
        :param jpype.JInt or int rowIndex: the index of the row to retrieve
        """

    def getRowCount(self) -> int:
        """
        :return: the total number of rows include open child rows.
        :rtype: int
        """

    def isExpandable(self, rowIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        :return: true if the row at the given index can be expanded
        :rtype: bool
        
        
        :param jpype.JInt or int rowIndex: the row to test if expandable
        """

    def isExpanded(self, rowIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        :return: true if the row at the given index is expanded.
        :rtype: bool
        
        
        :param jpype.JInt or int rowIndex: the index of the row to test for expanded
        """

    def removeListener(self, l: GTrableModeRowlListener):
        """
        Removes a listener from the list that is notified each time a
        change to the model occurs.
        
        :param GTrableModeRowlListener l: the listener to remove
        """

    @property
    def expanded(self) -> jpype.JBoolean:
        ...

    @property
    def indentLevel(self) -> jpype.JInt:
        ...

    @property
    def expandable(self) -> jpype.JBoolean:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def row(self) -> T:
        ...


class AbstractGTrableRowModel(GTrableRowModel[T], typing.Generic[T]):
    """
    Abstract base class for GTrable models. Adds support for listeners.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DefaultGTrableCellRenderer(javax.swing.table.DefaultTableCellRenderer, GTrableCellRenderer[T], typing.Generic[T]):
    """
    Base class for GTrable cell renderers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GTrableColumnModel(java.lang.Object, typing.Generic[T]):
    """
    Abstract base class for :obj:`GTrable` column models
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getColumn(self, column: typing.Union[jpype.JInt, int]) -> GTrableColumn[T, typing.Any]:
        """
        :return: the column object for the given column index.
        :rtype: GTrableColumn[T, typing.Any]
        
        
        :param jpype.JInt or int column: the index of the column
        """

    def getColumnCount(self) -> int:
        """
        :return: the number of columns in this model.
        :rtype: int
        """

    def getPreferredWidth(self) -> int:
        """
        :return: the preferred width of the model which is the sum of the preferred widths of each
        column.
        :rtype: int
        """

    @property
    def preferredWidth(self) -> jpype.JInt:
        ...

    @property
    def column(self) -> GTrableColumn[T, typing.Any]:
        ...

    @property
    def columnCount(self) -> jpype.JInt:
        ...


class GTrableColumn(java.lang.Object, typing.Generic[R, C]):
    """
    Abstract base class for :obj:`GTrable` column objects in the :obj:`GTrableColumnModel`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMinWidth(self) -> int:
        ...

    def getRenderer(self) -> GTrableCellRenderer[C]:
        ...

    def getValue(self, row: R) -> C:
        """
        Returns the column value given the row object
        
        :param R row: the row object containing the data for the entire row
        :return: the value to be displayed in this column
        :rtype: C
        """

    def getWidth(self) -> int:
        ...

    def isResizable(self) -> bool:
        ...

    @property
    def renderer(self) -> GTrableCellRenderer[C]:
        ...

    @property
    def resizable(self) -> jpype.JBoolean:
        ...

    @property
    def width(self) -> jpype.JInt:
        ...

    @property
    def minWidth(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> C:
        ...


class DefaultGTrableRowModel(AbstractGTrableRowModel[T], typing.Generic[T]):
    """
    Default implementation for a simple :obj:`GTrable` row data model.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, roots: java.util.List[T]):
        ...


class GTrable(javax.swing.JComponent, javax.swing.Scrollable, GTrableModeRowlListener, typing.Generic[T]):
    """
    Component that combines the display of a tree and a table. Data is presented in columns like a 
    table, but rows can have child rows like a tree which are displayed indented in the first
    column.
     
    
    A GTrable uses two different models: a row model and a column model. The row model contains
    row objects that contains the data to be displayed on a given row. The column model specifies
    how to display the data in the row object as a series of column values.
     
    
    The row model also provides information about the parent child relationship of rows. If the
    model reports that a row can be expanded, an expand control is show on that row. If the row
    is then expanded, the model will then report additional rows immediately below the parent row,
    pushing any existing rows further down (i.e. all rows below the row being opened have their row
    indexes increased by the number of rows added.)
    """

    @typing.type_check_only
    class GTrableMouseListener(java.awt.event.MouseAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def findClosestColumnBoundary(self, x: typing.Union[jpype.JInt, int]) -> int:
            ...


    @typing.type_check_only
    class GTrableKeyListener(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rowModel: GTrableRowModel[T], columnModel: GTrableColumnModel[T]):
        """
        Constructor
        
        :param GTrableRowModel[T] rowModel: the model that provides the row data.
        :param GTrableColumnModel[T] columnModel: the model the provides the column information for displaying the data
        stored in the row data.
        """

    def addCellClickedListener(self, listener: GTrableCellClickedListener):
        """
        Adds a listener to be notified if the user clicks on a cell in the GTrable.
        
        :param GTrableCellClickedListener listener: the listener to be notified
        """

    def addSelectedRowConsumer(self, consumer: java.util.function.Consumer[java.lang.Integer]):
        """
        Adds a consumer to be notified when the selected row changes.
        
        :param java.util.function.Consumer[java.lang.Integer] consumer: the consumer to be notified when the selected row changes
        """

    def clearSelectedRow(self):
        """
        Deselects any selected row
        """

    def collapseAll(self):
        """
        Collapses all rows.
        """

    def collapseRow(self, rowIndex: typing.Union[jpype.JInt, int]):
        """
        Collapse the row (remove any of its descendants) at the given row index.
        
        :param jpype.JInt or int rowIndex: the index of the row to collapse
        """

    def expandAll(self):
        """
        Expands all rows fully.
        """

    def expandRow(self, rowIndex: typing.Union[jpype.JInt, int]):
        """
        Expands the row at the given index.
        
        :param jpype.JInt or int rowIndex: the index of the row to expand
        """

    def expandRowRecursively(self, rowIndex: typing.Union[jpype.JInt, int]):
        """
        Fully expands the given row and all its descendants.
        
        :param jpype.JInt or int rowIndex: the index of the row to fully expand
        """

    def getRow(self, p: java.awt.Point) -> int:
        ...

    def getRowHeight(self) -> int:
        """
        :return: the height of a row in the trable.
        :rtype: int
        """

    def getRowOffcut(self) -> int:
        """
        :return: the amount the view is scrolled such that the first line is not fully visible.
        :rtype: int
        """

    def getSelectedRow(self) -> int:
        """
        :return: the currently selected row or -1 if not row is selected.
        :rtype: int
        """

    def getSelectionBackground(self) -> java.awt.Color:
        """
        :return: the selection background color
        :rtype: java.awt.Color
        """

    def getSelectionForeground(self) -> java.awt.Color:
        """
        :return: the selection foreground color
        :rtype: java.awt.Color
        """

    def getVisibleRows(self) -> ghidra.util.datastruct.Range:
        """
        :return: the range of visible row indices.
        :rtype: ghidra.util.datastruct.Range
        """

    def removeCellClickedListener(self, listener: GTrableCellClickedListener):
        """
        Removes a cell clicked listener.
        
        :param GTrableCellClickedListener listener: the listener to be removed
        """

    def removeSelectedRowConsumer(self, consumer: java.util.function.Consumer[java.lang.Integer]):
        """
        Removes the consumer to be notified when the selected row changes.
        
        :param java.util.function.Consumer[java.lang.Integer] consumer: the consumer to be removed
        """

    def scrollToSelectedRow(self):
        """
        Scrolls the view to make the currently selected row visible.
        """

    def setColumnModel(self, columnModel: GTrableColumnModel[T]):
        """
        Sets a new column model.
        
        :param GTrableColumnModel[T] columnModel: the new column model to use
        """

    def setPreferredVisibleRowCount(self, minVisibleRows: typing.Union[jpype.JInt, int], maxVisibleRows: typing.Union[jpype.JInt, int]):
        """
        Sets the preferred number of visible rows to be displayed in the scrollable area.
        
        :param jpype.JInt or int minVisibleRows: the minimum number of visible rows.
        :param jpype.JInt or int maxVisibleRows: the maximum number of visible rows.
        """

    def setRowModel(self, newRowModel: GTrableRowModel[T]):
        """
        Sets a new row model.
        
        :param GTrableRowModel[T] newRowModel: the new row model to use
        """

    def setSelectedRow(self, rowIndex: typing.Union[jpype.JInt, int]):
        """
        Sets the selected row to the given row index
        
        :param jpype.JInt or int rowIndex: the row index to select
        """

    @property
    def rowOffcut(self) -> jpype.JInt:
        ...

    @property
    def selectionBackground(self) -> java.awt.Color:
        ...

    @property
    def selectionForeground(self) -> java.awt.Color:
        ...

    @property
    def selectedRow(self) -> jpype.JInt:
        ...

    @selectedRow.setter
    def selectedRow(self, value: jpype.JInt):
        ...

    @property
    def row(self) -> jpype.JInt:
        ...

    @property
    def visibleRows(self) -> ghidra.util.datastruct.Range:
        ...

    @property
    def rowHeight(self) -> jpype.JInt:
        ...



__all__ = ["GTrableRow", "GTrableModeRowlListener", "GTrableCellRenderer", "OpenCloseIcon", "GTrableCellClickedListener", "GTrableRowModel", "AbstractGTrableRowModel", "DefaultGTrableCellRenderer", "GTrableColumnModel", "GTrableColumn", "DefaultGTrableRowModel", "GTrable"]
