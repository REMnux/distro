from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.actions
import docking.util
import docking.widgets
import docking.widgets.filter
import docking.widgets.table.columnfilter
import docking.widgets.table.constraint
import ghidra.docking.settings
import ghidra.framework.plugintool
import ghidra.util.classfinder
import ghidra.util.table.column
import ghidra.util.task
import java.awt # type: ignore
import java.awt.dnd # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.table # type: ignore
import org.jdom # type: ignore
import utility.function


COLUMN_TYPE = typing.TypeVar("COLUMN_TYPE")
DATA_SOURCE = typing.TypeVar("DATA_SOURCE")
EXPECTED_ROW_TYPE = typing.TypeVar("EXPECTED_ROW_TYPE")
FILTER_TYPE = typing.TypeVar("FILTER_TYPE")
M = typing.TypeVar("M")
ROW_OBJECT = typing.TypeVar("ROW_OBJECT")
ROW_TYPE = typing.TypeVar("ROW_TYPE")
T = typing.TypeVar("T")


class FocusableEditor(java.lang.Object):
    """
    Signals that the implementing cell editor desires to be notified when editing begins so that the
    editor can request focus on the right widget.
    """

    class_: typing.ClassVar[java.lang.Class]

    def focusEditor(self):
        """
        Called with the editor should take focus.
        """


class DiscoverableTableUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def adaptColumForModel(model: GDynamicColumnTableModel[ROW_TYPE, COLUMN_TYPE], column: AbstractDynamicTableColumn[typing.Any, typing.Any, typing.Any]) -> DynamicTableColumn[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]:
        """
        Returns a column object that is usable by the given model.
         
        
        Dynamic columns and models work on row types.  This method allows clients to use columns
        with row types that differ from the model's row type, as long as a suitable mapper can
        be found.  If no mapper can be found, then an IllegalArgumentException is thrown.  Also,
        if the given column is of the correct type, then that column is returned.
        
        :param ROW_TYPE: the **model's** row type:param COLUMN_TYPE: the **model's** row type:param GDynamicColumnTableModel[ROW_TYPE, COLUMN_TYPE] model: the table model for which a column is needed
        :param AbstractDynamicTableColumn[typing.Any, typing.Any, typing.Any] column: the column that you want to use with the given model
        :return: a column object that is usable by the given model.
        :rtype: DynamicTableColumn[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]
        :raises IllegalArgumentException: if this method cannot figure out how to map the given
                column's row type to the given model's row type.
        """

    @staticmethod
    @typing.overload
    def getColumnConstraints(mapper: docking.widgets.table.constraint.ColumnTypeMapper[T, M]) -> java.util.Collection[docking.widgets.table.constraint.ColumnConstraint[T]]:
        """
        Returns a list of all the :obj:`ColumnConstraint` that are capable of filtering the
        destination type of the given mapper.  The mapper will be used to create a mapped constraint
        that will be called with an instance of the type ``T``.
        
        :param docking.widgets.table.constraint.ColumnTypeMapper[T, M] mapper: the mapper that will be used to convert
        :return: a list of all the :obj:`ColumnConstraint` that are capable of filtering the
                    given column type
        :rtype: java.util.Collection[docking.widgets.table.constraint.ColumnConstraint[T]]
        """

    @staticmethod
    @typing.overload
    def getColumnConstraints(columnType: java.lang.Class[T]) -> java.util.Collection[docking.widgets.table.constraint.ColumnConstraint[T]]:
        """
        Returns a list of all the :obj:`ColumnConstraint` that are capable of filtering the
        given column type.
        
        :param java.lang.Class[T] columnType: the class of the data that is return by the table model for specific column.
        :return: a list of all the :obj:`ColumnConstraint` that are capable of filtering the
        given column type.
        :rtype: java.util.Collection[docking.widgets.table.constraint.ColumnConstraint[T]]
        """

    @staticmethod
    def getDynamicTableColumns(rowTypeClass: java.lang.Class[ROW_TYPE]) -> java.util.Collection[DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]]:
        """
        Returns all "discovered" :obj:`AbstractDynamicTableColumn` classes that are compatible with the
        given class, which represents the object for a table's row.  For example, many tables use
        ``Address`` as the row type.  In this case, passing ``Address.class`` as the
        parameter to this method will return all :obj:`AbstractDynamicTableColumn`s that can provide column
        data by working with ``Address`` instances.
         
         
        Usage Notes:  This class will not only discover :obj:`AbstractDynamicTableColumn`s
        that directly support the given class type, but will also use discovered
        :obj:`TableRowMapper` objects to create adapters that allow the
        use of table row data that does not exactly match the supported type of discovered
        :obj:`AbstractDynamicTableColumn` classes.  For example, suppose that a table's row type is
        ``Address``.  This methods will return at least all :obj:`AbstractDynamicTableColumn`s
        that support ``Address`` data.  In order to support extra columns, Ghidra has
        created a :obj:`TableRowMapper` that can convert a ``ProgramLocation`` into an
        ``Address``.  This method will find and use this mapper to return a
        :obj:`MappedTableColumn` instance (which is an :obj:`AbstractDynamicTableColumn`).  By doing
        this, any table that has ``Address`` objects as its row type can now use
        :obj:`AbstractDynamicTableColumn`s that support ``ProgramLocations`` in addition to
        ``Address`` objects.  These mappers provide a way for tables that have non-standard
        Ghidra data as their row type to take advantage of existing dynamic columns for standard
        Ghidra data (like ProgramLocations and Addresses).
        
        :param java.lang.Class[ROW_TYPE] rowTypeClass: table's row type
        :return: the discovered column
        :rtype: java.util.Collection[DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]]
        """


class DynamicTableColumnExtensionPoint(AbstractDynamicTableColumn[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE], ghidra.util.classfinder.ExtensionPoint, typing.Generic[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]):
    """
    NOTE:  ALL DynamicTableColumnExtensionPoint CLASSES MUST END IN "TableColumn".  If not,
    the ClassSearcher will not find them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TableUtils(java.lang.Object):
    """
    A utility class for JTables used in Ghidra.
    """

    @typing.type_check_only
    class SortEmphasisAnimationRunner(docking.util.AnimationRunner):
        """
        An animation runner that creates the painter and the values that will be interpolated by
        the animator.  Each column that is sorted will be emphasized, except for the column that was
        clicked, as not to be annoying to the user.   The intent of emphasizing the columns is to 
        signal to the user that other columns are part of the sort, not just the column that was 
        clicked.   We hope that this will remind the user of the overall sort so they are not 
        confused when the column that was clicked produces unexpected sort results.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, table: javax.swing.JTable, tableSortState: TableSortState, clickedColumn: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class EmphasizingSortPainter(docking.util.AnimationPainter):
        """
        A painter that will emphasize each sorted column, except for the clicked column, over the 
        course of an animation.  The painter is called with the current emphasis that is passed to
        the column along with a repaint request.
        """

        @typing.type_check_only
        class ColumnAndRange(java.lang.Record):
            """
            Simple container for a column index and it's range (from 0 to .99)
            """

            class_: typing.ClassVar[java.lang.Class]

            def column(self) -> int:
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def range(self) -> float:
                ...

            def toString(self) -> str:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, table: javax.swing.JTable, tableSortState: TableSortState, clickedColumnIndex: typing.Union[jpype.JInt, int], ordinals: jpype.JArray[jpype.JInt]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def columnAlternativelySelected(table: javax.swing.JTable, columnIndex: typing.Union[jpype.JInt, int]):
        """
        Attempts to sort the given table based upon the given column index.  If the :obj:`TableModel`
        of the given table is not a :obj:`SortedTableModel`, then this method will do nothing.
         
        
        If the given column index is not sortable, then this method will not change the state of
        the model. The results of calling this method depend upon the current sorted state
        of the given column:
         
        1. if the column is not yet sorted, then the column is made sorted, if sortable,
        and any other sorted columns will not be changed, or
        2. if the column is sorted, then:
            
            1. if there are other sorted columns, this column will no longer be sorted
            2. if there are no other sorted columns, then no action will be taken
        
        
        
        :param javax.swing.JTable table: The table whose model shall be sorted.
        :param jpype.JInt or int columnIndex: The column index upon which to sort.
        """

    @staticmethod
    def columnSelected(table: javax.swing.JTable, columnIndex: typing.Union[jpype.JInt, int]):
        """
        Attempts to sort the given table based upon the given column index.  If the :obj:`TableModel`
        of the given table is not a :obj:`SortedTableModel`, then this method will do nothing.
         
        
        If the given column index is not sortable, then this method will not change the state of
        the model.  Otherwise, the sorted model will be sorted on the given column index.  The
        results of calling this method depend upon the current sorted state of the given column:
         
        1. if the column is not yet the sorted column, then the column is made the sorted
        column, if sortable,and any other sorted columns will be made unsorted, or
        2. if the column is the sorted column and the direction will simply be toggled.
        
        
        :param javax.swing.JTable table: The table whose model shall be sorted.
        :param jpype.JInt or int columnIndex: The column index upon which to sort.
        """

    @staticmethod
    def getTableCellStringValue(model: RowObjectTableModel[ROW_OBJECT], rowObject: ROW_OBJECT, column: typing.Union[jpype.JInt, int]) -> str:
        """
        Uses the given row-based table model, row object and column index to determine what the
        String value should be for that cell.
        
         
        This is used to provide a means for filtering on the text that is displayed to the user.
        
        :param ROW_OBJECT: The model's row object type:param RowObjectTableModel[ROW_OBJECT] model: the model
        :param ROW_OBJECT rowObject: the row object for the row being queried
        :param jpype.JInt or int column: the column index **in the table model**
        :return: the string value; null if no value can be fabricated
        :rtype: str
        """

    @staticmethod
    def setSelectedItems(table: javax.swing.JTable, items: java.util.List[ROW_OBJECT]):
        """
        Select the given row objects.  No selection will be made if the objects are filtered out of
        view.  Passing a ``null`` list or an empty list will clear the selection.
        
        :param javax.swing.JTable table: the table in which to select the items
        :param java.util.List[ROW_OBJECT] items: the row objects to select
        """


class GBooleanCellRenderer(GTableCellRenderer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def isSelected(self) -> bool:
        ...

    @property
    def selected(self) -> jpype.JBoolean:
        ...


class AutoscrollAdapter(java.awt.dnd.Autoscroll):
    """
    Helper class for autoscrolling on a component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, component: javax.swing.JComponent, scrollIncrement: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param javax.swing.JComponent component: component that is scrollable
        :param jpype.JInt or int scrollIncrement: value to use to calculate the new
        visible rectangle for scrolling
        """


class GTableCellRenderingData(java.lang.Object):
    """
    A state object to provide a table cell renderer with data beyond the standard Java 
    :obj:`javax.swing.table.TableCellRenderer` interface.
     
    
    Additional data about the context of a rendering operation -- like the columns' Settings 
    or the row-object -- are easily passed to the renderer without refactor of each client.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, jTable: javax.swing.JTable, column: typing.Union[jpype.JInt, int], columnSettings: ghidra.docking.settings.Settings):
        """
        Create a data object for a specific column in a table
        
        :param javax.swing.JTable jTable: Reference to the associated JTable
        :param jpype.JInt or int column: View index of this column
        :param ghidra.docking.settings.Settings columnSettings: Settings state provided and used by this column
        """

    def copyWithNewValue(self, newValue: java.lang.Object) -> GTableCellRenderingData:
        """
        Create a new data object from this data, changing only the cells' value object.
         
         
        This method is a convenience for use by renderers that wish to change the value 
        passed to them.
        
        :param java.lang.Object newValue: New cell value object
        :return: A new data object with the same state as this object
        :rtype: GTableCellRenderingData
        """

    def getColumnModelIndex(self) -> int:
        ...

    def getColumnSettings(self) -> ghidra.docking.settings.Settings:
        ...

    def getColumnViewIndex(self) -> int:
        ...

    def getRowModelIndex(self) -> int:
        ...

    def getRowObject(self) -> java.lang.Object:
        ...

    def getRowViewIndex(self) -> int:
        ...

    def getTable(self) -> javax.swing.JTable:
        ...

    def getValue(self) -> java.lang.Object:
        ...

    def hasFocus(self) -> bool:
        ...

    def isSelected(self) -> bool:
        ...

    def setCellData(self, value: java.lang.Object, column: typing.Union[jpype.JInt, int], isSelected: typing.Union[jpype.JBoolean, bool], hasFocus: typing.Union[jpype.JBoolean, bool]):
        """
        Set data specific to a cell, as used during the rendering phase
        
        :param java.lang.Object value: The models' value at row-column
        :param jpype.JInt or int column: the view column index
        :param jpype.JBoolean or bool isSelected: True if the cell is to be rendered with the 
        selection highlighted; otherwise false
        :param jpype.JBoolean or bool hasFocus: This cell has the users' focus
        """

    def setRowData(self, row: typing.Union[jpype.JInt, int], rowObject: java.lang.Object):
        """
        Set data specific to a row, as used during the rendering phase
        
        :param jpype.JInt or int row: View row index
        :param java.lang.Object rowObject: Object for which this table row is generated
        """

    @property
    def rowModelIndex(self) -> jpype.JInt:
        ...

    @property
    def columnViewIndex(self) -> jpype.JInt:
        ...

    @property
    def columnModelIndex(self) -> jpype.JInt:
        ...

    @property
    def rowViewIndex(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...

    @property
    def selected(self) -> jpype.JBoolean:
        ...

    @property
    def table(self) -> javax.swing.JTable:
        ...

    @property
    def rowObject(self) -> java.lang.Object:
        ...

    @property
    def columnSettings(self) -> ghidra.docking.settings.Settings:
        ...


class TableComparators(java.lang.Object):
    """
    A utility class for tables to use when sorting
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def compareWithNullValues(o1: java.lang.Object, o2: java.lang.Object) -> int:
        ...

    @staticmethod
    def getNoSortComparator() -> java.util.Comparator[T]:
        ...


class TableSortStateEditor(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, tableSortState: TableSortState):
        ...

    @typing.overload
    def addSortedColumn(self, sortState: ColumnSortState):
        ...

    @typing.overload
    def addSortedColumn(self, columnIndex: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def addSortedColumn(self, columnIndex: typing.Union[jpype.JInt, int], direction: ColumnSortState.SortDirection):
        ...

    def clear(self):
        ...

    def createTableSortState(self) -> TableSortState:
        ...

    def flipColumnSortDirection(self, columnIndex: typing.Union[jpype.JInt, int]):
        ...

    def getColumnSortState(self, sortStateIndex: typing.Union[jpype.JInt, int]) -> ColumnSortState:
        ...

    def getSortedColumnCount(self) -> int:
        ...

    def isColumnSorted(self, columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def iterator(self) -> java.util.Iterator[ColumnSortState]:
        ...

    def removeSortedColumn(self, columnIndex: typing.Union[jpype.JInt, int]):
        ...

    @property
    def columnSortState(self) -> ColumnSortState:
        ...

    @property
    def columnSorted(self) -> jpype.JBoolean:
        ...

    @property
    def sortedColumnCount(self) -> jpype.JInt:
        ...


class TableModelWrapper(RowObjectFilterModel[ROW_OBJECT], SelectionStorage[ROW_OBJECT], WrappingTableModel, typing.Generic[ROW_OBJECT]):
    """
    A wrapper that will take a table model and decorate it with filtering capability.  This is
    only needed when the given model does not have filtering.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, wrappedModel: RowObjectTableModel[ROW_OBJECT]):
        ...


class GTableCellRenderer(docking.widgets.AbstractGCellRenderer, javax.swing.table.TableCellRenderer):
    """
    A default table cell renderer that relies on the ``toString()`` method when rendering
    the cells of the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new GTableCellRenderer.
        """

    @typing.overload
    def __init__(self, f: java.awt.Font):
        """
        Constructs a new GTableCellRenderer using the specified font.
        
        :param java.awt.Font f: the font to use when rendering text in the table cells
        """

    @typing.overload
    def getTableCellRendererComponent(self, table: javax.swing.JTable, value: java.lang.Object, isSelected: typing.Union[jpype.JBoolean, bool], hasFocus: typing.Union[jpype.JBoolean, bool], row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]) -> java.awt.Component:
        """
        Satisfies the Java :obj:`javax.swing.table.TableCellRenderer` interface; retrieves column
        data via a GTableCellRenderingData object, and defers painting to
        :meth:`getTableCellRendererComponent(GTableCellRenderingData) <.getTableCellRendererComponent>`.
         
        
        This is marked ``final`` to redirect subclasses to the enhanced method,
        :meth:`getTableCellRendererComponent(GTableCellRenderingData) <.getTableCellRendererComponent>`.
         
        
        Throws an AssertException if the table this renderer is used with is not a
        :obj:`docking.widgets.table.GTable` instance.
        
        
        .. seealso::
        
            | :obj:`javax.swing.table.TableCellRenderer.getTableCellRendererComponent(javax.swing.JTable,
            java.lang.Object, boolean, boolean, int, int)`
        
            | :obj:`.getTableCellRendererComponent(GTableCellRenderingData)`
        """

    @typing.overload
    def getTableCellRendererComponent(self, data: GTableCellRenderingData) -> java.awt.Component:
        """
        Provide basic cell rendering -- setting foreground and background colors, font, text,
        alignment, drop color, and border. Additional data that may be of use to the renderer is
        passed through the :obj:`docking.widgets.table.GTableCellRenderingData` object.
        
        :param GTableCellRenderingData data: Context data used in the rendering of a data cell.
        :return: The component used for drawing the table cell.
        :rtype: java.awt.Component
        """

    @property
    def tableCellRendererComponent(self) -> java.awt.Component:
        ...


class GTableToCSV(java.lang.Object):

    @typing.type_check_only
    class ConvertTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def writeCSV(file: jpype.protocol.SupportsPath, table: GTable):
        ...

    @staticmethod
    def writeCSVUsingColunns(file: jpype.protocol.SupportsPath, table: GTable, selectedColumns: java.util.List[java.lang.Integer]):
        ...


class AnyObjectTableModel(GDynamicColumnTableModel[T, java.lang.Object], typing.Generic[T]):
    """
    A table that allow users to provide a list of data objects whose method can be used
    to create columns.
    """

    @typing.type_check_only
    class MethodColumn(AbstractDynamicTableColumn[T, java.lang.Object, java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, dataClass: java.lang.Class[T], methodName: typing.Union[java.lang.String, str]):
            ...

        @typing.overload
        def __init__(self, method: java.lang.reflect.Method):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], dataClass: java.lang.Class[T], *methodNames: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], *methods: java.lang.reflect.Method):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], methods: java.util.List[java.lang.reflect.Method]):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], dataClass: java.lang.Class[T], methodNames: java.util.List[java.lang.String]):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], data: java.util.List[T], dataClass: java.lang.Class[T], methodNames: java.util.List[java.lang.String]):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], data: java.util.List[T], methods: java.util.List[java.lang.reflect.Method]):
        ...

    def setModelData(self, data: java.util.List[T]):
        ...


class WrappingTableModel(javax.swing.table.TableModel):
    """
    Signals that the implementing table model is wrapping another table model.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fireTableChanged(self, e: javax.swing.event.TableModelEvent):
        """
        This method allows us to call the delegate model with a translated event
        
        :param javax.swing.event.TableModelEvent e: the event
        """

    def getModelRow(self, viewRow: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unwrapped model's row for the given view row.
        
        :param jpype.JInt or int viewRow: the row in the GUI
        :return: the row in the wrapped model's indexing
        :rtype: int
        """

    def getWrappedModel(self) -> javax.swing.table.TableModel:
        """
        Returns the wrapped model
        
        :return: the model
        :rtype: javax.swing.table.TableModel
        """

    def wrappedModelChangedFromTableChangedEvent(self):
        """
        Allows this wrapping model to get update notifications directly from the filtering framework
        """

    @property
    def wrappedModel(self) -> javax.swing.table.TableModel:
        ...

    @property
    def modelRow(self) -> jpype.JInt:
        ...


class ChooseColumnsDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class Renderer(GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TableColumnWrapper(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getTableColumn(self) -> javax.swing.table.TableColumn:
            ...

        @property
        def tableColumn(self) -> javax.swing.table.TableColumn:
            ...


    @typing.type_check_only
    class SelectColumnsModel(javax.swing.table.DefaultTableModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class TableTextFilter(TableFilter[ROW_OBJECT], typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, textFilter: docking.widgets.filter.TextFilter, transformer: RowFilterTransformer[ROW_OBJECT]):
        ...


class TableColumnDescriptor(java.lang.Object, typing.Generic[ROW_TYPE]):

    @typing.type_check_only
    class TableColumnInfo(java.lang.Comparable[TableColumnDescriptor.TableColumnInfo]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addHiddenColumn(self, column: DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]):
        ...

    @typing.overload
    def addVisibleColumn(self, column: DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]):
        ...

    @typing.overload
    def addVisibleColumn(self, column: DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any], sortOrdinal: typing.Union[jpype.JInt, int], ascending: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        :param DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any] column: the column to add
        :param jpype.JInt or int sortOrdinal: the **ordinal (i.e., 1, 2, 3...n)**, not the index (i.e, 0, 1, 2...n).
        :param jpype.JBoolean or bool ascending: true to sort ascending
        """

    def getAllColumns(self) -> java.util.List[DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]]:
        ...

    def getDefaultTableSortState(self, model: DynamicColumnTableModel[ROW_TYPE]) -> TableSortState:
        ...

    def getDefaultVisibleColumns(self) -> java.util.List[DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]]:
        ...

    def setVisible(self, columnName: typing.Union[java.lang.String, str], visible: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def defaultVisibleColumns(self) -> java.util.List[DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]]:
        ...

    @property
    def defaultTableSortState(self) -> TableSortState:
        ...

    @property
    def allColumns(self) -> java.util.List[DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]]:
        ...


class GFilterTable(javax.swing.JPanel, typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: RowObjectTableModel[ROW_OBJECT]):
        ...

    def addSelectionListener(self, l: ObjectSelectedListener[ROW_OBJECT]):
        ...

    def clearSelection(self):
        ...

    def dispose(self):
        ...

    def focusFilter(self):
        ...

    def getCellValue(self, point: java.awt.Point) -> java.lang.Object:
        ...

    def getColumn(self, point: java.awt.Point) -> int:
        ...

    def getFilterPanel(self) -> GTableFilterPanel[ROW_OBJECT]:
        ...

    def getItemAt(self, point: java.awt.Point) -> ROW_OBJECT:
        ...

    def getModel(self) -> RowObjectTableModel[ROW_OBJECT]:
        ...

    def getRow(self, point: java.awt.Point) -> int:
        ...

    def getRowObject(self, viewRow: typing.Union[jpype.JInt, int]) -> ROW_OBJECT:
        ...

    def getSelectedRowObject(self) -> ROW_OBJECT:
        ...

    def getSelectedRowObjects(self) -> java.util.List[ROW_OBJECT]:
        """
        Returns all row objects corresponding to all selected rows in the table.
        
        :return: all row objects corresponding to all selected rows in the table.
        :rtype: java.util.List[ROW_OBJECT]
        """

    def getTable(self) -> GTable:
        ...

    def isInView(self, o: ROW_OBJECT) -> bool:
        ...

    def removeSelectionListener(self, l: ObjectSelectedListener[ROW_OBJECT]):
        ...

    def setAccessibleNamePrefix(self, prefix: typing.Union[java.lang.String, str]):
        """
        Sets the accessible name prefix for both the table and the filter panel
        
        :param java.lang.String or str prefix: the name prefix
        """

    def setFiterText(self, text: typing.Union[java.lang.String, str]):
        ...

    def setSelectedRowObject(self, rowObject: ROW_OBJECT):
        ...

    def setTableFilter(self, tableFilter: TableFilter[ROW_OBJECT]):
        ...

    @property
    def selectedRowObject(self) -> ROW_OBJECT:
        ...

    @selectedRowObject.setter
    def selectedRowObject(self, value: ROW_OBJECT):
        ...

    @property
    def column(self) -> jpype.JInt:
        ...

    @property
    def inView(self) -> jpype.JBoolean:
        ...

    @property
    def cellValue(self) -> java.lang.Object:
        ...

    @property
    def filterPanel(self) -> GTableFilterPanel[ROW_OBJECT]:
        ...

    @property
    def selectedRowObjects(self) -> java.util.List[ROW_OBJECT]:
        ...

    @property
    def itemAt(self) -> ROW_OBJECT:
        ...

    @property
    def model(self) -> RowObjectTableModel[ROW_OBJECT]:
        ...

    @property
    def row(self) -> jpype.JInt:
        ...

    @property
    def table(self) -> GTable:
        ...

    @property
    def rowObject(self) -> ROW_OBJECT:
        ...


class TableTextFilterFactory(java.lang.Object, typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]

    def getTableFilter(self, text: typing.Union[java.lang.String, str], transformer: RowFilterTransformer[ROW_OBJECT]) -> TableFilter[ROW_OBJECT]:
        """
        Returns a filter using the given text as the filter string.
        
        :param java.lang.String or str text: the text to filter on.
        :param RowFilterTransformer[ROW_OBJECT] transformer: the object that converts a table row into a list of strings.
        :return: the filter that will determine if a table row matches the given text.
        :rtype: TableFilter[ROW_OBJECT]
        """


class ColumnSortState(java.lang.Object):
    """
    Not meant to be created by users.  They should instead use the :obj:`TableSortStateEditor`.
    """

    class SortDirection(java.lang.Enum[ColumnSortState.SortDirection]):

        class_: typing.ClassVar[java.lang.Class]
        ASCENDING: typing.Final[ColumnSortState.SortDirection]
        DESCENDING: typing.Final[ColumnSortState.SortDirection]
        UNSORTED: typing.Final[ColumnSortState.SortDirection]

        @staticmethod
        def getSortDirection(direction: typing.Union[java.lang.String, str]) -> ColumnSortState.SortDirection:
            ...

        def isAscending(self) -> bool:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ColumnSortState.SortDirection:
            ...

        @staticmethod
        def values() -> jpype.JArray[ColumnSortState.SortDirection]:
            ...

        @property
        def ascending(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def createFlipState(self) -> ColumnSortState:
        ...

    def getColumnModelIndex(self) -> int:
        ...

    def getSortDirection(self) -> ColumnSortState.SortDirection:
        ...

    def getSortOrder(self) -> int:
        ...

    def isAscending(self) -> bool:
        ...

    @staticmethod
    def restoreFromXML(element: org.jdom.Element) -> ColumnSortState:
        ...

    @property
    def sortDirection(self) -> ColumnSortState.SortDirection:
        ...

    @property
    def sortOrder(self) -> jpype.JInt:
        ...

    @property
    def columnModelIndex(self) -> jpype.JInt:
        ...

    @property
    def ascending(self) -> jpype.JBoolean:
        ...


class DynamicTableColumn(java.lang.Object, typing.Generic[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]):
    """
    The root interface for defining columns for :obj:`DynamicColumnTableModel`s. The class allows
    you to create objects for tables that know how to give a column value for a given row.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getColumnClass(self) -> java.lang.Class[COLUMN_TYPE]:
        """
        Determines the class of object that is associated with this field (column).
        
        :return: the column class
        :rtype: java.lang.Class[COLUMN_TYPE]
        """

    def getColumnDescription(self) -> str:
        """
        Returns a description of this column. This may be used as a tooltip for the column header
        
        :return: a description of this column. This may be used as a tooltip for the column header.
        :rtype: str
        """

    def getColumnDisplayName(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        Determines the column heading that will be displayed.
        
        :param ghidra.docking.settings.Settings settings: the settings
        :return: the field name to display as the column heading.
        :rtype: str
        """

    def getColumnName(self) -> str:
        """
        Determines the unique column heading that may be used to identify a column instance. This
        name must be non-changing and is used to save/restore state information.
        
        :return: the field instance name.
        :rtype: str
        """

    def getColumnPreferredWidth(self) -> int:
        """
        Returns the preferred width for this column. Column should either return a valid positive
        preferred size or -1.
        
        :return: the preferred width for this column.
        :rtype: int
        """

    def getColumnRenderer(self) -> ghidra.util.table.column.GColumnRenderer[COLUMN_TYPE]:
        """
        Returns the optional cell renderer for this column; null if no renderer is used.
         
         
        
        This method allows columns to define custom rendering. The interface returned here ensures
        that the text used for filtering matches what the users sees (via the
        :meth:`GColumnRenderer.getFilterString(Object, Settings) <GColumnRenderer.getFilterString>` method).
         
         
        
        Note: some types should not make use of the aforementioned filter string. These types include
        the :obj:`Number` wrapper types, :obj:`Date` and :obj:`Enum`s. (This is because the
        filtering system works naturally with these types.) See :obj:`GColumnRenderer`.
        
        :return: the renderer
        :rtype: ghidra.util.table.column.GColumnRenderer[COLUMN_TYPE]
        """

    def getComparator(self, model: DynamicColumnTableModel[typing.Any], columnIndex: typing.Union[jpype.JInt, int]) -> java.util.Comparator[COLUMN_TYPE]:
        """
        If implemented, will return a comparator that knows how to sort values for this column.
        Implementors should return ``null`` if they do not wish to provider a comparator
        
        :return: the comparator
        :rtype: java.util.Comparator[COLUMN_TYPE]
        """

    def getHeaderRenderer(self) -> GTableHeaderRenderer:
        """
        Returns the optional header renderer for this column; null if no renderer is used.
         
         
        
        This method allows columns to define custom header rendering.
        
        :return: the renderer
        :rtype: GTableHeaderRenderer
        """

    def getMaxLines(self, settings: ghidra.docking.settings.Settings) -> int:
        """
        Gets the maximum number of text display lines needed for any given cell with the specified
        settings.
        
        :param ghidra.docking.settings.Settings settings: field settings
        :return: maximum number of lines needed
        :rtype: int
        """

    def getSettingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        """
        Returns a list of settings definitions for this field.
        
        :return: list of settings definitions for this field.
        :rtype: jpype.JArray[ghidra.docking.settings.SettingsDefinition]
        """

    def getSupportedRowType(self) -> java.lang.Class[ROW_TYPE]:
        """
        Returns the single class type of the data that this table field can use to generate columnar
        data.
        
        :return: the single class type of the data that this table field can use to generate columnar
                data.
        :rtype: java.lang.Class[ROW_TYPE]
        """

    def getUniqueIdentifier(self) -> str:
        """
        Returns a value that is unique for this table column. This is different than getting the
        display name, which may be shared by different columns.
        
        :return: the identifier
        :rtype: str
        """

    def getValue(self, rowObject: ROW_TYPE, settings: ghidra.docking.settings.Settings, data: DATA_SOURCE, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> COLUMN_TYPE:
        """
        Creates an object that is appropriate for this field (table column) and for the object that
        is associated with this row of the table.
        
        :param ROW_TYPE rowObject: the object associated with the row in the table.
        :param ghidra.docking.settings.Settings settings: field settings
        :param DATA_SOURCE data: the expected data object, as defined by the DATA_SOURCE type
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: the :obj:`ServiceProvider` associated with the table.
        :return: the object for the model to display in the table cell.
        :rtype: COLUMN_TYPE
        :raises java.lang.IllegalArgumentException: if the rowObject is not one supported by this class.
        """

    @property
    def columnClass(self) -> java.lang.Class[COLUMN_TYPE]:
        ...

    @property
    def supportedRowType(self) -> java.lang.Class[ROW_TYPE]:
        ...

    @property
    def columnDisplayName(self) -> java.lang.String:
        ...

    @property
    def maxLines(self) -> jpype.JInt:
        ...

    @property
    def columnPreferredWidth(self) -> jpype.JInt:
        ...

    @property
    def columnDescription(self) -> java.lang.String:
        ...

    @property
    def settingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        ...

    @property
    def columnRenderer(self) -> ghidra.util.table.column.GColumnRenderer[COLUMN_TYPE]:
        ...

    @property
    def uniqueIdentifier(self) -> java.lang.String:
        ...

    @property
    def headerRenderer(self) -> GTableHeaderRenderer:
        ...

    @property
    def columnName(self) -> java.lang.String:
        ...


class SelectColumnsDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class ColumnComparator(java.util.Comparator[SelectColumnsDialog.TableColumnWrapper]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ColumnSelectorStringRenderer(GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ColumnSelectorBooleanRenderer(GBooleanCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TableColumnWrapper(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SelectColumnsModel(javax.swing.table.DefaultTableModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, columnModel: GTableColumnModel, model: javax.swing.table.TableModel):
        ...


class DynamicTableModel(AbstractSortedTableModel[T], typing.Generic[T]):

    @typing.type_check_only
    class AnnotatedColumn(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, method: java.lang.reflect.Method):
            ...

        def getName(self) -> str:
            ...

        def getValue(self, t: T) -> java.lang.Object:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def value(self) -> java.lang.Object:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: java.util.List[T], tClass: java.lang.Class[T]):
        ...


class GTableTextCellEditor(javax.swing.DefaultCellEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, textField: javax.swing.JTextField):
        ...


class SortedTableModel(javax.swing.table.TableModel):
    """
    A table model that allows for setting the sorted column(s) and direction
    """

    class_: typing.ClassVar[java.lang.Class]
    ASCENDING_ORDER: typing.Final = True
    """
    Sort order in ascending order.
    """

    DESCENDING_ORDER: typing.Final = False
    """
    Sort order in descending order.
    """


    def addSortListener(self, l: SortListener):
        """
        Adds a listener to be notified when the sort state of this model changes. 
         
        
        **Note: the listener may be stored in a weak collection, which means you have to 
                maintain a handle to the listener so that it does not get garbage collected.
        **
        
        :param SortListener l: the listener
        """

    def getPrimarySortColumnIndex(self) -> int:
        """
        Returns the column index that is the primary sorted column; -1 if no column is sorted
        
        :return: the index
        :rtype: int
        """

    def getTableSortState(self) -> TableSortState:
        """
        Gets the sort state of this sorted model
        
        :return: the current sort state
        :rtype: TableSortState
        """

    def isSortable(self, columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the specified columnIndex is sortable.
        
        :param jpype.JInt or int columnIndex: the column index
        :return: true if the specified columnIndex is sortable
        :rtype: bool
        """

    def setTableSortState(self, state: TableSortState):
        """
        Sets the sort state for this table model
        
        :param TableSortState state: the sort state
        """

    @property
    def primarySortColumnIndex(self) -> jpype.JInt:
        ...

    @property
    def tableSortState(self) -> TableSortState:
        ...

    @tableSortState.setter
    def tableSortState(self, value: TableSortState):
        ...

    @property
    def sortable(self) -> jpype.JBoolean:
        ...


class DefaultTableCellRendererWrapper(GTableCellRenderer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, renderer: javax.swing.table.TableCellRenderer):
        ...

    def setHTMLRenderingEnabled(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Enables and disables the rendering of HTML content in this renderer.  If enabled, this
        renderer will interpret HTML content when the text this renderer is showing begins with 
        ``<html>``
        
        :param jpype.JBoolean or bool enable: true to enable HTML rendering; false to disable it
        """


class SortListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def modelSorted(self, sortState: TableSortState):
        ...


class GTableMouseListener(java.awt.event.MouseAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@deprecated("this class is no longer used and will be removed")
class RowObject(java.lang.Object):
    """
    An object that represents a row in a table.  Most tables used in the system create models that
    use their own row objects (see :obj:`AbstractSortedTableModel`).  This class exists to 
    compensate for those models that do not do this, but instead rely on the classic Java 
    :obj:`TableModel` method :meth:`TableModel.getValueAt(int, int) <TableModel.getValueAt>`.
     
    
    For the best behavior, a table model implementation should extend 
    :obj:`AbstractSortedTableModel`, as the system is written to work for those models.  Use of
    this class as a workaround is a suitable default, but will not always result in the desired
    behavior.  A major reason for this is that if any of the table's cell values change, the 
    row objects that created for non-:obj:`AbstractSortedTableModel`s will not be equal to 
    those created before the data change.  This causes some features to break, such as selection
    restoration after user edits.
    
    
    .. deprecated::
    
    this class is no longer used and will be removed
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createRowObject(model: javax.swing.table.TableModel, row: typing.Union[jpype.JInt, int]) -> RowObject:
        """
        Factory method to create and initialize a row object.
        
        :param javax.swing.table.TableModel model: the model required to gather data for the row object.
        :param jpype.JInt or int row: the row for which to create a row object
        :return: the row object
        :rtype: RowObject
        """


class TableSortingContext(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sortState: TableSortState, comparator: java.util.Comparator[T]):
        ...

    def getComparator(self) -> java.util.Comparator[T]:
        ...

    def getSortState(self) -> TableSortState:
        ...

    def isReverseOf(self, otherContext: TableSortingContext[T]) -> bool:
        ...

    def isUnsorted(self) -> bool:
        """
        Returns true if there are no columns marked as sorted, which represents a 'no sort' state
        
        :return: true if there are no columns sorted
        :rtype: bool
        """

    @property
    def unsorted(self) -> jpype.JBoolean:
        ...

    @property
    def comparator(self) -> java.util.Comparator[T]:
        ...

    @property
    def sortState(self) -> TableSortState:
        ...

    @property
    def reverseOf(self) -> jpype.JBoolean:
        ...


class TableSortState(java.lang.Iterable[ColumnSortState]):
    """
    Represents the concept of a table's sorted state, which is the number of sorted columns, their
    sort order and their sort direction.
     
    You can create instances of this class via the :obj:`TableSortStateEditor`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, sortStates: java.util.List[ColumnSortState]):
        ...

    @typing.overload
    def __init__(self, columnSortState: ColumnSortState):
        ...

    @staticmethod
    @typing.overload
    def createDefaultSortState(columnModelIndex: typing.Union[jpype.JInt, int]) -> TableSortState:
        """
        Creates a sort state with the given column as the sorted column (sorted ascending).
        
        :param jpype.JInt or int columnModelIndex: The column to sort
        :return: a sort state with the given column as the sorted column (sorted ascending).
        :rtype: TableSortState
        
        .. seealso::
        
            | :obj:`TableSortStateEditor`
        """

    @staticmethod
    @typing.overload
    def createDefaultSortState(columnModelIndex: typing.Union[jpype.JInt, int], isAscending: typing.Union[jpype.JBoolean, bool]) -> TableSortState:
        """
        Creates a sort state with the given column as the sorted column in the given direction.
        
        :param jpype.JInt or int columnModelIndex: The column to sort
        :param jpype.JBoolean or bool isAscending: True to sort ascending; false to sort descending
        :return: a sort state with the given column as the sorted column (sorted ascending).
        :rtype: TableSortState
        
        .. seealso::
        
            | :obj:`TableSortStateEditor`
        """

    @staticmethod
    def createUnsortedSortState() -> TableSortState:
        """
        Creates a sort state that represents being unsorted
        
        :return: a sort state that represents being unsorted
        :rtype: TableSortState
        """

    def getAllSortStates(self) -> java.util.List[ColumnSortState]:
        ...

    def getColumnSortState(self, columnModelIndex: typing.Union[jpype.JInt, int]) -> ColumnSortState:
        ...

    def getSortedColumnCount(self) -> int:
        ...

    def isUnsorted(self) -> bool:
        ...

    @staticmethod
    def restoreFromXML(element: org.jdom.Element) -> TableSortState:
        ...

    def writeToXML(self) -> org.jdom.Element:
        ...

    @property
    def unsorted(self) -> jpype.JBoolean:
        ...

    @property
    def columnSortState(self) -> ColumnSortState:
        ...

    @property
    def sortedColumnCount(self) -> jpype.JInt:
        ...

    @property
    def allSortStates(self) -> java.util.List[ColumnSortState]:
        ...


class ObjectSelectedListener(java.lang.Object, typing.Generic[T]):
    """
    An interface for clients to know when an object is selected and when the selection is cleared
    """

    class_: typing.ClassVar[java.lang.Class]

    def objectSelected(self, t: T):
        """
        When an object is select; null if the selection is cleared
        
        :param T t: the object selected or null
        """


class TableItemPickedListener(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def itemPicked(self, t: T):
        ...


class AbstractSortedTableModel(AbstractGTableModel[T], SortedTableModel, typing.Generic[T]):
    """
    Table models should extends this model when they want sorting, potentially across multiple
    columns, but do not want Threading or do not work on Program-related data (Address,
    ProgramLocations, etc...).
     
    
    In order to define custom comparators for a column, simply override
    :meth:`createSortComparator(int) <.createSortComparator>`.  Otherwise, a default comparator will be created for you.
    
     
    Note on sorting: it is possible that the user can disable sorting by de-selecting all
    sorted columns.   This can also be achieved programmatically by calling
    :meth:`setTableSortState(TableSortState) <.setTableSortState>` with a value of
    :meth:`TableSortState.createUnsortedSortState() <TableSortState.createUnsortedSortState>`.
    """

    @typing.type_check_only
    class ComparatorLink(java.util.Comparator[T]):
        """
        A comparator that can be linked to other comparators to form a chain of comparators
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class EndOfChainComparator(java.util.Comparator[T]):
        """
        This class is designed to be used as the last link in a chain of comparators.  If we get
        to this comparator, then the two given objects are assumed to have compared as equal.  Thus,
        when we get to this comparator, then we have to make a decision about reasonable default
        comparisons in order to maintain sorting consistency across sorts.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReverseComparator(java.util.Comparator[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, comparator: java.util.Comparator[T]):
            ...


    @typing.type_check_only
    class StringBasedBackupRowToColumnComparator(java.util.Comparator[java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, defaultSortColumn: typing.Union[jpype.JInt, int]):
        ...

    def getPendingSortState(self) -> TableSortState:
        ...

    def getRowIndex(self, rowObject: T) -> int:
        """
        Returns the index of the given row object in this model; a negative value if the model
        does not contain the given object.
        
         
        Warning: if the this model has no sort applied, then performance will be O(n).  If
        sorted, then performance is O(log n).  You can call :meth:`isSorted() <.isSorted>` to know when
        this will happen.
        """

    def getRowObject(self, viewRow: typing.Union[jpype.JInt, int]) -> T:
        """
        Returns the corresponding object for the given row.
        
        :param jpype.JInt or int viewRow: The row for which to get the row object.
        :return: the row object.
        :rtype: T
        """

    def getValueAt(self, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        The default implementation of :meth:`TableModel.getValueAt(int, int) <TableModel.getValueAt>` that calls the
        abstract :meth:`getColumnValueForRow(Object, int) <.getColumnValueForRow>`.
        """

    def isSortPending(self) -> bool:
        """
        Returns true if there is a pending change to the current sort state
        (this includes a sort state that signals no sort will be applied)
        
        :return: true if there is a pending change to the current sort state
        :rtype: bool
        """

    def isSorted(self) -> bool:
        """
        Returns true if this model has been sorted and does not have a new pending sort that will
        be applied
        
        :return: true if sorted
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.isSortPending()`
        """

    @property
    def sorted(self) -> jpype.JBoolean:
        ...

    @property
    def pendingSortState(self) -> TableSortState:
        ...

    @property
    def sortPending(self) -> jpype.JBoolean:
        ...

    @property
    def rowIndex(self) -> jpype.JInt:
        ...

    @property
    def rowObject(self) -> T:
        ...


class RowObjectSelectionManager(javax.swing.DefaultListSelectionModel, SelectionManager, typing.Generic[T]):
    """
    A class to track and restore selections made in a table.  We use this in the docking
    environment primarily due to the heavy usage of filtering for most tables.  As tables are
    filtered, the contents change (and then change back when the filter is removed).  It is nice
    to be able to filter a table, select an item of interest, and then unfilter the table to see
    that item in more context.
    """

    @typing.type_check_only
    class FilterModelAdapter(RowObjectFilterModel[T]):
        """
        Base class for models that are not themselves FilterModel implementations.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FilterModelPassThrough(RowObjectSelectionManager.FilterModelAdapter):
        """
        Subclass that delegates filter methods to the wrapped model.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SelectionStorageHelper(SelectionStorage[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: javax.swing.JTable, model: RowObjectTableModel[T]):
        ...


class DefaultRowFilterTransformer(RowFilterTransformer[ROW_OBJECT], typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tableModel: RowObjectTableModel[ROW_OBJECT], columnModel: javax.swing.table.TableColumnModel):
        ...


class GTableColumnModel(javax.swing.table.TableColumnModel, java.beans.PropertyChangeListener, javax.swing.event.ListSelectionListener):

    @typing.type_check_only
    class VisibleColumns(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            ...

        @typing.overload
        def __init__(self, newVisibleList: java.util.List[javax.swing.table.TableColumn]):
            ...

        @typing.overload
        def add(self, column: javax.swing.table.TableColumn):
            ...

        @typing.overload
        def add(self, insertIndex: typing.Union[jpype.JInt, int], column: javax.swing.table.TableColumn):
            ...

        def get(self, index: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableColumn:
            ...

        def indexOf(self, column: javax.swing.table.TableColumn) -> int:
            ...

        @typing.overload
        def remove(self, column: javax.swing.table.TableColumn):
            ...

        @typing.overload
        def remove(self, index: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableColumn:
            ...

        def toEnumeration(self) -> java.util.Enumeration[javax.swing.table.TableColumn]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addHiddenColumn(self, aColumn: javax.swing.table.TableColumn):
        """
        Adds a table column to this model that is not visible default.  This column may be made
        visible later by the user or by the system restoring a previously used visible column state.
        
        :param javax.swing.table.TableColumn aColumn: the column
        """

    def getAllColumns(self) -> java.util.List[javax.swing.table.TableColumn]:
        """
        This returns all columns known by this model, both visible and not seen.
        
        :return: all columns known by this model, both visible and not seen.
        :rtype: java.util.List[javax.swing.table.TableColumn]
        """

    @typing.overload
    def isVisible(self, column: javax.swing.table.TableColumn) -> bool:
        """
        Returns true if the given column is visible.
        
        :param javax.swing.table.TableColumn column: The column for which to check visibility.
        :return: true if the given column is visible.
        :rtype: bool
        """

    @typing.overload
    def isVisible(self, modelIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the column at the given index is visible.  This call is handy when
        checking for visibility when dealing with model data that knows nothing about the
        hidden columns.
        
        :param jpype.JInt or int modelIndex: The column index for which to check visibility.  This is the model's
                        index and **not the table's index**.
        :return: true if the given column is visible.
        :rtype: bool
        """

    def restoreFromXML(self, element: org.jdom.Element):
        ...

    def saveToXML(self) -> org.jdom.Element:
        ...

    def setVisible(self, column: javax.swing.table.TableColumn, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @property
    def allColumns(self) -> java.util.List[javax.swing.table.TableColumn]:
        ...


class FilterTypeConverter(java.lang.Object, typing.Generic[COLUMN_TYPE, FILTER_TYPE]):
    """
    An interface that is meant to take the column type of a :obj:`DynamicTableColumn`
    and convert it to the specified type.   This class is meant to be used when the dynamic 
    filtering mechanism is not correctly filtering a column, usually because the default filter
    for the column type does not match what the renderer is displaying in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def convert(self, t: COLUMN_TYPE, settings: ghidra.docking.settings.Settings) -> FILTER_TYPE:
        """
        Converts in instance of the column type to an instance of the destination type
        
        :param COLUMN_TYPE t: the column type instance
        :param ghidra.docking.settings.Settings settings: any settings the converter may need to convert the type
        :return: the new object
        :rtype: FILTER_TYPE
        """

    def getFilterType(self) -> java.lang.Class[FILTER_TYPE]:
        """
        Returns the destination class of the conversion
        
        :return: the destination class
        :rtype: java.lang.Class[FILTER_TYPE]
        """

    @property
    def filterType(self) -> java.lang.Class[FILTER_TYPE]:
        ...


class SelectionManager(javax.swing.ListSelectionModel, javax.swing.event.TableModelListener):
    """
    A class to track and restore selections made in a table.  We use this in the docking 
    environment primarily due to the heavy usage of filtering for most tables.  As tables are
    filtered, the contents change (and then change back when the filter is removed).  It is nice
    to be able to filter a table, select an item of interest, and then unfilter the table to see
    that item in more context.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addSelectionManagerListener(self, listener: SelectionManagerListener):
        ...

    def clearSavedSelection(self):
        ...

    def dispose(self):
        ...

    def removeSelectionManagerListener(self, listener: SelectionManagerListener):
        ...


class GTableWidget(javax.swing.JPanel, typing.Generic[T]):
    """
    A GUI that provides a filterable table.  You are required to provide the method names
    of ``T`` that should be used to create columns in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], tClass: java.lang.Class[T], *methodNames: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], *methods: java.lang.reflect.Method):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], tClass: java.lang.Class[T], methodNames: java.util.List[java.lang.String]):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], methodNames: java.util.List[java.lang.reflect.Method]):
        ...

    @typing.overload
    def addColumn(self, column: AbstractDynamicTableColumn[T, typing.Any, java.lang.Object]):
        ...

    @typing.overload
    def addColumn(self, column: AbstractDynamicTableColumn[T, typing.Any, java.lang.Object], index: typing.Union[jpype.JInt, int]):
        ...

    def addSelectionListener(self, l: ObjectSelectedListener[T]):
        ...

    def dispose(self):
        ...

    def focusFilter(self):
        ...

    def getData(self) -> java.util.List[T]:
        ...

    def getItemAt(self, point: java.awt.Point) -> T:
        ...

    def getModel(self) -> AnyObjectTableModel[T]:
        ...

    def getRowCount(self) -> int:
        ...

    def getRowObject(self, row: typing.Union[jpype.JInt, int]) -> T:
        ...

    def getSelectedRow(self) -> int:
        ...

    def getSelectedRowCount(self) -> int:
        ...

    def getSelectedRowObjects(self) -> java.util.List[T]:
        ...

    def getSelectionMode(self) -> int:
        ...

    def getTable(self) -> GTable:
        ...

    def isRowSelected(self, row: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def removeSelectionListener(self, l: ObjectSelectedListener[T]):
        ...

    def rowAtPoint(self, point: java.awt.Point) -> int:
        ...

    def selectRow(self, row: typing.Union[jpype.JInt, int]):
        ...

    def selectRowObject(self, rowObject: T):
        ...

    def setColumnPreferredWidths(self, *widths: typing.Union[jpype.JInt, int]):
        """
        Sets the column preferred widths.  If you give less widths then there are columns, then
        the widths will be applied in order, with the remaining columns going untouched.
         
        
        Note: this method needs to be called after building your columns. So, call this after
        making any calls to :meth:`addColumn(AbstractDynamicTableColumn) <.addColumn>`.
         
        
        **WARNING!**  If you set the widths to a size that is smaller than the total display,
        then the table model will apply the extra space equally across your columns, resulting
        in sizes that you did not set.  So, the best way to use this method is to set the
        actual preferred size for your small columns and then set a very large size (400 or so)
        for your columns that can be any size.
        
        :param jpype.JArray[jpype.JInt] widths: the widths to apply
        """

    @typing.overload
    def setData(self, data: java.util.List[T]):
        ...

    @typing.overload
    def setData(self, data: collections.abc.Sequence):
        ...

    def setFilterText(self, text: typing.Union[java.lang.String, str]):
        ...

    def setItemPickListener(self, listener: TableItemPickedListener[T]):
        ...

    def setSelectionMode(self, mode: typing.Union[jpype.JInt, int]):
        """
        Sets the selection mode of this table.
        
        :param jpype.JInt or int mode: the mode
        
        .. seealso::
        
            | :obj:`ListSelectionModel.setSelectionMode(int)`
        """

    @typing.overload
    def setSortColumn(self, column: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def setSortColumn(self, column: typing.Union[jpype.JInt, int], ascending: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def data(self) -> java.util.List[T]:
        ...

    @data.setter
    def data(self, value: java.util.List[T]):
        ...

    @property
    def rowSelected(self) -> jpype.JBoolean:
        ...

    @property
    def selectedRowObjects(self) -> java.util.List[T]:
        ...

    @property
    def itemAt(self) -> T:
        ...

    @property
    def model(self) -> AnyObjectTableModel[T]:
        ...

    @property
    def selectedRow(self) -> jpype.JInt:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def selectedRowCount(self) -> jpype.JInt:
        ...

    @property
    def table(self) -> GTable:
        ...

    @property
    def selectionMode(self) -> jpype.JInt:
        ...

    @selectionMode.setter
    def selectionMode(self, value: jpype.JInt):
        ...

    @property
    def rowObject(self) -> T:
        ...


class TableColumnModelState(SortListener):
    """
    A class to keep track of and persist state for column models, including size, ordering and
    visibility.
     
    
    This class performs a bit of magic to accomplish its goals.  Resultingly, some of the code
    herein may seem a bit odd or of poor quality.  These rough spots are documented as best as
    possible.
     
    
    The basic outline of how this class works:
    
    
    This class loads and save table column state via requests made by clients like the :obj:`GTable` or
    the :obj:`GTableColumnModel`.  These requests are in response to direct users actions (like
    showing a new column) or to table changes (like column resizing).  There are few things that
    make this code tricky.  Namely, when a change notification comes from the subsystem and not
    direct user intervention, we do not know if the change was motived by the user directly or
    by programmatic table configuration.  We would prefer to only save data when the user makes
    changes, but we can not always know the source of the change.  For example, column resizing
    can happen due to user dragging or due to the table subsystem performing a column layout.
     
    
    To facilitate this magic, we listen to all changes, attempting to: 1) ignore those that we know
    are not from the user, and 2) buffer the changes so that they are not excessive and so they
    happen in the correct order.
     
    
    For 1, we ignore all changes until the table has been shown for the first time.  For 2, we use
    SwingUpdate managers.
     
    
    The complicated part is that we allow clients to add columns at any time.  If they do so
    after the table has been made visible, then we cannot ignore the event like we do when the
    table has not yet been realized.  In our world view, the uniqueness of a table is based upon
    it's class and its columns.  Thus, when a column is added or removed, it becomes a different
    table and thus, saved settings must be applied.
    """

    class_: typing.ClassVar[java.lang.Class]


class TableRowMapper(ghidra.util.classfinder.ExtensionPoint, typing.Generic[ROW_TYPE, EXPECTED_ROW_TYPE, DATA_SOURCE]):
    """
    NOTE:  ALL TableRowMapper CLASSES MUST END IN "TableRowMapper".  If not,
    the ClassSearcher will not find them.
     
    An interface that allows implementors to map an object of one type to another.  This is useful
    for table models that have row types that are easily converted to other more generic types.
     
    
    This interface is an ExtensionPoint so that once created, they will be ingested automatically
    by Ghidra.  Once discovered, these mappers will be used to provide dynamic columns to 
    tables with row types that match ``ROW_TYPE``.
    
    
    .. seealso::
    
        | :obj:`DynamicTableColumn`
    
        | :obj:`TableUtils`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def createMappedTableColumn(self, destinationColumn: DynamicTableColumn[EXPECTED_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]) -> DynamicTableColumn[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]:
        """
        Creates a table column that will create a table column that knows how to map the 
        given **ROW_TYPE** to the type of the column passed in, the **EXPECTED_ROW_TYPE**.
        
        :param COLUMN_TYPE: The column type of the given and created columns:param DynamicTableColumn[EXPECTED_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE] destinationColumn: The existing column, which is based upon EXPECTED_ROW_TYPE,
                that we want to be able to use with the type we have, the ROW_TYPE.
        """

    def getDestinationType(self) -> java.lang.Class[EXPECTED_ROW_TYPE]:
        ...

    def getSourceType(self) -> java.lang.Class[ROW_TYPE]:
        ...

    def map(self, rowObject: ROW_TYPE, data: DATA_SOURCE, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> EXPECTED_ROW_TYPE:
        ...

    @property
    def sourceType(self) -> java.lang.Class[ROW_TYPE]:
        ...

    @property
    def destinationType(self) -> java.lang.Class[EXPECTED_ROW_TYPE]:
        ...


class MappedTableColumn(AbstractDynamicTableColumn[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE], typing.Generic[ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]):
    """
    A class that is an Adapter in order to allow for the use of existing :obj:`DynamicTableColumn`s
    when the actual row type of the table is not the same as the row type that the
    :obj:`DynamicTableColumn` supports.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMappedColumnClass(self) -> java.lang.Class[typing.Any]:
        """
        Returns the class of the column that this mapper wraps
        
        :return: the class of the column that this mapper wraps
        :rtype: java.lang.Class[typing.Any]
        """

    def map(self, rowObject: ROW_TYPE, data: DATA_SOURCE, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> EXPECTED_ROW_TYPE:
        ...

    @property
    def mappedColumnClass(self) -> java.lang.Class[typing.Any]:
        ...


class ConfigurableColumnTableModel(javax.swing.table.TableModel):
    """
    A model that provides access to table columns that are "configurable," whether by way of 
    :obj:`Settings` object, or by the implementations and how they were written (like supplying 
    custom renderers and such).
    """

    class_: typing.ClassVar[java.lang.Class]

    def getColumnSettings(self, index: typing.Union[jpype.JInt, int]) -> ghidra.docking.settings.Settings:
        """
        Returns settings for the specified column index
        
        :param jpype.JInt or int index: column index
        :return: column settings.
        :rtype: ghidra.docking.settings.Settings
        """

    def getColumnSettingsDefinitions(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        """
        Returns settings definitions for the specified column index
        
        :param jpype.JInt or int index: column index
        :return: column settings definitions.
        :rtype: jpype.JArray[ghidra.docking.settings.SettingsDefinition]
        """

    def getHeaderRenderer(self, columnIndex: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableCellRenderer:
        """
        Returns the header cell renderer for the given column
        
        :param jpype.JInt or int columnIndex: the index of the column
        :return: the renderer
        :rtype: javax.swing.table.TableCellRenderer
        """

    def getMaxLines(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the maximum number of text display lines needed for any given cell within the 
        specified column
        
        :param jpype.JInt or int index: column field index
        :return: maximum number of lines needed for specified column
        :rtype: int
        """

    def getRenderer(self, columnIndex: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableCellRenderer:
        """
        Returns the table cell renderer for the given column
        
        :param jpype.JInt or int columnIndex: the index of the column
        :return: the renderer
        :rtype: javax.swing.table.TableCellRenderer
        """

    def setAllColumnSettings(self, settings: jpype.JArray[ghidra.docking.settings.Settings]):
        """
        Allows for the bulk setting of Settings.  This prevents excessive event 
        notification when all settings need to be changed.
        
        :param jpype.JArray[ghidra.docking.settings.Settings] settings: An array of Settings that contains Settings for each column  
                where the index of the Settings in the array is the index of the column
                in the model
        """

    @property
    def renderer(self) -> javax.swing.table.TableCellRenderer:
        ...

    @property
    def columnSettingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        ...

    @property
    def maxLines(self) -> jpype.JInt:
        ...

    @property
    def headerRenderer(self) -> javax.swing.table.TableCellRenderer:
        ...

    @property
    def columnSettings(self) -> ghidra.docking.settings.Settings:
        ...


class SelectionStorage(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def getLastSelectedObjects(self) -> java.util.List[T]:
        ...

    def setLastSelectedObjects(self, lastSelectedObjects: java.util.List[T]):
        ...

    @property
    def lastSelectedObjects(self) -> java.util.List[T]:
        ...

    @lastSelectedObjects.setter
    def lastSelectedObjects(self, value: java.util.List[T]):
        ...


class DynamicColumnTableModel(ConfigurableColumnTableModel, RowObjectTableModel[ROW_TYPE], typing.Generic[ROW_TYPE]):
    """
    Marks this model as one that is column-based, using :obj:`DynamicTableColumn`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getColumn(self, index: typing.Union[jpype.JInt, int]) -> DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]:
        """
        Returns the column for the given model index
        
        :param jpype.JInt or int index: the model index of the column (this can differ from the view index)
        :return: the column
        :rtype: DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]
        """

    def getColumnIndex(self, column: DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]) -> int:
        """
        Returns the model index for the given column
        
        :param DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any] column: the column
        :return: the model index
        :rtype: int
        """

    @property
    def column(self) -> DynamicTableColumn[ROW_TYPE, typing.Any, typing.Any]:
        ...

    @property
    def columnIndex(self) -> jpype.JInt:
        ...


class AddRemoveListItem(java.lang.Object, typing.Generic[T]):
    """
    An object that represents and add, remove or change operation for one row of a table
    """

    class Type(java.lang.Enum[AddRemoveListItem.Type]):

        class_: typing.ClassVar[java.lang.Class]
        ADD: typing.Final[AddRemoveListItem.Type]
        REMOVE: typing.Final[AddRemoveListItem.Type]
        CHANGE: typing.Final[AddRemoveListItem.Type]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AddRemoveListItem.Type:
            ...

        @staticmethod
        def values() -> jpype.JArray[AddRemoveListItem.Type]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, type: AddRemoveListItem.Type, value: T):
        ...

    def getType(self) -> AddRemoveListItem.Type:
        ...

    def getValue(self) -> T:
        ...

    def isAdd(self) -> bool:
        ...

    def isChange(self) -> bool:
        ...

    def isRemove(self) -> bool:
        ...

    @property
    def add(self) -> jpype.JBoolean:
        ...

    @property
    def change(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> AddRemoveListItem.Type:
        ...

    @property
    def value(self) -> T:
        ...

    @property
    def remove(self) -> jpype.JBoolean:
        ...


class RowFilterTransformer(java.lang.Object, typing.Generic[ROW_OBJECT]):
    """
    Instances of this class converts table rows into lists of strings.  These objects can be set
    on GTableFilterPanel to customize how the user typed text filters are applied to a table row.
    For example, a custom row transformer could be used to limit which columns of a table are 
    included in the filter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def transform(self, rowObject: ROW_OBJECT) -> java.util.List[java.lang.String]:
        ...


class DefaultTableTextFilterFactory(TableTextFilterFactory[ROW_OBJECT], typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterOptions: docking.widgets.filter.FilterOptions):
        ...


class RowObjectTableModel(javax.swing.table.TableModel, typing.Generic[T]):
    """
    An interface to mark that the given model uses a single object to represent each row in the
    table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fireTableDataChanged(self):
        """
        Sends an event to all listeners that all the data inside of this model may have changed.
        """

    def getColumnValueForRow(self, t: T, columnIndex: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        Implementors are expected to return a value at the given column index for the specified
        row object.  This is essentially a more specific version of the
        :meth:`TableModel.getValueAt(int, int) <TableModel.getValueAt>` that allows this class's comparator objects to work.
        
        :param T t: The object that represents a given row.
        :param jpype.JInt or int columnIndex: The column index for which a value is requested.
        :return: a value at the given column index for the specified row object.
        :rtype: java.lang.Object
        """

    def getModelData(self) -> java.util.List[T]:
        """
        Implementors should return the current data of the model.  For models that support
        filtering, this will be the filtered version of the data.  Furthermore, the data should be
        the underlying data and not a copy, as this method will potentially sort the given data.
         
        
        For those subclasses using an array, you may use the ``Arrays`` class to create
        a list backed by the array (:meth:`Arrays.asList(Object...) <Arrays.asList>`).
        
        :return: the model data.
        :rtype: java.util.List[T]
        """

    def getName(self) -> str:
        """
        Returns the name of this model
        
        :return: the name of this model
        :rtype: str
        """

    def getRowIndex(self, t: T) -> int:
        """
        Returns the row number for the given object.
         
        
        **Note: the index returned is always the 'view' index.  For non-filtering table models,
        the 'view' and the 'model' index are the same.  However, for filtering table models,
        the 'view' may be a subset of the 'model' index.   Thus, it is possible, if this model
        is a filtering model, that the given ``t`` may not have a row value for the current
        state of the model (i.e., when the model is filtered in the view.  If you really need to
        get the model index in such a situation, see :obj:`RowObjectFilterModel`.
        **
        
        :param T t: the object
        :return: the row number
        :rtype: int
        """

    def getRowObject(self, viewRow: typing.Union[jpype.JInt, int]) -> T:
        """
        Returns the row object for the given row.  This is the row in the UI.  For models that
        know how to filter, the model row value will not match the view row value.  For
        non-filtering models the view and model rows will always be the same.
        
        :param jpype.JInt or int viewRow: the row for which to return a row object.
        :return: the row object
        :rtype: T
        """

    @staticmethod
    def unwrap(m: javax.swing.table.TableModel) -> javax.swing.table.TableModel:
        ...

    @property
    def modelData(self) -> java.util.List[T]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def rowIndex(self) -> jpype.JInt:
        ...

    @property
    def rowObject(self) -> T:
        ...


class GTable(javax.swing.JTable):
    """
    A sub-class of ``JTable`` that provides navigation and auto-lookup.
    By default, both of these features are disabled.
     
    
    Auto-lookup is only supported on one column and must be specified
    using the ``setAutoLookupColumn()`` method.
     
    
    Auto-lookup allows a user to begin typing the first few letters
    of a desired row. The table will attempt to locate the first row
    that contains the letters typed up to that point. There is an
    800ms timeout between typed letters, at which point the list of
    typed letters will be flushed.
     
    
    Auto-lookup is much faster if the underlying table model implements
    ``SortedTableModel``, because a binary search can used
    to locate the desired row. A linear search is used if the model is not sorted.
     
    
    Other features provided:
     
    * Column hiding/showing
    * Multi-column sorting
    * Column settings
    * Column state saving (visibility, size, positioning, sort values)
    * Selection management (saving/restoring selection when used with a filter panel)
    
    
    
    .. seealso::
    
        | :obj:`GTableFilterPanel`
    """

    @typing.type_check_only
    class ColumnSelectionState(java.lang.Object):
        """
        A class that captures attribute of the table's column model so that we can change and then
        restore those values.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyTableColumnModelListener(javax.swing.event.TableColumnModelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GTableAction(docking.action.DockingAction, docking.action.ComponentBasedDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new GTable
        """

    @typing.overload
    def __init__(self, dm: javax.swing.table.TableModel):
        """
        Constructs a new GTable using the specified table model.
        
        :param javax.swing.table.TableModel dm: the table model
        """

    def areActionsEnabled(self) -> bool:
        """
        Returns true if key strokes are used to trigger actions.
        
         
        This method has a relationship with :meth:`setAutoLookupColumn(int) <.setAutoLookupColumn>`.  If this method
        returns ``true``, then the auto-lookup feature is disabled.  If this method
        returns ``false``, then the auto-lookup may or may not be enabled.
        
        :return: true if key strokes are used to trigger actions
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.setActionsEnabled(boolean)`
        
            | :obj:`.setAutoLookupColumn(int)`
        """

    @staticmethod
    def createSharedActions(tool: docking.Tool, toolActions: docking.actions.ToolActions, owner: typing.Union[java.lang.String, str]):
        ...

    def dispose(self):
        """
        Call this when the table will no longer be used
        """

    def editCellAt(self, row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int], e: java.util.EventObject) -> bool:
        """
        If you just begin typing into an editable cell in a JTable, then the cell editor will be
        displayed. However, the editor component will not have a focus. This method has been
        overridden to request focus on the editor component.
        
        
        .. seealso::
        
            | :obj:`javax.swing.JTable.editCellAt(int, int, EventObject)`
        """

    def getCellRendererOverride(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableCellRenderer:
        """
        Performs custom work to locate renderers for special table model types.  This method allows
        clients to bypass the :meth:`getCellRenderer(int, int) <.getCellRenderer>`, which is sometimes overridden by
        subclasses to return a hard-coded renderer.  In that case, some clients still want a way to
        perform normal cell renderer lookup.
        
        :param jpype.JInt or int row: the row
        :param jpype.JInt or int col: the column
        :return: the cell renderer
        :rtype: javax.swing.table.TableCellRenderer
        """

    def getConfigurableColumnTableModel(self) -> ConfigurableColumnTableModel:
        """
        Returns the underlying ConfigurableColumnTableModel if one is in-use
        
        :return: the underlying ConfigurableColumnTableModel if one is in-use
        :rtype: ConfigurableColumnTableModel
        """

    def getHeaderRendererOverride(self, col: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableCellRenderer:
        """
        Performs custom work to locate header renderers for special table model types.  The headers
        are located and installed at the time the table's model is set.
        
        :param jpype.JInt or int col: the column
        :return: the header cell renderer
        :rtype: javax.swing.table.TableCellRenderer
        """

    def getPreferenceKey(self) -> str:
        """
        
        
        :return: the preference key
        :rtype: str
        
        .. seealso::
        
            | :obj:`.setPreferenceKey(String)`
        """

    def getSelectionManager(self) -> SelectionManager:
        """
        Returns the :obj:`SelectionManager` in use by this GTable.  ``null`` is returned
        if the user has installed their own :obj:`ListSelectionModel`.
        
        :return: the selection manager
        :rtype: SelectionManager
        """

    def getTableColumnPopupMenu(self, columnIndex: typing.Union[jpype.JInt, int]) -> javax.swing.JPopupMenu:
        ...

    def getTableFilterPanel(self) -> GTableFilterPanel[typing.Any]:
        """
        Returns the filter panel being used by this table or null.
        
        :return: the filter panel or null
        :rtype: GTableFilterPanel[typing.Any]
        """

    def isColumnHeaderPopupEnabled(self) -> bool:
        ...

    def notifyTableChanged(self, event: javax.swing.event.TableModelEvent):
        """
        A method that allows clients to signal to this GTable and its internals that the table
        model has changed.  Usually, :meth:`tableChanged(TableModelEvent) <.tableChanged>` is called, but clients
        alter the table, but do not do so through the model.  In this case, they need a way to
        signal to the table that the model has been updated.
        
        :param javax.swing.event.TableModelEvent event: the event for the change
        """

    def requestTableEditorFocus(self):
        ...

    def savePreferences(self):
        """
        Signals that the preferences of this table (visible columns, sort order, etc.) should be
        saved.  Most clients never need to call this method, as changes are saved for free when
        the user manipulates columns.  However, sometimes the client can change the state of the
        columns programmatically, which is not guaranteed to get saved; for example, setting
        the sort state of a sorted table model programmatically will not get saved.
        """

    def scrollToSelectedRow(self):
        ...

    @typing.overload
    def selectRow(self, row: typing.Union[jpype.JInt, int]):
        """
        Selects the given row.  This is a convenience method for
        :meth:`setRowSelectionInterval(int, int) <.setRowSelectionInterval>`.
        
        :param jpype.JInt or int row: The row to select
        """

    @typing.overload
    def selectRow(self, event: java.awt.event.MouseEvent) -> bool:
        """
        Selects the row under the given mouse point.  This method is useful when the user
        triggers a popup mouse action and you would like to have the table select that row if it
        is not already selected.  This allows you to guarantee that there is always a selection
        when the user triggers a popup menu.
        
        :param java.awt.event.MouseEvent event: The event that triggered the popup menu
        :return: true if the row is selected or was already selected.
        :rtype: bool
        """

    def setAccessibleNamePrefix(self, namePrefix: typing.Union[java.lang.String, str]):
        """
        Sets an accessible name on the GTable such that screen readers will properly describe them.
         
        
        This prefix should be the base name that describes the type of items in the table. 
        This method will then append the necessary information to property name the table.
        
        :param java.lang.String or str namePrefix: the accessible name prefix to assign to the filter component. For
        example if the table contains fruits, then "Fruits" would be an appropriate prefix name.
        """

    def setActionsEnabled(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Enables the keyboard actions to pass through this table and up the component hierarchy.
        Specifically, passing true to this method allows unmodified keystrokes to work
        in the tool when this table is focused.  Modified keystrokes, like ``
        Ctrl-C``, will work at all times.   Finally, if true is passed to this
        method, then the :meth:`auto lookup <.setAutoLookupColumn>` feature is
        disabled.
        
         
        The default state is for actions to be disabled.
        
        :param jpype.JBoolean or bool b: true allows keyboard actions to pass up the component hierarchy.
        """

    def setAutoEditEnabled(self, allowAutoEdit: typing.Union[jpype.JBoolean, bool]):
        """
        Enables or disables auto-edit.  When enabled, the user can start typing to trigger an
        edit of an editable table cell.
        
        :param jpype.JBoolean or bool allowAutoEdit: true for auto-editing
        """

    def setAutoLookupColumn(self, lookupColumn: typing.Union[jpype.JInt, int]):
        """
        Sets the column in which auto-lookup will be enabled.
        
         
        Note: calling this method with a valid column index will disable key binding support
        of actions.  See :meth:`setActionsEnabled(boolean) <.setActionsEnabled>`.  Passing an invalid column index
        will disable the auto-lookup feature.
        
        :param jpype.JInt or int lookupColumn: the column in which auto-lookup will be enabled
        """

    def setAutoLookupTimeout(self, timeout: typing.Union[jpype.JLong, int]):
        """
        Sets the delay between keystrokes after which each keystroke is considered a new lookup
        
        :param jpype.JLong or int timeout: the timeout
        
        .. seealso::
        
            | :obj:`.setAutoLookupColumn(int)`
        
            | :obj:`AutoLookup.KEY_TYPING_TIMEOUT`
        """

    def setColumnHeaderPopupEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setHTMLRenderingEnabled(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Enables and disables the rendering of HTML content in this table.  If enabled, this table
        will:
         
        * Wrap tooltip text content with an <html> tag so that it is possible for
        the content to be formatted in a manner that is easier for the user read, and
        * Enable any default:obj:`GTableCellRenderer` instances to render
        HTML content, which they do not do by default.
        
         
        
        HTML rendering is disabled by default.
        
        :param jpype.JBoolean or bool enable: true to enable HTML rendering; false to disable it
        """

    def setPreferenceKey(self, preferenceKey: typing.Union[java.lang.String, str]):
        """
        Sets the key for saving and restoring column configuration state.  Use this if you have
        multiple instances of a table and you want different column settings for each instance.
        
        :param java.lang.String or str preferenceKey: the unique string to use a key for this instance.
        """

    def setTableFilterPanel(self, filterPanel: GTableFilterPanel[typing.Any]):
        """
        Sets the table filter panel being used for this table.
        
        :param GTableFilterPanel[typing.Any] filterPanel: the filter panel
        """

    def setUserSortingEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Allows for the disabling of the user's ability to sort an instance of
        :obj:`AbstractSortedTableModel` by clicking the table's headers.  The default setting is
        enabled.
        
        :param jpype.JBoolean or bool enabled: true to enable; false to disable
        """

    def setVisibleRowCount(self, visibleRowCount: typing.Union[jpype.JInt, int]):
        ...

    @property
    def tableColumnPopupMenu(self) -> javax.swing.JPopupMenu:
        ...

    @property
    def headerRendererOverride(self) -> javax.swing.table.TableCellRenderer:
        ...

    @property
    def columnHeaderPopupEnabled(self) -> jpype.JBoolean:
        ...

    @columnHeaderPopupEnabled.setter
    def columnHeaderPopupEnabled(self, value: jpype.JBoolean):
        ...

    @property
    def configurableColumnTableModel(self) -> ConfigurableColumnTableModel:
        ...

    @property
    def preferenceKey(self) -> java.lang.String:
        ...

    @preferenceKey.setter
    def preferenceKey(self, value: java.lang.String):
        ...

    @property
    def tableFilterPanel(self) -> GTableFilterPanel[typing.Any]:
        ...

    @tableFilterPanel.setter
    def tableFilterPanel(self, value: GTableFilterPanel[typing.Any]):
        ...

    @property
    def selectionManager(self) -> SelectionManager:
        ...


class TableFilter(java.lang.Object, typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]

    def acceptsRow(self, rowObject: ROW_OBJECT) -> bool:
        """
        Returns true if this filter matches the given row (data)
        
        :param ROW_OBJECT rowObject: the current row object
        :return: true if the element at the given row matches this filter.
        :rtype: bool
        """

    def hasColumnFilter(self, columnModelIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the there is a column filter on the column specified
        
        :param jpype.JInt or int columnModelIndex: the model index of the column to test for column filters.
        :return: true if the there is a column filter on the column specified.
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        A method that allows filters to report that they have nothing to actually filter.  This
        is useful for empty/null filters.
        
        :return: true if this filter will not perform any filtering
        :rtype: bool
        """

    def isSubFilterOf(self, tableFilter: TableFilter[typing.Any]) -> bool:
        """
        Returns true if this filter is a more specific version of the given filter.
        
         
        For example, if this filter is a 'starts with' text filter, with the
        value of 'bobo', then if the given filter is also a 'starts with' filter,
        with a value of 'bob', then this
        filter is considered a sub-filter of the given sub-filter.
        
        :param TableFilter[typing.Any] tableFilter: the filter to check
        :return: true if this filter is a sub-filter of the given filter
        :rtype: bool
        """

    @property
    def subFilterOf(self) -> jpype.JBoolean:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class AbstractDynamicTableColumnStub(AbstractDynamicTableColumn[ROW_TYPE, COLUMN_TYPE, java.lang.Object], typing.Generic[ROW_TYPE, COLUMN_TYPE]):
    """
    This class is meant to be used by DynamicTableColumn implementations that do not care about
    the DATA_SOURCE parameter of DynamicTableColumn.  This class will stub the default
    :meth:`getValue(Object, Settings, Object, ServiceProvider) <.getValue>` method and
    call a version of the method that does not have the DATA_SOURCE parameter.
     
    
    Subclasses are not discoverable.  To create discoverable columns for the framework, you must
    extends :obj:`DynamicTableColumnExtensionPoint`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getValue(self, rowObject: ROW_TYPE, settings: ghidra.docking.settings.Settings, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> COLUMN_TYPE:
        ...


class InvertedTableFilter(TableFilter[ROW_OBJECT], typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter: TableFilter[ROW_OBJECT]):
        ...


class GTableAutoLookup(docking.widgets.AutoLookup):
    """
    :obj:`AutoLookup` implementation for :obj:`GTable`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: GTable):
        ...


class DisplayStringProvider(java.lang.Object):
    """
    An interface used by classes to indicate that they can produce a String representation that
    is meant to be seen by the user in the UI.  One example use of this interface is the 
    table filtering mechanism, which will look for this interface when attempting to transform
    table cell data to filterable Strings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDisplayString(self) -> str:
        """
        Returns a display String suitable for user consumption
        
        :return: a display String suitable for user consumption
        :rtype: str
        """

    @property
    def displayString(self) -> java.lang.String:
        ...


class SelectionManagerListener(java.lang.Object):
    """
    A listener that will get notified of selections made by the :obj:`SelectionManager`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def restoringSelection(self, preRestore: typing.Union[jpype.JBoolean, bool]):
        """
        Called before and after a selection is restored.  This is useful for clients that wish to
        know when selections are changing due to the SelectionManager versus user initiated 
        selections or programmatic selections.
        
        :param jpype.JBoolean or bool preRestore: true if the :obj:`SelectionManager` is about to restore selections; 
                        false when the :obj:`SelectionManager` is finished restoring selections.
        """


class AbstractDynamicTableColumn(DynamicTableColumn[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE], typing.Generic[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]):
    """
    An Table Column is an interface that should be implemented by each class that provides a field
    (column) of an object based table (each row relates to a particular type of object). It
    determines the appropriate cell object for use by the table column this field represents. It can
    then return the appropriate object to display in the table cell for the indicated row object.
    """

    class_: typing.ClassVar[java.lang.Class]
    NO_SETTINGS_DEFINITIONS: typing.ClassVar[jpype.JArray[ghidra.docking.settings.SettingsDefinition]]

    def __init__(self):
        ...

    def getComparator(self) -> java.util.Comparator[COLUMN_TYPE]:
        ...

    @property
    def comparator(self) -> java.util.Comparator[COLUMN_TYPE]:
        ...


class GTableHeaderRenderer(javax.swing.table.DefaultTableCellRenderer):

    @typing.type_check_only
    class NumberPainterIcon(javax.swing.Icon):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int], numberText: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setSortEmphasis(self, sortEmphasis: typing.Union[jpype.JDouble, float]):
        """
        Sets the an emphasis value for this column that is used to slightly enlarge and call out the
        sort for the column.
        
        :param jpype.JDouble or float sortEmphasis: the emphasis value
        """


class MultiTextFilterTableFilter(TableFilter[ROW_OBJECT], typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filters: java.util.List[docking.widgets.filter.TextFilter], transformer: RowFilterTransformer[ROW_OBJECT], evalMode: docking.widgets.filter.MultitermEvaluationMode):
        ...


class CombinedTableFilter(TableFilter[T], typing.Generic[T]):
    """
    Combines multiple Table Filters into a single TableFilter that can be applied.  All contained
    filters must pass for this combined filter to pass.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter1: TableFilter[T], filter2: TableFilter[T], filter3: TableFilter[T]):
        ...

    def getFilter(self, index: typing.Union[jpype.JInt, int]) -> TableFilter[typing.Any]:
        """
        Returns the filter at the given index into the list of sub filters.
        
        :param jpype.JInt or int index: the index of the filter to retrieve
        :return: the i'th filter.
        :rtype: TableFilter[typing.Any]
        """

    def getFilterCount(self) -> int:
        """
        Returns the number of sub-filters in this combined filter.
        
        :return: the number of sub-filters in this combined filter.
        :rtype: int
        """

    @property
    def filter(self) -> TableFilter[typing.Any]:
        ...

    @property
    def filterCount(self) -> jpype.JInt:
        ...


class RowObjectFilterModel(RowObjectTableModel[ROW_OBJECT], typing.Generic[ROW_OBJECT]):

    class_: typing.ClassVar[java.lang.Class]
    SUB_FILTERING_DISABLED_PROPERTY: typing.Final = "tables.subfilter.disabled"
    """
    This property allows for the disabling of 'sub-filtering'.  When enabled, which is the
    default, data from current filters will be reused when additional filter criteria is
    added to that current filter.  For example,
         
        
        Given a table has a 'contains' filter with a text value of 'bob',
         
        
        then, if the users types an 'o' into the filter field, producing a value of 'bobo',
         
        
        then the data that matched 'bob' will be used as the data to filter for the new 'bobo'
        text.
         
    
    
     
    The downside of this is that we cache data for every completed filter.  So, in a
    degenerate case, with a large dataset, with many incremental filtering steps, where each
    did not significantly reduce the previous set of data, the table could then consume
    a large amount of memory, roughly equal to ``allData.size() * numberOfFilterSteps``
    
     
    Most tables do not have enough data for this to have a significant impact.
    """


    def getModelIndex(self, t: ROW_OBJECT) -> int:
        """
        Returns the model index of the given item.  When filtered, this is the index is the larger,
        set of data; when unfiltered, this index is the same as that returned by
        :meth:`getModelIndex(Object) <.getModelIndex>`.
         
         
        This operation will be O(n) unless the implementation is sorted, in which case the 
        operation is O(log n), as it uses a binary search.
        
        :param ROW_OBJECT t: the item
        :return: the model index
        :rtype: int
        """

    def getModelRow(self, viewRow: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getTableFilter(self) -> TableFilter[ROW_OBJECT]:
        ...

    def getUnfilteredData(self) -> java.util.List[ROW_OBJECT]:
        ...

    def getUnfilteredRowCount(self) -> int:
        ...

    def getViewIndex(self, t: ROW_OBJECT) -> int:
        """
        Returns the view index of the given item.  When filtered, this is the index is the smaller,
        visible set of data; when unfiltered, this index is the same as that returned by
        :meth:`getModelIndex(Object) <.getModelIndex>`.
         
         
        This operation will be O(n) unless the implementation is sorted, in which case the 
        operation is O(log n), as it uses a binary search.
        
        :param ROW_OBJECT t: the item
        :return: the view index
        :rtype: int
        """

    def getViewRow(self, modelRow: typing.Union[jpype.JInt, int]) -> int:
        ...

    def isFiltered(self) -> bool:
        ...

    def setTableFilter(self, filter: TableFilter[ROW_OBJECT]):
        ...

    @property
    def filtered(self) -> jpype.JBoolean:
        ...

    @property
    def modelIndex(self) -> jpype.JInt:
        ...

    @property
    def viewRow(self) -> jpype.JInt:
        ...

    @property
    def unfilteredRowCount(self) -> jpype.JInt:
        ...

    @property
    def viewIndex(self) -> jpype.JInt:
        ...

    @property
    def modelRow(self) -> jpype.JInt:
        ...

    @property
    def unfilteredData(self) -> java.util.List[ROW_OBJECT]:
        ...

    @property
    def tableFilter(self) -> TableFilter[ROW_OBJECT]:
        ...

    @tableFilter.setter
    def tableFilter(self, value: TableFilter[ROW_OBJECT]):
        ...


class GDynamicColumnTableModel(AbstractSortedTableModel[ROW_TYPE], javax.swing.event.ChangeListener, VariableColumnTableModel, DynamicColumnTableModel[ROW_TYPE], typing.Generic[ROW_TYPE, DATA_SOURCE]):
    """
    An abstract table model for showing DynamicTableColumns where each row is based on an object of
    type ROW_TYPE. The client is responsible for implementing :meth:`createTableColumnDescriptor() <.createTableColumnDescriptor>`.
    This method specifies which default columns the table should have and whether they should be
    visible or hidden. Hidden columns can be made visible through the UI.
     
    
    This model will also discover other system columns that understand how to render
    ``ROW_TYPE`` data directly. Also, if you create a :obj:`mapper <TableRowMapper>`(s) for
    your row type, then this model will load columns for each type for which a mapper was created,
    all as optional, hidden columns.
     
    
    The various attributes of the columns of this model (visibility, position, size, etc) are saved
    to disk as tool preferences when the user exits the tool.
     
    
    Implementation Note: this model loads all columns, specific and discovered, as being visible.
    Then, during initialization, the :obj:`TableColumnModelState` class will either hide all
    non-default columns, or reload the column state if any previous saved state is found.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        ...

    def getColumnIndex(self, columnClass: java.lang.Class[typing.Any]) -> int:
        """
        Returns the column index of the given column class
        
        :param java.lang.Class[typing.Any] columnClass: the class for the type of DynamicTableColumn you want to find.
        :return: the column index for the specified DynamicTableColumn. -1 if not found.
        :rtype: int
        """

    def getDataSource(self) -> DATA_SOURCE:
        """
        Returns the table's context for the data.
        
        :return: the table's context for the data.
        :rtype: DATA_SOURCE
        """

    def getHeaderRenderer(self, index: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableCellRenderer:
        """
        Gets the special header cell renderer for the specified table field column. A null value
        indicates that this column uses a default header renderer.
        
        :param jpype.JInt or int index: the model column index
        :return: a table cell renderer for this field's header. Otherwise, null if a default renderer
                should be used.
        :rtype: javax.swing.table.TableCellRenderer
        """

    def getMaxLines(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the maximum number of text display lines needed for any given cell within the specified
        column.
        
        :param jpype.JInt or int index: column field index
        :return: maximum number of lines needed for specified column
        :rtype: int
        """

    def getRenderer(self, index: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableCellRenderer:
        """
        Gets the special table cell renderer for the specified table field column. A null value
        indicates that this field uses a default cell renderer.
        
        :param jpype.JInt or int index: the model column index
        :return: a table cell renderer for this field. Otherwise, null if a default renderer should be
                used.
        :rtype: javax.swing.table.TableCellRenderer
        """

    def isDefaultColumn(self, modelIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the column indicated by the index in the model is a default column (meaning
        that it was specified by the model and not discovered).
        
        :param jpype.JInt or int modelIndex: the index of the column in the model.
        :return: true if the column is a default.
        :rtype: bool
        """

    def stateChanged(self, e: javax.swing.event.ChangeEvent):
        """
        Callback when column settings have changed
        """

    @property
    def renderer(self) -> javax.swing.table.TableCellRenderer:
        ...

    @property
    def defaultColumn(self) -> jpype.JBoolean:
        ...

    @property
    def maxLines(self) -> jpype.JInt:
        ...

    @property
    def columnIndex(self) -> jpype.JInt:
        ...

    @property
    def dataSource(self) -> DATA_SOURCE:
        ...

    @property
    def headerRenderer(self) -> javax.swing.table.TableCellRenderer:
        ...


class GTableHeader(javax.swing.table.JTableHeader):
    """
    A special header for GhidraTables to handle things like tooltips and hover information.
    """

    class_: typing.ClassVar[java.lang.Class]
    HELP_ICON_HEIGHT: typing.Final = 8

    def getDraggedColumn(self) -> javax.swing.table.TableColumn:
        """
        Overridden to fix a 'bug' in Java whereby it tries to render columns that we have just
        removed when editing the visible columns.
        
        :return: the column being dragged by the user
        :rtype: javax.swing.table.TableColumn
        
        .. seealso::
        
            | :obj:`JTableHeader.getDraggedColumn()`
        """

    @property
    def draggedColumn(self) -> javax.swing.table.TableColumn:
        ...


class VariableColumnTableModel(javax.swing.table.TableModel):
    """
    An interface for marking table models whose supported columns are discovered at runtime
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def from_(m: javax.swing.table.TableModel) -> VariableColumnTableModel:
        """
        Returns a :obj:`VariableColumnTableModel` if the given model is an instance of this
        type or is wraps another table model that is an instance of this type.  If the given 
        model is not such an instance, then null is returned.
        
        :return: the variable column model
        :rtype: VariableColumnTableModel
        """

    def getColumnDescription(self, column: typing.Union[jpype.JInt, int]) -> str:
        ...

    def getColumnDisplayName(self, column: typing.Union[jpype.JInt, int]) -> str:
        ...

    def getDefaultColumnCount(self) -> int:
        """
        Gets the count of the default columns for this model.  This model may have non-default
        columns added.  This method will return the count of columns that have been setup 
        specifically by the table model.  This method can be used to iterate of the first 
        ``n`` columns of this model in order to get information for the default columns by
        calling methods like :meth:`getColumnName(int) <.getColumnName>`.
        
        :return: Gets the count of the default columns for this model.
        :rtype: int
        """

    def getUniqueIdentifier(self, column: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns a value that is unique for a given table column.  This is different than getting
        the display name, which may be shared by different columns.
        
        :param jpype.JInt or int column: the index (in the model space) of the column for which to get the identifier
        """

    def isDefaultColumn(self, modelIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the column denoted by the given model index is default (specified 
        initially by the table model).
        
        :param jpype.JInt or int modelIndex: The index in the column in the column model.
        :return: true if the column denoted by the given model index is default.
        :rtype: bool
        """

    def isVisibleByDefault(self, modelIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the column denoted by the given model index is specified by the table 
        model as being visible when the table is loaded for the first time.
        
        :param jpype.JInt or int modelIndex: The index in the column in the column model.
        :return: true if the column denoted by the given model index is visible default.
        :rtype: bool
        """

    @property
    def defaultColumn(self) -> jpype.JBoolean:
        ...

    @property
    def columnDisplayName(self) -> java.lang.String:
        ...

    @property
    def visibleByDefault(self) -> jpype.JBoolean:
        ...

    @property
    def defaultColumnCount(self) -> jpype.JInt:
        ...

    @property
    def columnDescription(self) -> java.lang.String:
        ...

    @property
    def uniqueIdentifier(self) -> java.lang.String:
        ...


class AbstractGTableModel(javax.swing.table.AbstractTableModel, RowObjectTableModel[T], SelectionStorage[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]
    WIDTH_UNDEFINED: typing.Final = -1

    def __init__(self):
        ...

    def dispose(self):
        """
        Call this when the model will no longer be used
        """

    def getPreferredColumnWidth(self, columnIndex: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getValueAt(self, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        The default implementation of :meth:`TableModel.getValueAt(int, int) <TableModel.getValueAt>` that calls the
        abstract :meth:`getColumnValueForRow(Object, int) <.getColumnValueForRow>`.
        """

    def isDisposed(self) -> bool:
        """
        Returns true if :meth:`dispose() <.dispose>` has been called
        
        :return: true if :meth:`dispose() <.dispose>` has been called
        :rtype: bool
        """

    def refresh(self):
        """
        Invoke this method when the underlying data has changed, but a reload is not required.
        """

    @property
    def preferredColumnWidth(self) -> jpype.JInt:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...


class GTableFilterPanel(javax.swing.JPanel, typing.Generic[ROW_OBJECT]):
    """
    This class is a panel that provides a label and text field that allows users to input text that
    filters the contents of the table.
     
    
    This class also handles restoring selection for the client when the table has been filtered.
    See `below <restore_selection_>`_ for a caveat.
     
    
    
    Filter Reminder
    
    The filter text will flash as the table (by default) gains focus.  This is done to remind the
    user that the data has been filtered.  To change the component that triggers the flashing use
    :meth:`setFocusComponent(Component) <.setFocusComponent>`, where the ``Component`` parameter is the
    component that will trigger focus flashing when it gains focus.  To disable focus flashing,
    pass in null to :meth:`setFocusComponent(Component) <.setFocusComponent>`.
     
    
    
    Filtering
    
    The filtering behavior is controlled by the filter button displayed to the right of this
    panel's text field.
     
    
    
    **Important Usage Notes**
     
    * You must translate row values retrieved from the table using
        this panel.
    
    Since this class wraps the given table with a new model, you must use this class to
    translate row number values.  For example, when getting the selected row, the normal Java
    code snippet below will give the incorrect value:
    
            JTable table = ...
            int selectedRowNumber = table.getSelectedRow();
         
    Instead, you must translate the returned value from above, as in the following snippet:
    
            JTable table = ...
             
            int selectedRowNumber = table.getSelectedRow();
            int modelRowNumber = tableFilterPanel.getModelRow( selectedRowNumber );  // see :meth:`getModelRow(int) <.getModelRow>`
         
    * This class may set a new model on the given table, which can affect how tables are sized.
    * If :meth:`JTable.getAutoCreateColumnsFromModel() <JTable.getAutoCreateColumnsFromModel>` returns true, then the columns will
    be recreated and resized when this class is constructed.
    * The :obj:`TableFilter` used by this class will be passed the empty string ("") when
    :meth:`TableFilter.acceptsRow(Object) <TableFilter.acceptsRow>` is called.
    * You cannot rely on :meth:`JTable.getRowCount() <JTable.getRowCount>` to access all of the table data,
        since the data may be filtered. To get a row count that is always all of the model's \
    data, call:meth:`getUnfilteredRowCount() <.getUnfilteredRowCount>`.
    """

    @typing.type_check_only
    class SortedTableModelWrapper(TableModelWrapper[ROW_OBJECT], SortedTableModel):
        """
        Created so that GhidraTable will still 'play nice' with our model wrapper pattern.  The
        wrapped model must be an instance of SortedTableModel for various things to work, such as
        keystroke lookup and column sorting.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TranslatingTableModelListener(javax.swing.event.TableModelListener):
        """
        A listener to translate TableModelEvents from the **wrapped** model's indices to that
        of the view, which may be filtered.  This listener will make sure the indices are
        correct for the view and then broadcast the event to any listeners that have been added
        (including the Table itself).
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UpdateTableModelListener(javax.swing.event.TableModelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GTableFilterListener(docking.widgets.filter.FilterListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FILTER_TEXTFIELD_NAME: typing.Final = "filter.panel.textfield"

    @typing.overload
    def __init__(self, table: javax.swing.JTable, tableModel: RowObjectTableModel[ROW_OBJECT]):
        """
        Creates a table filter panel that filters the contents of the given table.
        
        :param javax.swing.JTable table: The table whose contents will be filtered.
        :param RowObjectTableModel[ROW_OBJECT] tableModel: The table model used by the table--passed in by the type that we require
        """

    @typing.overload
    def __init__(self, table: javax.swing.JTable, tableModel: RowObjectTableModel[ROW_OBJECT], filterLabel: typing.Union[java.lang.String, str]):
        ...

    def activate(self):
        """
        Activates this filter by showing it, if not visible, and then requesting focus in the filter
        text field.
        """

    def addEnterListener(self, callback: utility.function.Callback):
        """
        Adds a listener to this widget that is called when the user presses enter in the
        filtering area.
        
         
        Note: this listener cannot be anonymous, as the underlying storage mechanism may be
        using a weak data structure.  This means that you will need to store the listener in
        a field inside of your class.
        
        :param utility.function.Callback callback: the listener
        """

    def addFilterChagnedListener(self, l: docking.widgets.filter.FilterListener):
        """
        Adds a listener that gets notified when the filter is changed
        
         
        Note: this listener cannot be anonymous, as the underlying storage mechanism may be
        using a weak data structure.  This means that you will need to store the listener in
        a field inside of your class.
        
        :param docking.widgets.filter.FilterListener l: the listener
        """

    def createUniqueFilterPreferenceKey(self, jTable: javax.swing.JTable) -> str:
        """
        Generates a key used to store user filter configuration state.  You can override this
        method to generate unique keys yourself.  You are required to override this method if
        you create multiple versions of a filter panel from the same place in your code, as
        multiple instances created in the same place will cause them all to share the same key and
        thus to have the same filter settings when they are created initially.
         
        
        As an example, consider a plugin that creates ``n`` providers.  If each provider uses
        a filter panel, then each provider will share the same filter settings when that provider
        is created.  If this is not what you want, then you need to override this method to
        generate a unique key for each provider.
        
        :param javax.swing.JTable jTable: the table
        :return: a key used to store user filter configuration state.
        :rtype: str
        """

    def dispose(self):
        ...

    def getColumnTableFilter(self) -> docking.widgets.table.columnfilter.ColumnBasedTableFilter[ROW_OBJECT]:
        """
        Returns the ColumnTableFilter that has been set on this GTableFilterPanel or null if there
        is none.
        
        :return: the ColumnTableFilter that has been set.
        :rtype: docking.widgets.table.columnfilter.ColumnBasedTableFilter[ROW_OBJECT]
        """

    def getFilterOptions(self) -> docking.widgets.filter.FilterOptions:
        """
        Returns the filter options used by the filter factory of this class.
        
        :return: the filter options used by the filter factory of this class.
        :rtype: docking.widgets.filter.FilterOptions
        """

    def getFilterText(self) -> str:
        """
        Gets the contents of the filter's text field.
        
        :return: The filter text field text.
        :rtype: str
        """

    def getModelRow(self, viewRow: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns a row number for this panel's underlying table model that is tied to the given
        row number that represents a row in a table's display.  For example, if a user clicks a
        table row in a filtered table, then this method can be used to return the table's
        underlying TableModel row index for that row. `Click here <translation_>`_ for more
        information.
         
        
        **Update**: The simpler way of getting the selected object is to call the newly
        added :meth:`getSelectedItem() <.getSelectedItem>` method(s), which saves the client from having to get the
        index and then lookup the data.  Further, it handles differences in filtering across
        different model implementations.
         
        
        This method is used as a means for models to translate user actions on a table to the
        underlying data model, since table models maintain a complete list of data, some of which
        may not be displayed, due to user filtering.
         
        
        This is the companion method to :meth:`getViewRow(int) <.getViewRow>`
        
        :param jpype.JInt or int viewRow: The table's row, as seen in the display.
        :return: the corresponding model row, based upon the table's row.
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getSelectedItem()`
        
            | :obj:`.getSelectedItems()`
        """

    def getPreferenceKey(self) -> str:
        """
        Return a unique key that can be used to store preferences for this table.
        
        :return: a unique key that can be used to store preferences for this table.
        :rtype: str
        """

    def getRowCount(self) -> int:
        ...

    def getRowObject(self, viewRow: typing.Union[jpype.JInt, int]) -> ROW_OBJECT:
        """
        Returns the row object for the given view row index.
        
        :param jpype.JInt or int viewRow: the desired row in terms of the UI (e.g., the table's row index)
        :return: the row object matching the given index
        :rtype: ROW_OBJECT
        """

    def getSelectedItem(self) -> ROW_OBJECT:
        """
        Returns the currently selected row object or null if there is no table selection.
        
        :return: the currently selected row object or null if there is no table selection.
        :rtype: ROW_OBJECT
        """

    def getSelectedItems(self) -> java.util.List[ROW_OBJECT]:
        """
        Returns the currently selected row objects or an empty list if there is no selection.
        
        :return: the currently selected row objects or an empty list if there is no selection.
        :rtype: java.util.List[ROW_OBJECT]
        """

    def getTableFilterModel(self) -> RowObjectFilterModel[ROW_OBJECT]:
        ...

    def getUnfilteredRowCount(self) -> int:
        ...

    def getViewRow(self, modelRow: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns a row number in the table (the view) for the given table model row number (the
        model).  The given value is the **unfiltered** row value and the returned value is the
        **filtered** value.
         
        
        This is the companion method to :meth:`getModelRow(int) <.getModelRow>`
        
        :param jpype.JInt or int modelRow: the row number in the unfiltered model.
        :return: the row in the table for the given model row.
        :rtype: int
        """

    def isFiltered(self) -> bool:
        ...

    def isInView(self, o: ROW_OBJECT) -> bool:
        """
        Returns true if the given row object is currently in the view of the table; false implies
        the object has been filtered out of view.
        
        :param ROW_OBJECT o: the row object
        :return: true if in the view
        :rtype: bool
        """

    def requestFocus(self):
        """
        Overridden to focus the text field if requestFocus() is called on this panel
        """

    def scrollToSelectedRow(self):
        """
        Scrolls the view to the currently selected item.
        """

    def setAccessibleNamePrefix(self, namePrefix: typing.Union[java.lang.String, str]):
        """
        Sets an accessible name on the filter component. This prefix will be used to assign
        meaningful accessible names to the filter text field and the filter options button such
        that screen readers will properly describe them.
         
        
        This prefix should be the base name that describes the type of items in the table.  For
        example if the table contains fruits, then "Fruits" would be an appropriate prefix name.
        This method will then append the necessary information to name the text field and the button.
        
        :param java.lang.String or str namePrefix: the accessible name prefix to assign to the filter component.
        """

    def setColumnTableFilter(self, newFilter: docking.widgets.table.columnfilter.ColumnBasedTableFilter[ROW_OBJECT]):
        """
        Sets a ColumnTableFilter on this panel.
        
        :param docking.widgets.table.columnfilter.ColumnBasedTableFilter[ROW_OBJECT] newFilter: the ColumnTableFilter to use for filtering this table.
        """

    def setFilterOptions(self, filterOptions: docking.widgets.filter.FilterOptions):
        """
        Sets the filter options used by the filter factory. The options are items like "starts with",
        "contains", "regex", etc.
        
        :param docking.widgets.filter.FilterOptions filterOptions: the filter options to be used by the filter factory.
        """

    def setFilterRowTransformer(self, transformer: RowFilterTransformer[ROW_OBJECT]):
        """
        Sets a custom RowFilterTransformer.  The default row transformer will gather strings
        for each column in the table and use those strings for filtering.  This method allows
        the user to have complete control on generating the strings used to filter a table row;
        for example, to only filter on some columns but not others.
        
        :param RowFilterTransformer[ROW_OBJECT] transformer: the custom row to string transformer used to generate strings from a
        row to be used for filtering.
        """

    def setFilterText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the contents of the filter's text field to the given text.
        
        :param java.lang.String or str text: The text to set.
        """

    def setFocusComponent(self, component: java.awt.Component):
        """
        Setting this component will trigger the filter field to flash when the component gains focus.
        If you do not want the filter field to flash as focus returns to the client,
        then pass in null.
        
        :param java.awt.Component component: The component that will trigger the filter field to flash when it gains
                focus.
        """

    def setSecondaryFilter(self, tableFilter: TableFilter[ROW_OBJECT]):
        """
        Sets a secondary filter that users can use to filter table rows by other criteria other than
        the text typed in at the bottom of a table.  This filter is an additional filter that will
        be applied with the typed text filter.
        
        :param TableFilter[ROW_OBJECT] tableFilter: the additional filter to use for the table.
        """

    def setSelectedItem(self, t: ROW_OBJECT):
        """
        Select the given row object.  No selection will be made if the object is filtered out of
        view.   Passing ``null`` will clear the selection.
        
        :param ROW_OBJECT t: the row object to select
        """

    def setSelectedItems(self, items: java.util.List[ROW_OBJECT]):
        """
        Select the given row objects.  No selection will be made if the objects are filtered out of
        view.  Passing a ``null`` list or an empty list will clear the selection.
        
        :param java.util.List[ROW_OBJECT] items: the row objects to select
        """

    def setToolTipText(self, text: typing.Union[java.lang.String, str]):
        """
        Allows the caller to set tooltip text on the filter's search label.  This can be used
        to provide an indication as to exactly how the filter text field will filter the table.
        
        :param java.lang.String or str text: The tooltip text.
        """

    def toggleVisibility(self):
        """
        Changes the visibility of this filter panel, make it not visible it if showing, showing it if
        not visible.
        """

    @property
    def selectedItem(self) -> ROW_OBJECT:
        ...

    @selectedItem.setter
    def selectedItem(self, value: ROW_OBJECT):
        ...

    @property
    def viewRow(self) -> jpype.JInt:
        ...

    @property
    def unfilteredRowCount(self) -> jpype.JInt:
        ...

    @property
    def inView(self) -> jpype.JBoolean:
        ...

    @property
    def modelRow(self) -> jpype.JInt:
        ...

    @property
    def filterText(self) -> java.lang.String:
        ...

    @filterText.setter
    def filterText(self, value: java.lang.String):
        ...

    @property
    def filtered(self) -> jpype.JBoolean:
        ...

    @property
    def preferenceKey(self) -> java.lang.String:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def tableFilterModel(self) -> RowObjectFilterModel[ROW_OBJECT]:
        ...

    @property
    def selectedItems(self) -> java.util.List[ROW_OBJECT]:
        ...

    @selectedItems.setter
    def selectedItems(self, value: java.util.List[ROW_OBJECT]):
        ...

    @property
    def filterOptions(self) -> docking.widgets.filter.FilterOptions:
        ...

    @filterOptions.setter
    def filterOptions(self, value: docking.widgets.filter.FilterOptions):
        ...

    @property
    def rowObject(self) -> ROW_OBJECT:
        ...

    @property
    def columnTableFilter(self) -> docking.widgets.table.columnfilter.ColumnBasedTableFilter[ROW_OBJECT]:
        ...

    @columnTableFilter.setter
    def columnTableFilter(self, value: docking.widgets.table.columnfilter.ColumnBasedTableFilter[ROW_OBJECT]):
        ...



__all__ = ["FocusableEditor", "DiscoverableTableUtils", "DynamicTableColumnExtensionPoint", "TableUtils", "GBooleanCellRenderer", "AutoscrollAdapter", "GTableCellRenderingData", "TableComparators", "TableSortStateEditor", "TableModelWrapper", "GTableCellRenderer", "GTableToCSV", "AnyObjectTableModel", "WrappingTableModel", "ChooseColumnsDialog", "TableTextFilter", "TableColumnDescriptor", "GFilterTable", "TableTextFilterFactory", "ColumnSortState", "DynamicTableColumn", "SelectColumnsDialog", "DynamicTableModel", "GTableTextCellEditor", "SortedTableModel", "DefaultTableCellRendererWrapper", "SortListener", "GTableMouseListener", "RowObject", "TableSortingContext", "TableSortState", "ObjectSelectedListener", "TableItemPickedListener", "AbstractSortedTableModel", "RowObjectSelectionManager", "DefaultRowFilterTransformer", "GTableColumnModel", "FilterTypeConverter", "SelectionManager", "GTableWidget", "TableColumnModelState", "TableRowMapper", "MappedTableColumn", "ConfigurableColumnTableModel", "SelectionStorage", "DynamicColumnTableModel", "AddRemoveListItem", "RowFilterTransformer", "DefaultTableTextFilterFactory", "RowObjectTableModel", "GTable", "TableFilter", "AbstractDynamicTableColumnStub", "InvertedTableFilter", "GTableAutoLookup", "DisplayStringProvider", "SelectionManagerListener", "AbstractDynamicTableColumn", "GTableHeaderRenderer", "MultiTextFilterTableFilter", "CombinedTableFilter", "RowObjectFilterModel", "GDynamicColumnTableModel", "GTableHeader", "VariableColumnTableModel", "AbstractGTableModel", "GTableFilterPanel"]
