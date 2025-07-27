from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import docking.widgets.table.threaded
import ghidra.app.nav
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import utility.function


COLUMN_TYPE = typing.TypeVar("COLUMN_TYPE")
T = typing.TypeVar("T")


class TableChooserExecutor(java.lang.Object):
    """
    The interface clients must implement to use the :obj:`TableChooserDialog`.  This class is the
    callback that is used to process items from the dialog's table as users select one or more
    rows in the table and then press the table's "apply" button.
    """

    class_: typing.ClassVar[java.lang.Class]

    def execute(self, rowObject: AddressableRowObject) -> bool:
        """
        Applies this executors action to the given rowObject.  Return true if the given object
        should be removed from the table.
        
         
        This method call will be wrapped in a transaction so the client does not have to do so.
        Multiple selected rows will all be processed in a single transaction.
        
        :param AddressableRowObject rowObject: the AddressRowObject to be executed upon
        :return: true if the rowObject should be removed from the table, false otherwise
        :rtype: bool
        """

    def executeInBulk(self, rowObjects: java.util.List[AddressableRowObject], deleted: java.util.List[AddressableRowObject], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        A callback that clients can choose to use instead of :meth:`execute(AddressableRowObject) <.execute>`.
         
        
        To use this method, simply override it to perform work on each item passed in.  Due to
        supporting backward compatibility, clients still have to implement
        :meth:`execute(AddressableRowObject) <.execute>`.  When using
        :meth:`executeInBulk(List, List, TaskMonitor) <.executeInBulk>`, simply implement
        :meth:`execute(AddressableRowObject) <.execute>` as a do-nothing method.
         
        
        You are responsible for checking the cancelled state of the task monitor by calling
        :meth:`TaskMonitor.isCancelled() <TaskMonitor.isCancelled>`.  This allows long-running operations to be cancelled.  You
        should also call :meth:`TaskMonitor.incrementProgress(long) <TaskMonitor.incrementProgress>` as you process each item in
        order to show progress in the UI.
         
        
        Note: the :meth:`execute(AddressableRowObject) <.execute>` method is only called with items that are
        still in the dialog's table model.  Some clients may programmatically manipulate the table
        model by removing row objects via the dialog's add/remove methods. The
        :meth:`execute(AddressableRowObject) <.execute>` method is only called for items that still exist in
        the model.  Contrastingly, this version of execute offers no such protection.  Thus, if you
        manipulate the table model yourself, you also need to ensure that any items you process in
        this method are still in the dialog.  To see if the item is still in the dialog, call
        :meth:`TableChooserDialog.contains(AddressableRowObject) <TableChooserDialog.contains>`.
        
        :param java.util.List[AddressableRowObject] rowObjects: the objects to be processed
        :param java.util.List[AddressableRowObject] deleted: place any items to be removed from the table into this list
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if you wish to execute items in bulk; always return true from this method if
                    you override it
        :rtype: bool
        """

    def getButtonName(self) -> str:
        """
        A short name suitable for display in the "apply" button that indicates what the "apply"
        action does.
        
        :return: A short name suitable for display in the "apply" button that indicates what the "apply"
        action does.
        :rtype: str
        """

    @property
    def buttonName(self) -> java.lang.String:
        ...


class ColumnDisplay(java.util.Comparator[AddressableRowObject], typing.Generic[COLUMN_TYPE]):
    """
    An interface that allows users to add columns to the :obj:`TableChooserDialog`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getColumnClass(self) -> java.lang.Class[COLUMN_TYPE]:
        ...

    def getColumnName(self) -> str:
        ...

    def getColumnValue(self, rowObject: AddressableRowObject) -> COLUMN_TYPE:
        ...

    def getRenderer(self) -> ghidra.util.table.column.GColumnRenderer[COLUMN_TYPE]:
        """
        Override this method to use a custom renderer.
         
        
        Use this method to perform any desired custom cell rendering for this column.  This method
        may be used to enable html rendering with correct table filtering.
        See :obj:`GColumnRenderer` and
        :meth:`GColumnRenderer.getFilterString(Object, ghidra.docking.settings.Settings) <GColumnRenderer.getFilterString>`.
        
        :return: the renderer
        :rtype: ghidra.util.table.column.GColumnRenderer[COLUMN_TYPE]
        """

    @property
    def renderer(self) -> ghidra.util.table.column.GColumnRenderer[COLUMN_TYPE]:
        ...

    @property
    def columnClass(self) -> java.lang.Class[COLUMN_TYPE]:
        ...

    @property
    def columnValue(self) -> COLUMN_TYPE:
        ...

    @property
    def columnName(self) -> java.lang.String:
        ...


class AddressableRowObjectToFunctionTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[AddressableRowObject, ghidra.program.model.listing.Function]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TableChooserDialog(docking.DialogComponentProvider, ghidra.app.nav.NavigatableRemovalListener):
    """
    Dialog to show a table of items.  If the dialog is constructed with a non-null
    :obj:`TableChooserExecutor`, then a button will be placed in the dialog, allowing the user
    to perform the action defined by the executor.
    
     
    Each button press will use the selected items as the items to be processed.  While the
    items are scheduled to be processed, they will still be in the table, painted light gray.
    Attempting to reschedule any of these pending items will have no effect.   Each time the
    button is pressed, a new :obj:`SwingWorker` is created, which will put the processing into
    a background thread.   Further, by using multiple workers, the work will be performed in
    parallel.
    """

    @typing.type_check_only
    class TableChooserDialogPanel(ghidra.util.table.GhidraThreadedTablePanel[AddressableRowObject]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: docking.widgets.table.threaded.ThreadedTableModel[AddressableRowObject, typing.Any]):
            ...


    @typing.type_check_only
    class TableChooserDialogGhidraTable(ghidra.util.table.GhidraTable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tm: docking.widgets.table.threaded.ThreadedTableModel[AddressableRowObject, typing.Any]):
            ...


    @typing.type_check_only
    class WrappingCellRenderer(ghidra.util.table.GhidraTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExecutorSwingWorker(javax.swing.SwingWorker[java.lang.Object, java.lang.Object]):
        """
        Runs our work off the Swing thread, so that the GUI updates as the task is being executed
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, executor: TableChooserExecutor, program: ghidra.program.model.listing.Program, title: typing.Union[java.lang.String, str], navigatable: ghidra.app.nav.Navigatable, isModal: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, executor: TableChooserExecutor, program: ghidra.program.model.listing.Program, title: typing.Union[java.lang.String, str], navigatable: ghidra.app.nav.Navigatable):
        ...

    def add(self, rowObject: AddressableRowObject):
        """
        Adds the given object to this dialog.  This method can be called from any thread.
        
        :param AddressableRowObject rowObject: the object to add
        """

    def addCustomColumn(self, columnDisplay: ColumnDisplay[typing.Any]):
        ...

    def clearSelection(self):
        ...

    def contains(self, rowObject: AddressableRowObject) -> bool:
        """
        Returns true if the given object is still in the dialog.  Clients can use this method to see
        if the user has already processed the given item.
        
        :param AddressableRowObject rowObject: the row object
        :return: true if the object is still in the dialog
        :rtype: bool
        """

    def getRowCount(self) -> int:
        ...

    def getSelectedRowObjects(self) -> java.util.List[AddressableRowObject]:
        ...

    def getSelectedRows(self) -> jpype.JArray[jpype.JInt]:
        ...

    def getTable(self) -> ghidra.util.table.GhidraTable:
        ...

    def isBusy(self) -> bool:
        ...

    def remove(self, rowObject: AddressableRowObject):
        """
        Removes the given object from this dialog.  Nothing will happen if the given item is not
        in this dialog.  This method can be called from any thread.
        
        :param AddressableRowObject rowObject: the object to remove
        """

    def selectRows(self, *rows: typing.Union[jpype.JInt, int]):
        ...

    def setClosedListener(self, callback: utility.function.Callback):
        """
        Sets the given listener that will get notified when this dialog is closed
        
        :param utility.function.Callback callback: the callback to notify
        """

    def setMessage(self, message: typing.Union[java.lang.String, str]):
        ...

    def setSortColumn(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the default sorted column for this dialog.
        
         
        This method should be called after all custom columns have been added via
        :meth:`addCustomColumn(ColumnDisplay) <.addCustomColumn>`.
        
        :param jpype.JInt or int index: the view's 0-based column index
        :raises IllegalArgumentException: if an invalid column is requested for sorting
        
        .. seealso::
        
            | :obj:`.setSortState(TableSortState)`
        """

    def setSortState(self, state: docking.widgets.table.TableSortState):
        """
        Sets the column sort state for this dialog.   The :obj:`TableSortState` allows for
        combinations of sorted columns in ascending or descending order.
        
         
        This method should be called after all custom columns have been added via
        :meth:`addCustomColumn(ColumnDisplay) <.addCustomColumn>`.
        
        :param docking.widgets.table.TableSortState state: the sort state
        :raises IllegalArgumentException: if an invalid column is requested for sorting
        
        .. seealso::
        
            | :obj:`.setSortColumn(int)`
        """

    def show(self):
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def selectedRowObjects(self) -> java.util.List[AddressableRowObject]:
        ...

    @property
    def selectedRows(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def table(self) -> ghidra.util.table.GhidraTable:
        ...


class AddressableRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[AddressableRowObject, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractColumnDisplay(ColumnDisplay[COLUMN_TYPE], typing.Generic[COLUMN_TYPE]):
    """
    A base implementation of :obj:`ColumnDisplay` that knows how to figure out the column 
    type dynamically.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressableRowObject(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class AbstractComparableColumnDisplay(AbstractColumnDisplay[COLUMN_TYPE], typing.Generic[COLUMN_TYPE]):
    """
    A version of :obj:`ColumnDisplay` to be used when the column value returned from
    :meth:`getColumnValue(AddressableRowObject) <.getColumnValue>` is :obj:`Comparable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class StringColumnDisplay(AbstractComparableColumnDisplay[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressableRowObjectToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[AddressableRowObject, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TableChooserTableModel(ghidra.util.table.AddressBasedTableModel[AddressableRowObject]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], serviceProvider: ghidra.framework.plugintool.ServiceProvider, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor):
        ...

    def addCustomColumn(self, columnDisplay: ColumnDisplay[T]):
        ...

    def containsObject(self, obj: AddressableRowObject) -> bool:
        ...


class ColumnDisplayDynamicTableColumnAdapter(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[AddressableRowObject, COLUMN_TYPE], java.util.Comparator[AddressableRowObject], typing.Generic[COLUMN_TYPE]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, display: ColumnDisplay[COLUMN_TYPE]):
        ...



__all__ = ["TableChooserExecutor", "ColumnDisplay", "AddressableRowObjectToFunctionTableRowMapper", "TableChooserDialog", "AddressableRowObjectToAddressTableRowMapper", "AbstractColumnDisplay", "AddressableRowObject", "AbstractComparableColumnDisplay", "StringColumnDisplay", "AddressableRowObjectToProgramLocationTableRowMapper", "TableChooserTableModel", "ColumnDisplayDynamicTableColumnAdapter"]
