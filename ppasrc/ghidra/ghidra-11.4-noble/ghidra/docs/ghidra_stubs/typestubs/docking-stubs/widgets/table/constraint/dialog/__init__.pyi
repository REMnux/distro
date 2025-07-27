from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.list
import docking.widgets.table
import docking.widgets.table.columnfilter
import docking.widgets.table.constraint
import docking.widgets.table.constrainteditor
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.table # type: ignore
import utility.function


R = typing.TypeVar("R")
T = typing.TypeVar("T")


class ColumnFilterDialog(docking.ReusableDialogComponentProvider, TableFilterDialogModelListener, typing.Generic[R]):
    """
    Dialog for creating and editing column table filters.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterManager: docking.widgets.table.columnfilter.ColumnFilterManager[R], table: javax.swing.JTable, tableModel: docking.widgets.table.RowObjectFilterModel[R]):
        """
        Constructor
        
        :param docking.widgets.table.columnfilter.ColumnFilterManager[R] filterManager: the filter manager
        :param javax.swing.JTable table: the table being filtered.
        :param docking.widgets.table.RowObjectFilterModel[R] tableModel: the table model.
        """

    def filterChanged(self, newFilter: docking.widgets.table.columnfilter.ColumnBasedTableFilter[R]):
        ...

    @staticmethod
    def hasFilterableColumns(table: javax.swing.JTable, model: docking.widgets.table.RowObjectFilterModel[R]) -> bool:
        ...

    def setCloseCallback(self, callback: utility.function.Callback):
        """
        The callback to call when the "Apply" or "Ok" button is pressed.
        
        :param utility.function.Callback callback: the callback to execute to apply the filter.
        """


class ColumnFilterDialogModel(java.lang.Object, typing.Generic[R]):
    """
    This class is for constructing and editing :obj:`ColumnBasedTableFilter`. It is used by the
    :obj:`ColumnFilterDialog` and exists primarily to make testing easier.
    """

    @typing.type_check_only
    class MyTableColumnModelListener(javax.swing.event.TableColumnModelListener):
        """
        A listener for changes to the column structure of the table being filtered.  The ColumnFilterModel
        must adjust for these changes as follows:
         
        1.  Table column removed - any filters for that column must be deleted. 
        2.  Table column added - the list of columns that the user can filter must be updated. 
        3.  Table column moved - the model must update its mappings of view indexes to model indexes
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: docking.widgets.table.RowObjectFilterModel[R], columnModel: javax.swing.table.TableColumnModel, currentColumnTableFilter: docking.widgets.table.columnfilter.ColumnBasedTableFilter[R]):
        """
        Constructs a new ColumnFilterModel
        
        :param docking.widgets.table.RowObjectFilterModel[R] model: the RowObjectFilterModel of the table being filtered.
        :param javax.swing.table.TableColumnModel columnModel: the TableColumnModel of the table being filtered.
        :param docking.widgets.table.columnfilter.ColumnBasedTableFilter[R] currentColumnTableFilter: the currently applied TableColumnFilter or null if there is
        no current TableColumnFilter applied.
        """

    def addListener(self, listener: TableFilterDialogModelListener):
        """
        Adds a listener to be notified for various changes that occur in this filter model.
        
        :param TableFilterDialogModelListener listener: the listener to add.
        """

    def clear(self):
        """
        Clears the model of all filters.
        """

    def createFilterRow(self, logicOperation: docking.widgets.table.columnfilter.LogicOperation) -> DialogFilterRow:
        """
        Creates a new filter row (a new major row in the dialog filter panel)
        
        :param docking.widgets.table.columnfilter.LogicOperation logicOperation: the logical operation for how this row interacts with preceding rows
        :return: the new filter row that represents a major row in the dialog filter panel
        :rtype: DialogFilterRow
        """

    def deleteFilterRow(self, filterRow: DialogFilterRow):
        """
        Deletes a filter row (a major row in the dialog filter panel)
        
        :param DialogFilterRow filterRow: the row to delete.
        """

    def dispose(self):
        """
        clean up.
        """

    @staticmethod
    @typing.overload
    def getAllColumnFilterData(model: docking.widgets.table.RowObjectFilterModel[R], columnModel: javax.swing.table.TableColumnModel) -> java.util.List[ColumnFilterData[typing.Any]]:
        ...

    @typing.overload
    def getAllColumnFilterData(self) -> java.util.List[ColumnFilterData[typing.Any]]:
        """
        Returns a list of the columnFilterData for all filterable columns in the table
        
        :return: a list of the columnFilterData for all filterable columns in the table
        :rtype: java.util.List[ColumnFilterData[typing.Any]]
        """

    def getFilterRows(self) -> java.util.List[DialogFilterRow]:
        """
        Returns a list of all filter rows in this model.
        
        :return: a list of all filter rows in this model.
        :rtype: java.util.List[DialogFilterRow]
        """

    def getTableColumnFilter(self) -> docking.widgets.table.columnfilter.ColumnBasedTableFilter[R]:
        """
        Builds a ColumnTableFilter from this model if the model is valid.
        
        :return: a new ColumnTableFilter based on the configuration of this model or null if the model
        is invalid.
        :rtype: docking.widgets.table.columnfilter.ColumnBasedTableFilter[R]
        """

    def hasUnappliedChanges(self) -> bool:
        """
        Returns true if this model has changes that make the filter different from the currently
        applied filter.
        
        :return: if there are unapplied user changes to the filter.
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        Return true if there are no conditions (valid or invalid) defined for this filter model.
        
        :return: true if there are no conditions (valid or invalid) defined for this filter model.
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        Checks if this model represents a valid filter. While editing, some elements of the filter
        may be incomplete or invalid and if so, then this method will return false.
        
        :return: true if the model represents a valid filter.
        :rtype: bool
        """

    def removeListener(self, listener: TableFilterDialogModelListener):
        """
        Removes the given listener.
        
        :param TableFilterDialogModelListener listener: the listener to remove.
        """

    def setCurrentlyAppliedFilter(self, tableColumnFilter: docking.widgets.table.columnfilter.ColumnBasedTableFilter[R]):
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def allColumnFilterData(self) -> java.util.List[ColumnFilterData[typing.Any]]:
        ...

    @property
    def tableColumnFilter(self) -> docking.widgets.table.columnfilter.ColumnBasedTableFilter[R]:
        ...

    @property
    def filterRows(self) -> java.util.List[DialogFilterRow]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ConstraintFilterPanel(javax.swing.JPanel):
    """
    Panel for display a single constraint entry within a column.
    """

    @typing.type_check_only
    class ConstraintComboBoxCellRenderer(docking.widgets.list.GComboBoxCellRenderer[docking.widgets.table.constraint.ColumnConstraint[typing.Any]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class DialogFilterRow(java.lang.Object):
    """
    This class represents a major "and-able" row in the dialog's filter panel.  It is associated with
    a single column at any given time.  It has a single :obj:`DialogFilterConditionSet`  which is
    typed on the ColumnType. If the column changes, it will create a new condition set for the new
    Column.
    
     
    The :obj:`DialogFilterRow` and the :obj:`DialogFilterConditionSet` classes work together to
    represent a row in the dialog's filter panel.  The row is untyped since the associated column can
    change.  The :obj:`DialogFilterConditionSet` is typed on the column's value type which allows
    it to take advantage of Java's templating for type safety.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dialogModel: ColumnFilterDialogModel[typing.Any], logicOperation: docking.widgets.table.columnfilter.LogicOperation):
        """
        Constructor with the first column selected
        
        :param ColumnFilterDialogModel[typing.Any] dialogModel: the model that created this filter row.
        :param docking.widgets.table.columnfilter.LogicOperation logicOperation: the logic operation for how this filter row is combined with previous
        rows.
        """

    @typing.overload
    def __init__(self, dialogModel: ColumnFilterDialogModel[typing.Any], columnFilter: docking.widgets.table.columnfilter.ColumnConstraintSet[typing.Any, T]):
        """
        Constructor when constructing the model from an exiting filter.
        
        :param ColumnFilterDialogModel[typing.Any] dialogModel: the model that created this class.
        :param docking.widgets.table.columnfilter.ColumnConstraintSet[typing.Any, T] columnFilter: A column filter from the existing filter.
        """

    def addFilterCondition(self) -> DialogFilterCondition[typing.Any]:
        """
        Adds a new DialogFilterCondition to this filter row.
        
        :return: the newly created condition.
        :rtype: DialogFilterCondition[typing.Any]
        """

    def getAllColumnData(self) -> java.util.List[ColumnFilterData[typing.Any]]:
        """
        Method for the dialog to use to get the columns for the comboBox
        
        :return: all the columns available to be filtered in the table.
        :rtype: java.util.List[ColumnFilterData[typing.Any]]
        """

    def getColumnFilterData(self) -> ColumnFilterData[typing.Any]:
        """
        Gets the current ColumnData for this filter row.
        
        :return: the current ColumnData for this filter row.
        :rtype: ColumnFilterData[typing.Any]
        """

    def getFilterConditions(self) -> java.util.List[DialogFilterCondition[typing.Any]]:
        """
        Returns a list of the "or-able" constraints configured for this column.
        
        :return: a list of the "or-able" constraints configured for this column.
        :rtype: java.util.List[DialogFilterCondition[typing.Any]]
        """

    def getLogicOperation(self) -> docking.widgets.table.columnfilter.LogicOperation:
        """
        Returns the :obj:`LogicOperation` that specifies how this DialogFilterRow relates to
        previous rows.
        
        :return: the LogicOperation for this row.
        :rtype: docking.widgets.table.columnfilter.LogicOperation
        """

    def hasValidFilterValue(self) -> bool:
        """
        Pass through for checking filter condition validity.
        
        :return: true if valid, false otherwise.
        :rtype: bool
        """

    def setColumnData(self, columnData: ColumnFilterData[typing.Any]):
        """
        Sets the column for this filter row.
        
        :param ColumnFilterData[typing.Any] columnData: the data for the column.
        """

    @property
    def filterConditions(self) -> java.util.List[DialogFilterCondition[typing.Any]]:
        ...

    @property
    def logicOperation(self) -> docking.widgets.table.columnfilter.LogicOperation:
        ...

    @property
    def columnFilterData(self) -> ColumnFilterData[typing.Any]:
        ...

    @property
    def allColumnData(self) -> java.util.List[ColumnFilterData[typing.Any]]:
        ...


class ColumnFilterArchiveDialog(docking.DialogComponentProvider, typing.Generic[R]):
    """
    Dialog for loading saved ColumnFilters.
    """

    class_: typing.ClassVar[java.lang.Class]


class FilterPanelLayout(java.awt.LayoutManager):
    """
    Specialized layout for the TableFilterDialog panels.  It is intended for a container with
    exactly three components.  The first two components are sized to the width specified and the
    last component gets its preferred width.  When laying out the components, the first two are
    always sized to the specified width and the 3rd component gets all remaining size;
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, componentWidth: typing.Union[jpype.JInt, int], hgap: typing.Union[jpype.JInt, int]):
        """
        Construct layout where first two components always have given width.
        
        :param jpype.JInt or int componentWidth: the width of each of the first two components.
        :param jpype.JInt or int hgap: the space between componennts.
        """


class ColumnFilterData(java.lang.Comparable[ColumnFilterData[T]], typing.Generic[T]):
    """
    This class provides all known :obj:`ColumnConstraint`s for a given table column.
     
     
    Class for maintaining information about a particular table's column for the purpose of 
    configuring filters based on that column's values.  Instances of this class are generated 
    by examining a table's column types and finding any :obj:`ColumnConstraint`s that support 
    that type. If column constraints are found, a :obj:`ColumnFilterData` is created for that column 
    which then allows filtering on that columns data via the column constraints mechanism (which
    is different than the traditional text filter).
    """

    @typing.type_check_only
    class ColumnRendererMapper(docking.widgets.table.constraint.ColumnTypeMapper[T, java.lang.String]):
        """
        This class allows us to turn client columns of type ``T`` to a String.  We use 
        the renderer provided at construction time to generate a filter string when 
        :meth:`convert(Object) <.convert>` is called.
         
         
        Implementation Note:  the type 'T' here is used to satisfy the external client's 
            expected list of constraints.  We will not be able to identify 'T' at runtime.  Rather,
            our parent's :meth:`getSourceType() <.getSourceType>` will simply be :obj:`Object`.   This is fine, as
            this particular class will not have :meth:`getSourceType() <.getSourceType>` called, due to how we 
            are using it.  (Normally, the source type is used to find compatible constraints; we
            are not using the discovery mechanism with this private class.)
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: docking.widgets.table.RowObjectFilterModel[typing.Any], columnModelIndex: typing.Union[jpype.JInt, int], columnViewIndex: typing.Union[jpype.JInt, int], columnClass: java.lang.Class[T]):
        """
        Constructs a new ColumnFilterData for a table column
        
        :param docking.widgets.table.RowObjectFilterModel[typing.Any] model: the table model
        :param jpype.JInt or int columnModelIndex: the model index of the column
        :param jpype.JInt or int columnViewIndex: the view index of the column
        :param java.lang.Class[T] columnClass: the class (type) of the column
        """

    def getColumnModelIndex(self) -> int:
        """
        Returns the model index for the column represented by this class.
        
        :return: the model index for the column represented by this class.
        :rtype: int
        """

    def getConstraint(self, constraintName: typing.Union[java.lang.String, str]) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        """
        Returns the ColumnConstraint with the given name
        
        :param java.lang.String or str constraintName: the name of the constraint to retrieve
        :return: the ColumnConstraint with the given name.
        :rtype: docking.widgets.table.constraint.ColumnConstraint[T]
        """

    def getConstraints(self) -> jpype.JArray[docking.widgets.table.constraint.ColumnConstraint[typing.Any]]:
        """
        Returns the list of applicable constraints for this column
        
        :return: the list of applicable constraints for this column
        :rtype: jpype.JArray[docking.widgets.table.constraint.ColumnConstraint[typing.Any]]
        """

    def getFirstConstraint(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        """
        Returns the first constraint in the list.
        
        :return: the constraint
        :rtype: docking.widgets.table.constraint.ColumnConstraint[T]
        """

    def getName(self) -> str:
        """
        Returns the name of the column represented by this ColumnFilterData
        
        :return: the name of the column represented by this ColumnFilterData
        :rtype: str
        """

    def getViewIndex(self) -> int:
        """
        Returns the view index of the column
        
        :return: the view index of the column.
        :rtype: int
        """

    def isFilterable(self) -> bool:
        """
        Returns true if the column represented by this data has applicable column filters.
        
        :return: true if the column represented by this data has applicable column filters.
        :rtype: bool
        """

    def replace(self, value: docking.widgets.table.constraint.ColumnConstraint[T]):
        """
        Replace the same named constraint with the given constraint.  This allows the
        column constraint to remember the last used value.
        
        :param docking.widgets.table.constraint.ColumnConstraint[T] value: the constraint to be used to replace the existing one with the same name.
        """

    def setViewIndex(self, viewIndex: typing.Union[jpype.JInt, int]):
        """
        Sets the viewIndex
        
         
        This needs to be updated whenever columns are added, deleted, or moved.
        
        :param jpype.JInt or int viewIndex: the new view index
        """

    @property
    def filterable(self) -> jpype.JBoolean:
        ...

    @property
    def columnModelIndex(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def viewIndex(self) -> jpype.JInt:
        ...

    @viewIndex.setter
    def viewIndex(self, value: jpype.JInt):
        ...

    @property
    def firstConstraint(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        ...

    @property
    def constraint(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        ...

    @property
    def constraints(self) -> jpype.JArray[docking.widgets.table.constraint.ColumnConstraint[typing.Any]]:
        ...


class DialogFilterCondition(java.lang.Object, typing.Generic[T]):
    """
    This class represents an "or'able" condition in the DialogFilterConditionSet
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, parentCondition: DialogFilterConditionSet[T]):
        """
        Constructor
        
        :param DialogFilterConditionSet[T] parentCondition: the parent condition that created this condition.
        """

    @typing.overload
    def __init__(self, parent: DialogFilterConditionSet[T], constraint: docking.widgets.table.constraint.ColumnConstraint[T]):
        """
        Constructor when building from an existing ColumnTableFilter
        
        :param DialogFilterConditionSet[T] parent: the parent condition that created this condition.
        :param docking.widgets.table.constraint.ColumnConstraint[T] constraint: the constraint from an existing ColumnTableFilter.
        """

    def delete(self):
        """
        Deletes this OrFilterCondition from its parent.  If it is the last one in the parent, the
        parent will then delete itself from its parent and so on.
        """

    def getColumnConstraints(self) -> jpype.JArray[docking.widgets.table.constraint.ColumnConstraint[typing.Any]]:
        """
        Returns a list of valid constraints for the column
        
         
        Used by the dialog to populate the constraint comboBox
        
        :return: a list of valid constraints for the column.
        :rtype: jpype.JArray[docking.widgets.table.constraint.ColumnConstraint[typing.Any]]
        """

    def getConstraint(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        """
        Return the constraint from the editor.
        
        :return: the constraint from the editor.
        :rtype: docking.widgets.table.constraint.ColumnConstraint[T]
        """

    def getDetailEditorComponent(self) -> java.awt.Component:
        """
        For future expansion, a larger component may be allowed that will be displayed on an entire
        line below the constraint name.
        
        :return: an editor component for use by the user to change the constraint value.
        :rtype: java.awt.Component
        """

    def getInlineEditorComponent(self) -> java.awt.Component:
        """
        Returns an editor component for use by the user to change the constraint value. This is the
        component that the dialog's filter panel will display inline with the constraint name.
        
        :return: an editor component for use by the user to change the constraint value.
        :rtype: java.awt.Component
        """

    def getSelectedConstraint(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        """
        Returns the current Constraint for this OrFilterCondition.
        
        :return: the current Constraint for this OrFilterCondition.
        :rtype: docking.widgets.table.constraint.ColumnConstraint[T]
        """

    def getSelectedConstraintName(self) -> str:
        """
        Returns the name of the current constraint for this OrFilterCondition.
        
        :return: the name of the current constraint for this OrFilterCondition.
        :rtype: str
        """

    def hasValidFilterValue(self) -> bool:
        """
        Returns true if the editor has a valid value.
        
        :return: true if the editor has a valid value.
        :rtype: bool
        """

    def setSelectedConstraint(self, constraintName: typing.Union[java.lang.String, str]):
        """
        Change the constraint to the constraint with the given name.
        
        :param java.lang.String or str constraintName: the name of the constraint to change to.
        """

    def setValue(self, valueString: typing.Union[java.lang.String, str], dataSource: java.lang.Object):
        """
        Sets the constraint value from a string.  Used for testing.
        
        :param java.lang.String or str valueString: the constraint value as a string that will be parsed.
        :param java.lang.Object dataSource: the table's DataSource object.
        """

    @property
    def columnConstraints(self) -> jpype.JArray[docking.widgets.table.constraint.ColumnConstraint[typing.Any]]:
        ...

    @property
    def detailEditorComponent(self) -> java.awt.Component:
        ...

    @property
    def selectedConstraint(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        ...

    @property
    def selectedConstraintName(self) -> java.lang.String:
        ...

    @property
    def constraint(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        ...

    @property
    def inlineEditorComponent(self) -> java.awt.Component:
        ...


class TableFilterDialogModelListener(java.lang.Object):
    """
    Listener interface for the ColumnFilterModel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def editorValueChanged(self, editor: docking.widgets.table.constrainteditor.ColumnConstraintEditor[typing.Any]):
        """
        Invoked when the user types into an editor component.
        
        :param docking.widgets.table.constrainteditor.ColumnConstraintEditor[typing.Any] editor: the editor whose component has changed.
        """

    def structureChanged(self):
        """
        Invoked when any change to the structure of the ColumnFilterModel occurs such as adding
        entries
        """


class DialogFilterConditionSet(java.lang.Object, typing.Generic[T]):
    """
    This class represents the set of "or-able" filter conditions for a single column.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ColumnFilterPanel(javax.swing.JPanel):
    """
    Panel for displaying a single column filter entry.  This consists of multiple ConstraintFilterPanels
    for each "OR" condition in this column filter entry.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ColumnFilterDialog", "ColumnFilterDialogModel", "ConstraintFilterPanel", "DialogFilterRow", "ColumnFilterArchiveDialog", "FilterPanelLayout", "ColumnFilterData", "DialogFilterCondition", "TableFilterDialogModelListener", "DialogFilterConditionSet", "ColumnFilterPanel"]
