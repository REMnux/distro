from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.menu
import docking.widgets.table
import docking.widgets.table.constraint
import ghidra.framework.options
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import utility.function


R = typing.TypeVar("R")
ROW_OBJECT = typing.TypeVar("ROW_OBJECT")
T = typing.TypeVar("T")


class ColumnFilterManager(java.lang.Object, typing.Generic[ROW_OBJECT]):
    """
    A class that manages column filters for a table.  This includes creating the UI elements that 
    allow users to build filters, as well as a means to save and restore filters.
    """

    @typing.type_check_only
    class ColumnFilterActionState(docking.menu.ActionState[ColumnBasedTableFilter[ROW_OBJECT]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ClearFilterActionState(ColumnFilterManager.ColumnFilterActionState):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class CreateFilterActionState(ColumnFilterManager.ColumnFilterActionState):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class EditFilterActionState(ColumnFilterManager.ColumnFilterActionState):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, filter: ColumnBasedTableFilter[ROW_OBJECT]):
            ...


    @typing.type_check_only
    class ApplyFilterActionState(ColumnFilterManager.ColumnFilterActionState):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, filter: ColumnBasedTableFilter[ROW_OBJECT]):
            ...


    @typing.type_check_only
    class ApplyLastUsedActionState(ColumnFilterManager.ColumnFilterActionState):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, filter: ColumnBasedTableFilter[ROW_OBJECT]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    FILTER_EXTENSION: typing.Final = ".FilterExtension"
    FILTER_TEXTFIELD_NAME: typing.Final = "filter.panel.textfield"

    def __init__(self, table: javax.swing.JTable, rowObjectFilterModel: docking.widgets.table.RowObjectFilterModel[ROW_OBJECT], preferenceKey: typing.Union[java.lang.String, str], filterChangedCallback: utility.function.Callback):
        ...

    def dispose(self):
        ...

    def getConfigureButton(self) -> javax.swing.JButton:
        ...

    def getCurrentFilter(self) -> ColumnBasedTableFilter[ROW_OBJECT]:
        ...

    def getPreferenceKey(self) -> str:
        ...

    def setFilter(self, newFilter: ColumnBasedTableFilter[ROW_OBJECT]):
        ...

    def updateSavedFilters(self, filter: ColumnBasedTableFilter[ROW_OBJECT], add: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def configureButton(self) -> javax.swing.JButton:
        ...

    @property
    def currentFilter(self) -> ColumnBasedTableFilter[ROW_OBJECT]:
        ...

    @property
    def preferenceKey(self) -> java.lang.String:
        ...


class ColumnConstraintSet(java.lang.Object, typing.Generic[R, T]):
    """
    This class maintains a collection of :obj:`ColumnConstraint` that are applied to a specific table column
    for filtering purposes. In order for this ColumnConstraintSet to "pass", (i.e. accept the table
    row) the column value for that row must pass at least one of the constraints in this set, thus
    effectively OR'ing the constraints.
    
     
    Instances of this class are used by the :obj:`ColumnBasedTableFilter` to filter rows of table.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, model: docking.widgets.table.RowObjectTableModel[R], columnIndex: typing.Union[jpype.JInt, int], constraints: java.util.List[docking.widgets.table.constraint.ColumnConstraint[T]], logicOperation: LogicOperation):
        """
        Constructor
        
        :param docking.widgets.table.RowObjectTableModel[R] model: the table model being filtered.
        :param jpype.JInt or int columnIndex: the index of the column whose values are tested by this filter.
        :param java.util.List[docking.widgets.table.constraint.ColumnConstraint[T]] constraints: the list of ColumnConstraints whose results are or'ed together.
        :param LogicOperation logicOperation: the logical operation for how this constraintSet relates to other contraint sets.
        """

    @typing.overload
    def __init__(self, model: docking.widgets.table.RowObjectTableModel[R], saveState: ghidra.framework.options.SaveState, dataSource: java.lang.Object):
        """
        Constructor when deserializing from a SaveState
        
        :param docking.widgets.table.RowObjectTableModel[R] model: the table model being filtered
        :param ghidra.framework.options.SaveState saveState: the SaveState which contains the configuration for this filter.
        :param java.lang.Object dataSource: the table's DataSource.
        """

    def accepts(self, rowObject: R, context: docking.widgets.table.constraint.TableFilterContext) -> bool:
        """
        Return true if the given table row object passes this filter.
        
        :param R rowObject: the table row object.
        :param docking.widgets.table.constraint.TableFilterContext context: the :obj:`TableFilterContext` for this table's filter.
        :return: true if the given table row object passes this filter.
        :rtype: bool
        """

    def getColumnModelIndex(self) -> int:
        """
        Returns the model index of the column whose values will be tested by this filter.
        
        :return: the model index of the column whose values will be tested by this filter.
        :rtype: int
        """

    def getColumnName(self) -> str:
        """
        Return the name of the column whose values will be tested by this filter.
        
        :return: the name of the column whose values will be tested by this filter.
        :rtype: str
        """

    def getConstraints(self) -> java.util.List[docking.widgets.table.constraint.ColumnConstraint[T]]:
        """
        Returns a list of ColumnConstraints in this ColumnFilter
        
        :return: a list of ColumnConstraints in this ColumnFilter
        :rtype: java.util.List[docking.widgets.table.constraint.ColumnConstraint[T]]
        """

    def getLogicOperation(self) -> LogicOperation:
        """
        Returns the logical operation (AND or OR) for how to combine this object's :meth:`accepts(Object, TableFilterContext) <.accepts>`
        results with the results of previous constraintSet results in the overall filter.
        
        :return: the logical operation (AND or OR)
        :rtype: LogicOperation
        """

    @property
    def logicOperation(self) -> LogicOperation:
        ...

    @property
    def columnModelIndex(self) -> jpype.JInt:
        ...

    @property
    def constraints(self) -> java.util.List[docking.widgets.table.constraint.ColumnConstraint[T]]:
        ...

    @property
    def columnName(self) -> java.lang.String:
        ...


class ColumnFilterSaveManager(java.lang.Object, typing.Generic[R]):
    """
    Loads and Save a list of ColumnTableFilters for a specific table to the tool
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tablePreferenceKey: typing.Union[java.lang.String, str], table: javax.swing.JTable, model: docking.widgets.table.RowObjectTableModel[R], dataSource: java.lang.Object):
        """
        Constructor
        
        :param java.lang.String or str tablePreferenceKey: the key used to save table settings.   This is used to make a 
        preference key for saving the column filters.
        :param javax.swing.JTable table: The JTable that is filterable.
        :param docking.widgets.table.RowObjectTableModel[R] model: the TableModel that supports filtering.
        :param java.lang.Object dataSource: the table's DataSource object.
        """

    def addFilter(self, filter: ColumnBasedTableFilter[R]):
        """
        Adds a new ColumnTableFilter to be saved.
        
        :param ColumnBasedTableFilter[R] filter: The filter to be saved.
        """

    def containsFilterWithName(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if this save manager contains any filters with the given name.
        
        :param java.lang.String or str name: the name to check for a filter's existence.
        :return: true if this save manager contains any filters with the given name.
        :rtype: bool
        """

    def getSavedFilters(self) -> java.util.List[ColumnBasedTableFilter[R]]:
        """
        Returns a list of the saved ColumnTableFilters
        
        :return: a list of the saved ColumnTableFilters
        :rtype: java.util.List[ColumnBasedTableFilter[R]]
        """

    def removeFilter(self, filter: ColumnBasedTableFilter[R]):
        """
        Deletes a ColumnTableFilter from the list of saved filters.
        
        :param ColumnBasedTableFilter[R] filter: the filter to remove from the list of saved filters.
        """

    def save(self):
        """
        Saves the list of filters to the tool's preference state.
        """

    @property
    def savedFilters(self) -> java.util.List[ColumnBasedTableFilter[R]]:
        ...


class ColumnBasedTableFilter(docking.widgets.table.TableFilter[R], typing.Generic[R]):
    """
    A :obj:`TableFilter`  that filters based on column values
    
     
    This class maintains a list of :obj:`ColumnConstraintSet` objects that are logically combined
    to determine if the overall filter accepts the given row object. Each ColumnConstraint has an
    associated :obj:`LogicOperation` which determines how its result are combined with the constraint
    set before it. (The first ConstraintSets LogicOperation is not used).  AND operations have higher
    precedence than the OR operations.
    """

    @typing.type_check_only
    class AndList(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OrList(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: docking.widgets.table.RowObjectTableModel[R]):
        """
        Constructs a new empty ColumnBasedTableFilter
        
        :param docking.widgets.table.RowObjectTableModel[R] model: the table model
        """

    def addConstraintSet(self, logicalOp: LogicOperation, columnIndex: typing.Union[jpype.JInt, int], constraints: java.util.List[docking.widgets.table.constraint.ColumnConstraint[T]]):
        """
        Adds a new constraintSet to this ColumnBasedTableFilter
        
        :param LogicOperation logicalOp: The logic operation (AND or OR) for how the new ConstraintSet's result will be
        combined with the previous ConstraintSet's result.
        :param jpype.JInt or int columnIndex: the model index of the column whose values must past the given constraint filters.
        :param java.util.List[docking.widgets.table.constraint.ColumnConstraint[T]] constraints: a list of ColumnConstraints where at least one must pass for the constraintSet to pass.
        """

    def copy(self) -> ColumnBasedTableFilter[R]:
        ...

    def getConstraintSets(self) -> java.util.List[ColumnConstraintSet[R, typing.Any]]:
        """
        Return the list of ConstraintSets in this TableFilter
        
        :return: the list of ConstraintSets in this TableFilter
        :rtype: java.util.List[ColumnConstraintSet[R, typing.Any]]
        """

    def getHtmlRepresentation(self) -> str:
        """
        Returns an HTML description of this filter.
         
        
        Note: the HTML string returned does NOT start with the HTML tag so that it can be combined
        with other text.
        
        :return: an HTML description of this filter.
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of this filter.
        
         
        Names are used for saving filters, so unless they are saved they typically don't have a name.
        
        :return: the name of this filter.
        :rtype: str
        """

    def getToolTip(self, columnIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Return a tooltip  that describes the effect of this filter for a specific filter.
        
        :param jpype.JInt or int columnIndex: the model index of the column to get a filter description of.
        :return: a tooltip that describes this filter for a specific column.
        :rtype: str
        """

    def isEquivalent(self, other: ColumnBasedTableFilter[typing.Any]) -> bool:
        """
        Checks if the given :obj:`ColumnBasedTableFilter` is the same as this one except for
        its name.
        
        :param ColumnBasedTableFilter[typing.Any] other: the other filter to check for equivalence.
        :return: true if the other filter is the same as this one except for its name
        :rtype: bool
        """

    def isSaved(self) -> bool:
        """
        Returns true if this filter has been saved (i.e. has a name)
        
        :return: true if this filter has been saved (i.e. has a name)
        :rtype: bool
        """

    def restore(self, saveState: ghidra.framework.options.SaveState, dataSource: java.lang.Object):
        """
        Restore this filter from the given saveState.
        
        :param ghidra.framework.options.SaveState saveState: that contains the serialized filter data
        :param java.lang.Object dataSource: the Table's DataSource which some objects might need to restore themselves.
        """

    def save(self) -> ghidra.framework.options.SaveState:
        """
        Serializes this filter into a SaveState object.
        
        :return: the SaveState serialized version of this filter.
        :rtype: ghidra.framework.options.SaveState
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name of this filter.
        
        :param java.lang.String or str name: the new name for this filter.
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def saved(self) -> jpype.JBoolean:
        ...

    @property
    def htmlRepresentation(self) -> java.lang.String:
        ...

    @property
    def toolTip(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def constraintSets(self) -> java.util.List[ColumnConstraintSet[R, typing.Any]]:
        ...


class LogicOperation(java.lang.Enum[LogicOperation]):

    class_: typing.ClassVar[java.lang.Class]
    AND: typing.Final[LogicOperation]
    OR: typing.Final[LogicOperation]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LogicOperation:
        ...

    @staticmethod
    def values() -> jpype.JArray[LogicOperation]:
        ...



__all__ = ["ColumnFilterManager", "ColumnConstraintSet", "ColumnFilterSaveManager", "ColumnBasedTableFilter", "LogicOperation"]
