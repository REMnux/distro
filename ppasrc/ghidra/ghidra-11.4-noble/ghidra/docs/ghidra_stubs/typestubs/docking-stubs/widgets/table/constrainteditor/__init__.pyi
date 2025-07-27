from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import docking.widgets.list
import docking.widgets.table.constraint
import docking.widgets.table.constraint.provider
import docking.widgets.textfield
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.time # type: ignore
import java.time.format # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


M = typing.TypeVar("M")
T = typing.TypeVar("T")


class LocalDateSpinnerModel(javax.swing.AbstractSpinnerModel):
    """
    Spinner Model for LocalDate
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: java.time.LocalDate, minDate: java.time.LocalDate, maxDate: java.time.LocalDate, calendarField: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param java.time.LocalDate value: initial value for spinner model
        :param java.time.LocalDate minDate: minimum value for spinner model. (Can be null)
        :param java.time.LocalDate maxDate: maximum value for spinner model. (Can be null)
        :param jpype.JInt or int calendarField: specifies the year, month, or day to increment/decrement. One of:
          
        * :obj:`Calendar.YEAR`
        * :obj:`Calendar.MONTH`
        * :obj:`Calendar.DAY_OF_MONTH`
        """

    def getDate(self) -> java.time.LocalDate:
        ...

    def getMaxDate(self) -> java.time.LocalDate:
        """
        Returns the current maximum allowed date.
        
        :return: the current maximum allowed date.
        :rtype: java.time.LocalDate
        """

    def getMinDate(self) -> java.time.LocalDate:
        """
        Returns the current minimum allowed date.
        
        :return: the current minimum allowed date.
        :rtype: java.time.LocalDate
        """

    def setCalendarField(self, calendarField: typing.Union[jpype.JInt, int]):
        """
        Specifies whether the increment/decrement methods should adjust the year, month, or day.
        
        :param jpype.JInt or int calendarField: one of
          
        * :obj:`Calendar.YEAR`
        * :obj:`Calendar.MONTH`
        * :obj:`Calendar.DAY_OF_MONTH`
        """

    @property
    def date(self) -> java.time.LocalDate:
        ...

    @property
    def minDate(self) -> java.time.LocalDate:
        ...

    @property
    def maxDate(self) -> java.time.LocalDate:
        ...


class DateRangeConstraintEditor(AbstractColumnConstraintEditor[java.time.LocalDate]):
    """
    A constraint editor for specifying ranges of dates.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[java.time.LocalDate]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.ColumnConstraint[java.time.LocalDate] constraint: Date constraint for which this component is an editor.
        """


class DummyConstraintEditor(ColumnConstraintEditor[T], typing.Generic[T]):
    """
    An editor that is always invalid.
     
    
    Used internally to indicate a constraint does not provide an editor of its own.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param java.lang.String or str message: to display
        """


class EnumConstraintEditor(AbstractColumnConstraintEditor[T], typing.Generic[T]):
    """
    A constraint editor for enumerated-type values;
    """

    class_: typing.ClassVar[java.lang.Class]
    CHECKBOX_NAME_PREFIX: typing.Final = "enumCheckbox_"

    def __init__(self, constraint: docking.widgets.table.constraint.EnumColumnConstraint[T]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.EnumColumnConstraint[T] constraint: Enum-type constraint for which this component is an editor.
        """

    def getElementDisplayName(self, value: T) -> str:
        """
        Resolves and returns a more friendly display name for a given Enum value.
         
        
        Several Ghidra enumerated types provide functions for retrieving formatted
        name for a value; this attempts to locate one such function within the Enum class.
         
        
        This searches the enum class for a zero-argument, String-returning method called
        ``getName()``, ``getDisplayName()``, or ``getDisplayString()``
        before falling back to ``toString()``.
        
        :return: a more user-friendly name for the value
        :rtype: str
        """

    @property
    def elementDisplayName(self) -> java.lang.String:
        ...


class ColumnConstraintEditor(java.lang.Object, typing.Generic[T]):
    """
    Defines the contract for building user-interface elements for manipulating
    constraint configuration.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addChangeListener(self, constraintEditorChangeListener: javax.swing.event.ChangeListener):
        """
        Register a callback handler for responding to changes made within the editor
        
        :param javax.swing.event.ChangeListener constraintEditorChangeListener: listener callback
        """

    def getDetailComponent(self) -> java.awt.Component:
        """
        The *detail* component resides in the configuration interface below
        the column and constraint selection widgets, and is afforded greater space.
        It is intended to be a more feature-rich editor that provides greater
        insight or control of the constraints value definition.
        
        :return: the detail editor component
        :rtype: java.awt.Component
        """

    def getErrorMessage(self) -> str:
        """
        If the editor contains and invalid value, this message should indicate
        why the value is invalid. Only called if ``hasValidValue()`` returns false.
        
        :return: an error message, or an empty string if no error
        :rtype: str
        """

    def getInlineComponent(self) -> java.awt.Component:
        """
        The *inline* component resides in the configuration interface on the same
        visual line as the column and constraint selection widgets. It is intended to be
        a relatively small and simple interface for configuring the constraints' values.
        
        :return: the inline editor component
        :rtype: java.awt.Component
        """

    def getValue(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        """
        Get the current value from the editor, in the form of a constraint.
        
        :return: the editors' current value
        :rtype: docking.widgets.table.constraint.ColumnConstraint[T]
        """

    def hasValidValue(self) -> bool:
        """
        Determine if the editor contains a valid value; do the UI widgets and state
        match, is the state sensible for the constraint.
        
        :return: true if the configuration is valid, false otherwise
        :rtype: bool
        """

    def removeChangeListener(self, constraintEditorChangeListener: javax.swing.event.ChangeListener):
        """
        Remove a callback handler that was responding changes made within the editor
        
        :param javax.swing.event.ChangeListener constraintEditorChangeListener: listener callback
        """

    def reset(self):
        """
        Reset the editor to a known-good state.
        """

    def setValue(self, value: docking.widgets.table.constraint.ColumnConstraint[T]):
        """
        Set the current value within the editor
        
        :param docking.widgets.table.constraint.ColumnConstraint[T] value: the new value to set
        """

    @property
    def detailComponent(self) -> java.awt.Component:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def inlineComponent(self) -> java.awt.Component:
        ...

    @property
    def value(self) -> docking.widgets.table.constraint.ColumnConstraint[T]:
        ...

    @value.setter
    def value(self, value: docking.widgets.table.constraint.ColumnConstraint[T]):
        ...


class UnsignedLongConstraintEditorProvider(docking.widgets.table.constraint.provider.EditorProvider[java.math.BigInteger]):
    """
    Provides an editor for editing constraints for unsigned 64 bit values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AutocompletingStringConstraintEditor(DataLoadingConstraintEditor[java.lang.String]):
    """
    An editor that provides suggestions of values that, according to
    :obj:`StringColumnConstraint`, match a user-supplied
    pattern.
    """

    @typing.type_check_only
    class AutocompleteDataModel(docking.widgets.DropDownTextFieldDataModel[java.lang.String]):
        """
        String-based data model for the DropDownSelectionTextField. Values from the column,
        converted to String, are stored and queried here.
        """

        class_: typing.ClassVar[java.lang.Class]

        def clear(self):
            ...

        def collect(self, value: typing.Union[java.lang.String, str]):
            ...

        def loadCancelled(self):
            ...


    @typing.type_check_only
    class AutocompleteListCellRenderer(docking.widgets.list.GListCellRenderer[java.lang.String]):
        """
        Cell renderer for suggestion candidates. Substrings that match the models' query are
        highlighted for ease-of-use.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, autocompleteDataModel: AutocompletingStringConstraintEditor.AutocompleteDataModel):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.StringColumnConstraint, columnDataSource: docking.widgets.table.constraint.ColumnData[java.lang.String]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.StringColumnConstraint constraint: String constraint for which this component is an editor
        :param docking.widgets.table.constraint.ColumnData[java.lang.String] columnDataSource: provides access to table data and. Must be non-null.
        """


class UnsignedLongConstraintEditor(AbstractColumnConstraintEditor[java.math.BigInteger]):
    """
    A constraint editor for 64 bit unsigned numbers.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_VALUE: typing.ClassVar[java.math.BigInteger]

    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[java.math.BigInteger]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.ColumnConstraint[java.math.BigInteger] constraint: uses BigInteger to represent unsigned 64 bit values.
        """


class DoubleValueConstraintEditor(AbstractColumnConstraintEditor[java.lang.Double]):
    """
    A constraint editor for specifying comparison with a single floating-point value (Float and Double).
    """

    class_: typing.ClassVar[java.lang.Class]
    FLOATING_POINT_FORMAT: typing.Final = "0.##########;-0.##########"

    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[java.lang.Double]):
        ...


class DataLoadingConstraintEditor(AbstractColumnConstraintEditor[T], ghidra.util.task.TaskListener, typing.Generic[T]):
    """
    Abstract base class for constraint editors that load all the data in a column in order to
    initialize themselves.
    """

    @typing.type_check_only
    class LoadDataTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegateConstraint: docking.widgets.table.constraint.ColumnConstraint[T], columnDataSource: docking.widgets.table.constraint.ColumnData[T]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.ColumnConstraint[T] delegateConstraint: the constraint to feed column data to. Provides
        editors for manipulating constraint values.
        :param docking.widgets.table.constraint.ColumnData[T] columnDataSource: provides access to table data and. Must be non-null.
        """

    def clearColumnData(self):
        """
        Request that any state maintained by the delegate editor pertaining to
        column data be cleared.
        """

    def columnDataLoadCancelled(self):
        """
        Notification that the column data-load was cancelled.
        """

    def columnDataLoadComplete(self):
        """
        Notification that the column data-load has been completed.
        """

    def handleColumnDataValue(self, value: T):
        """
        A value has been read from the table (column); handle it in an
        editor-specific way.
        
        :param T value: the value read from the table (column)
        """


class LongConverter(java.lang.Object, typing.Generic[T]):
    """
    Interface used by number constraints. This allows all the integer number constraints (byte,short
    int, long) to share the same editor (which uses long values). This interface allows the editor
    values to be converted back to T.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fromLong(self, value: typing.Union[jpype.JLong, int]) -> T:
        """
        Converts a long value back to a T
        
        :param jpype.JLong or int value: the long value.
        :return: the long value converted to T
        :rtype: T
        """


class IntegerRangeConstraintEditor(AbstractColumnConstraintEditor[T], typing.Generic[T]):
    """
    A constraint editor for specifying ranges of integer-type numbers (Byte, Short, Integer,
    and Long).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[T], converter: LongConverter[T]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.ColumnConstraint[T] constraint: Integer-type constraint for which this component is an editor.
        :param LongConverter[T] converter: Utility class to convert integer types to Long-type for internal operation.
        """


class MappedColumnConstraintEditor(ColumnConstraintEditor[T], typing.Generic[T, M]):
    """
    A constraint editor that supports object type conversions, wrapping the editor for the
    converted-to type. This is used to convert one column type to another that we already have
    editors for. For example, suppose there is a Foo type where the column is returning Foo objects
    but the rendering is just displaying Foo.getName().  In this case you would create a FooEditor
    that wraps the various string editors. So even though the column uses Foo objects, the user
    filters on just strings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.MappedColumnConstraint[T, M], delegateEditor: ColumnConstraintEditor[M]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.MappedColumnConstraint[T, M] constraint: Type-converting constraint for which this component is an editor.
        :param ColumnConstraintEditor[M] delegateEditor: Editor for the converted-to type.
        """


class UnsignedLongRangeEditorProvider(docking.widgets.table.constraint.provider.EditorProvider[java.math.BigInteger]):
    """
    :obj:`EditorProvider` for the :obj:`UnsignedLongRangeConstraintEditor`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DateSpinner(java.lang.Object):
    """
    Creates a component for editing Dates using a formated textfield and a Jspinner.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spinnerModel: LocalDateSpinnerModel, pattern: typing.Union[java.lang.String, str]):
        """
        Creates a DateSpinner object using the given spinnerModel and a pattern for a formated text field.
        
        :param LocalDateSpinnerModel spinnerModel: the spinner model
        :param java.lang.String or str pattern: a pattern to be used by a JFormattedTextField
        """

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Adds a ChangeListener to the model's listener list.  The
        ChangeListeners must be notified when the models value changes.
        
        :param javax.swing.event.ChangeListener listener: the ChangeListener to add
        
        .. seealso::
        
            | :obj:`.removeChangeListener`
        
            | :obj:`SpinnerModel.addChangeListener`
        """

    def getDateField(self) -> docking.widgets.textfield.LocalDateTextField:
        """
        Returns the DateTextField component.
        
        :return: the DateTextField component.
        :rtype: docking.widgets.textfield.LocalDateTextField
        """

    def getSpinner(self) -> javax.swing.JSpinner:
        """
        Returns the spinner component.
        
        :return: the spinner component.
        :rtype: javax.swing.JSpinner
        """

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Removes a ChangeListener from the model's listener list.
        
        :param javax.swing.event.ChangeListener listener: the ChangeListener to remove
        
        .. seealso::
        
            | :obj:`.addChangeListener`
        
            | :obj:`SpinnerModel.removeChangeListener`
        """

    def setValue(self, newValue: java.time.LocalDate):
        """
        Sets the Date value for this DateSpinner.
        
        :param java.time.LocalDate newValue: the new Date for this DateSpinner.
        """

    @property
    def dateField(self) -> docking.widgets.textfield.LocalDateTextField:
        ...

    @property
    def spinner(self) -> javax.swing.JSpinner:
        ...


class StringConstraintEditor(AbstractColumnConstraintEditor[java.lang.String]):
    """
    A constraint editor for String-type values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.StringColumnConstraint, errorMessage: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.StringColumnConstraint constraint: String-type constraint for which this component is an editor.
        :param java.lang.String or str errorMessage: the message to display if the textField is blank.
        """


class DateValueConstraintEditor(AbstractColumnConstraintEditor[java.time.LocalDate]):
    """
    A constraint editor for specifying comparison with a single Date value.
    """

    class_: typing.ClassVar[java.lang.Class]
    DATE_PATTERN: typing.Final = "MM/dd/yyyy"
    LOCAL_DATE_FORMAT: typing.Final[java.time.format.DateTimeFormatter]
    """
    Specifies how Date values are to be formatted within the editor
    """


    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[java.time.LocalDate]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.ColumnConstraint[java.time.LocalDate] constraint: Date constraint for which this component is an editor.
        """


class IntegerConstraintEditor(AbstractColumnConstraintEditor[T], typing.Generic[T]):
    """
    A constraint editor for specifying comparison with a single integer-type value (Byte, Short,
    Integer, and Long).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[T], converter: LongConverter[T]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.ColumnConstraint[T] constraint: Integer-type constraint for which this component is an editor.
        :param LongConverter[T] converter: Utility class to convert integer types to Long-type for internal operation.
        """


class DoNothingColumnConstraintEditor(AbstractColumnConstraintEditor[T], typing.Generic[T]):
    """
    Editor for constraints that don't have a value that needs editing.  The "IsEmpty" constraint
    is an example of a constraint that doesn't need an editor.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[T]):
        ...


class UnsignedLongRangeConstraintEditor(AbstractColumnConstraintEditor[java.math.BigInteger]):
    """
    A constraint editor for specifying ranges of unsigned long values.  There are no direct
    constraints that use the editor since java doesn't have unsigned long types. This exists for
    objects that represent an unsigned long value and are converted to BigInteger for editing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[java.math.BigInteger]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.ColumnConstraint[java.math.BigInteger] constraint: Integer-type constraint for which this component is an editor.
        """


class DoubleRangeConstraintEditor(AbstractColumnConstraintEditor[java.lang.Double]):
    """
    A constraint editor for specifying ranges of floating-point numbers (Float and Double)
    """

    class_: typing.ClassVar[java.lang.Class]
    FLOATING_POINT_FORMAT: typing.Final = "0.##########;-0.##########"
    DISPLAY_FORMAT: typing.Final = "#,##0.##########;-#,##0.##########"

    def __init__(self, constraint: docking.widgets.table.constraint.ColumnConstraint[java.lang.Double]):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.ColumnConstraint[java.lang.Double] constraint: Floating-point constraint for which this component is an editor.
        """


class BooleanConstraintEditor(AbstractColumnConstraintEditor[java.lang.Boolean]):
    """
    A constraint editor for Boolean-type constraints, offering a choice of boolean values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: docking.widgets.table.constraint.BooleanMatchColumnConstraint):
        """
        Constructor.
        
        :param docking.widgets.table.constraint.BooleanMatchColumnConstraint constraint: Boolean constraint for which this component is an editor.
        """


class AbstractColumnConstraintEditor(ColumnConstraintEditor[T], typing.Generic[T]):
    """
    Base class for many constraint editors, providing implementation for much of the interface.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BoundedSpinnerNumberModel(javax.swing.SpinnerNumberModel):
    """
    :obj:`SpinnerNumberModel` that adds checking to make sure setValue is in the allowed range.  Strangely,
    the default SpinnerNumberModel has min and max values, but does not check except during the
    increment/decrement using the spinner widget.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, value: java.lang.Number, minimum: java.lang.Comparable[java.lang.Number], maximum: java.lang.Comparable[java.lang.Number], stepSize: java.lang.Number):
        ...

    @typing.overload
    def __init__(self, value: typing.Union[jpype.JInt, int], minimum: typing.Union[jpype.JInt, int], maximum: typing.Union[jpype.JInt, int], stepSize: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, value: typing.Union[jpype.JDouble, float], minimum: typing.Union[jpype.JDouble, float], maximum: typing.Union[jpype.JDouble, float], stepSize: typing.Union[jpype.JDouble, float]):
        ...

    @typing.overload
    def __init__(self):
        ...



__all__ = ["LocalDateSpinnerModel", "DateRangeConstraintEditor", "DummyConstraintEditor", "EnumConstraintEditor", "ColumnConstraintEditor", "UnsignedLongConstraintEditorProvider", "AutocompletingStringConstraintEditor", "UnsignedLongConstraintEditor", "DoubleValueConstraintEditor", "DataLoadingConstraintEditor", "LongConverter", "IntegerRangeConstraintEditor", "MappedColumnConstraintEditor", "UnsignedLongRangeEditorProvider", "DateSpinner", "StringConstraintEditor", "DateValueConstraintEditor", "IntegerConstraintEditor", "DoNothingColumnConstraintEditor", "UnsignedLongRangeConstraintEditor", "DoubleRangeConstraintEditor", "BooleanConstraintEditor", "AbstractColumnConstraintEditor", "BoundedSpinnerNumberModel"]
