from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table.constraint.provider
import docking.widgets.table.constrainteditor
import ghidra.util.classfinder
import java.lang # type: ignore
import java.time # type: ignore
import java.util # type: ignore
import java.util.regex # type: ignore


M = typing.TypeVar("M")
T = typing.TypeVar("T")


class ObjectToStringMapper(ColumnTypeMapper[T, java.lang.String], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceType: java.lang.Class[T]):
        ...


class AtMostColumnConstraint(SingleValueColumnConstraint[T], typing.Generic[T]):
    """
    Column Constraint where acceptable column values are less than or equal to some specified
    value of the column type.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, maxValue: T, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[T]):
        """
        Constructs a new AtMostColumnConstraint with a default name, default group and a maximum value.
        
        :param T maxValue: the value for which all acceptable column values must be less than or equal.
        :param docking.widgets.table.constraint.provider.EditorProvider[T] editorProvider: an object that can provide a ConstraintEditor for this constraint type.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], maxValue: T, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[T], group: typing.Union[java.lang.String, str]):
        """
        Constructs a new AtMostColumnConstraint with a maximum value, constraint name, and group
        
        :param java.lang.String or str name: the name of the constraint.  For some types T, the default "At Most" may not be best.
        :param T maxValue: the value for which all acceptable column values must be less than or equal.
        :param docking.widgets.table.constraint.provider.EditorProvider[T] editorProvider: an object that can provide a ConstraintEditor for this constraint type.
        :param java.lang.String or str group: the name of the group used to organize the list of constraints for a column.
        """


class InRangeColumnConstraint(RangeColumnConstraint[T], typing.Generic[T]):
    """
    Column Constraint where acceptable column values are within some range defined by a min value and
    a max value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, minValue: T, maxValue: T, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[T]):
        """
        Construct a new InRangeConstraint that uses the default name and group and specifies the min
        and max values for the range.
        
        :param T minValue: the min value of the acceptable range.
        :param T maxValue: the max value of the acceptable range.
        :param docking.widgets.table.constraint.provider.EditorProvider[T] editorProvider: an object that can provide an appropriate range editor for the column type.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], minValue: T, maxValue: T, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[T], group: typing.Union[java.lang.String, str]):
        """
        Construct a new InRangeConstraint that specifies the name and group and specifies the min
        and max values for the range.
        
        :param java.lang.String or str name: the constraint to use instead of the default "In Range".
        :param T minValue: the min value of the acceptable range.
        :param T maxValue: the max value of the acceptable range.
        :param docking.widgets.table.constraint.provider.EditorProvider[T] editorProvider: an object that can provide an appropriate range editor for the column type.
        :param java.lang.String or str group: the group to use instead of the default value of "number".
        """


class AtMostDateColumnConstraint(SingleValueColumnConstraint[java.time.LocalDate]):
    """
    Column Constraint where acceptable column values are greater than or equal to some specified
    value of the column type
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, minValue: java.time.LocalDate, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[java.time.LocalDate]):
        """
        Constructs a new AtLeastDateColumnConstraint with a default name, default group and a minimum value
        
        :param java.time.LocalDate minValue: the value for which all acceptable column values must be greater than or equal.
        :param docking.widgets.table.constraint.provider.EditorProvider[java.time.LocalDate] editorProvider: an object that can provide a ConstraintEditor for this constraint type.
        """


class StringNotEndsWithColumnConstraint(StringEndsWithColumnConstraint):
    """
    String column constraint for matching column values if they don't end with the constraint value pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, patternString: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str patternString: the string to use to create an "ends with" pattern.
        """


class StringNotContainsColumnConstraint(StringContainsColumnConstraint):
    """
    String column constraint for matching column values if they don't contain the constraint value pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spec: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str spec: the string to use to create a "not contains" pattern.
        """


class NotInRangeColumnConstraint(RangeColumnConstraint[T], typing.Generic[T]):
    """
    Column Constraint where acceptable column values are outside some range defined by a min value and
    a max value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, minValue: T, maxValue: T, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[T]):
        """
        Construct a new instance of this class that uses the default name and group and specifies the min
        and max values for the range.
        
        :param T minValue: the min value of the acceptable range.
        :param T maxValue: the max value of the acceptable range.
        :param docking.widgets.table.constraint.provider.EditorProvider[T] editorProvider: an object that can provide an appropriate range editor for the column type.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], minValue: T, maxValue: T, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[T], group: typing.Union[java.lang.String, str]):
        """
        Construct a new instance of this class that specifies the name and group and specifies the min
        and max values for the range.
        
        :param java.lang.String or str name: the constraint to use instead of the default "Not In Range".
        :param T minValue: the min value of the acceptable range.
        :param T maxValue: the max value of the acceptable range.
        :param docking.widgets.table.constraint.provider.EditorProvider[T] editorProvider: an object that can provide an appropriate range editor for the column type.
        :param java.lang.String or str group: the group to use instead of the default value of "number".
        """


class AtLeastColumnConstraint(SingleValueColumnConstraint[T], typing.Generic[T]):
    """
    Column Constraint where acceptable column values are greater than or equal to some specified
    value of the column type.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, minValue: T, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[T]):
        """
        Constructs a new AtLeastColumnConstraint with a default name, default group and a minimum value.
        
        :param T minValue: the value for which all acceptable column values must be greater than or equal.
        :param docking.widgets.table.constraint.provider.EditorProvider[T] editorProvider: an object that can provide a ConstraintEditor for this constraint type.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], minValue: T, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[T], group: typing.Union[java.lang.String, str]):
        """
        Constructs a new AtLeastColumnConstraint with a minimum value, constraint name, and group
        
        :param java.lang.String or str name: the name of the constraint.  For some types T, the default "At Least" may not be best.
        :param T minValue: the value for which all acceptable column values must be greater than or equal.
        :param docking.widgets.table.constraint.provider.EditorProvider[T] editorProvider: an object that can provide a ConstraintEditor for this constraint type.
        :param java.lang.String or str group: the name of the group used to organize the list of constraints for a column.
        """


class StringNotMatchesColumnConstraint(StringMatchesColumnConstraint):
    """
    String column constraint for matching column values if they do not match a full regular
    expression pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spec: typing.Union[java.lang.String, str]):
        """
        Constructor
        
         
        This class is for users to enter true regular expression which is why it creates
        a pattern directly without using the :obj:`UserSearchUtils`
        
        :param java.lang.String or str spec: the string to use to create a "matcher" pattern.
        """


class StringColumnConstraint(ColumnConstraint[java.lang.String]):
    """
    Base class for various String constraints.
    """

    class_: typing.ClassVar[java.lang.Class]

    def copy(self, newPatternString: typing.Union[java.lang.String, str]) -> ColumnConstraint[java.lang.String]:
        """
        subclasses must override to generate new versions of themselves but with a new pattern string.
        
        :param java.lang.String or str newPatternString: the new string to use for creating the match pattern.
        :return: a new ColumnConstraint that is the same type as this constraint but with a new range defined.
        :rtype: ColumnConstraint[java.lang.String]
        """

    def getHighlightMatcher(self, value: typing.Union[java.lang.String, str]) -> java.util.regex.Matcher:
        ...

    def getPatternString(self) -> str:
        """
        Returns the pattern string for this constraint.
        
        :return: the pattern string for this constraint.
        :rtype: str
        """

    def isValidPatternString(self, value: typing.Union[java.lang.String, str]) -> bool:
        ...

    @property
    def highlightMatcher(self) -> java.util.regex.Matcher:
        ...

    @property
    def validPatternString(self) -> jpype.JBoolean:
        ...

    @property
    def patternString(self) -> java.lang.String:
        ...


class RangeColumnConstraint(ColumnConstraint[T], typing.Generic[T]):
    """
    Abstract base class for range constraints.
    """

    class_: typing.ClassVar[java.lang.Class]

    def copy(self, min: T, max: T) -> RangeColumnConstraint[T]:
        """
        subclasses must override to generate new versions of themselves but with new range values.
        
        :param T min: the min value of the range.
        :param T max: the max value of the range.
        :return: a new ColumnConstraint that is the same type as this constraint but with a new range defined.
        :rtype: RangeColumnConstraint[T]
        """

    def getMaxValue(self) -> T:
        """
        Returns the max value of the range used by this constraint.
        
        :return: the max value of the range used by this constraint.
        :rtype: T
        """

    def getMinValue(self) -> T:
        """
        Returns the min value of the range used by this constraint.
        
        :return: the min value of the range used by this constraint.
        :rtype: T
        """

    @property
    def minValue(self) -> T:
        ...

    @property
    def maxValue(self) -> T:
        ...


class SingleValueColumnConstraint(ColumnConstraint[T], typing.Generic[T]):
    """
    Abstract base class for single value constraints such as "At Most" or "At Least"
    """

    class_: typing.ClassVar[java.lang.Class]

    def copy(self, newValue: T) -> SingleValueColumnConstraint[T]:
        """
        subclasses must override to generate new versions of themselves but with new comparison value.
        
        :param T newValue: the new value to compare column values against.
        :return: a new ColumnConstraint that is the same type as this constraint but with a new comparison value.
        :rtype: SingleValueColumnConstraint[T]
        """

    def getConstraintValue(self) -> T:
        """
        Returns the constraint value
        
        :return: the constraint value
        :rtype: T
        """

    @property
    def constraintValue(self) -> T:
        ...


class MappedColumnConstraint(ColumnConstraint[T], typing.Generic[T, M]):
    """
    Class that maps one type of column constraint into another.  Typically, these are created
    automatically based on :obj:`ColumnTypeMapper` that are discovered by the system.  For example,
    if you have a column type of "Foo", and you create a ColumnTypeMapper<Foo, String>, then all the string constraints would now be available that column.
    """

    @typing.type_check_only
    class DelegateColumnData(ColumnData[M]):
        """
        Class for converting a ColumnDataSource<T> to a ColumnDataSource<W> to be used when
        getting the editor for the delegateColumnConstraint<W>.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, columnDataSource: ColumnData[T]):
            """
            Constructor
            
            :param ColumnData[T] columnDataSource: theColumnDataSource<T> whose T data will be converted to
            W data for the delegate editor.
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mapper: ColumnTypeMapper[T, M], delegate: ColumnConstraint[M]):
        """
        Constructs a new Mapped ColumnConstraint
        
        :param ColumnTypeMapper[T, M] mapper: a mapper from the column type to a mapped type.
        :param ColumnConstraint[M] delegate: the column constraint of the mapped type.
        """

    def copy(self, newDelegate: ColumnConstraint[M]) -> ColumnConstraint[T]:
        """
        Creates a copy of this class using the same mapper but with a different mapped delegate.
        
        :param ColumnConstraint[M] newDelegate: the new M type delegate column constraint.
        :return: a copy of this class using the same mapper but with a different mapped delegate.
        :rtype: ColumnConstraint[T]
        """

    def getDelegate(self) -> ColumnConstraint[M]:
        """
        Returns the delegate constraint (current value for this mapped constraint)
        
        :return: the delegate constraint.
        :rtype: ColumnConstraint[M]
        """

    @property
    def delegate(self) -> ColumnConstraint[M]:
        ...


class StringMatchesColumnConstraint(StringColumnConstraint):
    """
    String column constraint for matching column values if they match a full regular expression pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spec: typing.Union[java.lang.String, str]):
        """
        Constructor
        
         
        This class is for users to enter true regular expression which is why it creates
        a pattern directly without using the :obj:`UserSearchUtils`.
        
        :param java.lang.String or str spec: the string to use to create a "matcher" pattern.
        """


class StringIsEmptyColumnConstraint(ColumnConstraint[java.lang.String]):
    """
    String column constraint for matching when the value is null or the empty string.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NotInDateRangeColumnConstraint(RangeColumnConstraint[java.time.LocalDate]):
    """
    Column Constraint where acceptable column values are not within some range defined by a min value and
    a max value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, minValue: java.time.LocalDate, maxValue: java.time.LocalDate, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[java.time.LocalDate]):
        """
        Construct a new NotInDateRangeConstraint that uses the default name and group and specifies the min
        and max values for the range.
        
        :param java.time.LocalDate minValue: the min value of the excluded range.
        :param java.time.LocalDate maxValue: the max value of the excluded range.
        :param docking.widgets.table.constraint.provider.EditorProvider[java.time.LocalDate] editorProvider: an object that can provide an appropriate range editor for the column type.
        """


class StringNotStartsWithColumnConstraint(StringStartsWithColumnConstraint):
    """
    String column constraint for matching column values if they don't start with the constraint value pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spec: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str spec: the string to use to create a "not contains" pattern.
        """


class ColumnData(java.lang.Object, typing.Generic[T]):
    """
    Interface for providing column data and a table's DataSource to a constraint editor.  Some editors
    require access to the table column data.  One example is a String "Starts With" column might
    pre-process the data to provide an autocompletion feature in the editor.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getColumnName(self) -> str:
        """
        Returns the name of the column being filtered.
        
        :return: the name of the column being filtered.
        :rtype: str
        """

    def getColumnValue(self, row: typing.Union[jpype.JInt, int]) -> T:
        """
        Returns the column value for the given row.
        
        :param jpype.JInt or int row: the row for which to get the column value.
        :return: the column value for the given row.
        :rtype: T
        """

    def getCount(self) -> int:
        """
        Returns the number of column values (unfiltered table row count)
        
        :return: the number of column values (unfiltered table row count)
        :rtype: int
        """

    def getTableDataSource(self) -> java.lang.Object:
        """
        Returns the table's DataSource.
        
        :return: the table's DataSource.
        :rtype: java.lang.Object
        """

    @property
    def tableDataSource(self) -> java.lang.Object:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def columnValue(self) -> T:
        ...

    @property
    def columnName(self) -> java.lang.String:
        ...


class ColumnTypeMapper(ghidra.util.classfinder.ExtensionPoint, typing.Generic[T, M]):
    """
    ColumnConstraintTypeMappers allows columns of one type be filterable using an existing :obj:`ColumnConstraint`
    for a different type by defining a  mapping from the column type to the desired
    filter type. To get the benefit of one of these mappers, all that is required is to implement
    one of these mappers.  The mapper class must be public and it's name must end in "TypeMapper".
    
     
    
    For example, if you have a column type of "Person" that holds various information about a person
    including their age and you want to filter on their age, you could define a ColumnTypeMapper that
    converts a "Person" to an int.  Just by creating such a mapper class, any table with "Person"
    column types would now be able to filter on a person's age.
     
    
    In the example above, you created a filter of a single attribute of person.  If, however, you
    want more than that, you could instead create a new :obj:`ColumnConstraint` that filters on
    more attributes of a Person.  See :obj:`NumberColumnConstraintProvider` for an example
    of how to create these ColumnConstraints and their associated editors.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def convert(self, value: T) -> M:
        """
        Converts an object of type T1 to an object of type T2
        
        :param T value: the object to convert.
        :return: the converted object.
        :rtype: M
        """

    def getDestinationType(self) -> java.lang.Class[M]:
        """
        Returns the class of the objects that this mapper will convert to.
        
        :return: the class of the objects that this mapper will convert to.
        :rtype: java.lang.Class[M]
        """

    def getSourceType(self) -> java.lang.Class[T]:
        """
        Returns the class of the objects that this mapper will convert from.
        
        :return: the class of the objects that this mapper will convert from.
        :rtype: java.lang.Class[T]
        """

    @property
    def sourceType(self) -> java.lang.Class[T]:
        ...

    @property
    def destinationType(self) -> java.lang.Class[M]:
        ...


class TableFilterContext(java.lang.Object):
    """
    T
    Provides additional information (context) to column filter constraint objects.  This  allows
    the possibility for :obj:`ColumnConstraint` objects to make filtering decisions based on
    information other than just the column value.  For example, the column value might be a key
    into some other data mapping.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDataSource(self) -> java.lang.Object:
        """
        Returns the table's data source object if it has one; otherwise it returns null.
        
        :return: the table's data source object if it has one; otherwise it returns null.
        :rtype: java.lang.Object
        
        .. seealso::
        
            | :obj:`GDynamicColumnTableModel.getDataSource()`
        """

    @property
    def dataSource(self) -> java.lang.Object:
        ...


class BooleanMatchColumnConstraint(ColumnConstraint[java.lang.Boolean]):
    """
    Column Constraint for boolean values where the column values must match the constraint value
    of either true of false.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, matchValue: typing.Union[java.lang.Boolean, bool]):
        """
        Construct a new BooleanMatchColumnConstraint that matches the given boolean value.
        
        :param java.lang.Boolean or bool matchValue: the value (true or false) that acceptable column values have.
        """

    def getValue(self) -> bool:
        """
        Returns the constraints boolean value for matching.
        
        :return: the constraints boolean value for matching.
        :rtype: bool
        """

    @property
    def value(self) -> jpype.JBoolean:
        ...


class InDateRangeColumnConstraint(RangeColumnConstraint[java.time.LocalDate]):
    """
    Column Constraint where acceptable column values are within some range defined by a min value and
    a max value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, minValue: java.time.LocalDate, maxValue: java.time.LocalDate, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[java.time.LocalDate]):
        """
        Construct a new InDateRangeConstraint that uses the default name and group and specifies the min
        and max values for the range.
        
        :param java.time.LocalDate minValue: the min value of the acceptable range.
        :param java.time.LocalDate maxValue: the max value of the acceptable range.
        :param docking.widgets.table.constraint.provider.EditorProvider[java.time.LocalDate] editorProvider: an object that can provide an appropriate range editor for the column type.
        """


class ColumnConstraint(java.lang.Comparable[ColumnConstraint[T]], typing.Generic[T]):
    """
    ColumnConstraints are objects used to filter table rows based on values from a particular column.
    """

    class_: typing.ClassVar[java.lang.Class]

    def accepts(self, value: T, context: TableFilterContext) -> bool:
        """
        Compares value against the current constraint value to determine
        acceptance; true if value satisfies the constraints' value, false
        otherwise
        
        :param T value: the column value to be tested.
        :param TableFilterContext context: provides additional information about the table and its data. This
        allows the filter to base its decision on information other than just the column value.
        :return: true if the column value passes the constraint, false otherwise
        :rtype: bool
        """

    def asString(self) -> str:
        """
        Returns a reasonable String version of this constraint useful for debugging.
        
        :return: the String representation of this constraint
        :rtype: str
        """

    def compareTo(self, other: ColumnConstraint[T]) -> int:
        """
        ColumnConstraints are displayed by group and then by name
        """

    def getColumnType(self) -> java.lang.Class[T]:
        """
        Returns the column type that this constraint can be used to filter.
        
        :return: the column type
        :rtype: java.lang.Class[T]
        """

    def getConstraintValueString(self) -> str:
        """
        Returns the "value" of the constraint in string form
        
         
        This is used for serializing the constraint.
        
        :return: the "value" of the constraint in string form.
        :rtype: str
        """

    def getConstraintValueTooltip(self) -> str:
        """
        returns a description of the constraint suitable for displaying in a tooltip
        
        :return: a description of the constraint.
        :rtype: str
        """

    def getEditor(self, columnDataSource: ColumnData[T]) -> docking.widgets.table.constrainteditor.ColumnConstraintEditor[T]:
        """
        Returns a ColumnConstraintEditor which will provide gui components for users to edit the
        constraint values.
        
        :param ColumnData[T] columnDataSource: This provides the constraint with access to the column data in the
        table model as well as the DataProvider of the table (if it has one)
        :return: A columnConstraintEditor for editing the constraints value.
        :rtype: docking.widgets.table.constrainteditor.ColumnConstraintEditor[T]
        """

    def getGroup(self) -> str:
        """
        Returns a "group" string that is used to logically group column constraints for
        presentation to the user
        
        :return: the group this constraint belongs to.
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of the constraint
        
        :return: the name of the constraint.
        :rtype: str
        """

    def parseConstraintValue(self, constraintValueString: typing.Union[java.lang.String, str], dataSource: java.lang.Object) -> ColumnConstraint[T]:
        """
        Parses the constraint value string for deserialization purposes.
        
        :param java.lang.String or str constraintValueString: the value of the constraint in string form.
        :param java.lang.Object dataSource: the DataSource from the Table.
        :return: a new ColumnConstraint
        :rtype: ColumnConstraint[T]
        """

    @property
    def constraintValueTooltip(self) -> java.lang.String:
        ...

    @property
    def constraintValueString(self) -> java.lang.String:
        ...

    @property
    def editor(self) -> docking.widgets.table.constrainteditor.ColumnConstraintEditor[T]:
        ...

    @property
    def columnType(self) -> java.lang.Class[T]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def group(self) -> java.lang.String:
        ...


class EnumColumnConstraint(ColumnConstraint[T], typing.Generic[T]):
    """
    Column Constraint where acceptable column values are Enum values that match one of a set of
    selected values from the Enum.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, enumClass: java.lang.Class[T], acceptableValues: java.util.Set[T]):
        """
        Construct an EnumColumnConstraint with a set of acceptable Enum values.
        
        :param java.lang.Class[T] enumClass: the Enum class.
        :param java.util.Set[T] acceptableValues: the set of acceptable Enum values.
        """

    def getEnumClass(self) -> java.lang.Class[T]:
        """
        Return the class of the column's Enum type.
        
        :return: the class of the column's Enum type.
        :rtype: java.lang.Class[T]
        """

    def getSelectedValues(self) -> java.util.Set[T]:
        """
        Returns the set of acceptable (matching) Enum values that are acceptable to this constraint.
        
        :return: the set of acceptable (matching) Enum values that are acceptable to this constraint.
        :rtype: java.util.Set[T]
        """

    @property
    def selectedValues(self) -> java.util.Set[T]:
        ...

    @property
    def enumClass(self) -> java.lang.Class[T]:
        ...


class StringStartsWithColumnConstraint(StringColumnConstraint):
    """
    String column constraint for matching column values if they start with the constraint value pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, patternString: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param java.lang.String or str patternString: the string to use to create a "starts with" pattern.
        """


class StringEndsWithColumnConstraint(StringColumnConstraint):
    """
    String column constraint for matching column values if they end with the constraint value pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, patternString: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str patternString: the string to use to create an "ends with" pattern.
        """


class StringContainsColumnConstraint(StringColumnConstraint):
    """
    String column constraint for matching column values if they contain the constraint value pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, patternString: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param java.lang.String or str patternString: the string to use to create a "contains" pattern.
        """


class AtLeastDateColumnConstraint(SingleValueColumnConstraint[java.time.LocalDate]):
    """
    Column Constraint where acceptable column values are greater than or equal to some specified
    value of the column type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, minValue: java.time.LocalDate, editorProvider: docking.widgets.table.constraint.provider.EditorProvider[java.time.LocalDate]):
        """
        Constructs a new AtLeasDateColumnConstraint with a default name, default group and a minimum value
        
        :param java.time.LocalDate minValue: the value for which all acceptable column values must be greater than or equal.
        :param docking.widgets.table.constraint.provider.EditorProvider[java.time.LocalDate] editorProvider: an object that can provide a ConstraintEditor for this constraint type.
        """


class ColumnConstraintProvider(ghidra.util.classfinder.ExtensionPoint):
    """
    Extension point for introducing ColumnConstraints to the system.  File names must end 
    with 'ColumnConstraintProvider' in order to be found.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getColumnConstraints(self) -> java.util.Collection[ColumnConstraint[typing.Any]]:
        """
        Returns a collection of ColumnConstraints that will be used by the table column filtering
        feature to filter tables based on column values.
        
        :return: a collection of ColumnConstraints to be added as possible column filters.
        :rtype: java.util.Collection[ColumnConstraint[typing.Any]]
        """

    @property
    def columnConstraints(self) -> java.util.Collection[ColumnConstraint[typing.Any]]:
        ...


class StringIsNotEmptyColumnConstraint(ColumnConstraint[java.lang.String]):
    """
    String column constraint for matching when the value is not null and not the empty string.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ObjectToStringMapper", "AtMostColumnConstraint", "InRangeColumnConstraint", "AtMostDateColumnConstraint", "StringNotEndsWithColumnConstraint", "StringNotContainsColumnConstraint", "NotInRangeColumnConstraint", "AtLeastColumnConstraint", "StringNotMatchesColumnConstraint", "StringColumnConstraint", "RangeColumnConstraint", "SingleValueColumnConstraint", "MappedColumnConstraint", "StringMatchesColumnConstraint", "StringIsEmptyColumnConstraint", "NotInDateRangeColumnConstraint", "StringNotStartsWithColumnConstraint", "ColumnData", "ColumnTypeMapper", "TableFilterContext", "BooleanMatchColumnConstraint", "InDateRangeColumnConstraint", "ColumnConstraint", "EnumColumnConstraint", "StringStartsWithColumnConstraint", "StringEndsWithColumnConstraint", "StringContainsColumnConstraint", "AtLeastDateColumnConstraint", "ColumnConstraintProvider", "StringIsNotEmptyColumnConstraint"]
