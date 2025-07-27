from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table.constraint
import docking.widgets.table.constrainteditor
import java.lang # type: ignore
import java.time # type: ignore


T = typing.TypeVar("T")


class LongEditorProvider(IntegerEditorProvider[java.lang.Long]):
    """
    Class for providing editor for long columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class StringColumnConstraintProvider(docking.widgets.table.constraint.ColumnConstraintProvider):
    """
    Provides String related column constraints.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IntegerEditorProvider(EditorProvider[T], typing.Generic[T]):
    """
    Base class for providing single value numeric editors.
    """

    class_: typing.ClassVar[java.lang.Class]


class IntegerRangeEditorProvider(IntegerEditorProvider[T], typing.Generic[T]):
    """
    Base class for providing numeric range editors.
    """

    class_: typing.ClassVar[java.lang.Class]


class NumberColumnConstraintProvider(docking.widgets.table.constraint.ColumnConstraintProvider):
    """
    Provides number related column constraints.
    """

    @typing.type_check_only
    class ByteEditorProvider(IntegerEditorProvider[java.lang.Byte]):
        """
        Class for providing editor for byte columns.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ShortEditorProvider(IntegerEditorProvider[java.lang.Short]):
        """
        Class for providing editor for short columns.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class IntEditorProvider(IntegerEditorProvider[java.lang.Integer]):
        """
        Class for providing editor for int columns.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ByteRangeEditorProvider(IntegerRangeEditorProvider[java.lang.Byte]):
        """
        Class for providing range editor for byte columns.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ShortRangeEditorProvider(IntegerRangeEditorProvider[java.lang.Short]):
        """
        Class for providing range editor for short columns.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class IntRangeEditorProvider(IntegerRangeEditorProvider[java.lang.Integer]):
        """
        Class for providing range editor for int columns.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class FloatingEditorProvider(EditorProvider[java.lang.Double]):
        """
        Base class for providing single floating point value editors.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FloatingRangeEditorProvider(EditorProvider[java.lang.Double]):
        """
        Base class for providing floating point range editors.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DateColumnConstraintProvider(docking.widgets.table.constraint.ColumnConstraintProvider):
    """
    Provides Date related column constraints.
    """

    @typing.type_check_only
    class LocalDateEditorProvider(EditorProvider[java.time.LocalDate]):
        """
        class for providing a date editor
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocalDateRangeEditorProvider(DateColumnConstraintProvider.LocalDateEditorProvider):
        """
        class for providing a date range editor.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_DATE: typing.Final[java.time.LocalDate]
    """
    Date object representing an invalid date.
    """


    def __init__(self):
        ...


class DateColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[java.util.Date, java.time.LocalDate]):
    """
    Converts Date Column objects to LocalDate objects so that column gets LocalDate type column
    filters
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FloatColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[java.lang.Float, java.lang.Double]):
    """
    Converts Float Column objects to Double objects so that column gets Double type column
    filters
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BooleanMatchColumnConstraintProvider(docking.widgets.table.constraint.ColumnConstraintProvider):
    """
    Provides boolean related column constraints.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LongRangeEditorProvider(IntegerRangeEditorProvider[java.lang.Long]):
    """
    Class for providing range editor for long columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EditorProvider(java.lang.Object, typing.Generic[T]):
    """
    Class used by some generic constraints to fulfill their requirement to provide and editor. These types
    of constraints are passed in an EditorProvider in their constructor.  This allows these constraint
    types to be created using generics without subclassing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getEditor(self, columnConstraint: docking.widgets.table.constraint.ColumnConstraint[T], columnData: docking.widgets.table.constraint.ColumnData[T]) -> docking.widgets.table.constrainteditor.ColumnConstraintEditor[T]:
        """
        Returns an editor initialized to the given columnConstraint.
        
        :param docking.widgets.table.constraint.ColumnConstraint[T] columnConstraint: the constraint whose value is to be edited.
        :param docking.widgets.table.constraint.ColumnData[T] columnData: the context of the data in the table.
        :return: an editor initialized to the given columnConstraint.
        :rtype: docking.widgets.table.constrainteditor.ColumnConstraintEditor[T]
        """

    def parseValue(self, value: typing.Union[java.lang.String, str], dataSource: java.lang.Object) -> T:
        """
        Parses the given string into a T object.
        
        :param java.lang.String or str value: the value to parse.
        :param java.lang.Object dataSource: the table's context object.
        :return: a new T object created by parsing the given string.
        :rtype: T
        """

    def toString(self, value: T) -> str:
        """
        Converts the T value into a string that can be parsed back by the :meth:`parseValue(String, Object) <.parseValue>` method.
        
        :param T value: the value to convert to a parsable string.
        :return: The parsable string fromthe T value.
        :rtype: str
        """



__all__ = ["LongEditorProvider", "StringColumnConstraintProvider", "IntegerEditorProvider", "IntegerRangeEditorProvider", "NumberColumnConstraintProvider", "DateColumnConstraintProvider", "DateColumnTypeMapper", "FloatColumnTypeMapper", "BooleanMatchColumnConstraintProvider", "LongRangeEditorProvider", "EditorProvider"]
