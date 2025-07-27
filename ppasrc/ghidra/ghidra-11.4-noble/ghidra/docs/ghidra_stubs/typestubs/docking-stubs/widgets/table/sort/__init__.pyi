from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class RowBasedColumnComparator(java.util.Comparator[T], typing.Generic[T]):
    """
    A comparator for a specific column that will take in a T row object, extract the value
    for the given column and then call the give comparator
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, model: docking.widgets.table.RowObjectTableModel[T], sortColumn: typing.Union[jpype.JInt, int], comparator: java.util.Comparator[java.lang.Object]):
        """
        Constructs this class with the given column comparator that will get called after the
        given row is converted to the column value for the given sort column
        
        :param docking.widgets.table.RowObjectTableModel[T] model: the table model using this comparator
        :param jpype.JInt or int sortColumn: the column being sorted
        :param java.util.Comparator[java.lang.Object] comparator: the column comparator to use for sorting
        """

    @typing.overload
    def __init__(self, model: docking.widgets.table.RowObjectTableModel[T], sortColumn: typing.Union[jpype.JInt, int], comparator: java.util.Comparator[java.lang.Object], backupRowComparator: java.util.Comparator[java.lang.Object]):
        """
        This version of the constructor is used for the default case where the client will 
        supply a backup row comparator that will get called if the given column comparator returns
        a '0' value.
        
        :param docking.widgets.table.RowObjectTableModel[T] model: the table model using this comparator
        :param jpype.JInt or int sortColumn: the column being sorted
        :param java.util.Comparator[java.lang.Object] comparator: the column comparator to use for sorting
        :param java.util.Comparator[java.lang.Object] backupRowComparator: the backup row comparator
        """


class ColumnRenderedValueBackupComparator(java.util.Comparator[java.lang.Object], typing.Generic[T]):
    """
    A special version of the backup comparator that uses the column's rendered value for 
    the backup sort, rather the just ``toString``, which is what the default parent
    table model will do.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: docking.widgets.table.DynamicColumnTableModel[T], sortColumn: typing.Union[jpype.JInt, int]):
        ...


class DefaultColumnComparator(java.util.Comparator[java.lang.Object]):
    """
    A column comparator that is used when columns do not supply their own comparator.   This
    comparator will use the natural sorting (i.e., the value implements Comparable), 
    defaulting to the String representation for the given value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["RowBasedColumnComparator", "ColumnRenderedValueBackupComparator", "DefaultColumnComparator"]
