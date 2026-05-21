from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import docking.widgets.table
import docking.widgets.table.threaded
import ghidra.framework.plugintool
import ghidra.util.table.column
import java.lang # type: ignore


@typing.type_check_only
class AbstractColumnAdapter(docking.widgets.table.AbstractDynamicTableColumnStub[db.DBRecord, java.lang.Object]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LongRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.Object]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class BinaryColumnAdapter(AbstractColumnAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class BooleanColumnAdapter(AbstractColumnAdapter):

    @typing.type_check_only
    class BooleanRenderer(docking.widgets.table.GBooleanCellRenderer, ghidra.util.table.column.GColumnRenderer[java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ByteColumnAdapter(AbstractColumnAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DbSmallTableModel(docking.widgets.table.threaded.ThreadedTableModel[db.DBRecord, java.lang.Object]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, table: db.Table) -> None:
        ...


class IntegerColumnAdapter(AbstractColumnAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LongColumnAdapter(AbstractColumnAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ShortColumnAdapter(AbstractColumnAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class StringColumnAdapter(AbstractColumnAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["AbstractColumnAdapter", "LongRenderer", "BinaryColumnAdapter", "BooleanColumnAdapter", "ByteColumnAdapter", "DbSmallTableModel", "IntegerColumnAdapter", "LongColumnAdapter", "ShortColumnAdapter", "StringColumnAdapter"]
