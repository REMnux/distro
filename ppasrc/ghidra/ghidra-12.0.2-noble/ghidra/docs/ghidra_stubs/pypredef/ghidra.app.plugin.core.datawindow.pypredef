from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.filter
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.util
import ghidra.util.table
import ghidra.util.table.field
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class DataWindowContext(docking.DefaultActionContext):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DataWindowFilterDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class FilterActionFilterListener(docking.widgets.filter.FilterListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class DataToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.listing.Data, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class DataRowObject(java.lang.Comparable[DataRowObject]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[DataRowObject, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class DataWindowProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class_: typing.ClassVar[java.lang.Class]
    ICON: typing.Final[javax.swing.Icon]


class DataWindowPlugin(ghidra.app.plugin.ProgramPlugin):

    @typing.type_check_only
    class DataTypeNameComparator(java.util.Comparator[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class Coverage(java.lang.Enum[DataWindowPlugin.Coverage]):

        class_: typing.ClassVar[java.lang.Class]
        PROGRAM: typing.Final[DataWindowPlugin.Coverage]
        SELECTION: typing.Final[DataWindowPlugin.Coverage]
        VIEW: typing.Final[DataWindowPlugin.Coverage]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DataWindowPlugin.Coverage:
            ...

        @staticmethod
        def values() -> jpype.JArray[DataWindowPlugin.Coverage]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DataRowObjectToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[DataRowObject, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class FilterAction(docking.action.ToggleDockingAction):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DataTableModel(ghidra.util.table.AddressBasedTableModel[DataRowObject]):

    @typing.type_check_only
    class DataKeyIterator(ghidra.util.LongIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataValueTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[DataRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TypeTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[DataRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SizeTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[DataRowObject, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class DataToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.listing.Data, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["DataWindowContext", "DataWindowFilterDialog", "DataToProgramLocationTableRowMapper", "DataRowObject", "DataRowObjectToAddressTableRowMapper", "DataWindowProvider", "DataWindowPlugin", "DataRowObjectToProgramLocationTableRowMapper", "FilterAction", "DataTableModel", "DataToAddressTableRowMapper"]
