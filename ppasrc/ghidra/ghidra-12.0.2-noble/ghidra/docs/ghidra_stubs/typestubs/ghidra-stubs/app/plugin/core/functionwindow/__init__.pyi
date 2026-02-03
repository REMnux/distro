from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.context
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import java.lang # type: ignore
import javax.swing # type: ignore


class FunctionToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.listing.Function, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionRowObjectToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[FunctionRowObject, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionRowObject(java.lang.Comparable[FunctionRowObject]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function):
        ...

    def getFunction(self) -> ghidra.program.model.listing.Function:
        ...

    def getKey(self) -> int:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...


class FunctionWindowPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class FunctionRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[FunctionRowObject, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionRowObjectToFunctionTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[FunctionRowObject, ghidra.program.model.listing.Function]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionTableModel(ghidra.util.table.AddressBasedTableModel[FunctionRowObject]):

    @typing.type_check_only
    class FunctionKeyIterator(ghidra.util.LongIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NameTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[FunctionRowObject, java.lang.String]):

        @typing.type_check_only
        class FunctionNameRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[java.lang.String]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program):
        ...

    def getKeyCount(self) -> int:
        ...

    def reload(self, newProgram: ghidra.program.model.listing.Program):
        ...

    @property
    def keyCount(self) -> jpype.JInt:
        ...


class FunctionWindowProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    Provider that displays all functions in the selected program
    """

    @typing.type_check_only
    class FunctionWindowActionContext(docking.DefaultActionContext, ghidra.app.context.FunctionSupplierContext):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ICON: typing.Final[javax.swing.Icon]


class FunctionToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.listing.Function, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["FunctionToAddressTableRowMapper", "FunctionRowObjectToProgramLocationTableRowMapper", "FunctionRowObject", "FunctionWindowPlugin", "FunctionRowObjectToAddressTableRowMapper", "FunctionRowObjectToFunctionTableRowMapper", "FunctionTableModel", "FunctionWindowProvider", "FunctionToProgramLocationTableRowMapper"]
