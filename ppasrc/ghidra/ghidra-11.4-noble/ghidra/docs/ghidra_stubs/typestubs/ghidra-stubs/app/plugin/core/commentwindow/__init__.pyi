from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.util.table
import ghidra.util.table.field
import java.lang # type: ignore


class CommentWindowPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class CommentTableModel(ghidra.util.table.AddressBasedTableModel[CommentRowObject]):

    @typing.type_check_only
    class TypeTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[CommentRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CommentTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[CommentRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class CommentRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[CommentRowObject, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CommentWindowContext(docking.DefaultActionContext):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CommentWindowProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    Provider for the comment window.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getTable(self) -> ghidra.util.table.GhidraTable:
        ...

    @property
    def table(self) -> ghidra.util.table.GhidraTable:
        ...


class CommentRowObjectToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[CommentRowObject, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class CommentRowObject(java.lang.Comparable[CommentRowObject]):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["CommentWindowPlugin", "CommentTableModel", "CommentRowObjectToAddressTableRowMapper", "CommentWindowContext", "CommentWindowProvider", "CommentRowObjectToProgramLocationTableRowMapper", "CommentRowObject"]
