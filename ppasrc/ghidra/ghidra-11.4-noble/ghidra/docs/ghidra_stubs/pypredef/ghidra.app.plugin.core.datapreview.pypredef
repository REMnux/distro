from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.dnd
import docking.widgets.table
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.mem
import ghidra.util.table
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class DataTypePreviewPlugin(ghidra.app.plugin.ProgramPlugin):

    @typing.type_check_only
    class DTPPComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class DTPPDroppable(docking.dnd.Droppable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DTPPScrollPane(javax.swing.JScrollPane):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DTPPTable(ghidra.util.table.GhidraTable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DTPPMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DTPPTableModel(docking.widgets.table.AbstractSortedTableModel[Preview]):

        @typing.type_check_only
        class NamePreviewColumnComparator(java.util.Comparator[Preview]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class PreviewColumnComparator(java.util.Comparator[Preview]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class DataTypePreview(Preview):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class Preview(java.lang.Comparable[Preview]):

    class_: typing.ClassVar[java.lang.Class]

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getName(self) -> str:
        ...

    def getPreview(self, memory: ghidra.program.model.mem.Memory, addr: ghidra.program.model.address.Address) -> str:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


@typing.type_check_only
class DataTypeComponentPreview(Preview):

    class_: typing.ClassVar[java.lang.Class]

    def compareTo(self, p: Preview) -> int:
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getName(self) -> str:
        ...

    def getPreview(self, memory: ghidra.program.model.mem.Memory, addr: ghidra.program.model.address.Address) -> str:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...



__all__ = ["DataTypePreviewPlugin", "DataTypePreview", "Preview", "DataTypeComponentPreview"]
