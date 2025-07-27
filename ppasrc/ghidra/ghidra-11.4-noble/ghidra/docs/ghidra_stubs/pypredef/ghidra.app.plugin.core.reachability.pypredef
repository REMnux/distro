from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.graph
import ghidra.util.datastruct
import ghidra.util.table
import java.lang # type: ignore
import java.util # type: ignore


class FunctionReachabilityTableModel(ghidra.util.table.GhidraProgramTableModel[FunctionReachabilityResult]):

    @typing.type_check_only
    class PassThroughAccumulator(ghidra.util.datastruct.Accumulator[java.util.List[FRVertex]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FromFunctionTableColumn(docking.widgets.table.AbstractDynamicTableColumn[FunctionReachabilityResult, java.lang.String, ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToFunctionTableColumn(docking.widgets.table.AbstractDynamicTableColumn[FunctionReachabilityResult, java.lang.String, ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PathLengthTableColumn(docking.widgets.table.AbstractDynamicTableColumn[FunctionReachabilityResult, java.lang.Integer, ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class FunctionReachabilityProvider(docking.ComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionReachabilityPlugin):
        ...


@typing.type_check_only
class FunctionReachabilityResult(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getPathLength(self) -> int:
        ...

    @property
    def pathLength(self) -> jpype.JInt:
        ...


@typing.type_check_only
class FRVertex(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FRPathsModel(ghidra.util.table.AddressBasedTableModel[FRVertex]):

    @typing.type_check_only
    class FunctionTableColumn(docking.widgets.table.AbstractDynamicTableColumn[FRVertex, java.lang.String, ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FRPreviewTableColumn(docking.widgets.table.AbstractDynamicTableColumn[FRVertex, ghidra.util.table.PreviewTableCellData, ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class FunctionReachabilityPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class FREdge(ghidra.graph.GEdge[FRVertex]):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["FunctionReachabilityTableModel", "FunctionReachabilityProvider", "FunctionReachabilityResult", "FRVertex", "FRPathsModel", "FunctionReachabilityPlugin", "FREdge"]
