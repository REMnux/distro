from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action.builder
import ghidra.app.plugin.core.decompiler.taint # type: ignore
import ghidra.framework.plugintool
import ghidra.pcode.exec_
import ghidra.program.model.address
import ghidra.program.model.data.ISF # type: ignore
import ghidra.program.model.listing
import ghidra.trace.model
import java.lang # type: ignore
import sarif.export # type: ignore


class EmulatorTaintState(ghidra.app.plugin.core.decompiler.taint.AbstractTaintState):
    """
    Container for all the decompiler elements the users "selects" via the menu.
    This data is used to build queries.
    """

    class KTV(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, key: typing.Union[java.lang.String, str], type: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str], displayName: typing.Union[java.lang.String, str]) -> None:
            ...

        def displayName(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def key(self) -> str:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> str:
            ...

        def value(self) -> str:
            ...


    class SetTaintAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Set Taint"
        DESCRIPTION: typing.Final = "Set taint for given varnode"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "set_taint"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompiler.taint.TaintPlugin) -> None:
        ...

    def queryIndex(self, program: ghidra.program.model.listing.Program, tool: ghidra.framework.plugintool.PluginTool, queryType: ghidra.app.plugin.core.decompiler.taint.TaintState.QueryType) -> bool:
        """
        Build the query string, save it to a file the users selects, and run the
        engine using the index and the query that is saved to the file.
        """

    def rebase(self, target: ghidra.program.model.address.Address, orig: ghidra.pcode.exec_.PcodeProgram) -> ghidra.pcode.exec_.PcodeProgram:
        ...

    def setTaint(self, type: ghidra.app.plugin.core.decompiler.taint.TaintState.MarkType, mark: ghidra.app.plugin.core.decompiler.taint.TaintLabel) -> None:
        ...


class ExtKeyValue(ghidra.program.model.data.ISF.IsfObject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ktv: EmulatorTaintState.KTV) -> None:
        ...


class AngrTaintState(ghidra.app.plugin.core.decompiler.taint.AbstractTaintState):
    """
    Container for all the decompiler elements the users "selects" via the menu. This data is used to
    build queries.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompiler.taint.TaintPlugin) -> None:
        ...


class SarifKeyValueWriter(sarif.export.AbstractExtWriter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ktv: EmulatorTaintState.KTV, wll: sarif.export.WrappedLogicalLocation) -> None:
        ...


class SarifLogicalLocationWriter(sarif.export.AbstractExtWriter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, entry: java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, java.lang.String], fmgr: ghidra.program.model.listing.FunctionManager) -> None:
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getKey(self) -> str:
        ...

    def getLogicalLocation(self) -> sarif.export.WrappedLogicalLocation:
        ...

    def getType(self) -> str:
        ...

    def getValue(self) -> str:
        ...

    @property
    def logicalLocation(self) -> sarif.export.WrappedLogicalLocation:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def type(self) -> java.lang.String:
        ...

    @property
    def value(self) -> java.lang.String:
        ...

    @property
    def key(self) -> java.lang.String:
        ...



__all__ = ["EmulatorTaintState", "ExtKeyValue", "AngrTaintState", "SarifKeyValueWriter", "SarifLogicalLocationWriter"]
