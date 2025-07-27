from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import ghidra.util.state
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class MySwitchAnalyzer(ghidra.util.state.FunctionAnalyzer):

    @typing.type_check_only
    class MultipleRegInputsException(java.lang.RuntimeException):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    @staticmethod
    def analyze(program: ghidra.program.model.listing.Program, functionEntry: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> ghidra.util.state.ResultsState:
        ...

    def dataReference(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], storageVarnode: ghidra.program.model.pcode.Varnode, refType: ghidra.program.model.symbol.RefType, monitor: ghidra.util.task.TaskMonitor):
        ...

    def indirectDataReference(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], offsetVarnode: ghidra.program.model.pcode.Varnode, size: typing.Union[jpype.JInt, int], storageSpaceID: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def resolvedFlow(self, op: ghidra.program.model.pcode.PcodeOp, opIndex: java.lang.Object, destAddr: ghidra.program.model.address.Address, currentState: ghidra.util.state.ContextState, results: ghidra.util.state.ResultsState, monitor: ghidra.util.task.TaskMonitor) -> bool:
        ...

    @typing.overload
    def resolvedFlow(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], destAddr: ghidra.program.model.address.Address, currentState: ghidra.util.state.ContextState, results: ghidra.util.state.ResultsState, monitor: ghidra.util.task.TaskMonitor) -> bool:
        ...

    @typing.overload
    def stackReference(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], stackOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], storageSpaceID: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def stackReference(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], computedStackOffset: ghidra.util.state.VarnodeOperation, size: typing.Union[jpype.JInt, int], storageSpaceID: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def unresolvedIndirectFlow(self, op: ghidra.program.model.pcode.PcodeOp, opIndex: java.lang.Object, destination: ghidra.program.model.pcode.Varnode, currentState: ghidra.util.state.ContextState, results: ghidra.util.state.ResultsState, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.program.model.address.Address]:
        ...

    @typing.overload
    def unresolvedIndirectFlow(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], destination: ghidra.program.model.pcode.Varnode, currentState: ghidra.util.state.ContextState, results: ghidra.util.state.ResultsState, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.program.model.address.Address]:
        ...


class Switch(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RelativeJumpTableSwitch(Switch):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, jumpBase: ghidra.program.model.address.Address, offset: TableEntry):
        ...


class TableEntry(Switch):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class TableEntryAddress(Switch):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ComputedTableOffset(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["MySwitchAnalyzer", "Switch", "RelativeJumpTableSwitch", "TableEntry", "TableEntryAddress", "ComputedTableOffset"]
