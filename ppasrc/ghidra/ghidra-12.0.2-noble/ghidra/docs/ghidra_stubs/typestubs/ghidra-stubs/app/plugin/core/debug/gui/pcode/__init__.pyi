from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.app.plugin.core.debug
import ghidra.app.util.pcode
import ghidra.base.widgets.table
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.pcode.exec_
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.pcode
import ghidra.trace.model
import ghidra.util.table.column
import java.lang # type: ignore
import java.math # type: ignore


T = typing.TypeVar("T")


class EnumPcodeRow(java.lang.Enum[EnumPcodeRow], PcodeRow):

    class_: typing.ClassVar[java.lang.Class]
    NO_THREAD: typing.Final[EnumPcodeRow]
    DECODE: typing.Final[EnumPcodeRow]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EnumPcodeRow:
        ...

    @staticmethod
    def values() -> jpype.JArray[EnumPcodeRow]:
        ...


class BranchPcodeRow(PcodeRow):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sequence: typing.Union[jpype.JInt, int], fromSeq: typing.Union[jpype.JInt, int]):
        ...


class FallthroughPcodeRow(PcodeRow):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sequence: typing.Union[jpype.JInt, int], isNext: typing.Union[jpype.JBoolean, bool], label: typing.Union[java.lang.String, str]):
        ...


class UniqueRow(java.lang.Object):

    class RefType(java.lang.Enum[UniqueRow.RefType]):

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[UniqueRow.RefType]
        READ: typing.Final[UniqueRow.RefType]
        WRITE: typing.Final[UniqueRow.RefType]
        READ_WRITE: typing.Final[UniqueRow.RefType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> UniqueRow.RefType:
            ...

        @staticmethod
        def values() -> jpype.JArray[UniqueRow.RefType]:
            ...


    class ConcretizedState(java.lang.Object, typing.Generic[T]):
        """
        Putting these related methods, all using a common type, into a nested class allows us to
        introduce ``<T>``, essentially a "universal type."
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, state: ghidra.pcode.exec_.PcodeExecutorState[T], arithmetic: ghidra.pcode.exec_.PcodeArithmetic[T]):
            ...

        def getBytes(self, vn: ghidra.program.model.pcode.Varnode) -> jpype.JArray[jpype.JByte]:
            ...

        def getValue(self, vn: ghidra.program.model.pcode.Varnode) -> java.math.BigInteger:
            ...

        @property
        def bytes(self) -> jpype.JArray[jpype.JByte]:
            ...

        @property
        def value(self) -> java.math.BigInteger:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerPcodeStepperProvider, language: ghidra.program.model.lang.Language, state: ghidra.pcode.exec_.PcodeExecutorState[T], arithmetic: ghidra.pcode.exec_.PcodeArithmetic[T], vn: ghidra.program.model.pcode.Varnode):
        ...

    def getBytes(self) -> str:
        """
        Renders the raw bytes as space-separated hexadecimal-digit pairs, if concrete
         
         
        
        If the state's concrete piece cannot be extracted by the machine's arithmetic, this simply
        returns ``"(not concrete)"``.
        
        :return: the byte string
        :rtype: str
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getName(self) -> str:
        ...

    def getRefType(self) -> UniqueRow.RefType:
        ...

    def getValue(self) -> java.math.BigInteger:
        """
        Extract the concrete part of the variable as an unsigned big integer
        
        :return: the value, or null if the value cannot be made concrete
        :rtype: java.math.BigInteger
        """

    def getValueRepresentation(self) -> str:
        ...

    def setDataType(self, dataType: ghidra.program.model.data.DataType):
        ...

    @property
    def valueRepresentation(self) -> java.lang.String:
        ...

    @property
    def bytes(self) -> java.lang.String:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @dataType.setter
    def dataType(self, value: ghidra.program.model.data.DataType):
        ...

    @property
    def refType(self) -> UniqueRow.RefType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def value(self) -> java.math.BigInteger:
        ...


class DebuggerPcodeStepperProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class PcodeTableColumns(java.lang.Enum[DebuggerPcodeStepperProvider.PcodeTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerPcodeStepperProvider.PcodeTableColumns, PcodeRow]):

        class_: typing.ClassVar[java.lang.Class]
        SEQUENCE: typing.Final[DebuggerPcodeStepperProvider.PcodeTableColumns]
        LABEL: typing.Final[DebuggerPcodeStepperProvider.PcodeTableColumns]
        CODE: typing.Final[DebuggerPcodeStepperProvider.PcodeTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerPcodeStepperProvider.PcodeTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerPcodeStepperProvider.PcodeTableColumns]:
            ...


    @typing.type_check_only
    class PcodeTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerPcodeStepperProvider.PcodeTableColumns, PcodeRow]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    @typing.type_check_only
    class UniqueTableColumns(java.lang.Enum[DebuggerPcodeStepperProvider.UniqueTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerPcodeStepperProvider.UniqueTableColumns, UniqueRow]):

        class_: typing.ClassVar[java.lang.Class]
        REF: typing.Final[DebuggerPcodeStepperProvider.UniqueTableColumns]
        UNIQUE: typing.Final[DebuggerPcodeStepperProvider.UniqueTableColumns]
        BYTES: typing.Final[DebuggerPcodeStepperProvider.UniqueTableColumns]
        VALUE: typing.Final[DebuggerPcodeStepperProvider.UniqueTableColumns]
        TYPE: typing.Final[DebuggerPcodeStepperProvider.UniqueTableColumns]
        REPR: typing.Final[DebuggerPcodeStepperProvider.UniqueTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerPcodeStepperProvider.UniqueTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerPcodeStepperProvider.UniqueTableColumns]:
            ...


    @typing.type_check_only
    class UniqueTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerPcodeStepperProvider.UniqueTableColumns, UniqueRow]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    @typing.type_check_only
    class UniqueDataTypeEditor(ghidra.base.widgets.table.DataTypeTableCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class CounterBackgroundCellRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PcodeCellRenderer(DebuggerPcodeStepperProvider.CounterBackgroundCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UniqueRefCellRenderer(ghidra.util.table.column.AbstractGColumnRenderer[UniqueRow.RefType]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToPcodeRowsAppender(ghidra.app.util.pcode.AbstractAppender[java.util.List[PcodeRow]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, frame: ghidra.pcode.exec_.PcodeFrame):
            ...


    @typing.type_check_only
    class PcodeRowHtmlFormatter(ghidra.app.util.pcode.AbstractPcodeFormatter[java.util.List[PcodeRow], DebuggerPcodeStepperProvider.ToPcodeRowsAppender]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, frame: ghidra.pcode.exec_.PcodeFrame):
            ...


    @typing.type_check_only
    class ForRadixTraceListener(ghidra.trace.model.TraceDomainObjectListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerPcodeStepperPlugin):
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...


class PcodeRow(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getCode(self) -> str:
        ...

    def getLabel(self) -> str:
        ...

    def getOp(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def getSequence(self) -> int:
        ...

    def isNext(self) -> bool:
        ...

    @property
    def next(self) -> jpype.JBoolean:
        ...

    @property
    def sequence(self) -> jpype.JInt:
        ...

    @property
    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    @property
    def code(self) -> java.lang.String:
        ...

    @property
    def label(self) -> java.lang.String:
        ...


class DebuggerPcodeStepperPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class OpPcodeRow(PcodeRow):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, op: ghidra.program.model.pcode.PcodeOp, isNext: typing.Union[jpype.JBoolean, bool], label: typing.Union[java.lang.String, str], code: typing.Union[java.lang.String, str]):
        ...



__all__ = ["EnumPcodeRow", "BranchPcodeRow", "FallthroughPcodeRow", "UniqueRow", "DebuggerPcodeStepperProvider", "PcodeRow", "DebuggerPcodeStepperPlugin", "OpPcodeRow"]
