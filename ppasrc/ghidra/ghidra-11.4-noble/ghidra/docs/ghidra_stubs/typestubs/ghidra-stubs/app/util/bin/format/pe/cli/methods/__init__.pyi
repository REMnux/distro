from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.program.model.address
import ghidra.program.model.data
import java.lang # type: ignore


class CliMethodExtraSections(ghidra.app.util.bin.StructConverter):

    @typing.type_check_only
    class ExtraSection(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        isEHTable: jpype.JBoolean
        isFat: jpype.JBoolean
        hasMoreSections: jpype.JBoolean
        dataSize: jpype.JInt
        isFilterBasedException: jpype.JBoolean
        CorILMethod_Sect_EHTable: typing.Final = 1
        CorILMethod_Sect_OptIL: typing.Final = 2
        CorILMethod_Sect_FatFormat: typing.Final = 64
        CorILMethod_Sect_MoreSects: typing.Final = 128
        COR_ILEXCEPTION_CLAUSE_EXCEPTION: typing.Final = 0
        COR_ILEXCEPTION_CLAUSE_FILTER: typing.Final = 1
        COR_ILEXCEPTION_CLAUSE_FINALLY: typing.Final = 2
        COR_ILEXCEPTION_CLAUSE_FAULT: typing.Final = 4

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...

        def getFatExceptionClauseDataType(self) -> ghidra.program.model.data.StructureDataType:
            ...

        def getSmallExceptionClauseDataType(self) -> ghidra.program.model.data.StructureDataType:
            ...

        def toDataType(self) -> ghidra.program.model.data.DataType:
            ...

        @property
        def fatExceptionClauseDataType(self) -> ghidra.program.model.data.StructureDataType:
            ...

        @property
        def smallExceptionClauseDataType(self) -> ghidra.program.model.data.StructureDataType:
            ...


    class_: typing.ClassVar[java.lang.Class]
    PATH: typing.Final = "/PE/CLI/Methods/ExtraSections"

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...


class CliMethodDef(ghidra.app.util.bin.StructConverter):

    class HeaderFormat(java.lang.Enum[CliMethodDef.HeaderFormat]):

        class_: typing.ClassVar[java.lang.Class]
        Fat: typing.Final[CliMethodDef.HeaderFormat]
        Tiny: typing.Final[CliMethodDef.HeaderFormat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CliMethodDef.HeaderFormat:
            ...

        @staticmethod
        def values() -> jpype.JArray[CliMethodDef.HeaderFormat]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    PATH: typing.Final = "/PE/CLI/Methods/MethodDefs"

    def __init__(self, addr: ghidra.program.model.address.Address, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getHeaderFormat(self) -> CliMethodDef.HeaderFormat:
        ...

    def getMethodSize(self) -> int:
        ...

    def hasLocals(self) -> bool:
        ...

    def hasMoreSections(self) -> bool:
        ...

    @property
    def headerFormat(self) -> CliMethodDef.HeaderFormat:
        ...

    @property
    def methodSize(self) -> jpype.JInt:
        ...



__all__ = ["CliMethodExtraSections", "CliMethodDef"]
