from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf
import ghidra.app.util.bin.format.dwarf.attribs
import ghidra.app.util.bin.format.dwarf.line
import ghidra.app.util.bin.format.dwarf.macro.entry
import java.lang # type: ignore
import java.util # type: ignore


class DWARFMacroHeader(java.lang.Object):
    """
    Represents a DWARF Macro Header
    """

    class_: typing.ClassVar[java.lang.Class]
    EMTPY: typing.Final[DWARFMacroHeader]

    def __init__(self, startOffset: typing.Union[jpype.JLong, int], version: typing.Union[jpype.JInt, int], flags: typing.Union[jpype.JInt, int], debug_line_offset: typing.Union[jpype.JLong, int], intSize: typing.Union[jpype.JInt, int], entriesStartOffset: typing.Union[jpype.JLong, int], cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit, line: ghidra.app.util.bin.format.dwarf.line.DWARFLine, opcodeMap: collections.abc.Mapping):
        ...

    def getCompilationUnit(self) -> ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit:
        ...

    def getDebug_line_offset(self) -> int:
        ...

    def getEntries(self) -> java.util.List[ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroInfoEntry]:
        ...

    def getEntriesStartOffset(self) -> int:
        ...

    def getIntSize(self) -> int:
        ...

    def getLine(self) -> ghidra.app.util.bin.format.dwarf.line.DWARFLine:
        ...

    def getOpcodeMap(self) -> java.util.Map[java.lang.Integer, java.util.List[ghidra.app.util.bin.format.dwarf.attribs.DWARFForm]]:
        ...

    @staticmethod
    def readMacroEntries(reader: ghidra.app.util.bin.BinaryReader, macroHeader: DWARFMacroHeader) -> java.util.List[ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroInfoEntry]:
        ...

    @staticmethod
    def readV5(reader: ghidra.app.util.bin.BinaryReader, cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit) -> DWARFMacroHeader:
        """
        Reads a ``DWARFMacroHeader`` from a stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: source of bytes
        :param ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit cu: :obj:`DWARFCompilationUnit` that pointed to this macro header
        :return: macro header, never null
        :rtype: DWARFMacroHeader
        :raises IOException: if reading fails
        """

    @property
    def entries(self) -> java.util.List[ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroInfoEntry]:
        ...

    @property
    def compilationUnit(self) -> ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit:
        ...

    @property
    def entriesStartOffset(self) -> jpype.JLong:
        ...

    @property
    def debug_line_offset(self) -> jpype.JLong:
        ...

    @property
    def line(self) -> ghidra.app.util.bin.format.dwarf.line.DWARFLine:
        ...

    @property
    def opcodeMap(self) -> java.util.Map[java.lang.Integer, java.util.List[ghidra.app.util.bin.format.dwarf.attribs.DWARFForm]]:
        ...

    @property
    def intSize(self) -> jpype.JInt:
        ...


class DWARFMacroOpcode(java.lang.Enum[DWARFMacroOpcode]):
    """
    DWARF macro entry opcodes and their expected operand types.
     
    
    DWARF5
    """

    class Def(ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeDef[DWARFMacroOpcode]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, opcode: DWARFMacroOpcode, rawOpcode: typing.Union[jpype.JInt, int], form: ghidra.app.util.bin.format.dwarf.attribs.DWARFForm):
            ...


    class_: typing.ClassVar[java.lang.Class]
    MACRO_UNIT_TERMINATOR: typing.Final[DWARFMacroOpcode]
    """
    This is not an official opcode in the DWARF standard, but represents the
    entry with opcode 0 that terminates a macro unit.
    """

    DW_MACRO_define: typing.Final[DWARFMacroOpcode]
    DW_MACRO_undef: typing.Final[DWARFMacroOpcode]
    DW_MACRO_start_file: typing.Final[DWARFMacroOpcode]
    DW_MACRO_end_file: typing.Final[DWARFMacroOpcode]
    DW_MACRO_define_strp: typing.Final[DWARFMacroOpcode]
    DW_MACRO_undef_strp: typing.Final[DWARFMacroOpcode]
    DW_MACRO_import: typing.Final[DWARFMacroOpcode]
    DW_MACRO_define_sup: typing.Final[DWARFMacroOpcode]
    DW_MACRO_undef_sup: typing.Final[DWARFMacroOpcode]
    DW_MACRO_import_sup: typing.Final[DWARFMacroOpcode]
    DW_MACRO_define_strx: typing.Final[DWARFMacroOpcode]
    DW_MACRO_undef_strx: typing.Final[DWARFMacroOpcode]
    defaultOpcodeOperandMap: typing.Final[java.util.Map[java.lang.Integer, java.util.List[ghidra.app.util.bin.format.dwarf.attribs.DWARFForm]]]

    def getDescription(self) -> str:
        ...

    def getOperandForms(self) -> jpype.JArray[ghidra.app.util.bin.format.dwarf.attribs.DWARFForm]:
        ...

    def getRawOpcode(self) -> int:
        ...

    @staticmethod
    def of(opcodeVal: typing.Union[jpype.JInt, int]) -> DWARFMacroOpcode:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFMacroOpcode:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFMacroOpcode]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def operandForms(self) -> jpype.JArray[ghidra.app.util.bin.format.dwarf.attribs.DWARFForm]:
        ...

    @property
    def rawOpcode(self) -> jpype.JInt:
        ...



__all__ = ["DWARFMacroHeader", "DWARFMacroOpcode"]
