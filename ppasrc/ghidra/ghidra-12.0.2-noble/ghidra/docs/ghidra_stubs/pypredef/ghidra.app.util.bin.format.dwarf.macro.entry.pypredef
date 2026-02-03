from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf.macro
import ghidra.program.database.sourcemap
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class DWARFMacroDefine(DWARFMacroInfoEntry):
    """
    Represents a "#define ...." macro element.
    """

    class MacroInfo(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, macro: typing.Union[java.lang.String, str], symbolName: typing.Union[java.lang.String, str], parameters: java.util.List[java.lang.String], isFunctionLike: typing.Union[jpype.JBoolean, bool], definition: typing.Union[java.lang.String, str]):
            ...

        def definition(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def isFunctionLike(self) -> bool:
            ...

        def macro(self) -> str:
            ...

        def parameters(self) -> java.util.List[java.lang.String]:
            ...

        def symbolName(self) -> str:
            ...

        @property
        def functionLike(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, lineNumber: typing.Union[jpype.JInt, int], defineString: typing.Union[java.lang.String, str], parent: ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader):
        ...

    @typing.overload
    def __init__(self, other: DWARFMacroInfoEntry):
        ...

    def getLineNumber(self) -> int:
        ...

    def getMacro(self) -> str:
        ...

    def getMacroInfo(self) -> DWARFMacroDefine.MacroInfo:
        ...

    @staticmethod
    def parseMacro(macroString: typing.Union[java.lang.String, str]) -> DWARFMacroDefine.MacroInfo:
        ...

    @property
    def macro(self) -> java.lang.String:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def macroInfo(self) -> DWARFMacroDefine.MacroInfo:
        ...


class DWARFMacroImport(DWARFMacroInfoEntry):
    """
    Represents the inclusion of macro entries from another macro header.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, other: DWARFMacroInfoEntry):
        ...

    def getImportedMacroHeader(self) -> ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader:
        ...

    def getOffset(self) -> int:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def importedMacroHeader(self) -> ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader:
        ...


class DWARFMacroStartFile(DWARFMacroInfoEntry):
    """
    Represents the start of a source file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, other: DWARFMacroInfoEntry):
        ...

    def getFileNumber(self) -> int:
        ...

    def getLineNumber(self) -> int:
        ...

    def getSourceFile(self) -> ghidra.program.database.sourcemap.SourceFile:
        ...

    @property
    def fileNumber(self) -> jpype.JInt:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def sourceFile(self) -> ghidra.program.database.sourcemap.SourceFile:
        ...


class DWARFMacroUndef(DWARFMacroDefine):
    """
    Represents a "#undef" macro element.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, other: DWARFMacroInfoEntry):
        ...


class DWARFMacroInfoEntry(java.lang.Object):
    """
    Represents a generic macro info entry, and can contain any macro entry element.
     
    
    Specific macro entry classes are derived from this and provide getters to ease fetching
    values that are expected for that class.  These classes are expected to implement a copy-ctor
    that accepts a DWARFMacroInfoEntry containing the raw data to be wrapped, and must be registered
    in :meth:`toSpecializedForm(DWARFMacroInfoEntry) <.toSpecializedForm>` method's switch() statement.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, opcode: ghidra.app.util.bin.format.dwarf.macro.DWARFMacroOpcode, rawOpcode: typing.Union[jpype.JInt, int], operandValues: jpype.JArray[ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue], macroHeader: ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader):
        ...

    def getName(self) -> str:
        ...

    def getOpcode(self) -> ghidra.app.util.bin.format.dwarf.macro.DWARFMacroOpcode:
        ...

    def getOperand(self, index: typing.Union[jpype.JInt, int], valueClass: java.lang.Class[T]) -> T:
        ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, macroHeader: ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader) -> DWARFMacroInfoEntry:
        """
        Reads a DWARF macro info entry from the stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` stream
        :param ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader macroHeader: the parent :obj:`DWARFMacroHeader`
        :return: a :obj:`DWARFMacroInfoEntry`, or subclass if element is a known opcode, or 
        ``null`` if the element was the end-of-list marker
        :rtype: DWARFMacroInfoEntry
        :raises IOException: if error reading or unknown opcode
        """

    @staticmethod
    def toSpecializedForm(genericEntry: DWARFMacroInfoEntry) -> DWARFMacroInfoEntry:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def opcode(self) -> ghidra.app.util.bin.format.dwarf.macro.DWARFMacroOpcode:
        ...


class DWARFMacroEndFile(DWARFMacroInfoEntry):
    """
    Represents the end of an included source file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, other: DWARFMacroInfoEntry):
        ...



__all__ = ["DWARFMacroDefine", "DWARFMacroImport", "DWARFMacroStartFile", "DWARFMacroUndef", "DWARFMacroInfoEntry", "DWARFMacroEndFile"]
