from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class BindingTable(OpcodeTable):
    """
    A Mach-O binding table
    """

    class Binding(java.lang.Object):
        """
        A piece of binding information from a :obj:`BindingTable`
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            """
            Creates a new :obj:`Binding`
            """

        @typing.overload
        def __init__(self, binding: BindingTable.Binding):
            """
            Creates a copy of the given :obj:`Binding`
            
            :param BindingTable.Binding binding: The :obj:`Binding` to copy
            """

        def getAddend(self) -> int:
            """
            :return: The addend
            :rtype: int
            """

        def getLibraryOrdinal(self) -> int:
            """
            :return: The library ordinal
            :rtype: int
            """

        def getSegmentIndex(self) -> int:
            """
            :return: The segment index
            :rtype: int
            """

        def getSegmentOffset(self) -> int:
            """
            :return: The segment offset
            :rtype: int
            """

        def getSymbolName(self) -> str:
            """
            :return: The symbol name
            :rtype: str
            """

        def getType(self) -> int:
            """
            :return: The type
            :rtype: int
            """

        def getUnknownOpcode(self) -> int:
            """
            :return: null if the opcode is known; otherwise, returns the unknown opcode's value
            :rtype: int
            """

        def isWeak(self) -> bool:
            """
            :return: True if the binding is "weak"; otherwise false
            :rtype: bool
            """

        @property
        def unknownOpcode(self) -> jpype.JInt:
            ...

        @property
        def segmentIndex(self) -> jpype.JInt:
            ...

        @property
        def symbolName(self) -> java.lang.String:
            ...

        @property
        def type(self) -> jpype.JInt:
            ...

        @property
        def libraryOrdinal(self) -> jpype.JInt:
            ...

        @property
        def addend(self) -> jpype.JLong:
            ...

        @property
        def segmentOffset(self) -> jpype.JLong:
            ...

        @property
        def weak(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates an empty :obj:`BindingTable`
        """

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader, tableSize: typing.Union[jpype.JLong, int], lazy: typing.Union[jpype.JBoolean, bool]):
        """
        Creates and parses a new :obj:`BindingTable`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`reader <BinaryReader>` positioned at the start of the binding table
        :param ghidra.app.util.bin.format.macho.MachHeader header: The header
        :param jpype.JLong or int tableSize: The size of the table, in bytes
        :param jpype.JBoolean or bool lazy: True if this is a lazy binding table; otherwise, false
        :raises IOException: if an IO-related error occurs while parsing
        """

    def getBindings(self) -> java.util.List[BindingTable.Binding]:
        """
        :return: the bindings
        :rtype: java.util.List[BindingTable.Binding]
        """

    def getThreadedBindings(self) -> java.util.List[BindingTable.Binding]:
        """
        :return: the threaded bindings, or null if threaded bindings are not being used
        :rtype: java.util.List[BindingTable.Binding]
        """

    @property
    def bindings(self) -> java.util.List[BindingTable.Binding]:
        ...

    @property
    def threadedBindings(self) -> java.util.List[BindingTable.Binding]:
        ...


class ClassicBindProcessor(AbstractClassicProcessor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ghidra.app.util.bin.format.macho.MachHeader, program: ghidra.program.model.listing.Program):
        ...

    def process(self, monitor: ghidra.util.task.TaskMonitor):
        ...


class RebaseTable(OpcodeTable):
    """
    A Mach-O rebase table
    """

    class Rebase(java.lang.Object):
        """
        A piece of rebase information from a :obj:`RebaseTable`
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            """
            Creates a new :obj:`Rebase`
            """

        @typing.overload
        def __init__(self, rebase: RebaseTable.Rebase):
            """
            Creates a copy of the given :obj:`Rebase`
            
            :param RebaseTable.Rebase rebase: The :obj:`Rebase` to copy
            """

        def getSegmentIndex(self) -> int:
            """
            :return: The segment index
            :rtype: int
            """

        def getSegmentOffset(self) -> int:
            """
            :return: The segment offset
            :rtype: int
            """

        def getType(self) -> int:
            """
            :return: The type
            :rtype: int
            """

        def getUnknownOpcode(self) -> int:
            """
            :return: null if the opcode is known; otherwise, returns the unknown opcode's value
            :rtype: int
            """

        @property
        def unknownOpcode(self) -> jpype.JInt:
            ...

        @property
        def segmentIndex(self) -> jpype.JInt:
            ...

        @property
        def type(self) -> jpype.JInt:
            ...

        @property
        def segmentOffset(self) -> jpype.JLong:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates an empty :obj:`RebaseTable`
        """

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader, tableSize: typing.Union[jpype.JLong, int]):
        """
        Creates and parses a new :obj:`RebaseTable`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`reader <BinaryReader>` positioned at the start of the rebase table
        :param ghidra.app.util.bin.format.macho.MachHeader header: The header
        :param jpype.JLong or int tableSize: The size of the table, in bytes
        :raises IOException: if an IO-related error occurs while parsing
        """

    def getRebases(self) -> java.util.List[RebaseTable.Rebase]:
        """
        :return: the rebases
        :rtype: java.util.List[RebaseTable.Rebase]
        """

    @property
    def rebases(self) -> java.util.List[RebaseTable.Rebase]:
        ...


class OpcodeTable(java.lang.Object):
    """
    Abstract class used to represent the generic components of a Mach-O opcode table
    
    
    .. seealso::
    
        | `common/MachOLayout.cpp <https://github.com/apple-oss-distributions/dyld/blob/main/common/MachOLayout.cpp>`_
    
        | `common/MachOAnalyzer.cpp <https://github.com/apple-oss-distributions/dyld/blob/main/common/MachOAnalyzer.cpp>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getOpcodeOffsets(self) -> java.util.List[java.lang.Long]:
        """
        :return: opcode offsets from the start of the bind data
        :rtype: java.util.List[java.lang.Long]
        """

    def getSlebOffsets(self) -> java.util.List[java.lang.Long]:
        """
        :return: SLEB128 offsets from the start of the bind data
        :rtype: java.util.List[java.lang.Long]
        """

    def getStringOffsets(self) -> java.util.List[java.lang.Long]:
        """
        :return: string offsets from the start of the bind data
        :rtype: java.util.List[java.lang.Long]
        """

    def getUlebOffsets(self) -> java.util.List[java.lang.Long]:
        """
        :return: ULEB128 offsets from the start of the bind data
        :rtype: java.util.List[java.lang.Long]
        """

    @property
    def slebOffsets(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def opcodeOffsets(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def ulebOffsets(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def stringOffsets(self) -> java.util.List[java.lang.Long]:
        ...


class RebaseOpcode(java.lang.Enum[RebaseOpcode]):
    """
    Rebase opcodes
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/loader.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    REBASE_OPCODE_DONE: typing.Final[RebaseOpcode]
    REBASE_OPCODE_SET_TYPE_IMM: typing.Final[RebaseOpcode]
    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: typing.Final[RebaseOpcode]
    REBASE_OPCODE_ADD_ADDR_ULEB: typing.Final[RebaseOpcode]
    REBASE_OPCODE_ADD_ADDR_IMM_SCALED: typing.Final[RebaseOpcode]
    REBASE_OPCODE_DO_REBASE_IMM_TIMES: typing.Final[RebaseOpcode]
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES: typing.Final[RebaseOpcode]
    REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: typing.Final[RebaseOpcode]
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: typing.Final[RebaseOpcode]

    @staticmethod
    def forOpcode(opcode: typing.Union[jpype.JInt, int]) -> RebaseOpcode:
        """
        Gets the :obj:`RebaseOpcode` that corresponds to the given opcode value
        
        :param jpype.JInt or int opcode: The opcode value
        :return: The :obj:`RebaseOpcode` that corresponds to the given opcode value, or null if it 
        does not exist
        :rtype: RebaseOpcode
        """

    def getOpcode(self) -> int:
        """
        :return: the opcode value
        :rtype: int
        """

    @staticmethod
    def toDataType() -> ghidra.program.model.data.DataType:
        """
        :return: a new data type from this enum
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> RebaseOpcode:
        ...

    @staticmethod
    def values() -> jpype.JArray[RebaseOpcode]:
        ...

    @property
    def opcode(self) -> jpype.JInt:
        ...


class ClassicLazyBindProcessor(AbstractClassicProcessor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ghidra.app.util.bin.format.macho.MachHeader, program: ghidra.program.model.listing.Program):
        ...

    def process(self, monitor: ghidra.util.task.TaskMonitor):
        ...


class BindOpcode(java.lang.Enum[BindOpcode]):
    """
    Bind opcodes
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/loader.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    BIND_OPCODE_DONE: typing.Final[BindOpcode]
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: typing.Final[BindOpcode]
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: typing.Final[BindOpcode]
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: typing.Final[BindOpcode]
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: typing.Final[BindOpcode]
    BIND_OPCODE_SET_TYPE_IMM: typing.Final[BindOpcode]
    BIND_OPCODE_SET_ADDEND_SLEB: typing.Final[BindOpcode]
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: typing.Final[BindOpcode]
    BIND_OPCODE_ADD_ADDR_ULEB: typing.Final[BindOpcode]
    BIND_OPCODE_DO_BIND: typing.Final[BindOpcode]
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: typing.Final[BindOpcode]
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: typing.Final[BindOpcode]
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: typing.Final[BindOpcode]
    BIND_OPCODE_THREADED: typing.Final[BindOpcode]

    @staticmethod
    def forOpcode(opcode: typing.Union[jpype.JInt, int]) -> BindOpcode:
        """
        Gets the :obj:`BindOpcode` that corresponds to the given opcode value
        
        :param jpype.JInt or int opcode: The opcode value
        :return: The :obj:`BindOpcode` that corresponds to the given opcode value, or null if it does
        not exist
        :rtype: BindOpcode
        """

    def getOpcode(self) -> int:
        """
        :return: the opcode value
        :rtype: int
        """

    @staticmethod
    def toDataType() -> ghidra.program.model.data.DataType:
        """
        :return: a new data type from this enum
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BindOpcode:
        ...

    @staticmethod
    def values() -> jpype.JArray[BindOpcode]:
        ...

    @property
    def opcode(self) -> jpype.JInt:
        ...


class AbstractClassicProcessor(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def perform(self, segmentName: typing.Union[java.lang.String, str], sectionName: typing.Union[java.lang.String, str], addressValue: typing.Union[jpype.JLong, int], fromDylib: typing.Union[java.lang.String, str], nList: ghidra.app.util.bin.format.macho.commands.NList, isWeak: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        ...



__all__ = ["BindingTable", "ClassicBindProcessor", "RebaseTable", "OpcodeTable", "RebaseOpcode", "ClassicLazyBindProcessor", "BindOpcode", "AbstractClassicProcessor"]
