from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class DyldChainedStartsInImage(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_chained_starts_in_image structure.
    
    
    .. seealso::
    
        | `mach-o/fixup-chains.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`DyldChainedStartsInImage`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getChainedStarts(self) -> java.util.List[DyldChainedStartsInSegment]:
        ...

    def getSegCount(self) -> int:
        ...

    def getSegInfoOffset(self) -> jpype.JArray[jpype.JInt]:
        ...

    def markup(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, header: ghidra.app.util.bin.format.macho.MachHeader, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks up this data structure with data structures and comments
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to mark up
        :param ghidra.program.model.address.Address address: The :obj:`Address` of this data structure
        :param ghidra.app.util.bin.format.macho.MachHeader header: The Mach-O header
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises CancelledException: if the user cancelled the operation
        """

    @property
    def segInfoOffset(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def segCount(self) -> jpype.JInt:
        ...

    @property
    def chainedStarts(self) -> java.util.List[DyldChainedStartsInSegment]:
        ...


class DyldChainedFixupHeader(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_chained_fixups_header structure.
    
    
    .. seealso::
    
        | `mach-o/fixup-chains.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`DyldChainedFixupHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getChainedImports(self) -> DyldChainedImports:
        ...

    def getChainedStartsInImage(self) -> DyldChainedStartsInImage:
        ...

    def getFixupsVersion(self) -> int:
        ...

    def getImportsCount(self) -> int:
        ...

    def getImportsFormat(self) -> int:
        ...

    def getImportsOffset(self) -> int:
        ...

    def getStartsOffset(self) -> int:
        ...

    def getSymbolsFormat(self) -> int:
        ...

    def getSymbolsOffset(self) -> int:
        ...

    def isCompress(self) -> bool:
        ...

    def markup(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, header: ghidra.app.util.bin.format.macho.MachHeader, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks up this data structure with data structures and comments
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to mark up
        :param ghidra.program.model.address.Address address: The :obj:`Address` of this data structure
        :param ghidra.app.util.bin.format.macho.MachHeader header: The Mach-O header
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises CancelledException: if the user cancelled the operation
        """

    @property
    def chainedStartsInImage(self) -> DyldChainedStartsInImage:
        ...

    @property
    def importsOffset(self) -> jpype.JLong:
        ...

    @property
    def importsCount(self) -> jpype.JLong:
        ...

    @property
    def compress(self) -> jpype.JBoolean:
        ...

    @property
    def startsOffset(self) -> jpype.JLong:
        ...

    @property
    def chainedImports(self) -> DyldChainedImports:
        ...

    @property
    def symbolsOffset(self) -> jpype.JLong:
        ...

    @property
    def fixupsVersion(self) -> jpype.JLong:
        ...

    @property
    def symbolsFormat(self) -> jpype.JInt:
        ...

    @property
    def importsFormat(self) -> jpype.JInt:
        ...


class DyldChainedStartsInSegment(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_chained_starts_in_segment structure.
    
    
    .. seealso::
    
        | `mach-o/fixup-chains.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`DyldChainedStartsInSegment`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getMaxValidPointer(self) -> int:
        ...

    def getPageCount(self) -> int:
        ...

    def getPageSize(self) -> int:
        ...

    def getPageStarts(self) -> jpype.JArray[jpype.JShort]:
        ...

    def getPointerFormat(self) -> int:
        ...

    def getSegmentOffset(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    def markup(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, header: ghidra.app.util.bin.format.macho.MachHeader, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks up this data structure with data structures and comments
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to mark up
        :param ghidra.program.model.address.Address address: The :obj:`Address` of this data structure
        :param ghidra.app.util.bin.format.macho.MachHeader header: The Mach-O header
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises CancelledException: if the user cancelled the operation
        """

    @property
    def pageStarts(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def pageCount(self) -> jpype.JShort:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def maxValidPointer(self) -> jpype.JInt:
        ...

    @property
    def pageSize(self) -> jpype.JShort:
        ...

    @property
    def segmentOffset(self) -> jpype.JLong:
        ...

    @property
    def pointerFormat(self) -> jpype.JShort:
        ...


class DyldChainedFixups(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    RELOCATION_TYPE: typing.Final = 34952

    def __init__(self):
        ...

    @staticmethod
    def fixupChainedPointers(fixups: java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldFixup], program: ghidra.program.model.listing.Program, imagebase: ghidra.program.model.address.Address, libraryPaths: java.util.List[java.lang.String], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Fixes up the program's chained pointers
        
        :param java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldFixup] fixups: A :obj:`List` of the fixups
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.Address imagebase: The image base
        :param java.util.List[java.lang.String] libraryPaths: A :obj:`List` of library paths
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :return: A :obj:`List` of fixed up :obj:`Address`'s
        :rtype: java.util.List[ghidra.program.model.address.Address]
        :raises CancelledException: If the user cancelled the operation
        """

    @staticmethod
    def getChainedFixups(reader: ghidra.app.util.bin.BinaryReader, chainedImports: DyldChainedImports, pointerFormat: ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType, page: typing.Union[jpype.JLong, int], nextOff: typing.Union[jpype.JLong, int], auth_value_add: typing.Union[jpype.JLong, int], imagebase: typing.Union[jpype.JLong, int], symbolTable: ghidra.program.model.symbol.SymbolTable, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldFixup]:
        """
        Walks the chained fixup information and collects a :obj:`List` of :obj:`DyldFixup`s that 
        will need to be applied to the image
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that can read the image
        :param DyldChainedImports chainedImports: chained imports (could be null)
        :param ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType pointerFormat: format of pointers within this chain
        :param jpype.JLong or int page: within data pages that has pointers to be unchained
        :param jpype.JLong or int nextOff: offset within the page that is the chain start
        :param jpype.JLong or int auth_value_add: value to be added to each chain pointer
        :param jpype.JLong or int imagebase: The image base
        :param ghidra.program.model.symbol.SymbolTable symbolTable: The :obj:`SymbolTable`, or null if not available
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :return: A :obj:`List` of :obj:`DyldFixup`s
        :rtype: java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldFixup]
        :raises IOException: If there was an IO-related issue
        :raises CancelledException: If the user cancelled the operation
        """

    @staticmethod
    def processPointerChain(reader: ghidra.app.util.bin.BinaryReader, chainStart: typing.Union[jpype.JLong, int], nextOffSize: typing.Union[jpype.JLong, int], imagebase: typing.Union[jpype.JLong, int], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldFixup]:
        """
        Fixes up any chained pointers, starting at the given address.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that can read the image
        :param jpype.JLong or int chainStart: The starting of address of the pointer chain to fix.
        :param jpype.JLong or int nextOffSize: The size of the next offset.
        :param jpype.JLong or int imagebase: The image base
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :return: A list of addresses where pointer fixes were performed.
        :rtype: java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldFixup]
        :raises IOException: If there was an IO-related issue
        :raises CancelledException: If the user cancelled the operation
        """


class DyldChainedStartsOffsets(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_chained_starts_offsets structure.
    
    
    .. seealso::
    
        | `mach-o/fixup-chains.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`DyldChainedStartsOffsets`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getChainStartOffsets(self) -> jpype.JArray[jpype.JInt]:
        """
        Gets the chain start offsets
        
        :return: The chain start offsets
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getPointerFormat(self) -> ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType:
        """
        Gets the pointer format
        
        :return: The pointer format
        :rtype: ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType
        """

    def getStartsCount(self) -> int:
        """
        Gets the starts count
        
        :return: The starts count
        :rtype: int
        """

    @property
    def startsCount(self) -> jpype.JInt:
        ...

    @property
    def chainStartOffsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def pointerFormat(self) -> ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType:
        ...


class DyldChainedImport(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_chained_import structure.
    
    
    .. seealso::
    
        | `mach-o/fixup-chains.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, binding: ghidra.app.util.bin.format.macho.commands.dyld.BindingTable.Binding):
        ...

    def getAddend(self) -> int:
        ...

    def getLibOrdinal(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getNameOffset(self) -> int:
        ...

    def initString(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def isWeakImport(self) -> bool:
        ...

    @property
    def nameOffset(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def weakImport(self) -> jpype.JBoolean:
        ...

    @property
    def libOrdinal(self) -> jpype.JInt:
        ...

    @property
    def addend(self) -> jpype.JLong:
        ...


class DyldChainedImports(java.lang.Object):
    """
    Represents a dyld_chained_import array.
    
    
    .. seealso::
    
        | `mach-o/fixup-chains.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bindings: java.util.List[ghidra.app.util.bin.format.macho.commands.dyld.BindingTable.Binding]):
        ...

    def getChainedImport(self, ordinal: typing.Union[jpype.JInt, int]) -> DyldChainedImport:
        ...

    def getChainedImports(self) -> jpype.JArray[DyldChainedImport]:
        ...

    def getImportsCount(self) -> int:
        ...

    def getImportsOffset(self) -> int:
        ...

    def initSymbols(self, reader: ghidra.app.util.bin.BinaryReader, dyldChainedFixupHeader: DyldChainedFixupHeader):
        ...

    @property
    def importsOffset(self) -> jpype.JLong:
        ...

    @property
    def importsCount(self) -> jpype.JLong:
        ...

    @property
    def chainedImport(self) -> DyldChainedImport:
        ...

    @property
    def chainedImports(self) -> jpype.JArray[DyldChainedImport]:
        ...



__all__ = ["DyldChainedStartsInImage", "DyldChainedFixupHeader", "DyldChainedStartsInSegment", "DyldChainedFixups", "DyldChainedStartsOffsets", "DyldChainedImport", "DyldChainedImports"]
