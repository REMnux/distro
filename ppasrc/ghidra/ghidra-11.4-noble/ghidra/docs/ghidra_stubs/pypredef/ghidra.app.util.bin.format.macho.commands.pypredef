from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands.chained
import ghidra.app.util.bin.format.macho.commands.dyld
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.importer
import ghidra.program.flatapi
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class VersionMinCommand(LoadCommand):
    """
    Represents a version_min_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getSdk(self) -> int:
        ...

    def getVersion(self) -> int:
        ...

    @property
    def sdk(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...


class SubFrameworkCommand(LoadCommand):
    """
    Represents a sub_framework_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getUmbrellaFrameworkName(self) -> LoadCommandString:
        ...

    @property
    def umbrellaFrameworkName(self) -> LoadCommandString:
        ...


class CorruptLoadCommand(LoadCommand):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, t: java.lang.Throwable):
        ...

    def getProblem(self) -> java.lang.Throwable:
        ...

    @property
    def problem(self) -> java.lang.Throwable:
        ...


class DynamicSymbolTableConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    INDIRECT_SYMBOL_LOCAL: typing.Final = -2147483648
    INDIRECT_SYMBOL_ABS: typing.Final = 1073741824

    def __init__(self):
        ...


class DynamicLibraryModule(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader):
        ...

    def getExtDefSymCount(self) -> int:
        ...

    def getExtDefSymIndex(self) -> int:
        ...

    def getExternalRelocationCount(self) -> int:
        ...

    def getExternalRelocationIndex(self) -> int:
        ...

    def getInitTermCount(self) -> int:
        """
        Low 16 bits are the number of init section entries, high 16 bits are the number of term 
        section entries
        
        :return: The init term count
        :rtype: int
        """

    def getInitTermIndex(self) -> int:
        """
        Low 16 bits are the index into the init section, high 16 bits are the index into the term 
        section
        
        :return: The init term index
        :rtype: int
        """

    def getLocalSymbolCount(self) -> int:
        ...

    def getLocalSymbolIndex(self) -> int:
        ...

    def getModuleName(self) -> str:
        ...

    def getModuleNameIndex(self) -> int:
        ...

    def getObjcModuleInfoAddress(self) -> int:
        ...

    def getObjcModuleInfoSize(self) -> int:
        ...

    def getReferenceSymbolTableCount(self) -> int:
        ...

    def getReferenceSymbolTableIndex(self) -> int:
        ...

    @property
    def referenceSymbolTableIndex(self) -> jpype.JInt:
        ...

    @property
    def initTermIndex(self) -> jpype.JInt:
        ...

    @property
    def externalRelocationIndex(self) -> jpype.JInt:
        ...

    @property
    def moduleName(self) -> java.lang.String:
        ...

    @property
    def extDefSymCount(self) -> jpype.JInt:
        ...

    @property
    def objcModuleInfoAddress(self) -> jpype.JLong:
        ...

    @property
    def initTermCount(self) -> jpype.JInt:
        ...

    @property
    def objcModuleInfoSize(self) -> jpype.JInt:
        ...

    @property
    def referenceSymbolTableCount(self) -> jpype.JInt:
        ...

    @property
    def localSymbolCount(self) -> jpype.JInt:
        ...

    @property
    def moduleNameIndex(self) -> jpype.JInt:
        ...

    @property
    def externalRelocationCount(self) -> jpype.JInt:
        ...

    @property
    def localSymbolIndex(self) -> jpype.JInt:
        ...

    @property
    def extDefSymIndex(self) -> jpype.JInt:
        ...


class PrebindChecksumCommand(LoadCommand):
    """
    Represents a prebind_cksum_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCheckSum(self) -> int:
        """
        Returns the check sum or zero.
        
        :return: the check sum or zero
        :rtype: int
        """

    @property
    def checkSum(self) -> jpype.JInt:
        ...


class DataInCodeEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a data_in_code_entry structure
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/loader.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of a :obj:`DataInCodeEntry` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`DataInCodeEntry`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getKind(self) -> int:
        """
        Gets the kind
        
        :return: The kind
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Gets the length
        
        :return: The length
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Gets the offset
        
        :return: The offset
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def kind(self) -> jpype.JShort:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class SegmentConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    PROTECTION_R: typing.Final = 1
    """
    Read protection flag.
    """

    PROTECTION_W: typing.Final = 2
    """
    Write protection flag.
    """

    PROTECTION_X: typing.Final = 4
    """
    Execute protection flag.
    """

    FLAG_APPLE_PROTECTED: typing.Final = 8
    """
    If this flag bit is set, the segment contains Apple protection.
    """


    def __init__(self):
        ...


class ExportTrie(java.lang.Object):
    """
    Mach-O export trie
    
    
    .. seealso::
    
        | `Exported Symbol <https://github.com/qyang-nj/llios/blob/main/exported_symbol/README.md>`_
    
        | `dyld/launch-cache/MachOTrie.hpp <https://github.com/opensource-apple/dyld/blob/master/launch-cache/MachOTrie.hpp>`_
    """

    class ExportEntry(java.lang.Record):
        """
        Creates a new :obj:`ExportEntry`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], address: typing.Union[jpype.JLong, int], flags: typing.Union[jpype.JLong, int], other: typing.Union[jpype.JLong, int], importName: typing.Union[java.lang.String, str]):
            ...

        def address(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def flags(self) -> int:
            ...

        def hashCode(self) -> int:
            ...

        def importName(self) -> str:
            ...

        def isReExport(self) -> bool:
            """
            Check to see if the export is a "re-export"
            
            :return: True if re-export; otherwise, false
            :rtype: bool
            """

        def name(self) -> str:
            ...

        def other(self) -> int:
            ...

        @property
        def reExport(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class Node(java.lang.Record):
        """
        A trie node
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def offset(self) -> int:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates an empty :obj:`ExportTrie`.  This is useful for export trie load commands that are
        defined but do not point to any data.
        """

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates and parses a new :obj:`ExportTrie`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`reader <BinaryReader>` positioned at the start of the export trie
        :raises IOException: if an IO-related error occurs while parsing
        """

    @typing.overload
    def getExports(self) -> java.util.List[ExportTrie.ExportEntry]:
        """
        Gets the :obj:`List` of :obj:`exports <ExportEntry>`
        
        :return: The :obj:`List` of :obj:`exports <ExportEntry>`
        :rtype: java.util.List[ExportTrie.ExportEntry]
        """

    @typing.overload
    def getExports(self, filter: java.util.function.Predicate[ExportTrie.ExportEntry]) -> java.util.List[ExportTrie.ExportEntry]:
        """
        Gets the :obj:`List` of :obj:`exports <ExportEntry>`
        
        :param java.util.function.Predicate[ExportTrie.ExportEntry] filter: A filter on the returned :obj:`List`
        :return: The :obj:`List` of :obj:`exports <ExportEntry>`
        :rtype: java.util.List[ExportTrie.ExportEntry]
        """

    def getStringOffsets(self) -> java.util.List[java.lang.Long]:
        """
        :return: String offsets from the start of the export trie
        :rtype: java.util.List[java.lang.Long]
        """

    def getUlebOffsets(self) -> java.util.List[java.lang.Long]:
        """
        :return: ULEB128 offsets from the start of the export trie
        :rtype: java.util.List[java.lang.Long]
        """

    @property
    def exports(self) -> java.util.List[ExportTrie.ExportEntry]:
        ...

    @property
    def ulebOffsets(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def stringOffsets(self) -> java.util.List[java.lang.Long]:
        ...


class DynamicLinkerCommand(LoadCommand):
    """
    Represents a dylinker_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLoadCommandString(self) -> LoadCommandString:
        ...

    @property
    def loadCommandString(self) -> LoadCommandString:
        ...


class SymbolCommand(ObsoleteCommand):
    """
    Represents a symseg_command structure.
    
    
    .. seealso::
    
        | `mach-o/loader.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOffset(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...


class LinkEditDataCommand(LoadCommand):
    """
    Represents a linkedit_data_command structure
    """

    class_: typing.ClassVar[java.lang.Class]


class TwoLevelHint(ghidra.app.util.bin.StructConverter):
    """
    Represents a twolevel_hint structure.
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/loader.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 4

    def getSubImageIndex(self) -> int:
        """
        An index into the sub-images (sub-frameworks and sub-umbrellas list).
        
        :return: index into the sub-images
        :rtype: int
        """

    def getTableOfContentsIndex(self) -> int:
        """
        An index into the library's table of contents.
        
        :return: index into the library's table of contents
        :rtype: int
        """

    @property
    def subImageIndex(self) -> jpype.JInt:
        ...

    @property
    def tableOfContentsIndex(self) -> jpype.JInt:
        ...


class DyldChainedFixupsCommand(LinkEditDataCommand):
    """
    Represents a ``dyld_chained_fixups_command`` structure
    
    
    .. seealso::
    
        | `mach-o/fixup-chains.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def getChainHeader(self) -> ghidra.app.util.bin.format.macho.commands.chained.DyldChainedFixupHeader:
        """
        Gets the :obj:`DyldChainedFixupHeader`
        
        :return: The :obj:`DyldChainedFixupHeader`
        :rtype: ghidra.app.util.bin.format.macho.commands.chained.DyldChainedFixupHeader
        """

    def getChainedFixups(self, reader: ghidra.app.util.bin.BinaryReader, imagebase: typing.Union[jpype.JLong, int], symbolTable: ghidra.program.model.symbol.SymbolTable, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldFixup]:
        """
        Walks this command's chained fixup information and collects a :obj:`List` of 
        :obj:`DyldFixup`s that will need to be applied to the image
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that can read the image
        :param jpype.JLong or int imagebase: The image base
        :param ghidra.program.model.symbol.SymbolTable symbolTable: The :obj:`SymbolTable`, or null if not available
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :return: A :obj:`List` of :obj:`DyldFixup`s
        :rtype: java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldFixup]
        :raises IOException: If there was an IO-related issue
        :raises CancelledException: If the user cancelled the operation
        """

    @property
    def chainHeader(self) -> ghidra.app.util.bin.format.macho.commands.chained.DyldChainedFixupHeader:
        ...


class DynamicSymbolTableCommand(LoadCommand):
    """
    Represents a dysymtab_command structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getExternalRelocationOffset(self) -> int:
        """
        Returns the byte index from the start of the file to the external relocation table.
        
        :return: the byte index of the external relocation table
        :rtype: int
        """

    def getExternalRelocationSize(self) -> int:
        """
        Returns the number of entries in the external relocation table.
        
        :return: the number of entries in the external relocation table
        :rtype: int
        """

    def getExternalRelocations(self) -> java.util.List[ghidra.app.util.bin.format.macho.RelocationInfo]:
        ...

    def getExternalSymbolCount(self) -> int:
        """
        Returns the total number of external symbols.
        
        :return: the total number of external symbols
        :rtype: int
        """

    def getExternalSymbolIndex(self) -> int:
        """
        Returns the index of the first external symbol.
        
        :return: the index of the first external symbol
        :rtype: int
        """

    def getIndirectSymbolTableOffset(self) -> int:
        """
        Returns the byte index from the start of the file to the indirect symbol table.
        
        :return: the byte index of the indirect symbol table
        :rtype: int
        """

    def getIndirectSymbolTableSize(self) -> int:
        """
        Returns the number of entries in the indirect symbol table.
        
        :return: the number of entries in the indirect symbol table
        :rtype: int
        """

    def getIndirectSymbols(self) -> java.util.List[java.lang.Integer]:
        ...

    def getLocalRelocationOffset(self) -> int:
        """
        Returns the byte index from the start of the file to the local relocation table.
        
        :return: the byte index of the local relocation table
        :rtype: int
        """

    def getLocalRelocationSize(self) -> int:
        """
        Returns the number of entries in the local relocation table.
        
        :return: the number of entries in the local relocation table
        :rtype: int
        """

    def getLocalRelocations(self) -> java.util.List[ghidra.app.util.bin.format.macho.RelocationInfo]:
        ...

    def getLocalSymbolCount(self) -> int:
        """
        Returns the total number of local symbols.
        
        :return: the total number of local symbols
        :rtype: int
        """

    def getLocalSymbolIndex(self) -> int:
        """
        Returns the index of the first local symbol.
        
        :return: the index of the first local symbol
        :rtype: int
        """

    def getModuleList(self) -> java.util.List[DynamicLibraryModule]:
        ...

    def getModuleTableOffset(self) -> int:
        """
        Returns the byte index from the start of the file to the module table.
        
        :return: the byte index of the module table
        :rtype: int
        """

    def getModuleTableSize(self) -> int:
        """
        Returns the number of entries in the module table.
        
        :return: the number of entries in the module table
        :rtype: int
        """

    def getReferencedSymbolList(self) -> java.util.List[DynamicLibraryReference]:
        ...

    def getReferencedSymbolTableOffset(self) -> int:
        """
        Returns the byte index from the start of the file to the external reference table.
        
        :return: the byte index of the external reference table
        :rtype: int
        """

    def getReferencedSymbolTableSize(self) -> int:
        """
        Returns the number of entries in the external reference table.
        
        :return: the number of entries in the external reference table
        :rtype: int
        """

    def getTableOfContentsList(self) -> java.util.List[TableOfContents]:
        ...

    def getTableOfContentsOffset(self) -> int:
        """
        Returns the byte index from the start of the file to the table of contents (TOC).
        
        :return: the byte index of the TOC
        :rtype: int
        """

    def getTableOfContentsSize(self) -> int:
        """
        Returns the number of entries in the table of contents.
        
        :return: the number of entries in the table of contents
        :rtype: int
        """

    def getUndefinedSymbolCount(self) -> int:
        """
        Returns the total number of undefined symbols.
        
        :return: the total number of undefined symbols
        :rtype: int
        """

    def getUndefinedSymbolIndex(self) -> int:
        """
        Returns the index of the first undefined symbol.
        
        :return: the index of the first undefined symbol
        :rtype: int
        """

    @property
    def externalSymbolCount(self) -> jpype.JLong:
        ...

    @property
    def undefinedSymbolCount(self) -> jpype.JLong:
        ...

    @property
    def localRelocations(self) -> java.util.List[ghidra.app.util.bin.format.macho.RelocationInfo]:
        ...

    @property
    def tableOfContentsOffset(self) -> jpype.JLong:
        ...

    @property
    def referencedSymbolList(self) -> java.util.List[DynamicLibraryReference]:
        ...

    @property
    def externalSymbolIndex(self) -> jpype.JLong:
        ...

    @property
    def tableOfContentsSize(self) -> jpype.JLong:
        ...

    @property
    def indirectSymbolTableSize(self) -> jpype.JLong:
        ...

    @property
    def referencedSymbolTableSize(self) -> jpype.JLong:
        ...

    @property
    def localSymbolCount(self) -> jpype.JLong:
        ...

    @property
    def moduleList(self) -> java.util.List[DynamicLibraryModule]:
        ...

    @property
    def localRelocationOffset(self) -> jpype.JLong:
        ...

    @property
    def moduleTableSize(self) -> jpype.JLong:
        ...

    @property
    def moduleTableOffset(self) -> jpype.JLong:
        ...

    @property
    def externalRelocationOffset(self) -> jpype.JLong:
        ...

    @property
    def tableOfContentsList(self) -> java.util.List[TableOfContents]:
        ...

    @property
    def externalRelocations(self) -> java.util.List[ghidra.app.util.bin.format.macho.RelocationInfo]:
        ...

    @property
    def indirectSymbols(self) -> java.util.List[java.lang.Integer]:
        ...

    @property
    def referencedSymbolTableOffset(self) -> jpype.JLong:
        ...

    @property
    def externalRelocationSize(self) -> jpype.JLong:
        ...

    @property
    def localSymbolIndex(self) -> jpype.JLong:
        ...

    @property
    def undefinedSymbolIndex(self) -> jpype.JLong:
        ...

    @property
    def indirectSymbolTableOffset(self) -> jpype.JLong:
        ...

    @property
    def localRelocationSize(self) -> jpype.JLong:
        ...


class UuidCommand(LoadCommand):
    """
    Represents a uuid_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getUUID(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns a 128-bit unique random number that identifies an object.
        
        :return: a 128-bit unique random number that identifies an object
        :rtype: jpype.JArray[jpype.JByte]
        """

    @property
    def uUID(self) -> jpype.JArray[jpype.JByte]:
        ...


class CodeSignatureCommand(LinkEditDataCommand):
    """
    Represents a LC_CODE_SIGNATURE command.
    """

    class_: typing.ClassVar[java.lang.Class]


class SubUmbrellaCommand(LoadCommand):
    """
    Represents a sub_umbrella_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getSubUmbrellaFrameworkName(self) -> LoadCommandString:
        ...

    @property
    def subUmbrellaFrameworkName(self) -> LoadCommandString:
        ...


class DataInCodeCommand(LinkEditDataCommand):
    """
    Represents a LC_DATA_IN_CODE command.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getEntries(self) -> java.util.List[DataInCodeEntry]:
        """
        Gets the :obj:`List` of :obj:`DataInCodeEntry`s
        
        :return: The :obj:`List` of :obj:`DataInCodeEntry`s
        :rtype: java.util.List[DataInCodeEntry]
        """

    @property
    def entries(self) -> java.util.List[DataInCodeEntry]:
        ...


class DynamicLibraryReference(ghidra.app.util.bin.StructConverter):
    """
    Represents a dylib_reference structure.
    
    
    .. seealso::
    
        | `mach-o/loader.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFlags(self) -> int:
        ...

    def getSymbolIndex(self) -> int:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def symbolIndex(self) -> jpype.JInt:
        ...


class BuildVersionCommand(LoadCommand):
    """
    Represents a build_version_command structure
    """

    class BuildToolVersion(ghidra.app.util.bin.StructConverter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: typing.Union[jpype.JInt, int], version: typing.Union[jpype.JInt, int]):
            ...

        def getTool(self) -> int:
            ...

        def getVersion(self) -> int:
            ...

        @property
        def version(self) -> jpype.JInt:
            ...

        @property
        def tool(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getMinOS(self) -> int:
        ...

    def getNumTools(self) -> int:
        ...

    def getPlatform(self) -> int:
        ...

    def getSdk(self) -> int:
        ...

    @property
    def minOS(self) -> jpype.JInt:
        ...

    @property
    def sdk(self) -> jpype.JInt:
        ...

    @property
    def numTools(self) -> jpype.JLong:
        ...

    @property
    def platform(self) -> jpype.JInt:
        ...


class FixedVirtualMemoryFileCommand(LoadCommand):
    """
    Represents a fvmfile_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getHeaderAddress(self) -> int:
        """
        Returns the file's virtual address.
        
        :return: the file's virtual address
        :rtype: int
        """

    def getPathname(self) -> str:
        """
        Returns the file's pathname.
        
        :return: the file's pathname
        :rtype: str
        """

    @property
    def headerAddress(self) -> jpype.JLong:
        ...

    @property
    def pathname(self) -> java.lang.String:
        ...


class SegmentCommand(LoadCommand):
    """
    Represents a segment_command and segment_command_64 structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, is32bit: typing.Union[jpype.JBoolean, bool]):
        ...

    def contains(self, addr: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the segment contains the given address
        
        :param jpype.JLong or int addr: The address to check
        :return: True if the segment contains the given address; otherwise, false
        :rtype: bool
        """

    @staticmethod
    def create(magic: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], vmAddr: typing.Union[jpype.JLong, int], vmSize: typing.Union[jpype.JLong, int], fileOffset: typing.Union[jpype.JLong, int], fileSize: typing.Union[jpype.JLong, int], maxProt: typing.Union[jpype.JInt, int], initProt: typing.Union[jpype.JInt, int], flags: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Creates a new segment command byte array.
         
        
        NOTE: The new segment will have 0 sections.
        
        :param jpype.JInt or int magic: The magic
        :param java.lang.String or str name: The name of the segment (must be less than or equal to 16 bytes)
        :param jpype.JLong or int vmAddr: The address of the start of the segment
        :param jpype.JLong or int vmSize: The size of the segment in memory
        :param jpype.JLong or int fileOffset: The file offset of the start of the segment
        :param jpype.JLong or int fileSize: The size of the segment on disk
        :param jpype.JInt or int maxProt: The maximum protections of the segment
        :param jpype.JInt or int initProt: The initial protection of the segment
        :param jpype.JInt or int flags: The segment flags
        :return: The new segment in byte array form
        :rtype: jpype.JArray[jpype.JByte]
        :raises MachException: if an invalid magic value was passed in (see :obj:`MachConstants`), or
        if the desired segment name exceeds 16 bytes
        """

    def getFileOffset(self) -> int:
        ...

    def getFileSize(self) -> int:
        ...

    def getFlags(self) -> int:
        ...

    def getInitProtection(self) -> int:
        """
        Returns a octal model value reflecting the
        segment's initial protection value.
        For example:``7 -> 0x111 -> rwx5 -> 0x101 -> rx``
        
        :return: the initial protections of a segment
        :rtype: int
        """

    def getMaxProtection(self) -> int:
        """
        Returns a octal model value reflecting the
        segment's maximum protection value allowed.
        For example:``7 -> 0x111 -> rwx5 -> 0x101 -> rx``
        
        :return: the maximum protections of a segment
        :rtype: int
        """

    def getNumberOfSections(self) -> int:
        ...

    def getSectionByName(self, sectionName: typing.Union[java.lang.String, str]) -> ghidra.app.util.bin.format.macho.Section:
        ...

    def getSectionContaining(self, address: ghidra.program.model.address.Address) -> ghidra.app.util.bin.format.macho.Section:
        ...

    def getSections(self) -> java.util.List[ghidra.app.util.bin.format.macho.Section]:
        ...

    def getSegmentName(self) -> str:
        ...

    def getVMaddress(self) -> int:
        ...

    def getVMsize(self) -> int:
        ...

    def is32bit(self) -> bool:
        ...

    def isAppleProtected(self) -> bool:
        ...

    def isExecute(self) -> bool:
        """
        Returns true if the initial protections include EXECUTE.
        
        :return: true if the initial protections include EXECUTE
        :rtype: bool
        """

    def isRead(self) -> bool:
        """
        Returns true if the initial protections include READ.
        
        :return: true if the initial protections include READ
        :rtype: bool
        """

    def isWrite(self) -> bool:
        """
        Returns true if the initial protections include WRITE.
        
        :return: true if the initial protections include WRITE
        :rtype: bool
        """

    def setFileOffset(self, fileOffset: typing.Union[jpype.JLong, int]):
        ...

    def setFileSize(self, fileSize: typing.Union[jpype.JLong, int]):
        ...

    def setSegmentName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setVMaddress(self, vmaddr: typing.Union[jpype.JLong, int]):
        ...

    def setVMsize(self, vmSize: typing.Union[jpype.JLong, int]):
        ...

    @staticmethod
    def size(magic: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the size a segment command would be for the given magic
        
        :param jpype.JInt or int magic: The magic
        :return: The size in bytes a segment command would be for the given magic
        :rtype: int
        :raises MachException: if an invalid magic value was passed in (see :obj:`MachConstants`)
        """

    @property
    def vMaddress(self) -> jpype.JLong:
        ...

    @vMaddress.setter
    def vMaddress(self, value: jpype.JLong):
        ...

    @property
    def appleProtected(self) -> jpype.JBoolean:
        ...

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @fileOffset.setter
    def fileOffset(self, value: jpype.JLong):
        ...

    @property
    def sectionContaining(self) -> ghidra.app.util.bin.format.macho.Section:
        ...

    @property
    def numberOfSections(self) -> jpype.JLong:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @property
    def segmentName(self) -> java.lang.String:
        ...

    @segmentName.setter
    def segmentName(self, value: java.lang.String):
        ...

    @property
    def sections(self) -> java.util.List[ghidra.app.util.bin.format.macho.Section]:
        ...

    @property
    def initProtection(self) -> jpype.JInt:
        ...

    @property
    def maxProtection(self) -> jpype.JInt:
        ...

    @property
    def fileSize(self) -> jpype.JLong:
        ...

    @fileSize.setter
    def fileSize(self, value: jpype.JLong):
        ...

    @property
    def vMsize(self) -> jpype.JLong:
        ...

    @vMsize.setter
    def vMsize(self, value: jpype.JLong):
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @property
    def sectionByName(self) -> ghidra.app.util.bin.format.macho.Section:
        ...


class LoadCommandTypes(java.lang.Object):
    """
    :obj:`LoadCommand` types
    """

    class_: typing.ClassVar[java.lang.Class]
    LC_REQ_DYLD: typing.Final = -2147483648
    """
    After MacOS X 10.1 when a new load command is added that is required to be
    understood by the dynamic linker for the image to execute properly the
    LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
    linker sees such a load command that it does not understand, it will issue a
    "unknown load command required for execution" error and refuse to use the
    image.  Other load commands without this bit that are not understood will
    simply be ignored.
    """

    LC_SEGMENT: typing.Final = 1
    """
    segment of this file to be mapped
    """

    LC_SYMTAB: typing.Final = 2
    """
    link-edit stab symbol table info
    """

    LC_SYMSEG: typing.Final = 3
    """
    link-edit gdb symbol table info (obsolete)
    """

    LC_THREAD: typing.Final = 4
    """
    thread
    """

    LC_UNIXTHREAD: typing.Final = 5
    """
    unix thread (includes a stack)
    """

    LC_LOADFVMLIB: typing.Final = 6
    """
    load a specified fixed VM shared library
    """

    LC_IDFVMLIB: typing.Final = 7
    """
    fixed VM shared library identification
    """

    LC_IDENT: typing.Final = 8
    """
    object identification info (obsolete)
    """

    LC_FVMFILE: typing.Final = 9
    """
    fixed VM file inclusion (internal use)
    """

    LC_PREPAGE: typing.Final = 10
    """
    prepage command (internal use)
    """

    LC_DYSYMTAB: typing.Final = 11
    """
    dynamic link-edit symbol table info
    """

    LC_LOAD_DYLIB: typing.Final = 12
    """
    load a dynamically linked shared library
    """

    LC_ID_DYLIB: typing.Final = 13
    """
    dynamically linked shared lib ident
    """

    LC_LOAD_DYLINKER: typing.Final = 14
    """
    load a dynamic linker
    """

    LC_ID_DYLINKER: typing.Final = 15
    """
    dynamic linker identification
    """

    LC_PREBOUND_DYLIB: typing.Final = 16
    """
    modules prebound for a dynamically linked shared library
    """

    LC_ROUTINES: typing.Final = 17
    """
    image routines
    """

    LC_SUB_FRAMEWORK: typing.Final = 18
    """
    sub framework
    """

    LC_SUB_UMBRELLA: typing.Final = 19
    """
    sub umbrella
    """

    LC_SUB_CLIENT: typing.Final = 20
    """
    sub client
    """

    LC_SUB_LIBRARY: typing.Final = 21
    """
    sub library
    """

    LC_TWOLEVEL_HINTS: typing.Final = 22
    """
    two-level namespace lookup hints
    """

    LC_PREBIND_CKSUM: typing.Final = 23
    """
    prebind checksum
    """

    LC_LOAD_WEAK_DYLIB: typing.Final = -2147483624
    """
    load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported)
    """

    LC_SEGMENT_64: typing.Final = 25
    """
    64-bit segment of this file to be mapped
    """

    LC_ROUTINES_64: typing.Final = 26
    """
    64-bit image routines
    """

    LC_UUID: typing.Final = 27
    """
    specifies the 128 bit UUID for an image
    """

    LC_RPATH: typing.Final = -2147483620
    """
    Run path additions
    """

    LC_CODE_SIGNATURE: typing.Final = 29
    """
    local of code signature
    """

    LC_SEGMENT_SPLIT_INFO: typing.Final = 30
    """
    local of info to split segments
    """

    LC_REEXPORT_DYLIB: typing.Final = -2147483617
    """
    load and re-export dylib
    """

    LC_LAZY_LOAD_DYLIB: typing.Final = 32
    """
    Delay load of dylib until first use
    """

    LC_ENCRYPTION_INFO: typing.Final = 33
    """
    encrypted segment information
    """

    LC_DYLD_INFO: typing.Final = 34
    """
    compressed dyld information
    """

    LC_DYLD_INFO_ONLY: typing.Final = -2147483614
    """
    compressed dyld information only
    """

    LC_LOAD_UPWARD_DYLIB: typing.Final = -2147483613
    """
    Load upward dylib
    """

    LC_VERSION_MIN_MACOSX: typing.Final = 36
    """
    Build for MacOSX min OS version
    """

    LC_VERSION_MIN_IPHONEOS: typing.Final = 37
    """
    Build for iPhoneOS min OS version
    """

    LC_FUNCTION_STARTS: typing.Final = 38
    """
    Compressed table of function start addresses
    """

    LC_DYLD_ENVIRONMENT: typing.Final = 39
    """
    String for DYLD to treat environment variable
    """

    LC_MAIN: typing.Final = -2147483608
    """
    Replacement for LC_UNIXTHREAD
    """

    LC_DATA_IN_CODE: typing.Final = 41
    """
    Table of non-instructions in __text
    """

    LC_SOURCE_VERSION: typing.Final = 42
    """
    Source version used to build binary
    """

    LC_DYLIB_CODE_SIGN_DRS: typing.Final = 43
    """
    Code signing DRs copied from linked dylibs
    """

    LC_ENCRYPTION_INFO_64: typing.Final = 44
    """
    64-bit encrypted segment information
    """

    LC_LINKER_OPTIONS: typing.Final = 45
    """
    Linker options in MH_OBJECT files
    """

    LC_OPTIMIZATION_HINT: typing.Final = 46
    """
    Optimization hints in MH_OBJECT files
    """

    LC_VERSION_MIN_TVOS: typing.Final = 47
    """
    Build for AppleTV min OS version
    """

    LC_VERSION_MIN_WATCHOS: typing.Final = 48
    """
    Build for Watch min OS version
    """

    LC_NOTE: typing.Final = 49
    """
    Arbitrary data included within a Mach-O file
    """

    LC_BUILD_VERSION: typing.Final = 50
    """
    Build for platform min OS version
    """

    LC_DYLD_EXPORTS_TRIE: typing.Final = -2147483597
    """
    Used with linkedit_data_command, payload is trie
    """

    LC_DYLD_CHAINED_FIXUPS: typing.Final = -2147483596
    """
    Used with linkedit_data_command
    """

    LC_FILESET_ENTRY: typing.Final = -2147483595
    """
    Used with fileset_entry_command
    """


    def __init__(self):
        ...

    @staticmethod
    def getLoadCommandName(type: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets the name of the given load command type
        
        :param jpype.JInt or int type: The load command type
        :return: The name of the given load command type
        :rtype: str
        """


class NListConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MASK_N_STAB: typing.Final = 224
    """
    if any of these bits set, a symbolic debugging entry
    """

    MASK_N_PEXT: typing.Final = 16
    """
    private external symbol bit
    """

    MASK_N_TYPE: typing.Final = 14
    """
    mask for the type bits
    """

    MASK_N_EXT: typing.Final = 1
    """
    external symbol bit, set for external symbols
    """

    TYPE_N_UNDF: typing.Final = 0
    """
    undefined, n_sect == NO_SECT
    """

    TYPE_N_ABS: typing.Final = 2
    """
    absolute, n_sect == NO_SECT
    """

    TYPE_N_INDR: typing.Final = 10
    """
    indirect
    """

    TYPE_N_PBUD: typing.Final = 12
    """
    prebound undefined (defined in a dylib)
    """

    TYPE_N_SECT: typing.Final = 14
    """
    defined in section number n_sect
    """

    REFERENCE_TYPE: typing.Final = 7
    """
    Reference type bits of the n_desc field of undefined symbols
    """

    REFERENCE_FLAG_UNDEFINED_NON_LAZY: typing.Final = 0
    REFERENCE_FLAG_UNDEFINED_LAZY: typing.Final = 1
    REFERENCE_FLAG_DEFINED: typing.Final = 2
    REFERENCE_FLAG_PRIVATE_DEFINED: typing.Final = 3
    REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: typing.Final = 4
    REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: typing.Final = 5
    REFERENCED_DYNAMICALLY: typing.Final = 16
    NO_SECT: typing.Final = 0
    """
    symbol is not in any section
    """

    DESC_N_NO_DEAD_STRIP: typing.Final = 32
    DESC_N_DESC_DISCARDED: typing.Final = 32
    DESC_N_WEAK_REF: typing.Final = 64
    DESC_N_WEAK_DEF: typing.Final = 128
    DESC_N_REF_TO_WEAK: typing.Final = 128
    DESC_N_ARM_THUMB_DEF: typing.Final = 8
    DEBUG_N_GSYM: typing.Final = 32
    """
    global symbol: name,,NO_SECT,type,0
    """

    DEBUG_N_FNAME: typing.Final = 34
    """
    procedure name (f77 kludge): name,,NO_SECT,0,0
    """

    DEBUG_N_FUN: typing.Final = 36
    """
    procedure: name,,n_sect,linenumber,address
    """

    DEBUG_N_STSYM: typing.Final = 38
    """
    static symbol: name,,n_sect,type,address
    """

    DEBUG_N_LCSYM: typing.Final = 40
    """
    .lcomm symbol: name,,n_sect,type,address
    """

    DEBUG_N_BNSYM: typing.Final = 46
    """
    begin nsect sym: 0,,n_sect,0,address
    """

    DEBUG_N_OPT: typing.Final = 60
    """
    emitted with gcc2_compiled and in gcc source
    """

    DEBUG_N_RSYM: typing.Final = 64
    """
    register sym: name,,NO_SECT,type,register
    """

    DEBUG_N_SLINE: typing.Final = 68
    """
    src line: 0,,n_sect,linenumber,address
    """

    DEBUG_N_ENSYM: typing.Final = 78
    """
    end nsect sym: 0,,n_sect,0,address
    """

    DEBUG_N_SSYM: typing.Final = 96
    """
    structure elt: name,,NO_SECT,type,struct_offset
    """

    DEBUG_N_SO: typing.Final = 100
    """
    source file name: name,,n_sect,0,address
    """

    DEBUG_N_OSO: typing.Final = 102
    """
    object file name: name,,0,0,st_mtime
    """

    DEBUG_N_LSYM: typing.Final = -128
    """
    local sym: name,,NO_SECT,type,offset
    """

    DEBUG_N_BINCL: typing.Final = -126
    """
    include file beginning: name,,NO_SECT,0,sum
    """

    DEBUG_N_SOL: typing.Final = -124
    """
    #included file name: name,,n_sect,0,address
    """

    DEBUG_N_PARAMS: typing.Final = -122
    """
    compiler parameters: name,,NO_SECT,0,0
    """

    DEBUG_N_VERSION: typing.Final = -120
    """
    compiler version: name,,NO_SECT,0,0
    """

    DEBUG_N_OLEVEL: typing.Final = -118
    """
    compiler -O level: name,,NO_SECT,0,0
    """

    DEBUG_N_PSYM: typing.Final = -96
    """
    parameter: name,,NO_SECT,type,offset
    """

    DEBUG_N_EINCL: typing.Final = -94
    """
    include file end: name,,NO_SECT,0,0
    """

    DEBUG_N_ENTRY: typing.Final = -92
    """
    alternate entry: name,,n_sect,linenumber,address
    """

    DEBUG_N_LBRAC: typing.Final = -64
    """
    left bracket: 0,,NO_SECT,nesting level,address
    """

    DEBUG_N_EXCL: typing.Final = -62
    """
    deleted include file: name,,NO_SECT,0,sum
    """

    DEBUG_N_RBRAC: typing.Final = -32
    """
    right bracket: 0,,NO_SECT,nesting level,address
    """

    DEBUG_N_BCOMM: typing.Final = -30
    """
    begin common: name,,NO_SECT,0,0
    """

    DEBUG_N_ECOMM: typing.Final = -28
    """
    end common: name,,n_sect,0,0
    """

    DEBUG_N_ECOML: typing.Final = -24
    """
    end common (local name): 0,,n_sect,0,address
    """

    DEBUG_N_LENG: typing.Final = -2
    """
    second stab entry with length information
    """

    SELF_LIBRARY_ORDINAL: typing.Final = 0
    MAX_LIBRARY_ORDINAL: typing.Final = -3
    DYNAMIC_LOOKUP_ORDINAL: typing.Final = -2
    EXECUTABLE_ORDINAL: typing.Final = -1

    def __init__(self):
        ...


class DyldInfoCommandConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    REBASE_TYPE_POINTER: typing.Final = 1
    REBASE_TYPE_TEXT_ABSOLUTE32: typing.Final = 2
    REBASE_TYPE_TEXT_PCREL32: typing.Final = 3
    REBASE_OPCODE_MASK: typing.Final = 240
    REBASE_IMMEDIATE_MASK: typing.Final = 15
    REBASE_OPCODE_DONE: typing.Final = 0
    REBASE_OPCODE_SET_TYPE_IMM: typing.Final = 16
    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: typing.Final = 32
    REBASE_OPCODE_ADD_ADDR_ULEB: typing.Final = 48
    REBASE_OPCODE_ADD_ADDR_IMM_SCALED: typing.Final = 64
    REBASE_OPCODE_DO_REBASE_IMM_TIMES: typing.Final = 80
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES: typing.Final = 96
    REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: typing.Final = 112
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: typing.Final = 128
    BIND_TYPE_POINTER: typing.Final = 1
    BIND_TYPE_TEXT_ABSOLUTE32: typing.Final = 2
    BIND_TYPE_TEXT_PCREL32: typing.Final = 3
    BIND_SPECIAL_DYLIB_SELF: typing.Final = 0
    BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: typing.Final = -1
    BIND_SPECIAL_DYLIB_FLAT_LOOKUP: typing.Final = -2
    BIND_SPECIAL_DYLIB_WEAK_LOOKUP: typing.Final = -3
    BIND_SYMBOL_FLAGS_WEAK_IMPORT: typing.Final = 1
    BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: typing.Final = 8
    BIND_OPCODE_MASK: typing.Final = 240
    BIND_IMMEDIATE_MASK: typing.Final = 15
    BIND_OPCODE_DONE: typing.Final = 0
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: typing.Final = 16
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: typing.Final = 32
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: typing.Final = 48
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: typing.Final = 64
    BIND_OPCODE_SET_TYPE_IMM: typing.Final = 80
    BIND_OPCODE_SET_ADDEND_SLEB: typing.Final = 96
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: typing.Final = 112
    BIND_OPCODE_ADD_ADDR_ULEB: typing.Final = 128
    BIND_OPCODE_DO_BIND: typing.Final = 144
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: typing.Final = 160
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: typing.Final = 176
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: typing.Final = 192
    BIND_OPCODE_THREADED: typing.Final = 208
    BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: typing.Final = 0
    BIND_SUBOPCODE_THREADED_APPLY: typing.Final = 1
    EXPORT_SYMBOL_FLAGS_KIND_MASK: typing.Final = 3
    EXPORT_SYMBOL_FLAGS_KIND_REGULAR: typing.Final = 0
    EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: typing.Final = 1
    EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: typing.Final = 2
    EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: typing.Final = 4
    EXPORT_SYMBOL_FLAGS_REEXPORT: typing.Final = 8
    EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: typing.Final = 16

    def __init__(self):
        ...


class LoadCommand(ghidra.app.util.bin.StructConverter):
    """
    Represents a load_command structure
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/loader.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`LoadCommand`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the load command
        :raises IOException: if there was an IO-related error
        """

    def getCommandName(self) -> str:
        """
        Gets the name of this load command
        
        :return: The name of this load command
        :rtype: str
        """

    def getCommandSize(self) -> int:
        """
        Gets the size of this load command in bytes
        
        :return: The size of this load command in bytes
        :rtype: int
        """

    def getCommandType(self) -> int:
        """
        Gets the type of this load command
        
        :return: The type of this load command
        :rtype: int
        """

    def getLinkerDataOffset(self) -> int:
        """
        Gets the file offset of this load command's "linker data".  Not all load commands with data
        will have linker data.  Linker data typically resides in the __LINKEDIT segment.
        
        :return: The file offset of this load command's "linker data", or 0 if it has no linker data
        :rtype: int
        """

    def getLinkerDataSize(self) -> int:
        """
        Gets the file size of this load command's "linker data". Not all load commands with data
        will have linker data.  Linker data typically resides in the __LINKEDIT segment.
        
        :return: The file size of this load command's "linker data", or 0 if it has no linker data
        :rtype: int
        """

    def getStartIndex(self) -> int:
        """
        Returns the binary start index of this load command
        
        :return: the binary start index of this load command
        :rtype: int
        """

    def markup(self, program: ghidra.program.model.listing.Program, header: ghidra.app.util.bin.format.macho.MachHeader, source: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks up this :obj:`LoadCommand` data with data structures and comments.  Assumes the
        program was imported as a Mach-O.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to mark up
        :param ghidra.app.util.bin.format.macho.MachHeader header: The Mach-O header
        :param java.lang.String or str source: A name that represents where the header came from (could be null)
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises CancelledException: if the user cancelled the operation
        """

    def markupRawBinary(self, header: ghidra.app.util.bin.format.macho.MachHeader, api: ghidra.program.flatapi.FlatProgramAPI, baseAddress: ghidra.program.model.address.Address, parentModule: ghidra.program.model.listing.ProgramModule, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks-up this :obj:`LoadCommand` with data structures and comments.  Assumes the program
        was imported as a Raw Binary.
        
        :param ghidra.app.util.bin.format.macho.MachHeader header: The Mach-O header
        :param ghidra.program.flatapi.FlatProgramAPI api: A :obj:`FlatProgramAPI`
        :param ghidra.program.model.address.Address baseAddress: The base address of the program
        :param ghidra.program.model.listing.ProgramModule parentModule: The parent :obj:`module <ProgramModule>` to create fragments
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        
        .. seealso::
        
            | :obj:`MachoBinaryAnalysisCommand`
        """

    @property
    def startIndex(self) -> jpype.JLong:
        ...

    @property
    def commandType(self) -> jpype.JInt:
        ...

    @property
    def commandName(self) -> java.lang.String:
        ...

    @property
    def linkerDataOffset(self) -> jpype.JLong:
        ...

    @property
    def linkerDataSize(self) -> jpype.JLong:
        ...

    @property
    def commandSize(self) -> jpype.JInt:
        ...


class SegmentNames(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SEG_PAGEZERO: typing.Final = "__PAGEZERO"
    """
    the pagezero segment which has no protections and catches NULL
    references for MH_EXECUTE files
    """

    SEG_TEXT: typing.Final = "__TEXT"
    """
    the traditional UNIX text segment
    """

    SEG_DATA: typing.Final = "__DATA"
    """
    the traditional UNIX data segment
    """

    SEG_OBJC: typing.Final = "__OBJC"
    """
    objective-C runtime segment
    """

    SEG_ICON: typing.Final = "__ICON"
    """
    the icon segment
    """

    SEG_LINKEDIT: typing.Final = "__LINKEDIT"
    """
    the segment containing all structs created and maintained by the link editor.  
    Created with -seglinkedit option to ld(1) for MH_EXECUTE and FVMLIB file types only
    """

    SEG_UNIXSTACK: typing.Final = "__UNIXSTACK"
    """
    the unix stack segment
    """

    SEG_IMPORT: typing.Final = "__IMPORT"
    """
    the segment for the self (dyld) modifying code 
    stubs that has read, write and execute permissions
    """

    SEG_TEXT_EXEC: typing.Final = "__TEXT_EXEC"
    SEG_PRELINK_TEXT: typing.Final = "__PRELINK_TEXT"
    SEG_BRANCH_STUBS: typing.Final = "__BRANCH_STUBS"
    SEG_BRANCH_GOTS: typing.Final = "__BRANCH_GOTS"

    def __init__(self):
        ...


class SymbolTableCommand(LoadCommand):
    """
    Represents a symtab_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loadCommandReader: ghidra.app.util.bin.BinaryReader, dataReader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader):
        """
        Creates and parses a new :obj:`SymbolTableCommand`
        
        :param ghidra.app.util.bin.BinaryReader loadCommandReader: A :obj:`reader <BinaryReader>` that points to the start of the load
        command
        :param ghidra.app.util.bin.BinaryReader dataReader: A :obj:`reader <BinaryReader>` that can read the data that the load command
        references.  Note that this might be in a different underlying provider.
        :param ghidra.app.util.bin.format.macho.MachHeader header: The :obj:`header <MachHeader>` associated with this load command
        :raises IOException: if an IO-related error occurs while parsing
        """

    def addSymbols(self, list: java.util.List[NList]):
        """
        Adds the given :obj:`List` of :obj:`NList`s to this symbol/string table, and adjusts the
        affected symbol table load command fields appropriately
        
        :param java.util.List[NList] list: The :obj:`List` of :obj:`NList`s to add
        """

    def getNumberOfSymbols(self) -> int:
        """
        An integer indicating the number of entries in the symbol table.
        
        :return: the number of entries in the symbol table
        :rtype: int
        """

    def getStringTableOffset(self) -> int:
        """
        An integer containing the byte offset from the start of the image to the
        location of the string table.
        
        :return: string table offset
        :rtype: int
        """

    def getStringTableSize(self) -> int:
        """
        An integer indicating the size (in bytes) of the string table.
        
        :return: string table size in bytes
        :rtype: int
        """

    def getSymbolAt(self, index: typing.Union[jpype.JInt, int]) -> NList:
        ...

    def getSymbolOffset(self) -> int:
        """
        An integer containing the byte offset from the start
        of the file to the location of the symbol table entries.
        The symbol table is an array of nlist data structures.
        
        :return: symbol table offset
        :rtype: int
        """

    def getSymbols(self) -> java.util.List[NList]:
        ...

    @property
    def symbolOffset(self) -> jpype.JLong:
        ...

    @property
    def symbolAt(self) -> NList:
        ...

    @property
    def numberOfSymbols(self) -> jpype.JLong:
        ...

    @property
    def stringTableSize(self) -> jpype.JLong:
        ...

    @property
    def stringTableOffset(self) -> jpype.JLong:
        ...

    @property
    def symbols(self) -> java.util.List[NList]:
        ...


class LoadCommandString(ghidra.app.util.bin.StructConverter):
    """
    Represents an lc_str union
    
    
    .. seealso::
    
        | :obj:`LoadCommand`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOffset(self) -> int:
        ...

    def getString(self) -> str:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...


class PreboundDynamicLibraryCommand(LoadCommand):
    """
    Represents a prebound_dylib_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLibraryName(self) -> str:
        """
        Returns library's path name.
        
        :return: library's path name
        :rtype: str
        """

    def getLinkedModules(self) -> str:
        """
        Returns bit vector of linked modules.
        
        :return: bit vector of linked modules
        :rtype: str
        """

    def getNumberOfModules(self) -> int:
        """
        Returns number of modules in library.
        
        :return: number of modules in library
        :rtype: int
        """

    @property
    def libraryName(self) -> java.lang.String:
        ...

    @property
    def numberOfModules(self) -> jpype.JLong:
        ...

    @property
    def linkedModules(self) -> java.lang.String:
        ...


class TwoLevelHintsCommand(LoadCommand):
    """
    Represents a twolevel_hints_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getHints(self) -> java.util.List[TwoLevelHint]:
        ...

    def getNumberOfHints(self) -> int:
        """
        Returns the number of hints in the hint table.
        
        :return: the number of hints in the hint table
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Returns the offset to the hint table.
        
        :return: the offset to the hint table
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def hints(self) -> java.util.List[TwoLevelHint]:
        ...

    @property
    def numberOfHints(self) -> jpype.JLong:
        ...


class FileSetEntryCommand(LoadCommand):
    """
    Represents a fileset_entry_command
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFileOffset(self) -> int:
        """
        Gets the file offset of the DYLIB
        
        :return: the file offset of the DYLIB
        :rtype: int
        """

    def getFileSetEntryId(self) -> LoadCommandString:
        """
        Gets the identifier of the DYLIB
        
        :return: the identifier of the DYLIB
        :rtype: LoadCommandString
        """

    def getReserved(self) -> int:
        """
        Gets the reserved field (should just be padding)
        
        :return: The reserved field
        :rtype: int
        """

    def getVMaddress(self) -> int:
        """
        Gets the virtual address of the DYLIB
        
        :return: The virtual address of the DYLIB
        :rtype: int
        """

    @property
    def vMaddress(self) -> jpype.JLong:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def fileSetEntryId(self) -> LoadCommandString:
        ...


class RunPathCommand(LoadCommand):
    """
    Represents a rpath_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPath(self) -> LoadCommandString:
        ...

    @property
    def path(self) -> LoadCommandString:
        ...


class FunctionStartsCommand(LinkEditDataCommand):
    """
    Represents a LC_FUNCTION_STARTS command.
    """

    class_: typing.ClassVar[java.lang.Class]

    def findFunctionStartAddrs(self, textSegmentAddr: ghidra.program.model.address.Address) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Finds the :obj:`List` of function start addresses
        
        :param ghidra.program.model.address.Address textSegmentAddr: The :obj:`Address` of the function starts' __TEXT segment
        :return: The :obj:`List` of function start addresses
        :rtype: java.util.List[ghidra.program.model.address.Address]
        :raises IOException: if there was an issue reading bytes
        """


class FixedVirtualMemorySharedLibraryCommand(ObsoleteCommand):
    """
    Represents a fvmlib_command structure.
    
    
    .. seealso::
    
        | `mach-o/loader.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]


class IdentCommand(ObsoleteCommand):
    """
    Represents a ident_command structure.
    
    
    .. seealso::
    
        | `mach-o/loader.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]


class EncryptedInformationCommand(LoadCommand):
    """
    Represents an encryption_info_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCryptID(self) -> int:
        ...

    def getCryptOffset(self) -> int:
        ...

    def getCryptSize(self) -> int:
        ...

    @property
    def cryptOffset(self) -> jpype.JLong:
        ...

    @property
    def cryptID(self) -> jpype.JInt:
        ...

    @property
    def cryptSize(self) -> jpype.JLong:
        ...


class DynamicLibraryCommand(LoadCommand):
    """
    Represents a dylib_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getDynamicLibrary(self) -> DynamicLibrary:
        """
        Returns the dynamically linked shared library.
        
        :return: the dynamically linked shared library
        :rtype: DynamicLibrary
        """

    @property
    def dynamicLibrary(self) -> DynamicLibrary:
        ...


class DyldInfoCommand(LoadCommand):
    """
    Represents a dyld_info_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBindOffset(self) -> int:
        """
        :return: The bind info offset
        :rtype: int
        """

    def getBindSize(self) -> int:
        """
        :return: The bind info size
        :rtype: int
        """

    def getBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        """
        :return: The binding table
        :rtype: ghidra.app.util.bin.format.macho.commands.dyld.BindingTable
        """

    def getExportOffset(self) -> int:
        """
        :return: The export info offset
        :rtype: int
        """

    def getExportSize(self) -> int:
        """
        :return: The export info size
        :rtype: int
        """

    def getExportTrie(self) -> ExportTrie:
        """
        :return: The export trie
        :rtype: ExportTrie
        """

    def getLazyBindOffset(self) -> int:
        """
        :return: The lazy bind info offset
        :rtype: int
        """

    def getLazyBindSize(self) -> int:
        """
        :return: The lazy bind info size
        :rtype: int
        """

    def getLazyBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        """
        :return: The lazy binding table
        :rtype: ghidra.app.util.bin.format.macho.commands.dyld.BindingTable
        """

    def getRebaseOffset(self) -> int:
        """
        :return: The rebase info offset
        :rtype: int
        """

    def getRebaseSize(self) -> int:
        """
        :return: The rebase info size
        :rtype: int
        """

    def getRebaseTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.RebaseTable:
        """
        :return: The rebase table
        :rtype: ghidra.app.util.bin.format.macho.commands.dyld.RebaseTable
        """

    def getWeakBindOffset(self) -> int:
        """
        :return: The weak bind info offset
        :rtype: int
        """

    def getWeakBindSize(self) -> int:
        """
        :return: The weak bind info size
        :rtype: int
        """

    def getWeakBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        """
        :return: The weak binding table
        :rtype: ghidra.app.util.bin.format.macho.commands.dyld.BindingTable
        """

    @property
    def weakBindSize(self) -> jpype.JLong:
        ...

    @property
    def lazyBindOffset(self) -> jpype.JLong:
        ...

    @property
    def bindSize(self) -> jpype.JLong:
        ...

    @property
    def exportSize(self) -> jpype.JLong:
        ...

    @property
    def rebaseTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.RebaseTable:
        ...

    @property
    def weakBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        ...

    @property
    def exportOffset(self) -> jpype.JLong:
        ...

    @property
    def bindOffset(self) -> jpype.JLong:
        ...

    @property
    def rebaseOffset(self) -> jpype.JLong:
        ...

    @property
    def rebaseSize(self) -> jpype.JLong:
        ...

    @property
    def weakBindOffset(self) -> jpype.JLong:
        ...

    @property
    def exportTrie(self) -> ExportTrie:
        ...

    @property
    def lazyBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        ...

    @property
    def bindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        ...

    @property
    def lazyBindSize(self) -> jpype.JLong:
        ...


class SubLibraryCommand(LoadCommand):
    """
    Represents a sub_library_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getSubLibraryName(self) -> LoadCommandString:
        ...

    @property
    def subLibraryName(self) -> LoadCommandString:
        ...


class LoadCommandFactory(java.lang.Object):
    """
    A factory used to create :obj:`LoadCommand`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getLoadCommand(reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader, splitDyldCache: ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache) -> LoadCommand:
        """
        Create and parses a :obj:`LoadCommand`
         
        
        NOTE: Parsing :obj:`LoadCommand`s whose data lives in the __LINKEDIT segment require that
        the __LINKEDIT :obj:`SegmentCommand` have already been parsed.  Thus, it is required that
        this method be called on :obj:`SegmentCommand`s before other types of :obj:`LoadCommand`s.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`reader <BinaryReader>` that points to the start of the load command
        :param ghidra.app.util.bin.format.macho.MachHeader header: The :obj:`header <MachHeader>` associated with this load command
        :param ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache splitDyldCache: The :obj:`SplitDyldCache` that this header resides in.  Could be null
        if a split DYLD cache is not being used.
        :return: A new :obj:`LoadCommand`
        :rtype: LoadCommand
        :raises IOException: if an IO-related error occurs while parsing
        :raises MachException: if the load command is invalid
        """


class SubClientCommand(LoadCommand):
    """
    Represents a sub_client_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getClientName(self) -> LoadCommandString:
        """
        Returns the client name.
        
        :return: the client name
        :rtype: LoadCommandString
        """

    @property
    def clientName(self) -> LoadCommandString:
        ...


class UnsupportedLoadCommand(LoadCommand):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ObsoleteCommand(LoadCommand):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...


class DynamicLibrary(ghidra.app.util.bin.StructConverter):
    """
    Represents a dylib structure.
    
    
    .. seealso::
    
        | `mach-o/loader.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, command: LoadCommand):
        ...

    def getCompatibilityVersion(self) -> int:
        ...

    def getCurrentVersion(self) -> int:
        ...

    def getName(self) -> LoadCommandString:
        ...

    def getTimestamp(self) -> int:
        ...

    @property
    def compatibilityVersion(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> LoadCommandString:
        ...

    @property
    def currentVersion(self) -> jpype.JInt:
        ...

    @property
    def timestamp(self) -> jpype.JInt:
        ...


class TableOfContents(ghidra.app.util.bin.StructConverter):
    """
    Represents a dylib_table_of_contents structure.
    
    
    .. seealso::
    
        | `mach-o/loader.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def getModuleIndex(self) -> int:
        """
        An index into the module table indicating the module in which this defined
        external symbol is defined.
        
        :return: an index into the module table
        :rtype: int
        """

    def getSymbolIndex(self) -> int:
        """
        An index into the symbol table indicating the defined external symbols
        to which this entry refers.
        
        :return: an index into the symbol table
        :rtype: int
        """

    @property
    def moduleIndex(self) -> jpype.JInt:
        ...

    @property
    def symbolIndex(self) -> jpype.JInt:
        ...


class LinkerOptionCommand(LoadCommand):
    """
    Represents a linker_option_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLinkerOptions(self) -> java.util.List[java.lang.String]:
        """
        Gets this :obj:`LinkerOptionCommand`'s linker options
        
        :return: This :obj:`LinkerOptionCommand`'s linker options
        :rtype: java.util.List[java.lang.String]
        """

    @property
    def linkerOptions(self) -> java.util.List[java.lang.String]:
        ...


class NList(ghidra.app.util.bin.StructConverter):
    """
    Represents an nlist and nlist_64 structure.
    
    
    .. seealso::
    
        | `EXTERNAL_HEADERS/mach-o/nlist.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/nlist.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, is32bit: typing.Union[jpype.JBoolean, bool]):
        ...

    def getDescription(self) -> int:
        """
        A 16-bit value providing additional information about this symbol.
        
        :return: a 16-bit value providing additional information about this symbol
        :rtype: int
        """

    def getLibraryOrdinal(self) -> int:
        ...

    def getSection(self) -> int:
        """
        An integer specifying the number of the section that this
        symbol can be found in, or NO_SECT if
        symbol is not found in a section of this image.
        
        :return: the number of the section
        :rtype: int
        """

    @typing.overload
    def getSize(self) -> int:
        ...

    @staticmethod
    @typing.overload
    def getSize(nlists: java.util.List[NList]) -> int:
        """
        Gets the size in bytes of the given :obj:`NList`s (including associated strings)
        
        :param java.util.List[NList] nlists: A :obj:`List` of :obj:`NList`s
        :return: The size in bytes of the given :obj:`NList`s (including associated strings)
        :rtype: int
        """

    def getString(self) -> str:
        """
        Returns the symbol string defined at the symbol table command
        string table offset plus n_strx.
        
        :return: the symbol string
        :rtype: str
        """

    def getStringTableIndex(self) -> int:
        """
        Returns the index into the string table.
        
        :return: the index into the string table
        :rtype: int
        """

    def getType(self) -> int:
        """
        Returns the symbol type flag.
        
        :return: the symbol type flag
        :rtype: int
        """

    def getValue(self) -> int:
        """
        An integer that contains the value of this symbol.
        The format of this value is different for each type of symbol.
        
        :return: the value of this symbol
        :rtype: int
        """

    def initString(self, reader: ghidra.app.util.bin.BinaryReader, stringTableOffset: typing.Union[jpype.JLong, int]):
        """
        Initialize the string from the string table.
         
        
        You MUST call this method after the NLIST element is created!
         
        
        Reading a large NList table can cause a large performance issue if the strings
        are initialized as the NList entry is created.  The string table indexes are
        scattered.  Initializing the strings linearly from the string table is much
        faster.
        
        :param ghidra.app.util.bin.BinaryReader reader: The BinaryReader
        :param jpype.JLong or int stringTableOffset: offset of the string table
        """

    def is32bit(self) -> bool:
        ...

    def isExternal(self) -> bool:
        ...

    def isIndirect(self) -> bool:
        ...

    def isLazyBind(self) -> bool:
        ...

    def isPrivateExternal(self) -> bool:
        ...

    def isSymbolicDebugging(self) -> bool:
        ...

    def isThumbSymbol(self) -> bool:
        ...

    def isTypeAbsolute(self) -> bool:
        ...

    def isTypePreboundUndefined(self) -> bool:
        ...

    def isTypeUndefined(self) -> bool:
        ...

    @property
    def lazyBind(self) -> jpype.JBoolean:
        ...

    @property
    def indirect(self) -> jpype.JBoolean:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def typeAbsolute(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> jpype.JShort:
        ...

    @property
    def privateExternal(self) -> jpype.JBoolean:
        ...

    @property
    def section(self) -> jpype.JByte:
        ...

    @property
    def type(self) -> jpype.JByte:
        ...

    @property
    def symbolicDebugging(self) -> jpype.JBoolean:
        ...

    @property
    def stringTableIndex(self) -> jpype.JInt:
        ...

    @property
    def thumbSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def external(self) -> jpype.JBoolean:
        ...

    @property
    def typePreboundUndefined(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def typeUndefined(self) -> jpype.JBoolean:
        ...

    @property
    def libraryOrdinal(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class RoutinesCommand(LoadCommand):
    """
    Represents a routines_command and routines_command_64 structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getInitializationRoutineAddress(self) -> int:
        """
        Address of initialization routine.
        
        :return: address of initialization routine
        :rtype: int
        """

    def getInitializationRoutineModuleIndex(self) -> int:
        """
        Index into the module table that the init routine is defined in.
        
        :return: index into the module table that the init routine is defined in
        :rtype: int
        """

    def getReserved1(self) -> int:
        ...

    def getReserved2(self) -> int:
        ...

    def getReserved3(self) -> int:
        ...

    def getReserved4(self) -> int:
        ...

    def getReserved5(self) -> int:
        ...

    def getReserved6(self) -> int:
        ...

    @property
    def initializationRoutineAddress(self) -> jpype.JLong:
        ...

    @property
    def initializationRoutineModuleIndex(self) -> jpype.JLong:
        ...

    @property
    def reserved3(self) -> jpype.JLong:
        ...

    @property
    def reserved2(self) -> jpype.JLong:
        ...

    @property
    def reserved1(self) -> jpype.JLong:
        ...

    @property
    def reserved6(self) -> jpype.JLong:
        ...

    @property
    def reserved5(self) -> jpype.JLong:
        ...

    @property
    def reserved4(self) -> jpype.JLong:
        ...


class SourceVersionCommand(LoadCommand):
    """
    Represents a source_version_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getVersion(self) -> int:
        """
        Returns the version A.B.C.D.E packed as a24.b.10.c10.d10.e10.
        
        :return: the version A.B.C.D.E packed as a24.b.10.c10.d10.e10
        :rtype: int
        """

    @property
    def version(self) -> jpype.JLong:
        ...


class EntryPointCommand(LoadCommand):
    """
    Represents an entry_point_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def getEntryOffset(self) -> int:
        """
        Returns the file (__TEXT) offset of main().
        
        :return: the file (__TEXT) offset of main()
        :rtype: int
        """

    def getStackSize(self) -> int:
        """
        Return the initial stack size, if not zero.
        
        :return: the initial stack size, if not zero
        :rtype: int
        """

    @property
    def stackSize(self) -> jpype.JLong:
        ...

    @property
    def entryOffset(self) -> jpype.JLong:
        ...


class DyldExportsTrieCommand(LinkEditDataCommand):
    """
    Represents a LC_DYLD_EXPORTS_TRIE command
    """

    class_: typing.ClassVar[java.lang.Class]

    def getExportTrie(self) -> ExportTrie:
        """
        Gets the :obj:`ExportTrie`
        
        :return: The :obj:`ExportTrie`
        :rtype: ExportTrie
        """

    @property
    def exportTrie(self) -> ExportTrie:
        ...



__all__ = ["VersionMinCommand", "SubFrameworkCommand", "CorruptLoadCommand", "DynamicSymbolTableConstants", "DynamicLibraryModule", "PrebindChecksumCommand", "DataInCodeEntry", "SegmentConstants", "ExportTrie", "DynamicLinkerCommand", "SymbolCommand", "LinkEditDataCommand", "TwoLevelHint", "DyldChainedFixupsCommand", "DynamicSymbolTableCommand", "UuidCommand", "CodeSignatureCommand", "SubUmbrellaCommand", "DataInCodeCommand", "DynamicLibraryReference", "BuildVersionCommand", "FixedVirtualMemoryFileCommand", "SegmentCommand", "LoadCommandTypes", "NListConstants", "DyldInfoCommandConstants", "LoadCommand", "SegmentNames", "SymbolTableCommand", "LoadCommandString", "PreboundDynamicLibraryCommand", "TwoLevelHintsCommand", "FileSetEntryCommand", "RunPathCommand", "FunctionStartsCommand", "FixedVirtualMemorySharedLibraryCommand", "IdentCommand", "EncryptedInformationCommand", "DynamicLibraryCommand", "DyldInfoCommand", "SubLibraryCommand", "LoadCommandFactory", "SubClientCommand", "UnsupportedLoadCommand", "ObsoleteCommand", "DynamicLibrary", "TableOfContents", "LinkerOptionCommand", "NList", "RoutinesCommand", "SourceVersionCommand", "EntryPointCommand", "DyldExportsTrieCommand"]
