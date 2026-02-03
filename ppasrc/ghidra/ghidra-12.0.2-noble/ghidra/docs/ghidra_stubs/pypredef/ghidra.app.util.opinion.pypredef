from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.pathmanager
import generic.jar
import ghidra.app.util
import ghidra.app.util.bin
import ghidra.app.util.bin.format
import ghidra.app.util.bin.format.elf
import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.bin.format.macho.prelink
import ghidra.app.util.bin.format.mz
import ghidra.app.util.bin.format.pe
import ghidra.app.util.bin.format.unixaout
import ghidra.app.util.importer
import ghidra.formats.gfilesystem
import ghidra.framework.model
import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util.classfinder
import ghidra.util.task
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import org.apache.commons.collections4 # type: ignore
import org.xml.sax # type: ignore


T = typing.TypeVar("T")


class SomLoader(AbstractProgramWrapperLoader):
    """
    A :obj:`Loader` for System Object Model files
    """

    class_: typing.ClassVar[java.lang.Class]
    SOM_NAME: typing.Final = "System Object Model (SOM)"

    def __init__(self):
        ...


class MzLoader(AbstractLibrarySupportLoader):
    """
    A :obj:`Loader` for processing old-style DOS MZ executables
    
    
    .. seealso::
    
        | `OSDev.org MZ <https://wiki.osdev.org/MZ>`_
    
        | `Notes on the format of DOS .EXE files <https://www.tavi.co.uk/phobos/exeformat.html>`_
    
        | `Removing the Mystery from SEGMENT : OFFSET Addressing <https://thestarman.pcministry.com/asm/debug/Segments.html>`_
    """

    @typing.type_check_only
    class RelocationFixup(java.lang.Record):
        """
        Stores a relocation's fixup information
        """

        class_: typing.ClassVar[java.lang.Class]

        def address(self) -> ghidra.program.model.address.SegmentedAddress:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def fileOffset(self) -> int:
            ...

        def hashCode(self) -> int:
            ...

        def relocation(self) -> ghidra.app.util.bin.format.mz.MzRelocation:
            ...

        def segment(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def valid(self) -> bool:
            ...


    class_: typing.ClassVar[java.lang.Class]
    MZ_NAME: typing.Final = "Old-style DOS Executable (MZ)"

    def __init__(self):
        ...


@typing.type_check_only
class AbstractPeDebugLoader(AbstractOrdinalSupportLoader):

    class_: typing.ClassVar[java.lang.Class]
    SHOW_LINE_NUMBERS_OPTION_NAME: typing.Final = "Show Debug Line Number Comments"
    """
    Loader option to display line numbers
    """



class IntelHexRecordReader(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def readRecord(line: typing.Union[java.lang.String, str]) -> IntelHexRecord:
        ...


@typing.type_check_only
class IntelHexMemImage(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LoaderService(java.lang.Object):
    """
    Factory and utility methods for working with :obj:`Loader`s.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACCEPT_ALL: typing.ClassVar[java.util.function.Predicate[Loader]]

    def __init__(self):
        ...

    @staticmethod
    def getAllLoaderNames() -> java.util.Collection[java.lang.String]:
        """
        Gets all known :obj:`Loader`s' names.
        
        :return: All known :obj:`Loader`s' names.  The :obj:`Loader` names are sorted
        according to their corresponding :obj:`Loader`s :meth:`natural 
        ordering <Loader.compareTo>`.
        :rtype: java.util.Collection[java.lang.String]
        """

    @staticmethod
    def getAllSupportedLoadSpecs(provider: ghidra.app.util.bin.ByteProvider) -> LoaderMap:
        """
        Gets all supported :obj:`LoadSpec`s for loading the given :obj:`ByteProvider`.
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` to load.
        :return: All supported :obj:`LoadSpec`s in the form of a :obj:`LoaderMap`.
        :rtype: LoaderMap
        """

    @staticmethod
    def getLoaderClassByName(name: typing.Union[java.lang.String, str]) -> java.lang.Class[Loader]:
        """
        Gets the :obj:`Loader` :obj:`Class` that corresponds to the given simple :obj:`Class`
        name.
        
        :param java.lang.String or str name: The name of the :obj:`Loader` to get the :obj:`Class` of.
        :return: The :obj:`Loader` :obj:`Class` that corresponds to the given simple :obj:`Class`
        name, or ``null`` if it does not exist.
        :rtype: java.lang.Class[Loader]
        """

    @staticmethod
    def getSupportedLoadSpecs(provider: ghidra.app.util.bin.ByteProvider, loaderFilter: java.util.function.Predicate[Loader]) -> LoaderMap:
        """
        Gets all supported :obj:`LoadSpec`s for loading the given :obj:`ByteProvider`.
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` to load.
        :param java.util.function.Predicate[Loader] loaderFilter: A :obj:`Predicate` that will filter out undesired :obj:`Loader`s.
        :return: All supported :obj:`LoadSpec`s in the form of a :obj:`LoaderMap`.
        :rtype: LoaderMap
        """


class BinaryLoader(AbstractProgramLoader):

    class_: typing.ClassVar[java.lang.Class]
    BINARY_NAME: typing.Final = "Raw Binary"
    OPTION_NAME_LEN: typing.Final = "Length"
    OPTION_NAME_FILE_OFFSET: typing.Final = "File Offset"
    OPTION_NAME_BASE_ADDR: typing.Final = "Base Address"
    OPTION_NAME_BLOCK_NAME: typing.Final = "Block Name"
    OPTION_NAME_IS_OVERLAY: typing.Final = "Overlay"

    def __init__(self):
        ...


class CoffLoader(AbstractLibrarySupportLoader):

    @typing.type_check_only
    class CoffPair(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        offset: jpype.JLong
        size: jpype.JLong


    class_: typing.ClassVar[java.lang.Class]
    COFF_NAME: typing.Final = "Common Object File Format (COFF)"
    FAKE_LINK_OPTION_NAME: typing.Final = "Attempt to link sections located at 0x0"

    def __init__(self):
        ...

    def isMicrosoftFormat(self) -> bool:
        """
        
        
        :return: true if this loader assumes the Microsoft variant of the COFF format
        :rtype: bool
        """

    @property
    def microsoftFormat(self) -> jpype.JBoolean:
        ...


class DyldCacheOptions(java.lang.Record):
    """
    Options from the :obj:`DyldCacheLoader`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fixupSlidePointers: typing.Union[jpype.JBoolean, bool], markupSlidePointers: typing.Union[jpype.JBoolean, bool], addSlidePointerRelocations: typing.Union[jpype.JBoolean, bool], processLocalSymbols: typing.Union[jpype.JBoolean, bool], markupLocalSymbols: typing.Union[jpype.JBoolean, bool], processDylibMemory: typing.Union[jpype.JBoolean, bool], processDylibSymbols: typing.Union[jpype.JBoolean, bool], processDylibExports: typing.Union[jpype.JBoolean, bool], markupDylibLoadCommandData: typing.Union[jpype.JBoolean, bool], processLibobjc: typing.Union[jpype.JBoolean, bool]):
        ...

    def addSlidePointerRelocations(self) -> bool:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def fixupSlidePointers(self) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def markupDylibLoadCommandData(self) -> bool:
        ...

    def markupLocalSymbols(self) -> bool:
        ...

    def markupSlidePointers(self) -> bool:
        ...

    def processDylibExports(self) -> bool:
        ...

    def processDylibMemory(self) -> bool:
        ...

    def processDylibSymbols(self) -> bool:
        ...

    def processLibobjc(self) -> bool:
        ...

    def processLocalSymbols(self) -> bool:
        ...

    def toString(self) -> str:
        ...


class ElfLoaderOptionsFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    PERFORM_RELOCATIONS_NAME: typing.Final = "Perform Symbol Relocations"
    APPLY_UNDEFINED_SYMBOL_DATA_NAME: typing.Final = "Apply Undefined Symbol Data"
    IMAGE_BASE_OPTION_NAME: typing.Final = "Image Base"
    IMAGE16_BASE_DEFAULT: typing.Final = 4096
    IMAGE32_BASE_DEFAULT: typing.Final = 65536
    IMAGE64_BASE_DEFAULT: typing.Final = 1048576
    IMAGE_DATA_IMAGE_BASE_OPTION_NAME: typing.Final = "Data Image Base"
    INCLUDE_OTHER_BLOCKS: typing.Final = "Import Non-Loaded Data"
    DISCARDABLE_SEGMENT_SIZE_OPTION_NAME: typing.Final = "Max Zero-Segment Discard Size"

    @staticmethod
    def applyUndefinedSymbolData(options: java.util.List[ghidra.app.util.Option]) -> bool:
        ...

    @staticmethod
    def getDataImageBaseOption(options: java.util.List[ghidra.app.util.Option]) -> str:
        ...

    @staticmethod
    def getImageBaseOption(options: java.util.List[ghidra.app.util.Option]) -> str:
        ...

    @staticmethod
    def getMaxSegmentDiscardSize(options: java.util.List[ghidra.app.util.Option]) -> int:
        ...


class ElfLoader(AbstractLibrarySupportLoader):
    """
    A :obj:`Loader` for processing executable and linking files (ELF).
    """

    class_: typing.ClassVar[java.lang.Class]
    ELF_NAME: typing.Final = "Executable and Linking Format (ELF)"
    ELF_ENTRY_FUNCTION_NAME: typing.Final = "entry"
    ELF_FILE_TYPE_PROPERTY: typing.Final = "ELF File Type"
    ELF_ORIGINAL_IMAGE_BASE_PROPERTY: typing.Final = "ELF Original Image Base"
    ELF_PRELINKED_PROPERTY: typing.Final = "ELF Prelinked"
    ELF_SOURCE_FILE_PROPERTY_PREFIX: typing.Final = "ELF Source File ["

    def __init__(self):
        ...

    @staticmethod
    def getElfOriginalImageBase(program: ghidra.program.model.listing.Program) -> int:
        """
        Getter for the :obj:`.ELF_ORIGINAL_IMAGE_BASE_PROPERTY` property.
        
        :param ghidra.program.model.listing.Program program: Ghidra program that has the property to get
        :return: Long value of the original image base, or null if the property is not present
        :rtype: int
        """


class LoaderMap(java.util.TreeMap[Loader, java.util.Collection[LoadSpec]]):
    """
    A :obj:`Map` of :obj:`Loader`s to their respective :obj:`LoadSpec`s.
     
    
    The :obj:`Loader` keys are sorted according to their :meth:`natural 
    ordering <Loader.compareTo>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DecompileDebugXmlLoader(AbstractProgramLoader):
    """
    Loader for handling XML files generated by the Decompiler on the central function that was in the
    Decompiler pane when the Debug Function Decompilation feature in the Decompiler is used.
     
    Reference @DecompileDebug.java for the generation of the XML file.
    """

    @typing.type_check_only
    class ParseGhidraDebugResult(java.lang.Object):
        """
        Class to organize the XML format handler and the program info as extracted from the 
        uploaded decompiler debug XML file.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DecompileDebugProgramInfo(java.lang.Record):
        """
        Hold program details from the spec string for loading. Object is then passed forward in the 
        .getProgramInfo() function implemented in @DecompileDebugFormatManager.java and populated by @DecompileDebugXmlLoader.java.
        """

        class_: typing.ClassVar[java.lang.Class]

        def compilerString(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def offset(self) -> str:
            ...

        def specString(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DECOMPILER_DEBUG_SRC_NAME: typing.Final = "Decompiler Debug XML"

    def __init__(self):
        ...


class DyldCacheUtils(java.lang.Object):
    """
    Utilities methods for working with Mach-O DYLD shared cache binaries.
    """

    class DyldCacheImageRecord(java.lang.Record):
        """
        A :obj:`DyldCacheImage` and its corresponding metadata
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, image: ghidra.app.util.bin.format.macho.dyld.DyldCacheImage, splitCacheIndex: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def image(self) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheImage:
            ...

        def splitCacheIndex(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class SplitDyldCache(java.io.Closeable):
        """
        Class to store a "split" DYLD Cache, which is split across several subcache files (base file,
        .1, .2, .symbols, etc).
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, baseProvider: ghidra.app.util.bin.ByteProvider, shouldProcessLocalSymbols: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
            """
            Creates a new :obj:`SplitDyldCache`
            
            :param ghidra.app.util.bin.ByteProvider baseProvider: The :obj:`ByteProvider` of the "base" DYLD Cache file
            :param jpype.JBoolean or bool shouldProcessLocalSymbols: True if local symbols should be processed; otherwise, 
            false
            :param ghidra.app.util.importer.MessageLog log: The log
            :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
            :raises IOException: If there was an IO-related issue with processing the split DYLD Cache
            :raises CancelledException: If the user canceled the operation
            """

        @typing.overload
        def __init__(self, providers: java.util.List[ghidra.app.util.bin.ByteProvider], headers: java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader], names: java.util.List[java.lang.String], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
            """
            Creates a new :obj:`SplitDyldCache`
            
            :param java.util.List[ghidra.app.util.bin.ByteProvider] providers: The cache's ordered :obj:`ByteProvider`s
            :param java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader] headers: The cache's ordered :obj:`DyldCacheHeader`s
            :param java.util.List[java.lang.String] names: The cache's ordered names
            :param ghidra.app.util.importer.MessageLog log: The log
            :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
            """

        def getBaseAddress(self) -> int:
            """
            Gets the base address of the split DYLD cache.  This is where the cache should be loaded 
            in memory.
            
            :return: The base address of the split DYLD cache
            :rtype: int
            """

        def getDyldCacheHeader(self, i: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader:
            """
            Gets the i'th :obj:`DyldCacheHeader` in the split DYLD Cache
            
            :param jpype.JInt or int i: The index of the :obj:`DyldCacheHeader` to get
            :return: The i'th :obj:`DyldCacheHeader` in the split DYLD Cache
            :rtype: ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader
            """

        def getImageRecords(self) -> java.util.List[DyldCacheUtils.DyldCacheImageRecord]:
            """
            Gets all the :obj:`DyldCacheImageRecord`s from the entire cache
            
            :return: A :obj:`List` of :obj:`DyldCacheImageRecord`s from the entire cache
            :rtype: java.util.List[DyldCacheUtils.DyldCacheImageRecord]
            """

        def getLocalSymbolInfo(self) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo:
            """
            Gets the :obj:`DyldCacheLocalSymbolsInfo` from the split DYLD Cache files
            
            :return: The :obj:`DyldCacheLocalSymbolsInfo` from the split DYLD Cache files, or null 
            if no local symbols are defined
            :rtype: ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo
            """

        def getMacho(self, imageRecord: DyldCacheUtils.DyldCacheImageRecord) -> ghidra.app.util.bin.format.macho.MachHeader:
            """
            Gets the Mach-O of the given :obj:`DyldCacheImageRecord`.
             
            
            NOTE: The returned Mach-O is not yet :meth:`parsed <MachHeader.parse>`.
            
            :param DyldCacheUtils.DyldCacheImageRecord imageRecord: The desired Mach-O's :obj:`DyldCacheImageRecord`
            :return: The :obj:`DyldCacheImageRecord`'s Mach-O
            :rtype: ghidra.app.util.bin.format.macho.MachHeader
            :raises MachException: If there was a problem creating the :obj:`MachHeader`
            :raises IOException: If there was an IO-related error
            """

        def getName(self, i: typing.Union[jpype.JInt, int]) -> str:
            """
            Gets the i'th :obj:`name <String>` in the split DYLD Cache
            
            :param jpype.JInt or int i: The index of the :obj:`name <String>` to get
            :return: The i'th :obj:`name <String>` in the split DYLD Cache
            :rtype: str
            """

        def getProvider(self, i: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.ByteProvider:
            """
            Gets the i'th :obj:`ByteProvider` in the split DYLD Cache
            
            :param jpype.JInt or int i: The index of the :obj:`ByteProvider` to get
            :return: The i'th :obj:`ByteProvider` in the split DYLD Cache
            :rtype: ghidra.app.util.bin.ByteProvider
            """

        def size(self) -> int:
            """
            Gets the number of split DYLD Cache files
            
            :return: The number of split DYLD Cache files
            :rtype: int
            """

        @property
        def provider(self) -> ghidra.app.util.bin.ByteProvider:
            ...

        @property
        def dyldCacheHeader(self) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader:
            ...

        @property
        def baseAddress(self) -> jpype.JLong:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def imageRecords(self) -> java.util.List[DyldCacheUtils.DyldCacheImageRecord]:
            ...

        @property
        def localSymbolInfo(self) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo:
            ...

        @property
        def macho(self) -> ghidra.app.util.bin.format.macho.MachHeader:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getImageRecords(headers: java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader]) -> java.util.List[DyldCacheUtils.DyldCacheImageRecord]:
        """
        Gets all the :obj:`DyldCacheImageRecord`s for the given :obj:`List` of 
        :obj:`DyldCacheHeader`s
        
        :param java.util.List[ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader] headers: The :obj:`List` of :obj:`DyldCacheHeader`s
        :return: A :obj:`List` of :obj:`DyldCacheImageRecord`s
        :rtype: java.util.List[DyldCacheUtils.DyldCacheImageRecord]
        """

    @staticmethod
    @typing.overload
    def isDyldCache(program: ghidra.program.model.listing.Program) -> bool:
        """
        Determines if the given :obj:`Program` is a DYLD cache.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :return: True if the given :obj:`Program` is a DYLD cache; otherwise, false
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isDyldCache(provider: ghidra.app.util.bin.ByteProvider) -> bool:
        """
        Determines if the given :obj:`ByteProvider` is a DYLD cache.
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider`
        :return: True if the given :obj:`ByteProvider` is a DYLD cache; otherwise, false
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isDyldCache(signature: typing.Union[java.lang.String, str]) -> bool:
        """
        Determines if the given signature represents a DYLD cache signature with an architecture we
        support.
        
        :param java.lang.String or str signature: The DYLD cache signature
        :return: True if the given signature represents a DYLD cache signature with an architecture we
        support; otherwise, false
        :rtype: bool
        """


class QueryResult(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    pair: typing.Final[ghidra.program.model.lang.LanguageCompilerSpecPair]
    preferred: typing.Final[jpype.JBoolean]

    def __init__(self, pair: ghidra.program.model.lang.LanguageCompilerSpecPair, preferred: typing.Union[jpype.JBoolean, bool]):
        ...


class DyldCacheProgramBuilder(MachoProgramBuilder):
    """
    Builds up a DYLD Cache :obj:`Program` by parsing the DYLD Cache headers.
    """

    @typing.type_check_only
    class DyldCacheMachoInfo(java.lang.Object):
        """
        Convenience class to store information we need about an individual Mach-O.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, splitDyldCache: DyldCacheUtils.SplitDyldCache, header: ghidra.app.util.bin.format.macho.MachHeader, headerAddr: ghidra.program.model.address.Address, path: typing.Union[java.lang.String, str]):
            """
            Creates a new :obj:`DyldCacheMachoInfo` object with the given parameters.
            
            :param DyldCacheUtils.SplitDyldCache splitDyldCache: The :obj:`SplitDyldCache`
            :param ghidra.app.util.bin.format.macho.MachHeader header: The :meth:`unparsed <MachHeader.parse>` :obj:`MachHeader`
            :param ghidra.program.model.address.Address headerAddr: The Mach-O's header address
            :param java.lang.String or str path: The path of the Mach-O
            :raises java.lang.Exception: If there was a problem handling the Mach-O info
            """

        def addToProgramTree(self):
            """
            Adds an entry to the program tree for this Mach-O.  An entry consists of a 
            :obj:`module <ProgramModule>` named the path of this Mach-O in the DYLD Cache, and
            :obj:`fragments <ProgramFragment>` for each of this Mach-O's segments and sections.
            
            :raises java.lang.Exception: If there was a problem adding this Mach-O to the program tree
            """

        def createExports(self) -> bool:
            """
            Creates exports for this Mach-O.
            
            :return: True if exports were created; otherwise, false
            :rtype: bool
            :raises java.lang.Exception: If there was a problem creating exports for this Mach-O
            """

        def createSymbols(self, processExports: typing.Union[jpype.JBoolean, bool]):
            """
            Creates symbols for this Mach-O (does not include exports).
            
            :param jpype.JBoolean or bool processExports: True if symbol table exports should be processed; otherwise, false
            :raises java.lang.Exception: If there was a problem creating symbols for this Mach-O
            
            .. seealso::
            
                | :obj:`DyldCacheProgramBuilder.processSymbolTables(MachHeader, boolean)`
            """

        def markupHeaders(self):
            """
            Marks up the Mach-O headers.
            
            :raises java.lang.Exception: If there was a problem marking up the Mach-O's headers
            
            .. seealso::
            
                | :obj:`DyldCacheProgramBuilder.markupHeaders(MachHeader, Address)`
            """

        def markupLoadCommandData(self):
            """
            Marks up the Mach-O load command data.
            
            :raises java.lang.Exception: If there was a problem marking up the Mach-O's load command data
            
            .. seealso::
            
                | :obj:`DyldCacheProgramBuilder.markupLoadCommandData(MachHeader, String)`
            """

        def processMemoryBlocks(self):
            """
            Processes memory blocks for this Mach-O.
            
            :raises java.lang.Exception: If there was a problem processing memory blocks for this Mach-O
            
            .. seealso::
            
                | :obj:`DyldCacheProgramBuilder.processMemoryBlocks(MachHeader, String, boolean, boolean)`
            """


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def buildProgram(program: ghidra.program.model.listing.Program, provider: ghidra.app.util.bin.ByteProvider, fileBytes: ghidra.program.database.mem.FileBytes, options: DyldCacheOptions, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Builds up a DYLD Cache :obj:`Program`.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to build up
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` that contains the DYLD Cache's bytes
        :param ghidra.program.database.mem.FileBytes fileBytes: Where the Mach-O's bytes came from
        :param DyldCacheOptions options: Options from the :obj:`DyldCacheLoader`
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
        :raises java.lang.Exception: if a problem occurs
        """


@typing.type_check_only
class ElfProgramBuilder(MemorySectionResolver, ghidra.app.util.bin.format.elf.ElfLoadHelper):

    @typing.type_check_only
    class RelocatableImageBaseProvider(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    BLOCK_SOURCE_NAME: typing.Final = "Elf Loader"
    PROCESS_ENTRY_CALLING_CONVENTION_NAME: typing.Final = "processEntry"


class MemorySectionResolver(java.lang.Object):

    @typing.type_check_only
    class AllocatedFileSectionRange(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ProxyAddressRange(ghidra.program.model.address.AddressRangeImpl):
        """
        Indicates range supplied by another section (same file region mapping)
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OverlayAddressRange(ghidra.program.model.address.AddressRangeImpl):
        """
        Indicates range must be converted to a named overlay
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    def addInitializedMemorySection(self, key: ghidra.app.util.bin.format.MemoryLoadable, fileOffset: typing.Union[jpype.JLong, int], numberOfBytes: typing.Union[jpype.JLong, int], startAddress: ghidra.program.model.address.Address, sectionName: typing.Union[java.lang.String, str], isReadable: typing.Union[jpype.JBoolean, bool], isWritable: typing.Union[jpype.JBoolean, bool], isExecutable: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str], isFragmentationOK: typing.Union[jpype.JBoolean, bool], isLoadedSection: typing.Union[jpype.JBoolean, bool]):
        """
        Add initialized memory "section" based upon a specified data source fileOffset.
        The last "section" defined will take precedence when resolving conflicts. Sections identified 
        as loaded will take precedence over those that are non-loaded.
        placed into memory
        
        :param ghidra.app.util.bin.format.MemoryLoadable key: the loadable section key which corresponds to this memory "section"
        :param jpype.JLong or int fileOffset: data source file offset.  It is assumed that all initialized
        "sections" draw from a single data source.
        :param jpype.JLong or int numberOfBytes: number of bytes within "section"
        :param ghidra.program.model.address.Address startAddress: desired physical start address of "section" (not overlay address)
        :param java.lang.String or str sectionName: name of "section"
        :param jpype.JBoolean or bool isReadable: true if "section" has read privilege
        :param jpype.JBoolean or bool isWritable: true if "section" has write privilege
        :param jpype.JBoolean or bool isExecutable: true if "section" has execute privilege
        :param java.lang.String or str comment: section comment (used as basis for block comment)
        :param jpype.JBoolean or bool isFragmentationOK: if true this memory section may be fragmented due to
        :param jpype.JBoolean or bool isLoadedSection: if true this memory section will take precedence over non-loaded sections
        conflict/overlap with other memory sections of higher precedence.
        :raises AddressOverflowException:
        """

    def addUninitializedMemorySection(self, key: ghidra.app.util.bin.format.MemoryLoadable, numberOfBytes: typing.Union[jpype.JLong, int], startAddress: ghidra.program.model.address.Address, sectionName: typing.Union[java.lang.String, str], isReadable: typing.Union[jpype.JBoolean, bool], isWritable: typing.Union[jpype.JBoolean, bool], isExecutable: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str], isFragmentationOK: typing.Union[jpype.JBoolean, bool]):
        """
        Add uninitialized memory "section".
        The last "section" defined will take precedence when resolving conflicts.
        
        :param ghidra.app.util.bin.format.MemoryLoadable key: the loadable section key which corresponds to this memory "section"
        :param jpype.JLong or int numberOfBytes: number of bytes within "section"
        :param ghidra.program.model.address.Address startAddress: desired physical start address of "section" (not overlay address)
        :param java.lang.String or str sectionName: name of "section"
        :param jpype.JBoolean or bool isReadable: true if "section" has read privilege
        :param jpype.JBoolean or bool isWritable: true if "section" has write privilege
        :param jpype.JBoolean or bool isExecutable: true if "section" has execute privilege
        :param java.lang.String or str comment: section comment (used as basis for block comment)
        :param jpype.JBoolean or bool isFragmentationOK: if true this memory section may be fragmented due to 
        conflict/overlap with other memory sections of higher precedence.
        :raises AddressOverflowException:
        """

    def getMemory(self) -> ghidra.program.model.mem.Memory:
        """
        Get program memory object
        
        :return: program memory
        :rtype: ghidra.program.model.mem.Memory
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get program object
        
        :return: program
        :rtype: ghidra.program.model.listing.Program
        """

    def resolve(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform final resolve of all defined memory "sections" to establish final memory mappings.
        This method will resolve all conflicts and create memory blocks within the associated program.
        
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException:
        """

    @property
    def memory(self) -> ghidra.program.model.mem.Memory:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class GzfLoader(Loader):
    """
    Loads a packed Ghidra program.
    """

    class_: typing.ClassVar[java.lang.Class]
    GZF_NAME: typing.Final = "GZF Input Format"

    def __init__(self):
        ...


class MSCoffLoader(CoffLoader):

    class_: typing.ClassVar[java.lang.Class]
    MSCOFF_NAME: typing.Final = "MS Common Object File Format (COFF)"

    def __init__(self):
        ...


class IntelHexLoader(AbstractProgramLoader):

    class_: typing.ClassVar[java.lang.Class]
    INTEL_HEX_NAME: typing.Final = "Intel Hex"

    def __init__(self):
        ...


class MotorolaHexLoader(AbstractProgramLoader):

    class_: typing.ClassVar[java.lang.Class]
    MOTOROLA_HEX_NAME: typing.Final = "Motorola Hex"

    def __init__(self):
        ...


class MachoProgramUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getNextAvailableAddress(program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        Gets the next available :obj:`Address` in the :obj:`Program`
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :return: The next available :obj:`Address` in the :obj:`Program`
        :rtype: ghidra.program.model.address.Address
        """


class AbstractLibrarySupportLoader(AbstractProgramLoader):
    """
    An abstract :obj:`Loader` that provides a framework to conveniently load :obj:`Program`s with
    support for linking against libraries contained in other :obj:`Program`s.
     
    
    Subclasses may override various protected methods to customize how libraries are loaded.
    """

    @typing.type_check_only
    class UnprocessedLibrary(java.lang.Record):
        """
        A library that has not been processed by the loader yet
        """

        class_: typing.ClassVar[java.lang.Class]

        def depth(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def temporary(self) -> bool:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class LibrarySearchPath(java.lang.Record):
        """
        A library search path
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def fsRef(self) -> ghidra.formats.gfilesystem.FileSystemRef:
            ...

        def hashCode(self) -> int:
            ...

        def relativeFsPath(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    LINK_EXISTING_OPTION_NAME: typing.Final = "Link Existing Project Libraries"
    """
    Option to attempt to fix up the :obj:`Loaded` :obj:`Program`'s external programs with
    libraries discovered in the project. This alone does not cause new library programs to be 
    loaded.
    """

    LINK_SEARCH_FOLDER_OPTION_NAME: typing.Final = "Project Library Search Folder"
    """
    Path of a :obj:`DomainFolder` to search for libraries
    """

    LOAD_LIBRARY_OPTION_NAME: typing.Final = "Load Libraries From Disk"
    """
    Whether or not to search for libraries on disk (or in a :obj:`GFileSystem`)
    """

    LIBRARY_SEARCH_PATH_DUMMY_OPTION_NAME: typing.Final = "Library Search Paths"
    """
    A dummy option used to produce a custom renderer to select library search paths.
    
    
    .. seealso::
    
        | :obj:`LibrarySearchPathDummyOption`
    """

    DEPTH_OPTION_NAME: typing.Final = "Recursive Library Load Depth"
    """
    How many levels of libraries to load
    """

    LIBRARY_DEST_FOLDER_OPTION_NAME: typing.Final = "Library Destination Folder"
    """
    Path of a :obj:`DomainFolder` to save libraries to. This location will also be used as
    a location to :obj:`search for already-loaded libraries <.LINK_EXISTING_OPTION_NAME>`.
    """

    MIRROR_LAYOUT_OPTION_NAME: typing.Final = "Mirror Library Disk Layout"
    LOAD_ONLY_LIBRARIES_OPTION_NAME: typing.Final = "Only Load Libraries"
    """
    A hidden option used by the :obj:`ImporterPlugin`'s "Load Libraries" action to inform this
    :obj:`Loader` that the :obj:`Program` to import has already been saved to the project and
    is currently open, and that only libraries should be loaded.
    """


    def __init__(self):
        ...


class OmfLoader(AbstractProgramWrapperLoader):
    """
    A :obj:`Loader` for Relocatable Object Module (OMF) files
    """

    class_: typing.ClassVar[java.lang.Class]
    OMF_NAME: typing.Final = "Relocatable Object Module Format (OMF)"
    MIN_BYTE_LENGTH: typing.Final = 11
    IMAGE_BASE: typing.Final = 8192
    MAX_UNINITIALIZED_FILL: typing.Final = 8192

    def __init__(self):
        ...


class QueryOpinionService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getQueryResultWithSecondaryMasking(secondaryKey: typing.Union[java.lang.String, str], byPrimary: collections.abc.Mapping) -> java.util.Set[QueryResult]:
        ...

    @staticmethod
    def query(loaderName: typing.Union[java.lang.String, str], primaryKey: typing.Union[java.lang.String, str], secondaryKey: typing.Union[java.lang.String, str]) -> java.util.List[QueryResult]:
        ...


class UnixAoutLoader(AbstractProgramWrapperLoader):
    """
    A :obj:`Loader` for processing UNIX-style A.out executables
     
    
    This style was also used by UNIX-like systems such as SunOS, BSD, and VxWorks, as well as some 
    early distributions of Linux. Although there do exist implementations of A.out with 64-bit and \
    GNU extensions, this loader does not currently support them.
    
    
    .. seealso::
    
        | `OSDev.org A.out <https://wiki.osdev.org/A.out>`_
    
        | `FreeBSD manpage <https://man.freebsd.org/cgi/man.cgi?a.out(5)>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    UNIX_AOUT_NAME: typing.Final = "UNIX A.out"
    OPTION_NAME_BASE_ADDR: typing.Final = "Base Address"

    def __init__(self):
        ...


class Loader(ghidra.util.classfinder.ExtensionPoint, java.lang.Comparable[Loader]):
    """
    An interface that all loaders must implement. A particular loader implementation should be 
    designed to identify one and only one file format.
     
    
    NOTE:  ALL loader CLASSES MUST END IN "Loader".  If not, the :obj:`ClassSearcher` will not find 
    them.
    """

    class ImporterSettings(java.lang.Record):
        """
        A :obj:`Loader` configuration
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, provider: ghidra.app.util.bin.ByteProvider, importName: typing.Union[java.lang.String, str], project: ghidra.framework.model.Project, projectRootPath: typing.Union[java.lang.String, str], mirrorFsLayout: typing.Union[jpype.JBoolean, bool], loadSpec: LoadSpec, options: java.util.List[ghidra.app.util.Option], consumer: java.lang.Object, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
            ...

        def consumer(self) -> java.lang.Object:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def importName(self) -> str:
            ...

        def importNameOnly(self) -> str:
            """
            :return: The name portion of the ``importName``, stripping off any leading path
            information that may be present
            :rtype: str
            """

        def importPathOnly(self) -> str:
            """
            :return: The path portion of the ``importName`` if present, stripping off the
            trailing name (could be the empty string)
            :rtype: str
            """

        def loadSpec(self) -> LoadSpec:
            ...

        def log(self) -> ghidra.app.util.importer.MessageLog:
            ...

        def mirrorFsLayout(self) -> bool:
            ...

        def monitor(self) -> ghidra.util.task.TaskMonitor:
            ...

        def options(self) -> java.util.List[ghidra.app.util.Option]:
            ...

        def project(self) -> ghidra.framework.model.Project:
            ...

        def projectRootPath(self) -> str:
            ...

        def provider(self) -> ghidra.app.util.bin.ByteProvider:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    COMMAND_LINE_ARG_PREFIX: typing.Final = "-loader"
    """
    A string prefixed to each loader headless command line argument to avoid naming conflicts 
    with other headless command line argument names
    """

    OPTIONS_PROJECT_SAVE_STATE_KEY: typing.Final = "LOADER_OPTIONS"
    """
    Key used to lookup and store all loader options in the project's saved state
    """

    loggingDisabled: typing.Final[jpype.JBoolean]
    """
    System property used to disable the loaders' message logs being echoed to the
    application.log file
    """


    def findSupportedLoadSpecs(self, provider: ghidra.app.util.bin.ByteProvider) -> java.util.Collection[LoadSpec]:
        """
        If this :obj:`Loader` supports loading the given :obj:`ByteProvider`, this methods returns
        a :obj:`Collection` of all supported :obj:`LoadSpec`s that contain discovered load 
        specification information that this :obj:`Loader` will need to load.  If this :obj:`Loader`
        cannot support loading the given :obj:`ByteProvider`, an empty :obj:`Collection` is
        returned.
        
        :param ghidra.app.util.bin.ByteProvider provider: The bytes being loaded.
        :return: A :obj:`Collection` of :obj:`LoadSpec`s that this :obj:`Loader` supports loading, 
        or an empty :obj:`Collection` if this :obj:`Loader` doesn't support loading the given 
        :obj:`ByteProvider`.
        :rtype: java.util.Collection[LoadSpec]
        :raises IOException: if there was an IO-related issue finding the :obj:`LoadSpec`s.
        """

    def getDefaultOptions(self, provider: ghidra.app.util.bin.ByteProvider, loadSpec: LoadSpec, domainObject: ghidra.framework.model.DomainObject, loadIntoProgram: typing.Union[jpype.JBoolean, bool], mirrorFsLayout: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.app.util.Option]:
        """
        Gets the default :obj:`Loader` options.
        
        :param ghidra.app.util.bin.ByteProvider provider: The bytes of the thing being loaded.
        :param LoadSpec loadSpec: The :obj:`LoadSpec`.
        :param ghidra.framework.model.DomainObject domainObject: The :obj:`DomainObject` being loaded.
        :param jpype.JBoolean or bool loadIntoProgram: True if the load is adding to an existing :obj:`DomainObject`; 
        otherwise, false.
        :param jpype.JBoolean or bool mirrorFsLayout: True if the filesystem layout should be mirrored when loading;
        otherwise, false
        :return: A list of the :obj:`Loader`'s default options.
        :rtype: java.util.List[ghidra.app.util.Option]
        """

    def getName(self) -> str:
        """
        Gets the :obj:`Loader`'s name, which is used both for display purposes, and to identify the 
        :obj:`Loader` in the opinion files.
        
        :return: The :obj:`Loader`'s name.
        :rtype: str
        """

    def getPreferredFileName(self, provider: ghidra.app.util.bin.ByteProvider) -> str:
        """
        The preferred file name to use when loading.
         
        
        The default behavior of this method is to return the (cleaned up) name of the given 
        :obj:`ByteProvider`.
         
        
        NOTE: This method may get called frequently, so only parse the given :obj:`ByteProvider`
        if absolutely necessary.
        
        :param ghidra.app.util.bin.ByteProvider provider: The bytes to load.
        :return: The preferred file name to use when loading, or ``null`` if a name could not
        be determined from the provider.
        :rtype: str
        """

    def getTier(self) -> LoaderTier:
        """
        For ordering purposes; lower tier numbers are more important (and listed
        first).
        
        :return: the tier of the loader
        :rtype: LoaderTier
        """

    def getTierPriority(self) -> int:
        """
        For ordering purposes; lower numbers are more important (and listed
        first, within its tier).
        
        :return: the ordering of the loader within its tier
        :rtype: int
        """

    def load(self, settings: Loader.ImporterSettings) -> LoadResults[ghidra.framework.model.DomainObject]:
        """
        Loads bytes in a particular format as a new :obj:`Loaded` :obj:`DomainObject`. Multiple
        :obj:`DomainObject`s may end up getting created, depending on the nature of the format.
        The :obj:`Loaded` :obj:`DomainObject`s are bundled together in a :obj:`LoadResults`
        object which provides convenience methods to operate on the entire group of :obj:`Loaded`
        :obj:`DomainObject`s. 
         
        
        Note that when the load completes, the returned :obj:`Loaded` :obj:`DomainObject`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded`
        :obj:`DomainObject`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
        :param Loader.ImporterSettings settings: The :obj:`ImporterSettings`.
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` 
        :obj:`DomainObject`s (created but not saved).
        :rtype: LoadResults[ghidra.framework.model.DomainObject]
        :raises LoadException: if the load failed in an expected way
        :raises IOException: if there was an IO-related problem loading.
        :raises CancelledException: if the user cancelled the load.
        :raises VersionException: if the load process tried to open an existing :obj:`DomainFile` 
        which was created with a newer or unsupported version of Ghidra
        """

    def loadInto(self, program: ghidra.program.model.listing.Program, settings: Loader.ImporterSettings):
        """
        Loads bytes into the specified :obj:`Program`.  This method will not create any new 
        :obj:`Program`s.  It is only for adding to an existing :obj:`Program`.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to load into.
        :param Loader.ImporterSettings settings: The :obj:`ImporterSettings`.
        :raises LoadException: if the load failed in an expected way.
        :raises IOException: if there was an IO-related problem loading.
        :raises CancelledException: if the user cancelled the load.
        """

    def loadsIntoNewFolder(self) -> bool:
        """
        Checks to see if this :obj:`Loader` loads into a new :obj:`DomainFolder` instead of a new
        :obj:`DomainFile`
        
        :return: True if this :obj:`Loader` loads into a new :obj:`DomainFolder` instead of a new
        :obj:`DomainFile`
        :rtype: bool
        """

    @typing.overload
    @deprecated("use supportsLoadIntoProgram(Program) instead so you can restrict what\n   types of Programs can get loaded into other types of Programs")
    def supportsLoadIntoProgram(self) -> bool:
        """
        Checks to see if this :obj:`Loader` supports loading into an existing :obj:`Program`.
         
        
        The default behavior of this method is to return false.
        
        :return: True if this :obj:`Loader` supports loading into an existing :obj:`Program`; 
        otherwise, false.
        :rtype: bool
        
        .. deprecated::
        
        use :meth:`supportsLoadIntoProgram(Program) <.supportsLoadIntoProgram>` instead so you can restrict what
        types of :obj:`Program`s can get loaded into other types of :obj:`Program`s
        """

    @typing.overload
    def supportsLoadIntoProgram(self, program: ghidra.program.model.listing.Program) -> bool:
        """
        Checks to see if this :obj:`Loader` supports loading into the given :obj:`Program`.
         
        
        The default behavior of this method is to return false.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to load into
        :return: True if this :obj:`Loader` supports loading into the given :obj:`Program`; 
        otherwise, false.
        :rtype: bool
        """

    def validateOptions(self, provider: ghidra.app.util.bin.ByteProvider, loadSpec: LoadSpec, options: java.util.List[ghidra.app.util.Option], program: ghidra.program.model.listing.Program) -> str:
        """
        Validates the :obj:`Loader`'s options and returns null if all options are valid; otherwise, 
        an error message describing the problem is returned.
        
        :param ghidra.app.util.bin.ByteProvider provider: The bytes of the thing being loaded.
        :param LoadSpec loadSpec: The proposed :obj:`LoadSpec`.
        :param java.util.List[ghidra.app.util.Option] options: The list of :obj:`Option`s to validate.
        :param ghidra.program.model.listing.Program program: existing program if the loader is adding to an existing program. If it is
        a fresh import, then this will be null.
        :return: null if all :obj:`Option`s are valid; otherwise, an error message describing the 
        problem is returned.
        :rtype: str
        """

    @property
    def tierPriority(self) -> jpype.JInt:
        ...

    @property
    def tier(self) -> LoaderTier:
        ...

    @property
    def preferredFileName(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


@typing.type_check_only
class DefExportLine(java.lang.Object):
    """
    An object to parse an EXPORTS line from a ".def" file.
    
    
    .. seealso::
    
        | `EXPORTS <https://learn.microsoft.com/en-us/cpp/build/reference/exports?view=msvc-170>`_
    """

    class_: typing.ClassVar[java.lang.Class]


class DefLoader(AbstractProgramWrapperLoader):
    """
    A :obj:`Loader` for processing Microsoft DEF files.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEF_NAME: typing.Final = "Module Definition (DEF)"
    NO_MAGIC: typing.Final = "0"

    def __init__(self):
        ...


class DyldCacheLoader(AbstractProgramWrapperLoader):
    """
    A :obj:`Loader` for DYLD shared cache files.
    """

    class_: typing.ClassVar[java.lang.Class]
    DYLD_CACHE_NAME: typing.Final = "DYLD Cache"

    def __init__(self):
        ...


class LoadResults(java.lang.Iterable[Loaded[T]], java.lang.AutoCloseable, typing.Generic[T]):
    """
    The result of a 
    :meth:`Loader.load(ghidra.app.util.opinion.Loader.ImporterSettings) <Loader.load>`. Provides convenient 
    access to and operations on the underlying :obj:`Loaded` :obj:`DomainObject`s that got loaded.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, loadedList: java.util.List[Loaded[T]]):
        """
        Creates a new :obj:`LoadResults` that contains the given non-empty :obj:`List` of 
        :obj:`Loaded` :obj:`DomainObject`s.  The first entry in the :obj:`List` is assumed to be
        the :meth:`primary <.getPrimary>` :obj:`Loaded` :obj:`DomainObject`.
         
        
        This object needs to be :meth:`closed <.close>` when done with it.
        
        :param java.util.List[Loaded[T]] loadedList: A :obj:`List` of :obj:`Loaded` :obj:`DomainObject`s
        :raises java.lang.IllegalArgumentException: if the provided :obj:`List` is null or empty
        """

    @typing.overload
    def __init__(self, loaded: Loaded[T]):
        """
        Creates a new :obj:`LoadResults` that contains the given :obj:`Loaded` 
        :obj:`DomainObject`. This :obj:`Loaded` :obj:`DomainObject` is assumed to be the 
        :meth:`primary <.getPrimary>` :obj:`Loaded` :obj:`DomainObject`.
        
        :param Loaded[T] loaded: The :obj:`Loaded` :obj:`DomainObject`
        """

    def close(self):
        """
        Closes this :obj:`LoadResults` and releases the reference on the object consuming it.
         
        
        NOTE: Any :obj:`DomainObject`s obtained via :meth:`getPrimaryDomainObject(Object) <.getPrimaryDomainObject>` must
        still be explicitly :meth:`released <DomainObject.release>` after calling this method,
        since they were obtained with their own consumers.
        """

    def getNonPrimary(self) -> java.util.List[Loaded[T]]:
        """
        Gets the "non-primary" :obj:`Loaded` :obj:`DomainObject`s, whose meaning is defined by each
        :obj:`Loader` implementation
        
        :return: The "non-primary" :obj:`Loaded` :obj:`DomainObject`s
        :rtype: java.util.List[Loaded[T]]
        """

    def getPrimary(self) -> Loaded[T]:
        """
        Gets the "primary" :obj:`Loaded` :obj:`DomainObject`, whose meaning is defined by each 
        :obj:`Loader` implementation
        
        :return: The "primary" :obj:`Loaded` :obj:`DomainObject`
        :rtype: Loaded[T]
        """

    @typing.overload
    def getPrimaryDomainObject(self, consumer: java.lang.Object) -> T:
        """
        Gets the "primary" :obj:`DomainObject`, whose meaning is defined by each :obj:`Loader` 
        implementation.
         
        
        NOTE: It is the responsibility of the caller to properly 
        :meth:`release <DomainObject.release>` it when done. This
        :meth:`DomainObject.release(Object) <DomainObject.release>` does not replace the requirement to 
        :meth:`close() <.close>` the :obj:`LoadResults` object when done.
        
        :param java.lang.Object consumer: A new reference to the object "consuming" the returned :obj:`DomainObject`,
        used to ensure the underlying :obj:`DomainObject` is only released when every consumer is
        done with it (see :meth:`DomainObject.release(Object) <DomainObject.release>`). NOTE: This method adds the given
        consumer to the returned :obj:`DomainObject`, requiring an explicit 
        :meth:`DomainObject.release(Object) <DomainObject.release>` to be called on the return value (this entire
        :obj:`LoadResults` must also still be :meth:`closed <.close>`).
        :return: The "primary" :obj:`DomainObject`
        :rtype: T
        """

    @typing.overload
    @deprecated("This class\'s internal DomainObjects are now cleaned up with the \n   close() method.  If the primary DomainObject needs to be retrieved from \n   this class, instead use getPrimaryDomainObject(Object) and independently clean up\n   the new reference with a separate call to DomainObject.release(Object).")
    def getPrimaryDomainObject(self) -> T:
        """
        Gets the "primary" loaded :obj:`DomainObject`, whose meaning is defined by each 
        :obj:`Loader` implementation. Unsafe resource management is used. Temporarily exists to 
        provide backwards compatibility.
        
        :return: The "primary" :obj:`DomainObject`
        :rtype: T
        
        .. deprecated::
        
        This class's internal :obj:`DomainObject`s are now cleaned up with the 
        :meth:`close() <.close>` method.  If the primary :obj:`DomainObject` needs to be retrieved from 
        this class, instead use :meth:`getPrimaryDomainObject(Object) <.getPrimaryDomainObject>` and independently clean up
        the new reference with a separate call to :meth:`DomainObject.release(Object) <DomainObject.release>`.
        """

    @typing.overload
    @deprecated("Use close() instead")
    def release(self, consumer: java.lang.Object):
        """
        Unsafely notifies all of the :obj:`Loaded` :obj:`DomainObject`s that the specified consumer
        is no longer using them. Temporarily exists to provide backwards compatibility.
        
        :param java.lang.Object consumer: the consumer
        
        .. deprecated::
        
        Use :meth:`close() <.close>` instead
        """

    @typing.overload
    @deprecated("Use close() instead")
    def release(self, consumer: java.lang.Object, filter: java.util.function.Predicate[Loaded[T]]):
        """
        Unsafely notifies the filtered :obj:`Loaded` :obj:`DomainObject`s that the specified 
        consumer is no longer using them. Temporarily exists to provide backwards compatibility.
        
        :param java.lang.Object consumer: the consumer
        :param java.util.function.Predicate[Loaded[T]] filter: a filter to apply to the :obj:`Loaded` :obj:`DomainObject`s prior to the
        release
        
        .. deprecated::
        
        Use :meth:`close() <.close>` instead
        """

    @deprecated("Use getNonPrimary() and Loaded.close() on the List \n   elements instead")
    def releaseNonPrimary(self, consumer: java.lang.Object):
        """
        Notify the non-primary :obj:`Loaded` :obj:`DomainObject`s that the specified consumer is no 
        longer using them. When the last consumer invokes this method, the non-primary :obj:`Loaded` 
        :obj:`DomainObject`s will be closed and will become invalid.
        
        :param java.lang.Object consumer: the consumer
        
        .. deprecated::
        
        Use :meth:`getNonPrimary() <.getNonPrimary>` and :meth:`Loaded.close() <Loaded.close>` on the :obj:`List` 
        elements instead
        """

    def save(self, monitor: ghidra.util.task.TaskMonitor):
        """
        :meth:`Saves <Loaded.save>` each :obj:`Loaded` :obj:`DomainObject` to the given 
        :obj:`Project`.
        
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
        :raises CancelledException: if the operation was cancelled
        :raises IOException: If there was a problem saving. A thrown exception may result in only some
        of the :obj:`Loaded` elements being saved. It is the responsibility of the caller to clean
        things up appropriately.
        :raises InvalidNameException: if saving with an invalid name
        
        .. seealso::
        
            | :obj:`Loaded.save(TaskMonitor)`
        """

    def size(self) -> int:
        """
        Gets the number of :obj:`Loaded` :obj:`DomainObject`s in this :obj:`LoadResults`.  The
        size will always be greater than 0.
        
        :return: The number of :obj:`Loaded` :obj:`DomainObject`s in this :obj:`LoadResults`
        :rtype: int
        """

    @property
    def nonPrimary(self) -> java.util.List[Loaded[T]]:
        ...

    @property
    def primaryDomainObject(self) -> T:
        ...

    @property
    def primary(self) -> Loaded[T]:
        ...


class LoaderTier(java.lang.Enum[LoaderTier]):

    class_: typing.ClassVar[java.lang.Class]
    SPECIALIZED_TARGET_LOADER: typing.Final[LoaderTier]
    GENERIC_TARGET_LOADER: typing.Final[LoaderTier]
    AMBIGUOUS_TARGET_LOADER: typing.Final[LoaderTier]
    UNTARGETED_LOADER: typing.Final[LoaderTier]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LoaderTier:
        ...

    @staticmethod
    def values() -> jpype.JArray[LoaderTier]:
        ...


class DecompileDebugFormatManager(java.lang.Object):
    """
    Main manager for handling the coordination of the parsing of the XML and loading of the program 
    details into Ghidra.
    """

    @typing.type_check_only
    class MyErrorHandler(org.xml.sax.ErrorHandler):
        """
        Simple handling of error messages
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Constructs a new program Decompiler Debug XML manager using the provided file.
        The file should be an XML file generated by the Ghidra Decompiler as a debug file.
        
        :param jpype.protocol.SupportsPath file: generated XML Decompile Debug file
        """

    @typing.overload
    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        """
        Constructs a new program Decompiler Debug XML manager using the provided ByteProvider.
         
        
        If :obj:`ByteProvider` has a :obj:`FSRL` and it is a simple local filepath,
        convert that to a normal local java.io.File instance instead of using the
        :obj:`ByteProvider`'s File property which is probably located in the
        :obj:`FileSystemService` filecache directory, which will break the ability
        to find the *.bytes file associated with this .xml file.
        
        :param ghidra.app.util.bin.ByteProvider provider: The provider
        """

    def getProgramInfo(self) -> DecompileDebugXmlLoader.DecompileDebugProgramInfo:
        """
        Initial parsing of the XML file to obtain the binary image info with load specs.
        
        :return: DecompileDebugProgramInfo binary image / load spec details
        :rtype: DecompileDebugXmlLoader.DecompileDebugProgramInfo
        :raises SAXException: If there was a problem parsing the XML
        :raises IOException: If there was an IO-related error
        """

    def read(self, prog: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, programName: typing.Union[java.lang.String, str]) -> ghidra.app.util.importer.MessageLog:
        """
        Perform the parsing from the underlying decompile debug XML file and populates the program fields.
        See @DecompileDebug.java for reference on the generation of the XML file.
        Tags currently supported/expected: 
         
        * ``<binaryimage>``
        * ``<coretypes>``
        * ``<typegrp>``
        * ``<save_state>``
        * ``<db>``
        * ``<commentdb>``
        * ``<stringmanage>``
        
        
        NOTE: the following subtree tags are not yet supported:
         
        * ``<context_points>``
        * ``<optionslist>``
        
        
        :param ghidra.program.model.listing.Program prog: created program
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :param java.lang.String or str programName: name of program
        :return: MessageLog
        :rtype: ghidra.app.util.importer.MessageLog
        :raises LoadException: If there is a parsing issue with the XML file.
        """

    @property
    def programInfo(self) -> DecompileDebugXmlLoader.DecompileDebugProgramInfo:
        ...


class MachoPrelinkProgramBuilder(MachoProgramBuilder):
    """
    Builds up a PRELINK Mach-O :obj:`Program` by parsing the Mach-O headers.
    """

    @typing.type_check_only
    class MachoInfo(java.lang.Object):
        """
        Convenience class to store information we need about an individual inner Mach-O
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, provider: ghidra.app.util.bin.ByteProvider, offset: typing.Union[jpype.JLong, int], headerAddr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]):
            """
            Creates a new :obj:`MachoInfo` object with the given parameters.
            
            :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` that contains the Mach-O's bytes.
            :param jpype.JLong or int offset: The offset in the provider to the start of the Mach-O.
            :param ghidra.program.model.address.Address headerAddr: The Mach-O's header address.
            :param java.lang.String or str name: The Mach-O's name.
            :raises java.lang.Exception: If there was a problem handling the Mach-O or PRELINK info.
            """

        def addToProgramTree(self):
            """
            Adds an entry to the program tree for this Mach-O.
            
            :raises java.lang.Exception: If there was a problem adding this Mach-O to the program tree.
            """

        def markupHeaders(self):
            """
            Marks up the Mach-O headers.
            
            :raises java.lang.Exception: If there was a problem marking up the Mach-O's headers.
            
            .. seealso::
            
                | :obj:`MachoProgramBuilder.markupHeaders(MachHeader, Address)`
            """

        def markupLoadCommandData(self):
            """
            Marks up the Mach-O load command data.
            
            :raises java.lang.Exception: If there was a problem marking up the Mach-O's load command data.
            
            .. seealso::
            
                | :obj:`MachoProgramBuilder.markupLoadCommandData(MachHeader, String)`
            """

        def processMemoryBlocks(self):
            """
            Processes memory blocks for this Mach-O.
            
            :raises java.lang.Exception: If there was a problem processing memory blocks for this Mach-O.
            
            .. seealso::
            
                | :obj:`MachoProgramBuilder.processMemoryBlocks(MachHeader, String, boolean, boolean)`
            """


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def buildProgram(program: ghidra.program.model.listing.Program, provider: ghidra.app.util.bin.ByteProvider, fileBytes: ghidra.program.database.mem.FileBytes, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Builds up a PRELINK Mach-O :obj:`Program`.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to build up.
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` that contains the Mach-O's bytes.
        :param ghidra.program.database.mem.FileBytes fileBytes: Where the Mach-O's bytes came from.
        :param ghidra.app.util.importer.MessageLog log: The log.
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor.
        :raises java.lang.Exception: if a problem occurs.
        """


class LoadException(java.io.IOException):
    """
    Thrown when a :meth:`load <Loader.load>`
    fails in an expected way.  The supplied message should explain the reason.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Create a new :obj:`LoadException` with the given message
        
        :param java.lang.String or str message: The exception message
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Create a new :obj:`LoadException` with the given message and cause
        
        :param java.lang.String or str message: The exception message
        :param java.lang.Throwable cause: The exception cause
        """

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        """
        Create a new :obj:`LoadException` with the given cause
        
        :param java.lang.Throwable cause: The exception cause
        """


class LoaderOpinionException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...


class QueryOpinionServiceHandler(java.lang.Object):

    @typing.type_check_only
    class FullQuery(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, fullQuery: QueryOpinionServiceHandler.FullQuery, loader: typing.Union[java.lang.String, str], primary: typing.Union[java.lang.String, str], secondary: typing.Union[java.lang.String, str], query: ghidra.program.model.lang.LanguageCompilerSpecQuery):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def read(parser: ghidra.xml.XmlPullParser):
        ...


@typing.type_check_only
class MemorySection(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getComment(self) -> str:
        ...

    def getFileOffset(self) -> int:
        ...

    def getKey(self) -> ghidra.app.util.bin.format.MemoryLoadable:
        ...

    def getMaxPhysicalAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the maximum physical address of the section
        (i.e., not an overlay address)
        
        :return: maximum physical address of the section
        :rtype: ghidra.program.model.address.Address
        """

    def getMinPhysicalAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the minimum physical address of the section
        (i.e., not an overlay address)
        
        :return: minimum physical address of the section
        :rtype: ghidra.program.model.address.Address
        """

    def getNumberOfBytes(self) -> int:
        ...

    def getPhysicalAddressRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the physical address range of the section
        (i.e., not an overlay address range)
        
        :return: physical address range of the section
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getPhysicalAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the physical address space of the section
        (i.e., not an overlay address space)
        
        :return: physical address space of the section
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getSectionName(self) -> str:
        ...

    def isExecute(self) -> bool:
        ...

    def isInitialized(self) -> bool:
        ...

    def isLoaded(self) -> bool:
        ...

    def isReadable(self) -> bool:
        ...

    def isWritable(self) -> bool:
        ...

    @property
    def readable(self) -> jpype.JBoolean:
        ...

    @property
    def minPhysicalAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def maxPhysicalAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @property
    def physicalAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def writable(self) -> jpype.JBoolean:
        ...

    @property
    def loaded(self) -> jpype.JBoolean:
        ...

    @property
    def sectionName(self) -> java.lang.String:
        ...

    @property
    def physicalAddressRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def initialized(self) -> jpype.JBoolean:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def numberOfBytes(self) -> jpype.JLong:
        ...

    @property
    def key(self) -> ghidra.app.util.bin.format.MemoryLoadable:
        ...


class PefLoader(AbstractProgramWrapperLoader):

    class_: typing.ClassVar[java.lang.Class]
    PEF_NAME: typing.Final = "Preferred Executable Format (PEF)"

    def __init__(self):
        ...


class ElfDataType(ghidra.program.model.data.FactoryStructureDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new ELF datatype.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...


class BoundedBufferedReader(java.io.Reader):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, in_: java.io.Reader, sz: typing.Union[jpype.JInt, int]):
        """
        Creates a buffering character-input stream that uses an input buffer of
        the specified size.
        
        :param java.io.Reader in: A Reader
        :param jpype.JInt or int sz: Input-buffer size
        :raises IllegalArgumentException: If sz is <= 0
        """

    @typing.overload
    def __init__(self, in_: java.io.Reader):
        """
        Creates a buffering character-input stream that uses a default-sized
        input buffer.
        
        :param java.io.Reader in: A Reader
        """

    def mark(self, readAheadLimit: typing.Union[jpype.JInt, int]):
        """
        Marks the present position in the stream. Subsequent calls to reset()
        will attempt to reposition the stream to this point.
        
        :param jpype.JInt or int readAheadLimit: Limit on the number of characters that may be read while still
                    preserving the mark. An attempt to reset the stream after
                    reading characters up to this limit or beyond may fail. A
                    limit value larger than the size of the input buffer will
                    cause a new buffer to be allocated whose size is no smaller
                    than limit. Therefore large values should be used with care.
        :raises IllegalArgumentException: If readAheadLimit is < 0
        :raises IOException: If an I/O error occurs
        """

    def markSupported(self) -> bool:
        """
        Tells whether this stream supports the mark() operation, which it does.
        """

    @typing.overload
    def read(self) -> int:
        """
        Reads a single character.
        
        :return: The character read, as an integer in the range 0 to 65535 (
                ``0x00-0xffff``), or -1 if the end of the stream has been
                reached
        :rtype: int
        :raises IOException: If an I/O error occurs
        """

    @typing.overload
    def read(self, cbuf: jpype.JArray[jpype.JChar], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Reads characters into a portion of an array.
         
         
        
        This method implements the general contract of the corresponding
        ``:meth:`read <Reader.read>``` method of the
        ``:obj:`Reader``` class. As an additional convenience, it
        attempts to read as many characters as possible by repeatedly invoking
        the ``read`` method of the underlying stream. This iterated
        ``read`` continues until one of the following conditions becomes
        true:
         
        * The specified number of characters have been read,
        * The read method of the underlying stream returns
        -1, indicating end-of-file, or
        * The ready method of the underlying stream returns
        false, indicating that further input requests would block.
        
        If the first ``read`` on the underlying stream returns
        ``-1`` to indicate end-of-file then this method returns
        ``-1``. Otherwise this method returns the number of characters
        actually read.
         
         
        
        Subclasses of this class are encouraged, but not required, to attempt to
        read as many characters as possible in the same fashion.
         
         
        
        Ordinarily this method takes characters from this stream's character
        buffer, filling it from the underlying stream as necessary. If, however,
        the buffer is empty, the mark is not valid, and the requested length is
        at least as large as the buffer, then this method will read characters
        directly from the underlying stream into the given array. Thus redundant
        ``BufferedReader``s will not copy data unnecessarily.
        
        :param jpype.JArray[jpype.JChar] cbuf: Destination buffer
        :param jpype.JInt or int off: Offset at which to start storing characters
        :param jpype.JInt or int len: Maximum number of characters to read
        :return: The number of characters read, or -1 if the end of the stream has
                been reached
        :rtype: int
        :raises IOException: If an I/O error occurs
        """

    def readLine(self) -> str:
        """
        Reads a line of text. A line is considered to be terminated by any one of
        a line feed ('\n'), a carriage return ('\r'), or a carriage return
        followed immediately by a linefeed.
        
        :return: A String containing the contents of the line, not including any
                line-termination characters, or null if the end of the stream has
                been reached
        :rtype: str
        :raises IOException: If an I/O error occurs
        """

    def ready(self) -> bool:
        """
        Tells whether this stream is ready to be read. A buffered character
        stream is ready if the buffer is not empty, or if the underlying
        character stream is ready.
        
        :raises IOException: If an I/O error occurs
        """

    def reset(self):
        """
        Resets the stream to the most recent mark.
        
        :raises IOException: If the stream has never been marked, or if the mark has
                        been invalidated
        """

    def skip(self, n: typing.Union[jpype.JLong, int]) -> int:
        """
        Skips characters.
        
        :param jpype.JLong or int n: The number of characters to skip
        :return: The number of characters actually skipped
        :rtype: int
        :raises IllegalArgumentException: If ``n`` is negative.
        :raises IOException: If an I/O error occurs
        """


@typing.type_check_only
class LibrarySymbolTable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def applyOrdinalFile(self, ordinalExportsFile: generic.jar.ResourceFile, addMissingOrdinals: typing.Union[jpype.JBoolean, bool]):
        """
        Parse a ordinal exports file produced by Microsoft DUMPBIN /EXPORTS <DLL>
        It is expected to start parsing lines following the table header containing the 'ordinal' header.
        Each ordinal mapping line is expected to have the format, starting with ordinal number and
        ending with symbol name:
        <ordinal> <other-column-data> <name>
        The name column contains the symbol name followed by an optional demangled form.  If the name starts with 
        [NONAME] this will be stripped.
        
        :param generic.jar.ResourceFile ordinalExportsFile: file path to ordinal mapping file produced by DUMPBIN /EXPORTS
        :param jpype.JBoolean or bool addMissingOrdinals: if true new entries will be created for ordinal mappings
        not already existing within this symbol table, otherwise only those which already
        exist will be updated with a name if specified by mapping file.
        """


@typing.type_check_only
class LibraryHints(java.lang.Object):
    """
    ``LibraryHints`` provides a means of specifying certain LIBRARY
    EXPORT attributes which should be included when the associated .exports file
    is created.
    """

    class_: typing.ClassVar[java.lang.Class]


class Loaded(java.lang.AutoCloseable, typing.Generic[T]):
    """
    A loaded :obj:`DomainObject` produced by a :obj:`Loader`.  In addition to storing the loaded
    :obj:`DomainObject`, it also stores the :obj:`Loader`'s desired name and project folder path 
    for the loaded :obj:`DomainObject`, should it get saved to a project.
    """

    @typing.type_check_only
    class MirroredLink(java.lang.Record):
        """
        A project link and its associated metadata that was created during the mirror process
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def linkFile(self) -> ghidra.framework.model.DomainFile:
            ...

        def projectLinkTarget(self) -> str:
            ...

        def relative(self) -> bool:
            ...

        def symlink(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, domainObject: T, name: typing.Union[java.lang.String, str], fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectRootPath: typing.Union[java.lang.String, str], mirrorFsLayout: typing.Union[jpype.JBoolean, bool], consumer: java.lang.Object):
        """
        Creates a new :obj:`Loaded` object.
         
        
        This object needs to be :meth:`closed <.close>` when done with it.
        
        :param T domainObject: The loaded :obj:`DomainObject`
        :param java.lang.String or str name: The name of the loaded :obj:`DomainObject`. Path information that appears at the
        beginning the name will be appended to the ``projectRootPath`` during a 
        :meth:`operation <.save>`.
        :param ghidra.formats.gfilesystem.FSRL fsrl: The :obj:`FSRL` of the loaded :obj:`DomainObject`
        :param ghidra.framework.model.Project project: If not ``null``, the project this will get saved to during a 
        :meth:`save(TaskMonitor) <.save>` operation
        :param java.lang.String or str projectRootPath: The project folder path that all :obj:`Loaded` :obj:`DomainObject`s
        will be :meth:`saved <.save>` relative to. If ``null``, "/" will be used.
        :param jpype.JBoolean or bool mirrorFsLayout: True if the filesystem layout should be mirrored when 
        :meth:`saving <.save>`; otherwise, false
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`Loaded` 
        :obj:`DomainObject`, used to ensure the underlying :obj:`DomainObject` is only closed 
        when every consumer is done with it (see :meth:`close() <.close>`). NOTE:  Wrapping a 
        :obj:`DomainObject` in a :obj:`Loaded` transfers responsibility of releasing the 
        given :obj:`DomainObject` to this :obj:`Loaded`'s :meth:`close() <.close>` method.
        """

    @typing.overload
    def __init__(self, domainObject: T, settings: Loader.ImporterSettings):
        """
        Creates a new :obj:`Loaded` object.
         
        
        This object needs to be :meth:`closed <.close>` when done with it.
        
        :param T domainObject: The loaded :obj:`DomainObject`
        :param Loader.ImporterSettings settings: The :obj:`Loader.ImporterSettings`.
        """

    def apply(self, operation: java.util.function.Consumer[T]):
        """
        Safely applies the given operation to the loaded :obj:`DomainObject` without the need to 
        worry about resource management
        
        :param java.util.function.Consumer[T] operation: The operation to apply to the loaded :obj:`DomainObject`
        """

    def check(self, predicate: java.util.function.Predicate[T]) -> bool:
        """
        Safely tests the given predicate on the loaded :obj:`DomainObject` without the need to 
        worry about resource management
        
        :param java.util.function.Predicate[T] predicate: The predicate to test
        :return: The result of the test
        :rtype: bool
        """

    def close(self):
        """
        Closes this :obj:`Loaded` :obj:`DomainObject` and releases the reference on the object
        consuming it.
         
        
        NOTE: Any :obj:`DomainObject`s obtained via :meth:`getDomainObject(Object) <.getDomainObject>` must still be
        explicitly :meth:`released <DomainObject.release>` after calling this method, since 
        they were obtained with their own consumers.
        """

    @typing.overload
    def getDomainObject(self, consumer: java.lang.Object) -> T:
        """
        Gets the loaded :obj:`DomainObject`.
         
        
        NOTE: The given It is the responsibility of the caller to properly 
        :meth:`release <DomainObject.release>` it when done. This
        :meth:`DomainObject.release(Object) <DomainObject.release>` does not replace the requirement to 
        :meth:`close() <.close>` the :obj:`Loaded` object when done.
        
        :param java.lang.Object consumer: A new reference to the object "consuming" the returned :obj:`DomainObject`,
        used to ensure the underlying :obj:`DomainObject` is only released when every consumer is
        done with it (see :meth:`DomainObject.release(Object) <DomainObject.release>`). NOTE: This method adds the given
        consumer to the returned :obj:`DomainObject`, requiring an explicit 
        :meth:`DomainObject.release(Object) <DomainObject.release>` to be called on the return value (this 
        :obj:`Loaded` must also still be :meth:`closed <.close>`).
        :return: The loaded :obj:`DomainObject`
        :rtype: T
        """

    @typing.overload
    @deprecated("This class\'s internal DomainObject is now cleaned up with the \n   close() method.  If the DomainObject needs to be retrieved from this \n   class, instead use getDomainObject(Object) and independently clean up the new\n   reference with a separate call to DomainObject.release(Object).")
    def getDomainObject(self) -> T:
        """
        Gets the loaded :obj:`DomainObject` with unsafe resource management. Temporarily exists
        to provide backwards compatibility.
        
        :return: The loaded :obj:`DomainObject`
        :rtype: T
        
        .. deprecated::
        
        This class's internal :obj:`DomainObject` is now cleaned up with the 
        :meth:`close() <.close>` method.  If the :obj:`DomainObject` needs to be retrieved from this 
        class, instead use :meth:`getDomainObject(Object) <.getDomainObject>` and independently clean up the new
        reference with a separate call to :meth:`DomainObject.release(Object) <DomainObject.release>`.
        """

    def getDomainObjectType(self) -> java.lang.Class[ghidra.framework.model.DomainObject]:
        """
        Gets the loaded :obj:`DomainObject`'s type
        
        :return: the loaded :obj:`DomainObject`'s type
        :rtype: java.lang.Class[ghidra.framework.model.DomainObject]
        """

    def getName(self) -> str:
        """
        Gets the name of the loaded :obj:`DomainObject`.  If a :meth:`save(TaskMonitor) <.save>` occurs, 
        this will attempted to be used for the resulting :obj:`DomainFile`'s name.
        
        :return: the name of the loaded :obj:`DomainObject`
        :rtype: str
        """

    def getProject(self) -> ghidra.framework.model.Project:
        """
        Gets the :obj:`Project` this will get saved to during a :meth:`save(TaskMonitor) <.save>` operation
        
        :return: The :obj:`Project` this will get saved to during a :meth:`save(TaskMonitor) <.save>` 
        operation (could be null)
        :rtype: ghidra.framework.model.Project
        """

    def getProjectFolderPath(self) -> str:
        """
        Gets the project folder path this will get saved to during a :meth:`save(TaskMonitor) <.save>` 
        operation.
         
        
        NOTE: The returned path will always end with a "/".
        
        :return: the project folder path
        :rtype: str
        """

    def getSavedDomainFile(self) -> ghidra.framework.model.DomainFile:
        """
        Gets the loaded :obj:`DomainObject`'s associated :obj:`DomainFile` that was
        :meth:`saved <.save>`
        
        :return: The loaded :obj:`DomainObject`'s associated saved :obj:`DomainFile`, or null if 
        was not saved
        :rtype: ghidra.framework.model.DomainFile
        :raises FileNotFoundException: If the loaded :obj:`DomainObject` was saved but the associated
        :obj:`DomainFile` no longer exists
        
        .. seealso::
        
            | :obj:`.save(TaskMonitor)`
        """

    @deprecated("Use close() instead")
    def release(self, consumer: java.lang.Object):
        """
        Unsafely notifies the loaded :obj:`DomainObject` that the specified consumer is no longer
        using it. Temporarily exists to provide backwards compatibility.
        
        :param java.lang.Object consumer: the consumer
        
        .. deprecated::
        
        Use :meth:`close() <.close>` instead
        """

    def save(self, monitor: ghidra.util.task.TaskMonitor) -> ghidra.framework.model.DomainFile:
        """
        Saves the loaded :obj:`DomainObject` to the given :obj:`Project` at this object's 
        project folder path, using this object's name.
         
        
        If a :obj:`DomainFile` already exists with the same desired name and project folder path,
        the desired name will get a counter value appended to it to avoid a naming conflict.
        Therefore, it should not be assumed that the returned :obj:`DomainFile` will have the same
        name as a call to :meth:`getName() <.getName>`.
        
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
        :return: The :obj:`DomainFile` where the save happened
        :rtype: ghidra.framework.model.DomainFile
        :raises CancelledException: if the operation was cancelled
        :raises ClosedException: if the loaded :obj:`DomainObject` was already closed
        :raises IOException: If there was an IO-related error, a project wasn't specified, an invalid
        name was specified, or it was already successfully saved and still exists
        :raises InvalidNameException: if saving with an invalid name
        """

    def setProjectFolderPath(self, projectRootPath: typing.Union[java.lang.String, str]):
        """
        Sets the project folder path this will get saved to during a :meth:`save(TaskMonitor) <.save>` 
        operation.
        
        :param java.lang.String or str projectRootPath: The project folder path that all :obj:`Loaded` :obj:`DomainObject`s
        will be saved relative to. If ``null``, "/" will be used.
        """

    @property
    def domainObjectType(self) -> java.lang.Class[ghidra.framework.model.DomainObject]:
        ...

    @property
    def projectFolderPath(self) -> java.lang.String:
        ...

    @projectFolderPath.setter
    def projectFolderPath(self, value: java.lang.String):
        ...

    @property
    def savedDomainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def project(self) -> ghidra.framework.model.Project:
        ...

    @property
    def domainObject(self) -> T:
        ...


class LoadSpec(java.lang.Object):
    """
    Represents a possible way for a :obj:`Loader` to load something.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, loader: Loader, imageBase: typing.Union[jpype.JLong, int], languageCompilerSpec: ghidra.program.model.lang.LanguageCompilerSpecPair, isPreferred: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a :obj:`LoadSpec` from a manually supplied :obj:`LanguageCompilerSpecPair`.
        
        :param Loader loader: This :obj:`LoadSpec`'s :obj:`Loader`.
        :param jpype.JLong or int imageBase: The desired image base address for the load.
        :param ghidra.program.model.lang.LanguageCompilerSpecPair languageCompilerSpec: The language/compiler spec ID.  If this is not needed or not 
        known, use :meth:`LoadSpec(Loader, long, boolean) <.LoadSpec>`.
        :param jpype.JBoolean or bool isPreferred: true if this :obj:`LoadSpec` is preferred; otherwise, false.
        """

    @typing.overload
    def __init__(self, loader: Loader, imageBase: typing.Union[jpype.JLong, int], languageCompilerSpecQueryResult: QueryResult):
        """
        Constructs a :obj:`LoadSpec` from a :obj:`QueryResult`.
        
        :param Loader loader: This :obj:`LoadSpec`'s :obj:`Loader`.
        :param jpype.JLong or int imageBase: The desired image base address for the load.
        :param QueryResult languageCompilerSpecQueryResult: The language/compiler spec ID.
        """

    @typing.overload
    def __init__(self, loader: Loader, imageBase: typing.Union[jpype.JLong, int], requiresLanguageCompilerSpec: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a :obj:`LoadSpec` with an unknown language/compiler.  Some :obj:`Loader`'s do
        not require a language/compiler.
        
        :param Loader loader: This :obj:`LoadSpec`'s :obj:`Loader`.
        :param jpype.JLong or int imageBase: The desired image base address for the load.
        :param jpype.JBoolean or bool requiresLanguageCompilerSpec: True if this :obj:`LoadSpec` requires a
        language/compiler; otherwise, false.  If a language/compiler is required, it will have
        to be supplied to the :obj:`Loader` by some other means, and this :obj:`LoadSpec` will
        be considered incomplete.
        
        .. seealso::
        
            | :obj:`.isComplete()`
        """

    def getDesiredImageBase(self) -> int:
        """
        Gets the desired image base to use during the load.
        
        :return: The desired image base to use during the load.
        :rtype: int
        """

    def getLanguageCompilerSpec(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        """
        Gets this :obj:`LoadSpec`'s :obj:`LanguageCompilerSpecPair`.
        
        :return: This :obj:`LoadSpec`'s :obj:`LanguageCompilerSpecPair`.  Could be null if this
        :obj:`LoadSpec` doesn't need or know the language/compiler.
        :rtype: ghidra.program.model.lang.LanguageCompilerSpecPair
        """

    def getLoader(self) -> Loader:
        """
        Gets this :obj:`LoadSpec`'s :obj:`Loader`.
        
        :return: This :obj:`LoadSpec`'s :obj:`Loader`.
        :rtype: Loader
        """

    def isComplete(self) -> bool:
        """
        Gets whether or not this :obj:`LoadSpec` is complete.  A :obj:`LoadSpec` is not considered
        complete if it requires a language/compiler to load something, but the language/compiler
        is currently unknown.
        
        :return: True if this :obj:`LoadSpec` is complete; otherwise, false.
        :rtype: bool
        """

    def isPreferred(self) -> bool:
        """
        Gets whether or not this :obj:`LoadSpec` is a preferred :obj:`LoadSpec`.
        
        :return: True if this :obj:`LoadSpec` is a preferred :obj:`LoadSpec`; otherwise, false.
        :rtype: bool
        """

    def requiresLanguageCompilerSpec(self) -> bool:
        """
        Gets whether or not this :obj:`LoadSpec` requires a language/compiler to load something.
        
        :return: True if this :obj:`LoadSpec` requires a language/compiler to load something; 
        otherwise, false.
        :rtype: bool
        """

    @property
    def desiredImageBase(self) -> jpype.JLong:
        ...

    @property
    def loader(self) -> Loader:
        ...

    @property
    def languageCompilerSpec(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    @property
    def complete(self) -> jpype.JBoolean:
        ...

    @property
    def preferred(self) -> jpype.JBoolean:
        ...


class LoadedOpen(Loaded[T], typing.Generic[T]):
    """
    A loaded, open :obj:`DomainObject` that has already been saved to a :obj:`DomainFile`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, domainObject: T, domainFile: ghidra.framework.model.DomainFile, fsrl: ghidra.formats.gfilesystem.FSRL, consumer: java.lang.Object):
        """
        Creates a :obj:`Loaded` view on an existing :obj:`DomainFile`. This type of :obj:`Loaded`
        object cannot be re-saved.
        
        :param T domainObject: The loaded :obj:`DomainObject`
        :param ghidra.framework.model.DomainFile domainFile: The :obj:`DomainFile` associated with the loaded :obj:`DomainObject`
        :param ghidra.formats.gfilesystem.FSRL fsrl: The :obj:`FSRL` of the loaded :obj:`DomainObject`
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`Loaded` 
        :obj:`DomainObject`, used to ensure the underlying :obj:`DomainObject` is only closed 
        when every consumer is done with it (see :meth:`close() <.close>`). NOTE:  Wrapping a 
        :obj:`DomainObject` in a :obj:`Loaded` transfers responsibility of releasing the 
        given :obj:`DomainObject` to this :obj:`Loaded`'s :meth:`close() <.close>` method.
        :raises LoadException: if the given :obj:`DomainFile` is not open
        """


class PeDataType(ghidra.program.model.data.FactoryStructureDataType):
    """
    A datatype for creating portable executable data structures.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new PE datatype.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...


class OpinionException(java.lang.Exception):
    """
    A class to represent an error when processing an opinion.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructs a new opinion exception with the specified detail message.
        
        :param java.lang.String or str msg: the detail message
        """

    @typing.overload
    def __init__(self, cause: java.lang.Exception):
        """
        Constructs a new exception with the specified cause
        
        :param java.lang.Exception cause: the cause of the exception
        """


class NeLoader(AbstractOrdinalSupportLoader):
    """
    A :obj:`Loader` for processing Microsoft New Executable (NE) files.
    """

    @typing.type_check_only
    class CallNameComparator(java.util.Comparator[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NE_NAME: typing.Final = "New Executable (NE)"

    def __init__(self):
        ...


class XmlLoader(AbstractProgramLoader):

    @typing.type_check_only
    class ParseResult(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    XML_SRC_NAME: typing.Final = "XML Input Format"

    def __init__(self):
        ...


class UnixAoutProgramLoader(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    dot_text: typing.Final = ".text"
    dot_data: typing.Final = ".data"
    dot_bss: typing.Final = ".bss"
    dot_rel_text: typing.Final = ".rel.text"
    dot_rel_data: typing.Final = ".rel.data"
    dot_strtab: typing.Final = ".strtab"
    dot_symtab: typing.Final = ".symtab"

    def __init__(self, program: ghidra.program.model.listing.Program, header: ghidra.app.util.bin.format.unixaout.UnixAoutHeader, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        ...

    def loadAout(self, baseAddr: typing.Union[jpype.JLong, int]):
        ...


class AddressSetPartitioner(java.lang.Iterable[ghidra.program.model.address.AddressRange]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, set: ghidra.program.model.address.AddressSet, rangeMap: collections.abc.Mapping, partitionSet: java.util.Set[ghidra.program.model.address.Address]):
        ...

    def getPartionedRangeMap(self) -> java.util.Map[ghidra.program.model.address.AddressRange, jpype.JArray[jpype.JByte]]:
        ...

    @property
    def partionedRangeMap(self) -> java.util.Map[ghidra.program.model.address.AddressRange, jpype.JArray[jpype.JByte]]:
        ...


@typing.type_check_only
class LibraryExportedSymbol(java.lang.Object):
    """
    A class to represent an exported symbol in a library (or DLL).
    """

    class_: typing.ClassVar[java.lang.Class]


class MachoProgramBuilder(java.lang.Object):
    """
    Builds up a Mach-O :obj:`Program` by parsing the Mach-O headers.
    """

    class_: typing.ClassVar[java.lang.Class]
    HEADER_SYMBOL: typing.Final = "MACH_HEADER"

    @staticmethod
    def buildProgram(program: ghidra.program.model.listing.Program, provider: ghidra.app.util.bin.ByteProvider, fileBytes: ghidra.program.database.mem.FileBytes, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Builds up a Mach-O :obj:`Program`.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to build up.
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` that contains the Mach-O's bytes.
        :param ghidra.program.database.mem.FileBytes fileBytes: Where the Mach-O's bytes came from.
        :param ghidra.app.util.importer.MessageLog log: The log.
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor.
        :raises java.lang.Exception: if a problem occurs.
        """

    @staticmethod
    def createOneByteFunction(program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        create a one-byte function, so that when the code is analyzed,
        it will be disassembled, and the function created with the correct body.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param java.lang.String or str name: the name of the function
        :param ghidra.program.model.address.Address address: location to create the function
        :return: If a function already existed at the given address, that function will be returned.
        Otherwise, the newly created function will be returned.  If there was a problem creating
        the function, null will be returned.
        :rtype: ghidra.program.model.listing.Function
        """

    @staticmethod
    def fixupExternalLibrary(program: ghidra.program.model.listing.Program, libraryPaths: java.util.List[java.lang.String], libraryOrdinal: typing.Union[jpype.JInt, int], symbol: typing.Union[java.lang.String, str]):
        """
        Associates the given :obj:`Symbol` with the correct external :obj:`Library` (fixing
        the ``<EXTERNAL>`` association)
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param java.util.List[java.lang.String] libraryPaths: A :obj:`List` of library paths
        :param jpype.JInt or int libraryOrdinal: The library ordinal
        :param java.lang.String or str symbol: The symbol
        :raises java.lang.Exception: if an unexpected problem occurs
        """

    def processChainedFixups(self, libraryPaths: java.util.List[java.lang.String]) -> java.util.List[ghidra.program.model.address.Address]:
        ...


class DbgLoader(AbstractPeDebugLoader):
    """
    An opinion service for processing Microsoft DBG files.
    """

    class_: typing.ClassVar[java.lang.Class]
    DBG_NAME: typing.Final = "Debug Symbols (DBG)"
    """
    DBG files are portable executable (PE) format files that contain debug
    information in Codeview format for the Visual Studio debugger (and
    possibly other formats, depending on how the DBG was created). When you
    do not have source for certain code, such libraries or Windows APIs, DBG
    files permit debugging. DBG files also permit you to do OLE RPC
    debugging. Microsoft Corporation. All rights reserved.
    """


    def __init__(self):
        ...


class Omf51Loader(AbstractProgramWrapperLoader):
    """
    A :obj:`Loader` for OMF-51 files
    """

    class_: typing.ClassVar[java.lang.Class]
    OMF51_NAME: typing.Final = "Object Module Format (OMF-51)"
    MIN_BYTE_LENGTH: typing.Final = 11

    def __init__(self):
        ...


class DecompileDebugByteManager(java.lang.Object):
    """
    Manager to hold byte information from the ``<bytechunk>`` tags inside the Decompiler Debug's 
    XML.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, prog: ghidra.program.model.listing.Program, programName: typing.Union[java.lang.String, str]):
        """
        
        
        :param ghidra.util.task.TaskMonitor monitor: TaskMonitor
        :param ghidra.program.model.listing.Program prog: main program
        :param java.lang.String or str programName: name of program
        """

    def parse(self, parser: ghidra.xml.XmlPullParser, log: ghidra.xml.XmlMessageLog):
        """
        Parse the ``<bytechunk>`` tag - has the memory offset and the raw bytes
        
        :param ghidra.xml.XmlPullParser parser: XmlPullParser
        :param ghidra.xml.XmlMessageLog log: Xml
        """


class LibraryLookupTable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def createFile(program: ghidra.program.model.listing.Program, overwrite: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> generic.jar.ResourceFile:
        ...

    @staticmethod
    @typing.overload
    def createFile(program: ghidra.program.model.listing.Program, overwrite: typing.Union[jpype.JBoolean, bool], inSystem: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> generic.jar.ResourceFile:
        ...


class DecompileDebugDataTypeManager(java.lang.Object):
    """
    Manager for parsing and storing data type objects from the XML - identified by 
    the ``<coretypes>`` and ``<typegrp>`` tags. 
     
    NOTE: In the typegrp subtree, ID is often on a different line from the element's name and 
    metatype, so we need a way to reference this for use in the map -- String idHolder var 
    helps with this.
    """

    @typing.type_check_only
    class DataTypeKey(java.lang.Record, java.lang.Comparable[DecompileDebugDataTypeManager.DataTypeKey]):
        """
        Data Types are organized by their name and ID; utilize a combo key structure for this organization
        Name, ID -> DataType
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, typeRefElement: ghidra.xml.XmlElement):
            ...

        @typing.overload
        def __init__(self, name: typing.Union[java.lang.String, str], id: typing.Union[java.lang.String, str]):
            ...

        @typing.overload
        def __init__(self, name: typing.Union[java.lang.String, str], id: typing.Union[java.lang.String, str], val: java.math.BigInteger):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def id(self) -> str:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...

        def val(self) -> java.math.BigInteger:
            ...


    class_: typing.ClassVar[java.lang.Class]
    dtConflictHandler: typing.ClassVar[ghidra.program.model.data.DataTypeConflictHandler]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, prog: ghidra.program.model.listing.Program):
        """
        
        
        :param ghidra.util.task.TaskMonitor monitor: TaskMonitor
        :param ghidra.program.model.listing.Program prog: main program info
        """

    def parseDataTypeTag(self, parser: ghidra.xml.XmlPullParser, log: ghidra.xml.XmlMessageLog) -> ghidra.program.model.data.DataType:
        """
        Parse Data Type tag, handling types:
         
        * ``<type>``
        * ``<typeref>``
        * ``<def>``
        * ``<void>``
        
        
        :param ghidra.xml.XmlPullParser parser: XmlPullParser
        :param ghidra.xml.XmlMessageLog log: XmlMessageLog
        :return: retrieved DataType
        :rtype: ghidra.program.model.data.DataType
        """


class IntelHexRecordWriter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, maxBytesPerLine: typing.Union[jpype.JInt, int], dropExtraBytes: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param jpype.JInt or int maxBytesPerLine: the maximum number of bytes to write per line in the hex output
        :param jpype.JBoolean or bool dropExtraBytes: if true, only lines matching :obj:`.maxBytesPerLine` will be output; 
        remaining bytes will be left out
        """

    def addByte(self, address: ghidra.program.model.address.Address, b: typing.Union[jpype.JByte, int]):
        ...

    def finish(self, entryPoint: ghidra.program.model.address.Address) -> java.util.List[IntelHexRecord]:
        ...


class GdtLoader(Loader):
    """
    Loads a packed Ghidra data type archive.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractOrdinalSupportLoader(AbstractLibrarySupportLoader):
    """
    An abstract :obj:`Loader` that provides support for programs that link to external libraries
    with an ordinal mechanism.  Supports caching library lookup information to XML files.
    """

    class_: typing.ClassVar[java.lang.Class]
    ORDINAL_LOOKUP_OPTION_NAME: typing.Final = "Perform Library Ordinal Lookup"

    def __init__(self):
        ...


class AbstractProgramWrapperLoader(AbstractProgramLoader):
    """
    An abstract :obj:`Loader` that provides a convenience wrapper around 
    :obj:`AbstractProgramLoader`, minimizing the amount of work a subclass needs to do to load a
    :obj:`Program`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MachoPrelinkUtils(java.lang.Object):
    """
    Utilities methods for working with Mach-O PRELINK binaries.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def findPrelinkMachoHeaderOffsets(provider: ghidra.app.util.bin.ByteProvider, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[java.lang.Long]:
        """
        Scans the provider looking for PRELINK Mach-O headers.  
         
        
        NOTE: The "System" Mach-O at offset 0 is not considered a PRELINK Mach-O.
         
        
        NOTE: We used to scan on 0x1000, and then 0x10 byte boundaries.  Now iOS 12 seems to 
        put them on 0x8-byte boundaries.
        
        :param ghidra.app.util.bin.ByteProvider provider: The provider to scan.
        :param ghidra.util.task.TaskMonitor monitor: A monitor.
        :return: A list of provider offsets where PRELINK Mach-O headers start (not including the
        "System" Mach-O at offset 0).
        :rtype: java.util.List[java.lang.Long]
        :raises IOException: If there was an IO-related issue searching for PRELINK Mach-O headers.
        """

    @staticmethod
    def getPrelinkStartAddr(header: ghidra.app.util.bin.format.macho.MachHeader) -> int:
        """
        Gets the start address of the PRELINK Mach-O's in memory.
         
        
        NOTE: This method only works for pre iOS 12 binaries.  If called on an iOS 12 binary, it will
        fail and return 0 because the __PRELINK_TEXT segment has a size of 0.  In this case, some
        other means of computing the start address of the PRELINK Mach-O's must be used.
        
        :param ghidra.app.util.bin.format.macho.MachHeader header: The Mach-O header.
        :return: The start address of the PRELINK Mach-O's in memory, or 0 if it could not be found.
        :rtype: int
        """

    @staticmethod
    def isMachoFileset(provider: ghidra.app.util.bin.ByteProvider) -> bool:
        """
        Check to see if the given :obj:`ByteProvider` is a Mach-O file set
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` to check
        :return: True if the given :obj:`ByteProvider` is a Mach-O file set; otherwise, false
        :rtype: bool
        """

    @staticmethod
    def isMachoPrelink(provider: ghidra.app.util.bin.ByteProvider, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Check to see if the given :obj:`ByteProvider` is a Mach-O PRELINK binary.
         
        
        NOTE: This method will return false if the binary is a Mach-O file set.
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider` to check
        :param ghidra.util.task.TaskMonitor monitor: A monitor
        :return: True if the given :obj:`ByteProvider` is a Mach-O PRELINK binary; otherwise, false
        :rtype: bool
        """

    @staticmethod
    def matchPrelinkToMachoHeaderOffsets(provider: ghidra.app.util.bin.ByteProvider, prelinkList: java.util.List[ghidra.app.util.bin.format.macho.prelink.MachoPrelinkMap], machoHeaderOffsets: java.util.List[java.lang.Long], monitor: ghidra.util.task.TaskMonitor) -> org.apache.commons.collections4.BidiMap[ghidra.app.util.bin.format.macho.prelink.MachoPrelinkMap, java.lang.Long]:
        """
        Forms a bidirectional mapping of PRELINK XML to Mach-O header offset in the given provider.
        
        :param ghidra.app.util.bin.ByteProvider provider: The PRELINK Mach-O provider.
        :param java.util.List[ghidra.app.util.bin.format.macho.prelink.MachoPrelinkMap] prelinkList: A list of :obj:`MachoPrelinkMap`s.
        :param java.util.List[java.lang.Long] machoHeaderOffsets: A list of provider offsets where PRELINK Mach-O headers start (not 
        including the "System" Mach-O at offset 0).
        :param ghidra.util.task.TaskMonitor monitor: A monitor
        :return: A bidirectional mapping of PRELINK XML to Mach-O header offset in the given provider.
        :rtype: org.apache.commons.collections4.BidiMap[ghidra.app.util.bin.format.macho.prelink.MachoPrelinkMap, java.lang.Long]
        :raises MachException: If there was a problem parsing a Mach-O header.
        :raises IOException: If there was an IO-related issue mapping PRELINK XML to Mach-O headers.
        """

    @staticmethod
    def parsePrelinkXml(provider: ghidra.app.util.bin.ByteProvider, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.app.util.bin.format.macho.prelink.MachoPrelinkMap]:
        """
        Parses the provider looking for PRELINK XML.
        
        :param ghidra.app.util.bin.ByteProvider provider: The provider to parse.
        :param ghidra.util.task.TaskMonitor monitor: A monitor.
        :return: A list of discovered :obj:`MachoPrelinkMap`s.  An empty list indicates that the provider
        did not represent valid Mach-O PRELINK binary.
        :rtype: java.util.List[ghidra.app.util.bin.format.macho.prelink.MachoPrelinkMap]
        :raises IOException: if there was an IO-related issue.
        :raises JDOMException: if there was a issue parsing the PRELINK XML.
        """


class MachoLoader(AbstractLibrarySupportLoader):
    """
    A :obj:`Loader` for Mach-O files.
    """

    class_: typing.ClassVar[java.lang.Class]
    MACH_O_NAME: typing.Final = "Mac OS X Mach-O"
    REEXPORT_OPTION_NAME: typing.Final = "Perform Reexports"

    def __init__(self):
        ...


class IntelHexRecord(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MAX_RECORD_LENGTH: typing.Final = 255
    DATA_RECORD_TYPE: typing.Final = 0
    END_OF_FILE_RECORD_TYPE: typing.Final = 1
    EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE: typing.Final = 2
    START_SEGMENT_ADDRESS_RECORD: typing.Final = 3
    EXTENDED_LINEAR_ADDRESS_RECORD_TYPE: typing.Final = 4
    START_LINEAR_ADDRESS_RECORD_TYPE: typing.Final = 5

    @typing.overload
    def __init__(self, recordLength: typing.Union[jpype.JInt, int], loadOffset: typing.Union[jpype.JInt, int], recordType: typing.Union[jpype.JInt, int], data: jpype.JArray[jpype.JByte], checksum: typing.Union[jpype.JInt, int]):
        """
        Use this constructor when reading, so you know if the record's checksum is correct.
        
        :param jpype.JInt or int recordLength: 
        :param jpype.JInt or int loadOffset: 
        :param jpype.JInt or int recordType: 
        :param jpype.JArray[jpype.JByte] data: 
        :param jpype.JInt or int checksum:
        """

    @typing.overload
    def __init__(self, recordLength: typing.Union[jpype.JInt, int], loadOffset: typing.Union[jpype.JInt, int], recordType: typing.Union[jpype.JInt, int], data: jpype.JArray[jpype.JByte]):
        """
        Only use this constructor when writing...it computes the checksum for you (cheating)!
        
        :param jpype.JInt or int recordLength: 
        :param jpype.JInt or int loadOffset: 
        :param jpype.JInt or int recordType: 
        :param jpype.JArray[jpype.JByte] data:
        """

    def format(self) -> str:
        ...

    def getActualChecksum(self) -> int:
        ...

    def getData(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getDataString(self) -> str:
        ...

    def getLoadOffset(self) -> int:
        ...

    def getRecordLength(self) -> int:
        ...

    def getRecordType(self) -> int:
        ...

    def getReportedChecksum(self) -> int:
        ...

    def isReportedChecksumCorrect(self) -> bool:
        ...

    @property
    def actualChecksum(self) -> jpype.JInt:
        ...

    @property
    def reportedChecksumCorrect(self) -> jpype.JBoolean:
        ...

    @property
    def reportedChecksum(self) -> jpype.JInt:
        ...

    @property
    def data(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def recordType(self) -> jpype.JInt:
        ...

    @property
    def recordLength(self) -> jpype.JInt:
        ...

    @property
    def dataString(self) -> java.lang.String:
        ...

    @property
    def loadOffset(self) -> jpype.JInt:
        ...


class DecompileDebugFunctionManager(java.lang.Object):
    """
    Manage the parsing and population of function objects. All functions are loaded the same way, 
    even if it's only referenced by the "central function" (the function that was in the decompiler 
    pane when the Decompile Debug (@DecompileDebug.java) feature was used).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, prog: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, dataTypeManager: DecompileDebugDataTypeManager):
        """
        Each function requires a program, task monitor and the program's Data Type Manager in order
        to be generated.
        
        :param ghidra.program.model.listing.Program prog: Program
        :param ghidra.util.task.TaskMonitor monitor: TaskMonitor
        :param DecompileDebugDataTypeManager dataTypeManager: Program's DataTypeManager
        """

    def parseFunctionSignature(self, parser: ghidra.xml.XmlPullParser, scopeMap: collections.abc.Mapping, log: ghidra.xml.XmlMessageLog):
        """
        Setup functions from within the ``<symbollist>`` tag.
        Functions referenced by the central function are loaded the same except we do not 
        (currently) have the memory/program context for them. Thus, they will show up in the Listing
        with a red "X". 
        NOTE: This is the expected functionality.
        
        :param ghidra.xml.XmlPullParser parser: XmlPullParser
        :param collections.abc.Mapping scopeMap: ``Map<String, Namespace>`` used for getting parent namespace
        :param ghidra.xml.XmlMessageLog log: XmlMessageLog
        """


class MapLoader(AbstractProgramWrapperLoader):
    """
    A :obj:`Loader` for processing Microsoft MAP files.
     
    
    Sample .map file section we parse to extract symbol information:
    `` ... ... ... Address         Publics by Value              Rva+Base               Lib:Object0000:00000000       ___safe_se_handler_table   0000000000000000     <absolute>0000:00000000       ___safe_se_handler_count   0000000000000000     <absolute>0000:00000000       __ImageBase                0000000140000000     <linker-defined>0001:00000040       foo                        0000000140001040 f   foo.obj0001:000000c0       bar                        00000001400010c0 f   foo.obj......Static symbols0000:00000020       blah                       0000000140000010     foo.dll0001:00000020       stuff                      0000000140000020     bar.dll.........``
    """

    @typing.type_check_only
    class MapSymbol(java.lang.Record):
        """
        Represents a MAP file symbol
        """

        class_: typing.ClassVar[java.lang.Class]

        def addr(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    MAP_NAME: typing.Final = "Program Mapfile (MAP)"
    NO_MAGIC: typing.Final = "0"

    def __init__(self):
        ...


class AbstractProgramLoader(Loader):
    """
    An abstract :obj:`Loader` that provides a framework to conveniently load :obj:`Program`s.
    Subclasses are responsible for the actual load.
     
    
    This :obj:`Loader` provides a couple processor-related options, as all :obj:`Program`s will
    have a processor associated with them.
    """

    class_: typing.ClassVar[java.lang.Class]
    APPLY_LABELS_OPTION_NAME: typing.Final = "Apply Processor Defined Labels"
    ANCHOR_LABELS_OPTION_NAME: typing.Final = "Anchor Processor Defined Labels"

    def __init__(self):
        ...

    @staticmethod
    def addExternalBlock(program: ghidra.program.model.listing.Program, size: typing.Union[jpype.JLong, int], log: ghidra.app.util.importer.MessageLog) -> ghidra.program.model.address.Address:
        """
        Adds the :obj:`EXERNAL block <MemoryBlock.EXTERNAL_BLOCK_NAME>` to memory, or adds to an
        existing one
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param jpype.JLong or int size: The desired size of the new EXTERNAL block
        :param ghidra.app.util.importer.MessageLog log: The :obj:`MessageLog`
        :return: The :obj:`Address` of the new (or new piece) of EXTERNAL block
        :rtype: ghidra.program.model.address.Address
        :raises java.lang.Exception: if there was an issue creating or adding to the EXTERNAL block
        """

    @staticmethod
    def markAsFunction(program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], funcStart: ghidra.program.model.address.Address):
        """
        Mark this address as a function by creating a one byte function.  The single byte body
        function is picked up by the function analyzer, disassembled, and the body fixed.
        Marking the function this way keeps disassembly and follow on analysis out of the loaders.
        
        :param ghidra.program.model.listing.Program program: the program
        :param java.lang.String or str name: name of function, null if name not known
        :param ghidra.program.model.address.Address funcStart: starting address of the function
        """

    @staticmethod
    def setProgramProperties(prog: ghidra.program.model.listing.Program, provider: ghidra.app.util.bin.ByteProvider, executableFormatName: typing.Union[java.lang.String, str]):
        """
        Sets a program's Executable Path, Executable Format, MD5, SHA256, and FSRL properties.
        
        :param ghidra.program.model.listing.Program prog: :obj:`Program` (with active transaction)
        :param ghidra.app.util.bin.ByteProvider provider: :obj:`ByteProvider` that the program was created from
        :param java.lang.String or str executableFormatName: executable format string
        :raises IOException: if error reading from ByteProvider
        """


class PeLoader(AbstractPeDebugLoader):
    """
    Microsoft Portable Executable (PE) loader.
    """

    class CompilerOpinion(java.lang.Object):

        class CompilerEnum(java.lang.Enum[PeLoader.CompilerOpinion.CompilerEnum]):

            class_: typing.ClassVar[java.lang.Class]
            VisualStudio: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            GCC: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            Clang: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            BorlandPascal: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            BorlandCpp: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            BorlandUnk: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            CLI: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            Rustc: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            GOLANG: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            Swift: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            Unknown: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            GCC_VS: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            GCC_VS_Clang: typing.Final[PeLoader.CompilerOpinion.CompilerEnum]
            label: typing.Final[java.lang.String]
            family: typing.Final[java.lang.String]

            @staticmethod
            def valueOf(name: typing.Union[java.lang.String, str]) -> PeLoader.CompilerOpinion.CompilerEnum:
                ...

            @staticmethod
            def values() -> jpype.JArray[PeLoader.CompilerOpinion.CompilerEnum]:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @staticmethod
        def getOpinion(pe: ghidra.app.util.bin.format.pe.PortableExecutable, provider: ghidra.app.util.bin.ByteProvider, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> PeLoader.CompilerOpinion.CompilerEnum:
            ...


    class_: typing.ClassVar[java.lang.Class]
    PE_NAME: typing.Final = "Portable Executable (PE)"
    """
    The name of the PE loader
    """

    HEADERS: typing.Final = "Headers"
    """
    The name of the PE headers memory block.
    """

    PARSE_CLI_HEADERS_OPTION_NAME: typing.Final = "Parse CLI headers (if present)"
    """
    PE loader option to control parsing CLI headers
    """


    def __init__(self):
        ...


class LibraryPathsDialog(docking.widgets.pathmanager.AbstractPathsDialog):
    """
    Dialog for editing Library Search Paths which are used by the importer to locate referenced
    shared libraries.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["SomLoader", "MzLoader", "AbstractPeDebugLoader", "IntelHexRecordReader", "IntelHexMemImage", "LoaderService", "BinaryLoader", "CoffLoader", "DyldCacheOptions", "ElfLoaderOptionsFactory", "ElfLoader", "LoaderMap", "DecompileDebugXmlLoader", "DyldCacheUtils", "QueryResult", "DyldCacheProgramBuilder", "ElfProgramBuilder", "MemorySectionResolver", "GzfLoader", "MSCoffLoader", "IntelHexLoader", "MotorolaHexLoader", "MachoProgramUtils", "AbstractLibrarySupportLoader", "OmfLoader", "QueryOpinionService", "UnixAoutLoader", "Loader", "DefExportLine", "DefLoader", "DyldCacheLoader", "LoadResults", "LoaderTier", "DecompileDebugFormatManager", "MachoPrelinkProgramBuilder", "LoadException", "LoaderOpinionException", "QueryOpinionServiceHandler", "MemorySection", "PefLoader", "ElfDataType", "BoundedBufferedReader", "LibrarySymbolTable", "LibraryHints", "Loaded", "LoadSpec", "LoadedOpen", "PeDataType", "OpinionException", "NeLoader", "XmlLoader", "UnixAoutProgramLoader", "AddressSetPartitioner", "LibraryExportedSymbol", "MachoProgramBuilder", "DbgLoader", "Omf51Loader", "DecompileDebugByteManager", "LibraryLookupTable", "DecompileDebugDataTypeManager", "IntelHexRecordWriter", "GdtLoader", "AbstractOrdinalSupportLoader", "AbstractProgramWrapperLoader", "MachoPrelinkUtils", "MachoLoader", "IntelHexRecord", "DecompileDebugFunctionManager", "MapLoader", "AbstractProgramLoader", "PeLoader", "LibraryPathsDialog"]
