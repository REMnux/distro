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
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class DyldCacheImageInfoExtra(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_image_info_extra structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheImageInfoExtra`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD image info extra
        :raises IOException: if there was an IO-related problem creating the DYLD image info extra
        """


class DyldCacheImageInfo(DyldCacheImage, ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_image_info structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheImageInfo`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD image info
        :raises IOException: if there was an IO-related problem creating the DYLD image info
        """


class DyldCacheAcceleratorDof(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_accelerator_dof structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheAcceleratorDof`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD accelerator DOF
        :raises IOException: if there was an IO-related problem creating the DYLD accelerator DOF
        """


class DyldChainedPtr(java.lang.Object):
    """
    
    
    
    .. seealso::
    
        | `mach-o/fixup-chains.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>`_
    """

    class DyldChainType(java.lang.Enum[DyldChainedPtr.DyldChainType]):

        class_: typing.ClassVar[java.lang.Class]
        DYLD_CHAINED_PTR_ARM64E: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_64: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_32: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_32_CACHE: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_32_FIRMWARE: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_64_OFFSET: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_ARM64E_KERNEL: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_64_KERNEL_CACHE: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_ARM64E_USERLAND: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_ARM64E_FIRMWARE: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_ARM64E_USERLAND24: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE: typing.Final[DyldChainedPtr.DyldChainType]
        DYLD_CHAINED_PTR_TYPE_UNKNOWN: typing.Final[DyldChainedPtr.DyldChainType]

        def getName(self) -> str:
            ...

        def getValue(self) -> int:
            ...

        @staticmethod
        def lookupChainPtr(val: typing.Union[jpype.JInt, int]) -> DyldChainedPtr.DyldChainType:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DyldChainedPtr.DyldChainType:
            ...

        @staticmethod
        def values() -> jpype.JArray[DyldChainedPtr.DyldChainType]:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def value(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DYLD_CHAINED_PTR_START_NONE: typing.Final = 65535
    DYLD_CHAINED_PTR_START_MULTI: typing.Final = 32768
    DYLD_CHAINED_PTR_START_LAST: typing.Final = 32768

    def __init__(self):
        ...

    @staticmethod
    def getAddend(ptrFormat: DyldChainedPtr.DyldChainType, chainValue: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def getChainValue(reader: ghidra.app.util.bin.BinaryReader, chainLoc: typing.Union[jpype.JLong, int], ptrFormat: DyldChainedPtr.DyldChainType) -> int:
        ...

    @staticmethod
    def getNext(ptrFormat: DyldChainedPtr.DyldChainType, chainValue: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def getOrdinal(ptrFormat: DyldChainedPtr.DyldChainType, chainValue: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def getSize(ptrFormat: DyldChainedPtr.DyldChainType) -> int:
        ...

    @staticmethod
    def getStride(ptrFormat: DyldChainedPtr.DyldChainType) -> int:
        ...

    @staticmethod
    def getTarget(ptrFormat: DyldChainedPtr.DyldChainType, chainValue: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def isAuthenticated(ptrFormat: DyldChainedPtr.DyldChainType, chainValue: typing.Union[jpype.JLong, int]) -> bool:
        ...

    @staticmethod
    def isBound(ptrFormat: DyldChainedPtr.DyldChainType, chainValue: typing.Union[jpype.JLong, int]) -> bool:
        ...

    @staticmethod
    def isRelative(ptrFormat: DyldChainedPtr.DyldChainType) -> bool:
        ...


class DyldCacheLocalSymbolsInfo(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_local_symbols_info structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, architecture: DyldArchitecture, use64bitOffsets: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new :obj:`DyldCacheLocalSymbolsInfo`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD local symbols info
        :param DyldArchitecture architecture: The :obj:`DyldArchitecture`
        :param jpype.JBoolean or bool use64bitOffsets: True if the DYLD local symbol entries use 64-bit dylib offsets; false
        if they use 32-bit
        :raises IOException: if there was an IO-related problem creating the DYLD local symbols info
        """

    def getLocalSymbolsEntries(self) -> java.util.List[DyldCacheLocalSymbolsEntry]:
        """
        Gets the :obj:`List` of :obj:`DyldCacheLocalSymbolsEntry`s.
        
        :return: The :obj:`List` of :obj:`DyldCacheLocalSymbolsEntry`
        :rtype: java.util.List[DyldCacheLocalSymbolsEntry]
        """

    @typing.overload
    def getNList(self) -> java.util.List[ghidra.app.util.bin.format.macho.commands.NList]:
        """
        Gets the :obj:`List` of :obj:`NList`.
        
        :return: The :obj:`List` of :obj:`NList`
        :rtype: java.util.List[ghidra.app.util.bin.format.macho.commands.NList]
        """

    @typing.overload
    def getNList(self, dylibOffset: typing.Union[jpype.JLong, int]) -> java.util.List[ghidra.app.util.bin.format.macho.commands.NList]:
        """
        Gets the :obj:`List` of :obj:`NList` for the given dylib offset.
        
        :param jpype.JLong or int dylibOffset: The offset of dylib in the DYLD Cache
        :return: The :obj:`List` of :obj:`NList` for the given dylib offset
        :rtype: java.util.List[ghidra.app.util.bin.format.macho.commands.NList]
        """

    def markup(self, program: ghidra.program.model.listing.Program, localSymbolsInfoAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks up this :obj:`DyldCacheLocalSymbolsInfo` with data structures and comments.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to mark up
        :param ghidra.program.model.address.Address localSymbolsInfoAddr: The :obj:`Address` of the :obj:`DyldCacheLocalSymbolsInfo`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises CancelledException: if the user cancelled the operation
        """

    def parse(self, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Parses the structures referenced by this :obj:`DyldCacheLocalSymbolsInfo`.
        
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :raises CancelledException: if the user cancelled the operation
        """

    @property
    def localSymbolsEntries(self) -> java.util.List[DyldCacheLocalSymbolsEntry]:
        ...

    @property
    def nList(self) -> java.util.List[ghidra.app.util.bin.format.macho.commands.NList]:
        ...


class LibObjcDylib(java.lang.Object):
    """
    A class to represent the libobjc DYLIB Mach-O that resides within a DYLD cache
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, libObjcHeader: ghidra.app.util.bin.format.macho.MachHeader, program: ghidra.program.model.listing.Program, space: ghidra.program.model.address.AddressSpace, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new :obj:`LibObjcDylib`
        
        :param ghidra.app.util.bin.format.macho.MachHeader libObjcHeader: The libobjc DYLIB header
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.AddressSpace space: The :obj:`AddressSpace`
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
        :raises IOException: if an IO-related error occurred while parsing
        """

    def markup(self):
        """
        Marks up the libobjc DYLIB
        """


class LibObjcOptimization(ghidra.app.util.bin.StructConverter):
    """
    Represents a objc_opt_t structure, which resides in the libobjc DYLIB within a DYLD cache
    
    
    .. seealso::
    
        | `dyld/include/objc-shared-cache.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/objc-shared-cache.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME: typing.Final = "__objc_opt_ro"
    """
    The name of the section that contains the objc_opt_t_structure
    """


    def __init__(self, program: ghidra.program.model.listing.Program, objcOptRoSectionAddr: ghidra.program.model.address.Address):
        """
        Create a new :obj:`LibObjcOptimization`.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.Address objcOptRoSectionAddr: The start address of the __objc_opt_ro section
        :raises IOException: if there was an IO-related problem parsing the structure
        """

    def getAddr(self) -> int:
        """
        Gets the address of the objc_opt_t structure
        
        :return: The address of the objc_opt_t structure
        :rtype: int
        """

    def getRelativeSelectorBaseAddressOffset(self) -> int:
        """
        Gets the relative method selector base address offset.  This will be 0 if the version is less
        than 16.
        
        :return: The relative method selector base address offset
        :rtype: int
        """

    def markup(self, program: ghidra.program.model.listing.Program, space: ghidra.program.model.address.AddressSpace, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Marks up this structure in memory
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.AddressSpace space: The :obj:`AddressSpace`
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
        """

    @property
    def addr(self) -> jpype.JLong:
        ...

    @property
    def relativeSelectorBaseAddressOffset(self) -> jpype.JLong:
        ...


class DyldCacheMappingInfo(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_mapping_info structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheImageInfo`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD mapping info
        :raises IOException: if there was an IO-related problem creating the DYLD mapping info
        """

    def contains(self, addr: typing.Union[jpype.JLong, int], isAddr: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Returns true if the mapping contains the given address
        
        :param jpype.JLong or int addr: The address to check
        :param jpype.JBoolean or bool isAddr: True if the ``addr`` parameter is an address; false if it's a file offset
        :return: True if the mapping contains the given address; otherwise, false
        :rtype: bool
        """

    def getAddress(self) -> int:
        """
        Gets the address of the start of the mapping.
        
        :return: The address of the start of the mapping
        :rtype: int
        """

    def getFileOffset(self) -> int:
        """
        Gets the file offset of the start of the mapping.
        
        :return: The file offset of the start of the mapping
        :rtype: int
        """

    def getInitialProtection(self) -> int:
        ...

    def getMaxProtection(self) -> int:
        ...

    def getSize(self) -> int:
        """
        Gets the size of the mapping.
        
        :return: The size of the mapping
        :rtype: int
        """

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

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> jpype.JLong:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def initialProtection(self) -> jpype.JInt:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @property
    def maxProtection(self) -> jpype.JInt:
        ...


class DyldCacheAcceleratorInitializer(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_accelerator_initializer structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheAcceleratorInitializer`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD accelerator 
        initializer
        :raises IOException: if there was an IO-related problem creating the DYLD accelerator
        initializer
        """

    def getFunctionsOffset(self) -> int:
        """
        Gets the functions offset, which is an address offset from the start of the cache mapping.
        
        :return: The functions offset,  which is an address offset from the start of the cache 
        mapping
        :rtype: int
        """

    @property
    def functionsOffset(self) -> jpype.JInt:
        ...


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

    def getPointerFormat(self) -> DyldChainedPtr.DyldChainType:
        """
        Gets the pointer format
        
        :return: The pointer format
        :rtype: DyldChainedPtr.DyldChainType
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
    def pointerFormat(self) -> DyldChainedPtr.DyldChainType:
        ...


class DyldCacheRangeEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_range_entry structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheRangeEntry`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD range entry
        :raises IOException: if there was an IO-related problem creating the DYLD range entry
        """


class DyldFixup(java.lang.Record):
    """
    Stores information needed to perform a dyld pointer fixup
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, offset: typing.Union[jpype.JLong, int], value: typing.Union[java.lang.Long, int], size: typing.Union[jpype.JInt, int], symbol: typing.Union[java.lang.String, str], libOrdinal: typing.Union[java.lang.Integer, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def libOrdinal(self) -> int:
        ...

    def offset(self) -> int:
        ...

    def size(self) -> int:
        ...

    def symbol(self) -> str:
        ...

    def toString(self) -> str:
        ...

    def value(self) -> int:
        ...


class DyldCacheHeader(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_header structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheHeader`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD cache header
        :raises IOException: if there was an IO-related problem creating the DYLD cache header
        """

    def getAccelerateInfoAddrOrDyldInCacheMH(self) -> int:
        """
        :return: the old accelerate info address or new address of mach header in dyld cache, or 
        ``null`` if it is not defined
        :rtype: int
        """

    def getAccelerateInfoSizeOrDyldInCacheEntry(self) -> int:
        """
        :return: the old accelerate info size or new address of entry point in dyld cache, or 
        ``null`` if it is not defined
        :rtype: int
        """

    def getAltOsVersion(self) -> int:
        """
        :return: the alt OS version
        :rtype: int
        """

    def getAltPlatform(self) -> int:
        """
        :return: the alt platform
        :rtype: int
        """

    def getArchitecture(self) -> DyldArchitecture:
        """
        Gets architecture information.
        
        :return: architecture information
        :rtype: DyldArchitecture
        """

    def getBaseAddress(self) -> int:
        """
        :return: the base address of the DYLD cache
        :rtype: int
        
         
        
        This is where the cache should be loaded in memory.
        """

    def getBranchPoolAddresses(self) -> java.util.List[java.lang.Long]:
        """
        Gets the :obj:`List` of branch pool address.  Requires header to have been parsed.
        
        :return: The :obj:`List` of branch pool address
        :rtype: java.util.List[java.lang.Long]
        """

    def getBranchPoolsCount(self) -> int:
        """
        :return: the branch pools count
        :rtype: int
        """

    def getBranchPoolsOffset(self) -> int:
        """
        :return: the branch pools offset
        :rtype: int
        """

    def getBuiltFromChainedFixups(self) -> bool:
        """
        :return: the built from chained fixups value
        :rtype: bool
        """

    def getCacheAtlasOffset(self) -> int:
        """
        :return: the cache atlas offset
        :rtype: int
        """

    def getCacheAtlasSize(self) -> int:
        """
        :return: the cache atlas size
        :rtype: int
        """

    def getCacheMappingAndSlideInfos(self) -> java.util.List[DyldCacheMappingAndSlideInfo]:
        """
        Gets the :obj:`List` of :obj:`DyldCacheMappingAndSlideInfo`s.  Requires header to have been parsed.
        
        :return: The :obj:`List` of :obj:`DyldCacheMappingAndSlideInfo`s
        :rtype: java.util.List[DyldCacheMappingAndSlideInfo]
        """

    def getCacheSubType(self) -> int:
        """
        :return: the cache subtype, or ``null`` if it is not defined
        :rtype: int
        """

    def getCacheType(self) -> int:
        """
        :return: the cache type
        :rtype: int
        """

    def getCodeSignatureOffset(self) -> int:
        """
        :return: the code signature offset
        :rtype: int
        """

    def getCodeSignatureSize(self) -> int:
        """
        :return: the code signature size
        :rtype: int
        """

    def getDyldBaseAddress(self) -> int:
        """
        :return: the dyld base address
        :rtype: int
        """

    def getDyldInfo(self) -> int:
        """
        :return: the dyld info
        :rtype: int
        """

    def getDylibsExpectedOnDisk(self) -> bool:
        """
        :return: the dylibs expected on disk value
        :rtype: bool
        """

    def getDylibsImageArrayAddr(self) -> int:
        """
        :return: the dylibs image array address
        :rtype: int
        """

    def getDylibsImageArraySize(self) -> int:
        """
        :return: the dylibs image array size
        :rtype: int
        """

    def getDylibsPBLSetAddr(self) -> int:
        """
        :return: the dylibs PrebuildLoaderSet set address
        :rtype: int
        """

    def getDylibsPBLStateArrayAddrUnused(self) -> int:
        """
        :return: the dylibs PrebuildLoaderSet state array address (unused), or ``null`` if it is
        not defined
        :rtype: int
        """

    def getDylibsTriAddr(self) -> int:
        """
        :return: the dylibs trie address
        :rtype: int
        """

    def getDylibsTrieSize(self) -> int:
        """
        :return: the dylibs trie size
        :rtype: int
        """

    def getDynamicDataMaxSize(self) -> int:
        """
        :return: the dynamic data max size
        :rtype: int
        """

    def getDynamicDataOffset(self) -> int:
        """
        :return: the dynamic data offset
        :rtype: int
        """

    def getFormatVersion(self) -> int:
        """
        :return: the format version
        :rtype: int
        """

    def getFunctionVariantInfoAddr(self) -> int:
        """
        :return: the function variant info address
        :rtype: int
        """

    def getFunctionVariantInfoSize(self) -> int:
        """
        :return: the function variant info size
        :rtype: int
        """

    def getImageInfos(self) -> java.util.List[DyldCacheImageInfo]:
        """
        Gets the :obj:`List` of :obj:`DyldCacheImageInfo`s.  Requires header to have been parsed.
        
        :return: The :obj:`List` of :obj:`DyldCacheImageInfo`s
        :rtype: java.util.List[DyldCacheImageInfo]
        """

    def getImagesCount(self) -> int:
        """
        :return: the images count
        :rtype: int
        """

    def getImagesCountOld(self) -> int:
        """
        :return: the old images count
        :rtype: int
        """

    def getImagesOffset(self) -> int:
        """
        :return: the images offset
        :rtype: int
        """

    def getImagesOffsetOld(self) -> int:
        """
        :return: the old images offset
        :rtype: int
        """

    def getImagesTextCount(self) -> int:
        """
        :return: the images text count
        :rtype: int
        """

    def getImagesTextOffset(self) -> int:
        """
        :return: the images text offset
        :rtype: int
        """

    def getLocalSymbolsInfo(self) -> DyldCacheLocalSymbolsInfo:
        """
        Gets the :obj:`DyldCacheLocalSymbolsInfo`.
        
        :return: The :obj:`DyldCacheLocalSymbolsInfo`.  Could be null if it didn't parse.
        :rtype: DyldCacheLocalSymbolsInfo
        """

    def getLocalSymbolsOffset(self) -> int:
        """
        :return: the local symbols offset
        :rtype: int
        """

    def getLocalSymbolsSize(self) -> int:
        """
        :return: the local symbols size
        :rtype: int
        """

    def getLocallyBuildCache(self) -> bool:
        """
        :return: the locally built cache value
        :rtype: bool
        """

    def getMagic(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the magic bytes, which contain version information
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getMappingCount(self) -> int:
        """
        :return: the mapping count
        :rtype: int
        """

    def getMappingInfos(self) -> java.util.List[DyldCacheMappingInfo]:
        """
        Gets the :obj:`List` of :obj:`DyldCacheMappingInfo`s.  Requires header to have been parsed.
        
        :return: The :obj:`List` of :obj:`DyldCacheMappingInfo`s
        :rtype: java.util.List[DyldCacheMappingInfo]
        """

    def getMappingOffset(self) -> int:
        """
        :return: the mapping offset
        :rtype: int
        """

    def getMappingWithSlideCount(self) -> int:
        """
        :return: the mapping with slide count
        :rtype: int
        """

    def getMappingWithSlideOffset(self) -> int:
        """
        :return: the mapping with slide offset
        :rtype: int
        """

    def getMaxSlide(self) -> int:
        """
        :return: the max slide
        :rtype: int
        """

    def getObjcOptsOffset(self) -> int:
        """
        :return: the ObjC opts offset
        :rtype: int
        """

    def getObjcOptsSize(self) -> int:
        """
        :return: the ObjC opts size
        :rtype: int
        """

    def getOsVersion(self) -> int:
        """
        :return: the OS version
        :rtype: int
        """

    def getOtherImageArrayAddr(self) -> int:
        """
        :return: the other image array address
        :rtype: int
        """

    def getOtherImageArraySize(self) -> int:
        """
        :return: the other image array size
        :rtype: int
        """

    def getOtherImageGroupAddrUnused(self) -> int:
        """
        :return: the other image group address (unused)
        :rtype: int
        """

    def getOtherImageGroupSizeUnused(self) -> int:
        """
        :return: the other image group size (unused)
        :rtype: int
        """

    def getOtherTriAddr(self) -> int:
        """
        :return: the other trie address
        :rtype: int
        """

    def getOtherTrieSize(self) -> int:
        """
        :return: the other trie size
        :rtype: int
        """

    def getPatchInfoAddr(self) -> int:
        """
        :return: the patch info address
        :rtype: int
        """

    def getPatchInfoSize(self) -> int:
        """
        :return: the patch info size
        :rtype: int
        """

    def getPlatform(self) -> int:
        """
        :return: the platform
        :rtype: int
        """

    def getPreWarmingDataOffset(self) -> int:
        """
        :return: the pre-warming data offset
        :rtype: int
        """

    def getPreWarmingDataSize(self) -> int:
        """
        :return: the pre-warming data size
        :rtype: int
        """

    def getProgClosuresAddr(self) -> int:
        """
        :return: the program launch closures address
        :rtype: int
        """

    def getProgClosuresSize(self) -> int:
        """
        :return: the program launch closures size
        :rtype: int
        """

    def getProgClosuresTrieAddr(self) -> int:
        """
        :return: the program launch closures trie address
        :rtype: int
        """

    def getProgClosuresTrieSize(self) -> int:
        """
        :return: the program launch closures trie size
        :rtype: int
        """

    def getProgramTrieAddr(self) -> int:
        """
        :return: the program trie address
        :rtype: int
        """

    def getProgramTrieSize(self) -> int:
        """
        :return: the program trie size
        :rtype: int
        """

    def getProgramsPBLSetPoolAddr(self) -> int:
        """
        :return: the programs PrebuildLoaderSet set pool address, or ``null`` if it is not
        defined
        :rtype: int
        """

    def getProgramsPBLSetPoolSize(self) -> int:
        """
        :return: the programs PrebuildLoaderSet set pool size
        :rtype: int
        """

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        :return: the reader associated with the header
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getRosettaReadOnlyAddr(self) -> int:
        """
        :return: the rosetta read-only address
        :rtype: int
        """

    def getRosettaReadOnlySize(self) -> int:
        """
        :return: the rosetta read-only size
        :rtype: int
        """

    def getRosettaReadWriteAddr(self) -> int:
        """
        :return: the rosetta read-write address
        :rtype: int
        """

    def getRosettaReadWriteSize(self) -> int:
        """
        :return: the rosetta read-write size
        :rtype: int
        """

    def getSharedRegionSize(self) -> int:
        """
        :return: the shared region size
        :rtype: int
        """

    def getSharedRegionStart(self) -> int:
        """
        :return: the shared region start
        :rtype: int
        """

    def getSimulator(self) -> bool:
        """
        :return: the simulator value
        :rtype: bool
        """

    def getSlideInfoOffset(self) -> int:
        """
        :return: the slide info offset
        :rtype: int
        """

    def getSlideInfoSize(self) -> int:
        """
        :return: the slide info size
        :rtype: int
        """

    def getSlideInfos(self) -> java.util.List[DyldCacheSlideInfoCommon]:
        """
        Gets the :obj:`List` of :obj:`DyldCacheSlideInfoCommon`s.
        
        :return: the :obj:`List` of :obj:`DyldCacheSlideInfoCommon`s.
        :rtype: java.util.List[DyldCacheSlideInfoCommon]
        """

    def getSubCacheArrayCount(self) -> int:
        """
        :return: the subcache array count, or ``null`` if it is not defined
        :rtype: int
        """

    def getSubCacheArrayOffset(self) -> int:
        """
        :return: the subcache array offset
        :rtype: int
        """

    def getSubcacheEntries(self) -> java.util.List[DyldSubcacheEntry]:
        """
        Gets the :obj:`List` of :obj:`DyldSubcacheEntry`s.  Requires header to have been parsed.
        
        :return: The :obj:`List` of :obj:`DyldSubcacheEntry`s
        :rtype: java.util.List[DyldSubcacheEntry]
        """

    def getSwiftOptsOffset(self) -> int:
        """
        :return: the swift opts offset
        :rtype: int
        """

    def getSwiftOptsSize(self) -> int:
        """
        :return: the swift opts size
        :rtype: int
        """

    def getSymbolFileUUID(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the symbol file UUID, or ``null`` if it is not defined
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getTproMappingsCount(self) -> int:
        """
        :return: the tpro mappings count
        :rtype: int
        """

    def getTproMappingsOffset(self) -> int:
        """
        :return: the tpro mappings offset
        :rtype: int
        """

    def getUUID(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the UUID, or ``null`` if it is not defined
        :rtype: jpype.JArray[jpype.JByte]
        """

    def hasAccelerateInfo(self) -> bool:
        """
        Checks to see whether or not the old accelerate info fields are being used
        
        :return: True if the old accelerate info fields are being used; otherwise, false if the new
        dyldInCache fields are being used
        :rtype: bool
        """

    def hasSlideInfo(self) -> bool:
        """
        Checks to see if any slide info exists
        
        :return: True if any slide info exists; otherwise, false
        :rtype: bool
        """

    def isSubcache(self) -> bool:
        """
        Checks to see whether or not this is a subcache
        
        :return: True if this is a subcache; otherwise, false if it's a base cache
        :rtype: bool
        """

    def markup(self, program: ghidra.program.model.listing.Program, markupLocalSymbols: typing.Union[jpype.JBoolean, bool], space: ghidra.program.model.address.AddressSpace, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks up this :obj:`DyldCacheHeader` with data structures and comments.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to mark up
        :param jpype.JBoolean or bool markupLocalSymbols: True if the local symbols should be marked up; otherwise, false
        :param ghidra.program.model.address.AddressSpace space: The :obj:`Program`'s :obj:`AddressSpace`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises CancelledException: if the user cancelled the operation
        """

    def parseFromFile(self, parseLocalSymbols: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Parses the structures referenced by this :obj:`DyldCacheHeader` from a file.
        
        :param jpype.JBoolean or bool parseLocalSymbols: True if local symbols should be parsed; otherwise, false
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :raises CancelledException: if the user cancelled the operation
        """

    def parseFromMemory(self, program: ghidra.program.model.listing.Program, space: ghidra.program.model.address.AddressSpace, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Parses the structures referenced by this :obj:`DyldCacheHeader` from memory.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` whose memory to parse
        :param ghidra.program.model.address.AddressSpace space: The :obj:`Program`'s :obj:`AddressSpace`
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :raises CancelledException: if the user cancelled the operation
        """

    def parseLocalSymbolsInfo(self, shouldParse: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        ...

    def setFileBlock(self, block: ghidra.program.model.mem.MemoryBlock):
        """
        Sets the :obj:`MemoryBlock` associated with this header's FILE block.
        
        :param ghidra.program.model.mem.MemoryBlock block: The :obj:`MemoryBlock` associated with this header's FILE block
        """

    def unslidLoadAddress(self) -> int:
        """
        Get the original unslid load address.  This is found in the first mapping infos.
        
        :return: the original unslid load address
        :rtype: int
        """

    @property
    def magic(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def altPlatform(self) -> jpype.JInt:
        ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def cacheSubType(self) -> jpype.JInt:
        ...

    @property
    def dylibsTrieSize(self) -> jpype.JLong:
        ...

    @property
    def dylibsPBLStateArrayAddrUnused(self) -> jpype.JLong:
        ...

    @property
    def maxSlide(self) -> jpype.JLong:
        ...

    @property
    def slideInfoOffset(self) -> jpype.JLong:
        ...

    @property
    def dylibsTriAddr(self) -> jpype.JLong:
        ...

    @property
    def progClosuresSize(self) -> jpype.JLong:
        ...

    @property
    def branchPoolsOffset(self) -> jpype.JInt:
        ...

    @property
    def codeSignatureSize(self) -> jpype.JLong:
        ...

    @property
    def symbolFileUUID(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def rosettaReadOnlySize(self) -> jpype.JLong:
        ...

    @property
    def progClosuresAddr(self) -> jpype.JLong:
        ...

    @property
    def builtFromChainedFixups(self) -> jpype.JBoolean:
        ...

    @property
    def otherImageArraySize(self) -> jpype.JLong:
        ...

    @property
    def imagesTextCount(self) -> jpype.JLong:
        ...

    @property
    def accelerateInfoSizeOrDyldInCacheEntry(self) -> jpype.JLong:
        ...

    @property
    def otherTrieSize(self) -> jpype.JLong:
        ...

    @property
    def formatVersion(self) -> jpype.JInt:
        ...

    @property
    def programsPBLSetPoolAddr(self) -> jpype.JLong:
        ...

    @property
    def mappingWithSlideCount(self) -> jpype.JInt:
        ...

    @property
    def codeSignatureOffset(self) -> jpype.JLong:
        ...

    @property
    def imageInfos(self) -> java.util.List[DyldCacheImageInfo]:
        ...

    @property
    def imagesOffsetOld(self) -> jpype.JInt:
        ...

    @property
    def baseAddress(self) -> jpype.JLong:
        ...

    @property
    def cacheAtlasOffset(self) -> jpype.JLong:
        ...

    @property
    def mappingCount(self) -> jpype.JInt:
        ...

    @property
    def uUID(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def dyldInfo(self) -> jpype.JInt:
        ...

    @property
    def cacheMappingAndSlideInfos(self) -> java.util.List[DyldCacheMappingAndSlideInfo]:
        ...

    @property
    def altOsVersion(self) -> jpype.JInt:
        ...

    @property
    def otherTriAddr(self) -> jpype.JLong:
        ...

    @property
    def dyldBaseAddress(self) -> jpype.JLong:
        ...

    @property
    def subcacheEntries(self) -> java.util.List[DyldSubcacheEntry]:
        ...

    @property
    def branchPoolsCount(self) -> jpype.JInt:
        ...

    @property
    def objcOptsSize(self) -> jpype.JLong:
        ...

    @property
    def branchPoolAddresses(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def swiftOptsOffset(self) -> jpype.JLong:
        ...

    @property
    def mappingWithSlideOffset(self) -> jpype.JInt:
        ...

    @property
    def tproMappingsOffset(self) -> jpype.JInt:
        ...

    @property
    def otherImageGroupAddrUnused(self) -> jpype.JLong:
        ...

    @property
    def objcOptsOffset(self) -> jpype.JLong:
        ...

    @property
    def cacheAtlasSize(self) -> jpype.JLong:
        ...

    @property
    def patchInfoAddr(self) -> jpype.JLong:
        ...

    @property
    def functionVariantInfoAddr(self) -> jpype.JLong:
        ...

    @property
    def localSymbolsSize(self) -> jpype.JLong:
        ...

    @property
    def dylibsExpectedOnDisk(self) -> jpype.JBoolean:
        ...

    @property
    def imagesCountOld(self) -> jpype.JInt:
        ...

    @property
    def functionVariantInfoSize(self) -> jpype.JLong:
        ...

    @property
    def platform(self) -> jpype.JInt:
        ...

    @property
    def preWarmingDataOffset(self) -> jpype.JLong:
        ...

    @property
    def localSymbolsOffset(self) -> jpype.JLong:
        ...

    @property
    def imagesTextOffset(self) -> jpype.JLong:
        ...

    @property
    def programTrieAddr(self) -> jpype.JLong:
        ...

    @property
    def imagesOffset(self) -> jpype.JInt:
        ...

    @property
    def swiftOptsSize(self) -> jpype.JLong:
        ...

    @property
    def progClosuresTrieAddr(self) -> jpype.JLong:
        ...

    @property
    def sharedRegionStart(self) -> jpype.JLong:
        ...

    @property
    def osVersion(self) -> jpype.JInt:
        ...

    @property
    def dylibsImageArraySize(self) -> jpype.JLong:
        ...

    @property
    def tproMappingsCount(self) -> jpype.JInt:
        ...

    @property
    def dynamicDataMaxSize(self) -> jpype.JLong:
        ...

    @property
    def patchInfoSize(self) -> jpype.JLong:
        ...

    @property
    def mappingOffset(self) -> jpype.JInt:
        ...

    @property
    def cacheType(self) -> jpype.JLong:
        ...

    @property
    def locallyBuildCache(self) -> jpype.JBoolean:
        ...

    @property
    def architecture(self) -> DyldArchitecture:
        ...

    @property
    def slideInfoSize(self) -> jpype.JLong:
        ...

    @property
    def accelerateInfoAddrOrDyldInCacheMH(self) -> jpype.JLong:
        ...

    @property
    def rosettaReadWriteAddr(self) -> jpype.JLong:
        ...

    @property
    def simulator(self) -> jpype.JBoolean:
        ...

    @property
    def otherImageGroupSizeUnused(self) -> jpype.JLong:
        ...

    @property
    def imagesCount(self) -> jpype.JInt:
        ...

    @property
    def subCacheArrayOffset(self) -> jpype.JInt:
        ...

    @property
    def rosettaReadWriteSize(self) -> jpype.JLong:
        ...

    @property
    def slideInfos(self) -> java.util.List[DyldCacheSlideInfoCommon]:
        ...

    @property
    def localSymbolsInfo(self) -> DyldCacheLocalSymbolsInfo:
        ...

    @property
    def otherImageArrayAddr(self) -> jpype.JLong:
        ...

    @property
    def subCacheArrayCount(self) -> jpype.JInt:
        ...

    @property
    def dylibsPBLSetAddr(self) -> jpype.JLong:
        ...

    @property
    def programsPBLSetPoolSize(self) -> jpype.JLong:
        ...

    @property
    def mappingInfos(self) -> java.util.List[DyldCacheMappingInfo]:
        ...

    @property
    def subcache(self) -> jpype.JBoolean:
        ...

    @property
    def programTrieSize(self) -> jpype.JInt:
        ...

    @property
    def preWarmingDataSize(self) -> jpype.JLong:
        ...

    @property
    def progClosuresTrieSize(self) -> jpype.JLong:
        ...

    @property
    def dynamicDataOffset(self) -> jpype.JLong:
        ...

    @property
    def dylibsImageArrayAddr(self) -> jpype.JLong:
        ...

    @property
    def sharedRegionSize(self) -> jpype.JLong:
        ...

    @property
    def rosettaReadOnlyAddr(self) -> jpype.JLong:
        ...


class DyldCacheAccelerateInfo(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_accelerator_info structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheAccelerateInfo`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD accelerate info
        :raises IOException: if there was an IO-related problem creating the DYLD accelerate info
        """

    def markup(self, program: ghidra.program.model.listing.Program, accelerateInfoAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks up this :obj:`DyldCacheAccelerateInfo` with data structures and comments.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to mark up
        :param ghidra.program.model.address.Address accelerateInfoAddr: The :obj:`Address` of the :obj:`DyldCacheAccelerateInfo`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises CancelledException: if the user cancelled the operation
        """

    def parse(self, program: ghidra.program.model.listing.Program, accelerateInfoAddr: ghidra.program.model.address.Address, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Parses the structures referenced by this :obj:`DyldCacheAccelerateInfo`.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to parse.
        :param ghidra.program.model.address.Address accelerateInfoAddr: The :obj:`Address` of the :obj:`DyldCacheAccelerateInfo`
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :raises CancelledException: if the user cancelled the operation
        """


class DyldArchitecture(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DYLD_V1_SIGNATURE_PREFIX: typing.Final = "dyld_v1"
    """
    Magic value prefix
    """

    DYLD_V1_SIGNATURE_LEN: typing.Final = 16
    """
    Maximum length of any signature
    """

    X86: typing.Final[DyldArchitecture]
    X86_64: typing.Final[DyldArchitecture]
    X86_64h: typing.Final[DyldArchitecture]
    POWERPC: typing.Final[DyldArchitecture]
    ARMV6: typing.Final[DyldArchitecture]
    ARMV7: typing.Final[DyldArchitecture]
    ARMV7F: typing.Final[DyldArchitecture]
    ARMV7S: typing.Final[DyldArchitecture]
    ARMV7K: typing.Final[DyldArchitecture]
    ARMV8A: typing.Final[DyldArchitecture]
    ARMV8Ae: typing.Final[DyldArchitecture]
    ARM64_32: typing.Final[DyldArchitecture]
    ARCHITECTURES: typing.Final[jpype.JArray[DyldArchitecture]]

    @staticmethod
    @typing.overload
    def getArchitecture(signature: typing.Union[java.lang.String, str]) -> DyldArchitecture:
        """
        Returns the architecture object with the given signature.
        Returns NULL if one does not exist.
        
        :param java.lang.String or str signature: the signature string
        :return: the architecture object with the given signature or NULL
        :rtype: DyldArchitecture
        """

    @staticmethod
    @typing.overload
    def getArchitecture(provider: ghidra.app.util.bin.ByteProvider) -> DyldArchitecture:
        ...

    def getCpuSubType(self) -> int:
        ...

    def getCpuType(self) -> int:
        ...

    def getEndianness(self) -> ghidra.program.model.lang.Endian:
        ...

    def getLanguageCompilerSpecPair(self, languageService: ghidra.program.model.lang.LanguageService) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    def getProcessor(self) -> str:
        ...

    def getSignature(self) -> str:
        ...

    def is64bit(self) -> bool:
        ...

    def isARM(self) -> bool:
        ...

    def isPowerPC(self) -> bool:
        ...

    def isX86(self) -> bool:
        ...

    @property
    def cpuType(self) -> jpype.JInt:
        ...

    @property
    def signature(self) -> java.lang.String:
        ...

    @property
    def x86(self) -> jpype.JBoolean:
        ...

    @property
    def languageCompilerSpecPair(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    @property
    def powerPC(self) -> jpype.JBoolean:
        ...

    @property
    def cpuSubType(self) -> jpype.JInt:
        ...

    @property
    def aRM(self) -> jpype.JBoolean:
        ...

    @property
    def processor(self) -> java.lang.String:
        ...

    @property
    def endianness(self) -> ghidra.program.model.lang.Endian:
        ...


class DyldCacheSlideInfo5(DyldCacheSlideInfoCommon):
    """
    Represents a dyld_cache_slide_info5 structure.
     
    
    Seen in macOS 14.4 and later.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, mappingInfo: DyldCacheMappingInfo):
        """
        Create a new :obj:`DyldCacheSlideInfo5`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD slide info 5
        :param DyldCacheMappingInfo mappingInfo: The :obj:`DyldCacheMappingInfo` of where the slide fixups will take place
        :raises IOException: if there was an IO-related problem creating the DYLD slide info 5
        """

    def getPageSize(self) -> int:
        """
        :return: The page size
        :rtype: int
        """

    def getPageStarts(self) -> jpype.JArray[jpype.JShort]:
        """
        :return: The page starts array
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getPageStartsCount(self) -> int:
        """
        :return: The page starts count
        :rtype: int
        """

    def getValueAdd(self) -> int:
        """
        :return: The "value add"
        :rtype: int
        """

    @property
    def pageStarts(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def valueAdd(self) -> jpype.JLong:
        ...

    @property
    def pageStartsCount(self) -> jpype.JInt:
        ...

    @property
    def pageSize(self) -> jpype.JInt:
        ...


class DyldCacheSlideInfo3(DyldCacheSlideInfoCommon):
    """
    Represents a dyld_cache_slide_info3 structure.
     
    
    Seen in iOS 12 and later.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, mappingInfo: DyldCacheMappingInfo):
        """
        Create a new :obj:`DyldCacheSlideInfo3`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD slide info 3
        :param DyldCacheMappingInfo mappingInfo: The :obj:`DyldCacheMappingInfo` of where the slide fixups will take place
        :raises IOException: if there was an IO-related problem creating the DYLD slide info 3
        """

    def getAuthValueAdd(self) -> int:
        """
        :return: The "auth value add"
        :rtype: int
        """

    def getPageSize(self) -> int:
        """
        :return: The page size
        :rtype: int
        """

    def getPageStarts(self) -> jpype.JArray[jpype.JShort]:
        """
        :return: The page starts array
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getPageStartsCount(self) -> int:
        """
        :return: The page starts count
        :rtype: int
        """

    @property
    def pageStarts(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def pageStartsCount(self) -> jpype.JInt:
        ...

    @property
    def pageSize(self) -> jpype.JInt:
        ...

    @property
    def authValueAdd(self) -> jpype.JLong:
        ...


class DyldCacheSlideInfo1(DyldCacheSlideInfoCommon):
    """
    Represents a dyld_cache_slide_info structure.
     
    
    Seen in iOS 8 and earlier.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, mappingInfo: DyldCacheMappingInfo):
        """
        Create a new :obj:`DyldCacheSlideInfo1`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD slide info 1
        :param DyldCacheMappingInfo mappingInfo: The :obj:`DyldCacheMappingInfo` of where the slide fixups will take place
        :raises IOException: if there was an IO-related problem creating the DYLD slide info 1
        """

    def getEntries(self) -> jpype.JArray[jpype.JArray[jpype.JByte]]:
        """
        :return: The entries
        :rtype: jpype.JArray[jpype.JArray[jpype.JByte]]
        """

    def getEntriesCount(self) -> int:
        """
        :return: The entries count
        :rtype: int
        """

    def getEntriesOffset(self) -> int:
        """
        :return: The entries offset
        :rtype: int
        """

    def getEntriesSize(self) -> int:
        """
        :return: The entries size
        :rtype: int
        """

    def getToc(self) -> jpype.JArray[jpype.JShort]:
        """
        :return: The TOC
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getTocCount(self) -> int:
        """
        :return: The TOC count
        :rtype: int
        """

    def getTocOffset(self) -> int:
        """
        :return: The TOC offset
        :rtype: int
        """

    @property
    def entriesCount(self) -> jpype.JInt:
        ...

    @property
    def tocOffset(self) -> jpype.JInt:
        ...

    @property
    def entries(self) -> jpype.JArray[jpype.JArray[jpype.JByte]]:
        ...

    @property
    def entriesSize(self) -> jpype.JInt:
        ...

    @property
    def tocCount(self) -> jpype.JInt:
        ...

    @property
    def toc(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def entriesOffset(self) -> jpype.JInt:
        ...


class DyldCacheMappingAndSlideInfo(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_mapping_and_slide_info structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    DYLD_CACHE_MAPPING_AUTH_DATA: typing.ClassVar[jpype.JLong]
    DYLD_CACHE_MAPPING_DIRTY_DATA: typing.ClassVar[jpype.JLong]
    DYLD_CACHE_MAPPING_CONST_DATA: typing.ClassVar[jpype.JLong]
    DYLD_CACHE_MAPPING_TEXT_STUBS: typing.ClassVar[jpype.JLong]
    DYLD_CACHE_DYNAMIC_CONFIG_DATA: typing.ClassVar[jpype.JLong]
    DYLD_CACHE_READ_ONLY_DATA: typing.ClassVar[jpype.JLong]
    DYLD_CACHE_MAPPING_CONST_TPRO_DATA: typing.ClassVar[jpype.JLong]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheImageInfo`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD mapping info
        :raises IOException: if there was an IO-related problem creating the DYLD mapping info
        """

    def contains(self, addr: typing.Union[jpype.JLong, int], isAddr: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Returns true if the mapping contains the given address
        
        :param jpype.JLong or int addr: The address to check
        :param jpype.JBoolean or bool isAddr: True if the ``addr`` parameter is an address; false if it's a file offset
        :return: True if the mapping contains the given address; otherwise, false
        :rtype: bool
        """

    def getAddress(self) -> int:
        """
        Gets the address of the start of the mapping.
        
        :return: The address of the start of the mapping
        :rtype: int
        """

    def getFileOffset(self) -> int:
        """
        Gets the file offset of the start of the mapping.
        
        :return: The file offset of the start of the mapping
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        Get slide info flags
        
        :return: slide info flags
        :rtype: int
        """

    def getInitialProtection(self) -> int:
        ...

    def getMaxProtection(self) -> int:
        ...

    def getSize(self) -> int:
        """
        Gets the size of the mapping.
        
        :return: The size of the mapping
        :rtype: int
        """

    def getSlideInfoFileOffset(self) -> int:
        """
        Get slide info file offset
        
        :return: slide info file offset
        :rtype: int
        """

    def getSlideInfoFileSize(self) -> int:
        """
        Get slide info file size
        
        :return: slide info file size
        :rtype: int
        """

    def isAuthData(self) -> bool:
        ...

    def isConfigData(self) -> bool:
        ...

    def isConstData(self) -> bool:
        ...

    def isConstTproData(self) -> bool:
        ...

    def isDirtyData(self) -> bool:
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

    def isReadOnlyData(self) -> bool:
        ...

    def isTextStubs(self) -> bool:
        ...

    def isWrite(self) -> bool:
        """
        Returns true if the initial protections include WRITE.
        
        :return: true if the initial protections include WRITE
        :rtype: bool
        """

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> jpype.JLong:
        ...

    @property
    def dirtyData(self) -> jpype.JBoolean:
        ...

    @property
    def configData(self) -> jpype.JBoolean:
        ...

    @property
    def authData(self) -> jpype.JBoolean:
        ...

    @property
    def textStubs(self) -> jpype.JBoolean:
        ...

    @property
    def readOnlyData(self) -> jpype.JBoolean:
        ...

    @property
    def flags(self) -> jpype.JLong:
        ...

    @property
    def constData(self) -> jpype.JBoolean:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @property
    def slideInfoFileOffset(self) -> jpype.JLong:
        ...

    @property
    def maxProtection(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def slideInfoFileSize(self) -> jpype.JLong:
        ...

    @property
    def initialProtection(self) -> jpype.JInt:
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @property
    def constTproData(self) -> jpype.JBoolean:
        ...


class DyldCacheSlideInfo4(DyldCacheSlideInfoCommon):
    """
    Represents a dyld_cache_slide_info4 structure. 
     
    
    Not seen yet.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, mappingInfo: DyldCacheMappingInfo):
        """
        Create a new :obj:`DyldCacheSlideInfo4`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD slide info 3
        :param DyldCacheMappingInfo mappingInfo: The :obj:`DyldCacheMappingInfo` of where the slide fixups will take place
        :raises IOException: if there was an IO-related problem creating the DYLD slide info 3
        """

    def getDeltaMask(self) -> int:
        """
        :return: The delta mask
        :rtype: int
        """

    def getPageExtras(self) -> jpype.JArray[jpype.JShort]:
        """
        :return: The page extras array
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getPageExtrasCount(self) -> int:
        """
        :return: The page extras count
        :rtype: int
        """

    def getPageExtrasOffset(self) -> int:
        """
        :return: The page extras offset
        :rtype: int
        """

    def getPageSize(self) -> int:
        """
        :return: The page size
        :rtype: int
        """

    def getPageStarts(self) -> jpype.JArray[jpype.JShort]:
        """
        :return: The page starts array
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getPageStartsCount(self) -> int:
        """
        :return: The page starts count
        :rtype: int
        """

    def getPageStartsOffset(self) -> int:
        """
        :return: The page starts offset
        :rtype: int
        """

    def getValueAdd(self) -> int:
        """
        :return: The "value add"
        :rtype: int
        """

    @property
    def pageStarts(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def pageExtrasCount(self) -> jpype.JInt:
        ...

    @property
    def valueAdd(self) -> jpype.JLong:
        ...

    @property
    def pageStartsCount(self) -> jpype.JInt:
        ...

    @property
    def deltaMask(self) -> jpype.JLong:
        ...

    @property
    def pageExtrasOffset(self) -> jpype.JInt:
        ...

    @property
    def pageStartsOffset(self) -> jpype.JInt:
        ...

    @property
    def pageSize(self) -> jpype.JInt:
        ...

    @property
    def pageExtras(self) -> jpype.JArray[jpype.JShort]:
        ...


class DyldCacheImageTextInfo(DyldCacheImage, ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_image_text_info structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldCacheImageTextInfo`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD image text info
        :raises IOException: if there was an IO-related problem creating the DYLD image text info
        """


class DyldCacheImage(java.lang.Object):
    """
    A convenience interface for getting the address and path of a DYLD Cache image
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> int:
        """
        Gets the address the start of the image
        
        :return: The address of the start of the image
        :rtype: int
        """

    def getPath(self) -> str:
        """
        Gets the path of the image
        
        :return: The path of the image
        :rtype: str
        """

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def address(self) -> jpype.JLong:
        ...


class DyldSubcacheEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_subcache_entry structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`DyldSubcacheEntry`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD subCache entry
        :raises IOException: if there was an IO-related problem creating the DYLD subCache entry
        """

    def getCacheExtension(self) -> str:
        """
        Gets the extension of this subCache, if it is known
        
        :return: The extension of this subCache, or null if it is not known
        :rtype: str
        """

    def getCacheVMOffset(self) -> int:
        """
        Gets the offset of this subCache from the main cache base address
        
        :return: The offset of this subCache from the main cache base address
        :rtype: int
        """

    def getUuid(self) -> str:
        """
        Gets the UUID of the subCache file
        
        :return: The UUID of the subCache file
        :rtype: str
        """

    @property
    def cacheExtension(self) -> java.lang.String:
        ...

    @property
    def uuid(self) -> java.lang.String:
        ...

    @property
    def cacheVMOffset(self) -> jpype.JLong:
        ...


class DyldCacheSlideInfoCommon(ghidra.app.util.bin.StructConverter):
    """
    Class for representing the common components of the various dyld_cache_slide_info structures.
    The intent is for the full dyld_cache_slide_info structures to extend this and add their
    specific parts.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    DATA_PAGE_MAP_ENTRY: typing.Final = 1
    BYTES_PER_CHAIN_OFFSET: typing.Final = 4
    CHAIN_OFFSET_MASK: typing.Final = 16383

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, mappingInfo: DyldCacheMappingInfo):
        """
        Create a new :obj:`DyldCacheSlideInfoCommon`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD slide info
        :param DyldCacheMappingInfo mappingInfo: The :obj:`DyldCacheMappingInfo` of where the slide fixups will take place
        :raises IOException: if there was an IO-related problem creating the DYLD slide info
        """

    def fixupSlidePointers(self, program: ghidra.program.model.listing.Program, markup: typing.Union[jpype.JBoolean, bool], addRelocations: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Fixes up the program's slide pointers
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param jpype.JBoolean or bool markup: True if the slide pointers should be marked up; otherwise, false
        :param jpype.JBoolean or bool addRelocations: True if slide pointer locations should be added to the relocation
        table; otherwise, false
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :raises MemoryAccessException: If there was a problem accessing memory
        :raises CancelledException: If the user cancelled the operation
        """

    def getMappingInfo(self) -> DyldCacheMappingInfo:
        """
        :return: The base address of where the slide fixups will take place
        :rtype: DyldCacheMappingInfo
        """

    def getSlideFixups(self, reader: ghidra.app.util.bin.BinaryReader, pointerSize: typing.Union[jpype.JInt, int], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[DyldFixup]:
        """
        Walks the slide fixup information and collects a :obj:`List` of :obj:`DyldFixup`s that will
        need to be applied to the image
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the segment to fix up
        :param jpype.JInt or int pointerSize: The size of a pointer in bytes
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :return: A :obj:`List` of :obj:`DyldFixup`s
        :rtype: java.util.List[DyldFixup]
        :raises IOException: If there was an IO-related issue
        :raises CancelledException: If the user cancelled the operation
        """

    def getSlideInfoOffset(self) -> int:
        """
        :return: The original slide info offset
        :rtype: int
        """

    def getVersion(self) -> int:
        """
        :return: The version of the DYLD slide info
        :rtype: int
        """

    @staticmethod
    def parseSlideInfo(reader: ghidra.app.util.bin.BinaryReader, slideInfoOffset: typing.Union[jpype.JLong, int], mappingInfo: DyldCacheMappingInfo, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> DyldCacheSlideInfoCommon:
        """
        Parses the slide info
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD slide info
        :param jpype.JLong or int slideInfoOffset: The offset of the slide info to parse
        :param DyldCacheMappingInfo mappingInfo: The :obj:`DyldCacheMappingInfo` of where the slide fixups will take place
        :param ghidra.app.util.importer.MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
        :return: The slide info object
        :rtype: DyldCacheSlideInfoCommon
        """

    @property
    def mappingInfo(self) -> DyldCacheMappingInfo:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def slideInfoOffset(self) -> jpype.JLong:
        ...


class DyldCacheLocalSymbolsEntry(ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_local_symbols_entry structure.
    
    
    .. seealso::
    
        | `dyld_cache_format.h <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, use64bitOffsets: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new :obj:`DyldCacheLocalSymbolsEntry`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD local symbols entry
        :param jpype.JBoolean or bool use64bitOffsets: True if the DYLD local symbol entries use 64-bit dylib offsets; false
        if they use 32-bit
        :raises IOException: if there was an IO-related problem creating the DYLD local symbols entry
        """

    def getDylibOffset(self) -> int:
        """
        :return: The dylib offset
        :rtype: int
        """

    def getNListCount(self) -> int:
        """
        :return: The nlist count
        :rtype: int
        """

    def getNListStartIndex(self) -> int:
        """
        :return: The nlist start index
        :rtype: int
        """

    @property
    def dylibOffset(self) -> jpype.JLong:
        ...

    @property
    def nListStartIndex(self) -> jpype.JInt:
        ...

    @property
    def nListCount(self) -> jpype.JInt:
        ...


class DyldCacheSlideInfo2(DyldCacheSlideInfoCommon):
    """
    Represents a dyld_cache_slide_info2 structure.
     
    
    Seen in iOS 10 and 11.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, mappingInfo: DyldCacheMappingInfo):
        """
        Create a new :obj:`DyldCacheSlideInfo2`.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a DYLD slide info 2
        :param DyldCacheMappingInfo mappingInfo: The :obj:`DyldCacheMappingInfo` of where the slide fixups will take place
        :raises IOException: if there was an IO-related problem creating the DYLD slide info 2
        """

    def getDeltaMask(self) -> int:
        """
        :return: The delta mask
        :rtype: int
        """

    def getPageExtras(self) -> jpype.JArray[jpype.JShort]:
        """
        :return: The page extras array
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getPageExtrasCount(self) -> int:
        """
        :return: The page extras count
        :rtype: int
        """

    def getPageExtrasOffset(self) -> int:
        """
        :return: The page extras offset
        :rtype: int
        """

    def getPageSize(self) -> int:
        """
        :return: The page size
        :rtype: int
        """

    def getPageStarts(self) -> jpype.JArray[jpype.JShort]:
        """
        :return: The page starts array
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getPageStartsCount(self) -> int:
        """
        :return: The page starts count
        :rtype: int
        """

    def getPageStartsOffset(self) -> int:
        """
        :return: The page starts offset
        :rtype: int
        """

    def getValueAdd(self) -> int:
        """
        :return: The "value add"
        :rtype: int
        """

    @property
    def pageStarts(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def pageExtrasCount(self) -> jpype.JLong:
        ...

    @property
    def valueAdd(self) -> jpype.JLong:
        ...

    @property
    def pageStartsCount(self) -> jpype.JLong:
        ...

    @property
    def deltaMask(self) -> jpype.JLong:
        ...

    @property
    def pageExtrasOffset(self) -> jpype.JLong:
        ...

    @property
    def pageStartsOffset(self) -> jpype.JLong:
        ...

    @property
    def pageSize(self) -> jpype.JLong:
        ...

    @property
    def pageExtras(self) -> jpype.JArray[jpype.JShort]:
        ...



__all__ = ["DyldCacheImageInfoExtra", "DyldCacheImageInfo", "DyldCacheAcceleratorDof", "DyldChainedPtr", "DyldCacheLocalSymbolsInfo", "LibObjcDylib", "LibObjcOptimization", "DyldCacheMappingInfo", "DyldCacheAcceleratorInitializer", "DyldChainedStartsOffsets", "DyldCacheRangeEntry", "DyldFixup", "DyldCacheHeader", "DyldCacheAccelerateInfo", "DyldArchitecture", "DyldCacheSlideInfo5", "DyldCacheSlideInfo3", "DyldCacheSlideInfo1", "DyldCacheMappingAndSlideInfo", "DyldCacheSlideInfo4", "DyldCacheImageTextInfo", "DyldCacheImage", "DyldSubcacheEntry", "DyldCacheSlideInfoCommon", "DyldCacheLocalSymbolsEntry", "DyldCacheSlideInfo2"]
