from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action.builder
import ghidra.app.services
import ghidra.debug.api.modules
import ghidra.debug.api.tracemgr
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.memory
import ghidra.trace.model.modules
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


E = typing.TypeVar("E")
F = typing.TypeVar("F")
J = typing.TypeVar("J")
K = typing.TypeVar("K")
M = typing.TypeVar("M")
MP = typing.TypeVar("MP")
P = typing.TypeVar("P")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class DefaultRegionMapProposal(AbstractMapProposal[ghidra.trace.model.memory.TraceMemoryRegion, ghidra.program.model.mem.MemoryBlock, ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry], ghidra.debug.api.modules.RegionMapProposal):

    class DefaultRegionMapEntry(AbstractMapEntry[ghidra.trace.model.memory.TraceMemoryRegion, ghidra.program.model.mem.MemoryBlock], ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, region: ghidra.trace.model.memory.TraceMemoryRegion, snap: typing.Union[jpype.JLong, int], program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock):
            ...


    @typing.type_check_only
    class RegionMatcher(AbstractMapProposal.Matcher[ghidra.trace.model.memory.TraceMemoryRegion, ghidra.program.model.mem.MemoryBlock]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, region: ghidra.trace.model.memory.TraceMemoryRegion, snap: typing.Union[jpype.JLong, int], block: ghidra.program.model.mem.MemoryBlock):
            ...


    @typing.type_check_only
    class RegionMatcherMap(AbstractMapProposal.MatcherMap[java.lang.Void, ghidra.trace.model.memory.TraceMemoryRegion, ghidra.program.model.mem.MemoryBlock, DefaultRegionMapProposal.RegionMatcher]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, snap: typing.Union[jpype.JLong, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]


class DynamicStaticSynchronizationPlugin(ghidra.framework.plugintool.Plugin):

    @typing.type_check_only
    class SyncLocationsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Synchronize Static and Dynamic Locations"
        DESCRIPTION: typing.Final = "Automatically synchronize the static and dynamic listings\' cursors"
        HELP_ANCHOR: typing.Final = "sync_locations"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class SyncSelectionsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Synchronize Static and Dynamic Selections"
        DESCRIPTION: typing.Final = "Automatically synchronize the static and dynamic listings\' selections"
        HELP_ANCHOR: typing.Final = "sync_selections"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class TransferSelectionDynamicToStaticAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Transfer Dynamic Selection to Static"
        DESCRIPTION: typing.Final = "Change the static selection to match the dynamic selection"
        HELP_ANCHOR: typing.Final = "transfer_selection_dynamic_to_static"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class TransferSelectionStaticToDynamicAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Transfer Static Selection to Dynamic"
        DESCRIPTION: typing.Final = "Change the dynamic seleciton to mathc the static selection"
        HELP_ANCHOR: typing.Final = "transfer_selection_static_to_dynamic"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class OpenProgramAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Open Program"
        ICON: typing.Final[javax.swing.Icon]
        DESCRIPTION: typing.Final = "Open the program"
        HELP_ANCHOR: typing.Final = "open_program"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class ForStaticSyncMappingChangeListener(ghidra.debug.api.modules.DebuggerStaticMappingChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StablePoint(java.lang.Enum[DynamicStaticSynchronizationPlugin.StablePoint]):

        class_: typing.ClassVar[java.lang.Class]
        STATIC: typing.Final[DynamicStaticSynchronizationPlugin.StablePoint]
        DYNAMIC: typing.Final[DynamicStaticSynchronizationPlugin.StablePoint]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DynamicStaticSynchronizationPlugin.StablePoint:
            ...

        @staticmethod
        def values() -> jpype.JArray[DynamicStaticSynchronizationPlugin.StablePoint]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def isSyncLocations(self) -> bool:
        ...

    def isSyncSelections(self) -> bool:
        ...

    def setSyncLocations(self, sync: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSyncSelections(self, sync: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def syncLocations(self) -> jpype.JBoolean:
        ...

    @syncLocations.setter
    def syncLocations(self, value: jpype.JBoolean):
        ...

    @property
    def syncSelections(self) -> jpype.JBoolean:
        ...

    @syncSelections.setter
    def syncSelections(self, value: jpype.JBoolean):
        ...


class DebuggerStaticMappingUtils(java.lang.Enum[DebuggerStaticMappingUtils]):

    class Extrema(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @typing.overload
        def consider(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address):
            ...

        @typing.overload
        def consider(self, range: ghidra.program.model.address.AddressRange):
            ...

        @typing.overload
        def consider(self, address: ghidra.program.model.address.Address):
            ...

        def getLength(self) -> int:
            ...

        def getMax(self) -> ghidra.program.model.address.Address:
            ...

        def getMin(self) -> ghidra.program.model.address.Address:
            ...

        def getRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        @property
        def min(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def max(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def length(self) -> jpype.JLong:
            ...

        @property
        def range(self) -> ghidra.program.model.address.AddressRange:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def addIdentityMapping(from_: ghidra.trace.model.Trace, toProgram: ghidra.program.model.listing.Program, lifespan: ghidra.trace.model.Lifespan, truncateExisting: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    @typing.overload
    def addMapping(from_: ghidra.trace.model.TraceLocation, to: ghidra.program.util.ProgramLocation, length: typing.Union[jpype.JLong, int], truncateExisting: typing.Union[jpype.JBoolean, bool]):
        """
        Add a static mapping (relocation) from the given trace to the given program
         
         
        
        Note if the trace is backed by a Ghidra database, the caller must already have started a
        transaction on the relevant domain object.
        
        :param ghidra.trace.model.TraceLocation from: the source trace location, including lifespan
        :param ghidra.program.util.ProgramLocation to: the destination program location
        :param jpype.JLong or int length: the length of the mapped region
        :param jpype.JBoolean or bool truncateExisting: true to delete or truncate the lifespan of overlapping entries
        :raises TraceConflictedMappingException: if a conflicting mapping overlaps the source and
                    ``truncateExisting`` is false.
        """

    @staticmethod
    @typing.overload
    def addMapping(entry: ghidra.debug.api.modules.MapEntry[typing.Any, typing.Any], truncateExisting: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    def collectLibraries(seeds: collections.abc.Sequence) -> java.util.Set[ghidra.framework.model.DomainFile]:
        """
        Recursively collect external programs, i.e., libraries, starting at the given seeds
         
         
        
        This will only descend into domain files that are already opened. This will only include
        results whose content type is a :obj:`Program`.
        
        :param collections.abc.Sequence seeds: the seeds, usually including the executable
        :return: the set of found domain files, including the seeds
        :rtype: java.util.Set[ghidra.framework.model.DomainFile]
        """

    @staticmethod
    def computeMappedFiles(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange) -> str:
        """
        Compute a string suitable for displaying the mapped module names for a given range
         
         
        
        Ideally, the entire range is covered by a single mapping entry. In that case, the "image
        name" (see :meth:`getImageName(URL) <.getImageName>`) for that one mapping is returned. If a single mapping
        is found, but it only partially covers the given range, an asterisk is appended. If no
        mappings are found, the empty string is returned. If multiple mappings are found, they are
        each listed alphabetically. No asterisk is displayed in the case of multiple images, since
        it's implied that none cover the entire range.
        
        :param ghidra.trace.model.Trace trace: the trace whose mappings to query
        :param jpype.JLong or int snap: the relevant snapshot
        :param ghidra.program.model.address.AddressRange range: the address range to consider
        :return: the names of any mapped images
        :rtype: str
        """

    @staticmethod
    def computeModuleShortName(path: typing.Union[java.lang.String, str]) -> str:
        ...

    @staticmethod
    @typing.overload
    def getFunction(pc: ghidra.program.model.address.Address, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.model.listing.Function:
        ...

    @staticmethod
    @typing.overload
    def getFunction(pc: ghidra.program.model.address.Address, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.model.listing.Function:
        ...

    @staticmethod
    def getImageName(staticProgramURL: java.net.URL) -> str:
        """
        Parse the final file name from the given URL.
         
         
        
        This is used when listing the "image" name for mappings, since displaying a full URL would
        probably clutter the table. This generally matches the "program name," but in certain cases
        may not.
        
        :param java.net.URL staticProgramURL: the URL of the static program image
        :return: the piece after the final "/"
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getModuleName(pc: ghidra.program.model.address.Address, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> str:
        ...

    @staticmethod
    @typing.overload
    def getModuleName(pc: ghidra.program.model.address.Address, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]) -> str:
        ...

    @staticmethod
    def isReal(block: ghidra.program.model.mem.MemoryBlock) -> bool:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerStaticMappingUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[DebuggerStaticMappingUtils]:
        ...


class AbstractMapEntry(ghidra.debug.api.modules.MapEntry[T, P], typing.Generic[T, P]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fromTrace: ghidra.trace.model.Trace, fromObject: T, snap: typing.Union[jpype.JLong, int], toProgram: ghidra.program.model.listing.Program, toObject: P):
        ...


@typing.type_check_only
class InfoPerTrace(ghidra.trace.model.TraceDomainObjectListener):

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        ...


class ProgramModuleIndexer(ghidra.framework.model.DomainFolderChangeListener):

    @typing.type_check_only
    class NameSource(java.lang.Enum[ProgramModuleIndexer.NameSource]):

        class_: typing.ClassVar[java.lang.Class]
        MODULE_PATH: typing.Final[ProgramModuleIndexer.NameSource]
        MODULE_NAME: typing.Final[ProgramModuleIndexer.NameSource]
        PROGRAM_EXECUTABLE_PATH: typing.Final[ProgramModuleIndexer.NameSource]
        PROGRAM_EXECUTABLE_NAME: typing.Final[ProgramModuleIndexer.NameSource]
        PROGRAM_NAME: typing.Final[ProgramModuleIndexer.NameSource]
        DOMAIN_FILE_NAME: typing.Final[ProgramModuleIndexer.NameSource]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ProgramModuleIndexer.NameSource:
            ...

        @staticmethod
        def values() -> jpype.JArray[ProgramModuleIndexer.NameSource]:
            ...


    @typing.type_check_only
    class IndexEntry(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def dfID(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def source(self) -> ProgramModuleIndexer.NameSource:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ModuleChangeListener(ghidra.framework.model.DomainObjectListener, ghidra.framework.model.DomainObjectClosedListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program):
            ...


    @typing.type_check_only
    class MapOfSets(java.lang.Object, typing.Generic[K, V]):

        class_: typing.ClassVar[java.lang.Class]
        map: typing.Final[java.util.Map[K, java.util.Set[V]]]

        def put(self, key: K, value: V):
            ...

        def remove(self, key: K, value: V):
            ...


    @typing.type_check_only
    class ModuleIndex(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getByName(self, name: typing.Union[java.lang.String, str]) -> java.util.Collection[ProgramModuleIndexer.IndexEntry]:
            ...

        @property
        def byName(self) -> java.util.Collection[ProgramModuleIndexer.IndexEntry]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    MODULE_PATHS_PROPERTY: typing.Final = "Module Paths"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def addModulePaths(program: ghidra.program.model.listing.Program, moduleNames: collections.abc.Sequence):
        ...

    def filter(self, entries: collections.abc.Sequence, programs: collections.abc.Sequence) -> java.util.Collection[ProgramModuleIndexer.IndexEntry]:
        ...

    def getBestEntries(self, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int]) -> java.util.List[ProgramModuleIndexer.IndexEntry]:
        ...

    @typing.overload
    def getBestMatch(self, space: ghidra.program.model.address.AddressSpace, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int], currentProgram: ghidra.program.model.listing.Program, entries: collections.abc.Sequence) -> ghidra.framework.model.DomainFile:
        ...

    @typing.overload
    def getBestMatch(self, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int], currentProgram: ghidra.program.model.listing.Program, entries: collections.abc.Sequence) -> ghidra.framework.model.DomainFile:
        ...

    @typing.overload
    def getBestMatch(self, space: ghidra.program.model.address.AddressSpace, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int], currentProgram: ghidra.program.model.listing.Program) -> ghidra.framework.model.DomainFile:
        ...

    @staticmethod
    @typing.overload
    def getModulePaths(df: ghidra.framework.model.DomainFile) -> java.util.Collection[java.lang.String]:
        ...

    @staticmethod
    @typing.overload
    def getModulePaths(metadata: collections.abc.Mapping) -> java.util.Collection[java.lang.String]:
        ...

    @staticmethod
    def setModulePaths(program: ghidra.program.model.listing.Program, moduleNames: collections.abc.Sequence):
        ...


class DefaultModuleMapProposal(AbstractMapProposal[ghidra.trace.model.modules.TraceModule, ghidra.program.model.listing.Program, ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry], ghidra.debug.api.modules.ModuleMapProposal):

    class DefaultModuleMapEntry(AbstractMapEntry[ghidra.trace.model.modules.TraceModule, ghidra.program.model.listing.Program], ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry):
        """
        A module-program entry in a proposed module map
        """

        class_: typing.ClassVar[java.lang.Class]

        @staticmethod
        def computeImageRange(program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressRange:
            """
            Compute the "size" of an image
             
             
            
            This is considered the maximum loaded address as mapped in memory, minus the image base.
            
            :param ghidra.program.model.listing.Program program: the program image whose size to compute
            :return: the size
            :rtype: ghidra.program.model.address.AddressRange
            """

        @staticmethod
        def includeBlock(program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock) -> bool:
            """
            Check if a block should be included in size computations or analyzed for proposals
            
            :param ghidra.program.model.listing.Program program: the program containing the block
            :param ghidra.program.model.mem.MemoryBlock block: the block
            :return: true if included, false otherwise
            :rtype: bool
            """


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MappingEntry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mapping: ghidra.trace.model.modules.TraceStaticMapping):
        ...

    def getStaticAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getStaticProgramUrl(self) -> java.net.URL:
        ...

    def getStaticRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    def getTraceAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getTraceAddressSnapRange(self) -> ghidra.trace.model.TraceAddressSnapRange:
        ...

    def getTraceRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getTraceSpan(self) -> ghidra.trace.model.TraceSpan:
        ...

    @typing.overload
    def isInProgramRange(self, address: ghidra.program.model.address.Address) -> bool:
        ...

    @typing.overload
    def isInProgramRange(self, rng: ghidra.program.model.address.AddressRange) -> bool:
        ...

    def isInTraceLifespan(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        ...

    @typing.overload
    def isInTraceRange(self, address: ghidra.program.model.address.Address, snap: typing.Union[java.lang.Long, int]) -> bool:
        ...

    @typing.overload
    def isInTraceRange(self, rng: ghidra.program.model.address.AddressRange, snap: typing.Union[java.lang.Long, int]) -> bool:
        ...

    def isStaticProgramOpen(self) -> bool:
        ...

    def mapProgramRangeToTrace(self, rng: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        ...

    def mapTraceAddressToProgramLocation(self, address: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        ...

    def mapTraceRangeToProgram(self, rng: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def traceAddressSnapRange(self) -> ghidra.trace.model.TraceAddressSnapRange:
        ...

    @property
    def traceSpan(self) -> ghidra.trace.model.TraceSpan:
        ...

    @property
    def staticProgramUrl(self) -> java.net.URL:
        ...

    @property
    def staticRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def traceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def inTraceLifespan(self) -> jpype.JBoolean:
        ...

    @property
    def staticAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def inProgramRange(self) -> jpype.JBoolean:
        ...

    @property
    def staticProgramOpen(self) -> jpype.JBoolean:
        ...

    @property
    def traceRange(self) -> ghidra.program.model.address.AddressRange:
        ...


class DebuggerStaticMappingServicePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DebuggerStaticMappingService, ghidra.framework.model.DomainFolderChangeListener):

    @typing.type_check_only
    class ChangeCollector(java.lang.Record, java.lang.AutoCloseable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, plugin: DebuggerStaticMappingServicePlugin):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def plugin(self) -> DebuggerStaticMappingServicePlugin:
            ...

        def programAffected(self, program: ghidra.program.model.listing.Program):
            ...

        def programs(self) -> java.util.Set[ghidra.program.model.listing.Program]:
            ...

        def toString(self) -> str:
            ...

        def traceAffected(self, trace: ghidra.trace.model.Trace):
            ...

        def traces(self) -> java.util.Set[ghidra.trace.model.Trace]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class PeekOpenedDomainObject(java.lang.AutoCloseable):

    class_: typing.ClassVar[java.lang.Class]
    object: typing.Final[ghidra.framework.model.DomainObject]

    def __init__(self, df: ghidra.framework.model.DomainFile):
        ...


class AbstractMapProposal(ghidra.debug.api.modules.MapProposal[T, P, E], typing.Generic[T, P, E]):

    @typing.type_check_only
    class Matcher(java.lang.Object, typing.Generic[T, P]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MatcherMap(java.lang.Object, typing.Generic[K, T, P, M]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, snap: typing.Union[jpype.JLong, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.model.Trace, program: ghidra.program.model.listing.Program):
        ...


class DebuggerStaticMappingProposals(java.lang.Enum[DebuggerStaticMappingProposals]):

    @typing.type_check_only
    class ProposalGenerator(java.lang.Object, typing.Generic[F, T, MP]):

        class_: typing.ClassVar[java.lang.Class]

        def proposeBestMap(self, from_: F, snap: typing.Union[jpype.JLong, int], tos: collections.abc.Sequence) -> MP:
            ...

        def proposeBestMaps(self, froms: collections.abc.Sequence, snap: typing.Union[jpype.JLong, int], tos: collections.abc.Sequence) -> java.util.Map[F, MP]:
            ...

        def proposeMap(self, from_: F, snap: typing.Union[jpype.JLong, int], to: T) -> MP:
            ...


    @typing.type_check_only
    class AbstractProposalGenerator(java.lang.Object, typing.Generic[F, T, J, MP]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, snap: typing.Union[jpype.JLong, int]):
            ...


    @typing.type_check_only
    class ModuleMapProposalGenerator(DebuggerStaticMappingProposals.ProposalGenerator[ghidra.trace.model.modules.TraceModule, ghidra.program.model.listing.Program, ghidra.debug.api.modules.ModuleMapProposal]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, indexer: ProgramModuleIndexer):
            ...


    class SectionMapProposalGenerator(DebuggerStaticMappingProposals.AbstractProposalGenerator[ghidra.trace.model.modules.TraceModule, ghidra.program.model.listing.Program, java.lang.String, ghidra.debug.api.modules.SectionMapProposal]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, snap: typing.Union[jpype.JLong, int]):
            ...


    class RegionMapProposalGenerator(DebuggerStaticMappingProposals.AbstractProposalGenerator[java.util.Collection[ghidra.trace.model.memory.TraceMemoryRegion], ghidra.program.model.listing.Program, java.util.Set[java.lang.String], ghidra.debug.api.modules.RegionMapProposal]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, snap: typing.Union[jpype.JLong, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def groupByComponents(vertices: collections.abc.Sequence, precompute: java.util.function.Function[V, J], areConnected: java.util.function.BiPredicate[J, J]) -> java.util.Set[java.util.Set[V]]:
        ...

    @staticmethod
    def groupRegionsByLikelyModule(regions: collections.abc.Sequence) -> java.util.Set[java.util.Set[ghidra.trace.model.memory.TraceMemoryRegion]]:
        ...

    @staticmethod
    def proposeRegionMap(regions: collections.abc.Sequence, snap: typing.Union[jpype.JLong, int], programs: collections.abc.Sequence) -> ghidra.debug.api.modules.RegionMapProposal:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerStaticMappingProposals:
        ...

    @staticmethod
    def values() -> jpype.JArray[DebuggerStaticMappingProposals]:
        ...


class MapSectionsBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.trace.model.Trace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, service: ghidra.app.services.DebuggerStaticMappingService, entries: collections.abc.Sequence):
        ...


class DefaultSectionMapProposal(AbstractMapProposal[ghidra.trace.model.modules.TraceSection, ghidra.program.model.mem.MemoryBlock, ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry], ghidra.debug.api.modules.SectionMapProposal):

    class DefaultSectionMapEntry(AbstractMapEntry[ghidra.trace.model.modules.TraceSection, ghidra.program.model.mem.MemoryBlock], ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry):
        """
        A section-block entry in a proposed section map
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SectionMatcher(AbstractMapProposal.Matcher[ghidra.trace.model.modules.TraceSection, ghidra.program.model.mem.MemoryBlock]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, section: ghidra.trace.model.modules.TraceSection, snap: typing.Union[jpype.JLong, int], block: ghidra.program.model.mem.MemoryBlock):
            ...


    @typing.type_check_only
    class SectionMatcherMap(AbstractMapProposal.MatcherMap[java.lang.String, ghidra.trace.model.modules.TraceSection, ghidra.program.model.mem.MemoryBlock, DefaultSectionMapProposal.SectionMatcher]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, snap: typing.Union[jpype.JLong, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]


class MapModulesBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.trace.model.Trace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, service: ghidra.app.services.DebuggerStaticMappingService, entries: collections.abc.Sequence):
        ...


class MapRegionsBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.trace.model.Trace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, service: ghidra.app.services.DebuggerStaticMappingService, entries: collections.abc.Sequence):
        ...


@typing.type_check_only
class ModuleRegionMatcher(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, snap: typing.Union[jpype.JLong, int]):
        ...


@typing.type_check_only
class InfoPerProgram(ghidra.framework.model.DomainObjectListener):

    @typing.type_check_only
    class NavMultiMap(java.lang.Object, typing.Generic[K, V]):

        class_: typing.ClassVar[java.lang.Class]

        def put(self, k: K, v: V) -> bool:
            ...

        def remove(self, k: K, v: V) -> bool:
            ...


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["DefaultRegionMapProposal", "DynamicStaticSynchronizationPlugin", "DebuggerStaticMappingUtils", "AbstractMapEntry", "InfoPerTrace", "ProgramModuleIndexer", "DefaultModuleMapProposal", "MappingEntry", "DebuggerStaticMappingServicePlugin", "PeekOpenedDomainObject", "AbstractMapProposal", "DebuggerStaticMappingProposals", "MapSectionsBackgroundCommand", "DefaultSectionMapProposal", "MapModulesBackgroundCommand", "MapRegionsBackgroundCommand", "ModuleRegionMatcher", "InfoPerProgram"]
