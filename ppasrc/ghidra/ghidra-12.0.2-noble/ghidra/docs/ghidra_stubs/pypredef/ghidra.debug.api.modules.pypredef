from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.memory
import ghidra.trace.model.modules
import java.lang # type: ignore
import java.util # type: ignore


E = typing.TypeVar("E")
M = typing.TypeVar("M")
P = typing.TypeVar("P")
T = typing.TypeVar("T")


class ModuleMapProposal(MapProposal[ghidra.trace.model.modules.TraceModule, ghidra.program.model.listing.Program, ModuleMapProposal.ModuleMapEntry]):
    """
    A proposed mapping of module to program
    """

    class ModuleMapEntry(MapEntry[ghidra.trace.model.modules.TraceModule, ghidra.program.model.listing.Program]):

        class_: typing.ClassVar[java.lang.Class]

        def getModule(self) -> ghidra.trace.model.modules.TraceModule:
            """
            Get the module for this entry
            
            :return: the module
            :rtype: ghidra.trace.model.modules.TraceModule
            """

        def getModuleName(self) -> str:
            """
            Get the module name for this entry (may depend on the snap)
            
            :return: the name
            :rtype: str
            """

        def getModuleRange(self) -> ghidra.program.model.address.AddressRange:
            """
            Get the address range of the module in the trace, as computed from the matched program's
            image size
            
            :return: the module range
            :rtype: ghidra.program.model.address.AddressRange
            """

        def isMemorize(self) -> bool:
            """
            Check if the user would like to memorize this mapping for future traces
            
            :return: true to memorize
            :rtype: bool
            """

        def setMemorize(self, memorize: typing.Union[jpype.JBoolean, bool]):
            """
            Set whether this mapping should be memorized for future traces
            
            :param jpype.JBoolean or bool memorize: true to memorize
            """

        def setProgram(self, program: ghidra.program.model.listing.Program):
            """
            Set the matched program
             
             
            
            This is generally used in UIs to let the user tweak and reassign, if desired. This will
            also re-compute the module range based on the new program's image size.
            
            :param ghidra.program.model.listing.Program program: the program
            """

        @property
        def module(self) -> ghidra.trace.model.modules.TraceModule:
            ...

        @property
        def moduleName(self) -> java.lang.String:
            ...

        @property
        def moduleRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        @property
        def memorize(self) -> jpype.JBoolean:
            ...

        @memorize.setter
        def memorize(self, value: jpype.JBoolean):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getModule(self) -> ghidra.trace.model.modules.TraceModule:
        """
        Get the trace module of this proposal
        
        :return: the module
        :rtype: ghidra.trace.model.modules.TraceModule
        """

    @property
    def module(self) -> ghidra.trace.model.modules.TraceModule:
        ...


class DebuggerMissingModuleActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, module: ghidra.trace.model.modules.TraceModule):
        ...

    def getModule(self) -> ghidra.trace.model.modules.TraceModule:
        ...

    @property
    def module(self) -> ghidra.trace.model.modules.TraceModule:
        ...


class DebuggerOpenProgramActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, df: ghidra.framework.model.DomainFile):
        ...

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...


class RegionMapProposal(MapProposal[ghidra.trace.model.memory.TraceMemoryRegion, ghidra.program.model.mem.MemoryBlock, RegionMapProposal.RegionMapEntry]):
    """
    A proposed map of regions to program memory blocks
    """

    class RegionMapEntry(MapEntry[ghidra.trace.model.memory.TraceMemoryRegion, ghidra.program.model.mem.MemoryBlock]):

        class_: typing.ClassVar[java.lang.Class]

        def getBlock(self) -> ghidra.program.model.mem.MemoryBlock:
            """
            Get the matched memory block
            
            :return: the block
            :rtype: ghidra.program.model.mem.MemoryBlock
            """

        def getRegion(self) -> ghidra.trace.model.memory.TraceMemoryRegion:
            """
            Get the region
            
            :return: the region
            :rtype: ghidra.trace.model.memory.TraceMemoryRegion
            """

        def getRegionMinAddress(self) -> ghidra.program.model.address.Address:
            """
            Get the region's minimum address (may depend on snap)
            
            :return: the address
            :rtype: ghidra.program.model.address.Address
            """

        def getRegionName(self) -> str:
            """
            Get the region's name (may depend on snap)
            
            :return: the name
            :rtype: str
            """

        def setBlock(self, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock):
            """
            Set the matched memory block
            
            :param ghidra.program.model.listing.Program program: the program containing the block
            :param ghidra.program.model.mem.MemoryBlock block: the block
            """

        @property
        def regionMinAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def regionName(self) -> java.lang.String:
            ...

        @property
        def block(self) -> ghidra.program.model.mem.MemoryBlock:
            ...

        @property
        def region(self) -> ghidra.trace.model.memory.TraceMemoryRegion:
            ...


    class_: typing.ClassVar[java.lang.Class]


class MapEntry(java.lang.Object, typing.Generic[T, P]):

    class_: typing.ClassVar[java.lang.Class]

    def getFromLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def getFromObject(self) -> T:
        ...

    def getFromRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getFromTrace(self) -> ghidra.trace.model.Trace:
        ...

    def getFromTraceLocation(self) -> ghidra.trace.model.TraceLocation:
        ...

    def getMappingLength(self) -> int:
        ...

    def getToObject(self) -> P:
        ...

    def getToProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getToProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getToRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def toProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def fromObject(self) -> T:
        ...

    @property
    def mappingLength(self) -> jpype.JLong:
        ...

    @property
    def toProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def fromLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def fromTraceLocation(self) -> ghidra.trace.model.TraceLocation:
        ...

    @property
    def fromTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def toObject(self) -> P:
        ...

    @property
    def toRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def fromRange(self) -> ghidra.program.model.address.AddressRange:
        ...


class DebuggerMissingProgramActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.model.Trace, program: ghidra.program.model.listing.Program):
        ...

    @staticmethod
    @typing.overload
    def getMappingProbeAddress(program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        ...

    @typing.overload
    def getMappingProbeAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def mappingProbeAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class DebuggerStaticMappingChangeListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def mappingsChanged(self, affectedTraces: java.util.Set[ghidra.trace.model.Trace], affectedPrograms: java.util.Set[ghidra.program.model.listing.Program]):
        """
        The mappings among programs and traces open in this tool have changed
         
         
        
        TODO: Consider more precise callbacks: added, removed for each MappingEntry? One reason is
        that this callback is hit no matter the snap(s) of the affected entries. It could be a
        listeners is only interested in a particular snap, and could duly ignore some callbacks if
        precise information was provided.
        
        :param java.util.Set[ghidra.trace.model.Trace] affectedTraces: the set of traces affected by the change(s)
        :param java.util.Set[ghidra.program.model.listing.Program] affectedPrograms: the set of programs affected by the change(s)
        """


class SectionMapProposal(MapProposal[ghidra.trace.model.modules.TraceSection, ghidra.program.model.mem.MemoryBlock, SectionMapProposal.SectionMapEntry]):
    """
    A proposed map of sections to program memory blocks
    """

    class SectionMapEntry(MapEntry[ghidra.trace.model.modules.TraceSection, ghidra.program.model.mem.MemoryBlock]):

        class_: typing.ClassVar[java.lang.Class]

        def getBlock(self) -> ghidra.program.model.mem.MemoryBlock:
            """
            Get the matched memory block
            
            :return: the block
            :rtype: ghidra.program.model.mem.MemoryBlock
            """

        def getModule(self) -> ghidra.trace.model.modules.TraceModule:
            """
            Get the module containing the section
            
            :return: the module
            :rtype: ghidra.trace.model.modules.TraceModule
            """

        def getModuleName(self) -> str:
            """
            Get the name of the module containing the section (may depend on snap)
            
            :return: the name
            :rtype: str
            """

        def getSection(self) -> ghidra.trace.model.modules.TraceSection:
            """
            Get the section
            
            :return: the section
            :rtype: ghidra.trace.model.modules.TraceSection
            """

        def getSectionName(self) -> str:
            """
            Get the section name (may depend on the snap)
            
            :return: the name
            :rtype: str
            """

        def getSectionStart(self) -> ghidra.program.model.address.Address:
            """
            Get the start address of the section (may depend on the snap)
            
            :return: the start address
            :rtype: ghidra.program.model.address.Address
            """

        def setBlock(self, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock):
            """
            Set the matched memory block
            
            :param ghidra.program.model.listing.Program program: the program containing the block
            :param ghidra.program.model.mem.MemoryBlock block: the block
            """

        @property
        def sectionName(self) -> java.lang.String:
            ...

        @property
        def sectionStart(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def module(self) -> ghidra.trace.model.modules.TraceModule:
            ...

        @property
        def moduleName(self) -> java.lang.String:
            ...

        @property
        def section(self) -> ghidra.trace.model.modules.TraceSection:
            ...

        @property
        def block(self) -> ghidra.program.model.mem.MemoryBlock:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getModule(self) -> ghidra.trace.model.modules.TraceModule:
        """
        Get the trace module of this proposal
        
        :return: the module
        :rtype: ghidra.trace.model.modules.TraceModule
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the corresponding program image of this proposal
        
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def module(self) -> ghidra.trace.model.modules.TraceModule:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class MapProposal(java.lang.Object, typing.Generic[T, P, E]):

    class_: typing.ClassVar[java.lang.Class]

    def computeMap(self) -> java.util.Map[T, E]:
        """
        Compute the overall map given by this proposal
        
        :return: the map
        :rtype: java.util.Map[T, E]
        """

    def computeScore(self) -> float:
        """
        Compute a notional "score" of the proposal
         
         
        
        This may examine attributes of the "from" and "to" objects, in order to determine the
        likelihood of the match based on this proposal. The implementation need not assign meaning to
        any particular score, but a higher score must imply a more likely match.
        
        :return: a score of the proposed pair
        :rtype: float
        """

    @staticmethod
    def flatten(proposals: collections.abc.Sequence) -> java.util.Collection[E]:
        """
        Flatten proposals into a single collection of entries
         
         
        
        The output is suitable for use in
        :meth:`DebuggerStaticMappingService.addMappings(Collection, TaskMonitor, boolean, String) <DebuggerStaticMappingService.addMappings>`.
        In some contexts, the user should be permitted to see and optionally adjust the collection
        first.
         
         
        
        Note, it is advisable to filter the returned collection using
        :meth:`removeOverlapping(Collection) <.removeOverlapping>` to avoid errors from adding overlapped mappings.
        Alternatively, you can set ``truncateExisting`` to true when calling
        :meth:`DebuggerStaticMappingService.addMappings(Collection, TaskMonitor, boolean, String) <DebuggerStaticMappingService.addMappings>`.
        
        :param collections.abc.Sequence proposals: the collection of proposed maps
        :return: the flattened, filtered collection
        :rtype: java.util.Collection[E]
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the corresponding program image of this proposal
        
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    def getToObject(self, from_: T) -> P:
        """
        Get the destination (program) object for a given source (trace) object
        
        :param T from: the trace object
        :return: the proposed program object
        :rtype: P
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing the trace objects in this proposal
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    @staticmethod
    def removeOverlapping(entries: collections.abc.Sequence) -> java.util.Set[E]:
        """
        Remove entries from a collection which overlap existing entries in the trace
        
        :param collections.abc.Sequence entries: the entries to filter
        :return: the filtered entries
        :rtype: java.util.Set[E]
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def toObject(self) -> P:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...



__all__ = ["ModuleMapProposal", "DebuggerMissingModuleActionContext", "DebuggerOpenProgramActionContext", "RegionMapProposal", "MapEntry", "DebuggerMissingProgramActionContext", "DebuggerStaticMappingChangeListener", "SectionMapProposal", "MapProposal"]
