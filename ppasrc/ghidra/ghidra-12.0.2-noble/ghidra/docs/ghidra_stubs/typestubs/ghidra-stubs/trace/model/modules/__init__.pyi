from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.target.iface
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore


class TraceModuleSpace(TraceModuleOperations):

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceStaticMapping(ghidra.trace.model.TraceUniqueObject):
    """
    A mapped range from this trace to a Ghidra :obj:`Program`
    """

    class_: typing.ClassVar[java.lang.Class]

    def conflictsWith(self, range: ghidra.program.model.address.AddressRange, lifespan: ghidra.trace.model.Lifespan, toProgramURL: java.net.URL, toAddress: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if this mapping would conflict with the given prospective mapping
        
        :param ghidra.program.model.address.AddressRange range: the range in the trace ("from")
        :param ghidra.trace.model.Lifespan lifespan: the span of time in the trace
        :param java.net.URL toProgramURL: the (Ghidra) URL of the static image ("to")
        :param java.lang.String or str toAddress: the starting address (in string form) in the staic image ("to")
        :return: true if this mapping conflicts.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`TraceStaticMappingManager.findAnyConflicting(AddressRange, Lifespan, URL, String)`
        """

    def delete(self):
        """
        Remove this mapping from the "from" trace
        """

    def getEndSnap(self) -> int:
        """
        Get the ending snap of the lifespan
        
        :return: the end snap
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Get the length of the mapping, i.e., the length of the range
        
        :return: the length, where 0 indicates ``1 << 64``
        :rtype: int
        """

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        """
        Get the span of time of the mapping
        
        :return: the lifespan
        :rtype: ghidra.trace.model.Lifespan
        """

    def getMaxTraceAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the "from" range's maximum address
        
        :return: the maximum address
        :rtype: ghidra.program.model.address.Address
        """

    def getMinTraceAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the "from" range's minimum address
        
        :return: the minimum address
        :rtype: ghidra.program.model.address.Address
        """

    def getShift(self) -> int:
        """
        Get the shift in offset from static program to dynamic trace
        
        :return: the shift
        :rtype: int
        """

    def getStartSnap(self) -> int:
        """
        Get the starting snap of the lifespan
        
        :return: the start snap
        :rtype: int
        """

    def getStaticAddress(self) -> str:
        """
        Get the "to" address range's minimum address, as a string
        
        :return: the address string
        :rtype: str
        """

    def getStaticProgramURL(self) -> java.net.URL:
        """
        Get the Ghidra URL of the "to" :obj:`Program`, i.e., static image
        
        :return: the program URL
        :rtype: java.net.URL
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the "from" trace, i.e., the trace containing this mapping
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def getTraceAddressRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the "from" range
        
        :return: the range
        :rtype: ghidra.program.model.address.AddressRange
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def staticProgramURL(self) -> java.net.URL:
        ...

    @property
    def minTraceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def endSnap(self) -> jpype.JLong:
        ...

    @property
    def shift(self) -> jpype.JLong:
        ...

    @property
    def maxTraceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def staticAddress(self) -> java.lang.String:
        ...

    @property
    def startSnap(self) -> jpype.JLong:
        ...

    @property
    def traceAddressRange(self) -> ghidra.program.model.address.AddressRange:
        ...


class TraceModuleManager(TraceModuleOperations):
    """
    A store for loaded modules over time
     
     
    
    The manager is not bound to any particular address space and may be used to access information
    about any memory address. For module and section management, only section information can be
    space bound.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addLoadedModule(self, modulePath: typing.Union[java.lang.String, str], moduleName: typing.Union[java.lang.String, str], range: ghidra.program.model.address.AddressRange, snap: typing.Union[jpype.JLong, int]) -> TraceModule:
        """
        Add a module which is still loaded
        
        :param java.lang.String or str modulePath: the "full name" of the module
        :param java.lang.String or str moduleName: the "short name" of the module
        :param ghidra.program.model.address.AddressRange range: the address range of the module -- min should be the base address
        :param jpype.JLong or int snap: the snap at which the module was loaded
        :return: the new module
        :rtype: TraceModule
        :raises DuplicateNameException: if another module with the same name already exists for the
                    desired lifespan
        """

    def addModule(self, modulePath: typing.Union[java.lang.String, str], moduleName: typing.Union[java.lang.String, str], range: ghidra.program.model.address.AddressRange, lifespan: ghidra.trace.model.Lifespan) -> TraceModule:
        """
        Add a module
         
         
        
        Note that modules may overlap.
        
        :param java.lang.String or str modulePath: the "full name" of the module
        :param java.lang.String or str moduleName: the "short name" of the module, usually its path on the file system
        :param ghidra.program.model.address.AddressRange range: the address range of the module -- min should be the base address
        :param ghidra.trace.model.Lifespan lifespan: the span from load time to unload time
        :return: the new module
        :rtype: TraceModule
        :raises DuplicateNameException: if another module with the same name already exists for the
                    desired lifespan
        """

    def getLoadedModuleByPath(self, snap: typing.Union[jpype.JLong, int], modulePath: typing.Union[java.lang.String, str]) -> TraceModule:
        """
        Get the module loaded at the given snap having the given path
        
        :param jpype.JLong or int snap: the snap which the module's lifespan must contain
        :param java.lang.String or str modulePath: the module's "full name"
        :return: the module, or ``null`` if no module matches
        :rtype: TraceModule
        """

    def getLoadedSectionByPath(self, snap: typing.Union[jpype.JLong, int], sectionPath: typing.Union[java.lang.String, str]) -> TraceSection:
        """
        Get the section loaded at the given snap having the given path
        
        :param jpype.JLong or int snap: the snap which the section's (module's) lifespan must contain
        :param java.lang.String or str sectionPath: the section's "full name"
        :return: the section, or ``null`` if no section matches
        :rtype: TraceSection
        """

    def getModulesByPath(self, modulePath: typing.Union[java.lang.String, str]) -> java.util.Collection[TraceModule]:
        """
        Get modules by path
         
         
        
        Note it is possible the same module was loaded and unloaded multiple times. In that case,
        each load will have an separate record. It is also possible it was loaded at a different
        address, or that it's an entirely different module which happens to have the same path.
         
         
        
        Note that the "module path" in this case is not necessarily path of the module's image on the
        target file system, though this name often contains it. Rather, this is typically the full
        path to the module in the target debugger's object model. Likely, the "short name" is the
        file system path of the module's image.
        
        :param java.lang.String or str modulePath: the "full name" of the module
        :return: the collection of modules having the given path
        :rtype: java.util.Collection[TraceModule]
        """

    def getSectionsByPath(self, sectionPath: typing.Union[java.lang.String, str]) -> java.util.Collection[TraceSection]:
        """
        Get sections by path
         
         
        
        Note because it's possible for a module path to be duplicated (but not within any overlapping
        snap), it is also possible for a section path to be duplicated.
        
        :param java.lang.String or str sectionPath: the "full name" of the section
        :return: the collection of sections having the given path
        :rtype: java.util.Collection[TraceSection]
        """

    @property
    def modulesByPath(self) -> java.util.Collection[TraceModule]:
        ...

    @property
    def sectionsByPath(self) -> java.util.Collection[TraceSection]:
        ...


class TraceModuleOperations(java.lang.Object):
    """
    Operations for retrieving sections from a trace
     
     
    
    Modules do not occupy target memory in and of themselves, but rather, their sections do. Thus,
    only the section information is mapped out by memory address. Each section inherits its lifespan
    from the containing module.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAllModules(self) -> java.util.Collection[TraceModule]:
        """
        Get all modules
        
        :return: the (possibly empty) collection of modules
        :rtype: java.util.Collection[TraceModule]
        """

    def getAllSections(self) -> java.util.Collection[TraceSection]:
        """
        Get all sections
        
        :return: the (possibly empty) collection of sections
        :rtype: java.util.Collection[TraceSection]
        """

    def getLoadedModules(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Collection[TraceModule]:
        """
        Get all modules loaded at the given snap
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the collection of loaded modules
        :rtype: java.util.Collection[TraceModule]
        """

    def getModulesAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Collection[TraceModule]:
        """
        Get modules at the given snap and address
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the (possibly empty) collection of modules
        :rtype: java.util.Collection[TraceModule]
        """

    def getModulesIntersecting(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.util.Collection[TraceModule]:
        """
        Get the modules loaded at the given snap intersecting the given address range
        
        :param ghidra.trace.model.Lifespan lifespan: the span which the module must intersect
        :param ghidra.program.model.address.AddressRange range: the range of memory the module must intersect
        :return: the collection of sections
        :rtype: java.util.Collection[TraceModule]
        """

    def getSectionsAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Collection[TraceSection]:
        """
        Get sections at the given snap and address
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the (possibly empty) collection of sections
        :rtype: java.util.Collection[TraceSection]
        """

    def getSectionsIntersecting(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.util.Collection[TraceSection]:
        """
        Get the sections loaded at the given snap intersecting the given address range
        
        :param ghidra.trace.model.Lifespan lifespan: the span which the section's (module's) lifespan must intersect
        :param ghidra.program.model.address.AddressRange range: the range of memory each loaded section must intersect
        :return: the collection of sections
        :rtype: java.util.Collection[TraceSection]
        """

    @property
    def allSections(self) -> java.util.Collection[TraceSection]:
        ...

    @property
    def allModules(self) -> java.util.Collection[TraceModule]:
        ...

    @property
    def loadedModules(self) -> java.util.Collection[TraceModule]:
        ...


class TraceConflictedMappingException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str], conflicts: collections.abc.Sequence):
        ...

    def getConflicts(self) -> java.util.Set[TraceStaticMapping]:
        ...

    @property
    def conflicts(self) -> java.util.Set[TraceStaticMapping]:
        ...


class TraceStaticMappingManager(java.lang.Object):
    """
    Manages mappings from this trace into static images (Ghida :obj:`Program`s)
     
     
    
    Most commonly, this is used to map modules listed by a connected debugger to programs already
    imported into the same Ghidra project. It is vitally important that the image loaded by the
    target is an exact copy of the image imported by Ghidra, or else things may not be aligned.
     
     
    
    Note, to best handle mapping ranges to a variety of programs, and to validate the addition of new
    entries, it is unlikely a client should consume mapping entries directly. Instead, a service
    should track the mappings among all open traces and programs, permitting clients to mutate and
    consume mappings more naturally, e.g., by passing in a :obj:`Program` and :obj:`Address` rather
    than a URL and string-ized address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, range: ghidra.program.model.address.AddressRange, lifespan: ghidra.trace.model.Lifespan, toProgramURL: java.net.URL, toAddress: typing.Union[java.lang.String, str]) -> TraceStaticMapping:
        """
        Add a new mapping, if not already covered
         
         
        
        A new mapping may overlap an existing mapping, so long as they agree in address shift.
        Furthermore, in such cases, the implementation may coalesce mappings to remove duplication.
        
        :param ghidra.program.model.address.AddressRange range: the range in the trace ("from")
        :param ghidra.trace.model.Lifespan lifespan: the span of time in the trace
        :param java.net.URL toProgramURL: the (Ghidra) URL of the static image ("to")
        :param java.lang.String or str toAddress: the starting address (in string form) in the static image ("to")
        :raises TraceConflictedMappingException: if an existing mapping conflicts. See
                    :meth:`findAnyConflicting(AddressRange, Lifespan, URL, String) <.findAnyConflicting>`
        :return: the new entry, or any entry which subsumes the specified mapping
        :rtype: TraceStaticMapping
        """

    def findAllOverlapping(self, range: ghidra.program.model.address.AddressRange, lifespan: ghidra.trace.model.Lifespan) -> java.util.Collection[TraceStaticMapping]:
        """
        Find all mappings which overlap the given adddress range and span of time
         
         
        
        Note, this returns overlapping entries whether or not they conflict.
        
        :param ghidra.program.model.address.AddressRange range: the range in the trace ("from")
        :param ghidra.trace.model.Lifespan lifespan: the span of time in the trace
        :return: an unmodifiable collection of overlapped entries
        :rtype: java.util.Collection[TraceStaticMapping]
        """

    def findAnyConflicting(self, range: ghidra.program.model.address.AddressRange, lifespan: ghidra.trace.model.Lifespan, toProgramURL: java.net.URL, toAddress: typing.Union[java.lang.String, str]) -> TraceStaticMapping:
        """
        Check if another mapping would conflict with the given prospective mapping
         
         
        
        Mappings are allowed to overlap, but they must agree on the destination program and address
        throughout all overlapping portions.
         
         
        
        **TODO**: It'd be nice if the manager automatically merged overlapping mappings in
        agreement or provided a "de-duplicate" method which optimized the entries in the database.
        This gets complicated, since we're dealing with overlapping rectangles, not strict
        one-dimensional ranges. Look into existing research for optimizing coverage of shapes by
        rectangles. The same is needed for property maps in 2 dimensions.
        
        :param ghidra.program.model.address.AddressRange range: the range in the trace ("from")
        :param ghidra.trace.model.Lifespan lifespan: the span of time in the trace
        :param java.net.URL toProgramURL: the (Ghidra) URL of the static image ("to")
        :param java.lang.String or str toAddress: the starting address (in string form) in the static image ("to")
        :return: a conflicting mapping, or ``null`` if none exist
        :rtype: TraceStaticMapping
        """

    def findContaining(self, address: ghidra.program.model.address.Address, snap: typing.Union[jpype.JLong, int]) -> TraceStaticMapping:
        """
        Find any mapping applicable to the given snap and address
        
        :param ghidra.program.model.address.Address address: the address
        :param jpype.JLong or int snap: the snap
        :return: the mapping, or ``null`` if none exist at the given location
        :rtype: TraceStaticMapping
        """

    def getAllEntries(self) -> java.util.Collection[TraceStaticMapping]:
        """
        Get all mappings in the manager
        
        :return: the collection of mappings
        :rtype: java.util.Collection[TraceStaticMapping]
        """

    @property
    def allEntries(self) -> java.util.Collection[TraceStaticMapping]:
        ...


class TraceModule(ghidra.trace.model.TraceUniqueObject, ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    A binary module loaded by the target and/or debugger
     
     
    
    This also serves as a namespace for storing the module's sections. If the debugger cares to parse
    the modules for section information, those sections should be presented as successors to the
    module.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_RANGE: typing.Final = "_range"
    KEY_MODULE_NAME: typing.Final = "_module_name"

    @typing.overload
    def addSection(self, snap: typing.Union[jpype.JLong, int], sectionPath: typing.Union[java.lang.String, str], sectionName: typing.Union[java.lang.String, str], range: ghidra.program.model.address.AddressRange) -> TraceSection:
        """
        Add a section to this module
         
         
        
        Note while rare, it is permissible for sections to overlap. Module and section records are
        more informational and provide a means of recording module load and unload events, while
        noting the sections of which the debugger was aware. Typically each section, meeting certain
        criteria set by the target, is mapped into a memory region. Those regions cannot overlap.
        Furthermore, any overlapped mappings to static modules, which are usually derived from
        sections stored here, must agree on the address adjustment.
        
        :param jpype.JLong or int snap: the "load" snap of the module
        :param java.lang.String or str sectionPath: the "full name" of the section
        :param java.lang.String or str sectionName: the "short name" of the section
        :param ghidra.program.model.address.AddressRange range: the range of memory into which the section is loaded
        :return: the new section
        :rtype: TraceSection
        :raises DuplicateNameException: if a section with the given name already exists in this module
        """

    @typing.overload
    def addSection(self, snap: typing.Union[jpype.JLong, int], sectionPath: typing.Union[java.lang.String, str], range: ghidra.program.model.address.AddressRange) -> TraceSection:
        """
        Add a section having the same full and short names
        
        :param jpype.JLong or int snap: the "load" snap of the module
        :param java.lang.String or str sectionPath: the "full name" of the section
        :param ghidra.program.model.address.AddressRange range: the range of memory into which the section is loaded
        :return: the new section
        :rtype: TraceSection
        :raises DuplicateNameException: if a section with the given name already exists in this module
        
        .. seealso::
        
            | :obj:`.addSection(long, String, String, AddressRange)`
        """

    def delete(self):
        """
        Delete this module and its sections from the trace
        """

    def getAllSections(self) -> java.util.Collection[TraceSection]:
        """
        Collect all sections contained within this module at any time
        
        :return: the collection of sections
        :rtype: java.util.Collection[TraceSection]
        """

    def getBase(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the base address of the module
        
        :param jpype.JLong or int snap: the snap
        :return: the base address
        :rtype: ghidra.program.model.address.Address
        """

    def getLength(self, snap: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the length of the range of the module
        
        :param jpype.JLong or int snap: the snap
        :return: the length
        :rtype: int
        
        .. seealso::
        
            | :obj:`.setRange(long, AddressRange)`
        """

    def getMaxAddress(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the maximum address of the module
        
        :param jpype.JLong or int snap: the snap
        :return: the maximum address
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`.setRange(long, AddressRange)`
        """

    def getName(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the "short name" of this module
         
         
        
        This defaults to the "full name," but can be modified via :meth:`setName(long, String) <.setName>`
        
        :param jpype.JLong or int snap: the snap
        :return: the name
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Get the "full name" of this module
         
         
        
        This is a unique key (within any snap) for retrieving the module, and may not be suitable for
        display on the screen. This is not likely the file system path of the module's image. Rather,
        it's typically the path of the module in the target debugger's object model.
        
        :return: the path
        :rtype: str
        """

    def getRange(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressRange:
        """
        Get the address range of the module
        
        :param jpype.JLong or int snap: the snap
        :return: the address range
        :rtype: ghidra.program.model.address.AddressRange
        
        .. seealso::
        
            | :obj:`.setRange(long, AddressRange)`
        """

    def getSectionByName(self, snap: typing.Union[jpype.JLong, int], sectionName: typing.Union[java.lang.String, str]) -> TraceSection:
        """
        Get the section in this module having the given short name
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str sectionName: the name
        :return: the section, or ``null`` if no section has the given name
        :rtype: TraceSection
        """

    def getSections(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Collection[TraceSection]:
        """
        Collect all sections contained within this module at the given snap
        
        :param jpype.JLong or int snap: the snap
        :return: the collection of sections
        :rtype: java.util.Collection[TraceSection]
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this module
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def isAlive(self, span: ghidra.trace.model.Lifespan) -> bool:
        """
        Check if the module is alive for any of the given span
        
        :param ghidra.trace.model.Lifespan span: the span
        :return: true if its life intersects the span
        :rtype: bool
        """

    def isValid(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the module is valid at the given snapshot
        
        :param jpype.JLong or int snap: the snapshot key
        :return: true if valid, false if not
        :rtype: bool
        """

    def remove(self, snap: typing.Union[jpype.JLong, int]):
        """
        Remove this module from the given snap on
        
        :param jpype.JLong or int snap: the snap
        """

    def setBase(self, snap: typing.Union[jpype.JLong, int], base: ghidra.program.model.address.Address):
        """
        Set the base (usually minimum) address of the module
         
         
        
        If not given by the target's debugger, the model or the recorder should endeavor to compute
        it from whatever information is provided. In general, this should be the virtual memory
        address mapped to file offset 0 of the module's image.
         
         
        
        Note that this sets the range from the given snap on to the same range, no matter what
        changes may have occurred since.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address base: the base address
        """

    def setLength(self, snap: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int]):
        """
        Set the length of the range of the module
         
         
        
        This adjusts the max address of the range so that its length becomes that given. Note that
        this sets the range from the given snap on to the same range, no matter what changes may have
        occurred since.
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JLong or int length: the length
        :raises AddressOverflowException: if the length would cause the max address to overflow
        
        .. seealso::
        
            | :obj:`.setRange(long, AddressRange)`
        """

    def setMaxAddress(self, snap: typing.Union[jpype.JLong, int], max: ghidra.program.model.address.Address):
        """
        Set the maximum address of the module
         
         
        
        Note that this sets the range from the given snap on to the same range, no matter what
        changes may have occurred since.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address max: the maximum address
        
        .. seealso::
        
            | :obj:`.setRange(long, AddressRange)`
        """

    @typing.overload
    def setName(self, lifespan: ghidra.trace.model.Lifespan, name: typing.Union[java.lang.String, str]):
        """
        Set the "short name" of this module
         
         
        
        The given name is typically the file system path of the module's image, which is considered
        suitable for display on the screen.
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param java.lang.String or str name: the name
        """

    @typing.overload
    def setName(self, snap: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str]):
        """
        Set the "short name" of this module
         
         
        
        The given name is typically the file system path of the module's image, which is considered
        suitable for display on the screen.
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str name: the name
        """

    @typing.overload
    def setRange(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        """
        Set the address range of the module
         
         
        
        Typically, the minimum address in this range is the module's base address. If sections are
        given, this range should enclose all sections mapped into memory.
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param ghidra.program.model.address.AddressRange range: the address range.
        """

    @typing.overload
    def setRange(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange):
        """
        Set the address range of the module
         
         
        
        Typically, the minimum address in this range is the module's base address. If sections are
        given, this range should enclose all sections mapped into memory.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.AddressRange range: the address range.
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def allSections(self) -> java.util.Collection[TraceSection]:
        ...

    @property
    def alive(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def sections(self) -> java.util.Collection[TraceSection]:
        ...

    @property
    def base(self) -> ghidra.program.model.address.Address:
        ...


class TraceSection(ghidra.trace.model.TraceUniqueObject, ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    An allocated section of a binary module
     
     
    
    Note that the model should only present those sections which are allocated in memory. Otherwise
    strange things may happen, such as zero-length ranges (which AddressRange hates), or overlapping
    ranges (which Trace hates).
     
     
    
    LATER?: Present all sections, but include isAllocated
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_MODULE: typing.Final = "_module"
    KEY_RANGE: typing.Final = "_range"

    def delete(self):
        """
        Delete this section from the trace
        """

    def getEnd(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :return: the max address in the range
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`.getRange(long)`
        """

    def getModule(self) -> TraceModule:
        """
        Get the module containing this section
        
        :return: the module
        :rtype: TraceModule
        """

    def getName(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the "short name" of this section
         
         
        
        This defaults to the "full name," but can be modified via :meth:`setName(long, String) <.setName>`
        
        :param jpype.JLong or int snap: the snap
        :return: the name
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Get the "full name" of this section
         
         
        
        This is a unique key (within a snap) among all sections, and may not be suitable for display
        on the screen.
        
        :return: the path
        :rtype: str
        """

    def getRange(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressRange:
        """
        Get the virtual memory address range of this section
        
        :param jpype.JLong or int snap: the snap
        :return: the address range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getStart(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        
        
        :param jpype.JLong or int snap: the snap
        :return: the min address in the range
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`.getRange(long)`
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this section
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def isValid(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the section is valid at the given snapshot
        
        :param jpype.JLong or int snap: the snapshot key
        :return: true if valid, false if not
        :rtype: bool
        """

    def remove(self, snap: typing.Union[jpype.JLong, int]):
        """
        Remove this section from the given snap on
        
        :param jpype.JLong or int snap: the snap
        """

    @typing.overload
    def setName(self, lifespan: ghidra.trace.model.Lifespan, name: typing.Union[java.lang.String, str]):
        """
        Set the short name of this section
         
         
        
        The given name should be the section's name from its module's image, which is considered
        suitable for display on the screen.
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param java.lang.String or str name: the name
        """

    @typing.overload
    def setName(self, snap: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str]):
        """
        Set the short name of this section
         
         
        
        The given name should be the section's name from its module's image, which is considered
        suitable for display on the screen.
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str name: the name
        :raises DuplicateNameException: if the specified name would conflict with another section's in
                    this module
        """

    def setRange(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        """
        Set the virtual memory address range of this section
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param ghidra.program.model.address.AddressRange range: the span of addresses
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def module(self) -> TraceModule:
        ...

    @property
    def start(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def end(self) -> ghidra.program.model.address.Address:
        ...



__all__ = ["TraceModuleSpace", "TraceStaticMapping", "TraceModuleManager", "TraceModuleOperations", "TraceConflictedMappingException", "TraceStaticMappingManager", "TraceModule", "TraceSection"]
