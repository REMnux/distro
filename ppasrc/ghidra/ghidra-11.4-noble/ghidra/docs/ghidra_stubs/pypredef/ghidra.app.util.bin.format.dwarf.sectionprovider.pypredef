from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import ghidra.program.model.listing
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore


class ExternalDebugFileSectionProvider(BaseSectionProvider):
    """
    A :obj:`DWARFSectionProvider` that reads .debug_info (and friends) sections from an external
    ELF file that is referenced in the original ELF file's build-id or debuglink sections.
     
    
    Creates a pinning reference from the temporary external ELF debug file to this SectionProvider
    instance using the program's :meth:`Program.addConsumer(Object) <Program.addConsumer>`, and then releases the
    consumer when this instance is closed, allowing the temporary Program to be destroyed.
    """

    class_: typing.ClassVar[java.lang.Class]
    PROGRAM_INFO_DWARF_EXTERNAL_DEBUG_FILE: typing.Final = "DWARF External Debug File"

    @staticmethod
    def createExternalSectionProviderFor(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> DWARFSectionProvider:
        ...

    @staticmethod
    def getExternalDebugFileLocation(program: ghidra.program.model.listing.Program) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the previously saved value of the external debug file location from the program's
        metadata.
        
        :param ghidra.program.model.listing.Program program: DWARF that previously was analyzed
        :return: FSRL of external debug file, or null if missing or corrupted value
        :rtype: ghidra.formats.gfilesystem.FSRL
        """

    def getExternalProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def externalProgram(self) -> ghidra.program.model.listing.Program:
        ...


class NullSectionProvider(DWARFSectionProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DWARFSectionNames(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DEBUG_INFO: typing.Final = "debug_info"
    DEBUG_TYPES: typing.Final = "debug_types"
    DEBUG_ABBREV: typing.Final = "debug_abbrev"
    DEBUG_ARRANGES: typing.Final = "debug_arranges"
    DEBUG_LINE: typing.Final = "debug_line"
    DEBUG_LINE_STR: typing.Final = "debug_line_str"
    DEBUG_FRAME: typing.Final = "debug_frame"
    DEBUG_LOC: typing.Final = "debug_loc"
    DEBUG_LOCLISTS: typing.Final = "debug_loclists"
    DEBUG_STR: typing.Final = "debug_str"
    DEBUG_STROFFSETS: typing.Final = "debug_str_offsets"
    DEBUG_RANGES: typing.Final = "debug_ranges"
    DEBUG_RNGLISTS: typing.Final = "debug_rnglists"
    DEBUG_PUBNAMES: typing.Final = "debug_pubnames"
    DEBUG_PUBTYPES: typing.Final = "debug_pubtypes"
    DEBUG_MACINFO: typing.Final = "debug_macinfo"
    DEBUG_ADDR: typing.Final = "debug_addr"
    MINIMAL_DWARF_SECTIONS: typing.Final[jpype.JArray[java.lang.String]]

    def __init__(self):
        ...


class BaseSectionProvider(DWARFSectionProvider):
    """
    Fetches DWARF sections from a normal program using simple Ghidra memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    @staticmethod
    def createSectionProviderFor(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> BaseSectionProvider:
        ...


class DWARFSectionProviderFactory(java.lang.Object):
    """
    Auto-detects which :obj:`DWARFSectionProvider` matches a Ghidra program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createSectionProviderFor(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> DWARFSectionProvider:
        """
        Iterates through the statically registered :obj:`factory funcs <.sectionProviderFactoryFuncs>`,
        trying each factory method until one returns a :obj:`DWARFSectionProvider` 
        that can successfully retrieve the :obj:`minimal <DWARFSectionNames.MINIMAL_DWARF_SECTIONS>` 
        sections we need to do a DWARF import.
         
        
        The resulting :obj:`DWARFSectionProvider` is :obj:`Closeable` and it is the caller's
        responsibility to ensure that the object is closed when done.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: :obj:`DWARFSectionProvider` that should be closed by the caller or NULL if no
        section provider types match the specified program.
        :rtype: DWARFSectionProvider
        """


class CompressedSectionProvider(DWARFSectionProvider):
    """
    A wrapper around another DWARFSectionProvider, this provider
    fetches DWARF section data that has been compressed and stored in sections in the underlying 
    :obj:`DWARFSectionProvider`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sp: DWARFSectionProvider):
        ...


class DSymSectionProvider(DWARFSectionProvider):
    """
    Fetches DWARF section data for a MachO program with co-located .dSYM folder. (ie. Mac OSX
    binaries)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dsymFile: jpype.protocol.SupportsPath):
        ...

    @staticmethod
    def createSectionProviderFor(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> DSymSectionProvider:
        ...

    @staticmethod
    def getDSYMForProgram(program: ghidra.program.model.listing.Program) -> java.io.File:
        ...


class DWARFSectionProvider(java.io.Closeable):
    """
    A DWARFSectionProvider is responsible for allowing access to DWARF section data of
    a Ghidra program.
     
    
    Implementors of this interface need to be registered in 
    :obj:`DWARFSectionProviderFactory.sectionProviderFactoryFuncs` and should implement the 
    static method:
     
    
    ``public static DWARFSectionProvider createSectionProviderFor(Program program, TaskMonitor monitor)``
     
    
    that is called via a java Function wrapper.
     
    
    :obj:`DWARFSectionProvider` instances are responsible for :meth:`closing <ByteProvider.close>` 
    any :obj:`ByteProvider` that has been returned via 
    :meth:`getSectionAsByteProvider(String, TaskMonitor) <.getSectionAsByteProvider>` when the section provider instance is 
    itself closed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getSectionAsByteProvider(self, sectionName: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a ByteProvider for the specified section.
        
        :param java.lang.String or str sectionName: name of the section
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to use when performing long operations
        :return: ByteProvider, which will be closed by the section provider when itself is closed
        :rtype: ghidra.app.util.bin.ByteProvider
        :raises IOException: if error
        """

    def hasSection(self, *sectionNames: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified section names are present.
        
        :param jpype.JArray[java.lang.String] sectionNames: list of section names to test
        :return: true if all are present, false if not present
        :rtype: bool
        """

    def updateProgramInfo(self, program: ghidra.program.model.listing.Program):
        """
        Decorate the specified program with any information that is unique to this section provider.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` with an active transaction
        """



__all__ = ["ExternalDebugFileSectionProvider", "NullSectionProvider", "DWARFSectionNames", "BaseSectionProvider", "DWARFSectionProviderFactory", "CompressedSectionProvider", "DSymSectionProvider", "DWARFSectionProvider"]
