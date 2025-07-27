from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class CieSource(java.lang.Object):
    """
    Provides GCC exception handling model classes the means to obtain a Common Information Entry
    (CIE) object for a given address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCie(self, currAddress: ghidra.program.model.address.Address) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.Cie:
        """
        For the provided address, return a Common Information Entry (CIE)
        
        :param ghidra.program.model.address.Address currAddress: the address with the CIE
        :return: the Cie at ``currAddress``
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.Cie
        :raises MemoryAccessException: if memory for the CIE couldn't be read
        :raises ExceptionHandlerFrameException: if a problem was encountered
        """

    @property
    def cie(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.Cie:
        ...


class DebugFrameSection(AbstractFrameSection):
    """
    Parses the exception handling structures within a '.debug_frame' memory section, which 
    contains call frame debugging information.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEBUG_FRAME_BLOCK_NAME: typing.Final = ".debug_frame"

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Constructor for a debug frame section.
        
        :param ghidra.util.task.TaskMonitor monitor: a status monitor for indicating progress or allowing a task to be cancelled.
        :param ghidra.program.model.listing.Program program: the program containing this debug frame section.
        """

    def analyze(self) -> java.util.List[ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor]:
        """
        Analyzes and annotates the debug frame section.
        
        :return: the region descriptors that compose the debug frame section.
        :rtype: java.util.List[ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor]
        :raises MemoryAccessException: if memory couldn't be read/written while processing the section.
        :raises AddressOutOfBoundsException: if one or more expected addresses weren't in the program.
        :raises ExceptionHandlerFrameException: if the FDE table can't be decoded.
        """


class EhFrameHeaderSection(java.lang.Object):
    """
    Parses the exception handling structures within an '.eh_frame_hdr' memory section; contains 
    the frame header record and the FDE table.
    """

    class_: typing.ClassVar[java.lang.Class]
    EH_FRAME_HEADER_BLOCK_NAME: typing.Final = ".eh_frame_hdr"

    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Constructor for an eh frame header section.
        
        :param ghidra.program.model.listing.Program program: the program containing this eh frame header.
        """

    def analyze(self, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Analyzes and annotates the eh frame header.
        
        :param ghidra.util.task.TaskMonitor monitor: a status monitor for indicating progress or allowing a task to be cancelled.
        :return: the number of records in the FDE table or 0 if there was no EH frame header to analyze.
        :rtype: int
        :raises MemoryAccessException: if memory couldn't be read/written while processing the header.
        :raises AddressOutOfBoundsException: if one or more expected addresses weren't in the program.
        :raises ExceptionHandlerFrameException: if the FDE table can't be decoded.
        """


@typing.type_check_only
class AbstractFrameSection(CieSource):
    """
    Extend this class to parse the call frame information exception handling structures within a 
    particular frame memory section.
    """

    class_: typing.ClassVar[java.lang.Class]


class EhFrameSection(AbstractFrameSection):
    """
    Parses the call frame information exception handling structures within an '.eh_frame' 
    memory section.
    """

    class_: typing.ClassVar[java.lang.Class]
    EH_FRAME_BLOCK_NAME: typing.Final = ".eh_frame"

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Constructor for an eh frame section.
        
        :param ghidra.util.task.TaskMonitor monitor: a status monitor for indicating progress or allowing a task to be cancelled.
        :param ghidra.program.model.listing.Program program: the program containing this eh frame section.
        """

    def analyze(self, fdeTableCount: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor]:
        """
        Analyzes and annotates the eh frame section.
        
        :param jpype.JInt or int fdeTableCount: the number of exception handler FDEs.
        :return: the region descriptors for the eh frame section.
        :rtype: java.util.List[ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor]
        :raises MemoryAccessException: if memory couldn't be read/written while processing the eh frame.
        :raises AddressOutOfBoundsException: if one or more expected addresses weren't in the program.
        :raises ExceptionHandlerFrameException: if a problem was encountered determining eh frame data.
        """



__all__ = ["CieSource", "DebugFrameSection", "EhFrameHeaderSection", "AbstractFrameSection", "EhFrameSection"]
