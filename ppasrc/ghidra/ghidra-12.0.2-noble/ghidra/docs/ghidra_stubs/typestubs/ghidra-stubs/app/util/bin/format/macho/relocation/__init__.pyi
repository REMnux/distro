from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin.format.macho
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.reloc
import ghidra.util.classfinder
import java.lang # type: ignore


class MachoRelocationHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    An abstract class used to perform Mach-O relocations.  Classes should extend this class to
    provide relocations in a machine/processor specific way.
    
    
    .. seealso::
    
        | `mach-o/reloc.h <https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/reloc.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def canRelocate(self, header: ghidra.app.util.bin.format.macho.MachHeader) -> bool:
        """
        Checks to see whether or not an instance of this Mach-O relocation handler can handle 
        relocating the Mach-O defined by the provided file header
        
        :param ghidra.app.util.bin.format.macho.MachHeader header: The header associated with the Mach-O to relocate
        :return: True if this relocation handler can do the relocation; otherwise, false
        :rtype: bool
        """

    def isPairedRelocation(self, relocation: ghidra.app.util.bin.format.macho.RelocationInfo) -> bool:
        """
        Checks to see if the given relocation is a "paired" relocation.  A paired relocation has a 
        certain expectation from the relocation that follows it.
        
        :param ghidra.app.util.bin.format.macho.RelocationInfo relocation: The relocation to check
        :return: True if the given relocation is a "paired" relocation; otherwise, false
        :rtype: bool
        """

    @staticmethod
    def read(relocation: MachoRelocation) -> int:
        """
        Reads bytes at the given address.  The size of the read is determined by the length of the 
        relocation info.
        
        :param MachoRelocation relocation: The relocation to read
        :return: The read bytes
        :rtype: int
        :raises MemoryAccessException: If there is a problem accessing memory during the read
        """

    def relocate(self, relocation: MachoRelocation) -> ghidra.program.model.reloc.RelocationResult:
        """
        Performs a relocation
        
        :param MachoRelocation relocation: The relocation to perform
        :return: applied relocation result
        :rtype: ghidra.program.model.reloc.RelocationResult
        :raises MemoryAccessException: If there is a problem accessing memory during the relocation
        :raises RelocationException: if supported relocation encountered an error during processing.
        This exception should be thrown in place of returning :obj:`RelocationResult.FAILURE` or
        a status of :obj:`Status.FAILURE` which will facilitate a failure reason via 
        :meth:`RelocationException.getMessage() <RelocationException.getMessage>`.
        """

    @staticmethod
    def write(relocation: MachoRelocation, value: typing.Union[jpype.JLong, int]) -> int:
        """
        Writes bytes at the given address.  The size of the write is determined by the length of the 
        relocation info.
        
        :param MachoRelocation relocation: The relocation to write
        :param jpype.JLong or int value: The value to write
        :return: number of bytes written
        :rtype: int
        :raises MemoryAccessException: If there is a problem accessing memory during the write
        """

    @property
    def pairedRelocation(self) -> jpype.JBoolean:
        ...


class MachoRelocationHandlerFactory(java.lang.Object):
    """
    A class that gets the appropriate Mach-O relocation handler for a specific Mach-O file
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getHandler(header: ghidra.app.util.bin.format.macho.MachHeader) -> MachoRelocationHandler:
        """
        Gets the appropriate Mach-O relocation handler that is capable of relocating the Mach-O that 
        is defined by the given Mach-O header
        
        :param ghidra.app.util.bin.format.macho.MachHeader header: The header associated with the Mach-O to relocate
        :return: The appropriate Mach-O relocation handler that is capable of relocating the Mach-O 
        that is defined by the given Mach-O header.  Could return null if no such handler was
        found.
        :rtype: MachoRelocationHandler
        """


class MachoRelocation(java.lang.Object):
    """
    A representation of a single Mach-O relocation that the :obj:`MachoRelocationHandler` will use
    to perform the relocation.  In Mach-O, some relocations may be "paired," so an instance of this
    class may contain 2 :obj:`RelocationInfo`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, machoHeader: ghidra.app.util.bin.format.macho.MachHeader, relocationAddress: ghidra.program.model.address.Address, relocationInfo: ghidra.app.util.bin.format.macho.RelocationInfo):
        """
        Creates a new unpaired :obj:`MachoRelocation` object
        
        :param ghidra.program.model.listing.Program program: The program
        :param ghidra.app.util.bin.format.macho.MachHeader machoHeader: The Mach-O header
        :param ghidra.program.model.address.Address relocationAddress: The :obj:`Address` the relocation takes place at
        :param ghidra.app.util.bin.format.macho.RelocationInfo relocationInfo: The lower-level :obj:`RelocationInfo` that describes the relocation
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, machoHeader: ghidra.app.util.bin.format.macho.MachHeader, relocationAddress: ghidra.program.model.address.Address, relocationInfo: ghidra.app.util.bin.format.macho.RelocationInfo, relocationInfoExtra: ghidra.app.util.bin.format.macho.RelocationInfo):
        """
        Creates a new paired :obj:`MachoRelocation` object
        
        :param ghidra.program.model.listing.Program program: The program
        :param ghidra.app.util.bin.format.macho.MachHeader machoHeader: The Mach-O header
        :param ghidra.program.model.address.Address relocationAddress: The :obj:`Address` the relocation takes place at
        :param ghidra.app.util.bin.format.macho.RelocationInfo relocationInfo: The lower-level :obj:`RelocationInfo` that describes the first part
        of the relocation
        :param ghidra.app.util.bin.format.macho.RelocationInfo relocationInfoExtra: The lower-level :obj:`RelocationInfo` that describes the second
        part of the relocation
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the :obj:`Program` associated with this relocation
        
        :return: The :obj:`Program` associated with this relocation
        :rtype: ghidra.program.model.listing.Program
        """

    def getRelocationAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the :obj:`Address` the relocation takes place at
        
        :return: The :obj:`Address` the relocation takes place at
        :rtype: ghidra.program.model.address.Address
        """

    def getRelocationInfo(self) -> ghidra.app.util.bin.format.macho.RelocationInfo:
        """
        Gets the lower-level :obj:`RelocationInfo` that describes the relocation
        
        :return: The lower-level :obj:`RelocationInfo` that describes the relocation
        :rtype: ghidra.app.util.bin.format.macho.RelocationInfo
        """

    def getRelocationInfoExtra(self) -> ghidra.app.util.bin.format.macho.RelocationInfo:
        """
        Gets the lower-level :obj:`RelocationInfo` that describes the second part of the paired 
        relocation.  This could be null if the relocation is not paired.
        
        :return: The lower-level :obj:`RelocationInfo` that describes the second part of the paired 
        relocation, or null if the relocation is not paired
        :rtype: ghidra.app.util.bin.format.macho.RelocationInfo
        """

    def getTargetAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the :obj:`Address` of the relocation target
        
        :return: The :obj:`Address` of the relocation target
        :rtype: ghidra.program.model.address.Address
        :raises RelocationException: If the :obj:`Address` of the relocation target could not be found
        """

    def getTargetAddressExtra(self) -> ghidra.program.model.address.Address:
        """
        Gets the :obj:`Address` of the extra relocation target
        
        :return: The :obj:`Address` of the extra relocation target
        :rtype: ghidra.program.model.address.Address
        :raises RelocationException: If the :obj:`Address` of the extra relocation target could not be 
        found (of if there wasn't an extra relocation target).
        """

    def getTargetDescription(self) -> str:
        """
        Gets a short description of the target of the relocation
        
        :return: A short description of the target of the relocation
        :rtype: str
        """

    def requiresRelocation(self) -> bool:
        """
        Checks to see if this relocation requires work to be done on it. Since our
        :obj:`loader <MachoLoader>` does not allow non-default image bases, it is unnecessary to 
        perform relocations under certain conditions.
        
        :return: True if relocation steps are needed; otherwise, false
        :rtype: bool
        """

    @property
    def relocationInfo(self) -> ghidra.app.util.bin.format.macho.RelocationInfo:
        ...

    @property
    def targetDescription(self) -> java.lang.String:
        ...

    @property
    def relocationInfoExtra(self) -> ghidra.app.util.bin.format.macho.RelocationInfo:
        ...

    @property
    def targetAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def relocationAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def targetAddressExtra(self) -> ghidra.program.model.address.Address:
        ...



__all__ = ["MachoRelocationHandler", "MachoRelocationHandlerFactory", "MachoRelocation"]
