from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin.format.coff
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.reloc
import ghidra.program.model.symbol
import ghidra.util.classfinder
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class CoffRelocationHandlerFactory(java.lang.Object):
    """
    A class that gets the appropriate COFF relocation handler for a specific COFF.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getHandler(fileHeader: ghidra.app.util.bin.format.coff.CoffFileHeader) -> CoffRelocationHandler:
        """
        Gets the appropriate COFF relocation handler that is capable of relocating the COFF that is
        defined by the given COFF file header.
        
        :param ghidra.app.util.bin.format.coff.CoffFileHeader fileHeader: The file header associated with the COFF to relocate.
        :return: The appropriate COFF relocation handler that is capable of relocating the COFF that 
            is defined by the given COFF file header.  Could return null if there if no such handler
            was found.
        :rtype: CoffRelocationHandler
        """


class CoffRelocationContext(java.lang.Object):
    """
    ``CoffRelocationContext`` provide COFF relocation context data to be used by 
    :obj:`CoffRelocationHandler` during processing of relocations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, header: ghidra.app.util.bin.format.coff.CoffFileHeader, symbolsMap: collections.abc.Mapping):
        """
        Construct COFF relocation context
        
        :param ghidra.program.model.listing.Program program: program to which relocations are applied
        :param ghidra.app.util.bin.format.coff.CoffFileHeader header: COFF file header
        :param collections.abc.Mapping symbolsMap: symbol lookup map
        """

    def computeContextValueIfAbsent(self, key: typing.Union[java.lang.String, str], mappingFunction: java.util.function.Function[java.lang.String, java.lang.Object]) -> java.lang.Object:
        """
        Get and optionally compute context value for specified key
        
        :param java.lang.String or str key: extension-specific context key
        :param java.util.function.Function[java.lang.String, java.lang.Object] mappingFunction: function used to compute value if absent
        :return: context value
        :rtype: java.lang.Object
        """

    def getContextValue(self, key: typing.Union[java.lang.String, str]) -> java.lang.Object:
        """
        Get context value for specified key
        
        :param java.lang.String or str key: extension-specific key
        :return: context value or null if absent
        :rtype: java.lang.Object
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get program to which relocations are being applied
        
        :return: program
        :rtype: ghidra.program.model.listing.Program
        """

    def getSection(self) -> ghidra.app.util.bin.format.coff.CoffSectionHeader:
        """
        Get COFF section to which relocations are being applied
        
        :return: COFF section
        :rtype: ghidra.app.util.bin.format.coff.CoffSectionHeader
        """

    def getSymbol(self, relocation: ghidra.app.util.bin.format.coff.CoffRelocation) -> ghidra.program.model.symbol.Symbol:
        """
        Get symbol required to process a relocation.  Method should only be invoked
        when a symbol is required since some relocations may not require a symbol.
        
        :param ghidra.app.util.bin.format.coff.CoffRelocation relocation: relocation whose related symbol should be returned
        :return: relocation symbol
        :rtype: ghidra.program.model.symbol.Symbol
        :raises RelocationException: if symbol not found
        """

    def getSymbolAddress(self, relocation: ghidra.app.util.bin.format.coff.CoffRelocation) -> ghidra.program.model.address.Address:
        """
        Get address of symbol required to process a relocation.  Method should only be invoked
        when a symbol is required since some relocations may not require a symbol.
        
        :param ghidra.app.util.bin.format.coff.CoffRelocation relocation: relocation whose related symbol should be returned
        :return: relocation symbol
        :rtype: ghidra.program.model.address.Address
        :raises RelocationException: if symbol not found
        """

    def putContextValue(self, key: typing.Union[java.lang.String, str], value: java.lang.Object):
        """
        Store context value for specified key
        
        :param java.lang.String or str key: extension-specific context key
        :param java.lang.Object value: context value
        """

    def resetContext(self, coffSection: ghidra.app.util.bin.format.coff.CoffSectionHeader):
        """
        Reset context at start of COFF section relocation processing
        
        :param ghidra.app.util.bin.format.coff.CoffSectionHeader coffSection: COFF section
        """

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def symbolAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def contextValue(self) -> java.lang.Object:
        ...

    @property
    def section(self) -> ghidra.app.util.bin.format.coff.CoffSectionHeader:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class CoffRelocationHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    An abstract class used to perform COFF relocations.  Classes should extend this class to
    provide relocations in a machine/processor specific way.
    """

    class_: typing.ClassVar[java.lang.Class]

    def canRelocate(self, fileHeader: ghidra.app.util.bin.format.coff.CoffFileHeader) -> bool:
        """
        Checks to see whether or not an instance of this COFF relocation hander can handle 
        relocating the COFF defined by the provided file header.
        
        :param ghidra.app.util.bin.format.coff.CoffFileHeader fileHeader: The file header associated with the COFF to relocate.
        :return: True if this relocation handler can do the relocation; otherwise, false.
        :rtype: bool
        """

    def relocate(self, address: ghidra.program.model.address.Address, relocation: ghidra.app.util.bin.format.coff.CoffRelocation, relocationContext: CoffRelocationContext) -> ghidra.program.model.reloc.RelocationResult:
        """
        Performs a relocation at the specified address.
        
        :param ghidra.program.model.address.Address address: The address at which to perform the relocation.
        :param ghidra.app.util.bin.format.coff.CoffRelocation relocation: The relocation information to use to perform the relocation.
        :param CoffRelocationContext relocationContext: relocation context data
        :return: applied relocation result (conveys status and applied byte-length)
        :rtype: ghidra.program.model.reloc.RelocationResult
        :raises MemoryAccessException: If there is a problem accessing memory during the relocation.
        :raises RelocationException: if supported relocation encountered an error during processing.
        This exception should be thrown in place of returning :obj:`RelocationResult.FAILURE` or
        a status of :obj:`Status.FAILURE` which will facilitate a failure reason via 
        :meth:`RelocationException.getMessage() <RelocationException.getMessage>`.
        """



__all__ = ["CoffRelocationHandlerFactory", "CoffRelocationContext", "CoffRelocationHandler"]
