from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util
import ghidra.app.util.bin.format
import ghidra.app.util.bin.format.elf
import ghidra.program.model.address
import ghidra.util.classfinder
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class ElfExtensionFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getLoadAdapter(elf: ghidra.app.util.bin.format.elf.ElfHeader) -> ElfLoadAdapter:
        ...


class ElfLoadAdapter(java.lang.Object):
    """
    ``ElfLoadAdapter`` provides the base ELF load adapter implementation 
    which may be extended to facilitate target specific behavior.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addDynamicTypes(self, dynamicTypeMap: collections.abc.Mapping):
        """
        Add all extension specific Dynamic table entry types (e.g., DT_ prefix).
        This method will add all those statically defined ElfDynamicType fields
        within this class.
        
        :param collections.abc.Mapping dynamicTypeMap: map to which ElfDynamicType definitions should be added
        """

    def addLoadOptions(self, elf: ghidra.app.util.bin.format.elf.ElfHeader, options: java.util.List[ghidra.app.util.Option]):
        """
        Add extension-specific load options
        
        :param ghidra.app.util.bin.format.elf.ElfHeader elf: ELF header
        :param java.util.List[ghidra.app.util.Option] options: list to which load options may be added
        """

    def addProgramHeaderTypes(self, programHeaderTypeMap: collections.abc.Mapping):
        """
        Add all extension specific Program Header types (e.g., PT_ prefix).
        This method will add all those statically defined ElfProgramHeaderType fields
        within this class.
        
        :param collections.abc.Mapping programHeaderTypeMap: map to which ElfProgramHeaderType definitions should be added
        """

    def addSectionHeaderTypes(self, sectionHeaderTypeMap: java.util.HashMap[java.lang.Integer, ghidra.app.util.bin.format.elf.ElfSectionHeaderType]):
        """
        Add all extension specific Section Header types (e.g., SHT_ prefix).
        This method will add all those statically defined ElfSectionHeaderType fields
        within this class.
        
        :param java.util.HashMap[java.lang.Integer, ghidra.app.util.bin.format.elf.ElfSectionHeaderType] sectionHeaderTypeMap: map to which ElfSectionHeaderType definitions should be added
        """

    def calculateSymbolAddress(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, elfSymbol: ghidra.app.util.bin.format.elf.ElfSymbol) -> ghidra.program.model.address.Address:
        """
        This method allows an extension to override the default address calculation for loading
        a symbol.  This is generally only neccessary when symbol requires handling of processor-specific 
        flags or section index.  This method should return null when default symbol processing 
        is sufficient. :obj:`Address.NO_ADDRESS` should be returned if the symbol is external
        and is not handled by default processing.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.app.util.bin.format.elf.ElfSymbol elfSymbol: elf symbol
        :return: symbol memory address or null to defer to default implementation
        :rtype: ghidra.program.model.address.Address
        :raises NoValueException: if error logged and address calculation failed
        """

    @typing.overload
    def canHandle(self, elf: ghidra.app.util.bin.format.elf.ElfHeader) -> bool:
        """
        Check if this extension can handle the specified elf header.  If this method returns 
        true, this extension will be used to obtain extended types definitions and to perform
        additional load processing.
        
        :param ghidra.app.util.bin.format.elf.ElfHeader elf: elf header
        :return: true if this extension should be used when loading the elf image which
        corresponds to the specified header.
        :rtype: bool
        """

    @typing.overload
    def canHandle(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper) -> bool:
        """
        Check if this extension can handle the specified elf image.  This method can provide
        a more accurate check based upon the actual language utilized.  While the ELF header
        may have stipulated a specific processor via the machine-id, a completely different
        and incompatible language may have been used.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: elf header
        :return: true if this extension can properly support the ELF header and the 
        current program/language.
        :rtype: bool
        """

    def creatingFunction(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, functionAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Prior to the ELF loader creating a function this method will be invoked to permit an 
        extension to adjust the address and/or apply context to the intended location.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.program.model.address.Address functionAddress: function address
        :return: adjusted function address (required)
        :rtype: ghidra.program.model.address.Address
        """

    def evaluateElfSymbol(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, elfSymbol: ghidra.app.util.bin.format.elf.ElfSymbol, address: ghidra.program.model.address.Address, isExternal: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        """
        During symbol processing this method will be invoked to permit an extension to
        adjust the address and/or apply context to the intended symbol location.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.app.util.bin.format.elf.ElfSymbol elfSymbol: elf symbol
        :param ghidra.program.model.address.Address address: program memory address where symbol will be created.
        :param jpype.JBoolean or bool isExternal: true if symbol treated as external to the program and has been
        assigned a fake memory address in the EXTERNAL memory block.
        :return: adjusted symbol address or null if extension will handle applying the elfSymbol
        to the program (must also invoke :meth:`ElfLoadHelper.setElfSymbolAddress(ElfSymbol, Address) <ElfLoadHelper.setElfSymbolAddress>`,
        or symbol should not be applied.
        :rtype: ghidra.program.model.address.Address
        """

    def getAdjustedLoadSize(self, elfProgramHeader: ghidra.app.util.bin.format.elf.ElfProgramHeader) -> int:
        """
        Return the memory bytes to be loaded from the underlying file for the specified program header.
        The returned value will be consistent with any byte filtering which may be required.
        
        :param ghidra.app.util.bin.format.elf.ElfProgramHeader elfProgramHeader: 
        :return: preferred memory block size in bytes which corresponds to the specified program header
        :rtype: int
        """

    def getAdjustedMemoryOffset(self, elfOffset: typing.Union[jpype.JLong, int], space: ghidra.program.model.address.AddressSpace) -> int:
        """
        Perform any required offset adjustment to account for differences between offset 
        values contained within ELF headers and the language modeling of the 
        associated address space.
         
        
        WARNING: This is an experimental method and is not yet fully supported.
         
        
        NOTE: This has currently been utilized for symbol address offset adjustment only.
        
        :param jpype.JLong or int elfOffset: memory offset from ELF header
        :param ghidra.program.model.address.AddressSpace space: associated address space
        :return: offset appropriate for use in space (does not account for image base alterations)
        :rtype: int
        """

    def getAdjustedMemorySize(self, elfProgramHeader: ghidra.app.util.bin.format.elf.ElfProgramHeader) -> int:
        """
        Return the memory segment size in bytes for the specified program header.
        The returned value will be consistent with any byte filtering which may be required.
        
        :param ghidra.app.util.bin.format.elf.ElfProgramHeader elfProgramHeader: 
        :return: preferred memory block size in bytes which corresponds to the specified program header
        :rtype: int
        """

    def getAdjustedSize(self, section: ghidra.app.util.bin.format.elf.ElfSectionHeader) -> int:
        """
        Returns the memory section size in bytes for the specified section header.
         
        
        The returned value will be consistent with any byte filtering and decompression which 
        may be required.
         
        
        The default implementation returns the section's 
        :meth:`logical size <ElfSectionHeader.getLogicalSize>`
        
        :param ghidra.app.util.bin.format.elf.ElfSectionHeader section: the section header
        :return: preferred memory block size in bytes which corresponds to the specified section header
        :rtype: int
        """

    def getDataTypeSuffix(self) -> str:
        """
        Return the data type naming suffix which should be used when creating types derived 
        from data supplied by this extension.
        
        :return: type naming suffix or null
        :rtype: str
        """

    def getDefaultAlignment(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper) -> int:
        """
        Get the default alignment within the default address space.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: helper object
        :return: default alignment within the default address space.
        :rtype: int
        """

    def getDefaultImageBase(self, elfHeader: ghidra.app.util.bin.format.elf.ElfHeader) -> int:
        """
        Get the default image base to be used when one cannot be determined.
        
        :param ghidra.app.util.bin.format.elf.ElfHeader elfHeader: ELF header
        :return: default image base
        :rtype: int
        """

    def getExternalBlockReserveSize(self) -> int:
        """
        Get reserve size of the EXTERNAL memory block as addressable units
        within the default memory space.  This size represents the largest 
        expansion size to the block which could occur during relocation
        processing.
        
        :return: reserve size of the EXTERNAL memory block as addressable units
        :rtype: int
        """

    def getFilteredLoadInputStream(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, loadable: ghidra.app.util.bin.format.MemoryLoadable, start: ghidra.program.model.address.Address, dataLength: typing.Union[jpype.JLong, int], dataInput: java.io.InputStream) -> java.io.InputStream:
        """
        Return filtered InputStream for loading a memory block (includes non-loaded OTHER blocks).
        NOTE: If this method is overriden, the :meth:`hasFilteredLoadInputStream(ElfLoadHelper, MemoryLoadable, Address) <.hasFilteredLoadInputStream>`
        must also be overriden in a consistent fashion.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: 
        :param ghidra.app.util.bin.format.MemoryLoadable loadable: Corresponding ElfSectionHeader or ElfProgramHeader for the memory block to be created.
        :param ghidra.program.model.address.Address start: memory load address
        :param jpype.JLong or int dataLength: the in-memory data length in bytes (actual bytes read from dataInput may be more)
        :param java.io.InputStream dataInput: the source input stream
        :return: filtered input stream or original input stream
        :rtype: java.io.InputStream
        :raises IOException: if error initializing filtered stream
        """

    def getLinkageBlockAlignment(self) -> int:
        """
        Get the dynamic memory block allocation alignment as addressable units
        within the default memory space.
        
        :return: dynamic memory block allocation alignment.
        :rtype: int
        """

    def getPreferredExternalBlockSize(self) -> int:
        """
        Get the preferred free range size for the EXTERNAL memory block as addressable units
        within the default memory space.
        
        :return: minimum free range size for EXTERNAL memory block as addressable units
        :rtype: int
        """

    def getPreferredSectionAddress(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, elfSectionHeader: ghidra.app.util.bin.format.elf.ElfSectionHeader) -> ghidra.program.model.address.Address:
        """
        Get the preferred load address for an allocated program section.  
        This method may only return a physical address and not an overlay 
        address.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.app.util.bin.format.elf.ElfSectionHeader elfSectionHeader: elf program section header
        :return: preferred load address
        :rtype: ghidra.program.model.address.Address
        """

    def getPreferredSectionAddressSpace(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, elfSectionHeader: ghidra.app.util.bin.format.elf.ElfSectionHeader) -> ghidra.program.model.address.AddressSpace:
        """
        Get the preferred load address space for an allocated section.   The OTHER space
        is reserved and should not be returned by this method.
        This method may only return a physical address space and not an overlay 
        address space.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.app.util.bin.format.elf.ElfSectionHeader elfSectionHeader: elf section header
        :return: preferred load address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getPreferredSegmentAddress(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, elfProgramHeader: ghidra.app.util.bin.format.elf.ElfProgramHeader) -> ghidra.program.model.address.Address:
        """
        Get the preferred load address for a program segment.
        This method may only return a physical address and not an overlay 
        address.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.app.util.bin.format.elf.ElfProgramHeader elfProgramHeader: elf program segment header
        :return: preferred load address
        :rtype: ghidra.program.model.address.Address
        """

    def getPreferredSegmentAddressSpace(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, elfProgramHeader: ghidra.app.util.bin.format.elf.ElfProgramHeader) -> ghidra.program.model.address.AddressSpace:
        """
        Get the preferred load address space for an allocated program segment.
        The OTHER space is reserved and should not be returned by this method.
        This method may only return a physical address space and not an overlay 
        address space.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.app.util.bin.format.elf.ElfProgramHeader elfProgramHeader: elf program segment header
        :return: preferred load address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getRelocationClass(self, elfHeader: ghidra.app.util.bin.format.elf.ElfHeader) -> java.lang.Class[ghidra.app.util.bin.format.elf.ElfRelocation]:
        """
        Get the ElfRelocation class which should be used to properly parse
        the relocation tables.
        
        :param ghidra.app.util.bin.format.elf.ElfHeader elfHeader: ELF header object (for header field access only)
        :return: ElfRelocation class or null for default behavior
        :rtype: java.lang.Class[ghidra.app.util.bin.format.elf.ElfRelocation]
        """

    def getSectionSymbolRelativeOffset(self, section: ghidra.app.util.bin.format.elf.ElfSectionHeader, sectionBase: ghidra.program.model.address.Address, elfSymbol: ghidra.app.util.bin.format.elf.ElfSymbol) -> int:
        """
        Get the section-relative offset for the specified ELF symbol which is bound to
        the specified section.  If the symbol has an absolute symbol value/offset this method
        should return null.
         
        
        For Harvard Architectures it may be necessary to adjust offset if section was mapped
        to a non-default data space.
         
        
        The default behavior is to return :meth:`ElfSymbol.getValue() <ElfSymbol.getValue>` if :meth:`ElfHeader.isRelocatable() <ElfHeader.isRelocatable>`
        is true.
        
        :param ghidra.app.util.bin.format.elf.ElfSectionHeader section: ELF section header which is specified by the ELF symbol
        :param ghidra.program.model.address.Address sectionBase: memory address where section has been loaded.  Could be within overlay
        space if load conflict occured.
        :param ghidra.app.util.bin.format.elf.ElfSymbol elfSymbol: ELF symbol
        :return: section relative symbol offset or null if symbol value offset is absolute
        :rtype: int
        """

    def hasFilteredLoadInputStream(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, loadable: ghidra.app.util.bin.format.MemoryLoadable, start: ghidra.program.model.address.Address) -> bool:
        """
        Determine if the use of :meth:`getFilteredLoadInputStream(ElfLoadHelper, MemoryLoadable, Address, long, InputStream) <.getFilteredLoadInputStream>` 
        is required when loading a memory block.  If a filtered input stream is required this will prevent the use of a direct 
        mapping to file bytes.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: 
        :param ghidra.app.util.bin.format.MemoryLoadable loadable: Corresponding ElfSectionHeader or ElfProgramHeader for the memory block to be loaded.
        :param ghidra.program.model.address.Address start: memory load address
        :return: true if the use of a filtered input stream is required
        :rtype: bool
        """

    def isSectionAllocated(self, section: ghidra.app.util.bin.format.elf.ElfSectionHeader) -> bool:
        """
        Determine if the specified section is "allocated" within memory.
        
        :param ghidra.app.util.bin.format.elf.ElfSectionHeader section: section header object
        :return: true if section should be allocated, else false or null to use standard Elf section
        flags to make the determination.
        :rtype: bool
        """

    def isSectionExecutable(self, section: ghidra.app.util.bin.format.elf.ElfSectionHeader) -> bool:
        """
        Get the execute permission for the specified section (i.e., instructions permitted).
        
        :param ghidra.app.util.bin.format.elf.ElfSectionHeader section: section header object
        :return: true if execute enabled, else false or null to use standard Elf section
        flags to make the determination.
        :rtype: bool
        """

    def isSectionWritable(self, section: ghidra.app.util.bin.format.elf.ElfSectionHeader) -> bool:
        """
        Get the write permission for the specified section.
        
        :param ghidra.app.util.bin.format.elf.ElfSectionHeader section: section header object
        :return: true if write enabled, else false or null to use standard Elf section
        flags to make the determination.
        :rtype: bool
        """

    def isSegmentExecutable(self, segment: ghidra.app.util.bin.format.elf.ElfProgramHeader) -> bool:
        """
        Get the execute permission for the specified segment.
        
        :param ghidra.app.util.bin.format.elf.ElfProgramHeader segment: program header object
        :return: true if execute enabled, else false or null to use standard Elf program header
        flags to make the determination.
        :rtype: bool
        """

    def isSegmentReadable(self, segment: ghidra.app.util.bin.format.elf.ElfProgramHeader) -> bool:
        """
        Get the read permission for the specified segment.
        
        :param ghidra.app.util.bin.format.elf.ElfProgramHeader segment: program header object
        :return: true if read enabled, else false or null to use standard Elf program header
        flags to make the determination.
        :rtype: bool
        """

    def isSegmentWritable(self, segment: ghidra.app.util.bin.format.elf.ElfProgramHeader) -> bool:
        """
        Get the write permission for the specified segment.
        
        :param ghidra.app.util.bin.format.elf.ElfProgramHeader segment: program header object
        :return: true if write enabled, else false or null to use standard Elf program header
        flags to make the determination.
        :rtype: bool
        """

    def processElf(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform extension specific processing of Elf image during program load.
        The following loading steps will have already been completed:
         
        1. default processing of all program headers and section headers
        2. memory resolution and loading of all program headers and section headers
        3. Markup completed of Elf header, program headers, section headers, dynamic table,
            string tables, and symbol tables.
         
        Markup and application of relocation tables will NOT have been done yet.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException:
        """

    def processGotPlt(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform extension specific processing of Elf GOT/PLT tables and any other 
        related function relocation mechanism (e.g., function descriptors, etc) after
        normal REL/RELA relocation fix-ups have been applied.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: load helper object
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException:
        """

    @property
    def segmentReadable(self) -> jpype.JBoolean:
        ...

    @property
    def relocationClass(self) -> java.lang.Class[ghidra.app.util.bin.format.elf.ElfRelocation]:
        ...

    @property
    def adjustedLoadSize(self) -> jpype.JLong:
        ...

    @property
    def dataTypeSuffix(self) -> java.lang.String:
        ...

    @property
    def externalBlockReserveSize(self) -> jpype.JInt:
        ...

    @property
    def adjustedMemorySize(self) -> jpype.JLong:
        ...

    @property
    def segmentWritable(self) -> jpype.JBoolean:
        ...

    @property
    def segmentExecutable(self) -> jpype.JBoolean:
        ...

    @property
    def preferredExternalBlockSize(self) -> jpype.JInt:
        ...

    @property
    def defaultAlignment(self) -> jpype.JInt:
        ...

    @property
    def sectionWritable(self) -> jpype.JBoolean:
        ...

    @property
    def sectionAllocated(self) -> jpype.JBoolean:
        ...

    @property
    def sectionExecutable(self) -> jpype.JBoolean:
        ...

    @property
    def linkageBlockAlignment(self) -> jpype.JInt:
        ...

    @property
    def adjustedSize(self) -> jpype.JLong:
        ...

    @property
    def defaultImageBase(self) -> jpype.JLong:
        ...


class ElfExtension(ElfLoadAdapter, ghidra.util.classfinder.ExtensionPoint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ElfExtensionFactory", "ElfLoadAdapter", "ElfExtension"]
