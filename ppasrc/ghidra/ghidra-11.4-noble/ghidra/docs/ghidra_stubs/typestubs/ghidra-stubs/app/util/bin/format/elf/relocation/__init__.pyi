from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin.format.elf
import ghidra.app.util.bin.format.elf.extend
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.reloc
import ghidra.util.classfinder
import java.lang # type: ignore
import java.util # type: ignore


C = typing.TypeVar("C")
H = typing.TypeVar("H")
T = typing.TypeVar("T")


class ElfRelocationContext(java.lang.Object, typing.Generic[H]):
    """
    ``ElfRelocationContext`` provides a relocation handler context related
    to the processing of entries contained within a specific relocation table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Dispose relocation context when processing of corresponding relocation table is complete.
        Instance should be disposed to allow all program changes to be flushed prior to processing
        a subsequent relocation table.
        """

    def endRelocationTableProcessing(self):
        """
        Invoked at end of relocation processing for current relocation table.
        See :meth:`startRelocationTableProcessing(ElfRelocationTable) <.startRelocationTableProcessing>`.
        """

    def extractAddend(self) -> bool:
        """
        Determine if addend data must be extracted
        
        :return: true if relocation does not provide addend data and it must be
        extracted from relocation target if appropriate
        :rtype: bool
        """

    def getElfHeader(self) -> ghidra.app.util.bin.format.elf.ElfHeader:
        ...

    def getGOTValue(self) -> int:
        """
        Returns the appropriate .got section using the
        DT_PLTGOT value defined in the .dynamic section.
        If no such dynamic value defined, the symbol offset for _GLOBAL_OFFSET_TABLE_
        will be used, otherwise a NotFoundException will be thrown.
        
        :return: the .got section address offset
        :rtype: int
        :raises NotFoundException: if the dynamic DT_PLTGOT not defined and 
        _GLOBAL_OFFSET_TABLE_ symbol not defined
        """

    def getImageBaseWordAdjustmentOffset(self) -> int:
        """
        Get image base addressable word adjustment value to be applied to any pre-linked address values
        such as those contained with the dynamic table. (Applies to default address space only)
        
        :return: image base adjustment value
        :rtype: int
        """

    def getLoadAdapter(self) -> ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter:
        ...

    def getLoadHelper(self) -> ghidra.app.util.bin.format.elf.ElfLoadHelper:
        ...

    def getLog(self) -> ghidra.app.util.importer.MessageLog:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getRelocationAddress(self, baseAddress: ghidra.program.model.address.Address, relocOffset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get relocation address
        
        :param ghidra.program.model.address.Address baseAddress: base address
        :param jpype.JLong or int relocOffset: relocation offset relative to baseAddress
        :return: relocation address
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getRelocationContext(loadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, symbolMap: collections.abc.Mapping) -> ElfRelocationContext[typing.Any]:
        """
        Get a relocation context for a specfic Elf image and relocation table
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper loadHelper: Elf load helper
        :param collections.abc.Mapping symbolMap: Elf symbol placement map
        :return: relocation context object.  A generic context will be returned if a custom one
        is not defined.
        :rtype: ElfRelocationContext[typing.Any]
        """

    def getRelrRelocationType(self) -> int:
        """
        Get the RELR relocation type associated with the underlying
        relocation handler.
        
        :return: RELR relocation type or 0 if not supported
        :rtype: int
        """

    def getSymbol(self, symbolIndex: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.format.elf.ElfSymbol:
        """
        Get the Elf symbol which corresponds to the specified index.  Each relocation table
        may correspond to a specific symbol table to which the specified symbolIndex will be
        applied.  In the absense of a corresponding symbol table index 0 will return a special 
        null symbol.
        
        :param jpype.JInt or int symbolIndex: symbol index
        :return: Elf symbol which corresponds to symbol index or **null** if out of range
        :rtype: ghidra.app.util.bin.format.elf.ElfSymbol
        """

    def getSymbolAddress(self, symbol: ghidra.app.util.bin.format.elf.ElfSymbol) -> ghidra.program.model.address.Address:
        """
        Get the program address at which the specified Elf symbol was placed.
        
        :param ghidra.app.util.bin.format.elf.ElfSymbol symbol: Elf symbol
        :return: program address
        :rtype: ghidra.program.model.address.Address
        """

    def getSymbolName(self, symbolIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the ELF symbol name which corresponds to the specified index.
        
        :param jpype.JInt or int symbolIndex: symbol index
        :return: symbol name which corresponds to symbol index or null if out of range
        :rtype: str
        """

    def getSymbolValue(self, symbol: ghidra.app.util.bin.format.elf.ElfSymbol) -> int:
        """
        Get the adjusted symbol value based upon its placement within the program.
        This value may differ from symbol.getValue() and will reflect the addressable
        unit/word offset of it program address.
        
        :param ghidra.app.util.bin.format.elf.ElfSymbol symbol: Elf symbol
        :return: adjusted Elf symbol value or 0 if symbol mapping not found
        :rtype: int
        """

    def hasRelocationHandler(self) -> bool:
        """
        
        
        :return: true if a relocation handler was found
        :rtype: bool
        """

    def isBigEndian(self) -> bool:
        ...

    def markRelocationError(self, relocationAddress: ghidra.program.model.address.Address, typeId: typing.Union[jpype.JInt, int], symbolIndex: typing.Union[jpype.JInt, int], symbolName: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str]):
        """
        Generate relocation error log entry and bookmark.
        
        :param ghidra.program.model.address.Address relocationAddress: relocation address
        :param jpype.JInt or int typeId: relocation type ID value (will get mapped to :meth:`ElfRelocationType.name() <ElfRelocationType.name>`
        if possible).
        :param jpype.JInt or int symbolIndex: associated symbol index within symbol table (-1 to ignore)
        :param java.lang.String or str symbolName: relocation symbol name or null if unknown
        :param java.lang.String or str msg: error message
        """

    def processRelocation(self, relocation: ghidra.app.util.bin.format.elf.ElfRelocation, relocationAddress: ghidra.program.model.address.Address) -> ghidra.program.model.reloc.RelocationResult:
        """
        Process a relocation from the relocation table which corresponds to this context.
        All relocation entries will be processed in the order they appear within the table.
        
        :param ghidra.app.util.bin.format.elf.ElfRelocation relocation: relocation to be processed
        :param ghidra.program.model.address.Address relocationAddress: relocation address where it should be applied
        :return: applied relocation result
        :rtype: ghidra.program.model.reloc.RelocationResult
        """

    def startRelocationTableProcessing(self, relocTable: ghidra.app.util.bin.format.elf.ElfRelocationTable):
        """
        Invoked at start of relocation processing for specified table.
        The method :meth:`endRelocationTableProcessing() <.endRelocationTableProcessing>` will be invoked after last relocation
        is processed.
        
        :param ghidra.app.util.bin.format.elf.ElfRelocationTable relocTable: relocation table
        """

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def symbol(self) -> ghidra.app.util.bin.format.elf.ElfSymbol:
        ...

    @property
    def imageBaseWordAdjustmentOffset(self) -> jpype.JLong:
        ...

    @property
    def loadHelper(self) -> ghidra.app.util.bin.format.elf.ElfLoadHelper:
        ...

    @property
    def gOTValue(self) -> jpype.JLong:
        ...

    @property
    def log(self) -> ghidra.app.util.importer.MessageLog:
        ...

    @property
    def loadAdapter(self) -> ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter:
        ...

    @property
    def relrRelocationType(self) -> jpype.JInt:
        ...

    @property
    def symbolAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def symbolValue(self) -> jpype.JLong:
        ...

    @property
    def elfHeader(self) -> ghidra.app.util.bin.format.elf.ElfHeader:
        ...

    @property
    def symbolName(self) -> java.lang.String:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ElfRelocationType(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def name(self) -> str:
        """
        Get the name of this relocation type (i.e., enum name)
        
        :return: name of this relocation type
        :rtype: str
        """

    def typeId(self) -> int:
        """
        Get the value associated with this relocation type.
        
        :return: relocation type value.
        :rtype: int
        """


class ElfRelocationHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE: ELF relocation handler implementations should extend :obj:`AbstractElfRelocationHandler` 
    which now uses :obj:`ElfRelocationType` enum values instead of simple constants.  This class may 
    transition to an interface in the future.  This abstract class remains exposed for backward 
    compatibility with older implementations.
     
    
    ``ElfRelocationHandler`` provides the base class for processor specific
    ELF relocation handlers.  Implementations may only specify a public default constructor
    as they will be identified and instatiated by the :obj:`ClassSearcher`.  As such their
    name must end with "ElfRelocationHandler" (e.g., MyProc_ElfRelocationHandler).
    """

    class_: typing.ClassVar[java.lang.Class]
    GOT_BLOCK_NAME: typing.Final = "%got"
    """
    Fabricated Global Offset Table (GOT) name/prefix to be used when processing an object module
    and a GOT must be fabricated to allow relocation processing.
    """


    @staticmethod
    def applyComponentOffsetPointer(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentOffset: typing.Union[jpype.JLong, int]):
        """
        Apply a pointer-typedef with a specified component-offset if specified address
        is not contained within an execute block.
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address addr: address where data should be applied
        :param jpype.JLong or int componentOffset: component offset
        """

    @staticmethod
    def bookmarkNoHandlerError(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, typeId: typing.Union[jpype.JInt, int], symbolIndex: typing.Union[jpype.JInt, int], symbolName: typing.Union[java.lang.String, str]):
        """
        Generate error bookmark at relocationAddress indicating a missing relocation handler.
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked
        :param jpype.JInt or int typeId: relocation type ID value
        :param jpype.JInt or int symbolIndex: associated symbol index within symbol table (-1 to ignore)
        :param java.lang.String or str symbolName: associated symbol name
        """

    @staticmethod
    def bookmarkUnsupportedRelr(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, symbolIndex: typing.Union[jpype.JInt, int], symbolName: typing.Union[java.lang.String, str]):
        """
        Generate error bookmark at relocationAddress indicating an unsupported RELR relocation.
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked
        :param jpype.JInt or int symbolIndex: associated symbol index within symbol table (-1 to ignore)
        :param java.lang.String or str symbolName: associated symbol name
        """

    def canRelocate(self, elf: ghidra.app.util.bin.format.elf.ElfHeader) -> bool:
        ...

    def getRelrRelocationType(self) -> int:
        """
        Get the architecture-specific relative relocation type which should be applied to 
        RELR relocations.  The default implementation returns 0 which indicates RELR is unsupported.
        
        :return: RELR relocation type ID value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def markAsError(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, typeId: typing.Union[jpype.JInt, int], symbolIndex: typing.Union[jpype.JInt, int], symbolName: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str], log: ghidra.app.util.importer.MessageLog):
        """
        Generate error log entry and bookmark at relocationAddress
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked
        :param jpype.JInt or int typeId: relocation type
        :param jpype.JInt or int symbolIndex: associated symbol index within symbol table (-1 to ignore)
        :param java.lang.String or str symbolName: associated symbol name
        :param java.lang.String or str msg: error messge
        :param ghidra.app.util.importer.MessageLog log: import log
        """

    @staticmethod
    @typing.overload
    def markAsError(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, typeId: typing.Union[jpype.JLong, int], symbolName: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str], log: ghidra.app.util.importer.MessageLog):
        """
        Generate error log entry and bookmark at relocationAddress
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked
        :param jpype.JLong or int typeId: relocation type ID value
        :param java.lang.String or str symbolName: associated symbol name
        :param java.lang.String or str msg: error messge
        :param ghidra.app.util.importer.MessageLog log: import log
        """

    @staticmethod
    @typing.overload
    def markAsError(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str], symbolName: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str], log: ghidra.app.util.importer.MessageLog):
        """
        Generate error log entry and bookmark at relocationAddress
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked
        :param java.lang.String or str type: relocation type ID name
        :param java.lang.String or str symbolName: associated symbol name
        :param java.lang.String or str msg: additional error message
        :param ghidra.app.util.importer.MessageLog log: import log
        """

    @staticmethod
    def markAsUnhandled(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, typeId: typing.Union[jpype.JLong, int], symbolIndex: typing.Union[jpype.JLong, int], symbolName: typing.Union[java.lang.String, str], log: ghidra.app.util.importer.MessageLog):
        """
        Generate error log entry and bookmark at relocationAddress indicating 
        an unhandled relocation.
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked
        :param jpype.JLong or int typeId: relocation type ID value (limited to int value).
        :param jpype.JLong or int symbolIndex: associated symbol index within symbol table (limited to int value).
        :param java.lang.String or str symbolName: associated symbol name
        :param ghidra.app.util.importer.MessageLog log: import log
        """

    @staticmethod
    @typing.overload
    def markAsWarning(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str], log: ghidra.app.util.importer.MessageLog):
        """
        Generate warning log entry and bookmark at relocationAddress
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked
        :param java.lang.String or str type: relocation type ID name
        :param java.lang.String or str msg: message associated with warning
        :param ghidra.app.util.importer.MessageLog log: import log
        """

    @staticmethod
    @typing.overload
    def markAsWarning(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str], symbolName: typing.Union[java.lang.String, str], symbolIndex: typing.Union[jpype.JInt, int], msg: typing.Union[java.lang.String, str], log: ghidra.app.util.importer.MessageLog):
        """
        Generate warning log entry and bookmark at relocationAddress
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked
        :param java.lang.String or str type: relocation type ID name
        :param java.lang.String or str symbolName: symbol name
        :param jpype.JInt or int symbolIndex: symbol index (-1 to ignore)
        :param java.lang.String or str msg: message associated with warning
        :param ghidra.app.util.importer.MessageLog log: import log
        """

    @staticmethod
    def warnExternalOffsetRelocation(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, symbolAddr: ghidra.program.model.address.Address, symbolName: typing.Union[java.lang.String, str], adjustment: typing.Union[jpype.JLong, int], log: ghidra.app.util.importer.MessageLog):
        """
        Determine if symbolAddr is contained within the EXTERNAL block with a non-zero adjustment.  
        If so, relocationAddress will be marked with a ``EXTERNAL Data Elf Relocation with pointer-offset`` 
        warning or error bookmark.  Bookmark and logged message will be conveyed as an error if 
        relocationAddress resides within an executable memory block.
         
        
        NOTE: This method should only be invoked when the symbol offset will be adjusted with a non-zero 
        value (i.e., addend).
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address relocationAddress: relocation address to be bookmarked if EXTERNAL block relocation
        :param ghidra.program.model.address.Address symbolAddr: symbol address correspondng to relocation (may be null)
        :param java.lang.String or str symbolName: symbol name (may not be null if symbolAddr is not null)
        :param jpype.JLong or int adjustment: relocation symbol offset adjustment/addend
        :param ghidra.app.util.importer.MessageLog log: import log
        """

    @property
    def relrRelocationType(self) -> jpype.JInt:
        ...


class ElfRelocationHandlerFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getHandler(elf: ghidra.app.util.bin.format.elf.ElfHeader) -> ElfRelocationHandler:
        ...

    @staticmethod
    def getHandlers() -> java.util.List[ElfRelocationHandler]:
        ...


class AbstractElfRelocationHandler(ElfRelocationHandler, typing.Generic[T, C]):
    """
    ``ElfRelocationHandler`` provides the base class for processor specific
    ELF relocation handlers.  Implementations may only specify a public default constructor
    as they will be identified and instatiated by the :obj:`ClassSearcher`.  As such their
    name must end with "ElfRelocationHandler" (e.g., MyProc_ElfRelocationHandler).
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRelocationType(self, typeId: typing.Union[jpype.JInt, int]) -> T:
        """
        Get the relocation type enum object which corresponds to the specified type ID value.
        
        :param jpype.JInt or int typeId: relocation type ID value
        :return: relocation type enum value or null if type not found or this handler was not
        constructed with a :obj:`ElfRelocationType` enum class.  The returned value may be
        safely cast to the relocation enum class specified during handler construction.
        :rtype: T
        """

    @property
    def relocationType(self) -> T:
        ...



__all__ = ["ElfRelocationContext", "ElfRelocationType", "ElfRelocationHandler", "ElfRelocationHandlerFactory", "AbstractElfRelocationHandler"]
