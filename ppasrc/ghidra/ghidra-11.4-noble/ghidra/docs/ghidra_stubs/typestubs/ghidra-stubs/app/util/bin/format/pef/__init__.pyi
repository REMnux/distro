from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class LoaderInfoHeader(ghidra.app.util.bin.StructConverter):
    """
    See Apple's -- PEFBinaryFormat.h
    struct PEFLoaderInfoHeader {    SInt32  mainSection;              // Section containing the main symbol, -1 => none.    UInt32  mainOffset;               // Offset of main symbol.    SInt32  initSection;              // Section containing the init routine's TVector, -1 => none.    UInt32  initOffset;               // Offset of the init routine's TVector.    SInt32  termSection;              // Section containing the term routine's TVector, -1 => none.    UInt32  termOffset;               // Offset of the term routine's TVector.    UInt32  importedLibraryCount;     // Number of imported libraries.  ('l')    UInt32  totalImportedSymbolCount; // Total number of imported symbols.  ('i')    UInt32  relocSectionCount;        // Number of sections with relocations.  ('r')    UInt32  relocInstrOffset;         // Offset of the relocation instructions.    UInt32  loaderStringsOffset;      // Offset of the loader string table.    UInt32  exportHashOffset;         // Offset of the export hash table.    UInt32  exportHashTablePower;     // Export hash table size as log 2.  (Log2('h'))    UInt32  exportedSymbolCount;      // Number of exported symbols.  ('e')};
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 56

    def findLibrary(self, symbolIndex: typing.Union[jpype.JInt, int]) -> ImportedLibrary:
        """
        Finds the PEF library that contains the specified imported symbol index.
        
        :param jpype.JInt or int symbolIndex: the imported symbol index
        :return: PEF library that contains the specified imported symbol index
        :rtype: ImportedLibrary
        """

    def getExportHashOffset(self) -> int:
        """
        The exportHashOffset field (4 bytes) indicates the offset 
        (in bytes) from the beginning of the loader section 
        to the start of the export hash table. The hash table should be 4-byte aligned 
        with padding added if necessary.
        
        :return: offset to the export hash table
        :rtype: int
        """

    def getExportHashTablePower(self) -> int:
        """
        The exportHashTablePower field (4 bytes) indicates the 
        number of hash index values (that is, the number of entries in the 
        hash table). The number of entries is specified as a power of two. For example, 
        a value of 0 indicates one entry, while a value of 2 indicates four entries. If 
        no exports exist, the hash table still contains one entry, and the value of this 
        field is 0.
        
        :return: number of hash index values
        :rtype: int
        """

    def getExportedHashSlots(self) -> java.util.List[ExportedSymbolHashSlot]:
        ...

    def getExportedSymbolCount(self) -> int:
        """
        The exportedSymbolCount field (4 bytes) indicates the number of 
        symbols exported from this container.
        
        :return: number of symbols exported from this container
        :rtype: int
        """

    def getExportedSymbolKeys(self) -> java.util.List[ExportedSymbolKey]:
        ...

    def getExportedSymbols(self) -> java.util.List[ExportedSymbol]:
        ...

    def getImportedLibraries(self) -> java.util.List[ImportedLibrary]:
        ...

    def getImportedLibraryCount(self) -> int:
        """
        The importedLibraryCount field (4 bytes) indicates the 
        number of imported libraries.
        
        :return: number of imported libraries
        :rtype: int
        """

    def getImportedSymbols(self) -> java.util.List[ImportedSymbol]:
        ...

    def getInitOffset(self) -> int:
        """
        The initOffset field (4 bytes) indicates the offset (in bytes) from the 
        beginning of the section to the initialization function's transition vector.
        
        :return: offset to initialization function's transition vector
        :rtype: int
        """

    def getInitSection(self) -> int:
        """
        The initSection field (4 bytes) contains the number of the 
        section containing the initialization function's transition 
        vector. If no initialization function exists, this field is set to -1.
        
        :return: number of the section containing the initialization function's transition vector
        :rtype: int
        """

    def getLoaderStringsOffset(self) -> int:
        """
        The loaderStringsOffset field (4 bytes) indicates the offset 
        (in bytes) from the beginning of the loader 
        section to the start of the loader string table.
        
        :return: offset to the loader string table
        :rtype: int
        """

    def getMainOffset(self) -> int:
        """
        The mainOffset field (4 bytes) indicates the offset (in bytes) from the 
        beginning of the section to the main symbol.
        
        :return: offset to the main symbol
        :rtype: int
        """

    def getMainSection(self) -> int:
        """
        The mainSection field (4 bytes) specifies the number 
        of the section in this container that contains the main 
        symbol. If the fragment does not have a main symbol, 
        this field is set to -1.
        
        :return: number of section containing main symbol
        :rtype: int
        """

    def getRelocInstrOffset(self) -> int:
        """
        The relocInstrOffset field (4 bytes) indicates the offset (in bytes) from the 
        beginning of the loader section to the start of the relocations area.
        
        :return: offset to the relocations
        :rtype: int
        """

    def getRelocSectionCount(self) -> int:
        """
        The relocSectionCount field (4 bytes) indicates the 
        number of sections containing load-time relocations.
        
        :return: number of sections containing load-time relocations
        :rtype: int
        """

    def getRelocations(self) -> java.util.List[LoaderRelocationHeader]:
        ...

    def getSection(self) -> SectionHeader:
        """
        Returns the section corresponding to this loader.
        
        :return: the section corresponding to this loader
        :rtype: SectionHeader
        """

    def getTermOffset(self) -> int:
        """
        The termOffset field (4 bytes) indicates the offset 
        (in bytes) from the beginning of the section to the termination routine's 
        transition vector.
        
        :return: offset to termination routine's transition vector
        :rtype: int
        """

    def getTermSection(self) -> int:
        """
        The termSection field (4 bytes) contains the number of the section containing 
        the termination routine's transition vector. If no termination routine exists, 
        this field is set to -1.
        
        :return: number of the section containing the termination routine's transition vector
        :rtype: int
        """

    def getTotalImportedSymbolCount(self) -> int:
        """
        The totalImportedSymbolCount field (4 bytes) 
        indicates the total number of imported symbols.
        
        :return: number of imported symbols
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def totalImportedSymbolCount(self) -> jpype.JInt:
        ...

    @property
    def mainSection(self) -> jpype.JInt:
        ...

    @property
    def importedLibraries(self) -> java.util.List[ImportedLibrary]:
        ...

    @property
    def exportedSymbolKeys(self) -> java.util.List[ExportedSymbolKey]:
        ...

    @property
    def termSection(self) -> jpype.JInt:
        ...

    @property
    def exportHashTablePower(self) -> jpype.JInt:
        ...

    @property
    def initSection(self) -> jpype.JInt:
        ...

    @property
    def exportedSymbolCount(self) -> jpype.JInt:
        ...

    @property
    def exportHashOffset(self) -> jpype.JInt:
        ...

    @property
    def section(self) -> SectionHeader:
        ...

    @property
    def exportedSymbols(self) -> java.util.List[ExportedSymbol]:
        ...

    @property
    def relocSectionCount(self) -> jpype.JInt:
        ...

    @property
    def loaderStringsOffset(self) -> jpype.JInt:
        ...

    @property
    def termOffset(self) -> jpype.JInt:
        ...

    @property
    def initOffset(self) -> jpype.JInt:
        ...

    @property
    def mainOffset(self) -> jpype.JInt:
        ...

    @property
    def importedLibraryCount(self) -> jpype.JInt:
        ...

    @property
    def relocInstrOffset(self) -> jpype.JInt:
        ...

    @property
    def relocations(self) -> java.util.List[LoaderRelocationHeader]:
        ...

    @property
    def exportedHashSlots(self) -> java.util.List[ExportedSymbolHashSlot]:
        ...

    @property
    def importedSymbols(self) -> java.util.List[ImportedSymbol]:
        ...


class ImportedLibrary(ghidra.app.util.bin.StructConverter):
    """
    Imported Libraries
     
    See Apple's -- PEFBinaryFormat.h
     
    struct PEFImportedLibrary {
    UInt32              nameOffset;             // Loader string table offset of library's name.
    UInt32              oldImpVersion;          // Oldest compatible implementation version.
    UInt32              currentVersion;         // Current version at build time.
    UInt32              importedSymbolCount;    // Imported symbol count for this library.
    UInt32              firstImportedSymbol;    // Index of first imported symbol from this library.
    UInt8               options;                // Option bits for this library.
    UInt8               reservedA;              // Reserved, must be zero.
    UInt16              reservedB;              // Reserved, must be zero.
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 24
    OPTION_kPEFWeakImportLibMask: typing.Final = 64
    """
    The imported library is allowed to be missing.
    """

    OPTION_kPEFInitLibBeforeMask: typing.Final = 128
    """
    The imported library must be initialized first.
    """


    def getCurrentVersion(self) -> int:
        """
        The oldImpVersion and currentVersion fields (4 bytes each) provide version 
        information for checking the compatibility of the imported library.
        
        :return: current version at build time
        :rtype: int
        """

    def getFirstImportedSymbol(self) -> int:
        """
        The firstImportedSymbol field (4 bytes) holds the (zero-based) index of the 
        first entry in the imported symbol table for this library.
        
        :return: index of first imported symbol from this library
        :rtype: int
        """

    def getImportedSymbolCount(self) -> int:
        """
        The importedSymbolCount field (4 bytes) indicates the number of symbols 
        imported from this library.
        
        :return: imported symbol count for this library
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of the library being imported.
        
        :return: the name of the library being imported
        :rtype: str
        """

    def getNameOffset(self) -> int:
        """
        The nameOffset field (4 bytes) indicates the offset (in bytes) from the beginning 
        of the loader string table to the start of the null-terminated library name.
        
        :return: loader string table offset of library's name.
        :rtype: int
        """

    def getOldImpVersion(self) -> int:
        """
        The oldImpVersion and currentVersion fields (4 bytes each) provide version 
        information for checking the compatibility of the imported library.
        
        :return: oldest compatible implementation version
        :rtype: int
        """

    def getOptions(self) -> int:
        """
        The options byte contains bit flag information as follows:
         
        
        The high-order bit (mask 0x80) controls the order that the import libraries 
        are initialized. If set to 0, the default initialization order is used, which 
        specifies that the Code Fragment Manager should try to initialize the 
        import library before the fragment that imports it. When set to 1, the import 
        library must be initialized before the client fragment.
         
        
        The next bit (mask 0x40) controls whether the import library is weak. 
        When set to 1 (weak import), the Code Fragment Manager continues 
        preparation of the client fragment (and does not generate an error) even if 
        the import library cannot be found. If the import library is not found, all 
        imported symbols from that library have their addresses set to 0. You can 
        use this information to determine whether a weak import library is actually 
        present.
        
        :return: option bits for this library
        :rtype: int
        """

    def getReservedA(self) -> int:
        """
        Reserved, must be set to zero (0).
        
        :return: reserved, must be set to zero (0)
        :rtype: int
        """

    def getReservedB(self) -> int:
        """
        Reserved, must be set to zero (0).
        
        :return: reserved, must be set to zero (0)
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def nameOffset(self) -> jpype.JInt:
        ...

    @property
    def importedSymbolCount(self) -> jpype.JInt:
        ...

    @property
    def options(self) -> jpype.JByte:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def reservedB(self) -> jpype.JShort:
        ...

    @property
    def firstImportedSymbol(self) -> jpype.JInt:
        ...

    @property
    def reservedA(self) -> jpype.JByte:
        ...

    @property
    def oldImpVersion(self) -> jpype.JInt:
        ...

    @property
    def currentVersion(self) -> jpype.JInt:
        ...


class PefConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    TVECT: typing.Final = ".TVect"
    IMPORT: typing.Final = ".import"
    TERM: typing.Final = ".term"
    INIT: typing.Final = ".init"
    MAIN: typing.Final = ".main"
    TOC: typing.Final = ".toc"
    GLUE: typing.Final = ".glue"
    BASE_ADDRESS: typing.Final = 268435456

    def __init__(self):
        ...


class RelocBySectDWithSkip(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRelocCount(self) -> int:
        ...

    def getSkipCount(self) -> int:
        ...

    @property
    def relocCount(self) -> jpype.JInt:
        ...

    @property
    def skipCount(self) -> jpype.JInt:
        ...


class RelocUndefinedOpcode(Relocation):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ImportStateCache(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, header: ContainerHeader):
        ...

    def createLibrarySymbol(self, library: ImportedLibrary, symbolName: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address) -> bool:
        ...

    def dispose(self):
        ...

    def getMemoryBlockForSection(self, section: SectionHeader) -> ghidra.program.model.mem.MemoryBlock:
        """
        Returns the memory block for the given section.
        Generally sections do not specify a preferred address
        and are not named. This map provides a way to lookup
        the block that was created for the given section.
        
        :param SectionHeader section: the PEF section header
        :return: the memory block for the given section
        :rtype: ghidra.program.model.mem.MemoryBlock
        """

    def getNamespace(self, library: ImportedLibrary) -> ghidra.program.model.symbol.Namespace:
        """
        Returns a namespace for the given imported library.
        
        :param ImportedLibrary library: the imported library
        :return: a namespace for the given imported library
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getSymbol(self, symbolName: typing.Union[java.lang.String, str], library: ImportedLibrary) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the symbol object with the given name in the specified library.
        
        :param java.lang.String or str symbolName: the desired symbol's name
        :param ImportedLibrary library: the desired library
        :return: the symbol object with the given name in the specified library
        :rtype: ghidra.program.model.symbol.Symbol
        """

    def getTVectNamespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    def getTocAddress(self) -> ghidra.program.model.address.Address:
        ...

    def setMemoryBlockForSection(self, section: SectionHeader, block: ghidra.program.model.mem.MemoryBlock):
        ...

    def setTocAddress(self, tocAddress: ghidra.program.model.address.Address):
        ...

    @property
    def tVectNamespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def memoryBlockForSection(self) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @property
    def namespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def tocAddress(self) -> ghidra.program.model.address.Address:
        ...

    @tocAddress.setter
    def tocAddress(self, value: ghidra.program.model.address.Address):
        ...


class SectionShareKind(java.lang.Enum[SectionShareKind]):
    """
    Values for the shareKind field.
    """

    class_: typing.ClassVar[java.lang.Class]
    ProcessShare: typing.Final[SectionShareKind]
    """
    Indicates the section is shared within a process,
    but a fresh copy is created for different processes.
    """

    GlobalShare: typing.Final[SectionShareKind]
    """
    Indicates the section is shared between all
    processes in the system.
    """

    ProtectedShare: typing.Final[SectionShareKind]
    """
    Indicates the section is shared between all processes,
    but is protected. Protected sections are read/write
    in privileged mode and read-only in user mode.
    """


    @staticmethod
    def get(value: typing.Union[jpype.JInt, int]) -> SectionShareKind:
        ...

    def getValue(self) -> int:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SectionShareKind:
        ...

    @staticmethod
    def values() -> jpype.JArray[SectionShareKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class PefDebug(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 18

    def __init__(self, memory: ghidra.program.model.mem.Memory, address: ghidra.program.model.address.Address):
        ...

    def getDistance(self) -> int:
        ...

    def getFlags(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getNameLength(self) -> int:
        ...

    def getType(self) -> int:
        ...

    def getUnknown(self) -> int:
        ...

    def isValid(self) -> bool:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def nameLength(self) -> jpype.JInt:
        ...

    @property
    def distance(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def unknown(self) -> jpype.JInt:
        ...


class PefException(java.lang.Exception):
    """
    An exception class to handle encountering
    invalid PEF Headers.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructs a new exception with the specified detail message.
        
        :param java.lang.String or str message: the detail message.
        """

    @typing.overload
    def __init__(self, cause: java.lang.Exception):
        """
        Constructs a new exception with the specified cause and a detail message.
        
        :param java.lang.Exception cause: the cause (which is saved for later retrieval by the method
        """


class SymbolClass(java.lang.Enum[SymbolClass]):
    """
    Imported and exported symbol classes
    """

    class_: typing.ClassVar[java.lang.Class]
    kPEFCodeSymbol: typing.Final[SymbolClass]
    """
    A code address
    """

    kPEFDataSymbol: typing.Final[SymbolClass]
    """
    A data address
    """

    kPEFTVectSymbol: typing.Final[SymbolClass]
    """
    A standard procedure pointer
    """

    kPEFTOCSymbol: typing.Final[SymbolClass]
    """
    A direct data area (table of contents) symbol
    """

    kPEFGlueSymbol: typing.Final[SymbolClass]
    """
    A linker-inserted glue symbol
    """

    kPEFUndefinedSymbol: typing.Final[SymbolClass]
    """
    A undefined symbol
    """


    @staticmethod
    def get(value: typing.Union[jpype.JInt, int]) -> SymbolClass:
        ...

    def value(self) -> int:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SymbolClass:
        ...

    @staticmethod
    def values() -> jpype.JArray[SymbolClass]:
        ...


class ContainerHeader(ghidra.app.util.bin.StructConverter):
    """
    See Apple's -- PEFBinaryFormat.h
     
    struct PEFContainerHeader {
        OSType  tag1;              //Must contain 'Joy!'.
        SType   tag2;              //Must contain 'peff'.  (Yes, with two 'f's.)
        OSType  architecture;      //The ISA for code sections.  Constants in CodeFragments.h.
        UInt32  formatVersion;     //The physical format version.
        UInt32  dateTimeStamp;     //Macintosh format creation/modification stamp.
        UInt32  oldDefVersion;     //Old definition version number for the code fragment.
        UInt32  oldImpVersion;     //Old implementation version number for the code fragment.
        UInt32  currentVersion;    //Current version number for the code fragment.
        UInt16  sectionCount;      //Total number of section headers that follow.
        UInt16  instSectionCount;  //Number of instantiated sections.
        UInt32  reservedA;         //Reserved, must be written as zero
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    TAG1: typing.Final = "Joy!"
    TAG2: typing.Final = "peff"
    ARCHITECTURE_PPC: typing.Final = "pwpc"
    ARCHITECTURE_68k: typing.Final = "m68k"

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        ...

    def getArchitecture(self) -> str:
        """
        Returns the architecture for this container.
        Either PowerPC CFM or CFm-68k.
        
        :return: the architecture for this container
        :rtype: str
        """

    def getCurrentVersion(self) -> int:
        """
        Returns the current CFM version.
        
        :return: the current CFM version
        :rtype: int
        """

    def getDateTimeStamp(self) -> int:
        """
        Returns the creation date of this PEF container.
        The stamp follows the Mac time-measurement scheme.
        That is, the number of seconds measured from Jan 1, 1904.
        
        :return: the creation date of this PEF container
        :rtype: int
        """

    def getFormatVersion(self) -> int:
        """
        Returns the version of this PEF container.
        The current version is 1.
        
        :return: the version of this PEF container
        :rtype: int
        """

    def getImageBase(self) -> int:
        ...

    def getInstantiatedSectionCount(self) -> int:
        """
        Returns the number of instantiated sections.
        Instantiated sections contain code or data that 
        are required for execution.
        
        :return: the number of instantiated sections
        :rtype: int
        """

    def getLoader(self) -> LoaderInfoHeader:
        ...

    def getOldDefVersion(self) -> int:
        """
        Returns the old CFM version.
        
        :return: the old CFM version
        :rtype: int
        """

    def getOldImpVersion(self) -> int:
        """
        Returns the old CFM implementation version.
        
        :return: the old CFM implementation version
        :rtype: int
        """

    def getReservedA(self) -> int:
        """
        Reserved field, always returns zero (0).
        
        :return: always returns zero (0)
        :rtype: int
        """

    def getSectionCount(self) -> int:
        """
        Returns the total sections in this container.
        
        :return: the total sections in this container
        :rtype: int
        """

    def getSections(self) -> java.util.List[SectionHeader]:
        ...

    def getTag1(self) -> str:
        """
        Always returns "Joy!"
        
        :return: always returns "Joy!"
        :rtype: str
        """

    def getTag2(self) -> str:
        """
        Always returns "peff"
        
        :return: always returns "peff"
        :rtype: str
        """

    def parse(self):
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def tag1(self) -> java.lang.String:
        ...

    @property
    def oldDefVersion(self) -> jpype.JInt:
        ...

    @property
    def loader(self) -> LoaderInfoHeader:
        ...

    @property
    def reservedA(self) -> jpype.JInt:
        ...

    @property
    def instantiatedSectionCount(self) -> jpype.JShort:
        ...

    @property
    def tag2(self) -> java.lang.String:
        ...

    @property
    def sections(self) -> java.util.List[SectionHeader]:
        ...

    @property
    def oldImpVersion(self) -> jpype.JInt:
        ...

    @property
    def currentVersion(self) -> jpype.JInt:
        ...

    @property
    def sectionCount(self) -> jpype.JShort:
        ...

    @property
    def imageBase(self) -> jpype.JLong:
        ...

    @property
    def dateTimeStamp(self) -> jpype.JInt:
        ...

    @property
    def formatVersion(self) -> jpype.JInt:
        ...

    @property
    def architecture(self) -> java.lang.String:
        ...


class ExportedSymbol(AbstractSymbol):
    """
    See Apple's -- PEFBinaryFormat.h
     
    struct PEFExportedSymbol { //! This structure is 10 bytes long and arrays are packed.
        UInt32  classAndName;  //A combination of class and name offset.
        UInt32  symbolValue;   //Typically the symbol's offset within a section.
        SInt16  sectionIndex;  //The index of the section, or pseudo-section, for the symbol.
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    kPEFExpSymClassShift: typing.Final = 24
    kPEFAbsoluteExport: typing.Final = -2
    """
    The symbol value is an absolute address.
    """

    kPEFReexportedImport: typing.Final = -3
    """
    The symbol value is the index of a reexported import.
    """


    def getNameOffset(self) -> int:
        """
        Returns offset of symbol name in loader string table.
        
        :return: offset of symbol name in loader string table
        :rtype: int
        """

    def getSectionIndex(self) -> int:
        """
        Returns the index of the section, or pseudo-section, for the symbol.
        
        :return: the index of the section, or pseudo-section, for the symbol
        :rtype: int
        """

    def getSymbolValue(self) -> int:
        """
        Typically the symbol's offset within a section.
        
        :return: the symbol's offset within a section
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def sectionIndex(self) -> jpype.JShort:
        ...

    @property
    def nameOffset(self) -> jpype.JInt:
        ...

    @property
    def symbolValue(self) -> jpype.JInt:
        ...


class RelocLgRepeat(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]


class LoaderRelocationHeader(ghidra.app.util.bin.StructConverter):
    """
    See Apple's -- PEFBinaryFormat.h
     
    struct PEFLoaderRelocationHeader {
        UInt16   sectionIndex;     // Index of the section to be fixed up.
        UInt16   reservedA;        // Reserved, must be zero.
        UInt32   relocCount;       // Number of 16 bit relocation chunks.
        UInt32   firstRelocOffset; // Offset of first relocation instruction.
    };
     
    typedef UInt16 PEFRelocChunk;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFirstRelocOffset(self) -> int:
        """
        The firstRelocOffset field (4 bytes) indicates the byte 
        offset from the start of the relocations area to the first relocation 
        instruction for this section.
        
        :return: offset from the start of the relocations area to the first relocation
        :rtype: int
        """

    def getRelocCount(self) -> int:
        """
        The relocCount field (4 bytes) indicates the 
        number of 16-bit relocation blocks for this section.
        
        :return: number of 16-bit relocation blocks for this section
        :rtype: int
        """

    def getRelocations(self) -> java.util.List[Relocation]:
        ...

    def getReservedA(self) -> int:
        """
        Reserved, must be set to zero (0).
        
        :return: reserved, must be set to zero (0)
        :rtype: int
        """

    def getSectionIndex(self) -> int:
        """
        The sectionIndex field (2 bytes) designates the 
        section number to which this relocation header refers.
        
        :return: section number to which this relocation header refers
        :rtype: int
        """

    @property
    def sectionIndex(self) -> jpype.JShort:
        ...

    @property
    def relocCount(self) -> jpype.JInt:
        ...

    @property
    def reservedA(self) -> jpype.JShort:
        ...

    @property
    def firstRelocOffset(self) -> jpype.JInt:
        ...

    @property
    def relocations(self) -> java.util.List[Relocation]:
        ...


class RelocationState(java.lang.Object):
    """
    This class maintains the running state while
    applying relocations.
     
    
    **``relocAddress``**
    Holds an address within the section where the relocations
    are to be performed. The initial value is the base address
    of the section to be relocated.
     
    
    **``importIndex``**
    Holds a symbol index, which is used to access an
    imported symbol's address. This address can then
    be used for relocations. The initial value is 0.
     
    
    **``sectionC``**
    Holds the memory address of an instantiated section
    within the PEF container, this variable is used by relocation
    instructions that relocate section addresses. The initial 
    value is the memory address of section 0 (if that section
    is present and instantiated), otherwise it is 0.
     
    
    **``sectionD``**
    Holds the memory address of an instantiated section
    within the PEF container, this variable is used by relocation
    instructions that relocate section addresses. The initial 
    value is the memory address of section 1 (if that section
    is present and instantiated), otherwise it is 0.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, header: ContainerHeader, relocationHeader: LoaderRelocationHeader, program: ghidra.program.model.listing.Program, importState: ImportStateCache):
        """
        Constructs a new relocation state
        
        :param ContainerHeader header: the PEF container header
        :param LoaderRelocationHeader relocationHeader: the specific relocation header for this state
        :param ghidra.program.model.listing.Program program: the program being relocated
        :param ImportStateCache importState: the current import state
        """

    def dispose(self):
        ...

    def fixupMemory(self, address: ghidra.program.model.address.Address, fixupAddress: ghidra.program.model.address.Address, log: ghidra.app.util.importer.MessageLog):
        """
        Adds the fixup address to the contents stored at address,
        then creates a pointer at address.
        
        :param ghidra.program.model.address.Address address: the address to fixup
        :param ghidra.program.model.address.Address fixupAddress: the value to use in fixup
        :param ghidra.app.util.importer.MessageLog log: message log for recording errors
        """

    def getImportIndex(self) -> int:
        """
        Returns the current import index.
        
        :return: the current import index
        :rtype: int
        """

    def getRelocationAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the current relocation address.
        
        :return: the current relocation address
        :rtype: ghidra.program.model.address.Address
        """

    def getSectionC(self) -> ghidra.program.model.address.Address:
        """
        Returns the current sectionC address.
        
        :return: the current sectionC address
        :rtype: ghidra.program.model.address.Address
        """

    def getSectionD(self) -> ghidra.program.model.address.Address:
        """
        Returns the current sectionD address.
        
        :return: the current sectionD address
        :rtype: ghidra.program.model.address.Address
        """

    def getSectionToBeRelocated(self) -> ghidra.program.model.address.Address:
        """
        Returns the base address of the section to be relocated.
        
        :return: the base address of the section to be relocated
        :rtype: ghidra.program.model.address.Address
        """

    def incrementImportIndex(self):
        """
        Increments the import index by one.
        """

    def incrementRelocationAddress(self, addend: typing.Union[jpype.JInt, int]):
        """
        Increments the relocation address by the given addend
        
        :param jpype.JInt or int addend: the amount to increment the relocation address
        """

    def relocateMemoryAt(self, address: ghidra.program.model.address.Address, addend: typing.Union[jpype.JInt, int], log: ghidra.app.util.importer.MessageLog):
        """
        Increments the integer in memory at the specified address
        
        :param ghidra.program.model.address.Address address: the address to increment
        :param jpype.JInt or int addend: the value to add
        :param ghidra.app.util.importer.MessageLog log: a message log
        """

    def setImportIndex(self, importIndex: typing.Union[jpype.JInt, int]):
        """
        Sets the import index.
        
        :param jpype.JInt or int importIndex: the new import index value
        """

    def setRelocationAddress(self, relocationAddress: ghidra.program.model.address.Address):
        """
        Sets the relocation address.
        
        :param ghidra.program.model.address.Address relocationAddress: the new relocation address
        """

    def setSectionC(self, sectionC: ghidra.program.model.address.Address):
        """
        Set the sectionC variable to given address.
        
        :param ghidra.program.model.address.Address sectionC: the new sectionC address
        """

    def setSectionD(self, sectionD: ghidra.program.model.address.Address):
        """
        Set the sectionD variable to given address.
        
        :param ghidra.program.model.address.Address sectionD: the new sectionD address
        """

    @property
    def sectionToBeRelocated(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def relocationAddress(self) -> ghidra.program.model.address.Address:
        ...

    @relocationAddress.setter
    def relocationAddress(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def importIndex(self) -> jpype.JInt:
        ...

    @importIndex.setter
    def importIndex(self, value: jpype.JInt):
        ...

    @property
    def sectionC(self) -> ghidra.program.model.address.Address:
        ...

    @sectionC.setter
    def sectionC(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def sectionD(self) -> ghidra.program.model.address.Address:
        ...

    @sectionD.setter
    def sectionD(self, value: ghidra.program.model.address.Address):
        ...


class RelocLgSetOrBySection(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]
    kPEFRelocLgBySection: typing.Final = 0
    """
    This instruction adds the address of the instantiated
    section specified by ``index`` to the word
    pointed to by ``relocAddress``. After
    execution, ``relocAddress`` points to just
    past the modified word.
    """

    kPEFRelocLgSetSectC: typing.Final = 1
    """
    This instruction sets the variable ``sectionC``
    to the memory address of the instantiated section
    specified by ``index``.
    """

    kPEFRelocLgSetSectD: typing.Final = 2
    """
    This instruction sets the variable ``sectionD``
    to the memory adddress of the instantiated section
    specified by ``index``.
    """


    def getIndex(self) -> int:
        ...

    def getSubopcode(self) -> int:
        ...

    @property
    def subopcode(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class ExportedSymbolHashSlot(ghidra.app.util.bin.StructConverter):
    """
    See Apple's -- PEFBinaryFormat.h
     
    struct PEFExportedSymbolHashSlot {
        UInt32              countAndStart;
    };
    """

    class_: typing.ClassVar[java.lang.Class]

    def getIndexOfFirstExportKey(self) -> int:
        ...

    def getSymbolCount(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def indexOfFirstExportKey(self) -> jpype.JInt:
        ...

    @property
    def symbolCount(self) -> jpype.JInt:
        ...


class RelocByIndexGroup(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]
    kPEFRelocSmByImport: typing.Final = 0
    """
    This "RelocSmByImport" (SYMB) instruction adds the address of the imported symbol 
    whose index is held in ``index`` to the word pointed to by 
    ``relocAddress``. After the addition, ``relocAddress`` 
    points to just past the modified word, and ``importindex`` 
    is set to ``index+1``.
    """

    kPEFRelocSmSetSectC: typing.Final = 1
    """
    This "RelocSmSetSectC" (CDIS) instruction sets the variable ``sectionC`` 
    to the memory address of the instantiated section 
    specified by ``index``.
    """

    kPEFRelocSmSetSectD: typing.Final = 2
    """
    This "RelocSmSetSectD" (DTIS) instruction sets the variable ``sectionD``
    to the memory adddress of the instantiated section 
    specified by ``index``.
    """

    kPEFRelocSmBySection: typing.Final = 3
    """
    This "RelocSmBySection" (SECN) instruction adds the address of the instantiated 
    section specified by ``index`` to the word 
    pointed to by ``relocAddress``. After
    execution, ``relocAddress`` points to just 
    past the modified word.
    """


    def getIndex(self) -> int:
        ...

    def getSubopcode(self) -> int:
        ...

    @property
    def subopcode(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class SectionKind(java.lang.Enum[SectionKind]):
    """
    Values for the sectionKind field.
    Section kind values for instantiated sections.
    """

    class_: typing.ClassVar[java.lang.Class]
    Code: typing.Final[SectionKind]
    """
    Code, presumed pure and position independent.
    """

    UnpackedData: typing.Final[SectionKind]
    """
    Unpacked writeable data.
    """

    PackedData: typing.Final[SectionKind]
    """
    Packed writeable data.
    """

    Constant: typing.Final[SectionKind]
    """
    Read-only data.
    """

    Loader: typing.Final[SectionKind]
    """
    Loader tables.
    """

    Debug: typing.Final[SectionKind]
    """
    Reserved for future use.
    """

    ExecutableData: typing.Final[SectionKind]
    """
    Intermixed code and writeable data.
    """

    Exception: typing.Final[SectionKind]
    """
    Reserved for future use.
    """

    Traceback: typing.Final[SectionKind]
    """
    Reserved for future use.
    """


    @staticmethod
    def get(value: typing.Union[jpype.JInt, int]) -> SectionKind:
        ...

    def getValue(self) -> int:
        ...

    def isInstantiated(self) -> bool:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SectionKind:
        ...

    @staticmethod
    def values() -> jpype.JArray[SectionKind]:
        ...

    @property
    def instantiated(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class RelocationFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getRelocation(reader: ghidra.app.util.bin.BinaryReader) -> Relocation:
        ...


class PackedDataOpcodes(java.lang.Enum[PackedDataOpcodes]):
    """
    Packed Data Contents
     
    See Apple's -- IOPEFInternals.h
    """

    class_: typing.ClassVar[java.lang.Class]
    kPEFPkDataZero: typing.Final[PackedDataOpcodes]
    """
    Zero fill "count" bytes.
    """

    kPEFPkDataBlock: typing.Final[PackedDataOpcodes]
    """
    Block copy "count" bytes.
    """

    kPEFPkDataRepeat: typing.Final[PackedDataOpcodes]
    """
    Repeat "count" bytes "count2"+1 times.
    """

    kPEFPkDataRepeatBlock: typing.Final[PackedDataOpcodes]
    """
    Interleaved repeated and unique data.
    """

    kPEFPkDataRepeatZero: typing.Final[PackedDataOpcodes]
    """
    Interleaved zero and unique data.
    """

    kPEFPkDataReserved5: typing.Final[PackedDataOpcodes]
    """
    Reserved.
    """

    kPEFPkDataReserved6: typing.Final[PackedDataOpcodes]
    """
    Reserved.
    """

    kPEFPkDataReserved7: typing.Final[PackedDataOpcodes]
    """
    Reserved.
    """


    @staticmethod
    def get(value: typing.Union[jpype.JInt, int]) -> PackedDataOpcodes:
        ...

    def getValue(self) -> int:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PackedDataOpcodes:
        ...

    @staticmethod
    def values() -> jpype.JArray[PackedDataOpcodes]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class RelocSetPosition(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOffset(self) -> int:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...


class ImportedSymbol(AbstractSymbol):

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 4

    def getSymbolNameOffset(self) -> int:
        """
        The offset (in bytes) from the beginning of the loader 
        string table to the null-terminated name of the symbol.
        
        :return: offset to the null-terminated name of the symbol
        :rtype: int
        """

    def isWeak(self) -> bool:
        """
        The imported symbol does not have to 
        be present at fragment preparation time in 
        order for execution to continue.
        
        :return: if the symbol is weak
        :rtype: bool
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def symbolNameOffset(self) -> jpype.JInt:
        ...

    @property
    def weak(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class AbstractSymbol(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    kPEFWeakImportSymMask: typing.Final = 128
    """
    Weak symbol mask
    """


    def getName(self) -> str:
        """
        Returns the symbol's name.
        
        :return: the symbol's name
        :rtype: str
        """

    def getSymbolClass(self) -> SymbolClass:
        """
        Returns the symbol's class.
        
        :return: the symbol's class
        :rtype: SymbolClass
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def symbolClass(self) -> SymbolClass:
        ...


class ExportedSymbolKey(ghidra.app.util.bin.StructConverter):
    """
    See Apple's -- PEFBinaryFormat.h * Exported Symbol Hash Key
     
    struct PEFExportedSymbolKey {
        union {
            UInt32            fullHashWord;
            PEFSplitHashWord  splitHashWord;
        } u;
    };
     
     
    struct PEFSplitHashWord {
        UInt16  nameLength;
        UInt16  hashValue;
    };
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFullHashWord(self) -> int:
        ...

    def getHashValue(self) -> int:
        ...

    def getNameLength(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def nameLength(self) -> jpype.JShort:
        ...

    @property
    def hashValue(self) -> jpype.JShort:
        ...

    @property
    def fullHashWord(self) -> jpype.JInt:
        ...


class SectionHeader(ghidra.app.util.bin.StructConverter):
    """
    See Apple's -- PEFBinaryFormat
     
    struct PEFSectionHeader {
        SInt32   nameOffset;             // Offset of name within the section name table, -1 => none.
        UInt32   defaultAddress;         // Default address, affects relocations.
        UInt32   totalLength;            // Fully expanded size in bytes of the section contents.
        UInt32   unpackedLength;         // Size in bytes of the "initialized" part of the contents.
        UInt32   containerLength;        // Size in bytes of the raw data in the container.
        UInt32   containerOffset;        // Offset of section's raw data.
        UInt8    sectionKind;            // Kind of section contents/usage.
        UInt8    shareKind;              // Sharing level, if a writeable section.
        UInt8    alignment;              // Preferred alignment, expressed as log 2.
        UInt8    reservedA;              // Reserved, must be zero.
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    NO_NAME_OFFSET: typing.Final = -1

    def getAlignment(self) -> int:
        ...

    def getContainerLength(self) -> int:
        """
        Returns the size in bytes of the raw data in the container.
        
        :return: the size in bytes of the raw data in the container
        :rtype: int
        """

    def getContainerOffset(self) -> int:
        ...

    def getData(self) -> java.io.InputStream:
        """
        Returns an input stream to underlying bytes of this section.
        
        :return: an input stream to underlying bytes of this section
        :rtype: java.io.InputStream
        :raises IOException: if an i/o error occurs.
        """

    def getDefaultAddress(self) -> int:
        """
        Returns the preferred address of this section.
        
        :return: the preferred address of this section
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of this section.
        
        :return: the name of this section
        :rtype: str
        """

    def getNameOffset(self) -> int:
        """
        The offset from the start of the section name table
        to the name of this section.
        A value of -1 indicates an unnamed section.
        
        :return: the offset from the start of the section name table
        :rtype: int
        """

    def getReservedA(self) -> int:
        """
        Reserved!
        
        :return: Reserved!
        :rtype: int
        """

    def getSectionKind(self) -> SectionKind:
        ...

    def getShareKind(self) -> SectionShareKind:
        ...

    def getTotalLength(self) -> int:
        ...

    def getUnpackedData(self, monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[jpype.JByte]:
        """
        Unpack the data in a packed section.
        Calling this method is only valid on a packed section.
        
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the unpacked data
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if an i/o error occurs or the section is not packed.
        """

    def getUnpackedLength(self) -> int:
        """
        Returns the size in bytes of the "initialized" part of the contents.
        
        :return: the size in bytes of the "initialized" part of the contents
        :rtype: int
        """

    def isExecute(self) -> bool:
        """
        Returns true if this section has execute permissions.
        
        :return: true if this section has execute permissions
        :rtype: bool
        """

    def isRead(self) -> bool:
        """
        Returns true if this section has read permissions.
        
        :return: true if this section has read permissions
        :rtype: bool
        """

    def isWrite(self) -> bool:
        """
        Returns true if this section has write permissions.
        
        :return: true if this section has write permissions
        :rtype: bool
        """

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def data(self) -> java.io.InputStream:
        ...

    @property
    def sectionKind(self) -> SectionKind:
        ...

    @property
    def containerLength(self) -> jpype.JInt:
        ...

    @property
    def reservedA(self) -> jpype.JByte:
        ...

    @property
    def totalLength(self) -> jpype.JInt:
        ...

    @property
    def containerOffset(self) -> jpype.JInt:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...

    @property
    def nameOffset(self) -> jpype.JInt:
        ...

    @property
    def unpackedLength(self) -> jpype.JInt:
        ...

    @property
    def unpackedData(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def shareKind(self) -> SectionShareKind:
        ...

    @property
    def alignment(self) -> jpype.JByte:
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @property
    def defaultAddress(self) -> jpype.JInt:
        ...


class RelocLgByImport(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]

    def getIndex(self) -> int:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class RelocSmRepeat(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]


class RelocIncrPosition(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOffset(self) -> int:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...


class Relocation(ghidra.app.util.bin.StructConverter):
    """
    The high-order 7 bits for the currently defined relocation opcode values.
     
    Binary values indicated by "x" are "don't care" 
    operands. For example, any combination of the high-order 7 bits that starts 
    with two zero bits (00) indicates the RelocBySectDWithSkip instruction. 
     
    Relocation instructions are stored in 2-byte relocation blocks. Most instructions 
    take up one block that combines an opcode and related arguments. Instructions 
    that are larger than 2 bytes have an opcode and some of the operands in the 
    first 2-byte block, with other operands in the following 2-byte blocks. The 
    opcode occupies the upper (higher-order) bits of the block that contains it. 
    Relocation instructions can be decoded from the high-order 7 bits of their first 
    block. 
     
    All currently defined relocation instructions relocate locations as words 
    (that is, 4-byte values).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def apply(self, importState: ImportStateCache, relocState: RelocationState, header: ContainerHeader, program: ghidra.program.model.listing.Program, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        ...

    def getOpcode(self) -> int:
        ...

    def getRepeatChunks(self) -> int:
        ...

    def getRepeatCount(self) -> int:
        ...

    def getSizeInBytes(self) -> int:
        ...

    def isMatch(self) -> bool:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def repeatChunks(self) -> jpype.JInt:
        ...

    @property
    def sizeInBytes(self) -> jpype.JInt:
        ...

    @property
    def match(self) -> jpype.JBoolean:
        ...

    @property
    def opcode(self) -> jpype.JInt:
        ...

    @property
    def repeatCount(self) -> jpype.JInt:
        ...


class RelocValueGroup(Relocation):
    """
    See Apple's -- PEFBinaryFormat.h
    """

    class_: typing.ClassVar[java.lang.Class]
    kPEFRelocBySectC: typing.Final = 0
    kPEFRelocBySectD: typing.Final = 1
    kPEFRelocTVector12: typing.Final = 2
    kPEFRelocTVector8: typing.Final = 3
    kPEFRelocVTable8: typing.Final = 4
    kPEFRelocImportRun: typing.Final = 5

    def getRunLength(self) -> int:
        ...

    def getSubopcode(self) -> int:
        ...

    @property
    def subopcode(self) -> jpype.JInt:
        ...

    @property
    def runLength(self) -> jpype.JInt:
        ...



__all__ = ["LoaderInfoHeader", "ImportedLibrary", "PefConstants", "RelocBySectDWithSkip", "RelocUndefinedOpcode", "ImportStateCache", "SectionShareKind", "PefDebug", "PefException", "SymbolClass", "ContainerHeader", "ExportedSymbol", "RelocLgRepeat", "LoaderRelocationHeader", "RelocationState", "RelocLgSetOrBySection", "ExportedSymbolHashSlot", "RelocByIndexGroup", "SectionKind", "RelocationFactory", "PackedDataOpcodes", "RelocSetPosition", "ImportedSymbol", "AbstractSymbol", "ExportedSymbolKey", "SectionHeader", "RelocLgByImport", "RelocSmRepeat", "RelocIncrPosition", "Relocation", "RelocValueGroup"]
