from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format
import ghidra.app.util.bin.format.mz
import ghidra.app.util.bin.format.pe.cli
import ghidra.app.util.bin.format.pe.debug
import ghidra.app.util.bin.format.pe.resource
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class ROMHeader(java.lang.Object):
    """
    A class to represent the 
    ``IMAGE_ROM_HEADERS``
    struct as defined in 
    **``winnt.h``**.
    
     
    typedef struct _IMAGE_ROM_HEADERS {
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
    } IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFileHeader(self) -> FileHeader:
        ...

    def getOptionalHeader(self) -> OptionalHeaderROM:
        ...

    @property
    def optionalHeader(self) -> OptionalHeaderROM:
        ...

    @property
    def fileHeader(self) -> FileHeader:
        ...


class InvalidNTHeaderException(java.lang.Exception):
    """
    An exception class to handle encountering
    invalid NT Headers.
    
    
    .. seealso::
    
        | :obj:`ghidra.app.util.bin.format.pe.NTHeader`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ImageRuntimeFunctionEntries_ARM(ImageRuntimeFunctionEntries):
    """
    
    typedef struct _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    union {
        DWORD UnwindData;
        struct {
        DWORD Flag : 2;
        DWORD FunctionLength : 11;
        DWORD Ret : 2;
        DWORD H : 1;
        DWORD Reg : 3;
        DWORD R : 1;
        DWORD L : 1;
        DWORD C : 1;
        DWORD StackAdjust : 10;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    } IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY;
     
    
    
    .. seealso::
    
        | `arm-exception-handling.md <https://github.com/MicrosoftDocs/cpp-docs/blob/main/docs/build/arm-exception-handling.md>`_
    """

    @typing.type_check_only
    class ImageRuntimeFunctionEntry_ARM(java.lang.Record):
        """
        Creates a new :obj:`ImageRuntimeFunctionEntries_ARM`
        """

        class_: typing.ClassVar[java.lang.Class]

        def beginAddress(self) -> int:
            ...

        def data(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def isExceptionInfoRVA(self) -> bool:
            """
            Checks whether or not this entry is an exception info RVA or packed unwind data
            
            :return: True if this entry is an exception info RVA, or false if it's packed unwind data
            :rtype: bool
            """

        def markup(self, program: ghidra.program.model.listing.Program):
            """
            Marks up this entry
            
            :param ghidra.program.model.listing.Program program: The :obj:`Program`
            :raises IOException: If there was an IO-related error creating the data
            :raises DuplicateNameException: If a data type of the same name already exists
            :raises CodeUnitInsertionException: If data creation failed
            """

        def toString(self) -> str:
            ...

        @property
        def exceptionInfoRVA(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]


class Constants(java.lang.Object):
    """
    Constants used in the data structures of the PE.
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_ORDINAL_FLAG64: typing.Final = -9223372036854775808
    """
    A 64-bit flag.
    """

    IMAGE_ORDINAL_FLAG32: typing.Final = 2147483648
    """
    A 32-bit flag.
    """

    IMAGE_NT_SIGNATURE: typing.Final = 17744
    """
    The magic number for PE files..
    """

    IMAGE_OS2_SIGNATURE: typing.Final = 17742
    """
    The magic number for OS/2 files.
    """

    IMAGE_OS2_SIGNATURE_LE: typing.Final = 17740
    """
    The magic number for little endian OS/2 files.
    """

    IMAGE_VXD_SIGNATURE: typing.Final = 17740
    """
    The magic number for VXD files.
    """

    IMAGE_NT_OPTIONAL_HDR32_MAGIC: typing.Final = 267
    """
    The 32-bit optional header magic number.
    """

    IMAGE_NT_OPTIONAL_HDR64_MAGIC: typing.Final = 523
    """
    The 64-bit optional header magic number.
    """

    IMAGE_ROM_OPTIONAL_HDR_MAGIC: typing.Final = 263
    """
    The ROM optional header magic number.
    """

    IMAGE_SIZEOF_ROM_OPTIONAL_HEADER: typing.Final = 56
    """
    The size of the ROM optional header.
    """

    IMAGE_SIZEOF_STD_OPTIONAL_HEADER: typing.Final = 28
    """
    The size of the standard optional header.
    """

    IMAGE_SIZEOF_NT_OPTIONAL32_HEADER: typing.Final = 224
    """
    The size of the 32-bit optional header, in bytes.
    """

    IMAGE_SIZEOF_NT_OPTIONAL64_HEADER: typing.Final = 240
    """
    The size of the 64-bit optional header, in bytes.
    """

    IMAGE_ARCHIVE_START_SIZE: typing.Final = 8
    """
    The size of the archive start header.
    """

    IMAGE_ARCHIVE_START: typing.Final = "!<arch>\n"
    """
    The archive start magic value.
    """

    IMAGE_ARCHIVE_END: typing.Final = "`\n"
    """
    The archive end magic value.
    """

    IMAGE_ARCHIVE_PAD: typing.Final = "\n"
    """
    The archive padding.
    """

    IMAGE_ARCHIVE_LINKER_MEMBER: typing.Final = "/               "
    """
    The archive linker member.
    """

    IMAGE_ARCHIVE_LONGNAMES_MEMBER: typing.Final = "//              "
    """
    The archive long names member.
    """



class ImageRuntimeFunctionEntries(java.lang.Object):
    """
    An interface for working with function table entries used for exception handling, which are found
    in the .pdata section.  The actual implementations are architecture-specific.
    """

    class_: typing.ClassVar[java.lang.Class]

    def markup(self, program: ghidra.program.model.listing.Program, start: ghidra.program.model.address.Address):
        """
        Marks up an :obj:`ImageRuntimeFunctionEntries`
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.Address start: The start :obj:`Address`
        :raises IOException: If there was an IO-related error creating the data
        :raises DuplicateNameException: If a data type of the same name already exists
        :raises CodeUnitInsertionException: If data creation failed
        """


class LoadConfigDirectory(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the ``IMAGE_LOAD_CONFIG_DIRECTORY``
    data structure which is defined in **``winnt.h``**.
    """

    @typing.type_check_only
    class GuardFlags(ghidra.app.util.bin.StructConverter):
        """
        Control Flow Guard flags.
        """

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "IMAGE_GUARD_FLAGS"

        def __init__(self, flags: typing.Union[jpype.JInt, int]):
            ...

        def getFlags(self) -> int:
            ...

        @property
        def flags(self) -> jpype.JInt:
            ...


    @typing.type_check_only
    class CodeIntegrity(ghidra.app.util.bin.StructConverter):
        """
        Not sure yet what this is used for.
        """

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "IMAGE_LOAD_CONFIG_CODE_INTEGRITY"

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME32: typing.Final = "IMAGE_LOAD_CONFIG_DIRECTORY32"
    NAME64: typing.Final = "IMAGE_LOAD_CONFIG_DIRECTORY64"

    def getCfgCheckFunctionPointer(self) -> int:
        """
        Gets the ControlFlowGuard check function pointer address.
        
        :return: The ControlFlowGuard check function pointer address.  
        Could be 0 if ControlFlowGuard is not being used.
        :rtype: int
        """

    def getCfgDispatchFunctionPointer(self) -> int:
        """
        Gets the ControlFlowGuard dispatch function pointer address.
        
        :return: The ControlFlowGuard dispatch function pointer address.  
        Could be 0 if ControlFlowGuard is not being used.
        :rtype: int
        """

    def getCfgFunctionCount(self) -> int:
        """
        Gets the ControlFlowGuard function count.
        
        :return: The ControlFlowGuard function count.  Could be 0 if ControlFlowGuard is 
        not being used.
        :rtype: int
        """

    def getCfgFunctionTablePointer(self) -> int:
        """
        Gets the ControlFlowGuard function table pointer address.
        
        :return: The ControlFlowGuard function table function pointer address.  
        Could be 0 if ControlFlowGuard is not being used.
        :rtype: int
        """

    def getCfgGuardFlags(self) -> LoadConfigDirectory.GuardFlags:
        """
        Gets the ControlFlowGuard :obj:`GuardFlags`.
        
        :return: The ControlFlowGuard :obj:`GuardFlags`.
        :rtype: LoadConfigDirectory.GuardFlags
        """

    def getCriticalSectionDefaultTimeout(self) -> int:
        """
        Returns the critical section default time-out value.
        
        :return: the critical section default time-out value
        :rtype: int
        """

    def getGuardAddressIatTableCount(self) -> int:
        """
        Gets the ControlFlowGuard IAT entries count.
        
        :return: The ControlFlowGuard IAT entries count.  Could be 0 if ControlFlowGuard is not being used
        :rtype: int
        """

    def getGuardAddressIatTableTablePointer(self) -> int:
        """
        Gets the ControlFlowGuard IAT table pointer address.
        
        :return: The ControlFlowGuard IAT table function pointer address. Could be 0 if ControlFlowGuard is not being used
        :rtype: int
        """

    def getRfgFailureRoutine(self) -> int:
        """
        Gets the ReturnFlowGuard failure routine address.
        
        :return: The ReturnFlowGuard failure routine address.
        Could be 0 if ReturnFlowGuard is not being used.
        :rtype: int
        """

    def getRfgFailureRoutineFunctionPointer(self) -> int:
        """
        Gets the ReturnFlowGuard failure routine function pointer address.
        
        :return: The ReturnFlowGuard failure routine function pointer address.
        Could be 0 if ReturnFlowGuard is not being used.
        :rtype: int
        """

    def getRfgVerifyStackPointerFunctionPointer(self) -> int:
        """
        Gets the ReturnFlowGuard verify stack pointer function pointer address.
        
        :return: The ReturnFlowGuard verify stack pointer function pointer address.
        Could be 0 if ReturnFlowGuard is not being used.
        :rtype: int
        """

    def getSeHandlerCount(self) -> int:
        """
        Gets the safe exception handler table count.
        
        :return: the safe exception handler table count.
        :rtype: int
        """

    def getSeHandlerTable(self) -> int:
        """
        Gets the safe exception handler table.
        
        :return: the safe exception handler table.
        :rtype: int
        """

    def getSize(self) -> int:
        """
        Returns the size (in bytes) of this structure.
        
        :return: the size (in bytes) of this structure
        :rtype: int
        """

    @property
    def cfgGuardFlags(self) -> LoadConfigDirectory.GuardFlags:
        ...

    @property
    def cfgFunctionTablePointer(self) -> jpype.JLong:
        ...

    @property
    def rfgFailureRoutineFunctionPointer(self) -> jpype.JLong:
        ...

    @property
    def criticalSectionDefaultTimeout(self) -> jpype.JInt:
        ...

    @property
    def guardAddressIatTableCount(self) -> jpype.JLong:
        ...

    @property
    def seHandlerCount(self) -> jpype.JLong:
        ...

    @property
    def cfgCheckFunctionPointer(self) -> jpype.JLong:
        ...

    @property
    def seHandlerTable(self) -> jpype.JLong:
        ...

    @property
    def rfgFailureRoutine(self) -> jpype.JLong:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def cfgDispatchFunctionPointer(self) -> jpype.JLong:
        ...

    @property
    def guardAddressIatTableTablePointer(self) -> jpype.JLong:
        ...

    @property
    def rfgVerifyStackPointerFunctionPointer(self) -> jpype.JLong:
        ...

    @property
    def cfgFunctionCount(self) -> jpype.JLong:
        ...


class ArchitectureDataDirectory(DataDirectory, ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getCopyright(self) -> str:
        """
        Returns the copyright string defined in this directory.
        
        :return: the copyright string defined in this directory
        :rtype: str
        """

    @property
    def copyright(self) -> java.lang.String:
        ...


class ImportDataDirectory(DataDirectory):
    """
    Points to the imports (an array of IMAGE_IMPORT_DESCRIPTOR structures).
    """

    class_: typing.ClassVar[java.lang.Class]

    def getImportDescriptors(self) -> jpype.JArray[ImportDescriptor]:
        """
        Returns the array of ImportDescriptor defined in this import directory.
        
        :return: the array of ImportDescriptor defined in this import directory
        :rtype: jpype.JArray[ImportDescriptor]
        """

    def getImports(self) -> jpype.JArray[ImportInfo]:
        """
        Returns the array of ImportInfo defined in this import directory.
        
        :return: the array of ImportInfo defined in this import directory
        :rtype: jpype.JArray[ImportInfo]
        """

    @property
    def imports(self) -> jpype.JArray[ImportInfo]:
        ...

    @property
    def importDescriptors(self) -> jpype.JArray[ImportDescriptor]:
        ...


class ExceptionDataDirectory(DataDirectory):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ImportAddressTableDataDirectory(DataDirectory):

    class_: typing.ClassVar[java.lang.Class]

    def getThunkDataSet(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[ThunkData]:
        """
        Returns the thunk data set at the specified index.
        
        :param jpype.JInt or int index: the desired thunk data index
        :return: the thunk data array at the specified index
        :rtype: jpype.JArray[ThunkData]
        """

    @property
    def thunkDataSet(self) -> jpype.JArray[ThunkData]:
        ...


class ThunkData(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    A class to represent the 
    **``IMAGE_THUNK_DATA32 struct``**
    as defined in 
    **``winnt.h``**.
     
     
    typedef struct _IMAGE_THUNK_DATA32 {
        union {
            DWORD ForwarderString;  // PBYTE
            DWORD Function;         // PDWORD
            DWORD Ordinal;
            DWORD AddressOfData;    // PIMAGE_IMPORT_BY_NAME
        } u1;
    } IMAGE_THUNK_DATA32;
    typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;
     
     
     
    typedef struct _IMAGE_THUNK_DATA64 {
        union {
            PBYTE  ForwarderString;
            PDWORD Function;
            ULONGLONG Ordinal;
            PIMAGE_IMPORT_BY_NAME  AddressOfData;
        } u1;
    } IMAGE_THUNK_DATA64;
    typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: typing.Union[jpype.JInt, int]):
        """
        Constructs a new thunk data with the specified value
        
        :param jpype.JInt or int value: the new thunk value
        """

    def getAddressOfData(self) -> int:
        """
        Returns the address of the data.
        
        :return: the address of the data
        :rtype: int
        """

    def getForwarderString(self) -> int:
        """
        Returns the forward string pointer.
        
        :return: the forward string pointer
        :rtype: int
        """

    def getFunction(self) -> int:
        """
        Returns the function pointer.
        
        :return: the function pointer
        :rtype: int
        """

    def getImportByName(self) -> ImportByName:
        """
        Returns the underlying import by name structure.
        
        :return: the underlying import by name structure
        :rtype: ImportByName
        """

    def getOrdinal(self) -> int:
        """
        Returns the ordinal.
        
        :return: the ordinal
        :rtype: int
        """

    def getStructName(self) -> str:
        """
        Returns the struct name.
        
        :return: the struct name
        :rtype: str
        """

    def getStructSize(self) -> int:
        """
        Returns the size of the thunk (in bytes) based on the size of the
        executable (32 vs 64 bit).
        
        :return: the size of the thunk (in bytes)
        :rtype: int
        """

    def isOrdinal(self) -> bool:
        ...

    def setValue(self, value: typing.Union[jpype.JInt, int]):
        """
        Sets the value of the thunk.
        
        :param jpype.JInt or int value: the new thunk value
        """

    @property
    def forwarderString(self) -> jpype.JLong:
        ...

    @property
    def addressOfData(self) -> jpype.JLong:
        ...

    @property
    def structName(self) -> java.lang.String:
        ...

    @property
    def importByName(self) -> ImportByName:
        ...

    @property
    def function(self) -> jpype.JLong:
        ...

    @property
    def structSize(self) -> jpype.JInt:
        ...

    @property
    def ordinal(self) -> jpype.JLong:
        ...


@typing.type_check_only
class MachineName(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SectionFlags(java.lang.Enum[SectionFlags]):

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SCN_TYPE_NO_PAD: typing.Final[SectionFlags]
    IMAGE_SCN_RESERVED_0001: typing.Final[SectionFlags]
    IMAGE_SCN_CNT_CODE: typing.Final[SectionFlags]
    IMAGE_SCN_CNT_INITIALIZED_DATA: typing.Final[SectionFlags]
    IMAGE_SCN_CNT_UNINITIALIZED_DATA: typing.Final[SectionFlags]
    IMAGE_SCN_LNK_OTHER: typing.Final[SectionFlags]
    IMAGE_SCN_LNK_INFO: typing.Final[SectionFlags]
    IMAGE_SCN_RESERVED_0040: typing.Final[SectionFlags]
    IMAGE_SCN_LNK_REMOVE: typing.Final[SectionFlags]
    IMAGE_SCN_LNK_COMDAT: typing.Final[SectionFlags]
    IMAGE_SCN_GPREL: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_PURGEABLE: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_16BIT: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_LOCKED: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_PRELOAD: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_1BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_2BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_4BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_8BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_16BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_32BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_64BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_128BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_256BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_512BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_1024BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_2048BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_4096BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_ALIGN_8192BYTES: typing.Final[SectionFlags]
    IMAGE_SCN_LNK_NRELOC_OVFL: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_DISCARDABLE: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_NOT_CACHED: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_NOT_PAGED: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_SHARED: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_EXECUTE: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_READ: typing.Final[SectionFlags]
    IMAGE_SCN_MEM_WRITE: typing.Final[SectionFlags]

    def getAlias(self) -> str:
        ...

    def getDescription(self) -> str:
        ...

    def getMask(self) -> int:
        ...

    @staticmethod
    def resolveFlags(value: typing.Union[jpype.JInt, int]) -> java.util.Set[SectionFlags]:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SectionFlags:
        ...

    @staticmethod
    def values() -> jpype.JArray[SectionFlags]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def alias(self) -> java.lang.String:
        ...

    @property
    def mask(self) -> jpype.JInt:
        ...


class OptionalHeaderImpl(OptionalHeader):
    """
    
    typedef struct _IMAGE_OPTIONAL_HEADER {
        WORD    Magic;                                    // MANDATORY
        BYTE    MajorLinkerVersion;
        BYTE    MinorLinkerVersion;
        DWORD   SizeOfCode;
        DWORD   SizeOfInitializedData;
        DWORD   SizeOfUninitializedData;
        DWORD   AddressOfEntryPoint;                        // MANDATORY
        DWORD   BaseOfCode;
        DWORD   BaseOfData;
        DWORD   ImageBase;                                // MANDATORY
        DWORD   SectionAlignment;                        // MANDATORY
        DWORD   FileAlignment;                            // MANDATORY
        WORD    MajorOperatingSystemVersion;                // MANDATORY
        WORD    MinorOperatingSystemVersion;
        WORD    MajorImageVersion;
        WORD    MinorImageVersion;
        WORD    MajorSubsystemVersion;
        WORD    MinorSubsystemVersion;
        DWORD   Win32VersionValue;
        DWORD   SizeOfImage;                                // MANDATORY
        DWORD   SizeOfHeaders;                            // MANDATORY
        DWORD   CheckSum;
        WORD    Subsystem;                                // MANDATORY
        WORD    DllCharacteristics;
        DWORD   SizeOfStackReserve;
        DWORD   SizeOfStackCommit;
        DWORD   SizeOfHeapReserve;
        DWORD   SizeOfHeapCommit;
        DWORD   LoaderFlags;
        DWORD   NumberOfRvaAndSizes;                        // USED
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };
     
     
     
    typedef struct _IMAGE_OPTIONAL_HEADER64 {
        WORD        Magic;
        BYTE        MajorLinkerVersion;
        BYTE        MinorLinkerVersion;
        DWORD       SizeOfCode;
        DWORD       SizeOfInitializedData;
        DWORD       SizeOfUninitializedData;
        DWORD       AddressOfEntryPoint;
        DWORD       BaseOfCode;
        ULONGLONG   ImageBase;
        DWORD       SectionAlignment;
        DWORD       FileAlignment;
        WORD        MajorOperatingSystemVersion;
        WORD        MinorOperatingSystemVersion;
        WORD        MajorImageVersion;
        WORD        MinorImageVersion;
        WORD        MajorSubsystemVersion;
        WORD        MinorSubsystemVersion;
        DWORD       Win32VersionValue;
        DWORD       SizeOfImage;
        DWORD       SizeOfHeaders;
        DWORD       CheckSum;
        WORD        Subsystem;
        WORD        DllCharacteristics;
        ULONGLONG   SizeOfStackReserve;
        ULONGLONG   SizeOfStackCommit;
        ULONGLONG   SizeOfHeapReserve;
        ULONGLONG   SizeOfHeapCommit;
        DWORD       LoaderFlags;
        DWORD       NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };
    """

    class_: typing.ClassVar[java.lang.Class]


class BoundImportForwarderRef(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    A class to represent the 
    ``IMAGE_BOUND_FORWARDER_REF``
    data structure defined in **``winnt.h``**.
     
    typedef struct _IMAGE_BOUND_FORWARDER_REF {
        DWORD   TimeDateStamp;
        WORD    OffsetModuleName;
        WORD    Reserved;
    } IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_BOUND_FORWARDER_REF"
    """
    The name to use when converting into a structure data type.
    """

    IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF: typing.Final = 8
    """
    The size of the ``IMAGE_BOUND_FORWARDER_REF`` in bytes.
    """


    def getModuleName(self) -> str:
        """
        Returns the imported module name.
        
        :return: the imported module name
        :rtype: str
        """

    def getOffsetModuleName(self) -> int:
        """
        Returns the offset, relative the beginning of the Bound Import Table,
        to the import name.
        
        :return: the offset to the import name
        :rtype: int
        """

    def getReserved(self) -> int:
        """
        Returns the reserved word (use unknown).
        
        :return: the reserved word
        :rtype: int
        """

    def getTimeDateStamp(self) -> int:
        """
        Returns the time stamp.
        
        :return: the time stamp
        :rtype: int
        """

    @property
    def timeDateStamp(self) -> jpype.JInt:
        ...

    @property
    def offsetModuleName(self) -> jpype.JShort:
        ...

    @property
    def reserved(self) -> jpype.JShort:
        ...

    @property
    def moduleName(self) -> java.lang.String:
        ...


class PeMarkupable(java.lang.Object):
    """
    Common interface for standardizing the markup of a PE structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def markup(self, program: ghidra.program.model.listing.Program, isBinary: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog, ntHeader: NTHeader):
        """
        Marks up a PE structure.
        
        :param ghidra.program.model.listing.Program program: The program to markup.
        :param jpype.JBoolean or bool isBinary: True if the program is binary; otherwise, false.
        :param ghidra.util.task.TaskMonitor monitor: The monitor.
        :param ghidra.app.util.importer.MessageLog log: The log.
        :param NTHeader ntHeader: The PE's NT Header structure.
        :raises DuplicateNameException: 
        :raises CodeUnitInsertionException: 
        :raises IOException: 
        :raises MemoryAccessException:
        """


class ImportByName(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    A class to represent the ``IMAGE_IMPORT_BY_NAME``
    data structure defined in **``winnt.h``**.
    
     
    typedef struct _IMAGE_IMPORT_BY_NAME {
        WORD    Hint;
        BYTE    Name[1];
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_IMPORT_BY_NAME"

    def __init__(self, hint: typing.Union[jpype.JShort, int], name: typing.Union[java.lang.String, str]):
        """
        
        
        :param jpype.JShort or int hint: the import hint (ordinal)
        :param java.lang.String or str name: the name of the imported function.
        """

    def getHint(self) -> int:
        """
        
        
        :return: the export ordinal for the imported function
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns an ASCIIZ string with the name of the imported function.
        
        :return: an ASCIIZ string with the name of the imported function
        :rtype: str
        """

    def getSizeOf(self) -> int:
        """
        Returns the actual number of bytes consumed by this structure in memory.
        
        :return: the actual number of bytes consumed by this structure in memory
        :rtype: int
        """

    @property
    def sizeOf(self) -> jpype.JInt:
        ...

    @property
    def hint(self) -> jpype.JShort:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class DebugDataDirectory(DataDirectory):
    """
    Points to an array of IMAGE_DEBUG_DIRECTORY structures.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getParser(self) -> ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser:
        """
        Returns the debug parser used by this debug directory.
        
        :return: the debug parser used by this debug directory
        :rtype: ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser
        """

    @property
    def parser(self) -> ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser:
        ...


class ImportDescriptor(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    
    typedef struct _IMAGE_IMPORT_DESCRIPTOR {
        union {
            DWORD   Characteristics;            // 0 for terminating null import descriptor
            DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        };
        DWORD   TimeDateStamp;
        DWORD   ForwarderChain;                 // -1 if no forwarders
        DWORD   Name;
        DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
    }
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_IMPORT_DESCRIPTOR"
    SIZEOF: typing.Final = 20
    NOT_BOUND: typing.Final = 0

    def __init__(self):
        """
        Constructs a new import descriptor initialized to zero.
        """

    def getCharacteristics(self) -> int:
        """
        At one time, this may have been a set of flags. 
        However, Microsoft changed its meaning and 
        never bothered to update WINNT.H. 
        This field is really an offset (an RVA) to an 
        array of pointers. Each of these pointers points 
        to an IMAGE_IMPORT_BY_NAME structure.
        
        :return: an offset (an RVA) to an array of pointers
        :rtype: int
        """

    def getDLL(self) -> str:
        ...

    def getFirstThunk(self) -> int:
        """
        This field is an offset (an RVA) to an 
        IMAGE_THUNK_DATA union. In almost every case, 
        the union is interpreted as a pointer to an 
        IMAGE_IMPORT_BY_NAME structure. If the field 
        isn't one of these pointers, then it's supposedly 
        treated as an export ordinal value for the DLL 
        that's being imported. It's not clear from the 
        documentation if you really can import a function 
        by ordinal rather than by name.
        
        :return: an offset (an RVA) to an IMAGE_THUNK_DATA union
        :rtype: int
        """

    def getForwarderChain(self) -> int:
        """
        This field relates to forwarding. 
        Forwarding involves one DLL sending on 
        references to one of its functions to 
        another DLL. For example, in Windows NT, 
        NTDLL.DLL appears to forward some of its 
        exported functions to KERNEL32.DLL. An 
        application may think it's calling a function 
        in NTDLL.DLL, but it actually ends up calling 
        into KERNEL32.DLL. This field contains an index 
        into FirstThunk array (described momentarily). 
        The function indexed by this field will be 
        forwarded to another DLL. Unfortunately, the 
        format of how a function is forwarded isn't 
        documented, and examples of forwarded functions 
        are hard to find.
        
        :return: the forwarder chain
        :rtype: int
        """

    def getImportAddressTableThunkData(self) -> jpype.JArray[ThunkData]:
        """
        Returns the array of thunks from the import address table.
        
        :return: the array of thunks from the import address table
        :rtype: jpype.JArray[ThunkData]
        """

    def getImportNameTableThunkData(self) -> jpype.JArray[ThunkData]:
        """
        Returns the array of thunks from the import name table.
        
        :return: the array of thunks from the import name table
        :rtype: jpype.JArray[ThunkData]
        """

    def getName(self) -> int:
        """
        Returns an RVA to a NULL-terminated 
        ASCII string containing the imported 
        DLL's name. Common examples are 
        "KERNEL32.DLL" and "USER32.DLL".
        
        :return: an RVA to a NULL-terminated ASCII string
        :rtype: int
        """

    def getOriginalFirstThunk(self) -> int:
        """
        At one time, this may have been a set of flags. 
        However, Microsoft changed its meaning and 
        never bothered to update WINNT.H. 
        This field is really an offset (an RVA) to an 
        array of pointers. Each of these pointers points 
        to an IMAGE_IMPORT_BY_NAME structure.
        
        :return: an offset (an RVA) to an array of pointers
        :rtype: int
        """

    def getTimeDateStamp(self) -> int:
        """
        Returns the time/date stamp indicating when the file was built.
        
        :return: the time/date stamp indicating when the file was built
        :rtype: int
        """

    def isBound(self) -> bool:
        """
        Returns true if the import descriptor is bound to an imported library.
        Being bound implies that the import has the function's preferred address
        
        :return: true if the import descriptor is bound
        :rtype: bool
        """

    def isNullEntry(self) -> bool:
        """
        Checks to see if this descriptor is a null entry.  A null entry
        indicates that no more descriptors follow in the import table.
        
        :return: True if this descriptor is a null entry; otherwise, false.
        :rtype: bool
        """

    def setFirstThunk(self, i: typing.Union[jpype.JInt, int]):
        """
        Sets the first thunk to the specified value.
        
        :param jpype.JInt or int i: the new first thunk value.
        
        .. seealso::
        
            | :obj:`.getFirstThunk()`
        """

    def setForwarderChain(self, i: typing.Union[jpype.JInt, int]):
        """
        Sets the forwarder to the specified value.
        
        :param jpype.JInt or int i: the new forwarder value.
        
        .. seealso::
        
            | :obj:`.getForwarderChain()`
        """

    def setName(self, i: typing.Union[jpype.JInt, int]):
        """
        Sets the name to the specified value.
        
        :param jpype.JInt or int i: the new name value.
        
        .. seealso::
        
            | :obj:`.getName()`
        """

    def setOriginalFirstThunk(self, i: typing.Union[jpype.JInt, int]):
        """
        Sets the original first thunk to the specified value.
        
        :param jpype.JInt or int i: the new original first thunk value.
        
        .. seealso::
        
            | :obj:`.getOriginalFirstThunk()`
        """

    def setTimeDateStamp(self, i: typing.Union[jpype.JInt, int]):
        """
        Sets the time/date stamp to the specified value.
        
        :param jpype.JInt or int i: the new time/date stamp value.
        
        .. seealso::
        
            | :obj:`.getTimeDateStamp()`
        """

    @property
    def timeDateStamp(self) -> jpype.JInt:
        ...

    @timeDateStamp.setter
    def timeDateStamp(self, value: jpype.JInt):
        ...

    @property
    def importNameTableThunkData(self) -> jpype.JArray[ThunkData]:
        ...

    @property
    def originalFirstThunk(self) -> jpype.JInt:
        ...

    @originalFirstThunk.setter
    def originalFirstThunk(self, value: jpype.JInt):
        ...

    @property
    def characteristics(self) -> jpype.JInt:
        ...

    @property
    def firstThunk(self) -> jpype.JInt:
        ...

    @firstThunk.setter
    def firstThunk(self, value: jpype.JInt):
        ...

    @property
    def forwarderChain(self) -> jpype.JInt:
        ...

    @forwarderChain.setter
    def forwarderChain(self, value: jpype.JInt):
        ...

    @property
    def dLL(self) -> java.lang.String:
        ...

    @property
    def nullEntry(self) -> jpype.JBoolean:
        ...

    @property
    def bound(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> jpype.JInt:
        ...

    @name.setter
    def name(self, value: jpype.JInt):
        ...

    @property
    def importAddressTableThunkData(self) -> jpype.JArray[ThunkData]:
        ...


class DataDirectory(PeMarkupable):
    """
    An abstract base class to represent the
    ``IMAGE_DATA_DIRECTORY``
    data structure defined in **``winnt.h``**.
     
    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD   VirtualAddress;
        DWORD   Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY; {
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY: typing.Final = 8
    """
    The size of the data directory, in bytes.
    """


    def __init__(self):
        ...

    def getDirectoryName(self) -> str:
        ...

    def getPointer(self) -> int:
        ...

    def getSize(self) -> int:
        """
        Returns the size of this data directory.
        
        :return: the size of this data directory
        :rtype: int
        """

    def getVirtualAddress(self) -> int:
        """
        Returns the relative virtual address of this data directory.
        
        :return: the relative virtual address of this data directory
        :rtype: int
        """

    def hasParsedCorrectly(self) -> bool:
        ...

    def parse(self) -> bool:
        """
        Parses this data directory.
        
        :return: True if parsing completed successfully; otherwise, false.
        :rtype: bool
        :raises IOException: If there was an IO problem while parsing.
        """

    def setSize(self, size: typing.Union[jpype.JInt, int]):
        """
        Sets the size of this data directory.
        
        :param jpype.JInt or int size: the new size of this data directory
        """

    def setVirtualAddress(self, addr: typing.Union[jpype.JInt, int]):
        """
        Sets the relative virtual address of this data directory.
        
        :param jpype.JInt or int addr: the new relative virtual address
        """

    def writeBytes(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter, template: PortableExecutable):
        """
        Directories that are not contained inside of sections
        should override this method to write their bytes into the
        specified file.
        
        :param java.io.RandomAccessFile raf: the random access file used for output
        :param ghidra.util.DataConverter dc: the data converter for endianness
        :param PortableExecutable template: the original unadulterated PE
        :raises IOException: if an I/O error occurs
        """

    @property
    def pointer(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @size.setter
    def size(self, value: jpype.JInt):
        ...

    @property
    def virtualAddress(self) -> jpype.JInt:
        ...

    @virtualAddress.setter
    def virtualAddress(self, value: jpype.JInt):
        ...

    @property
    def directoryName(self) -> java.lang.String:
        ...


class FileHeader(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the IMAGE_FILE_HEADER struct as
    defined in ``winnt.h``.
     
    
     
    typedef struct _IMAGE_FILE_HEADER {
        WORD    Machine;                                // MANDATORY
        WORD    NumberOfSections;                    // USED
        DWORD   TimeDateStamp;
        DWORD   PointerToSymbolTable;
        DWORD   NumberOfSymbols;
        WORD    SizeOfOptionalHeader;                // USED
        WORD    Characteristics;                        // MANDATORY
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_FILE_HEADER"
    """
    The name to use when converting into a structure data type.
    """

    IMAGE_SIZEOF_FILE_HEADER: typing.Final = 20
    """
    The size of the ``IMAGE_FILE_HEADER`` in bytes.
    """

    IMAGE_FILE_RELOCS_STRIPPED: typing.Final = 1
    """
    Relocation info stripped from file.
    """

    IMAGE_FILE_EXECUTABLE_IMAGE: typing.Final = 2
    """
    File is executable (no unresolved externel references).
    """

    IMAGE_FILE_LINE_NUMS_STRIPPED: typing.Final = 4
    """
    Line nunbers stripped from file.
    """

    IMAGE_FILE_LOCAL_SYMS_STRIPPED: typing.Final = 8
    """
    Local symbols stripped from file.
    """

    IMAGE_FILE_AGGRESIVE_WS_TRIM: typing.Final = 16
    """
    Agressively trim working set
    """

    IMAGE_FILE_LARGE_ADDRESS_AWARE: typing.Final = 32
    """
    App can handle >2gb addresses
    """

    IMAGE_FILE_BYTES_REVERSED_LO: typing.Final = 128
    """
    Bytes of machine word are reversed.
    """

    IMAGE_FILE_32BIT_MACHINE: typing.Final = 256
    """
    32 bit word machine.
    """

    IMAGE_FILE_DEBUG_STRIPPED: typing.Final = 512
    """
    Debugging info stripped from file in .DBG file
    """

    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: typing.Final = 1024
    """
    If Image is on removable media, copy and run from the swap file.
    """

    IMAGE_FILE_NET_RUN_FROM_SWAP: typing.Final = 2048
    """
    If Image is on Net, copy and run from the swap file.
    """

    IMAGE_FILE_SYSTEM: typing.Final = 4096
    """
    System File.
    """

    IMAGE_FILE_DLL: typing.Final = 8192
    """
    File is a DLL.
    """

    IMAGE_FILE_UP_SYSTEM_ONLY: typing.Final = 16384
    """
    File should only be run on a UP machine.
    """

    IMAGE_FILE_BYTES_REVERSED_HI: typing.Final = 32768
    """
    Bytes of machine word are reversed.
    """

    CHARACTERISTICS: typing.Final[jpype.JArray[java.lang.String]]
    IMAGE_FILE_MACHINE_MASK: typing.Final = 65535
    """
    Values for the Machine field indicating the intended processor architecture
    """

    IMAGE_FILE_MACHINE_UNKNOWN: typing.Final = 0
    IMAGE_FILE_MACHINE_AM33: typing.Final = 467
    IMAGE_FILE_MACHINE_AMD64: typing.Final = 34404
    IMAGE_FILE_MACHINE_ARM: typing.Final = 448
    IMAGE_FILE_MACHINE_ARM64: typing.Final = 43620
    IMAGE_FILE_MACHINE_ARMNT: typing.Final = 452
    IMAGE_FILE_MACHINE_EBC: typing.Final = 3772
    IMAGE_FILE_MACHINE_I386: typing.Final = 332
    IMAGE_FILE_MACHINE_IA64: typing.Final = 512
    IMAGE_FILE_MACHINE_M32R: typing.Final = 36929
    IMAGE_FILE_MACHINE_MIPS16: typing.Final = 614
    IMAGE_FILE_MACHINE_MIPSFPU: typing.Final = 870
    IMAGE_FILE_MACHINE_MIPSFPU16: typing.Final = 1126
    IMAGE_FILE_MACHINE_POWERPC: typing.Final = 496
    IMAGE_FILE_MACHINE_POWERPCFP: typing.Final = 497
    IMAGE_FILE_MACHINE_R4000: typing.Final = 358
    IMAGE_FILE_MACHINE_RISCV32: typing.Final = 20530
    IMAGE_FILE_MACHINE_RISCV64: typing.Final = 20580
    IMAGE_FILE_MACHINE_RISCV128: typing.Final = 20776
    IMAGE_FILE_MACHINE_SH3: typing.Final = 418
    IMAGE_FILE_MACHINE_SH3DSP: typing.Final = 419
    IMAGE_FILE_MACHINE_SH4: typing.Final = 422
    IMAGE_FILE_MACHINE_SH5: typing.Final = 424
    IMAGE_FILE_MACHINE_THUMB: typing.Final = 450
    IMAGE_FILE_MACHINE_WCEMIPSV2: typing.Final = 361

    def addSection(self, block: ghidra.program.model.mem.MemoryBlock, optionalHeader: OptionalHeader):
        """
        Adds a new section to this file header. Uses the given memory block
        as the section template. The section will have the memory block's name, start address,
        size, etc. The optional header is needed to determine the free byte position in the
        file.
        
        :param ghidra.program.model.mem.MemoryBlock block: the memory block template
        :param OptionalHeader optionalHeader: the related optional header
        :raises RuntimeException: if the memory block is uninitialized
        """

    def getCharacteristics(self) -> int:
        """
        Returns a set of bit flags indicating attributes of the file.
        
        :return: a set of bit flags indicating attributes
        :rtype: int
        """

    def getMachine(self) -> int:
        """
        Returns the architecture type of the computer.
        
        :return: the architecture type of the computer
        :rtype: int
        """

    def getMachineName(self) -> str:
        """
        Returns a string representation of the architecture type of the computer.
        
        :return: a string representation of the architecture type of the computer
        :rtype: str
        """

    def getNumberOfSections(self) -> int:
        """
        Returns the number of sections.
        Sections equate to Ghidra memory blocks.
        
        :return: the number of sections
        :rtype: int
        """

    def getNumberOfSymbols(self) -> int:
        """
        Returns the number of symbols in the COFF symbol table
        
        :return: the number of symbols in the COFF symbol table
        :rtype: int
        """

    def getPointerToSections(self) -> int:
        """
        Returns the file pointer to the section headers.
        
        :return: the file pointer to the section headers
        :rtype: int
        """

    def getPointerToSymbolTable(self) -> int:
        """
        Returns the file offset of the COFF symbol table
        
        :return: the file offset of the COFF symbol table
        :rtype: int
        """

    @typing.overload
    def getSectionHeader(self, index: typing.Union[jpype.JInt, int]) -> SectionHeader:
        """
        Returns the section header at the specified position in the array.
        
        :param jpype.JInt or int index: index of section header to return
        :return: the section header at the specified position in the array, or null if invalid
        :rtype: SectionHeader
        """

    @typing.overload
    def getSectionHeader(self, name: typing.Union[java.lang.String, str]) -> SectionHeader:
        """
        Get the first section header defined with the specified name
        
        :param java.lang.String or str name: section name
        :return: first section header defined with the specified name or null if not found
        :rtype: SectionHeader
        """

    def getSectionHeaderContaining(self, virtualAddr: typing.Union[jpype.JInt, int]) -> SectionHeader:
        """
        Returns the section header that contains the specified virtual address.
        
        :param jpype.JInt or int virtualAddr: the virtual address
        :return: the section header that contains the specified virtual address
        :rtype: SectionHeader
        """

    def getSectionHeaders(self) -> jpype.JArray[SectionHeader]:
        """
        Returns the array of section headers.
        
        :return: the array of section headers
        :rtype: jpype.JArray[SectionHeader]
        """

    def getSizeOfOptionalHeader(self) -> int:
        """
        Returns the size of the optional header data
        
        :return: the size of the optional header, in bytes
        :rtype: int
        """

    def getSymbols(self) -> java.util.List[ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol]:
        """
        Returns the array of symbols.
        
        :return: the array of symbols
        :rtype: java.util.List[ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol]
        """

    def getTimeDateStamp(self) -> int:
        """
        Returns the time stamp of the image.
        
        :return: the time stamp of the image
        :rtype: int
        """

    def isLordPE(self) -> bool:
        ...

    @property
    def timeDateStamp(self) -> jpype.JInt:
        ...

    @property
    def characteristics(self) -> jpype.JInt:
        ...

    @property
    def sizeOfOptionalHeader(self) -> jpype.JInt:
        ...

    @property
    def pointerToSymbolTable(self) -> jpype.JInt:
        ...

    @property
    def numberOfSections(self) -> jpype.JInt:
        ...

    @property
    def symbols(self) -> java.util.List[ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol]:
        ...

    @property
    def pointerToSections(self) -> jpype.JInt:
        ...

    @property
    def machineName(self) -> java.lang.String:
        ...

    @property
    def sectionHeaders(self) -> jpype.JArray[SectionHeader]:
        ...

    @property
    def lordPE(self) -> jpype.JBoolean:
        ...

    @property
    def machine(self) -> jpype.JShort:
        ...

    @property
    def sectionHeader(self) -> SectionHeader:
        ...

    @property
    def numberOfSymbols(self) -> jpype.JInt:
        ...

    @property
    def sectionHeaderContaining(self) -> SectionHeader:
        ...


class BoundImportDataDirectory(DataDirectory):
    """
    Points to an array of IMAGE_BOUND_IMPORT_DESCRIPTORs.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addDescriptor(self, bid: BoundImportDescriptor):
        ...

    def getBoundImportDescriptors(self) -> jpype.JArray[BoundImportDescriptor]:
        """
        Returns the array of bound import descriptors defined in this bound import data directory.
        
        :return: the array of bound import descriptors defined in this bound import data directory
        :rtype: jpype.JArray[BoundImportDescriptor]
        """

    @property
    def boundImportDescriptors(self) -> jpype.JArray[BoundImportDescriptor]:
        ...


class PeUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def createData(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, datatype: ghidra.program.model.data.DataType, log: ghidra.app.util.importer.MessageLog) -> ghidra.program.model.listing.Data:
        ...

    @staticmethod
    @typing.overload
    def createData(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, datatype: ghidra.program.model.data.DataType, datatypeLength: typing.Union[jpype.JInt, int], log: ghidra.app.util.importer.MessageLog):
        ...

    @staticmethod
    def getMarkupAddress(program: ghidra.program.model.listing.Program, isBinary: typing.Union[jpype.JBoolean, bool], ntHeader: NTHeader, offset: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        ...


class DllCharacteristics(java.lang.Enum[DllCharacteristics]):

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_NO_SEH: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_NO_BIND: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_GUARD_CF: typing.Final[DllCharacteristics]
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: typing.Final[DllCharacteristics]

    def getAlias(self) -> str:
        ...

    def getDescription(self) -> str:
        ...

    def getMask(self) -> int:
        ...

    @staticmethod
    def resolveCharacteristics(value: typing.Union[jpype.JInt, int]) -> java.util.Set[DllCharacteristics]:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DllCharacteristics:
        ...

    @staticmethod
    def values() -> jpype.JArray[DllCharacteristics]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def alias(self) -> java.lang.String:
        ...

    @property
    def mask(self) -> jpype.JInt:
        ...


class ImportInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> int:
        """
        Returns the adjusted address where the import occurs.
        
        :return: the adjusted address where the import occurs
        :rtype: int
        """

    def getComment(self) -> str:
        """
        Returns a comment string containing extra information about the import.
        
        :return: a comment string containing extra information about the import
        :rtype: str
        """

    def getDLL(self) -> str:
        """
        Returns the name of the imported DLL.
        
        :return: the name of the imported DLL
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of the imported symbol.
        
        :return: the name of the imported symbol
        :rtype: str
        """

    def isBound(self) -> bool:
        """
        Returns true if this is a bound import.
        
        :return: true if this is a bound import
        :rtype: bool
        """

    @property
    def address(self) -> jpype.JInt:
        ...

    @property
    def dLL(self) -> java.lang.String:
        ...

    @property
    def bound(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...


class DelayImportDataDirectory(DataDirectory):
    """
    Points to the delayload information. 
    See DELAYIMP.H from Visual C++.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDelayImportDescriptors(self) -> jpype.JArray[DelayImportDescriptor]:
        """
        Returns the array of delay import descriptors defined in this delay import data directory.
        
        :return: the array of delay import descriptors defined in this delay import data directory
        :rtype: jpype.JArray[DelayImportDescriptor]
        """

    @property
    def delayImportDescriptors(self) -> jpype.JArray[DelayImportDescriptor]:
        ...


class RichHeader(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.Writeable):
    """
    The "Rich" header contains encoded metadata about the tool chain used to generate the binary.
    This class decodes and writes the Rich header (if it exists).
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_RICH_SIGNATURE: typing.Final = 1751345490
    IMAGE_DANS_SIGNATURE: typing.Final = 1399742788
    NAME: typing.Final = "IMAGE_RICH_HEADER"

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates the Rich header found from the given reader.  The reader should be
        positioned directly after the DOS header.
        
        :param ghidra.app.util.bin.BinaryReader reader: The reader to read the PE with.
        """

    def getMask(self) -> int:
        """
        Gets the Rich header mask.
        
        :return: the Rich header mask, or -1 if a Rich header was not found.
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Gets the offset of the Rich header.
        
        :return: the offset of the Rich header, or -1 if a Rich header was not found.
        :rtype: int
        """

    def getRecords(self) -> jpype.JArray[ghidra.app.util.bin.format.pe.rich.RichHeaderRecord]:
        """
        Gets the Rich header records.
        
        :return: the Rich header records.  Could be empty if a Rich header was not found.
        :rtype: jpype.JArray[ghidra.app.util.bin.format.pe.rich.RichHeaderRecord]
        """

    def getSize(self) -> int:
        """
        Gets the size of the Rich header.
        
        :return: the size of the Rich header.  Will be 0 if a Rich header was not found.
        :rtype: int
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def records(self) -> jpype.JArray[ghidra.app.util.bin.format.pe.rich.RichHeaderRecord]:
        ...

    @property
    def mask(self) -> jpype.JInt:
        ...


class ExportDataDirectory(DataDirectory, ghidra.app.util.bin.StructConverter):
    """
    A class to represent the ``IMAGE_EXPORT_DIRECTORY``
    data structure defined in **``winnt.h``**.
     
    typedef struct _IMAGE_EXPORT_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Name;
        DWORD   Base;
        DWORD   NumberOfFunctions;
        DWORD   NumberOfNames;
        DWORD   AddressOfFunctions;     // RVA from base of image
        DWORD   AddressOfNames;         // RVA from base of image
        DWORD   AddressOfNameOrdinals;  // RVA from base of image
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SIZEOF_EXPORT_DIRECTORY: typing.Final = 40
    """
    The size of the ``IMAGE_EXPORT_DIRECTORY`` in bytes.
    """


    def getAddressOfFunctions(self) -> int:
        ...

    def getAddressOfNameOrdinals(self) -> int:
        ...

    def getAddressOfNames(self) -> int:
        ...

    def getBase(self) -> int:
        ...

    def getCharacteristics(self) -> int:
        ...

    def getExportName(self) -> str:
        ...

    def getExports(self) -> jpype.JArray[ExportInfo]:
        """
        Returns an array of the exports defined in this export data directory.
        
        :return: an array of the exports defined in this export data directory
        :rtype: jpype.JArray[ExportInfo]
        """

    def getMajorVersion(self) -> int:
        ...

    def getMinorVersion(self) -> int:
        ...

    def getName(self) -> int:
        ...

    def getNumberOfFunctions(self) -> int:
        ...

    def getNumberOfNames(self) -> int:
        ...

    def getTimeDateStamp(self) -> int:
        ...

    @property
    def timeDateStamp(self) -> jpype.JInt:
        ...

    @property
    def characteristics(self) -> jpype.JInt:
        ...

    @property
    def addressOfFunctions(self) -> jpype.JInt:
        ...

    @property
    def numberOfFunctions(self) -> jpype.JInt:
        ...

    @property
    def exports(self) -> jpype.JArray[ExportInfo]:
        ...

    @property
    def name(self) -> jpype.JInt:
        ...

    @property
    def exportName(self) -> java.lang.String:
        ...

    @property
    def addressOfNames(self) -> jpype.JInt:
        ...

    @property
    def addressOfNameOrdinals(self) -> jpype.JInt:
        ...

    @property
    def numberOfNames(self) -> jpype.JInt:
        ...

    @property
    def minorVersion(self) -> jpype.JShort:
        ...

    @property
    def majorVersion(self) -> jpype.JShort:
        ...

    @property
    def base(self) -> jpype.JInt:
        ...


class TLSDataDirectory(DataDirectory):
    """
    Points to the Thread Local Storage initialization section.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getTLSDirectory(self) -> TLSDirectory:
        """
        Returns the thread local storage directory.
        
        :return: the thread local storage directory
        :rtype: TLSDirectory
        """

    @property
    def tLSDirectory(self) -> TLSDirectory:
        ...


class PortableExecutable(java.lang.Object):
    """
    A class to manage loading Portable Executables (PE).
    """

    class SectionLayout(java.lang.Enum[PortableExecutable.SectionLayout]):
        """
        Indicates how sections of this PE are laid out in the underlying ByteProvider.
        Use :obj:`SectionLayout.FILE` when loading from a file, and :obj:`SectionLayout.MEMORY` when
        loading from a memory model (like an already-loaded program in Ghidra).
        """

        class_: typing.ClassVar[java.lang.Class]
        FILE: typing.Final[PortableExecutable.SectionLayout]
        """
        Indicates the sections of this PE are laid out as stored in a file.
        """

        MEMORY: typing.Final[PortableExecutable.SectionLayout]
        """
        Indicates the sections of this PE are laid out as loaded into memory
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PortableExecutable.SectionLayout:
            ...

        @staticmethod
        def values() -> jpype.JArray[PortableExecutable.SectionLayout]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "PORTABLE_EXECUTABLE"
    DEBUG: typing.ClassVar[jpype.JBoolean]

    @typing.overload
    def __init__(self, bp: ghidra.app.util.bin.ByteProvider, layout: PortableExecutable.SectionLayout):
        """
        Constructs a new Portable Executable using the specified byte provider and layout.
          
        
        Same as calling ``createFileAlignedPortableExecutable(factory, bp, layout, true, false)``
        
        :param ghidra.app.util.bin.ByteProvider bp: the byte provider
        :param PortableExecutable.SectionLayout layout: specifies the layout of the underlying provider and governs RVA resolution
        :raises IOException: if an I/O error occurs.
        
        .. seealso::
        
            | :obj:`.PortableExecutable(ByteProvider, SectionLayout, boolean, boolean)`
        """

    @typing.overload
    def __init__(self, bp: ghidra.app.util.bin.ByteProvider, layout: PortableExecutable.SectionLayout, advancedProcess: typing.Union[jpype.JBoolean, bool], parseCliHeaders: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new Portable Executable using the specified byte provider and layout.
        
        :param ghidra.app.util.bin.ByteProvider bp: the byte provider
        :param PortableExecutable.SectionLayout layout: specifies the layout of the underlying provider and governs RVA resolution
        :param jpype.JBoolean or bool advancedProcess: if true, the data directories are also processed
        :param jpype.JBoolean or bool parseCliHeaders: if true, CLI headers are parsed (if present)
        :raises IOException: if an I/O error occurs.
        """

    @staticmethod
    def computeAlignment(value: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getDOSHeader(self) -> ghidra.app.util.bin.format.mz.DOSHeader:
        """
        Returns the DOS header from the PE image.
        
        :return: the DOS header from the PE image
        :rtype: ghidra.app.util.bin.format.mz.DOSHeader
        """

    def getFileLength(self) -> int:
        ...

    def getNTHeader(self) -> NTHeader:
        """
        Returns the NT header from the PE image.
        
        :return: the NT header from the PE image
        :rtype: NTHeader
        """

    def getRichHeader(self) -> RichHeader:
        """
        Returns the Rich header from the PE image.
        
        :return: the Rich header from the PE image
        :rtype: RichHeader
        """

    def writeHeader(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter):
        ...

    @property
    def dOSHeader(self) -> ghidra.app.util.bin.format.mz.DOSHeader:
        ...

    @property
    def richHeader(self) -> RichHeader:
        ...

    @property
    def nTHeader(self) -> NTHeader:
        ...

    @property
    def fileLength(self) -> jpype.JLong:
        ...


class ResourceDataDirectory(DataDirectory):
    """
    Points to the root resource directory.
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY: typing.Final = 8
    """
    The size of a resource directory entry, in bytes.
    """

    IMAGE_SIZEOF_RESOURCE_DIRECTORY: typing.Final = 16
    """
    The size of a resource directory, in bytes.
    """

    IMAGE_RESOURCE_NAME_IS_STRING: typing.Final = -2147483648
    """
    A flag indicating that a resources is a string.
    """

    IMAGE_RESOURCE_DATA_IS_DIRECTORY: typing.Final = -2147483648
    """
    A flag indicating that a resources is a directory.
    """

    PREDEFINED_RESOURCE_NAMES: typing.Final[jpype.JArray[java.lang.String]]
    """
    A lookup table to obtain a string name for a resource type.
    """

    RT_NOTDEFINED: typing.Final = 0
    """
    Not defined in documentation but PNGs and WAVs are both this type
    """

    RT_CURSOR: typing.Final = 1
    """
    /**
    Hardware-dependent cursor resource.
    """

    RT_BITMAP: typing.Final = 2
    """
    Bitmap resource.
    """

    RT_ICON: typing.Final = 3
    """
    Hardware-dependent icon resource.
    """

    RT_MENU: typing.Final = 4
    """
    Menu resource.
    """

    RT_DIALOG: typing.Final = 5
    """
    Dialog box.
    """

    RT_STRING: typing.Final = 6
    """
    String-table entry.
    """

    RT_FONTDIR: typing.Final = 7
    """
    Font directory resource.
    """

    RT_FONT: typing.Final = 8
    """
    Font resource.
    """

    RT_ACCELERATOR: typing.Final = 9
    """
    Accelerator table.
    """

    RT_RCDATA: typing.Final = 10
    """
    Application-defined resource (raw data).
    """

    RT_MESSAGETABLE: typing.Final = 11
    """
    Message-table entry.
    """

    RT_GROUP_CURSOR: typing.Final = 12
    """
    Hardware-independent cursor resource.
    """

    RT_GROUP_ICON: typing.Final = 14
    """
    Hardware-independent icon resource.
    """

    RT_VERSION: typing.Final = 16
    """
    Version resource.
    """

    RT_DLGINCLUDE: typing.Final = 17
    RT_PLUGPLAY: typing.Final = 19
    """
    Plug and Play resource.
    """

    RT_VXD: typing.Final = 20
    """
    VXD resource.
    """

    RT_ANICURSOR: typing.Final = 21
    """
    Animated cursor resource.
    """

    RT_ANIICON: typing.Final = 22
    """
    Animated icon resource.
    """

    RT_HTML: typing.Final = 23
    """
    HTML resource.
    """

    RT_MANIFEST: typing.Final = 24
    """
    Manifest resource
    """

    directoryMap: typing.ClassVar[java.util.Set[java.lang.Integer]]

    @staticmethod
    def getPeResourceProperty(key: typing.Union[java.lang.String, str]) -> str:
        """
        Gets a program property name to represent PE resource property with the given key name
        
        :param java.lang.String or str key: The key name
        :return: A program property name to represent PE resource property with the given key name
        :rtype: str
        """

    def getResources(self) -> java.util.List[ghidra.app.util.bin.format.pe.resource.ResourceInfo]:
        ...

    def getRootDirectory(self) -> ghidra.app.util.bin.format.pe.resource.ResourceDirectory:
        ...

    @property
    def rootDirectory(self) -> ghidra.app.util.bin.format.pe.resource.ResourceDirectory:
        ...

    @property
    def resources(self) -> java.util.List[ghidra.app.util.bin.format.pe.resource.ResourceInfo]:
        ...


class OptionalHeaderROM(java.lang.Object):
    """
    A class to represent the IMAGE_ROM_OPTIONAL_HEADER 
    data structure.
     
    
     
    typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
        WORD   Magic;
        BYTE   MajorLinkerVersion;
        BYTE   MinorLinkerVersion;
        DWORD  SizeOfCode;
        DWORD  SizeOfInitializedData;
        DWORD  SizeOfUninitializedData;
        DWORD  AddressOfEntryPoint;
        DWORD  BaseOfCode;
        DWORD  BaseOfData;
        DWORD  BaseOfBss;
        DWORD  GprMask;
        DWORD  CprMask[4];
        DWORD  GpValue;
    } IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getAddressOfEntryPoint(self) -> int:
        ...

    def getBaseOfBss(self) -> int:
        ...

    def getBaseOfCode(self) -> int:
        ...

    def getBaseOfData(self) -> int:
        ...

    def getCprMask(self) -> jpype.JArray[jpype.JInt]:
        ...

    def getGpValue(self) -> int:
        ...

    def getGprMask(self) -> int:
        ...

    def getMagic(self) -> int:
        ...

    def getMajorLinkerVersion(self) -> int:
        ...

    def getMinorLinkerVersion(self) -> int:
        ...

    def getSizeOfCode(self) -> int:
        ...

    def getSizeOfInitializedData(self) -> int:
        ...

    def getSizeOfUninitializedData(self) -> int:
        ...

    @property
    def magic(self) -> jpype.JShort:
        ...

    @property
    def baseOfCode(self) -> jpype.JInt:
        ...

    @property
    def gpValue(self) -> jpype.JInt:
        ...

    @property
    def sizeOfUninitializedData(self) -> jpype.JInt:
        ...

    @property
    def cprMask(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def sizeOfCode(self) -> jpype.JInt:
        ...

    @property
    def minorLinkerVersion(self) -> jpype.JByte:
        ...

    @property
    def baseOfData(self) -> jpype.JInt:
        ...

    @property
    def baseOfBss(self) -> jpype.JInt:
        ...

    @property
    def addressOfEntryPoint(self) -> jpype.JInt:
        ...

    @property
    def majorLinkerVersion(self) -> jpype.JByte:
        ...

    @property
    def sizeOfInitializedData(self) -> jpype.JInt:
        ...

    @property
    def gprMask(self) -> jpype.JInt:
        ...


class OffsetValidator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def checkPointer(self, ptr: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def checkRVA(self, rva: typing.Union[jpype.JLong, int]) -> bool:
        ...


class DelayImportDescriptor(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the 
    ``ImgDelayDescr``
    data structure defined in **``DELAYIMP.H``**.
     
    typedef struct ImgDelayDescr {
        DWORD           grAttrs;        // attributes
        LPCSTR          szName;         // pointer to dll name
        HMODULE *       phmod;          // address of module handle
        PImgThunkData   pIAT;           // address of the IAT
        PCImgThunkData  pINT;           // address of the INT
        PCImgThunkData  pBoundIAT;      // address of the optional bound IAT
        PCImgThunkData  pUnloadIAT;     // address of optional copy of original IAT
        DWORD           dwTimeStamp;    // 0 if not bound,
                                        // O.W. date/time stamp of DLL bound to (old BIND)
    } ImgDelayDescr, * PImgDelayDescr;
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ImgDelayDescr"

    def getAddressOfBoundIAT(self) -> int:
        """
        Returns the address of the optional bound IAT.
        
        :return: the address of the optional bound IAT
        :rtype: int
        """

    def getAddressOfIAT(self) -> int:
        """
        Returns the address of the import address table.
        
        :return: the address of the import address table
        :rtype: int
        """

    def getAddressOfINT(self) -> int:
        """
        Returns the address of the import name table.
        
        :return: the address of the import name table
        :rtype: int
        """

    def getAddressOfModuleHandle(self) -> int:
        """
        Returns the address of the module handle.
        
        :return: the address of the module handle
        :rtype: int
        """

    def getAddressOfOriginalIAT(self) -> int:
        """
        Returns the address of the optional copy of original IAT.
        
        :return: the address of the optional copy of original IAT
        :rtype: int
        """

    def getAttibutes(self) -> int:
        """
        Returns the attributes.
        
        :return: the attributes
        :rtype: int
        """

    def getDLLName(self) -> str:
        """
        Returns the DLL name.
        
        :return: the DLL name
        :rtype: str
        """

    def getImportByNameMap(self) -> java.util.Map[ThunkData, ImportByName]:
        ...

    def getImportList(self) -> java.util.List[ImportInfo]:
        ...

    def getPointerToDLLName(self) -> int:
        """
        Returns the pointer to the DLL name.
        
        :return: the pointer to the DLL name
        :rtype: int
        """

    def getThunksBoundIAT(self) -> java.util.List[ThunkData]:
        ...

    def getThunksIAT(self) -> java.util.List[ThunkData]:
        ...

    def getThunksINT(self) -> java.util.List[ThunkData]:
        ...

    def getThunksUnloadIAT(self) -> java.util.List[ThunkData]:
        ...

    def getTimeStamp(self) -> int:
        """
        Returns the date/time stamp of DLL bound to (Old BIND),
        otherwise 0 if not bound.
        
        :return: if bound returns the time stamp, otherwise 0
        :rtype: int
        """

    def isUsingRVA(self) -> bool:
        """
        Returns true if the "using relative virtual address" is flag is set
        
        :return: true if the "using relative virtual address" is flag is set
        :rtype: bool
        """

    def isValid(self) -> bool:
        ...

    def sizeof(self) -> int:
        """
        Returns the size of this structure. It accounts for 32 vs 64 bit.
        
        :return: the size of this structure
        :rtype: int
        """

    @property
    def addressOfModuleHandle(self) -> jpype.JLong:
        ...

    @property
    def thunksIAT(self) -> java.util.List[ThunkData]:
        ...

    @property
    def importByNameMap(self) -> java.util.Map[ThunkData, ImportByName]:
        ...

    @property
    def addressOfIAT(self) -> jpype.JLong:
        ...

    @property
    def importList(self) -> java.util.List[ImportInfo]:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def timeStamp(self) -> jpype.JInt:
        ...

    @property
    def thunksUnloadIAT(self) -> java.util.List[ThunkData]:
        ...

    @property
    def attibutes(self) -> jpype.JInt:
        ...

    @property
    def addressOfOriginalIAT(self) -> jpype.JLong:
        ...

    @property
    def addressOfBoundIAT(self) -> jpype.JLong:
        ...

    @property
    def thunksBoundIAT(self) -> java.util.List[ThunkData]:
        ...

    @property
    def usingRVA(self) -> jpype.JBoolean:
        ...

    @property
    def thunksINT(self) -> java.util.List[ThunkData]:
        ...

    @property
    def dLLName(self) -> java.lang.String:
        ...

    @property
    def addressOfINT(self) -> jpype.JLong:
        ...

    @property
    def pointerToDLLName(self) -> jpype.JLong:
        ...


class SecurityCertificate(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the ``WIN_CERTIFICATE``
    struct as defined in **``winbase.h``**.
     
    
    This structure encapsulates a signature used in verifying executables.
     
    typedef struct _WIN_CERTIFICATE {
        DWORD       dwLength;
        WORD        wRevision;
        WORD        wCertificateType;   // WIN_CERT_TYPE_xxx
        BYTE        bCertificate[ANYSIZE_ARRAY];
    } WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "WIN_CERTIFICATE"
    """
    The name to use when converting into a structure data type.
    """

    WIN_CERT_REVISION_1_0: typing.Final = 256
    WIN_CERT_REVISION_2_0: typing.Final = 512
    WIN_CERT_TYPE_X509: typing.Final = 1
    """
    bCertificate contains an X.509 Certificate.
    """

    WIN_CERT_TYPE_PKCS_SIGNED_DATA: typing.Final = 2
    """
    bCertificate contains a PKCS SignedData structure.
    """

    WIN_CERT_TYPE_RESERVED_1: typing.Final = 3
    """
    Reserved.
    """

    WIN_CERT_TYPE_PKCS1_SIGN: typing.Final = 9
    """
    bCertificate contains PKCS1_MODULE_SIGN fields.
    """


    def __init__(self):
        ...

    def getData(self) -> jpype.JArray[jpype.JByte]:
        """
        An array of certificates. The format of this member 
        depends on the value of wCertificateType.
        
        :return: an array of certificates
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getLength(self) -> int:
        """
        Returns the length, in bytes, of the signature.
        
        :return: the length, in bytes, of the signature
        :rtype: int
        """

    def getRevision(self) -> int:
        """
        Returns the certificate revision. Currently, 
        the only defined certificate revision is 
        WIN_CERT_REVISION_1_0 (0x0100).
        
        :return: the certificate revision
        :rtype: int
        """

    def getType(self) -> int:
        """
        Returns the certificate type.
        
        :return: the certificate type
        :rtype: int
        """

    def getTypeAsString(self) -> str:
        """
        Returns a string representation of the certificate type.
        
        :return: a string representation of the certificate type
        :rtype: str
        """

    @property
    def typeAsString(self) -> java.lang.String:
        ...

    @property
    def data(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def revision(self) -> jpype.JInt:
        ...


class PEx64UnwindInfoDataType(ghidra.program.model.data.DynamicDataType):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[PEx64UnwindInfoDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...


class NTHeader(ghidra.app.util.bin.StructConverter, OffsetValidator):
    """
    A class to represent the **``IMAGE_NT_HEADERS32``** and
    IMAGE_NT_HEADERS64 structs as defined in
    ``winnt.h``.
     
    typedef struct _IMAGE_NT_HEADERS {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF_SIGNATURE: typing.Final = 4
    """
    The size of the NT header signature.
    """

    MAX_SANE_COUNT: typing.Final = 65536

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int], layout: PortableExecutable.SectionLayout, advancedProcess: typing.Union[jpype.JBoolean, bool], parseCliHeaders: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new NT header.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :param jpype.JInt or int index: the index into the reader to the start of the NT header
        :param PortableExecutable.SectionLayout layout: The :obj:`SectionLayout`
        :param jpype.JBoolean or bool advancedProcess: if true, information outside of the base header will be processed
        :param jpype.JBoolean or bool parseCliHeaders: if true, CLI headers are parsed (if present)
        :raises InvalidNTHeaderException: if the bytes the specified index
        :raises IOException: if an IO-related exception occurred
        do not constitute an accurate NT header.
        """

    def getFileHeader(self) -> FileHeader:
        """
        Returns the file header.
        
        :return: the file header
        :rtype: FileHeader
        """

    def getName(self) -> str:
        """
        Returns the name to use when converting into a structure data type.
        
        :return: the name to use when converting into a structure data type
        :rtype: str
        """

    def getOptionalHeader(self) -> OptionalHeader:
        """
        Returns the optional header.
        
        :return: the optional header
        :rtype: OptionalHeader
        """

    def isRVAResoltionSectionAligned(self) -> bool:
        ...

    @typing.overload
    def rvaToPointer(self, rva: typing.Union[jpype.JInt, int]) -> int:
        """
        Converts a relative virtual address (RVA) into a pointer.
        
        :param jpype.JInt or int rva: the relative virtual address
        :return: the pointer into binary image, 0 if not valid
        :rtype: int
        """

    @typing.overload
    def rvaToPointer(self, rva: typing.Union[jpype.JLong, int]) -> int:
        """
        Converts a relative virtual address (RVA) into a pointer.
        
        :param jpype.JLong or int rva: the relative virtual address
        :return: the pointer into binary image, -1 if not valid
        :rtype: int
        """

    @typing.overload
    def vaToPointer(self, va: typing.Union[jpype.JInt, int]) -> int:
        """
        Converts a virtual address (VA) into a pointer.
        
        :param jpype.JInt or int va: the virtual address
        :return: the pointer into binary image, 0 if not valid
        :rtype: int
        """

    @typing.overload
    def vaToPointer(self, va: typing.Union[jpype.JLong, int]) -> int:
        """
        Converts a virtual address (VA) into a pointer.
        
        :param jpype.JLong or int va: the virtual address
        :return: the pointer into binary image, 0 if not valid
        :rtype: int
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def optionalHeader(self) -> OptionalHeader:
        ...

    @property
    def fileHeader(self) -> FileHeader:
        ...

    @property
    def rVAResoltionSectionAligned(self) -> jpype.JBoolean:
        ...


class RichTable(java.lang.Object):
    """
    Top level object model of the :obj:`RichHeader`.  Stores an array of
    :obj:`RichHeaderRecord`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, buf: ghidra.program.model.mem.MemBuffer):
        ...

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getMask(self) -> int:
        ...

    def getOffset(self) -> int:
        ...

    def getRecords(self) -> jpype.JArray[ghidra.app.util.bin.format.pe.rich.RichHeaderRecord]:
        ...

    def getSize(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def records(self) -> jpype.JArray[ghidra.app.util.bin.format.pe.rich.RichHeaderRecord]:
        ...

    @property
    def mask(self) -> jpype.JInt:
        ...


class TLSDirectory(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the IMAGE_TLS_DIRECTORY32 and
    IMAGE_TLS_DIRECTORY64 data structures.
     
    
     
    typedef struct _IMAGE_TLS_DIRECTORY32 {
        DWORD   StartAddressOfRawData;
        DWORD   EndAddressOfRawData;
        DWORD   AddressOfIndex;             // PDWORD
        DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
        DWORD   SizeOfZeroFill;
        DWORD   Characteristics;
    } IMAGE_TLS_DIRECTORY32;
    typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;
     
     
    
     
    typedef struct _IMAGE_TLS_DIRECTORY64 {
        ULONGLONG   StartAddressOfRawData;
        ULONGLONG   EndAddressOfRawData;
        PDWORD      AddressOfIndex;
        PIMAGE_TLS_CALLBACK * AddressOfCallBacks;
        DWORD       SizeOfZeroFill;
        DWORD       Characteristics;
    } IMAGE_TLS_DIRECTORY64;
    typedef IMAGE_TLS_DIRECTORY64 * PIMAGE_TLS_DIRECTORY64;
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddressOfCallBacks(self) -> int:
        """
        
        
        :return: the address of an array of ``PIMAGE_TLS_CALLBACK`` function pointers
        :rtype: int
        """

    def getAddressOfIndex(self) -> int:
        """
        
        
        :return: the index to locate the thread local data.
        :rtype: int
        """

    def getCharacteristics(self) -> int:
        """
        Reserved, currently set to 0.
        
        :return: reserved, currently set to 0
        :rtype: int
        """

    def getEndAddressOfRawData(self) -> int:
        """
        Returns the ending address of the range of memory used to initialize a new thread's TLS data in memory.
        
        :return: the ending address of the range of memory used to initialize a new thread's TLS data in memory.
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of the structure.
        
        :return: the name of the structure
        :rtype: str
        """

    def getSizeOfZeroFill(self) -> int:
        """
        
        
        :return: the size in bytes of the initialization data
        :rtype: int
        """

    def getStartAddressOfRawData(self) -> int:
        """
        Returns the beginning address of a range of memory used to initialize a new thread's TLS data in memory.
        
        :return: the beginning address of a range of memory used to initialize a new thread's TLS data in memory.
        :rtype: int
        """

    @property
    def characteristics(self) -> jpype.JInt:
        ...

    @property
    def addressOfIndex(self) -> jpype.JLong:
        ...

    @property
    def startAddressOfRawData(self) -> jpype.JLong:
        ...

    @property
    def sizeOfZeroFill(self) -> jpype.JInt:
        ...

    @property
    def endAddressOfRawData(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def addressOfCallBacks(self) -> jpype.JLong:
        ...


class ImageRuntimeFunctionEntries_X86(ImageRuntimeFunctionEntries):
    """
    
    typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    DWORD EndAddress;
    union {
        DWORD UnwindInfoAddress;
        DWORD UnwindData;
    } DUMMYUNIONNAME;
    } RUNTIME_FUNCTION, *PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;
    
    #define UNW_FLAG_NHANDLER 0x0
    #define UNW_FLAG_EHANDLER 0x1
    #define UNW_FLAG_UHANDLER 0x2
    #define UNW_FLAG_CHAININFO 0x4
    
    typedef struct _UNWIND_INFO {
        UCHAR Version : 3;
        UCHAR Flags : 5;
        UCHAR SizeOfProlog;
        UCHAR CountOfUnwindCodes;
        UCHAR FrameRegister : 4;
        UCHAR FrameOffset : 4;
        UNWIND_CODE UnwindCode[1];
    
    //
    // The unwind codes are followed by an optional DWORD aligned field that
    // contains the exception handler address or the address of chained unwind
    // information. If an exception handler address is specified, then it is
    // followed by the language specified exception handler data.
    //
    //  union {
    //      ULONG ExceptionHandler;
    //      ULONG FunctionEntry;
    //  };
    //
    //  ULONG ExceptionData[];
    //
    } UNWIND_INFO, *PUNWIND_INFO;
    """

    @typing.type_check_only
    class ImageRuntimeFunctionEntry_X86(java.lang.Record):
        """
        Creates a new :obj:`ImageRuntimeFunctionEntries_X86`
        """

        class_: typing.ClassVar[java.lang.Class]

        def beginAddress(self) -> int:
            ...

        def endAddress(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def markup(self, program: ghidra.program.model.listing.Program):
            """
            Marks up this entry
            
            :param ghidra.program.model.listing.Program program: The :obj:`Program`
            :raises IOException: If there was an IO-related error creating the data
            :raises DuplicateNameException: If a data type of the same name already exists
            """

        def toString(self) -> str:
            ...

        def unwindInfo(self) -> PEx64UnwindInfo:
            ...

        def unwindInfoAddressOrData(self) -> int:
            ...


    class_: typing.ClassVar[java.lang.Class]


class SecurityDataDirectory(DataDirectory, ghidra.app.util.bin.ByteArrayConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getCertificate(self) -> jpype.JArray[SecurityCertificate]:
        """
        Returns an array of security certificates.
        
        :return: an array of security certificates
        :rtype: jpype.JArray[SecurityCertificate]
        """

    def getMarkupAddress(self, program: ghidra.program.model.listing.Program, isBinary: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        ...

    @property
    def certificate(self) -> jpype.JArray[SecurityCertificate]:
        ...


class ExportInfo(java.lang.Object):
    """
    A class to hold the information extracted from a 
    export data directory.
     
    NOTE:
    This class is simply a storage class created for 
    parsing the PE header data structures.
    It does not map back to a PE data data structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> int:
        """
        Returns the adjusted address where the export occurs.
        
        :return: the adjusted address where the export occurs
        :rtype: int
        """

    def getComment(self) -> str:
        """
        Returns a comment string containing extra information about the export.
        
        :return: a comment string containing extra information about the export
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of the export.
        
        :return: the name of the export
        :rtype: str
        """

    def getOrdinal(self) -> int:
        """
        Returns the ordinal value of the export.
        
        :return: the ordinal value of the export
        :rtype: int
        """

    def isForwarded(self) -> bool:
        """
        Returns true of this export is going to be forwarded.
        Generally, a forwarded export just through another export.
        
        :return: true of this export is going to be forwarded
        :rtype: bool
        """

    @property
    def address(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def forwarded(self) -> jpype.JBoolean:
        ...

    @property
    def ordinal(self) -> jpype.JInt:
        ...


class ImageCor20Header(ghidra.app.util.bin.StructConverter, PeMarkupable):
    """
    
    typedef struct IMAGE_COR20_HEADER
    {
        // Header versioning
        DWORD                   cb;                      // Size of the structure
        WORD                    MajorRuntimeVersion;     // Version of the CLR Runtime
        WORD                    MinorRuntimeVersion;     // Version of the CLR Runtime
    
        // Symbol table and startup information
        IMAGE_DATA_DIRECTORY    MetaData;                // A Data Directory giving RVA and Size of MetaData
        DWORD                   Flags;
        union {
        DWORD                 EntryPointRVA;           // Points to the .NET native EntryPoint method
        DWORD                 EntryPointToken;         // Points to the .NET IL EntryPoint method
        };
    
        // Binding information
        IMAGE_DATA_DIRECTORY    Resources;               // A Data Directory for Resources, which are referenced in the MetaData
        IMAGE_DATA_DIRECTORY    StrongNameSignature;     // A Data Directory for unique .NET assembly signatures
    
        // Regular fixup and binding information
        IMAGE_DATA_DIRECTORY    CodeManagerTable;        // Always 0
        IMAGE_DATA_DIRECTORY    VTableFixups;            // Not well documented VTable used by languages who don't follow the common type system runtime model
        IMAGE_DATA_DIRECTORY    ExportAddressTableJumps; // Always 0 in normal .NET assemblies, only present in native images
    
        // Precompiled image info (internal use only - set to zero)
        IMAGE_DATA_DIRECTORY    ManagedNativeHeader;
    
    };
    """

    class ImageCor20Flags(ghidra.program.model.data.EnumDataType):
        """
        Data type for :obj:`ImageCor20Header.flags`.
        """

        class_: typing.ClassVar[java.lang.Class]
        PATH: typing.Final = "/PE/CLI/Flags"
        COMIMAGE_FLAGS_ILONLY: typing.Final = 1
        COMIMAGE_FLAGS_32BITREQUIRED: typing.Final = 2
        COMIMAGE_FLAGS_IL_LIBRARY: typing.Final = 4
        COMIMAGE_FLAGS_STRONGNAMESIGNED: typing.Final = 8
        COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: typing.Final = 16
        COMIMAGE_FLAGS_TRACKDEBUGDATA: typing.Final = 65536

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getCb(self) -> int:
        """
        Gets the size of this structure in bytes.
        
        :return: The size of this structure in bytes.
        :rtype: int
        """

    def getCodeManagerTable(self) -> DefaultDataDirectory:
        """
        Gets the CodeManagerTable directory.
        
        :return: The CodeManagerTable directory.
        :rtype: DefaultDataDirectory
        """

    def getEntryPointToken(self) -> int:
        """
        Gets the entry point token.
        
        :return: The entry point token.
        :rtype: int
        """

    def getEntryPointVA(self) -> ghidra.program.model.address.Address:
        """
        Gets the entry point virtual address.
        
        :return: The entry point address.
        :rtype: ghidra.program.model.address.Address
        """

    def getExportAddressTableJumps(self) -> DefaultDataDirectory:
        """
        Gets the ExportAddressTableJumps directory.
        
        :return: The ExportAddressTableJumps directory.
        :rtype: DefaultDataDirectory
        """

    def getFlags(self) -> int:
        """
        Gets the flags.
        
        :return: The flags.
        :rtype: int
        """

    def getMajorRuntimeVersion(self) -> int:
        """
        Gets the major runtime version.
        
        :return: The major runtime version.
        :rtype: int
        """

    def getManagedNativeHeader(self) -> DefaultDataDirectory:
        """
        Gets the ManagedNativeHeader directory.
        
        :return: The ManagedNativeHeader directory.
        :rtype: DefaultDataDirectory
        """

    def getMetadata(self) -> ghidra.app.util.bin.format.pe.cli.CliMetadataDirectory:
        """
        Gets the MetaData directory.
        
        :return: The MetaData directory.
        :rtype: ghidra.app.util.bin.format.pe.cli.CliMetadataDirectory
        """

    def getMinorRuntimeVersion(self) -> int:
        """
        Gets the major runtime version.
        
        :return: The major runtime version.
        :rtype: int
        """

    def getResources(self) -> DefaultDataDirectory:
        """
        Gets the Resources directory.
        
        :return: The Resources directory.
        :rtype: DefaultDataDirectory
        """

    def getStrongNameSignature(self) -> DefaultDataDirectory:
        """
        Gets the StrongNameSignature directory.
        
        :return: The StrongNameSignature directory.
        :rtype: DefaultDataDirectory
        """

    def getVTableFixups(self) -> DefaultDataDirectory:
        """
        Gets the VTableFixups directory.
        
        :return: The VTableFixups directory.
        :rtype: DefaultDataDirectory
        """

    def parse(self) -> bool:
        """
        Parses this header
        
        :return: True if parsing completed successfully; otherwise, false.
        :rtype: bool
        :raises IOException: If there was an IO problem while parsing.
        """

    @property
    def vTableFixups(self) -> DefaultDataDirectory:
        ...

    @property
    def metadata(self) -> ghidra.app.util.bin.format.pe.cli.CliMetadataDirectory:
        ...

    @property
    def managedNativeHeader(self) -> DefaultDataDirectory:
        ...

    @property
    def entryPointToken(self) -> jpype.JInt:
        ...

    @property
    def exportAddressTableJumps(self) -> DefaultDataDirectory:
        ...

    @property
    def strongNameSignature(self) -> DefaultDataDirectory:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def entryPointVA(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def resources(self) -> DefaultDataDirectory:
        ...

    @property
    def minorRuntimeVersion(self) -> jpype.JShort:
        ...

    @property
    def codeManagerTable(self) -> DefaultDataDirectory:
        ...

    @property
    def majorRuntimeVersion(self) -> jpype.JShort:
        ...

    @property
    def cb(self) -> jpype.JInt:
        ...


class DefaultDataDirectory(DataDirectory, ghidra.app.util.bin.StructConverter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class MachineConstants(java.lang.Object):
    """
    PE machine ID constants defined by standard header file 'ntimage.h'
    
    
    .. seealso::
    
        | `Image File Machine Constants <https://msdn.microsoft.com/en-us/library/windows/desktop/mt804345%28v=vs.85%29.aspx>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_FILE_MACHINE_UNKNOWN: typing.Final = 0
    IMAGE_FILE_MACHINE_I386: typing.Final = 332
    IMAGE_FILE_MACHINE_R3000: typing.Final = 354
    IMAGE_FILE_MACHINE_R4000: typing.Final = 358
    IMAGE_FILE_MACHINE_R10000: typing.Final = 360
    IMAGE_FILE_MACHINE_WCEMIPSV2: typing.Final = 361
    IMAGE_FILE_MACHINE_ALPHA: typing.Final = 388
    IMAGE_FILE_MACHINE_SH3: typing.Final = 418
    IMAGE_FILE_MACHINE_SH3DSP: typing.Final = 419
    IMAGE_FILE_MACHINE_SH3E: typing.Final = 420
    IMAGE_FILE_MACHINE_SH4: typing.Final = 422
    IMAGE_FILE_MACHINE_SH5: typing.Final = 424
    IMAGE_FILE_MACHINE_ARM: typing.Final = 448
    IMAGE_FILE_MACHINE_THUMB: typing.Final = 450
    IMAGE_FILE_MACHINE_ARMNT: typing.Final = 452
    IMAGE_FILE_MACHINE_AM33: typing.Final = 467
    IMAGE_FILE_MACHINE_POWERPC: typing.Final = 496
    IMAGE_FILE_MACHINE_POWERPCFP: typing.Final = 497
    IMAGE_FILE_MACHINE_IA64: typing.Final = 512
    IMAGE_FILE_MACHINE_MIPS16: typing.Final = 614
    IMAGE_FILE_MACHINE_ALPHA64: typing.Final = 644
    IMAGE_FILE_MACHINE_MIPSFPU: typing.Final = 870
    IMAGE_FILE_MACHINE_MIPSFPU16: typing.Final = 1126
    IMAGE_FILE_MACHINE_TRICORE: typing.Final = 1312
    IMAGE_FILE_MACHINE_CEF: typing.Final = 3311
    IMAGE_FILE_MACHINE_EBC: typing.Final = 3772
    IMAGE_FILE_MACHINE_AMD64: typing.Final = -31132
    IMAGE_FILE_MACHINE_M32R: typing.Final = -28607
    IMAGE_FILE_MACHINE_ARM64: typing.Final = -21916
    IMAGE_FILE_MACHINE_CEE: typing.Final = -16146
    IMAGE_FILE_MACHINE_AXP64: typing.Final = 644

    def __init__(self):
        ...


class BaseRelocation(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    A class to represent the ``IMAGE_BASE_RELOCATION``
    data structure defined in **``winnt.h``**.
     
    typedef struct _IMAGE_BASE_RELOCATION {
        DWORD   VirtualAddress;
        DWORD   SizeOfBlock;
    //  WORD    TypeOffset[1];
    } IMAGE_BASE_RELOCATION;
    typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
    """

    @typing.type_check_only
    class TypeOffset(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_BASE_RELOCATION"
    """
    The name to use when converting into a structure data type.
    """

    IMAGE_SIZEOF_BASE_RELOCATION: typing.Final = 8
    """
    The size of the ``IMAGE_BASE_RELOCATION`` in bytes.
    """

    IMAGE_REL_BASED_NOOP: typing.Final = 0
    IMAGE_REL_BASED_ABSOLUTE: typing.Final = 0
    IMAGE_REL_BASED_HIGH: typing.Final = 1
    IMAGE_REL_BASED_LOW: typing.Final = 2
    IMAGE_REL_BASED_HIGHLOW: typing.Final = 3
    IMAGE_REL_BASED_HIGHADJ: typing.Final = 4
    IMAGE_REL_BASED_MIPS_JMPADDR: typing.Final = 5
    IMAGE_REL_BASED_SECTION: typing.Final = 6
    IMAGE_REL_BASED_REL32: typing.Final = 7
    IMAGE_REL_BASED_MIPS_JMPADDR16: typing.Final = 9
    IMAGE_REL_BASED_IA64_IMM64: typing.Final = 9
    IMAGE_REL_BASED_DIR64: typing.Final = 10
    IMAGE_REL_BASED_HIGH3ADJ: typing.Final = 11
    TYPE_STRINGS: typing.Final[jpype.JArray[java.lang.String]]
    """
    Names of the available base relocations.
    """


    def addRelocation(self, type: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int]):
        """
        Adds a relocation to this base relocation block.
        
        :param jpype.JInt or int type: the relocation type
        :param jpype.JInt or int offset: the relocation offset
        """

    def getCount(self) -> int:
        """
        Returns the number of relocation in this block.
        
        :return: the number of relocation in this block
        :rtype: int
        """

    def getOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the lower 12 bits of the offset.
        
        :param jpype.JInt or int index: the ith relocation
        :return: int the offset of the relocation
        :rtype: int
        """

    def getSizeOfBlock(self) -> int:
        """
        Returns the size (in bytes) of this relocation block.
        
        :return: the size (in bytes) of this relocation block
        :rtype: int
        """

    def getType(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the upper 4 bits of the offset.
        
        :param jpype.JInt or int index: the ith relocation
        :return: int the type of the relocation
        ,
        :rtype: int
        """

    def getVirtualAddress(self) -> int:
        """
        Returns the base address of the relocations in this block.
        
        :return: the base address of the relocations in this block
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def virtualAddress(self) -> jpype.JInt:
        ...

    @property
    def sizeOfBlock(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...


class SeparateDebugHeader(OffsetValidator):
    """
    
    typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
        WORD        Signature;
        WORD        Flags;
        WORD        Machine;
        WORD        Characteristics;
        DWORD       TimeDateStamp;
        DWORD       CheckSum;
        DWORD       ImageBase;
        DWORD       SizeOfImage;
        DWORD       NumberOfSections;
        DWORD       ExportedNamesSize;
        DWORD       DebugDirectorySize;
        DWORD       SectionAlignment;
        DWORD       Reserved[2];
    } IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SEPARATE_DEBUG_SIGNATURE: typing.Final = 18756
    """
    The magic number for separate debug files.
    """

    IMAGE_SEPARATE_DEBUG_SIGNATURE_MAC: typing.Final = 17481
    """
    The magic number for separate debug files on MAC.
    """


    def __init__(self, bp: ghidra.app.util.bin.ByteProvider):
        """
        Constructs a new separate debug header using the specified byte provider.
        
        :param ghidra.app.util.bin.ByteProvider bp: the byte provider
        :raises IOException: if an I/O error occurs.
        """

    def getCharacteristics(self) -> int:
        """
        Returns the characteristics.
        
        :return: the characteristics
        :rtype: int
        """

    def getCheckSum(self) -> int:
        """
        Returns the check sum.
        
        :return: the check sum
        :rtype: int
        """

    def getDebugDirectorySize(self) -> int:
        """
        Returns the debug directory size.
        
        :return: the debug directory size
        :rtype: int
        """

    def getExportedNamesSize(self) -> int:
        """
        Returns the exported names size.
        
        :return: the exported names size
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        Returns the flags.
        
        :return: the flags
        :rtype: int
        """

    def getImageBase(self) -> int:
        """
        Returns the image base.
        
        :return: the image base
        :rtype: int
        """

    def getMachine(self) -> int:
        """
        Returns the machine type (or processor).
        
        :return: the machine type
        :rtype: int
        """

    def getMachineName(self) -> str:
        """
        Returns the machine name (or processor name).
        
        :return: the machine name
        :rtype: str
        """

    def getNumberOfSections(self) -> int:
        """
        Returns the number of sections.
        
        :return: the number of sections
        :rtype: int
        """

    def getParser(self) -> ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser:
        """
        Returns the debug directory parser.
        
        :return: the debug directory parser
        :rtype: ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser
        """

    def getReserved(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the reserved int array.
        
        :return: the reserved int array
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getSectionAlignment(self) -> int:
        """
        Returns the section alignment value.
        
        :return: the section alignment value
        :rtype: int
        """

    def getSignature(self) -> int:
        """
        Returns the signature (or magic number).
        
        :return: the signature
        :rtype: int
        """

    def getSizeOfImage(self) -> int:
        """
        Returns the size of the image.
        
        :return: the size of the image
        :rtype: int
        """

    def getTimeDateStamp(self) -> int:
        """
        Returns the time date stamp.
        
        :return: the time date stamp
        :rtype: int
        """

    @property
    def timeDateStamp(self) -> jpype.JInt:
        ...

    @property
    def sizeOfImage(self) -> jpype.JInt:
        ...

    @property
    def characteristics(self) -> jpype.JShort:
        ...

    @property
    def signature(self) -> jpype.JShort:
        ...

    @property
    def flags(self) -> jpype.JShort:
        ...

    @property
    def numberOfSections(self) -> jpype.JInt:
        ...

    @property
    def machineName(self) -> java.lang.String:
        ...

    @property
    def exportedNamesSize(self) -> jpype.JInt:
        ...

    @property
    def imageBase(self) -> jpype.JInt:
        ...

    @property
    def parser(self) -> ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser:
        ...

    @property
    def reserved(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def machine(self) -> jpype.JShort:
        ...

    @property
    def debugDirectorySize(self) -> jpype.JInt:
        ...

    @property
    def checkSum(self) -> jpype.JInt:
        ...

    @property
    def sectionAlignment(self) -> jpype.JInt:
        ...


class ControlFlowGuard(java.lang.Object):
    """
    ControlFlowGuard is a platform security feature that was created to combat memory
    corruption vulnerabilities.
     
    
    ReturnFlowGuard was introduced as an addition to ControlFlowGuard in the Windows 10
    Creator's update.
    """

    class_: typing.ClassVar[java.lang.Class]
    GuardCFFunctionTableName: typing.ClassVar[java.lang.String]
    GuardCFAddressTakenIatTableName: typing.ClassVar[java.lang.String]
    GuardCfgTableEntryName: typing.ClassVar[java.lang.String]

    def __init__(self):
        ...

    @staticmethod
    def markup(lcd: LoadConfigDirectory, program: ghidra.program.model.listing.Program, log: ghidra.app.util.importer.MessageLog, ntHeader: NTHeader):
        """
        Perform markup on the supported ControlFlowGuard and ReturnFlowGuard functions and 
        tables, if they exist.
        
        :param LoadConfigDirectory lcd: The PE LoadConfigDirectory.
        :param ghidra.program.model.listing.Program program: The program.
        :param ghidra.app.util.importer.MessageLog log: The log.
        :param NTHeader ntHeader: The PE NTHeader.
        """


class OptionalHeader(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: typing.Final = 32
    """
    ASLR with 64 bit address space.
    """

    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: typing.Final = 64
    """
    The DLL can be relocated at load time.
    """

    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: typing.Final = 128
    """
    Code integrity checks are forced.
    """

    IMAGE_DLLCHARACTERISTICS_NX_COMPAT: typing.Final = 256
    """
    The image is compatible with data execution prevention (DEP)
    """

    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: typing.Final = 512
    """
    The image is isolation aware, but should not be isolated.
    """

    IMAGE_DLLCHARACTERISTICS_NO_SEH: typing.Final = 1024
    """
    The image does not use structured exception handling (SEH).
    """

    IMAGE_DLLCHARACTERISTICS_NO_BIND: typing.Final = 2048
    """
    Do not bind the image.
    """

    IMAGE_DLLCHARACTERISTICS_APPCONTAINER: typing.Final = 4096
    """
    Image should execute in an AppContainer.
    """

    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: typing.Final = 8192
    """
    A WDM driver.
    """

    IMAGE_DLLCHARACTERISTICS_GUARD_CF: typing.Final = 16384
    """
    Image supports Control Flow Guard.
    """

    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: typing.Final = 32768
    """
    The image is terminal server aware.
    """

    IMAGE_NUMBEROF_DIRECTORY_ENTRIES: typing.Final = 16
    """
    The count of data directories in the optional header.
    """

    IMAGE_DIRECTORY_ENTRY_EXPORT: typing.Final = 0
    """
    Export directory index
    """

    IMAGE_DIRECTORY_ENTRY_IMPORT: typing.Final = 1
    """
    Import directory index
    """

    IMAGE_DIRECTORY_ENTRY_RESOURCE: typing.Final = 2
    """
    Resource directory index
    """

    IMAGE_DIRECTORY_ENTRY_EXCEPTION: typing.Final = 3
    """
    Exception directory index
    """

    IMAGE_DIRECTORY_ENTRY_SECURITY: typing.Final = 4
    """
    Security directory index
    """

    IMAGE_DIRECTORY_ENTRY_BASERELOC: typing.Final = 5
    """
    Base Relocation Table directory index
    """

    IMAGE_DIRECTORY_ENTRY_DEBUG: typing.Final = 6
    """
    Debug directory index
    """

    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: typing.Final = 7
    """
    Architecture Specific Data directory index
    """

    IMAGE_DIRECTORY_ENTRY_GLOBALPTR: typing.Final = 8
    """
    Global Pointer directory index
    """

    IMAGE_DIRECTORY_ENTRY_TLS: typing.Final = 9
    """
    TLS directory index
    """

    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: typing.Final = 10
    """
    Load Configuration directory index
    """

    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: typing.Final = 11
    """
    Bound Import directory  index
    """

    IMAGE_DIRECTORY_ENTRY_IAT: typing.Final = 12
    """
    Import Address Table directory index
    """

    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: typing.Final = 13
    """
    Delay Load Import Descriptors directory index
    """

    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: typing.Final = 14
    """
    COM Runtime Descriptor directory index
    """

    IMAGE_DIRECTORY_ENTRY_COMHEADER: typing.Final = 14
    """
    New name for the COM Descriptor directory index
    """


    def getAddressOfEntryPoint(self) -> int:
        """
        
        
        :return: the RVA of the first code byte in the file that will be executed
        :rtype: int
        """

    def getBaseOfCode(self) -> int:
        """
        Returns the RVA of the first byte of code when loaded in memory.
        
        :return: the RVA of the first byte of code when loaded in memory
        :rtype: int
        """

    def getBaseOfData(self) -> int:
        """
        
        
        :return: the RVA of the first byte of data when loaded into memory
        :rtype: int
        """

    def getChecksum(self) -> int:
        """
        Get the image file checksum.
        
        :return: 
        :rtype: int
        """

    def getDataDirectories(self) -> jpype.JArray[DataDirectory]:
        """
        Returns the array of data directories.
        
        :return: the array of data directories
        :rtype: jpype.JArray[DataDirectory]
        """

    def getDllCharacteristics(self) -> int:
        """
        Return flags that describe properties of and features of this binary.
        
        :return: 
        :rtype: int
        
        .. seealso::
        
            | :obj:`ghidra.app.util.bin.format.pe.DllCharacteristics`
        """

    def getFileAlignment(self) -> int:
        """
        
        
        :return: the file alignment
        :rtype: int
        """

    def getImageBase(self) -> int:
        """
        
        
        :return: the preferred load address of this file in memory
        :rtype: int
        """

    def getLoaderFlags(self) -> int:
        """
        Return the flags passed to the loader. Obsolete.
        
        :return: 
        :rtype: int
        """

    def getMajorImageVersion(self) -> int:
        """
        Get the major version number of the image.
        
        :return: 
        :rtype: int
        """

    def getMajorLinkerVersion(self) -> int:
        """
        Return the major version number of the linker that built this binary.
        
        :return: 
        :rtype: int
        """

    def getMajorOperatingSystemVersion(self) -> int:
        """
        Return the major version number of the required operating system.
        
        :return: 
        :rtype: int
        """

    def getMajorSubsystemVersion(self) -> int:
        """
        Get the major version number of the subsystem.
        """

    def getMinorImageVersion(self) -> int:
        """
        Get the minor version number of the image.
        
        :return: 
        :rtype: int
        """

    def getMinorLinkerVersion(self) -> int:
        """
        Return the minor version number of the linker that built this binary.
        
        :return: 
        :rtype: int
        """

    def getMinorOperatingSystemVersion(self) -> int:
        """
        Return the minor version number of the required operating system.
        
        :return: 
        :rtype: int
        """

    def getMinorSubsystemVersion(self) -> int:
        """
        Get the minor version number of the subsystem.
        
        :return: 
        :rtype: int
        """

    def getNumberOfRvaAndSizes(self) -> int:
        ...

    def getSectionAlignment(self) -> int:
        """
        
        
        :return: the section alignment
        :rtype: int
        """

    def getSizeOfCode(self) -> int:
        """
        Returns the combined total size of all sections with
        the ``IMAGE_SCN_CNT_CODE`` attribute.
        
        :return: the combined total size of all sections with
        the ``IMAGE_SCN_CNT_CODE`` attribute.
        :rtype: int
        """

    def getSizeOfHeaders(self) -> int:
        """
        
        
        :return: the combined size of all headers
        :rtype: int
        """

    def getSizeOfHeapCommit(self) -> int:
        """
        Return the size of the heap to commit
        
        :return: 
        :rtype: int
        """

    def getSizeOfHeapReserve(self) -> int:
        """
        Return the size of the heap reservation
        
        :return: 
        :rtype: int
        """

    def getSizeOfImage(self) -> int:
        """
        
        
        :return: the RVA that would be assigned to the next section following the last section
        :rtype: int
        """

    def getSizeOfInitializedData(self) -> int:
        """
        Returns the combined size of all initialized data sections.
        
        :return: the combined size of all initialized data sections
        :rtype: int
        """

    def getSizeOfStackCommit(self) -> int:
        """
        Return the size of the stack to commit
        
        :return: 
        :rtype: int
        """

    def getSizeOfStackReserve(self) -> int:
        """
        Return the size of the stack reservation
        
        :return: 
        :rtype: int
        """

    def getSizeOfUninitializedData(self) -> int:
        """
        Returns the size of all sections with the uninitialized
        data attributes.
        
        :return: the size of all sections with the uninitialized data attributes
        :rtype: int
        """

    def getSubsystem(self) -> int:
        """
        Get the subsystem that is required to run this image.
        
        :return: 
        :rtype: int
        """

    def getWin32VersionValue(self) -> int:
        """
        This value is reserved, and must be 0
        """

    def is64bit(self) -> bool:
        """
        Returns true of this optional header is 64-bit.
        
        :return: true of this optional header is 64-bit
        :rtype: bool
        """

    def isCLI(self) -> bool:
        """
        
        
        :return: true if the PE uses predominantly CLI code; otherwise, false.
        :rtype: bool
        """

    def processDataDirectories(self, monitor: ghidra.util.task.TaskMonitor):
        """
        This methods tells this optional header to process its data directories.
        """

    def setSizeOfCode(self, size: typing.Union[jpype.JLong, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`.getSizeOfCode()`
        """

    def setSizeOfHeaders(self, size: typing.Union[jpype.JLong, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`.getSizeOfHeaders()`
        """

    def setSizeOfImage(self, size: typing.Union[jpype.JLong, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`.getSizeOfImage()`
        """

    def setSizeOfInitializedData(self, size: typing.Union[jpype.JLong, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`.getSizeOfInitializedData()`
        """

    def setSizeOfUninitializedData(self, size: typing.Union[jpype.JLong, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`.getSizeOfUninitializedData()`
        """

    def validateDataDirectories(self, program: ghidra.program.model.listing.Program):
        ...

    def writeHeader(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter):
        """
        Writes this optional header to the specified random access file.
        
        :param java.io.RandomAccessFile raf: the random access file
        :param ghidra.util.DataConverter dc: the data converter
        :raises IOException:
        """

    @property
    def sizeOfStackReserve(self) -> jpype.JLong:
        ...

    @property
    def majorSubsystemVersion(self) -> jpype.JShort:
        ...

    @property
    def baseOfCode(self) -> jpype.JLong:
        ...

    @property
    def sizeOfCode(self) -> jpype.JLong:
        ...

    @sizeOfCode.setter
    def sizeOfCode(self, value: jpype.JLong):
        ...

    @property
    def minorSubsystemVersion(self) -> jpype.JShort:
        ...

    @property
    def baseOfData(self) -> jpype.JLong:
        ...

    @property
    def subsystem(self) -> jpype.JInt:
        ...

    @property
    def minorImageVersion(self) -> jpype.JShort:
        ...

    @property
    def majorImageVersion(self) -> jpype.JShort:
        ...

    @property
    def sizeOfHeaders(self) -> jpype.JLong:
        ...

    @sizeOfHeaders.setter
    def sizeOfHeaders(self, value: jpype.JLong):
        ...

    @property
    def majorLinkerVersion(self) -> jpype.JByte:
        ...

    @property
    def sizeOfInitializedData(self) -> jpype.JLong:
        ...

    @sizeOfInitializedData.setter
    def sizeOfInitializedData(self, value: jpype.JLong):
        ...

    @property
    def minorOperatingSystemVersion(self) -> jpype.JShort:
        ...

    @property
    def imageBase(self) -> jpype.JLong:
        ...

    @property
    def win32VersionValue(self) -> jpype.JInt:
        ...

    @property
    def loaderFlags(self) -> jpype.JInt:
        ...

    @property
    def checksum(self) -> jpype.JInt:
        ...

    @property
    def sectionAlignment(self) -> jpype.JInt:
        ...

    @property
    def sizeOfHeapReserve(self) -> jpype.JLong:
        ...

    @property
    def fileAlignment(self) -> jpype.JInt:
        ...

    @property
    def cLI(self) -> jpype.JBoolean:
        ...

    @property
    def sizeOfImage(self) -> jpype.JLong:
        ...

    @sizeOfImage.setter
    def sizeOfImage(self, value: jpype.JLong):
        ...

    @property
    def majorOperatingSystemVersion(self) -> jpype.JShort:
        ...

    @property
    def dataDirectories(self) -> jpype.JArray[DataDirectory]:
        ...

    @property
    def dllCharacteristics(self) -> jpype.JShort:
        ...

    @property
    def sizeOfHeapCommit(self) -> jpype.JLong:
        ...

    @property
    def sizeOfUninitializedData(self) -> jpype.JLong:
        ...

    @sizeOfUninitializedData.setter
    def sizeOfUninitializedData(self, value: jpype.JLong):
        ...

    @property
    def minorLinkerVersion(self) -> jpype.JByte:
        ...

    @property
    def numberOfRvaAndSizes(self) -> jpype.JLong:
        ...

    @property
    def addressOfEntryPoint(self) -> jpype.JLong:
        ...

    @property
    def sizeOfStackCommit(self) -> jpype.JLong:
        ...


class SectionHeader(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    A class to the represent the IMAGE_SECTION_HEADER
    struct as defined in ``winnt.h``.
     
    
     
    typedef struct _IMAGE_SECTION_HEADER {
        BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
                DWORD   PhysicalAddress;
                DWORD   VirtualSize;            // MANDATORY
        } Misc;
        DWORD   VirtualAddress;                // MANDATORY
        DWORD   SizeOfRawData;                // MANDATORY
        DWORD   PointerToRawData;                // MANDATORY
        DWORD   PointerToRelocations;
        DWORD   PointerToLinenumbers;
        WORD    NumberOfRelocations;
        WORD    NumberOfLinenumbers;
        DWORD   Characteristics;                // MANDATORY
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER; * 
     
     
    
    ``#define IMAGE_SIZEOF_SECTION_HEADER 40`` *
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_SECTION_HEADER"
    """
    The name to use when converting into a structure data type.
    """

    IMAGE_SIZEOF_SHORT_NAME: typing.Final = 8
    """
    The size of the section header short name.
    """

    IMAGE_SIZEOF_SECTION_HEADER: typing.Final = 40
    """
    The size of the section header.
    """

    IMAGE_SCN_CNT_CODE: typing.Final = 32
    """
    Section contains code.
    """

    IMAGE_SCN_CNT_INITIALIZED_DATA: typing.Final = 64
    """
    Section contains initialized data.
    """

    IMAGE_SCN_CNT_UNINITIALIZED_DATA: typing.Final = 128
    """
    Section contains uninitialized data.
    """

    IMAGE_SCN_LNK_INFO: typing.Final = 512
    """
    Section contains information for use by the linker. 
    Only exists in OBJs.
    """

    IMAGE_SCN_LNK_REMOVE: typing.Final = 2048
    """
    Section contents will not become part of the image. 
    This only appears in OBJ files.
    """

    IMAGE_SCN_LNK_COMDAT: typing.Final = 4096
    """
    Section contents is communal data (comdat). 
    Communal data is data (or code) that can be 
    defined in multiple OBJs. The linker will select 
    one copy to include in the executable. Comdats 
    are vital for support of C++ template functions 
    and function-level linking. Comdat sections only 
    appear in OBJ files.
    """

    IMAGE_SCN_NO_DEFER_SPEC_EXC: typing.Final = 16384
    """
    Reset speculative exceptions handling bits in the TLB entries for this section.
    """

    IMAGE_SCN_GPREL: typing.Final = 32768
    """
    Section content can be accessed relative to GP.
    """

    IMAGE_SCN_ALIGN_1BYTES: typing.Final = 1048576
    """
    Align on 1-byte boundary.
    """

    IMAGE_SCN_ALIGN_2BYTES: typing.Final = 2097152
    """
    Align on 2-byte boundary.
    """

    IMAGE_SCN_ALIGN_4BYTES: typing.Final = 3145728
    """
    Align on 4-byte boundary.
    """

    IMAGE_SCN_ALIGN_8BYTES: typing.Final = 4194304
    """
    Align on 8-byte boundary.
    """

    IMAGE_SCN_ALIGN_16BYTES: typing.Final = 5242880
    """
    Align on 16-byte boundary.
    """

    IMAGE_SCN_ALIGN_32BYTES: typing.Final = 6291456
    """
    Align on 32-byte boundary.
    """

    IMAGE_SCN_ALIGN_64BYTES: typing.Final = 7340032
    """
    Align on 64-byte boundary.
    """

    IMAGE_SCN_ALIGN_128BYTES: typing.Final = 8388608
    """
    Align on 128-byte boundary.
    """

    IMAGE_SCN_ALIGN_256BYTES: typing.Final = 9437184
    """
    Align on 256-byte boundary.
    """

    IMAGE_SCN_ALIGN_512BYTES: typing.Final = 10485760
    """
    Align on 512-byte boundary.
    """

    IMAGE_SCN_ALIGN_1024BYTES: typing.Final = 11534336
    """
    Align on 1024-byte boundary.
    """

    IMAGE_SCN_ALIGN_2048BYTES: typing.Final = 12582912
    """
    Align on 2048-byte boundary.
    """

    IMAGE_SCN_ALIGN_4096BYTES: typing.Final = 13631488
    """
    Align on 4096-byte boundary.
    """

    IMAGE_SCN_ALIGN_8192BYTES: typing.Final = 14680064
    """
    Align on 8192-byte boundary.
    """

    IMAGE_SCN_ALIGN_MASK: typing.Final = 15728640
    """
    Mask for alignment flags
    """

    IMAGE_SCN_LNK_NRELOC_OVFL: typing.Final = 16777216
    """
    Section contains extended relocations.
    """

    IMAGE_SCN_MEM_DISCARDABLE: typing.Final = 33554432
    """
    The section can be discarded from the final executable. 
    Used to hold information for the linker's use, 
    including the .debug$ sections.
    """

    IMAGE_SCN_MEM_NOT_CACHED: typing.Final = 67108864
    """
    Section is not cachable.
    """

    IMAGE_SCN_MEM_NOT_PAGED: typing.Final = 134217728
    """
    The section is not pageable, so it should 
    always be physically present in memory. 
    Often used for kernel-mode drivers.
    """

    IMAGE_SCN_MEM_SHARED: typing.Final = 268435456
    """
    Section is shareable. The physical pages containing this 
    section's data will be shared between all processes 
    that have this executable loaded. Thus, every process 
    will see the exact same values for data in this section. 
    Useful for making global variables shared between all 
    instances of a process. To make a section shared, 
    use the /section:name,S linker switch.
    """

    IMAGE_SCN_MEM_EXECUTE: typing.Final = 536870912
    """
    Section is executable.
    """

    IMAGE_SCN_MEM_READ: typing.Final = 1073741824
    """
    Section is readable.
    """

    IMAGE_SCN_MEM_WRITE: typing.Final = -2147483648
    """
    Section is writeable.
    """

    NOT_SET: typing.Final = -1

    def getCharacteristics(self) -> int:
        """
        Returns the flags OR'ed together, indicating the 
        attributes of this section. Many of these flags 
        can be set with the linker's /SECTION option. 
        Common values include those listed in Figure 7.
        
        :return: the flags OR'ed together, indicating the attributes of this section
        :rtype: int
        """

    def getDataStream(self) -> java.io.InputStream:
        """
        Returns an input stream to underlying bytes of this section.
        
        :return: an input stream to underlying bytes of this section
        :rtype: java.io.InputStream
        :raises IOException: if an i/o error occurs.
        """

    def getName(self) -> str:
        """
        Returns the ASCII name of the section. A 
        section name is not guaranteed to be 
        null-terminated. If you specify a section name 
        longer than eight characters, the linker 
        truncates it to eight characters in the 
        executable. A mechanism exists for allowing 
        longer section names in OBJ files. Section 
        names often start with a period, but this is 
        not a requirement. Section names with a $ in 
        the name get special treatment from the linker. 
        Sections with identical names prior to the $ 
        character are merged. The characters following 
        the $ provide an alphabetic ordering for how the 
        merged sections appear in the final section. 
        There's quite a bit more to the subject of sections 
        with $ in the name and how they're combined, but 
        the details are outside the scope of this article
        
        :return: the ASCII name of the section
        :rtype: str
        """

    def getNumberOfLinenumbers(self) -> int:
        """
        Returns the number of line numbers pointed to by the 
        NumberOfRelocations field.
        
        :return: the number of line numbers
        :rtype: int
        """

    def getNumberOfRelocations(self) -> int:
        """
        Returns the number of relocations pointed 
        to by the PointerToRelocations field.
        
        :return: the number of relocations
        :rtype: int
        """

    def getPhysicalAddress(self) -> int:
        """
        Returns the physical (file) address of this section.
        
        :return: the physical (file) address of this section
        :rtype: int
        """

    def getPointerToLinenumbers(self) -> int:
        """
        Return the file offset for COFF-style line 
        numbers for this section.
        
        :return: the file offset for COFF-style line numbers for this section
        :rtype: int
        """

    def getPointerToRawData(self) -> int:
        """
        Returns the file offset where the data 
        for the section begins. For executables, 
        this value must be a multiple of the file 
        alignment given in the PE header.
         
        
        If a section is uninitialized, this value will be 0.
        
        :return: the file offset where the data for the section begins
        :rtype: int
        """

    def getPointerToRelocations(self) -> int:
        """
        Returns the file offset of relocations for this section.
        
        :return: the file offset of relocations for this section
        :rtype: int
        """

    def getReadableName(self) -> str:
        """
        Returns a readable ascii version of the name.
        All non-readable characters
        are replaced with underscores.
        
        :return: a readable ascii version of the name
        :rtype: str
        """

    def getSizeOfRawData(self) -> int:
        """
        Returns the size (in bytes) of data stored for the section 
        in the executable or OBJ.
        
        :return: the size (in bytes) of data stored for the section
        :rtype: int
        """

    def getVirtualAddress(self) -> int:
        """
        In executables, returns the RVA where 
        the section begins in memory. Should be set to 0 in OBJs.
        this section should be loaded into memory.
        
        :return: the RVA where the section begins in memory.
        :rtype: int
        """

    def getVirtualSize(self) -> int:
        """
        Returns the actual, used size of the section. 
        This field may be larger or 
        smaller than the SizeOfRawData field. 
        If the VirtualSize is larger, the 
        SizeOfRawData field is the size of the 
        initialized data from the executable, 
        and the remaining bytes up to the VirtualSize 
        should be zero-padded. This field is set 
        to 0 in OBJ files.
        
        :return: the actual, used size of the section
        :rtype: int
        """

    @staticmethod
    def readSectionHeader(reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JLong, int], stringTableOffset: typing.Union[jpype.JLong, int]) -> SectionHeader:
        """
        Read a :obj:`SectionHeader` from the specified stream starting at ``index``.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` to read from
        :param jpype.JLong or int index: long offset in the reader where the section header starts
        :param jpype.JLong or int stringTableOffset: offset of the string table, or -1 if not available
        :return: new :obj:`SectionHeader`
        :rtype: SectionHeader
        :raises IOException: if error reading data
        """

    def setSizeOfRawData(self, size: typing.Union[jpype.JInt, int]):
        ...

    def setVirtualSize(self, size: typing.Union[jpype.JInt, int]):
        ...

    def writeBytes(self, raf: java.io.RandomAccessFile, rafIndex: typing.Union[jpype.JInt, int], dc: ghidra.util.DataConverter, block: ghidra.program.model.mem.MemoryBlock, useBlockBytes: typing.Union[jpype.JBoolean, bool]):
        """
        Writes the bytes from this section into the specified random access file.
        The bytes will be written starting at the byte position
        specified by ``getPointerToRawData()``.
        
        :param java.io.RandomAccessFile raf: the random access file
        :param jpype.JInt or int rafIndex: the index into the RAF where the bytes will be written
        :param ghidra.util.DataConverter dc: the data converter
        :param ghidra.program.model.mem.MemoryBlock block: the memory block corresponding to this section
        :param jpype.JBoolean or bool useBlockBytes: if true, then use the bytes from the memory block, 
                            otherwise use the bytes from this section.
        :raises IOException: if there are errors writing to the file
        :raises MemoryAccessException: if the byte from the memory block cannot be accesses
        """

    def writeHeader(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter):
        """
        Writes this section header to the specified random access file.
        
        :param java.io.RandomAccessFile raf: the random access file
        :param ghidra.util.DataConverter dc: the data converter
        :raises IOException: if an I/O error occurs
        """

    @property
    def pointerToRelocations(self) -> jpype.JInt:
        ...

    @property
    def sizeOfRawData(self) -> jpype.JInt:
        ...

    @sizeOfRawData.setter
    def sizeOfRawData(self, value: jpype.JInt):
        ...

    @property
    def readableName(self) -> java.lang.String:
        ...

    @property
    def characteristics(self) -> jpype.JInt:
        ...

    @property
    def pointerToLinenumbers(self) -> jpype.JInt:
        ...

    @property
    def virtualAddress(self) -> jpype.JInt:
        ...

    @property
    def numberOfLinenumbers(self) -> jpype.JShort:
        ...

    @property
    def virtualSize(self) -> jpype.JInt:
        ...

    @virtualSize.setter
    def virtualSize(self, value: jpype.JInt):
        ...

    @property
    def pointerToRawData(self) -> jpype.JInt:
        ...

    @property
    def dataStream(self) -> java.io.InputStream:
        ...

    @property
    def physicalAddress(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def numberOfRelocations(self) -> jpype.JShort:
        ...


class PeSubsystem(java.lang.Enum[PeSubsystem]):

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_SUBSYSTEM_UNKNOWN: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_NATIVE: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_WINDOWS_GUI: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_WINDOWS_CUI: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_OS2_CUI: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_POSIX_CUI: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_EFI_APPLICATION: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_EFI_ROM: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_XBOX: typing.Final[PeSubsystem]
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: typing.Final[PeSubsystem]

    def getAlias(self) -> str:
        ...

    def getDescription(self) -> str:
        ...

    def getValue(self) -> int:
        ...

    @staticmethod
    def parse(id: typing.Union[jpype.JInt, int]) -> PeSubsystem:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PeSubsystem:
        ...

    @staticmethod
    def values() -> jpype.JArray[PeSubsystem]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def alias(self) -> java.lang.String:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class BoundImportDescriptor(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    A class to represent the 
    ``IMAGE_BOUND_IMPORT_DESCRIPTOR``
    data structure defined in **``winnt.h``**.
     
    typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
        DWORD   TimeDateStamp;
        WORD    OffsetModuleName;
        WORD    NumberOfModuleForwarderRefs;
        // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
    } IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_BOUND_IMPORT_DESCRIPTOR"
    """
    The name to use when converting into a structure data type.
    """

    IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR: typing.Final = 8
    """
    The size of the ``IMAGE_BOUND_IMPORT_DESCRIPTOR`` in bytes.
    """


    def __init__(self, name: typing.Union[java.lang.String, str], timeDateStamp: typing.Union[jpype.JInt, int]):
        ...

    def getBoundImportForwarderRef(self, index: typing.Union[jpype.JInt, int]) -> BoundImportForwarderRef:
        """
        Returns the forwarder ref at the specified index
        
        :param jpype.JInt or int index: the index of the forwarder ref
        :return: the forwarder ref at the specified index
        :rtype: BoundImportForwarderRef
        """

    def getModuleName(self) -> str:
        """
        Returns the module name of the imported DLL.
        
        :return: the module name of the imported DLL
        :rtype: str
        """

    def getNumberOfModuleForwarderRefs(self) -> int:
        """
        Returns the number of IMAGE_BOUND_FORWARDER_REF 
        structures that immediately follow this structure.
        
        :return: the number of IMAGE_BOUND_FORWARDER_REF structures that immediately follow this structure
        :rtype: int
        """

    def getOffsetModuleName(self) -> int:
        """
        Returns an offset to a string with the name of the imported DLL.
        
        :return: an offset to a string with the name
        :rtype: int
        """

    def getTimeDateStamp(self) -> int:
        """
        Returns the time/data stamp of the imported DLL.
        
        :return: the time/data stamp of the imported DLL
        :rtype: int
        """

    @property
    def timeDateStamp(self) -> jpype.JInt:
        ...

    @property
    def numberOfModuleForwarderRefs(self) -> jpype.JShort:
        ...

    @property
    def offsetModuleName(self) -> jpype.JShort:
        ...

    @property
    def moduleName(self) -> java.lang.String:
        ...

    @property
    def boundImportForwarderRef(self) -> BoundImportForwarderRef:
        ...


class BaseRelocationDataDirectory(DataDirectory, ghidra.app.util.bin.ByteArrayConverter):
    """
    Points to the base relocation information.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addBaseRelocation(self, reloc: BaseRelocation):
        """
        Adds the specified base relocation.
        
        :param BaseRelocation reloc: the new base relocation
        """

    def createBaseRelocation(self, va: typing.Union[jpype.JInt, int]) -> BaseRelocation:
        """
        Create a new base relocation using the specified
        virtual address.
        
        :param jpype.JInt or int va: the virtual address of the new base relocation
        :return: the new base relocation
        :rtype: BaseRelocation
        """

    def getBaseRelocations(self) -> jpype.JArray[BaseRelocation]:
        """
        Returns the array of base relocations defined in this base relocation data directory.
        
        :return: the array of base relocations defined in this base relocation data directory
        :rtype: jpype.JArray[BaseRelocation]
        """

    def removeAllRelocations(self):
        """
        Removes all base relocations from this base relocation
        directory.
        """

    @property
    def baseRelocations(self) -> jpype.JArray[BaseRelocation]:
        ...


class LoadConfigDataDirectory(DataDirectory):

    class_: typing.ClassVar[java.lang.Class]

    def getLoadConfigDirectory(self) -> LoadConfigDirectory:
        """
        Returns the load config directory object defined in this data directory.
        
        :return: the load config directory object
        :rtype: LoadConfigDirectory
        """

    @property
    def loadConfigDirectory(self) -> LoadConfigDirectory:
        ...


class GlobalPointerDataDirectory(DataDirectory):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PEx64UnwindInfo(ghidra.app.util.bin.StructConverter):

    class UNWIND_CODE_OPCODE(java.lang.Enum[PEx64UnwindInfo.UNWIND_CODE_OPCODE]):

        class_: typing.ClassVar[java.lang.Class]
        UWOP_PUSH_NONVOL: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_ALLOC_LARGE: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_ALLOC_SMALL: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_SET_FPREG: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_SAVE_NONVOL: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_SAVE_NONVOL_FAR: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_SAVE_XMM: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_SAVE_XMM_FAR: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_SAVE_XMM128: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_SAVE_XMM128_FAR: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        UWOP_PUSH_MACHFRAME: typing.Final[PEx64UnwindInfo.UNWIND_CODE_OPCODE]
        id: typing.Final[jpype.JInt]

        @staticmethod
        def fromInt(id: typing.Union[jpype.JInt, int]) -> PEx64UnwindInfo.UNWIND_CODE_OPCODE:
            ...

        def id(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PEx64UnwindInfo.UNWIND_CODE_OPCODE:
            ...

        @staticmethod
        def values() -> jpype.JArray[PEx64UnwindInfo.UNWIND_CODE_OPCODE]:
            ...


    @typing.type_check_only
    class UNWIND_CODE(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, offset: typing.Union[jpype.JLong, int]):
        ...

    def hasChainedUnwindInfo(self) -> bool:
        ...

    def hasExceptionHandler(self) -> bool:
        ...

    def hasUnwindHandler(self) -> bool:
        ...


class COMDescriptorDataDirectory(DataDirectory):
    """
    This value has been renamed to IMAGE_DIRECTORY_ENTRY_COMHEADER.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getHeader(self) -> ImageCor20Header:
        ...

    @property
    def header(self) -> ImageCor20Header:
        ...



__all__ = ["ROMHeader", "InvalidNTHeaderException", "ImageRuntimeFunctionEntries_ARM", "Constants", "ImageRuntimeFunctionEntries", "LoadConfigDirectory", "ArchitectureDataDirectory", "ImportDataDirectory", "ExceptionDataDirectory", "ImportAddressTableDataDirectory", "ThunkData", "MachineName", "SectionFlags", "OptionalHeaderImpl", "BoundImportForwarderRef", "PeMarkupable", "ImportByName", "DebugDataDirectory", "ImportDescriptor", "DataDirectory", "FileHeader", "BoundImportDataDirectory", "PeUtils", "DllCharacteristics", "ImportInfo", "DelayImportDataDirectory", "RichHeader", "ExportDataDirectory", "TLSDataDirectory", "PortableExecutable", "ResourceDataDirectory", "OptionalHeaderROM", "OffsetValidator", "DelayImportDescriptor", "SecurityCertificate", "PEx64UnwindInfoDataType", "NTHeader", "RichTable", "TLSDirectory", "ImageRuntimeFunctionEntries_X86", "SecurityDataDirectory", "ExportInfo", "ImageCor20Header", "DefaultDataDirectory", "MachineConstants", "BaseRelocation", "SeparateDebugHeader", "ControlFlowGuard", "OptionalHeader", "SectionHeader", "PeSubsystem", "BoundImportDescriptor", "BaseRelocationDataDirectory", "LoadConfigDataDirectory", "GlobalPointerDataDirectory", "PEx64UnwindInfo", "COMDescriptorDataDirectory"]
