from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf
import ghidra.app.util.bin.format.dwarf.funcfixup
import ghidra.app.util.bin.format.elf.info
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class GoFunctionMultiReturn(java.lang.Object):
    """
    Handles creating a Ghidra structure to represent multiple return values returned from a golang
    function.
     
    
    Assigning custom storage for the return value is complicated by:
     
    * golang storage allocations depend on the formal ordering of the return values
    * stack storage must be last in a list of varnodes
    * the decompiler maps a structure's contents to the list of varnodes in an endian-dependent
    manner.
    
    To meet these complications, the structure's layout is modified to put all items that were
    marked as being stack parameters to either the front or back of the structure.
     
    
    To allow this artificial structure to adjusted by the user and reused at some later time
    to re-calculate the correct storage, the items in the structure are tagged with the original
    ordinal of that item as a text comment of each structure field, so that the correct ordering
    of items can be re-created when needed.
     
    
    If the structure layout is modified to conform to an arch's requirements, the structure's
    name will be modified to include that arch's description at the end (eg. "_x86_64")
    """

    @typing.type_check_only
    class StackComponentInfo(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def comment(self) -> str:
            ...

        def dtc(self) -> ghidra.program.model.data.DataTypeComponent:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def ordinal(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    MULTIVALUE_RETURNTYPE_SUFFIX: typing.Final = "_multivalue_return_type"
    SHORT_MULTIVALUE_RETURNTYPE_PREFIX: typing.Final = "multireturn{"
    SHORT_MULTIVALUE_RETURNTYPE_SUFFIX: typing.Final = "}"

    @typing.overload
    def __init__(self, categoryPath: ghidra.program.model.data.CategoryPath, returnParams: java.util.List[ghidra.app.util.bin.format.dwarf.DWARFVariable], dfunc: ghidra.app.util.bin.format.dwarf.DWARFFunction, dtm: ghidra.program.model.data.DataTypeManager, storageAllocator: GoParamStorageAllocator):
        ...

    @typing.overload
    def __init__(self, categoryPath: ghidra.program.model.data.CategoryPath, types: java.util.List[ghidra.program.model.data.DataType], dtm: ghidra.program.model.data.DataTypeManager, storageAllocator: GoParamStorageAllocator):
        ...

    @typing.overload
    def __init__(self, categoryPath: ghidra.program.model.data.CategoryPath, returnParams: jpype.JArray[ghidra.program.model.data.ParameterDefinition], dtm: ghidra.program.model.data.DataTypeManager, storageAllocator: GoParamStorageAllocator):
        ...

    @typing.overload
    def __init__(self, struct: ghidra.program.model.data.Structure, dtm: ghidra.program.model.data.DataTypeManager, storageAllocator: GoParamStorageAllocator):
        ...

    @staticmethod
    def fromStructure(dt: ghidra.program.model.data.DataType, dtm: ghidra.program.model.data.DataTypeManager, storageAllocator: GoParamStorageAllocator) -> GoFunctionMultiReturn:
        ...

    def getComponentsInOriginalOrder(self) -> java.util.List[ghidra.program.model.data.DataTypeComponent]:
        ...

    def getNormalStorageComponents(self) -> java.util.List[ghidra.program.model.data.DataTypeComponent]:
        ...

    def getStackStorageComponents(self) -> java.util.List[ghidra.program.model.data.DataTypeComponent]:
        ...

    def getStruct(self) -> ghidra.program.model.data.Structure:
        ...

    @staticmethod
    def isMultiReturnDataType(dt: ghidra.program.model.data.DataType) -> bool:
        ...

    @property
    def struct(self) -> ghidra.program.model.data.Structure:
        ...

    @property
    def normalStorageComponents(self) -> java.util.List[ghidra.program.model.data.DataTypeComponent]:
        ...

    @property
    def stackStorageComponents(self) -> java.util.List[ghidra.program.model.data.DataTypeComponent]:
        ...

    @property
    def componentsInOriginalOrder(self) -> java.util.List[ghidra.program.model.data.DataTypeComponent]:
        ...


class GoConstants(java.lang.Object):
    """
    Misc constant values for golang
    """

    class_: typing.ClassVar[java.lang.Class]
    GOLANG_CSPEC_NAME: typing.Final = "golang"
    GOLANG_CATEGORYPATH: typing.Final[ghidra.program.model.data.CategoryPath]
    """
    Category path to place golang types in
    """

    GOLANG_BOOTSTRAP_FUNCS_CATEGORYPATH: typing.Final[ghidra.program.model.data.CategoryPath]
    GOLANG_RECOVERED_TYPES_CATEGORYPATH: typing.Final[ghidra.program.model.data.CategoryPath]
    GOLANG_ABI_INTERNAL_CALLINGCONVENTION_NAME: typing.Final = "abi-internal"
    GOLANG_ABI0_CALLINGCONVENTION_NAME: typing.Final = "abi0"
    GOLANG_DUFFZERO_CALLINGCONVENTION_NAME: typing.Final = "duffzero"
    GOLANG_DUFFCOPY_CALLINGCONVENTION_NAME: typing.Final = "duffcopy"
    GOLANG_AUTOGENERATED_FILENAME: typing.Final = "<autogenerated>"
    GCWRITE_BUFFERED_VERS: typing.Final[GoVerRange]
    """
    Initial gcWriteBarrier scheme with signature ``func gcWriteBarrier(val,dest)``,
    x86-64 has gcWriteBarrierReg() variants.
    """

    GOLANG_GCWRITE_BUFFERED_CALLINGCONVENTION_NAME: typing.Final = "gcwrite_buffered"
    GCWRITE_BUFFERED_x86_64_Regs: typing.Final[java.util.List[java.lang.String]]
    GCWRITE_BATCH_VERS: typing.Final[GoVerRange]
    """
    Next gcWriteBarrier scheme with signature: ``func gcWriteBarrier[1-8]() uintptr``
    """

    GOLANG_GCWRITE_BATCH_CALLINGCONVENTION_NAME: typing.Final = "gcwrite_batch"
    GOLANG_RECEIVER_PARAM_NAME: typing.Final = "self"
    GOLANG_GENERICS_PARAM_NAME: typing.Final = "generics_dict"
    GOLANG_CLOSURE_CONTEXT_NAME: typing.Final = ".context"

    def __init__(self):
        ...


class GoBuildInfo(ghidra.app.util.bin.format.elf.info.ElfInfoItem):
    """
    A program section that contains Go build information strings, namely go module package names,
    go module dependencies, and build/compiler flags, as well as the golang version itself.
    """

    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME: typing.Final = "go.buildinfo"
    ELF_SECTION_NAME: typing.Final = ".go.buildinfo"
    MACHO_SECTION_NAME: typing.Final = "go_buildinfo"

    def decorateProgramInfo(self, props: ghidra.framework.options.Options):
        ...

    @staticmethod
    def findBuildInfo(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress[GoBuildInfo]:
        """
        Searches for the GoBuildInfo structure in the most common and easy locations.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to search
        :return: new :obj:`GoBuildInfo` instance, if present, null if missing or error
        :rtype: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress[GoBuildInfo]
        """

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> GoBuildInfo:
        """
        Reads a GoBuildInfo ".go.buildinfo" section from the specified Program, if present.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` that contains the ".go.buildinfo" section
        :return: new :obj:`GoBuildInfo` instance, if present, null if missing or error
        :rtype: GoBuildInfo
        """

    def getBuildSetting(self, key: typing.Union[java.lang.String, str]) -> GoBuildSettings:
        ...

    def getBuildSettings(self) -> java.util.List[GoBuildSettings]:
        ...

    def getDependencies(self) -> java.util.List[GoModuleInfo]:
        ...

    def getEndian(self) -> ghidra.program.model.lang.Endian:
        ...

    def getGOARCH(self, program: ghidra.program.model.listing.Program) -> str:
        """
        Returns the Golang Arch string for the specified program, either from previously parsed
        metadata value, or from a static Ghidra language to golang mapping.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: golang GOARCH string, see https://go.dev/doc/install/source#environment
        :rtype: str
        """

    def getGOOS(self, program: ghidra.program.model.listing.Program) -> str:
        """
        Returns the Golang OS string for the specified program, either from previously parsed
        metadata value, or from a static Ghidra-loader to golang mapping.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: golang GOOS string, see https://go.dev/doc/install/source#environment
        :rtype: str
        """

    def getGoVer(self) -> GoVer:
        ...

    def getModuleInfo(self) -> GoModuleInfo:
        ...

    def getPath(self) -> str:
        ...

    def getPointerSize(self) -> int:
        ...

    @staticmethod
    def getProgramGOARCH(program: ghidra.program.model.listing.Program) -> str:
        """
        Returns a Golang "GOARCH" string created by a mapping from the Ghidra program's language (arch).
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: Golang "GOARCH" string
        :rtype: str
        """

    @staticmethod
    def getProgramGOOS(program: ghidra.program.model.listing.Program) -> str:
        """
        Returns a Golang "GOOS" string created by a mapping from the Ghidra program's loader type.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: Golang "GOOS" string
        :rtype: str
        """

    def getVersion(self) -> str:
        ...

    @staticmethod
    def isPresent(is_: java.io.InputStream) -> bool:
        """
        Probes the specified InputStream and returns true if it starts with a go buildinfo magic
        signature.
        
        :param java.io.InputStream is: InputStream
        :return: true if starts with buildinfo magic signature
        :rtype: bool
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, program: ghidra.program.model.listing.Program) -> GoBuildInfo:
        """
        Reads a GoBuildInfo ".go.buildinfo" section from the specified stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: BinaryReader that contains the ".go.buildinfo" section
        :param ghidra.program.model.listing.Program program: Program that contains the ".go.buildinfo" section
        :return: new :obj:`GoBuildInfo` instance, never null
        :rtype: GoBuildInfo
        :raises IOException: if error reading or bad data
        """

    @property
    def buildSetting(self) -> GoBuildSettings:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def goVer(self) -> GoVer:
        ...

    @property
    def gOARCH(self) -> java.lang.String:
        ...

    @property
    def moduleInfo(self) -> GoModuleInfo:
        ...

    @property
    def buildSettings(self) -> java.util.List[GoBuildSettings]:
        ...

    @property
    def gOOS(self) -> java.lang.String:
        ...

    @property
    def version(self) -> java.lang.String:
        ...

    @property
    def pointerSize(self) -> jpype.JInt:
        ...

    @property
    def endian(self) -> ghidra.program.model.lang.Endian:
        ...

    @property
    def dependencies(self) -> java.util.List[GoModuleInfo]:
        ...


class GoBuildId(java.lang.Object):
    """
    This class represents a go build id string, along with a magic header.
     
    
    Similar to :obj:`NoteGoBuildId`, but re-implemented here because of the different
    serialization used.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buildId: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def findBuildId(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress[GoBuildId]:
        ...

    def getBuildId(self) -> str:
        ...

    def markupProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address):
        ...

    @staticmethod
    @typing.overload
    def read(br: ghidra.app.util.bin.BinaryReader, program_notused: ghidra.program.model.listing.Program) -> GoBuildId:
        """
        Attempts to read a GoBuildId from the specified stream.
        
        :param ghidra.app.util.bin.BinaryReader br: BinaryReader stream (typically the beginning of the ".text" section)
        :param ghidra.program.model.listing.Program program_notused: not used, but needed to match functional interface
        :return: GoBuildId instance, or null if not present
        :rtype: GoBuildId
        """

    @staticmethod
    @typing.overload
    def read(is_: java.io.InputStream) -> GoBuildId:
        """
        Attempts to read a GoBuildId from the specified InputStream (useful for early compiler
        detection before file is loaded).
        
        :param java.io.InputStream is: :obj:`InputStream` providing access to the ".text" section of a PE binary
        :return: GoBuildId instance, or null if not present
        :rtype: GoBuildId
        """

    @property
    def buildId(self) -> java.lang.String:
        ...


class GolangElfInfoProducer(ghidra.app.util.bin.format.elf.info.ElfInfoProducer):
    """
    Handles marking up and program info for Golang binaries.
     
    * NoteGoBuildId
    * GoBuildInfo
    *     
        * Go version
        * App path, main package
        * Module dependency list
        * Build settings / flags
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GoRegisterInfoManager(java.lang.Object):
    """
    XML config file format:
     
        <golang>
            <register_info versions="-1.2,1.3.3-1.4.2,1.8-"> // or "all"
                <int_registers list="RAX,RBX,RCX,RDI,RSI,R8,R9,R10,R11"/>
                <float_registers list="XMM0,XMM1,XMM2,XMM3,XMM4,XMM5,XMM6,XMM7,XMM8,XMM9,XMM10,XMM11,XMM12,XMM13,XMM14"/>
                <stack initialoffset="8" maxalign="8"/>
                <current_goroutine register="R14"/>
                <zero_register register="XMM15" builtin="true|false"/>
                <duffzero dest="RDI" zero_arg="XMM0" zero_type="float|int"/>
                <closurecontext register="RDX" />
            </register_info>
            <register_info versions="1.2">
                ...
            </register_info>
        </golang>
    """

    @typing.type_check_only
    class SingletonHolder(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getInstance() -> GoRegisterInfoManager:
        ...

    def getRegisterInfoForLang(self, lang: ghidra.program.model.lang.Language, goVer: GoVer) -> GoRegisterInfo:
        """
        Returns a :obj:`GoRegisterInfo` instance for the specified :obj:`Language`.
         
        
        If the language didn't define golang register info, a generic/empty instance will be
        returned that forces all parameters to be stack allocated.
        
        :param ghidra.program.model.lang.Language lang: :obj:`Language`
        :param GoVer goVer: :obj:`GoVer`
        :return: :obj:`GoRegisterInfo`, never null
        :rtype: GoRegisterInfo
        """


class GoFunctionFixup(java.lang.Object):
    """
    Utility class that fixes golang function parameter storage using each function's current
    parameter list (formal info only) as starting information.
     
    TODO: verify GoFuncData.argsize property against what we calculate here
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, func: ghidra.program.model.listing.Function, goVersion: GoVer):
        ...

    @typing.overload
    def __init__(self, func: ghidra.program.model.listing.Function, newSignature: ghidra.program.model.listing.FunctionSignature, newCallingConv: typing.Union[java.lang.String, str], storageAllocator: GoParamStorageAllocator):
        ...

    def apply(self):
        ...

    @staticmethod
    @typing.overload
    def isClosureContext(p: ghidra.program.model.data.ParameterDefinition) -> bool:
        ...

    @staticmethod
    @typing.overload
    def isClosureContext(p: ghidra.program.model.listing.Parameter) -> bool:
        ...

    @staticmethod
    def makeEmptyArrayDataType(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Returns a Ghidra data type that represents a zero-length array, to be used as a replacement
        for a zero-length array parameter.
        
        :param ghidra.program.model.data.DataType dt: data type that will donate its name to the created empty array type
        :return: :obj:`DataType` that represents a specific zero-length array type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def reverseNonStackStorageLocations(varnodes: java.util.List[ghidra.program.model.pcode.Varnode]):
        """
        Invert the order of the any register storage locations to match the decompiler's logic
        for assigning storage to structs that varies on endianness.
         
        
        Only valid for storage scheme that has all register storages listed first / contiguous.
        
        :param java.util.List[ghidra.program.model.pcode.Varnode] varnodes: list of :obj:`varnodes <Varnode>` that will be modified in-place
        """


class BootstrapInfoException(java.io.IOException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class GoParamStorageAllocator(java.lang.Object):
    """
    Logic and helper for allocating storage for a function's parameters and return value.
     
    
    Not threadsafe.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, goVersion: GoVer):
        """
        Creates a new golang function call storage allocator for the specified Ghidra Language.
         
        
        See :meth:`GoRegisterInfoManager.getRegisterInfoForLang(Language, GoVer) <GoRegisterInfoManager.getRegisterInfoForLang>`
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :param GoVer goVersion: version of go used to create the program
        """

    def alignStack(self):
        ...

    def alignStackFor(self, dt: ghidra.program.model.data.DataType):
        ...

    def getArchDescription(self) -> str:
        ...

    def getClosureContextRegister(self) -> ghidra.program.model.lang.Register:
        ...

    def getNextIntParamRegister(self, reg: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.Register:
        """
        Returns the integer parameter that follows the supplied register.
        
        :param ghidra.program.model.lang.Register reg: register in the integer reg list
        :return: the following register of the queried register, or null if no following register
        found
        :rtype: ghidra.program.model.lang.Register
        """

    @typing.overload
    def getRegistersFor(self, dt: ghidra.program.model.data.DataType) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Returns a list of :obj:`registers <Register>` that will successfully store the specified
        data type, as well as marking those registers as used and unavailable.
        
        :param ghidra.program.model.data.DataType dt: :obj:`DataType` to allocate register space for
        :return: list of :obj:`registers <Register>`, possibly empty if the data type was zero-length,
        possibly null if the data type is not compatible with register storage
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        """

    @typing.overload
    def getRegistersFor(self, dt: ghidra.program.model.data.DataType, allowEndianFixups: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Returns a list of :obj:`registers <Register>` that will successfully store the specified
        data type, as well as marking those registers as used and unavailable.
        
        :param ghidra.program.model.data.DataType dt: :obj:`DataType` to allocate register space for
        :param jpype.JBoolean or bool allowEndianFixups: boolean flag, if true the result (if it contains more than a single
        location) will automatically be adjusted in little endian programs to match how storage
        varnodes are laid-out, if false the result will not be adjusted
        :return: list of :obj:`registers <Register>`, possibly empty if the data type was zero-length,
        possibly null if the data type is not compatible with register storage
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        """

    def getStackAllocation(self, dt: ghidra.program.model.data.DataType) -> int:
        """
        Returns the stack offset that should be used to store the data type on the stack, as well
        as marking that stack area as used and unavailable.
        
        :param ghidra.program.model.data.DataType dt: :obj:`DataType` to allocate stack space for
        :return: offset in stack where the data item will be located
        :rtype: int
        """

    def getStackOffset(self) -> int:
        ...

    def isAbi0Mode(self) -> bool:
        ...

    def isBigEndian(self) -> bool:
        ...

    def resetRegAllocation(self):
        ...

    def setAbi0Mode(self):
        ...

    def setStackOffset(self, newStackOffset: typing.Union[jpype.JLong, int]):
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def abi0Mode(self) -> jpype.JBoolean:
        ...

    @property
    def closureContextRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def stackOffset(self) -> jpype.JLong:
        ...

    @stackOffset.setter
    def stackOffset(self, value: jpype.JLong):
        ...

    @property
    def nextIntParamRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def registersFor(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def archDescription(self) -> java.lang.String:
        ...

    @property
    def stackAllocation(self) -> jpype.JLong:
        ...


class GoModuleInfo(java.lang.Record):
    """
    Represents information about a single golang module dependency.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: typing.Union[java.lang.String, str], version: typing.Union[java.lang.String, str], sum: typing.Union[java.lang.String, str], replace: GoModuleInfo):
        ...

    def asKeyValuePairs(self, prefix: typing.Union[java.lang.String, str]) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Returns the values in this object as elements of a map.
        
        :param java.lang.String or str prefix: String prefix to put in front of each value name
        :return: map of String → String
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    @staticmethod
    def fromString(s: typing.Union[java.lang.String, str], replace: GoModuleInfo) -> GoModuleInfo:
        """
        Parses a GoModuleInfo from a formatted string "path[tab]version[tab]checksum".
        
        :param java.lang.String or str s: string to parse
        :param GoModuleInfo replace: GoModuleInfo that is the replacement for this module, or null if no 
        replacement specified
        :return: new GoModuleInfo instance, never null
        :rtype: GoModuleInfo
        :raises IOException: if error parsing string
        """

    def getFormattedString(self) -> str:
        """
        Returns a formatted version of the information in this instance.
        
        :return: formatted string
        :rtype: str
        """

    def hashCode(self) -> int:
        ...

    def path(self) -> str:
        ...

    def replace(self) -> GoModuleInfo:
        ...

    def sum(self) -> str:
        ...

    def toString(self) -> str:
        ...

    def version(self) -> str:
        ...

    @property
    def formattedString(self) -> java.lang.String:
        ...


class GoBuildSettings(java.lang.Record):
    """
    Key=value element of Golang Build settings
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    @staticmethod
    def fromString(s: typing.Union[java.lang.String, str]) -> GoBuildSettings:
        """
        Parses a "key=value" string and returns the parts as a :obj:`GoBuildSettings`.
        
        :param java.lang.String or str s: "key=value" string
        :return: new :obj:`GoBuildSettings` instance
        :rtype: GoBuildSettings
        :raises IOException: if error splitting the string into key and value
        """

    def hashCode(self) -> int:
        ...

    def key(self) -> str:
        ...

    def toString(self) -> str:
        ...

    def value(self) -> str:
        ...


class NoteGoBuildId(ghidra.app.util.bin.format.elf.info.ElfNote):
    """
    An ELF note that specifies the golang build-id.
    """

    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME: typing.Final = ".note.go.buildid"
    PROGRAM_INFO_KEY: typing.Final = "Golang BuildId"

    def __init__(self, nameLen: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], vendorType: typing.Union[jpype.JInt, int], description: jpype.JArray[jpype.JByte]):
        ...

    def getBuildId(self) -> str:
        """
        Returns the go buildid value
        
        :return: go buildid value
        :rtype: str
        """

    @staticmethod
    def read(br: ghidra.app.util.bin.BinaryReader, unusedProgram: ghidra.program.model.listing.Program) -> NoteGoBuildId:
        """
        Reads a NoteGoBuildId from the specified BinaryReader, matching the signature of 
        ElfInfoItem.ReaderFunc.
        
        :param ghidra.app.util.bin.BinaryReader br: BinaryReader
        :param ghidra.program.model.listing.Program unusedProgram: context (unused but needed to match signature)
        :return: new NoteGoBuildId instance, never null
        :rtype: NoteGoBuildId
        :raises IOException: if data error
        """

    @property
    def buildId(self) -> java.lang.String:
        ...


class GoVer(java.lang.Record, java.lang.Comparable[GoVer]):
    """
    Represents a Golang version number (major.minor.patch), with some special sentinel values
    for wildcarding.
    """

    class_: typing.ClassVar[java.lang.Class]
    GOLANG_VERSION_PROPERTY_NAME: typing.Final = "Golang go version"
    INVALID: typing.Final[GoVer]
    ANY: typing.Final[GoVer]

    def __init__(self, major: typing.Union[jpype.JInt, int], minor: typing.Union[jpype.JInt, int], patch: typing.Union[jpype.JInt, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    @staticmethod
    def fromProgramProperties(program: ghidra.program.model.listing.Program) -> GoVer:
        """
        Parses a version string found in a Ghidra program info properties list
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: :obj:`GoVer` instance, or INVALID, never null
        :rtype: GoVer
        """

    def getMajor(self) -> int:
        """
        Major value
        
        :return: major
        :rtype: int
        """

    def getMinor(self) -> int:
        """
        Minor value
        
        :return: minor
        :rtype: int
        """

    def getPatch(self) -> int:
        """
        Patch value
        
        :return: patch
        :rtype: int
        """

    def hashCode(self) -> int:
        ...

    def isInvalid(self) -> bool:
        ...

    def isWildcard(self) -> bool:
        ...

    def major(self) -> int:
        ...

    def minor(self) -> int:
        ...

    @staticmethod
    def parse(s: typing.Union[java.lang.String, str]) -> GoVer:
        """
        Parses a version string ("1.2.0") and returns a GoVer instance, or INVALID if bad data.
         
        
        Missing patch numbers will be defaulted to 0.
        
        :param java.lang.String or str s: string to parse, "1.2.3", or "1.2"
        :return: GoVer instance, or INVALID
        :rtype: GoVer
        """

    @staticmethod
    def parseWildcardPatch(s: typing.Union[java.lang.String, str]) -> GoVer:
        """
        Parses a version string ("1.2.0") and returns a GoVer instance, or INVALID if bad data.
         
        
        Missing patch numbers will be replaced with the wildcard value.
        
        :param java.lang.String or str s: string to parse, "1.2.3", or "1.2"
        :return: GoVer instance, or INVALID
        :rtype: GoVer
        """

    def patch(self) -> int:
        ...

    def prevPatch(self) -> GoVer:
        ...

    @staticmethod
    def setProgramPropertiesWithOriginalVersionString(props: ghidra.framework.options.Options, s: typing.Union[java.lang.String, str]):
        """
        Writes a version string to a Ghidra program info properties list.
        
        :param ghidra.framework.options.Options props: props from a program
        :param java.lang.String or str s: version string
        """

    def withPatch(self, newPatchNum: typing.Union[jpype.JInt, int]) -> GoVer:
        ...

    @property
    def invalid(self) -> jpype.JBoolean:
        ...

    @property
    def wildcard(self) -> jpype.JBoolean:
        ...


class GoRegisterInfo(java.lang.Object):
    """
    Immutable information about registers, alignment sizes, etc needed to allocate storage
    for parameters during a function call.
    """

    class RegType(java.lang.Enum[GoRegisterInfo.RegType]):

        class_: typing.ClassVar[java.lang.Class]
        INT: typing.Final[GoRegisterInfo.RegType]
        FLOAT: typing.Final[GoRegisterInfo.RegType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GoRegisterInfo.RegType:
            ...

        @staticmethod
        def values() -> jpype.JArray[GoRegisterInfo.RegType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getAlignmentForType(self, dt: ghidra.program.model.data.DataType) -> int:
        ...

    def getClosureContextRegister(self) -> ghidra.program.model.lang.Register:
        ...

    def getCurrentGoroutineRegister(self) -> ghidra.program.model.lang.Register:
        ...

    def getDuffzeroParams(self, program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.program.model.listing.Variable]:
        ...

    def getFloatRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    def getIntRegisterSize(self) -> int:
        ...

    def getIntRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    def getMaxAlign(self) -> int:
        ...

    def getStackInitialOffset(self) -> int:
        ...

    def getValidVersions(self) -> GoVerSet:
        ...

    def getZeroRegister(self) -> ghidra.program.model.lang.Register:
        ...

    def hasAbiInternalParamRegisters(self) -> bool:
        ...

    def isZeroRegisterIsBuiltin(self) -> bool:
        ...

    @property
    def alignmentForType(self) -> jpype.JInt:
        ...

    @property
    def zeroRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def floatRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def closureContextRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def validVersions(self) -> GoVerSet:
        ...

    @property
    def stackInitialOffset(self) -> jpype.JInt:
        ...

    @property
    def intRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def maxAlign(self) -> jpype.JInt:
        ...

    @property
    def intRegisterSize(self) -> jpype.JInt:
        ...

    @property
    def duffzeroParams(self) -> java.util.List[ghidra.program.model.listing.Variable]:
        ...

    @property
    def zeroRegisterIsBuiltin(self) -> jpype.JBoolean:
        ...

    @property
    def currentGoroutineRegister(self) -> ghidra.program.model.lang.Register:
        ...


class GolangDWARFFunctionFixup(ghidra.app.util.bin.format.dwarf.funcfixup.DWARFFunctionFixup):
    """
    Fixups for golang functions found during DWARF processing.
     
    
    Fixes storage of parameters to match the go callspec and modifies parameter lists to match
    Ghidra's capabilities.
     
    
    Special characters used by golang in symbol names (middle dot ·, weird slash ∕) are 
    fixed up in DWARFProgram.getDWARFNameInfo() by calling 
    GoSymbolName.fixGolangSpecialSymbolnameChars().
     
    
    Go's 'unique' usage of DW_TAG_subroutine_type to define its ptr-to-ptr-to-func is handled in
    DWARFDataTypeImporter.makeDataTypeForFunctionDefinition().
    """

    class_: typing.ClassVar[java.lang.Class]
    GOLANG_API_EXPORT: typing.Final[ghidra.program.model.data.CategoryPath]

    def __init__(self):
        ...

    @staticmethod
    def isGolangFunction(dfunc: ghidra.app.util.bin.format.dwarf.DWARFFunction) -> bool:
        """
        Returns true if the specified :obj:`DWARFFunction` wrapper refers to a function in a golang
        compile unit.
        
        :param ghidra.app.util.bin.format.dwarf.DWARFFunction dfunc: :obj:`DWARFFunction`
        :return: boolean true or false
        :rtype: bool
        """


class GoVerRange(java.lang.Record):
    """
    Represents a range of versions
    """

    class_: typing.ClassVar[java.lang.Class]
    ALL: typing.Final[GoVerRange]
    EMPTY: typing.Final[GoVerRange]

    def __init__(self, start: GoVer, end: GoVer):
        ...

    def asList(self) -> java.util.List[GoVer]:
        """
        Returns a list of minor GoVers between the start and end of this range (inclusive).
         
        
        NOTE: does not work if the major version is different between start and end.
        
        :return: List of GoVers
        :rtype: java.util.List[GoVer]
        :raises IOException: if start and end are not same major ver
        """

    def contains(self, ver: GoVer) -> bool:
        """
        Returns true if this range contains the specified version.
        
        :param GoVer ver: :obj:`GoVer` to test
        :return: boolean true if present, false if not
        :rtype: bool
        """

    def end(self) -> GoVer:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hasWildcard(self) -> bool:
        """
        Returns true if this range has wildcard start or end
        
        :return: boolean true if has wildcard boundaries
        :rtype: bool
        """

    def hashCode(self) -> int:
        ...

    def isEmpty(self) -> bool:
        """
        Returns true if this range is empty
        
        :return: boolean true if empty
        :rtype: bool
        """

    @staticmethod
    def parse(s: typing.Union[java.lang.String, str]) -> GoVerRange:
        """
        Parses a version range string (eg. "1.2-1.5", or "-1.5", or "1.2+")
         
        
        Version ranges can be specified with leading or trailing wildcards
        (eg. "-end_ver", or "start_ver-", or "start_ver+").
        
        :param java.lang.String or str s: string to parse
        :return: returns a :obj:`GoVerRange` instance, or the special :obj:`.EMPTY` instance
        if the string string is bad
        :rtype: GoVerRange
        """

    def start(self) -> GoVer:
        ...

    def toString(self) -> str:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class GoVerSet(java.lang.Record):
    """
    Represents a set of version numbers.
    """

    class_: typing.ClassVar[java.lang.Class]
    ALL: typing.Final[GoVerSet]

    def __init__(self, ranges: java.util.List[GoVerRange]):
        ...

    def contains(self, ver: GoVer) -> bool:
        """
        Returns true if the specified version is present in the set.
        
        :param GoVer ver: :obj:`GoVer` to search for
        :return: boolean true if version is present
        :rtype: bool
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def isEmpty(self) -> bool:
        """
        Returns true if the set contains no versions
        
        :return: boolean true if empty
        :rtype: bool
        """

    @staticmethod
    def parse(s: typing.Union[java.lang.String, str]) -> GoVerSet:
        """
        Parses a version list string (eg. "all", or "1.0-1.5,1.8-1.9,1.11-") and returns 
        a :obj:`GoVerSet` containing the found versions.
        
        :param java.lang.String or str s: string to parse
        :return: :obj:`GoVerSet` containing the found versions
        :rtype: GoVerSet
        :raises IOException: if the string had invalid start or end wildcard ranges
        """

    def ranges(self) -> java.util.List[GoVerRange]:
        ...

    def toString(self) -> str:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...



__all__ = ["GoFunctionMultiReturn", "GoConstants", "GoBuildInfo", "GoBuildId", "GolangElfInfoProducer", "GoRegisterInfoManager", "GoFunctionFixup", "BootstrapInfoException", "GoParamStorageAllocator", "GoModuleInfo", "GoBuildSettings", "NoteGoBuildId", "GoVer", "GoRegisterInfo", "GolangDWARFFunctionFixup", "GoVerRange", "GoVerSet"]
