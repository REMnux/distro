from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.google.gson # type: ignore
import generic.jar
import ghidra.app.util.bin
import ghidra.app.util.bin.format.golang
import ghidra.app.util.bin.format.golang.rtti.types
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import java.util.regex # type: ignore


T = typing.TypeVar("T")


class GoPcHeader(java.lang.Object):
    """
    A low-level structure embedded in golang binaries that contains useful bootstrapping
    information.
     
    
    Introduced in golang 1.16
    """

    @typing.type_check_only
    class GoVerEndian(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def endian(self) -> ghidra.program.model.lang.Endian:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def goVer(self) -> ghidra.app.util.bin.format.golang.GoVer:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    GO_STRUCTURE_NAME: typing.Final = "runtime.pcHeader"
    GOPCLNTAB_SECTION_NAME: typing.Final = "gopclntab"
    GO_1_2_MAGIC: typing.Final = -5
    GO_1_16_MAGIC: typing.Final = -6
    GO_1_18_MAGIC: typing.Final = -16
    GO_1_20_MAGIC: typing.Final = -15

    def __init__(self):
        ...

    @staticmethod
    def createArtificialGoPcHeaderStructure(cp: ghidra.program.model.data.CategoryPath, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.Structure:
        ...

    @staticmethod
    def findPcHeaderAddress(programContext: GoRttiMapper, range: ghidra.program.model.address.AddressRange, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        Searches (possibly slowly) for a pclntab/pcHeader structure in the specified memory range,
        which is typically necessary in stripped PE binaries.
        
        :param GoRttiMapper programContext: :obj:`GoRttiMapper`
        :param ghidra.program.model.address.AddressRange range: memory range to search (typically .rdata or .noptrdata sections)
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` that will let the user cancel
        :return: :obj:`Address` of the found pcHeader structure, or null if not found
        :rtype: ghidra.program.model.address.Address
        :raises IOException: if error reading
        """

    def getCuAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns address of the cu tab slice, used by the cuOffset field's markup annotation.
        
        :return: address of the cu tab slice
        :rtype: ghidra.program.model.address.Address
        """

    def getFiletabAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the filetab slice, used by the filetabOffset field's markup annotation
        
        :return: address of the filetab slice
        :rtype: ghidra.program.model.address.Address
        """

    def getFuncnameAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns address of the func name slice
        
        :return: address of func name slice
        :rtype: ghidra.program.model.address.Address
        """

    def getGoVersion(self) -> ghidra.app.util.bin.format.golang.GoVer:
        ...

    def getMagic(self) -> int:
        ...

    def getMinLC(self) -> int:
        """
        Returns the min lc, used as the GoPcValueEvaluator's pcquantum
        
        :return: minLc
        :rtype: int
        """

    @staticmethod
    def getPcHeaderAddress(program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        Returns the :obj:`Address` (if present) of the go pclntab section or symbol.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: :obj:`Address` of go pclntab, or null if not present
        :rtype: ghidra.program.model.address.Address
        """

    def getPclnAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the pcln slice, used by the pclnOffset field's markup annotation
        
        :return: address of the pcln slice
        :rtype: ghidra.program.model.address.Address
        """

    def getPctabAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the pctab slice, used by the pctabOffset field's markup annotation
        
        :return: address of the pctab slice
        :rtype: ghidra.program.model.address.Address
        """

    def getPtrSize(self) -> int:
        """
        Returns the pointer size
        
        :return: pointer size
        :rtype: int
        """

    def getTextStart(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of where the text area starts.
        
        :return: address of text starts
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def hasPcHeader(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the specified program has an easily found pclntab w/pcHeader
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: boolean true if program has a pclntab, false otherwise
        :rtype: bool
        """

    def hasTextStart(self) -> bool:
        """
        Returns true if this pcln structure contains a textStart value (only present >= 1.18)
        
        :return: boolean true if struct has textstart value
        :rtype: bool
        """

    @staticmethod
    def isPcHeader(provider: ghidra.app.util.bin.ByteProvider) -> bool:
        """
        Returns true if there is a pclntab at the current position of the specified ByteProvider.
        
        :param ghidra.app.util.bin.ByteProvider provider: :obj:`ByteProvider`
        :return: boolean true if the byte provider has the magic signature of a pclntab
        :rtype: bool
        :raises IOException: if error reading
        """

    @property
    def pctabAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def magic(self) -> jpype.JInt:
        ...

    @property
    def cuAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def ptrSize(self) -> jpype.JByte:
        ...

    @property
    def minLC(self) -> jpype.JByte:
        ...

    @property
    def goVersion(self) -> ghidra.app.util.bin.format.golang.GoVer:
        ...

    @property
    def funcnameAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def pclnAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def textStart(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def filetabAddress(self) -> ghidra.program.model.address.Address:
        ...


class GoVarlenString(ghidra.app.util.bin.format.golang.structmapping.StructureReader[GoVarlenString]):
    """
    A pascal-ish string, using a LEB128 (or a uint16 in pre-1.16) value as the length of the
    following bytes.
     
    
    Used mainly in lower-level RTTI structures, this class is a ghidra'ism used to parse the
    golang rtti data and does not have a counterpart in the golang src.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the raw bytes of the string
        
        :return: raw bytes of the string
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getString(self) -> str:
        """
        Returns the string value.
        
        :return: string value
        :rtype: str
        """

    def getStrlen(self) -> int:
        """
        Returns the string's length
        
        :return: string's length
        :rtype: int
        """

    def getStrlenDataType(self) -> ghidra.program.model.data.DataTypeInstance:
        """
        Returns the data type that is needed to hold the string length field.
        
        :return: data type needed to hold the string length field
        :rtype: ghidra.program.model.data.DataTypeInstance
        """

    def getStrlenLen(self) -> int:
        """
        Returns the size of the string length field.
        
        :return: size of the string length field
        :rtype: int
        """

    def getValueDataType(self) -> ghidra.program.model.data.DataType:
        """
        Returns the data type that holds the raw string value.
        
        :return: data type that holds the raw string value.
        :rtype: ghidra.program.model.data.DataType
        """

    @property
    def strlen(self) -> jpype.JInt:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def valueDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def strlenLen(self) -> jpype.JInt:
        ...

    @property
    def strlenDataType(self) -> ghidra.program.model.data.DataTypeInstance:
        ...


class GoName(ghidra.app.util.bin.format.golang.structmapping.StructureReader[GoName], ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoName]):
    """
    Represents a golang "name" construct, which isn't represented in go as a normal structure
    since it is full of variable length and optional fields.
     
    struct {
        byte flag;
        varint strlen;
        char[strlen] chars; 
        (optional: varint tag_strlen; char [tag_strlen];)
        (optional: int32 pkgpath)
    }
     
    Because this type has variable length fields (@FieldOutput(isVariableLength=true)), there will
    be unique structure data types produced for each size combination of a GoName structure, and
    will be named "GoName_N_M", where N and M are the lengths of the variable fields [name, tag]
    """

    class Flag(java.lang.Enum[GoName.Flag]):

        class_: typing.ClassVar[java.lang.Class]
        EXPORTED: typing.Final[GoName.Flag]
        HAS_TAG: typing.Final[GoName.Flag]
        HAS_PKGPATH: typing.Final[GoName.Flag]
        EMBEDDED: typing.Final[GoName.Flag]

        def isSet(self, value: typing.Union[jpype.JInt, int]) -> bool:
            ...

        @staticmethod
        def parseFlags(b: typing.Union[jpype.JInt, int]) -> java.util.Set[GoName.Flag]:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GoName.Flag:
            ...

        @staticmethod
        def values() -> jpype.JArray[GoName.Flag]:
            ...

        @property
        def set(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createFakeInstance(fakeName: typing.Union[java.lang.String, str]) -> GoName:
        """
        Create a GoName instance that supplies a specified name.
        
        :param java.lang.String or str fakeName: string name to return from the GoName's getName()
        :return: new GoName instance that can only be used to call getName()
        :rtype: GoName
        """

    def getFlags(self) -> int:
        """
        Returns the flags found in this structure.
        
        :return: flags, as an int
        :rtype: int
        """

    def getFlagsSet(self) -> java.util.Set[GoName.Flag]:
        """
        Returns the flags found in this structure.
        
        :return: flags, as a set of :obj:`Flag` enum values
        :rtype: java.util.Set[GoName.Flag]
        """

    def getFullNameString(self) -> str:
        """
        Returns a descriptive string containing the full name value.
        
        :return: descriptive string
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name value.
        
        :return: name string
        :rtype: str
        """

    def getPkgPath(self) -> GoName:
        """
        Returns the package path string, or null if not present.
        
        :return: package path string, or null if not present
        :rtype: GoName
        :raises IOException: if error reading data
        """

    def getPkgPathDataType(self) -> ghidra.program.model.data.DataType:
        """
        Returns the data type needed to store the pkg path offset field, called by serialization
        from the fieldoutput annotation.
        
        :return: Ghidra data type needed to store the pkg path offset field, or null if not present
        :rtype: ghidra.program.model.data.DataType
        """

    def getTag(self) -> str:
        """
        Returns the tag string.
        
        :return: tag string
        :rtype: str
        """

    @property
    def pkgPath(self) -> GoName:
        ...

    @property
    def fullNameString(self) -> java.lang.String:
        ...

    @property
    def pkgPathDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def flagsSet(self) -> java.util.Set[GoName.Flag]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def tag(self) -> java.lang.String:
        ...


class GoPcValueEvaluator(java.lang.Object):
    """
    Evaluates a sequence of (value_delta,pc_delta) leb128 pairs to calculate a value for a certain 
    PC location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, func: GoFuncData, offset: typing.Union[jpype.JLong, int]):
        """
        Creates a :obj:`GoPcValueEvaluator` instance, tied to the specified GoFuncData, starting
        at the specified offset in the moduledata's pctab.
        
        :param GoFuncData func: :obj:`GoFuncData`
        :param jpype.JLong or int offset: offset in moduledata's pctab
        :raises IOException: if error reading pctab
        """

    def eval(self, targetPC: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the value encoded into the table at the specified pc.
        
        :param jpype.JLong or int targetPC: pc
        :return: value at specified pc, or -1 if error evaluating table
        :rtype: int
        :raises IOException: if error reading data
        """

    def evalAll(self, targetPC: typing.Union[jpype.JLong, int]) -> java.util.List[java.lang.Integer]:
        """
        Returns the set of all values for each unique pc section.
        
        :param jpype.JLong or int targetPC: max pc to advance the sequence to when evaluating the table
        :return: list of integer values
        :rtype: java.util.List[java.lang.Integer]
        :raises IOException: if error reading data
        """

    def evalNext(self) -> int:
        ...

    def getMaxPC(self) -> int:
        """
        Returns the largest PC value calculated when evaluating the result of the table's sequence.
        
        :return: largest PC value encountered
        :rtype: int
        :raises IOException: if error evaluating result
        """

    def getPC(self) -> int:
        ...

    def reset(self):
        ...

    @property
    def pC(self) -> jpype.JLong:
        ...

    @property
    def maxPC(self) -> jpype.JLong:
        ...


class GoItab(ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoItab]):
    """
    Represents a mapping between a golang interface and a type that implements the methods of
    the interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def discoverGoTypes(self, discoveredTypes: java.util.Set[java.lang.Long]):
        ...

    def getFunSlice(self) -> GoSlice:
        """
        Returns an artificial slice that contains the address of the functions that implement
        the interface methods.
        
        :return: artificial slice that contains the address of the functions that implement
        the interface methods
        :rtype: GoSlice
        :raises IOException: if error reading method info
        """

    def getFuncCount(self) -> int:
        """
        Return the number of methods implemented.
        
        :return: number of methods implemented
        :rtype: int
        :raises IOException: if error reading interface structure
        """

    def getInterfaceType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoInterfaceType:
        """
        Returns the interface implemented by the specified type.
        
        :return: interface implemented by the specified type
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoInterfaceType
        :raises IOException: if error reading ref'd interface structure
        """

    def getMethodInfoList(self) -> java.util.List[ghidra.app.util.bin.format.golang.rtti.types.GoIMethod.GoIMethodInfo]:
        """
        Returns list of :obj:`GoIMethodInfo` instances, that represent the methods implemented by
        the specified type / interface.
        
        :return: list of :obj:`GoIMethodInfo` instances
        :rtype: java.util.List[ghidra.app.util.bin.format.golang.rtti.types.GoIMethod.GoIMethodInfo]
        :raises IOException: if error reading interface method list
        """

    def getType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the type that implements the specified interface.
        
        :return: type that implements the specified interface
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        :raises IOException: if error reading the ref'd type structure
        """

    @property
    def methodInfoList(self) -> java.util.List[ghidra.app.util.bin.format.golang.rtti.types.GoIMethod.GoIMethodInfo]:
        ...

    @property
    def interfaceType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoInterfaceType:
        ...

    @property
    def funcCount(self) -> jpype.JLong:
        ...

    @property
    def funSlice(self) -> GoSlice:
        ...

    @property
    def type(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...


class GoRttiMapper(ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper, ghidra.app.util.bin.format.golang.structmapping.DataTypeMapperContext):
    """
    :obj:`DataTypeMapper` for golang binaries. 
     
    
    When bootstrapping golang binaries, the following steps are used:
     
    * Find the GoBuildInfo struct.  This struct is the easiest to locate, even when the binary
    is stripped.  This gives us the go pointerSize (probably same as ghidra pointer size) and the
    goVersion.  This struct does not rely on StructureMapping, allowing its use before a
    DataTypeMapper is created.
    * Create DataTypeMapper
    * Find the runtime.firstmoduledata structure.
    *     
        * If there are symbols, just use the symbol or named memory block.
        * If stripped:
        *     
            * Find the pclntab.  This has a magic signature, a pointerSize, and references
            to a couple of tables that are also referenced in the moduledata structure.
            * Search memory for a pointer to the pclntab struct.  This should be the first
            field of the moduledata structure.  The values that are duplicated between the
            two structures can be compared to ensure validity.
            * Different binary formats (Elf vs PE) will determine which memory blocks to
            search.
    """

    class FuncDefFlags(java.lang.Enum[GoRttiMapper.FuncDefFlags]):

        class_: typing.ClassVar[java.lang.Class]
        RECV_MISSING: typing.Final[GoRttiMapper.FuncDefFlags]
        RECV_ARTIFICIAL: typing.Final[GoRttiMapper.FuncDefFlags]
        PARAMS_PARTIAL: typing.Final[GoRttiMapper.FuncDefFlags]
        PARAM_SUBSTITUTION: typing.Final[GoRttiMapper.FuncDefFlags]
        PARAMS_MISSING: typing.Final[GoRttiMapper.FuncDefFlags]
        RETURN_INFO_PARTIAL: typing.Final[GoRttiMapper.FuncDefFlags]
        RESULT_SUBSTITUTION: typing.Final[GoRttiMapper.FuncDefFlags]
        RETURN_INFO_MISSING: typing.Final[GoRttiMapper.FuncDefFlags]
        FROM_RTTI_METHOD: typing.Final[GoRttiMapper.FuncDefFlags]
        FROM_SNAPSHOT: typing.Final[GoRttiMapper.FuncDefFlags]
        FROM_ANALYSIS: typing.Final[GoRttiMapper.FuncDefFlags]
        CLOSURE: typing.Final[GoRttiMapper.FuncDefFlags]
        METHOD_WRAPPER: typing.Final[GoRttiMapper.FuncDefFlags]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GoRttiMapper.FuncDefFlags:
            ...

        @staticmethod
        def values() -> jpype.JArray[GoRttiMapper.FuncDefFlags]:
            ...


    class FuncDefResult(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, funcDef: ghidra.program.model.data.FunctionDefinition, recvType: ghidra.app.util.bin.format.golang.rtti.types.GoType, flags: java.util.Set[GoRttiMapper.FuncDefFlags], funcDefStr: typing.Union[java.lang.String, str], symbolName: GoSymbolName):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def flags(self) -> java.util.Set[GoRttiMapper.FuncDefFlags]:
            ...

        def funcDef(self) -> ghidra.program.model.data.FunctionDefinition:
            ...

        def funcDefStr(self) -> str:
            ...

        def hashCode(self) -> int:
            ...

        def recvType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
            ...

        def symbolName(self) -> GoSymbolName:
            ...

        def toString(self) -> str:
            ...


    class GoNameSupplier(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def get(self) -> GoName:
            ...


    @typing.type_check_only
    class BootstrapFuncInfo(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def func(self) -> ghidra.program.model.listing.Function:
            ...

        def funcData(self) -> GoFuncData:
            ...

        def hashCode(self) -> int:
            ...

        def isBootstrapFunction(self) -> bool:
            """
            Returns true if the specified function should be included in the bootstrap function defs
            that are written to the golang_NNNN.gdt archive.
            
            :return: true if function should be included in golang.gdt bootstrap file
            :rtype: bool
            """

        def isNotPlatformSpecificSourceFile(self) -> bool:
            """
            Returns true if function is a generic function and is not located in a source filename
            that has a platform specific substring (eg. "_linux")
            
            :return: true if function is a generic function and is not located in a platform specific
            source file
            :rtype: bool
            """

        def toString(self) -> str:
            ...

        @property
        def notPlatformSpecificSourceFile(self) -> jpype.JBoolean:
            ...

        @property
        def bootstrapFunction(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]
    SUPPORTED_VERSIONS: typing.Final[ghidra.app.util.bin.format.golang.GoVerRange]
    ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME: typing.Final = "ARTIFICIAL.runtime.zerobase"

    def __init__(self, program: ghidra.program.model.listing.Program, buildInfo: ghidra.app.util.bin.format.golang.GoBuildInfo, ptrSize: typing.Union[jpype.JInt, int], goVer: ghidra.app.util.bin.format.golang.GoVer, archiveGDT: generic.jar.ResourceFile, apiSnapshot: GoApiSnapshot):
        """
        Creates a GoRttiMapper using the specified bootstrap information.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` containing the go binary
        :param ghidra.app.util.bin.format.golang.GoBuildInfo buildInfo: :obj:`GoBuildInfo`
        :param jpype.JInt or int ptrSize: size of pointers
        :param ghidra.app.util.bin.format.golang.GoVer goVer: version of go
        :param generic.jar.ResourceFile archiveGDT: path to the matching golang bootstrap gdt data type file, or null
        if not present and types recovered via DWARF should be used instead
        :param GoApiSnapshot apiSnapshot: json func signatures and data types
        :raises IOException: if error linking a structure mapped structure to its matching
        ghidra structure, which is a programming error or a corrupted bootstrap gdt
        :raises BootstrapInfoException: if there is no matching bootstrap gdt for this specific
        type of golang binary
        """

    def addModule(self, module: GoModuledata):
        """
        Adds a module data instance to the context
        
        :param GoModuledata module: :obj:`GoModuledata` to add
        """

    @typing.overload
    def createFuncDef(self, params: java.util.List[ghidra.program.model.data.ParameterDefinition], returnParams: java.util.List[ghidra.program.model.data.ParameterDefinition], symbolName: GoSymbolName, noReturn: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.FunctionDefinitionDataType:
        ...

    @typing.overload
    def createFuncDef(self, params: java.util.List[ghidra.program.model.data.ParameterDefinition], returnDT: ghidra.program.model.data.DataType, symbolName: GoSymbolName, noReturn: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.FunctionDefinitionDataType:
        ...

    def exportTypesToGDT(self, gdtFile: jpype.protocol.SupportsPath, runtimeFuncSnapshot: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Export the currently registered struct mapping types to a gdt file, producing a bootstrap
        GDT archive.
         
        
        The struct data types will either be from the current program's DWARF data, or
        from an earlier golang.gdt (if this binary doesn't have DWARF)
        
        :param jpype.protocol.SupportsPath gdtFile: destination :obj:`File` to write the bootstrap types to
        :param jpype.JBoolean or bool runtimeFuncSnapshot: boolean flag, if true include function definitions
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :raises IOException: if error
        :raises CancelledException: if cancelled
        """

    def findContainingModule(self, offset: typing.Union[jpype.JLong, int]) -> GoModuledata:
        """
        Finds the :obj:`GoModuledata` that contains the specified offset.
         
        
        Useful for finding the :obj:`GoModuledata` to resolve a relative offset of the text,
        types or other area.
        
        :param jpype.JLong or int offset: absolute offset of a structure that a :obj:`GoModuledata` contains
        :return: :obj:`GoModuledata` instance that contains the structure, or null if not found
        :rtype: GoModuledata
        """

    def findContainingModuleByFuncData(self, offset: typing.Union[jpype.JLong, int]) -> GoModuledata:
        """
        Finds the :obj:`GoModuledata` that contains the specified func data offset.
        
        :param jpype.JLong or int offset: absolute offset of a func data structure
        :return: :obj:`GoModuledata` instance that contains the specified func data, or null if not
        found
        :rtype: GoModuledata
        """

    @staticmethod
    def findGolangBootstrapGDT(goVer: ghidra.app.util.bin.format.golang.GoVer, ptrSize: typing.Union[jpype.JInt, int], osName: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Searches for a golang bootstrap gdt file that matches the specified Go version/size/OS.
         
        
        First looks for a gdt with an exact match, then for a gdt with version/size match and
        "any" OS, and finally, a gdt that matches the version and "any" size and "any" OS.
        
        :param ghidra.app.util.bin.format.golang.GoVer goVer: version of Go
        :param jpype.JInt or int ptrSize: size of pointers
        :param java.lang.String or str osName: name of OS
        :return: ResourceFile of matching bootstrap gdt, or null if nothing matches
        :rtype: generic.jar.ResourceFile
        """

    def getAllFunctions(self) -> java.util.List[GoFuncData]:
        """
        Return a list of all functions
        
        :return: list of all functions contained in the golang func metadata table
        :rtype: java.util.List[GoFuncData]
        """

    @staticmethod
    def getAllSupportedVersions() -> java.util.List[ghidra.app.util.bin.format.golang.GoVer]:
        ...

    def getBootstrapFunctionDefintion(self, funcName: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.FunctionDefinition:
        """
        Returns a :obj:`FunctionDefinition` for a built-in golang runtime function.
        
        :param java.lang.String or str funcName: name of function
        :return: :obj:`FunctionDefinition`, or null if not found in bootstrap gdt
        :rtype: ghidra.program.model.data.FunctionDefinition
        """

    def getBuildInfo(self) -> ghidra.app.util.bin.format.golang.GoBuildInfo:
        ...

    def getCallingConventionFor(self, func: GoFuncData) -> str:
        ...

    def getDefaultCallingConventionName(self) -> str:
        ...

    @staticmethod
    def getFirstGoSection(program: ghidra.program.model.listing.Program, *blockNames: typing.Union[java.lang.String, str]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    def getFirstModule(self) -> GoModuledata:
        """
        Returns the first module data instance
        
        :return: :obj:`GoModuledata`
        :rtype: GoModuledata
        """

    def getFuncDefFor(self, funcData: GoFuncData) -> GoRttiMapper.FuncDefResult:
        """
        Returns function definition information for a func.
        
        :param GoFuncData funcData: :obj:`GoFuncData` representing a go func
        :return: :obj:`FuncDefResult` record, or null if no information could be found or
        generated
        :rtype: GoRttiMapper.FuncDefResult
        :raises IOException: if error reading type info
        """

    def getFunctionByName(self, funcName: typing.Union[java.lang.String, str]) -> GoFuncData:
        """
        Returns a function based on its name
        
        :param java.lang.String or str funcName: name of function
        :return: :obj:`GoFuncData`, or null if not found
        :rtype: GoFuncData
        """

    def getFunctionData(self, funcAddr: ghidra.program.model.address.Address) -> GoFuncData:
        """
        Returns metadata about a function
        
        :param ghidra.program.model.address.Address funcAddr: entry point of a function
        :return: :obj:`GoFuncData`, or null if function not found in lookup tables
        :rtype: GoFuncData
        """

    def getFunctionsByNamePattern(self, pattern: java.util.regex.Pattern) -> java.util.List[GoFuncData]:
        ...

    @staticmethod
    def getGDTFilename(goVer: ghidra.app.util.bin.format.golang.GoVer, pointerSizeInBytes: typing.Union[jpype.JInt, int], osName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the name of the golang bootstrap gdt data type archive, using the specified
        version, pointer size and OS name.
        
        :param ghidra.app.util.bin.format.golang.GoVer goVer: :obj:`GoVer`
        :param jpype.JInt or int pointerSizeInBytes: pointer size for this binary, or -1 to use wildcard "any"
        :param java.lang.String or str osName: name of the operating system, or "any"
        :return: String, "golang_1.18_64bit_any.gdt"
        :rtype: str
        """

    @staticmethod
    def getGoBinary(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> GoRttiMapper:
        """
        Creates a :obj:`GoRttiMapper` representing the specified program.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: new :obj:`GoRttiMapper`, or null if basic golang information is not found in the
        binary
        :rtype: GoRttiMapper
        :raises BootstrapInfoException: if it is a golang binary and has an unsupported or
        unparseable version number or if there was a missing golang bootstrap .gdt file
        :raises IOException: if there was an error in the Ghidra golang rtti reading logic
        """

    def getGoName(self, offset: typing.Union[jpype.JLong, int]) -> GoName:
        """
        Returns the :obj:`GoName` instance at the specified offset.
        
        :param jpype.JLong or int offset: location to read
        :return: :obj:`GoName` instance, or null if offset was special value 0
        :rtype: GoName
        :raises IOException: if error reading
        """

    @staticmethod
    @typing.overload
    def getGoSection(program: ghidra.program.model.listing.Program, sectionName: typing.Union[java.lang.String, str]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @typing.overload
    def getGoSection(self, sectionName: typing.Union[java.lang.String, str]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @staticmethod
    @typing.overload
    def getGoSymbol(program: ghidra.program.model.listing.Program, symbolName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        """
        Returns a matching symbol from the specified program, using golang specific logic.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :param java.lang.String or str symbolName: name of golang symbol
        :return: :obj:`Symbol`, or null if not found
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @typing.overload
    def getGoSymbol(self, symbolName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        ...

    def getGoTypes(self) -> GoTypeManager:
        ...

    def getGoVer(self) -> ghidra.app.util.bin.format.golang.GoVer:
        """
        Returns the golang version
        
        :return: :obj:`GoVer`
        :rtype: ghidra.app.util.bin.format.golang.GoVer
        """

    def getMethodInfoForFunction(self, funcAddr: ghidra.program.model.address.Address) -> ghidra.app.util.bin.format.golang.rtti.types.GoMethod.GoMethodInfo:
        """
        Returns method info about the specified function.
        
        :param ghidra.program.model.address.Address funcAddr: function address
        :return: :obj:`GoMethodInfo`, or null
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoMethod.GoMethodInfo
        """

    def getMinLC(self) -> int:
        """
        Returns the minLC (pcquantum) value found in the pcln header structure
        
        :return: minLC value
        :rtype: int
        :raises IOException: if value has not been initialized yet
        """

    def getModules(self) -> java.util.List[GoModuledata]:
        ...

    def getPtrSize(self) -> int:
        """
        Returns the size of pointers in this binary.
        
        :return: pointer size (ex. 4, or 8)
        :rtype: int
        """

    def getRegInfo(self) -> ghidra.app.util.bin.format.golang.GoRegisterInfo:
        """
        Returns a shared :obj:`GoRegisterInfo` instance
        
        :return: :obj:`GoRegisterInfo`
        :rtype: ghidra.app.util.bin.format.golang.GoRegisterInfo
        """

    def getSafeName(self, supplier: GoRttiMapper.GoNameSupplier, structInstance: T, defaultValue: typing.Union[java.lang.String, str]) -> GoName:
        """
        An exception handling wrapper around a "getName()" call that could throw an IOException.
         
        
        When there is an error fetching the GoName instance via the specified callback, a limited
        usage GoName instance will be created and returned that will provide a replacement name
        that is built using the calling structure's offset as the identifier.
        
        :param T: struct mapped instance type:param GoRttiMapper.GoNameSupplier supplier: Supplier callback
        :param T structInstance: reference to the caller's struct-mapped instance
        :param java.lang.String or str defaultValue: string value to return (wrapped in a GoName) if the GoName is simply 
        missing
        :return: GoName, either from the callback, or a limited-functionality instance created to
        hold a fallback name string
        :rtype: GoName
        """

    @staticmethod
    def getSharedGoBinary(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> GoRttiMapper:
        """
        Returns a shared :obj:`GoRttiMapper` for the specified program, or null if the binary
        is not a supported golang binary.
         
        
        The returned value will be cached and returned in any additional calls to this method, and
        automatically :meth:`closed <.close>` when the current analysis session is finished.
         
        
        NOTE: Only valid during an analysis session.  If outside of an analysis session, use
        :meth:`getGoBinary(Program, TaskMonitor) <.getGoBinary>` to create a new instance if you need to use this 
        outside of an analyzer.
        
        :param ghidra.program.model.listing.Program program: golang :obj:`Program`
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: a shared :obj:`go binary <GoRttiMapper>` instance, or null if unable to find valid
        golang info in the Program
        :rtype: GoRttiMapper
        """

    def getStringDataRange(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the address range that is valid for string char[] data to be found in.
        
        :return: :obj:`AddressSetView` of range that is valid for string char[] data
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getStringStructRange(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the address range that is valid for string structs to be found in.
        
        :return: :obj:`AddressSetView` of range that is valid to find string structs in
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getTextAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def getUninitializedNoPtrDataRange(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @staticmethod
    def getZerobaseAddress(prog: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        Return the address of the golang zerobase symbol, or an artificial substitute.
         
        
        The zerobase symbol is used as the location of parameters that are zero-length.
        
        :param ghidra.program.model.listing.Program prog: :obj:`Program`
        :return: :obj:`Address` of the runtime.zerobase, or artificial substitute
        :rtype: ghidra.program.model.address.Address
        """

    def hasCallingConvention(self, ccName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified calling convention is defined for the program.
        
        :param java.lang.String or str ccName: calling convention name
        :return: true if the specified calling convention is defined for the program
        :rtype: bool
        """

    @staticmethod
    def hasGolangSections(sectionNames: java.util.List[java.lang.String]) -> bool:
        ...

    def init(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Finishes making this instance ready to be used.
        
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :raises IOException: if error reading data
        """

    def initMethodInfoIfNeeded(self):
        """
        Initializes golang function / method lookup info
        
        :raises IOException: if error reading data
        """

    @staticmethod
    def isAbi0Func(funcEntry: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program) -> bool:
        ...

    def isGolangAbi0Func(self, func: ghidra.program.model.listing.Function) -> bool:
        """
        Returns true if the specified function uses the abi0 calling convention.
        
        :param ghidra.program.model.listing.Function func: :obj:`Function` to test
        :return: boolean true if function uses abi0 calling convention
        :rtype: bool
        """

    @staticmethod
    def isGolangProgram(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the specified Program is marked as "golang".
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: boolean true if program is marked as golang
        :rtype: bool
        """

    def newStorageAllocator(self) -> ghidra.app.util.bin.format.golang.GoParamStorageAllocator:
        """
        Returns a new param storage allocator instance.
        
        :return: new :obj:`GoParamStorageAllocator` instance
        :rtype: ghidra.app.util.bin.format.golang.GoParamStorageAllocator
        """

    def resolveNameOff(self, ptrInModule: typing.Union[jpype.JLong, int], off: typing.Union[jpype.JLong, int]) -> GoName:
        """
        Returns the :obj:`GoName` corresponding to an offset that is relative to the controlling
        GoModuledata's typesOffset.
        
        :param jpype.JLong or int ptrInModule: the address of the structure that contains the offset that needs to be
        calculated.  The containing-structure's address is important because it indicates which
        GoModuledata is the 'parent'
        :param jpype.JLong or int off: offset
        :return: :obj:`GoName`, or null if offset was special value 0
        :rtype: GoName
        :raises IOException: if error reading name or unable to find containing module
        """

    def resolveTextOff(self, ptrInModule: typing.Union[jpype.JLong, int], off: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Returns the :obj:`Address` to an offset that is relative to the controlling
        GoModuledata's text value.
        
        :param jpype.JLong or int ptrInModule: the address of the structure that contains the offset that needs to be
        calculated.  The containing-structure's address is important because it indicates which
        GoModuledata is the 'parent'
        :param jpype.JLong or int off: offset
        :return: :obj:`Address`, or null if offset was special value -1
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def stringStructRange(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def functionData(self) -> GoFuncData:
        ...

    @property
    def stringDataRange(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def methodInfoForFunction(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoMethod.GoMethodInfo:
        ...

    @property
    def goVer(self) -> ghidra.app.util.bin.format.golang.GoVer:
        ...

    @property
    def defaultCallingConventionName(self) -> java.lang.String:
        ...

    @property
    def buildInfo(self) -> ghidra.app.util.bin.format.golang.GoBuildInfo:
        ...

    @property
    def callingConventionFor(self) -> java.lang.String:
        ...

    @property
    def functionByName(self) -> GoFuncData:
        ...

    @property
    def functionsByNamePattern(self) -> java.util.List[GoFuncData]:
        ...

    @property
    def goSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def regInfo(self) -> ghidra.app.util.bin.format.golang.GoRegisterInfo:
        ...

    @property
    def allFunctions(self) -> java.util.List[GoFuncData]:
        ...

    @property
    def modules(self) -> java.util.List[GoModuledata]:
        ...

    @property
    def goSection(self) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @property
    def funcDefFor(self) -> GoRttiMapper.FuncDefResult:
        ...

    @property
    def goTypes(self) -> GoTypeManager:
        ...

    @property
    def bootstrapFunctionDefintion(self) -> ghidra.program.model.data.FunctionDefinition:
        ...

    @property
    def ptrSize(self) -> jpype.JInt:
        ...

    @property
    def textAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def goName(self) -> GoName:
        ...

    @property
    def minLC(self) -> jpype.JByte:
        ...

    @property
    def uninitializedNoPtrDataRange(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def golangAbi0Func(self) -> jpype.JBoolean:
        ...

    @property
    def firstModule(self) -> GoModuledata:
        ...


class GoApiSnapshot(java.lang.Object):
    """
    Contains function definitions and type information found in a specific Golang runtime toolchain
    version.
     
    
    Useful to apply function parameter information to functions found in a go binary.
     
    
    Snapshot json files contain function / type information about functions and types extracted from
    the golang toolchain itself, for each arch and OSes that the golang toolchain supports,
    via cross-compiling against each GOARCH and GOOS.
     
    
    Function and type info that is incompatible or not present in other arch / os targets will be
    split into different arch lookup keys that can be specified when deserializing the json.
     
    
    The arch names will be one of "all", cpu-arch-name (eg. amd64), operating-system-name (eg. linux),
    operating-system-cpu-arch-name (eg. linux-amd64), or "unix" (artificial arch name that indicates
    the sub-elements are common to all unix-like arches).  
     
    
    Non-exhaustive list of current values:
     
    * all - everything that is generically compatible with all platforms
    * 386
    * amd64
    * arm
    * arm64
    * cgo
    * darwin
    * darwin-amd64
    * darwin-amd64-cgo
    * darwin-arm64
    * darwin-arm64-cgo
    * linux
    * linux-386
    * linux-386-cgo
    * linux-amd64
    * linux-amd64-cgo
    * linux-arm
    * linux-arm-cgo
    * linux-arm64
    * linux-arm64-cgo
    * linux-cgo
    * unix - an artificial goos that groups linux/bsd/darwin/aix/etc together
    * windows
    * windows-386
    * windows-386-cgo
    * windows-amd64
    * windows-amd64-cgo
    """

    class GoNameTypePair(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def getPairString(self) -> str:
            ...

        @staticmethod
        def listToString(list: java.util.List[GoApiSnapshot.GoNameTypePair]) -> str:
            ...

        @property
        def pairString(self) -> java.lang.String:
            ...


    class FuncFlags(java.lang.Enum[GoApiSnapshot.FuncFlags]):

        class_: typing.ClassVar[java.lang.Class]
        VarArg: typing.Final[GoApiSnapshot.FuncFlags]
        Generic: typing.Final[GoApiSnapshot.FuncFlags]
        Method: typing.Final[GoApiSnapshot.FuncFlags]
        NoReturn: typing.Final[GoApiSnapshot.FuncFlags]

        @staticmethod
        def parse(i: typing.Union[jpype.JInt, int]) -> java.util.EnumSet[GoApiSnapshot.FuncFlags]:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GoApiSnapshot.FuncFlags:
            ...

        @staticmethod
        def values() -> jpype.JArray[GoApiSnapshot.FuncFlags]:
            ...


    class GoFuncDef(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def getDefinitionString(self, symbolName: GoSymbolName) -> str:
            ...

        @property
        def definitionString(self) -> java.lang.String:
            ...


    class GoTypeDef(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class GoStructDef(GoApiSnapshot.GoTypeDef):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class GoInterfaceDef(GoApiSnapshot.GoTypeDef):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class GoAliasDef(GoApiSnapshot.GoTypeDef):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class GoBasicDef(GoApiSnapshot.GoTypeDef):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class GoFuncTypeDef(GoApiSnapshot.GoTypeDef):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class GoArch(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GoTypeDefDeserializer(com.google.gson.JsonDeserializer[GoApiSnapshot.GoTypeDef]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[GoApiSnapshot]

    def __init__(self, ver: ghidra.app.util.bin.format.golang.GoVer, arches: collections.abc.Mapping):
        ...

    @staticmethod
    def get(goVer: ghidra.app.util.bin.format.golang.GoVer, goArch: typing.Union[java.lang.String, str], goOS: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> GoApiSnapshot:
        """
        Returns a matching :obj:`GoApiSnapshot` for the specified golang version.  If an exact
        match isn't found, earlier patch revs will be tried until all patch levels are exhausted.
        
        :param ghidra.app.util.bin.format.golang.GoVer goVer: go version (controls which .json file is opened)
        :param java.lang.String or str goArch: GOARCH string
        :param java.lang.String or str goOS: GOOS string
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: :obj:`GoApiSnapshot` instance, possibly an :obj:`.EMPTY` instance if no matching
        snapshot file is found
        :rtype: GoApiSnapshot
        :raises IOException: if error parsing json or opening the snapshot container file
        :raises CancelledException: if user cancels
        """

    @staticmethod
    def getApiFile(baseDir: jpype.protocol.SupportsPath, ver: ghidra.app.util.bin.format.golang.GoVer) -> java.io.File:
        ...

    @staticmethod
    def getApiSnapshotJsonFile(goVer: ghidra.app.util.bin.format.golang.GoVer, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        ...

    def getFuncdef(self, funcName: typing.Union[java.lang.String, str]) -> GoApiSnapshot.GoFuncDef:
        """
        Returns a :obj:`GoFuncDef` for the specified function name.  The function name should
        not contain generics (eg. "cmp.Compare" and not "cmp.Compare[sometypename]").
        
        :param java.lang.String or str funcName: fully qualified name of function, without any generics
        :return: :obj:`GoFuncDef` instance, or null
        :rtype: GoApiSnapshot.GoFuncDef
        """

    def getTypeDef(self, typeName: typing.Union[java.lang.String, str]) -> GoApiSnapshot.GoTypeDef:
        ...

    def getVer(self) -> ghidra.app.util.bin.format.golang.GoVer:
        ...

    @property
    def ver(self) -> ghidra.app.util.bin.format.golang.GoVer:
        ...

    @property
    def typeDef(self) -> GoApiSnapshot.GoTypeDef:
        ...

    @property
    def funcdef(self) -> GoApiSnapshot.GoFuncDef:
        ...


class GoSlice(ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoSlice]):
    """
    A structure that represents a golang slice instance (similar to a java ArrayList).  Not to be
    confused with a :obj:`GoSliceType`, which is RTTI info about a slice type.
     
    
    An initialized static image of a slice found in a go binary will tend to have len==cap (full).
     
    
    Like java's type erasure for generics, a golang slice instance does not have type information 
    about the elements found in the array blob (nor the size of the blob).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, array: typing.Union[jpype.JLong, int], len: typing.Union[jpype.JLong, int], cap: typing.Union[jpype.JLong, int], programContext: GoRttiMapper):
        """
        Creates an artificial slice instance using the supplied values.
        
        :param jpype.JLong or int array: offset of the slice's data
        :param jpype.JLong or int len: number of initialized elements in the slice
        :param jpype.JLong or int cap: total number of elements in the data array
        :param GoRttiMapper programContext: the go binary that contains the slice
        """

    def containsOffset(self, offset: typing.Union[jpype.JLong, int], sizeofElement: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if this slice contains the specified offset.
        
        :param jpype.JLong or int offset: memory offset in question
        :param jpype.JInt or int sizeofElement: size of elements in this slice
        :return: true if this slice contains the specified offset
        :rtype: bool
        """

    def getArrayAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the array blob
        
        :return: address of the array blob
        :rtype: ghidra.program.model.address.Address
        """

    def getArrayEnd(self, elementClass: java.lang.Class[typing.Any]) -> int:
        """
        Returns the address of the end of the array.
        
        :param java.lang.Class[typing.Any] elementClass: structure mapped class
        :return: location of the end of the array blob
        :rtype: int
        """

    def getArrayOffset(self) -> int:
        """
        Returns address of the array blob.
        
        :return: location of the array blob
        :rtype: int
        """

    def getCap(self) -> int:
        """
        Returns the number of elements allocated in the array blob. (capacity)
        
        :return: number of allocated elements in the array blob
        :rtype: int
        """

    def getElementDataType(self) -> ghidra.program.model.data.DataType:
        """
        Returns the :obj:`DataType` of elements of this slice, as detected by the type information
        contained in the struct field that contains this slice.
         
        
        Returns null if this slice instance was not nested (contained) in a structure.  If the
        slice data type wasn't a specialized slice data type (it was "runtime.slice" instead of
        "[]element"), void data type will be returned.
        
        :return: data type of the elements of this slice, if possible, or null
        :rtype: ghidra.program.model.data.DataType
        """

    def getElementOffset(self, elementSize: typing.Union[jpype.JLong, int], elementIndex: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the offset of the specified element
        
        :param jpype.JLong or int elementSize: size of elements in this slice
        :param jpype.JLong or int elementIndex: index of desired element
        :return: offset of element
        :rtype: int
        """

    def getElementReader(self, elementSize: typing.Union[jpype.JInt, int], elementIndex: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns a :obj:`BinaryReader` positioned at the specified slice element.
        
        :param jpype.JInt or int elementSize: size of elements in this slice
        :param jpype.JInt or int elementIndex: index of desired element
        :return: :obj:`BinaryReader` positioned at specified element
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getLen(self) -> int:
        """
        Returns the number of initialized elements
        
        :return: number of initialized elements
        :rtype: int
        """

    def getSubSlice(self, startElement: typing.Union[jpype.JLong, int], elementCount: typing.Union[jpype.JLong, int], elementSize: typing.Union[jpype.JLong, int]) -> GoSlice:
        """
        Return a artificial view of a portion of this slice's contents.
        
        :param jpype.JLong or int startElement: index of element that will be the new sub-slice's starting element
        :param jpype.JLong or int elementCount: number of elements to include in new sub-slice
        :param jpype.JLong or int elementSize: size of an individual element
        :return: new :obj:`GoSlice` instance that is limited to a portion of this slice
        :rtype: GoSlice
        """

    def isFull(self) -> bool:
        """
        Returns true if this slice's element count is equal to the slice's capacity.  This is
        typically true for all slices that are static.
        
        :return: boolean true if this slice's element count is equal to capacity
        :rtype: bool
        """

    @typing.overload
    def isValid(self) -> bool:
        """
        Returns true if this slice seems valid.
        
        :return: boolean true if array blob is a valid memory location
        :rtype: bool
        """

    @typing.overload
    def isValid(self, elementSize: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if this slice seems valid.
        
        :param jpype.JInt or int elementSize: size of elements in this slice
        :return: boolean true if array blob is a valid memory location
        :rtype: bool
        """

    @typing.overload
    def markupArray(self, sliceName: typing.Union[java.lang.String, str], namespaceName: typing.Union[java.lang.String, str], elementClazz: java.lang.Class[typing.Any], ptr: typing.Union[jpype.JBoolean, bool], session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession):
        """
        Marks up the memory occupied by the array elements with a name and a Ghidra ArrayDataType,
        which has elements who's type is determined by the specified structure class.
        
        :param java.lang.String or str sliceName: used to label the memory location
        :param java.lang.String or str namespaceName: namespace the label symbol should be placed in
        :param java.lang.Class[typing.Any] elementClazz: structure mapped class of the element of the array
        :param jpype.JBoolean or bool ptr: boolean flag, if true the element type is really a pointer to the supplied
        data type
        :param ghidra.app.util.bin.format.golang.structmapping.MarkupSession session: state and methods to assist marking up the program
        :raises IOException: if error
        """

    @typing.overload
    def markupArray(self, sliceName: typing.Union[java.lang.String, str], namespaceName: typing.Union[java.lang.String, str], elementType: ghidra.program.model.data.DataType, ptr: typing.Union[jpype.JBoolean, bool], session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession):
        """
        Marks up the memory occupied by the array elements with a name and a Ghidra ArrayDataType.
        
        :param java.lang.String or str sliceName: used to label the memory location
        :param java.lang.String or str namespaceName: namespace the label symbol should be placed in
        :param ghidra.program.model.data.DataType elementType: Ghidra datatype of the array elements, null ok if ptr == true
        :param jpype.JBoolean or bool ptr: boolean flag, if true the element type is really a pointer to the supplied
        data type
        :param ghidra.app.util.bin.format.golang.structmapping.MarkupSession session: state and methods to assist marking up the program
        :raises IOException: if error
        """

    def markupArrayElements(self, clazz: java.lang.Class[T], session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> java.util.List[T]:
        """
        Marks up each element of the array, useful when the elements are themselves structures.
        
        :param T: element type:param java.lang.Class[T] clazz: structure mapped class of element
        :param ghidra.app.util.bin.format.golang.structmapping.MarkupSession session: state and methods to assist marking up the program
        :return: list of element instances
        :rtype: java.util.List[T]
        :raises IOException: if error reading
        :raises CancelledException: if cancelled
        """

    def markupElementReferences(self, elementSize: typing.Union[jpype.JInt, int], targetAddrs: java.util.List[ghidra.program.model.address.Address], session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession):
        """
        Marks up each element of the array with an outbound reference to the corresponding address
        in the targetAddrs list.
         
        
        Useful when marking up an array of offsets.
         
        
        The Listing UI doesn't show the outbound reference from each element (for arrays of primitive
        types), but the target will show the inbound reference.
        
        :param jpype.JInt or int elementSize: size of each element in the array
        :param java.util.List[ghidra.program.model.address.Address] targetAddrs: list of addresses, should be same size as this slice
        :param ghidra.app.util.bin.format.golang.structmapping.MarkupSession session: state and methods to assist marking up the program
        :raises IOException: if error creating references
        """

    @typing.overload
    def readList(self, clazz: java.lang.Class[T]) -> java.util.List[T]:
        """
        Reads the content of the slice, treating each element as an instance of the specified
        structure mapped class.
        
        :param T: struct mapped type of element:param java.lang.Class[T] clazz: element type
        :return: list of instances
        :rtype: java.util.List[T]
        :raises IOException: if error reading an element
        """

    @typing.overload
    def readList(self, readFunc: ghidra.app.util.bin.BinaryReader.ReaderFunction[T]) -> java.util.List[T]:
        """
        Reads the contents of the slice, treating each element as an instance of an object that can
        be read using the supplied reading function.
        
        :param T: struct mapped type of element:param ghidra.app.util.bin.BinaryReader.ReaderFunction[T] readFunc: function that will read an instance from a BinaryReader
        :return: list of instances
        :rtype: java.util.List[T]
        :raises IOException: if error reading an element
        """

    def readUIntElement(self, intSize: typing.Union[jpype.JInt, int], elementIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Reads an unsigned int element from this slice.
        
        :param jpype.JInt or int intSize: size of ints
        :param jpype.JInt or int elementIndex: index of element
        :return: unsigned int value
        :rtype: int
        :raises IOException: if error reading element
        """

    def readUIntList(self, intSize: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JLong]:
        """
        Treats this slice as a array of unsigned integers, of the specified intSize.
        
        :param jpype.JInt or int intSize: size of integer
        :return: array of longs, containing the (possibly smaller) integers contained in the slice
        :rtype: jpype.JArray[jpype.JLong]
        :raises IOException: if error reading
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def cap(self) -> jpype.JLong:
        ...

    @property
    def arrayAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def len(self) -> jpype.JLong:
        ...

    @property
    def arrayOffset(self) -> jpype.JLong:
        ...

    @property
    def arrayEnd(self) -> jpype.JLong:
        ...

    @property
    def full(self) -> jpype.JBoolean:
        ...

    @property
    def elementDataType(self) -> ghidra.program.model.data.DataType:
        ...


class MethodInfo(java.lang.Object):
    """
    Abstract base for information about type methods and interface methods
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Entry point of the method
        
        :return: :obj:`Address`
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class GoFuncData(ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoFuncData]):
    """
    A structure that golang generates that contains metadata about a function.
    """

    @typing.type_check_only
    class RecoveredSignature(java.lang.Record):
        """
        Represents approximate parameter signatures for a function.
         
        
        Golang's exception/stack-trace metadata is mined to provide these approximate signatures,
        and any limitation in the information recovered is due to what golang stores.
         
        
        Instead of data types, only the size and limited grouping of structure/array parameters
        is recoverable.
        """

        class_: typing.ClassVar[java.lang.Class]

        def args(self) -> java.util.List[GoFuncData.RecoveredArg]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def error(self) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def partial(self) -> bool:
            ...

        @staticmethod
        def read(funcData: GoFuncData, goBinary: GoRttiMapper) -> GoFuncData.RecoveredSignature:
            ...

        @staticmethod
        def readArgs(funcData: GoFuncData, goBinary: GoRttiMapper) -> GoFuncData.RecoveredArg:
            ...


    @typing.type_check_only
    class RecoveredArg(java.lang.Record):
        """
        Represents the information recovered about a single argument.
        """

        class_: typing.ClassVar[java.lang.Class]

        def argSize(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def partial(self) -> bool:
            ...

        def subArgs(self) -> java.util.List[GoFuncData.RecoveredArg]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getBody(self) -> ghidra.program.model.address.AddressRange:
        """
        Returns the address range of this function's body, recovered by examining addresses in the
        function's pc-to-filename translation table, or if not present, a single address range
        that contains the function's entry point.
        
        :return: :obj:`AddressRange` representing the function's known footprint
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getDeferreturnAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getDescription(self) -> str:
        """
        Returns a descriptive string.
         
        
        Referenced from the entry, entryoff field's markup annotation
        
        :return: String description
        :rtype: str
        """

    def getFlags(self) -> java.util.Set[GoFuncFlag]:
        """
        Returns the func flags for this function.
        
        :return: :obj:`GoFuncFlag`s
        :rtype: java.util.Set[GoFuncFlag]
        """

    def getFuncAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of this function.
        
        :return: the address of this function
        :rtype: ghidra.program.model.address.Address
        """

    def getFuncDataValue(self, tableIndex: GoFuncDataTable) -> int:
        """
        Returns a value associated with this function.
        
        :param GoFuncDataTable tableIndex: :obj:`GoFuncDataTable` enum
        :return: requested value, or -1 if the requested table index is not present for this function
        :rtype: int
        :raises IOException: if error reading lookup data
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns the Ghidra function that corresponds to this go function.
        
        :return: Ghidra :obj:`Function`, or null if there is no Ghidra function at the address
        :rtype: ghidra.program.model.listing.Function
        """

    def getModuledata(self) -> GoModuledata:
        """
        Returns a reference to the :obj:`GoModuledata` that contains this function.
        
        :return: :obj:`GoModuledata` that contains this function
        :rtype: GoModuledata
        """

    def getName(self) -> str:
        """
        Returns the name of this function.
        
        :return: String name of this function
        :rtype: str
        """

    def getNameAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of this function's name string.
         
        
        Referenced from nameoff's markup annotation
        
        :return: :obj:`Address`
        :rtype: ghidra.program.model.address.Address
        """

    def getPcDataValue(self, tableIndex: GoPcDataTable, targetPC: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns a value from the specified pc->value lookup table, for a specific 
        address (that should be within the function's footprint).
        
        :param GoPcDataTable tableIndex: :obj:`GoPcDataTable` enum
        :param jpype.JLong or int targetPC: address (inside the function) to determine the value of
        :return: int value, will be specific to the :obj:`table <GoPcDataTable>` it comes from, or
        -1 if the requested table index is not present for this function
        :rtype: int
        :raises IOException: if error reading lookup data
        """

    def getPcDataValues(self, tableIndex: GoPcDataTable) -> java.util.List[java.lang.Integer]:
        """
        Returns all values for the specified pc->value lookup table for the entire range of the
        function's footprint.
        
        :param GoPcDataTable tableIndex: :obj:`GoPcDataTable` enum
        :return: list of int values, will be specific to the :obj:`table <GoPcDataTable>` it comes 
        from, or an empty list if the requested table index is not present for this function
        :rtype: java.util.List[java.lang.Integer]
        :raises IOException: if error reading lookup data
        """

    def getSourceFileInfo(self) -> GoSourceFileInfo:
        """
        Returns information about the source file that this function was defined in.
        
        :return: :obj:`GoSourceFileInfo`, or null if no source file info present
        :rtype: GoSourceFileInfo
        :raises IOException: if error reading lookup data
        """

    def getSymbolName(self) -> GoSymbolName:
        """
        Returns the name of this function, as a parsed symbol object.
        
        :return: :obj:`GoSymbolName` containing this function's name
        :rtype: GoSymbolName
        """

    def isAsmFunction(self) -> bool:
        """
        Returns true if this function is an ASM function
        
        :return: true if this function is an ASM function
        :rtype: bool
        """

    def isInline(self) -> bool:
        """
        Returns true if this function is inline
        
        :return: true if this function is inline
        :rtype: bool
        """

    def markupSourceFileInfo(self):
        ...

    def recoverFunctionSignature(self) -> str:
        """
        Attempts to build a 'function signature' string representing the known information about
        this function's arguments, using go's built-in stack trace metadata.
         
        
        The information that can be recovered about arguments is limited to:
         
        * the size of the argument
        * general grouping (eg. grouping of arg values as a structure or array)
        
        Return value information is unknown and always represented as an "undefined" data type.
        
        :return: pseudo-function signature string, such as "undefined foo( 8, 8 )" which would
        indicate the function had 2 8-byte arguments
        :rtype: str
        :raises IOException: if error reading lookup data
        """

    def setEntry(self, entry: typing.Union[jpype.JLong, int]):
        """
        Sets the absolute entry address.
         
        
        Called via deserialization for entry fieldmapping annotation
        
        :param jpype.JLong or int entry: absolute value.
        """

    def setEntryoff(self, entryoff: typing.Union[jpype.JLong, int]):
        """
        Sets the function's entry point via a relative offset value
         
        
        Called via deserialization for entryoff fieldmapping annotation
        
        :param jpype.JLong or int entryoff: relative offset to function
        """

    @property
    def asmFunction(self) -> jpype.JBoolean:
        ...

    @property
    def flags(self) -> java.util.Set[GoFuncFlag]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def nameAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def funcAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def body(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def deferreturnAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def funcDataValue(self) -> jpype.JLong:
        ...

    @property
    def inline(self) -> jpype.JBoolean:
        ...

    @property
    def pcDataValues(self) -> java.util.List[java.lang.Integer]:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def symbolName(self) -> GoSymbolName:
        ...

    @property
    def sourceFileInfo(self) -> GoSourceFileInfo:
        ...

    @property
    def moduledata(self) -> GoModuledata:
        ...


class JsonPatch(java.lang.Object):
    """
    Represents a sequence of operations that describe how a json file has changed.
     
    
    This implementation currently only supports reading jd (https://github.com/josephburnett/jd)
    native format diffs.
    """

    class PatchOp(java.lang.Enum[JsonPatch.PatchOp]):

        class_: typing.ClassVar[java.lang.Class]
        ADD: typing.Final[JsonPatch.PatchOp]
        REMOVE: typing.Final[JsonPatch.PatchOp]
        CONTEXT: typing.Final[JsonPatch.PatchOp]

        @staticmethod
        def fromChar(ch: typing.Union[jpype.JChar, int, str]) -> JsonPatch.PatchOp:
            ...

        def getOpChar(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JsonPatch.PatchOp:
            ...

        @staticmethod
        def values() -> jpype.JArray[JsonPatch.PatchOp]:
            ...

        @property
        def opChar(self) -> java.lang.String:
            ...


    class PatchSection(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, path: com.google.gson.JsonArray, lines: java.util.List[JsonPatch.PatchLine]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def lines(self) -> java.util.List[JsonPatch.PatchLine]:
            ...

        def path(self) -> com.google.gson.JsonArray:
            ...

        def toJson(self) -> com.google.gson.JsonObject:
            ...

        def toString(self) -> str:
            ...


    class PatchLine(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, operation: JsonPatch.PatchOp, value: com.google.gson.JsonElement):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def operation(self) -> JsonPatch.PatchOp:
            ...

        def toJson(self) -> com.google.gson.JsonObject:
            ...

        def toString(self) -> str:
            ...

        def value(self) -> com.google.gson.JsonElement:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sections: java.util.List[JsonPatch.PatchSection]):
        ...

    def getSectionCount(self) -> int:
        ...

    def getSections(self) -> java.util.List[JsonPatch.PatchSection]:
        ...

    @staticmethod
    @typing.overload
    def read(patchString: typing.Union[java.lang.String, str]) -> JsonPatch:
        """
        Creates a new instance using the contents in the supplied string.
        
        :param java.lang.String or str patchString: diff text
        :return: new JsonPatch instance
        :rtype: JsonPatch
        :raises IOException: if error
        """

    @staticmethod
    @typing.overload
    def read(patchFile: jpype.protocol.SupportsPath) -> JsonPatch:
        """
        Creates a new instance using the contents of the supplied file.
        
        :param jpype.protocol.SupportsPath patchFile: path to file containing json diff
        :return: new JsonPatch instance
        :rtype: JsonPatch
        :raises IOException: if error
        """

    @staticmethod
    @typing.overload
    def read(lineIterator: java.util.ListIterator[java.lang.String]) -> JsonPatch:
        """
        Creates a new instance using the contents of the supplied text lines.
        
        :param java.util.ListIterator[java.lang.String] lineIterator: iterator that provides lines of text containing the json diff
        :return: new JsonPatch instance
        :rtype: JsonPatch
        :raises IOException: if error
        """

    @staticmethod
    @typing.overload
    def read(patchSectionElements: com.google.gson.JsonArray) -> JsonPatch:
        """
        Creates a new instance using the contents of the jsonarray.  Allows storing a json
        patch in a json document.
        
        :param com.google.gson.JsonArray patchSectionElements: json array containing the json diff sections
        :return: new JsonPatch instance
        :rtype: JsonPatch
        :raises IOException: if error
        """

    def toJson(self) -> com.google.gson.JsonArray:
        """
        Converts this patch to a json array.
        
        :return: json array with json encoded patch/diff elements.
        :rtype: com.google.gson.JsonArray
        """

    @property
    def sectionCount(self) -> jpype.JInt:
        ...

    @property
    def sections(self) -> java.util.List[JsonPatch.PatchSection]:
        ...


class GoSymbolNameType(java.lang.Enum[GoSymbolNameType]):

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN: typing.Final[GoSymbolNameType]
    FUNC: typing.Final[GoSymbolNameType]
    METHOD_WRAPPER: typing.Final[GoSymbolNameType]
    ANON_FUNC: typing.Final[GoSymbolNameType]
    DEFER_WRAPPER: typing.Final[GoSymbolNameType]
    GO_WRAPPER: typing.Final[GoSymbolNameType]
    DATA_TYPE: typing.Final[GoSymbolNameType]

    @staticmethod
    def fromNameSuffix(suffix: typing.Union[java.lang.String, str]) -> GoSymbolNameType:
        ...

    @staticmethod
    def fromNameWithDashSuffix(name: typing.Union[java.lang.String, str]) -> GoSymbolNameType:
        ...

    def isClosure(self) -> bool:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GoSymbolNameType:
        ...

    @staticmethod
    def values() -> jpype.JArray[GoSymbolNameType]:
        ...

    @property
    def closure(self) -> jpype.JBoolean:
        ...


class GoFuncFlag(java.lang.Enum[GoFuncFlag]):
    """
    Bitmask flags for runtime._func (GoFuncData) flags field.
    """

    class_: typing.ClassVar[java.lang.Class]
    TOPFRAME: typing.Final[GoFuncFlag]
    SPWRITE: typing.Final[GoFuncFlag]
    ASM: typing.Final[GoFuncFlag]

    def getValue(self) -> int:
        ...

    def isSet(self, i: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def parseFlags(b: typing.Union[jpype.JInt, int]) -> java.util.Set[GoFuncFlag]:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GoFuncFlag:
        ...

    @staticmethod
    def values() -> jpype.JArray[GoFuncFlag]:
        ...

    @property
    def set(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class GoPcDataTable(java.lang.Enum[GoPcDataTable]):
    """
    An index into a GoFuncData's variable-sized pcdata array.  See GoFuncData's npcdata field
    for the actual array size.
    """

    class_: typing.ClassVar[java.lang.Class]
    PCDATA_UnsafePoint: typing.Final[GoPcDataTable]
    PCDATA_StackMapIndex: typing.Final[GoPcDataTable]
    PCDATA_InlTreeIndex: typing.Final[GoPcDataTable]
    PCDATA_ArgLiveIndex: typing.Final[GoPcDataTable]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GoPcDataTable:
        ...

    @staticmethod
    def values() -> jpype.JArray[GoPcDataTable]:
        ...


class GoSymbolName(java.lang.Record):
    """
    Represents a Golang symbol name.
     
    
    Handles formats such as:
     
    
    "package/domain.name/packagename.(*ReceiverTypeName).Functionname"
    or
    "package/domain.name/packagename.(*ReceiverTypeName[genericinfo { method(); fieldname fieldtype; }]).Functionname"
    or
    "package/domain.name/packagename.Functionname[genericinfo]"
    or
    "type:.eq.[39]package/domain.name/packagename.Functionname"
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbolName: typing.Union[java.lang.String, str], packagePath: typing.Union[java.lang.String, str], packageName: typing.Union[java.lang.String, str], receiverString: typing.Union[java.lang.String, str], genericInfo: typing.Union[java.lang.String, str], baseName: typing.Union[java.lang.String, str], prefix: typing.Union[java.lang.String, str], symtype: GoSymbolNameType):
        ...

    def asNonPtrReceiverSymbolName(self) -> GoSymbolName:
        """
        Returns a new :obj:`GoSymbolName` instance with the current instance's information
        (which should be without receiver info) re-interpreted to be a non-pointer receiver symbol.
         
        
        Example, symbol "package.name1.name2" would normally be parsed as a non-receiver symbol
        with a complex basename of "name1.name2", and this method will return a version
        that is equivalent of "package.(name1).name2".
        
        :return: new :obj:`GoSymbolName`
        :rtype: GoSymbolName
        """

    def asString(self) -> str:
        """
        Returns the full name of the golang symbol
        
        :return: full name of the golang symbol
        :rtype: str
        """

    def baseName(self) -> str:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    @staticmethod
    def fixGolangSpecialSymbolnameChars(s: typing.Union[java.lang.String, str]) -> str:
        """
        Fixes the specified string if it contains any of the golang special symbolname characters:
        middle-dot and the weird slash.
        
        :param java.lang.String or str s: string to fix
        :return: original string, or fixed version
        :rtype: str
        """

    @staticmethod
    def fromPackagePath(packagePath: typing.Union[java.lang.String, str]) -> GoSymbolName:
        """
        Constructs a GoSymbolName instance that only has a package path / package name.
        
        :param java.lang.String or str packagePath: package path to parse
        :return: GoSymbolName that only has a package path and package name value
        :rtype: GoSymbolName
        """

    @staticmethod
    def from_(packageName: typing.Union[java.lang.String, str], symbolName: typing.Union[java.lang.String, str]) -> GoSymbolName:
        """
        Constructs a minimal GoSymbolName instance from the supplied values.
        
        :param java.lang.String or str packageName: package name, does not handle package paths, eg. "runtime"
        :param java.lang.String or str symbolName: full symbol name, eg. "runtime.foo"
        :return: new GoSymbolName instance
        :rtype: GoSymbolName
        """

    def genericInfo(self) -> str:
        ...

    def getBaseName(self) -> str:
        ...

    def getBaseTypeName(self) -> str:
        ...

    def getFunction(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.Function:
        """
        Returns the matching Ghidra function (based on namespace and symbol name).
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` containing the function
        :return: Ghidra :obj:`Function`
        :rtype: ghidra.program.model.listing.Function
        """

    def getGenericParts(self) -> java.util.List[java.lang.String]:
        ...

    def getGenericsString(self) -> str:
        ...

    def getNameType(self) -> GoSymbolNameType:
        ...

    def getPackageName(self) -> str:
        """
        Returns portion of the symbol name that is the package name, or null
        
        :return: portion of the symbol name that is the package name, or null
        :rtype: str
        """

    def getPackagePath(self) -> str:
        """
        Returns the portion the symbol name that is the packagePath (path+packagename), or null
        
        :return: the portion the symbol name that is the packagePath (path+packagename), or null
        :rtype: str
        """

    def getPrefix(self) -> str:
        ...

    @typing.overload
    def getReceiverString(self) -> str:
        """
        Returns portion of the symbol name that is the receiver string, or null
        
        :return: portion of the symbol name that is the receiver string, or null
        :rtype: str
        """

    @typing.overload
    def getReceiverString(self, modifiedGenerics: typing.Union[java.lang.String, str]) -> str:
        ...

    @typing.overload
    def getReceiverTypeName(self) -> GoSymbolName:
        ...

    @typing.overload
    def getReceiverTypeName(self, modifiedGenerics: typing.Union[java.lang.String, str]) -> GoSymbolName:
        ...

    def getShapelessGenericsString(self) -> str:
        ...

    def getStrippedReceiverString(self) -> str:
        ...

    def getStrippedSymbolString(self) -> str:
        ...

    def getSymbolNamespace(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Returns a Ghidra :obj:`Namespace` based on the golang package path.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` that will contain the namespace
        :return: :obj:`Namespace` cooresponding to the golang package path, or the program's root
        namespace if no package path information is present
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getTruncatedPackagePath(self) -> str:
        """
        Returns the portion of the package path before the package name, eg. "internal/sys" would
        become "internal/".
        
        :return: package path, without the trailing package name, or empty string if there is no path 
        portion of the string
        :rtype: str
        """

    def getTypePrefixSubKeyword(self) -> str:
        ...

    def hasGenerics(self) -> bool:
        ...

    def hasReceiver(self) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def isAnonType(self) -> bool:
        ...

    def isMethod(self) -> bool:
        ...

    def isNonPtrReceiverCandidate(self) -> bool:
        ...

    def isUnparsed(self) -> bool:
        ...

    def packageName(self) -> str:
        ...

    def packagePath(self) -> str:
        ...

    @staticmethod
    def parse(s: typing.Union[java.lang.String, str]) -> GoSymbolName:
        ...

    @staticmethod
    def parseTypeName(s: typing.Union[java.lang.String, str], packagePath: typing.Union[java.lang.String, str]) -> GoSymbolName:
        ...

    def prefix(self) -> str:
        ...

    def receiverString(self) -> str:
        ...

    def symbolName(self) -> str:
        ...

    def symtype(self) -> GoSymbolNameType:
        ...

    @property
    def method(self) -> jpype.JBoolean:
        ...

    @property
    def shapelessGenericsString(self) -> java.lang.String:
        ...

    @property
    def unparsed(self) -> jpype.JBoolean:
        ...

    @property
    def typePrefixSubKeyword(self) -> java.lang.String:
        ...

    @property
    def symbolNamespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def receiverTypeName(self) -> GoSymbolName:
        ...

    @property
    def strippedSymbolString(self) -> java.lang.String:
        ...

    @property
    def strippedReceiverString(self) -> java.lang.String:
        ...

    @property
    def nameType(self) -> GoSymbolNameType:
        ...

    @property
    def genericParts(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def genericsString(self) -> java.lang.String:
        ...

    @property
    def nonPtrReceiverCandidate(self) -> jpype.JBoolean:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def truncatedPackagePath(self) -> java.lang.String:
        ...

    @property
    def baseTypeName(self) -> java.lang.String:
        ...

    @property
    def anonType(self) -> jpype.JBoolean:
        ...


class JsonPatchApplier(java.lang.Object):
    """
    Simplistic implementation, applies a json diff (see https://github.com/josephburnett/jd)
    to an in memory json element to create a new json value.
     
    
    Does not use any context hints in the diff to correct for mismatches, hence should only be used
    against the exact original value to produce the new value, useful for compressing json files
    that are derived from each other.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, json: com.google.gson.JsonElement):
        ...

    @typing.overload
    def __init__(self, baseFile: jpype.protocol.SupportsPath):
        ...

    @typing.overload
    def apply(self, patchString: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def apply(self, patch: JsonPatch, monitor: ghidra.util.task.TaskMonitor):
        ...

    def getJson(self) -> com.google.gson.JsonElement:
        ...

    def writeJson(self, destFile: jpype.protocol.SupportsPath):
        ...

    @property
    def json(self) -> com.google.gson.JsonElement:
        ...


class GoFunctabEntry(java.lang.Object):
    """
    A structure that golang generates that maps between a function's entry point and the
    location of the function's GoFuncData structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getFuncAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the function's entry point
        
        :return: address of the function's entry point
        :rtype: ghidra.program.model.address.Address
        """

    def getFuncData(self) -> GoFuncData:
        """
        Return the GoFuncData structure that contains metadata about the function.
        
        :return: :obj:`GoFuncData` structure that contains metadata about the function.
        :rtype: GoFuncData
        :raises IOException: if error
        """

    def getFuncoff(self) -> int:
        """
        Returns the offset of the GoFuncData structure.
        
        :return: offset of the GoFuncData structure.
        :rtype: int
        """

    def setEntry(self, entry: typing.Union[jpype.JLong, int]):
        """
        Set the function's entry point using the absolute address.
         
        
        Called via deserialization for entry fieldmapping annotation.
        
        :param jpype.JLong or int entry: address of the function's entry point
        """

    def setEntryoff(self, entryoff: typing.Union[jpype.JLong, int]):
        """
        Set the function's entry point using a relative offset.
         
        
        Called via deserialization for entryoff fieldmapping annotation.
        
        :param jpype.JLong or int entryoff: relative offset of the function's entry point
        """

    @property
    def funcoff(self) -> jpype.JLong:
        ...

    @property
    def funcData(self) -> GoFuncData:
        ...

    @property
    def funcAddress(self) -> ghidra.program.model.address.Address:
        ...


class GoIface(java.lang.Object):
    """
    A structure that golang generates that maps between a interface and its data
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getItab(self) -> GoItab:
        ...

    @property
    def itab(self) -> GoItab:
        ...


class GoString(ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoString]):
    """
    A structure that represents a golang string instance.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_SANE_STR_LEN: typing.Final = 1048576

    def __init__(self):
        ...

    @staticmethod
    def createInlineString(goBinary: GoRttiMapper, stringData: ghidra.program.model.address.Address, len: typing.Union[jpype.JLong, int]) -> GoString:
        """
        Creates a artificial gostring instance that was not read from a memory location.
        
        :param GoRttiMapper goBinary: :obj:`GoRttiMapper`
        :param ghidra.program.model.address.Address stringData: location of char array
        :param jpype.JLong or int len: length of char array
        :return: new GoString instance
        :rtype: GoString
        """

    def getLength(self) -> int:
        """
        Returns the length of the string data
        
        :return: length of the string data
        :rtype: int
        """

    def getStringAddr(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the char data, referenced via the str field's markup annotation
        
        :return: address of the char data
        :rtype: ghidra.program.model.address.Address
        """

    def getStringDataRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Returns an AddressRange that encompasses the string char data.
        
        :return: AddressRange that encompasses the string char data
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getStringValue(self) -> str:
        """
        Returns the string value.
        
        :return: string value
        :rtype: str
        :raises IOException: if error reading char data
        """

    def isValid(self, charValidRange: ghidra.program.model.address.AddressSetView, stringContentValidator: java.util.function.Predicate[java.lang.String]) -> bool:
        """
        Returns true if this string instance is valid and probably contains a go string.
        
        :param ghidra.program.model.address.AddressSetView charValidRange: addresses that are valid locations for a string's char[] data
        :param java.util.function.Predicate[java.lang.String] stringContentValidator: a callback that will test a recovered string for validity
        :return: boolean true if valid string, false if not valid string
        :rtype: bool
        :raises IOException: if error reading data
        """

    def isValidInlineString(self, charValidRange: ghidra.program.model.address.AddressSetView, stringContentValidator: java.util.function.Predicate[java.lang.String]) -> bool:
        """
        Returns true if this string instance points to valid char[] data.
        
        :param ghidra.program.model.address.AddressSetView charValidRange: addresses that are valid locations for a string's char[] data
        :param java.util.function.Predicate[java.lang.String] stringContentValidator: a callback that will test a recovered string for validity
        :return: boolean true if valid string, false if not valid string
        :rtype: bool
        :raises IOException: if error reading data
        """

    @property
    def stringAddr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def stringValue(self) -> java.lang.String:
        ...

    @property
    def stringDataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...


class GoFuncDataTable(java.lang.Enum[GoFuncDataTable]):
    """
    An index into a GoFuncData's variable-size funcdata array.  See GoFuncData's nfuncdata for
    actual array size.
    """

    class_: typing.ClassVar[java.lang.Class]
    FUNCDATA_ArgsPointerMaps: typing.Final[GoFuncDataTable]
    FUNCDATA_LocalsPointerMaps: typing.Final[GoFuncDataTable]
    FUNCDATA_StackObjects: typing.Final[GoFuncDataTable]
    FUNCDATA_InlTree: typing.Final[GoFuncDataTable]
    FUNCDATA_OpenCodedDeferInfo: typing.Final[GoFuncDataTable]
    FUNCDATA_ArgInfo: typing.Final[GoFuncDataTable]
    FUNCDATA_ArgLiveInfo: typing.Final[GoFuncDataTable]
    FUNCDATA_WrapInfo: typing.Final[GoFuncDataTable]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GoFuncDataTable:
        ...

    @staticmethod
    def values() -> jpype.JArray[GoFuncDataTable]:
        ...


class GoModuledata(ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoModuledata]):
    """
    Represents a golang moduledata structure, which contains a lot of valuable bootstrapping
    data for RTTI and function data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def containsFuncDataInstance(self, offset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if this GoModuleData is the module data that contains the specified
        GoFuncData structure.
        
        :param jpype.JLong or int offset: offset of a GoFuncData structure
        :return: true if this GoModuleData is the module data that contains the specified GoFuncData
        structure
        :rtype: bool
        """

    def getAllFunctionData(self) -> java.util.List[GoFuncData]:
        """
        Returns a list of all functions contained in this module.
        
        :return: list of all functions contained in this module
        :rtype: java.util.List[GoFuncData]
        :raises IOException: if error reading data
        """

    def getCutab(self) -> GoSlice:
        """
        Returns the cutab slice.
        
        :return: cutab slice
        :rtype: GoSlice
        """

    def getDataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getFiletab(self) -> GoSlice:
        """
        Returns the filetab slice.
        
        :return: filetab slice
        :rtype: GoSlice
        """

    def getFuncDataInstance(self, offset: typing.Union[jpype.JLong, int]) -> GoFuncData:
        """
        Reads a :obj:`GoFuncData` structure from the pclntable.
        
        :param jpype.JLong or int offset: relative to the pclntable
        :return: :obj:`GoFuncData`
        :rtype: GoFuncData
        :raises IOException: if error reading data
        """

    def getFuncnametab(self) -> GoSlice:
        """
        Returns a slice that contains all the function names.
        
        :return: slice that contains all the function names
        :rtype: GoSlice
        """

    def getFunctabEntriesSlice(self) -> GoSlice:
        """
        Returns an artificial slice of the functab entries that are valid.
        
        :return: artificial slice of the functab entries that are valid
        :rtype: GoSlice
        """

    def getGoBinary(self) -> GoRttiMapper:
        """
        Returns a reference to the controlling :obj:`go binary <GoRttiMapper>` context.
        
        :return: reference to the controlling :obj:`go binary <GoRttiMapper>` context
        :rtype: GoRttiMapper
        """

    def getGofunc(self) -> int:
        """
        Return the offset of the gofunc location
        
        :return: offset of the gofunc location
        :rtype: int
        """

    def getItabs(self) -> java.util.List[GoItab]:
        """
        Returns a list of the GoItabs present in this module.
        
        :return: list of the GoItabs present in this module
        :rtype: java.util.List[GoItab]
        :raises IOException: if error reading data
        """

    def getPcHeader(self) -> GoPcHeader:
        ...

    def getPcHeaderAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getPcValueTable(self) -> GoSlice:
        ...

    def getPclntable(self) -> GoSlice:
        ...

    def getPctab(self) -> GoSlice:
        """
        Returns the pctab slice.
        
        :return: pctab slice
        :rtype: GoSlice
        """

    def getRoDataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getText(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the beginning of the text section.
        
        :return: address of the beginning of the text section
        :rtype: ghidra.program.model.address.Address
        """

    def getTextRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getTypeList(self) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Returns a list of locations of the types contained in this module.
        
        :return: list of addresses of GoType structures
        :rtype: java.util.List[ghidra.program.model.address.Address]
        :raises IOException: if error reading data
        """

    def getTypesEndOffset(self) -> int:
        """
        Returns the ending offset of type info
        
        :return: ending offset of type info
        :rtype: int
        """

    def getTypesOffset(self) -> int:
        """
        Returns the starting offset of type info
        
        :return: starting offset of type info
        :rtype: int
        """

    def getUninitializedDataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getUninitializedNoPtrDataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def isValid(self) -> bool:
        """
        Returns true if this module data structure contains sane values.
        
        :return: true if this module data structure contains sane values
        :rtype: bool
        """

    def matchesPcHeader(self, otherPcHeader: GoPcHeader) -> bool:
        """
        Compares the data in this structure to fields in a GoPcHeader and returns true if they
        match.
        
        :param GoPcHeader otherPcHeader: GoPcHeader instance
        :return: boolean true if match, false if no match
        :rtype: bool
        """

    @property
    def gofunc(self) -> jpype.JLong:
        ...

    @property
    def dataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def pcHeader(self) -> GoPcHeader:
        ...

    @property
    def typesEndOffset(self) -> jpype.JLong:
        ...

    @property
    def funcnametab(self) -> GoSlice:
        ...

    @property
    def cutab(self) -> GoSlice:
        ...

    @property
    def typesOffset(self) -> jpype.JLong:
        ...

    @property
    def allFunctionData(self) -> java.util.List[GoFuncData]:
        ...

    @property
    def goBinary(self) -> GoRttiMapper:
        ...

    @property
    def roDataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def pclntable(self) -> GoSlice:
        ...

    @property
    def pcValueTable(self) -> GoSlice:
        ...

    @property
    def filetab(self) -> GoSlice:
        ...

    @property
    def typeList(self) -> java.util.List[ghidra.program.model.address.Address]:
        ...

    @property
    def pcHeaderAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def uninitializedDataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def textRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def uninitializedNoPtrDataRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def itabs(self) -> java.util.List[GoItab]:
        ...

    @property
    def text(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def pctab(self) -> GoSlice:
        ...

    @property
    def functabEntriesSlice(self) -> GoSlice:
        ...

    @property
    def funcDataInstance(self) -> GoFuncData:
        ...


class GoSourceFileInfo(java.lang.Record):
    """
    Represents a golang source file and line number tuple.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fileName: typing.Union[java.lang.String, str], lineNum: typing.Union[jpype.JInt, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def fileName(self) -> str:
        ...

    def getDescription(self) -> str:
        """
        Returns the source location info as a string formatted as "filename:linenum"
        
        :return: "filename:linenum"
        :rtype: str
        """

    def getFileName(self) -> str:
        ...

    def getLineNum(self) -> int:
        ...

    def getVerboseDescription(self) -> str:
        """
        Returns the source location info as a string formatted as "File: filename Line: linenum"
        
        :return: "File: filename Line: linenum"
        :rtype: str
        """

    def hashCode(self) -> int:
        ...

    def lineNum(self) -> int:
        ...

    def toString(self) -> str:
        ...

    @property
    def verboseDescription(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class GoTypeManager(java.lang.Object):
    """
    Manages all go RTTI type info, along with their Ghidra data type equivs.
    """

    @typing.type_check_only
    class TypeRec(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TypeStructRange(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def end(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def start(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, goBinary: GoRttiMapper, apiSnapshot: GoApiSnapshot):
        ...

    def allTypeOffsets(self) -> java.util.List[java.lang.Long]:
        ...

    def allTypes(self) -> java.util.List[ghidra.app.util.bin.format.golang.rtti.types.GoType]:
        ...

    def cacheRecoveredDataType(self, typ: ghidra.app.util.bin.format.golang.rtti.types.GoType, dt: ghidra.program.model.data.DataType):
        """
        Inserts a mapping between a :obj:`golang type <GoType>` and a 
        :obj:`ghidra data type <DataType>`.
         
        
        Useful to prepopulate the data type mapping before recursing into contained/referenced types
        that might be self-referencing.
        
        :param ghidra.app.util.bin.format.golang.rtti.types.GoType typ: :obj:`golang type <GoType>`
        :param ghidra.program.model.data.DataType dt: :obj:`Ghidra type <DataType>`
        :raises IOException: if golang type struct is not a valid struct mapped instance
        """

    @typing.overload
    def findGoType(self, typeName: typing.Union[java.lang.String, str]) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Finds a go type by its go-type name, from the list of discovered go types.
        
        :param java.lang.String or str typeName: name string
        :return: :obj:`GoType`, or null if not found
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        """

    @typing.overload
    def findGoType(self, name: GoSymbolName) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @typing.overload
    def findGoType(self, name: GoSymbolName, defaultTypeName: typing.Union[java.lang.String, str]) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @typing.overload
    def findGoType(self, typeName: typing.Union[java.lang.String, str], defaultTypeName: typing.Union[java.lang.String, str]) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @typing.overload
    def getCP(self) -> ghidra.program.model.data.CategoryPath:
        ...

    @typing.overload
    def getCP(self, typ: ghidra.app.util.bin.format.golang.rtti.types.GoType) -> ghidra.program.model.data.CategoryPath:
        """
        Returns category path that should be used to place recovered golang types.
        
        :param ghidra.app.util.bin.format.golang.rtti.types.GoType typ: :obj:`GoType`
        :return: :obj:`CategoryPath` to use when creating recovered golang types
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @typing.overload
    def getCP(self, symbolName: GoSymbolName) -> ghidra.program.model.data.CategoryPath:
        """
        Returns category path that should be used to place recovered golang types.
        
        :param GoSymbolName symbolName: :obj:`GoSymbolName` to convert to a category path
        :return: :obj:`CategoryPath` to use when creating recovered golang types
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def getChanArgGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the go type that represents a generic chan argument value.
        
        :return: golang type for chan args
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        """

    def getChanGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the go type that represents the built-in golang channel RTTI type struct.
        
        :return: golang channel type
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        """

    def getClosureTypes(self) -> java.util.List[ghidra.app.util.bin.format.golang.rtti.types.GoType]:
        ...

    def getDTM(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    def getDefaultClosureType(self) -> ghidra.program.model.data.DataType:
        ...

    def getDefaultMethodWrapperClosureType(self) -> ghidra.program.model.data.Structure:
        ...

    def getFuncMultiReturn(self, returnTypes: java.util.List[ghidra.program.model.data.DataType]) -> ghidra.program.model.data.Structure:
        ...

    def getGenericDictDT(self) -> ghidra.program.model.data.DataType:
        ...

    def getGenericITabDT(self) -> ghidra.program.model.data.Structure:
        ...

    def getGenericInterfaceDT(self) -> ghidra.program.model.data.Structure:
        ...

    def getGenericSliceDT(self) -> ghidra.program.model.data.Structure:
        """
        Returns the data type that represents a generic golang slice.
        
        :return: golang generic slice data type
        :rtype: ghidra.program.model.data.Structure
        """

    @typing.overload
    def getGhidraDataType(self, typ: ghidra.app.util.bin.format.golang.rtti.types.GoType) -> ghidra.program.model.data.DataType:
        """
        Returns a :obj:`Ghidra data type <DataType>` that represents the :obj:`golang type <GoType>`, 
        using a cache of already recovered types to eliminate extra work and self recursion.
        
        :param ghidra.app.util.bin.format.golang.rtti.types.GoType typ: the :obj:`GoType` to convert
        :return: Ghidra :obj:`DataType`
        :rtype: ghidra.program.model.data.DataType
        :raises IOException: if golang type struct is not a valid struct mapped instance
        """

    @typing.overload
    def getGhidraDataType(self, typ: ghidra.app.util.bin.format.golang.rtti.types.GoType, clazz: java.lang.Class[T], cacheOnly: typing.Union[jpype.JBoolean, bool]) -> T:
        ...

    @typing.overload
    def getGhidraDataType(self, goTypeName: typing.Union[java.lang.String, str], clazz: java.lang.Class[T]) -> T:
        ...

    def getInt32DT(self) -> ghidra.program.model.data.DataType:
        """
        Returns the data type that represents a golang int32
        
        :return: golang int32 data type
        :rtype: ghidra.program.model.data.DataType
        """

    def getInterfacesImplementedByType(self, type: ghidra.app.util.bin.format.golang.rtti.types.GoType) -> java.util.List[GoItab]:
        """
        Returns a list of interfaces that the specified type has implemented.
        
        :param ghidra.app.util.bin.format.golang.rtti.types.GoType type: GoType
        :return: list of itabs that map a GoType to the interfaces it was found to implement
        :rtype: java.util.List[GoItab]
        """

    def getMapArgGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the go type that represents a generic map argument value.
        
        :return: :obj:`GoType`
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        """

    def getMapGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the go type that represents a golang built-in map RTTI type struct.
        
        :return: golang map data type
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        """

    def getMethodClosureType(self, recvType: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataType:
        ...

    def getMethodWrapperClosureTypes(self) -> java.util.List[ghidra.app.util.bin.format.golang.rtti.types.GoType]:
        ...

    def getMissingGoTypes(self) -> java.util.Set[java.lang.String]:
        ...

    def getSubstitutionType(self, typeName: typing.Union[java.lang.String, str]) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @typing.overload
    def getType(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the :obj:`GoType` for the specified offset
        
        :param jpype.JLong or int offset: absolute position of a go type
        :return: specialized :obj:`GoType` (example, GoStructType, GoArrayType, etc)
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        :raises IOException: if error reading
        """

    @typing.overload
    def getType(self, offset: typing.Union[jpype.JLong, int], cacheOnly: typing.Union[jpype.JBoolean, bool]) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @typing.overload
    def getType(self, addr: ghidra.program.model.address.Address) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns a specialized :obj:`GoType` for the type that is located at the specified location.
        
        :param ghidra.program.model.address.Address addr: location of a go type
        :return: specialized :obj:`GoType` (example, GoStructType, GoArrayType, etc)
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        :raises IOException: if error reading
        """

    @typing.overload
    def getTypeName(self, offset: typing.Union[jpype.JLong, int]) -> str:
        """
        Returns the name of a gotype.
        
        :param jpype.JLong or int offset: offset of the gotype RTTI record
        :return: string name, with a fallback if the specified offset was invalid
        :rtype: str
        """

    @typing.overload
    def getTypeName(self, type: ghidra.app.util.bin.format.golang.rtti.types.GoType) -> str:
        ...

    def getTypeUnchecked(self, addr: ghidra.program.model.address.Address) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    def getTypesThatImplementInterface(self, iface: ghidra.app.util.bin.format.golang.rtti.types.GoInterfaceType) -> java.util.List[GoItab]:
        ...

    def getUint32DT(self) -> ghidra.program.model.data.DataType:
        """
        Returns the data type that represents a golang uint32
        
        :return: golang uint32 data type
        :rtype: ghidra.program.model.data.DataType
        """

    def getUint8DT(self) -> ghidra.program.model.data.DataType:
        ...

    def getUintDT(self) -> ghidra.program.model.data.DataType:
        ...

    def getUintptrDT(self) -> ghidra.program.model.data.DataType:
        """
        Returns the data type that represents a golang uintptr
        
        :return: golang uinptr data type
        :rtype: ghidra.program.model.data.DataType
        """

    def getVoidPtrDT(self) -> ghidra.program.model.data.DataType:
        ...

    def init(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Discovers available golang types
        
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :raises IOException: if error reading data or cancelled
        """

    def resolveTypeOff(self, ptrInModule: typing.Union[jpype.JLong, int], off: typing.Union[jpype.JLong, int]) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the :obj:`GoType` corresponding to an offset that is relative to the controlling
        GoModuledata's typesOffset.
        
        :param jpype.JLong or int ptrInModule: the address of the structure that contains the offset that needs to be
        calculated.  The containing-structure's address is important because it indicates which
        GoModuledata is the 'parent'
        :param jpype.JLong or int off: offset
        :return: :obj:`GoType`, or null if offset is special value 0 or -1
        :rtype: ghidra.app.util.bin.format.golang.rtti.types.GoType
        :raises IOException: if error
        """

    @property
    def typeUnchecked(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @property
    def int32DT(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def uintptrDT(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def ghidraDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def uint8DT(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def chanArgGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @property
    def uintDT(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def typeName(self) -> java.lang.String:
        ...

    @property
    def methodClosureType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def funcMultiReturn(self) -> ghidra.program.model.data.Structure:
        ...

    @property
    def methodWrapperClosureTypes(self) -> java.util.List[ghidra.app.util.bin.format.golang.rtti.types.GoType]:
        ...

    @property
    def type(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @property
    def defaultMethodWrapperClosureType(self) -> ghidra.program.model.data.Structure:
        ...

    @property
    def cP(self) -> ghidra.program.model.data.CategoryPath:
        ...

    @property
    def uint32DT(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def genericInterfaceDT(self) -> ghidra.program.model.data.Structure:
        ...

    @property
    def voidPtrDT(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def genericDictDT(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def substitutionType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @property
    def missingGoTypes(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def closureTypes(self) -> java.util.List[ghidra.app.util.bin.format.golang.rtti.types.GoType]:
        ...

    @property
    def mapArgGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @property
    def defaultClosureType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def dTM(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    @property
    def typesThatImplementInterface(self) -> java.util.List[GoItab]:
        ...

    @property
    def mapGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @property
    def interfacesImplementedByType(self) -> java.util.List[GoItab]:
        ...

    @property
    def chanGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        ...

    @property
    def genericSliceDT(self) -> ghidra.program.model.data.Structure:
        ...

    @property
    def genericITabDT(self) -> ghidra.program.model.data.Structure:
        ...



__all__ = ["GoPcHeader", "GoVarlenString", "GoName", "GoPcValueEvaluator", "GoItab", "GoRttiMapper", "GoApiSnapshot", "GoSlice", "MethodInfo", "GoFuncData", "JsonPatch", "GoSymbolNameType", "GoFuncFlag", "GoPcDataTable", "GoSymbolName", "JsonPatchApplier", "GoFunctabEntry", "GoIface", "GoString", "GoFuncDataTable", "GoModuledata", "GoSourceFileInfo", "GoTypeManager"]
