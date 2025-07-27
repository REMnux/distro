from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.objc2
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class ObjectiveC1_InstanceVariableList(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_method_list"

    def applyTo(self):
        ...

    def getInstanceVariableCount(self) -> int:
        ...

    def getInstanceVariables(self) -> java.util.List[ObjectiveC1_InstanceVariable]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def toGenericDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def instanceVariables(self) -> java.util.List[ObjectiveC1_InstanceVariable]:
        ...

    @property
    def instanceVariableCount(self) -> jpype.JInt:
        ...


class ObjectiveC_Method(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getImplementation(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getMethodType(self) -> ObjectiveC_MethodType:
        ...

    def getName(self) -> str:
        ...

    def getTypes(self) -> str:
        ...

    @property
    def types(self) -> java.lang.String:
        ...

    @property
    def methodType(self) -> ObjectiveC_MethodType:
        ...

    @property
    def implementation(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...


class ObjectiveC1_ProtocolMethodList(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_protocol_method_list"

    def applyTo(self):
        ...

    def getMethodCount(self) -> int:
        ...

    def getMethodList(self) -> java.util.List[ObjectiveC1_ProtocolMethod]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def toGenericDataType(state: ObjectiveC1_State) -> ghidra.program.model.data.DataType:
        ...

    @property
    def methodList(self) -> java.util.List[ObjectiveC1_ProtocolMethod]:
        ...

    @property
    def methodCount(self) -> jpype.JInt:
        ...


class ObjectiveC1_Category(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 0

    def __init__(self, state: ObjectiveC1_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getCategoryName(self) -> str:
        ...

    def getClassMethods(self) -> ObjectiveC1_MethodList:
        ...

    def getClassName(self) -> str:
        ...

    def getInstanceMethods(self) -> ObjectiveC1_MethodList:
        ...

    def getProtocols(self) -> ObjectiveC1_ProtocolList:
        ...

    def getUnknown0(self) -> int:
        ...

    def getUnknown1(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def unknown1(self) -> jpype.JInt:
        ...

    @property
    def unknown0(self) -> jpype.JInt:
        ...

    @property
    def className(self) -> java.lang.String:
        ...

    @property
    def instanceMethods(self) -> ObjectiveC1_MethodList:
        ...

    @property
    def protocols(self) -> ObjectiveC1_ProtocolList:
        ...

    @property
    def categoryName(self) -> java.lang.String:
        ...

    @property
    def classMethods(self) -> ObjectiveC1_MethodList:
        ...


class ObjectiveC1_InstanceVariable(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def applyTo(self):
        ...

    def getName(self) -> str:
        ...

    def getOffset(self) -> int:
        ...

    def getType(self) -> str:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def type(self) -> java.lang.String:
        ...


class ObjectiveC1_ProtocolMethod(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getMethodType(self) -> ObjectiveC_MethodType:
        ...

    def getName(self) -> str:
        ...

    def getTypes(self) -> str:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def types(self) -> java.lang.String:
        ...

    @property
    def methodType(self) -> ObjectiveC_MethodType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class ObjectiveC1_TypeEncodings(java.lang.Object):

    @typing.type_check_only
    class AnonymousTypes(java.lang.Enum[ObjectiveC1_TypeEncodings.AnonymousTypes]):

        class_: typing.ClassVar[java.lang.Class]
        STRUCTURE: typing.Final[ObjectiveC1_TypeEncodings.AnonymousTypes]
        UNION: typing.Final[ObjectiveC1_TypeEncodings.AnonymousTypes]
        BIT_FIELD_UNION: typing.Final[ObjectiveC1_TypeEncodings.AnonymousTypes]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ObjectiveC1_TypeEncodings.AnonymousTypes:
            ...

        @staticmethod
        def values() -> jpype.JArray[ObjectiveC1_TypeEncodings.AnonymousTypes]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    _C_ID: typing.Final = '@'
    _C_CLASS: typing.Final = '#'
    _C_SEL: typing.Final = ':'
    _C_CHR: typing.Final = 'c'
    _C_UCHR: typing.Final = 'C'
    _C_SHT: typing.Final = 's'
    _C_USHT: typing.Final = 'S'
    _C_INT: typing.Final = 'i'
    _C_UINT: typing.Final = 'I'
    _C_LNG: typing.Final = 'l'
    _C_ULNG: typing.Final = 'L'
    _C_LNG_LNG: typing.Final = 'q'
    _C_ULNG_LNG: typing.Final = 'Q'
    _C_FLT: typing.Final = 'f'
    _C_DBL: typing.Final = 'd'
    _C_BOOL: typing.Final = 'B'
    _C_VOID: typing.Final = 'v'
    _C_UNDEF: typing.Final = '?'
    _C_PTR: typing.Final = '^'
    _C_CHARPTR: typing.Final = '*'
    _C_ATOM: typing.Final = '%'
    _C_ARY_B: typing.Final = '['
    _C_ARY_E: typing.Final = ']'
    _C_UNION_B: typing.Final = '('
    _C_UNION_E: typing.Final = ')'
    _C_STRUCT_B: typing.Final = '{'
    _C_STRUCT_E: typing.Final = '}'
    _C_VECTOR: typing.Final = '!'
    _C_BFLD: typing.Final = 'b'
    _C_CONST: typing.Final = 'r'
    _C_IN: typing.Final = 'n'
    _C_INOUT: typing.Final = 'N'
    _C_OUT: typing.Final = 'o'
    _C_BYCOPY: typing.Final = 'O'
    _C_BYREF: typing.Final = 'R'
    _C_ONEWAY: typing.Final = 'V'
    _C_ATOMIC: typing.Final = 'A'

    def __init__(self, pointerSize: typing.Union[jpype.JInt, int], categoryPath: ghidra.program.model.data.CategoryPath):
        ...

    @typing.overload
    def processInstanceVariableSignature(self, program: ghidra.program.model.listing.Program, instanceVariableAddress: ghidra.program.model.address.Address, mangledType: typing.Union[java.lang.String, str], instanceVariableSize: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def processInstanceVariableSignature(self, name: typing.Union[java.lang.String, str], mangledType: typing.Union[java.lang.String, str]) -> str:
        ...

    def processMethodSignature(self, program: ghidra.program.model.listing.Program, methodAddress: ghidra.program.model.address.Address, mangledSignature: typing.Union[java.lang.String, str], methodType: ObjectiveC_MethodType):
        ...

    def toFunctionSignature(self, methodName: typing.Union[java.lang.String, str], mangledSignature: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.FunctionSignature:
        ...


class ObjectiveC_MethodType(java.lang.Enum[ObjectiveC_MethodType]):

    class_: typing.ClassVar[java.lang.Class]
    CLASS: typing.Final[ObjectiveC_MethodType]
    INSTANCE: typing.Final[ObjectiveC_MethodType]

    def getIndicator(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ObjectiveC_MethodType:
        ...

    @staticmethod
    def values() -> jpype.JArray[ObjectiveC_MethodType]:
        ...

    @property
    def indicator(self) -> jpype.JChar:
        ...


class ObjectiveC1_State(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    beenApplied: typing.Final[java.util.Set[java.lang.Long]]
    """
    If an index is contained in this set, then the corresponding data structure has been applied to the program.
    """

    methodMap: typing.Final[java.util.Map[ghidra.program.model.address.Address, ObjectiveC_Method]]
    """
    A map of method addresses to mangled signature strings.
    """

    thumbCodeLocations: typing.Final[java.util.Set[ghidra.program.model.address.Address]]
    """
    If an address is contained in this set, then it is thumb code.
    """

    program: typing.Final[ghidra.program.model.listing.Program]
    is32bit: typing.Final[jpype.JBoolean]
    is64bit: typing.Final[jpype.JBoolean]
    isARM: typing.Final[jpype.JBoolean]
    isPowerPC: typing.Final[jpype.JBoolean]
    isX86: typing.Final[jpype.JBoolean]
    pointerSize: typing.Final[jpype.JInt]
    monitor: typing.Final[ghidra.util.task.TaskMonitor]
    encodings: typing.Final[ObjectiveC1_TypeEncodings]

    def __init__(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, categoryPath: ghidra.program.model.data.CategoryPath):
        ...

    def dispose(self):
        ...

    def getObjectiveCSectionNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def objectiveCSectionNames(self) -> java.util.List[java.lang.String]:
        ...


class ObjectiveC1_Method(ObjectiveC_Method):

    class_: typing.ClassVar[java.lang.Class]

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...


class ObjectiveC_MethodList(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getMethods(self) -> java.util.List[ObjectiveC_Method]:
        ...

    @property
    def methods(self) -> java.util.List[ObjectiveC_Method]:
        ...


class ObjectiveC1_Class(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_class"
    SIZEOF: typing.Final = 48

    def __init__(self, state: ObjectiveC1_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getCache(self) -> int:
        ...

    def getISA(self) -> ObjectiveC1_MetaClass:
        ...

    def getInfo(self) -> int:
        ...

    def getInstanceSize(self) -> int:
        ...

    def getInstanceVariableList(self) -> ObjectiveC1_InstanceVariableList:
        ...

    def getMethodList(self) -> ObjectiveC1_MethodList:
        ...

    def getName(self) -> str:
        ...

    def getProtocols(self) -> ObjectiveC1_ProtocolList:
        ...

    def getSuperClass(self) -> str:
        ...

    def getUnknown0(self) -> int:
        ...

    def getUnknown1(self) -> int:
        ...

    def getVersion(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def instanceSize(self) -> jpype.JInt:
        ...

    @property
    def cache(self) -> jpype.JInt:
        ...

    @property
    def superClass(self) -> java.lang.String:
        ...

    @property
    def instanceVariableList(self) -> ObjectiveC1_InstanceVariableList:
        ...

    @property
    def iSA(self) -> ObjectiveC1_MetaClass:
        ...

    @property
    def unknown1(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def unknown0(self) -> jpype.JInt:
        ...

    @property
    def methodList(self) -> ObjectiveC1_MethodList:
        ...

    @property
    def protocols(self) -> ObjectiveC1_ProtocolList:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> jpype.JInt:
        ...


class ObjectiveC1_Utilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def applyData(program: ghidra.program.model.listing.Program, dt: ghidra.program.model.data.DataType, address: ghidra.program.model.address.Address):
        """
        Applies the data type at the specified address.
        """

    @staticmethod
    def clear(state: ghidra.app.util.bin.format.objc2.ObjectiveC2_State, block: ghidra.program.model.mem.MemoryBlock):
        """
        Clears the code units defined in the given memory block.
        """

    @staticmethod
    def createInstanceVariablesC2_OBJC2(state: ghidra.app.util.bin.format.objc2.ObjectiveC2_State):
        ...

    @staticmethod
    def createMethods(state: ObjectiveC1_State):
        ...

    @staticmethod
    def createNamespace(program: ghidra.program.model.listing.Program, *namespacePath: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        """
        Creates a namespace hierarchy using the list of strings specified in namespacePath.
        """

    @staticmethod
    def createPointerAndReturnAddressBeingReferenced(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Applies a pointer data type at the specified address and returns the address being referenced.
        """

    @staticmethod
    def createString(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> str:
        """
        Applies a string data type at the specified address and returns the string object.
        """

    @staticmethod
    def createSymbol(program: ghidra.program.model.listing.Program, parentNamespace: ghidra.program.model.symbol.Namespace, symbolName: typing.Union[java.lang.String, str], symbolAddress: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
        """
        Creates a symbol.
        
        TODO - make symbols primary?
        """

    @staticmethod
    def dereferenceAsciiString(reader: ghidra.app.util.bin.BinaryReader, is32bit: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Dereferences a string pointer and returns the string.
        If 32-bit only reads a 32-bit pointer.
        """

    @staticmethod
    def fixupReferences(state: ObjectiveC1_State):
        """
        This method will remove references to the NULL address
        and it will adjust THUMB references to no longer be offcut.
        """

    @staticmethod
    @typing.overload
    def formatAsObjectiveC(function: ghidra.program.model.listing.Function, methodType: ObjectiveC_MethodType) -> str:
        ...

    @staticmethod
    @typing.overload
    def formatAsObjectiveC(signature: ghidra.program.model.listing.FunctionSignature, methodType: ObjectiveC_MethodType, appendSemicolon: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @staticmethod
    def getClassNamespace(program: ghidra.program.model.listing.Program, parentNamespace: ghidra.program.model.symbol.Namespace, namespaceName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the class inside the given parent name space.
        If it does not exist, then create it and return it.
        """

    @staticmethod
    def isNull(address: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the given address is zero.
        """

    @staticmethod
    @typing.overload
    def isThumb(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the address is THUMB code.
        """

    @staticmethod
    @typing.overload
    def isThumb(program: ghidra.program.model.listing.Program, address: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the address is THUMB code.
        """

    @staticmethod
    def readNextIndex(reader: ghidra.app.util.bin.BinaryReader, is32bit: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Reads the next index value. If is32bit is true, then 4 bytes
        will be read to form index. Otherwise, 8 bytes will be read to form index.
        """

    @staticmethod
    def setThumbBit(state: ObjectiveC1_State, address: ghidra.program.model.address.Address):
        """
        If needed, sets the TMode bit at the specified address.
        """

    @staticmethod
    def toAddress(program: ghidra.program.model.listing.Program, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Manufactures an address from the given long.
        """


class ObjectiveC1_MetaClass(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def applyTo(self):
        ...

    def getCache(self) -> int:
        ...

    def getISA(self) -> str:
        ...

    def getInfo(self) -> int:
        ...

    def getInstanceSize(self) -> int:
        ...

    def getInstanceVariableList(self) -> ObjectiveC1_InstanceVariableList:
        ...

    def getMethodList(self) -> ObjectiveC1_MethodList:
        ...

    def getName(self) -> str:
        ...

    def getProtocols(self) -> ObjectiveC1_ProtocolList:
        ...

    def getSuperClass(self) -> str:
        ...

    def getUnknown0(self) -> int:
        ...

    def getUnknown1(self) -> int:
        ...

    def getVersion(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def instanceSize(self) -> jpype.JInt:
        ...

    @property
    def cache(self) -> jpype.JInt:
        ...

    @property
    def superClass(self) -> java.lang.String:
        ...

    @property
    def instanceVariableList(self) -> ObjectiveC1_InstanceVariableList:
        ...

    @property
    def iSA(self) -> java.lang.String:
        ...

    @property
    def unknown1(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def unknown0(self) -> jpype.JInt:
        ...

    @property
    def methodList(self) -> ObjectiveC1_MethodList:
        ...

    @property
    def protocols(self) -> ObjectiveC1_ProtocolList:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> jpype.JInt:
        ...


class ObjectiveC1_Constants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    NAMESPACE: typing.Final = "objc"
    CATEGORY: typing.Final = "/objc"
    CATEGORY_PATH: typing.Final[ghidra.program.model.data.CategoryPath]
    OBJC_SECTION_CATEGORY: typing.Final = "__category"
    OBJC_SECTION_CATEGORY_CLASS_METHODS: typing.Final = "__cat_cls_meth"
    OBJC_SECTION_CATEGORY_INSTANCE_METHODS: typing.Final = "__cat_inst_meth"
    OBJC_SECTION_CLASS: typing.Final = "__class"
    OBJC_SECTION_CLASS_METHODS: typing.Final = "__cls_meth"
    OBJC_SECTION_CLASS_REFS: typing.Final = "__cls_refs"
    OBJC_SECTION_INSTANCE_METHODS: typing.Final = "__inst_meth"
    OBJC_SECTION_INSTANCE_VARS: typing.Final = "__instance_vars"
    OBJC_SECTION_MESSAGE_REFS: typing.Final = "__message_refs"
    OBJC_SECTION_METACLASS: typing.Final = "__meta_class"
    OBJC_SECTION_MODULE_INFO: typing.Final = "__module_info"
    OBJC_SECTION_PROTOCOL: typing.Final = "__protocol"
    OBJC_SECTION_SYMBOLS: typing.Final = "__symbols"
    OBJC_SECTION_DATA: typing.Final = "__data"
    READ_UNIX2003: typing.Final = "_read$UNIX2003"
    OBJC_MSG_SEND: typing.Final = "_objc_msgSend"
    OBJC_MSG_SEND_WILDCARD: typing.Final = "_objc_msgSend*"
    OBJC_MSG_SEND_RTP_NAME: typing.Final = "_objc_msgSend_rtp"
    OBJ_MSGSEND_RTP: typing.Final = 4294901504
    """
    Absolute symbol binding the runtime page (RTP) version of objc_msgSend.
    """

    OBJ_MSGSEND_RTP_EXIT: typing.Final = 4294901760
    """
    Absolute symbol binding the runtime page (RTP) version of objc_msgSend_Exit.
    """


    def __init__(self):
        ...

    @staticmethod
    def getObjectiveCSectionNames() -> java.util.List[java.lang.String]:
        """
        Returns a list containing valid Objective-C section names.
        
        :return: a list containing valid Objective-C section names
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def isObjectiveC(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if this program contains Objective-C.
        
        :param ghidra.program.model.listing.Program program: the program to check
        :return: true if the program contains Objective-C.
        :rtype: bool
        """


class ObjectiveC1_Protocol(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_protocol"
    SIZEOF: typing.Final = 20

    def __init__(self, state: ObjectiveC1_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getClassMethods(self) -> ObjectiveC1_ProtocolMethodList:
        ...

    def getInstanceMethods(self) -> ObjectiveC1_ProtocolMethodList:
        ...

    def getIsa(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getProtocolList(self) -> ObjectiveC1_ProtocolList:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def protocolList(self) -> ObjectiveC1_ProtocolList:
        ...

    @property
    def isa(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def instanceMethods(self) -> ObjectiveC1_ProtocolMethodList:
        ...

    @property
    def classMethods(self) -> ObjectiveC1_ProtocolMethodList:
        ...


class ObjectiveC1_ProtocolList(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_protocol_list"

    def applyTo(self):
        ...

    def getCount(self) -> int:
        ...

    def getNext(self) -> ObjectiveC1_ProtocolList:
        ...

    def getProtocols(self) -> java.util.List[ObjectiveC1_Protocol]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def toGenericDataType(state: ObjectiveC1_State) -> ghidra.program.model.data.DataType:
        ...

    @property
    def next(self) -> ObjectiveC1_ProtocolList:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def protocols(self) -> java.util.List[ObjectiveC1_Protocol]:
        ...


class ObjectiveC1_SymbolTable(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_symtab"

    def applyTo(self):
        ...

    def getCategories(self) -> java.util.List[ObjectiveC1_Category]:
        ...

    def getCategoryDefinitionCount(self) -> int:
        ...

    def getClassDefinitionCount(self) -> int:
        ...

    def getClasses(self) -> java.util.List[ObjectiveC1_Class]:
        ...

    def getRefs(self) -> int:
        ...

    def getSelectorReferenceCount(self) -> int:
        ...

    @staticmethod
    def toGenericDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def refs(self) -> jpype.JInt:
        ...

    @property
    def classes(self) -> java.util.List[ObjectiveC1_Class]:
        ...

    @property
    def classDefinitionCount(self) -> jpype.JShort:
        ...

    @property
    def categories(self) -> java.util.List[ObjectiveC1_Category]:
        ...

    @property
    def selectorReferenceCount(self) -> jpype.JInt:
        ...

    @property
    def categoryDefinitionCount(self) -> jpype.JShort:
        ...


class ObjectiveC1_Module(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: ObjectiveC1_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getName(self) -> str:
        ...

    def getSize(self) -> int:
        ...

    def getSymbolTable(self) -> ObjectiveC1_SymbolTable:
        ...

    def getVersion(self) -> int:
        ...

    @property
    def symbolTable(self) -> ObjectiveC1_SymbolTable:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...


class ObjectiveC1_MethodList(ObjectiveC_MethodList):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_method_list"

    def getMethodCount(self) -> int:
        ...

    def getObsolete(self) -> ObjectiveC1_MethodList:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def toGenericDataType(state: ObjectiveC1_State) -> ghidra.program.model.data.DataType:
        ...

    @property
    def obsolete(self) -> ObjectiveC1_MethodList:
        ...

    @property
    def methodCount(self) -> jpype.JInt:
        ...



__all__ = ["ObjectiveC1_InstanceVariableList", "ObjectiveC_Method", "ObjectiveC1_ProtocolMethodList", "ObjectiveC1_Category", "ObjectiveC1_InstanceVariable", "ObjectiveC1_ProtocolMethod", "ObjectiveC1_TypeEncodings", "ObjectiveC_MethodType", "ObjectiveC1_State", "ObjectiveC1_Method", "ObjectiveC_MethodList", "ObjectiveC1_Class", "ObjectiveC1_Utilities", "ObjectiveC1_MetaClass", "ObjectiveC1_Constants", "ObjectiveC1_Protocol", "ObjectiveC1_ProtocolList", "ObjectiveC1_SymbolTable", "ObjectiveC1_Module", "ObjectiveC1_MethodList"]
