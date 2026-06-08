from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.objc
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class Objc1Class(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_class"
    SIZEOF: typing.Final = 48

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getCache(self) -> int:
        ...

    def getISA(self) -> Objc1MetaClass:
        ...

    def getInfo(self) -> int:
        ...

    def getInstanceSize(self) -> int:
        ...

    def getInstanceVariableList(self) -> Objc1InstanceVariableList:
        ...

    def getMethodList(self) -> Objc1MethodList:
        ...

    def getName(self) -> str:
        ...

    def getProtocols(self) -> Objc1ProtocolList:
        ...

    def getSuperClass(self) -> str:
        ...

    def getUnknown0(self) -> int:
        ...

    def getUnknown1(self) -> int:
        ...

    def getVersion(self) -> int:
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
    def instanceVariableList(self) -> Objc1InstanceVariableList:
        ...

    @property
    def iSA(self) -> Objc1MetaClass:
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
    def methodList(self) -> Objc1MethodList:
        ...

    @property
    def protocols(self) -> Objc1ProtocolList:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> jpype.JInt:
        ...


class Objc1ProtocolMethodList(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_protocol_method_list"

    def getMethodCount(self) -> int:
        ...

    def getMethodList(self) -> java.util.List[Objc1ProtocolMethod]:
        ...

    @staticmethod
    def toGenericDataType(state: ghidra.app.util.bin.format.objc.ObjcState) -> ghidra.program.model.data.DataType:
        ...

    @property
    def methodList(self) -> java.util.List[Objc1ProtocolMethod]:
        ...

    @property
    def methodCount(self) -> jpype.JInt:
        ...


class Objc1InstanceVariable(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def getName(self) -> str:
        ...

    def getOffset(self) -> int:
        ...

    def getType(self) -> str:
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


class Objc1MetaClass(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def getCache(self) -> int:
        ...

    def getISA(self) -> str:
        ...

    def getInfo(self) -> int:
        ...

    def getInstanceSize(self) -> int:
        ...

    def getInstanceVariableList(self) -> Objc1InstanceVariableList:
        ...

    def getMethodList(self) -> Objc1MethodList:
        ...

    def getName(self) -> str:
        ...

    def getProtocols(self) -> Objc1ProtocolList:
        ...

    def getSuperClass(self) -> str:
        ...

    def getUnknown0(self) -> int:
        ...

    def getUnknown1(self) -> int:
        ...

    def getVersion(self) -> int:
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
    def instanceVariableList(self) -> Objc1InstanceVariableList:
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
    def methodList(self) -> Objc1MethodList:
        ...

    @property
    def protocols(self) -> Objc1ProtocolList:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> jpype.JInt:
        ...


class Objc1Constants(java.lang.Object):

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


    def __init__(self) -> None:
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


class Objc1Protocol(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_protocol"
    SIZEOF: typing.Final = 20

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getClassMethods(self) -> Objc1ProtocolMethodList:
        ...

    def getInstanceMethods(self) -> Objc1ProtocolMethodList:
        ...

    def getIsa(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getProtocolList(self) -> Objc1ProtocolList:
        ...

    @property
    def protocolList(self) -> Objc1ProtocolList:
        ...

    @property
    def isa(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def instanceMethods(self) -> Objc1ProtocolMethodList:
        ...

    @property
    def classMethods(self) -> Objc1ProtocolMethodList:
        ...


class Objc1Module(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getName(self) -> str:
        ...

    def getSize(self) -> int:
        ...

    def getSymbolTable(self) -> Objc1SymbolTable:
        ...

    def getVersion(self) -> int:
        ...

    @property
    def symbolTable(self) -> Objc1SymbolTable:
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


class Objc1SymbolTable(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_symtab"

    def getCategories(self) -> java.util.List[Objc1Category]:
        ...

    def getCategoryDefinitionCount(self) -> int:
        ...

    def getClassDefinitionCount(self) -> int:
        ...

    def getClasses(self) -> java.util.List[Objc1Class]:
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
    def classes(self) -> java.util.List[Objc1Class]:
        ...

    @property
    def classDefinitionCount(self) -> jpype.JShort:
        ...

    @property
    def categories(self) -> java.util.List[Objc1Category]:
        ...

    @property
    def selectorReferenceCount(self) -> jpype.JInt:
        ...

    @property
    def categoryDefinitionCount(self) -> jpype.JShort:
        ...


class Objc1TypeEncodings(java.lang.Object):

    @typing.type_check_only
    class AnonymousTypes(java.lang.Enum[Objc1TypeEncodings.AnonymousTypes]):

        class_: typing.ClassVar[java.lang.Class]
        STRUCTURE: typing.Final[Objc1TypeEncodings.AnonymousTypes]
        UNION: typing.Final[Objc1TypeEncodings.AnonymousTypes]
        BIT_FIELD_UNION: typing.Final[Objc1TypeEncodings.AnonymousTypes]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Objc1TypeEncodings.AnonymousTypes:
            ...

        @staticmethod
        def values() -> jpype.JArray[Objc1TypeEncodings.AnonymousTypes]:
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

    def __init__(self, pointerSize: typing.Union[jpype.JInt, int], categoryPath: ghidra.program.model.data.CategoryPath) -> None:
        ...

    @typing.overload
    def processInstanceVariableSignature(self, program: ghidra.program.model.listing.Program, instanceVariableAddress: ghidra.program.model.address.Address, mangledType: typing.Union[java.lang.String, str], instanceVariableSize: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def processInstanceVariableSignature(self, name: typing.Union[java.lang.String, str], mangledType: typing.Union[java.lang.String, str]) -> str:
        ...

    def processMethodSignature(self, program: ghidra.program.model.listing.Program, methodAddress: ghidra.program.model.address.Address, mangledSignature: typing.Union[java.lang.String, str], methodType: ghidra.app.util.bin.format.objc.ObjcMethodType) -> None:
        ...

    def toFunctionSignature(self, methodName: typing.Union[java.lang.String, str], mangledSignature: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.FunctionSignature:
        ...


class Objc1ProtocolMethod(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def getMethodType(self) -> ghidra.app.util.bin.format.objc.ObjcMethodType:
        ...

    def getName(self) -> str:
        ...

    def getTypes(self) -> str:
        ...

    @property
    def types(self) -> java.lang.String:
        ...

    @property
    def methodType(self) -> ghidra.app.util.bin.format.objc.ObjcMethodType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class Objc1ProtocolList(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_protocol_list"

    def getCount(self) -> int:
        ...

    def getNext(self) -> Objc1ProtocolList:
        ...

    def getProtocols(self) -> java.util.List[Objc1Protocol]:
        ...

    @staticmethod
    def toGenericDataType(pointerSize: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataType:
        ...

    @property
    def next(self) -> Objc1ProtocolList:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def protocols(self) -> java.util.List[Objc1Protocol]:
        ...


class Objc1Method(ghidra.app.util.bin.format.objc.ObjcMethod):
    ...
    class_: typing.ClassVar[java.lang.Class]


class Objc1Category(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 0

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getCategoryName(self) -> str:
        ...

    def getClassMethods(self) -> Objc1MethodList:
        ...

    def getClassName(self) -> str:
        ...

    def getInstanceMethods(self) -> Objc1MethodList:
        ...

    def getProtocols(self) -> Objc1ProtocolList:
        ...

    def getUnknown0(self) -> int:
        ...

    def getUnknown1(self) -> int:
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
    def instanceMethods(self) -> Objc1MethodList:
        ...

    @property
    def protocols(self) -> Objc1ProtocolList:
        ...

    @property
    def categoryName(self) -> java.lang.String:
        ...

    @property
    def classMethods(self) -> Objc1MethodList:
        ...


class Objc1TypeMetadata(ghidra.app.util.bin.format.objc.AbstractObjcTypeMetadata):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Creates a new :obj:`Objc1TypeMetadata`
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises IOException: if there was an IO-related error
        :raises CancelledException: if the user cancelled the operation
        """

    def getModules(self) -> java.util.List[Objc1Module]:
        """
        :return: a :obj:`List` of :obj:`modules <Objc1Module>`
        :rtype: java.util.List[Objc1Module]
        """

    def getProtocols(self) -> java.util.List[Objc1Protocol]:
        """
        :return: a :obj:`List` of :obj:`protocols <Objc1Protocol>`
        :rtype: java.util.List[Objc1Protocol]
        """

    @property
    def protocols(self) -> java.util.List[Objc1Protocol]:
        ...

    @property
    def modules(self) -> java.util.List[Objc1Module]:
        ...


class Objc1InstanceVariableList(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_method_list"

    def getInstanceVariableCount(self) -> int:
        ...

    def getInstanceVariables(self) -> java.util.List[Objc1InstanceVariable]:
        ...

    @staticmethod
    def toGenericDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def instanceVariables(self) -> java.util.List[Objc1InstanceVariable]:
        ...

    @property
    def instanceVariableCount(self) -> jpype.JInt:
        ...


class Objc1MethodList(ghidra.app.util.bin.format.objc.ObjcMethodList):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_method_list"

    def getMethodCount(self) -> int:
        ...

    def getObsolete(self) -> Objc1MethodList:
        ...

    @staticmethod
    def toGenericDataType(pointerSize: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataType:
        ...

    @property
    def obsolete(self) -> Objc1MethodList:
        ...

    @property
    def methodCount(self) -> jpype.JInt:
        ...



__all__ = ["Objc1Class", "Objc1ProtocolMethodList", "Objc1InstanceVariable", "Objc1MetaClass", "Objc1Constants", "Objc1Protocol", "Objc1Module", "Objc1SymbolTable", "Objc1TypeEncodings", "Objc1ProtocolMethod", "Objc1ProtocolList", "Objc1Method", "Objc1Category", "Objc1TypeMetadata", "Objc1InstanceVariableList", "Objc1MethodList"]
