from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.bin.format.objectiveC
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class ObjectiveC2_Utilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createSymbolUsingMemoryBlockAsNamespace(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
        """
        Creates a symbol with the given name at the specified address.
        The symbol will be created in a name space with the name of
        the memory block that contains the address.
        """


class ObjectiveC2_State(ghidra.app.util.bin.format.objectiveC.ObjectiveC1_State):

    class_: typing.ClassVar[java.lang.Class]
    classIndexMap: typing.Final[java.util.Map[java.lang.Long, ObjectiveC2_Class]]
    """
    A map of the index where the class structure was defined to instantiated class object.
    """

    variableMap: typing.Final[java.util.Map[ghidra.program.model.address.Address, ObjectiveC2_InstanceVariable]]
    """
    A map of instance variable addresses to mangled type strings.
    """

    libObjcOptimization: ghidra.app.util.bin.format.macho.dyld.LibObjcOptimization
    """
    The dyld_shared_cache libobjc objc_opt_t structure, if it exists
    """


    def __init__(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, categoryPath: ghidra.program.model.data.CategoryPath):
        ...


class ObjectiveC2_Constants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    OBJC2_PREFIX: typing.Final = "__objc_"
    """
    The name prefix of all Objective-C 2 sections.
    """

    OBJC2_CATEGORY_LIST: typing.Final = "__objc_catlist"
    """
    Objective-C 2 category list.
    """

    OBJC2_CLASS_LIST: typing.Final = "__objc_classlist"
    """
    Objective-C 2 class list.
    """

    OBJC2_CLASS_REFS: typing.Final = "__objc_classrefs"
    """
    Objective-C 2 class references.
    """

    OBJC2_CONST: typing.Final = "__objc_const"
    """
    Objective-C 2 constants.
    """

    OBJC2_DATA: typing.Final = "__objc_data"
    OBJC2_IMAGE_INFO: typing.Final = "__objc_imageinfo"
    OBJC2_MESSAGE_REFS: typing.Final = "__objc_msgrefs"
    OBJC2_NON_LAZY_CLASS_LIST: typing.Final = "__objc_nlclslist"
    """
    Objective-C 2 non-lazy class list
    """

    OBJC2_PROTOCOL_LIST: typing.Final = "__objc_protolist"
    OBJC2_PROTOCOL_REFS: typing.Final = "__objc_protorefs"
    OBJC2_SELECTOR_REFS: typing.Final = "__objc_selrefs"
    OBJC2_SUPER_REFS: typing.Final = "__objc_superrefs"
    NAMESPACE: typing.Final = "objc2"
    CATEGORY: typing.Final = "/_objc2_"
    CATEGORY_PATH: typing.Final[ghidra.program.model.data.CategoryPath]

    def __init__(self):
        ...

    @staticmethod
    def getObjectiveC2SectionNames() -> java.util.List[java.lang.String]:
        """
        Returns a list containing valid Objective-C 2.0 section names.
        
        :return: a list containing valid Objective-C 2.0 section names
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def isObjectiveC2(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if this program contains Objective-C 2.
        
        :param ghidra.program.model.listing.Program program: the program to check
        :return: true if the program contains Objective-C 2.
        :rtype: bool
        """


class ObjectiveC2_InstanceVariable(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getAlignment(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getOffset(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    def getType(self) -> str:
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
    def name(self) -> java.lang.String:
        ...

    @property
    def type(self) -> java.lang.String:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...


class ObjectiveC2_MethodList(ghidra.app.util.bin.format.objectiveC.ObjectiveC_MethodList):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "method_list_t"

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader, methodType: ghidra.app.util.bin.format.objectiveC.ObjectiveC_MethodType):
        ...

    def getCount(self) -> int:
        ...

    def getEntsizeAndFlags(self) -> int:
        ...

    @staticmethod
    def toGenericDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def count(self) -> jpype.JLong:
        ...

    @property
    def entsizeAndFlags(self) -> jpype.JLong:
        ...


class ObjectiveC2_Method(ghidra.app.util.bin.format.objectiveC.ObjectiveC_Method):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader, methodType: ghidra.app.util.bin.format.objectiveC.ObjectiveC_MethodType, isSmallList: typing.Union[jpype.JBoolean, bool]):
        ...


class ObjectiveC2_PropertyList(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_property_list"

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getCount(self) -> int:
        ...

    def getEntrySize(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getProperties(self) -> java.util.List[ObjectiveC2_Property]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def toGenericDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def properties(self) -> java.util.List[ObjectiveC2_Property]:
        ...

    @property
    def entrySize(self) -> jpype.JInt:
        ...


class ObjectiveC2_Category(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "category_t"

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getClassMethods(self) -> ObjectiveC2_MethodList:
        ...

    def getCls(self) -> ObjectiveC2_Class:
        ...

    def getIndex(self) -> int:
        ...

    def getInstanceMethods(self) -> ObjectiveC2_MethodList:
        ...

    def getInstanceProperties(self) -> ObjectiveC2_PropertyList:
        ...

    def getName(self) -> str:
        ...

    def getProtocols(self) -> ObjectiveC2_ProtocolList:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def instanceProperties(self) -> ObjectiveC2_PropertyList:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def instanceMethods(self) -> ObjectiveC2_MethodList:
        ...

    @property
    def cls(self) -> ObjectiveC2_Class:
        ...

    @property
    def protocols(self) -> ObjectiveC2_ProtocolList:
        ...

    @property
    def classMethods(self) -> ObjectiveC2_MethodList:
        ...


class ObjectiveC2_MessageReference(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "message_ref"

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    @staticmethod
    def SIZEOF(state: ObjectiveC2_State) -> int:
        ...

    def getImplementation(self) -> int:
        ...

    def getSelector(self) -> str:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def implementation(self) -> jpype.JLong:
        ...

    @property
    def selector(self) -> java.lang.String:
        ...


class ObjectiveC2_ImageInfo(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    OBJC_IMAGE_IS_REPLACEMENT: typing.Final = 1
    OBJC_IMAGE_SUPPORTS_GC: typing.Final = 2
    OBJC_IMAGE_REQUIRES_GC: typing.Final = 4

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getFlags(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getVersion(self) -> int:
        ...

    def isReplacement(self) -> bool:
        ...

    def isRequiresGarbageCollection(self) -> bool:
        ...

    def isSupportsGarbageCollection(self) -> bool:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def supportsGarbageCollection(self) -> jpype.JBoolean:
        ...

    @property
    def requiresGarbageCollection(self) -> jpype.JBoolean:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def replacement(self) -> jpype.JBoolean:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...


class ObjectiveC2_Implementation(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader, isSmall: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getImplementation(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def implementation(self) -> jpype.JLong:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...


class ObjectiveC2_InstanceVariableList(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ivar_list_t"

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getCount(self) -> int:
        ...

    def getEntsize(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getIvars(self) -> java.util.List[ObjectiveC2_InstanceVariable]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def toGenericDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def count(self) -> jpype.JLong:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def ivars(self) -> java.util.List[ObjectiveC2_InstanceVariable]:
        ...

    @property
    def entsize(self) -> jpype.JLong:
        ...


class ObjectiveC2_Cache(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getCache(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def cache(self) -> jpype.JLong:
        ...


class ObjectiveC2_Property(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getAttributes(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def attributes(self) -> java.lang.String:
        ...


class ObjectiveC2_ClassRW(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "class_rw_t"

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getBaseMethods(self) -> ObjectiveC2_MethodList:
        ...

    def getBaseProperties(self) -> ObjectiveC2_PropertyList:
        ...

    def getBaseProtocols(self) -> ObjectiveC2_ProtocolList:
        ...

    def getFlags(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getInstanceSize(self) -> int:
        ...

    def getInstanceStart(self) -> int:
        ...

    def getInstanceVariables(self) -> ObjectiveC2_InstanceVariableList:
        ...

    def getName(self) -> str:
        ...

    def getReserved(self) -> int:
        ...

    def getWeakIvarLayout(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def baseMethods(self) -> ObjectiveC2_MethodList:
        ...

    @property
    def instanceSize(self) -> jpype.JLong:
        ...

    @property
    def instanceStart(self) -> jpype.JLong:
        ...

    @property
    def instanceVariables(self) -> ObjectiveC2_InstanceVariableList:
        ...

    @property
    def weakIvarLayout(self) -> jpype.JLong:
        ...

    @property
    def reserved(self) -> jpype.JLong:
        ...

    @property
    def baseProperties(self) -> ObjectiveC2_PropertyList:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def flags(self) -> jpype.JLong:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def baseProtocols(self) -> ObjectiveC2_ProtocolList:
        ...


class ObjectiveC2_Class(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "class_t"

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self):
        ...

    def getCache(self) -> ObjectiveC2_Cache:
        ...

    def getData(self) -> ObjectiveC2_ClassRW:
        ...

    def getISA(self) -> ObjectiveC2_Class:
        ...

    def getIndex(self) -> int:
        ...

    def getSuperClass(self) -> ObjectiveC2_Class:
        ...

    def getVTable(self) -> ObjectiveC2_Implementation:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def vTable(self) -> ObjectiveC2_Implementation:
        ...

    @property
    def cache(self) -> ObjectiveC2_Cache:
        ...

    @property
    def data(self) -> ObjectiveC2_ClassRW:
        ...

    @property
    def superClass(self) -> ObjectiveC2_Class:
        ...

    @property
    def iSA(self) -> ObjectiveC2_Class:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...


class ObjectiveC2_Protocol(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "protocol_t"

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getClassMethods(self) -> ObjectiveC2_MethodList:
        ...

    def getIndex(self) -> int:
        ...

    def getInstanceMethods(self) -> ObjectiveC2_MethodList:
        ...

    def getInstanceProperties(self) -> ObjectiveC2_PropertyList:
        ...

    def getIsa(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getOptionalClassMethods(self) -> ObjectiveC2_MethodList:
        ...

    def getOptionalInstanceMethods(self) -> ObjectiveC2_MethodList:
        ...

    def getProtocols(self) -> ObjectiveC2_ProtocolList:
        ...

    def getUnknown0(self) -> int:
        ...

    def getUnknown1(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def instanceProperties(self) -> ObjectiveC2_PropertyList:
        ...

    @property
    def isa(self) -> jpype.JLong:
        ...

    @property
    def unknown1(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def unknown0(self) -> jpype.JLong:
        ...

    @property
    def optionalClassMethods(self) -> ObjectiveC2_MethodList:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def instanceMethods(self) -> ObjectiveC2_MethodList:
        ...

    @property
    def protocols(self) -> ObjectiveC2_ProtocolList:
        ...

    @property
    def optionalInstanceMethods(self) -> ObjectiveC2_MethodList:
        ...

    @property
    def classMethods(self) -> ObjectiveC2_MethodList:
        ...


class ObjectiveC2_ProtocolList(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "protocol_list_t"

    def __init__(self, state: ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getCount(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getProtocols(self) -> java.util.List[ObjectiveC2_Protocol]:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def toGenericDataType(state: ObjectiveC2_State) -> ghidra.program.model.data.DataType:
        ...

    @property
    def count(self) -> jpype.JLong:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def protocols(self) -> java.util.List[ObjectiveC2_Protocol]:
        ...



__all__ = ["ObjectiveC2_Utilities", "ObjectiveC2_State", "ObjectiveC2_Constants", "ObjectiveC2_InstanceVariable", "ObjectiveC2_MethodList", "ObjectiveC2_Method", "ObjectiveC2_PropertyList", "ObjectiveC2_Category", "ObjectiveC2_MessageReference", "ObjectiveC2_ImageInfo", "ObjectiveC2_Implementation", "ObjectiveC2_InstanceVariableList", "ObjectiveC2_Cache", "ObjectiveC2_Property", "ObjectiveC2_ClassRW", "ObjectiveC2_Class", "ObjectiveC2_Protocol", "ObjectiveC2_ProtocolList"]
