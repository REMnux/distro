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


class Objc2PropertyList(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "objc_property_list"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getCount(self) -> int:
        ...

    def getEntrySize(self) -> int:
        ...

    def getProperties(self) -> java.util.List[Objc2Property]:
        ...

    @staticmethod
    def toGenericDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def properties(self) -> java.util.List[Objc2Property]:
        ...

    @property
    def entrySize(self) -> jpype.JInt:
        ...


class Objc2Constants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    OBJC2_PREFIX: typing.Final = "__objc_"
    """
    The name prefix of all Objective-C 2 sections.
    """

    OBJC2_CATEGORY_LIST: typing.Final = "__objc_catlist"
    OBJC2_CLASS_LIST: typing.Final = "__objc_classlist"
    OBJC2_CLASS_REFS: typing.Final = "__objc_classrefs"
    OBJC2_CONST: typing.Final = "__objc_const"
    OBJC2_DATA: typing.Final = "__objc_data"
    OBJC2_IMAGE_INFO: typing.Final = "__objc_imageinfo"
    OBJC2_MESSAGE_REFS: typing.Final = "__objc_msgrefs"
    OBJC2_NON_LAZY_CLASS_LIST: typing.Final = "__objc_nlclslist"
    OBJC2_PROTOCOL_LIST: typing.Final = "__objc_protolist"
    OBJC2_PROTOCOL_REFS: typing.Final = "__objc_protorefs"
    OBJC2_SELECTOR_REFS: typing.Final = "__objc_selrefs"
    OBJC2_SUPER_REFS: typing.Final = "__objc_superrefs"
    OBJC2_STUBS: typing.Final = "__objc_stubs"
    NAMESPACE: typing.Final = "objc2"
    CATEGORY: typing.Final = "/_objc2_"
    CATEGORY_PATH: typing.Final[ghidra.program.model.data.CategoryPath]

    def __init__(self) -> None:
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


class Objc2Protocol(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "protocol_t"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getClassMethods(self) -> Objc2MethodList:
        ...

    def getIndex(self) -> int:
        ...

    def getInstanceMethods(self) -> Objc2MethodList:
        ...

    def getInstanceProperties(self) -> Objc2PropertyList:
        ...

    def getIsa(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getOptionalClassMethods(self) -> Objc2MethodList:
        ...

    def getOptionalInstanceMethods(self) -> Objc2MethodList:
        ...

    def getProtocols(self) -> Objc2ProtocolList:
        ...

    def getUnknown0(self) -> int:
        ...

    def getUnknown1(self) -> int:
        ...

    @property
    def instanceProperties(self) -> Objc2PropertyList:
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
    def optionalClassMethods(self) -> Objc2MethodList:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...

    @property
    def instanceMethods(self) -> Objc2MethodList:
        ...

    @property
    def protocols(self) -> Objc2ProtocolList:
        ...

    @property
    def optionalInstanceMethods(self) -> Objc2MethodList:
        ...

    @property
    def classMethods(self) -> Objc2MethodList:
        ...


class Objc2MessageReference(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "message_ref"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    @staticmethod
    def SIZEOF(pointerSize: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getImplementation(self) -> int:
        ...

    def getSelector(self) -> str:
        ...

    @property
    def implementation(self) -> jpype.JLong:
        ...

    @property
    def selector(self) -> java.lang.String:
        ...


class Objc2InstanceVariableList(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ivar_list_t"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getCount(self) -> int:
        ...

    def getEntsize(self) -> int:
        ...

    def getIvars(self) -> java.util.List[Objc2InstanceVariable]:
        ...

    @staticmethod
    def toGenericDataType() -> ghidra.program.model.data.DataType:
        ...

    @property
    def count(self) -> jpype.JLong:
        ...

    @property
    def ivars(self) -> java.util.List[Objc2InstanceVariable]:
        ...

    @property
    def entsize(self) -> jpype.JLong:
        ...


class Objc2MethodList(ghidra.app.util.bin.format.objc.ObjcMethodList):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "method_list_t"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader, methodType: ghidra.app.util.bin.format.objc.ObjcMethodType) -> None:
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


class Objc2ClassRW(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "class_rw_t"

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState) -> None:
        ...

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getBaseMethods(self) -> Objc2MethodList:
        ...

    def getBaseProperties(self) -> Objc2PropertyList:
        ...

    def getBaseProtocols(self) -> Objc2ProtocolList:
        ...

    def getFlags(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getInstanceSize(self) -> int:
        ...

    def getInstanceStart(self) -> int:
        ...

    def getInstanceVariables(self) -> Objc2InstanceVariableList:
        ...

    def getName(self) -> str:
        ...

    def getReserved(self) -> int:
        ...

    def getWeakIvarLayout(self) -> int:
        ...

    @property
    def baseMethods(self) -> Objc2MethodList:
        ...

    @property
    def instanceSize(self) -> jpype.JLong:
        ...

    @property
    def instanceStart(self) -> jpype.JLong:
        ...

    @property
    def instanceVariables(self) -> Objc2InstanceVariableList:
        ...

    @property
    def weakIvarLayout(self) -> jpype.JLong:
        ...

    @property
    def reserved(self) -> jpype.JLong:
        ...

    @property
    def baseProperties(self) -> Objc2PropertyList:
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
    def baseProtocols(self) -> Objc2ProtocolList:
        ...


class Objc2Property(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getAttributes(self) -> str:
        ...

    def getName(self) -> str:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def attributes(self) -> java.lang.String:
        ...


class Objc2TypeMetadata(ghidra.app.util.bin.format.objc.AbstractObjcTypeMetadata):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Creates a new :obj:`Objc2TypeMetadata`
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises IOException: if there was an IO-related error
        :raises CancelledException: if the user cancelled the operation
        """

    def getCategories(self) -> java.util.List[Objc2Category]:
        """
        :return: the :obj:`List` of :obj:`categories <Objc2Category>`
        :rtype: java.util.List[Objc2Category]
        """

    def getClasses(self) -> java.util.List[Objc2Class]:
        """
        :return: the :obj:`List` of :obj:`classes <Objc2Class>`
        :rtype: java.util.List[Objc2Class]
        """

    def getImageInfos(self) -> java.util.List[Objc2ImageInfo]:
        """
        :return: the :obj:`List` of :obj:`image info entries <Objc2ImageInfo>`
        :rtype: java.util.List[Objc2ImageInfo]
        """

    def getMessageRefs(self) -> java.util.List[Objc2MessageReference]:
        """
        :return: the :obj:`List` of :obj:`message references <Objc2MessageReference>`
        :rtype: java.util.List[Objc2MessageReference]
        """

    def getProtocols(self) -> java.util.List[Objc2Protocol]:
        """
        :return: the :obj:`List` of :obj:`protocols <Objc2Protocol>`
        :rtype: java.util.List[Objc2Protocol]
        """

    def getRefs(self) -> java.util.Set[ghidra.program.model.address.Address]:
        """
        :return: the :obj:`Set` of :obj:`refs <Address>`
        :rtype: java.util.Set[ghidra.program.model.address.Address]
        """

    @property
    def imageInfos(self) -> java.util.List[Objc2ImageInfo]:
        ...

    @property
    def messageRefs(self) -> java.util.List[Objc2MessageReference]:
        ...

    @property
    def refs(self) -> java.util.Set[ghidra.program.model.address.Address]:
        ...

    @property
    def classes(self) -> java.util.List[Objc2Class]:
        ...

    @property
    def categories(self) -> java.util.List[Objc2Category]:
        ...

    @property
    def protocols(self) -> java.util.List[Objc2Protocol]:
        ...


class Objc2Implementation(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader, isSmall: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getImplementation(self) -> int:
        ...

    @property
    def implementation(self) -> jpype.JLong:
        ...


class Objc2Method(ghidra.app.util.bin.format.objc.ObjcMethod):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader, methodType: ghidra.app.util.bin.format.objc.ObjcMethodType, isSmallList: typing.Union[jpype.JBoolean, bool]) -> None:
        ...


class Objc2ProtocolList(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "protocol_list_t"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getCount(self) -> int:
        ...

    def getProtocols(self) -> java.util.List[Objc2Protocol]:
        ...

    @staticmethod
    def toGenericDataType(is32bit: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.DataType:
        ...

    @property
    def count(self) -> jpype.JLong:
        ...

    @property
    def protocols(self) -> java.util.List[Objc2Protocol]:
        ...


class Objc2ImageInfo(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    OBJC_IMAGE_IS_REPLACEMENT: typing.Final = 1
    OBJC_IMAGE_SUPPORTS_GC: typing.Final = 2
    OBJC_IMAGE_REQUIRES_GC: typing.Final = 4

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getFlags(self) -> int:
        ...

    def getVersion(self) -> int:
        ...

    def isReplacement(self) -> bool:
        ...

    def isRequiresGarbageCollection(self) -> bool:
        ...

    def isSupportsGarbageCollection(self) -> bool:
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
    def replacement(self) -> jpype.JBoolean:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...


class Objc2InstanceVariable(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
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


class Objc2Class(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "class_t"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getCache(self) -> Objc2Cache:
        ...

    def getData(self) -> Objc2ClassRW:
        ...

    def getISA(self) -> Objc2Class:
        ...

    def getIndex(self) -> int:
        ...

    def getSuperClass(self) -> Objc2Class:
        ...

    def getVTable(self) -> Objc2Implementation:
        ...

    @property
    def vTable(self) -> Objc2Implementation:
        ...

    @property
    def cache(self) -> Objc2Cache:
        ...

    @property
    def data(self) -> Objc2ClassRW:
        ...

    @property
    def superClass(self) -> Objc2Class:
        ...

    @property
    def iSA(self) -> Objc2Class:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...


class Objc2Category(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "category_t"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getClassMethods(self) -> Objc2MethodList:
        ...

    def getCls(self) -> Objc2Class:
        ...

    def getInstanceMethods(self) -> Objc2MethodList:
        ...

    def getInstanceProperties(self) -> Objc2PropertyList:
        ...

    def getName(self) -> str:
        ...

    def getProtocols(self) -> Objc2ProtocolList:
        ...

    @property
    def instanceProperties(self) -> Objc2PropertyList:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def instanceMethods(self) -> Objc2MethodList:
        ...

    @property
    def cls(self) -> Objc2Class:
        ...

    @property
    def protocols(self) -> Objc2ProtocolList:
        ...

    @property
    def classMethods(self) -> Objc2MethodList:
        ...


class Objc2Cache(ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, state: ghidra.app.util.bin.format.objc.ObjcState, reader: ghidra.app.util.bin.BinaryReader) -> None:
        ...

    def getCache(self) -> int:
        ...

    @property
    def cache(self) -> jpype.JLong:
        ...



__all__ = ["Objc2PropertyList", "Objc2Constants", "Objc2Protocol", "Objc2MessageReference", "Objc2InstanceVariableList", "Objc2MethodList", "Objc2ClassRW", "Objc2Property", "Objc2TypeMetadata", "Objc2Implementation", "Objc2Method", "Objc2ProtocolList", "Objc2ImageInfo", "Objc2InstanceVariable", "Objc2Class", "Objc2Category", "Objc2Cache"]
