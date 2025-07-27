from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macos.asd
import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore


class ResourceHeader(ghidra.app.util.bin.format.macos.asd.Entry, ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        ...

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, entry: ghidra.app.util.bin.format.macos.asd.EntryDescriptor):
        ...

    def getMap(self) -> ResourceMap:
        ...

    def getResourceDataLength(self) -> int:
        """
        Returns the length of the resource data.
        
        :return: the length of the resource data
        :rtype: int
        """

    def getResourceDataOffset(self) -> int:
        """
        Returns the offset from the beginning of resource fork
        to resource data.
        
        :return: offset to resource data
        :rtype: int
        """

    def getResourceMapLength(self) -> int:
        """
        Returns the length of the resource map.
        
        :return: the length of the resource map
        :rtype: int
        """

    def getResourceMapOffset(self) -> int:
        """
        Returns the offset from the beginning of resource fork
        to resource map.
        
        :return: offset to resource map
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def resourceDataOffset(self) -> jpype.JInt:
        ...

    @property
    def resourceMapOffset(self) -> jpype.JInt:
        ...

    @property
    def resourceMapLength(self) -> jpype.JInt:
        ...

    @property
    def map(self) -> ResourceMap:
        ...

    @property
    def resourceDataLength(self) -> jpype.JInt:
        ...


class ResourceTypeFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getResourceObject(reader: ghidra.app.util.bin.BinaryReader, header: ResourceHeader, resourceType: ResourceType) -> java.lang.Object:
        ...


class SingleResourceData(java.lang.Object):
    """
    Format of resource data for a single resource.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getData(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the resource data for this resource.
        
        :return: the resource data for this resource
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getLength(self) -> int:
        """
        Returns the length of the following resource.
        
        :return: the length of the following resource
        :rtype: int
        """

    @property
    def data(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class ResourceTypes(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    TYPE_CFRG: typing.Final = 1667658343
    """
    Resource Type ID for the Code Fragment Manager (CFM).
    """

    TYPE_STR_SPACE: typing.Final = 1398034976
    TYPE_STR_POUND: typing.Final = 1398034979
    TYPE_ICON: typing.Final = 1229147683


class ResourceMap(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getCopy(self) -> ResourceHeader:
        ...

    def getFileReferenceNumber(self) -> int:
        ...

    def getHandleToNextResourceMap(self) -> int:
        ...

    def getMapStartIndex(self) -> int:
        ...

    def getNumberOfTypes(self) -> int:
        ...

    def getReferenceEntryList(self) -> java.util.List[ReferenceListEntry]:
        ...

    def getResourceForkAttributes(self) -> int:
        ...

    def getResourceNameListOffset(self) -> int:
        ...

    def getResourceTypeList(self) -> java.util.List[ResourceType]:
        ...

    def getResourceTypeListOffset(self) -> int:
        ...

    def getStringAt(self, offset: typing.Union[jpype.JShort, int]) -> str:
        ...

    @property
    def mapStartIndex(self) -> jpype.JLong:
        ...

    @property
    def resourceTypeListOffset(self) -> jpype.JShort:
        ...

    @property
    def stringAt(self) -> java.lang.String:
        ...

    @property
    def resourceTypeList(self) -> java.util.List[ResourceType]:
        ...

    @property
    def resourceNameListOffset(self) -> jpype.JShort:
        ...

    @property
    def numberOfTypes(self) -> jpype.JShort:
        ...

    @property
    def handleToNextResourceMap(self) -> jpype.JInt:
        ...

    @property
    def fileReferenceNumber(self) -> jpype.JShort:
        ...

    @property
    def copy(self) -> ResourceHeader:
        ...

    @property
    def resourceForkAttributes(self) -> jpype.JShort:
        ...

    @property
    def referenceEntryList(self) -> java.util.List[ReferenceListEntry]:
        ...


class ResourceType(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getNumberOfResources(self) -> int:
        """
        Returns the number of resources of this type
        in map minus 1.
        
        :return: the number of resources
        :rtype: int
        """

    def getOffsetToReferenceList(self) -> int:
        """
        Returns the offset from the beginning of the 
        resource type list to reference list for this type.
        
        :return: the offset to reference list
        :rtype: int
        """

    def getReferenceList(self) -> java.util.List[ReferenceListEntry]:
        ...

    def getResourceObject(self) -> java.lang.Object:
        ...

    def getType(self) -> int:
        """
        Returns the resource type.
        
        :return: the resource type
        :rtype: int
        """

    def getTypeAsString(self) -> str:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def typeAsString(self) -> java.lang.String:
        ...

    @property
    def referenceList(self) -> java.util.List[ReferenceListEntry]:
        ...

    @property
    def resourceObject(self) -> java.lang.Object:
        ...

    @property
    def numberOfResources(self) -> jpype.JShort:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def offsetToReferenceList(self) -> jpype.JShort:
        ...


class ReferenceListEntry(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getAttributes(self) -> int:
        """
        Returns the resource attributes.
        
        :return: the resource attributes
        :rtype: int
        """

    def getDataOffset(self) -> int:
        """
        Returns the offset from the beginning of the
        resource data to the data for this resource.
        
        :return: the offset to the resource data
        :rtype: int
        """

    def getHandle(self) -> int:
        """
        Returns the resource handle.
        This field is reserved.
        
        :return: the resource handle
        :rtype: int
        """

    def getID(self) -> int:
        """
        Returns the resource ID.
        
        :return: the resource ID
        :rtype: int
        """

    def getName(self) -> str:
        ...

    def getNameOffset(self) -> int:
        """
        Returns the offset from the beginning of the resource
        name list to resource name.
        
        :return: the offset to the resource name
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def nameOffset(self) -> jpype.JShort:
        ...

    @property
    def dataOffset(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def handle(self) -> jpype.JInt:
        ...

    @property
    def attributes(self) -> jpype.JByte:
        ...

    @property
    def iD(self) -> jpype.JShort:
        ...



__all__ = ["ResourceHeader", "ResourceTypeFactory", "SingleResourceData", "ResourceTypes", "ResourceMap", "ResourceType", "ReferenceListEntry"]
