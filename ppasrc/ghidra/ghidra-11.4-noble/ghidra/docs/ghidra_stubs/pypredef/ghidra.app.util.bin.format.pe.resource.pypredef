from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore


class ResourceDirectoryStringU(ghidra.app.util.bin.StructConverter):
    """
    
    typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
        WORD    Length;
        WCHAR   NameString[ 1 ];
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_RESOURCE_DIR_STRING_U"

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :param jpype.JInt or int index: the index where this resource string begins
        """

    def getLength(self) -> int:
        """
        Returns the length of the string, in bytes.
        
        :return: the length of the string, in bytes
        :rtype: int
        """

    def getNameString(self) -> str:
        """
        Returns the resource name string.
        
        :return: the resource name string
        :rtype: str
        """

    @property
    def nameString(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JShort:
        ...


class ResourceStringInfo(java.lang.Object):
    """
    A class to hold the information extracted from a 
    resource data directory.
     
    NOTE:
    This class is simply a storage class created for 
    parsing the PE header data structures.
    It does not map back to a PE data data structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: typing.Union[jpype.JInt, int], string: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param jpype.JInt or int address: the adjusted address where the resource exists
        :param java.lang.String or str string: the resource string
        :param jpype.JInt or int length: the length of the resource
        """

    def getAddress(self) -> int:
        """
        Returns the adjusted address where the resource exists.
        
        :return: the adjusted address where the resource exists
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Returns the length of the resource.
        
        :return: the length of the resource
        :rtype: int
        """

    def getString(self) -> str:
        """
        Returns the resource string.
        
        :return: the resource string
        :rtype: str
        """

    @property
    def address(self) -> jpype.JInt:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class VS_VERSION_INFO(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the VS_VERSION_INFO data structure.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "VS_VERSION_INFO"
    SIZEOF: typing.Final = 92

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int]):
        """
        Constructs a new VS_VERSION_INFO object.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :param jpype.JInt or int index: the index where the VS_VERSION_INFO begins
        :raises IOException: if an I/O error occurs
        """

    def getChildren(self) -> jpype.JArray[VS_VERSION_CHILD]:
        """
        Returns the array of VS_VERSION_CHILD defined in this VS_VERSION_INFO object.
        
        :return: the array of VS_VERSION_CHILD defined in this VS_VERSION_INFO object
        :rtype: jpype.JArray[VS_VERSION_CHILD]
        """

    def getFileFlags(self) -> int:
        """
        Returns the file flags.
        
        :return: the file flags
        :rtype: int
        """

    def getFileFlagsMask(self) -> str:
        """
        Returns the file flags mask.
        
        :return: the file flags mask
        :rtype: str
        """

    def getFileOS(self) -> int:
        """
        Returns the file OS.
        
        :return: the file OS
        :rtype: int
        """

    def getFileSubtype(self) -> int:
        """
        Returns the file sub-type.
        
        :return: the file sub-type
        :rtype: int
        """

    def getFileTimestamp(self) -> int:
        """
        Returns the file timestamp.
        
        :return: the file timestamp
        :rtype: int
        """

    def getFileType(self) -> int:
        """
        Returns the file type.
        
        :return: the file type
        :rtype: int
        """

    def getFileVersion(self) -> str:
        """
        Returns the file version.
        
        :return: the file version
        :rtype: str
        """

    def getInfo(self) -> str:
        """
        Returns the info.
        
        :return: the info
        :rtype: str
        """

    def getKeys(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the array of keys in this version child.
        
        :return: the array of keys in this version child
        :rtype: jpype.JArray[java.lang.String]
        """

    def getProductVersion(self) -> str:
        """
        Returns the product version.
        
        :return: the product version
        :rtype: str
        """

    def getSignature(self) -> int:
        """
        Returns the signature.
        
        :return: the signature
        :rtype: int
        """

    def getStructLength(self) -> int:
        """
        Returns the structure length.
        
        :return: the structure length
        :rtype: int
        """

    def getStructType(self) -> int:
        """
        Returns the structure type.
        
        :return: the structure type
        :rtype: int
        """

    def getStructVersion(self) -> str:
        """
        Returns the structure version.
        
        :return: the structure version
        :rtype: str
        """

    def getValue(self, key: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the value for the specified key.
        
        :param java.lang.String or str key: the key
        :return: the value for the specified key
        :rtype: str
        """

    def getValueLength(self) -> int:
        """
        Returns the value length.
        
        :return: the value length
        :rtype: int
        """

    @property
    def fileFlagsMask(self) -> java.lang.String:
        ...

    @property
    def signature(self) -> jpype.JInt:
        ...

    @property
    def fileSubtype(self) -> jpype.JInt:
        ...

    @property
    def keys(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def fileOS(self) -> jpype.JInt:
        ...

    @property
    def fileFlags(self) -> jpype.JInt:
        ...

    @property
    def productVersion(self) -> java.lang.String:
        ...

    @property
    def structVersion(self) -> java.lang.String:
        ...

    @property
    def children(self) -> jpype.JArray[VS_VERSION_CHILD]:
        ...

    @property
    def structType(self) -> jpype.JShort:
        ...

    @property
    def valueLength(self) -> jpype.JShort:
        ...

    @property
    def structLength(self) -> jpype.JShort:
        ...

    @property
    def fileTimestamp(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> java.lang.String:
        ...

    @property
    def fileVersion(self) -> java.lang.String:
        ...

    @property
    def fileType(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> java.lang.String:
        ...


class ResourceInfo(java.lang.Comparable[ResourceInfo]):
    """
    A class to hold the information extracted from a 
    resource data directory.
     
    NOTE:
    This class is simply a storage class created for 
    parsing the PE header data structures.
    It does not map back to a PE data data structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param jpype.JInt or int address: the adjusted address where the resource exists
        :param java.lang.String or str name: the name of the resource
        :param jpype.JInt or int size: the size of the resource
        """

    def compareTo(self, that: ResourceInfo) -> int:
        ...

    def getAddress(self) -> int:
        """
        Returns the adjusted address where the resource exists.
        
        :return: the adjusted address where the resource exists
        :rtype: int
        """

    def getID(self) -> int:
        """
        Returns the ID of the resource.
        
        :return: the ID of the resource
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of the resource.
        
        :return: the name of the resource
        :rtype: str
        """

    def getSize(self) -> int:
        """
        Returns the size of the resource.
        
        :return: the size of the resource
        :rtype: int
        """

    def getTypeID(self) -> int:
        """
        Returns the resource type ID.
        For example, RT_CURSOR, RT_BITMAP, etc.
        Returns -1 if this is a named resource.
        """

    def setID(self, id: typing.Union[jpype.JInt, int]):
        ...

    def setName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setTypeID(self, typeID: typing.Union[jpype.JInt, int]):
        ...

    @property
    def address(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def typeID(self) -> jpype.JInt:
        ...

    @typeID.setter
    def typeID(self, value: jpype.JInt):
        ...

    @property
    def iD(self) -> jpype.JInt:
        ...

    @iD.setter
    def iD(self, value: jpype.JInt):
        ...


class ResourceDirectoryString(ghidra.app.util.bin.StructConverter):
    """
    
    typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
        WORD    Length;
        CHAR    NameString[ 1 ];
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_RESOURCE_DIRECTORY_STRING"

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :param jpype.JInt or int index: the index where this resource string begins
        """

    def getLength(self) -> int:
        """
        Returns the length of the string, in bytes.
        
        :return: the length of the string, in bytes
        :rtype: int
        """

    def getNameString(self) -> str:
        """
        Returns the resource name string.
        
        :return: the resource name string
        :rtype: str
        """

    @property
    def nameString(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JShort:
        ...


class ResourceDirectoryEntry(ghidra.app.util.bin.StructConverter):
    """
    
    typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
        union {
            struct {
                DWORD NameOffset:31;
                DWORD NameIsString:1;
            };
            DWORD   Name;
            WORD    Id;
        };
        union {
            DWORD   OffsetToData;
            struct {
                DWORD   OffsetToDirectory:31;
                DWORD   DataIsDirectory:1;
            };
        };
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 8

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int], resourceBase: typing.Union[jpype.JInt, int], isNameEntry: typing.Union[jpype.JBoolean, bool], isFirstLevel: typing.Union[jpype.JBoolean, bool], ntHeader: ghidra.app.util.bin.format.pe.NTHeader):
        """
        Constructor.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :param jpype.JInt or int index: the index where this directory begins
        """

    def getData(self) -> ResourceDataEntry:
        ...

    def getDataIsDirectory(self) -> bool:
        """
        Returns a pointer to information about a specific resource instance.
        
        :return: a pointer to information about a specific resource instance
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.getOffsetToData()`
        """

    def getDirectoryString(self) -> ResourceDirectoryStringU:
        ...

    def getId(self) -> int:
        """
        Returns a resource ID.
        
        :return: a resource ID
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getName()`
        """

    def getName(self) -> int:
        """
        
        
        :return: either an integer ID or a pointer to a structure that contains a string name
        :rtype: int
        """

    def getNameIsString(self) -> bool:
        """
        Returns the ID of the name of this resource.
        
        :return: the ID of the name of this resource
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.getName()`
        """

    def getNameOffset(self) -> int:
        """
        Returns the offset to the name of this resource.
        
        :return: the offset to the name of this resource
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getName()`
        """

    def getOffsetToData(self) -> int:
        """
        
        
        :return: either an offset to another resource directory 
                or a pointer to information about a specific resource instance
        :rtype: int
        """

    def getOffsetToDirectory(self) -> int:
        """
        Returns an offset to another resource directory.
        
        :return: an offset to another resource directory
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getOffsetToData()`
        """

    def getResources(self, level: typing.Union[jpype.JInt, int]) -> java.util.List[ResourceInfo]:
        ...

    def getSubDirectory(self) -> ResourceDirectory:
        ...

    def isNameEntry(self) -> bool:
        """
        Returns true if the parent resource directory is named,
        false indicates an ID.
        """

    def isValid(self) -> bool:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def nameOffset(self) -> jpype.JInt:
        ...

    @property
    def data(self) -> ResourceDataEntry:
        ...

    @property
    def offsetToDirectory(self) -> jpype.JInt:
        ...

    @property
    def nameIsString(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> jpype.JInt:
        ...

    @property
    def resources(self) -> java.util.List[ResourceInfo]:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...

    @property
    def offsetToData(self) -> jpype.JInt:
        ...

    @property
    def nameEntry(self) -> jpype.JBoolean:
        ...

    @property
    def directoryString(self) -> ResourceDirectoryStringU:
        ...

    @property
    def dataIsDirectory(self) -> jpype.JBoolean:
        ...

    @property
    def subDirectory(self) -> ResourceDirectory:
        ...


class ResourceDataEntry(ghidra.app.util.bin.StructConverter):
    """
    
    typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
        DWORD   OffsetToData;
        DWORD   Size;
        DWORD   CodePage;
        DWORD   Reserved;
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_RESOURCE_DATA_ENTRY"
    SIZEOF: typing.Final = 16

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :param jpype.JInt or int index: the index where this entry begins
        """

    def getCodePage(self) -> int:
        """
        
        
        :return: a CodePage that should be used when decoding the resource data
        :rtype: int
        """

    def getOffsetToData(self) -> int:
        """
        Returns the offset, relative to the beginning of the resource
        directory of the data for the resource.
        
        :return: the offset, relative to the beginning of the resource directory
        :rtype: int
        """

    def getReserved(self) -> int:
        """
        Reserved, use unknown.
        
        :return: reserved, use unknown
        :rtype: int
        """

    def getSize(self) -> int:
        """
        Returns a size field that gives the number of bytes of data at that offset.
        
        :return: a size field that gives the number of bytes of data at that offset,
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def offsetToData(self) -> jpype.JInt:
        ...

    @property
    def codePage(self) -> jpype.JInt:
        ...


class ResourceDirectory(ghidra.app.util.bin.StructConverter):
    """
    
    typedef struct _IMAGE_RESOURCE_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        WORD    NumberOfNamedEntries;
        WORD    NumberOfIdEntries;
    };
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_RESOURCE_DIRECTORY"
    SIZEOF: typing.Final = 16

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: typing.Union[jpype.JInt, int], resourceBase: typing.Union[jpype.JInt, int], isFirstLevel: typing.Union[jpype.JBoolean, bool], ntHeader: ghidra.app.util.bin.format.pe.NTHeader):
        ...

    def getCharacteristics(self) -> int:
        """
        Theoretically, this field could hold flags for the resource, but appears to always be 0.
        
        :return: the flags for the resource
        :rtype: int
        """

    def getEntries(self) -> java.util.List[ResourceDirectoryEntry]:
        ...

    def getMajorVersion(self) -> int:
        """
        Theoretically these fields would hold a version number for the resource.
        These field appear to always be set to 0.
        
        :return: the major version number
        :rtype: int
        """

    def getMinorVersion(self) -> int:
        """
        Theoretically these fields would hold a version number for the resource.
        These field appear to always be set to 0.
        
        :return: the minor version number
        :rtype: int
        """

    def getNumberOfIdEntries(self) -> int:
        """
        Returns the number of array elements that use integer IDs, and which follow this structure.
        
        :return: the number of array elements that use integer IDs, and which follow this structure
        :rtype: int
        """

    def getNumberOfNamedEntries(self) -> int:
        """
        Returns the number of array elements that use names and that follow this structure.
        
        :return: the number of array elements that use names and that follow this structure
        :rtype: int
        """

    def getTimeDataStamp(self) -> int:
        """
        Returns the time/date stamp describing the creation time of the resource.
        
        :return: the time/date stamp describing the creation time of the resource
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def entries(self) -> java.util.List[ResourceDirectoryEntry]:
        ...

    @property
    def characteristics(self) -> jpype.JInt:
        ...

    @property
    def numberOfNamedEntries(self) -> jpype.JInt:
        ...

    @property
    def numberOfIdEntries(self) -> jpype.JInt:
        ...

    @property
    def timeDataStamp(self) -> jpype.JInt:
        ...

    @property
    def minorVersion(self) -> jpype.JShort:
        ...

    @property
    def majorVersion(self) -> jpype.JShort:
        ...


class VS_VERSION_CHILD(ghidra.app.util.bin.StructConverter):
    """
    A class to represent the VS_VERSION_CHILD data structure which generally corresponds 
    to either StringFileInfo or VarFileInfo.  Only a single instance of each childName
    is expected.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getChildName(self) -> str:
        """
        Returns the version child name.
        
        :return: the version child name
        :rtype: str
        """

    def getChildSize(self) -> int:
        """
        Returns the version child size.
        
        :return: the version child size
        :rtype: int
        """

    def getChildren(self) -> jpype.JArray[VS_VERSION_CHILD]:
        """
        Returns the array of children
        
        :return: the array of children
        :rtype: jpype.JArray[VS_VERSION_CHILD]
        """

    def getNameRelativeOffset(self) -> int:
        """
        Return unicode name string offset relative to parent structure start
        
        :return: relative name offset or 0 if data type is unknown
        :rtype: int
        """

    def getRelativeOffset(self) -> int:
        """
        Return structure offset relative to parent structure start
        
        :return: relative offset
        :rtype: int
        """

    def getValueRelativeOffset(self) -> int:
        """
        Return value offset relative to parent structure start.
        
        :return: relative value offset or 0 if no value exists
        :rtype: int
        """

    def hasChildren(self) -> bool:
        """
        
        
        :return: true if this child has children
        :rtype: bool
        """

    def valueIsDWord(self) -> bool:
        """
        
        
        :return: true if value is 4-byte integer value in memory 
        while string value return by :meth:`DataType.getValue(MemBuffer, Settings, int) <DataType.getValue>` is a numeric hex string.
        :rtype: bool
        """

    def valueIsUnicodeString(self) -> bool:
        """
        
        
        :return: true if value is unicode string
        :rtype: bool
        """

    @property
    def children(self) -> jpype.JArray[VS_VERSION_CHILD]:
        ...

    @property
    def childName(self) -> java.lang.String:
        ...

    @property
    def nameRelativeOffset(self) -> jpype.JLong:
        ...

    @property
    def relativeOffset(self) -> jpype.JLong:
        ...

    @property
    def childSize(self) -> jpype.JShort:
        ...

    @property
    def valueRelativeOffset(self) -> jpype.JLong:
        ...



__all__ = ["ResourceDirectoryStringU", "ResourceStringInfo", "VS_VERSION_INFO", "ResourceInfo", "ResourceDirectoryString", "ResourceDirectoryEntry", "ResourceDataEntry", "ResourceDirectory", "VS_VERSION_CHILD"]
