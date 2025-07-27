from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class FileType(java.lang.Enum[FileType]):
    """
    Enumeration of file types
    """

    class_: typing.ClassVar[java.lang.Class]
    FILE: typing.Final[FileType]
    DIRECTORY: typing.Final[FileType]
    SYMBOLIC_LINK: typing.Final[FileType]
    OTHER: typing.Final[FileType]
    UNKNOWN: typing.Final[FileType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FileType:
        ...

    @staticmethod
    def values() -> jpype.JArray[FileType]:
        ...


class FileAttributes(java.lang.Object):
    """
    A collection of :obj:`FileAttribute` values that describe a file.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.ClassVar[FileAttributes]
    """
    Read-only empty instance.
    """


    def __init__(self):
        """
        Creates a new / empty :obj:`FileAttributes` instance.
        """

    @typing.overload
    def add(self, name: typing.Union[java.lang.String, str], attributeValue: java.lang.Object):
        """
        Adds a custom named file attribute.
         
        
        The value class should have a reasonable toString() that converts the value to something
        that is presentable to the user.
        
        :param java.lang.String or str name: name of the attribute
        :param java.lang.Object attributeValue: value of the attribute
        """

    @typing.overload
    def add(self, attributeType: FileAttributeType, attributeValue: java.lang.Object):
        """
        Adds a typed file attribute value.
         
        
        The value class needs to match :meth:`FileAttributeType.getValueType() <FileAttributeType.getValueType>`.
        
        :param FileAttributeType attributeType: :obj:`FileAttributeType` type of this value
        :param java.lang.Object attributeValue: value of attribute
        """

    @typing.overload
    def add(self, attributeType: FileAttributeType, displayName: typing.Union[java.lang.String, str], attributeValue: java.lang.Object):
        """
        Adds a typed file attribute value.
         
        
        The value class needs to match :meth:`FileAttributeType.getValueType() <FileAttributeType.getValueType>`.
        
        :param FileAttributeType attributeType: :obj:`FileAttributeType` type of this value
        :param java.lang.String or str displayName: string used to label the value when displayed to the user
        :param java.lang.Object attributeValue: value of attribute
        :raises IllegalArgumentException: if attributeValue does not match attributeType's 
        :meth:`FileAttributeType.getValueType() <FileAttributeType.getValueType>`.
        """

    def contains(self, attributeType: FileAttributeType) -> bool:
        """
        Returns true if the specified attribute is present.
        
        :param FileAttributeType attributeType: attribute to query
        :return: boolean true if present
        :rtype: bool
        """

    def get(self, attributeType: FileAttributeType, valueClass: java.lang.Class[T], defaultValue: T) -> T:
        """
        Gets the value of the specified attribute.
        
        :param T: expected class of the attribute value:param FileAttributeType attributeType: :obj:`FileAttributeType` enum type of attribute to search for
        :param java.lang.Class[T] valueClass: java class of the value
        :param T defaultValue: value to return if attribute is not present
        :return: value of requested attribute, or defaultValue if not present
        :rtype: T
        """

    def getAttributes(self) -> java.util.List[FileAttribute[typing.Any]]:
        """
        Return a list of all the attributes added to this instance.
        
        :return: list of :obj:`FileAttribute`
        :rtype: java.util.List[FileAttribute[typing.Any]]
        """

    @staticmethod
    def of(*attribs: FileAttribute[typing.Any]) -> FileAttributes:
        """
        Creates a :obj:`FileAttributes` instance containing the specified attribute values.
        
        :param jpype.JArray[FileAttribute[typing.Any]] attribs: var-arg list of :obj:`FileAttribute` values, null values are ignored and
        skipped
        :return: a new :obj:`FileAttributes` instance
        :rtype: FileAttributes
        """

    @property
    def attributes(self) -> java.util.List[FileAttribute[typing.Any]]:
        ...


class FileAttributeType(java.lang.Enum[FileAttributeType]):
    """
    Well known types of file attributes.
     
    
    Uncommon information about a file should be added to the :obj:`FileAttributes` collection
    as an :obj:`.UNKNOWN_ATTRIBUTE` with a custom display name.
     
    
    When adding new attribute types to this enum, add them adjacent to other types of the same 
    :obj:`category <FileAttributeTypeGroup>`.  The enum ordinal controls display ordering.
    """

    class_: typing.ClassVar[java.lang.Class]
    FSRL_ATTR: typing.Final[FileAttributeType]
    NAME_ATTR: typing.Final[FileAttributeType]
    PATH_ATTR: typing.Final[FileAttributeType]
    FILE_TYPE_ATTR: typing.Final[FileAttributeType]
    PROJECT_FILE_ATTR: typing.Final[FileAttributeType]
    SIZE_ATTR: typing.Final[FileAttributeType]
    COMPRESSED_SIZE_ATTR: typing.Final[FileAttributeType]
    CREATE_DATE_ATTR: typing.Final[FileAttributeType]
    MODIFIED_DATE_ATTR: typing.Final[FileAttributeType]
    ACCESSED_DATE_ATTR: typing.Final[FileAttributeType]
    USER_NAME_ATTR: typing.Final[FileAttributeType]
    USER_ID_ATTR: typing.Final[FileAttributeType]
    GROUP_NAME_ATTR: typing.Final[FileAttributeType]
    GROUP_ID_ATTR: typing.Final[FileAttributeType]
    UNIX_ACL_ATTR: typing.Final[FileAttributeType]
    IS_ENCRYPTED_ATTR: typing.Final[FileAttributeType]
    HAS_GOOD_PASSWORD_ATTR: typing.Final[FileAttributeType]
    SYMLINK_DEST_ATTR: typing.Final[FileAttributeType]
    COMMENT_ATTR: typing.Final[FileAttributeType]
    FILENAME_EXT_OVERRIDE: typing.Final[FileAttributeType]
    UNKNOWN_ATTRIBUTE: typing.Final[FileAttributeType]

    def getDisplayName(self) -> str:
        """
        Returns the display name of this attribute type.
        
        :return: string display name
        :rtype: str
        """

    def getGroup(self) -> FileAttributeTypeGroup:
        """
        Returns the :obj:`group <FileAttributeTypeGroup>` this attribute belongs in.
        
        :return: :obj:`FileAttributeTypeGroup`
        :rtype: FileAttributeTypeGroup
        """

    def getValueType(self) -> java.lang.Class[typing.Any]:
        """
        Returns the class the value should match.
        
        :return: expected class of the value
        :rtype: java.lang.Class[typing.Any]
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FileAttributeType:
        ...

    @staticmethod
    def values() -> jpype.JArray[FileAttributeType]:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...

    @property
    def valueType(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def group(self) -> FileAttributeTypeGroup:
        ...


class FileAttributeTypeGroup(java.lang.Enum[FileAttributeTypeGroup]):
    """
    Categories of file attributes.
    """

    class_: typing.ClassVar[java.lang.Class]
    GENERAL_INFO: typing.Final[FileAttributeTypeGroup]
    SIZE_INFO: typing.Final[FileAttributeTypeGroup]
    DATE_INFO: typing.Final[FileAttributeTypeGroup]
    OWNERSHIP_INFO: typing.Final[FileAttributeTypeGroup]
    PERMISSION_INFO: typing.Final[FileAttributeTypeGroup]
    ENCRYPTION_INFO: typing.Final[FileAttributeTypeGroup]
    MISC_INFO: typing.Final[FileAttributeTypeGroup]
    ADDITIONAL_INFO: typing.Final[FileAttributeTypeGroup]

    def getDescriptiveName(self) -> str:
        """
        Returns the descriptive name of the group.
        
        :return: string descriptive name
        :rtype: str
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FileAttributeTypeGroup:
        ...

    @staticmethod
    def values() -> jpype.JArray[FileAttributeTypeGroup]:
        ...

    @property
    def descriptiveName(self) -> java.lang.String:
        ...


class FileAttribute(java.lang.Object, typing.Generic[T]):
    """
    A (type, type_display_string, value) tuple.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def create(name: typing.Union[java.lang.String, str], attributeValue: T) -> FileAttribute[T]:
        """
        Creates a new :obj:`FileAttribute` instance with an 
        :obj:`FileAttributeType.UNKNOWN_ATTRIBUTE` type and the specified display name.
        
        :param T: type of the value:param java.lang.String or str name: custom display name for the value
        :param T attributeValue: value (should be .toString()'able)
        :return: new FileAttribute instance
        :rtype: FileAttribute[T]
        """

    @staticmethod
    @typing.overload
    def create(attributeType: FileAttributeType, attributeValue: T) -> FileAttribute[T]:
        """
        Creates a new :obj:`FileAttribute` instance with the specified type and value.
        
        :param T: type of the value:param FileAttributeType attributeType: :obj:`FileAttributeType` type
        :param T attributeValue: value (should match the 
        type specified in :meth:`FileAttributeType.getValueType() <FileAttributeType.getValueType>`)
        :return: new FileAttribute instance
        :rtype: FileAttribute[T]
        """

    @staticmethod
    @typing.overload
    def create(attributeType: FileAttributeType, attributeDisplayName: typing.Union[java.lang.String, str], attributeValue: T) -> FileAttribute[T]:
        """
        Creates a new :obj:`FileAttribute` instance with the specified type, display name and
        value.
        
        :param T: type of the value:param FileAttributeType attributeType: :obj:`FileAttributeType` type
        :param java.lang.String or str attributeDisplayName: display name of the type
        :param T attributeValue: value (should match the 
        type specified in :meth:`FileAttributeType.getValueType() <FileAttributeType.getValueType>`)
        :return: new FileAttribute instance
        :rtype: FileAttribute[T]
        """

    def getAttributeDisplayName(self) -> str:
        """
        Returns the display name of this instance.  This is usually derived from
        the :meth:`FileAttributeType.getDisplayName() <FileAttributeType.getDisplayName>`.
        
        :return: string display name
        :rtype: str
        """

    def getAttributeType(self) -> FileAttributeType:
        """
        Returns the :obj:`FileAttributeType` of this instance.
        
        :return: :obj:`FileAttributeType`
        :rtype: FileAttributeType
        """

    def getAttributeValue(self) -> T:
        """
        Return the value.
        
        :return: value
        :rtype: T
        """

    @property
    def attributeDisplayName(self) -> java.lang.String:
        ...

    @property
    def attributeValue(self) -> T:
        ...

    @property
    def attributeType(self) -> FileAttributeType:
        ...



__all__ = ["FileType", "FileAttributes", "FileAttributeType", "FileAttributeTypeGroup", "FileAttribute"]
