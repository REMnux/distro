from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore


class Entry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getEntryDescriptor(self) -> EntryDescriptor:
        ...

    @property
    def entryDescriptor(self) -> EntryDescriptor:
        ...


class EntryFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getEntry(reader: ghidra.app.util.bin.BinaryReader, descriptor: EntryDescriptor) -> java.lang.Object:
        ...


class EntryDescriptor(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, entryID: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        ...

    def getEntry(self) -> java.lang.Object:
        ...

    def getEntryID(self) -> int:
        """
        Returns the entry's ID.
        Note: 0 is invalid.
        
        :return: the entry's ID
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Returns the length of the entry's data.
        The length can be zero (0).
        
        :return: the length of the entry's data
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        The offset from the beginning of the file
        to the beginning of the entry's data.
        
        :return: the offset to entry's data
        :rtype: int
        """

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def entry(self) -> java.lang.Object:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def entryID(self) -> jpype.JInt:
        ...


class EntryDescriptorID(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    ENTRY_DATA_FORK: typing.Final = 1
    """
    The data fork.
    """

    ENTRY_RESOURCE_FORK: typing.Final = 2
    """
    The resource fork.
    """

    ENTRY_REAL_NAME: typing.Final = 3
    """
    File's name as created on home file system.
    """

    ENTRY_COMMENT: typing.Final = 4
    """
    Standard Macintosh comment.
    """

    ENTRY_ICON_BW: typing.Final = 5
    """
    Standard Macintosh black-and-white icon.
    """

    ENTRY_ICON_COLOR: typing.Final = 6
    """
    Macintosh color icon.
    """

    ENTRY_FILE_DATE_INFO: typing.Final = 7
    """
    File creation date, modification date, etc.
    """

    ENTRY_FINDER_INFO: typing.Final = 8
    """
    Standard Macintosh Finder information.
    """

    ENTRY_MAC_FILE_INFO: typing.Final = 9
    """
    Macintosh file information, attributes, etc.
    """

    ENTRY_PRODOS_FILE_INFO: typing.Final = 10
    """
    ProDOS file information, attributes, etc.
    """

    ENTRY_MSDOS_FILE_INFO: typing.Final = 11
    """
    MS-DOS file information, attributes, etc.
    """

    ENTRY_SHORT_NAME: typing.Final = 12
    """
    AFP short name.
    """

    ENTRY_AFP_FILE_INFO: typing.Final = 13
    """
    AFP file information, attributes, etc.
    """

    ENTRY_DIRECTORY_ID: typing.Final = 14
    """
    AFP directory ID.
    """


    def __init__(self):
        ...

    @staticmethod
    def convertEntryIdToName(entryID: typing.Union[jpype.JInt, int]) -> str:
        ...


class AppleSingleDouble(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    SINGLE_MAGIC_NUMBER: typing.Final = 333312
    DOUBLE_MAGIC_NUMBER: typing.Final = 333319

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        ...

    def getEntryList(self) -> java.util.List[EntryDescriptor]:
        ...

    def getFiller(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getMagicNumber(self) -> int:
        ...

    def getNumberOfEntries(self) -> int:
        ...

    def getVersionNumber(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def numberOfEntries(self) -> jpype.JShort:
        ...

    @property
    def magicNumber(self) -> jpype.JInt:
        ...

    @property
    def filler(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def entryList(self) -> java.util.List[EntryDescriptor]:
        ...

    @property
    def versionNumber(self) -> jpype.JInt:
        ...



__all__ = ["Entry", "EntryFactory", "EntryDescriptor", "EntryDescriptorID", "AppleSingleDouble"]
