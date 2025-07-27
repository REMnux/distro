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
import java.util.stream # type: ignore


T = typing.TypeVar("T")


class OmfIndex(ghidra.app.util.bin.StructConverter):
    """
    An OMF index that is either 1 or 2 bytes
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, length: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Creates a new :obj:`OmfIndex`
        
        :param jpype.JInt or int length: 1 or 2
        :param jpype.JInt or int value: The 1 or 2 byte index value
        """

    def length(self) -> int:
        """
        :return: the length of the index (1 or 2)
        :rtype: int
        """

    def value(self) -> int:
        """
        :return: the index value
        :rtype: int
        """


class OmfException(java.lang.Exception):
    """
    An :obj:`Exception` used to indicate there was a problem parsing an OMF record
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`OmfException`
        
        :param java.lang.String or str message: The exception message
        """


class Omf2or4(ghidra.app.util.bin.StructConverter):
    """
    An OMF value that is either 2 or 4 bytes
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, length: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Creates a new :obj:`Omf2or4`
        
        :param jpype.JInt or int length: 2 or 4
        :param jpype.JLong or int value: The 2 or 4 byte value
        """

    def length(self) -> int:
        """
        :return: the length of the value (2 or 4)
        :rtype: int
        """

    def value(self) -> int:
        """
        :return: the value
        :rtype: int
        """


class AbstractOmfRecordFactory(java.lang.Object):
    """
    Classes that implement this interface can read various flavors of the OMF format
    """

    class_: typing.ClassVar[java.lang.Class]

    def getEndRecordType(self) -> int:
        """
        Gets a valid record type that can end a supported OMF binary
        
        :return: A valid record types that can end a supported OMF binary
        :rtype: int
        """

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        :return: the reader associated with this factory
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getStartRecordTypes(self) -> java.util.List[java.lang.Integer]:
        """
        Gets a :obj:`List` of valid record types that can start a supported OMF binary
        
        :return: A :obj:`List` of valid record types that can start a supported OMF binary
        :rtype: java.util.List[java.lang.Integer]
        """

    def readNextRecord(self) -> OmfRecord:
        """
        Reads the next :obj:`OmfRecord` pointed to by the reader
        
        :return: The next read :obj:`OmfRecord`
        :rtype: OmfRecord
        :raises IOException: if there was an IO-related error
        :raises OmfException: if there was a problem with the OMF specification
        """

    def reset(self):
        """
        Reset this factory's reader to index 0
        """

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def endRecordType(self) -> jpype.JInt:
        ...

    @property
    def startRecordTypes(self) -> java.util.List[java.lang.Integer]:
        ...


class OmfUnsupportedRecord(OmfRecord):
    """
    A known but currently unsupported OMF record
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, recordTypesClass: java.lang.Class[typing.Any]):
        """
        Create a new :obj:`OmfUnsupportedRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :param java.lang.Class[typing.Any] recordTypesClass: The class that contains accessible OMF type fields
        :raises IOException: If an IO-related error occurred
        """


class OmfString(ghidra.app.util.bin.StructConverter):
    """
    An variable length OMF string
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, length: typing.Union[jpype.JInt, int], str: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`OmfString`
        
        :param jpype.JInt or int length: The length of the string
        :param java.lang.String or str str: The string
        """

    def getDataTypeSize(self) -> int:
        """
        :return: the length (in bytes) of this data type
        :rtype: int
        """

    def length(self) -> int:
        """
        :return: the length of the string
        :rtype: int
        """

    def str(self) -> str:
        """
        :return: the string
        :rtype: str
        """

    @property
    def dataTypeSize(self) -> jpype.JInt:
        ...


class OmfRecord(ghidra.app.util.bin.StructConverter):
    """
    A generic OMF record
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`OmfRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: if there was an IO-related error
        """

    def calcCheckSum(self) -> int:
        """
        Computes the record's checksum
        
        :return: The record's checksum
        :rtype: int
        :raises IOException: if an IO-related error occurred
        """

    def getData(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the record data
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getRecordChecksum(self) -> int:
        """
        :return: the record checksum
        :rtype: int
        """

    def getRecordLength(self) -> int:
        """
        :return: the record length
        :rtype: int
        """

    def getRecordOffset(self) -> int:
        """
        :return: the record offset
        :rtype: int
        """

    def getRecordType(self) -> int:
        """
        :return: the record type
        :rtype: int
        """

    def hasBigFields(self) -> bool:
        """
        :return: true if this record has big fields; otherwise, false
        :rtype: bool
        """

    def parseData(self):
        """
        Parses this :obj:`OmfRecord`'s type-spefic data
        
        :raises IOException: if there was an IO-related error
        :raises OmfException: if there was a problem with the OMF specification
        """

    def validCheckSum(self) -> bool:
        """
        Validates the record's checksum
        
        :return: True if the checksum is valid; otherwise, false
        :rtype: bool
        :raises IOException: if an IO-related error occurred
        """

    @property
    def recordChecksum(self) -> jpype.JByte:
        ...

    @property
    def data(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def recordType(self) -> jpype.JInt:
        ...

    @property
    def recordLength(self) -> jpype.JInt:
        ...

    @property
    def recordOffset(self) -> jpype.JLong:
        ...


class OmfUnknownRecord(OmfRecord):
    """
    An unknown OMF record
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`OmfUnknownRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: If an IO-related error occurred
        """


class OmfUtils(java.lang.Object):
    """
    Utility class for OMF-based file formats
    """

    class_: typing.ClassVar[java.lang.Class]
    CATEGORY_PATH: typing.Final = "/OMF"
    """
    Data type category
    """


    def __init__(self):
        ...

    @staticmethod
    def filterRecords(records: java.util.List[OmfRecord], classType: java.lang.Class[T]) -> java.util.stream.Stream[T]:
        """
        Returns a :obj:`Stream` of :obj:`records <OmfRecord>` that match the given class type
        
        :param T: The class type:param java.util.List[OmfRecord] records: The :obj:`List` of all :obj:`records <OmfRecord>`
        :param java.lang.Class[T] classType: The class type to match on
        :return: A :obj:`Stream` of matching (@link OmfRecord records}
        :rtype: java.util.stream.Stream[T]
        """

    @staticmethod
    def getRecordName(type: typing.Union[jpype.JInt, int], recordTypesClass: java.lang.Class[typing.Any]) -> str:
        """
        Gets the name of the given record type
        
        :param jpype.JInt or int type: The record type
        :param java.lang.Class[typing.Any] recordTypesClass: The class that contains accessible OMF type fields
        :return: The name of the given record type
        :rtype: str
        """

    @staticmethod
    def readIndex(reader: ghidra.app.util.bin.BinaryReader) -> OmfIndex:
        ...

    @staticmethod
    def readInt2Or4(reader: ghidra.app.util.bin.BinaryReader, isBig: typing.Union[jpype.JBoolean, bool]) -> Omf2or4:
        ...

    @staticmethod
    def readRecords(factory: AbstractOmfRecordFactory) -> java.util.List[OmfRecord]:
        """
        Reads all the :obj:`records <OmfRecord>` associated with the given 
        :obj:`AbstractOmfRecordFactory`
        
        :param AbstractOmfRecordFactory factory: The :obj:`AbstractOmfRecordFactory`
        :return: A :obj:`List` of read :obj:`records <OmfRecord>`
        :rtype: java.util.List[OmfRecord]
        :raises IOException: if there was an IO-related error
        :raises OmfException: if there was a problem with the OMF specification
        """

    @staticmethod
    def readString(reader: ghidra.app.util.bin.BinaryReader) -> OmfString:
        """
        Read the OMF string format: 1-byte length, followed by that many ascii characters
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the string
        :return: the read OMF string
        :rtype: OmfString
        :raises IOException: if an IO-related error occurred
        """

    @staticmethod
    def toOmfRecordDataType(record: OmfRecord, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataType:
        """
        Converts the given :obj:`OmfRecord` to a generic OMF record :obj:`DataType`
        
        :param OmfRecord record: The OMF record to convert
        :param java.lang.String or str name: The name of the OMF record
        :return: A :obj:`DataType` for the given OMF record
        :rtype: ghidra.program.model.data.DataType
        """


class OmfObsoleteRecord(OmfRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`OmfObsoleteRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the record
        :raises IOException: If an IO-related error occurred
        """



__all__ = ["OmfIndex", "OmfException", "Omf2or4", "AbstractOmfRecordFactory", "OmfUnsupportedRecord", "OmfString", "OmfRecord", "OmfUnknownRecord", "OmfUtils", "OmfObsoleteRecord"]
