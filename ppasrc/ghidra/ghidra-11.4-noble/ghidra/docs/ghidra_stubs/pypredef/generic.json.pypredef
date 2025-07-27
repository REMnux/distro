from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore
import org.apache.commons.lang3.builder # type: ignore


class JSONToken(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    type: JSONType
    start: jpype.JInt
    end: jpype.JInt
    size: jpype.JInt

    def __init__(self, type: JSONType, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]):
        """
        JSON token description.
        
        :param JSONType type: the token type (object, array, string etc.)
        :param jpype.JInt or int start: the start position in JSON data string
        :param jpype.JInt or int end: the end position in JSON data string
        """

    def getEnd(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    def getStart(self) -> int:
        ...

    def getType(self) -> JSONType:
        ...

    def incSize(self):
        ...

    def setEnd(self, end: typing.Union[jpype.JInt, int]):
        ...

    def setSize(self, size: typing.Union[jpype.JInt, int]):
        ...

    def setStart(self, start: typing.Union[jpype.JInt, int]):
        ...

    def setType(self, type: JSONType):
        ...


class Json(org.apache.commons.lang3.builder.ToStringStyle):
    """
    A utility class to format strings in JSON format.   This is useful for easily generating
    ``toString()`` representations of objects.
    """

    class JsonWithNewlinesToStringStyle(org.apache.commons.lang3.builder.ToStringStyle):
        """
        A :obj:`ToStringStyle` inspired by :obj:`ToStringStyle.JSON_STYLE` that places
        object fields on newlines for more readability
        """

        class_: typing.ClassVar[java.lang.Class]


    class JsonWithFlatToStringStyle(org.apache.commons.lang3.builder.ToStringStyle):
        """
        A :obj:`ToStringStyle` inspired by :obj:`ToStringStyle.JSON_STYLE` that places
        object fields all on one line, with Json style formatting.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InclusiveReflectionToStringBuilder(org.apache.commons.lang3.builder.ReflectionToStringBuilder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, object: java.lang.Object):
            ...

        def setIncludeFieldNames(self, *includeFieldNamesParam: typing.Union[java.lang.String, str]) -> org.apache.commons.lang3.builder.ReflectionToStringBuilder:
            """
            Sets the names to be included
            
            :param jpype.JArray[java.lang.String] includeFieldNamesParam: the names
            :return: this builder
            :rtype: org.apache.commons.lang3.builder.ReflectionToStringBuilder
            """


    class_: typing.ClassVar[java.lang.Class]
    WITH_NEWLINES: typing.Final[Json.JsonWithNewlinesToStringStyle]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def toString(o: java.lang.Object) -> str:
        """
        Creates a Json string representation of the given object and all of its fields.  To exclude
        some fields, call :meth:`toStringExclude(Object, String...) <.toStringExclude>`.  To only include particular
        fields, call :meth:`appendToString(StringBuffer, String) <.appendToString>`.
         
        
        The returned string is formatted for pretty printing using whitespace, such as tabs and 
        newlines.
        
        :param java.lang.Object o: the object
        :return: the string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toString(o: java.lang.Object, *includFields: typing.Union[java.lang.String, str]) -> str:
        """
        Creates a Json string representation of the given object and the given fields
        
        :param java.lang.Object o: the object
        :param jpype.JArray[java.lang.String] includFields: the fields to include
        :return: the string
        :rtype: str
        """

    @staticmethod
    def toStringExclude(o: java.lang.Object, *excludedFields: typing.Union[java.lang.String, str]) -> str:
        """
        Creates a Json string representation of the given object and all of its fields except for
        those in the given exclusion list
        
        :param java.lang.Object o: the object
        :param jpype.JArray[java.lang.String] excludedFields: the excluded field names
        :return: the string
        :rtype: str
        """

    @staticmethod
    def toStringFlat(o: java.lang.Object) -> str:
        """
        Creates a Json string representation of the given object and all of its fields.
         
        
        The returned string is formatted without newlines for better use in logging.
        
        :param java.lang.Object o: the object
        :return: the string
        :rtype: str
        """


class JSONType(java.lang.Enum[JSONType]):

    class_: typing.ClassVar[java.lang.Class]
    JSMN_PRIMITIVE: typing.Final[JSONType]
    """
    JSON type identifier. Basic types are:
        o Object
        o Array
        o String
        o Other primitive: number, boolean (true/false) or null
    """

    JSMN_OBJECT: typing.Final[JSONType]
    JSMN_ARRAY: typing.Final[JSONType]
    JSMN_STRING: typing.Final[JSONType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> JSONType:
        ...

    @staticmethod
    def values() -> jpype.JArray[JSONType]:
        ...


class JSONError(java.lang.Enum[JSONError]):

    class_: typing.ClassVar[java.lang.Class]
    JSMN_SUCCESS: typing.Final[JSONError]
    JSMN_ERROR_NOMEM: typing.Final[JSONError]
    JSMN_ERROR_INVAL: typing.Final[JSONError]
    JSMN_ERROR_PART: typing.Final[JSONError]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> JSONError:
        ...

    @staticmethod
    def values() -> jpype.JArray[JSONError]:
        ...


class JSONParser(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new parser based over a given  buffer with an array of tokens 
        available.
        """

    def convert(self, s: jpype.JArray[jpype.JChar], t: java.util.List[JSONToken]) -> java.lang.Object:
        ...

    def parse(self, js: jpype.JArray[jpype.JChar], tokens: java.util.List[JSONToken]) -> JSONError:
        """
        Parse JSON string and fill tokens.
        """



__all__ = ["JSONToken", "Json", "JSONType", "JSONError", "JSONParser"]
