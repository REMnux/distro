from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.base.memsearch.gui
import ghidra.features.base.memsearch.matcher
import java.lang # type: ignore


class SearchFormat(java.lang.Object):
    """
    SearchFormats are responsible for parsing user input data into a :obj:`ByteMatcher` that
    can be used for searching memory. It also can convert search matches back into string data and 
    can convert string data from other formats into string data for this format.
    """

    class SearchFormatType(java.lang.Enum[SearchFormat.SearchFormatType]):

        class_: typing.ClassVar[java.lang.Class]
        BYTE: typing.Final[SearchFormat.SearchFormatType]
        INTEGER: typing.Final[SearchFormat.SearchFormatType]
        FLOATING_POINT: typing.Final[SearchFormat.SearchFormatType]
        STRING_TYPE: typing.Final[SearchFormat.SearchFormatType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SearchFormat.SearchFormatType:
            ...

        @staticmethod
        def values() -> jpype.JArray[SearchFormat.SearchFormatType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    HEX: typing.ClassVar[SearchFormat]
    BINARY: typing.ClassVar[SearchFormat]
    DECIMAL: typing.ClassVar[SearchFormat]
    STRING: typing.ClassVar[SearchFormat]
    REG_EX: typing.ClassVar[SearchFormat]
    FLOAT: typing.ClassVar[SearchFormat]
    DOUBLE: typing.ClassVar[SearchFormat]
    ALL: typing.ClassVar[jpype.JArray[SearchFormat]]

    def compareValues(self, bytes1: jpype.JArray[jpype.JByte], bytes2: jpype.JArray[jpype.JByte], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> int:
        """
        Compares bytes from search results based on how this format interprets the bytes.
        By default, formats just compare the bytes one by one as if they were unsigned values.
        SearchFormats whose bytes represent numerical values will override this method and
        compare the bytes after interpreting them as numerical values.
        
        :param jpype.JArray[jpype.JByte] bytes1: the first array of bytes to compare
        :param jpype.JArray[jpype.JByte] bytes2: the second array of bytes to compare
        :param ghidra.features.base.memsearch.gui.SearchSettings settings: the search settings used to generate the bytes.
        :return: a negative integer, zero, or a positive integer as the first byte array 
        is less than, equal to, or greater than the second byte array
        :rtype: int
        """

    def convertText(self, text: typing.Union[java.lang.String, str], oldSettings: ghidra.features.base.memsearch.gui.SearchSettings, newSettings: ghidra.features.base.memsearch.gui.SearchSettings) -> str:
        """
        Returns a new search input string, doing its best to convert an input string that
        was parsed by a previous :obj:`SearchFormat`. When it makes sense to do so, it will
        re-interpret the parsed bytes from the old format and reconstruct the input from those
        bytes. This allows the user to do conversions, for example, from numbers to hex or binary and 
        vise-versa. If the byte conversion doesn't make sense based on the old and new formats, it
        will use the original input if that input can be parsed by the new input. Finally, if all
        else fails, the new input will be the empty string.
        
        :param java.lang.String or str text: the old input that is parsable by the old format
        :param ghidra.features.base.memsearch.gui.SearchSettings oldSettings: the search settings used to parse the old text
        :param ghidra.features.base.memsearch.gui.SearchSettings newSettings: the search settings to used for the new text
        :return: the "best" text to change the user search input to
        :rtype: str
        """

    def getFormatType(self) -> SearchFormat.SearchFormatType:
        """
        Returns the :obj:`SearchFormatType` for this format. This is used to help with the
        :meth:`convertText(String, SearchSettings, SearchSettings) <.convertText>` method.
        
        :return: the type for this format
        :rtype: SearchFormat.SearchFormatType
        """

    def getName(self) -> str:
        """
        Returns the name of the search format.
        
        :return: the name of the search format
        :rtype: str
        """

    def getToolTip(self) -> str:
        """
        Returns a tool tip describing this search format
        
        :return: a tool tip describing this search format
        :rtype: str
        """

    def getValueString(self, bytes: jpype.JArray[jpype.JByte], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> str:
        """
        Reverse parses the bytes back into input value strings. Note that this is only used by
        numerical and string type formats. Byte oriented formats just return an empty string.
        
        :param jpype.JArray[jpype.JByte] bytes: the to convert back into input value strings
        :param ghidra.features.base.memsearch.gui.SearchSettings settings: The search settings used to parse the input into bytes
        :return: the string of the reversed parsed byte values
        :rtype: str
        """

    def parse(self, input: typing.Union[java.lang.String, str], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> ghidra.features.base.memsearch.matcher.ByteMatcher:
        """
        Parse the given input and settings into a :obj:`ByteMatcher`
        
        :param java.lang.String or str input: the user input string
        :param ghidra.features.base.memsearch.gui.SearchSettings settings: the current search/parse settings
        :return: a ByteMatcher that can be used for searching bytes (or an error version of a matcher)
        :rtype: ghidra.features.base.memsearch.matcher.ByteMatcher
        """

    @property
    def toolTip(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def formatType(self) -> SearchFormat.SearchFormatType:
        ...


@typing.type_check_only
class FloatSearchFormat(SearchFormat):
    """
    :obj:`SearchFormat` for parsing and display bytes in a float or double format.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getValue(self, bytes: jpype.JArray[jpype.JByte], index: typing.Union[jpype.JInt, int], isBigEndian: typing.Union[jpype.JBoolean, bool]) -> float:
        ...


@typing.type_check_only
class NumberParseResult(java.lang.Record):
    """
    Used by the NumberSearchFormat and the FloatSearchFormat for intermediate parsing results.
    """

    class_: typing.ClassVar[java.lang.Class]

    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def errorMessage(self) -> str:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def validInput(self) -> bool:
        ...


@typing.type_check_only
class RegExSearchFormat(SearchFormat):
    """
    :obj:`SearchFormat` for parsing input as a regular expression. This format can't generate
    bytes or parse results.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BinarySearchFormat(SearchFormat):
    """
    :obj:`SearchFormat` for parsing and display bytes in a binary format. This format only
    accepts 0s or 1s or wild card characters.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DecimalSearchFormat(SearchFormat):
    """
    :obj:`SearchFormat` for parsing and display bytes in a decimal format. It supports sizes of
    2,4,8,16 and can be either signed or unsigned.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getValue(self, bytes: jpype.JArray[jpype.JByte], index: typing.Union[jpype.JInt, int], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> int:
        ...


@typing.type_check_only
class StringSearchFormat(SearchFormat):
    """
    :obj:`SearchFormat` for parsing and display bytes in a string format. This format uses
    several values from SearchSettings included character encoding, case sensitive, and escape
    sequences.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class HexSearchFormat(SearchFormat):
    """
    :obj:`SearchFormat` for parsing and display bytes in a hex format. This format only 
    accepts hex digits or wild card characters.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["SearchFormat", "FloatSearchFormat", "NumberParseResult", "RegExSearchFormat", "BinarySearchFormat", "DecimalSearchFormat", "StringSearchFormat", "HexSearchFormat"]
