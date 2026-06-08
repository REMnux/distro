from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.base.memsearch.gui
import ghidra.util.bytesearch
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class RegExByteMatcher(UserInputByteMatcher):
    """
    :obj:`ByteMatcher` where the user search input has been parsed as a regular expression.
    """

    @typing.type_check_only
    class ByteCharSequence(java.lang.CharSequence):
        """
        Class for converting byte sequences into a :obj:`CharSequence` that can be used by
        the java regular expression engine
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PatternMatchIterator(java.lang.Iterable[ghidra.util.bytesearch.Match[SearchData]], java.util.Iterator[ghidra.util.bytesearch.Match[SearchData]]):
        """
        Adapter class for converting java :obj:`Pattern` matching into an iterator of
        :obj:`Match`s.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, byteSequence: ghidra.util.bytesearch.ExtendedByteSequence) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, input: typing.Union[java.lang.String, str], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> None:
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], input: typing.Union[java.lang.String, str], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> None:
        ...


class SearchData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], input: typing.Union[java.lang.String, str], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> None:
        ...

    def getInput(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getSettings(self) -> ghidra.features.base.memsearch.gui.SearchSettings:
        ...

    @property
    def settings(self) -> ghidra.features.base.memsearch.gui.SearchSettings:
        ...

    @property
    def input(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class ByteMatcher(java.lang.Object, typing.Generic[T]):
    """
    ByteMatcher is the base class for an object that be used to scan bytes looking for sequences
    that match some criteria. As a convenience, it also stores the input string and settings that
    were used to generated this ByteMatcher.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self) -> str:
        ...

    def match(self, bytes: ghidra.util.bytesearch.ExtendedByteSequence) -> java.lang.Iterable[ghidra.util.bytesearch.Match[T]]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class BulkPatternByteMatcher(ByteMatcher[T], typing.Generic[T]):
    """
    :obj:`ByteMatcher` that uses a BulkPatternSearcher to simultaneously search for multiple
    byte patterns.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, patterns: java.util.List[T]) -> None:
        """
        Constructor
        
        :param java.util.List[T] patterns: the list of patterns that this byte matcher will simultaneously search for
        """


class InvalidByteMatcher(UserInputByteMatcher):
    """
    Objects of this class are the result of :obj:`SearchFormat`s not being able to fully parse
    input text. There are two cases. The first is the user type an illegal character for the
    selected search format. In that case this matcher is both an invalid search and an invalid
    input and the description will explain the error. The second case is the input is valid text,
    but not complete so that a fully valid byte matcher could not be created. In this case, the
    search is still invalid, but the input is valid. The description will reflect this situation.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, errorMessage: typing.Union[java.lang.String, str]) -> None:
        """
        Construct an invalid matcher from invalid input text.
        
        :param java.lang.String or str errorMessage: the message describing the invalid input
        """

    @typing.overload
    def __init__(self, errorMessage: typing.Union[java.lang.String, str], isValidInput: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Construct an invalid matcher from invalid input text or partial input text.
        
        :param java.lang.String or str errorMessage: the message describing why this matcher is invalid
        :param jpype.JBoolean or bool isValidInput: return true if the reason this is invalid is simply that the input
        text is not complete. For example, the user types "-" as they are starting to input
        a negative number.
        """


class UserInputByteMatcher(ByteMatcher[SearchData]):

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self) -> str:
        """
        Returns a description of what this byte matcher matches. (Typically a sequence of bytes)
        
        :return: a description of what this byte matcher matches
        :rtype: str
        """

    def getInput(self) -> str:
        ...

    def getName(self) -> str:
        """
        :return: the name of this byte matcher.
        :rtype: str
        """

    def getSearchData(self) -> SearchData:
        ...

    def getSettings(self) -> ghidra.features.base.memsearch.gui.SearchSettings:
        ...

    def getToolTip(self) -> str:
        """
        Returns additional information about this byte matcher. (Typically the mask bytes)
        
        :return: additional information about this byte matcher
        :rtype: str
        """

    def isValidInput(self) -> bool:
        """
        Returns true if this byte matcher has valid (but possibly incomplete) input text. For 
        example, when entering decimal values, the input could be just "-" as the user starts
        to enter a negative number. In this case the input is valid, but the :meth:`isValidSearch() <.isValidSearch>`
        would return false.
        
        :return: true if this byte matcher has valid text
        :rtype: bool
        """

    def isValidSearch(self) -> bool:
        """
        Returns true if this byte matcher is valid and can be used to perform a search. If false,
        the description will return an error message explaining why this byte matcher is
        invalid.
        
        :return: true if this byte matcher is valid and can be used to perform a search.
        :rtype: bool
        """

    def match(self, bytes: ghidra.util.bytesearch.ExtendedByteSequence) -> java.lang.Iterable[ghidra.util.bytesearch.Match[SearchData]]:
        """
        Returns an :obj:`Iterable` for returning matches within the given byte sequence.
        
        :param ghidra.util.bytesearch.ExtendedByteSequence bytes: the byte sequence to search
        :return: an iterable for return matches in the given sequence
        :rtype: java.lang.Iterable[ghidra.util.bytesearch.Match[SearchData]]
        """

    @property
    def settings(self) -> ghidra.features.base.memsearch.gui.SearchSettings:
        ...

    @property
    def input(self) -> java.lang.String:
        ...

    @property
    def validSearch(self) -> jpype.JBoolean:
        ...

    @property
    def toolTip(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def validInput(self) -> jpype.JBoolean:
        ...

    @property
    def searchData(self) -> SearchData:
        ...


class MaskedByteSequenceByteMatcher(UserInputByteMatcher):
    """
    :obj:`ByteMatcher` where the user search input has been parsed into a sequence of bytes and
    masks to be used for searching a byte sequence.
    """

    @typing.type_check_only
    class MatchIterator(java.util.Iterator[ghidra.util.bytesearch.Match[SearchData]], java.lang.Iterable[ghidra.util.bytesearch.Match[SearchData]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, byteSequence: ghidra.util.bytesearch.ByteSequence) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, input: typing.Union[java.lang.String, str], bytes: jpype.JArray[jpype.JByte], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> None:
        """
        Constructor where no masking will be required. The bytes must match exactly.
        
        :param java.lang.String or str input: the input text used to create this matcher
        :param jpype.JArray[jpype.JByte] bytes: the sequence of bytes to use for searching
        :param ghidra.features.base.memsearch.gui.SearchSettings settings: the :obj:`SearchSettings` used to parse the input text
        """

    @typing.overload
    def __init__(self, input: typing.Union[java.lang.String, str], bytes: jpype.JArray[jpype.JByte], masks: jpype.JArray[jpype.JByte], settings: ghidra.features.base.memsearch.gui.SearchSettings) -> None:
        """
        Constructor that includes a mask byte for each search byte.
        
        :param java.lang.String or str input: the input text used to create this matcher
        :param jpype.JArray[jpype.JByte] bytes: the sequence of bytes to use for searching
        :param jpype.JArray[jpype.JByte] masks: the sequence of mask bytes to use for search. Each mask byte will be applied
        to the bytes being search before comparing them to the target bytes.
        :param ghidra.features.base.memsearch.gui.SearchSettings settings: the :obj:`SearchSettings` used to parse the input text
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getMask(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def mask(self) -> jpype.JArray[jpype.JByte]:
        ...



__all__ = ["RegExByteMatcher", "SearchData", "ByteMatcher", "BulkPatternByteMatcher", "InvalidByteMatcher", "UserInputByteMatcher", "MaskedByteSequenceByteMatcher"]
