from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.data
import ghidra.program.model.lang
import java.lang # type: ignore


class MinLengthCharSequenceMatcher(java.lang.Object):
    """
    Instances of this class will find sequences of characters that are in the given char set and
    of a minimum length.  Characters a fed one at a time into this object. Adding a char may trigger
    the discovery of a sequence if the char is a 0 or not in the char set and we already have seen
    a sequence of included chars at least as long as the minimum length.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, minimumSequenceLength: typing.Union[jpype.JInt, int], charSet: CharSetRecognizer, alignment: typing.Union[jpype.JInt, int]):
        ...

    def addChar(self, c: typing.Union[jpype.JInt, int]) -> bool:
        """
        Adds a character to this sequence matcher.
        
        :param jpype.JInt or int c: the character to add.
        :return: a Sequence if the added char triggered an end of a valid sequence, otherwise null.
        :rtype: bool
        """

    def endSequence(self) -> bool:
        """
        Indicates there are no more contiguous chars to add to this matcher.  If a minimum or more
        number of included chars have been seen before this call, then a sequence is returned.
        
        :return: a Sequence if there was a sequence of chars >= the min length just before this call.
        :rtype: bool
        """

    def getSequence(self) -> Sequence:
        ...

    def reset(self):
        ...

    @property
    def sequence(self) -> Sequence:
        ...


class AsciiCharSetRecognizer(CharSetRecognizer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Sequence(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], stringDataType: ghidra.program.model.data.AbstractStringDataType, nullTerminated: typing.Union[jpype.JBoolean, bool]):
        ...

    def getEnd(self) -> int:
        ...

    def getLength(self) -> int:
        ...

    def getStart(self) -> int:
        ...

    def getStringDataType(self) -> ghidra.program.model.data.AbstractStringDataType:
        ...

    def isNullTerminated(self) -> bool:
        ...

    @property
    def nullTerminated(self) -> jpype.JBoolean:
        ...

    @property
    def start(self) -> jpype.JLong:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def end(self) -> jpype.JLong:
        ...

    @property
    def stringDataType(self) -> ghidra.program.model.data.AbstractStringDataType:
        ...


class CharWidth(java.lang.Enum[CharWidth]):

    class_: typing.ClassVar[java.lang.Class]
    UTF8: typing.Final[CharWidth]
    UTF16: typing.Final[CharWidth]
    UTF32: typing.Final[CharWidth]

    def size(self) -> int:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CharWidth:
        ...

    @staticmethod
    def values() -> jpype.JArray[CharWidth]:
        ...


class MultiByteCharMatcher(ByteStreamCharMatcher):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, minLength: typing.Union[jpype.JInt, int], charSet: CharSetRecognizer, charWidth: CharWidth, endian: ghidra.program.model.lang.Endian, alignment: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int]):
        ...


class ByteStreamCharMatcher(java.lang.Object):
    """
    ByteStreamCharMatcher are state machines used to look for char sequences within a stream of bytes.  
    Bytes from the stream are added one a time and converted to character stream which are in
    turn fed into a char stream recognizer.  As each byte is added, an indication is returned if that byte caused
    a terminated sequence to be found.  A sequence is simply a pair of indexes indicated the start and
    end indexes into the byte stream where the char sequence started and ended respectively along with
    an indication that the sequence was null terminated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, b: typing.Union[jpype.JByte, int]) -> bool:
        """
        Adds the next contiguous byte to this matcher
        
        :param jpype.JByte or int b: the next contiguous byte in the search stream.
        :return: true if the given byte triggered a sequence match.  Note that this byte may not be
        a part of the recognized sequence.
        :rtype: bool
        """

    def endSequence(self) -> bool:
        """
        Tells the matcher that there are no more contiguous bytes.  If the current state of the 
        matcher is such that there is a valid sequence that can be at the end of the stream, then
        a sequence will be created and true will be returned.
        
        :return: true if there is a valid sequence at the end of the stream.
        :rtype: bool
        """

    def getSequence(self) -> Sequence:
        """
        Returns the currently recognized sequence which only exists immediately after an add or
        end sequence is called with a return value of true.
        
        :return: 
        :rtype: Sequence
        """

    def reset(self):
        """
        Resets the internal state of this ByteMatcher so that it can be reused against another byte stream.
        """

    @property
    def sequence(self) -> Sequence:
        ...


class CharSetRecognizer(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, c: typing.Union[jpype.JInt, int]) -> bool:
        ...



__all__ = ["MinLengthCharSequenceMatcher", "AsciiCharSetRecognizer", "Sequence", "CharWidth", "MultiByteCharMatcher", "ByteStreamCharMatcher", "CharSetRecognizer"]
