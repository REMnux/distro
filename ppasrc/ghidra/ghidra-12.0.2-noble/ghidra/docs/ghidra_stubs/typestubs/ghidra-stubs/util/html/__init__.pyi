from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore


class HtmlLineSplitter(java.lang.Object):
    """
    Splits into lines a given String that is meant to be rendered as HTML.
     
     
    Really, this class exists simply to remove hundreds of lines of code from 
    :obj:`HTMLUtilities`, which is what this code supports.  The methods in here could easily
    be in :obj:`StringUtils`, but to keep dependencies low on code that has such a specific use, 
    it lives here, with a name that implies you shouldn't use it unless you are working with 
    HTML.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_WORD_LENGTH: typing.Final = 10
    """
    Used when trying to split on word boundaries; the value past which to give up
    """


    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def split(text: typing.Union[java.lang.String, str], maxLineLength: typing.Union[jpype.JInt, int]) -> java.util.List[java.lang.String]:
        """
        Splits the given line into multiple lines based upon the given max length.  This method
        will first split on each newline and then wrap each of the lines returned from that split.
         
         
        The wrapping routine will attempt to wrap at word boundaries.
         
         
        This method does not retain leading whitespace.
        
        :param java.lang.String or str text: the text to wrap
        :param jpype.JInt or int maxLineLength: the max desired length of each output line; 0 or less signals not
                to wrap the line based upon length
        :return: the new lines
        :rtype: java.util.List[java.lang.String]
        
        .. seealso::
        
            | :obj:`.wrap(String, int, WhitespaceHandler)`
        
            | :obj:`.split(String, int, boolean)`
        """

    @staticmethod
    @typing.overload
    def split(text: typing.Union[java.lang.String, str], maxLineLength: typing.Union[jpype.JInt, int], retainSpacing: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.lang.String]:
        """
        Splits the given line into multiple lines based upon the given max length.  This method
        will first split on each newline and then wrap each of the lines returned from that split.
         
         
        The wrapping routine will attempt to wrap at word boundaries.
        
        :param java.lang.String or str text: the text to wrap
        :param jpype.JInt or int maxLineLength: the max desired length of each output line; 0 or less signals not
                to wrap the line based upon length
        :param jpype.JBoolean or bool retainSpacing: true signals to keep whitespace on line breaks; false discards 
                leading whitespace
        :return: the new lines
        :rtype: java.util.List[java.lang.String]
        
        .. seealso::
        
            | :obj:`.wrap(String, int, WhitespaceHandler)`
        """


@typing.type_check_only
class TrimmingWhitespaceHandler(WhitespaceHandler):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PreservingWhitespaceHandler(WhitespaceHandler):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class WhitespaceHandler(java.lang.Object):
    """
    Simple interface to handle dealing with whitespace in strings when wrapping.
    """

    class_: typing.ClassVar[java.lang.Class]

    def countSpaces(self, s: typing.Union[java.lang.String, str], offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Counts the number of contiguous spaces in the given string starting from the 
        given offset.
        
        :param java.lang.String or str s: the string
        :param jpype.JInt or int offset: the offset in the string at which to start
        :return: the number of contiguous spaces
        :rtype: int
        """

    def trim(self, s: typing.Union[java.lang.String, str]) -> str:
        """
        Trim the given string (or don't, it's up to the implementation).
        
        :param java.lang.String or str s: the string
        :return: the trimmed string
        :rtype: str
        """


class HTMLElement(java.util.ArrayList[java.lang.Object]):

    @typing.type_check_only
    class HTMLContent(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    def addElement(self, elementName: typing.Union[java.lang.String, str]) -> HTMLElement:
        ...

    def addHTMLContent(self, htmlContent: typing.Union[java.lang.String, str]):
        ...

    def getAttribute(self, key: typing.Union[java.lang.String, str]) -> str:
        ...

    def putAttribute(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> str:
        ...

    def removeAttribute(self, key: typing.Union[java.lang.String, str]) -> str:
        ...

    @property
    def attribute(self) -> java.lang.String:
        ...



__all__ = ["HtmlLineSplitter", "TrimmingWhitespaceHandler", "PreservingWhitespaceHandler", "WhitespaceHandler", "HTMLElement"]
