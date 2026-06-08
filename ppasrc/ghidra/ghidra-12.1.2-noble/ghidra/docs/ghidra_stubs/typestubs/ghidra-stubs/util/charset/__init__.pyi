from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import java.io # type: ignore
import java.lang # type: ignore
import java.nio.charset # type: ignore
import java.util # type: ignore


class CharsetInfoManager(java.lang.Object):
    """
    Maintains a list of charsets and info about each charset.  More common charsets are ordered
    toward the beginning of the list.
     
    
    Created instances are immutable, but the "INSTANCE" singleton can be replaced by a new value
    when :meth:`reinitializeWithUserDefinedCharsets() <.reinitializeWithUserDefinedCharsets>` is called.  (This is done to avoid reading
    the user config file and causing slow downs during certain stages of the startup)
    """

    @typing.type_check_only
    class Singleton(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CharSetsSingleton(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class CharsetInfoConfigFile(java.lang.Object):
        """
        Class to represent the charsetinfo json configuration file.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self) -> None:
            ...

        @typing.overload
        def __init__(self, comment: typing.Union[java.lang.String, str], charsets: java.util.List[CharsetInfo]) -> None:
            ...

        def getCharsets(self) -> java.util.List[CharsetInfo]:
            ...

        def getComment(self) -> str:
            ...

        @staticmethod
        def read(configFile: generic.jar.ResourceFile) -> CharsetInfoManager.CharsetInfoConfigFile:
            """
            Read config info from the specified file
            
            :param generic.jar.ResourceFile configFile: :obj:`ResourceFile`
            :return: new :obj:`CharsetInfoConfigFile`, never null, but maybe empty
            :rtype: CharsetInfoManager.CharsetInfoConfigFile
            """

        def validateData(self) -> None:
            ...

        def write(self, configFilename: jpype.protocol.SupportsPath) -> None:
            """
            Writes this instance to a json file.
            
            :param jpype.protocol.SupportsPath configFilename: where to write to
            :raises IOException: if error writing
            """

        @property
        def charsets(self) -> java.util.List[CharsetInfo]:
            ...

        @property
        def comment(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]
    UTF8: typing.Final = "UTF-8"
    UTF16: typing.Final = "UTF-16"
    UTF32: typing.Final = "UTF-32"
    USASCII: typing.Final = "US-ASCII"
    CHARSET_NAME_COMP: typing.ClassVar[java.util.Comparator[java.lang.String]]
    """
    Comparator that ignores charset name "x-" prefixes
    """

    CHARSET_COMP: typing.ClassVar[java.util.Comparator[CharsetInfo]]
    """
    Comparator that ignores charset name "x-" prefixes
    """


    @typing.overload
    def get(self, cs: java.nio.charset.Charset) -> CharsetInfo:
        """
        :return: charset info object that represents the specified charset
        :rtype: CharsetInfo
        
        
        :param java.nio.charset.Charset cs: charset
        """

    @typing.overload
    def get(self, name: typing.Union[java.lang.String, str]) -> CharsetInfo:
        """
        :return: charset info object that represents the specified charset
        :rtype: CharsetInfo
        
        
        :param java.lang.String or str name: charset name
        """

    @typing.overload
    def get(self, name: typing.Union[java.lang.String, str], defaultCS: java.nio.charset.Charset) -> CharsetInfo:
        """
        :return: charset info object that represents the specified charset, and if not found,
        returning the defaultCS value
        :rtype: CharsetInfo
        
        
        :param java.lang.String or str name: charset name
        :param java.nio.charset.Charset defaultCS: default value to return if not found
        """

    def getCharsetCharSize(self, charsetName: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the number of bytes that the specified charset needs to specify a
        character.
        
        :param java.lang.String or str charsetName: charset name
        :return: number of bytes in a character, ie. 1, 2, 4, etc, defaults to 1
                if charset is unknown or not specified in config file.
        :rtype: int
        """

    def getCharsetNames(self) -> java.util.List[java.lang.String]:
        """
        :return: List of names of current configured charsets
        :rtype: java.util.List[java.lang.String]
        """

    def getCharsetNamesWithCharSize(self, size: typing.Union[jpype.JInt, int]) -> java.util.List[java.lang.String]:
        """
        Returns list of :obj:`Charset`s that encode with the number of bytes specified.
        
        :param jpype.JInt or int size: the number of bytes for the :obj:`Charset` encoding.
        :return: Charsets that encode one byte characters.
        :rtype: java.util.List[java.lang.String]
        """

    def getCharsets(self) -> java.util.List[CharsetInfo]:
        """
        :return: list of all available charsets
        :rtype: java.util.List[CharsetInfo]
        """

    @staticmethod
    def getConfigFileLocation() -> generic.jar.ResourceFile:
        """
        :return: filename of the config file
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def getInstance() -> CharsetInfoManager:
        """
        Get the global singleton instance of this :obj:`CharsetInfoManager`.
         
        
        This singleton will only have generic information until 
        :meth:`CharsetInfoManager.reinitializeWithUserDefinedCharsets() <CharsetInfoManager.reinitializeWithUserDefinedCharsets>` is called.
        
        :return: global singleton instance
        :rtype: CharsetInfoManager
        """

    def getMostImplementedScripts(self) -> java.util.List[java.lang.Character.UnicodeScript]:
        """
        :return: a hopefully short list of non-LATIN UnicodeScripts that are supported by a 
        charset that is present in this jvm.  (ignoring any charsets that support all scripts).
        This list of scripts can be useful when presenting the user with a list of scripts or 
        things related to a script.  Typically the list will contain:
        ARABIC, BOPOMOFO, CYRILLIC, DEVANAGARI, HANGUL, HAN, HEBREW, HIRAGANA, KATAKANA, THAI 
        :rtype: java.util.List[java.lang.Character.UnicodeScript]
        """

    @staticmethod
    def getStandardCharsetNames() -> java.util.List[java.lang.String]:
        ...

    @staticmethod
    def isBOMCharset(charsetName: typing.Union[java.lang.String, str]) -> bool:
        """
        :return: true if the specified charset needs additional care for handling byte-order-mark
        byte values (eg. UTF-16/32).  If the charset is a LE/BE variant, no extra care is needed.
        :rtype: bool
        
        
        :param java.lang.String or str charsetName: name of charset
        """

    @staticmethod
    def reinitializeWithUserDefinedCharsets() -> None:
        """
        Replaces the current singleton with a new singleton that has been initialized with the
        optional information found in the charset_info.json file.
        """

    @property
    def mostImplementedScripts(self) -> java.util.List[java.lang.Character.UnicodeScript]:
        ...

    @property
    def charsetNamesWithCharSize(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def charsets(self) -> java.util.List[CharsetInfo]:
        ...

    @property
    def charsetCharSize(self) -> jpype.JInt:
        ...

    @property
    def charsetNames(self) -> java.util.List[java.lang.String]:
        ...


class CharsetInfo(java.lang.Object):
    """
    Additional information about :obj:`java.nio.charset.Charset's <Charset>` that
    Ghidra needs to be able to create Ghidra string datatype instances.
     
    
    See charset_info.json to specify info about a custom charset.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, cs: java.nio.charset.Charset) -> None:
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], minBytesPerChar: typing.Union[jpype.JInt, int], maxBytesPerChar: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], codePointCount: typing.Union[jpype.JInt, int], standardCharset: typing.Union[jpype.JBoolean, bool], canProduceError: typing.Union[jpype.JBoolean, bool], scripts: java.util.EnumSet[java.lang.Character.UnicodeScript], contains: java.util.Set[java.lang.String]) -> None:
        ...

    def getAlignment(self) -> int:
        """
        :return: the alignment value for this charset, typically 1 for most charsets, but for
        well-known fixed-width charsets, it will return those charsets fixed-width
        :rtype: int
        """

    def getCharset(self) -> java.nio.charset.Charset:
        """
        
        
        :return: :obj:`Charset`
        :rtype: java.nio.charset.Charset
        """

    def getCodePointCount(self) -> int:
        """
        :return: the number of codepoints that this charset can produce
        :rtype: int
        """

    def getComment(self) -> str:
        """
        :return: a string comment describing this charset, or null
        :rtype: str
        """

    def getContains(self) -> java.util.Set[java.lang.String]:
        """
        Returns the names of other charsets that this charset :meth:`Charset.contains(Charset) <Charset.contains>`.
        
        :return: names of other charsets
        :rtype: java.util.Set[java.lang.String]
        """

    def getMaxBytesPerChar(self) -> int:
        """
        :return: the largest number of bytes needed to produce a codepoint
        :rtype: int
        """

    def getMinBytesPerChar(self) -> int:
        """
        :return: the smallest number of bytes needed to produce a codepoint
        :rtype: int
        """

    def getName(self) -> str:
        """
        :return: name of the charset
        :rtype: str
        """

    def getScripts(self) -> java.util.Set[java.lang.Character.UnicodeScript]:
        """
        :return: the UnicodeScripts that this charset can produce
        :rtype: java.util.Set[java.lang.Character.UnicodeScript]
        """

    def hasFixedLengthChars(self) -> bool:
        """
        :return: true if this charset only consumes a fixed number of bytes per output codepoint
        :rtype: bool
        """

    def isCanProduceError(self) -> bool:
        """
        :return: true if this charset can produce Unicode REPLACEMENT codepoints for
        bad byte sequences, otherwise false if there are no byte sequences that result in REPLACEMENT
        codepoints.  This is typically single-byte charsets that map all byte values to a codepoint
        :rtype: bool
        """

    def isStandardCharset(self) -> bool:
        """
        :return: boolean flag, true if this is a standard charset that is guaranteed to be present
        in the jvm, otherwise false
        :rtype: bool
        """

    def supportsAllScripts(self) -> bool:
        """
        :return: true if this charset can produce Unicode codepoints that are in all scripts
        :rtype: bool
        """

    def withComment(self, newComment: typing.Union[java.lang.String, str]) -> CharsetInfo:
        """
        :return: a copy of this instance, with a new comment value
        :rtype: CharsetInfo
        
        
        :param java.lang.String or str newComment: string
        """

    @property
    def charset(self) -> java.nio.charset.Charset:
        ...

    @property
    def contains(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def canProduceError(self) -> jpype.JBoolean:
        ...

    @property
    def standardCharset(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def maxBytesPerChar(self) -> jpype.JInt:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def scripts(self) -> java.util.Set[java.lang.Character.UnicodeScript]:
        ...

    @property
    def minBytesPerChar(self) -> jpype.JInt:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @property
    def codePointCount(self) -> jpype.JInt:
        ...



__all__ = ["CharsetInfoManager", "CharsetInfo"]
