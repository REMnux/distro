from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.demangler
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class RustString(SymbolNode):
    """
    A class to represent a string node
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: typing.Union[java.lang.String, str]):
        ...


class RustDemanglerLegacy(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def demangle(symbol: typing.Union[java.lang.String, str]) -> str:
        ...


@typing.type_check_only
class RustType(SymbolNode):
    """
    Parses and represents a rust symbol type node
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, typeName: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, path: RustPath):
        ...

    @staticmethod
    def parse(s: Symbol) -> RustType:
        """
        Parses a rust type from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: the rust type object
        :rtype: RustType
        """

    @staticmethod
    def parseBinder(s: Symbol) -> str:
        """
        Parses a rust binding from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: a string representing the binding
        :rtype: str
        """

    @staticmethod
    def parseDynBounds(s: Symbol) -> str:
        """
        Parses a rust dyn bounds from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: a string representing the dyn bounds
        :rtype: str
        """

    @staticmethod
    def parseDynTrait(s: Symbol) -> str:
        """
        Parses a rust dyn trait from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: a string representing the dyn trait
        :rtype: str
        """

    @staticmethod
    def parseDynTraitAssocBinding(s: Symbol) -> str:
        """
        Parses a rust dyn trait associated binding from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: a string representing the dyn trait associated binding
        :rtype: str
        """


class RustDemanglerFormat(java.lang.Enum[RustDemanglerFormat]):
    """
    Enum representation of the available Rust demangler formats
    """

    @typing.type_check_only
    class Version(java.lang.Enum[RustDemanglerFormat.Version]):

        class_: typing.ClassVar[java.lang.Class]
        DEPRECATED: typing.Final[RustDemanglerFormat.Version]
        MODERN: typing.Final[RustDemanglerFormat.Version]
        ALL: typing.Final[RustDemanglerFormat.Version]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> RustDemanglerFormat.Version:
            ...

        @staticmethod
        def values() -> jpype.JArray[RustDemanglerFormat.Version]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    AUTO: typing.Final[RustDemanglerFormat]
    """
    Automatic mangling format detection
    """

    LEGACY: typing.Final[RustDemanglerFormat]
    """
    legacy mangling format
    """

    V0: typing.Final[RustDemanglerFormat]
    """
    v0 mangling format
    """


    def getFormat(self) -> str:
        """
        Gets the format option to be passed to the demangler via the ``-s`` option
        
        :return: the format option to be passed to the demangler
        :rtype: str
        """

    def isAvailable(self, isDeprecated: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Checks if this format is available for the specified demangler
        
        :param jpype.JBoolean or bool isDeprecated: true for the deprecated demangler, false for the modern demangler
        :return: true if the format is available
        :rtype: bool
        """

    def isDeprecatedFormat(self) -> bool:
        """
        Checks if this format is available in the deprecated rust demangler
        
        :return: true if this format is available in the deprecated rust demangler
        :rtype: bool
        """

    def isModernFormat(self) -> bool:
        """
        Checks if this format is available in a modern version of the rust demangler
        
        :return: true if this format is available in a modern version of the rust demangler
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> RustDemanglerFormat:
        ...

    @staticmethod
    def values() -> jpype.JArray[RustDemanglerFormat]:
        ...

    @property
    def modernFormat(self) -> jpype.JBoolean:
        ...

    @property
    def available(self) -> jpype.JBoolean:
        ...

    @property
    def format(self) -> java.lang.String:
        ...

    @property
    def deprecatedFormat(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class RustIdentifier(SymbolNode):
    """
    Parses and represents an rust symbol identifier
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, namespace: RustNamespace, id: typing.Union[java.lang.String, str], disambiguator: RustString):
        ...

    @staticmethod
    def parse(s: Symbol, namespace: RustNamespace) -> RustIdentifier:
        """
        Parses a rust identifier from a mangled symbol
        
        :param Symbol s: symbol to parse
        :param RustNamespace namespace: namespace of symbol
        :return: the rust identifier object
        :rtype: RustIdentifier
        """

    @staticmethod
    def parseDisambiguator(s: Symbol) -> RustString:
        """
        Parses a rust disambiguator from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: a string representing the disambiguator
        :rtype: RustString
        """

    @staticmethod
    def parseUndisambiguatedIdentifier(s: Symbol) -> str:
        """
        Parses a rust undisambiguated identifier from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: the corresponding string object
        :rtype: str
        """


@typing.type_check_only
class RustGenericArg(SymbolNode):
    """
    Parses and represents a generic argument node in a rust symbol
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, child: SymbolNode):
        ...

    @staticmethod
    def parse(s: Symbol) -> RustGenericArg:
        """
        Parses a rust generic argument from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: the rust generic argument object
        :rtype: RustGenericArg
        """


@typing.type_check_only
class RustNamespace(java.lang.Object):
    """
    Parses and represents a rust symbol namespace node
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def parse(s: Symbol) -> RustNamespace:
        """
        Parses a rust namespace from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: the rust path object
        :rtype: RustNamespace
        """


@typing.type_check_only
class SymbolNode(java.lang.Object):
    """
    A node to be used in symbol parsing
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RustLifetime(SymbolNode):
    """
    Parses a rust lifetime from a mangled symbol
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, num: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def parse(s: Symbol) -> SymbolNode:
        """
        Parses a rust lifetime node from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: the rust lifetime node
        :rtype: SymbolNode
        """


class RustDemanglerParser(java.lang.Object):
    """
    Parses a demangled rust string
    """

    @typing.type_check_only
    class CondensedString(java.lang.Object):
        """
        A class to handle whitespace manipulation within demangled strings.  This class will
        remove bad spaces, which is all whitespace that is not needed to separate distinct objects
        inside of a demangled string.
        
         
        Generally, this class removes spaces within templates and parameter lists.   It will
        remove some spaces, while converting some to underscores.
        """

        @typing.type_check_only
        class Part(java.lang.Object):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def parse(self, mangled: typing.Union[java.lang.String, str], demangled: typing.Union[java.lang.String, str]) -> ghidra.app.util.demangler.DemangledObject:
        """
        Parses the given demangled string and creates a :obj:`DemangledObject`
        
        :param java.lang.String or str mangled: the original mangled text
        :param java.lang.String or str demangled: the demangled text
        :return: the demangled object
        :rtype: ghidra.app.util.demangler.DemangledObject
        :raises java.lang.RuntimeException: if there is an unexpected error parsing
        """


@typing.type_check_only
class RustPath(SymbolNode):
    """
    A class to represent and parse a rust symbol path node
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, child: SymbolNode):
        ...

    @typing.overload
    def __init__(self, child: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def parse(s: Symbol) -> RustPath:
        """
        Parses a rust path from a mangled symbol
        
        :param Symbol s: parse the rust path
        :return: the rust path object
        :rtype: RustPath
        """


@typing.type_check_only
class RustPathNested(SymbolNode):
    """
    A class to represent a nested path node
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: SymbolNode, identifier: RustIdentifier):
        ...


@typing.type_check_only
class RustGenericArgs(SymbolNode):
    """
    Parses and represents rust generic arguments
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, args: java.util.ArrayList[RustGenericArg]):
        ...

    @staticmethod
    def parse(s: Symbol) -> RustGenericArgs:
        """
        Parses generics arguments from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: the rust generic arguments object
        :rtype: RustGenericArgs
        """


@typing.type_check_only
class RustImplPath(SymbolNode):
    """
    Parses and represents a rust symbol impl path node
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: RustPath, disambiguator: RustString):
        ...

    @staticmethod
    def parse(s: Symbol) -> RustImplPath:
        """
        Parses a impl rust path from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: the rust impl path object
        :rtype: RustImplPath
        """


class RustDemangler(ghidra.app.util.demangler.Demangler):
    """
    A class for demangling debug symbols created using rustc
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def isRustMangled(mangled: typing.Union[java.lang.String, str]) -> bool:
        """
        Return true if the string is a mangled rust string in a rust program
        
        :param java.lang.String or str mangled: potential mangled string
        :return: true if the string could be a mangled string in a rust program
        :rtype: bool
        """


class RustDemanglerV0(java.lang.Object):
    """
    A class that will demangle Rust symbols mangled according to the V0 format. This class
    implements the grammar that will translate a mangled string into a demangled one.
    
    
    .. seealso::
    
        | `2603-rust-symbol-name-mangling-v0.html <https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def demangle(symbol: typing.Union[java.lang.String, str]) -> str:
        """
        Demangles a symbol according to the format
        
        :param java.lang.String or str symbol: the mangled symbol name
        :return: the demangled symbol name
        :rtype: str
        """


@typing.type_check_only
class RustConst(SymbolNode):
    """
    Parses and represents a rust symbol const node
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def parse(s: Symbol) -> RustConst:
        """
        Parses a rust const from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: the rust const object
        :rtype: RustConst
        """

    @staticmethod
    def parseConstData(s: Symbol) -> str:
        """
        Parses a rust const data from a mangled symbol
        
        :param Symbol s: symbol to parse
        :return: a string representing the const data
        :rtype: str
        """


class RustDemanglerOptions(ghidra.app.util.demangler.DemanglerOptions):
    """
    Rust demangler options
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor to use the modern demangler with auto-detect for the format.  This
        constructor will limit demangling to only known symbols.
        """

    @typing.overload
    def __init__(self, format: RustDemanglerFormat):
        """
        Constructor to specify a particular format
        
        :param RustDemanglerFormat format: signals to use the given format
        """

    @typing.overload
    def __init__(self, format: RustDemanglerFormat, isDeprecated: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor to specify the format to use and whether to prefer the deprecated format when
        both deprecated and modern are available
        
        :param RustDemanglerFormat format: the format
        :param jpype.JBoolean or bool isDeprecated: true if the format is not available in the modern demangler
        :raises IllegalArgumentException: if the given format is not available in the deprecated
                demangler
        """

    @typing.overload
    def __init__(self, copy: ghidra.app.util.demangler.DemanglerOptions):
        """
        Copy constructor to create a version of this class from a more generic set of options
        
        :param ghidra.app.util.demangler.DemanglerOptions copy: the options to copy
        """

    def getDemanglerFormat(self) -> RustDemanglerFormat:
        """
        Gets the current demangler format
        
        :return: the demangler format
        :rtype: RustDemanglerFormat
        """

    @property
    def demanglerFormat(self) -> RustDemanglerFormat:
        ...


@typing.type_check_only
class Symbol(java.lang.Object):
    """
    A class that represents a symbol in the demangling process. It keeps track of
    the current state of the symbol and implements various methods to assist with
    demangling it.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str]):
        """
        Creates a symbol object
        
        :param java.lang.String or str mangled: the mangled symbol name
        """

    def backChar(self):
        """
        Subtracts one from the position in the mangled string
        """

    def backrefAdd(self, index: typing.Union[jpype.JInt, int], value: SymbolNode):
        """
        Adds a backref to the list
        
        :param jpype.JInt or int index: the index of the backref
        :param SymbolNode value: the backref object to add
        """

    def getBackref(self, index: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets the backref at a certain index
        
        :param jpype.JInt or int index: the index of he backref to return
        :return: the backref object
        :rtype: str
        """

    def isEmpty(self) -> bool:
        """
        Returns if the end of the mangled string has been reached
        
        :return: if the end has been reached
        :rtype: bool
        """

    def nextChar(self) -> str:
        """
        Gets the next char in the mangled string
        
        :return: the next char
        :rtype: str
        """

    def nextInt(self) -> int:
        """
        Gets the next int in the mangled string
        
        :return: the next int
        :rtype: int
        """

    def parseBackref(self) -> str:
        """
        Returns the number of the encoded backref
        
        :return: the number sting
        :rtype: str
        """

    def parseBase62Number(self) -> str:
        """
        Parses the following base 62 number
        
        :return: the parsed num string
        :rtype: str
        """

    def parseDigits(self) -> int:
        """
        Parses the following numerical digits in the mangled sting
        
        :return: the parsed integer
        :rtype: int
        """

    def parseString(self, n: typing.Union[jpype.JInt, int]) -> str:
        """
        Parses the
        
        :param jpype.JInt or int n: number of characters
        :return: the parsed string
        :rtype: str
        """

    def parseUntil(self, c: typing.Union[jpype.JChar, int, str]) -> str:
        """
        Parses the string until the passed char is reached
        
        :param jpype.JChar or int or str c: the char to parse until
        :return: the parsed string
        :rtype: str
        """

    def popChar(self) -> str:
        """
        Pops the next char in the mangled string
        
        :return: the next char
        :rtype: str
        """

    def remaining(self) -> str:
        """
        Returns the remaining string to be demangled
        
        :return: the mangled string
        :rtype: str
        """

    def stripPrefix(self, c: typing.Union[jpype.JChar, int, str]) -> bool:
        """
        Strips the first char of the mangled string if it's equal to the argument
        
        :param jpype.JChar or int or str c: the char to strip
        :return: if the strip succeeded
        :rtype: bool
        """

    @property
    def backref(self) -> java.lang.String:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class RustBackref(SymbolNode):
    """
    A class that will represent and parse a backref node
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, backref: typing.Union[jpype.JInt, int], s: Symbol):
        ...



__all__ = ["RustString", "RustDemanglerLegacy", "RustType", "RustDemanglerFormat", "RustIdentifier", "RustGenericArg", "RustNamespace", "SymbolNode", "RustLifetime", "RustDemanglerParser", "RustPath", "RustPathNested", "RustGenericArgs", "RustImplPath", "RustDemangler", "RustDemanglerV0", "RustConst", "RustDemanglerOptions", "Symbol", "RustBackref"]
