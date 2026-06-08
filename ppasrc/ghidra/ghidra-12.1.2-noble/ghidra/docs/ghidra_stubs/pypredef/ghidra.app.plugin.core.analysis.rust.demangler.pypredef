from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.demangler
import java.lang # type: ignore


class RustDemanglerLegacy(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    @staticmethod
    def demangle(symbol: typing.Union[java.lang.String, str]) -> str:
        ...


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

    def __init__(self) -> None:
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


class RustDemangler(ghidra.app.util.demangler.Demangler):
    """
    A class for demangling debug symbols created using rustc
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
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

    @typing.type_check_only
    class ParseErrorKind(java.lang.Enum[RustDemanglerV0.ParseErrorKind]):

        class_: typing.ClassVar[java.lang.Class]
        INVALID: typing.Final[RustDemanglerV0.ParseErrorKind]
        RECURSED_TOO_DEEP: typing.Final[RustDemanglerV0.ParseErrorKind]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> RustDemanglerV0.ParseErrorKind:
            ...

        @staticmethod
        def values() -> jpype.JArray[RustDemanglerV0.ParseErrorKind]:
            ...


    @typing.type_check_only
    class ParseException(java.lang.Exception):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Parser(java.lang.Object):
        """
        Stateful cursor used while walking the v0 grammar. The parser owns the original
        mangled string, maintains the current offset, and keeps a recursion counter so we can
        mirror rustc's depth limits when following backrefs.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Printer(java.lang.Object):
        """
        Pretty printer that mirrors the upstream rustc-demangle formatter. It consumes parsed
        tokens by delegating back into :obj:`Parser` and emits either the normal or the
        alternate (hash-stripped) textual form depending on the ``alternate`` flag.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PrinterConsumer(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def accept(self, printer: RustDemanglerV0.Printer) -> None:
            ...


    @typing.type_check_only
    class Ident(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HexNibbles(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    RECURSION_LIMIT_MESSAGE: typing.Final = "{recursion limit reached}"
    MAX_DEPTH: typing.Final = 500

    @staticmethod
    def demangle(symbol: typing.Union[java.lang.String, str]) -> str:
        """
        Demangles a symbol according to the format
        
        :param java.lang.String or str symbol: the mangled symbol name
        :return: the demangled symbol name
        :rtype: str
        """

    @staticmethod
    def demangleAlternate(symbol: typing.Union[java.lang.String, str]) -> str:
        """
        Demangles a Rust V0 mangled symbol using an alternate format that omits
        hash/disambiguator suffixes.
        
        :param java.lang.String or str symbol: the mangled symbol
        :return: the demangled representation without hash suffixes, or ``null`` if the input is not
                a valid V0-mangled symbol
        :rtype: str
        """


class RustDemanglerOptions(ghidra.app.util.demangler.DemanglerOptions):
    """
    Rust demangler options
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        """
        Default constructor to use the modern demangler with auto-detect for the format.  This
        constructor will limit demangling to only known symbols.
        """

    @typing.overload
    def __init__(self, format: RustDemanglerFormat) -> None:
        """
        Constructor to specify a particular format
        
        :param RustDemanglerFormat format: signals to use the given format
        """

    @typing.overload
    def __init__(self, format: RustDemanglerFormat, isDeprecated: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Constructor to specify the format to use and whether to prefer the deprecated format when
        both deprecated and modern are available
        
        :param RustDemanglerFormat format: the format
        :param jpype.JBoolean or bool isDeprecated: true if the format is not available in the modern demangler
        :raises IllegalArgumentException: if the given format is not available in the deprecated
                demangler
        """

    @typing.overload
    def __init__(self, copy: ghidra.app.util.demangler.DemanglerOptions) -> None:
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



__all__ = ["RustDemanglerLegacy", "RustDemanglerFormat", "RustDemanglerParser", "RustDemangler", "RustDemanglerV0", "RustDemanglerOptions"]
