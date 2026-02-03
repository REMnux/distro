from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.grammars
import ghidra.app.plugin.assembler.sleigh.tree
import ghidra.app.plugin.processors.sleigh.symbol
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang # type: ignore
import java.util # type: ignore
import org.apache.commons.collections4 # type: ignore


class AssemblyNumericMapTerminal(AssemblyNumericTerminal):
    """
    A terminal that accepts only a particular set of numeric values, mapping each to another value
     
     
    
    This often used for non-conventional numeric encodings.
    
    
    .. seealso::
    
        | :obj:`ValueMapSymbol`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], map: collections.abc.Mapping):
        """
        Construct a terminal with the given name, accepting only the keys of a given map
        
        :param java.lang.String or str name: the name
        :param collections.abc.Mapping map: the map from display value to token value
        """

    def getMap(self) -> java.util.Map[java.lang.Long, java.lang.Integer]:
        ...

    @property
    def map(self) -> java.util.Map[java.lang.Long, java.lang.Integer]:
        ...


class AssemblyNonTerminal(AssemblySymbol):
    """
    The type of non-terminal for an assembly grammar
    
    
    .. seealso::
    
        | :obj:`AssemblyGrammar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Construct a non-terminal having the given name
        
        :param java.lang.String or str name: the name
        """


class AssemblyStringTerminal(AssemblyTerminal):
    """
    A terminal that accepts only a particular string
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, str: typing.Union[java.lang.String, str], defsym: ghidra.app.plugin.processors.sleigh.symbol.VarnodeSymbol):
        """
        Construct a terminal that accepts only the given string
        
        :param java.lang.String or str str: the string to accept
        """

    def getDefiningSymbol(self) -> ghidra.app.plugin.processors.sleigh.symbol.VarnodeSymbol:
        ...

    def getString(self) -> str:
        ...

    def isWhiteSpace(self) -> bool:
        ...

    @property
    def whiteSpace(self) -> jpype.JBoolean:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def definingSymbol(self) -> ghidra.app.plugin.processors.sleigh.symbol.VarnodeSymbol:
        ...


class AssemblySymbol(java.lang.Comparable[AssemblySymbol]):
    """
    A symbol in a context-free grammar
     
     
    
    Symbols can be either terminals or non-terminals. Non-terminals must have a defining production,
    i.e., it must appear as the left-hand side of some production in the grammar.
     
     
    
    Traditionally, when displayed, non-terminals should be immediately distinguishable from
    terminals. In classic CS literature, this usually means non-terminals are in CAPS, and terminals
    are in lower-case. Because the assembler doesn't control the names provided by SLEIGH, we
    surround non-terminals in [brackets].
    
    
    .. seealso::
    
        | :obj:`AbstractAssemblyGrammar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Construct a new symbol with the given name
        
        :param java.lang.String or str name: the name
        """

    def getName(self) -> str:
        """
        Get the name of this symbol
        
        :return: the name
        :rtype: str
        """

    def takesOperandIndex(self) -> bool:
        """
        Check if this symbol consumes an operand index of its constructor
        
        :return: true if the symbol represents an operand
        :rtype: bool
        """

    @property
    def name(self) -> java.lang.String:
        ...


class AssemblyNumericTerminal(AssemblyTerminal):
    """
    A terminal that accepts any numeric value or program symbol (label, equate)
     
     
    
    The literal may take any form accepted by UNIX strtol() with base=0. By default, the literal is
    interpreted in base 10, but it may be prefixed such that it's interpreted in an alternative base.
    With the prefix '0x', it is interpreted in hexadecimal. With the prefix '0', it is interpreted in
    octal.
     
     
    
    It may also take the value of a label. If this operand is an address operand, the acceptable
    labels are restricted to those in the expected address space.
    """

    class_: typing.ClassVar[java.lang.Class]
    PREFIX_HEX: typing.Final = "0x"
    PREFIX_OCT: typing.Final = "0"

    def __init__(self, name: typing.Union[java.lang.String, str], bitsize: typing.Union[jpype.JInt, int], space: ghidra.program.model.address.AddressSpace):
        """
        Construct a terminal with the given name, accepting any numeric value or program label
        
        :param java.lang.String or str name: the name
        :param jpype.JInt or int bitsize: the maximum size of the value in bits
        :param ghidra.program.model.address.AddressSpace space: the address space if this terminal represents an address operand
        """

    def getBitSize(self) -> int:
        ...

    def getSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def match(self, buffer: typing.Union[java.lang.String, str]) -> ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken:
        """
        This is only a convenience for testing
         
         
        
        Please use :meth:`match(String, int, AssemblyGrammar, AssemblyNumericSymbols) <.match>`
        
        :param java.lang.String or str buffer: the input buffer
        :return: the parsed token
        :rtype: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken
        """

    @property
    def bitSize(self) -> jpype.JInt:
        ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...


class AssemblyNumericSymbols(java.lang.Object):
    """
    A context to hold various symbols offered to the assembler, usable where numbers are expected.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[AssemblyNumericSymbols]
    programEquates: typing.Final[java.util.NavigableMap[java.lang.String, java.util.Set[java.lang.Long]]]
    languageLabels: typing.Final[java.util.NavigableMap[java.lang.String, java.util.Set[ghidra.program.model.address.Address]]]

    def choose(self, name: typing.Union[java.lang.String, str], space: ghidra.program.model.address.AddressSpace) -> java.util.Set[java.lang.Long]:
        """
        Choose a symbol with the given name, using the space as a hint
         
         
        
        If a space is not given, or if that space is the constant space, then this will choose from
        all symbols, via :meth:`chooseAll(String) <.chooseAll>`. If a space is given, and it is not the constant
        space, then this will choose from symbols in the given space, via
        :meth:`chooseBySpace(String, AddressSpace) <.chooseBySpace>`.
        
        :param java.lang.String or str name: the name
        :param ghidra.program.model.address.AddressSpace space: the address space, or null
        :return: the equate value, or label addressable word offset, or null
        :rtype: java.util.Set[java.lang.Long]
        """

    def chooseAll(self, name: typing.Union[java.lang.String, str]) -> java.util.Set[java.lang.Long]:
        """
        Choose any symbol with the given name
         
         
        
        This will order equates first, then program labels, then language labels. For addresses, the
        value is its addressable word offset.
        
        :param java.lang.String or str name: the name
        :return: the value, or null
        :rtype: java.util.Set[java.lang.Long]
        """

    def chooseBySpace(self, name: typing.Union[java.lang.String, str], space: ghidra.program.model.address.AddressSpace) -> java.util.Set[java.lang.Long]:
        """
        Choose a label with the given name in the given space
        
        :param java.lang.String or str name: the name
        :param ghidra.program.model.address.AddressSpace space: the address space
        :return: the addressable word offset of the found label, or null
        :rtype: java.util.Set[java.lang.Long]
        """

    @staticmethod
    def fromLanguage(language: ghidra.program.model.lang.Language) -> AssemblyNumericSymbols:
        """
        Get symbols from a language, when no program is available
        
        :param ghidra.program.model.lang.Language language: the language
        :return: the symbols
        :rtype: AssemblyNumericSymbols
        """

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> AssemblyNumericSymbols:
        """
        Get symbols from a program (and its language)
        
        :param ghidra.program.model.listing.Program program: the program
        :return: the symbols
        :rtype: AssemblyNumericSymbols
        """

    def getSuggestions(self, got: typing.Union[java.lang.String, str], space: ghidra.program.model.address.AddressSpace, max: typing.Union[jpype.JInt, int]) -> java.util.Collection[java.lang.String]:
        """
        Suggest up to max symbols having the given prefix, using space as a hint
         
         
        
        As in :meth:`chooseAll(String) <.chooseAll>`, if space is null or the constant space, then this will
        suggest from all symbols, via :meth:`suggestAny(String, int) <.suggestAny>`. If space is given, and it is
        not the constant space, then this will suggest from symbols in the given space, via
        :meth:`suggestBySpace(String, AddressSpace, int) <.suggestBySpace>`.
        
        :param java.lang.String or str got: the prefix
        :param ghidra.program.model.address.AddressSpace space: the space, or null
        :param jpype.JInt or int max: the maximum number of symbols to suggest
        :return: the collection of symbol names
        :rtype: java.util.Collection[java.lang.String]
        """

    def suggestAny(self, got: typing.Union[java.lang.String, str], max: typing.Union[jpype.JInt, int]) -> java.util.Collection[java.lang.String]:
        """
        Suggest up to max symbols having the given prefix
        
        :param java.lang.String or str got: the prefix
        :param jpype.JInt or int max: the maximum number of symbols to suggest
        :return: the collection of symbol names
        :rtype: java.util.Collection[java.lang.String]
        """

    def suggestBySpace(self, got: typing.Union[java.lang.String, str], space: ghidra.program.model.address.AddressSpace, max: typing.Union[jpype.JInt, int]) -> java.util.Collection[java.lang.String]:
        """
        Suggest up to max symbols from the given space having the given prefix
        
        :param java.lang.String or str got: the prefix
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param jpype.JInt or int max: the maximum number of symbols to suggest
        :return: the collection of symbol names
        :rtype: java.util.Collection[java.lang.String]
        """


class AssemblyFixedNumericTerminal(AssemblyNumericTerminal):
    """
    A terminal that accepts only a particular numeric value
     
     
    
    This is different from a fixed string, because it will accept any encoding of the given numeric
    value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, val: typing.Union[jpype.JLong, int]):
        """
        Construct a terminal that accepts only the given numeric value
        
        :param jpype.JLong or int val: the value to accept
        """

    def getVal(self) -> int:
        ...

    @property
    def val(self) -> jpype.JLong:
        ...


class AssemblyStringMapTerminal(AssemblyTerminal):
    """
    A terminal that accepts only a particular set of strings, mapping each to a numeric value
    
    
    .. seealso::
    
        | :obj:`ghidra.app.plugin.processors.sleigh.symbol.NameSymbol`NameSymbol
    
        | :obj:`VarnodeListSymbol`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], map: org.apache.commons.collections4.MultiValuedMap[java.lang.String, java.lang.Integer]):
        """
        Construct a terminal with the given name, accepting only the keys of a given map
        
        :param java.lang.String or str name: the name
        :param org.apache.commons.collections4.MultiValuedMap[java.lang.String, java.lang.Integer] map: the map from display text to token value
        """

    def getMap(self) -> org.apache.commons.collections4.MultiValuedMap[java.lang.String, java.lang.Integer]:
        ...

    @property
    def map(self) -> org.apache.commons.collections4.MultiValuedMap[java.lang.String, java.lang.Integer]:
        ...


class AssemblyTerminal(AssemblySymbol):
    """
    The type of terminal for an assembly grammar
     
     
    
    Unlike classical parsing, each terminal provides its own tokenizer. If multiple tokenizers yield
    a token, the parser branches, possibly creating multiple, ambiguous trees.
    
    
    .. seealso::
    
        | :obj:`AssemblyGrammar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Construct a terminal having the give name
        
        :param java.lang.String or str name:
        """

    def getSuggestions(self, got: typing.Union[java.lang.String, str], symbols: AssemblyNumericSymbols) -> java.util.Collection[java.lang.String]:
        """
        Provide a collection of strings that this terminal would have accepted
        
        :param java.lang.String or str got: the remaining contents of the input buffer
        :param AssemblyNumericSymbols symbols: the program symbols, if applicable
        :return: a, possibly empty, collection of suggestions
        :rtype: java.util.Collection[java.lang.String]
        """

    def match(self, buffer: typing.Union[java.lang.String, str], pos: typing.Union[jpype.JInt, int], grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar, symbols: AssemblyNumericSymbols) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken]:
        """
        Attempt to match a token from the input buffer starting at a given position
        
        :param java.lang.String or str buffer: the input buffer
        :param jpype.JInt or int pos: the cursor position in the buffer
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar containing this terminal
        :param AssemblyNumericSymbols symbols: symbols from the program, suitable for use as numeric terminals
        :return: the matched token, or null
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken]
        """


class AssemblyEOI(AssemblyTerminal):
    """
    A terminal that accepts the end of input
    """

    class_: typing.ClassVar[java.lang.Class]
    EOI: typing.Final[AssemblyEOI]
    """
    The end-of-input terminal
    """



class AssemblyExtendedNonTerminal(AssemblyNonTerminal):
    """
    The type of non-terminal for an "extended grammar"
    
    
    .. seealso::
    
        | :obj:`AssemblyExtendedGrammar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: typing.Union[jpype.JInt, int], nt: AssemblyNonTerminal, end: typing.Union[jpype.JInt, int]):
        """
        Construct a new extended non terminal, derived from the given non-terminal
        
        :param jpype.JInt or int start: the start state for the extended non-terminal
        :param AssemblyNonTerminal nt: the non-terminal from which the extended non-terminal is derived
        :param jpype.JInt or int end: the end state for the extended non-terminal
        """



__all__ = ["AssemblyNumericMapTerminal", "AssemblyNonTerminal", "AssemblyStringTerminal", "AssemblySymbol", "AssemblyNumericTerminal", "AssemblyNumericSymbols", "AssemblyFixedNumericTerminal", "AssemblyStringMapTerminal", "AssemblyTerminal", "AssemblyEOI", "AssemblyExtendedNonTerminal"]
