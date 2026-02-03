from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler
import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.assembler.sleigh.symbol
import ghidra.app.plugin.assembler.sleigh.tree
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.pattern
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


NT = typing.TypeVar("NT")
P = typing.TypeVar("P")


class AbstractAssemblyProduction(java.lang.Comparable[AbstractAssemblyProduction[NT]], typing.Generic[NT]):
    """
    Defines a production in a context-free grammar, usually for parsing mnemonic assembly
    
    
    .. seealso::
    
        | :obj:`AbstractAssemblyGrammar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lhs: NT, rhs: AssemblySentential[NT]):
        """
        Construct a production with the given LHS and RHS
        
        :param NT lhs: the left-hand side
        :param AssemblySentential[NT] rhs: the right-hand side
        """

    def getIndex(self) -> int:
        """
        Get the index of the production
         
         
        
        Instead of using deep comparison, the index is often used as the identity of the production
        within a grammar.
        
        :return: the index
        :rtype: int
        """

    def getLHS(self) -> NT:
        """
        Get the left-hand side
        
        :return: the LHS
        :rtype: NT
        """

    def getName(self) -> str:
        """
        Get the "name" of this production
         
         
        
        This is mostly just notional and for debugging. The name is taken as the name of the LHS.
        
        :return: the name of the LHS
        :rtype: str
        """

    def getRHS(self) -> AssemblySentential[NT]:
        """
        Get the right-hand side
        
        :return: the RHS
        :rtype: AssemblySentential[NT]
        """

    @property
    def lHS(self) -> NT:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def rHS(self) -> AssemblySentential[NT]:
        ...


class AssemblyExtendedGrammar(AbstractAssemblyGrammar[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal, AssemblyExtendedProduction]):
    """
    Defines an "extended" grammar
     
     
    
    "Extended grammar" as in a grammar extended with state numbers from an LR0 parser. See
    `LALR(1) Parsing <http://web.cs.dal.ca/~sjackson/lalr1.html>`_ from Stephen Jackson of
    Dalhousie University, Halifax, Nova Scotia, Canada.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractAssemblyGrammar(java.lang.Iterable[P], typing.Generic[NT, P]):
    """
    Defines a context-free grammar, usually for the purpose of parsing mnemonic assembly instructions
     
     
    
    As in classic computer science, a CFG consists of productions of non-terminals and terminals. The
    left-hand side of the a production must be a single non-terminal, but the right-hand side may be
    any string of symbols. To avoid overloading the term "String," here we call it a "Sentential."
     
     
    
    To define a grammar, simply construct an appropriate subclass (probably :obj:`AssemblyGrammar`)
    and call :meth:`addProduction(AbstractAssemblyProduction) <.addProduction>` or
    :meth:`addProduction(AssemblyNonTerminal, AssemblySentential) <.addProduction>`.
     
     
    
    By default, the start symbol is taken from the left-hand side of the first production added to
    the grammar.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def addProduction(self, lhs: NT, rhs: AssemblySentential[NT]):
        """
        Add a production to the grammar
        
        :param NT lhs: the left-hand side
        :param AssemblySentential[NT] rhs: the right-hand side
        """

    @typing.overload
    def addProduction(self, prod: P):
        """
        Add a production to the grammar
        
        :param P prod: the production
        """

    def combine(self, that: AbstractAssemblyGrammar[NT, P]):
        """
        Add all the productions of a given grammar to this one
        
        :param AbstractAssemblyGrammar[NT, P] that: the grammar whose productions to add
        """

    def contains(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if the grammar contains any symbol with the given name
        
        :param java.lang.String or str name: the name to find
        :return: true iff a terminal or non-terminal has the given name
        :rtype: bool
        """

    def getNonTerminal(self, name: typing.Union[java.lang.String, str]) -> NT:
        """
        Get the named non-terminal
        
        :param java.lang.String or str name: the name of the desired non-terminal
        :return: the non-terminal, or null if it is not in this grammar
        :rtype: NT
        """

    def getStart(self) -> NT:
        """
        Get the start symbol for the grammar
        
        :return: the start symbol
        :rtype: NT
        """

    def getStartName(self) -> str:
        """
        Get the name of the start symbol for the grammar
        
        :return: the name of the start symbol
        :rtype: str
        """

    def getTerminal(self, name: typing.Union[java.lang.String, str]) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal:
        """
        Get the named terminal
        
        :param java.lang.String or str name: the name of the desired terminal
        :return: the terminal, or null if it is not in this grammar
        :rtype: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal
        """

    def iterator(self) -> java.util.Iterator[P]:
        """
        Traverse the productions
        """

    def nonTerminals(self) -> java.util.Collection[NT]:
        """
        Get the non-terminals
        
        :return: 
        :rtype: java.util.Collection[NT]
        """

    def print(self, out: java.io.PrintStream):
        """
        Print the productions of this grammar to the given stream
        
        :param java.io.PrintStream out: the stream
        """

    @typing.overload
    def productionsOf(self, name: typing.Union[java.lang.String, str]) -> java.util.Collection[P]:
        """
        Get all productions where the left-hand side non-terminal has the given name
        
        :param java.lang.String or str name: the name of the non-terminal
        :return: all productions "defining" the named non-terminal
        :rtype: java.util.Collection[P]
        """

    @typing.overload
    def productionsOf(self, nt: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal) -> java.util.Collection[P]:
        """
        Get all productions where the left-hand side is the given non-terminal
        
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal nt: the non-terminal whose defining productions to find
        :return: all productions "defining" the given non-terminal
        :rtype: java.util.Collection[P]
        """

    def setStart(self, nt: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal):
        """
        Change the start symbol for the grammar
        
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal nt: the new start symbol
        """

    def setStartName(self, startName: typing.Union[java.lang.String, str]):
        """
        Change the start symbol for the grammar
        
        :param java.lang.String or str startName: the name of the new start symbol
        """

    def terminals(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]:
        """
        Get the terminals
        
        :return: 
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]
        """

    def verify(self):
        """
        Check that the grammar is consistent
         
         
        
        The grammar is consistent if every non-terminal appearing in the grammar also appears as the
        left-hand side of some production. If not, such non-terminals are said to be undefined.
        
        :raises AssemblyGrammarException: the grammar is inconsistent, i.e., contains undefined
                    non-terminals.
        """

    @property
    def start(self) -> NT:
        ...

    @property
    def terminal(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal:
        ...

    @property
    def startName(self) -> java.lang.String:
        ...

    @startName.setter
    def startName(self, value: java.lang.String):
        ...

    @property
    def nonTerminal(self) -> NT:
        ...


class AssemblyProduction(AbstractAssemblyProduction[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal]):
    """
    Defines a production for parsing mnemonic assembly
    
    
    .. seealso::
    
        | :obj:`AssemblyGrammar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lhs: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal, rhs: AssemblySentential[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal]):
        ...

    def isConstructor(self) -> bool:
        ...

    @property
    def constructor(self) -> jpype.JBoolean:
        ...


class AssemblyGrammar(AbstractAssemblyGrammar[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal, AssemblyProduction]):
    """
    Defines a context free grammar, used to parse mnemonic assembly instructions
     
     
    
    This stores the CFG and the associated semantics for each production. It also has mechanisms for
    tracking "purely recursive" productions. These are productions of the form I => I, and they
    necessarily create ambiguity. Thus, when constructing a parser, it is useful to identify them
    early.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory[typing.Any, typing.Any]):
        ...

    def addProduction(self, lhs: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal, rhs: AssemblySentential[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal], pattern: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern, cons: ghidra.app.plugin.processors.sleigh.Constructor, indices: java.util.List[java.lang.Integer]):
        """
        Add a production associated with a SLEIGH constructor semantic
        
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal lhs: the left-hand side
        :param AssemblySentential[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal] rhs: the right-hand side
        :param ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern pattern: the pattern associated with the constructor
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the SLEIGH constructor
        :param java.util.List[java.lang.Integer] indices: the indices of RHS non-terminals that represent an operand in the constructor
        """

    def getPureRecursion(self, lhs: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal) -> AssemblyProduction:
        """
        Obtain, if present, the purely recursive production having the given LHS
        
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal lhs: the left-hand side
        :return: the desired production, or null
        :rtype: AssemblyProduction
        """

    def getPureRecursive(self) -> java.util.Collection[AssemblyProduction]:
        """
        Get all productions in the grammar that are purely recursive
        
        :return: 
        :rtype: java.util.Collection[AssemblyProduction]
        """

    def getSemantic(self, cons: ghidra.app.plugin.processors.sleigh.Constructor) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic:
        ...

    def getSemantics(self, prod: AssemblyProduction) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic]:
        """
        Get the semantics associated with a given production
        
        :param AssemblyProduction prod: the production
        :return: all semantics associated with the given production
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic]
        """

    @property
    def semantic(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic:
        ...

    @property
    def pureRecursive(self) -> java.util.Collection[AssemblyProduction]:
        ...

    @property
    def pureRecursion(self) -> AssemblyProduction:
        ...

    @property
    def semantics(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic]:
        ...


class AssemblySentential(java.lang.Comparable[AssemblySentential[NT]], java.lang.Iterable[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol], typing.Generic[NT]):
    """
    A "string" of symbols
     
     
    
    To avoid overloading the word "string", we call this a "sentential". Technically, to be a
    "sentential" in the classic sense, it must be a possible element in the derivation of a sentence
    in the grammar starting with the start symbol. We ignore that if only for the sake of naming.
    """

    @typing.type_check_only
    class WhiteSpace(ghidra.app.plugin.assembler.sleigh.symbol.AssemblyStringTerminal):
        """
        A "whitespace" terminal
         
         
        
        This terminal represents "optional" whitespace. "Optional" because in certain circumstances,
        whitespace is not actually required, i.e., before or after a special character.
        """

        class_: typing.ClassVar[java.lang.Class]


    class WhiteSpaceParseToken(ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken):
        """
        The token consumed by a whitespace terminal
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, grammar: AssemblyGrammar, term: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal, str: typing.Union[java.lang.String, str]):
            ...


    class TruncatedWhiteSpaceParseToken(AssemblySentential.WhiteSpaceParseToken):
        """
        The token consumed by a whitespace terminal when it anticipates the end of input
         
         
        
        "Expected" tokens given by a parse machine when this is the last token it has consumed are
        not valid suggestions. The machine should instead suggest a whitespace character.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, grammar: AssemblyGrammar, term: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal):
            ...


    class_: typing.ClassVar[java.lang.Class]
    WHITE_SPACE: typing.Final[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyStringTerminal]

    @typing.overload
    def __init__(self, symbols: java.util.List[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol]):
        """
        Construct a string from the given list of symbols
        
        :param java.util.List[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol] symbols:
        """

    @typing.overload
    def __init__(self):
        """
        Construct a blank string
         
        This is suitable as a blank start, to add new symbols, or to use directly as the RHS,
        effectively creating an "epsilon" production.
        """

    @typing.overload
    def __init__(self, *syms: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol):
        """
        Construct a string from any number of symbols
        
        :param jpype.JArray[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol] syms:
        """

    def addCommaWS(self):
        """
        Add a comma followed by optional whitespace.
        """

    def addSeparatorPart(self, str: typing.Union[java.lang.String, str]):
        """
        Add a syntactic terminal element, but with consideration for optional whitespace surrounding
        special characters
        
        :param java.lang.String or str str: the expected terminal
        """

    def addSeparators(self, str: typing.Union[java.lang.String, str]):
        """
        Add a syntactic terminal element, but considering that commas contained within may be
        followed by optional whitespace
        
        :param java.lang.String or str str: the expected terminal
        """

    def addSymbol(self, symbol: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol) -> bool:
        """
        Add a symbol to the right of this sentential
        
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol symbol: the symbol to add
        :return: true
        :rtype: bool
        """

    def addWS(self) -> bool:
        """
        Add optional whitespace, if not already preceded by whitespace
        
        :return: true if whitespace was added
        :rtype: bool
        """

    def finish(self):
        """
        Trim leading and trailing whitespace, and make the sentential immutable
        """

    def getSymbol(self, pos: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol:
        ...

    def getSymbols(self) -> java.util.List[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol]:
        """
        Get the symbols in this sentential
        
        :return: the symbols;
        :rtype: java.util.List[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol]
        """

    def size(self) -> int:
        """
        Get the number of symbols, including whitespace, in this sentential
        
        :return: the number of symbols
        :rtype: int
        """

    def sub(self, fromIndex: typing.Union[jpype.JInt, int], toIndex: typing.Union[jpype.JInt, int]) -> AssemblySentential[NT]:
        ...

    @property
    def symbol(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol:
        ...

    @property
    def symbols(self) -> java.util.List[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol]:
        ...


class AssemblyGrammarException(ghidra.app.plugin.assembler.AssemblyException):
    """
    An exception to identify errors associated with grammar construction
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class AssemblyExtendedProduction(AbstractAssemblyProduction[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal]):
    """
    Defines a production of an "extended" grammar
    
    
    .. seealso::
    
        | :obj:`AssemblyExtendedGrammar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lhs: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal, rhs: AssemblySentential[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal], finalState: typing.Union[jpype.JInt, int], ancestor: AssemblyProduction):
        """
        Construct an extended production based on the given ancestor
        
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal lhs: the extended left-hand side
        :param AssemblySentential[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal] rhs: the extended right-hand side
        :param jpype.JInt or int finalState: the end state of the final symbol of the RHS
        :param AssemblyProduction ancestor: the original production from which this extended production is derived
        """

    def getAncestor(self) -> AssemblyProduction:
        """
        Get the original production from which this production was derived
        
        :return: the original production
        :rtype: AssemblyProduction
        """

    def getFinalState(self) -> int:
        """
        Get the final state of this production
        
        :return: the end state of the last symbol of the RHS
        :rtype: int
        """

    @property
    def ancestor(self) -> AssemblyProduction:
        ...

    @property
    def finalState(self) -> jpype.JInt:
        ...



__all__ = ["AbstractAssemblyProduction", "AssemblyExtendedGrammar", "AbstractAssemblyGrammar", "AssemblyProduction", "AssemblyGrammar", "AssemblySentential", "AssemblyGrammarException", "AssemblyExtendedProduction"]
