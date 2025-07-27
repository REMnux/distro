from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.grammars
import ghidra.app.plugin.assembler.sleigh.symbol
import ghidra.app.plugin.assembler.sleigh.tree
import ghidra.app.plugin.assembler.sleigh.util
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class AssemblyParseState(java.lang.Comparable[AssemblyParseState]):
    """
    A state in an LR(0) parsing machine
     
     
    
    Each item consists of a kernel and an implied closure. Only the kernel is necessary to define the
    item, but the whole closure must be considered when deriving new states. The kernel can be
    retrieved and mutated via :meth:`getKernel() <.getKernel>`, then the closure derived from it via
    :meth:`getClosure() <.getClosure>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar):
        """
        Construct a new state associated with the given grammar
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar
        """

    @typing.overload
    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar, item: AssemblyParseStateItem):
        """
        Construct a new state associated with the given grammar, seeded with the given item
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar
        :param AssemblyParseStateItem item: an item in the state
        """

    def getClosure(self) -> java.util.Set[AssemblyParseStateItem]:
        """
        Get the closure of this item, caching the result
        
        :return: the closure
        :rtype: java.util.Set[AssemblyParseStateItem]
        """

    def getKernel(self) -> java.util.Set[AssemblyParseStateItem]:
        """
        Get the (mutable) kernel for this state
        
        :return: the kernel
        :rtype: java.util.Set[AssemblyParseStateItem]
        """

    @property
    def kernel(self) -> java.util.Set[AssemblyParseStateItem]:
        ...

    @property
    def closure(self) -> java.util.Set[AssemblyParseStateItem]:
        ...


class AssemblyParseAcceptResult(AssemblyParseResult):
    """
    A successful result from parsing
    """

    class_: typing.ClassVar[java.lang.Class]

    def getTree(self) -> ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch:
        """
        Get the tree
        
        :return: the tree
        :rtype: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch
        """

    @property
    def tree(self) -> ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch:
        ...


class AssemblyParseStateItem(java.lang.Comparable[AssemblyParseStateItem]):
    """
    An item in the state of an LR(0) parser
     
     
    
    An item is a production with a dot indicating a position while parsing
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, prod: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction):
        """
        Construct a new item starting at the far left of the given production
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction prod: the production
        """

    @typing.overload
    def __init__(self, prod: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction, pos: typing.Union[jpype.JInt, int]):
        """
        Construct a new item starting immediately before the symbol at the given position in the
        given production
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction prod: the production
        :param jpype.JInt or int pos: the position of the dot
        """

    def completed(self) -> bool:
        """
        Check if this item is completed
         
         
        
        The item is completed if all symbols have been matched, i.e., the dot is at the far right of
        the production.
        
        :return: true iff the item is completed
        :rtype: bool
        """

    def getClosure(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar) -> java.util.Collection[AssemblyParseStateItem]:
        """
        "Fill" one step out to close a state containing this item
         
         
        
        To compute the full closure, you must continue stepping out until no new items are generated
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar containing the production
        :return: a subset of items in the closure of a state containing this item
        :rtype: java.util.Collection[AssemblyParseStateItem]
        """

    def getNext(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol:
        """
        Get the symbol immediately to the right of the dot
         
         
        
        This is the symbol which must be matched to advance the dot.
        
        :return: the symbol, or null if the item is completed, i.e., the dot is at the far right
        :rtype: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol
        """

    def getPos(self) -> int:
        """
        Get the position of the dot
         
         
        
        The position is the number of symbols to the left of the dot.
        
        :return: 
        :rtype: int
        """

    def getProduction(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction:
        """
        Get the production associated with this item
        
        :return: the production
        :rtype: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction
        """

    def read(self) -> AssemblyParseStateItem:
        """
        Advance the dot by one position, producing a new item
        
        :return: the new item
        :rtype: AssemblyParseStateItem
        """

    @property
    def next(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol:
        ...

    @property
    def production(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction:
        ...

    @property
    def pos(self) -> jpype.JInt:
        ...

    @property
    def closure(self) -> java.util.Collection[AssemblyParseStateItem]:
        ...


class AssemblyParseActionGotoTable(java.lang.Object):
    """
    The Action/Goto table for a LALR(1) parser
     
     
    
    This table is unconventional in that it permits a single cell to be populated by more than one
    action. Typically, such a situation would indicate ambiguity, or the need for a longer look-ahead
    value. Because we do not presume to control the grammar (which was automatically derived from
    another source), the parsing algorithm will simply branch, eventually trying both options.
    """

    class Action(java.lang.Comparable[AssemblyParseActionGotoTable.Action]):
        """
        An action in the Action/Goto table
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ShiftAction(AssemblyParseActionGotoTable.Action):
        """
        A SHIFT (S*n*) entry
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, newStateNum: typing.Union[jpype.JInt, int]):
            ...


    class ReduceAction(AssemblyParseActionGotoTable.Action):
        """
        A REDUCE (R*n*) entry
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, prod: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction):
            ...


    class GotoAction(AssemblyParseActionGotoTable.Action):
        """
        A GOTO (G*n*) entry
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, newStateNum: typing.Union[jpype.JInt, int]):
            ...


    class AcceptAction(AssemblyParseActionGotoTable.Action):
        """
        An ACCEPT (acc) entry
        """

        class_: typing.ClassVar[java.lang.Class]
        ACCEPT: typing.Final[AssemblyParseActionGotoTable.AcceptAction]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def get(self, fromState: typing.Union[jpype.JInt, int], next: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol) -> java.util.Collection[AssemblyParseActionGotoTable.Action]:
        """
        Get all entries in a given cell
        
        :param jpype.JInt or int fromState: the state (row) in the table
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol next: the symbol (column) in the table
        :return: all action entries in the given cell
        :rtype: java.util.Collection[AssemblyParseActionGotoTable.Action]
        """

    def getExpected(self, fromState: typing.Union[jpype.JInt, int]) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]:
        """
        Get the terminals that are expected, i.e., have entries for the given state
        
        :param jpype.JInt or int fromState: the state (row) in the table
        :return: the collection of populated columns (terminals) for the given state
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]
        """

    def put(self, fromState: typing.Union[jpype.JInt, int], next: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol, action: AssemblyParseActionGotoTable.Action) -> bool:
        """
        Add an action entry to the given cell
        
        :param jpype.JInt or int fromState: the state (row) in the table
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol next: the symbol (column) in the table
        :param AssemblyParseActionGotoTable.Action action: the entry to add to the cell
        :return: true, if the given entry was not already present
        :rtype: bool
        """

    def putAccept(self, fromState: typing.Union[jpype.JInt, int]) -> bool:
        """
        Add an ACCEPT entry for the given state at the end of input
        
        :param jpype.JInt or int fromState: the state (row) in the table
        :return: true, if the state does not already accept on end of input
        :rtype: bool
        """

    def putGoto(self, fromState: typing.Union[jpype.JInt, int], next: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal, newState: typing.Union[jpype.JInt, int]) -> bool:
        """
        Add a GOTO entry to the given cell
        
        :param jpype.JInt or int fromState: the state (row) in the table
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal next: the symbol (column) in the table
        :param jpype.JInt or int newState: the target state
        :return: true, if the given entry was not already present
        :rtype: bool
        """

    def putReduce(self, fromState: typing.Union[jpype.JInt, int], next: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal, prod: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction) -> bool:
        """
        Add a REDUCE (R*n*) entry to the given cell
        
        :param jpype.JInt or int fromState: the state (row) in the table
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal next: the symbol (column) in the table
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction prod: the production (having index *n*) associated with the reduction
        :return: true, if the given entry was not already present
        :rtype: bool
        """

    def putShift(self, fromState: typing.Union[jpype.JInt, int], next: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal, newState: typing.Union[jpype.JInt, int]) -> bool:
        """
        Add a SHIFT (S*n*) entry to the given cell
        
        :param jpype.JInt or int fromState: the state (row) in the table
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal next: the symbol (column) in the table
        :param jpype.JInt or int newState: the state (*n*) after the shift is applied
        :return: true, if the given entry was not already present
        :rtype: bool
        """

    @property
    def expected(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]:
        ...


class AssemblyParseErrorResult(AssemblyParseResult):
    """
    An unsuccessful result from parsing
    """

    class_: typing.ClassVar[java.lang.Class]

    def describeError(self) -> str:
        """
        Get a description of the error
        
        :return: a description
        :rtype: str
        """

    def getBuffer(self) -> str:
        """
        Get the leftover contents of the input buffer when the error occurred
        
        :return: the remaining buffer contents
        :rtype: str
        """

    def getSuggestions(self) -> java.util.Set[java.lang.String]:
        """
        Get a set of suggested tokens that would have allowed parsing to continue
        
        :return: the token set
        :rtype: java.util.Set[java.lang.String]
        """

    @property
    def suggestions(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def buffer(self) -> java.lang.String:
        ...


class AssemblyParser(java.lang.Object):
    """
    A class to encapsulate LALR(1) parsing for a given grammar
     
     
    
    This class constructs the Action/Goto table (and all the other trappings) of a LALR(1) parser and
    provides a :meth:`parse(String) <.parse>` method to parse actual sentences.
     
     
    
    This implementation is somewhat unconventional in that it permits ambiguous grammars. Instead of
    complaining, it produces the set of all possible parse trees. Of course, this comes at the cost
    of some efficiency.
     
     
    
    See Alfred V. Aho, Monica S. Lam, Ravi Sethi, Jeffrey D. Ullman, *Compilers: Principles,
    Techniques, & Tools*. Boston, MA: Pearson, 2007.
     
     
    
    See Jackson, Stephen. `LALR(1) Parsing <http://web.cs.dal.ca/~sjackson/lalr1.html>`_.
    Halifax, Nova Scotia, Canada: Dalhousie University.
    <http://web.cs.dal.ca/~sjackson/lalr1.html>
    """

    @typing.type_check_only
    class MergeKey(java.lang.Comparable[AssemblyParser.MergeKey]):
        """
        A map key used to identify merges for Step 4 in Stephen Jackson's rant
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MergeValue(java.lang.Object):
        """
        The map value keyed by :obj:`MergeKey`
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar):
        """
        Construct a LALR(1) parser from the given grammar
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar
        """

    def getGrammar(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar:
        """
        Get the grammar used to construct this parser
        
        :return: the grammar
        :rtype: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar
        """

    @typing.overload
    def parse(self, input: typing.Union[java.lang.String, str]) -> java.lang.Iterable[AssemblyParseResult]:
        """
        Parse the given sentence
        
        :param java.lang.String or str input: the sentence to parse
        :return: all possible parse trees (and possible errors)
        :rtype: java.lang.Iterable[AssemblyParseResult]
        """

    @typing.overload
    def parse(self, input: typing.Union[java.lang.String, str], symbols: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols) -> java.util.Collection[AssemblyParseResult]:
        """
        Parse the given sentence with the given defined symbols
         
         
        
        The tokenizer for numeric terminals also accepts any key in ``labels``. In such cases,
        the resulting token is assigned the value of the symbols.
        
        :param java.lang.String or str input: the sentence to parser
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols symbols: the symbols
        :return: all possible parse results (trees and errors)
        :rtype: java.util.Collection[AssemblyParseResult]
        """

    def printExtendedFF(self, out: java.io.PrintStream):
        """
        For debugging
        """

    def printExtendedGrammar(self, out: java.io.PrintStream):
        """
        For debugging
        """

    def printGeneralFF(self, out: java.io.PrintStream):
        """
        For debugging
        """

    def printGrammar(self, out: java.io.PrintStream):
        """
        For debugging
        """

    def printLR0States(self, out: java.io.PrintStream):
        """
        For debugging
        """

    def printLR0TransitionTable(self, out: java.io.PrintStream):
        """
        For debugging
        """

    def printMergers(self, out: java.io.PrintStream):
        """
        For debugging
        """

    def printParseTable(self, out: java.io.PrintStream):
        """
        For debugging
        """

    def printStuff(self, out: java.io.PrintStream):
        """
        For debugging
        """

    @property
    def grammar(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar:
        ...


class AssemblyParseResult(java.lang.Comparable[AssemblyParseResult]):
    """
    A result of parsing a sentence
     
     
    
    If the sentence was accepted, this yields a parse tree. If not, this describes the error and
    provides suggestions to correct the error.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def accept(tree: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch) -> AssemblyParseAcceptResult:
        """
        Construct a successful parse result
        
        :param ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch tree: the tree output by the parser
        """

    @staticmethod
    def error(got: typing.Union[java.lang.String, str], suggestions: java.util.Set[java.lang.String]) -> AssemblyParseErrorResult:
        """
        Construct an error parse result
        
        :param java.lang.String or str got: the input buffer when the error occurred
        :param java.util.Set[java.lang.String] suggestions: a subset of strings that would have allowed parsing to proceed
        """

    def isError(self) -> bool:
        """
        Check if the parse result is successful or an error
        
        :return: true if the result describes an error
        :rtype: bool
        """


class AssemblyFirstFollow(java.lang.Object):
    """
    A class to compute the first and follow of every non-terminal in a grammar
     
     
    
    See Alfred V. Aho, Monica S. Lam, Ravi Sethi, Jeffrey D. Ullman, *Compilers: Principles,
    Techniques, & Tools*. Bostom, MA: Pearson, 2007, pp. 220-2.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyGrammar[typing.Any, typing.Any]):
        """
        Compute the first and follow sets for every non-terminal in the given grammar
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyGrammar[typing.Any, typing.Any] grammar: the grammar
        """

    def getFirst(self, nt: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]:
        """
        Get the first set for a given non-terminal
         
         
        
        That is the set of all terminals, which through some derivation from the given non-terminal,
        can appear first in a sentential form.
        
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal nt: the non-terminal
        :return: the set
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]
        """

    def getFollow(self, nt: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]:
        """
        Get the follow set for a given non-terminal
         
         
        
        That is the set of all terminals, which through some derivation from the start symbol, can
        appear immediately after the given non-terminal in a sentential form.
        
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal nt: the non-terminal
        :return: the set
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]
        """

    def getNullable(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal]:
        """
        Get the nullable set
         
         
        
        That is the set of all non-terminals, which through some derivation, can produce epsilon.
        
        :return: the set
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal]
        """

    def print(self, out: java.io.PrintStream):
        """
        For debugging, print out the computed sets to the given stream
        
        :param java.io.PrintStream out: the stream
        """

    @property
    def nullable(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal]:
        ...

    @property
    def follow(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]:
        ...

    @property
    def first(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal]:
        ...


class AssemblyParseTransitionTable(java.lang.Object):
    """
    The transition table defining an LR(0) parsing machine
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def forEach(self, consumer: java.util.function.Consumer[ghidra.app.plugin.assembler.sleigh.util.TableEntry[java.lang.Integer]]):
        """
        Traverse every entry in the table, invoking :meth:`Consumer.accept(Object) <Consumer.accept>` on each
        
        :param java.util.function.Consumer[ghidra.app.plugin.assembler.sleigh.util.TableEntry[java.lang.Integer]] consumer: the callback
        """

    def get(self, fromState: typing.Union[jpype.JInt, int], next: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol) -> int:
        """
        Get an entry from the state machine
        
        :param jpype.JInt or int fromState: the source state
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol next: the symbol that has been matched
        :return: the destination state
        :rtype: int
        """

    def put(self, fromState: typing.Union[jpype.JInt, int], next: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol, newState: typing.Union[jpype.JInt, int]) -> int:
        """
        Put an entry into the state machine
         
         
        
        **NOTE:** Generally, if this returns non-null, something is probably wrong with your LR(0)
        machine generator
        
        :param jpype.JInt or int fromState: the source state
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol next: the symbol that is matched
        :param jpype.JInt or int newState: the destination state
        :return: the previous value for newState
        :rtype: int
        """


class AssemblyParseMachine(java.lang.Comparable[AssemblyParseMachine]):
    """
    A class that implements the LALR(1) parsing algorithm
     
     
    
    Instances of this class store a parse state. In order to work correctly, the class must be given
    a properly-constructed Action/Goto table.
     
     
    
    This implementation is somewhat unconventional. First, instead of strictly tokenizing and then
    parsing, each terminal is given the opportunity to match a token in the input. If none match, it
    results in a syntax error (equivalent to the token type having an empty cell in the classical
    algorithm). If more than one match, the parser branches. Also, because a single cell may also
    contain multiple actions, the parser could branch again. Thus, if a sentence is ambiguous, this
    algorithm will identify all possible parse trees, including ones where the input is tokenized
    differently than in other trees.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parser: AssemblyParser, input: typing.Union[java.lang.String, str], pos: typing.Union[jpype.JInt, int], lastTok: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken, symbols: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols):
        """
        Construct a new parse state
        
        :param AssemblyParser parser: the parser driving this machine
        :param java.lang.String or str input: the full input line
        :param jpype.JInt or int pos: the position in the line identifying the next characters to parse
        :param ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken lastTok: 
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols symbols:
        """

    def copy(self) -> AssemblyParseMachine:
        """
        Duplicate this machine state
         
         
        
        This is used extensively when branching
        
        :return: the duplicate
        :rtype: AssemblyParseMachine
        """

    def exhaust(self) -> java.util.Set[AssemblyParseMachine]:
        """
        Parse (or continue parsing) all possible trees from this machine state
        
        :return: the set of all possible trees and errors
        :rtype: java.util.Set[AssemblyParseMachine]
        """

    def getTree(self) -> ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch:
        """
        If in the accepted state, get the resulting parse tree for this machine
        
        :return: the parse tree
        :rtype: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch
        """

    @property
    def tree(self) -> ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch:
        ...



__all__ = ["AssemblyParseState", "AssemblyParseAcceptResult", "AssemblyParseStateItem", "AssemblyParseActionGotoTable", "AssemblyParseErrorResult", "AssemblyParser", "AssemblyParseResult", "AssemblyFirstFollow", "AssemblyParseTransitionTable", "AssemblyParseMachine"]
