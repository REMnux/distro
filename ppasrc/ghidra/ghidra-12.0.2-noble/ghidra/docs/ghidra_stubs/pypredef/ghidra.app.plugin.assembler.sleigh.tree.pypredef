from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.grammars
import ghidra.app.plugin.assembler.sleigh.symbol
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class AssemblyParseTreeNode(java.lang.Object):
    """
    A node in a parse tree
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar):
        """
        Construct a node for a tree parsed by the given grammar
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar
        """

    def generateString(self) -> str:
        """
        Generate the string that this node parsed
        
        :return: the string
        :rtype: str
        """

    def getGrammar(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar:
        """
        Get the grammar used to parse the tree
        
        :return: the grammar
        :rtype: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar
        """

    def getParent(self) -> AssemblyParseBranch:
        """
        Get the branch which contains this node
        
        :return: 
        :rtype: AssemblyParseBranch
        """

    def getSym(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol:
        """
        Get the symbol for which this node is substituted
         
         
        
        For a branch, this is the LHS of the corresponding production. For a token, this is the
        terminal whose tokenizer matched it.
        
        :return: the symbol
        :rtype: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol
        """

    def print(self, out: java.io.PrintStream):
        """
        For debugging: Display this parse tree via the given stream
        
        :param java.io.PrintStream out: the stream
        """

    @property
    def parent(self) -> AssemblyParseBranch:
        ...

    @property
    def grammar(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar:
        ...

    @property
    def sym(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol:
        ...


class AssemblyParseNumericToken(AssemblyParseToken):
    """
    A token having a numeric value
    
    
    .. seealso::
    
        | :obj:`AssemblyFixedNumericTerminal`
    
        | :obj:`AssemblyNumericMapTerminal`
    
        | :obj:`AssemblyNumericTerminal`
    
        | :obj:`AssemblyStringMapTerminal`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar, term: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal, str: typing.Union[java.lang.String, str], val: typing.Union[jpype.JLong, int]):
        """
        Construct a numeric terminal having the given string and numeric values
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar containing the terminal
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal term: the terminal that matched this token
        :param java.lang.String or str str: the portion of the input comprising this token
        :param jpype.JLong or int val: the numeric value represented by this token
        """

    def getNumericValue(self) -> int:
        """
        Get the numeric value of the token
        
        :return: the value
        :rtype: int
        """

    @property
    def numericValue(self) -> jpype.JLong:
        ...


class AssemblyParseHiddenNode(AssemblyParseTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar):
        ...


class AssemblyParseToken(AssemblyParseTreeNode):
    """
    A string token
    
    
    .. seealso::
    
        | :obj:`AssemblyStringTerminal`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar, term: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal, str: typing.Union[java.lang.String, str]):
        """
        Construct a new token having the given string value
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar containing the terminal
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal term: the terminal that matched this token
        :param java.lang.String or str str: the portion of the input comprising this token
        """

    def getString(self) -> str:
        """
        Get the portion of the input comprising the token
        
        :return: the string value
        :rtype: str
        """

    @property
    def string(self) -> java.lang.String:
        ...


class AssemblyParseBranch(AssemblyParseTreeNode, java.lang.Iterable[AssemblyParseTreeNode]):
    """
    A branch in a parse tree, corresponding to the application of a production
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar, prod: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction):
        """
        Construct a branch from the given grammar and production
        
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar containing the production
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction prod: the production applied to create this branch
        """

    def addChild(self, child: AssemblyParseTreeNode):
        """
        Prepend a child to this branch
         
         
        
        Because LR parsers produce rightmost derivations, they necessarily populate the branches
        right to left. During reduction, each child is popped from the stack, traversing them in
        reverse order. This method prepends children so that when reduction is complete, the children
        are aligned to the corresponding symbols from the RHS of the production.
        
        :param AssemblyParseTreeNode child: the child
        """

    def getProduction(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction:
        """
        Get the production applied to create this branch
        
        :return: 
        :rtype: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction
        """

    def getSubstitution(self, i: typing.Union[jpype.JInt, int]) -> AssemblyParseTreeNode:
        """
        Get the *i*th child, corresponding to the *i*th symbol from the RHS
        
        :param jpype.JInt or int i: the position
        :return: the child
        :rtype: AssemblyParseTreeNode
        """

    def getSubstitutions(self) -> java.util.List[AssemblyParseTreeNode]:
        """
        Get the list of children, indexed by corresponding symbol from the RHS
        
        :return: 
        :rtype: java.util.List[AssemblyParseTreeNode]
        """

    def isConstructor(self) -> bool:
        ...

    @property
    def substitution(self) -> AssemblyParseTreeNode:
        ...

    @property
    def substitutions(self) -> java.util.List[AssemblyParseTreeNode]:
        ...

    @property
    def production(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction:
        ...

    @property
    def constructor(self) -> jpype.JBoolean:
        ...



__all__ = ["AssemblyParseTreeNode", "AssemblyParseNumericToken", "AssemblyParseHiddenNode", "AssemblyParseToken", "AssemblyParseBranch"]
