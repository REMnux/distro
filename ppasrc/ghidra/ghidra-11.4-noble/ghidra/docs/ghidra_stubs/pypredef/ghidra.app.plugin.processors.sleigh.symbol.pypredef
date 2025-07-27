from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.expression
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.util # type: ignore


class TripleSymbol(Symbol):
    """
    Abstract class for the primary sleigh variable. An object that
    has a printing, pattern, and semantic interpretation
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getFixedHandle(self, hand: ghidra.app.plugin.processors.sleigh.FixedHandle, walker: ghidra.app.plugin.processors.sleigh.ParserWalker):
        ...

    def getPatternExpression(self) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression:
        ...

    def print(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker) -> str:
        ...

    def printList(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker, list: java.util.ArrayList[java.lang.Object]):
        ...

    def resolve(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker, debug: ghidra.app.plugin.processors.sleigh.SleighDebugLogger) -> ghidra.app.plugin.processors.sleigh.Constructor:
        ...

    @property
    def patternExpression(self) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression:
        ...


class UseropSymbol(Symbol):
    """
    A user-defined pcode operation (PcodeOp)
    This is implemented as a name and a unique id which is passed
    as the first parameter to a PcodeOp with the opcode = "CALLOTHER".
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getIndex(self) -> int:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class OperandSymbol(SpecificSymbol):
    """
    Variable representing an operand to a specific Constructor
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getDefiningExpression(self) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression:
        ...

    def getDefiningSymbol(self) -> TripleSymbol:
        ...

    def getIndex(self) -> int:
        ...

    def getMinimumLength(self) -> int:
        ...

    def getOffsetBase(self) -> int:
        ...

    def getRelativeOffset(self) -> int:
        ...

    def isCodeAddress(self) -> bool:
        ...

    @property
    def minimumLength(self) -> jpype.JInt:
        ...

    @property
    def offsetBase(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def relativeOffset(self) -> jpype.JInt:
        ...

    @property
    def definingSymbol(self) -> TripleSymbol:
        ...

    @property
    def codeAddress(self) -> jpype.JBoolean:
        ...

    @property
    def definingExpression(self) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression:
        ...


class Next2Symbol(SpecificSymbol):
    """
    Symbol with semantic value equal to offset of address immediately
    after the next instruction (inst_next2)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ValueSymbol(FamilySymbol):
    """
    A variable with its semantic (and printing) value equal to a fixed
    mapping of its pattern
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SpecificSymbol(TripleSymbol):
    """
    This is a TripleSymbol whose semantic value can be determined
    at compile time (i.e. without an InstructionContext)
    The functionality is not needed for the disassembler interface
    but we keep the structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VarnodeListSymbol(ValueSymbol):
    """
    A ValueSymbol where the semantic context is obtained by looking
    up the value in a table of VarnodeSymbols
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getVarnodeTable(self) -> java.util.Collection[VarnodeSymbol]:
        ...

    @property
    def varnodeTable(self) -> java.util.Collection[VarnodeSymbol]:
        ...


class FamilySymbol(TripleSymbol):
    """
    TripleSymbols whose semantic value and printing changes depending
    on the pattern that they match
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getPatternValue(self) -> ghidra.app.plugin.processors.sleigh.expression.PatternValue:
        ...

    @property
    def patternValue(self) -> ghidra.app.plugin.processors.sleigh.expression.PatternValue:
        ...


class StartSymbol(SpecificSymbol):
    """
    TripleSymbol with semantic value equal to offset of instruction's
    current address
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EndSymbol(SpecificSymbol):
    """
    Symbol with semantic value equal to offset of address immediately
    after current instruction
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NameSymbol(ValueSymbol):
    """
    A ValueSymbol whose printing aspect is determined by looking
    up the context value of the symbol in a table of strings
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getNameTable(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def nameTable(self) -> java.util.List[java.lang.String]:
        ...


class ValueMapSymbol(ValueSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMap(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def map(self) -> java.util.List[java.lang.Long]:
        ...


class VarnodeSymbol(PatternlessSymbol):
    """
    A symbol representing a global varnode, i.e. a named memory location
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getFixedVarnode(self) -> ghidra.app.plugin.processors.sleigh.VarnodeData:
        ...

    @property
    def fixedVarnode(self) -> ghidra.app.plugin.processors.sleigh.VarnodeData:
        ...


class SymbolTable(java.lang.Object):
    """
    Full symbol table for sleigh
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, sleigh: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        ...

    def decodeSymbolHeader(self, decoder: ghidra.program.model.pcode.Decoder):
        ...

    def findGlobalSymbol(self, nm: typing.Union[java.lang.String, str]) -> Symbol:
        ...

    @typing.overload
    def findSymbol(self, nm: typing.Union[java.lang.String, str]) -> Symbol:
        ...

    @typing.overload
    def findSymbol(self, nm: typing.Union[java.lang.String, str], skip: typing.Union[jpype.JInt, int]) -> Symbol:
        ...

    @typing.overload
    def findSymbol(self, id: typing.Union[jpype.JInt, int]) -> Symbol:
        ...

    def getCurrentScope(self) -> SymbolScope:
        ...

    def getGlobalScope(self) -> SymbolScope:
        ...

    def getNumberOfUserDefinedOpNames(self) -> int:
        ...

    def getSymbolList(self) -> jpype.JArray[Symbol]:
        ...

    def getUserDefinedOpName(self, index: typing.Union[jpype.JInt, int]) -> str:
        ...

    def setCurrentScope(self, scope: SymbolScope):
        ...

    @property
    def numberOfUserDefinedOpNames(self) -> jpype.JInt:
        ...

    @property
    def userDefinedOpName(self) -> java.lang.String:
        ...

    @property
    def globalScope(self) -> SymbolScope:
        ...

    @property
    def currentScope(self) -> SymbolScope:
        ...

    @currentScope.setter
    def currentScope(self, value: SymbolScope):
        ...

    @property
    def symbolList(self) -> jpype.JArray[Symbol]:
        ...


class ContextSymbol(ValueSymbol):
    """
    A ValueSymbol that gets its semantic value from contiguous bits
    in a VarnodeSymbol. This serves as an embedding of a ContextOp
    into an actual Varnode and is probably only relevant at compile time
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def followsFlow(self) -> bool:
        ...

    def getHigh(self) -> int:
        """
        Get ending bit of context value within its context register.
        
        :return: the ending bit
        :rtype: int
        """

    def getInternalHigh(self) -> int:
        """
        Get the ending bit of the context value within the "global" buffer, after
        the values have been packed.
        
        :return: the ending bit
        :rtype: int
        """

    def getInternalLow(self) -> int:
        """
        Get the starting bit of the context value within the "global" buffer, after
        the values have been packed.
        
        :return: the starting bit
        :rtype: int
        """

    def getLow(self) -> int:
        """
        Get starting bit of context value within its context register.
        
        :return: the starting bit
        :rtype: int
        """

    def getVarnode(self) -> VarnodeSymbol:
        ...

    @property
    def high(self) -> jpype.JInt:
        ...

    @property
    def low(self) -> jpype.JInt:
        ...

    @property
    def varnode(self) -> VarnodeSymbol:
        ...

    @property
    def internalHigh(self) -> jpype.JInt:
        ...

    @property
    def internalLow(self) -> jpype.JInt:
        ...


class SubtableSymbol(TripleSymbol):
    """
    A collection of Constructors or a Symbol representing
    one out of a family of Constructors, chosen based on InstructionContext
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getConstructor(self, i: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.processors.sleigh.Constructor:
        ...

    def getDecisionNode(self) -> ghidra.app.plugin.processors.sleigh.DecisionNode:
        ...

    def getNumConstructors(self) -> int:
        ...

    @property
    def decisionNode(self) -> ghidra.app.plugin.processors.sleigh.DecisionNode:
        ...

    @property
    def constructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor:
        ...

    @property
    def numConstructors(self) -> jpype.JInt:
        ...


class EpsilonSymbol(PatternlessSymbol):
    """
    A pattern with no semantic or printing content, that will match
    any pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SymbolScope(java.lang.Object):
    """
    A single scope of symbol names for sleigh
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, p: SymbolScope, i: typing.Union[jpype.JInt, int]):
        ...

    def addSymbol(self, a: Symbol):
        ...

    def findSymbol(self, nm: typing.Union[java.lang.String, str]) -> Symbol:
        ...

    def getId(self) -> int:
        ...

    def getParent(self) -> SymbolScope:
        ...

    @property
    def parent(self) -> SymbolScope:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...


class PatternlessSymbol(SpecificSymbol):
    """
    Symbols with semantic value, but with no pattern aspect,
    i.e. they match all patterns
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Symbol(java.lang.Object):
    """
    Base class for symbols in sleigh
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, sleigh: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        ...

    def decodeHeader(self, decoder: ghidra.program.model.pcode.Decoder):
        ...

    def getId(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getScopeId(self) -> int:
        ...

    @property
    def scopeId(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...



__all__ = ["TripleSymbol", "UseropSymbol", "OperandSymbol", "Next2Symbol", "ValueSymbol", "SpecificSymbol", "VarnodeListSymbol", "FamilySymbol", "StartSymbol", "EndSymbol", "NameSymbol", "ValueMapSymbol", "VarnodeSymbol", "SymbolTable", "ContextSymbol", "SubtableSymbol", "EpsilonSymbol", "SymbolScope", "PatternlessSymbol", "Symbol"]
