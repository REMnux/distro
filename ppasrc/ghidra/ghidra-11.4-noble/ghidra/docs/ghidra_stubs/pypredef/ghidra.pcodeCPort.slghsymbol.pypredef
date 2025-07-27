from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.pcodeCPort.context
import ghidra.pcodeCPort.pcoderaw
import ghidra.pcodeCPort.semantics
import ghidra.pcodeCPort.slghpatexpress
import ghidra.pcodeCPort.slghpattern
import ghidra.pcodeCPort.space
import ghidra.program.model.pcode
import ghidra.sleigh.grammar
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class TripleSymbol(SleighSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str]):
        ...

    def collectLocalValues(self, results: java.util.ArrayList[java.lang.Long]):
        ...

    def getPatternExpression(self) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression:
        ...

    def getSize(self) -> int:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def patternExpression(self) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression:
        ...


class UserOpSymbol(SleighSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str]):
        ...

    def getIndex(self) -> int:
        ...

    def setIndex(self, ind: typing.Union[jpype.JInt, int]):
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @index.setter
    def index(self, value: jpype.JInt):
        ...


class OperandSymbol(SpecificSymbol):

    class_: typing.ClassVar[java.lang.Class]
    code_address: typing.Final = 1
    offset_irrel: typing.Final = 2
    variable_len: typing.Final = 4
    marked: typing.Final = 8
    reloffset: jpype.JInt
    offsetbase: jpype.JInt

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int], ct: Constructor):
        ...

    def clearMark(self):
        ...

    @typing.overload
    def defineOperand(self, pe: ghidra.pcodeCPort.slghpatexpress.PatternExpression):
        ...

    @typing.overload
    def defineOperand(self, tri: TripleSymbol):
        ...

    def getDefiningExpression(self) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression:
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

    def isMarked(self) -> bool:
        ...

    def isOffsetIrrelevant(self) -> bool:
        ...

    def isVariableLength(self) -> bool:
        ...

    def setCodeAddress(self):
        ...

    def setMark(self):
        ...

    def setOffsetIrrelevant(self):
        ...

    def setVariableLength(self):
        ...

    @property
    def variableLength(self) -> jpype.JBoolean:
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
    def offsetIrrelevant(self) -> jpype.JBoolean:
        ...

    @property
    def definingExpression(self) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression:
        ...


class Next2Symbol(SpecificSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], cspc: ghidra.pcodeCPort.space.AddrSpace):
        ...


class ValueSymbol(FamilySymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], pv: ghidra.pcodeCPort.slghpatexpress.PatternValue):
        ...


class ContextCommit(ContextChange):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, s: TripleSymbol, sbit: typing.Union[jpype.JInt, int], ebit: typing.Union[jpype.JInt, int], fl: typing.Union[jpype.JBoolean, bool]):
        ...


class Constructor(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, p: SubtableSymbol):
        ...

    def addContext(self, vec: generic.stl.VectorSTL[ContextChange]):
        ...

    def addEquation(self, pe: ghidra.pcodeCPort.slghpatexpress.PatternEquation):
        ...

    def addInvisibleOperand(self, sym: OperandSymbol):
        ...

    def addOperand(self, sym: OperandSymbol):
        ...

    def addSyntax(self, syn: typing.Union[java.lang.String, str]):
        ...

    def collectLocalExports(self, results: java.util.ArrayList[java.lang.Long]):
        ...

    def dispose(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def getFilename(self) -> str:
        ...

    def getId(self) -> int:
        ...

    def getIndex(self) -> int:
        """
        Return the source file index
        
        :return: index
        :rtype: int
        """

    def getLineno(self) -> int:
        ...

    def getMinimumLength(self) -> int:
        ...

    def getNamedTempl(self, secnum: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def getNumOperands(self) -> int:
        ...

    def getNumSections(self) -> int:
        ...

    def getOperand(self, i: typing.Union[jpype.JInt, int]) -> OperandSymbol:
        ...

    def getParent(self) -> SubtableSymbol:
        ...

    def getPattern(self) -> ghidra.pcodeCPort.slghpatexpress.TokenPattern:
        ...

    def getPatternEquation(self) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation:
        ...

    def getTempl(self) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def isError(self) -> bool:
        ...

    def isRecursive(self) -> bool:
        ...

    def markSubtableOperands(self, check: generic.stl.VectorSTL[java.lang.Integer]):
        ...

    def printInfo(self, s: java.io.PrintStream):
        ...

    def removeTrailingSpace(self):
        ...

    def setError(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setId(self, i: typing.Union[jpype.JLong, int]):
        ...

    def setMainSection(self, tpl: ghidra.pcodeCPort.semantics.ConstructTpl):
        ...

    def setMinimumLength(self, l: typing.Union[jpype.JInt, int]):
        ...

    def setNamedSection(self, tpl: ghidra.pcodeCPort.semantics.ConstructTpl, id: typing.Union[jpype.JInt, int]):
        ...

    def setSourceFileIndex(self, index: typing.Union[jpype.JInt, int]):
        """
        Set the source file index
        
        :param jpype.JInt or int index: index
        """

    @property
    def parent(self) -> SubtableSymbol:
        ...

    @property
    def minimumLength(self) -> jpype.JInt:
        ...

    @minimumLength.setter
    def minimumLength(self, value: jpype.JInt):
        ...

    @property
    def numSections(self) -> jpype.JInt:
        ...

    @property
    def pattern(self) -> ghidra.pcodeCPort.slghpatexpress.TokenPattern:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def templ(self) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    @property
    def error(self) -> jpype.JBoolean:
        ...

    @error.setter
    def error(self, value: jpype.JBoolean):
        ...

    @property
    def numOperands(self) -> jpype.JInt:
        ...

    @property
    def recursive(self) -> jpype.JBoolean:
        ...

    @property
    def lineno(self) -> jpype.JInt:
        ...

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def namedTempl(self) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    @property
    def id(self) -> jpype.JLong:
        ...

    @id.setter
    def id(self, value: jpype.JLong):
        ...

    @property
    def patternEquation(self) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation:
        ...

    @property
    def operand(self) -> OperandSymbol:
        ...


class SpecificSymbol(TripleSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str]):
        ...

    def getVarnode(self) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...

    @property
    def varnode(self) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...


class VarnodeListSymbol(ValueSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], pv: ghidra.pcodeCPort.slghpatexpress.PatternValue, vt: generic.stl.VectorSTL[SleighSymbol]):
        ...


class SleighSymbol(java.lang.Comparable[SleighSymbol]):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str]):
        ...

    def dispose(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def getId(self) -> int:
        ...

    def getLocation(self) -> ghidra.sleigh.grammar.Location:
        ...

    def getName(self) -> str:
        ...

    def getType(self) -> symbol_type:
        ...

    def setLocation(self, location: ghidra.sleigh.grammar.Location):
        ...

    def setWasSought(self, wasSought: typing.Union[jpype.JBoolean, bool]):
        ...

    def toDetailedString(self) -> str:
        ...

    def wasSought(self) -> bool:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> symbol_type:
        ...


class FamilySymbol(TripleSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str]):
        ...

    def getPatternValue(self) -> ghidra.pcodeCPort.slghpatexpress.PatternValue:
        ...

    @property
    def patternValue(self) -> ghidra.pcodeCPort.slghpatexpress.PatternValue:
        ...


@typing.type_check_only
class SymbolCompare(java.util.Comparator[SleighSymbol]):

    class_: typing.ClassVar[java.lang.Class]

    def compare(self, o1: SleighSymbol, o2: SleighSymbol) -> int:
        ...


class SectionSymbol(SleighSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loc: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], id: typing.Union[jpype.JInt, int]):
        ...

    def getDefineCount(self) -> int:
        ...

    def getRefCount(self) -> int:
        ...

    def getTemplateId(self) -> int:
        ...

    def incrementDefineCount(self):
        ...

    def incrementRefCount(self):
        ...

    @property
    def refCount(self) -> jpype.JInt:
        ...

    @property
    def templateId(self) -> jpype.JInt:
        ...

    @property
    def defineCount(self) -> jpype.JInt:
        ...


class ContextChange(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def dispose(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def validate(self):
        ...


class FlowDestSymbol(SpecificSymbol):
    """
    Symbol with semantic value equal to the original
    primary call destination address.
    NOTE: only useable for pcode snippets
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], cspc: ghidra.pcodeCPort.space.AddrSpace):
        ...


class StartSymbol(SpecificSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], cspc: ghidra.pcodeCPort.space.AddrSpace):
        ...


class TokenSymbol(SleighSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, t: ghidra.pcodeCPort.context.Token):
        ...

    def getToken(self) -> ghidra.pcodeCPort.context.Token:
        ...

    @property
    def token(self) -> ghidra.pcodeCPort.context.Token:
        ...


class EndSymbol(SpecificSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], cspc: ghidra.pcodeCPort.space.AddrSpace):
        ...


class symbol_type(java.lang.Enum[symbol_type]):

    class_: typing.ClassVar[java.lang.Class]
    space_symbol: typing.Final[symbol_type]
    token_symbol: typing.Final[symbol_type]
    userop_symbol: typing.Final[symbol_type]
    value_symbol: typing.Final[symbol_type]
    valuemap_symbol: typing.Final[symbol_type]
    name_symbol: typing.Final[symbol_type]
    varnode_symbol: typing.Final[symbol_type]
    varnodelist_symbol: typing.Final[symbol_type]
    operand_symbol: typing.Final[symbol_type]
    start_symbol: typing.Final[symbol_type]
    end_symbol: typing.Final[symbol_type]
    next2_symbol: typing.Final[symbol_type]
    subtable_symbol: typing.Final[symbol_type]
    macro_symbol: typing.Final[symbol_type]
    section_symbol: typing.Final[symbol_type]
    bitrange_symbol: typing.Final[symbol_type]
    context_symbol: typing.Final[symbol_type]
    epsilon_symbol: typing.Final[symbol_type]
    label_symbol: typing.Final[symbol_type]
    flowdest_symbol: typing.Final[symbol_type]
    flowref_symbol: typing.Final[symbol_type]
    dummy_symbol: typing.Final[symbol_type]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> symbol_type:
        ...

    @staticmethod
    def values() -> jpype.JArray[symbol_type]:
        ...


class NameSymbol(ValueSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], pv: ghidra.pcodeCPort.slghpatexpress.PatternValue, nt: generic.stl.VectorSTL[java.lang.String]):
        ...


class SpaceSymbol(SleighSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, spc: ghidra.pcodeCPort.space.AddrSpace):
        ...

    def getSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def space(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...


class MacroSymbol(SleighSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], i: typing.Union[jpype.JInt, int]):
        ...

    def addOperand(self, sym: OperandSymbol):
        ...

    def getConstruct(self) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def getIndex(self) -> int:
        ...

    def getNumOperands(self) -> int:
        ...

    def getOperand(self, i: typing.Union[jpype.JInt, int]) -> OperandSymbol:
        ...

    def setConstruct(self, ct: ghidra.pcodeCPort.semantics.ConstructTpl):
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def construct(self) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    @construct.setter
    def construct(self, value: ghidra.pcodeCPort.semantics.ConstructTpl):
        ...

    @property
    def numOperands(self) -> jpype.JInt:
        ...

    @property
    def operand(self) -> OperandSymbol:
        ...


class ValueMapSymbol(ValueSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], pv: ghidra.pcodeCPort.slghpatexpress.PatternValue, vt: generic.stl.VectorSTL[java.lang.Long]):
        ...


class VarnodeSymbol(PatternlessSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], base: ghidra.pcodeCPort.space.AddrSpace, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
        ...

    def getFixedVarnode(self) -> ghidra.pcodeCPort.pcoderaw.VarnodeData:
        ...

    def markAsContext(self):
        ...

    @property
    def fixedVarnode(self) -> ghidra.pcodeCPort.pcoderaw.VarnodeData:
        ...


class SymbolTable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addGlobalSymbol(self, a: SleighSymbol):
        ...

    def addScope(self):
        ...

    def addSymbol(self, a: SleighSymbol) -> int:
        ...

    def dispose(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def findGlobalSymbol(self, nm: typing.Union[java.lang.String, str]) -> SleighSymbol:
        ...

    @typing.overload
    def findSymbol(self, nm: typing.Union[java.lang.String, str]) -> SleighSymbol:
        ...

    @typing.overload
    def findSymbol(self, nm: typing.Union[java.lang.String, str], skip: typing.Union[jpype.JInt, int]) -> SleighSymbol:
        ...

    @typing.overload
    def findSymbol(self, id: typing.Union[jpype.JInt, int]) -> SleighSymbol:
        ...

    def getCurrentScope(self) -> SymbolScope:
        ...

    def getGlobalScope(self) -> SymbolScope:
        ...

    def getUnsoughtSymbols(self) -> generic.stl.VectorSTL[SleighSymbol]:
        ...

    def popScope(self):
        ...

    def purge(self):
        ...

    def replaceSymbol(self, a: SleighSymbol, b: SleighSymbol):
        ...

    def setCurrentScope(self, scope: SymbolScope):
        ...

    @property
    def unsoughtSymbols(self) -> generic.stl.VectorSTL[SleighSymbol]:
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


class ContextSymbol(ValueSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], pate: ghidra.pcodeCPort.slghpatexpress.ContextField, v: VarnodeSymbol, l: typing.Union[jpype.JInt, int], h: typing.Union[jpype.JInt, int], flow: typing.Union[jpype.JBoolean, bool]):
        ...

    def getHigh(self) -> int:
        ...

    def getLow(self) -> int:
        ...

    def getVarnode(self) -> VarnodeSymbol:
        ...

    def isFlow(self) -> bool:
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
    def flow(self) -> jpype.JBoolean:
        ...


class BitrangeSymbol(SleighSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], sym: VarnodeSymbol, bitoff: typing.Union[jpype.JInt, int], num: typing.Union[jpype.JInt, int]):
        ...

    def getBitOffset(self) -> int:
        ...

    def getParentSymbol(self) -> VarnodeSymbol:
        ...

    def numBits(self) -> int:
        ...

    @property
    def parentSymbol(self) -> VarnodeSymbol:
        ...

    @property
    def bitOffset(self) -> jpype.JInt:
        ...


class SubtableSymbol(TripleSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str]):
        ...

    def addConstructor(self, ct: Constructor):
        ...

    def buildDecisionTree(self, props: DecisionProperties):
        ...

    def buildPattern(self, s: java.io.PrintStream) -> ghidra.pcodeCPort.slghpatexpress.TokenPattern:
        ...

    def getConstructor(self, id: typing.Union[jpype.JInt, int]) -> Constructor:
        ...

    def getNumConstructors(self) -> int:
        ...

    def getPattern(self) -> ghidra.pcodeCPort.slghpatexpress.TokenPattern:
        ...

    def isBeingBuilt(self) -> bool:
        ...

    def isError(self) -> bool:
        ...

    @property
    def pattern(self) -> ghidra.pcodeCPort.slghpatexpress.TokenPattern:
        ...

    @property
    def constructor(self) -> Constructor:
        ...

    @property
    def error(self) -> jpype.JBoolean:
        ...

    @property
    def numConstructors(self) -> jpype.JInt:
        ...

    @property
    def beingBuilt(self) -> jpype.JBoolean:
        ...


class EpsilonSymbol(PatternlessSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], spc: ghidra.pcodeCPort.space.AddrSpace):
        ...


class ContextOp(ContextChange):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, startbit: typing.Union[jpype.JInt, int], endbit: typing.Union[jpype.JInt, int], pe: ghidra.pcodeCPort.slghpatexpress.PatternExpression):
        ...


class SymbolScope(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, p: SymbolScope, i: typing.Union[jpype.JInt, int]):
        ...

    def addSymbol(self, a: SleighSymbol) -> SleighSymbol:
        ...

    def begin(self) -> generic.stl.IteratorSTL[SleighSymbol]:
        ...

    def dispose(self):
        ...

    def end(self) -> generic.stl.IteratorSTL[SleighSymbol]:
        ...

    def findSymbol(self, nm: typing.Union[java.lang.String, str]) -> SleighSymbol:
        ...

    def getId(self) -> int:
        ...

    def getParent(self) -> SymbolScope:
        ...

    def removeSymbol(self, a: SleighSymbol):
        ...

    @property
    def parent(self) -> SymbolScope:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...


class DecisionProperties(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def conflictingPattern(self, pa: ghidra.pcodeCPort.slghpattern.DisjointPattern, a: Constructor, pb: ghidra.pcodeCPort.slghpattern.DisjointPattern, b: Constructor):
        ...

    def getConflictErrors(self) -> generic.stl.VectorSTL[java.lang.String]:
        ...

    def getIdentErrors(self) -> generic.stl.VectorSTL[java.lang.String]:
        ...

    def identicalPattern(self, a: Constructor, b: Constructor):
        ...

    @property
    def identErrors(self) -> generic.stl.VectorSTL[java.lang.String]:
        ...

    @property
    def conflictErrors(self) -> generic.stl.VectorSTL[java.lang.String]:
        ...


class SymbolTree(generic.stl.SetSTL[SleighSymbol]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class PatternlessSymbol(SpecificSymbol):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str]):
        ...


class LabelSymbol(SleighSymbol):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], i: typing.Union[jpype.JInt, int]):
        ...

    def getIndex(self) -> int:
        ...

    def getRefCount(self) -> int:
        ...

    def incrementRefCount(self):
        ...

    def isPlaced(self) -> bool:
        ...

    def setPlaced(self):
        ...

    @property
    def refCount(self) -> jpype.JInt:
        ...

    @property
    def placed(self) -> jpype.JBoolean:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class FlowRefSymbol(SpecificSymbol):
    """
    Symbol with semantic value equal to reference address at the injection site
    NOTE: only useable for pcode snippets
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str], cspc: ghidra.pcodeCPort.space.AddrSpace):
        ...


class DecisionNode(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, p: DecisionNode):
        ...

    def addConstructorPair(self, pat: ghidra.pcodeCPort.slghpattern.DisjointPattern, ct: Constructor):
        ...

    def dispose(self):
        ...

    def orderPatterns(self, props: DecisionProperties):
        ...



__all__ = ["TripleSymbol", "UserOpSymbol", "OperandSymbol", "Next2Symbol", "ValueSymbol", "ContextCommit", "Constructor", "SpecificSymbol", "VarnodeListSymbol", "SleighSymbol", "FamilySymbol", "SymbolCompare", "SectionSymbol", "ContextChange", "FlowDestSymbol", "StartSymbol", "TokenSymbol", "EndSymbol", "symbol_type", "NameSymbol", "SpaceSymbol", "MacroSymbol", "ValueMapSymbol", "VarnodeSymbol", "SymbolTable", "ContextSymbol", "BitrangeSymbol", "SubtableSymbol", "EpsilonSymbol", "ContextOp", "SymbolScope", "DecisionProperties", "SymbolTree", "PatternlessSymbol", "LabelSymbol", "FlowRefSymbol", "DecisionNode"]
