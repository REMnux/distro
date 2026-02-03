from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.pcodeCPort.context
import ghidra.pcodeCPort.slghpattern
import ghidra.pcodeCPort.slghsymbol
import ghidra.pcodeCPort.utils
import ghidra.program.model.pcode
import ghidra.sleigh.grammar
import java.lang # type: ignore


class ConstantValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, v: typing.Union[jpype.JLong, int]):
        ...


class XorExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class EquationOr(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternEquation, r: PatternEquation):
        ...


class EquationAnd(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternEquation, r: PatternEquation):
        ...


class PatternExpression(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def genMinPattern(self, ops: generic.stl.VectorSTL[TokenPattern]) -> TokenPattern:
        ...

    def getMinMax(self, minlist: generic.stl.VectorSTL[java.lang.Long], maxlist: generic.stl.VectorSTL[java.lang.Long]):
        ...

    @typing.overload
    def getSubValue(self, replace: generic.stl.VectorSTL[java.lang.Long], listpos: ghidra.pcodeCPort.utils.MutableInt) -> int:
        ...

    @typing.overload
    def getSubValue(self, replace: generic.stl.VectorSTL[java.lang.Long]) -> int:
        ...

    def layClaim(self):
        ...

    def listValues(self, list: generic.stl.VectorSTL[PatternValue]):
        ...

    @staticmethod
    def release(p: PatternExpression):
        ...

    @property
    def subValue(self) -> jpype.JLong:
        ...


class Next2InstructionValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...


class UnaryExpression(PatternExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, u: PatternExpression):
        ...

    def getUnary(self) -> PatternExpression:
        ...

    @property
    def unary(self) -> PatternExpression:
        ...


class SubExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class LessEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression):
        ...


class TokenPattern(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, tf: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, tok: ghidra.pcodeCPort.context.Token, value: typing.Union[jpype.JLong, int], bitstart: typing.Union[jpype.JInt, int], bitend: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, value: typing.Union[jpype.JLong, int], startbit: typing.Union[jpype.JInt, int], endbit: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, tokpat: TokenPattern):
        ...

    def alwaysFalse(self) -> bool:
        ...

    def alwaysInstructionTrue(self) -> bool:
        ...

    def alwaysTrue(self) -> bool:
        ...

    @staticmethod
    def buildLittleBlock(size: typing.Union[jpype.JInt, int], bitstart: typing.Union[jpype.JInt, int], bitend: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]) -> ghidra.pcodeCPort.slghpattern.PatternBlock:
        ...

    def commonSubPattern(self, tokpat: TokenPattern) -> TokenPattern:
        ...

    def copyInto(self, tokpat: TokenPattern) -> TokenPattern:
        ...

    def dispose(self):
        ...

    def doAnd(self, tokpat: TokenPattern) -> TokenPattern:
        ...

    def doCat(self, tokpat: TokenPattern) -> TokenPattern:
        ...

    def doOr(self, tokpat: TokenPattern) -> TokenPattern:
        ...

    def getLeftEllipsis(self) -> bool:
        ...

    def getMinimumLength(self) -> int:
        ...

    def getPattern(self) -> ghidra.pcodeCPort.slghpattern.Pattern:
        ...

    def getRightEllipsis(self) -> bool:
        ...

    def setLeftEllipsis(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setRightEllipsis(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def simplifyPattern(self):
        ...

    @property
    def leftEllipsis(self) -> jpype.JBoolean:
        ...

    @leftEllipsis.setter
    def leftEllipsis(self, value: jpype.JBoolean):
        ...

    @property
    def minimumLength(self) -> jpype.JInt:
        ...

    @property
    def rightEllipsis(self) -> jpype.JBoolean:
        ...

    @rightEllipsis.setter
    def rightEllipsis(self, value: jpype.JBoolean):
        ...

    @property
    def pattern(self) -> ghidra.pcodeCPort.slghpattern.Pattern:
        ...


class NotEqualEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression):
        ...


class EqualEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression):
        ...


class EquationCat(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternEquation, r: PatternEquation):
        ...


class LeftShiftExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class EquationRightEllipsis(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, e: PatternEquation):
        ...


class DivExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class MinusExpression(UnaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, u: PatternExpression):
        ...


class OperandValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, ind: typing.Union[jpype.JInt, int], c: ghidra.pcodeCPort.slghsymbol.Constructor):
        ...

    def changeIndex(self, newind: typing.Union[jpype.JInt, int]):
        ...

    def getName(self) -> str:
        ...

    def isConstructorRelative(self) -> bool:
        ...

    @property
    def constructorRelative(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class OperandResolve(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    operands: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.OperandSymbol]
    base: jpype.JInt
    offset: jpype.JInt
    cur_rightmost: jpype.JInt
    size: jpype.JInt

    def __init__(self, ops: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.OperandSymbol]):
        ...


class BinaryExpression(PatternExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...

    def getLeft(self) -> PatternExpression:
        ...

    def getRight(self) -> PatternExpression:
        ...

    @property
    def left(self) -> PatternExpression:
        ...

    @property
    def right(self) -> PatternExpression:
        ...


class NotExpression(UnaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, u: PatternExpression):
        ...


class PlusExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class ExpressUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class UnconstrainedEquation(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, p: PatternExpression):
        ...


class PatternValue(PatternExpression):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    def genPattern(self, val: typing.Union[jpype.JLong, int]) -> TokenPattern:
        ...

    def maxValue(self) -> int:
        ...

    def minValue(self) -> int:
        ...


class StartInstructionValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...


class AndExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class OrExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class TokenField(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, tk: ghidra.pcodeCPort.context.Token, s: typing.Union[jpype.JBoolean, bool], bstart: typing.Union[jpype.JInt, int], bend: typing.Union[jpype.JInt, int]):
        ...


class ContextField(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, s: typing.Union[jpype.JBoolean, bool], sbit: typing.Union[jpype.JInt, int], ebit: typing.Union[jpype.JInt, int]):
        ...

    def getEndBit(self) -> int:
        ...

    def getSignBit(self) -> bool:
        ...

    def getStartBit(self) -> int:
        ...

    @property
    def endBit(self) -> jpype.JInt:
        ...

    @property
    def startBit(self) -> jpype.JInt:
        ...

    @property
    def signBit(self) -> jpype.JBoolean:
        ...


class RightShiftExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class ValExpressEquation(PatternEquation):
    ...
    class_: typing.ClassVar[java.lang.Class]


class OperandEquation(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, ind: typing.Union[jpype.JInt, int]):
        ...


class EndInstructionValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...


class MultExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression):
        ...


class GreaterEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression):
        ...


class LessEqualEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression):
        ...


class GreaterEqualEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression):
        ...


class PatternEquation(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    def genPattern(self, ops: generic.stl.VectorSTL[TokenPattern]):
        ...

    def getTokenPattern(self) -> TokenPattern:
        ...

    def layClaim(self):
        ...

    def operandOrder(self, ct: ghidra.pcodeCPort.slghsymbol.Constructor, order: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.OperandSymbol]):
        """
        returns a vector of the self-defining OperandSymbols as they appear
                in left to right order in the pattern
        
        :param ghidra.pcodeCPort.slghsymbol.Constructor ct: is the Constructor containing the operands
        :param generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.OperandSymbol] order: is the vector that will hold the ordered list
        """

    @staticmethod
    def release(pateq: PatternEquation):
        ...

    def resolveOperandLeft(self, state: OperandResolve) -> bool:
        ...

    @property
    def tokenPattern(self) -> TokenPattern:
        ...


class EquationLeftEllipsis(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, e: PatternEquation):
        ...



__all__ = ["ConstantValue", "XorExpression", "EquationOr", "EquationAnd", "PatternExpression", "Next2InstructionValue", "UnaryExpression", "SubExpression", "LessEquation", "TokenPattern", "NotEqualEquation", "EqualEquation", "EquationCat", "LeftShiftExpression", "EquationRightEllipsis", "DivExpression", "MinusExpression", "OperandValue", "OperandResolve", "BinaryExpression", "NotExpression", "PlusExpression", "ExpressUtils", "UnconstrainedEquation", "PatternValue", "StartInstructionValue", "AndExpression", "OrExpression", "TokenField", "ContextField", "RightShiftExpression", "ValExpressEquation", "OperandEquation", "EndInstructionValue", "MultExpression", "GreaterEquation", "LessEqualEquation", "GreaterEqualEquation", "PatternEquation", "EquationLeftEllipsis"]
