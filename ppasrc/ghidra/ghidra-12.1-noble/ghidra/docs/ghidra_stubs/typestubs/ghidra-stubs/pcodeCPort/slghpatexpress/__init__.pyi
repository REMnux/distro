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


class TokenPattern(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, tf: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, tok: ghidra.pcodeCPort.context.Token, value: typing.Union[jpype.JLong, int], bitstart: typing.Union[jpype.JInt, int], bitend: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, value: typing.Union[jpype.JLong, int], startbit: typing.Union[jpype.JInt, int], endbit: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, tokpat: TokenPattern) -> None:
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

    def dispose(self) -> None:
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

    def setLeftEllipsis(self, val: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def setRightEllipsis(self, val: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def simplifyPattern(self) -> None:
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


class PatternEquation(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    def genPattern(self, ops: generic.stl.VectorSTL[TokenPattern]) -> None:
        ...

    def getTokenPattern(self) -> TokenPattern:
        ...

    def layClaim(self) -> None:
        ...

    def operandOrder(self, ct: ghidra.pcodeCPort.slghsymbol.Constructor, order: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.OperandSymbol]) -> None:
        """
        returns a vector of the self-defining OperandSymbols as they appear
                in left to right order in the pattern
        
        :param ghidra.pcodeCPort.slghsymbol.Constructor ct: is the Constructor containing the operands
        :param generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.OperandSymbol] order: is the vector that will hold the ordered list
        """

    @staticmethod
    def release(pateq: PatternEquation) -> None:
        ...

    def resolveOperandLeft(self, state: OperandResolve) -> bool:
        ...

    @property
    def tokenPattern(self) -> TokenPattern:
        ...


class OperandValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, ind: typing.Union[jpype.JInt, int], c: ghidra.pcodeCPort.slghsymbol.Constructor) -> None:
        ...

    def changeIndex(self, newind: typing.Union[jpype.JInt, int]) -> None:
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


class PatternValue(PatternExpression):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    def genPattern(self, val: typing.Union[jpype.JLong, int]) -> TokenPattern:
        ...

    def maxValue(self) -> int:
        ...

    def minValue(self) -> int:
        ...


class PatternExpression(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        ...

    def genMinPattern(self, ops: generic.stl.VectorSTL[TokenPattern]) -> TokenPattern:
        ...

    def getMinMax(self, minlist: generic.stl.VectorSTL[java.lang.Long], maxlist: generic.stl.VectorSTL[java.lang.Long]) -> None:
        ...

    @typing.overload
    def getSubValue(self, replace: generic.stl.VectorSTL[java.lang.Long], listpos: ghidra.pcodeCPort.utils.MutableInt) -> int:
        ...

    @typing.overload
    def getSubValue(self, replace: generic.stl.VectorSTL[java.lang.Long]) -> int:
        ...

    def layClaim(self) -> None:
        ...

    def listValues(self, list: generic.stl.VectorSTL[PatternValue]) -> None:
        ...

    @staticmethod
    def release(p: PatternExpression) -> None:
        ...

    @property
    def subValue(self) -> jpype.JLong:
        ...


class OperandResolve(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    operands: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.OperandSymbol]
    base: jpype.JInt
    offset: jpype.JInt
    cur_rightmost: jpype.JInt
    size: jpype.JInt

    def __init__(self, ops: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.OperandSymbol]) -> None:
        ...


class ConstantValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, v: typing.Union[jpype.JLong, int]) -> None:
        ...


class ContextField(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, s: typing.Union[jpype.JBoolean, bool], sbit: typing.Union[jpype.JInt, int], ebit: typing.Union[jpype.JInt, int]) -> None:
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


class AndExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...


class BinaryExpression(PatternExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
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


class DivExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...


class EndInstructionValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...


class EqualEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression) -> None:
        ...


class ValExpressEquation(PatternEquation):
    ...
    class_: typing.ClassVar[java.lang.Class]


class EquationAnd(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternEquation, r: PatternEquation) -> None:
        ...


class EquationCat(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternEquation, r: PatternEquation) -> None:
        ...


class EquationLeftEllipsis(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, e: PatternEquation) -> None:
        ...


class EquationOr(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternEquation, r: PatternEquation) -> None:
        ...


class EquationRightEllipsis(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, e: PatternEquation) -> None:
        ...


class ExpressUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class GreaterEqualEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression) -> None:
        ...


class GreaterEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression) -> None:
        ...


class LeftShiftExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...


class LessEqualEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression) -> None:
        ...


class LessEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression) -> None:
        ...


class MinusExpression(UnaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, u: PatternExpression) -> None:
        ...


class UnaryExpression(PatternExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, u: PatternExpression) -> None:
        ...

    def getUnary(self) -> PatternExpression:
        ...

    @property
    def unary(self) -> PatternExpression:
        ...


class MultExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...


class Next2InstructionValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...


class NotEqualEquation(ValExpressEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternValue, r: PatternExpression) -> None:
        ...


class NotExpression(UnaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, u: PatternExpression) -> None:
        ...


class OperandEquation(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, ind: typing.Union[jpype.JInt, int]) -> None:
        ...


class OrExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...


class PlusExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...


class RightShiftExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...


class StartInstructionValue(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...


class SubExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...


class TokenField(PatternValue):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, tk: ghidra.pcodeCPort.context.Token, s: typing.Union[jpype.JBoolean, bool], bstart: typing.Union[jpype.JInt, int], bend: typing.Union[jpype.JInt, int]) -> None:
        ...


class UnconstrainedEquation(PatternEquation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.sleigh.grammar.Location, p: PatternExpression) -> None:
        ...


class XorExpression(BinaryExpression):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location) -> None:
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, l: PatternExpression, r: PatternExpression) -> None:
        ...



__all__ = ["TokenPattern", "PatternEquation", "OperandValue", "PatternValue", "PatternExpression", "OperandResolve", "ConstantValue", "ContextField", "AndExpression", "BinaryExpression", "DivExpression", "EndInstructionValue", "EqualEquation", "ValExpressEquation", "EquationAnd", "EquationCat", "EquationLeftEllipsis", "EquationOr", "EquationRightEllipsis", "ExpressUtils", "GreaterEqualEquation", "GreaterEquation", "LeftShiftExpression", "LessEqualEquation", "LessEquation", "MinusExpression", "UnaryExpression", "MultExpression", "Next2InstructionValue", "NotEqualEquation", "NotExpression", "OperandEquation", "OrExpression", "PlusExpression", "RightShiftExpression", "StartInstructionValue", "SubExpression", "TokenField", "UnconstrainedEquation", "XorExpression"]
