from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.program.model.pcode
import java.lang # type: ignore


class ConstantValue(PatternValue):
    """
    A constant value associated with an alwaysTrue pattern
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, b: typing.Union[jpype.JLong, int]):
        ...

    def getValue(self) -> int:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class XorExpression(BinaryExpression):
    """
    Form new expression by XORing two PatternExpressions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PatternExpression(java.lang.Object):
    """
    An expression which results in a pattern for a specific InstructionContext
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, lang: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        ...

    @staticmethod
    def decodeExpression(decoder: ghidra.program.model.pcode.Decoder, lang: ghidra.app.plugin.processors.sleigh.SleighLanguage) -> PatternExpression:
        ...

    def getValue(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker) -> int:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class Next2InstructionValue(PatternValue):
    """
    The integer offset of the address following the current instruction
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class UnaryExpression(PatternExpression):
    """
    Base class for unary operators on PatternExpressions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getUnary(self) -> PatternExpression:
        ...

    @property
    def unary(self) -> PatternExpression:
        ...


class SubExpression(BinaryExpression):
    """
    New expression formed by subtracting two PatternExpressions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LeftShiftExpression(BinaryExpression):
    """
    Form new expression by left shifting PatternExpression the amount
    determined by another PatternExpression
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DivExpression(BinaryExpression):
    """
    Form new expression by dividing one PatternExpression by another
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MinusExpression(UnaryExpression):
    """
    Form new expression by taking twos complement of a PatternExpression
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OperandValue(PatternValue):
    """
    An Expression representing the value of a Constructor operand
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, i: typing.Union[jpype.JInt, int], c: ghidra.app.plugin.processors.sleigh.Constructor):
        ...

    def getConstructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor:
        ...

    def getIndex(self) -> int:
        ...

    @property
    def constructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class BinaryExpression(PatternExpression):
    """
    Base class for binary operators that combine PatternExpressions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
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
    """
    Form new expression by complementing a PatternExpression
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PlusExpression(BinaryExpression):
    """
    Expression formed by adding together two PatternExpressions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PatternValue(PatternExpression):
    """
    This is a PatternExpression which can be interpreted as an
    integer value. Restricting the PatternValue to a specific integer
    yields an actual pattern.
     
    None of the functionality is needed for the disassembly interface,
    (only for the compiler interface) but we preserve the structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def maxValue(self) -> int:
        ...

    def minValue(self) -> int:
        ...


class StartInstructionValue(PatternValue):
    """
    The offset value of the current instructions address
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AndExpression(BinaryExpression):
    """
    Form a new expression by ANDing two PatternExpressions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OrExpression(BinaryExpression):
    """
    Form new expression by ORing together two PatternExpressions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TokenField(PatternValue):
    """
    A contiguous set of bits within instruction stream, interpreted
    as an integer value
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def byteSwap(val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Swap the least sig -size- bytes in -val-
        
        :param jpype.JLong or int val: value to be byte swapped
        :param jpype.JInt or int size: number of bytes involved in swap
        :return: the byte swapped value
        :rtype: int
        """

    def getBitEnd(self) -> int:
        ...

    def getBitStart(self) -> int:
        ...

    def getByteEnd(self) -> int:
        ...

    def getByteStart(self) -> int:
        ...

    def getShift(self) -> int:
        ...

    def hasSignbit(self) -> bool:
        ...

    def isBigEndian(self) -> bool:
        ...

    @staticmethod
    def signExtend(val: typing.Union[jpype.JLong, int], bit: typing.Union[jpype.JInt, int]) -> int:
        """
        Sign extend -val- above -bit-
        
        :param jpype.JLong or int val: value to extend
        :param jpype.JInt or int bit: bit specifying sign
        :return: the extended value
        :rtype: int
        """

    @staticmethod
    def zeroExtend(val: typing.Union[jpype.JLong, int], bit: typing.Union[jpype.JInt, int]) -> int:
        """
        Clear all bits in -val- above -bit-
        
        :param jpype.JLong or int val: value to zero extend
        :param jpype.JInt or int bit: bit above which to zero extend
        :return: the extended value
        :rtype: int
        """

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def bitEnd(self) -> jpype.JInt:
        ...

    @property
    def shift(self) -> jpype.JInt:
        ...

    @property
    def byteEnd(self) -> jpype.JInt:
        ...

    @property
    def byteStart(self) -> jpype.JInt:
        ...

    @property
    def bitStart(self) -> jpype.JInt:
        ...


class ContextField(PatternValue):
    """
    Contiguous bits in the non-instruction part of the context interpreted
    as an integer value
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getByteEnd(self) -> int:
        ...

    def getByteStart(self) -> int:
        ...

    def getEndBit(self) -> int:
        ...

    def getShift(self) -> int:
        ...

    def getSignBit(self) -> bool:
        ...

    def getStartBit(self) -> int:
        ...

    def hasSignbit(self) -> bool:
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

    @property
    def shift(self) -> jpype.JInt:
        ...

    @property
    def byteEnd(self) -> jpype.JInt:
        ...

    @property
    def byteStart(self) -> jpype.JInt:
        ...


class RightShiftExpression(BinaryExpression):
    """
    Form new expression by right shifting a PatternExpression the amount
    determined by another PatternExpression
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EndInstructionValue(PatternValue):
    """
    The integer offset of the address following the current instruction
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MultExpression(BinaryExpression):
    """
    Form new expression by multiplying two PatternExpressions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ConstantValue", "XorExpression", "PatternExpression", "Next2InstructionValue", "UnaryExpression", "SubExpression", "LeftShiftExpression", "DivExpression", "MinusExpression", "OperandValue", "BinaryExpression", "NotExpression", "PlusExpression", "PatternValue", "StartInstructionValue", "AndExpression", "OrExpression", "TokenField", "ContextField", "RightShiftExpression", "EndInstructionValue", "MultExpression"]
