from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.math # type: ignore


class OpBehaviorLzcount(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntSrem(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntDiv(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatAdd(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntSlessEqual(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntLess(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatEqual(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatTrunc(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntZext(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorBoolOr(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatMult(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntRem(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntSdiv(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorSubpiece(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BinaryOpBehavior(OpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def evaluateBinary(self, sizeout: typing.Union[jpype.JInt, int], sizein: typing.Union[jpype.JInt, int], unsignedIn1: typing.Union[jpype.JLong, int], unsignedIn2: typing.Union[jpype.JLong, int]) -> int:
        """
        Evaluate the binary (2 input args) operation using long data
        
        :param jpype.JInt or int sizeout: intended output size (bytes)
        :param jpype.JInt or int sizein: in1 size (bytes)
        :param jpype.JLong or int unsignedIn1: unsigned input 1
        :param jpype.JLong or int unsignedIn2: unsigned input 2
        :return: operation result.  NOTE: if the operation overflows bits may be
        set beyond the specified sizeout.  Even though results should be treated
        as unsigned it may be returned as a signed long value.  It is expected that the 
        returned result always be properly truncated by the caller since the evaluation
        may not - this is done to conserve emulation cycles.
        :rtype: int
        
        .. seealso::
        
            | :obj:`Utils.longToBytes(long, int, boolean)`
        
            | :obj:`Utils.bytesToLong(byte[], int, boolean)`
        """

    @typing.overload
    def evaluateBinary(self, sizeout: typing.Union[jpype.JInt, int], sizein: typing.Union[jpype.JInt, int], unsignedIn1: java.math.BigInteger, unsignedIn2: java.math.BigInteger) -> java.math.BigInteger:
        """
        Evaluate the binary (2 input args) operation using BigInteger data
        
        :param jpype.JInt or int sizeout: intended output size (bytes)
        :param jpype.JInt or int sizein: in1 size (bytes)
        :param java.math.BigInteger unsignedIn1: unsigned input 1
        :param java.math.BigInteger unsignedIn2: unsigned input 2
        :return: operation result.  NOTE: if the operation overflows bits may be
        set beyond the specified sizeout.  Even though results should be treated
        as unsigned it may be returned as a signed value.  It is expected that the 
        returned result always be properly truncated by the caller since the evaluation
        may not - this is done to conserve emulation cycles.
        :rtype: java.math.BigInteger
        
        .. seealso::
        
            | :obj:`Utils.bigIntegerToBytes(BigInteger, int, boolean)`
        
            | :obj:`Utils.bytesToBigInteger(byte[], int, boolean, boolean)`
        """


class OpBehaviorFloatSub(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntMult(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntXor(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntCarry(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntSright(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorBoolAnd(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatNeg(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatLess(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatNan(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatFloor(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntSext(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatSqrt(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntSub(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatNotEqual(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorBoolXor(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatInt2Float(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorInt2Comp(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatAbs(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SpecialOpBehavior(OpBehavior):
    ...
    class_: typing.ClassVar[java.lang.Class]


class OpBehaviorIntAnd(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorNotEqual(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatCeil(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntNegate(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getOpBehavior(opcode: typing.Union[jpype.JInt, int]) -> OpBehavior:
        ...


class OpBehaviorIntSless(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatFloat2Float(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorCopy(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntSborrow(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatDiv(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntAdd(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorPopcount(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorBoolNegate(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntScarry(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class UnaryOpBehavior(OpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def evaluateUnary(self, sizeout: typing.Union[jpype.JInt, int], sizein: typing.Union[jpype.JInt, int], unsignedIn1: typing.Union[jpype.JLong, int]) -> int:
        """
        Evaluate the unary operation using long data
        
        :param jpype.JInt or int sizeout: intended output size (bytes)
        :param jpype.JInt or int sizein: in1 size (bytes)
        :param jpype.JLong or int unsignedIn1: unsigned input 1
        :return: operation result.  NOTE: if the operation overflows bits may be
        set beyond the specified sizeout.  Even though results should be treated
        as unsigned it may be returned as a signed long value.  It is expected that the 
        returned result always be properly truncated by the caller since the evaluation
        may not - this is done to conserve emulation cycles.
        :rtype: int
        
        .. seealso::
        
            | :obj:`Utils.longToBytes(long, int, boolean)`
        
            | :obj:`Utils.bytesToLong(byte[], int, boolean)`
        """

    @typing.overload
    def evaluateUnary(self, sizeout: typing.Union[jpype.JInt, int], sizein: typing.Union[jpype.JInt, int], unsignedIn1: java.math.BigInteger) -> java.math.BigInteger:
        """
        Evaluate the unary operation using BigInteger data
        
        :param jpype.JInt or int sizeout: intended output size (bytes)
        :param jpype.JInt or int sizein: in1 size (bytes)
        :param java.math.BigInteger unsignedIn1: unsigned input 1
        :return: operation result.  NOTE: if the operation overflows bits may be
        set beyond the specified sizeout.  Even though results should be treated
        as unsigned it may be returned as a signed value.  It is expected that the 
        returned result always be properly truncated by the caller since the evaluation
        may not - this is done to conserve emulation cycles.
        :rtype: java.math.BigInteger
        
        .. seealso::
        
            | :obj:`Utils.bigIntegerToBytes(BigInteger, int, boolean)`
        
            | :obj:`Utils.bytesToBigInteger(byte[], int, boolean, boolean)`
        """


class OpBehaviorIntLessEqual(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntOr(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorEqual(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatLessEqual(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorFloatRound(UnaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehavior(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getOpCode(self) -> int:
        ...

    @property
    def opCode(self) -> jpype.JInt:
        ...


class OpBehaviorIntLeft(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorIntRight(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorPiece(BinaryOpBehavior):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["OpBehaviorLzcount", "OpBehaviorIntSrem", "OpBehaviorIntDiv", "OpBehaviorFloatAdd", "OpBehaviorIntSlessEqual", "OpBehaviorIntLess", "OpBehaviorFloatEqual", "OpBehaviorFloatTrunc", "OpBehaviorIntZext", "OpBehaviorBoolOr", "OpBehaviorFloatMult", "OpBehaviorIntRem", "OpBehaviorIntSdiv", "OpBehaviorSubpiece", "BinaryOpBehavior", "OpBehaviorFloatSub", "OpBehaviorIntMult", "OpBehaviorIntXor", "OpBehaviorIntCarry", "OpBehaviorIntSright", "OpBehaviorBoolAnd", "OpBehaviorFloatNeg", "OpBehaviorFloatLess", "OpBehaviorFloatNan", "OpBehaviorFloatFloor", "OpBehaviorIntSext", "OpBehaviorFloatSqrt", "OpBehaviorIntSub", "OpBehaviorFloatNotEqual", "OpBehaviorBoolXor", "OpBehaviorFloatInt2Float", "OpBehaviorInt2Comp", "OpBehaviorFloatAbs", "SpecialOpBehavior", "OpBehaviorIntAnd", "OpBehaviorNotEqual", "OpBehaviorFloatCeil", "OpBehaviorIntNegate", "OpBehaviorFactory", "OpBehaviorIntSless", "OpBehaviorFloatFloat2Float", "OpBehaviorCopy", "OpBehaviorIntSborrow", "OpBehaviorFloatDiv", "OpBehaviorIntAdd", "OpBehaviorPopcount", "OpBehaviorBoolNegate", "OpBehaviorIntScarry", "UnaryOpBehavior", "OpBehaviorIntLessEqual", "OpBehaviorIntOr", "OpBehaviorEqual", "OpBehaviorFloatLessEqual", "OpBehaviorFloatRound", "OpBehavior", "OpBehaviorIntLeft", "OpBehaviorIntRight", "OpBehaviorPiece"]
