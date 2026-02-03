from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.error
import java.lang # type: ignore
import java.math # type: ignore


@typing.type_check_only
class FloatKind(java.lang.Enum[FloatKind]):

    class_: typing.ClassVar[java.lang.Class]
    FINITE: typing.Final[FloatKind]
    INFINITE: typing.Final[FloatKind]
    QUIET_NAN: typing.Final[FloatKind]
    SIGNALING_NAN: typing.Final[FloatKind]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatKind:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatKind]:
        ...


class UnsupportedFloatFormatException(ghidra.pcode.error.LowlevelError):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, formatSize: typing.Union[jpype.JInt, int]):
        ...


class BigFloat(java.lang.Comparable[BigFloat]):
    """
    An IEEE 754 floating point class.
    
     
    Values represented:
     
    * QUIET_NAN, SIGNALED_NAN
    * -INF, +INF
    * value = sign * unscaled * 2 ^ (scale-fracbits)
    
    sign = -1 or +1, unscaled has at most fracbits+1 bits, and scale is at most expbits bits.
          
     
    Operations compute exact result then round to nearest even.
    """

    class_: typing.ClassVar[java.lang.Class]
    INFINITY: typing.Final = "Infinity"
    POSITIVE_INFINITY: typing.Final = "+Infinity"
    NEGATIVE_INFINITY: typing.Final = "-Infinity"
    NAN: typing.Final = "NaN"
    BIG_POSITIVE_INFINITY: typing.Final[java.math.BigDecimal]
    BIG_NEGATIVE_INFINITY: typing.Final[java.math.BigDecimal]

    @staticmethod
    @typing.overload
    def abs(a: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :return: ``abs(a)``
        :rtype: BigFloat
        """

    @typing.overload
    def abs(self):
        """
        ``this=abs(this)``
        """

    @staticmethod
    @typing.overload
    def add(a: BigFloat, b: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :param BigFloat b: a BigFloat
        :return: ``a+b``
        :rtype: BigFloat
        """

    @typing.overload
    def add(self, other: BigFloat):
        """
        ``this+=other``
        
        :param BigFloat other: a BigFloat
        """

    @staticmethod
    @typing.overload
    def ceil(a: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :return: ``ceil(a)``
        :rtype: BigFloat
        """

    @typing.overload
    def ceil(self):
        """
        ``this=ceil(this)``
        """

    def copy(self) -> BigFloat:
        """
        
        
        :return: a copy of this BigFloat
        :rtype: BigFloat
        """

    @staticmethod
    @typing.overload
    def div(a: BigFloat, b: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :param BigFloat b: a BigFloat
        :return: ``a/b``
        :rtype: BigFloat
        """

    @typing.overload
    def div(self, other: BigFloat):
        """
        ``this/=other``
        
        :param BigFloat other: a BigFloat
        """

    @staticmethod
    @typing.overload
    def floor(a: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :return: ``floor(a)``
        :rtype: BigFloat
        """

    @typing.overload
    def floor(self):
        """
        ``this=floor(this)``
        """

    @staticmethod
    def infinity(fracbits: typing.Union[jpype.JInt, int], expbits: typing.Union[jpype.JInt, int], sign: typing.Union[jpype.JInt, int]) -> BigFloat:
        """
        
        
        :param jpype.JInt or int fracbits: number of fractional bits
        :param jpype.JInt or int expbits: number of bits in the exponent
        :param jpype.JInt or int sign: +1 or -1
        :return: +inf or -inf
        :rtype: BigFloat
        """

    def isDenormal(self) -> bool:
        """
        Determine if the state of this BigFloat reflects a subnormal/denormal value.
         
        NOTE: This method relies on the manner of construction and
        only checks for :obj:`FloatKind.FINITE` and that the non-zero
        unscaled valued does not use all fractional bits.
        
        :return: ``true`` if this BigFloat is FINITE and denormal
        :rtype: bool
        """

    def isInfinite(self) -> bool:
        """
        
        
        :return: ``true`` if this BigFloat is infinite
        :rtype: bool
        """

    def isNaN(self) -> bool:
        """
        
        
        :return: ``true`` if this BigFloat is NaN
        :rtype: bool
        """

    def isNormal(self) -> bool:
        """
        Determine if the state of this BigFloat reflects a normalized value.
         
        NOTE: This method relies on the manner of construction and
        only checks for :obj:`FloatKind.FINITE` and that full size of the
        fractional bits is used for the unscaled value.
        
        :return: ``true`` if this BigFloat is FINITE and normal.
        :rtype: bool
        """

    def isZero(self) -> bool:
        """
        
        
        :return: ``true`` if this BigFloat is zero
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def mul(a: BigFloat, b: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :param BigFloat b: a BigFloat
        :return: ``a*b``
        :rtype: BigFloat
        """

    @typing.overload
    def mul(self, other: BigFloat):
        """
        ``this*=other``
        
        :param BigFloat other: a BigFloat
        """

    @typing.overload
    def negate(self):
        """
        ``this*=-1``
        """

    @staticmethod
    @typing.overload
    def negate(a: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :return: ``-a``
        :rtype: BigFloat
        """

    @staticmethod
    def quietNaN(fracbits: typing.Union[jpype.JInt, int], expbits: typing.Union[jpype.JInt, int], sign: typing.Union[jpype.JInt, int]) -> BigFloat:
        """
        Return the BigFloat with the given number of bits representing (quiet) NaN.
        
        :param jpype.JInt or int fracbits: number of fractional bits
        :param jpype.JInt or int expbits: number of bits in the exponent
        :param jpype.JInt or int sign: +1 or -1
        :return: a BigFloat representing (quiet) NaN
        :rtype: BigFloat
        """

    @staticmethod
    @typing.overload
    def round(a: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :return: ``round(a)``
        :rtype: BigFloat
        """

    @typing.overload
    def round(self):
        """
        Round this value to the nearest whole number
        """

    @staticmethod
    @typing.overload
    def sqrt(a: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :return: the square root of ``a``
        :rtype: BigFloat
        """

    @typing.overload
    def sqrt(self):
        """
        ``this=sqrt(this)``
         
            
        Square root by abacus algorithm, Martin Guy @ UKC, June 1985.
            From a book on programming abaci by Mr C. Woo.
            Argument is a positive integer, as is result.
        
          
        adapted from http://medialab.freaknet.org/martin/src/sqrt/sqrt.c
        """

    @staticmethod
    @typing.overload
    def sub(a: BigFloat, b: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :param BigFloat b: a BigFloat
        :return: ``a-b``
        :rtype: BigFloat
        """

    @typing.overload
    def sub(self, other: BigFloat):
        """
        ``this-=other``
        
        :param BigFloat other: a BigFloat
        """

    def toBigDecimal(self) -> java.math.BigDecimal:
        """
        If finite, the returned BigDecimal is exactly equal to this.  If not finite, one of the
        FloatFormat.BIG_* constants is returned.
        
        :return: a BigDecimal or null if value is NaN (i.e., :obj:`FloatKind.QUIET_NAN` or 
        :obj:`FloatKind.SIGNALING_NAN`).
        :rtype: java.math.BigDecimal
        """

    def toBigInteger(self) -> java.math.BigInteger:
        """
        
        
        :return: the truncated integer form of this BigFloat
        :rtype: java.math.BigInteger
        """

    def toBinaryString(self) -> str:
        ...

    @typing.overload
    def toString(self) -> str:
        """
        Perform rounding and conversion to BigDecimal prior to generating
        a formatted decimal string of the specified BigFloat value.
        A default generated :obj:`MathContext` is used.
        
        :return: decimal string representation
        :rtype: str
        """

    @typing.overload
    def toString(self, displayContext: java.math.MathContext) -> str:
        """
        Perform rounding and conversion to BigDecimal prior to generating
        a formatted decimal string of the specified BigFloat value.
        
        :param java.math.MathContext displayContext: display context used for rounding and precision.
        :return: decimal string representation
        :rtype: str
        """

    @typing.overload
    def toString(self, ff: FloatFormat, compact: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Perform appropriate rounding and conversion to BigDecimal prior to generating
        a formatted decimal string of the specified BigFloat value.  
        See :meth:`toString(FloatFormat, boolean) <.toString>`,
        :meth:`FloatFormat.toDecimalString(BigFloat) <FloatFormat.toDecimalString>` and 
        :meth:`FloatFormat.toDecimalString(BigFloat, boolean) <FloatFormat.toDecimalString>`.
        
        :param FloatFormat ff: float format
        :param jpype.JBoolean or bool compact: if true the precision will be reduced to a form which is still equivalent at
        the binary encoding level for the specified FloatFormat.
        :return: decimal string representation
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def trunc(a: BigFloat) -> BigFloat:
        """
        
        
        :param BigFloat a: a BigFloat
        :return: ``trunc(a)`` (round toward zero)
        :rtype: BigFloat
        """

    @typing.overload
    def trunc(self):
        """
        ``this=trunc(this)`` (round toward zero)
        """

    @staticmethod
    @typing.overload
    def zero(fracbits: typing.Union[jpype.JInt, int], expbits: typing.Union[jpype.JInt, int], sign: typing.Union[jpype.JInt, int]) -> BigFloat:
        """
        Return the BigFloat with the given number of bits representing zero.
        
        :param jpype.JInt or int fracbits: number of fractional bits
        :param jpype.JInt or int expbits: number of bits in the exponent
        :param jpype.JInt or int sign: +1 or -1
        :return: a BigFloat representing +zero or -zero
        :rtype: BigFloat
        """

    @staticmethod
    @typing.overload
    def zero(fracbits: typing.Union[jpype.JInt, int], expbits: typing.Union[jpype.JInt, int]) -> BigFloat:
        """
        Return the BigFloat with the given number of bits representing (positive) zero.
        
        :param jpype.JInt or int fracbits: number of fractional bits
        :param jpype.JInt or int expbits: number of bits in the exponent
        :return: a BigFloat representing +zero
        :rtype: BigFloat
        """

    @property
    def normal(self) -> jpype.JBoolean:
        ...

    @property
    def infinite(self) -> jpype.JBoolean:
        ...

    @property
    def denormal(self) -> jpype.JBoolean:
        ...

    @property
    def naN(self) -> jpype.JBoolean:
        ...


class FloatFormatFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getFloatFormat(size: typing.Union[jpype.JInt, int]) -> FloatFormat:
        """
        Get float format
        
        :param jpype.JInt or int size: format storage size in bytes
        :return: float format or null if size is not supported
        :rtype: FloatFormat
        :raises UnsupportedFloatFormatException: if specified size is unsupported
        """


class FloatFormat(java.lang.Object):
    """
    :obj:`FloatFormat` provides IEEE 754 floating-point encoding formats in support of
    floating-point data types and floating-point emulation. A combination of Java float/double and
    :obj:`BigFloat` are used to facilitate floating-point operations.
    """

    @typing.type_check_only
    class SmallFloatData(java.lang.Object):
        """
        A small float (``float`` and ``double``) stand-in for ``BigFloat``
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, fracbits: typing.Union[jpype.JInt, int], expbits: typing.Union[jpype.JInt, int], kind: FloatKind, sign: typing.Union[jpype.JInt, int], unscaled: typing.Union[jpype.JLong, int], scale: typing.Union[jpype.JInt, int]):
            """
            Construct SmallFloat Data. (similar to BigFloat)
            
            :param jpype.JInt or int fracbits: number of fractional bits (positive non-zero value; includes additional
                        implied bit if relavent).
            :param jpype.JInt or int expbits: maximum number of bits in exponent
            :param FloatKind kind: the Kind, FINITE, INFINITE, ...
            :param jpype.JInt or int sign: +1 or -1
            :param jpype.JLong or int unscaled: the value's mantissa
            :param jpype.JInt or int scale: value's scale
            """

        def isZero(self) -> bool:
            ...

        @property
        def zero(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]
    maxValue: typing.Final[BigFloat]
    """
    A constant holding the largest positive finite value
    """

    minValue: typing.Final[BigFloat]
    """
    A constant holding the smallest positive normal value
    """


    @typing.overload
    def decodeBigFloat(self, encoding: typing.Union[jpype.JLong, int]) -> BigFloat:
        """
        Decode ``encoding`` to a BigFloat using this format.
         
        The method :meth:`decodeBigFloat(BigInteger) <.decodeBigFloat>` should be used for encodings larger than 8
        bytes.
        
        :param jpype.JLong or int encoding: the encoding
        :return: the decoded value as a BigFloat
        :rtype: BigFloat
        """

    @typing.overload
    def decodeBigFloat(self, encoding: java.math.BigInteger) -> BigFloat:
        ...

    def decodeHostFloat(self, encoding: typing.Union[jpype.JLong, int]) -> float:
        ...

    @typing.overload
    def getBigFloat(self, f: typing.Union[jpype.JFloat, float]) -> BigFloat:
        ...

    @typing.overload
    def getBigFloat(self, d: typing.Union[jpype.JDouble, float]) -> BigFloat:
        ...

    @typing.overload
    def getBigFloat(self, value: java.math.BigInteger) -> BigFloat:
        ...

    @typing.overload
    def getBigFloat(self, string: typing.Union[java.lang.String, str]) -> BigFloat:
        """
        Constructs a ``BigFloat`` initialized to the value represented by the specified decimal
        ``String``, as performed by :meth:`BigDecimal.BigDecimal(String) <BigDecimal.BigDecimal>`. Other values permitted
        are (case-insenstive): "NaN", "Infinity", "+Infinity", "-Infinity" (See :obj:`BigFloat.NAN`,
        :obj:`BigFloat.INFINITY`, :obj:`BigFloat.POSITIVE_INFINITY`,
        :obj:`BigFloat.NEGATIVE_INFINITY`).
        
        :param java.lang.String or str string: the string to be parsed.
        :return: value as a :obj:`BigFloat`
        :rtype: BigFloat
        :raises NullPointerException: if the string is null
        :raises java.lang.NumberFormatException: if the string parse fails.
        """

    @typing.overload
    def getBigFloat(self, value: decimal.Decimal) -> BigFloat:
        """
        Constructs a ``BigFloat`` initialized to the value represented by the specified
        ``BigDecimal``.
        
        :param decimal.Decimal value: the decimal value.
        :return: value as a :obj:`BigFloat`
        :rtype: BigFloat
        :raises NullPointerException: if the string is null
        :raises NumberFormatException: if the string parse fails.
        """

    def getBigInfinity(self, sgn: typing.Union[jpype.JBoolean, bool]) -> BigFloat:
        ...

    def getBigInfinityEncoding(self, sgn: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        ...

    def getBigNaN(self, sgn: typing.Union[jpype.JBoolean, bool]) -> BigFloat:
        ...

    def getBigNaNEncoding(self, sgn: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        ...

    def getBigZero(self, sgn: typing.Union[jpype.JBoolean, bool]) -> BigFloat:
        ...

    def getBigZeroEncoding(self, sgn: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        ...

    @typing.overload
    def getEncoding(self, host: typing.Union[jpype.JDouble, float]) -> int:
        ...

    @typing.overload
    def getEncoding(self, value: BigFloat) -> java.math.BigInteger:
        ...

    def getInfinityEncoding(self, sgn: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getMaxBigFloat(self) -> BigFloat:
        """
        Get the maximum finite :obj:`BigFloat` value for this format
        
        :return: maximum finite :obj:`BigFloat` value
        :rtype: BigFloat
        """

    def getMinBigFloat(self) -> BigFloat:
        """
        Get the minimum finite subnormal :obj:`BigFloat` value for this format
        
        :return: minimum finite subnormal :obj:`BigFloat` value
        :rtype: BigFloat
        """

    def getNaNEncoding(self, sgn: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getSize(self) -> int:
        ...

    def getZeroEncoding(self, sgn: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    @typing.overload
    def opAbs(self, a: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opAbs(self, a: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opAdd(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opAdd(self, a: java.math.BigInteger, b: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opCeil(self, a: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opCeil(self, a: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opDiv(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opDiv(self, a: java.math.BigInteger, b: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opEqual(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opEqual(self, a: java.math.BigInteger, b: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opFloat2Float(self, a: typing.Union[jpype.JLong, int], outformat: FloatFormat) -> int:
        ...

    @typing.overload
    def opFloat2Float(self, a: java.math.BigInteger, outformat: FloatFormat) -> java.math.BigInteger:
        ...

    @typing.overload
    def opFloor(self, a: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opFloor(self, a: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opInt2Float(self, a: typing.Union[jpype.JLong, int], sizein: typing.Union[jpype.JInt, int]) -> int:
        ...

    @typing.overload
    def opInt2Float(self, a: java.math.BigInteger, sizein: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        ...

    @typing.overload
    def opLess(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opLess(self, a: java.math.BigInteger, b: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opLessEqual(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opLessEqual(self, a: java.math.BigInteger, b: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opMult(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opMult(self, a: java.math.BigInteger, b: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opNan(self, a: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opNan(self, a: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opNeg(self, a: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opNeg(self, a: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opNotEqual(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opNotEqual(self, a: java.math.BigInteger, b: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opRound(self, a: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opRound(self, a: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opSqrt(self, a: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opSqrt(self, a: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opSub(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @typing.overload
    def opSub(self, a: java.math.BigInteger, b: java.math.BigInteger) -> java.math.BigInteger:
        ...

    @typing.overload
    def opTrunc(self, a: typing.Union[jpype.JLong, int], sizeout: typing.Union[jpype.JInt, int]) -> int:
        ...

    @typing.overload
    def opTrunc(self, a: java.math.BigInteger, sizeout: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        ...

    def round(self, bigFloat: BigFloat) -> java.math.BigDecimal:
        """
        Round ``bigFloat`` using this format's displayContext.
        
        :param BigFloat bigFloat: any BigFloat
        :return: a BigDecimal rounded according to this format's displayContext
        :rtype: java.math.BigDecimal
        """

    @staticmethod
    @typing.overload
    def toBigFloat(f: typing.Union[jpype.JFloat, float]) -> BigFloat:
        """
        Convert a native float to :obj:`BigFloat` using 4-byte IEEE 754 encoding
        
        :param jpype.JFloat or float f: a float
        :return: :obj:`BigFloat` equal to ``f``
        :rtype: BigFloat
        """

    @staticmethod
    @typing.overload
    def toBigFloat(d: typing.Union[jpype.JDouble, float]) -> BigFloat:
        """
        Convert a native double to :obj:`BigFloat` using 8-byte IEEE 754 encoding
        
        :param jpype.JDouble or float d: a double
        :return: :obj:`BigFloat` equal to ``f``
        :rtype: BigFloat
        """

    @typing.overload
    def toDecimalString(self, bigFloat: BigFloat) -> str:
        """
        Perform appropriate rounding and conversion to BigDecimal prior to generating a formatted
        decimal string of the specified BigFloat value.
        
        :param BigFloat bigFloat: value
        :return: decimal string representation
        :rtype: str
        """

    @typing.overload
    def toDecimalString(self, bigFloat: BigFloat, compact: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Perform appropriate rounding and conversion to BigDecimal prior to generating a formatted
        decimal string of the specified BigFloat value.
        
        :param BigFloat bigFloat: value
        :param jpype.JBoolean or bool compact: if true the precision will be reduced to a form which is still equivalent at
                    the binary encoding level for this format. Enabling this will incur additional
                    overhead.
        :return: decimal string representation
        :rtype: str
        """

    @property
    def naNEncoding(self) -> jpype.JLong:
        ...

    @property
    def bigInfinityEncoding(self) -> java.math.BigInteger:
        ...

    @property
    def zeroEncoding(self) -> jpype.JLong:
        ...

    @property
    def infinityEncoding(self) -> jpype.JLong:
        ...

    @property
    def bigNaN(self) -> BigFloat:
        ...

    @property
    def bigInfinity(self) -> BigFloat:
        ...

    @property
    def encoding(self) -> jpype.JLong:
        ...

    @property
    def bigZeroEncoding(self) -> java.math.BigInteger:
        ...

    @property
    def bigZero(self) -> BigFloat:
        ...

    @property
    def bigFloat(self) -> BigFloat:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def maxBigFloat(self) -> BigFloat:
        ...

    @property
    def bigNaNEncoding(self) -> java.math.BigInteger:
        ...

    @property
    def minBigFloat(self) -> BigFloat:
        ...



__all__ = ["FloatKind", "UnsupportedFloatFormatException", "BigFloat", "FloatFormatFactory", "FloatFormat"]
