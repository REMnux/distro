from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.math # type: ignore


class ScalarOverflowException(java.lang.RuntimeException):
    """
    
    A ScalarOverflowException indicates that some precision would
    be lost.  If the operation was signed, unused bits did not match the
    sign bit.  If the operation was unsigned, unsed bits were not all
    zero
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs a ScalarOverflowException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs a ScalarOverflowException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class Scalar(java.lang.Object):
    """
    The Scalar defines a immutable integer stored in an arbitrary number of bits (0..64), along
    with a preferred signed-ness attribute.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bitLength: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Construct a new signed scalar object.
        
        :param jpype.JInt or int bitLength: number of bits, valid values are 1..64, or 0 if value is also 0
        :param jpype.JLong or int value: value of the scalar, any bits that are set above bitLength will be ignored
        """

    @typing.overload
    def __init__(self, bitLength: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int], signed: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new scalar.
        
        :param jpype.JInt or int bitLength: number of bits, valid values are 1..64, or 0 if value is also 0
        :param jpype.JLong or int value: value of the scalar, any bits that are set above bitLength will be ignored
        :param jpype.JBoolean or bool signed: true for a signed value, false for an unsigned value.
        """

    def bitLength(self) -> int:
        """
        
        The size of this Scalar in bits.  This is constant for a
        Scalar.  It is not dependent on the particular value of the scalar.
        For example, a 16-bit Scalar should always return 16 regardless of the
        actual value held.
        
        
        :return: the width of this Scalar.
        :rtype: int
        """

    def byteArrayValue(self) -> jpype.JArray[jpype.JByte]:
        """
        
        Returns a byte array representing this Scalar.  The size of
        the byte array is the number of bytes required to hold the
        number of bits returned by ``bitLength()``.
        
        
        :return: a big-endian byte array containing the bits in this Scalar.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getBigInteger(self) -> java.math.BigInteger:
        """
        Returns the BigInteger representation of the value.
        
        :return: new BigInteger representation of the value
        :rtype: java.math.BigInteger
        """

    def getSignedValue(self) -> int:
        """
        Get the value as a signed long, where the highest bit of the value, if set, will be 
        extended to fill the remaining bits of a java long.
        
        :return: signed value
        :rtype: int
        """

    def getUnsignedValue(self) -> int:
        """
        Get the value as an unsigned long.
        
        :return: unsigned value
        :rtype: int
        """

    @typing.overload
    def getValue(self) -> int:
        """
        Returns the value in its preferred signed-ness.  See :meth:`getSignedValue() <.getSignedValue>` and
        :meth:`getUnsignedValue() <.getUnsignedValue>`.
        
        :return: value, as either signed or unsigned, depending on how this instance was created
        :rtype: int
        """

    @typing.overload
    def getValue(self, signednessOverride: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        :return: the value, using the specified signedness.  Equivalent to calling getSignedValue()
        or getUnsignedValue()
        :rtype: int
        
        
        :param jpype.JBoolean or bool signednessOverride: true for a signed value, false for an unsigned value
        """

    def isSigned(self) -> bool:
        """
        Returns true if scalar was created as a signed value
        
        :return: boolean true if this scalar was created as a signed value, false if was created as
        unsigned
        :rtype: bool
        """

    def testBit(self, n: typing.Union[jpype.JInt, int]) -> bool:
        """
        
        Returns true if and only if the designated bit is set to one.
        Computes ((this & (1<<n)) != 0).  Bits are numbered
        0..bitlength()-1 with 0 being the least significant bit.
        
        
        :param jpype.JInt or int n: the bit to test.
        :return: true if and only if the designated bit is set to one.
        :rtype: bool
        :raises IndexOutOfBoundsException: if n >= bitLength().
        """

    def toString(self, radix: typing.Union[jpype.JInt, int], zeroPadded: typing.Union[jpype.JBoolean, bool], showSign: typing.Union[jpype.JBoolean, bool], pre: typing.Union[java.lang.String, str], post: typing.Union[java.lang.String, str]) -> str:
        """
        
        Get a String representing this Scalar using the
        format defined by radix.
        
        
        :param jpype.JInt or int radix: an integer base to use in representing the number
        (only 2, 8, 10, 16 are valid).  If 10 is specified, all
        remaining parameters are ignored.
        :param jpype.JBoolean or bool zeroPadded: a boolean which if true will have the
        number left padded with 0 to the width necessary to hold
        the maximum value.
        :param jpype.JBoolean or bool showSign: if true the '-' sign will be prepended for negative values, else
        value will be treated as an unsigned value and output without a sign.
        :param java.lang.String or str pre: a String to append after the sign (if signed) but before
        the digits.
        :param java.lang.String or str post: a String to append after the digits.
        :return: a String representation of this scalar.
        :rtype: str
        :raises IllegalArgumentException: If radix is not valid.
        """

    @property
    def signed(self) -> jpype.JBoolean:
        ...

    @property
    def bigInteger(self) -> java.math.BigInteger:
        ...

    @property
    def unsignedValue(self) -> jpype.JLong:
        ...

    @property
    def signedValue(self) -> jpype.JLong:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...



__all__ = ["ScalarOverflowException", "Scalar"]
