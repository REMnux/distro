from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.processors.sleigh.expression
import ghidra.app.plugin.processors.sleigh.symbol
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class LeftShiftExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.LeftShiftExpression]):
    """
    Solves expressions of the form ``A << B``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PlusExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.PlusExpression]):
    """
    Solves expressions of the form ``A + B``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MaskedLong(java.lang.Comparable[MaskedLong]):
    """
    A ``64``-bit value where each bit is ``0``, ``1``, or ``x`` (undefined)
    """

    class_: typing.ClassVar[java.lang.Class]
    ZERO: typing.Final[MaskedLong]
    UNKS: typing.Final[MaskedLong]
    ONES: typing.Final[MaskedLong]

    def add(self, that: MaskedLong) -> MaskedLong:
        """
        Compute the arithmetic sum of this and another masked long
        
        :param MaskedLong that: the other masked long.
        :return: the result.
        :rtype: MaskedLong
        """

    @typing.overload
    def agrees(self, that: MaskedLong) -> bool:
        """
        Checks if this and another masked long agree
         
         
        
        Two masked longs agree iff their corresponding defined bit positions are equal. Where either
        or both positions are undefined, no check is applied. In the case that both masked longs are
        fully-defined, this is the same as an equality check on the values.
        
        :param MaskedLong that: the other masked long.
        :return: true if this and that agree.
        :rtype: bool
        """

    @typing.overload
    def agrees(self, that: typing.Union[jpype.JLong, int]) -> bool:
        """
        Checks if this and a long agree
         
         
        
        The masked long agrees with the given long iff the masked long's defined bit positions agree
        with the corresponding bit positions in the given long. Where there are undefined bits, no
        check is applied. In the case that the masked long is fully-defined, this is the same as an
        equality check on the value.
        
        :param jpype.JLong or int that: the long
        :return: true if this and that agree.
        :rtype: bool
        """

    @typing.overload
    def agrees(self, that: java.lang.Object) -> bool:
        """
        Check if this and another object agree
        
        :param java.lang.Object that: a :obj:`MaskedLong` or :obj:`Long` to check.
        :return: true if this and that agree.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.agrees(MaskedLong)`
        
            | :obj:`.agrees(long)`
        """

    def and_(self, that: MaskedLong) -> MaskedLong:
        """
        Compute the bitwise AND of this and another masked long
         
         
        
        To handle unknown bits, the result is derived from the following truth table:
         
        ``  0 x 1 <= A (this)0 0 0 0x 0 x x1 0 x 1^B (that)``
        
        :param MaskedLong that: the other masked long (``B``).
        :return: the result.
        :rtype: MaskedLong
        """

    def byteSwap(self, n: typing.Union[jpype.JInt, int]) -> MaskedLong:
        """
        Reverse the least significant ``n`` bytes
         
         
        
        This interprets the bits as an ``n``-byte value and changes the endianness. Any bits
        outside of the interpretation are truncated, i.e., become unknown.
        
        :param jpype.JInt or int n: the size, in bytes, of the interpreted value.
        :return: the result.
        :rtype: MaskedLong
        """

    def combine(self, that: MaskedLong) -> MaskedLong:
        """
        Combine this and another masked long into one, by taking defined bits from either
         
         
        
        If this masked long agrees with the other, then the two are combined. For each bit position
        in the result, the defined bit from either corresponding position is taken. If neither is
        defined, then the position is undefined in the result. If both are defined, they must agree.
        
        :param MaskedLong that: the other masked long
        :return: the combined masked long
        :rtype: MaskedLong
        :raises SolverException: if this and the other masked long disagree
        """

    def compareTo(self, that: MaskedLong) -> int:
        """
        "Compare" two masked longs
         
         
        
        This is not meant to reflect a numerical comparison. Rather, this is just to impose an
        ordering for the sake of storing these in sorted collections.
        """

    def divideSigned(self, that: MaskedLong) -> MaskedLong:
        ...

    def divideUnsigned(self, that: MaskedLong) -> MaskedLong:
        """
        Compute the unsigned arithmetic quotient: this masked long divided by another
        
        :param MaskedLong that: the other masked long.
        :return: the result.
        :rtype: MaskedLong
        """

    def equals(self, other: java.lang.Object) -> bool:
        """
        Check for equality
         
         
        
        This will only return true if the other object is a masked long, even if this one is
        fully-defined, and the value is equal to a given long (or :obj:`Long`). The other masked
        long must have the same mask and value to be considered equal. For other sorts of "equality"
        checks, see :meth:`agrees(Object) <.agrees>` and friends.
        """

    def fillMask(self) -> MaskedLong:
        """
        Set all undefined bits to 0
        
        :return: the result
        :rtype: MaskedLong
        """

    @staticmethod
    def fromLong(val: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Create a fully-defined value from the bits of a long
        
        :param jpype.JLong or int val: the value to take
        :return: the constructed masked long
        :rtype: MaskedLong
        """

    @staticmethod
    def fromMaskAndValue(msk: typing.Union[jpype.JLong, int], val: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Create a masked value from a mask and a long
         
         
        
        Any positions in ``msk`` set to 0 create an ``x`` in the corresponding position of
        the result. Otherwise, the position takes the corresponding bit from ``val``.
        
        :param jpype.JLong or int msk: the mask
        :param jpype.JLong or int val: the value
        :return: the constructed masked long
        :rtype: MaskedLong
        """

    def getMask(self) -> int:
        """
        Get the mask as a long
         
         
        
        Positions with a defined bit are ``1``; positions with an undefined bit are ``0``.
        
        :return: the mask as a long
        :rtype: int
        """

    def invAnd(self, that: MaskedLong) -> MaskedLong:
        """
        Solves the expression ``A & B = C, for B, given C and A``
         
         
        
        To handle unknown bits, the solution is derived from the following truth table, where
        ``*`` indicates no solution:
         
        ``  0 x 1 <= A (that)0 x x 0x x x x1 * 1 1^B (this)``
        
        :param MaskedLong that: the other masked long (``B``).
        :return: the result.
        :rtype: MaskedLong
        :raises SolverException: if no solution exists.
        """

    def invMultiplyUnsigned(self, that: MaskedLong) -> MaskedLong:
        """
        Compute the arithmetic quotient as a solution to unsigned multiplication
         
         
        
        This is slightly different than :meth:`divideUnsigned(MaskedLong) <.divideUnsigned>` in its treatment of
        unknowns.
        
        :param MaskedLong that: the known factor
        :return: a solution to that*x == this, if possible
        :rtype: MaskedLong
        :raises SolverException:
        """

    def invOr(self, that: MaskedLong) -> MaskedLong:
        """
        Solves the expression A | B = C, for B, given C and A
         
         
        
        To handle unknown bits, the solution is derived from the following truth table, where
        ``*`` indicates no solution:
         
        ``  0 x 1 <= A (that)0 0 0 *x x x x1 1 x x^B (this)``
        
        :param MaskedLong that: the other masked long (``B``).
        :return: the result.
        :rtype: MaskedLong
        :raises SolverException: if not solution exists.
        """

    @typing.overload
    def invShiftLeft(self, n: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Invert a left shift of ``n`` positions, that is shift right
         
         
        
        This is different from a normal shift right, in that it inserts unknowns at the left. The
        normal right shift inserts zeros or sign bits. Additionally, if any ones would fall off the
        right, the inversion is undefined.
        
        :param jpype.JLong or int n: the number of positions
        :return: the result
        :rtype: MaskedLong
        :raises SolverException: if the inversion is undefined
        """

    @typing.overload
    def invShiftLeft(self, n: MaskedLong) -> MaskedLong:
        """
        Invert a left shift of ``n`` positions, that is shift right
         
         
        
        This is different from a normal shift right, in that it inserts unknowns at the left. The
        normal right shift inserts zeros or sign bits. Additionally, if any ones would fall off the
        right, the inversion is undefined.
        
        :param MaskedLong n: the number of positions
        :return: the result
        :rtype: MaskedLong
        :raises SolverException: if the inversion is undefined
        """

    @typing.overload
    def invShiftRight(self, n: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Invert an arithmetic right shift of ``n`` positions, that is shift left
         
         
        
        This is different from a normal shift left, in that it inserts unknowns at the right. The
        normal left shift inserts zeros. Additionally, all bits that fall off the left must match the
        resulting sign bit, or else the inversion is undefined.
        
        :param jpype.JLong or int n: the number of positions
        :return: the result
        :rtype: MaskedLong
        :raises SolverException: if the inversion is undefined
        """

    @typing.overload
    def invShiftRight(self, n: MaskedLong) -> MaskedLong:
        """
        Invert an arithmetic right shift of ``n`` positions, that is shift left
         
         
        
        This is different from a normal shift left, in that it inserts unknowns at the right. The
        normal left shift inserts zeros. Additionally, all bits that fall off the left must match the
        resulting sign bit, or else the inversion is undefined.
        
        :param MaskedLong n: the number of positions
        :return: the result
        :rtype: MaskedLong
        :raises SolverException: if the inversion is undefined
        """

    @typing.overload
    def invShiftRightLogical(self, n: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Invert a logical right shift of ``n`` positions, that is shift left
         
         
        
        This is different from a normal shift left, in that it inserts unknowns at the right. The
        normal left shift inserts zeros. Additionally, if any ones would fall off the left, the
        inversion is undefined.
        
        :param jpype.JLong or int n: the number of positions
        :return: the result
        :rtype: MaskedLong
        :raises SolverException: if the inversion is undefined
        """

    @typing.overload
    def invShiftRightLogical(self, n: MaskedLong) -> MaskedLong:
        """
        Invert a logical right shift of ``n`` positions, that is shift left
         
         
        
        This is different from a normal shift left, in that it inserts unknowns at the right. The
        normal left shift inserts zeros. Additionally, if any ones would fall off the left, the
        inversion is undefined.
        
        :param MaskedLong n: the number of positions
        :return: the result
        :rtype: MaskedLong
        :raises SolverException: if the inversion is undefined
        """

    def isFullyDefined(self) -> bool:
        """
        True iff there are no undefined bits
        
        :return: true if fully-defined, false otherwise
        :rtype: bool
        """

    def isFullyUndefined(self) -> bool:
        """
        True iff there are no defined bits
        
        :return: true if full-undefined, false otherwise
        :rtype: bool
        """

    def isInRange(self, max: typing.Union[jpype.JLong, int], signed: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if the masked value falls within a given range
         
         
        
        The range is defined by a maximum and a signedness. The maximum must be one less than a
        positive power of 2. In other words, it defines a maximum number of bits, including the sign
        bit if applicable.
         
         
        
        The defined bits of this masked long are then checked to fall in the given range. The
        effective value is derived by sign/zero extending the value according to its mask. In
        general, if any ``1`` bits exist outside of the given max, the value is rejected, unless
        that ``1`` is purely a result of signedness.
        
        :param jpype.JLong or int max: the maximum value, taken as an unsigned long.
        :param jpype.JBoolean or bool signed: true to interpret the masked value as signed.
        :return: true if the masked value "fits" into the given range.
        :rtype: bool
        """

    def longValue(self) -> int:
        """
        Obtain the value as a long, where all undefined bits are treated as ``0``
        
        :return: the value as a long
        :rtype: int
        """

    def mask(self, mask: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Apply an additional mask to this masked long
         
         
        
        Any ``0`` bit in ``msk`` will result in an undefined bit in the result. ``1``
        bits result in a copy of the corresponding bit in the result.
        
        :param jpype.JLong or int mask: the mask to apply
        :return: the result.
        :rtype: MaskedLong
        """

    def multiply(self, that: MaskedLong) -> MaskedLong:
        """
        Compute the arithmetic product of this and another masked long
        
        :param MaskedLong that: the other masked long.
        :return: the result.
        :rtype: MaskedLong
        """

    def negate(self) -> MaskedLong:
        """
        Negate the value
        
        :return: the result.
        :rtype: MaskedLong
        """

    def not_(self) -> MaskedLong:
        """
        Compute the bitwise NOT
         
         
        
        To handle unknown bits, the result is derived from the following truth table:
         
        ``0 x 1 <= A (this)1 x 0``
        
        :return: the result.
        :rtype: MaskedLong
        """

    def or_(self, that: MaskedLong) -> MaskedLong:
        """
        Compute the bitwise OR of this and another masked long
         
         
        
        To handle unknown bits, the result is derived from the following truth table:
         
        ``  0 x 1 <= A (this)0 0 x 1x x x 11 1 1 1^B (that)``
        
        :param MaskedLong that: the other masked long (``B``).
        :return: the result.
        :rtype: MaskedLong
        """

    @typing.overload
    def shiftCircular(self, n: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], dir: typing.Union[jpype.JInt, int]) -> MaskedLong:
        """
        Shift ``size`` bits @{code n) positions circularly in a given direction
        
         
        
        The shifted bits are the least significant ``size`` bits. The remaining bits are
        unaffected.
        
        :param jpype.JLong or int n: the number of positions
        :param jpype.JInt or int size: the number of bits (least significant) to include in the shift
        :param jpype.JInt or int dir: the direction to shift (0 for left, 1 for right)
        :return: the result
        :rtype: MaskedLong
        """

    @typing.overload
    def shiftCircular(self, n: MaskedLong, size: typing.Union[jpype.JInt, int], dir: typing.Union[jpype.JInt, int]) -> MaskedLong:
        """
        Shift ``size`` bits @{code n) positions circularly in a given direction
        
         
        
        The shifted bits are the least significant ``size`` bits. The remaining bits are
        unaffected.
        
        :param MaskedLong n: the number of positions
        :param jpype.JInt or int size: the number of bits (least significant) to include in the shift
        :param jpype.JInt or int dir: the direction to shift (0 for left, 1 for right)
        :return: the result
        :rtype: MaskedLong
        """

    @typing.overload
    def shiftLeft(self, n: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Shift the bits @{code n} positions left
         
         
        
        This implements both a signed and unsigned shift.
        
        :param jpype.JLong or int n: the number of positions.
        :return: the result.
        :rtype: MaskedLong
        """

    @typing.overload
    def shiftLeft(self, n: MaskedLong) -> MaskedLong:
        """
        Shift the bits ``n`` positions left
         
         
        
        This implements both a signed and unsigned shift.
        
        :param MaskedLong n: the number of positions.
        :return: the result.
        :rtype: MaskedLong
        """

    @typing.overload
    def shiftRight(self, n: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Shift the bits arithmetically ``n`` positions right
         
         
        
        This implements a signed shift.
        
        :param jpype.JLong or int n: the number of positions.
        :return: the result.
        :rtype: MaskedLong
        """

    @typing.overload
    def shiftRight(self, n: MaskedLong) -> MaskedLong:
        """
        Shift the bits arithmetically ``n`` positions right
         
         
        
        This implements a signed shift.
        
        :param MaskedLong n: the number of positions.
        :return: the result.
        :rtype: MaskedLong
        """

    @typing.overload
    def shiftRightLogical(self, n: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Shift the bits logically ``n`` positions right
         
         
        
        This implements an unsigned shift.
        
        :param jpype.JLong or int n: the number of positions.
        :return: the result.
        :rtype: MaskedLong
        """

    @typing.overload
    def shiftRightLogical(self, n: MaskedLong) -> MaskedLong:
        """
        Shift the bits logically ``n`` positions right
         
         
        
        This implements an unsigned shift.
        
        :param MaskedLong n: the number of positions.
        :return: the result.
        :rtype: MaskedLong
        """

    def shiftRightPositional(self, n: typing.Union[jpype.JLong, int]) -> MaskedLong:
        """
        Shift the bits positionally ``n`` positions right
         
         
        
        This fills the left with unknown bits
        
        :param jpype.JLong or int n: 
        :return: 
        :rtype: MaskedLong
        """

    @typing.overload
    def signExtend(self) -> MaskedLong:
        """
        Sign extend the masked value, according to its mask, to a full long
         
         
        
        The leftmost defined bit is taken as the sign bit, and extended to the left.
        
        :return: the sign-extended masked long
        :rtype: MaskedLong
        """

    @typing.overload
    def signExtend(self, n: typing.Union[jpype.JInt, int]) -> MaskedLong:
        """
        Sign extend the masked value as if of the given size in bits, to a full long
        
        :param jpype.JInt or int n: the number of bits to take (right-to-left)
        :return: the sign-extended masked long
        :rtype: MaskedLong
        """

    def subtract(self, that: MaskedLong) -> MaskedLong:
        """
        Compute the arithmetic difference: this masked long minus another
        
        :param MaskedLong that: the other masked long.
        :return: the result.
        :rtype: MaskedLong
        """

    def unknownExtend(self, n: typing.Union[jpype.JInt, int]) -> MaskedLong:
        """
        Mask out all but the lowest ``n`` bits of the value
        
        :param jpype.JInt or int n: the number of bits to take (right-to-left)
        :return: the unknown-extended masked long
        :rtype: MaskedLong
        """

    def xor(self, that: MaskedLong) -> MaskedLong:
        """
        Compute the bitwise XOR of this and another masked long
         
         
        
        To handle unknown bits, the result is derived from the following truth table:
         
        ``  0 x 1 <= A (this)0 0 x 1x x x x1 1 x 0^B (that)``
        
        :param MaskedLong that: the other masked long (``B``).
        :return: the result.
        :rtype: MaskedLong
        """

    @typing.overload
    def zeroExtend(self) -> MaskedLong:
        """
        Zero extend the masked value, according to its mask, to a full long
         
         
        
        All bits to the left of the leftmost defined bit are set to 0.
        
        :return: the zero-extended masked long
        :rtype: MaskedLong
        """

    @typing.overload
    def zeroExtend(self, n: typing.Union[jpype.JInt, int]) -> MaskedLong:
        """
        Zero extend the masked value as if of the given size in bits, to a full long
        
        :param jpype.JInt or int n: the number of bits to take (right-to-left)
        :return: the zero-extended masked long
        :rtype: MaskedLong
        """

    @property
    def fullyUndefined(self) -> jpype.JBoolean:
        ...

    @property
    def fullyDefined(self) -> jpype.JBoolean:
        ...


class MinusExpressionSolver(AbstractUnaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.MinusExpression]):
    """
    Solves expressions of the form ``-A``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SolverHint(java.lang.Object):
    """
    A type for solver hints
     
     
    
    Hints inform sub-solvers of the techniques already being applied by the calling solvers. This
    helps prevent situations where, e.g., two multiplication solvers (applied to repeated or nested
    multiplication) both attempt to synthesize new goals for repetition. This sort of expression is
    common when decoding immediates in the AArch64 specification.
     
     
    
    Using an interface implemented by an enumeration (instead of just using the enumeration directly)
    eases expansion by extension without modifying the core code.
    
    
    .. seealso::
    
        | :obj:`DefaultSolverHint`
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def with_(set: java.util.Set[SolverHint], *plus: SolverHint) -> java.util.Set[SolverHint]:
        ...


class MultExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.MultExpression]):
    """
    Solves expressions of the form ``A * B``
    """

    @typing.type_check_only
    class SolverFunc(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def solve(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
            ...


    @typing.type_check_only
    class ResultTracker(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ConstantValueSolver(AbstractExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.ConstantValue]):
    """
    "Solves" constant expressions
     
     
    
    Essentially, this either evaluates successfully when asked for a constant value, or checks that
    the goal is equal to the constant. Otherwise, there is no solution.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class XorExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.XorExpression]):
    """
    Solves expressions of the form ``A $xor B``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class StartInstructionValueSolver(AbstractExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.StartInstructionValue]):
    """
    "Solves" expression of ``inst_start``
     
     
    
    Works like the constant solver, but takes the value of ``inst_start``, which is given by the
    assembly address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NotExpressionSolver(AbstractUnaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.NotExpression]):
    """
    Solves expressions of the form ``~A``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OrExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.OrExpression]):
    """
    Solves expressions of the form ``A | B``
    """

    @typing.type_check_only
    class Matchers(ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher.Context):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Next2InstructionValueSolver(AbstractExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.Next2InstructionValue]):
    """
    "Solves" expressions of ``inst_next2``
     
     
    
    Works like the constant solver, but takes the value of ``inst_next``, which is given by the
    assembly address and the resulting instruction length.
     
     
    
    **NOTE:** This solver requires backfill, since the value of ``inst_next2`` is not known
    until possible prefixes have been considered.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SubExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.SubExpression]):
    """
    Solves expressions of the form ``A - B``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AndExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.AndExpression]):
    """
    Solves expressions of the form ``A & B``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ContextFieldSolver(AbstractExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.ContextField]):
    """
    Solves expressions of a context register field
     
     
    
    Essentially, this just encodes the goal into the field, if it can be represented in the given
    space and format. Otherwise, there is no solution.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OperandValueSolver(AbstractExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.OperandValue]):
    """
    Solves expressions of an operand value
     
     
    
    These are a sort of named sub-expression, but they may also specify a shift in encoding.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getDefiningExpression(sym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression:
        """
        Obtains the "defining expression"
         
         
        
        This is either the symbol's assigned defining expression, or the expression associated with
        its defining symbol.
        
        :return: the defining expression, or null if neither is available
        :rtype: ghidra.app.plugin.processors.sleigh.expression.PatternExpression
        """


class SolverException(java.lang.Exception):
    """
    An exception that indicates no solution is possible
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class TokenFieldSolver(AbstractExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.TokenField]):
    """
    Solves expressions of a token (instruction encoding) field
     
     
    
    Essentially, this just encodes the goal into the field, if it can be represented in the given
    space and format. Otherwise, there is no solution.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DivExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.DivExpression]):
    """
    Solves expressions of the form ``A / B``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractExpressionSolver(java.lang.Object, typing.Generic[T]):
    """
    The root type of an expression solver
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tcls: java.lang.Class[T]):
        """
        Construct a solver that can solve expression of the given type
        
        :param java.lang.Class[T] tcls: the type of expressions it can solve
        """

    def getInstructionLength(self, exp: T) -> int:
        """
        Determines the length of the subconstructor that would be returned had the expression not
        depended on an undefined symbol.
         
         
        
        This is used by the backfilling process to ensure values are written to the correct offset
        
        :param T exp: the expression
        :return: the length of filled in token field(s).
        :rtype: int
        """

    def getValue(self, exp: T, vals: collections.abc.Mapping, cur: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> MaskedLong:
        """
        Attempt to get a constant value for the expression
        
        :param T exp: the expression
        :param collections.abc.Mapping vals: values of defined symbols
        :return: the constant value, or null if it depends on a variable
        :rtype: MaskedLong
        :raises NeedsBackfillException: if the expression refers to an undefined symbol
        """

    def solve(self, factory: ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory[typing.Any, typing.Any], exp: T, goal: MaskedLong, vals: collections.abc.Mapping, cur: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, hints: java.util.Set[SolverHint], description: typing.Union[java.lang.String, str]) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Attempt to solve an expression for a given value
        
        :param T exp: the expression to solve
        :param MaskedLong goal: the desired value of the expression
        :param collections.abc.Mapping vals: values of defined symbols
        :param java.util.Set[SolverHint] hints: describes techniques applied by calling solvers
        :param java.lang.String or str description: the description to give to resolved solutions
        :return: the resolution
        :rtype: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution
        :raises NeedsBackfillException: if the expression refers to an undefined symbol
        """

    def valueForResolution(self, exp: T, vals: collections.abc.Mapping, rc: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> MaskedLong:
        """
        Compute the value of the expression given the (possibly-intermediate) resolution
        
        :param T exp: the expression to evaluate
        :param collections.abc.Mapping vals: values of defined symbols
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns rc: the resolution on which to evaluate it
        :return: the result
        :rtype: MaskedLong
        """

    @property
    def instructionLength(self) -> jpype.JInt:
        ...


class AbstractUnaryExpressionSolver(AbstractExpressionSolver[T], typing.Generic[T]):
    """
    A solver that handles expressions of the form ``[OP]A``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tcls: java.lang.Class[T]):
        ...

    def compute(self, val: MaskedLong) -> MaskedLong:
        """
        Compute the result of applying the operator to the given value
        
        :param MaskedLong val: the input value
        :return: the result
        :rtype: MaskedLong
        """

    def computeInverse(self, goal: MaskedLong) -> MaskedLong:
        """
        Compute the input value given that the result is known
         
         
        
        **NOTE:** Assumes an involution by default
        
        :param MaskedLong goal: the result
        :return: the input value solution
        :rtype: MaskedLong
        """


class AbstractBinaryExpressionSolver(AbstractExpressionSolver[T], typing.Generic[T]):
    """
    A solver that handles expressions of the form ``A [OP] B``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tcls: java.lang.Class[T]):
        ...

    def compute(self, lval: MaskedLong, rval: MaskedLong) -> MaskedLong:
        """
        Compute the result of applying the operator to the two given values
        
        :param MaskedLong lval: the left-hand-side value
        :param MaskedLong rval: the right-hand-side value
        :return: the result
        :rtype: MaskedLong
        """

    def computeLeft(self, rval: MaskedLong, goal: MaskedLong) -> MaskedLong:
        """
        Compute the left-hand-side value given that the result and the right are known
        
        :param MaskedLong rval: the right-hand-side value
        :param MaskedLong goal: the result
        :return: the left-hand-side value solution
        :rtype: MaskedLong
        :raises SolverException: if the expression cannot be solved
        """

    def computeRight(self, lval: MaskedLong, goal: MaskedLong) -> MaskedLong:
        """
        Compute the right-hand-side value given that the result and the left are known
         
         
        
        **NOTE:** Assumes commutativity by default
        
        :param MaskedLong lval: the left-hand-side value
        :param MaskedLong goal: the result
        :return: the right-hand-side value solution
        :rtype: MaskedLong
        :raises SolverException: if the expression cannot be solved
        """


class DefaultSolverHint(java.lang.Enum[DefaultSolverHint], SolverHint):
    """
    A set of built-in :obj:`SolverHint`s
    """

    class_: typing.ClassVar[java.lang.Class]
    GUESSING_REPETITION: typing.Final[DefaultSolverHint]
    """
    A multiplication solver is synthesizing goals with repetition
    """

    GUESSING_CIRCULAR_SHIFT_AMOUNT: typing.Final[DefaultSolverHint]
    """
    A boolean ``or`` solver which matches a circular shift is solving the value having
    guessed a shift
    """

    GUESSING_LEFT_SHIFT_AMOUNT: typing.Final[DefaultSolverHint]
    """
    A left-shift solver is solving the value having guessed a shift
    """

    GUESSING_RIGHT_SHIFT_AMOUNT: typing.Final[DefaultSolverHint]
    """
    A right-shift solver is solving the value having guessed a shift
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DefaultSolverHint:
        ...

    @staticmethod
    def values() -> jpype.JArray[DefaultSolverHint]:
        ...


class NeedsBackfillException(SolverException):
    """
    An exception to indicate that the solution of an expression is not yet known
     
     
    
    Furthermore, it cannot be determined whether or not the expression is even solvable. When this
    exception is thrown, a backfill record is placed on the encoded resolution indicating that the
    resolver must attempt to solve the expression again, once the encoding is otherwise complete.
    This is needed, most notably, when an encoding depends on the address of the *next*
    instruction, because the length of the current instruction is not known until resolution has
    finished.
     
     
    
    Backfill becomes a possibility when an expression depends on a symbol that is not (yet) defined.
    Thus, as a matter of good record keeping, the exception takes the name of the missing symbol.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbol: typing.Union[java.lang.String, str]):
        """
        Construct a backfill exception, resulting from the given missing symbol name
        
        :param java.lang.String or str symbol: the missing symbol name
        """

    def getSymbol(self) -> str:
        """
        Retrieve the missing symbol name from the original solution attempt
        
        :return: the missing symbol name
        :rtype: str
        """

    @property
    def symbol(self) -> java.lang.String:
        ...


class EndInstructionValueSolver(AbstractExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.EndInstructionValue]):
    """
    "Solves" expressions of ``inst_next``
     
     
    
    Works like the constant solver, but takes the value of ``inst_next``, which is given by the
    assembly address and the resulting instruction length.
     
     
    
    **NOTE:** This solver requires backfill, since the value of ``inst_next`` is not known
    until possible prefixes have been considered.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RecursiveDescentSolver(java.lang.Object):
    """
    This singleton class seeks solutions to :obj:`PatternExpression`s
     
     
    
    It is rather naive. It does not perform algebraic transformations. Instead, it attempts to fold
    constants, assuming there is a single variable in the expression, modifying the goal as it
    descends toward that variable. If it finds a variable, i.e., token or context field, it encodes
    the solution, positioned in the field. If the expression is constant, it checks that the goal
    agrees. If not, an error is returned. There are some common cases where it is forced to solve
    expressions involving multiple variables. Those cases are addressed in the derivatives of
    :obj:`AbstractBinaryExpressionSolver` where the situation can be detected. One common example is
    field concatenation using the ``(A << 4) | B`` pattern.
     
     
    
    TODO: Perhaps this whole mechanism ought to just be factored directly into
    :obj:`PatternExpression`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getInstructionLength(self, exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression) -> int:
        """
        Determine the length of the instruction part of the encoded solution to the given expression
         
         
        
        This is used to keep operands in their appropriate position when backfilling becomes
        applicable. Normally, the instruction length is taken from the encoding of a solution, but if
        the solution cannot be determined yet, the instruction length must still be obtained.
         
         
        
        The length can be determined by finding token fields in the expression.
        
        :param ghidra.app.plugin.processors.sleigh.expression.PatternExpression exp: the expression, presumably containing a token field
        :return: the anticipated length, in bytes, of the instruction encoding
        :rtype: int
        """

    @staticmethod
    def getSolver() -> RecursiveDescentSolver:
        """
        Obtain an instance of the naive solver
        
        :return: the singleton instance
        :rtype: RecursiveDescentSolver
        """

    def solve(self, factory: ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory[typing.Any, typing.Any], exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, goal: MaskedLong, vals: collections.abc.Mapping, cur: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, description: typing.Union[java.lang.String, str]) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Solve a given expression, given a masked-value goal
         
         
        
        From a simplified perspective, we need only the expression and the desired value to solve it.
        Generally speaking, the expression may only contain a single field, and the encoded result
        specifies the bits of the solved field. It must be absorbed into the overall assembly
        pattern.
         
         
        
        More realistically, these expressions may depend on quite a bit of extra information. For
        example, PC-relative encodings (i.e., those involving ``inst_start`` or
        ``inst_next``, need to know the starting address of the resulting instruction. ``inst_start`` must be provided to the solver by the assembler. ``inst_next`` cannot be
        known until the instruction length is known. Thus, expressions using it always result in a
        :obj:`NeedsBackfillException`. The symbols, when known, are provided to the solver via the
        ``vals`` parameter.
        
        :param ghidra.app.plugin.processors.sleigh.expression.PatternExpression exp: the expression to solve
        :param MaskedLong goal: the desired output (modulo a mask) of the expression
        :param collections.abc.Mapping vals: any defined symbols (usually ``inst_start``, and ``inst_next``)
        :param java.lang.String or str description: a description to attached to the encoded solution
        :return: the encoded solution
        :rtype: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution
        :raises NeedsBackfillException: a solution may exist, but a required symbol is missing
        """

    def valueForResolution(self, exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, vals: collections.abc.Mapping, rc: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> MaskedLong:
        """
        Compute the value of an expression given a (possibly-intermediate) resolution
        
        :param ghidra.app.plugin.processors.sleigh.expression.PatternExpression exp: the expression to evaluate
        :param collections.abc.Mapping vals: values of defined symbols
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns rc: the resolution on which to evaluate it
        :return: the result
        :rtype: MaskedLong
        """

    @property
    def instructionLength(self) -> jpype.JInt:
        ...


class RightShiftExpressionSolver(AbstractBinaryExpressionSolver[ghidra.app.plugin.processors.sleigh.expression.RightShiftExpression]):
    """
    Solves expressions of the form ``A >> B``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["LeftShiftExpressionSolver", "PlusExpressionSolver", "MaskedLong", "MinusExpressionSolver", "SolverHint", "MultExpressionSolver", "ConstantValueSolver", "XorExpressionSolver", "StartInstructionValueSolver", "NotExpressionSolver", "OrExpressionSolver", "Next2InstructionValueSolver", "SubExpressionSolver", "AndExpressionSolver", "ContextFieldSolver", "OperandValueSolver", "SolverException", "TokenFieldSolver", "DivExpressionSolver", "AbstractExpressionSolver", "AbstractUnaryExpressionSolver", "AbstractBinaryExpressionSolver", "DefaultSolverHint", "NeedsBackfillException", "EndInstructionValueSolver", "RecursiveDescentSolver", "RightShiftExpressionSolver"]
