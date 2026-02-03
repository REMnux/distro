from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh.expression
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class OperandValueMatcher(AbstractExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.OperandValue]):
    """
    A matcher for a constructor's operand value, constrained by its defining expression
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, defMatcher: ExpressionMatcher[typing.Any]):
        ...


class ConstantValueMatcher(AbstractExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.ConstantValue]):
    """
    A matcher for a given constant value
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: typing.Union[jpype.JLong, int]):
        ...


class UnaryExpressionMatcher(AbstractExpressionMatcher[T], typing.Generic[T]):
    """
    A matcher for a unnary expression
     
     
    
    If the required type matches, the matching descends to the child operand.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ops: java.util.Set[java.lang.Class[T]], unaryMatcher: ExpressionMatcher[typing.Any]):
        ...

    @typing.overload
    def __init__(self, cls: java.lang.Class[T], unaryMatcher: ExpressionMatcher[typing.Any]):
        ...


class ExpressionMatcher(java.lang.Object, typing.Generic[T]):
    """
    A matcher for a form of patten expression
    
     
    
    Some solvers may need to apply sophisticated heuristics to recognize certain forms that commonly
    occur in pattern expressions. These can certainly be programmed manually, but for many cases, the
    form recognition can be accomplished by describing the form as an expression matcher. For a
    shorter syntax to construct such matchers. See :obj:`Context`.
    """

    class Context(java.lang.Object):
        """
        A context for defining expression matcher succinctly
         
         
        
        Implementations of this interface have easy access to factory methods for each kind of
        :obj:`PatternExpression`. Additionally, the class itself provide a convenient container for
        saving important sub-matchers, so that important sub-expression can be readily retrieved. For
        example:
         
        ``static class MyMatchers implements ExpressionMatcher.Context {    ExpressionMatcher<ConstantValue> shamt = var(ConstantValue.class);    ExpressionMatcher<LeftShiftExpression> exp = shl(var(), shamt);}static final MyMatchers MATCHERS = new MyMatchers();public long getConstantShift(PatternExpression expression) {    Map<ExpressionMatcher<?>, PatternExpression> result = MATCHERS.exp.match(expression);    if (result == null) {        return -1;    }    return MATCHERS.shamt.get(result).getValue();}``
         
         
        
        Saving a sub-matcher to a field (as in the example) also permits that sub-matcher to appear
        in multiple places. In that case, the sub-matcher must match identical expressions wherever
        it appears. For example, if ``cv`` matches any constant value, then ``plus(cv, cv)``
        would match ``2 + 2``, but not ``2 + 3``.
        """

        class_: typing.ClassVar[java.lang.Class]

        def and_(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.AndExpression]:
            """
            Match the form ``L & R`` or ``R & L``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the left operand
            :param ExpressionMatcher[typing.Any] right: the matcher for the right operand
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.AndExpression]
            """

        def cv(self, value: typing.Union[jpype.JLong, int]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.ConstantValue]:
            """
            Match a given constant value
             
             
            
            **NOTE:** To match an unspecified constant value, use :meth:`var(Class) <.var>` with
            :obj:`ConstantValue`.
            
            :param jpype.JLong or int value: the value to match
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.ConstantValue]
            """

        def div(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.DivExpression]:
            """
            Match the form ``L / R``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the dividend
            :param ExpressionMatcher[typing.Any] right: the matcher for the divisor
            :return: the matcher for the quotient
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.DivExpression]
            """

        def fldSz(self, size: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.PatternValue]:
            """
            Match a field by its size
             
             
            
            This matches either a :obj:`TokenField` or a :obj:`ContextField`. If matched, it then
            passes a :obj:`ConstantValue` of the field's size (in bits) into the given size matcher.
            
            :param ExpressionMatcher[typing.Any] size: the matcher for the field's size
            :return: the field matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.PatternValue]
            """

        def mul(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.MultExpression]:
            """
            Match the form ``L * R`` or ``R * L``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the left factor
            :param ExpressionMatcher[typing.Any] right: the matcher for the right factor
            :return: the matcher for the product
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.MultExpression]
            """

        def neg(self, unary: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.MinusExpression]:
            """
            Match the form ``-U``
            
            :param ExpressionMatcher[typing.Any] unary: the child matcher
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.MinusExpression]
            """

        def not_(self, unary: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.NotExpression]:
            """
            Match the form ``~U``
            
            :param ExpressionMatcher[typing.Any] unary: the child matcher
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.NotExpression]
            """

        def opnd(self, def_: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.OperandValue]:
            """
            Match an operand value
             
             
            
            Typically, this must wrap any use of a field, since that field is considered an operand
            from the constructor's perspective.
            
            :param ExpressionMatcher[typing.Any] def: the matcher for the operand's defining expression.
            :return: the operand matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.OperandValue]
            """

        def or_(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.OrExpression]:
            """
            Match the form ``L | R`` or ``R | L``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the left operand
            :param ExpressionMatcher[typing.Any] right: the matcher for the right operand
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.OrExpression]
            """

        def plus(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.PlusExpression]:
            """
            Match the form ``L + R`` or ``R + L``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the left term
            :param ExpressionMatcher[typing.Any] right: the matcher for the right term
            :return: the matcher for the sum
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.PlusExpression]
            """

        def shl(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.LeftShiftExpression]:
            """
            Match the form ``L << R``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the left operand
            :param ExpressionMatcher[typing.Any] right: the matcher for the shift amount
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.LeftShiftExpression]
            """

        def shr(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.RightShiftExpression]:
            """
            Match the form ``L >> R``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the left operand
            :param ExpressionMatcher[typing.Any] right: the matcher for the shift amount
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.RightShiftExpression]
            """

        def sub(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.SubExpression]:
            """
            Match the form ``L - R``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the left term
            :param ExpressionMatcher[typing.Any] right: the matcher for the right term
            :return: the matcher for the difference
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.SubExpression]
            """

        @typing.overload
        def var(self) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.PatternExpression]:
            """
            Match any expression
             
             
            
            This matches any expression without consideration of its operands, except insofar when it
            appears in multiple places, it will check that subsequent matches are identical to the
            first.
            
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.PatternExpression]
            """

        @typing.overload
        def var(self, cls: java.lang.Class[T]) -> ExpressionMatcher[T]:
            """
            Match any expression of the given type
            
            :param T: the type of expression to match:param java.lang.Class[T] cls: the class of expression to match
            :return: the matcher
            :rtype: ExpressionMatcher[T]
            """

        def xor(self, left: ExpressionMatcher[typing.Any], right: ExpressionMatcher[typing.Any]) -> ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.XorExpression]:
            """
            Match the form ``L $xor R`` or ``R $xor L``
            
            :param ExpressionMatcher[typing.Any] left: the matcher for the left operand
            :param ExpressionMatcher[typing.Any] right: the matcher for the right operand
            :return: the matcher
            :rtype: ExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.XorExpression]
            """


    class_: typing.ClassVar[java.lang.Class]

    def get(self, results: collections.abc.Mapping) -> T:
        """
        Retrieve the expression substituted for this matcher from a previous successful match
         
         
        
        Calling this on the root matcher is relatively useless, as it would simply return the
        expression passed to :meth:`match(PatternExpression) <.match>`. Instead, sub-matchers should be saved
        in a variable, allowing their values to be retrieved. See :obj:`Context`, for an example.
        
        :param collections.abc.Mapping results: the previous match results
        :return: the substituted expression
        :rtype: T
        """

    @typing.overload
    def match(self, expression: ghidra.app.plugin.processors.sleigh.expression.PatternExpression) -> java.util.Map[ExpressionMatcher[typing.Any], ghidra.app.plugin.processors.sleigh.expression.PatternExpression]:
        """
        Attempt to match the given expression, recording the substitutions if successful
        
        :param ghidra.app.plugin.processors.sleigh.expression.PatternExpression expression: the expression to match
        :return: a map of matchers to substituted expressions
        :rtype: java.util.Map[ExpressionMatcher[typing.Any], ghidra.app.plugin.processors.sleigh.expression.PatternExpression]
        """

    @typing.overload
    def match(self, expression: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, result: collections.abc.Mapping) -> bool:
        """
        Attempt to match the given expression, recording substitutions in the given map
         
         
        
        Even if the match was unsuccessful, the result map may contain attempted substitutions. Thus,
        the map should be discarded if unsuccessful.
        
        :param ghidra.app.plugin.processors.sleigh.expression.PatternExpression expression: the expression to match
        :param collections.abc.Mapping result: a map to store matchers to substituted expressions
        :return: true if successful, false if not
        :rtype: bool
        """


class BinaryExpressionMatcher(AbstractExpressionMatcher[T], typing.Generic[T]):
    """
    A matcher for a binary expression
     
     
    
    If the required type matches, the matching descends to the left then right operands.
    """

    class Commutative(BinaryExpressionMatcher[T], typing.Generic[T]):
        """
        A matcher for binary expression allowing commutativity
         
         
        
        This behaves the same as :obj:`BinaryExpressionMatcher`, but if the first attempt fails, the
        operand match is re-attempted with the operands swapped.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, ops: java.util.Set[java.lang.Class[T]], leftMatcher: ExpressionMatcher[typing.Any], rightMatcher: ExpressionMatcher[typing.Any]):
            ...

        @typing.overload
        def __init__(self, cls: java.lang.Class[T], leftMatcher: ExpressionMatcher[typing.Any], rightMatcher: ExpressionMatcher[typing.Any]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ops: java.util.Set[java.lang.Class[T]], leftMatcher: ExpressionMatcher[typing.Any], rightMatcher: ExpressionMatcher[typing.Any]):
        ...

    @typing.overload
    def __init__(self, cls: java.lang.Class[T], leftMatcher: ExpressionMatcher[typing.Any], rightMatcher: ExpressionMatcher[typing.Any]):
        ...


class AnyMatcher(AbstractExpressionMatcher[T], typing.Generic[T]):
    """
    A matcher which accept any expression of the required type
    
     
    
    This requires no further consideration of the expressions operands. If the type matches, the
    expression matches.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ops: java.util.Set[java.lang.Class[T]]):
        ...

    @typing.overload
    def __init__(self, cls: java.lang.Class[T]):
        ...

    @staticmethod
    def any() -> AnyMatcher[ghidra.app.plugin.processors.sleigh.expression.PatternExpression]:
        ...


class AbstractExpressionMatcher(ExpressionMatcher[T], typing.Generic[T]):
    """
    Base implementation for expression matchers
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ops: java.util.Set[java.lang.Class[T]]):
        ...

    @typing.overload
    def __init__(self, cls: java.lang.Class[T]):
        ...


class FieldSizeMatcher(AbstractExpressionMatcher[ghidra.app.plugin.processors.sleigh.expression.PatternValue]):
    """
    A matcher for a token or context field, constrained by its size in bits
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sizeMatcher: ExpressionMatcher[typing.Any]):
        ...



__all__ = ["OperandValueMatcher", "ConstantValueMatcher", "UnaryExpressionMatcher", "ExpressionMatcher", "BinaryExpressionMatcher", "AnyMatcher", "AbstractExpressionMatcher", "FieldSizeMatcher"]
