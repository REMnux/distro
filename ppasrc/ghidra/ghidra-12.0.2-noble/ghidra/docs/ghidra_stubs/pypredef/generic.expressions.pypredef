from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class LongExpressionValue(ExpressionValue):
    """
    Long operand values. See :obj:`ExpressionValue`. Defines supported operators and other
    operands for expression values that are long values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: typing.Union[jpype.JLong, int]):
        ...

    def getLongValue(self) -> int:
        ...

    @property
    def longValue(self) -> jpype.JLong:
        ...


class ExpressionException(java.lang.Exception):
    """
    Exception thrown when using an :obj:`ExpressionEvaluator`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class ExpressionGrouper(java.lang.Enum[ExpressionGrouper], ExpressionElement):
    """
    Grouping :obj:`ExpressionElement`s
    """

    class_: typing.ClassVar[java.lang.Class]
    LEFT_PAREN: typing.Final[ExpressionGrouper]
    RIGHT_PAREN: typing.Final[ExpressionGrouper]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ExpressionGrouper:
        ...

    @staticmethod
    def values() -> jpype.JArray[ExpressionGrouper]:
        ...


class ExpressionElement(java.lang.Object):
    """
    Base marker interface for :obj:`ExpressionGrouper`, :obj:`ExpressionOperator`, 
    and :obj:`ExpressionValue`
    """

    class_: typing.ClassVar[java.lang.Class]


class ExpressionValue(ExpressionElement):
    """
    Operand types use by the :obj:`ExpressionEvaluator` must implement this interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def applyBinaryOperator(self, operator: ExpressionOperator, value: ExpressionValue) -> ExpressionValue:
        """
        Method called to apply a binary operator to this value.
        
        :param ExpressionOperator operator: the binary operator being applied.
        :param ExpressionValue value: the other value to combine with this value by the operator
        :return: the new value after the operator is applied to this value
        :rtype: ExpressionValue
        :raises ExpressionException: if the operator is not applicable for this value or the other
        value is not applicable for this operand and operator
        """

    def applyUnaryOperator(self, operator: ExpressionOperator) -> ExpressionValue:
        """
        Method called to apply a unary operator to this value.
        
        :param ExpressionOperator operator: the operator being applied
        :return: the new value after the operator is applied to this value
        :rtype: ExpressionValue
        :raises ExpressionException: if the operator is not applicable for this value
        """


class ExpressionOperator(java.lang.Enum[ExpressionOperator], ExpressionElement):
    """
    Enum of support operators for the :obj:`ExpressionEvaluator`
    """

    @typing.type_check_only
    class OpType(java.lang.Enum[ExpressionOperator.OpType]):

        class_: typing.ClassVar[java.lang.Class]
        UNARY: typing.Final[ExpressionOperator.OpType]
        BINARY: typing.Final[ExpressionOperator.OpType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ExpressionOperator.OpType:
            ...

        @staticmethod
        def values() -> jpype.JArray[ExpressionOperator.OpType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    BITWISE_NOT: typing.Final[ExpressionOperator]
    LOGICAL_NOT: typing.Final[ExpressionOperator]
    UNARY_PLUS: typing.Final[ExpressionOperator]
    UNARY_MINUS: typing.Final[ExpressionOperator]
    MULTIPLY: typing.Final[ExpressionOperator]
    DIVIDE: typing.Final[ExpressionOperator]
    ADD: typing.Final[ExpressionOperator]
    SUBTRACT: typing.Final[ExpressionOperator]
    SHIFT_LEFT: typing.Final[ExpressionOperator]
    SHIFT_RIGHT: typing.Final[ExpressionOperator]
    LESS_THAN: typing.Final[ExpressionOperator]
    GREATER_THAN: typing.Final[ExpressionOperator]
    LESS_THAN_OR_EQUAL: typing.Final[ExpressionOperator]
    GREATER_THAN_OR_EQUAL: typing.Final[ExpressionOperator]
    EQUALS: typing.Final[ExpressionOperator]
    NOT_EQUALS: typing.Final[ExpressionOperator]
    BITWISE_AND: typing.Final[ExpressionOperator]
    BITWISE_XOR: typing.Final[ExpressionOperator]
    BITWISE_OR: typing.Final[ExpressionOperator]
    LOGICAL_AND: typing.Final[ExpressionOperator]
    LOGICAL_OR: typing.Final[ExpressionOperator]
    binaryOperatorsByPrecedence: typing.ClassVar[java.util.List[java.util.Set[ExpressionOperator]]]

    @staticmethod
    def getBinaryOperatorsByPrecedence() -> java.util.List[java.util.Set[ExpressionOperator]]:
        """
        Returns a list of all the binary operators in precedence order, organized into sets where
        each set contains all the operators of the same precedence.
        
        :return: a list of all the binary operators in precedence order, organized into sets where
        each set contains all the operators of the same precedence.
        :rtype: java.util.List[java.util.Set[ExpressionOperator]]
        """

    @staticmethod
    def getOperator(token: typing.Union[java.lang.String, str], lookahead1: typing.Union[java.lang.String, str], preferBinary: typing.Union[jpype.JBoolean, bool]) -> ExpressionOperator:
        """
        Returns the operator for the given token and look ahead token and if we are expecting to find
        a binary operator. This method first tries merging the tokens looking for a double char
        operator first.
        
        :param java.lang.String or str token: the first token
        :param java.lang.String or str lookahead1: the next token that may or may not be part of this operand
        :param jpype.JBoolean or bool preferBinary: if we are expecting a binary operator (the previous expression element
        was an operand value). We need this to know if the token '-' is the unary operator or the
        binary operator. If the token before was an operator, then we expect a unary operator. If
        the previous was a value, then we expect a binary operator.
        :return: the operator that matches the given tokens and expected type
        :rtype: ExpressionOperator
        """

    def isBinary(self) -> bool:
        """
        Returns if the operator is a binary operator.
        
        :return: if the operator is a binary operator.
        :rtype: bool
        """

    def isUnary(self) -> bool:
        """
        Returns if the operator is a unary operator.
        
        :return: if the operator is a unary operator.
        :rtype: bool
        """

    def size(self) -> int:
        """
        Returns the number of chars in the operator
        
        :return: the number of chars in the operator
        :rtype: int
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ExpressionOperator:
        ...

    @staticmethod
    def values() -> jpype.JArray[ExpressionOperator]:
        ...

    @property
    def binary(self) -> jpype.JBoolean:
        ...

    @property
    def unary(self) -> jpype.JBoolean:
        ...


class ExpressionEvaluator(java.lang.Object):
    """
    Class for evaluating numeric expressions. See 
    :obj:`ExpressionOperator` for the full list of supported operators. All values are interpreted
    as longs. Optionally, an ExpressionEvalualuator can be constructed with a symbol evaluator that
    will be called on any string that can't be evaluated as an operator or number.
     
    
    ExpressionEvaluators can operate in either decimal or hex mode. If in hex mode, all numbers are
    assumed to be hexadecimal values. In decimal mode, numbers are assumed to be decimal values, but
    hexadecimal values can still be specified by prefixing them with "0x".
     
    
    There are also two convenience static methods that can be called to evaluate expressions. These
    methods will either return a Long value as the result or null if there was an error evaluating
    the expression. To get error messages related to parsing the expression, instantiate an
    ExpressionEvaluator and call :meth:`parse(String) <.parse>` which will throw a 
    :obj:`ExpressionException` when the expression can't be evaluated.
    """

    @typing.type_check_only
    class LookAheadTokenizer(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def advance(self, count: typing.Union[jpype.JInt, int]):
            ...

        def getCurrentToken(self) -> str:
            ...

        def getNextToken(self) -> str:
            ...

        def hasMoreTokens(self) -> bool:
            ...

        @property
        def currentToken(self) -> java.lang.String:
            ...

        @property
        def nextToken(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs an ExpressionEvaluator in decimal mode.
        """

    @typing.overload
    def __init__(self, assumeHex: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs an ExpressionEvaluator in either decimal or hex mode.
        
        :param jpype.JBoolean or bool assumeHex: if true, the evaluator will assume all values are hexadecimal.
        """

    @typing.overload
    def __init__(self, evaluator: java.util.function.Function[java.lang.String, ExpressionValue]):
        """
        Constructs an ExpressionEvaluator in decimal mode with a given symbol evaluator.
        
        :param java.util.function.Function[java.lang.String, ExpressionValue] evaluator: A function that can convert a string token into a value (Must be Long
        ExpressionValues, unless this is being called by a subclass that can handle other types
        of operand values)
        """

    @typing.overload
    def __init__(self, assumeHex: typing.Union[jpype.JBoolean, bool], evaluator: java.util.function.Function[java.lang.String, ExpressionValue]):
        """
        Constructs an ExpressionEvaluator in either decimal or hex mode with a given symbol
        evaluator.
        
        :param jpype.JBoolean or bool assumeHex: if true, the evaluator will assume all values are hexadecimal.
        :param java.util.function.Function[java.lang.String, ExpressionValue] evaluator: A function that can convert a string token into a value (Must be Long
        ExpressionValues, unless this is being called by a subclass that can handle other types
        of operand values)
        """

    @staticmethod
    @typing.overload
    def evaluateToLong(input: typing.Union[java.lang.String, str]) -> int:
        """
        Evaluates the given input as a Long value. This call assumes all numbers are decimal unless
        prefixed with a "0x".
        
        :param java.lang.String or str input: the expression to be parsed into a Long value
        :return: the resulting Long value or null if the expression could not be evaluated.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def evaluateToLong(input: typing.Union[java.lang.String, str], assumeHex: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Evaluates the given input as a long value.
        
        :param java.lang.String or str input: the expression to be parsed into a Long value
        :param jpype.JBoolean or bool assumeHex: if true, numbers will be assumed to be hexadecimal values.
        :return: the resulting Long value or null if the expression could not be evaluated.
        :rtype: int
        """

    def parseAsLong(self, input: typing.Union[java.lang.String, str]) -> int:
        """
        Parses the given expression input, expecting the result to be long value.
        
        :param java.lang.String or str input: the expression string
        :return: the long value result.
        :rtype: int
        :raises ExpressionException: if the expression could not be evaluated to a long value.
        """

    def setAssumeHex(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Changes the hex/decimal mode.
        
        :param jpype.JBoolean or bool b: if true, all numbers will be assumed to be hexadecimal
        """



__all__ = ["LongExpressionValue", "ExpressionException", "ExpressionGrouper", "ExpressionElement", "ExpressionValue", "ExpressionOperator", "ExpressionEvaluator"]
