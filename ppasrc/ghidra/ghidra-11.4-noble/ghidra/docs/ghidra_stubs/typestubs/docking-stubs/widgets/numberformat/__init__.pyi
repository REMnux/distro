from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import javax.swing.text # type: ignore


class HexIntegerFormatter(IntegerFormatter):

    @typing.type_check_only
    class HexAllowedPositiveValueIntgerDocumentFilterWrapper(IntegerFormatter.PosiviteValueIntegerDocumentFilterWrapper):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def valueToString(self, value: java.lang.Object) -> str:
        """
        Overridden to translate the internal value to a hex representation.
        """


class IntegerFormatterFactory(javax.swing.text.DefaultFormatterFactory):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, allowsNegativeInput: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, formatter: IntegerFormatter, allowsNegativeInput: typing.Union[jpype.JBoolean, bool]):
        ...


class BoundedRangeDecimalFormatterFactory(javax.swing.text.DefaultFormatterFactory):
    """
    Bounded range factory for formatters with a min and max allowed value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, numberFormat: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str numberFormat: a format string compatible with :obj:`DecimalFormat`
        """

    @typing.overload
    def __init__(self, upperRangeValue: typing.Union[java.lang.Double, float], lowerRangeValue: typing.Union[java.lang.Double, float], numberFormat: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.Double or float upperRangeValue: the max value allowed
        :param java.lang.Double or float lowerRangeValue: the min value allowed
        :param java.lang.String or str numberFormat: a format string compatible with :obj:`DecimalFormat`
        """


@typing.type_check_only
class BoundedRangeDecimalFormatter(javax.swing.text.NumberFormatter):

    @typing.type_check_only
    class BoundedRangeDocumentFilterWrapper(javax.swing.text.DocumentFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class IntegerFormatter(javax.swing.text.NumberFormatter):

    @typing.type_check_only
    class PosiviteValueIntegerDocumentFilterWrapper(javax.swing.text.DocumentFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["HexIntegerFormatter", "IntegerFormatterFactory", "BoundedRangeDecimalFormatterFactory", "BoundedRangeDecimalFormatter", "IntegerFormatter"]
