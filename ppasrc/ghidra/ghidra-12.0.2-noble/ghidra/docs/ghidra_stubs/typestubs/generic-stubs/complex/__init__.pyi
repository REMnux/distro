from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


class Complex(java.lang.Object):
    """
    A complex number a + bi
    
    This doesn't support any actual operations, nor does it implement :obj:`Comparable`. It's simply
    enough to store and print the number.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, real: typing.Union[jpype.JDouble, float], imaginary: typing.Union[jpype.JDouble, float]):
        ...

    def getImaginary(self) -> float:
        ...

    def getReal(self) -> float:
        ...

    @property
    def imaginary(self) -> jpype.JDouble:
        ...

    @property
    def real(self) -> jpype.JDouble:
        ...



__all__ = ["Complex"]
