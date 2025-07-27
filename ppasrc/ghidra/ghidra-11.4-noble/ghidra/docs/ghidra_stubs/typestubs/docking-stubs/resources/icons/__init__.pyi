from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import javax.swing # type: ignore


class NumberIcon(javax.swing.Icon):
    """
    An icon that paints the given number
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, number: typing.Union[jpype.JInt, int]):
        ...

    def setNumber(self, number: typing.Union[jpype.JInt, int]):
        ...



__all__ = ["NumberIcon"]
