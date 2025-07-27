from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


class ByteBufferPtr(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buffer: jpype.JArray[jpype.JByte], index: typing.Union[jpype.JInt, int]):
        ...

    def add(self, offset: typing.Union[jpype.JInt, int]) -> ByteBufferPtr:
        ...

    def get(self, i: typing.Union[jpype.JInt, int]) -> int:
        ...



__all__ = ["ByteBufferPtr"]
