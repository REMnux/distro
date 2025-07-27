from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import java.lang # type: ignore


class LoadImage(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def loadFill(self, buf: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, bufOffset: typing.Union[jpype.JInt, int], generateInitializedMask: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JByte]:
        ...


class LoadImageFunc(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    address: ghidra.program.model.address.Address
    name: java.lang.String

    def __init__(self):
        ...



__all__ = ["LoadImage", "LoadImageFunc"]
