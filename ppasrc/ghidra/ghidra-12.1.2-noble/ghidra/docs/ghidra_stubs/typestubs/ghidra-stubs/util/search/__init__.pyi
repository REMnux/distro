from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.lang
import ghidra.util.classfinder


class InstructionSkipper(ghidra.util.classfinder.ExtensionPoint):

    class_: typing.ClassVar[java.lang.Class]

    def getApplicableProcessor(self) -> ghidra.program.model.lang.Processor:
        ...

    def shouldSkip(self, buffer: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @property
    def applicableProcessor(self) -> ghidra.program.model.lang.Processor:
        ...



__all__ = ["InstructionSkipper"]
