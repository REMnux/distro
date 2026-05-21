from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.exec_
import java.lang # type: ignore


T = typing.TypeVar("T")


class TrigPcodeUseropLibraryFactory(ghidra.pcode.exec_.PcodeUseropLibraryFactory):

    class TrigPcodeUseropLibrary(ghidra.pcode.exec_.AnnotatedPcodeUseropLibrary[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[TrigPcodeUseropLibraryFactory.TrigPcodeUseropLibrary[typing.Any]]

        def __init__(self) -> None:
            ...

        @typing.overload
        def sin(self, a: typing.Union[jpype.JFloat, float]) -> float:
            ...

        @typing.overload
        def sin(self, a: typing.Union[jpype.JDouble, float]) -> float:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...



__all__ = ["TrigPcodeUseropLibraryFactory"]
