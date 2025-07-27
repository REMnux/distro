from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.base.memsearch.searcher
import java.lang # type: ignore


class Scanner(java.lang.Enum[Scanner]):
    """
    Scan algorithms that examine the byte values of existing search results and look for changes.
    The specific scanner algorithm determines which results to keep and which to discard.
    """

    class_: typing.ClassVar[java.lang.Class]
    EQUALS: typing.Final[Scanner]
    NOT_EQUALS: typing.Final[Scanner]
    INCREASED: typing.Final[Scanner]
    DECREASED: typing.Final[Scanner]

    def accept(self, match: ghidra.features.base.memsearch.searcher.MemoryMatch) -> bool:
        ...

    def getDescription(self) -> str:
        ...

    def getName(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Scanner:
        ...

    @staticmethod
    def values() -> jpype.JArray[Scanner]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...



__all__ = ["Scanner"]
