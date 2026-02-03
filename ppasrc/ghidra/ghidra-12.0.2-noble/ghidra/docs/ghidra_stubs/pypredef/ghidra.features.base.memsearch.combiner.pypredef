from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.base.memsearch.searcher
import java.lang # type: ignore
import java.util # type: ignore


class Combiner(java.lang.Enum[Combiner]):
    """
    An enum of search results "combiners". Each combiner determines how to combine two sets of
    memory search results. The current or existing results is represented as the "A" set and the
    new search is represented as the "B" set.
    """

    class_: typing.ClassVar[java.lang.Class]
    REPLACE: typing.Final[Combiner]
    UNION: typing.Final[Combiner]
    INTERSECT: typing.Final[Combiner]
    XOR: typing.Final[Combiner]
    A_MINUS_B: typing.Final[Combiner]
    B_MINUS_A: typing.Final[Combiner]

    def combine(self, matches1: java.util.List[ghidra.features.base.memsearch.searcher.MemoryMatch], matches2: java.util.List[ghidra.features.base.memsearch.searcher.MemoryMatch]) -> java.util.Collection[ghidra.features.base.memsearch.searcher.MemoryMatch]:
        ...

    def getName(self) -> str:
        ...

    def isMerge(self) -> bool:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Combiner:
        ...

    @staticmethod
    def values() -> jpype.JArray[Combiner]:
        ...

    @property
    def merge(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...



__all__ = ["Combiner"]
