from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


class KandL(java.lang.Object):
    """
    Translated from the C++ version.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def kToL(k: typing.Union[jpype.JInt, int], taubound: typing.Union[jpype.JDouble, float], probthresh: typing.Union[jpype.JDouble, float]) -> int:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @staticmethod
    def memoryModelToL(model: LSHMemoryModel) -> int:
        ...


class LSHMemoryModel(java.lang.Enum[LSHMemoryModel]):

    class_: typing.ClassVar[java.lang.Class]
    SMALL: typing.Final[LSHMemoryModel]
    MEDIUM: typing.Final[LSHMemoryModel]
    LARGE: typing.Final[LSHMemoryModel]

    def getK(self) -> int:
        ...

    def getLabel(self) -> str:
        ...

    def getProbabilityThreshold(self) -> float:
        ...

    def getTauBound(self) -> float:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LSHMemoryModel:
        ...

    @staticmethod
    def values() -> jpype.JArray[LSHMemoryModel]:
        ...

    @property
    def tauBound(self) -> jpype.JDouble:
        ...

    @property
    def probabilityThreshold(self) -> jpype.JDouble:
        ...

    @property
    def label(self) -> java.lang.String:
        ...

    @property
    def k(self) -> jpype.JInt:
        ...


class Partition(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def hash(partitionIdentities: jpype.JArray[jpype.JInt], values: jpype.JArray[generic.lsh.vector.HashEntry]) -> int:
        ...



__all__ = ["KandL", "LSHMemoryModel", "Partition"]
