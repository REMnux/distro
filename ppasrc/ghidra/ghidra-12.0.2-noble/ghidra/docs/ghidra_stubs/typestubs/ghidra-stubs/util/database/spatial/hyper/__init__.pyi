from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.database
import ghidra.util.database.spatial
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore


B = typing.TypeVar("B")
DR = typing.TypeVar("DR")
DS = typing.TypeVar("DS")
NR = typing.TypeVar("NR")
NS = typing.TypeVar("NS")
P = typing.TypeVar("P")
Q = typing.TypeVar("Q")
T = typing.TypeVar("T")


class EuclideanHyperSpace(java.lang.Object, typing.Generic[P, B]):

    class_: typing.ClassVar[java.lang.Class]

    def boxArea(self, box: B) -> float:
        ...

    def boxCenter(self, box: B) -> P:
        ...

    def boxContains(self, box: B, point: P) -> bool:
        ...

    def boxEncloses(self, outer: B, inner: B) -> bool:
        ...

    def boxIntersection(self, b: B, shape: B) -> B:
        ...

    def boxMargin(self, box: B) -> float:
        ...

    def boxUnionBounds(self, a: B, b: B) -> B:
        ...

    def boxesEqual(self, a: B, b: B) -> bool:
        ...

    def collectBounds(self, box: B) -> jpype.JArray[java.lang.Object]:
        ...

    def computeAreaIntersection(self, a: B, b: B) -> float:
        ...

    def computeAreaUnionBounds(self, a: B, b: B) -> float:
        ...

    def getDimensions(self) -> java.util.List[Dimension[typing.Any, P, B]]:
        ...

    def getFull(self) -> B:
        ...

    def measureIntersection(self, dim: Dimension[T, P, B], a: B, b: B) -> float:
        ...

    def measureUnion(self, dim: Dimension[T, P, B], a: B, b: B) -> float:
        ...

    def sqDistance(self, a: P, b: P) -> float:
        ...

    @property
    def full(self) -> B:
        ...

    @property
    def dimensions(self) -> java.util.List[Dimension[typing.Any, P, B]]:
        ...


class HyperPoint(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LongDimension(Dimension[java.lang.Long, P, B], typing.Generic[P, B]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AbstractHyperRStarTree(ghidra.util.database.spatial.AbstractRStarConstraintsTree[DS, DR, NS, NR, T, Q], typing.Generic[P, DS, DR, NS, NR, T, Q]):

    @typing.type_check_only
    class AsSpatialMap(ghidra.util.database.spatial.AbstractConstraintsTreeSpatialMap[DS, DR, NS, T, Q], typing.Generic[DS, DR, NS, T, Q]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: ghidra.util.database.spatial.AbstractConstraintsTree[DS, DR, NS, typing.Any, T, Q], query: Q):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, tableName: typing.Union[java.lang.String, str], space: EuclideanHyperSpace[P, NS], dataType: java.lang.Class[DR], nodeType: java.lang.Class[NR], upgradeable: typing.Union[jpype.JBoolean, bool], maxChildren: typing.Union[jpype.JInt, int]):
        ...


class AbstractHyperBoxQuery(ghidra.util.database.spatial.Query[DS, NS], typing.Generic[P, DS, NS, Q]):

    class QueryFactory(java.lang.Object, typing.Generic[NS, Q]):

        class_: typing.ClassVar[java.lang.Class]

        def create(self, ls: NS, us: NS, direction: HyperDirection) -> Q:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ls: NS, us: NS, space: EuclideanHyperSpace[P, NS], direction: HyperDirection):
        ...

    def and_(self, query: Q) -> Q:
        ...

    def getDirection(self) -> HyperDirection:
        ...

    def starting(self, newDirection: HyperDirection) -> Q:
        ...

    @property
    def direction(self) -> HyperDirection:
        ...


class HyperDirection(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final[HyperDirection]

    def __init__(self, dimension: typing.Union[jpype.JInt, int], forward: typing.Union[jpype.JBoolean, bool]):
        ...

    def dimension(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def forward(self) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...


class ULongDimension(Dimension[java.lang.Long, P, B], typing.Generic[P, B]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class Dimension(java.lang.Object, typing.Generic[T, P, B]):

    class_: typing.ClassVar[java.lang.Class]

    def absoluteMax(self) -> T:
        ...

    def absoluteMin(self) -> T:
        ...

    def boxMid(self, box: B) -> T:
        ...

    def compare(self, a: T, b: T) -> int:
        ...

    def contains(self, box: B, point: P) -> bool:
        ...

    def distance(self, a: T, b: T) -> float:
        ...

    def encloses(self, outer: B, inner: B) -> bool:
        ...

    def intersect(self, a: B, b: B) -> bool:
        ...

    def intersectionLower(self, a: B, b: B) -> T:
        ...

    def intersectionUpper(self, a: B, b: B) -> T:
        ...

    def lower(self, box: B) -> T:
        ...

    def max(self, a: T, b: T) -> T:
        ...

    def measure(self, box: B) -> float:
        ...

    def mid(self, a: T, b: T) -> T:
        ...

    def min(self, a: T, b: T) -> T:
        ...

    def pointDistance(self, a: P, b: P) -> float:
        ...

    def unionLower(self, a: B, b: B) -> T:
        ...

    def unionUpper(self, a: B, b: B) -> T:
        ...

    def upper(self, box: B) -> T:
        ...

    def value(self, point: P) -> T:
        ...


class HyperBox(ghidra.util.database.spatial.BoundingShape[B], typing.Generic[P, B]):

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, p: P) -> bool:
        ...

    def doEquals(self, obj: java.lang.Object) -> bool:
        ...

    def doHashCode(self) -> int:
        ...

    def getCenter(self) -> P:
        ...

    def immutable(self, lCorner: P, uCorner: P) -> B:
        ...

    def intersection(self, shape: B) -> B:
        ...

    def lCorner(self) -> P:
        ...

    def space(self) -> EuclideanHyperSpace[P, B]:
        ...

    def uCorner(self) -> P:
        ...

    @property
    def center(self) -> P:
        ...


class StringDimension(Dimension[java.lang.String, P, B], typing.Generic[P, B]):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def add(a: typing.Union[java.lang.String, str], d: java.math.BigInteger, len: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    def charAt(s: typing.Union[java.lang.String, str], i: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def lenStrings(a: typing.Union[java.lang.String, str], b: typing.Union[java.lang.String, str]) -> int:
        ...

    @staticmethod
    def subtractExact(a: typing.Union[java.lang.String, str], b: typing.Union[java.lang.String, str]) -> java.math.BigInteger:
        ...



__all__ = ["EuclideanHyperSpace", "HyperPoint", "LongDimension", "AbstractHyperRStarTree", "AbstractHyperBoxQuery", "HyperDirection", "ULongDimension", "Dimension", "HyperBox", "StringDimension"]
