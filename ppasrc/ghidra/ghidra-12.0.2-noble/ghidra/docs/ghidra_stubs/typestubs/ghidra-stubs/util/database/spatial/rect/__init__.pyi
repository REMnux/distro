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


DR = typing.TypeVar("DR")
DS = typing.TypeVar("DS")
NR = typing.TypeVar("NR")
NS = typing.TypeVar("NS")
Q = typing.TypeVar("Q")
R = typing.TypeVar("R")
T = typing.TypeVar("T")
X = typing.TypeVar("X")
Y = typing.TypeVar("Y")


class Abstract2DRStarTree(ghidra.util.database.spatial.AbstractRStarConstraintsTree[DS, DR, NS, NR, T, Q], typing.Generic[X, Y, DS, DR, NS, NR, T, Q]):

    @typing.type_check_only
    class AsSpatialMap(ghidra.util.database.spatial.AbstractConstraintsTreeSpatialMap[DS, DR, NS, T, Q], typing.Generic[DS, DR, NS, T, Q]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: ghidra.util.database.spatial.AbstractConstraintsTree[DS, DR, NS, typing.Any, T, Q], query: Q):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, tableName: typing.Union[java.lang.String, str], space: EuclideanSpace2D[X, Y], dataType: java.lang.Class[DR], nodeType: java.lang.Class[NR], upgradable: typing.Union[jpype.JBoolean, bool], maxChildren: typing.Union[jpype.JInt, int]):
        ...

    def getShapeSpace(self) -> EuclideanSpace2D[X, Y]:
        ...

    @property
    def shapeSpace(self) -> EuclideanSpace2D[X, Y]:
        ...


class AbstractRectangle2DQuery(ghidra.util.database.spatial.Query[DS, NS], typing.Generic[X, Y, DS, NS, Q]):

    class QueryFactory(java.lang.Object, typing.Generic[NS, Q]):

        class_: typing.ClassVar[java.lang.Class]

        def create(self, r1: NS, r2: NS, direction: Rectangle2DDirection) -> Q:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, r1: NS, r2: NS, space: EuclideanSpace2D[X, Y], direction: Rectangle2DDirection):
        ...

    def and_(self, query: Q) -> Q:
        ...

    def getDirection(self) -> Rectangle2DDirection:
        ...

    def starting(self, newDirection: Rectangle2DDirection) -> Q:
        ...

    @property
    def direction(self) -> Rectangle2DDirection:
        ...


class ImmutablePoint2D(Point2D[X, Y], typing.Generic[X, Y]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, x: X, y: Y, space: EuclideanSpace2D[X, Y]):
        ...


class EuclideanSpace2D(java.lang.Object, typing.Generic[X, Y]):

    class_: typing.ClassVar[java.lang.Class]

    def compareX(self, x1: X, x2: X) -> int:
        ...

    def compareY(self, y1: Y, y2: Y) -> int:
        ...

    def distX(self, x1: X, x2: X) -> float:
        ...

    def distY(self, y1: Y, y2: Y) -> float:
        ...

    def getFull(self) -> Rectangle2D[X, Y, typing.Any]:
        ...

    def maxX(self, x1: X, x2: X) -> X:
        ...

    def maxY(self, y1: Y, y2: Y) -> Y:
        ...

    def midX(self, x1: X, x2: X) -> X:
        ...

    def midY(self, y1: Y, y2: Y) -> Y:
        ...

    def minX(self, x1: X, x2: X) -> X:
        ...

    def minY(self, y1: Y, y2: Y) -> Y:
        ...

    @property
    def full(self) -> Rectangle2D[X, Y, typing.Any]:
        ...


class Point2D(java.lang.Object, typing.Generic[X, Y]):

    class_: typing.ClassVar[java.lang.Class]

    def computeDistance(self, point: Point2D[X, Y]) -> float:
        ...

    def getSpace(self) -> EuclideanSpace2D[X, Y]:
        ...

    def getX(self) -> X:
        ...

    def getY(self) -> Y:
        ...

    @property
    def x(self) -> X:
        ...

    @property
    def y(self) -> Y:
        ...

    @property
    def space(self) -> EuclideanSpace2D[X, Y]:
        ...


class ImmutableRectangle2D(Rectangle2D[X, Y, R], typing.Generic[X, Y, R]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, x1: X, x2: X, y1: Y, y2: Y, space: EuclideanSpace2D[X, Y]):
        ...


class Rectangle2D(ghidra.util.database.spatial.BoundingShape[R], typing.Generic[X, Y, R]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def contains(self, point: Point2D[X, Y]) -> bool:
        ...

    @typing.overload
    def contains(self, x: X, y: Y) -> bool:
        ...

    def doEquals(self, obj: java.lang.Object) -> bool:
        ...

    def doHashCode(self) -> int:
        ...

    def enclosedBy(self, shape: R) -> bool:
        """
        Check if this rectangle is enclosed by another rectangle
        
        :param R shape: the other (presumably-outer) rectangle
        :return: true if this rectangle is enclosed by the other
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def encloses(outer: Rectangle2D[X, Y, typing.Any], inner: Rectangle2D[X, Y, typing.Any]) -> bool:
        ...

    @typing.overload
    def encloses(self, shape: R) -> bool:
        """
        Check if this rectangle encloses another rectangle
        
        :param R shape: the other (presumably-inner) rectangle
        :return: true if this rectangle encloses the other
        :rtype: bool
        """

    def getCenter(self) -> Point2D[X, Y]:
        ...

    def getSpace(self) -> EuclideanSpace2D[X, Y]:
        ...

    def getX1(self) -> X:
        ...

    def getX2(self) -> X:
        ...

    def getY1(self) -> Y:
        ...

    def getY2(self) -> Y:
        ...

    def immutable(self, x1: X, x2: X, y1: Y, y2: Y) -> R:
        ...

    def intersection(self, shape: R) -> R:
        ...

    def intersects(self, shape: R) -> bool:
        ...

    @property
    def center(self) -> Point2D[X, Y]:
        ...

    @property
    def y1(self) -> Y:
        ...

    @property
    def y2(self) -> Y:
        ...

    @property
    def x1(self) -> X:
        ...

    @property
    def x2(self) -> X:
        ...

    @property
    def space(self) -> EuclideanSpace2D[X, Y]:
        ...


class Rectangle2DDirection(java.lang.Enum[Rectangle2DDirection]):
    """
    Specifies which element of a query is returned by
    :meth:`AbstractConstraintsTreeSpatialMap.firstEntry() <AbstractConstraintsTreeSpatialMap.firstEntry>` and the like.
    """

    class_: typing.ClassVar[java.lang.Class]
    LEFTMOST: typing.Final[Rectangle2DDirection]
    """
    Start with element having the least x1 value
    """

    RIGHTMOST: typing.Final[Rectangle2DDirection]
    """
    Start with element having the greatest x2 value
    """

    BOTTOMMOST: typing.Final[Rectangle2DDirection]
    """
    Start with element having the least y1 value
    """

    TOPMOST: typing.Final[Rectangle2DDirection]
    """
    Start with element having the greatest y2 value
    """


    def isReversed(self) -> bool:
        """
        Check if the direction implies the greatest elements come first
         
        Implementors may find this useful for querying internal indices properly.
        
        :return: true if reversed
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Rectangle2DDirection:
        ...

    @staticmethod
    def values() -> jpype.JArray[Rectangle2DDirection]:
        ...

    @property
    def reversed(self) -> jpype.JBoolean:
        ...



__all__ = ["Abstract2DRStarTree", "AbstractRectangle2DQuery", "ImmutablePoint2D", "EuclideanSpace2D", "Point2D", "ImmutableRectangle2D", "Rectangle2D", "Rectangle2DDirection"]
