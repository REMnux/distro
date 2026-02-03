from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.util.database
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


A = typing.TypeVar("A")
DR = typing.TypeVar("DR")
DS = typing.TypeVar("DS")
K = typing.TypeVar("K")
NR = typing.TypeVar("NR")
NS = typing.TypeVar("NS")
Q = typing.TypeVar("Q")
RS = typing.TypeVar("RS")
S = typing.TypeVar("S")
T = typing.TypeVar("T")
U = typing.TypeVar("U")


class Query(java.lang.Object, typing.Generic[DS, NS]):

    class QueryInclusion(java.lang.Enum[Query.QueryInclusion]):
        """
        The result of testing a sub-tree for inclusion in a query
        """

        class_: typing.ClassVar[java.lang.Class]
        ALL: typing.Final[Query.QueryInclusion]
        """
        The query certainly includes all data in the sub-tree
        """

        SOME: typing.Final[Query.QueryInclusion]
        """
        The query may include some data in the sub-tree
        """

        NONE: typing.Final[Query.QueryInclusion]
        """
        The query certainly excludes all data in the sub-tree
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Query.QueryInclusion:
            ...

        @staticmethod
        def values() -> jpype.JArray[Query.QueryInclusion]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getBoundsComparator(self) -> java.util.Comparator[NS]:
        """
        If the query orders elements, get the (or an equivalent) comparator.
        
        :return: an comparator
        :rtype: java.util.Comparator[NS]
        """

    def terminateEarlyData(self, shape: DS) -> bool:
        """
        Test if internal data entry iteration can terminate early
        
        :param DS shape: the shape of the current data entry
        :return: true if no entry to follow could possibly be included in the query
        :rtype: bool
        """

    def terminateEarlyNode(self, shape: NS) -> bool:
        """
        Test if internal node entry iteration can terminate early
        
        :param NS shape: the shape of the current node entry
        :return: true if no entry to follow could possibly contain data entries included in the query
        :rtype: bool
        """

    def testData(self, shape: DS) -> bool:
        """
        Test if the given data shape is included in the query
        
        :param DS shape: the shape of the data entry
        :return: true if it is included
        :rtype: bool
        """

    def testNode(self, shape: NS) -> Query.QueryInclusion:
        """
        Test if the given node shape has data entries included in the query
        
        :param NS shape: the shape (bounds) of the node entry
        :return: a result as described in :obj:`QueryInclusion`
        :rtype: Query.QueryInclusion
        """

    @property
    def boundsComparator(self) -> java.util.Comparator[NS]:
        ...


class DBTreeDataRecord(DBTreeRecord[DS, NS], typing.Generic[DS, NS, T]):

    @typing.type_check_only
    class RecordEntry(java.util.Map.Entry[DS, T], typing.Generic[DS, NS, T]):

        class_: typing.ClassVar[java.lang.Class]

        def asRecord(self) -> DBTreeDataRecord[DS, NS, T]:
            ...

        def doEquals(self, obj: java.lang.Object) -> bool:
            ...

        def doHashCode(self) -> int:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class DBTreeNodeRecord(DBTreeRecord[NS, NS], typing.Generic[NS]):

    @typing.type_check_only
    class NodeType(java.lang.Enum[DBTreeNodeRecord.NodeType]):

        class_: typing.ClassVar[java.lang.Class]
        DIRECTORY: typing.Final[DBTreeNodeRecord.NodeType]
        LEAF_PARENT: typing.Final[DBTreeNodeRecord.NodeType]
        LEAF: typing.Final[DBTreeNodeRecord.NodeType]
        VALUES: typing.Final[java.util.List[DBTreeNodeRecord.NodeType]]

        def getParentType(self) -> DBTreeNodeRecord.NodeType:
            ...

        def isDirectory(self) -> bool:
            ...

        def isLeaf(self) -> bool:
            ...

        def isLeafParent(self) -> bool:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DBTreeNodeRecord.NodeType:
            ...

        @staticmethod
        def values() -> jpype.JArray[DBTreeNodeRecord.NodeType]:
            ...

        @property
        def leafParent(self) -> jpype.JBoolean:
            ...

        @property
        def leaf(self) -> jpype.JBoolean:
            ...

        @property
        def directory(self) -> jpype.JBoolean:
            ...

        @property
        def parentType(self) -> DBTreeNodeRecord.NodeType:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class DBTreeRecord(ghidra.util.database.DBAnnotatedObject, typing.Generic[RS, NS]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...

    def getBounds(self) -> NS:
        ...

    def getParentKey(self) -> int:
        ...

    def getShape(self) -> RS:
        ...

    def setParentKey(self, parentKey: typing.Union[jpype.JLong, int]):
        ...

    def setShape(self, shape: RS):
        ...

    @property
    def parentKey(self) -> jpype.JLong:
        ...

    @parentKey.setter
    def parentKey(self, value: jpype.JLong):
        ...

    @property
    def shape(self) -> RS:
        ...

    @shape.setter
    def shape(self, value: RS):
        ...

    @property
    def bounds(self) -> NS:
        ...


class AbstractRStarConstraintsTree(AbstractConstraintsTree[DS, DR, NS, NR, T, Q], typing.Generic[DS, DR, NS, NR, T, Q]):
    """
    An R*-Tree implementation of :obj:`AbstractConstraintsTree`
     
     
    
    The implementation follows
    `The R*-tree:
    An Efficient and Robust Access Method for Points and Rectangles <http://dbs.mathematik.uni-marburg.de/publications/myPapers/1990/BKSS90.pdf>`_. Comments in code referring
    to "the paper", specific sections, or steps of algorithms, are referring specifically to that
    paper.
    """

    @typing.type_check_only
    class LeastAreaEnlargementThenLeastArea(java.lang.Comparable[AbstractRStarConstraintsTree.LeastAreaEnlargementThenLeastArea]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, node: NR, bounds: NS):
            ...


    @typing.type_check_only
    class LeastDistanceFromCenterToPoint(java.lang.Comparable[AbstractRStarConstraintsTree.LeastDistanceFromCenterToPoint]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, record: DBTreeRecord[typing.Any, NS], parentBounds: NS):
            ...


    @typing.type_check_only
    class LevelInfo(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dstLevel: typing.Union[jpype.JInt, int]):
            ...

        def checkAndSetReinserted(self) -> bool:
            ...

        def decLevel(self) -> AbstractRStarConstraintsTree.LevelInfo:
            ...

        def incDepth(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, tableName: typing.Union[java.lang.String, str], dataType: java.lang.Class[DR], nodeType: java.lang.Class[NR], upgradable: typing.Union[jpype.JBoolean, bool], maxChildren: typing.Union[jpype.JInt, int]):
        ...


class AbstractConstraintsTreeSpatialMap(SpatialMap[DS, T, Q], typing.Generic[DS, DR, NS, T, Q]):

    @typing.type_check_only
    class ToArrayConsumer(java.util.function.Consumer[T], typing.Generic[A, T, U]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, arr: jpype.JArray[A]):
            ...


    @typing.type_check_only
    class ToListConsumer(java.util.function.Consumer[T], typing.Generic[A, T, U]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, list: java.util.List[A]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: AbstractConstraintsTree[DS, DR, NS, typing.Any, T, Q], query: Q):
        ...


class BoundedShape(java.lang.Object, typing.Generic[S]):

    class_: typing.ClassVar[java.lang.Class]

    def description(self) -> str:
        ...

    def getBounds(self) -> S:
        ...

    @property
    def bounds(self) -> S:
        ...


class SpatialMap(java.lang.Object, typing.Generic[DS, T, Q]):

    class EmptySpatialMap(SpatialMap[DS, T, Q], typing.Generic[DS, T, Q]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EMPTY_MAP: typing.Final[SpatialMap[typing.Any, typing.Any, typing.Any]]

    def clear(self):
        ...

    @staticmethod
    def emptyMap() -> SpatialMap[DS, T, Q]:
        ...

    def entries(self) -> java.util.Collection[java.util.Map.Entry[DS, T]]:
        ...

    def firstEntry(self) -> java.util.Map.Entry[DS, T]:
        ...

    def firstKey(self) -> DS:
        ...

    def firstValue(self) -> T:
        ...

    def isEmpty(self) -> bool:
        ...

    def keys(self) -> java.util.Collection[DS]:
        ...

    def orderedEntries(self) -> java.util.Collection[java.util.Map.Entry[DS, T]]:
        ...

    def orderedKeys(self) -> java.util.Collection[DS]:
        ...

    def orderedValues(self) -> java.util.Collection[T]:
        ...

    def put(self, shape: DS, value: T) -> T:
        """
        Put an entry into the map
         
         
        
        Note that the map may copy, and possibly modify, the given value. The value returned is the
        value actually stored by the map. This may be useful when the map's values are identical to
        its records. This allows the creation of a "blank" entry with a given shape. The entry is
        then populated by the user.
         
        ``class MyDBDataRecord extends DBTreeDataRecord<MyShape, MyNodeShape, MyDBDataRecord> {    &#64;Override    protected void setValue(MyDBDataRecord value) {        // Do nothing: value ought to be null. Map will create and return "blank" record    }    protected MyDBDataRecord getValue() {        return this; // The record is the value    }}MyDBDataRecord rec = map.put(MyShape.create(args), null);rec.setSomething(6);rec.setAnother("My user data");``
         
         
        
        This practice is preferred when the values are not simple, and/or when the shape is a
        property of the value. In other cases, e.g., when the value is an enum or a :obj:`Color`,
        then :meth:`DBTreeDataRecord.setRecordValue(Object) <DBTreeDataRecord.setRecordValue>` and
        :meth:`DBTreeDataRecord.getRecordValue() <DBTreeDataRecord.getRecordValue>` should be implemented as field accessors.
        
        :param DS shape: the shape of the entry
        :param T value: the value for the entry
        :return: the value as stored in the map
        :rtype: T
        """

    def reduce(self, query: Q) -> SpatialMap[DS, T, Q]:
        ...

    @typing.overload
    def remove(self, shape: DS, value: T) -> bool:
        """
        Remove an entry from the map
         
         
        
        Removes a single matching entry, if found, from the map. If you have a reference to an entry
        obtained from this map, use :meth:`remove(Entry) <.remove>` instead. Otherwise, this is the preferred
        method.
        
        :param DS shape: the shape of the entry to remove
        :param T value: the value of the entry to remove
        :return: true if the map was modified
        :rtype: bool
        """

    @typing.overload
    def remove(self, entry: java.util.Map.Entry[DS, T]) -> bool:
        """
        Remove an entry from the map
         
         
        
        This method is preferred *only* when the given entry comes directly from this map.
        This spares the implementation from having to search for a matching entry. If the entry does
        not come from this map, it will behave like :meth:`remove(BoundedShape, Object) <.remove>`.
        
        :param java.util.Map.Entry[DS, T] entry: the entry to remove
        :return: true if the map was modified
        :rtype: bool
        """

    def size(self) -> int:
        """
        Get or compute the size of this map
         
         
        
        Note that this may not necessarily be a quick operation, esp., if this map is the result of
        :meth:`reduce(Object) <.reduce>`. In the worst case, all elements in the reduced map will be visited.
        
        :return: the number of data entries in the map
        :rtype: int
        """

    def values(self) -> java.util.Collection[T]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class BoundingShape(BoundedShape[S], typing.Generic[S]):

    class_: typing.ClassVar[java.lang.Class]

    def computeAreaIntersection(self, shape: S) -> float:
        ...

    def computeAreaUnionBounds(self, shape: S) -> float:
        ...

    def computeCentroidDistance(self, shape: S) -> float:
        ...

    def encloses(self, shape: S) -> bool:
        ...

    def getArea(self) -> float:
        ...

    def getMargin(self) -> float:
        ...

    def unionBounds(self, shape: S) -> S:
        ...

    @staticmethod
    def unionIterable(shapes: collections.abc.Sequence) -> S:
        ...

    @property
    def area(self) -> jpype.JDouble:
        ...

    @property
    def margin(self) -> jpype.JDouble:
        ...


class AbstractConstraintsTree(java.lang.Object, typing.Generic[DS, DR, NS, NR, T, Q]):

    @typing.type_check_only
    class VisitResult(java.lang.Enum[AbstractConstraintsTree.VisitResult]):

        class_: typing.ClassVar[java.lang.Class]
        TERMINATE: typing.Final[AbstractConstraintsTree.VisitResult]
        NEXT: typing.Final[AbstractConstraintsTree.VisitResult]
        DESCEND: typing.Final[AbstractConstraintsTree.VisitResult]
        ASCEND: typing.Final[AbstractConstraintsTree.VisitResult]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AbstractConstraintsTree.VisitResult:
            ...

        @staticmethod
        def values() -> jpype.JArray[AbstractConstraintsTree.VisitResult]:
            ...


    @typing.type_check_only
    class TreeRecordVisitor(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, storeFactory: ghidra.util.database.DBCachedObjectStoreFactory, tableName: typing.Union[java.lang.String, str], dataType: java.lang.Class[DR], nodeType: java.lang.Class[NR], upgradable: typing.Union[jpype.JBoolean, bool]):
        ...

    def asSpatialMap(self) -> AbstractConstraintsTreeSpatialMap[DS, DR, NS, T, Q]:
        ...

    def checkIntegrity(self):
        """
        An integrity checker for use by tree developers and testers.
         
         
        
        To incorporate additional checks, please prefer to override
        :meth:`checkNodeIntegrity(DBTreeNodeRecord) <.checkNodeIntegrity>` and/or
        :meth:`checkDataIntegrity(DBTreeDataRecord) <.checkDataIntegrity>` instead of this method.
        """

    def getDataByKey(self, key: typing.Union[jpype.JLong, int]) -> DR:
        ...

    def getUserIndex(self, fieldClass: java.lang.Class[K], column: ghidra.util.database.DBObjectColumn) -> ghidra.util.database.DBCachedObjectIndex[K, DR]:
        ...

    def invalidateCache(self):
        ...

    @property
    def dataByKey(self) -> DR:
        ...



__all__ = ["Query", "DBTreeDataRecord", "DBTreeNodeRecord", "DBTreeRecord", "AbstractRStarConstraintsTree", "AbstractConstraintsTreeSpatialMap", "BoundedShape", "SpatialMap", "BoundingShape", "AbstractConstraintsTree"]
