from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.trace.model
import ghidra.trace.model.target
import ghidra.trace.model.target.path
import java.lang # type: ignore
import java.util.stream # type: ignore


class CanonicalSuccessorsRelativeVisitor(TreeTraversal.Visitor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter: ghidra.trace.model.target.path.PathFilter):
        ...


class OrderedSuccessorsVisitor(TreeTraversal.SpanIntersectingVisitor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: ghidra.trace.model.target.path.KeyPath, forward: typing.Union[jpype.JBoolean, bool]):
        ...


class AncestorsRootVisitor(TreeTraversal.SpanIntersectingVisitor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter: ghidra.trace.model.target.path.PathFilter):
        ...


class SuccessorsRelativeVisitor(TreeTraversal.SpanIntersectingVisitor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter: ghidra.trace.model.target.path.PathFilter):
        ...


class AllPathsVisitor(java.lang.Enum[AllPathsVisitor], TreeTraversal.SpanIntersectingVisitor):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[AllPathsVisitor]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> AllPathsVisitor:
        ...

    @staticmethod
    def values() -> jpype.JArray[AllPathsVisitor]:
        ...


class TreeTraversal(java.lang.Enum[TreeTraversal]):
    """
    Support for traversing a trace's object tree
     
     
    
    Many of these are already built into the object and value interfaces. Direct use of this
    traversal support is only needed when performing customized traversals. In most cases, it's
    sufficient to use a built-in traversal and filter the resulting stream. Customized traversal is
    only needed when it's beneficial to prune subtrees in a way that no built-in traversal provides.
    """

    class VisitResult(java.lang.Enum[TreeTraversal.VisitResult]):
        """
        A result directing the traversal how to proceed
        """

        class_: typing.ClassVar[java.lang.Class]
        INCLUDE_DESCEND: typing.Final[TreeTraversal.VisitResult]
        """
        Include the value that was just traversed, and descend
        """

        INCLUDE_PRUNE: typing.Final[TreeTraversal.VisitResult]
        """
        Include the value that was just traversed, but prune its subtree
        """

        EXCLUDE_DESCEND: typing.Final[TreeTraversal.VisitResult]
        """
        Exclude the value that was just traversed, but descend
        """

        EXCLUDE_PRUNE: typing.Final[TreeTraversal.VisitResult]
        """
        Exclude the value that was just traversed, and prune its subtree
        """


        @staticmethod
        def result(include: typing.Union[jpype.JBoolean, bool], cont: typing.Union[jpype.JBoolean, bool]) -> TreeTraversal.VisitResult:
            """
            Get the result that indicates the given inclusion and continuation
            
            :param jpype.JBoolean or bool include: true to include the value just traversed, false to exclude
            :param jpype.JBoolean or bool cont: true to continue traversal, false to terminate
            :return: the result
            :rtype: TreeTraversal.VisitResult
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TreeTraversal.VisitResult:
            ...

        @staticmethod
        def values() -> jpype.JArray[TreeTraversal.VisitResult]:
            ...


    class Visitor(java.lang.Object):
        """
        An object-tree visitor
         
         
        
        Traversal starts at a seed object or value (node or edge, respectively) and proceeds in
        alternating fashion from object to value to object and so on via
        :meth:`continueObject(TraceObjectValue) <.continueObject>` and
        :meth:`continueValues(TraceObject, Lifespan, TraceObjectValPath) <.continueValues>`. Filtering is performed on
        values via :meth:`visitValue(TraceObjectValue, TraceObjectValPath) <.visitValue>`. As traversal descends,
        paths and spans are composed to inform filtering and construct the final result stream. Note
        that some traversals start at a seed and "descend" along the ancestry.
        """

        class_: typing.ClassVar[java.lang.Class]

        def composePath(self, pre: ghidra.trace.model.target.TraceObjectValPath, value: ghidra.trace.model.target.TraceObjectValue) -> ghidra.trace.model.target.TraceObjectValPath:
            """
            When descending in a value, what path leads to the value
             
             
            
            This is usually :meth:`TraceObjectValPath.append(TraceObjectValue) <TraceObjectValPath.append>` or
            :meth:`TraceObjectValPath.prepend(TraceObjectValue) <TraceObjectValPath.prepend>`.
            
            :param ghidra.trace.model.target.TraceObjectValPath pre: the path from seed to the but excluding the current value
            :param ghidra.trace.model.target.TraceObjectValue value: the path from seed to the and including the current value
            :return: the path from seed to and including the current value
            :rtype: ghidra.trace.model.target.TraceObjectValPath
            """

        def composeSpan(self, pre: ghidra.trace.model.Lifespan, value: ghidra.trace.model.target.TraceObjectValue) -> ghidra.trace.model.Lifespan:
            """
            When descending in a value, what span to consider in the subtree
             
             
            
            Usually this is intersection. See :obj:`SpanIntersectingVisitor`
            
            :param ghidra.trace.model.Lifespan pre: the span composed from values from seed to but excluding the current value
            :param ghidra.trace.model.target.TraceObjectValue value: the current value
            :return: the span composed from values from seed to and including the current value
            :rtype: ghidra.trace.model.Lifespan
            """

        def continueObject(self, value: ghidra.trace.model.target.TraceObjectValue) -> ghidra.trace.model.target.TraceObject:
            """
            When descending in a value, the object to consider next
             
             
            
            This is usually :meth:`TraceObjectValue.getChild() <TraceObjectValue.getChild>` or
            :meth:`TraceObjectValue.getParent() <TraceObjectValue.getParent>`.
            
            :param ghidra.trace.model.target.TraceObjectValue value: the current value
            :return: the next object
            :rtype: ghidra.trace.model.target.TraceObject
            """

        def continueValues(self, object: ghidra.trace.model.target.TraceObject, span: ghidra.trace.model.Lifespan, path: ghidra.trace.model.target.TraceObjectValPath) -> java.util.stream.Stream[ghidra.trace.model.target.TraceObjectValue]:
            """
            When descending in an object, the values to consider next
            
            :param ghidra.trace.model.target.TraceObject object: the current object
            :param ghidra.trace.model.Lifespan span: the composed span of values from seed to the current object
            :param ghidra.trace.model.target.TraceObjectValPath path: the path from seed to the current object
            :return: the next values
            :rtype: java.util.stream.Stream[ghidra.trace.model.target.TraceObjectValue]
            """

        def visitValue(self, value: ghidra.trace.model.target.TraceObjectValue, path: ghidra.trace.model.target.TraceObjectValPath) -> TreeTraversal.VisitResult:
            """
            Visit a value
             
             
            
            Note that the path is the composed path, so it will likely have the current value at its
            beginning or end.
            
            :param ghidra.trace.model.target.TraceObjectValue value: the current value
            :param ghidra.trace.model.target.TraceObjectValPath path: the path from seed to value
            :return: directions for how traversal should proceed
            :rtype: TreeTraversal.VisitResult
            """


    class SpanIntersectingVisitor(TreeTraversal.Visitor):
        """
        A visitor providing default :meth:`composeSpan(Lifespan, TraceObjectValue) <.composeSpan>` that intersects
        the spans
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[TreeTraversal]
    """
    The singleton instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TreeTraversal:
        ...

    @staticmethod
    def values() -> jpype.JArray[TreeTraversal]:
        ...

    def walkObject(self, visitor: TreeTraversal.Visitor, object: ghidra.trace.model.target.TraceObject, span: ghidra.trace.model.Lifespan, path: ghidra.trace.model.target.TraceObjectValPath) -> java.util.stream.Stream[ghidra.trace.model.target.TraceObjectValPath]:
        """
        Walk an object and its subtree
        
        :param TreeTraversal.Visitor visitor: the visitor
        :param ghidra.trace.model.target.TraceObject object: the current object
        :param ghidra.trace.model.Lifespan span: the composed span from seed to current object
        :param ghidra.trace.model.target.TraceObjectValPath path: the path from seed to current object
        :return: the result stream of the object and subtree walked
        :rtype: java.util.stream.Stream[ghidra.trace.model.target.TraceObjectValPath]
        """

    def walkValue(self, visitor: TreeTraversal.Visitor, value: ghidra.trace.model.target.TraceObjectValue, span: ghidra.trace.model.Lifespan, path: ghidra.trace.model.target.TraceObjectValPath) -> java.util.stream.Stream[ghidra.trace.model.target.TraceObjectValPath]:
        """
        Walk a value and possibly its subtree
        
        :param TreeTraversal.Visitor visitor: the visitor
        :param ghidra.trace.model.target.TraceObjectValue value: the current value
        :param ghidra.trace.model.Lifespan span: the composed span from seed to but excluding the current value
        :param ghidra.trace.model.target.TraceObjectValPath path: the path from seed to but excluding the current value
        :return: the result stream of the value and subtree walked
        :rtype: java.util.stream.Stream[ghidra.trace.model.target.TraceObjectValPath]
        """


class AncestorsRelativeVisitor(TreeTraversal.SpanIntersectingVisitor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter: ghidra.trace.model.target.path.PathFilter):
        ...



__all__ = ["CanonicalSuccessorsRelativeVisitor", "OrderedSuccessorsVisitor", "AncestorsRootVisitor", "SuccessorsRelativeVisitor", "AllPathsVisitor", "TreeTraversal", "AncestorsRelativeVisitor"]
