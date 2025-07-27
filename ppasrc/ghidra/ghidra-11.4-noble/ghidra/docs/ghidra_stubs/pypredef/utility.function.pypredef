from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util.function # type: ignore


E = typing.TypeVar("E")
I = typing.TypeVar("I")
R = typing.TypeVar("R")
T = typing.TypeVar("T")
U = typing.TypeVar("U")


class TerminatingConsumer(java.util.function.Consumer[T], typing.Generic[T]):
    """
    TerminatingConsumer is a Consumer :obj:`Consumer` that can request termination
    of the supplier once some condition is reached, for example some number of consumed results
    accepted.  If termination is required override the terminationRequested()
    method to return true when termination state is reached.
    """

    class_: typing.ClassVar[java.lang.Class]

    def terminationRequested(self) -> bool:
        ...


class ExceptionalConsumer(java.lang.Object, typing.Generic[T, E]):
    """
    A generic functional interface that allows you to consume an item and potentially throw
    an exception.
    """

    class_: typing.ClassVar[java.lang.Class]

    def accept(self, t: T):
        """
        The method that will be called
        
        :param T t: the input
        :raises E: if the call throws an exception
        """


class ExceptionalCallback(java.lang.Object, typing.Generic[E]):
    """
    A generic functional interface that is more semantically sound than :obj:`Runnable`.  Use
    anywhere you wish to have a generic callback function and you need to throw an exception.
    """

    class_: typing.ClassVar[java.lang.Class]

    def call(self):
        """
        The method that will be called
        
        :raises E: if the call throws an exception
        """


class ExceptionalSupplier(java.lang.Object, typing.Generic[T, E]):
    """
    A generic functional interface that is more semantically sound than :obj:`Runnable`.  Use
    anywhere you wish to have a generic callback function and you need to throw an exception.
    """

    class_: typing.ClassVar[java.lang.Class]

    def get(self) -> T:
        """
        The supplier method
        
        :return: the item to return
        :rtype: T
        :raises E: the declared exception
        """


class ExceptionalFunction(java.lang.Object, typing.Generic[I, R, E]):
    """
    A generic functional interface that allows you to consume an item, return a result, 
    and potentially throw an exception.
    """

    class_: typing.ClassVar[java.lang.Class]

    def apply(self, i: I) -> R:
        """
        The method that will be called
        
        :param I i: the input
        :return: the result of the call
        :rtype: R
        :raises E: if the call throws an exception
        """


class Callback(java.lang.Object):
    """
    A generic functional interface that is more semantically sound than :obj:`Runnable`.  Use
    anywhere you wish to have a generic callback function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def call(self):
        """
        The method that will be called.
        """

    @staticmethod
    def dummy() -> Callback:
        """
        Creates a dummy callback function.  This is useful to avoid using ``null``.
        
        :return: a dummy callback function
        :rtype: Callback
        """

    @staticmethod
    def dummyIfNull(c: Callback) -> Callback:
        """
        Returns the given callback object if it is not ``null``.  Otherwise, a :meth:`dummy() <.dummy>` 
        callback is returned.  This is useful to avoid using ``null``.
        
        :param Callback c: the callback function to check for ``null``
        :return: a non-null callback function
        :rtype: Callback
        """


class Dummy(java.lang.Object):
    """
    A utility class to help create dummy stub functional interfaces
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def biConsumer() -> java.util.function.BiConsumer[T, U]:
        """
        Creates a dummy consumer
        
        :return: a dummy consumer
        :rtype: java.util.function.BiConsumer[T, U]
        """

    @staticmethod
    def biPredicate() -> java.util.function.BiPredicate[T, U]:
        """
        Creates a dummy :obj:`BiPredicate` that always returns true.
        
        :param T: the type of the first argument to the predicate:param U: the type of the second argument the predicate:return: the BiPredicate that always returns true
        :rtype: java.util.function.BiPredicate[T, U]
        """

    @staticmethod
    def callback() -> Callback:
        """
        Creates a dummy callback
        
        :return: a dummy callback
        :rtype: Callback
        """

    @staticmethod
    def consumer() -> java.util.function.Consumer[T]:
        """
        Creates a dummy consumer
        
        :return: a dummy consumer
        :rtype: java.util.function.Consumer[T]
        """

    @staticmethod
    def function() -> java.util.function.Function[T, R]:
        """
        Creates a dummy function
        
        :param T: the input type:param R: the result type:return: the function
        :rtype: java.util.function.Function[T, R]
        """

    @staticmethod
    @typing.overload
    def ifNull(c: java.util.function.Consumer[T]) -> java.util.function.Consumer[T]:
        """
        Returns the given consumer object if it is not ``null``.  Otherwise, a :meth:`consumer() <.consumer>`
        is returned.  This is useful to avoid using ``null``.
        
        :param java.util.function.Consumer[T] c: the consumer function to check for ``null``
        :return: a non-null consumer
        :rtype: java.util.function.Consumer[T]
        """

    @staticmethod
    @typing.overload
    def ifNull(c: java.util.function.BiConsumer[T, U]) -> java.util.function.BiConsumer[T, U]:
        """
        Returns the given consumer object if it is not ``null``.  Otherwise, a 
        :meth:`biConsumer() <.biConsumer>` is returned.  This is useful to avoid using ``null``.
        
        :param java.util.function.BiConsumer[T, U] c: the consumer function to check for ``null``
        :return: a non-null consumer
        :rtype: java.util.function.BiConsumer[T, U]
        """

    @staticmethod
    @typing.overload
    def ifNull(c: Callback) -> Callback:
        """
        Returns the given callback object if it is not ``null``.  Otherwise, a :meth:`callback() <.callback>`
        is returned.  This is useful to avoid using ``null``.
        
        :param Callback c: the callback function to check for ``null``
        :return: a non-null callback function
        :rtype: Callback
        """

    @staticmethod
    @typing.overload
    def ifNull(f: java.util.function.Function[T, R]) -> java.util.function.Function[T, R]:
        """
        Returns the given function object if it is not ``null``.  Otherwise, a
        :meth:`function() <.function>` is returned.  This is useful to avoid using ``null``.
        
        :param T: the input type:param R: the result type:param java.util.function.Function[T, R] f: the function to check for ``null``
        :return: a non-null function
        :rtype: java.util.function.Function[T, R]
        """

    @staticmethod
    @typing.overload
    def ifNull(s: java.util.function.Supplier[T]) -> java.util.function.Supplier[T]:
        """
        Returns the given callback object if it is not ``null``.  Otherwise, a :meth:`callback() <.callback>`
        is returned.  This is useful to avoid using ``null``.
        
        :param java.util.function.Supplier[T] s: the supplier function to check for ``null``
        :return: a non-null supplier
        :rtype: java.util.function.Supplier[T]
        """

    @staticmethod
    @typing.overload
    def ifNull(r: java.lang.Runnable) -> java.lang.Runnable:
        """
        Returns the given runnable object if it is not ``null``.  Otherwise, a :meth:`runnable() <.runnable>`
        is returned.  This is useful to avoid using ``null``.
        
        :param java.lang.Runnable r: the runnable function to check for ``null``
        :return: a non-null runnable
        :rtype: java.lang.Runnable
        """

    @staticmethod
    @typing.overload
    def ifNull(p: java.util.function.Predicate[T]) -> java.util.function.Predicate[T]:
        """
        Returns the given Predicate object if it is not ``null``.  Otherwise, a 
        :meth:`predicate() <.predicate>` (which always returns true) is returned.  This is useful to avoid
        using ``null``.
        
        :param java.util.function.Predicate[T] p: the predicate function to check for ``null``
        :return: a non-null predicate
        :rtype: java.util.function.Predicate[T]
        """

    @staticmethod
    @typing.overload
    def ifNull(p: java.util.function.BiPredicate[T, U]) -> java.util.function.BiPredicate[T, U]:
        """
        Returns the given BiPredicate object if it is not ``null``.  Otherwise, a 
        :meth:`biPredicate() <.biPredicate>` (which always returns true) is returned.  This is useful to avoid
        using ``null``.
        
        :param java.util.function.BiPredicate[T, U] p: the predicate function to check for ``null``
        :return: a non-null predicate
        :rtype: java.util.function.BiPredicate[T, U]
        """

    @staticmethod
    def predicate() -> java.util.function.Predicate[T]:
        """
        Creates a dummy :obj:`Predicate` that always returns true.
        
        :param T: the type of the value being tested:return: the predicate that always returns true
        :rtype: java.util.function.Predicate[T]
        """

    @staticmethod
    def runnable() -> java.lang.Runnable:
        """
        Creates a dummy runnable
        
        :return: the runnable
        :rtype: java.lang.Runnable
        """

    @staticmethod
    def supplier() -> java.util.function.Supplier[T]:
        """
        Creates a dummy supplier
        
        :param T: the result type:return: the supplier
        :rtype: java.util.function.Supplier[T]
        """



__all__ = ["TerminatingConsumer", "ExceptionalConsumer", "ExceptionalCallback", "ExceptionalSupplier", "ExceptionalFunction", "Callback", "Dummy"]
