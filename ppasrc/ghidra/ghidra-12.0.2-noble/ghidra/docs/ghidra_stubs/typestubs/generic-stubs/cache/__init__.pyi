from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


K = typing.TypeVar("K")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class CountingBasicFactory(BasicFactory[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def doCreate(self, itemNumber: typing.Union[jpype.JInt, int]) -> T:
        """
        The method subclass use to create :obj:`T`s.
        
        :param jpype.JInt or int itemNumber: the number of the item being created--
                                **one-based**; the first item 
                            is item ``1``.
        :return: a new instance of :obj:`T`.
        :rtype: T
        :raises java.lang.Exception: any Exception encountered during creation
        """

    def doDispose(self, t: T):
        ...


class CachingPool(java.lang.Object, typing.Generic[T]):
    """
    A thread-safe pool that knows how to create instances as needed.  When clients are done
    with the pooled item they then call :meth:`release(Object) <.release>`, thus enabling them to be
    re-used in the future.
    
     
    Calling :meth:`setCleanupTimeout(long) <.setCleanupTimeout>` with a non-negative value will start a timer when
    :meth:`release(Object) <.release>` is called to :meth:`BasicFactory.dispose(Object) <BasicFactory.dispose>` any objects in the
    pool.   By default, the cleanup timer does not run.
    
     
    Once :meth:`dispose() <.dispose>` has been called on this class, items created or released will no
    longer be pooled.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: BasicFactory[T]):
        """
        Creates a new pool that uses the given factory to create new items as needed
        
        :param BasicFactory[T] factory: the factory used to create new items
        """

    def dispose(self):
        """
        Triggers all pooled object to be disposed via this pool's factory.   Future calls to
        :meth:`get() <.get>` will still create new objects, but the internal cache will no longer be used.
        """

    def get(self) -> T:
        """
        Returns a cached or new ``T``
        
        :return: a cached or new ``T``
        :rtype: T
        :raises java.lang.Exception: if there is a problem instantiating a new instance
        """

    def release(self, t: T):
        """
        Signals that the given object is no longer being used.  The object will be placed back into
        the pool until it is disposed via the cleanup timer, if it is running.
        
        :param T t: the item to release
        """

    def setCleanupTimeout(self, timeout: typing.Union[jpype.JLong, int]):
        """
        Sets the time to wait for released items to be disposed by this pool by calling
        :meth:`BasicFactory.dispose(Object) <BasicFactory.dispose>`.  A negative timeout value signals to disable
        the cleanup task.
        
         
        When clients call :meth:`get() <.get>`, the timer will not be running.  It will be restarted
        again once :meth:`release(Object) <.release>` has been called.
        
        :param jpype.JLong or int timeout: the new timeout.
        """


class FixedSizeMRUCachingFactory(Factory[K, V], typing.Generic[K, V]):
    """
    An object that will cache values returned from the given factory.  This class lets you combine
    the work of building items as needed with cache maintenance operations, such as get and put 
    (and move, in the case of a sized cache).
       
     
    
    The caching of this class
    is bound by the size parameter of the constructor.   Further, the caching strategy is an 
    Most Recently Used strategy, meaning that the least accessed cache items will fall off of the
    cache.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: Factory[K, V], size: typing.Union[jpype.JInt, int]):
        ...


class Factory(java.lang.Object, typing.Generic[K, V]):
    """
    A simple interface that can build, lookup or otherwise return a value ``V`` for a
    key ``K``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def get(self, key: K) -> V:
        ...


class BasicFactory(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def create(self) -> T:
        """
        Creates an instance of :obj:`T`.
        
        :return: the new instance of T
        :rtype: T
        :raises java.lang.Exception: any Exception encountered during creation
        """

    def dispose(self, t: T):
        """
        Called when clients are finished with the given item and it should be disposed.
        
        :param T t: the item to dispose.
        """



__all__ = ["CountingBasicFactory", "CachingPool", "FixedSizeMRUCachingFactory", "Factory", "BasicFactory"]
