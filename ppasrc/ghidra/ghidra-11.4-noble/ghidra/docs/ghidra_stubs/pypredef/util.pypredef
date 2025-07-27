from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import java.util.stream # type: ignore


T = typing.TypeVar("T")


class HistoryList(java.lang.Object, typing.Generic[T]):
    """
    An object meant to track items with the ability to go back and forth within the list of
    items.
     
     
    By default, duplicate entries are not allowed.  This allows for a simplified history of
    unique items.  If the client prefers to have an accurate history, then call
    :meth:`setAllowDuplicates(boolean) <.setAllowDuplicates>` in order to keep all history entries.
     
     
    By default, null values are not allowed.  If the client allows null/empty values, then
    they should call :meth:`setAllowNulls(boolean) <.setAllowNulls>` with a value of true.  This allows the
    backward navigation to work correctly when the client's active item is cleared.  When that 
    item is cleared, then client is expected to call :meth:`add(Object) <.add>` with value of 
    null.  (This is safe to do, regardless of whether null are allowed).  When nulls are allowed
    and a null value is received, then current item is placed onto the history stack as the 
    previous item.  This way, when the user presses the back button, the last visible item 
    will be activated.  
     
     
    Note: when nulls are allowed, only a single null value will be stored.  Further, 
    if new, non-null items are added, then the null value is dropped.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, size: typing.Union[jpype.JInt, int], itemSelectedCallback: java.util.function.Consumer[T]):
        """
        The sized passed here limits the size of the list, with the oldest items being dropped
        as the list grows.  The given callback will be called when :meth:`goBack() <.goBack>` or 
        :meth:`goForward() <.goForward>` are called.
        
        :param jpype.JInt or int size: the max number of items to keep in the list
        :param java.util.function.Consumer[T] itemSelectedCallback: the function to call when the client selects an item by 
                going back or forward
        """

    @typing.overload
    def __init__(self, size: typing.Union[jpype.JInt, int], itemSelectedCallback: java.util.function.BiConsumer[T, T]):
        """
        The sized passed here limits the size of the list, with the oldest items being dropped
        as the list grows.  The given callback will be called when :meth:`goBack() <.goBack>` or 
        :meth:`goForward() <.goForward>` are called.
        
        :param jpype.JInt or int size: the max number of items to keep in the list
        :param java.util.function.BiConsumer[T, T] itemSelectedCallback: the function to call when the client selects an item by 
                going back or forward.  This callback will be passed the newly selected item as 
                the first argument and the previously selected item as the second argument.
        """

    def add(self, t: T):
        """
        Adds an item to this history list.  ``null`` values are ignored.
         
         
        Calls to this method during selection notification will have no effect.  If you need
        to update the history during a notification, then you must do so at a later time, perhaps
        by using  :meth:`SystemUtilities.runSwingLater(Runnable) <SystemUtilities.runSwingLater>`.
        
        :param T t: the item to add.
        """

    def clear(self):
        """
        Clears all history entries and resets the current item pointer.
        """

    def getCurrentHistoryItem(self) -> T:
        """
        Returns the item currently pointed to within the list of items.  When an item is 
        added, this will be that item.  Otherwise, it will be the last item navigated.
        
        :return: the item currently pointed to within the list of items.
        :rtype: T
        """

    def getNextHistoryItems(self) -> java.util.List[T]:
        """
        Get all items in the history that come after the current history item.  They are 
        returned in navigation order, as traversed if :meth:`goForward() <.goForward>` is called.
        
        :return: the items
        :rtype: java.util.List[T]
        """

    def getPreviousHistoryItems(self) -> java.util.List[T]:
        """
        Get all items in the history that come before the current history item.  They are 
        returned in navigation order, as traversed if :meth:`goBack() <.goBack>` is called.
        
        :return: the items
        :rtype: java.util.List[T]
        """

    def goBack(self):
        """
        Moves this history list's current item pointer back one and then calls the user-provided
        callback to signal the newly selected item.
         
         
        No action is taken if the current pointer is already at the beginning of the list.
        """

    def goBackTo(self, t: T):
        """
        Performs a :meth:`goBack() <.goBack>` until the given item becomes the current item.  This is 
        useful if you wish to go backward to a specific item in the list.
        
        :param T t: the item
        """

    def goForward(self):
        """
        Moves this history list's current item pointer forward one and then calls the user-provided
        callback to signal the newly selected item.
         
         
        No action is taken if the current pointer is already at the end of the list.
        """

    def goForwardTo(self, t: T):
        """
        Performs a :meth:`goForward() <.goForward>` until the given item becomes the current item.  This is 
        useful if you wish to go forward to a specific item in the list.
        
        :param T t: the item
        """

    def hasNext(self) -> bool:
        """
        Returns true if this history list's current item pointer is not at the end of the list.
        
        :return: true if this history list's current item pointer is not at the end of the list.
        :rtype: bool
        """

    def hasPrevious(self) -> bool:
        """
        Returns true if this history list's current item pointer is not at the beginning of the list.
        
        :return: true if this history list's current item pointer is not at the beginning of the list.
        :rtype: bool
        """

    def setAllowDuplicates(self, allowDuplicates: typing.Union[jpype.JBoolean, bool]):
        """
        True signals that this list will allow duplicate entries.  False signals to not only not
        allow duplicates, but to also move the position of an item if it is re-added to the 
        list.
           
         
        For correct behavior when not allowing duplicates, ensure you have defined an 
        ``equals`` method to work as you expect.  If two different items are considered
        equal, then this class will only remove the duplicate if the equals method returns true.
         
         
        The default is false
        
        :param jpype.JBoolean or bool allowDuplicates: true to allow duplicates
        """

    def setAllowNulls(self, allowNulls: typing.Union[jpype.JBoolean, bool]):
        """
        True signals that the client allows null items to be used.  When this is true, a null
        value will be stored in this list **only as the last item**.  See the javadoc for 
        more info.
        
        :param jpype.JBoolean or bool allowNulls: true to allow nulls; the default is false
        """

    def size(self) -> int:
        """
        Returns the number of items in this history list
        
        :return: the number of items in this history list
        :rtype: int
        """

    @property
    def previousHistoryItems(self) -> java.util.List[T]:
        ...

    @property
    def nextHistoryItems(self) -> java.util.List[T]:
        ...

    @property
    def currentHistoryItem(self) -> T:
        ...


class CollectionUtils(java.lang.Object):
    """
    A collection of utility methods that prevent you from having to do unsafe casts of
    :obj:`Collection` classes due to runtime type erasure.
    
     
    Be sure to check Apache collection utils before using this class, as it's a
    standard utility and often more efficient.
    
     
    Some examples:
     
    1. :obj:`org.apache.commons.collections4.CollectionUtils`
    2. :obj:`IterableUtils`
    3. :obj:`IteratorUtils`
    4. :meth:`StringUtils.join(Iterable, char) <StringUtils.join>` - for pretty printing collections with newlines
    5. Apache CollectionUtils.collect(Collection, Transformer) - to turn a
    collection in to collection of strings when the defaulttoString() is lacking
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def any(c: collections.abc.Sequence) -> T:
        """
        Returns an element from the given collection; null if the collection is null or empty.
        This is meant for clients that have a collection with any number of items and just need
        to get one.
        
        :param collections.abc.Sequence c: the collection
        :return: the item
        :rtype: T
        """

    @staticmethod
    @typing.overload
    def any(iterable: collections.abc.Sequence) -> T:
        """
        Returns an element from the given iterable; null if the iterable is null or empty.
        This is meant for clients that have a collection with any number of items and just need
        to get one.
        
        :param collections.abc.Sequence iterable: the items
        :return: the item
        :rtype: T
        """

    @staticmethod
    def asCancellableIterable(monitor: ghidra.util.task.TaskMonitor, *iterables: collections.abc.Sequence) -> java.lang.Iterable[T]:
        """
        Combines all collections passed-in into a pass-through (not creating a new collection)
        Iterable that uses the given task monitor.
        
        :param ghidra.util.task.TaskMonitor monitor: a task monitor that allows for cancelling iteration
        :param jpype.JArray[java.lang.Iterable[T]] iterables: the iterables to combine
        :return: the iterable
        :rtype: java.lang.Iterable[T]
        """

    @staticmethod
    @typing.overload
    def asCollection(c: collections.abc.Sequence) -> java.util.Collection[T]:
        """
        Returns the given collection if not null, an empty collection otherwise.  This is
        useful for clients avoid null checks.
        
        :param collections.abc.Sequence c: the collection to check
        :return: a non-null collection
        :rtype: java.util.Collection[T]
        """

    @staticmethod
    @typing.overload
    def asCollection(collection: collections.abc.Sequence, clazz: java.lang.Class[T]) -> java.util.Collection[T]:
        """
        Checks that the elements in the given collection are of the type specified by
        ``clazz`` and then casts the collection to be of the specified type.
        
        :param collections.abc.Sequence collection: the source collection
        :param java.lang.Class[T] clazz: the class of T
        :return: a casted list of type T
        :rtype: java.util.Collection[T]
        :raises IllegalArgumentException: if the given collection contains elements that are
                not of the type specified by ``clazz``.
        """

    @staticmethod
    @typing.overload
    def asIterable(t: T) -> java.lang.Iterable[T]:
        """
        Turns the given item into an iterable
        
        :param T t: the object from which to create an iterable
        :return: an iterable over the given iterator
        :rtype: java.lang.Iterable[T]
        """

    @staticmethod
    @typing.overload
    def asIterable(iterator: java.util.Iterator[T]) -> java.lang.Iterable[T]:
        """
        Returns an iterable over an iterator
        
        :param java.util.Iterator[T] iterator: the iterator to create an iterable from
        :return: an iterable over the given iterator
        :rtype: java.lang.Iterable[T]
        """

    @staticmethod
    @typing.overload
    def asIterable(*iterables: collections.abc.Sequence) -> java.lang.Iterable[T]:
        """
        Combines all collections passed-in into a pass-through (not creating a new collection)
        Iterable.
        
        :param jpype.JArray[java.lang.Iterable[T]] iterables: the iterables to combine
        :return: the iterable
        :rtype: java.lang.Iterable[T]
        """

    @staticmethod
    @typing.overload
    def asList(*items: T) -> java.util.List[T]:
        """
        Similar to :meth:`Arrays.asList(Object...) <Arrays.asList>`, except that this method will turn a single
        null parameter into an empty list.  Also, this method creates a new, mutable array,
        whereas the former's array is not mutable.
        
        :param jpype.JArray[T] items: the items to add to the list
        :return: the list
        :rtype: java.util.List[T]
        """

    @staticmethod
    @typing.overload
    def asList(list: java.util.List[T]) -> java.util.List[T]:
        """
        Returns the given list if not null, otherwise returns an empty list. This is
        useful for clients avoid null checks.
        
        :param java.util.List[T] list: the list to check
        :return: a non-null collection
        :rtype: java.util.List[T]
        """

    @staticmethod
    @typing.overload
    def asList(c: collections.abc.Sequence) -> java.util.List[T]:
        """
        A convenient way to check for null and whether the given collection is a :obj:`List`.
        If the value is a list, then it is returned.  If the value is null, an empty list is
        returned.  Otherwise, a new list is created from the given collection.
        
        :param collections.abc.Sequence c: the collection to check
        :return: a list
        :rtype: java.util.List[T]
        """

    @staticmethod
    @typing.overload
    def asList(enumeration: java.util.Enumeration[T]) -> java.util.List[T]:
        ...

    @staticmethod
    @typing.overload
    def asList(it: collections.abc.Sequence) -> java.util.List[T]:
        ...

    @staticmethod
    @typing.overload
    def asList(it: java.util.Iterator[T]) -> java.util.List[T]:
        ...

    @staticmethod
    @typing.overload
    def asList(list: java.util.List[typing.Any], clazz: java.lang.Class[T]) -> java.util.List[T]:
        """
        Checks that the elements in the given list are of the type specified by ``clazz``
        and then casts the list to be of the specified type.
        
        :param java.util.List[typing.Any] list: the source list
        :param java.lang.Class[T] clazz: the class of T
        :return: a casted list of type T
        :rtype: java.util.List[T]
        :raises IllegalArgumentException: if the given list contains elements that are not of the
                type specified by ``clazz``.
        """

    @staticmethod
    @typing.overload
    def asSet(*items: T) -> java.util.Set[T]:
        """
        Turns the given items into a set.  If there is only a single item and it is null, then
        an empty set will be returned.
        
        :param jpype.JArray[T] items: the items to put in the set
        :return: the list of items
        :rtype: java.util.Set[T]
        """

    @staticmethod
    @typing.overload
    def asSet(c: collections.abc.Sequence) -> java.util.Set[T]:
        ...

    @staticmethod
    @typing.overload
    def asSet(it: java.util.Iterator[T]) -> java.util.Set[T]:
        """
        Drains the given iterator into a new Set
        
        :param java.util.Iterator[T] it: the iterator
        :return: the set
        :rtype: java.util.Set[T]
        """

    @staticmethod
    @typing.overload
    def asSet(iterable: collections.abc.Sequence) -> java.util.Set[T]:
        """
        Turns the given iterable into a new Set, returning it directly if it is a set, draining
        it into a set if it is not already.
        
        :param collections.abc.Sequence iterable: the iterable
        :return: the set
        :rtype: java.util.Set[T]
        """

    @staticmethod
    @typing.overload
    def asStream(iterator: java.util.Iterator[T]) -> java.util.stream.Stream[T]:
        """
        Turns the given iterator into a stream
        
        :param java.util.Iterator[T] iterator: the iterator
        :return: the stream
        :rtype: java.util.stream.Stream[T]
        """

    @staticmethod
    @typing.overload
    def asStream(*iterables: collections.abc.Sequence) -> java.util.stream.Stream[T]:
        """
        Combines all iterables passed-in into a pass-through (not creating a new collection) Stream.
        
        :param jpype.JArray[java.lang.Iterable[T]] iterables: the iterables to combine
        :return: the stream
        :rtype: java.util.stream.Stream[T]
        """

    @staticmethod
    def get(c: collections.abc.Sequence) -> T:
        """
        Returns the only element from the given collection; null if the collection is null or empty
        or size is greater than 1. This is meant to clients to get the one and only element in 
        a collection of size 1.
        
        :param collections.abc.Sequence c: the collection
        :return: the item
        :rtype: T
        
        .. seealso::
        
            | :obj:`.any(Collection)`
        """

    @staticmethod
    @typing.overload
    def isAllNull(*objects: java.lang.Object) -> bool:
        """
        Returns true if all the given objects are null.
        
         
        See also apache :meth:`ObjectUtils.anyNotNull(Object...) <ObjectUtils.anyNotNull>` and
        :meth:`ObjectUtils.allNotNull(Object...) <ObjectUtils.allNotNull>`
        
        :param jpype.JArray[java.lang.Object] objects: the objects to check
        :return: true if all the given objects are null
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isAllNull(c: collections.abc.Sequence) -> bool:
        """
        Returns true if all the given objects are null.
        
         
        See also apache :meth:`ObjectUtils.anyNotNull(Object...) <ObjectUtils.anyNotNull>` and
        :meth:`ObjectUtils.allNotNull(Object...) <ObjectUtils.allNotNull>`
        
        :param collections.abc.Sequence c: the objects to check
        :return: true if all the given objects are null
        :rtype: bool
        """

    @staticmethod
    def isAllSameType(list: collections.abc.Sequence, clazz: java.lang.Class[T]) -> bool:
        """
        Returns true if each item in the list is of type clazz.
        
        :param T: the type:param collections.abc.Sequence list: the list to inspect
        :param java.lang.Class[T] clazz: the class type
        :return: true if each item in the list is of type clazz
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isBlank(c: collections.abc.Sequence) -> bool:
        """
        Returns true if the given array is null or has 0 length
        
        :param collections.abc.Sequence c: the collection to check
        :return: true if blank
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isBlank(*t: T) -> bool:
        """
        Returns true if the given array is null or has 0 length
        
        :param jpype.JArray[T] t: the items to check
        :return: true if blank
        :rtype: bool
        """

    @staticmethod
    def isOneOf(t: T, *possibles: T) -> bool:
        """
        Returns true if the given item is in the collection of possible items
        
        :param T t: the item in question
        :param jpype.JArray[T] possibles: the set of things
        :return: true if the given item is in the collection of possible items
        :rtype: bool
        """

    @staticmethod
    def nonNull(c: collections.abc.Sequence) -> java.util.Collection[T]:
        """
        Returns the given collection if not null, an empty collection (a Set) otherwise.  This is
        useful for clients avoid null checks.
        
        :param collections.abc.Sequence c: the collection to check
        :return: a non-null collection
        :rtype: java.util.Collection[T]
        """



__all__ = ["HistoryList", "CollectionUtils"]
