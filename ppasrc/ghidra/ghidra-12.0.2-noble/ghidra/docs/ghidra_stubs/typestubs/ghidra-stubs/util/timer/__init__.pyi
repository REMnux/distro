from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore
import java.lang # type: ignore
import java.time # type: ignore
import java.util # type: ignore


K = typing.TypeVar("K")
V = typing.TypeVar("V")


class GTimerMonitor(java.lang.Object):
    """
    Monitor object returned from a GTimer.schedule() call
    """

    class_: typing.ClassVar[java.lang.Class]
    DUMMY: typing.Final[GTimerMonitor]
    """
    A dummy implementation of this interface
    """


    def cancel(self) -> bool:
        """
        Cancels the scheduled runnable associated with this GTimerMonitor if it has not already run.
        
        :return: true if the scheduled runnable was cancelled before it had a chance to execute.
        :rtype: bool
        """

    def didRun(self) -> bool:
        """
        Return true if the scheduled runnable has completed.
        
        :return: true if the scheduled runnable has completed.
        :rtype: bool
        """

    def wasCancelled(self) -> bool:
        """
        Return true if the scheduled runnable was cancelled before it had a chance to run.
        
        :return: true if the scheduled runnable was cancelled before it had a chance to run.
        :rtype: bool
        """


class GTimerCache(java.lang.Object, typing.Generic[K, V]):
    """
    Class for caching key,value entries for a limited time and cache size. Entries in this cache
    will be removed after the cache duration time has passed. If the cache ever exceeds its capacity,
    the least recently used entry will be removed.
     
    
    This class uses a :obj:`LinkedHashMap` with it ordering mode set to "access order". This means
    that iterating through keys, values, or entries of the map will be presented oldest first. 
    Inserting or accessing an entry in the map will move the entry to the back of the list, thus
    making it the youngest. This means that entries closest to or past expiration will be presented
    first. 
     
    
    This class is designed to be subclassed for two specific cases. The first case is for when 
    additional processing is required when an entry is removed from the cache. This typically would
    be for cases where resources need to be released, such as closing a File or disposing the object.
    The second reason to subclass this cache is to get more control of expiring values. Overriding
    :meth:`shouldRemoveFromCache(Object, Object) <.shouldRemoveFromCache>`, which gets called when an entry's time
    has expired, gives the client a chance to decide if the entry should be removed.
    """

    @typing.type_check_only
    class CachedValue(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lifetime: java.time.Duration, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructs new GTimerCache with a duration for cached entries and a maximum
        number of entries to cache.
        
        :param java.time.Duration lifetime: the duration that a key,value will remain in the cache without being
        accessed (accessing a cached entry resets its time)
        :param jpype.JInt or int capacity: the maximum number of entries in the cache before least recently used
        entries are removed
        """

    def clear(self):
        """
        Clears all the values in the cache. The expired callback will be called for each entry
        that was in the cache.
        """

    def containsKey(self, key: K) -> bool:
        """
        Returns true if the cache contains a value for the given key.
        
        :param K key: the key to check if it is in the cache
        :return: true if the cache contains a value for the given key
        :rtype: bool
        """

    def get(self, key: K) -> V:
        """
        Returns the value for the given key. Also, resets time the associated with this entry.
        
        :param K key: the key to retrieve a value
        :return: the value for the given key
        :rtype: V
        """

    def put(self, key: K, value: V) -> V:
        """
        Adds an key,value entry to the cache
        
        :param K key: the key with which the value is associated
        :param V value: the value being cached
        :return: The previous value associated with the key or null if no previous value
        :rtype: V
        """

    def remove(self, key: K) -> V:
        """
        Removes the cache entry with the given key.
        
        :param K key: the key of the entry to remove
        :return: the value removed or null if the key wasn't in the cache
        :rtype: V
        """

    def setCapacity(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Sets the capacity for this cache. If this cache currently has more values than the new
        capacity, oldest values will be removed.
        
        :param jpype.JInt or int capacity: the new capacity for this cache
        """

    def setDuration(self, duration: java.time.Duration):
        """
        Sets the duration for keeping cached values.
        
        :param java.time.Duration duration: the length of time to keep a cached value
        """

    def size(self) -> int:
        """
        Returns the number of entries in the cache.
        
        :return: the number of entries in the cache
        :rtype: int
        """


class GTimer(java.lang.Object):
    """
    A class to schedule :obj:`Runnable`s to run after some delay, optionally repeating.  This class
    uses a :obj:`Timer` internally to schedule work.   Clients of this class are given a monitor
    that allows them to check on the state of the runnable, as well as to cancel the runnable.
     
    
    Note: The callback will be called on the :obj:`Timer`'s thread.
     
    
    See also :obj:`GhidraTimerFactory`
    """

    @typing.type_check_only
    class GTimerTask(java.util.TimerTask, GTimerMonitor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def scheduleRepeatingRunnable(delay: typing.Union[jpype.JLong, int], period: typing.Union[jpype.JLong, int], callback: java.lang.Runnable) -> GTimerMonitor:
        """
        Schedules a runnable for **repeated** execution after the specified delay. A delay value
        less than 0 will cause this timer to schedule nothing.  This allows clients to use this
        timer class with no added logic for managing timer enablement.
        
        :param jpype.JLong or int delay: the time (in milliseconds) to wait before executing the runnable.   A negative
                value signals not to run the timer--the callback will not be executed
        :param jpype.JLong or int period: time in milliseconds between successive runnable executions
        :param java.lang.Runnable callback: the runnable to be executed
        :return: a GTimerMonitor which allows the caller to cancel the timer and check its status
        :rtype: GTimerMonitor
        :raises IllegalArgumentException: if ``period <= 0``
        """

    @staticmethod
    def scheduleRunnable(delay: typing.Union[jpype.JLong, int], callback: java.lang.Runnable) -> GTimerMonitor:
        """
        Schedules a runnable for execution after the specified delay.   A delay value less than 0
        will cause this timer to schedule nothing.  This allows clients to use this timer class
        with no added logic for managing timer enablement.
        
        :param jpype.JLong or int delay: the time (in milliseconds) to wait before executing the runnable.  A negative
                value signals not to run the timer--the callback will not be executed
        :param java.lang.Runnable callback: the runnable to be executed.
        :return: a GTimerMonitor which allows the caller to cancel the timer and check its status.
        :rtype: GTimerMonitor
        """


class Watchdog(java.io.Closeable):
    """
    A reusable watchdog that will execute a callback if the watchdog is not disarmed before
    it expires.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, defaultTimeoutMS: typing.Union[jpype.JLong, int], timeoutMethod: java.lang.Runnable):
        """
        Creates a watchdog (initially disarmed) that will poll for expiration every
        defaultTimeoutMS milliseconds, calling ``timeoutMethod`` when triggered.
        
        :param jpype.JLong or int defaultTimeoutMS: number of milliseconds that the watchdog will wait after
        being armed before calling the timeout method.
        :param java.lang.Runnable timeoutMethod: :obj:`Runnable` functional callback.
        """

    def arm(self):
        """
        Enables this watchdog so that at :obj:`.defaultWatchdogTimeoutMS` milliseconds in the
        future the :obj:`.timeoutMethod` will be called.
        """

    def close(self):
        """
        Releases the background timer that this watchdog uses.
        """

    def disarm(self):
        """
        Disables this watchdog.
        """

    def isEnabled(self) -> bool:
        """
        Returns the status of the watchdog.
        
        :return: true if the watchdog is armed, false if the watchdog is disarmed
        :rtype: bool
        """

    @property
    def enabled(self) -> jpype.JBoolean:
        ...



__all__ = ["GTimerMonitor", "GTimerCache", "GTimer", "Watchdog"]
