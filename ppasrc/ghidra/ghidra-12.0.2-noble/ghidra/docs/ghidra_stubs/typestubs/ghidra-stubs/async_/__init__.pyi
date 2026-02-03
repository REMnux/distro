from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util
import java.lang # type: ignore
import java.lang.ref # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import java.util.function # type: ignore


C = typing.TypeVar("C")
K = typing.TypeVar("K")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class AsyncLazyMap(java.lang.Object, typing.Generic[K, V]):
    """
    A map of cached values computed upon the first request, asynchronously
     
     
    
    Each key present in the cache behaves similarly to :obj:`AsyncLazyValue`. The cache starts
    empty. Whenever a key is requested, a computation for that key is started, but a future is
    immediately returned. If the computation succeeds, the completed future is cached indefinitely,
    and the result is recorded. Any subsequent requests for the same key return the same future, even
    if the computation for that key has not yet completed. Thus, when it completes, all requests for
    that key will be fulfilled by the result of the first request. If the computation completes
    exceptionally, the key is optionally removed from the cache. Thus, a subsequent request for a
    failed key may retry the computation.
     
     
    
    Values can also be provided "out of band." That is, they may be provided by an alternative
    computation. This is accomplished using :meth:`get(Object, Function) <.get>`, :meth:`put(Object) <.put>` or
    :meth:`put(Object, Object) <.put>`. The last immediately provides a value and completes any outstanding
    requests, even if there was an active computation for the key. The first claims the key and
    promises to provide the value at a later time.
     
     
    
    At any point, an unmodifiable view of the completed, cached values may be obtained.
    """

    class KeyedFuture(java.util.concurrent.CompletableFuture[V], typing.Generic[K, V]):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, key: K):
            ...

        @typing.overload
        def __init__(self, key: K, value: V):
            ...

        def getFuture(self) -> java.util.concurrent.CompletableFuture[V]:
            ...

        def getKey(self) -> K:
            ...

        @property
        def future(self) -> java.util.concurrent.CompletableFuture[V]:
            ...

        @property
        def key(self) -> K:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, map: collections.abc.Mapping, function: java.util.function.Function[K, java.util.concurrent.CompletableFuture[V]]):
        """
        Construct a lazy map for the given function
        
        :param collections.abc.Mapping map: the backing map. The lazy map ought to have an exclusive reference to this map.
                    Mutations to the map outside of those caused by the lazy map may cause undefined
                    behavior.
        :param java.util.function.Function[K, java.util.concurrent.CompletableFuture[V]] function: specifies the computation, given a key
        """

    def clear(self):
        """
        Clear the lazy map, including pending requests
         
         
        
        Pending requests will be cancelled
        """

    def containsKey(self, key: K) -> bool:
        """
        Check if a given key is in the map, pending or completed
        
        :param K key: the key to check
        :return: true if present, false otherwise
        :rtype: bool
        """

    def forget(self, key: K) -> java.util.concurrent.CompletableFuture[V]:
        """
        Remove a key from the map, without canceling any pending computation
         
         
        
        If the removed future has not yet completed, its value will never be added to the map of
        values. Subsequent gets or puts to the invalidated key will behave as if the key had never
        been requested.
        
        :param K key: the key to remove
        :return: the invalidated future
        :rtype: java.util.concurrent.CompletableFuture[V]
        """

    def forgetErrors(self, predicate: java.util.function.BiPredicate[K, java.lang.Throwable]) -> AsyncLazyMap[K, V]:
        """
        Sets a predicate to determine which errors to forget (i.e., retry)
         
         
         
        
        A request resulting in an error that is remembered will not be retried until the cache is
        invalidated. For a forgotten error, the request is retried if re-requested later.
         
         
        
        This will replace the behavior of any previous error-testing predicate.
        
        :param java.util.function.BiPredicate[K, java.lang.Throwable] predicate: the predicate
        :return: this lazy map
        :rtype: AsyncLazyMap[K, V]
        """

    def forgetValues(self, predicate: java.util.function.BiPredicate[K, V]) -> AsyncLazyMap[K, V]:
        """
        Sets a predicate to determine which values to forget
         
         
        
        The predicate is applied to a cached entry when its key is re-requested. If forgotten, the
        request will launch a fresh computation. The predicate is also applied at the time a
        computation is completed. An entry that is forgotten still completes normally; however, it
        never enters the cache, thus a subsequent request for the same key will launch a fresh
        computation.
         
         
        
        This will replace the behavior of any previous value-testing predicate.
        
        :param java.util.function.BiPredicate[K, V] predicate: the rule for forgetting entries
        :return: this lazy map
        :rtype: AsyncLazyMap[K, V]
        """

    @typing.overload
    def get(self, key: K, func: java.util.function.Function[K, java.util.concurrent.CompletableFuture[V]]) -> AsyncLazyMap.KeyedFuture[K, V]:
        """
        Request the value for a given key, using an alternative computation
         
         
        
        If this is called before any other get or put, the given function is launched for the given
        key. A :obj:`CompletableFuture` is returned immediately. Subsequent gets or puts on the same
        key will return the same future without starting any new computation.
        
        :param K key: the key
        :param java.util.function.Function[K, java.util.concurrent.CompletableFuture[V]] func: an alternative computation function, given a key
        :return: a future, possibly already completed, for the key's value
        :rtype: AsyncLazyMap.KeyedFuture[K, V]
        """

    @typing.overload
    def get(self, key: K) -> AsyncLazyMap.KeyedFuture[K, V]:
        """
        Request the value for a given key
         
         
        
        If this is called before any other get or put, the computation given at construction is
        launched for the given key. A :obj:`CompletableFuture` is returned immediately. Subsequent
        calls gets or puts on the same key return the same future without starting any new
        computation.
        
        :param K key: the key
        :return: a future, possible already completed, for the key's value
        :rtype: AsyncLazyMap.KeyedFuture[K, V]
        """

    def getCompletedMap(self) -> java.util.Map[K, V]:
        """
        Get a view of completed keys with values
         
         
        
        The view is unmodifiable, but the backing map may still be modified as more keys are
        completed. Thus, access to the view ought to be synchronized on this lazy map.
        
        :return: a map view of keys to values
        :rtype: java.util.Map[K, V]
        """

    def getPendingKeySet(self) -> java.util.Set[K]:
        """
        Get a copy of the keys which are requested but not completed
         
         
        
        This should only be used for diagnostics.
        
        :return: a copy of the pending key set
        :rtype: java.util.Set[K]
        """

    @typing.overload
    def put(self, key: K, value: V) -> bool:
        """
        Immediately provide an out-of-band value for a given key
         
         
        
        On occasion, the value for a key may become known outside of the specified computation. This
        method circumvents the function given during construction by providing the value for a key.
        If there is an outstanding request for the key's value -- a rare occasion -- it is completed
        immediately with the provided value. Calling this method for a key that has already completed
        has no effect.
         
         
        
        This is equivalent to the code ``map.put(k).complete(value)``, but atomic.
        
        :param K key: the key whose value to provide
        :param V value: the provided value
        :return: true if the key was completed by this call, false if the key had already been
                completed
        :rtype: bool
        """

    @typing.overload
    def put(self, key: K) -> AsyncLazyMap.KeyedFuture[K, V]:
        """
        Provide an out-of-band value for a given key
         
         
        
        If this is called before :meth:`get(Object) <.get>`, the computation given at construction is
        ignored for the given key. A new :obj:`CompletableFuture` is returned instead. The caller
        must see to this future's completion. Subsequent calls to either :meth:`get(Object) <.get>` or
        :meth:`put(Object) <.put>` on the same key return this same future without starting any
        computation.
         
         
        
        Under normal circumstances, the caller cannot determine whether or not it has "claimed" the
        computation for the key. If the usual computation is already running, then the computations
        are essentially in a race. As such, it is essential that alternative computations result in
        the same value for a given key as the usual computation. In other words, the functions must
        not differ, but the means of computation can differ. Otherwise, race conditions may arise.
        
        :param K key: the key whose value to provide
        :return: a promise that the caller must fulfill or arrange to have fulfilled
        :rtype: AsyncLazyMap.KeyedFuture[K, V]
        """

    def rememberErrors(self, predicate: java.util.function.BiPredicate[K, java.lang.Throwable]) -> AsyncLazyMap[K, V]:
        """
        Sets a predicate to determine which errors to remember
        
        :param java.util.function.BiPredicate[K, java.lang.Throwable] predicate: the predicate
        :return: this lazy map
        :rtype: AsyncLazyMap[K, V]
        
        .. seealso::
        
            | :obj:`.forgetErrors(BiPredicate)`
        """

    def rememberValues(self, predicate: java.util.function.BiPredicate[K, V]) -> AsyncLazyMap[K, V]:
        """
        Sets a predicate to determine which values to remember
        
        :param java.util.function.BiPredicate[K, V] predicate: the rule for *not* forgetting entries
        :return: this lazy map
        :rtype: AsyncLazyMap[K, V]
        
        .. seealso::
        
            | :obj:`.forgetValues(BiPredicate)`
        """

    def remove(self, key: K) -> V:
        """
        Remove a key from the map, canceling any pending computation
        
        :param K key: the key to remove
        :return: the previous value, if completed
        :rtype: V
        """

    def retainKeys(self, keys: collections.abc.Sequence):
        """
        Retain only those entries whose keys appear in the given collection
         
         
        
        All removed entries with pending computations will be canceled
        
        :param collections.abc.Sequence keys: the keys to retain
        """

    @property
    def completedMap(self) -> java.util.Map[K, V]:
        ...

    @property
    def pendingKeySet(self) -> java.util.Set[K]:
        ...


class AsyncUtils(java.lang.Object):
    """
    Some conveniences when dealing with Java's :obj:`CompletableFuture`s.
    """

    class TemperamentalRunnable(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def run(self):
            ...


    class TemperamentalSupplier(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def get(self) -> T:
            ...


    class_: typing.ClassVar[java.lang.Class]
    CLEANER: typing.Final[java.lang.ref.Cleaner]
    FRAMEWORK_EXECUTOR: typing.Final[java.util.concurrent.ExecutorService]
    SWING_EXECUTOR: typing.Final[java.util.concurrent.ExecutorService]

    @staticmethod
    def copyTo(dest: java.util.concurrent.CompletableFuture[T]) -> java.util.function.BiFunction[T, java.lang.Throwable, T]:
        """
        Create a :obj:`BiFunction` that copies a result from one :obj:`CompletableFuture` to
        another
         
         
        
        The returned function is suitable for use in :meth:`CompletableFuture.handle(BiFunction) <CompletableFuture.handle>` and
        related methods, as in:
         
         
        sourceCF().handle(AsyncUtils.copyTo(destCF));
         
         
         
        
        This will effectively cause ``destCF`` to be completed identically to ``sourceCF``.
        The returned future from ``handle`` will also behave identically to ``source CF``,
        except that ``destCF`` is guaranteed to complete before the returned future does.
        
        :param T: the type of the future result:param java.util.concurrent.CompletableFuture[T] dest: the future to copy into
        :return: a function which handles the source future
        :rtype: java.util.function.BiFunction[T, java.lang.Throwable, T]
        """

    @staticmethod
    def nil() -> java.util.concurrent.CompletableFuture[T]:
        ...

    @staticmethod
    def unwrapThrowable(e: java.lang.Throwable) -> java.lang.Throwable:
        """
        Unwrap :obj:`CompletionException`s and :obj:`ExecutionException`s to get the real cause
        
        :param java.lang.Throwable e: the (usually wrapped) exception
        :return: the nearest cause in the chain that is not a :obj:`CompletionException`
        :rtype: java.lang.Throwable
        """


class SwingExecutorService(java.util.concurrent.AbstractExecutorService):
    """
    A wrapper for :meth:`SwingUtilities.invokeLater(Runnable) <SwingUtilities.invokeLater>` that implements
    :obj:`ExecutorService`.
    """

    class_: typing.ClassVar[java.lang.Class]
    LATER: typing.Final[SwingExecutorService]
    MAYBE_NOW: typing.Final[SwingExecutorService]
    """
    Wraps :meth:`Swing.runIfSwingOrRunLater(Runnable) <Swing.runIfSwingOrRunLater>` instead
    """



class AsyncReference(java.lang.Object, typing.Generic[T, C]):
    """
    An observable reference useful for asynchronous computations
     
     
    
    The reference supports the usual set and get operations. The set operation accepts an optional
    "cause" argument which is forwarded to some observers. The set operation may also be intercepted
    by an optional filter. The filter function is provided a copy of the current value, proposed
    value, and cause. The value it returns becomes the new value. If that value is different than the
    current value, the observers are notified. The default filter returns the new value, always.
     
     
    
    The reference provides three types of observation callbacks. The first is to listen for all
    changes. This follows the listener pattern. When the value changes, i.e., is set to a value
    different than the current value, all change listener are invoked with a copy of the new value
    and a reference to the provided cause, if given. The second is to wait for the very next change.
    It follows the promises pattern. The returned future completes with the new value upon the very
    next change. The cause is not provided to the type of observer. The third is to wait for a given
    value. It, too, follows the promises pattern. The returned future completes as soon as the
    reference takes the given value. The cause is not provided to this type of observer.
    """

    class FilterFunction(java.lang.Object, typing.Generic[T, C]):
        """
        A function to filter updates to an :obj:`AsyncReference`
        """

        class_: typing.ClassVar[java.lang.Class]

        def filter(self, cur: T, set: T, cause: C) -> T:
            """
            Filter an incoming update, i.e., call to :meth:`AsyncReference.set(Object, Object) <AsyncReference.set>`
            
            :param T cur: the current value of the reference
            :param T set: the incoming value from the update
            :param C cause: the cause of the update
            :return: the new value to assign to the reference
            :rtype: T
            """


    @typing.type_check_only
    class WaitUntilFuture(java.util.concurrent.CompletableFuture[T], typing.Generic[T]):
        """
        For :obj:`AsyncReference.waitUntil`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, predicate: java.util.function.Predicate[T]):
            ...


    @typing.type_check_only
    class ChangeRecord(java.lang.Object, typing.Generic[T, C]):
        """
        Used for debouncing
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, val: T, cause: C):
            ...


    @typing.type_check_only
    class DebouncedAsyncReference(AsyncReference[T, C], typing.Generic[T, C]):

        @typing.type_check_only
        class State(java.lang.Runnable, ghidra.util.TriConsumer[T, T, C], typing.Generic[T, C]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, to: java.lang.ref.WeakReference[AsyncReference.DebouncedAsyncReference[T, C]], from_: AsyncReference[T, C], timer: AsyncTimer, windowMillis: typing.Union[jpype.JLong, int]):
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: AsyncReference[T, C], timer: AsyncTimer, windowMillis: typing.Union[jpype.JLong, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a new reference initialized to ``null``
        """

    @typing.overload
    def __init__(self, t: T):
        """
        Construct a new reference initialized to the given value
        
        :param T t: the initial value
        """

    def addChangeListener(self, listener: ghidra.util.TriConsumer[T, T, C]):
        """
        Add a listener for any change to this reference's value
         
         
        
        Updates that get "filtered out" do not cause a change listener to fire.
        
        :param ghidra.util.TriConsumer[T, T, C] listener: the listener, which is passed the new value (post-filter) and cause
        """

    def compute(self, func: java.util.function.Function[T, T], cause: C) -> T:
        """
        Update this reference using the given function because of the given cause
        
        :param java.util.function.Function[T, T] func: the function taking the current value and returning the proposed value (subject
                    to the filter)
        :param C cause: the cause, often ``null``
        :return: the new value of this reference (post filter)
        :rtype: T
        """

    def debounced(self, timer: AsyncTimer, windowMillis: typing.Union[jpype.JLong, int]) -> AsyncReference[T, C]:
        """
        Obtain a new :obj:`AsyncReference` whose value is updated after this reference has settled
         
         
        
        The original :obj:`AsyncReference` continues to behave as usual, except that is has an
        additional listener on it. When this reference is updated, the update is passed through an
        :obj:`AsyncDebouncer` configured with the given timer and window. When the debouncer
        settles, the debounced reference is updated.
         
         
        
        Directly updating, i.e., calling :meth:`set(Object, Object) <.set>` on, the debounced reference
        subverts the debouncing mechanism, and will result in an exception. Only the original
        reference should be updated directly.
         
         
        
        Setting a filter on the debounced reference may have undefined behavior.
         
         
        
        If the original reference changes value rapidly, settling on the debounced reference's
        current value, no update event is produced by the debounced reference. If the original
        reference changes value rapidly, settling on a value different from the debounced reference's
        current value, an update event is produced, using the cause of the final update, even if an
        earlier cause was associated with the same final value.
        
        :param AsyncTimer timer: a timer for measuring the window
        :param jpype.JLong or int windowMillis: the period of inactive time to consider this reference settled
        :return: the new :obj:`AsyncReference`
        :rtype: AsyncReference[T, C]
        """

    def dispose(self, reason: java.lang.Throwable):
        """
        Clear out the queues of future, completing each exceptionally
        
        :param java.lang.Throwable reason: the reason for disposal
        """

    def filter(self, newFilter: AsyncReference.FilterFunction[T, C]):
        """
        Apply a filter function to all subsequent updates
         
         
        
        The given function replaces the current function.
        
        :param AsyncReference.FilterFunction[T, C] newFilter: the filter
        """

    def get(self) -> T:
        """
        Get the current value of this reference
        
        :return: the current value
        :rtype: T
        """

    def removeChangeListener(self, listener: ghidra.util.TriConsumer[T, T, C]):
        """
        Remove a change listener
        
        :param ghidra.util.TriConsumer[T, T, C] listener: the listener to remove
        """

    def set(self, newVal: T, cause: C) -> bool:
        """
        Update this reference to the given value because of the given cause
        
        :param T newVal: the proposed value (subject to the filter)
        :param C cause: the cause, often ``null``
        :return: true if the value of this reference changed (post filter)
        :rtype: bool
        """

    def waitChanged(self) -> java.util.concurrent.CompletableFuture[T]:
        """
        Wait for the next change and capture the new value
         
        The returned future completes with the value of the very next change, at the time of that
        change. Subsequent changes to the value of the reference do not affect the returned future.
        
        :return: the future value at the next change
        :rtype: java.util.concurrent.CompletableFuture[T]
        """

    def waitUntil(self, predicate: java.util.function.Predicate[T]) -> java.util.concurrent.CompletableFuture[T]:
        """
        Wait for this reference to accept the first value meeting the given condition (post-filter)
         
         
        
        If the current value already meets the condition, a completed future is returned.
        
        :param java.util.function.Predicate[T] predicate: the condition to meet
        :return: a future that completes the next time the reference accepts a passing value
        :rtype: java.util.concurrent.CompletableFuture[T]
        """

    def waitValue(self, t: T) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Wait for this reference to accept a particular value (post-filter)
         
         
        
        If the reference already has the given value, a completed future is returned.
        
        :param T t: the expected value to wait on
        :return: a future that completes the next time the reference accepts the given value
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """


class AsyncFence(java.lang.Object):
    """
    A fence that completes when all participating futures complete
     
     
    
    This provides an alternative shorthand for Java's
    :meth:`CompletableFuture.thenAcceptBoth(CompletionStage, BiConsumer) <CompletableFuture.thenAcceptBoth>` or
    :meth:`CompletableFuture.allOf(CompletableFuture...) <CompletableFuture.allOf>`.
     
     
    
    Example:
     
    ``public CompletableFuture<Void> processAll(List<Integer> list) {    AsyncFence fence = new AsyncFence();    for (int entry : list) {        fence.include(process(entry));    }    return fence.ready();}``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getPending(self) -> java.util.Set[java.util.concurrent.CompletableFuture[typing.Any]]:
        """
        Diagnostic: Get the participants which have not yet completed
        
        :return: the pending participants
        :rtype: java.util.Set[java.util.concurrent.CompletableFuture[typing.Any]]
        """

    def include(self, future: java.util.concurrent.CompletableFuture[typing.Any]) -> AsyncFence:
        """
        Include a participant with this fence
         
        The result of the participating future is ignored implicitly. If the result is needed, it
        must be consumed out of band, e.g., by using :meth:`CompletableFuture.thenAccept(Consumer) <CompletableFuture.thenAccept>`:
         
         
        fence.include(process(entry).thenAccept(result::addTo));
         
         
        Calling this method after :meth:`ready() <.ready>` will yield undefined results.
        
        :param java.util.concurrent.CompletableFuture[typing.Any] future: the participant to add
        :return: this fence
        :rtype: AsyncFence
        """

    def ready(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Obtain a future that completes when all participating futures have completed
         
        Calling this method more than once will yield undefined results.
        
        :return: the "all of" future
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @property
    def pending(self) -> java.util.Set[java.util.concurrent.CompletableFuture[typing.Any]]:
        ...


class AsyncLazyValue(java.lang.Object, typing.Generic[T]):
    """
    A value to be completed once upon the first request, asynchronously
    
    This contains a single lazy value. It is computed only if requested. When requested, a future is
    returned and the computation is started. If the computation succeeds, the completed future is
    cached indefinitely. Any subsequent requests return the same future, even if the computation has
    not yet completed. Thus, when it completes, all requests will be fulfilled by the result of the
    first request. If the computation completes exceptionally, the result is immediately discarded.
    Thus, a subsequent request will retry the computation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, supplier: java.util.function.Supplier[java.util.concurrent.CompletableFuture[T]]):
        """
        Construct a lazy value for the given computation
        
        :param java.util.function.Supplier[java.util.concurrent.CompletableFuture[T]] supplier: specifies the computation
        """

    def forget(self):
        """
        Forget the value
         
        Instead of returning a completed (or even in-progress) future, the next request will cause
        the value to be re-computed.
        """

    def isBusy(self) -> bool:
        """
        Check if the value has been requested, but not yet completed
         
         
        
        This will also return true if something is providing the value out of band.
        
        :return: true if :meth:`request() <.request>` or :meth:`provide() <.provide>` has been called, but not completed
        :rtype: bool
        """

    def isDone(self) -> bool:
        """
        Check if the value is available immediately
        
        :return: true if :meth:`request() <.request>` or :meth:`provide() <.provide>` has been called and completed.
        :rtype: bool
        """

    def provide(self) -> java.util.concurrent.CompletableFuture[T]:
        """
        Provide the value out of band
         
        If this is called before :meth:`request() <.request>`, the computation given at construction is
        ignored. A new :obj:`CompletableFuture` is returned instead. The caller must see to this
        future's completion. Subsequent calls to either :meth:`request() <.request>` or :meth:`provide() <.provide>`
        return this same future without starting any computation.
         
        Under normal circumstances, the caller cannot determine whethor or not is has "claimed" the
        computation. If the usual computation is already running, then the computations are
        essentially in a race. As such, it is essential that alternative computations result in the
        same value as the usual computation. In other words, the functions must not differ, but the
        means of computation can differ. Otherwise, race conditions may arise.
        
        :return: a promise that the caller must fulfill or arrange to have fulfilled
        :rtype: java.util.concurrent.CompletableFuture[T]
        """

    def request(self) -> java.util.concurrent.CompletableFuture[T]:
        """
        Request the value
         
        If this is called before :meth:`provide() <.provide>`, the computation given at construction is
        launched. The :obj:`CompletableFuture` it provides is returned immediately. Subsequent calls
        to either :meth:`request() <.request>` or :meth:`provide() <.provide>` return the same future without starting
        any new computation.
        
        :return: a future, possibly already completed, for the value
        :rtype: java.util.concurrent.CompletableFuture[T]
        """

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def done(self) -> jpype.JBoolean:
        ...


class AsyncTimer(java.lang.Object):
    """
    A timer for asynchronous scheduled tasks
     
     
    
    This object provides a futures which complete at specified times. This is useful for pausing amid
    a chain of callback actions, i.e., between iterations of a loop. A critical tenant of
    asynchronous reactive programming is to never block a thread, at least not for an indefinite
    period of time. If an action blocks, it may prevent completion of other tasks in its executor's
    queue, possibly resulting in deadlock. An easy and tempting way to accidentally block is to call
    :meth:`Object.wait() <Object.wait>` or :meth:`Thread.sleep(long) <Thread.sleep>` when trying to wait for a specific period of
    time. Unfortunately, this does not just block the chain, but blocks the thread. Java provides a
    :obj:`Timer`, but its :obj:`Future`s are not :obj:`CompletableFuture`s. The same is true of
    :obj:`ScheduledThreadPoolExecutor`.
     
     
    
    A delay is achieved using :meth:`mark() <.mark>`, then :meth:`Mark.after(long) <Mark.after>`.
     
     
    future.thenCompose(__ -> timer.mark().after(1000))
     
     
     
    
    :meth:`mark() <.mark>` marks the current system time; all calls to the mark's :meth:`Mark.after(long) <Mark.after>`
    schedule futures relative to this mark. Scheduling a timed sequence of actions is best
    accomplished using times relative to a single mark. For example:
     
     
    Mark mark = timer.mark();
    mark.after(1000).thenCompose(__ -> {
        doTaskAtOneSecond();
        return mark.after(2000);
    }).thenAccept(__ -> {
        doTaskAtTwoSeconds();
    });
     
     
     
    
    This provides slightly more precise scheduling than delaying for a fixed period between tasks.
    Consider a second example:
     
     
    
    Like :obj:`Timer`, each :obj:`AsyncTimer` is backed by a single thread which uses
    :meth:`Object.wait() <Object.wait>` to implement its timing. Thus, this is not suitable for real-time
    applications. Unlike :obj:`Timer`, the backing thread is always a daemon. It will not prevent
    process termination. If a task is long running, the sequence should queue it on another executor,
    perhaps using :meth:`CompletableFuture.supplyAsync(Supplier, Executor) <CompletableFuture.supplyAsync>`. Otherwise, other
    scheduled tasks may be inordinately delayed.
    """

    class Mark(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def after(self, intervalMillis: typing.Union[jpype.JLong, int]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
            """
            Schedule a task to run when the given number of milliseconds has passed since this mark
             
             
            
            The method returns immediately, giving a future result. The future completes "soon after"
            the requested interval since the last mark passes. There is some minimal overhead, but
            the scheduler endeavors to complete the future as close to the given time as possible.
            The actual scheduled time will not precede the requested time.
            
            :param jpype.JLong or int intervalMillis: the interval after which the returned future completes
            :return: a future that completes soon after the given interval
            :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
            """

        def timeOut(self, future: java.util.concurrent.CompletableFuture[T], millis: typing.Union[jpype.JLong, int], valueIfLate: java.util.function.Supplier[T]) -> java.util.concurrent.CompletableFuture[T]:
            """
            Time a future out after the given interval
            
            :param T: the type of the future:param java.util.concurrent.CompletableFuture[T] future: the future whose value is expected in the given interval
            :param jpype.JLong or int millis: the time interval in milliseconds
            :param java.util.function.Supplier[T] valueIfLate: a supplier for the value if the future doesn't complete in time
            :return: a future which completes with the given futures value, or the late value if it
                    times out.
            :rtype: java.util.concurrent.CompletableFuture[T]
            """


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_TIMER: typing.Final[AsyncTimer]

    def __init__(self):
        """
        Create a new timer
         
         
        
        Except to reduce contention among threads, most applications need only create one timer
        instance. See :obj:`AsyncTimer.DEFAULT_TIMER`.
        """

    def atSystemTime(self, timeMillis: typing.Union[jpype.JLong, int]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Schedule a task to run when :meth:`System.currentTimeMillis() <System.currentTimeMillis>` has passed a given time
         
         
        
        This method returns immediately, giving a future result. The future completes "soon after"
        the current system time passes the given time in milliseconds. There is some minimal
        overhead, but the scheduler endeavors to complete the future as close to the given time as
        possible. The actual scheduled time will not precede the requested time.
        
        :param jpype.JLong or int timeMillis: the time after which the returned future completes
        :return: a future that completes soon after the given time
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def mark(self) -> AsyncTimer.Mark:
        """
        Mark the current system time
        
        :return: this same timer
        :rtype: AsyncTimer.Mark
        """


class DisposedException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reason: java.lang.Throwable):
        ...


class AsyncPairingQueue(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def give(self, giver: java.util.concurrent.CompletableFuture[T]):
        ...

    @typing.overload
    def give(self) -> java.util.concurrent.CompletableFuture[T]:
        ...

    def isEmpty(self) -> bool:
        ...

    def take(self) -> java.util.concurrent.CompletableFuture[T]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class AsyncDebouncer(java.lang.Object, typing.Generic[T]):
    """
    A debouncer for asynchronous events
     
     
    
    A debouncer has an input "contact" event and produces an output "settled" once sufficient time
    has passed since the last contact event. The goal is to prevent the needless frequent firing of
    asynchronous events if the next event is going to negate the current one. The idea is that a
    series of events, each negating the previous, can be fired within relative temporal proximity.
    Without a debouncer, event processing time may be wasted. By passing the events through a
    debouncer configured with a time window that contains all the events, only the final event in the
    cluster will be processed. The cost of doing this is a waiting period, so event processing may be
    less responsive, but will also be less frantic.
    """

    class Bypass(AsyncDebouncer[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, timer: AsyncTimer, windowMillis: typing.Union[jpype.JLong, int]):
        """
        Construct a new debouncer
        
        :param AsyncTimer timer: the timer to use for delay
        :param jpype.JLong or int windowMillis: the timing window of changes to ignore
        """

    def addListener(self, listener: java.util.function.Consumer[T]):
        """
        Add a listener for the settled event
        
        :param java.util.function.Consumer[T] listener: the listener
        """

    def contact(self, val: T):
        """
        Send a contact event
         
         
        
        This sets or resets the timer for the event window. The settled event will fire with the
        given value after this waiting period, unless another contact event occurs first.
        
        :param T val: the new value
        """

    def removeListener(self, listener: java.util.function.Consumer[T]):
        """
        Remove a listener from the settled event
        
        :param java.util.function.Consumer[T] listener: the listener
        """

    def settled(self) -> java.util.concurrent.CompletableFuture[T]:
        """
        Receive the next settled event
         
         
        
        The returned future completes *after* all registered listeners have been invoked.
        
        :return: a future which completes with the value of the next settled event
        :rtype: java.util.concurrent.CompletableFuture[T]
        """

    def stable(self) -> java.util.concurrent.CompletableFuture[T]:
        """
        Wait for the debouncer to be stable
         
         
        
        If the debouncer has not received a contact event within the event window, it's considered
        stable, and this returns a completed future with the value of the last received contact
        event. Otherwise, the returned future completes on the next settled event, as in
        :meth:`settled() <.settled>`.
        
        :return: a future which completes, perhaps immediately, when the debouncer is stable
        :rtype: java.util.concurrent.CompletableFuture[T]
        """



__all__ = ["AsyncLazyMap", "AsyncUtils", "SwingExecutorService", "AsyncReference", "AsyncFence", "AsyncLazyValue", "AsyncTimer", "DisposedException", "AsyncPairingQueue", "AsyncDebouncer"]
