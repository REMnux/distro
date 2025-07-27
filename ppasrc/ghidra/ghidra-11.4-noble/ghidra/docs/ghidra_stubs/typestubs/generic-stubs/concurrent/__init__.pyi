from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.graph
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


I = typing.TypeVar("I")
R = typing.TypeVar("R")
T = typing.TypeVar("T")


class ConcurrentListenerSet(java.lang.Iterable[T], typing.Generic[T]):
    """
    A listener set that is weakly consistent.  This allows for iteration of the set while other
    threads modify the set.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, t: T):
        ...

    def asList(self) -> java.util.List[T]:
        ...

    def clear(self):
        ...

    def remove(self, t: T):
        ...


@typing.type_check_only
class FutureTaskMonitor(java.util.concurrent.FutureTask[R], ghidra.util.task.TaskMonitor, typing.Generic[I, R]):
    """
    This is the FutureTask that will be used to call the :obj:`QCallback` to work on
    an item from a ConcurrentQ. It has been overridden to serve as an individual
    TaskMonitor for the task as well as notifying the ConcurrentQ when a task
    has been completed or cancelled so that additional tasks can be sent to the
    thread pool.
     
    
    If it was cancelled, then the done() callback will occur in the thread that cancelled this
    task, otherwise it will be called by the thread from the thread pool that
    executed the task.  Note that when this task is cancelled, it is up to the
    executing thread to check if it was cancelled and terminate the task execution gracefully.
    Even if the executing task never checks the cancelled and completes the task,
    the return value will be ignored as this task has already been considered done
    and any threads waiting on the return will have already been told it was cancelled.
     
    
    On ConcurrentQs that only allow one task to run at a time, when a task is cancelled,
    the next task can begin.  Most likely, the thread that was running the cancelled
    task won't be free, and a new thread will be used to start running the next task.
    """

    @typing.type_check_only
    class ChainedCancelledListener(ghidra.util.task.CancelledListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, listener1: ghidra.util.task.CancelledListener, listener2: ghidra.util.task.CancelledListener):
            ...

        def removeListener(self, listener: ghidra.util.task.CancelledListener) -> ghidra.util.task.CancelledListener:
            ...


    class_: typing.ClassVar[java.lang.Class]


class QItemListener(java.lang.Object, typing.Generic[I, R]):
    """
    Callback for when items have completed processing.  It is also called if an item is cancelled
    or had an error condition.
    """

    class_: typing.ClassVar[java.lang.Class]

    def itemProcessed(self, result: QResult[I, R]):
        """
        Callback for when a item has completed processing, regardless of whether or not the item
        process normally, was cancelled, or encountered an error during processing.
        
        :param QResult[I, R] result: the QResult object.
        """


class ConcurrentQ(java.lang.Object, typing.Generic[I, R]):
    """
    A queue for easily scheduling tasks to be run in parallel (or sequentially)
    via a thread pool.  This class provides a clean separation of items that need to
    be processed from the algorithm that does the processing, making it easy to parallelize
    the processing of multiple items.   Further, you can control the maximum number of items that
    can be processed concurrently.  This is useful to throttle operations that may starve the
    other threads in the system.  You may also control how many items get placed into the queue
    at one time, blocking if some threshold is exceeded.
     
    
    Examples:
    ---
    
     
    
    Put and Forget:
    QCallback<ITEM, RESULT> callback = new AbstractQCallback<ITEM, RESULT>() {    public RESULT process(ITEM item, TaskMonitor monitor) {        // do work here...    }};ConcurrentQBuilder<ITEM, RESULT> builder = new ConcurrentQBuilder<ITEM, RESULT>();builder.setThreadPoolName("Thread Pool Name");concurrentQ = builder.getQueue(callback);......concurrentQ.add(item); // where item is one of the instances of ITEM
    ---
    
     
    
    Put Items and Handle Results in Any Order as They Available:
     
    QCallback<ITEM, RESULT> callback = new AbstractQCallback<ITEM, RESULT>() {
        public RESULT process(ITEM item, TaskMonitor monitor) {
            // do work here...
        }
    };
    
    QItemListener<ITEM, RESULT> itemListener = new QItemListener<ITEM, RESULT>() {
        public void itemProcessed(QResult<ITEM, RESULT> result) {
            RESULT result = result.getResult();
                **// work on my result...**
            }
    };
    
    ConcurrentQBuilder<ITEM, RESULT> builder = new ConcurrentQBuilder<ITEM, RESULT>();
    builder.setThreadPoolName("Thread Pool Name");
    **builder.setListener(itemListener);**
    concurrentQ = builder.build(callback);
    ...
    ...
    concurrentQ.add(item); // where item is one of the instances of ITEM
    concurrentQ.add(item);
    concurrentQ.add(item);
    
     
    
    ---
    
     
    
    Put Items and Handle Results When All Items Have Been Processed:
    QCallback<ITEM, RESULT> callback = new AbstractQCallback<ITEM, RESULT>() {    public RESULT process(ITEM item, TaskMonitor monitor) {        // do work here...    }};
    
    ConcurrentQBuilder<ITEM, RESULT> builder = new ConcurrentQBuilder<ITEM, RESULT>();
    builder.setThreadPoolName("Thread Pool Name");
    **builder.setCollectResults(true);**
    concurrentQ = builder.getQueue(callback);
    ...
    ...
    concurrentQ.add(item); // where item is one of the instances of ITEM
    concurrentQ.add(item);
    concurrentQ.add(item);
    ...
    
    **List<QResult<I, R>> results = concurrentQ.waitForResults();**// process the results...
    ---
    
     
    
    Put Items, **Blocking While Full**, and Handle Results in Any Order as They Available:
     
    QCallback<ITEM, RESULT> callback = new AbstractQCallback<ITEM, RESULT>() {
        public RESULT process(ITEM item, TaskMonitor monitor) {
            // do work here...
        }
    };
    
    QItemListener<ITEM, RESULT> itemListener = new QItemListener<ITEM, RESULT>() {
        public void itemProcessed(QResult<ITEM, RESULT> result) {
            RESULT result = result.getResult();
                // work on my result...
            }
    };
    
    ConcurrentQBuilder<ITEM, RESULT> builder = new ConcurrentQBuilder<ITEM, RESULT>();
    builder.setThreadPoolName("Thread Pool Name");
    **builder.setQueue(new LinkedBlockingQueue(100));**
    concurrentQ = builder.getQueue(callback);
    ...
    ...
    Iterator<ITEM> iterator = <get an iterator for 1000s of items somewhere>
    **``concurrentQ.offer(iterator); // this call will block when the queue fills up (100 items or more)``**
    
     
    ---
    """

    @typing.type_check_only
    class CallbackCallable(java.util.concurrent.Callable[R]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ChainedProgressListener(QProgressListener[I], typing.Generic[I]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class QMonitorAdapter(QProgressListener[I], ghidra.util.task.CancelledListener):
        """
        Simple connector for traditional TaskMonitor and a task from the ConcurrentQ.  This adapter
        adds a cancel listener to the TaskMonitor and when cancelled is called on the monitor,
        it cancels the currently running (scheduled on the thread pool) and leaves the waiting
        tasks alone.  It also implements a QProgressListener and adds itself to the concurrentQ so
        that it gets progress events and messages and sets them on the task monitor.
        """

        class_: typing.ClassVar[java.lang.Class]
        cancelClearsAllJobs: typing.Final[jpype.JBoolean]

        def dispose(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], callback: QCallback[I, R]):
        """
        Creates a ConcurrentQ that will process as many items as the given threadPool can handle
        at one time.
        
        :param java.lang.String or str name: The name of the thread pool that will be created by this constructor.
        :param QCallback[I, R] callback: the QWorker object that will be used to process items concurrently.
        """

    @typing.overload
    def __init__(self, callback: QCallback[I, R], queue: java.util.Queue[I], threadPool: GThreadPool, listener: QItemListener[I, R], collectResults: typing.Union[jpype.JBoolean, bool], maxInProgress: typing.Union[jpype.JInt, int], jobsReportProgress: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a ConcurrentQ that will process at most maxInProgress items at a time, regardless of
        how many threads are available in the GThreadPool.
        
        :param QCallback[I, R] callback: the QWorker object that will be used to process items concurrently.
        :param java.util.Queue[I] queue: the internal storage queue to use in this concurrent queue.
        :param GThreadPool threadPool: the GThreadPool to used for providing the threads for concurrent processing.
        :param QItemListener[I, R] listener: An optional QItemListener that will be called back with results when the
                        item has been processed.
        :param jpype.JBoolean or bool collectResults: specifies if this queue should collect the results as items are processed
                        so they can be returned in a waitForResults() call.
        :param jpype.JInt or int maxInProgress: specifies the maximum number of items that can be process at a time.
                        If this is set to 0, then this queue will attempt to execute as many
                        items at a time as there are threads in the given threadPool.  Setting
                        this parameter to 1 will have the effect of guaranteeing that
                        all times are processed one at a time in the order they were submitted.
                        Any other positive value will run that many items concurrently,
                        up to the number of available threads.
        :param jpype.JBoolean or bool jobsReportProgress: true signals that jobs wish to report progress via their task
                        monitor.  The default is false, which triggers this queue to report an
                        overall progress for each job that is processed.  False is a good default
                        for clients that have a finite number of jobs to be done.
        """

    @typing.overload
    def add(self, items: collections.abc.Sequence):
        """
        Adds the list of items to this queue for concurrent processing.
        
        :param collections.abc.Sequence items: the items to be scheduled for concurrent processing
        """

    @typing.overload
    def add(self, iterator: java.util.Iterator[I]):
        """
        Adds the items of the given iterator to this queue for concurrent processing.
        
        :param java.util.Iterator[I] iterator: an iterator from which the items to be scheduled for concurrent processing
                will be taken.
        """

    @typing.overload
    def add(self, item: I):
        """
        Adds the item to this queue for concurrent processing.
        
        :param I item: the item to be scheduled for concurrent processing.
        """

    def addProgressListener(self, listener: QProgressListener[I]):
        """
        Adds a progress listener for this queue.  All the progress and messages reported by a
        QWorker will be routed to these listener.
        
        :param QProgressListener[I] listener: the listener for receiving progress and message notifications.
        """

    def cancelAllTasks(self, interruptRunningTasks: typing.Union[jpype.JBoolean, bool]) -> java.util.List[I]:
        """
        Cancels the processing of currently scheduled items in this queue.  Any items that haven't
        yet been scheduled on the threadPool are returned immediately from this call.  Items that
        are currently being processed will be cancelled and those results will be available on the
        next waitForResults() call and also if there is a QItemListener, it will be called with
        the QResult.  There is no guarantee that scheduled tasks will terminate any time soon.  If
        they check the isCancelled() state of their QMonitor, it will be true.  Setting the
        interruptRunningTasks to true, will result in a thread interrupt to any currently running
        task which might be useful if the task perform waiting operations like I/O.
        
        :param jpype.JBoolean or bool interruptRunningTasks: if true, an attempt will be made to interrupt any currently
        processing thread.
        :return: a list of all items that have not yet been queued to the threadPool.
        :rtype: java.util.List[I]
        """

    def cancelScheduledJobs(self):
        ...

    def dispose(self):
        """
        Cancels all running tasks and disposes of the internal thread pool if it is a private
        pool.
        """

    def isEmpty(self) -> bool:
        """
        Returns true if this queue has no items waiting to be processed or currently being processed.
        
        :return: true if this queue has no items waiting to be processed or currently being processed.
        :rtype: bool
        """

    def offer(self, iterator: java.util.Iterator[I]):
        """
        Allows clients to use a bounded queue (such as a :obj:`LinkedBlockingQueue` to control
        how many items get placed into this queue at one time.  Calling the ``add`` methods
        will place all items into the queue, which for a large number of items, can consume a
        large amount of memory.  This method will block once the queue at maximum capacity,
        continuing to add new items as existing items on the queue are processed.
         
        
        To enable blocking on the queue when it is full, construct this ``ConcurrentQ``
        with an instance of :obj:`BlockingQueue`.
        
        :param java.util.Iterator[I] iterator: An iterator from which items will be taken.
        :raises java.lang.InterruptedException: if this queue is interrupted while waiting to add more items
        """

    def removeProgressListener(self, listener: QProgressListener[I]):
        """
        Removes a progress listener from this queue.  All the progress and messages reported by a
        QWorker will be routed to this listener.
        
        :param QProgressListener[I] listener: the listener for receiving progress and message notifications.
        """

    def removeUnscheduledJobs(self) -> java.util.List[I]:
        ...

    def setMonitor(self, monitor: ghidra.util.task.TaskMonitor, cancelClearsAllItems: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the monitor to use with this queue.
        
        :param ghidra.util.task.TaskMonitor monitor: the monitor to attache to this queue
        :param jpype.JBoolean or bool cancelClearsAllItems: if true, cancelling the monitor will cancel all items currently
                                        being processed by a thread and clear the scheduled
                                        items that haven't yet run.
                                        If false, only the items currently being processed will be cancelled.
        """

    def waitForNextResult(self) -> QResult[I, R]:
        """
        Wait until at least one result is available and then return the first result.
        
        :return: the first available result
        :rtype: QResult[I, R]
        :raises java.lang.InterruptedException: if interrupted while waiting for a result
        :raises IllegalStateException: if this queue has been set to not collect results
                (see the constructor).
        """

    @typing.overload
    def waitForResults(self) -> java.util.Collection[QResult[I, R]]:
        """
        Waits until all scheduled items have been completed or cancelled and returns a list of
        QResults if this queue has been told to collect results.
         
        
        You can still call this method to wait for items to be processed, even if you did not
        specify to collect results.  In that case, the list returned will be empty.
        
        :return: the list of QResult objects that have all the results of the completed jobs.
        :rtype: java.util.Collection[QResult[I, R]]
        :raises java.lang.InterruptedException: if this call was interrupted--Note:  this interruption only
                    happens if the calling thread cannot acquire the lock.  If the thread is
                    interrupted while waiting for results, then it will try again.
        """

    @typing.overload
    def waitForResults(self, timeout: typing.Union[jpype.JLong, int], unit: java.util.concurrent.TimeUnit) -> java.util.Collection[QResult[I, R]]:
        """
        Waits up to the specified time for scheduled jobs to complete.  The results of all completed
        jobs will be returned if this queue has been told to collect results.  At the time that this
        returns, there may still be work to process.  The returned list will contain as much work
        as has been processed when the wait has finished.  Repeated calls to this method will not
        return results from previous waits.
         
        
        You can still call this method to wait for items to be processed, even if you did not
        specify to collect results.  In that case, the list returned will be empty.
        
        :param jpype.JLong or int timeout: the timeout
        :param java.util.concurrent.TimeUnit unit: the timeout unit
        :return: the list of QResult objects that have all the results of the completed jobs.
        :rtype: java.util.Collection[QResult[I, R]]
        :raises java.lang.InterruptedException: if this call was interrupted.
        """

    @typing.overload
    def waitUntilDone(self):
        """
        Waits until all items have been processed **OR** an Exception happens during the
        processing of **ANY item**.
         
        
        **Note:**
        If an exception does occur then the remaining items in the
        queue will be cleared and all current items will be cancelled.
         
        
        If you wish for processing to continue for remaining items when any item encounters an
        exception, then you should instead use :meth:`waitForResults() <.waitForResults>`.  That method will return
        all results, both with and without exceptions, which you can then process, including
        checking for exceptions.  Note that to use :meth:`waitForResults() <.waitForResults>` to examine exceptions,
        you must have created this queue with ``collectResults`` as true.
        
        :raises java.lang.InterruptedException: if interrupted while waiting for a result
        :raises java.lang.Exception: any exception encountered while processing an item (this will cancel all
                items in the queue).
        """

    @typing.overload
    def waitUntilDone(self, timeout: typing.Union[jpype.JLong, int], unit: java.util.concurrent.TimeUnit) -> bool:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class GThreadPool(java.lang.Object):
    """
    Class for managing and sharing thread pools. The GThreadPool is simplified version of the
    ThreadPoolExecutor, which can be confusing to use with its many configuration parameters.
    The GThreadPool has a simple behavior that is controlled by only two configuration parameters -
    the minimum number of threads and the maximum number of threads.
     
    
    The simple behavior for when new tasks are submitted:
    
    1) If there any idle threads, use that thread.
    
    2) If all existing threads are busy and the number of threads is less than max threads, add a
        new thread and use it.
    
    3) if all threads are busy and there are max number of threads, queue the item until a thread
        becomes free.
    
     
    
    The simple behavior for when tasks are completed by a thread:
    
    1) If there are tasks in the queue, start processing a new item in the newly freed thread.
    
    2) if there are more threads that min threads, allow this thread to die if no new
        jobs arrive before
        the "KEEP ALIVE" time expires which is currently 15 seconds.
    
    3) if there are min threads or less, allow this thread to wait forever for a new job
        to arrive.
    """

    @typing.type_check_only
    class GThreadPoolExecutor(java.util.concurrent.ThreadPoolExecutor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def getMaxThreadCount(self) -> int:
            ...

        def getMinThreadCount(self) -> int:
            ...

        def setMaxThreadCount(self, maxThreadCount: typing.Union[jpype.JInt, int]):
            ...

        def setMinThreadCount(self, minThreadCount: typing.Union[jpype.JInt, int]):
            ...

        @property
        def maxThreadCount(self) -> jpype.JInt:
            ...

        @maxThreadCount.setter
        def maxThreadCount(self, value: jpype.JInt):
            ...

        @property
        def minThreadCount(self) -> jpype.JInt:
            ...

        @minThreadCount.setter
        def minThreadCount(self, value: jpype.JInt):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getExecutor(self) -> java.util.concurrent.Executor:
        """
        Returns the :obj:`Executor` used by this thread pool.
        
         
        Note: normal usage of this thread pool contraindicates accessing the executor of
        this pool.  For managing your own jobs, you should use the method on this class directly.
        The intent of this method is to provide access to the executor so that it may be
        passed to other asynchronous APIs, such as the :obj:`CompletableFuture`.
        
        :return: the executor
        :rtype: java.util.concurrent.Executor
        """

    def getMaxThreadCount(self) -> int:
        """
        Returns the maximum number of threads to use in this thread pool.
        
        :return: the maximum number of threads to use in this thread pool.
        :rtype: int
        """

    def getMinThreadCount(self) -> int:
        """
        Returns the minimum number of threads to keep alive in this thread pool.
        
        :return: the minimum number of threads to keep alive in this thread pool.
        :rtype: int
        """

    @staticmethod
    def getPrivateThreadPool(name: typing.Union[java.lang.String, str]) -> GThreadPool:
        """
        Creates a new, private thread pool with the given name.
        
        :param java.lang.String or str name: the name of the thread pool
        :return: a private GThreadPool with the given name.
        :rtype: GThreadPool
        """

    @staticmethod
    def getSharedThreadPool(name: typing.Union[java.lang.String, str]) -> GThreadPool:
        """
        Returns a shared GThreadPool.  If a shared GThreadPool already exists with the given name,
        it is returned.  Otherwise, a new shared GThreadPool is created and returned.
        
        :param java.lang.String or str name: the name of the GThreadPool.
        :return: a shared GThreadPool with the given name.
        :rtype: GThreadPool
        """

    def isPrivate(self) -> bool:
        """
        Returns true if this is not a shared thread pool.
        
        :return: true if this is not a shared thread pool.
        :rtype: bool
        """

    @staticmethod
    def runAsync(poolName: typing.Union[java.lang.String, str], r: java.lang.Runnable) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Runs the given runnable in a background thread using a shared thread pool of the given name.
        
        :param java.lang.String or str poolName: the thread pool name
        :param java.lang.Runnable r: the runnable
        :return: the future
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def setMaxThreadCount(self, maxThreadCount: typing.Union[jpype.JInt, int]):
        """
        Sets the max number of threads to use in this thread pool.  The default is the number
        of processors + 1.
        
        :param jpype.JInt or int maxThreadCount: the maximum number of threads to use in this thread pool.
        """

    def setMinThreadCount(self, minThreadCount: typing.Union[jpype.JInt, int]):
        """
        Sets the minimum number of threads to keep alive in this thread pool.
        
        :param jpype.JInt or int minThreadCount: the minimum number of threads to keep alive in this thread pool.
        """

    def shutdownNow(self):
        ...

    @typing.overload
    def submit(self, futureTask: java.util.concurrent.FutureTask[typing.Any]):
        """
        Submits a FutreTask to be executed by a thread in this thread pool.
        
        :param java.util.concurrent.FutureTask[typing.Any] futureTask: the future task to be executed.
        """

    @typing.overload
    def submit(self, task: java.lang.Runnable) -> java.util.concurrent.Future[typing.Any]:
        """
        Submits a runnable to be executed by this thread pool.
        
        :param java.lang.Runnable task: the runnable to be executed.
        :return: a Future for that runnable.
        :rtype: java.util.concurrent.Future[typing.Any]
        """

    @typing.overload
    def submit(self, task: java.lang.Runnable, result: T) -> java.util.concurrent.Future[T]:
        """
        Submits a runnable to be executed by this thread pool.
        
        :param java.lang.Runnable task: the runnable to be executed.
        :param T result: the result to be returned after the runnable has executed.
        :return: a Future for that runnable.
        :rtype: java.util.concurrent.Future[T]
        """

    @typing.overload
    def submit(self, task: java.util.concurrent.Callable[T]) -> java.util.concurrent.Future[T]:
        """
        Submits a callable to be executed by this thread pool.
        
        :param java.util.concurrent.Callable[T] task: the callable to be executed.
        :return: a Future for that callable.
        :rtype: java.util.concurrent.Future[T]
        """

    @property
    def maxThreadCount(self) -> jpype.JInt:
        ...

    @maxThreadCount.setter
    def maxThreadCount(self, value: jpype.JInt):
        ...

    @property
    def private(self) -> jpype.JBoolean:
        ...

    @property
    def minThreadCount(self) -> jpype.JInt:
        ...

    @minThreadCount.setter
    def minThreadCount(self, value: jpype.JInt):
        ...

    @property
    def executor(self) -> java.util.concurrent.Executor:
        ...


@typing.type_check_only
class ProgressTracker(java.lang.Object):
    """
    A class to synchronize and track the progress of the items being processed by a concurrentQ. It 
    provides various wait methods for when one item is completed or all items are completed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCompletedItemCount(self) -> int:
        ...

    def getItemsInProgressCount(self) -> int:
        ...

    def getNextID(self) -> int:
        ...

    def getTotalItemCount(self) -> int:
        ...

    def waitUntilDone(self, timeout: typing.Union[jpype.JLong, int], unit: java.util.concurrent.TimeUnit) -> bool:
        ...

    @property
    def itemsInProgressCount(self) -> jpype.JLong:
        ...

    @property
    def nextID(self) -> jpype.JLong:
        ...

    @property
    def completedItemCount(self) -> jpype.JLong:
        ...

    @property
    def totalItemCount(self) -> jpype.JLong:
        ...


class QResult(java.lang.Object, typing.Generic[I, R]):
    """
    Class for holding the result of processing an Item in a ConcurrentQ.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, item: I, future: java.util.concurrent.Future[R]):
        ...

    def getError(self) -> java.lang.Exception:
        """
        Returns any Exception that was encountered during processing of the item
        
        :return: any Exception that was encountered during processing of the item
        :rtype: java.lang.Exception
        """

    def getItem(self) -> I:
        """
        Returns the item that was processed.
        
        :return: the item that was processed.
        :rtype: I
        """

    def getResult(self) -> R:
        """
        The result from processing the item.  Will be null if the item was cancelled or had an error.
        
        :return: the result from processing the item or null if it did not complete successfully.
        :rtype: R
        :raises java.lang.Exception: any exception that was thrown during the processing of the input item
        """

    def hasError(self) -> bool:
        """
        Returns true if the item encountered an error while processing the item.
        
        :return: true if the item encountered an error while processing the item.
        :rtype: bool
        """

    def isCancelled(self) -> bool:
        """
        Returns true if the item's processing was cancelled.
        
        :return: true if the item's processing was cancelled.
        :rtype: bool
        """

    @property
    def result(self) -> R:
        ...

    @property
    def item(self) -> I:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def error(self) -> java.lang.Exception:
        ...


class ConcurrentQBuilder(java.lang.Object, typing.Generic[I, R]):
    """
    A helper class to build up the potentially complicated :obj:`ConcurrentQ`.
     
    
    Note: you must supply either a :obj:`GThreadPool` instance or a thread pool name.  Further,
    if you supply the name of a thread pool, then a private, non-shared pool will be used.  If you
    wish to make use of a shared pool, then you need to create that thread pool yourself.  See
    :meth:`GThreadPool.getSharedThreadPool(String) <GThreadPool.getSharedThreadPool>`.
    
     
    
    Examples:
    QCallback<I, R> callback = new AbstractQCallback<I, R>() {    public R process(I item, TaskMonitor monitor) {        // do work here...    }};ConcurrentQBuilder<I, R> builder = new ConcurrentQBuilder<I, R>();builder.setThreadPoolName("Thread Pool Name");builder.setQueue(new PriorityBlockingQueue());concurrentQ = builder.build(callback);// OR, you can chain the builder calls:ConcurrentQBuilder<I, R> builder = new ConcurrentQBuilder<I, R>();queue = builder.setThreadPoolName("Thread Pool Name").                setQueue(new PriorityBlockingQueue()).                setMaxInProgress(1).                build(callback);
     
    
    
    Note: if you wish to take advantage of blocking when adding items to the :obj:`ConcurrentQ`,
        see :meth:`setQueue(Queue) <.setQueue>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def build(self, callback: QCallback[I, R]) -> ConcurrentQ[I, R]:
        """
        Builds the final :obj:`ConcurrentQ`.
        
        :param QCallback[I, R] callback: the callback for processing each job
        :return: the new queue
        :rtype: ConcurrentQ[I, R]
        """

    def setCancelClearsAllJobs(self, clearAllJobs: typing.Union[jpype.JBoolean, bool]) -> ConcurrentQBuilder[I, R]:
        """
        Sets whether a cancel will clear all jobs (current and pending) or just the
        current jobs being processed.  The default value is ``true``.
        
        :param jpype.JBoolean or bool clearAllJobs: if true, cancelling the monitor will cancel all items currently being
                processed by a thread and clear the scheduled items that haven't yet run. If false,
                only the items currently being processed will be cancelled.
        :return: this builder
        :rtype: ConcurrentQBuilder[I, R]
        
        .. seealso::
        
            | :obj:`ConcurrentQ.setMonitor(TaskMonitor, boolean)`
        """

    def setCollectResults(self, collectResults: typing.Union[jpype.JBoolean, bool]) -> ConcurrentQBuilder[I, R]:
        """
        Specifies if the concurrent queue should collect the results as items are processed
        so they can be returned in a :meth:`ConcurrentQ.waitForResults() <ConcurrentQ.waitForResults>` or
        :meth:`ConcurrentQ.waitForNextResult() <ConcurrentQ.waitForNextResult>` call.
        
        :param jpype.JBoolean or bool collectResults: true signals to collect the generated results; defaults to false
        :return: this builder instance
        :rtype: ConcurrentQBuilder[I, R]
        """

    def setJobsReportProgress(self, reportsProgress: typing.Union[jpype.JBoolean, bool]) -> ConcurrentQBuilder[I, R]:
        """
        True signals that the jobs run by the client wish to report progress.  The default value
        is false.
         
        
        The default of false is good for clients that have a known amount of work to be processed.
        In this case, a total count of work jobs is maintained by the queue.  As items are
        completed, the queue will update the monitor provided to it at construction time to reflect
        the number of jobs completed as work is done.  On the other hand, some clients have
        no known number of jobs to complete, but simply add work to the queue as it arrives.
        In that case, the client should update its monitor for progress, as the queue cannot
        do so in a meaningful way.
        
        :param jpype.JBoolean or bool reportsProgress: true signals that the client will update progress; false signals
                that the queue should do so
        :return: this builder instance
        :rtype: ConcurrentQBuilder[I, R]
        """

    def setListener(self, listener: QItemListener[I, R]) -> ConcurrentQBuilder[I, R]:
        ...

    def setMaxInProgress(self, max: typing.Union[jpype.JInt, int]) -> ConcurrentQBuilder[I, R]:
        """
        Specifies the maximum number of items that can be process at a time.
        If this is set to 0, then the concurrent queue will attempt to execute as many
        items at a time as there are threads in the given threadPool.  Setting
        this parameter to 1 will have the effect of guaranteeing that
        all times are processed one at a time in the order they were submitted.
        Any other positive value will run that many items concurrently,
        up to the number of available threads.
        
        :param jpype.JInt or int max: the max number of items to execute at one time; defaults to 0
        :return: this builder instance
        :rtype: ConcurrentQBuilder[I, R]
        """

    def setMonitor(self, monitor: ghidra.util.task.TaskMonitor) -> ConcurrentQBuilder[I, R]:
        ...

    def setQueue(self, queue: java.util.Queue[I]) -> ConcurrentQBuilder[I, R]:
        """
        Sets the queue to be used by the :obj:`ConcurrentQ`.  If you would like advanced features,
        like a queue that blocks when too many items have been placed in it, then use an
        advanced queue here, such as a :obj:`LinkedBlockingQueue`.
         
        
        Note: if you wish to take advantage of blocking when adding items to the :obj:`ConcurrentQ`,
            then be sure to call the appropriate method, such as
            :meth:`ConcurrentQ.offer(java.util.Iterator) <ConcurrentQ.offer>`.
        
        :param java.util.Queue[I] queue: the queue to be used by the :obj:`ConcurrentQ`
        :return: this builder
        :rtype: ConcurrentQBuilder[I, R]
        """

    def setThreadPool(self, threadPool: GThreadPool) -> ConcurrentQBuilder[I, R]:
        """
        Use the given thread pool for processing the work items.  If you do not care to configure
        the thread pool used and you do not wish to make use of shared thread pools, then you
        can call :meth:`setThreadPoolName(String) <.setThreadPoolName>` instead of this method.
        
        :param GThreadPool threadPool: the thread pool to use
        :return: this builder instance
        :rtype: ConcurrentQBuilder[I, R]
        
        .. seealso::
        
            | :obj:`GThreadPool.getSharedThreadPool(String)`
        """

    def setThreadPoolName(self, name: typing.Union[java.lang.String, str]) -> ConcurrentQBuilder[I, R]:
        """
        Sets the name to be used when creating a **private thread pool**.  If you wish to use
        a *shared thread pool*, then you need to create that thread pool yourself and call
        :meth:`setThreadPool(GThreadPool) <.setThreadPool>`.
        
        :param java.lang.String or str name: the name of the thread pool.
        :return: this builder instance
        :rtype: ConcurrentQBuilder[I, R]
        
        .. seealso::
        
            | :obj:`GThreadPool.getSharedThreadPool(String)`
        """


class ReentryGuard(java.lang.Object, typing.Generic[T]):
    """
    A means of detecting and handling reentrant conditions.
     
     
    
    One example where this has been applied deals with updating actions upon changes in context. If,
    in the course of determining which actions are enabled, one of the ``isEnabled`` methods
    displays an error dialog, the Swing thread reenters its main loop while that dialog is showing,
    but before ``isEnabled`` has returned. This can cause all sorts of unexpected behaviors.
    Namely, a timer could fire, context could change again, etc., and the list of actions being
    updated may also change. At worst, this could result in many exceptions being thrown, because a
    data structure has been modified concurrently. At best, if the loop is allowed to finish, there's
    a lot of wasted time updating actions that will never be displayed.
     
     
    
    In that example, the loop that updates the actions would be the "guarded block." Any point at
    which the list of actions is modified might result in "reentrant access" and should be checked.
     
     
    
    This class provides a primitive for instrumenting, detecting, and properly reacting to such
    conditions. For example, if the modification should not be allowed at all, the guard can throw an
    exception at the moment of reentrant access. Alternatively, if the modification should be
    allowed, the guard would simply set a flag, then the guarded block can check that flag and
    terminate early.
     
     
    
    This implementation is *not* thread safe. It is designed to check for reentrant access,
    not concurrent access. The client must ensure that only one thread enters the guarded block or
    calls :meth:`checkAccess() <.checkAccess>` at a time. Otherwise, the behavior is undefined.
     
     
    public class ActionManager {
        private final ReentryGuard<Throwable> reentryGuard = new ReentryGuard<>() {
            @Override
            public Throwable violated(boolean nested, Throwable previous) {
                if (previous != null) {
                    return previous;
                }
                return new Throwable(); // record the stack of the violation
            }
        };
        private final List<Action> actions;
     
        public void addAction(Action action) {
            // Notify the guard we've committed some reentrant behavior.
            // Would need to add this to anything that modifies the action list. 
            reentryGuard.checkAccess();
            actions.add(action);
        }
     
        public void updateActions(Context ctx) {
            try (Guarded guarded = reentryGuard.enter()) {
                // There is no need to create a copy, since we'll bail before the next iteration
                for (Action action : actions) {
                    boolean enabled = action.isEnabledForContext(ctx);
                    if (reentryGuard.getViolation() != null) {
                        break; // Actions has been modified. Bail.
                        // NOTE: This leaves the update incomplete.
                        // Something has to call updateActions again.
                    }
                    actions.setEnabled(enabled);
                }
            }
        }
    }
    """

    class Guarded(java.lang.AutoCloseable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, guard: ReentryGuard[typing.Any]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def checkAccess(self):
        """
        Notify the guard of access to some resource used by the guarded block
         
         
        
        If the access turns out to be reentrant, i.e., the thread's current stack includes a frame in
        the guarded block, this will call :meth:`violated(boolean, Object) <.violated>` and record the result.
        It can be inspected later via :meth:`getViolation() <.getViolation>`.
        """

    def enter(self) -> ReentryGuard.Guarded:
        """
        Notify the guard of entry into the guarded block
         
         
        
        This should always be used in a ``try-with-resources`` block. This will ensure that the
        guard is notified of exit from the guarded block, even in exceptional circumstances.
         
         
        
        NOTE: Re-entering the guarded portion is itself a violation.
        
        :return: a closeable for notifying the guard of exit from the guarded block, or null if
                reentering the guarded block
        :rtype: ReentryGuard.Guarded
        """

    def getViolation(self) -> T:
        """
        Retrieve a violation, if applicable
         
         
        
        Calling this method outside of a guarded block has undefined behavior.
        
        :return: the violation; or null to indicate no violation
        :rtype: T
        """

    def isViolated(self) -> bool:
        """
        Check if there is a violation
         
         
        
        This is equivalent to checking if :meth:`getViolation() <.getViolation>` returns non-null.
        
        :return: true if there is a violation.
        :rtype: bool
        """

    @property
    def violated(self) -> jpype.JBoolean:
        ...

    @property
    def violation(self) -> T:
        ...


class QCallback(java.lang.Object, typing.Generic[I, R]):
    """
    Interface that defines the callback to work on the items given to the 
    :meth:`ConcurrentQ.add(I) <ConcurrentQ.add>` methods.  Each item that is processed will be handed to the
    :meth:`process(I, TaskMonitor) <.process>` method of the implementing class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def process(self, item: I, monitor: ghidra.util.task.TaskMonitor) -> R:
        """
        Processes the given item in background thread provided by a GThreadPool.
        
        :param I item: the item to process.
        :param ghidra.util.task.TaskMonitor monitor: a monitor that can be used to check for cancellation and to report progress and
        transient messages.
        :return: The return value resulting from processing the item.
        :rtype: R
        """


class QRunnable(java.lang.Object, typing.Generic[I]):
    """
    Interface that defines the Runnable to work on the items given to the 
    :meth:`ConcurrentQ.add(I) <ConcurrentQ.add>` methods.  Each item that is processed will be handed to the
    :meth:`run(I, TaskMonitor) <.run>` method of the implementing class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def run(self, item: I, monitor: ghidra.util.task.TaskMonitor):
        """
        Processes the given item in background thread provided by a GThreadPool.
        
        :param I item: the item to process.
        :param ghidra.util.task.TaskMonitor monitor: a monitor that can be used to check for cancellation and to report progress and
        transient messages.
        """


class QProgressListener(java.lang.Object, typing.Generic[I]):
    """
    Interface for listeners who want progress and transient message information from QWorkers while
    processing items.
    """

    class_: typing.ClassVar[java.lang.Class]

    def maxProgressChanged(self, id: typing.Union[jpype.JLong, int], item: I, maxProgress: typing.Union[jpype.JLong, int]):
        """
        Notification that the max progress value has changed.
        
        :param jpype.JLong or int id: the id of the item that has completed processing.
        :param I item: the item that was being processed when the worker changed the max progress.
        :param jpype.JLong or int maxProgress: the max value of the progress for this task.
        """

    def progressChanged(self, id: typing.Union[jpype.JLong, int], item: I, currentProgress: typing.Union[jpype.JLong, int]):
        """
        Notification that progress has changed during the processing of an item.
        
        :param jpype.JLong or int id: the id of the item being processed.  Since multiple items can be processed concurrently,
        the id can be used to "demultiplex" the progress and messages being generated.
        :param I item: the item that was being processed when the worker changed the max progress.
        :param jpype.JLong or int currentProgress: the current value of the progress for this task.
        """

    def progressMessageChanged(self, id: typing.Union[jpype.JLong, int], item: I, message: typing.Union[java.lang.String, str]):
        """
        
        
        :param jpype.JLong or int id: the id of the item that has completed processing.
        :param I item: the item that was being processed when the worker changed the max progress.
        :param java.lang.String or str message:
        """

    def progressModeChanged(self, id: typing.Union[jpype.JLong, int], item: I, indeterminate: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that the progress mode has changed from/to indeterminate mode
        
        :param jpype.JLong or int id: the id of the item that has completed processing.
        :param I item: the item that was being processed when the worker changed the max progress.
        :param jpype.JBoolean or bool indeterminate:
        """

    def taskEnded(self, id: typing.Union[jpype.JLong, int], item: I, totalCount: typing.Union[jpype.JLong, int], completedCount: typing.Union[jpype.JLong, int]):
        """
        Notification that a new task has completed processing for an item.
        
        :param jpype.JLong or int id: the id of the item that has completed processing.
        :param I item: the item that was being processed when the worker changed the max progress.
        :param jpype.JLong or int totalCount: the total number of items that have been submitted to the ConcurrentQ
        :param jpype.JLong or int completedCount: the total number of items that completed processing.
        """

    def taskStarted(self, id: typing.Union[jpype.JLong, int], item: I):
        """
        Notification that a new task has been generated to process an item.
        
        :param jpype.JLong or int id: the id of the item being processed.
        :param I item: the item that was being processed when the worker changed the max progress.
        """


class QRunnableAdapter(QCallback[I, java.lang.Object], typing.Generic[I]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, runnable: QRunnable[I]):
        ...


class ConcurrentGraphQ(java.lang.Object, typing.Generic[I]):

    @typing.type_check_only
    class MyItemListener(QItemListener[I, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, runnable: QRunnable[I], graph: ghidra.util.graph.AbstractDependencyGraph[I], pool: GThreadPool, monitor: ghidra.util.task.TaskMonitor):
        ...

    def dispose(self):
        ...

    def execute(self):
        ...



__all__ = ["ConcurrentListenerSet", "FutureTaskMonitor", "QItemListener", "ConcurrentQ", "GThreadPool", "ProgressTracker", "QResult", "ConcurrentQBuilder", "ReentryGuard", "QCallback", "QRunnable", "QProgressListener", "QRunnableAdapter", "ConcurrentGraphQ"]
