from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.concurrent
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


K = typing.TypeVar("K")
T = typing.TypeVar("T")


class PriorityJob(Job):

    class_: typing.ClassVar[java.lang.Class]

    def getPriority(self) -> int:
        ...

    @property
    def priority(self) -> jpype.JLong:
        ...


class AbstractWorker(java.lang.Object, typing.Generic[T]):
    """
    Class that uses a single thread to execute scheduled jobs.
     
    
    Subclasses provide the :obj:`BlockingQueue` implementation, which allows for controlling how
    jobs get scheduled (e.g., FIFO or priority-based).
    """

    @typing.type_check_only
    class ProgressListener(generic.concurrent.QProgressListener[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class JobCallback(generic.concurrent.QCallback[K, java.lang.Object], typing.Generic[K]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def clearAllJobs(self):
        """
        Clears any pending jobs and cancels any currently executing job.
        """

    def clearAllJobsWithInterrupt_IKnowTheRisks(self):
        """
        Clears any pending jobs and cancels any currently executing job.
         
        
        **Warning: Calling this method may leave the program in a bad state.  Thus, it is
        recommended that you only do so when you known that any job that could possibly be scheduled
        does not manipulate sensitive parts of the program; for example, opening file handles that
        should be closed before finishing.**
         
        **
        If you are unsure about whether your jobs handle interrupt correctly, then don't use this
        method.
        **
        """

    def clearPendingJobs(self):
        """
        Clears any jobs from the queue **that have not yet been run**.  This does not cancel the
        currently running job.
        """

    def dispose(self):
        """
        Disposes this worker and terminates its thread.
        """

    def isBusy(self) -> bool:
        ...

    def isDisposed(self) -> bool:
        ...

    def schedule(self, job: T):
        """
        Schedules the job for execution.  Jobs will be processed in priority order.  The
        highest priority jobs are those with the lowest value return by the job's getPriority()
        method. (i.e. the job with priority 0 will be processed before the job with priority 1)
        
        :param T job: the job to be executed.
        """

    def setBusyListener(self, listener: ghidra.util.task.BusyListener):
        ...

    def setTaskMonitor(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    def waitUntilNoJobsScheduled(self, maxWait: typing.Union[jpype.JInt, int]):
        """
        This method will block until there are no scheduled jobs in this worker. This method assumes
        that all jobs have a priority less than Long.MAX_VALUE.
         
        
        For a non-priority queue, this call will not wait for jobs that are scheduled after this
        call was made.
        
        :param jpype.JInt or int maxWait: the max number of milliseconds to wait
        """

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...


class Worker(AbstractWorker[Job]):
    """
    Executes a single job at a time in FIFO order.
    
    
    .. seealso::
    
        | :obj:`PriorityWorker`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Creates a Worker that will use a **shared** thread pool to process jobs.  Also, threads
        created using this constructor are not persistent.   Use this constructor when you do 
        not have a :obj:`TaskMonitor` that wants updates from this worker.
        
        :param java.lang.String or str name: the name of the shared thread pool.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a Worker that will use a **shared** thread pool to process jobs.  Also, threads
        created using this constructor are not persistent.
        
        :param java.lang.String or str name: the name of the shared thread pool.
        :param ghidra.util.task.TaskMonitor monitor: the monitor used to cancel jobs.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], isPersistentThread: typing.Union[jpype.JBoolean, bool], useSharedThreadPool: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        This constructor allows you to change persistence and shared thread pool usage.
        
        :param java.lang.String or str name: the name of the shared thread pool.
        :param jpype.JBoolean or bool isPersistentThread: if true, the worker thread will stay around when idle;
                    false means that the thread will go away if not needed. Should be true for 
                    high frequency usage.
        :param jpype.JBoolean or bool useSharedThreadPool: true signals to use the given name to find/create a thread pool 
                    that can be shared throughout the system.
        :param ghidra.util.task.TaskMonitor monitor: the monitor used to cancel jobs.
        """

    @staticmethod
    def createGuiWorker() -> Worker:
        """
        A convenience method to create a Worker that uses a shared thread pool for performing
        operations for GUI clients in a background thread 
         
         
        Note: the shared thread pool of the worker created here has a max number of 
        threads as defined by :meth:`SystemUtilities.getDefaultThreadPoolSize() <SystemUtilities.getDefaultThreadPoolSize>`.   If there is
        a point in time where we notice contention in thread due to too many clients of this
        method (i.e., too many tasks are blocking because the thread pool is full), then we 
        can update the size of the thread pool for this Worker.
        
        :return: the new worker
        :rtype: Worker
        """


class Job(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def cancel(self):
        ...

    def getError(self) -> java.lang.Throwable:
        ...

    def hasError(self) -> bool:
        ...

    def isCancelled(self) -> bool:
        ...

    def isCompleted(self) -> bool:
        ...

    def run(self, monitor: ghidra.util.task.TaskMonitor):
        """
        The method that gets called by the Worker when this job is selected to be run
        by the Worker.
        
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :raises CancelledException: jobs may choose to throw a cancelled exception
        """

    def setCompleted(self):
        ...

    def setError(self, t: java.lang.Throwable):
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def completed(self) -> jpype.JBoolean:
        ...

    @property
    def error(self) -> java.lang.Throwable:
        ...

    @error.setter
    def error(self, value: java.lang.Throwable):
        ...


class PriorityWorker(AbstractWorker[PriorityJob]):
    """
    Executes a single job at a time in priority order.
    
    
    .. seealso::
    
        | :obj:`Worker`
    """

    @typing.type_check_only
    class PriorityJobComparator(java.util.Comparator[PriorityJob]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a PriorityWorker that will use a **shared** thread pool to process jobs.  
        Also, threads created using this constructor are not persistent.
        
        :param java.lang.String or str name: the name of the shared thread pool.
        :param ghidra.util.task.TaskMonitor monitor: the monitor used to cancel jobs.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], isPersistentThread: typing.Union[jpype.JBoolean, bool], useSharedThreadPool: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        This constructor allows you to change persistence and shared thread pool usage.
        
        :param java.lang.String or str name: the name of the shared thread pool.
        :param jpype.JBoolean or bool isPersistentThread: if true, the worker thread will stay around when idle;
                    false means that the thread will go away if not needed. Should be true for 
                    high frequency usage.
        :param jpype.JBoolean or bool useSharedThreadPool: true signals to use the given name to find/create a thread pool 
                    that can be shared throughout the system.
        :param ghidra.util.task.TaskMonitor monitor: the monitor used to cancel jobs.
        """



__all__ = ["PriorityJob", "AbstractWorker", "Worker", "Job", "PriorityWorker"]
