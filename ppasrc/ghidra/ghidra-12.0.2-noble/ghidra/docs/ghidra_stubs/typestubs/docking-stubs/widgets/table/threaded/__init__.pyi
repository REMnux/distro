from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import docking.widgets.table.sort
import ghidra.framework.plugintool
import ghidra.util.datastruct
import ghidra.util.task
import ghidra.util.worker
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


DATA_SOURCE = typing.TypeVar("DATA_SOURCE")
ROW_OBJECT = typing.TypeVar("ROW_OBJECT")
T = typing.TypeVar("T")


class LoadJob(TableUpdateJob[T], typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ThreadedTableModel(docking.widgets.table.GDynamicColumnTableModel[ROW_OBJECT, DATA_SOURCE], docking.widgets.table.RowObjectFilterModel[ROW_OBJECT], typing.Generic[ROW_OBJECT, DATA_SOURCE]):
    """
    The base implementation of the threaded table model.
     
    
    You can optionally set this model to load data incrementally by passing the correct
    constructor argument.  Note, if you make this model incremental, then you need to set an
    incremental task monitor in order to get feedback about loading
    (see :meth:`setIncrementalTaskMonitor(TaskMonitor) <.setIncrementalTaskMonitor>`.  Alternatively, you can use
    a :obj:`GThreadedTablePanel`, which will install the proper monitor for you.
    """

    @typing.type_check_only
    class NonIncrementalUpdateManagerListener(ThreadedTableModelListener):
        """
        Standard (non-incremental) listener mechanism to receive notifications from the update
        manager.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IncrementalUpdateManagerListener(ThreadedTableModelListener):
        """
        Listener to get updates from the :obj:`ThreadedTableModelUpdateMgr`.  This listener is only
        here to make sure that non-loading actions, like sorting, will trigger notifications to
        clients.  "Loading" events are handled by the listener passed to the
        :obj:`IncrementalLoadJob` (this :obj:`IncrementalLoadJobListener`).
         
        
        We need the two different listeners due to how they are wired to the update manager.  The
        :obj:`IncrementalLoadJobListener` listener is added and removed for each load request.  We
        need that listener so that during an incremental load, when multiple starts and stops come
        from the update manager, we don't keep adding and removing the progress bar.  This works
        great for a normal loading processes.  However, we still need a listener for when the users
        manipulates the data, like for filtering or sorting.  Without having this listener, there is
        no way to get those notifications.  Thus, this listener has to be careful not to "get in the
        way" of the loading listener--the loading listener will thus always take precedence.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IncrementalLoadJobListener(IncrementalJobListener):
        """
        A special internal listener for the model to know when incremental jobs begin and end.  This
        allows the model to ignore repeated start/finished events from the update manager when it is
        in 'load incrementally' mode.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OneTimeListenerWrapper(ThreadedTableModelListener):
        """
        A listener wrapper that will pass on notifications and then remove itself after the
        loadFinished() call so that not more events are broadcast.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OneTimeCompletedLoadingAdapter(ThreadedTableModelListener):
        """
        Class to adapt a :obj:`ThreadedTableModelListener` to a single use Consumer that gets
        notified once when the table is done loading and then removes the threaded table model 
        listener.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addInitialLoadListener(self, listener: ThreadedTableModelListener):
        """
        Adds a listener that will be notified of the first table load of this model.  After the
        initial load, the listener is removed.
        
        :param ThreadedTableModelListener listener: the listener
        """

    @typing.overload
    def addInitialLoadListener(self, completedLoadingConsumer: java.util.function.Consumer[java.lang.Boolean]):
        """
        Adds a consumer that will be notified when the model finishes loading. The consumer
        is passed a boolean that indicates is true if the loading was cancelled. After the
        table completes loading, the listener is removed.
        
        :param java.util.function.Consumer[java.lang.Boolean] completedLoadingConsumer: the consumer to be notified when the table is done loading
        """

    def addObject(self, obj: ROW_OBJECT):
        """
        Adds the specified object to this model and schedules an update.
        
        :param ROW_OBJECT obj: the object to add
        """

    def addThreadedTableModelListener(self, listener: ThreadedTableModelListener):
        """
        This is a way to know about updates from the table.
        
        :param ThreadedTableModelListener listener: the listener to add
        
        .. seealso::
        
            | :obj:`.addInitialLoadListener(ThreadedTableModelListener)`
        
            | :obj:`.removeThreadedTableModelListener(ThreadedTableModelListener)`
        """

    def cancelAllUpdates(self):
        """
        Cancels all current and pending updates to the model.
        """

    def dispose(self):
        """
        Disposes this model. Once a model has been disposed, it cannot be reused.
        """

    def getModelRow(self, viewRow: typing.Union[jpype.JInt, int]) -> int:
        """
        Given a row index for the view (filtered) model, return the corresponding index in the raw
        (unfiltered) model.
        
        :param jpype.JInt or int viewRow: The row index that corresponds to filtered data
        :return: the index of that row in the unfiltered data
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getViewRow(int)`
        """

    def getName(self) -> str:
        """
        Returns the name of this model.
        
        :return: the name of this model.
        :rtype: str
        """

    def getRowObjects(self, rows: jpype.JArray[jpype.JInt]) -> java.util.List[ROW_OBJECT]:
        """
        Returns the corresponding row objects for the specified rows.
        
        :param jpype.JArray[jpype.JInt] rows: the table rows
        :return: the corresponding database keys.
        :rtype: java.util.List[ROW_OBJECT]
        """

    def getTableFilter(self) -> docking.widgets.table.TableFilter[ROW_OBJECT]:
        """
        Returns the filter for this model.  The value returned from this method will not be null,
        but will instead be an instanceof :obj:`NullTableFilter` when no filter is applied.   The
        value returned from this method may not actually yet be applied, depending upon when the
        background thread finishes loading.
        
        :return: the filter
        :rtype: docking.widgets.table.TableFilter[ROW_OBJECT]
        """

    def getViewRow(self, modelRow: typing.Union[jpype.JInt, int]) -> int:
        """
        Given a row index for the raw (unfiltered) model, return the corresponding index in the view
        (filtered) model.
        
        :param jpype.JInt or int modelRow: The row index that corresponds to unfiltered data
        :return: the index of that row in the filtered data
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getModelRow(int)`
        """

    def hasFilter(self) -> bool:
        """
        Returns true if there is a table filter set that is not the :obj:`NullTableFilter`.
        
        :return: true if there is a table filter set.
        :rtype: bool
        """

    def isBusy(self) -> bool:
        """
        Returns true if the model is busy. "Busy" means the model
        is either loading or updating.
        
        :return: true if the model is busy
        :rtype: bool
        """

    def isLoadIncrementally(self) -> bool:
        ...

    def reFilter(self):
        """
        Triggers this class to filter the contents of the data.
        """

    def reSort(self):
        """
        Resort the table using the current sort criteria.  This is useful if the data in the
        table has changed and is no longer sorted properly.  If the setSort method is used, nothing
        will happen because the table will think it is already sorted on that criteria.
        """

    def reload(self):
        """
        Schedules the model to completely reload its underlying data.
        """

    def removeObject(self, obj: ROW_OBJECT):
        """
        Removes the specified object from this model and schedules an update.
        
         
        Note: for this method to function correctly, the given object must compare as
        :meth:`equals(Object) <.equals>` and have the same :meth:`hashCode() <.hashCode>` as the object to be removed
        from the table data.   This allows clients to create proxy objects to pass into this method,
        as long as they honor those requirements.
        
         
        If this model's data is sorted, then a binary search will be used to locate the item
        to be removed.  However, for this to work, all field used to sort the data must still be
        available from the original object and must be the same values.   If this is not true, then
        the binary search will not work and a brute force search will be used.
        
        :param ROW_OBJECT obj: the object to remove
        """

    def removeThreadedTableModelListener(self, listener: ThreadedTableModelListener):
        ...

    def setIncrementalTaskMonitor(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    def setTableFilter(self, tableFilter: docking.widgets.table.TableFilter[ROW_OBJECT]):
        """
        Sets the given ``TableFilter`` on this model.  This table filter will then be used
        by this model in the default :meth:`doFilter(List, TableSortingContext, TaskMonitor) <.doFilter>`
        method.
        
        :param docking.widgets.table.TableFilter[ROW_OBJECT] tableFilter: The filter to use for table filtering.
        """

    def updateObject(self, obj: ROW_OBJECT):
        """
        Schedules an update for the specified object.
        
        :param ROW_OBJECT obj: the object for which to schedule the update
        """

    @property
    def loadIncrementally(self) -> jpype.JBoolean:
        ...

    @property
    def rowObjects(self) -> java.util.List[ROW_OBJECT]:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def viewRow(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def modelRow(self) -> jpype.JInt:
        ...

    @property
    def tableFilter(self) -> docking.widgets.table.TableFilter[ROW_OBJECT]:
        ...

    @tableFilter.setter
    def tableFilter(self, value: docking.widgets.table.TableFilter[ROW_OBJECT]):
        ...


class ThreadedTableModelListenerAdapter(ThreadedTableModelListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CoalescingAddRemoveStrategy(TableAddRemoveStrategy[T], typing.Generic[T]):
    """
    The :obj:`ThreadedTableModel` does not correctly function with data that can change outside of 
    the table.  For example, if a table uses db objects as row objects, these db objects can be 
    changed by the user and by analysis while table has already been loaded.   The problem with this 
    is that the table's sort can be broken when new items are to be added, removed or re-inserted, 
    as this process requires a binary search, which will be broken if the criteria used to sort the 
    data has changed.   Effectively, a row object change can break the binary search if that item 
    stays in a previously sorted position, but has updated data that would put the symbol in a new 
    position if sorted again.  For example, if the table is sorted on name and the name of an item 
    changes, then future uses of the binary search will be broken while that item is still in the 
    position that matches its old name.
     
    
    This issue has been around for quite some time.  To completely fix this issue, each row object
    of the table would need to be immutable, at least on the sort criteria.   We could fix this in 
    the future if the *mostly correct* sorting behavior is not good enough.  For now, the
    client can trigger a re-sort (e.g., by opening and closing the table) to fix the slightly 
    out-of-sort data.
     
    
    The likelihood of the sort being inconsistent now relates directly to how many changed items are 
    in the table at the time of an insert.   The more changed items, the higher the chance of a 
    stale/misplaced item being used during a binary search, thus producing an invalid insert 
    position.  
     
    
    This strategy is setup to mitigate the number of invalid items in the table at the time the 
    inserts are applied.   The basic workflow of this algorithm is:
     
    1) condense the add / remove requests to remove duplicate efforts
    2) process all removes first
        --all pure removes
        --all removes as part of a re-insert
    3) process all items that failed to remove due to the sort data changing
    4) process all adds (this step will fail if the data contains mis-sorted items)
        --all adds as part of a re-insert
        --all pure adds
     
     
    Step 3, processing failed removals, is done to avoid a brute force lookup at each removal 
    request.   
     
     
    This strategy allows for the use of client proxy objects.   The proxy objects should be coded 
    such that the ``hashCode()`` and ``equals()`` methods will match those methods of the 
    data's real objects.  These proxy objects allow clients to search for an item without having a
    reference to the actual item.  In this sense, the proxy object is equal to the existing row
    object in the table model, but is not the **same** instance as the row object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NullTableFilter(docking.widgets.table.TableFilter[ROW_OBJECT], typing.Generic[ROW_OBJECT]):
    """
    A table filter that represents the state of having no filter.  This allows us to not have to
    use ``null`` to have multiple meanings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TableAddRemoveStrategy(java.lang.Object, typing.Generic[T]):
    """
    A strategy to perform table add and remove updates
    """

    class_: typing.ClassVar[java.lang.Class]

    def process(self, addRemoveList: java.util.List[docking.widgets.table.AddRemoveListItem[T]], tableData: TableData[T], monitor: ghidra.util.task.TaskMonitor):
        """
        Adds to and removes from the table data those items in the given add/remove list
        
        :param java.util.List[docking.widgets.table.AddRemoveListItem[T]] addRemoveList: the items to add/remove
        :param TableData[T] tableData: the table's data
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :raises CancelledException: if the monitor is cancelled
        """


class FilterJob(TableUpdateJob[T], typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TableUpdateJob(java.lang.Object, typing.Generic[T]):
    """
    State machine object for performing the various update functions on a ThreadedTableModel.
    The general pattern is to:
     
    1. Load 
    2. Filter 
    3. Process individual adds and removes 
    4. Sort 
    5. Set the processed data back on the model
    
     
    
    Not all the update functions are performed on a run of a TableUpdateJob.  If the reloadData flag is
    not set, then the data is just copied from the model's current list, instead of calling the model's
    loadData() method. If the sortComparator is null,
    then the data is not sorted (for example, when only filtering needs to be done).  If there
    are no add/removes in the list, then that step does nothing.
     
    
    Before the job completes, new calls to sort and filter can be called.  If the job is past the
    stage of the new call, the ``monitor`` is cancelled, causing the current stage to abort.
    The next state of this job is set to the appropriate state for the call, the monitor is
    reset, and the job begins executing the next stage, based upon the new call.
    """

    @typing.type_check_only
    class JobState(java.lang.Enum[TableUpdateJob.JobState]):

        class_: typing.ClassVar[java.lang.Class]
        NOT_RUNNING: typing.Final[TableUpdateJob.JobState]
        LOADING: typing.Final[TableUpdateJob.JobState]
        FILTERING: typing.Final[TableUpdateJob.JobState]
        ADD_REMOVING: typing.Final[TableUpdateJob.JobState]
        SORTING: typing.Final[TableUpdateJob.JobState]
        APPLYING: typing.Final[TableUpdateJob.JobState]
        CANCELLED: typing.Final[TableUpdateJob.JobState]
        DONE: typing.Final[TableUpdateJob.JobState]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TableUpdateJob.JobState:
            ...

        @staticmethod
        def values() -> jpype.JArray[TableUpdateJob.JobState]:
            ...


    @typing.type_check_only
    class MonitoredComparator(java.util.Comparator[T], typing.Generic[T]):
        """
        Wraps a :obj:`Comparator` to add progress monitoring and cancel checking
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SortCancelledException(java.lang.RuntimeException):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def addRemove(self, item: docking.widgets.table.AddRemoveListItem[T], maxAddRemoveCount: typing.Union[jpype.JInt, int]):
        """
        Adds the Add/Remove item to the list of items to be processed in the add/remove phase. This
        call is not allowed on running jobs, only pending jobs.
        
        :param docking.widgets.table.AddRemoveListItem[T] item: the add/remove item to add to the list of items to be processed in the
                add/remove phase of this job.
        :param jpype.JInt or int maxAddRemoveCount: the maximum number of add/remove jobs to queue before performing a
                full reload
        """

    def cancel(self):
        ...

    def reload(self):
        """
        Forces this job to completely reload the data, instead of copying from the model's current
        data.  This call is not allowed on the currently running job and is only appropriate for a
        pending job.
        """

    def requestFilter(self) -> bool:
        """
        Tells the job that the filter criteria has changed.  This method can be called on the
        currently running job as well as the pending job.  If called on the running job, the effect
        depends on the running job's state:
         
        * If the filter state hasn't happened yet, then nothing needs to be done as this job
        will filter later anyway.
        * If the filter state has already been started or completed, then this method
        attempts to stop the current process phase and cause the state machine to return to
            the filter phase.
        * If the current job has already entered the DONE state, then the filter cannot take
        effect in this job and a false value is returned to indicate the filter was not
        handled by this job.
        
        
        :return: true if the filter can be processed by this job, false if this job is essentially
        already completed and therefore cannot perform the filter job.
        :rtype: bool
        """

    def requestSort(self, newSortingContext: docking.widgets.table.TableSortingContext[T], forceSort: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Sets the TableColumnComparator to use for sorting the data.  This method can be called on
        the currently running job as well as the pending job.  If called on the running job, the
        effect depends on the running job's state:
         
        * If the sort state hasn't happened yet, all it does is set the comparator for when
        the sort occurs.
        * If the sort state has already been started or completed, then this method attempts
        to stop the current process phase and cause the state machine to return to the sort
        phase.
        * If the current job has already entered the DONE state, then the sort cannot take
            effect in this job and a false value is returned to indicate the
        sort was not handled by this job.
        
        
        :param docking.widgets.table.TableSortingContext[T] newSortingContext: the TableColumnComparator to use to sort the data.
        :param jpype.JBoolean or bool forceSort: True signals to re-sort, even if this is already sorted
        :return: true if the sort can be processed by this job, false if this job is essentially
                already completed and therefore cannot perform the sort job.
        :rtype: bool
        """

    def run(self):
        """
        The basic run() method that executes the state machine.
        """


@typing.type_check_only
class IncrementalJobListener(java.lang.Object):
    """
    A package-level listener for the ThreadedTableModel to know when incremental load jobs are
    finished.
    """

    class_: typing.ClassVar[java.lang.Class]


class LoadSpecificDataJob(TableUpdateJob[T], typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ThreadedBackupRowComparator(docking.widgets.table.sort.ColumnRenderedValueBackupComparator[T], typing.Generic[T]):
    """
    A version of :obj:`ColumnRenderedValueBackupComparator` that uses the 
    :obj:`ThreadedTableModel`'s cache for column lookups
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: ThreadedTableModel[T, typing.Any], sortColumn: typing.Union[jpype.JInt, int]):
        """
        Constructs this class with the given column comparator that will get called after the
        given row is converted to the column value for the given sort column
        
        :param ThreadedTableModel[T, typing.Any] model: the table model using this comparator
        :param jpype.JInt or int sortColumn: the column being sorted
        
        .. seealso::
        
            | :obj:`RowBasedColumnComparator`
        """


class ThreadedTableColumnComparator(docking.widgets.table.sort.RowBasedColumnComparator[T], typing.Generic[T]):
    """
    A comparator for comparing table column values for threaded table models.  This comparator
    uses the column cache of the :obj:`ThreadedTableModel`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, model: ThreadedTableModel[T, typing.Any], sortColumn: typing.Union[jpype.JInt, int], comparator: java.util.Comparator[java.lang.Object]):
        """
        Constructs this class with the given column comparator that will get called after the
        given row is converted to the column value for the given sort column
        
        :param ThreadedTableModel[T, typing.Any] model: the table model using this comparator
        :param jpype.JInt or int sortColumn: the column being sorted
        :param java.util.Comparator[java.lang.Object] comparator: the column comparator to use for sorting
        
        .. seealso::
        
            | :obj:`RowBasedColumnComparator`
        """

    @typing.overload
    def __init__(self, model: ThreadedTableModel[T, typing.Any], sortColumn: typing.Union[jpype.JInt, int], comparator: java.util.Comparator[java.lang.Object], backupRowComparator: java.util.Comparator[java.lang.Object]):
        """
        This version of the constructor is used for the default case where the client will 
        supply a backup row comparator that will get called if the given column comparator returns
        a '0' value.
        
        :param ThreadedTableModel[T, typing.Any] model: the table model using this comparator
        :param jpype.JInt or int sortColumn: the column being sorted
        :param java.util.Comparator[java.lang.Object] comparator: the column comparator to use for sorting
        :param java.util.Comparator[java.lang.Object] backupRowComparator: the backup row comparator
        
        .. seealso::
        
            | :obj:`RowBasedColumnComparator`
        """


class TableData(java.lang.Iterable[ROW_OBJECT], typing.Generic[ROW_OBJECT]):
    """
    A concept that represents the data used by the :obj:`ThreadedTableModel`.  This class 
    encapsulates the actual data, along with any filter applied, any sort applied, along with 
    some convenience methods for performing operations on this group of data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def get(self, modelRow: typing.Union[jpype.JInt, int]) -> ROW_OBJECT:
        ...

    def indexOf(self, t: ROW_OBJECT) -> int:
        """
        Uses the current sort to perform a fast lookup of the given item in the given list when 
        sorted; a brute-force lookup when not sorted
        
        :param ROW_OBJECT t: the item
        :return: the index
        :rtype: int
        """

    def insert(self, value: ROW_OBJECT):
        """
        Adds the new ``value`` to the data at the appropriate location based on the sort
        
        :param ROW_OBJECT value: the row Object to insert
        """

    def process(self, function: java.util.function.BiFunction[java.util.List[ROW_OBJECT], docking.widgets.table.TableSortingContext[ROW_OBJECT], java.util.List[ROW_OBJECT]]):
        """
        A generic method that allows clients to process the contents of this table data.  This
        method is not synchronized and should only be called from a :obj:`TableUpdateJob` or
        one of its callbacks.
         
         
        Note: this method will do nothing if the data is not sorted.
        
        :param java.util.function.BiFunction[java.util.List[ROW_OBJECT], docking.widgets.table.TableSortingContext[ROW_OBJECT], java.util.List[ROW_OBJECT]] function: the consumer of the data and the current sort context
        """

    def remove(self, t: ROW_OBJECT) -> bool:
        ...

    def size(self) -> int:
        ...


@typing.type_check_only
class ThreadedTableModelUpdateMgr(java.lang.Object, typing.Generic[T]):
    """
    Manages the updating of ThreadTableModels.  As requests to load, sort, filter, add/remove item
    in a ThreadedTableModel occur, this class schedules a TableUpdateJob to do the work.  It uses
    a SwingUpdateManager to coalesce add/remove so that the table does not constantly update when
    are large number of table changing events are incoming.
    """

    @typing.type_check_only
    class ThreadRunnable(java.lang.Runnable):
        """
        Runnable used be new threads to run scheduled jobs.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PermantentlyCancelledMonitor(ghidra.util.task.TaskMonitorAdapter):
        """
        A monitor that allows us to make sure that this update manager does not clear the cancel
        done in :meth:`ThreadedTableModelUpdateMgr.dispose() <ThreadedTableModelUpdateMgr.dispose>`.  This is useful if we want to never
        again perform any work, such as when we are disposed.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    DELAY: typing.Final = 5000
    MAX_DELAY: typing.Final = 1200000

    def cancelAllJobs(self):
        """
        Warning!:  This cancels the current job, pending jobs and anything waiting in the update
        manager.  This method is meant to be used outside of normal usage.  That is, it should
        be used when you really have to cancel everything that is going on in order to restart
        things.
        """

    def updateNow(self):
        """
        Kicks the swing update manager to immediately process any accumulated add/removes.
        """


class ThreadedTableModelStub(ThreadedTableModel[ROW_OBJECT, java.lang.Object], typing.Generic[ROW_OBJECT]):
    """
    A version of :obj:`ThreadedTableModel` for clients that do not need a DATA_SOURCE.  
     
    
    **
    Note: this class will change a ``null`` value for the :obj:`ServiceProvider` parameter
    to a stubbed version.  If your model needs a real service provider, then you can pass a 
    non-null value.
    **
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], serviceProvider: ghidra.framework.plugintool.ServiceProvider, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def __init__(self, modelName: typing.Union[java.lang.String, str], serviceProvider: ghidra.framework.plugintool.ServiceProvider, monitor: ghidra.util.task.TaskMonitor, loadIncrementally: typing.Union[jpype.JBoolean, bool]):
        ...


class SortJob(TableUpdateJob[T], typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ThreadedTableModelListener(java.lang.Object):
    """
    A listener to be notified of :obj:`ThreadedTableModel` loading changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def loadPending(self):
        """
        Called when the model has new data to be loaded, but has not yet started the load process.
        """

    def loadingFinished(self, wasCancelled: typing.Union[jpype.JBoolean, bool]):
        """
        Called when the table is done loading data.
        
        :param jpype.JBoolean or bool wasCancelled: true if the load was cancelled.
        """

    def loadingStarted(self):
        """
        Called when the table begins to load new data.
        """


class IncrementalLoadJob(ghidra.util.worker.Job, ThreadedTableModelListener, typing.Generic[ROW_OBJECT]):

    @typing.type_check_only
    class IncrementalUpdatingAccumulator(ghidra.util.datastruct.SynchronizedListAccumulator[ROW_OBJECT]):
        """
        An accumulator that will essentially periodically update the table with the data that
        is being provided to the accumulator.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class GThreadedTablePanel(javax.swing.JPanel, typing.Generic[T]):
    """
    A convenience component designed specifically for rendering threaded table models.
    This panel will automatically create a threaded table and a task monitor component.
    """

    @typing.type_check_only
    class MessagePassingTaskMonitor(ghidra.util.task.TaskMonitorComponent):
        """
        A task monitor component that will pass message onto the task monitor that it has been 
        given.  This monitor will be used in one of two different ways: 1) if not loading 
        incrementally, then this model will appear in the GUI and will be used by the threaded 
        model while loading for incrementing progress; and 2)  when loading incrementally, this 
        monitor will not appear in the GUI, but is still used internally by the threaded model
        to allow cancelling and to report progress.    
         
        
        This class is useful when we are loading incrementally and are displaying the 
        :obj:`IncrementalLoadingTaskMonitor`, but would like messages to this monitor to appear
        in the GUI.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class IncrementalLoadingTaskMonitor(ghidra.util.task.TaskMonitorComponent):
        """
        This task monitor is shown in the GUI when the given threaded model of this class is
        loading incrementally (see :meth:`ThreadedTableModel.isLoadIncrementally() <ThreadedTableModel.isLoadIncrementally>`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, defaultMonitor: ghidra.util.task.TaskMonitorComponent):
            ...


    @typing.type_check_only
    class TableListener(ThreadedTableModelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, model: ThreadedTableModel[T, typing.Any]):
        """
        Constructs a new threaded table panel.
        
        :param ThreadedTableModel[T, typing.Any] model: the threaded table model
        """

    @typing.overload
    def __init__(self, model: ThreadedTableModel[T, typing.Any], minUpdateDelay: typing.Union[jpype.JInt, int]):
        """
        Constructs a new threaded table panel.
        
        :param ThreadedTableModel[T, typing.Any] model: the threaded table model
        :param jpype.JInt or int minUpdateDelay: the minimum amount of time to wait before the table model will
                update its data
        """

    @typing.overload
    def __init__(self, model: ThreadedTableModel[T, typing.Any], minUpdateDelay: typing.Union[jpype.JInt, int], maxUpdateDelay: typing.Union[jpype.JInt, int]):
        """
        Constructs a new threaded table panel.
        
        :param ThreadedTableModel[T, typing.Any] model: the threaded table model
        :param jpype.JInt or int minUpdateDelay: the minimum amount of time to wait before the table model will
                update its data
        :param jpype.JInt or int maxUpdateDelay: the maximum amount of time to wait before the table model will
                update its data
        """

    def dispose(self):
        ...

    def getTable(self) -> docking.widgets.table.GTable:
        """
        Returns the underlying table
        
        :return: the table
        :rtype: docking.widgets.table.GTable
        """

    def getTaskMonitor(self) -> ghidra.util.task.TaskMonitor:
        ...

    def isBusy(self) -> bool:
        ...

    def refresh(self):
        ...

    def setModel(self, model: ThreadedTableModel[T, typing.Any]):
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def taskMonitor(self) -> ghidra.util.task.TaskMonitor:
        ...

    @property
    def table(self) -> docking.widgets.table.GTable:
        ...


class AddRemoveJob(TableUpdateJob[T], typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["LoadJob", "ThreadedTableModel", "ThreadedTableModelListenerAdapter", "CoalescingAddRemoveStrategy", "NullTableFilter", "TableAddRemoveStrategy", "FilterJob", "TableUpdateJob", "IncrementalJobListener", "LoadSpecificDataJob", "ThreadedBackupRowComparator", "ThreadedTableColumnComparator", "TableData", "ThreadedTableModelUpdateMgr", "ThreadedTableModelStub", "SortJob", "ThreadedTableModelListener", "IncrementalLoadJob", "GThreadedTablePanel", "AddRemoveJob"]
