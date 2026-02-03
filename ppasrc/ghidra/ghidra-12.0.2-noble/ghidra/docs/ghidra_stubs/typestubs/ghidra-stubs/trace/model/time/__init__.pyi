from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.trace.model
import ghidra.trace.model.thread
import ghidra.trace.model.time.schedule
import java.lang # type: ignore
import java.util # type: ignore


class TraceSnapshot(java.lang.Object):
    """
    A "snapshot in time" in a trace
    
    This is not so much a snapshot as it is simply a marker in time. Each manager handles time on its
    own, using the keys from these snapshots. Snapshot keys are called "snaps" for short. While a
    snapshot need not exist for another manager to use its numeric key, it is proper convention to
    create a snapshot before populating any other manager with corresponding entries.
     
    NOTE: There is a transitional phase here where some managers may still use "tick" instead of
    "snap".
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        """
        Delete this snapshot
         
        This does not delete any entries in other managers associated with this snapshot. This simply
        deletes the marker and accompanying metadata. However, entries associated with deleted or
        otherwise non-existent snapshot keys may cause interesting behavior, especially for keys
        which exceed the latest snapshot key.
        """

    def getDescription(self) -> str:
        """
        Get the description of the snapshot
        
        :return: the description
        :rtype: str
        """

    def getEventThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        If this snapshot was created because of an event, get the thread that caused it
        
        :return: the event thread, if applicable
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getKey(self) -> int:
        """
        Get a key which orders the snapshot chronologically
        
        :return: the database key
        :rtype: int
        """

    def getRealTime(self) -> int:
        """
        Get the real creation time of this snapshot in milliseconds since the epoch
        
        :return: the real time
        :rtype: int
        """

    def getSchedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        """
        Get the schedule, if applicable and known, relating this snapshot to a previous one
         
         
        
        This information is not always known, or even applicable. If recording a single step,
        ideally, this is simply the previous snap plus one step of the event thread, e.g., for snap
        6, the schedule would be "5:1". For an emulated machine cached in scratch space, this should
        be the schedule that would recover the same machine state.
         
         
        
        The object managers in the trace pay no heed to this schedule. In particular, when retrieving
        the "most-recent" information from a snapshot with a known schedule, the "previous snap" part
        of that schedule is *not* taken into account. In other words, the managers still
        interpret time linearly, even though this schedule field might imply built-in forking.
        
        :return: the (possibly null) schedule
        :rtype: ghidra.trace.model.time.schedule.TraceSchedule
        """

    def getScheduleString(self) -> str:
        """
        Get the string representation of the schedule
        
        :return: the (possibly empty) string representation of the schedule
        :rtype: str
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    def getVersion(self) -> int:
        """
        Get the snapshot's version, esp., when it represents a cache entry
        
        :return: the version
        :rtype: int
        
        .. seealso::
        
            | :obj:`Trace.getEmulatorCacheVersion()`
        """

    def isSnapOnly(self, whenInconsistent: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if a snapshot involves any steps of emulation
         
        
        A scratch snapshot, i.e., whose key is negative, without a schedule set is considered
        inconsistent.
        
        :param jpype.JBoolean or bool whenInconsistent: the value to return for a scratch snapshot without a set schedule
        :return: true if no emulation is involved
        :rtype: bool
        """

    def isStale(self, whenInconsistent: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        For an emulated snapshot, check if re-emulation is necessary to produce an up-to-date
        snapshot.
         
        
        For non-emulated snapshots, this always returns false. A non-emulated snapshot is a snapshot
        whose schedule includes no emulation steps. An emulation snapshot is stale when its version
        is less than the trace's emulator cache version. A scratch snapshot, i.e., whose key is
        negative, without a schedule set is considered inconsistent.
        
        :param jpype.JBoolean or bool whenInconsistent: the value to return for a scratch snapshot without a set schedule
        :return: true if re-emulation is needed
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.getVersion()`
        
            | :obj:`.setVersion(long)`
        
            | :obj:`Trace.getEmulatorCacheVersion()`
        """

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        """
        Set the human-consumable description of the snapshot
        
        :param java.lang.String or str description: the description
        """

    def setEventThread(self, thread: ghidra.trace.model.thread.TraceThread):
        """
        If this snapshot was create because of an event, set the thread that caused it
        
        :param ghidra.trace.model.thread.TraceThread thread: the event thread, if applicable
        """

    def setRealTime(self, millisSinceEpoch: typing.Union[jpype.JLong, int]):
        """
        Set the real creation time of this snapshot in milliseconds since Jan 1, 1970 12:00 AM (UTC)
        
        :param jpype.JLong or int millisSinceEpoch: the real time
        """

    def setSchedule(self, schedule: ghidra.trace.model.time.schedule.TraceSchedule):
        """
        Set the schedule from some previous snapshot to this one
        
        :param ghidra.trace.model.time.schedule.TraceSchedule schedule: the schedule
        """

    def setVersion(self, version: typing.Union[jpype.JLong, int]):
        """
        Set the snapshot's version, esp., when it represents a cache entry
        
        :param jpype.JLong or int version: the version
        
        .. seealso::
        
            | :obj:`Trace.getEmulatorCacheVersion()`
        """

    @property
    def scheduleString(self) -> java.lang.String:
        ...

    @property
    def realTime(self) -> jpype.JLong:
        ...

    @realTime.setter
    def realTime(self, value: jpype.JLong):
        ...

    @property
    def schedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        ...

    @schedule.setter
    def schedule(self, value: ghidra.trace.model.time.schedule.TraceSchedule):
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def stale(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @description.setter
    def description(self, value: java.lang.String):
        ...

    @property
    def eventThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @eventThread.setter
    def eventThread(self, value: ghidra.trace.model.thread.TraceThread):
        ...

    @property
    def snapOnly(self) -> jpype.JBoolean:
        ...

    @property
    def version(self) -> jpype.JLong:
        ...

    @version.setter
    def version(self, value: jpype.JLong):
        ...

    @property
    def key(self) -> jpype.JLong:
        ...


class TraceTimeManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    KEY_TIME_RADIX: typing.Final = "_time_radix"
    """
    The attribute key for controlling the time radix
    """


    def createSnapshot(self, description: typing.Union[java.lang.String, str]) -> TraceSnapshot:
        """
        Create a new snapshot after the latest
        
        :param java.lang.String or str description: a description of the new snapshot, i.e., the reason for advancing
        :return: the created snapshot
        :rtype: TraceSnapshot
        """

    def findScratchSnapshot(self, schedule: ghidra.trace.model.time.schedule.TraceSchedule) -> TraceSnapshot:
        """
        Find or create a the snapshot with the given schedule
         
         
        
        If a snapshot with the given schedule already exists, this returns the first such snapshot
        found. Ideally, there is exactly one. If this method is consistently used for creating
        scratch snapshots, then that should always be the case. If no such snapshot exists, this
        creates a snapshot with the minimum available negative snapshot key, that is starting at
        :obj:`Long.MIN_VALUE` and increasing from there.
        
        :param ghidra.trace.model.time.schedule.TraceSchedule schedule: the schedule to find
        :return: the snapshot
        :rtype: TraceSnapshot
        """

    def findSnapshotWithNearestPrefix(self, schedule: ghidra.trace.model.time.schedule.TraceSchedule) -> TraceSnapshot:
        """
        Find the nearest related snapshot whose schedule is a prefix of the given schedule
         
         
        
        This finds a snapshot that can be used as the initial state of an emulator to materialize the
        state at the given schedule. The one it returns is the one that would require the fewest
        instruction steps. Note that since an emulator cannot be initialized into the middle of an
        instruction, snapshots whose schedules contain p-code op steps are ignored. Additionally,
        this will ignore any snapshots whose version is less than the emulator cache version.
        
        :param ghidra.trace.model.time.schedule.TraceSchedule schedule: the desired schedule
        :return: the found snapshot, or null
        :rtype: TraceSnapshot
        
        .. seealso::
        
            | :obj:`Trace.getEmulatorCacheVersion()`
        """

    def getAllSnapshots(self) -> java.util.Collection[TraceSnapshot]:
        """
        List all snapshots in the trace
        
        :return: the set of snapshots
        :rtype: java.util.Collection[TraceSnapshot]
        """

    def getMaxSnap(self) -> int:
        """
        Get maximum snapshot key that has ever existed, usually that of the latest snapshot
         
        Note, the corresponding snapshot need not exist, as it may have been deleted.
        
        :return: the key, or ``null`` if no snapshots have existed
        :rtype: int
        """

    def getMostRecentSnapshot(self, snap: typing.Union[jpype.JLong, int]) -> TraceSnapshot:
        """
        Get the most recent snapshot since a given key
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the snapshot or ``null``
        :rtype: TraceSnapshot
        """

    def getSnapshot(self, snap: typing.Union[jpype.JLong, int], createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceSnapshot:
        """
        Get the snapshot with the given key, optionally creating it
        
        :param jpype.JLong or int snap: the snapshot key
        :param jpype.JBoolean or bool createIfAbsent: create the snapshot if it's missing
        :return: the snapshot or ``null``
        :rtype: TraceSnapshot
        """

    def getSnapshotCount(self) -> int:
        """
        Get the number of snapshots
        
        :return: the count
        :rtype: int
        """

    def getSnapshots(self, fromSnap: typing.Union[jpype.JLong, int], fromInclusive: typing.Union[jpype.JBoolean, bool], toSnap: typing.Union[jpype.JLong, int], toInclusive: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[TraceSnapshot]:
        """
        List all snapshots between two given snaps in the trace
        
        :param jpype.JLong or int fromSnap: the starting snap
        :param jpype.JBoolean or bool fromInclusive: whether to include the from snap
        :param jpype.JLong or int toSnap: the ending snap
        :param jpype.JBoolean or bool toInclusive: when to include the to snap
        :return: the set of snapshots
        :rtype: java.util.Collection[TraceSnapshot]
        """

    def getSnapshotsWithSchedule(self, schedule: ghidra.trace.model.time.schedule.TraceSchedule) -> java.util.Collection[TraceSnapshot]:
        """
        Get all snapshots with the given schedule
         
         
        
        Ideally, the snapshot schedules should be managed such that the returned collection contains
        at most one snapshot.
        
        :param ghidra.trace.model.time.schedule.TraceSchedule schedule: the schedule to find
        :return: the snapshots
        :rtype: java.util.Collection[TraceSnapshot]
        """

    def getTimeRadix(self) -> ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix:
        """
        Get the radix for displaying and parsing time (snapshots and step counts)
        
        :return: radix the radix
        :rtype: ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix
        
        .. seealso::
        
            | :obj:`.setTimeRadix(TimeRadix)`
        """

    def setTimeRadix(self, radix: ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix):
        """
        Set the radix for displaying and parsing time (snapshots and step counts)
         
         
        
        This only affects the GUI, but storing it in the trace gives the back end a means of
        controlling it.
        
        :param ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix radix: the radix
        """

    @property
    def maxSnap(self) -> jpype.JLong:
        ...

    @property
    def mostRecentSnapshot(self) -> TraceSnapshot:
        ...

    @property
    def allSnapshots(self) -> java.util.Collection[TraceSnapshot]:
        ...

    @property
    def snapshotCount(self) -> jpype.JLong:
        ...

    @property
    def timeRadix(self) -> ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix:
        ...

    @timeRadix.setter
    def timeRadix(self, value: ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix):
        ...

    @property
    def snapshotsWithSchedule(self) -> java.util.Collection[TraceSnapshot]:
        ...



__all__ = ["TraceSnapshot", "TraceTimeManager"]
