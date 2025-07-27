from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.rmi # type: ignore


T = typing.TypeVar("T")


class BufferFileBlock(java.lang.Object):
    """
    ``BufferFileBlock`` is used to hold BufferFile blocks 
    for use during block streaming operations.
     
      
    Block indexes are absolute where 0 corresponds
    to the head block in the BufferFile.  It is important to note that 
    this number is off by 1 from DataBuffer numbering and the index values
    utilized by :meth:`BufferFile.getIndexCount() <BufferFile.getIndexCount>`, :meth:`BufferFile.get(DataBuffer, int) <BufferFile.get>`,
    :meth:`BufferFile.put(DataBuffer, int) <BufferFile.put>`, etc..  It is important for
    each implementation to normalize to absolute block indexes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, blockIndex: typing.Union[jpype.JInt, int], buffer: jpype.JArray[jpype.JByte]):
        """
        BufferFileBlock constructor
        
        :param jpype.JInt or int blockIndex: block index
        :param jpype.JArray[jpype.JByte] buffer: block buffer (size must match block-size for associated buffer file)
        """

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte]):
        """
        BufferFileBlock constructor for use when reconstructing instance
        from block stream
        
        :param jpype.JArray[jpype.JByte] bytes: buffer data received from block stream.  Buffer index will be
        determined by first 4-bytes contained within the bytes array (big-endian).
        """

    def getData(self) -> jpype.JArray[jpype.JByte]:
        """
        Get block data buffer
        
        :return: block data buffer
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getIndex(self) -> int:
        """
        Get absolute block index, where 0 corresponds to the first 
        physical block within the buffer file.
        
        :return: block index
        :rtype: int
        """

    def size(self) -> int:
        """
        Get block size
        
        :return: block size
        :rtype: int
        """

    def toBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Get block as byte array suitable for use in block stream and
        reconstruction.
        
        :return: block as byte array
        :rtype: jpype.JArray[jpype.JByte]
        """

    @property
    def data(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


@typing.type_check_only
class RecoveryMgr(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class InputBlockStream(BlockStream):
    """
    ``InputBlockStream`` provides a BufferFile input block stream.
    The nature of the stream and the block sequence is determined by the
    particular instance.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBlockCount(self) -> int:
        """
        Get the total number of blocks to be transfered.
        
        :return: total block count
        :rtype: int
        """

    def includesHeaderBlock(self) -> bool:
        """
        Determine if header block included in stream.  Some stream implementations
        do not include or don't have access to the buffer file header block and may 
        be excluded.  If header is required, it will need to be reconstructed by
        setting the free index list and all buffer file parameters.
        
        :return: true if header block #0 included in stream, else false
        :rtype: bool
        """

    def readBlock(self) -> BufferFileBlock:
        """
        Read next block from stream
        
        :return: a BufferFile block which corresponds to a specific block index
        or null if no more blocks available
        :rtype: BufferFileBlock
        :raises IOException: if an unexpected error occurs while 
        reading the file
        """

    @property
    def blockCount(self) -> jpype.JInt:
        ...


@typing.type_check_only
class BufferNode(java.lang.Object):
    """
    ``BufferNode`` is a DataBuffer wrapper which facilitates
    linking node into various lists and status tracking.  
    Linked lists supported, include:
     
    * Buffer cache
    * Buffer versions
    * Checkpoint list
    """

    class_: typing.ClassVar[java.lang.Class]


class BlockStreamHandle(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def openBlockStream(self) -> T:
        """
        Invoked by client to establish the remote connection and return 
        the opened block stream.
        
        :return: connected/open block stream
        :rtype: T
        :raises IOException:
        """


class LocalManagedBufferFile(LocalBufferFile, ManagedBufferFile):
    """
    ``LocalManagedBufferFile`` implements a BufferFile as block-oriented
    random-access file which utilizes a ``BufferFileManager`` to 
    identify and facilitate versioning of buffer files.  This type of
    buffer file supports both save-as and save operations.  The file
    format used is identical to a LocalBufferFile, although additional
    support is provided for associated files which facilitate versioning
    (e.g., ChangeMapFile, VersionFile, and changed data files).
    """

    @typing.type_check_only
    class PreSaveTask(java.lang.Runnable):
        """
        ``PreSaveTask`` facilitates the pre-saving a copy of this buffer 
        file for update use by a BufferMgr.
        """

        class_: typing.ClassVar[java.lang.Class]

        def cancelTask(self):
            ...

        def run(self):
            """
            Perform pre-save of sourceFile to preSaveFile.
            The preSaveFile is changed to null if an error occurs.
            """


    @typing.type_check_only
    class LocalManagedOutputBlockStream(LocalBufferFile.LocalOutputBlockStream):
        """
        ``LocalManagedOutputBlockStream`` extends ``LocalOutputBlockStream``
        for use when updating versioned buffer file.  This implementation causes change
        map data to be updated.  It is important that the free list is updated after 
        streaming is complete.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, blockCount: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bufferSize: typing.Union[jpype.JInt, int], bfManager: BufferFileManager, checkinId: typing.Union[jpype.JLong, int]):
        """
        Open the initial version of a block file for writing.
        
        :param jpype.JInt or int bufferSize: user buffer size
        :param BufferFileManager bfManager: buffer file version manager
        :param jpype.JLong or int checkinId: the checkinId for creating a versioned buffer file.
        :raises IOException: if an IO error occurs or the incorrect magicNumber
        was read from the file.
        """

    @typing.overload
    def __init__(self, bfManager: BufferFileManager, versionUpdateEnabled: typing.Union[jpype.JBoolean, bool], minChangeDataVer: typing.Union[jpype.JInt, int], checkinId: typing.Union[jpype.JLong, int]):
        """
        Open the current version of an existing block file as read-only.
        
        :param BufferFileManager bfManager: buffer file version manager
        :param jpype.JBoolean or bool versionUpdateEnabled: if true Save support is enabled (pre-save starts automatically).
        :param jpype.JInt or int minChangeDataVer: indicates the oldest change data buffer file to be
        included.  A -1 indicates only the last change data buffer file is applicable.
        :param jpype.JLong or int checkinId: the checkinId for versioned buffer files which are opened for update.
        :raises IOException: if an IO error occurs or the incorrect magicNumber
        was read from the file.
        """

    @typing.overload
    def __init__(self, bfManager: BufferFileManager, version: typing.Union[jpype.JInt, int], minChangeDataVer: typing.Union[jpype.JInt, int]):
        """
        Open an older version of an existing buffer file as read-only and NOT UPDATEABLE (bfMgr remains null).
        Version files must exist for all versions starting with the requested version.
        These version files will be used in conjunction with the current buffer file
        to emulate an older version buffer file.
        
        :param BufferFileManager bfManager: buffer file version manager
        :param jpype.JInt or int version: version of file to be opened
        :param jpype.JInt or int minChangeDataVer: indicates the oldest change data buffer file to be
        included.  A -1 indicates only the last change data buffer file is applicable.
        :raises IOException: if an IO error occurs or a problem with the version
        reconstruction.
        """

    def createNewVersion(self, destFile: ManagedBufferFile, fileComment: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Create a new buffer file version (used for check-in)
        
        :param ManagedBufferFile destFile: must be an versioned file representing an earlier version
        of srcFile.
        :param java.lang.String or str fileComment: a comment for the new version.
        :param ghidra.util.task.TaskMonitor monitor: the current monitor.
        :raises CancelledException: if the operation is canceled.
        :raises IOException: if the file is in an unexpected state.
        """

    @typing.overload
    def getInputBlockStream(self) -> InputBlockStream:
        """
        Obtain a direct stream to read all blocks of this buffer file
        
        :return: input block stream
        :rtype: InputBlockStream
        :raises IOException:
        """

    @typing.overload
    def getInputBlockStream(self, changeMapData: jpype.JArray[jpype.JByte]) -> InputBlockStream:
        """
        Obtain a direct stream to read modified blocks of this buffer file 
        based upon the specified changeMap
        
        :return: input block stream
        :rtype: InputBlockStream
        :raises IOException:
        """

    def getOutputBlockStream(self, blockCount: typing.Union[jpype.JInt, int]) -> OutputBlockStream:
        """
        Obtain a direct stream to write blocks to this buffer file
        
        :param jpype.JInt or int blockCount: number of blocks to be transferred
        :return: output block stream
        :rtype: OutputBlockStream
        :raises IOException:
        """

    def getSaveFile(self, monitor: ghidra.util.task.TaskMonitor) -> LocalManagedBufferFile:
        """
        Returns a Save file if available.  Returns null if
        a save can not be performed.  This method may block for an extended
        period of time if the pre-save process has not already completed.
        This method does not accept a monitor since a remote TaskMonitor does
        not yet exist.
        
        :param ghidra.util.task.TaskMonitor monitor: optional monitor for canceling pre-save (may be null)
        :raises IOException: if an I/O error occurs
        :raises CancelledException: if monitor specified and pre-save cancelled
        """

    def updateFrom(self, versionedBufferFile: ManagedBufferFile, oldVersion: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Create a new version of this file by updating it from a versionedBufferFile.  
        This file must be open as read-only with versionUpdateEnabled and have been derived 
        from an oldVersion of the versionedBufferFile (i.e., was based on a check-out of oldVersion).
        The save-file corresponding to this file is updated using those buffers
        which have been modified or added in the specified versionedBufferFile 
        since olderVersion.  When complete, this file should be closed
        as soon as possible.
        
        :param ManagedBufferFile versionedBufferFile: versioned buffer file
        :param jpype.JInt or int oldVersion: older version of versionedBufferFile from which this buffer file originated.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises IOException: if an I/O error occurs
        :raises CancelledException: if monitor cancels operation
        """

    @property
    def outputBlockStream(self) -> OutputBlockStream:
        ...

    @property
    def saveFile(self) -> LocalManagedBufferFile:
        ...

    @property
    def inputBlockStream(self) -> InputBlockStream:
        ...


class BufferMgr(java.lang.Object):
    """
    ``BufferMgr`` provides low-level buffer management and caching.
    Checkpointing and buffer versioning is supported along with an undo/redo
    capability.
    """

    @typing.type_check_only
    class PreCacheStatus(java.lang.Enum[BufferMgr.PreCacheStatus]):
        """
        An optional pre-cache of all buffers can be performed within a separate
        thread if enabled.
        """

        class_: typing.ClassVar[java.lang.Class]
        INIT: typing.Final[BufferMgr.PreCacheStatus]
        RUNNING: typing.Final[BufferMgr.PreCacheStatus]
        INTERUPTED: typing.Final[BufferMgr.PreCacheStatus]
        STOPPED: typing.Final[BufferMgr.PreCacheStatus]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> BufferMgr.PreCacheStatus:
            ...

        @staticmethod
        def values() -> jpype.JArray[BufferMgr.PreCacheStatus]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    ALWAYS_PRECACHE_PROPERTY: typing.Final = "db.always.precache"
    DEFAULT_BUFFER_SIZE: typing.Final = 16384
    DEFAULT_CHECKPOINT_COUNT: typing.Final = 10
    DEFAULT_CACHE_SIZE: typing.Final = 4194304

    @typing.overload
    def __init__(self):
        """
        Construct a new buffer manager with no underlying source file using the
        default buffer size, cache size and maximum undo count.
        
        :raises IOException: if a cache file access error occurs
        """

    @typing.overload
    def __init__(self, requestedBufferSize: typing.Union[jpype.JInt, int], approxCacheSize: typing.Union[jpype.JLong, int], maxUndos: typing.Union[jpype.JInt, int]):
        """
        Construct a new buffer manager with no underlying source file.
        
        :param jpype.JInt or int requestedBufferSize: requested buffer size.  Actual buffer size may
        vary.
        :param jpype.JLong or int approxCacheSize: approximate size of cache in Bytes.
        :param jpype.JInt or int maxUndos: maximum number of checkpoints retained for undo (Minimum=1).
        :raises IOException: if a cache file access error occurs
        """

    @typing.overload
    def __init__(self, sourceFile: BufferFile):
        """
        Construct a buffer manager for a given source file using default
        cache size and maximum undo count.
        
        :param BufferFile sourceFile: buffer file
        :raises IOException: if source or cache file access error occurs
        """

    @typing.overload
    def __init__(self, sourceFile: BufferFile, approxCacheSize: typing.Union[jpype.JLong, int], maxUndos: typing.Union[jpype.JInt, int]):
        """
        Construct a buffer manager for a given source file using default
        cache size and maximum undo count.
        
        :param BufferFile sourceFile: buffer file
        :param jpype.JLong or int approxCacheSize: approximate size of cache in Bytes.
        :param jpype.JInt or int maxUndos: maximum number of checkpoints retained for undo (Minimum=1).
        :raises IOException: if source or cache file access error occurs
        """

    def atCheckpoint(self) -> bool:
        """
        
        
        :return: true if no buffers have been updated since last checkpoint.
        :rtype: bool
        """

    @staticmethod
    def canRecover(bfMgr: BufferFileManager) -> bool:
        """
        Determine if unsaved changes can be recovered for the current BufferFile
        associated with the specified bfMgr.
        
        :param BufferFileManager bfMgr: buffer file manager
        :return: true if a recover is possible
        :rtype: bool
        """

    def canSave(self) -> bool:
        """
        
        
        :return: true if save operation can be performed.
        :rtype: bool
        :raises IOException: if IO error occurs
        """

    def checkpoint(self) -> bool:
        """
        Completes a transaction by closing the current checkpoint.  All
        modified buffers since the previous invocation of this method
        will be contained within "transaction".
        The redo stack will be cleared.
        
        :return: true if checkpoint successful, or false if buffers are read-only
        :rtype: bool
        """

    @staticmethod
    def cleanupOldCacheFiles():
        ...

    def clearCheckpoints(self):
        """
        Clear all checkpoints and re-baseline buffers
        """

    def clearRecoveryFiles(self):
        """
        Immediately following instantiation of this BufferMgr, discard any pre-existing
        recovery snapshots.
        """

    def createBuffer(self) -> DataBuffer:
        """
        Get a new or recycled buffer.
        New buffer is always returned with update enabled.
        When done working with the buffer, the method releaseBuffer
        must be used to return it to the buffer manager.  Buffers
        should not be held for long periods.
        
        :return: buffer object, or null if buffer not found
        :rtype: DataBuffer
        :raises IOException: if a cache file access error occurs
        """

    def deleteBuffer(self, id: typing.Union[jpype.JInt, int]):
        """
        Delete buffer.
        DataBuffer is added to the free list for reuse.
        
        :param jpype.JInt or int id: buffer id
        :raises IOException: if source or cache file access error occurs
        """

    @typing.overload
    def dispose(self):
        """
        Dispose of all buffer manager resources including any source
        buffer file.  Any existing recovery data will be discarded.
        This method should be called when this buffer manager instance
        is no longer needed.
        """

    @typing.overload
    def dispose(self, keepRecoveryData: typing.Union[jpype.JBoolean, bool]):
        """
        Dispose of all buffer manager resources including any source
        buffer file.
        This method should be called when this buffer manager instance
        is no longer needed.
        
        :param jpype.JBoolean or bool keepRecoveryData: true if existing snapshot recovery files
        should not be deleted.
        """

    def enablePreCache(self):
        """
        Enable and start source buffer file pre-cache if appropriate.
        This may be forced for all use cases by setting the System property
        db.always.precache=true
        WARNING! EXPERIMENTAL !!!
        """

    def getAllocatedBufferCount(self) -> int:
        ...

    def getAvailableRedoCount(self) -> int:
        """
        
        
        :return: the number of redo-able transactions
        :rtype: int
        """

    def getAvailableUndoCount(self) -> int:
        """
        
        
        :return: number of undo-able transactions
        :rtype: int
        """

    def getBuffer(self, id: typing.Union[jpype.JInt, int]) -> DataBuffer:
        """
        Get the specified buffer.
        When done working with the buffer, the method releaseBuffer
        must be used to return it to the buffer manager.  Buffers
        should not be held for long periods.
        
        :param jpype.JInt or int id: buffer id
        :return: buffer object, or null if buffer not found
        :rtype: DataBuffer
        :raises IOException: if source or cache file access error occurs
        """

    def getBufferSize(self) -> int:
        """
        
        
        :return: the size of each buffer in bytes.
        :rtype: int
        """

    def getCacheHits(self) -> int:
        ...

    def getCacheMisses(self) -> int:
        ...

    def getFreeBufferCount(self) -> int:
        ...

    def getLockCount(self) -> int:
        """
        Get the current number of locked buffers.
        
        :return: int
        :rtype: int
        """

    def getLowBufferCount(self) -> int:
        ...

    def getMaxUndos(self) -> int:
        """
        Get the maximum number of checkpoints retained.
        
        :return: int
        :rtype: int
        """

    def getModCount(self) -> int:
        """
        Provides a means of detecting changes to the underlying database during a transaction.
        
        :return: current modification count
        :rtype: int
        """

    def getRecoveryChangeSetFile(self) -> LocalBufferFile:
        """
        Returns the recovery changeSet data file for reading or null if one is not available.
        The caller must dispose of the returned file before peforming generating any new
        recovery snapshots.
        
        :return: recovery change set buffer file
        :rtype: LocalBufferFile
        :raises IOException: if IO error occurs
        """

    def getSourceFile(self) -> BufferFile:
        """
        
        
        :return: returns the source file
        :rtype: BufferFile
        """

    def getStatusInfo(self) -> str:
        ...

    def hasRedoCheckpoints(self) -> bool:
        """
        Indicates whether checkpoint versions are available for redo.
        
        :return: true if redo is available
        :rtype: bool
        """

    def hasUndoCheckpoints(self) -> bool:
        """
        Indicates whether checkpoint versions are available for undo.
        
        :return: true if undo is available
        :rtype: bool
        """

    def isChanged(self) -> bool:
        """
        
        
        :return: true if unsaved "buffer" changes exist.
        If no changes have been made, or all changes have been
        "undone", false will be returned.  Parameter changes
        are no considered.
        :rtype: bool
        """

    def isCorrupted(self) -> bool:
        """
        Determine if BufferMgr has become corrupted (IOException has occurred).
        
        :return: true if this BufferMgr is corrupt.
        :rtype: bool
        """

    def modifiedSinceSnapshot(self) -> bool:
        """
        
        
        :return: true if buffers have been modified since opening or since
        last snapshot.
        :rtype: bool
        """

    def recover(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Immediately following instatiation of this BufferMgr, attempt a unsaved data recovery.
        If successful, the method getRecoveryChangeSetFile should be invoked to obtain/open the
        changeSet data file which must be used by the application to recover the changeSet.
        If recovery is cancelled, this buffer manager must be disposed.
        since the underlying state will be corrupt.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if recovery successful else false
        :rtype: bool
        :raises IOException: if IO error occurs
        :raises CancelledException: if task monitor is cancelled
        """

    def redo(self) -> bool:
        """
        Redo next checkpoint. Method should not be invoked
        when one or more buffers are locked.
        
        :return: true if successful else false
        :rtype: bool
        """

    def releaseBuffer(self, buf: DataBuffer):
        """
        Release buffer back to buffer manager.
        After invoking this method, the buffer object should not
        be used and all references should be dropped.
        
        :param DataBuffer buf: data buffer
        :raises IOException: if IO error occurs
        """

    def resetCacheStatistics(self):
        ...

    def save(self, comment: typing.Union[java.lang.String, str], changeSet: db.DBChangeSet, monitor: ghidra.util.task.TaskMonitor):
        """
        Save the current set of buffers to a new version of the source buffer file.
        If the buffer manager was not instantiated with a source file an
        IllegalStateException will be thrown.
        
        :param java.lang.String or str comment: if version history is maintained, this comment will be
        associated with the new version.
        :param db.DBChangeSet changeSet: an optional database-backed change set which reflects changes
        made since the last version.
        :param ghidra.util.task.TaskMonitor monitor: a cancellable task monitor.  This method will establish the
        maximum progress count.
        :raises CancelledException: if the task monitor cancelled the operation.
        :raises IOException: if source, cache or destination file access error occurs
        """

    def saveAs(self, outFile: BufferFile, associateWithNewFile: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Save the current set of buffers to a new buffer file.
        
        :param BufferFile outFile: an empty buffer file open for writing
        :param jpype.JBoolean or bool associateWithNewFile: if true the outFile will be associated with this BufferMgr as the
        current source file, if false no change will be made to this BufferMgr's state and the outFile
        will be written and set as read-only.  The caller is responsible for disposing the outFile if
        this parameter is false.
        :param ghidra.util.task.TaskMonitor monitor: a cancelable task monitor.  This method will establish the
        maximum progress count.
        :raises CancelledException: if the task monitor canceled the operation.
        :raises IOException: if source, cache or destination file access error occurs
        """

    def setCorruptedState(self):
        """
        Set the corrupt state flag for this buffer manager.  This will cause any snapshot
        attempt to fail and cause most public access methods to throw an IOException.
        The caller should log this action and the reason for it.
        """

    def setDBVersionedSourceFile(self, versionedSourceBufferFile: LocalManagedBufferFile):
        """
        Set the source buffer file with a newer local buffer file version.
        Intended for use following a merge or commit operation only where a local checkout has been
        retained.
        
        :param LocalManagedBufferFile versionedSourceBufferFile: updated local source buffer file opened for versioning 
        update (NOTE: file itself is read-only).
        :raises IOException: if an IO error occurs
        """

    def setMaxUndos(self, maxUndos: typing.Union[jpype.JInt, int]):
        """
        Set the maximum number of undoable checkpoints maintained by buffer manager.
        Existing redo checkpoints are cleared and the stack of undo checkpoints
        will be reduced if maxUndos is less than the current setting.
        
        :param jpype.JInt or int maxUndos: maximum number of undo checkpoints.  A negative
        value restores the default value.
        """

    def takeRecoverySnapshot(self, changeSet: db.DBChangeSet, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Generate recovery snapshot of unsaved data.
        
        :param db.DBChangeSet changeSet: an optional database-backed change set which reflects changes
        made since the last version.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if snapshot successful, false if
        :rtype: bool
        :raises IOException: if IO error occurs
        :raises CancelledException: if task monitor is cancelled
        """

    def undo(self, redoable: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Backup to previous checkpoint.  Method should not be invoked
        when one or more buffers are locked.
        
        :param jpype.JBoolean or bool redoable: true if currrent checkpoint should be moved to redo stack
        :return: true if successful else false
        :rtype: bool
        :raises IOException: if IO error occurs
        """

    @property
    def corrupted(self) -> jpype.JBoolean:
        ...

    @property
    def lockCount(self) -> jpype.JInt:
        ...

    @property
    def lowBufferCount(self) -> jpype.JInt:
        ...

    @property
    def cacheMisses(self) -> jpype.JLong:
        ...

    @property
    def statusInfo(self) -> java.lang.String:
        ...

    @property
    def allocatedBufferCount(self) -> jpype.JInt:
        ...

    @property
    def maxUndos(self) -> jpype.JInt:
        ...

    @maxUndos.setter
    def maxUndos(self, value: jpype.JInt):
        ...

    @property
    def availableRedoCount(self) -> jpype.JInt:
        ...

    @property
    def sourceFile(self) -> BufferFile:
        ...

    @property
    def modCount(self) -> jpype.JLong:
        ...

    @property
    def recoveryChangeSetFile(self) -> LocalBufferFile:
        ...

    @property
    def cacheHits(self) -> jpype.JLong:
        ...

    @property
    def availableUndoCount(self) -> jpype.JInt:
        ...

    @property
    def buffer(self) -> DataBuffer:
        ...

    @property
    def freeBufferCount(self) -> jpype.JInt:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...

    @property
    def bufferSize(self) -> jpype.JInt:
        ...


class OutputBlockStream(BlockStream):
    """
    ``OutputBlockStream`` provides a BufferFile output block stream.
    The nature of the stream and the block sequence is determined by the
    particular instance.
    """

    class_: typing.ClassVar[java.lang.Class]

    def writeBlock(self, block: BufferFileBlock):
        """
        Write the specified block to the corresponding BufferFile.
        
        :param BufferFileBlock block: a BufferFile block which corresponds to a specific block index
        :raises IOException: if an unexpected error occurs while 
        writing the block
        """


class BufferFile(java.lang.Object):
    """
    ``BufferFile`` facilitates read/write access to buffer oriented file.
    Access to related resources, such as parameters and change data, is also facilitated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearParameters(self):
        """
        Deletes all parameters
        
        :raises IOException:
        """

    def close(self):
        """
        Close the buffer file.  If the file was open for write access,
        all buffers are flushed and the file header updated.  Once closed,
        this object is immediately disposed and may no longer be used.
        
        :raises IOException: if an I/O error occurs
        """

    def delete(self) -> bool:
        """
        Delete this buffer file if writable.  Once deleted,
        this object is immediately disposed and may no longer be used.
        
        :return: true if deleted, false if the file is read-only
        :rtype: bool
        :raises IOException: if an I/O error occurs.
        """

    def dispose(self):
        """
        Dispose of this buffer file object.  If file is not readOnly
        and has not been closed, an attempt will be made to delete the
        associated file(s).  Once disposed, it may no longer be used.
        """

    def get(self, buf: DataBuffer, index: typing.Union[jpype.JInt, int]) -> DataBuffer:
        """
        Get the specified buffer.
        DataBuffer data and flags are read from the file at index and 
        stored within the supplied DataBuffer object.  If the read buffer
        is empty, the DataBuffer's data field will remain unchanged (which could be null).
        
        :param DataBuffer buf: a buffer whose data array will be filled-in or replaced.
        :param jpype.JInt or int index: index of buffer to be read.  First user buffer
        is at index 0.
        :raises EOFException: if the requested buffer index is greater 
        than the number of available buffers of the end-of-file was
        encountered while reading the buffer.
        :raises IOException: if an I/O error occurs
        """

    def getBufferSize(self) -> int:
        """
        Return the actual size of a user data buffer.  This value should be 
        used when constructing DataBuffer objects.
        
        :return: DataBuffer data size as a number of bytes
        :rtype: int
        :raises IOException: if an I/O error occurs
        """

    def getFreeIndexes(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the list of free indexes sorted by value.
        The management of the free-index-list is implementation
        specific.
        
        :raises IOException:
        """

    def getIndexCount(self) -> int:
        """
        Returns the number of allocated buffer indexes.
        When a new buffer is allocated, and the file size
        grows, the buffer will remain allocated although it
        may be added to the list of free-indexes.  A file will
        never shrink in size due to this permanent allocation.
        
        :raises IOException:
        """

    def getParameter(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Get a the stored value for a named parameter.
        
        :param java.lang.String or str name: parameter name
        :return: integer value
        :rtype: int
        :raises NoSuchElementException: thrown if parameter not found
        :raises IOException:
        """

    def getParameterNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns a list of all parameter names.
        
        :raises IOException:
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if this file may not be modified 
        via the buffer put method.  
        A read-only file may be considered "updateable" if the canSave
        method returns true.  The term "updateable" means that a Save file
        can be obtained via the getSaveFile method.
        
        :raises IOException: if an I/O error occurs
        """

    def put(self, buf: DataBuffer, index: typing.Union[jpype.JInt, int]):
        """
        Store a data buffer at the specified block index.
        
        :param DataBuffer buf: data buffer
        :param jpype.JInt or int index: block index
        :raises IOException: thrown if an IO error occurs
        """

    def setFreeIndexes(self, indexes: jpype.JArray[jpype.JInt]):
        """
        Sets the list of free buffer indexes.
        The management of the free-index-list is implementation
        specific.
        
        :param jpype.JArray[jpype.JInt] indexes: 
        :raises IOException:
        """

    def setParameter(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Set the integer value for a named parameter.
        
        :param java.lang.String or str name: parameter name
        :param jpype.JInt or int value: parameter value
        :raises IOException:
        """

    def setReadOnly(self) -> bool:
        """
        If file is open read-write, the modified contents are flushed
        and the file re-opened as read-only.  This is also used to commit
        a new version if the file had been modified for update.
        
        :return: true if successfully transitioned from read-write to read-only
        :rtype: bool
        :raises IOException: if an I/O error occurs
        """

    @property
    def freeIndexes(self) -> jpype.JArray[jpype.JInt]:
        ...

    @freeIndexes.setter
    def freeIndexes(self, value: jpype.JArray[jpype.JInt]):
        ...

    @property
    def indexCount(self) -> jpype.JInt:
        ...

    @property
    def parameter(self) -> jpype.JInt:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def parameterNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def bufferSize(self) -> jpype.JInt:
        ...


class LocalBufferFile(BufferFile):
    """
    ``LocalBufferFile`` implements a BufferFile as block-oriented
    random-access file.  This type of buffer file supports save-as but does
    not support the save operation.
    """

    @typing.type_check_only
    class LocalBufferInputBlockStream(InputBlockStream):
        """
        ``LocalBufferInputBlockStream`` provides an input BlockStream for
        transferring the entire file content associated with a read-only buffer
        file use a buffer-based transfer.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocalFileInputBlockStream(InputBlockStream):
        """
        ``LocalFileInputBlockStream`` provides an input BlockStream for
        transferring the entire file content associated with a read-only file.
        This implementation reads the data directly from a single local file
        and must not be used when performing version reconstruction or
        change-map driven streams.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocalRandomInputBlockStream(InputBlockStream):
        """
        ``LocalRandomInputBlockStream`` provides ability to
        selectively read a select set of buffers from the LocalBufferFile
        based upon a specified ChangeMap.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocalOutputBlockStream(OutputBlockStream):
        """
        ``LocalOutputBlockStream`` provides an OutputBlockStream for
        updating specific buffers of a non-read-only file.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, blockCount: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class BlockStreamCancelMonitor(java.io.Closeable, ghidra.util.task.CancelledListener):
        """
        ``BlockStreamCancelMonitor`` is used to close associated BlockStreams
        when a TaskMonitor is cancelled
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BufferFileFilter(java.io.FileFilter):
        """
        File filter to identify various files
        """

        class_: typing.ClassVar[java.lang.Class]


    class InputBlockStreamFactory(java.lang.Object):
        """
        A simple interface that allows for dependency injection
        """

        class_: typing.ClassVar[java.lang.Class]

        def createInputBlockStream(self, bf: LocalBufferFile) -> InputBlockStream:
            ...


    @typing.type_check_only
    class DefaultInputBlockStreamFactory(LocalBufferFile.InputBlockStreamFactory):
        """
        A factory to supply the default implementation for create an :obj:`InputBlockStream`
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    BUFFER_FILE_EXTENSION: typing.Final = ".gbf"
    PRESAVE_FILE_EXT: typing.Final = ".ps"
    PRESAVE_FILE_PREFIX: typing.Final = "tmp"
    TEMP_FILE_EXT: typing.Final = ".tmp"

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath, bufferSize: typing.Union[jpype.JInt, int]):
        """
        Create a new buffer file for writing.
        If the file does not exist and create is true, a new buffer file will
        be created.
        The file will be saved when closed.
        
        :param jpype.protocol.SupportsPath file: buffer file
        :param jpype.JInt or int bufferSize: user buffer size
        :raises DuplicateFileException: if file already exists
        :raises IOException: if an I/O error occurs during file creation
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath, readOnly: typing.Union[jpype.JBoolean, bool]):
        """
        Open an existing block file.
        
        :param jpype.protocol.SupportsPath file: block file
        :param jpype.JBoolean or bool readOnly: if true the file will be opened read-only
        :raises IOException: if an error occurs or the incorrect magicNumber was read from the file.
        """

    @staticmethod
    def cleanupOldPreSaveFiles(dir: jpype.protocol.SupportsPath, beforeNow: typing.Union[jpype.JLong, int]):
        """
        Attempt to remove all pre-save files.
        Those still open by an existing process should
        not be removed by the operating system.
        
        :param jpype.protocol.SupportsPath dir: data directory containing pre-save files
        :param jpype.JLong or int beforeNow: if not 0, file mod time must be less than the specified time
        """

    def clone(self, destinationFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        """
        Clone this buffer file to the specified file.  The file must not already exist.  If the
        operation is cancelled or an error occurs the file is not created.
        
        :param jpype.protocol.SupportsPath destinationFile: destination file
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises IOException: if IO error occurs.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @staticmethod
    def copyFile(srcFile: BufferFile, destFile: BufferFile, changeMap: ChangeMap, monitor: ghidra.util.task.TaskMonitor):
        """
        Copy the complete content of a specified srcFile into a destFile excluding file ID.  Both
        files remain open.
        
        :param BufferFile srcFile: open buffer file
        :param BufferFile destFile: empty buffer file which is open for writing.
        :param ChangeMap changeMap: optional change map which indicates those buffers which must be copied.
        Any buffer index outside the range of the change map will also be copied.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises IOException: if IO error occurs.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @staticmethod
    def getBufferFileBlock(buf: DataBuffer, bufferSize: typing.Union[jpype.JInt, int]) -> BufferFileBlock:
        """
        Generate a BufferFileBlock instance which corresponds to the specified DataBuffer
        based upon LocalBufferFile block usage.  This should generally not be used for writing
        empty blocks since they will not be properly linked which is normally handled during
        header flush which is performed by BufferFile close on files being written.
        
        :param DataBuffer buf: the data buffer to be converted
        :param jpype.JInt or int bufferSize: data buffer size used for integrity check and generating empty buffer
        :return: BufferFileBlock instance.
        :rtype: BufferFileBlock
        """

    @staticmethod
    def getDataBuffer(block: BufferFileBlock) -> DataBuffer:
        """
        Generate a DataBuffer instance which corresponds to the specified block
        based upon LocalBufferFile block usage.
        
        :param BufferFileBlock block: the buffer file block to be converted
        :return: DataBuffer instance or null if head block.  If empty block
        DataBuffer will have null data
        :rtype: DataBuffer
        """

    def getFile(self) -> java.io.File:
        """
        Returns the physical file associated with this BufferFile.
        
        :return: the file
        :rtype: java.io.File
        """

    def getInputBlockStream(self) -> InputBlockStream:
        """
        Obtain a direct stream to read all blocks of this buffer file
        
        :return: input block stream
        :rtype: InputBlockStream
        :raises IOException: if there is an exception creating the stream
        """

    def getOutputBlockStream(self, blockCount: typing.Union[jpype.JInt, int]) -> OutputBlockStream:
        """
        Obtain a direct stream to write blocks to this buffer file
        
        :param jpype.JInt or int blockCount: number of blocks to be transferred
        :return: output block stream
        :rtype: OutputBlockStream
        :raises IOException: if an I/O error occurs
        """

    @staticmethod
    def peek(file: jpype.protocol.SupportsPath, bufferIndex: typing.Union[jpype.JInt, int]) -> DataBuffer:
        """
        Read a buffer from an existing buffer file.
        
        :param jpype.protocol.SupportsPath file: block file
        :param jpype.JInt or int bufferIndex: the index from which to read the buffer
        :return: the buffer
        :rtype: DataBuffer
        :raises IOException: if an I/O error occurs
        """

    @staticmethod
    def poke(file: jpype.protocol.SupportsPath, bufferIndex: typing.Union[jpype.JInt, int], buf: DataBuffer):
        """
        Modify an existing buffer file.
         
        
        WARNING! Use with extreme caution since this modifies the original file and could destroy
        data if used improperly.
        
        :param jpype.protocol.SupportsPath file: block file
        :param jpype.JInt or int bufferIndex: the index at which to place the buffer
        :param DataBuffer buf: the buffer add to the file
        :raises IOException: if an I/O error occurs
        """

    @property
    def outputBlockStream(self) -> OutputBlockStream:
        ...

    @property
    def file(self) -> java.io.File:
        ...

    @property
    def inputBlockStream(self) -> InputBlockStream:
        ...


class BufferFileAdapter(BufferFile):
    """
    ``BufferFileAdapter`` provides a BufferFile implementation which
    wraps a BufferFileHandle.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, remoteBufferFile: BufferFileHandle):
        """
        Constructor.
        
        :param BufferFileHandle remoteBufferFile: remote buffer file handle
        """

    def isRemote(self) -> bool:
        """
        Determine if this file is remotely accessed
        
        :return: true if file is remote
        :rtype: bool
        """

    @property
    def remote(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class VersionFile(java.lang.Object):
    """
    ``VersionFile`` records buffer changes and parameters necessary to reconstruct an
    older version of a LocalBufferFile.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOriginalBufferCount(self) -> int:
        """
        Returns buffer count for original buffer file.
        """

    def isPutOK(self, index: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if this version file will accept old buffer data for the specified buffer index.
        
        :param jpype.JInt or int index: buffer index
        """

    @property
    def originalBufferCount(self) -> jpype.JInt:
        ...

    @property
    def putOK(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class RecoveryFile(java.lang.Object):
    """
    ``VersionFile`` records buffer changes and parameters necessary to reconstruct an
    older version of a LocalBufferFile.
    """

    class_: typing.ClassVar[java.lang.Class]


class BufferFileHandle(java.lang.Object):
    """
    ``BufferFileHandle`` facilitates access to a BufferFile
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearParameters(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.clearParameters()`
        """

    def close(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.close()`
        """

    def delete(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.delete()`}
        """

    def dispose(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.dispose()`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> DataBuffer:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.get(DataBuffer, int)`
        """

    def getBufferSize(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.getBufferSize()`
        """

    def getFreeIndexes(self) -> jpype.JArray[jpype.JInt]:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.getFreeIndexes()`
        """

    def getIndexCount(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.getIndexCount()`
        """

    def getInputBlockStream(self) -> InputBlockStream:
        """
        Provides local access to an input block stream.  This method should only be used 
        if the associated :meth:`BufferFileAdapter.isRemote() <BufferFileAdapter.isRemote>` is *false*.
        
        
        .. seealso::
        
            | :obj:`BufferFileAdapter.getInputBlockStream()`
        """

    def getInputBlockStreamHandle(self) -> BlockStreamHandle[InputBlockStream]:
        """
        Get an input block stream handle which will facilitate access to a remote InputBlockStream.
        The handle will facilitate use of a remote streaming interface.  This method should only be used 
        if the associated :meth:`BufferFileAdapter.isRemote() <BufferFileAdapter.isRemote>` is *true*.
        
        
        .. seealso::
        
            | :obj:`BufferFileAdapter.getInputBlockStream()`
        """

    def getOutputBlockStream(self, blockCount: typing.Union[jpype.JInt, int]) -> OutputBlockStream:
        """
        Provides local access to an output block stream.  This method should only be used 
        if the associated :meth:`BufferFileAdapter.isRemote() <BufferFileAdapter.isRemote>` is *false*.
        
        
        .. seealso::
        
            | :obj:`BufferFileAdapter.getOutputBlockStream(int)`
        """

    def getOutputBlockStreamHandle(self, blockCount: typing.Union[jpype.JInt, int]) -> BlockStreamHandle[OutputBlockStream]:
        """
        Get an output block stream handle which will facilitate access to a remote InputBlockStream.
        The handle will facilitate use of a remote streaming interface.  This method should only be used 
        if the associated :meth:`BufferFileAdapter.isRemote() <BufferFileAdapter.isRemote>` is *true*.
        
        
        .. seealso::
        
            | :obj:`BufferFileAdapter.getOutputBlockStream(int)`
        """

    def getParameter(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.getParameter(java.lang.String)`
        """

    def getParameterNames(self) -> jpype.JArray[java.lang.String]:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.getParameterNames()`
        """

    def isReadOnly(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.isReadOnly()`
        """

    def put(self, buf: DataBuffer, index: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.put(DataBuffer, int)`
        """

    def setFreeIndexes(self, indexes: jpype.JArray[jpype.JInt]):
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.setFreeIndexes(int[])`
        """

    def setParameter(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.setParameter(java.lang.String, int)`
        """

    def setReadOnly(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`BufferFile.setReadOnly()`
        """

    @property
    def outputBlockStreamHandle(self) -> BlockStreamHandle[OutputBlockStream]:
        ...

    @property
    def outputBlockStream(self) -> OutputBlockStream:
        ...

    @property
    def freeIndexes(self) -> jpype.JArray[jpype.JInt]:
        ...

    @freeIndexes.setter
    def freeIndexes(self, value: jpype.JArray[jpype.JInt]):
        ...

    @property
    def inputBlockStreamHandle(self) -> BlockStreamHandle[InputBlockStream]:
        ...

    @property
    def indexCount(self) -> jpype.JInt:
        ...

    @property
    def parameter(self) -> jpype.JInt:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def parameterNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def inputBlockStream(self) -> InputBlockStream:
        ...

    @property
    def bufferSize(self) -> jpype.JInt:
        ...


class BufferFileManager(java.lang.Object):
    """
    ``BufferFileManager`` provides an interface for a 
    BufferFile manager who understands the storage for the various
    versions of BufferFiles associated with a single database.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBufferFile(self, version: typing.Union[jpype.JInt, int]) -> java.io.File:
        """
        Get the buffer file corresponding to a specified version.
        
        :param jpype.JInt or int version: 
        :return: database buffer file.
        :rtype: java.io.File
        """

    def getChangeDataFile(self, version: typing.Union[jpype.JInt, int]) -> java.io.File:
        """
        Get the change data buffer file corresponding to the specified version.
        This file contains application specific changes which were made going from the 
        specified version to the next version (version+1).
        May return null if change data files are not used.
        
        :param jpype.JInt or int version: version of the original buffer file which was changed
        :return: change data buffer file.
        :rtype: java.io.File
        """

    def getChangeMapFile(self) -> java.io.File:
        """
        Returns the change map file corresponding to this DB if one is defined.
        This file tracks all buffers which have been modified during a save
        operation.
        """

    def getCurrentVersion(self) -> int:
        """
        Returns the current version.  A value of 0 indicates that the 
        first buffer file has not yet been created.
        """

    def getVersionFile(self, version: typing.Union[jpype.JInt, int]) -> java.io.File:
        """
        Get the buffer version file corresponding to a specified version.
        This file contains data corresponding to a specified buffer file version
        and those buffers which have been modified in the next version (version+1).
        May return null if version files not used.
        
        :param jpype.JInt or int version: version of the original buffer file to be reconstructed
        :return: buffer version file.
        :rtype: java.io.File
        """

    def updateEnded(self, checkinId: typing.Union[jpype.JLong, int]):
        """
        Callback indicating that a buffer file update has ended without
        creating a new version.  This method terminates the checkin session.
        
        :param jpype.JLong or int checkinId: associated checkinId
        """

    def versionCreated(self, version: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str], checkinId: typing.Union[jpype.JLong, int]):
        """
        Callback for when a buffer file is created.
        
        :param jpype.JInt or int version: 
        :param java.lang.String or str comment: 
        :param jpype.JLong or int checkinId: associated checkinId
        :raises FileNotFoundException: database files not found
        """

    @property
    def changeDataFile(self) -> java.io.File:
        ...

    @property
    def bufferFile(self) -> java.io.File:
        ...

    @property
    def changeMapFile(self) -> java.io.File:
        ...

    @property
    def versionFile(self) -> java.io.File:
        ...

    @property
    def currentVersion(self) -> jpype.JInt:
        ...


class VersionFileHandler(java.lang.Object):
    """
    ``VersionFileHandler`` allows a set of VersionFile's to be used in
    the dynamic reconstruction of an older BufferFile.  In an attempt to
    conserve file handles, only one VersionFile is held open at any point
    in time.
     
    
    When constructed, this handler determines the set of VersionFile's needed to 
    reconstruct an older version from a specified target version.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOriginalBufferCount(self) -> int:
        """
        Returns buffer count for original buffer file.
        """

    @property
    def originalBufferCount(self) -> jpype.JInt:
        ...


class ChangeMapFile(java.lang.Object):
    """
    ``ChangeMapFile`` tracks which buffers within a LocalBufferFile 
    have been modified between an older and newer version.  The older
    file is also referred to as the target file.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataBuffer(db.Buffer, java.io.Externalizable):
    """
    ``DataBuffer`` provides an accessible binary buffer
    for use with a BufferMgr and BufferFile.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 3
    COMPRESSED_SERIAL_OUTPUT_PROPERTY: typing.Final = "db.buffers.DataBuffer.compressedOutput"

    def __init__(self):
        """
        Constructor for de-serialization
        """

    def clear(self):
        """
        Sets all the values in the buffer to 0;
        """

    def copy(self, offset: typing.Union[jpype.JInt, int], buf: DataBuffer, bufOffset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Copy data from another buffer into this buffer.
        
        :param jpype.JInt or int offset: offset within this buffer.
        :param DataBuffer buf: source buffer
        :param jpype.JInt or int bufOffset: source buffer offset
        :param jpype.JInt or int length: amount of data to copy.
        :raises IndexOutOfBoundsException: is thrown if parameters result in
        data access beyond the buffer size.
        """

    @staticmethod
    def enableCompressedSerializationOutput(enable: typing.Union[jpype.JBoolean, bool]):
        ...

    def getId(self) -> int:
        """
        Get the ID associated with this buffer.
        
        :return: buffer ID.
        :rtype: int
        """

    def isDirty(self) -> bool:
        """
        Return true if this buffer contains modified data.
        When this buffer is released to the BufferMgr, the data is consumed and 
        this flag reset to false.
        """

    def isEmpty(self) -> bool:
        """
        Return true if this buffer is empty/unused.  Writing to empty buffer
        does not change the state of this flag.
        """

    def move(self, src: typing.Union[jpype.JInt, int], dest: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Move the data within this buffer.
        
        :param jpype.JInt or int src: source offset within this buffer
        :param jpype.JInt or int dest: destination offset within this buffer
        :param jpype.JInt or int length: length of data to be moved
        :raises IndexOutOfBoundsException: is thrown if parameters result in
        data access beyond the buffer size.
        """

    def unsignedCompareTo(self, otherData: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Perform an unsigned data comparison
        
        :param jpype.JArray[jpype.JByte] otherData: other data to be compared
        :param jpype.JInt or int offset: offset within this buffer
        :param jpype.JInt or int len: length of data within this buffer
        :return: unsigned comparison result
        :rtype: int
        :raises IndexOutOfBoundsException: if specified region is not 
        contained within this buffer.
        """

    @staticmethod
    def usingCompressedSerializationOutput() -> bool:
        ...

    @property
    def dirty(self) -> jpype.JBoolean:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class BlockStream(java.io.Closeable):
    """
    ``BlockStream`` provides a BufferFile block stream.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBlockCount(self) -> int:
        """
        Get the number of blocks to be transferred
        
        :return: block count
        :rtype: int
        """

    def getBlockSize(self) -> int:
        """
        Get the raw block size
        
        :return: block size
        :rtype: int
        """

    @property
    def blockCount(self) -> jpype.JInt:
        ...

    @property
    def blockSize(self) -> jpype.JInt:
        ...


class RemoteBufferFileHandle(BufferFileHandle, java.rmi.Remote):
    """
    ``RemoteBufferFileHandle`` facilitates access to a remote BufferFile
    via RMI.
     
    
    Methods from :obj:`BufferFileHandle` **must** be re-declared here 
    so they may be properly marshalled for remote invocation via RMI.  
    This became neccessary with an OpenJDK 11.0.6 change made to 
    :obj:`RemoteObjectInvocationHandler`.
    """

    class_: typing.ClassVar[java.lang.Class]


class ChangeMap(java.lang.Object):
    """
    ``ChangeMap`` facilitates the decoding of change-data 
    to determine if a specific buffer was modified by the 
    corresponding buffer file version.
    
    
    .. seealso::
    
        | :obj:`ChangeMapFile`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mapData: jpype.JArray[jpype.JByte]):
        """
        Constructor.
        
        :param jpype.JArray[jpype.JByte] mapData: change map data
        """

    def containsIndex(self, index: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the specified index is within the bounds of this map.
        """

    def getData(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the underlying change map data as a byte array
        
        :return: change map data
        :rtype: jpype.JArray[jpype.JByte]
        """

    def hasChanged(self, index: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the change map data indicates that the 
        specified buffer has been modified.
        
        :param jpype.JInt or int index: buffer index
        """

    @property
    def data(self) -> jpype.JArray[jpype.JByte]:
        ...


@typing.type_check_only
class IndexProvider(java.lang.Object):
    """
    ``IndexProvider`` maintains the free index list associated
    with a BufferFile.  This provider will exhaust the free index list
    before allocating new indexes.  This provider relies on the BufferFile
    growing automatically when buffers having indexes beyond the end-of-file 
    are written.
    """

    class_: typing.ClassVar[java.lang.Class]


class ManagedBufferFile(BufferFile):
    """
    ``BufferFile`` facilitates read/write access to buffer oriented file.
    Access to related resources, such as parameters and change data, is also facilitated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def canSave(self) -> bool:
        """
        Returns true if a save file is provided for creating a new
        version of this buffer file.
        
        :raises IOException: if an I/O error occurs
        
        .. seealso::
        
            | :obj:`.getSaveFile()`
        """

    def getCheckinID(self) -> int:
        """
        Returns the checkin ID corresponding to this buffer file.
        The returned value is only valid if this buffer file has an associated
        buffer file manager and is either being created (see isReadOnly) or
        is intended for update (see canSave).
        
        :raises IOException: if an I/O error occurs
        """

    def getForwardModMapData(self, oldVersion: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Returns a bit map corresponding to all buffers modified since oldVersion.
        This identifies all buffers contained within the oldVersion
        which have been modified during any revision up until this file version.
        Buffers added since oldVersion are not identified
        NOTE: The bit mask may identify empty/free buffers within this file version.
        
        :param jpype.JInt or int oldVersion: indicates the older version of this file for which a change map
        will be returned.  This method may only be invoked if this file
        is at version 2 or higher, has an associated BufferFileManager and
        the oldVersion related files still exist.
        :return: ModMap buffer change map data
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if an I/O error occurs
        """

    def getNextChangeDataFile(self, getFirst: typing.Union[jpype.JBoolean, bool]) -> BufferFile:
        """
        Get the next change data file which corresponds to this buffer file.
        This method acts like an iterator which each successive invocation returning 
        the next available file.  Null is returned when no more files are available.
        The invoker is responsible for closing each file returned.  It is highly 
        recommended that each file be closed prior to requesting the next file.
        
        :param jpype.JBoolean or bool getFirst: causes the iterator to reset and return the first available file.
        :raises IOException: if an I/O error occurs
        """

    def getSaveChangeDataFile(self) -> BufferFile:
        """
        Returns a temporary change data buffer file which should be used to store a 
        application-level ChangeSet associated with this new buffer file version.  
        The getSaveFile method must be successfully invoked prior to invoking this method.
        
        :return: change data file or null if one is not available.
        :rtype: BufferFile
        :raises IOException: if an I/O error occurs
        """

    def getSaveFile(self) -> ManagedBufferFile:
        """
        Returns a Save file if available.  Returns null if
        a save can not be performed.  This method may block for an extended
        period of time if the pre-save process has not already completed.
        This method does not accept a monitor since a remote TaskMonitor does
        not yet exist.
        
        :raises IOException: if an I/O error occurs
        """

    def saveCompleted(self, commit: typing.Union[jpype.JBoolean, bool]):
        """
        After getting the save file, this method must be invoked to
        terminate the save.
        
        :param jpype.JBoolean or bool commit: if true the save file will be reopened as read-only 
        for update.  If false, the save file will be deleted and the object will 
        become invalid.
        :raises IOException:
        """

    def setVersionComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment which will be associated with this buffer file
        if saved.  The comment must be set prior to invoking close or
        setReadOnly.
        
        :param java.lang.String or str comment: comment text
        :raises IOException: if an I/O error occurs
        """

    @property
    def forwardModMapData(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def saveChangeDataFile(self) -> BufferFile:
        ...

    @property
    def checkinID(self) -> jpype.JLong:
        ...

    @property
    def nextChangeDataFile(self) -> BufferFile:
        ...

    @property
    def saveFile(self) -> ManagedBufferFile:
        ...


class ManagedBufferFileAdapter(BufferFileAdapter, ManagedBufferFile):
    """
    ``ManagedBufferFileAdapter`` provides a ManagedBufferFile implementation which
    wraps a ManagedBufferFileHandle.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, remoteManagedBufferFile: ManagedBufferFileHandle):
        """
        Constructor.
        
        :param ManagedBufferFileHandle remoteManagedBufferFile: remote buffer file handle
        """


class ManagedBufferFileHandle(BufferFileHandle):
    """
    ``ManagedBufferFileHandle`` facilitates access to a ManagedBufferFile
    """

    class_: typing.ClassVar[java.lang.Class]

    def canSave(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.canSave()`
        """

    def getCheckinID(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.getCheckinID()`
        """

    def getForwardModMapData(self, oldVersion: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.getForwardModMapData(int)`
        """

    def getInputBlockStream(self, changeMapData: jpype.JArray[jpype.JByte]) -> InputBlockStream:
        """
        Provides local access to an input block stream for a given change map.  
        This method should only be used if the associated 
        :meth:`BufferFileAdapter.isRemote() <BufferFileAdapter.isRemote>` is *false*.
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFileAdapter.getInputBlockStream(byte[])`
        """

    def getInputBlockStreamHandle(self, changeMapData: jpype.JArray[jpype.JByte]) -> BlockStreamHandle[InputBlockStream]:
        """
        Get an input block stream handle, for a given change map, which will facilitate 
        access to a remote InputBlockStream.  The handle will facilitate use of a 
        remote streaming interface.  This method should only be used 
        if the associated :meth:`BufferFileAdapter.isRemote() <BufferFileAdapter.isRemote>` is *true*.
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFileAdapter.getInputBlockStream(byte[])`
        """

    def getNextChangeDataFile(self, getFirst: typing.Union[jpype.JBoolean, bool]) -> BufferFileHandle:
        """
        
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.getNextChangeDataFile(boolean)`
        """

    def getSaveChangeDataFile(self) -> BufferFileHandle:
        """
        
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.getSaveChangeDataFile()`
        """

    def getSaveFile(self) -> ManagedBufferFileHandle:
        """
        
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.getSaveFile()`
        """

    def saveCompleted(self, commit: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.saveCompleted(boolean)`
        """

    def setVersionComment(self, comment: typing.Union[java.lang.String, str]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.setVersionComment(java.lang.String)`
        """

    @property
    def forwardModMapData(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def saveChangeDataFile(self) -> BufferFileHandle:
        ...

    @property
    def inputBlockStreamHandle(self) -> BlockStreamHandle[InputBlockStream]:
        ...

    @property
    def checkinID(self) -> jpype.JLong:
        ...

    @property
    def nextChangeDataFile(self) -> BufferFileHandle:
        ...

    @property
    def saveFile(self) -> ManagedBufferFileHandle:
        ...

    @property
    def inputBlockStream(self) -> InputBlockStream:
        ...


class RemoteManagedBufferFileHandle(ManagedBufferFileHandle, java.rmi.Remote):
    """
    ``RemoteManagedBufferFileHandle`` facilitates access to a ManagedBufferFile
    via RMI.
     
    
    Methods from :obj:`BufferFileHandle` and :obj:`ManagedBufferFile` **must** 
    be re-declared here so they may be properly marshalled for remote invocation via RMI.  
    This became neccessary with an OpenJDK 11.0.6 change made to 
    :obj:`RemoteObjectInvocationHandler`.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["BufferFileBlock", "RecoveryMgr", "InputBlockStream", "BufferNode", "BlockStreamHandle", "LocalManagedBufferFile", "BufferMgr", "OutputBlockStream", "BufferFile", "LocalBufferFile", "BufferFileAdapter", "VersionFile", "RecoveryFile", "BufferFileHandle", "BufferFileManager", "VersionFileHandler", "ChangeMapFile", "DataBuffer", "BlockStream", "RemoteBufferFileHandle", "ChangeMap", "IndexProvider", "ManagedBufferFile", "ManagedBufferFileAdapter", "ManagedBufferFileHandle", "RemoteManagedBufferFileHandle"]
