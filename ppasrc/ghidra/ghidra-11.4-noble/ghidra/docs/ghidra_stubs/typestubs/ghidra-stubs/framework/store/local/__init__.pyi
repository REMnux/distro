from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db.buffers
import generic.jar
import ghidra.framework.store
import ghidra.framework.store.db
import ghidra.util
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore


class LocalDataFileHandle(ghidra.framework.store.DataFileHandle):
    """
    ``LocalDataFileHandle`` provides random access to 
    a local File.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath, readOnly: typing.Union[jpype.JBoolean, bool]):
        """
        Construct and open a local DataFileHandle.
        
        :param jpype.protocol.SupportsPath file: file to be opened
        :param jpype.JBoolean or bool readOnly: if true resulting handle may only be read.
        :raises FileNotFoundException: if file was not found
        :raises IOException: if an IO Error occurs
        """

    def close(self):
        ...

    def isReadOnly(self) -> bool:
        ...

    def length(self) -> int:
        ...

    @typing.overload
    def read(self, b: jpype.JArray[jpype.JByte]):
        ...

    @typing.overload
    def read(self, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        ...

    def seek(self, pos: typing.Union[jpype.JLong, int]):
        ...

    def setLength(self, newLength: typing.Union[jpype.JLong, int]):
        ...

    def skipBytes(self, n: typing.Union[jpype.JInt, int]) -> int:
        ...

    @typing.overload
    def write(self, b: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte]):
        ...

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...


class LockFile(java.lang.Object):
    """
    Provides for the creation and management of a named lock file. Keep in mind
    that if a lock expires it may be removed without notice.  Care should be
    taken to renew a lock file in a timely manner.
    """

    @typing.type_check_only
    class WaitForLockRunnable(java.lang.Runnable):
        """
        Provides a runnable class which waits for a lock to be removed.
        If the lock expires while waiting, the lock file is removed.
        No attempt should be made to create the lock file while this
        task is running.
        """

        class_: typing.ClassVar[java.lang.Class]

        def run(self):
            """
            Check to see if the current lock file has exceeded the
            maximum allowed lease time.
            """


    @typing.type_check_only
    class HoldLockRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    nextInstanceId: typing.ClassVar[jpype.JInt]

    @typing.overload
    def __init__(self, dir: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param jpype.protocol.SupportsPath dir: directory containing lock file
        :param java.lang.String or str name: unmangled name of entity which this lock is associated with.
        """

    @typing.overload
    def __init__(self, dir: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str], lockType: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param jpype.protocol.SupportsPath dir: directory containing lock file
        :param java.lang.String or str name: unmangled name of entity which this lock is associated with.
        :param java.lang.String or str lockType: unique lock identifier (may not contain a '.')
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Constructor.
        
        :param jpype.protocol.SupportsPath file: file whose lock state will be controlled with this lock file.
        """

    @staticmethod
    def containsLock(dir: jpype.protocol.SupportsPath) -> bool:
        ...

    @typing.overload
    def createLock(self) -> bool:
        """
        Create the lock file using the default timeout.
        Lock is guaranteed for MAX_LOCK_LEASE_PERIOD seconds.
        
        :return: true if lock creation was successful.
        :rtype: bool
        """

    @typing.overload
    def createLock(self, timeout: typing.Union[jpype.JInt, int], hold: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Create the lock file.
        If another lock file already exists, wait for it to expire
        within the specified timeout period.  Method will block
        until either the lock is obtained or the timeout period lapses.
        
        :param jpype.JInt or int timeout: maximum time in milliseconds to wait for lock.
        :param jpype.JBoolean or bool hold: if true the lock will be held and maintained until
        removed, otherwise it is only guaranteed for MAX_LOCK_LEASE_PERIOD seconds.
        :return: true if lock creation was successful.
        :rtype: bool
        """

    def dispose(self):
        """
        Cleanup lock resources and tasks.
        Invoking this method could prevent stale locks from being removed
        if createLock was invoked with a very short timeout.
        Use of dispose is optional - the associated wait task should 
        stop by it self allowing the LockFile object to be finalized.
        """

    def getLockOwner(self) -> str:
        """
        Return the name of the current lock owner
        or ``"<Unknown>"`` if not locked or could not be determined.
        """

    @typing.overload
    def haveLock(self) -> bool:
        """
        Determine if lock file was successfully created by this instance.
        This does not quarentee that the lock is still present if more
        than MAX_LOCK_LEASE_PERIOD has lapsed since lock was created.
        
        :return: true if lock has been created, otherwise false.
        :rtype: bool
        """

    @typing.overload
    def haveLock(self, verify: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Determine if lock is still in place.
        Verifying the lock may be necessary when slow processes are holding 
        the lock without timely renewals.
        
        :return: true if lock is still in place, otherwise false.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isLocked(dir: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str]) -> bool:
        """
        
        
        :param jpype.protocol.SupportsPath dir: directory containing lock file
        :param java.lang.String or str name: of entity which this lock is associated with.
        :return: true if any lock exists within dir for the given entity name.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isLocked(file: jpype.protocol.SupportsPath) -> bool:
        """
        
        
        :param jpype.protocol.SupportsPath file: file whose lock state is controlled with this lock file.
        :return: true if any lock exists within dir for the given entity name.
        :rtype: bool
        """

    def removeLock(self):
        """
        Remove the lock file.
        This method should be invoked when the corresponding transaction is complete.
        """

    @property
    def lockOwner(self) -> java.lang.String:
        ...


class LocalFilesystemTestUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createIndexedV0Filesystem(rootPath: typing.Union[java.lang.String, str], isVersioned: typing.Union[jpype.JBoolean, bool], readOnly: typing.Union[jpype.JBoolean, bool], enableAsyncronousDispatching: typing.Union[jpype.JBoolean, bool]) -> IndexedLocalFileSystem:
        """
        Create empty V0 Indexed filesystem.  This is an original Indexed filesystem with the addition 
        of a version 0 indicator within the index file.
        
        :param java.lang.String or str rootPath: path for root directory (must already exist).
        :param jpype.JBoolean or bool isVersioned: if true item versioning will be enabled.
        :param jpype.JBoolean or bool readOnly: if true modifications within this file-system will not be allowed
        and result in an ReadOnlyException
        :param jpype.JBoolean or bool enableAsyncronousDispatching: if true a separate dispatch thread will be used
        to notify listeners.  If false, blocking notification will be performed.
        :raises IOException:
        """

    @staticmethod
    def createIndexedV1Filesystem(rootPath: typing.Union[java.lang.String, str], isVersioned: typing.Union[jpype.JBoolean, bool], readOnly: typing.Union[jpype.JBoolean, bool], enableAsyncronousDispatching: typing.Union[jpype.JBoolean, bool]) -> IndexedV1LocalFileSystem:
        """
        Create empty mangled filesystem
        
        :param java.lang.String or str rootPath: path for root directory (must already exist).
        :param jpype.JBoolean or bool isVersioned: if true item versioning will be enabled.
        :param jpype.JBoolean or bool readOnly: if true modifications within this file-system will not be allowed
        and result in an ReadOnlyException
        :param jpype.JBoolean or bool enableAsyncronousDispatching: if true a separate dispatch thread will be used
        to notify listeners.  If false, blocking notification will be performed.
        :raises IOException:
        """

    @staticmethod
    def createMangledFilesystem(rootPath: typing.Union[java.lang.String, str], isVersioned: typing.Union[jpype.JBoolean, bool], readOnly: typing.Union[jpype.JBoolean, bool], enableAsyncronousDispatching: typing.Union[jpype.JBoolean, bool]) -> MangledLocalFileSystem:
        """
        Create empty mangled filesystem
        
        :param java.lang.String or str rootPath: path for root directory (must already exist).
        :param jpype.JBoolean or bool isVersioned: if true item versioning will be enabled.
        :param jpype.JBoolean or bool readOnly: if true modifications within this file-system will not be allowed
        and result in an ReadOnlyException
        :param jpype.JBoolean or bool enableAsyncronousDispatching: if true a separate dispatch thread will be used
        to notify listeners.  If false, blocking notification will be performed.
        :raises IOException:
        """

    @staticmethod
    def createOriginalIndexedFilesystem(rootPath: typing.Union[java.lang.String, str], isVersioned: typing.Union[jpype.JBoolean, bool], readOnly: typing.Union[jpype.JBoolean, bool], enableAsyncronousDispatching: typing.Union[jpype.JBoolean, bool]) -> IndexedLocalFileSystem:
        """
        Create empty original Indexed filesystem.  The original index file lacked any version indicator
        but will be treated as a version 0 index.
        
        :param java.lang.String or str rootPath: path for root directory (must already exist).
        :param jpype.JBoolean or bool isVersioned: if true item versioning will be enabled.
        :param jpype.JBoolean or bool readOnly: if true modifications within this file-system will not be allowed
        and result in an ReadOnlyException
        :param jpype.JBoolean or bool enableAsyncronousDispatching: if true a separate dispatch thread will be used
        to notify listeners.  If false, blocking notification will be performed.
        :raises IOException:
        """


class IndexedLocalFileSystem(LocalFileSystem):
    """
    ``IndexedLocalFileSystem`` implements a case-sensitive indexed filesystem
    which uses a shallow storage hierarchy with no restriction on file name or path 
    length.  This filesystem is identified by the existence of an index file (~index.dat) 
    and recovery journal (~index.jrn).
    """

    @typing.type_check_only
    class GetFolderOption(java.lang.Enum[IndexedLocalFileSystem.GetFolderOption]):

        class_: typing.ClassVar[java.lang.Class]
        READ_ONLY: typing.Final[IndexedLocalFileSystem.GetFolderOption]
        CREATE: typing.Final[IndexedLocalFileSystem.GetFolderOption]
        CREATE_ALL: typing.Final[IndexedLocalFileSystem.GetFolderOption]
        CREATE_ALL_NOTIFY: typing.Final[IndexedLocalFileSystem.GetFolderOption]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> IndexedLocalFileSystem.GetFolderOption:
            ...

        @staticmethod
        def values() -> jpype.JArray[IndexedLocalFileSystem.GetFolderOption]:
            ...


    @typing.type_check_only
    class Item(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Folder(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getPathname(self) -> str:
            ...

        @property
        def pathname(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class IndexJournal(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IndexedItemStorage(LocalFileSystem.ItemStorage):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class BadStorageNameException(java.io.IOException):
        """
        ``BadStorageNameException`` invalid storage name
        encountered.
        """

        class_: typing.ClassVar[java.lang.Class]


    class IndexReadException(java.io.IOException):
        """
        ``IndexReadException`` occurs when an error occurs
        while reading/processing the filesystem index
        """

        class_: typing.ClassVar[java.lang.Class]


    class IndexVersionException(IndexedLocalFileSystem.IndexReadException):
        """
        ``IndexReadException`` occurs when an error occurs
        while reading/processing the filesystem index
        """

        class_: typing.ClassVar[java.lang.Class]

        def canUpgrade(self) -> bool:
            ...


    class_: typing.ClassVar[java.lang.Class]
    LATEST_INDEX_VERSION: typing.Final = 1

    def getIndexImplementationVersion(self) -> int:
        ...

    @staticmethod
    def hasIndexedStructure(rootPath: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the specified directory contains a likely 
        indexed filesystem.
        
        :param java.lang.String or str rootPath: filesystem root
        :return: true if filesystem appears to be indexed (not mangled)
        :rtype: bool
        """

    @staticmethod
    def isIndexed(rootPath: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the specified directory corresponds to an 
        indexed filesystem.
        
        :param java.lang.String or str rootPath: filesystem root
        :return: true if filesystem contains an index (not mangled)
        :rtype: bool
        """

    @staticmethod
    def readIndexVersion(rootPath: typing.Union[java.lang.String, str]) -> int:
        ...

    @staticmethod
    def rebuild(rootDir: jpype.protocol.SupportsPath) -> bool:
        """
        Completely rebuild filesystem index using item information contained
        within indexed property files.  Empty folders will be lost.
        
        :param jpype.protocol.SupportsPath rootDir: 
        :raises IOException:
        """

    @property
    def indexImplementationVersion(self) -> jpype.JInt:
        ...


class MangledLocalFileSystem(LocalFileSystem):
    """
    ``MangledLocalFileSystem`` implements the legacy project data storage 
    scheme which utilizes a simplified name mangling which provides case-sensitive 
    file-naming with support for spaces.  Project folder hierarchy maps directly to
    the actual storage hierarchy.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_NAME_LENGTH: typing.Final = 60

    def convertToIndexedLocalFileSystem(self):
        """
        Convert this mangled filesystem to an indexed filesystem.  This instance should be discarded
        and not used once the conversion has completed.
        
        :raises IOException:
        """


class DataDirectoryException(java.io.IOException):
    """
    ``DataDirectoryException`` is thrown when a folder item can not be 
    created because its associated data directory already exists.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str], dir: jpype.protocol.SupportsPath):
        """
        Constructor.
        
        :param java.lang.String or str msg: error message
        :param jpype.protocol.SupportsPath dir: existing data directory
        """

    def getDataDirectory(self) -> java.io.File:
        """
        Returns existing data directory
        """

    @property
    def dataDirectory(self) -> java.io.File:
        ...


class ItemDeserializer(java.lang.Object):
    """
    ``ItemDeserializer`` facilitates the reading of a compressed data stream
    contained within a "packed" file.  A "packed" file contains the following meta-data
    which is available after construction:
     
    * Item name
    * Content type (int)
    * File type (int)
    * Data length
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, packedFile: jpype.protocol.SupportsPath):
        """
        Constructor.
        
        :param jpype.protocol.SupportsPath packedFile: item to deserialize.
        :raises IOException:
        """

    @typing.overload
    def __init__(self, packedFile: generic.jar.ResourceFile):
        ...

    def dispose(self):
        """
        Close packed-file input stream and free resources.
        """

    def getContentType(self) -> str:
        """
        Returns packed content type
        """

    def getFileType(self) -> int:
        """
        Returns packed file type.
        """

    def getItemName(self) -> str:
        """
        Returns packed item name
        """

    def getLength(self) -> int:
        """
        Returns unpacked data length
        """

    def saveItem(self, out: java.io.OutputStream, monitor: ghidra.util.task.TaskMonitor):
        """
        Save the item to the specified output stream.
        This method may only be invoked once.
        
        :param java.io.OutputStream out: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises IOException:
        """

    @property
    def itemName(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def contentType(self) -> java.lang.String:
        ...

    @property
    def fileType(self) -> jpype.JInt:
        ...


class IndexedPropertyFile(ghidra.util.PropertyFile):

    class_: typing.ClassVar[java.lang.Class]
    NAME_PROPERTY: typing.Final = "NAME"
    PARENT_PATH_PROPERTY: typing.Final = "PARENT"

    @typing.overload
    def __init__(self, dir: jpype.protocol.SupportsPath, storageName: typing.Union[java.lang.String, str], parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Construct a new or existing PropertyFile.
        This form ignores retained property values for NAME and PARENT path.
        
        :param jpype.protocol.SupportsPath dir: parent directory
        :param java.lang.String or str storageName: stored property file name (without extension)
        :param java.lang.String or str parentPath: path to parent
        :param java.lang.String or str name: name of the property file
        :raises IOException:
        """

    @typing.overload
    def __init__(self, dir: jpype.protocol.SupportsPath, storageName: typing.Union[java.lang.String, str]):
        """
        Construct an existing PropertyFile.
        
        :param jpype.protocol.SupportsPath dir: parent directory
        :param java.lang.String or str storageName: stored property file name (without extension)
        :raises FileNotFoundException: if property file does not exist
        :raises IOException: if error occurs reading property file
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Construct an existing PropertyFile.
        
        :param jpype.protocol.SupportsPath file: 
        :raises FileNotFoundException: if property file does not exist
        :raises IOException: if error occurs reading property file
        """


@typing.type_check_only
class CheckoutManager(java.lang.Object):
    """
    ``CheckoutManager`` manages checkout data for a versioned
    LocalFolderItem. Checkout data is maintained within the file 'checkout.dat'
    located within the items data directory.
    """

    class_: typing.ClassVar[java.lang.Class]


class LocalFileSystem(ghidra.framework.store.FileSystem):
    """
    ``LocalFileSystem`` provides access to FolderItem's which
    exist within a File-based directory structure.  Although FolderItem
    caching is highly recommended, it is not provided by this implementation
    and should be provided by an encompassing set of folder/file objects.
     
    
    A LocalFileSystem may optionally support version control of its
    FolderItem's.  When versioned, FolderItem's must be checked-out
    to create new versions.  When not versioned, the check-out mechanism
    is not used.
     
    
    FileSystemListener's will only be notified of changes made by the
    associated LocalFileSystem instance.  For this reason, it is important
    that proper measures are taken to prevent concurrent modification of the
    underlying files/directories by another instance or by any other
    means.
    """

    @typing.type_check_only
    class ItemStorage(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    HIDDEN_DIR_PREFIX_CHAR: typing.Final = '~'
    """
    Hidden directory name prefix.
    Should only be prepended to an escaped base-name.
    
    
    .. seealso::
    
        | :obj:`.escapeHiddenDirPrefixChars(String)`
    """

    HIDDEN_DIR_PREFIX: typing.Final[java.lang.String]
    HIDDEN_ITEM_PREFIX: typing.Final = ".ghidra."
    """
    Hidden item name prefix.
    """


    def createTemporaryDatabase(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], fileID: typing.Union[java.lang.String, str], bufferFile: db.buffers.BufferFile, contentType: typing.Union[java.lang.String, str], resetDatabaseId: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> LocalDatabaseItem:
        ...

    @staticmethod
    def escapeHiddenDirPrefixChars(name: typing.Union[java.lang.String, str]) -> str:
        """
        Escape hidden prefix chars in name
        
        :param java.lang.String or str name: 
        :return: escaped name
        :rtype: str
        """

    def getItemNames(self, folderPath: typing.Union[java.lang.String, str], includeHiddenFiles: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[java.lang.String]:
        ...

    @staticmethod
    def getLocalFileSystem(rootPath: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool], isVersioned: typing.Union[jpype.JBoolean, bool], readOnly: typing.Union[jpype.JBoolean, bool], enableAsyncronousDispatching: typing.Union[jpype.JBoolean, bool]) -> LocalFileSystem:
        """
        Construct a local filesystem for existing data
        
        :param java.lang.String or str rootPath: 
        :param jpype.JBoolean or bool create: 
        :param jpype.JBoolean or bool isVersioned: 
        :param jpype.JBoolean or bool readOnly: 
        :param jpype.JBoolean or bool enableAsyncronousDispatching: 
        :return: local filesystem
        :rtype: LocalFileSystem
        :raises FileNotFoundException: if specified rootPath does not exist
        :raises IOException: if error occurs while reading/writing index files
        """

    def getMaxNameLength(self) -> int:
        """
        
        
        :return: the maximum name length permitted for folders or items.
        :rtype: int
        """

    @staticmethod
    def isHiddenDirName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Determines if the specified storage directory name corresponds to a 
        hidden directory (includes both system and application hidden directories).
        
        :param java.lang.String or str name: directory name as it appears on storage file system.
        :return: true if name is a hidden name, else false
        :rtype: bool
        """

    @staticmethod
    def isRefreshRequired() -> bool:
        """
        
        
        :return: true if folder item resources must be refreshed.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.setValidationRequired()`
        """

    @staticmethod
    def isValidNameCharacter(c: typing.Union[jpype.JChar, int, str]) -> bool:
        """
        
        
        :return: true if c is a valid character within the FileSystem.
        :rtype: bool
        """

    def migrationInProgress(self) -> bool:
        ...

    def setAssociatedRepositoryLogger(self, repositoryLogger: RepositoryLogger):
        """
        Associate file system with a specific repository logger
        
        :param RepositoryLogger repositoryLogger:
        """

    @staticmethod
    def setValidationRequired():
        """
        If set, the state of folder item resources will be continually refreshed.
        This is required if multiple instances exist for a single item.  The default is
        disabled.   This feature should be enabled for testing only since it may have a
        significant performance impact.  This does not provide locking which may be
        required for a shared environment (e.g., checkin locking is only managed by a
        single instance).
        """

    def testValidName(self, name: typing.Union[java.lang.String, str], isPath: typing.Union[jpype.JBoolean, bool]):
        """
        Validate a folder/item name or path.
        
        :param java.lang.String or str name: folder or item name
        :param jpype.JBoolean or bool isPath: if true name represents full path
        :raises InvalidNameException: if name is invalid
        """

    @staticmethod
    def unescapeHiddenDirPrefixChars(name: typing.Union[java.lang.String, str]) -> str:
        """
        Unescape a non-hidden directory name
        
        :param java.lang.String or str name: 
        :return: unescaped name or null if name is a hidden name
        :rtype: str
        """

    @property
    def maxNameLength(self) -> jpype.JInt:
        ...


class LocalDatabaseItem(LocalFolderItem, ghidra.framework.store.DatabaseItem):
    """
    ``LocalDatabaseItem`` provides a FolderItem implementation
    for a local database.  This item wraps an underlying VersionedDatabase
    if the file-system is versioned, otherwise a PrivateDatabase is wrapped.
     
    
    This item utilizes a data directory for storing all files relating to the
    database as well as history and checkout data files if this item is versioned.
    """

    @typing.type_check_only
    class LocalVersionedDbListener(ghidra.framework.store.db.VersionedDBListener):
        """
        ``LocalVersionedDbListener`` provides a listener 
        which maintains checkout and history data in response to 
        VersionedDatabase callbacks.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CleanupRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def openForUpdate(self, checkoutId: typing.Union[jpype.JLong, int]) -> db.buffers.LocalManagedBufferFile:
        """
        Open the latest database version for update.
        
        :param jpype.JLong or int checkoutId: reqiured for update to a versioned item, otherwise set to -1 for
        a non-versioned private database.
        :return: open database handle
        :rtype: db.buffers.LocalManagedBufferFile
        :raises IOException:
        """


class IndexedV1LocalFileSystem(IndexedLocalFileSystem):
    """
    ``IndexedV1LocalFileSystem`` implements a case-sensitive indexed filesystem
    which uses a shallow storage hierarchy with no restriction on file name or path 
    length.  This filesystem is identified by the existence of an index file (~index.dat) 
    and recovery journal (~index.jrn).  File system also maintains a file-ID mapping.
    """

    class_: typing.ClassVar[java.lang.Class]
    INDEX_VERSION: typing.Final = 1

    @staticmethod
    def rebuild(rootDir: jpype.protocol.SupportsPath) -> bool:
        """
        Completely rebuild filesystem index using item information contained
        within indexed property files.  Empty folders will be lost.
        
        :param jpype.protocol.SupportsPath rootDir: 
        :raises IOException:
        """


class UnknownFolderItem(LocalFolderItem):
    """
    ``UnknownFolderItem`` acts as a LocalFolderItem place-holder for 
    items of an unknown type.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN_CONTENT_TYPE: typing.Final = "Unknown-File"

    def canRecover(self) -> bool:
        ...

    def checkout(self, user: typing.Union[java.lang.String, str]) -> ghidra.framework.store.ItemCheckoutStatus:
        ...

    def getCurrentVersion(self) -> int:
        ...

    def getFileType(self) -> int:
        """
        Get the file type
        
        :return: file type or -1 if unspecified
        :rtype: int
        """

    def output(self, outputFile: jpype.protocol.SupportsPath, version: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        ...

    def setCheckout(self, checkoutId: typing.Union[jpype.JLong, int], checkoutVersion: typing.Union[jpype.JInt, int], localVersion: typing.Union[jpype.JInt, int]):
        ...

    def terminateCheckout(self, checkoutId: typing.Union[jpype.JLong, int]):
        ...

    @property
    def fileType(self) -> jpype.JInt:
        ...

    @property
    def currentVersion(self) -> jpype.JInt:
        ...


class FileChangeListener(java.lang.Object):
    """
    Defines a file change listener interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fileModified(self, file: jpype.protocol.SupportsPath):
        """
        Used to notify a listener that the specified file has been modified.
        If the file watcher was created with a lock file, the lock will be set
        on behalf of the caller.  This method should not attempt to alter the 
        lock.
        
        :param jpype.protocol.SupportsPath file: the modified file.
        """

    def fileRemoved(self, file: jpype.protocol.SupportsPath):
        """
        Used to notify a listener that the specified file has been removed.
        If the file watcher was created with a lock file, the lock will be set
        on behalf of the caller.  This method should not attempt to alter the 
        lock.
        
        :param jpype.protocol.SupportsPath file: the removed file.
        """


class ItemSerializer(java.lang.Object):
    """
    ``ItemSerializer`` facilitates the compressing and writing of a data stream
    to a "packed" file.  The resulting "packed" file will contain the following meta-data
    which is available after construction:
     
    * Item name
    * Content type (int)
    * File type (int)
    * Data length
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def isPackedFile(file: jpype.protocol.SupportsPath) -> bool:
        """
        A simple utility method to determine if the given file is a packed file as created by 
        this class.
        
        :param jpype.protocol.SupportsPath file: The file to check
        :return: True if it is a packed file
        :rtype: bool
        :raises IOException: If there is a problem reading the given file
        """

    @staticmethod
    @typing.overload
    def isPackedFile(inputStream: java.io.InputStream) -> bool:
        """
        A convenience method for checking if the file denoted by the given inputStream is a 
        packed file.  
         
        
        **Note: ** This method will NOT close the given inputStream.
        
        :param java.io.InputStream inputStream: a stream for accessing bytes of what may be a packed file
        :return: true if the bytes from the inputStream represent the bytes of a packed file
        :rtype: bool
        :raises IOException: If there is a problem accessing the inputStream
        
        .. seealso::
        
            | :obj:`.isPackedFile(File)`
        """

    @staticmethod
    def outputItem(itemName: typing.Union[java.lang.String, str], contentType: typing.Union[java.lang.String, str], fileType: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JLong, int], content: java.io.InputStream, packedFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        """
        Read and compress data from the specified content stream and write to 
        a packed file along with additional meta-data.
        
        :param java.lang.String or str itemName: item name
        :param java.lang.String or str contentType: content type
        :param jpype.JInt or int fileType: file type
        :param jpype.JLong or int length: content length to be read
        :param java.io.InputStream content: content input stream
        :param jpype.protocol.SupportsPath packedFile: output packed file to be created
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if output is cancelled
        :raises IOException: if IO error occurs
        """


class LocalFolderItem(ghidra.framework.store.FolderItem):
    """
    ``LocalFolderItem`` provides an abstract implementation of a folder
    item which resides on a local file-system.  An item is defined by a property file
    and generally has a hidden data directory which contains the actual data file(s).
    
    
    An item may be either private or shared (i.e., versioned) as defined by the
    associated file-system.  A shared item utilizes a CheckoutManager and HistoryManager
    for tracking version control data related to this item.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def updateCheckout(self, versionedFolderItem: ghidra.framework.store.FolderItem, updateItem: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Update this non-versioned item with the latest version of the specified versioned item.
        
        :param ghidra.framework.store.FolderItem versionedFolderItem: versioned item which corresponds to this
        non-versioned item.
        :param jpype.JBoolean or bool updateItem: if true this items content is updated using the versionedFolderItem
        :param ghidra.util.task.TaskMonitor monitor: progress monitor for update
        :raises IOException: if this file is not a checked-out non-versioned file 
        or an IO error occurs.
        :raises CancelledException: if monitor cancels operation
        """

    @typing.overload
    def updateCheckout(self, item: ghidra.framework.store.FolderItem, checkoutVersion: typing.Union[jpype.JInt, int]):
        """
        Update this non-versioned item with the contents of the specified item which must be 
        within the same non-versioned fileSystem.  If successful, the specified item will be 
        removed after its content has been moved into this item.
        
        :param ghidra.framework.store.FolderItem item: 
        :param jpype.JInt or int checkoutVersion: 
        :raises IOException: if this file is not a checked-out non-versioned file 
        or an IO error occurs.
        """


class LocalDataFile(LocalFolderItem, ghidra.framework.store.DataFileItem):
    """
    ``LocalDataFile`` provides a FolderItem implementation
    for a local serialized data file.  This implementation supports 
    a non-versioned file-system only.
     
    
    This item utilizes a data directory for storing the serialized 
    data file.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fileSystem: LocalFileSystem, propertyFile: ghidra.util.PropertyFile):
        ...

    @typing.overload
    def __init__(self, fileSystem: LocalFileSystem, propertyFile: ghidra.util.PropertyFile, istream: java.io.InputStream, contentType: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Create a new local data file item.
        
        :param LocalFileSystem fileSystem: file system
        :param ghidra.util.PropertyFile propertyFile: serialized data property file
        :param java.io.InputStream istream: data source input stream (should be a start of data and will be read to end of file).
        The invoker of this constructor is responsible for closing istream.
        :param java.lang.String or str contentType: user content type
        :param ghidra.util.task.TaskMonitor monitor: progress monitor (used for cancel support, 
        progress not used since length of input stream is unknown)
        :raises IOException: if an IO Error occurs
        :raises CancelledException: if monitor cancels operation
        """


@typing.type_check_only
class HistoryManager(java.lang.Object):
    """
    ``HistoryManager`` manages version data for a versioned LocalFolderItem.
    History data is maintained within the file 'historyt.dat' located within the
    items data directory.
    """

    class_: typing.ClassVar[java.lang.Class]


class RepositoryLogger(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def log(self, path: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str], user: typing.Union[java.lang.String, str]):
        ...



__all__ = ["LocalDataFileHandle", "LockFile", "LocalFilesystemTestUtils", "IndexedLocalFileSystem", "MangledLocalFileSystem", "DataDirectoryException", "ItemDeserializer", "IndexedPropertyFile", "CheckoutManager", "LocalFileSystem", "LocalDatabaseItem", "IndexedV1LocalFileSystem", "UnknownFolderItem", "FileChangeListener", "ItemSerializer", "LocalFolderItem", "LocalDataFile", "HistoryManager", "RepositoryLogger"]
