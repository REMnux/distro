from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.buffers
import generic.jar
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore


class PrivateDatabase(db.Database):
    """
    ``PrivateDatabase`` corresponds to a non-versioned database.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dbDir: jpype.protocol.SupportsPath):
        """
        Constructor for an existing "Non-Versioned" Database.
        
        :param jpype.protocol.SupportsPath dbDir: database directory
        :raises IOException:
        """

    @typing.overload
    def __init__(self, dbDir: jpype.protocol.SupportsPath, srcFile: db.buffers.BufferFile, resetDatabaseId: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new Database from an existing srcFile.
        
        :param jpype.protocol.SupportsPath dbDir: 
        :param db.buffers.BufferFile srcFile: 
        :param jpype.JBoolean or bool resetDatabaseId: if true database ID will be reset for new Database
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises IOException: 
        :raises CancelledException:
        """

    @typing.overload
    def __init__(self, dbDir: jpype.protocol.SupportsPath, packedFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new Database from an existing packed database file.
        
        :param jpype.protocol.SupportsPath dbDir: private database directory
        :param jpype.protocol.SupportsPath packedFile: packed database storage file
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises IOException: 
        :raises CancelledException:
        """

    def canRecover(self) -> bool:
        """
        Returns true if recovery data exists which may enable recovery of unsaved changes
        resulting from a previous crash.
        """

    @staticmethod
    def createDatabase(dbDir: jpype.protocol.SupportsPath, dbFileListener: db.DBFileListener, bufferSize: typing.Union[jpype.JInt, int]) -> db.buffers.LocalManagedBufferFile:
        """
        Create a new database and provide the initial buffer file for writing.
        
        :param jpype.protocol.SupportsPath dbDir: 
        :param jpype.JInt or int bufferSize: 
        :return: initial buffer file
        :rtype: db.buffers.LocalManagedBufferFile
        :raises IOException:
        """

    def dbMoved(self, dir: jpype.protocol.SupportsPath):
        """
        Following a move of the database directory,
        this method should be invoked if this instance will
        continue to be used.
        
        :param jpype.protocol.SupportsPath dir: new database directory
        :raises FileNotFoundException: if the database directory cannot be found
        """

    def openBufferFile(self) -> db.buffers.LocalManagedBufferFile:
        """
        Open the current version of this database for non-update use.
        
        :return: buffer file for non-update use
        :rtype: db.buffers.LocalManagedBufferFile
        :raises IOException:
        """

    def openBufferFileForUpdate(self) -> db.buffers.LocalManagedBufferFile:
        """
        Open the current version of this database for update use.
        
        :return: updateable buffer file
        :rtype: db.buffers.LocalManagedBufferFile
        :raises IOException: if updating this database file is not allowed
        """

    def output(self, outputFile: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str], filetype: typing.Union[jpype.JInt, int], contentType: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Output the current version of this database to a packed storage file.
        
        :param jpype.protocol.SupportsPath outputFile: packed storage file to be written
        :param java.lang.String or str name: database name
        :param jpype.JInt or int filetype: application file type
        :param java.lang.String or str contentType: user content type
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises IOException: 
        :raises CancelledException:
        """

    def setIsCheckoutCopy(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        If this is a checked-out copy and a cumulative change file
        should be maintained, this method must be invoked following
        construction.
        """

    @typing.overload
    def updateCheckoutCopy(self, srcFile: db.buffers.ManagedBufferFile, oldVersion: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        If this is a checked-out copy, replace the buffer file content with that
        provided by the specified srcFile.  This Database must be a checkout copy.
        If a cumulative change files exists, it will be deleted following the update.
        
        :param db.buffers.ManagedBufferFile srcFile: open source data buffer file or null if current version
        is already up-to-date.
        :param jpype.JInt or int oldVersion: older version of srcFile from which this database originated.
        :raises IOException: 
        :raises CancelledException:
        """

    @typing.overload
    def updateCheckoutCopy(self):
        """
        If a cumulative change files exists, it will be deleted.
        
        :raises IOException:
        """

    def updateCheckoutFrom(self, otherDb: PrivateDatabase):
        """
        Move the content of the otherDb into this database.
        The otherDb will no longer exist if this method is successful.
        If already open for update, a save should not be done or the database
        may become corrupted.  All existing handles should be closed and reopened
        when this method is complete.
        
        :param PrivateDatabase otherDb: the other database.
        :raises IOException: if an IO error occurs.  An attempt will be made to restore
        this database to its original state, however the otherDb will not be repaired
        and may become unusable.
        """


class VersionedDBListener(java.lang.Object):
    """
    ``VersionedDBListener`` provides listeners the ability to be notified
    when changes occur to a versioned database.
    """

    class_: typing.ClassVar[java.lang.Class]

    def checkinCompleted(self, checkoutId: typing.Union[jpype.JLong, int]):
        """
        Terminate the specified checkout.
        A new version may or may not have been created.
        
        :param jpype.JLong or int checkoutId:
        """

    def getCheckoutVersion(self, checkoutId: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the checkout version associated with the specified
        checkoutId.  A returned version of -1 indicates that the 
        checkoutId is not valid.
        
        :param jpype.JLong or int checkoutId: 
        :return: checkout version
        :rtype: int
        """

    def versionCreated(self, db: VersionedDatabase, version: typing.Union[jpype.JInt, int], time: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str], checkinId: typing.Union[jpype.JLong, int]) -> bool:
        """
        A new database version has been created.
        
        :param VersionedDatabase db: 
        :param jpype.JInt or int version: 
        :param jpype.JLong or int time: 
        :param java.lang.String or str comment: 
        :param jpype.JLong or int checkinId: 
        :return: true if version is allowed, if false is returned 
        the version will be removed.
        :rtype: bool
        """

    def versionDeleted(self, version: typing.Union[jpype.JInt, int]):
        """
        A version has been deleted.
        
        :param jpype.JInt or int version:
        """

    def versionsChanged(self, minVersion: typing.Union[jpype.JInt, int], currentVersion: typing.Union[jpype.JInt, int]):
        """
        Available database versions have been modified.
        This method is not invoked when a new version is created.
        
        :param jpype.JInt or int minVersion: minimum available version
        :param jpype.JInt or int currentVersion: current/latest version
        """

    @property
    def checkoutVersion(self) -> jpype.JInt:
        ...


class PackedDatabase(db.Database):
    """
    ``PackedDatabase`` provides a packed form of Database
    which compresses a single version into a file.  
     
    
    When opening a packed database, a PackedDBHandle is returned 
    after first expanding the file into a temporary Database.
    """

    @typing.type_check_only
    class PDBBufferFileManager(db.Database.DBBufferFileManager):
        """
        ``PDBBufferFileManager`` removes the update lock when 
        the update has completed.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    READ_ONLY_DIRECTORY_LOCK_FILE: typing.Final = ".dbDirLock"
    """
    Presence of the directory lock file will prevent the creation or
    modification of any packed database files contained within that directory
    or any sub-directory.
    """


    @staticmethod
    def cleanupOldTempDatabases():
        """
        Attempt to remove all old temporary databases.  This method is not intended for general use 
        and should only be invoked once during module initialization 
        (see :obj:`FileSystemInitializer`).
        """

    @typing.overload
    def delete(self):
        """
        Deletes the storage file associated with this packed database.
        This method should not be called while the database is open, if
        it is an attempt will be made to close the handle.
        
        :raises IOException: if IO error occurs (e.g., file in-use or write-protected)
        """

    @staticmethod
    @typing.overload
    def delete(packedDbFile: jpype.protocol.SupportsPath):
        """
        Deletes the storage file associated with this packed database.
        
        :param jpype.protocol.SupportsPath packedDbFile: packed DB file to be removed
        :raises FileInUseException: if packed DB is currently locked and in use
        :raises IOException: if an IO error occurs (e.g., file in-use or write-protected)
        """

    def dispose(self):
        """
        Free resources consumed by this object.
        If there is an associated database handle it will be closed.
        """

    def getContentType(self) -> str:
        """
        Returns the user defined content type associated with this database.
        
        :return: packed DB content type
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getPackedDatabase(packedDbFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor) -> PackedDatabase:
        """
        Get a packed database which whose unpacking will be cached if possible.
        
        :param jpype.protocol.SupportsPath packedDbFile: packed database file to be opened
        :param ghidra.util.task.TaskMonitor monitor: unpack/open monitor
        :return: packed database which corresponds to the specified packedDbFile
        :rtype: PackedDatabase
        :raises IOException: if IO error occurs
        :raises CancelledException: if unpack/open is cancelled
        """

    @staticmethod
    @typing.overload
    def getPackedDatabase(packedDbFile: jpype.protocol.SupportsPath, neverCache: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> PackedDatabase:
        """
        Get a packed database whose unpacking may be cached if possible
        provided doNotCache is false.
        
        :param jpype.protocol.SupportsPath packedDbFile: packed database file to be opened
        :param jpype.JBoolean or bool neverCache: if true unpacking will never be cache.
        :param ghidra.util.task.TaskMonitor monitor: unpack/open monitor
        :return: packed database which corresponds to the specified packedDbFile
        :rtype: PackedDatabase
        :raises IOException: if IO error occurs
        :raises CancelledException: if unpack/open is cancelled
        """

    @staticmethod
    @typing.overload
    def getPackedDatabase(packedDbFile: generic.jar.ResourceFile, neverCache: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> PackedDatabase:
        """
        Get a packed database whose unpacking may be cached if possible
        provided doNotCache is false.
        
        :param generic.jar.ResourceFile packedDbFile: packed database resource file to be opened
        :param jpype.JBoolean or bool neverCache: if true unpacking will never be cache.
        :param ghidra.util.task.TaskMonitor monitor: unpack/open monitor
        :return: packed database which corresponds to the specified packedDbFile
        :rtype: PackedDatabase
        :raises IOException: if IO error occurs
        :raises CancelledException: if unpack/open is cancelled
        """

    def getPackedFile(self) -> generic.jar.ResourceFile:
        """
        Returns the storage file associated with this packed database.
        
        :return: associated packed DB file
        :rtype: generic.jar.ResourceFile
        """

    def isReadOnly(self) -> bool:
        ...

    @staticmethod
    def isReadOnlyPDBDirectory(directory: generic.jar.ResourceFile) -> bool:
        """
        Check for the presence of directory read-only lock
        
        :param generic.jar.ResourceFile directory: directory to check for read-only lock
        :return: true if read-only lock exists
        :rtype: bool
        """

    @staticmethod
    def packDatabase(dbh: db.DBHandle, itemName: typing.Union[java.lang.String, str], contentType: typing.Union[java.lang.String, str], outputFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        """
        Serialize (i.e., pack) an open database into the specified outputFile.
        
        :param db.DBHandle dbh: open database handle
        :param java.lang.String or str itemName: name to associate with packed content
        :param java.lang.String or str contentType: supported DB content type
        :param jpype.protocol.SupportsPath outputFile: packed output file to be created
        :param ghidra.util.task.TaskMonitor monitor: save/pack monitor
        :raises ReadOnlyException: if ``outputFile`` location is write-protected
        :raises DuplicateFileException: if ``outputFile`` already exists
        :raises IOException: if IO error occurs
        :raises CancelledException: if monitor cancels operation
        """

    @staticmethod
    def unpackDatabase(bfMgr: db.buffers.BufferFileManager, checkinId: typing.Union[jpype.JLong, int], packedFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        """
        Create a new Database with data provided by an ItemDeserializer.
        
        :param db.buffers.BufferFileManager bfMgr: the buffer manager for the database
        :param jpype.JLong or int checkinId: the check-in id
        :param jpype.protocol.SupportsPath packedFile: the file to unpack
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if IO error occurs
        :raises CancelledException: if unpack is cancelled
        """

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def contentType(self) -> java.lang.String:
        ...

    @property
    def packedFile(self) -> generic.jar.ResourceFile:
        ...


class PackedDBHandle(db.DBHandle):
    """
    ``DBHandle`` provides access to a PackedDatabase.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, contentType: typing.Union[java.lang.String, str]):
        """
        Constructs a temporary packed database handle.
        
        :param java.lang.String or str contentType: user defined content type.
        :raises IOException:
        """

    def getContentType(self) -> str:
        """
        Returns user defined content type associated with this handle.
        """

    def getPackedDatabase(self) -> PackedDatabase:
        """
        Returns PackedDatabase associated with this handle, or null if
        this is a temporary handle which has not yet been saved to a
        PackedDatabase using saveAs.
        """

    def save(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Saves the open database to the corresponding PackedDatabase file.
        
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises IOException: 
        :raises CancelledException:
        """

    @typing.overload
    def saveAs(self, itemName: typing.Union[java.lang.String, str], dir: jpype.protocol.SupportsPath, packedFileName: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> PackedDatabase:
        """
        Save open database to a new packed database.
        If another PackedDatabase was associated with this handle prior to this invocation
        it should be disposed to that the underlying database resources can be cleaned-up.
        
        :param java.lang.String or str itemName: 
        :param jpype.protocol.SupportsPath dir: 
        :param java.lang.String or str packedFileName: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :return: new packed Database object now associated with this handle.
        :rtype: PackedDatabase
        :raises CancelledException: if task monitor cancelled operation.
        :raises IOException: 
        :raises DuplicateFileException:
        """

    @typing.overload
    def saveAs(self, itemName: typing.Union[java.lang.String, str], dir: jpype.protocol.SupportsPath, packedFileName: typing.Union[java.lang.String, str], newDatabaseId: typing.Union[java.lang.Long, int], monitor: ghidra.util.task.TaskMonitor) -> PackedDatabase:
        """
        Save open database to a new packed database with a specified newDatabaseId.
        If another PackedDatabase was associated with this handle prior to this invocation
        it should be disposed to that the underlying database resources can be cleaned-up.
        NOTE: This method is intended for use in transforming one database to
        match another existing database.
        
        :param java.lang.String or str itemName: 
        :param jpype.protocol.SupportsPath dir: 
        :param java.lang.String or str packedFileName: 
        :param java.lang.Long or int newDatabaseId: database ID to be forced for new database or null to generate 
        new database ID
        :param ghidra.util.task.TaskMonitor monitor: 
        :return: new packed Database object now associated with this handle.
        :rtype: PackedDatabase
        :raises CancelledException: if task monitor cancelled operation.
        :raises IOException: 
        :raises DuplicateFileException:
        """

    @property
    def packedDatabase(self) -> PackedDatabase:
        ...

    @property
    def contentType(self) -> java.lang.String:
        ...


class PackedDatabaseCache(java.lang.Object):

    @typing.type_check_only
    class CachedDB(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        packedDbFilePath: typing.Final[java.lang.String]
        itemName: typing.Final[java.lang.String]
        contentType: typing.Final[java.lang.String]
        dbDir: typing.Final[java.io.File]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getCache() -> PackedDatabaseCache:
        ...

    @staticmethod
    def isEnabled() -> bool:
        ...


class VersionedDatabase(db.Database):
    """
    ``VersionedDatabase`` corresponds to a versioned database.
    """

    @typing.type_check_only
    class VerDBBufferFileManager(db.buffers.BufferFileManager):
        """
        ``VerDBBufferFileManager`` provides buffer file management
        for this versioned database instead of the DBBufferFileManager.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    LATEST_VERSION: typing.Final = -1
    DEFAULT_CHECKOUT_ID: typing.Final = -1

    @typing.overload
    def __init__(self, dbDir: jpype.protocol.SupportsPath, verDBListener: VersionedDBListener):
        """
        Constructor for an existing "Versioned" Database.
        
        :param jpype.protocol.SupportsPath dbDir: database directory
        :param VersionedDBListener verDBListener: 
        :raises IOException:
        """

    @typing.overload
    def __init__(self, dbDir: jpype.protocol.SupportsPath, srcFile: db.buffers.BufferFile, verDBListener: VersionedDBListener, checkoutId: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new "Versioned" Database from an existing srcFile.
        
        :param jpype.protocol.SupportsPath dbDir: 
        :param db.buffers.BufferFile srcFile: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises IOException: 
        :raises CancelledException:
        """

    @typing.overload
    def __init__(self, dbDir: jpype.protocol.SupportsPath, packedFile: jpype.protocol.SupportsPath, verDBListener: VersionedDBListener, checkoutId: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new "Versioned" Database from a packed database file
        
        :param jpype.protocol.SupportsPath dbDir: 
        :param jpype.protocol.SupportsPath packedFile: 
        :param VersionedDBListener verDBListener: 
        :param jpype.JLong or int checkoutId: 
        :param java.lang.String or str comment: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises IOException: 
        :raises CancelledException:
        """

    @staticmethod
    def createVersionedDatabase(dbDir: jpype.protocol.SupportsPath, bufferSize: typing.Union[jpype.JInt, int], verDBListener: VersionedDBListener, checkoutId: typing.Union[jpype.JLong, int]) -> db.buffers.LocalManagedBufferFile:
        """
        Create a new database and provide the initial buffer file for writing.
        
        :param jpype.protocol.SupportsPath dbDir: 
        :param jpype.JInt or int bufferSize: 
        :return: initial buffer file
        :rtype: db.buffers.LocalManagedBufferFile
        :raises IOException:
        """

    def dbMoved(self, dbDir: jpype.protocol.SupportsPath):
        """
        Following a move of the database directory,
        this method should be invoked if this instance will
        continue to be used.
        
        :param jpype.protocol.SupportsPath dbDir: new database directory
        """

    def deleteCurrentVersion(self):
        """
        Delete latest version.
        
        :raises IOException: if an error occurs or this is the only version.
        """

    def deleteMinimumVersion(self):
        """
        Delete oldest version.
        
        :raises IOException: if an error occurs or this is the only version.
        """

    def getCurrentVersion(self) -> int:
        """
        Returns the version number associated with the latest buffer file version.
        """

    def getMinimumVersion(self) -> int:
        """
        Returns the version number associated with the oldest buffer file version.
        """

    def open(self, version: typing.Union[jpype.JInt, int], minChangeDataVer: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> db.DBHandle:
        """
        Open a specific version of the stored database for non-update use.
        The returned handle does not support the Save operation.
        
        :param jpype.JInt or int version: database version
        :param ghidra.util.task.TaskMonitor monitor: task monitor (may be null)
        :return: database handle
        :rtype: db.DBHandle
        :raises FileInUseException: thrown if unable to obtain the required database lock(s).
        :raises IOException: thrown if IO error occurs.
        """

    def openBufferFile(self, version: typing.Union[jpype.JInt, int], minChangeDataVer: typing.Union[jpype.JInt, int]) -> db.buffers.LocalManagedBufferFile:
        """
        Open a specific version of this database for non-update use.
        
        :param jpype.JInt or int version: database version or LATEST_VERSION for current version
        :param jpype.JInt or int minChangeDataVer: the minimum database version whose change data
        should be associated with the returned buffer file.  A value of -1 indicates that
        change data is not required.
        :return: buffer file for non-update use.
        :rtype: db.buffers.LocalManagedBufferFile
        :raises IOException:
        """

    def openBufferFileForUpdate(self, checkoutId: typing.Union[jpype.JLong, int]) -> db.buffers.LocalManagedBufferFile:
        """
        Open the current version of this database for update use.
        
        :param jpype.JLong or int checkoutId: checkout ID
        :return: updateable buffer file
        :rtype: db.buffers.LocalManagedBufferFile
        :raises IOException: if update not permitted or other error occurs
        """

    def output(self, version: typing.Union[jpype.JInt, int], outputFile: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str], filetype: typing.Union[jpype.JInt, int], contentType: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Output the current version of this database to a packed storage file.
        
        :param jpype.protocol.SupportsPath outputFile: packed storage file to be written
        :param java.lang.String or str name: database name
        :param jpype.JInt or int filetype: application file type
        :param java.lang.String or str contentType: user content type
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises IOException: 
        :raises CancelledException:
        """

    @property
    def minimumVersion(self) -> jpype.JInt:
        ...

    @property
    def currentVersion(self) -> jpype.JInt:
        ...



__all__ = ["PrivateDatabase", "VersionedDBListener", "PackedDatabase", "PackedDBHandle", "PackedDatabaseCache", "VersionedDatabase"]
