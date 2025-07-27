from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import ghidra
import ghidra.app.merge
import ghidra.app.nav
import ghidra.framework.client
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.store
import ghidra.framework.store.local
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class GhidraToolState(ToolState, ghidra.app.nav.NavigatableRemovalListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, domainObject: ghidra.framework.model.DomainObject):
        ...

    def navigatableRemoved(self, nav: ghidra.app.nav.Navigatable):
        ...


class RootGhidraFolder(GhidraFolder):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DBWithUserDataContentHandler(DBContentHandler[T], typing.Generic[T]):
    """
    ``DBContentHandler`` provides an abstract ContentHandler for 
    domain object content which is stored within a database file.
    This class provides helper methods for working with database files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def removeUserDataFile(self, associatedItem: ghidra.framework.store.FolderItem, userFilesystem: ghidra.framework.store.FileSystem):
        """
        Remove user data file associated with an existing folder item.
        
        :param ghidra.framework.store.FolderItem associatedItem: associated folder item
        :param ghidra.framework.store.FileSystem userFilesystem: user data file system from which corresponding data should be removed.
        :raises IOException: if an access error occurs
        """

    def saveUserDataFile(self, associatedDomainObj: ghidra.framework.model.DomainObject, userDbh: db.DBHandle, userfs: ghidra.framework.store.FileSystem, monitor: ghidra.util.task.TaskMonitor):
        """
        Create user data file associated with existing content.
        This facilitates the lazy creation of the user data file.
        
        :param ghidra.framework.model.DomainObject associatedDomainObj: associated domain object corresponding to this content handler
        :param db.DBHandle userDbh: user data handle
        :param ghidra.framework.store.FileSystem userfs: private user data filesystem
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if an IO or access error occurs
        :raises CancelledException: if operation is cancelled by user
        """


@typing.type_check_only
class SynchronizedTransactionManager(AbstractTransactionManager):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GhidraFolder(ghidra.framework.model.DomainFolder):
    ...
    class_: typing.ClassVar[java.lang.Class]


class OpenMode(java.lang.Enum[OpenMode]):
    """
    :obj:`OpenMode` provides an instantiation mode for :obj:`DomainObject`
    implementations and internal storage adapters.  Implementation code
    may impose restrictions on which modes are supported.
    """

    class_: typing.ClassVar[java.lang.Class]
    CREATE: typing.Final[OpenMode]
    """
    Creating new domain object.
    This mode is generally not supported by :obj:`DomainObject` object constructors since
    object creation would generally have a dedicated constructor.
    """

    IMMUTABLE: typing.Final[OpenMode]
    """
    Domain object opened as an immutable instance
    """

    UPDATE: typing.Final[OpenMode]
    """
    Domain object opened for modification
    """

    UPGRADE: typing.Final[OpenMode]
    """
    Domain object opened for modification with data upgrade permitted.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> OpenMode:
        ...

    @staticmethod
    def values() -> jpype.JArray[OpenMode]:
        ...


@typing.type_check_only
class AbstractTransactionManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def setImmutable(self):
        """
        Set instance as immutable by disabling use of transactions.  Attempts to start a transaction
        will result in a :obj:`TerminatedTransactionException`.
        """


class DomainObjectAdapterDB(DomainObjectAdapter, db.util.ErrorHandler):
    """
    Database version of the DomainObjectAdapter.  Adds the
    concept of starting a transaction before a change is made to the
    domain object and ending the transaction. The transaction allows for
    undo/redo changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addSynchronizedDomainObject(self, domainObj: ghidra.framework.model.DomainObject):
        """
        Synchronize the specified domain object with this domain object
        using a shared transaction manager.  If either or both is already shared,
        a transition to a single shared transaction manager will be
        performed.
        
        :param ghidra.framework.model.DomainObject domainObj: 
        :raises LockException: if lock or open transaction is active on either
        this or the specified domain object
        """

    def addTransactionListener(self, listener: ghidra.framework.model.TransactionListener):
        """
        Adds the given transaction listener to this domain object
        
        :param ghidra.framework.model.TransactionListener listener: the new transaction listener to add
        """

    def flushWriteCache(self):
        """
        Flush any pending database changes.
        This method will be invoked by the transaction manager
        prior to closing a transaction.
        """

    def getChangeSet(self) -> DomainObjectDBChangeSet:
        """
        Returns the change set corresponding to all unsaved changes in this domain object.
        
        :return: the change set corresponding to all unsaved changes in this domain object
        :rtype: DomainObjectDBChangeSet
        """

    def getDBHandle(self) -> db.DBHandle:
        """
        Returns the open handle to the underlying database.
        """

    def getOptionsNames(self) -> java.util.List[java.lang.String]:
        """
        Returns all properties lists contained by this domain object.
        
        :return: all property lists contained by this domain object.
        :rtype: java.util.List[java.lang.String]
        """

    def getSynchronizedDomainObjects(self) -> jpype.JArray[ghidra.framework.model.DomainObject]:
        """
        Return array of all domain objects synchronized with a
        shared transaction manager.
        
        :return: returns array of synchronized domain objects or
        null if this domain object is not synchronized with others.
        :rtype: jpype.JArray[ghidra.framework.model.DomainObject]
        """

    def getUndoStackDepth(self) -> int:
        """
        Returns the undo stack depth.
        (The number of items on the undo stack)
        This method is for JUnits.
        
        :return: the undo stack depth
        :rtype: int
        """

    def invalidateWriteCache(self):
        """
        Invalidate (i.e., clear) any pending database changes not yet written.
        This method will be invoked by the transaction manager
        prior to aborting a transaction.
        """

    def releaseSynchronizedDomainObject(self):
        """
        Release this domain object from a shared transaction manager.  If
        this object has not been synchronized with others via a shared
        transaction manager, this method will have no affect.
        
        :raises LockException: if lock or open transaction is active
        """

    def removeTransactionListener(self, listener: ghidra.framework.model.TransactionListener):
        """
        Removes the given transaction listener from this domain object.
        
        :param ghidra.framework.model.TransactionListener listener: the transaction listener to remove
        """

    @property
    def undoStackDepth(self) -> jpype.JInt:
        ...

    @property
    def synchronizedDomainObjects(self) -> jpype.JArray[ghidra.framework.model.DomainObject]:
        ...

    @property
    def optionsNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def dBHandle(self) -> db.DBHandle:
        ...

    @property
    def changeSet(self) -> DomainObjectDBChangeSet:
        ...


@typing.type_check_only
class LockingTaskMonitor(ghidra.util.task.TaskMonitor):

    @typing.type_check_only
    class MyTaskDialog(ghidra.util.task.TaskDialog):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class DomainFileProxy(ghidra.framework.model.DomainFile):
    """
    Implements the DomainFile interface for DomainObjects that are not currently
    associated with any real DomainFile. This class enforces the sharing of
    objects between tools.  After the first tool gets the implementation, all
    other gets() just get the same instance.  This class also keeps track of
    which tools are using a its domain object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], doa: DomainObjectAdapter):
        ...

    def isInUse(self) -> bool:
        ...

    def isUsedBy(self, consumer: java.lang.Object) -> bool:
        ...

    @property
    def inUse(self) -> jpype.JBoolean:
        ...

    @property
    def usedBy(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class DomainFileIndex(ghidra.framework.model.DomainFolderChangeListener):
    """
    Helper class to maintain mapping of fileID's to DomainFile's.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DomainFolderChangeListenerList(ghidra.framework.model.DomainFolderChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def clearAll(self):
        ...


class DefaultProjectData(ghidra.framework.model.ProjectData):
    """
    Helper class to manage files within a project.
    """

    @typing.type_check_only
    class MyFileSystemListener(ghidra.framework.store.FileSystemListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MANGLED_DATA_FOLDER_NAME: typing.Final = "data"
    INDEXED_DATA_FOLDER_NAME: typing.Final = "idata"
    USER_FOLDER_NAME: typing.Final = "user"
    VERSIONED_FOLDER_NAME: typing.Final = "versioned"
    SERVER_NAME: typing.Final = "SERVER"
    PORT_NUMBER: typing.Final = "PORT_NUMBER"
    REPOSITORY_NAME: typing.Final = "REPOSITORY_NAME"
    OWNER: typing.Final = "OWNER"

    @typing.overload
    def __init__(self, localStorageLocator: ghidra.framework.model.ProjectLocator, isInWritableProject: typing.Union[jpype.JBoolean, bool], resetOwner: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for existing projects.
        
        :param ghidra.framework.model.ProjectLocator localStorageLocator: the location of the project
        :param jpype.JBoolean or bool isInWritableProject: true if project content is writable, false if project is read-only
        :param jpype.JBoolean or bool resetOwner: true to reset the project owner
        :raises IOException: if an i/o error occurs
        :raises NotOwnerException: if inProject is true and user is not owner
        :raises LockException: if ``isInWritableProject`` is true and unable to establish project 
        write lock (i.e., project in-use)
        :raises FileNotFoundException: if project directory not found
        """

    @typing.overload
    def __init__(self, localStorageLocator: ghidra.framework.model.ProjectLocator, repository: ghidra.framework.client.RepositoryAdapter, isInWritableProject: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for a new project.
        
        :param ghidra.framework.model.ProjectLocator localStorageLocator: the location of the project
        :param ghidra.framework.client.RepositoryAdapter repository: a repository if this is a shared project or null if it is a private project
        :param jpype.JBoolean or bool isInWritableProject: true if project content is writable, false if project is read-only
        :raises IOException: if an i/o error occurs
        :raises LockException: if ``isInWritableProject`` is true and unable to establish project 
        lock (i.e., project in-use)
        """

    def findCheckedOutFiles(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.framework.model.DomainFile]:
        """
        Find all project files which are currently checked-out
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor (no progress updates)
        :return: list of current checkout files
        :rtype: java.util.List[ghidra.framework.model.DomainFile]
        :raises IOException: if IO error occurs
        :raises CancelledException: if task cancelled
        """

    def findOpenFiles(self, list: java.util.List[ghidra.framework.model.DomainFile]):
        """
        Finds all changed domain files and appends them to the specified list.
        
        :param java.util.List[ghidra.framework.model.DomainFile] list: the list to receive the changed domain files
        """

    def getOwner(self) -> str:
        """
        Returns the owner of the project that is associated with this 
        DefaultProjectData.  A value of null indicates an old multiuser
        project.
        
        :return: the owner of the project
        :rtype: str
        """

    def getPrivateFileSystem(self) -> ghidra.framework.store.FileSystem:
        ...

    def getProjectDir(self) -> java.io.File:
        ...

    def getProjectDisposalMonitor(self) -> ghidra.util.task.TaskMonitor:
        """
        Get monitor which will be cancelled if project is closed
        
        :return: cancel monitor
        :rtype: ghidra.util.task.TaskMonitor
        """

    @staticmethod
    def getUserDataFilename(associatedFileID: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the standard user data filename associated with the specified file ID.
        
        :param java.lang.String or str associatedFileID: the file id
        :return: user data filename
        :rtype: str
        """

    def hasInvalidCheckouts(self, checkoutList: java.util.List[ghidra.framework.model.DomainFile], newRepository: ghidra.framework.client.RepositoryAdapter, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Determine if any domain files listed does not correspond to a checkout in the specified 
        newRespository.
        
        :param java.util.List[ghidra.framework.model.DomainFile] checkoutList: project domain files to check
        :param ghidra.framework.client.RepositoryAdapter newRepository: repository to check against before updating
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if one or more files are not valid checkouts in newRepository
        :rtype: bool
        :raises IOException: if IO error occurs
        :raises CancelledException: if task cancelled
        """

    def isClosed(self) -> bool:
        ...

    def isDisposed(self) -> bool:
        ...

    @staticmethod
    def isLocked(locator: ghidra.framework.model.ProjectLocator) -> bool:
        """
        Determine if the specified project location currently has a write lock.
        
        :param ghidra.framework.model.ProjectLocator locator: project storage locator
        :return: true if project data current has write-lock else false
        :rtype: bool
        """

    @staticmethod
    def readProjectProperties(projectDir: jpype.protocol.SupportsPath) -> java.util.Properties:
        """
        Read the contents of the project properties file to include the following values if relavent:
        OWNER, SERVER, REPOSITORY_NAME, PORT_NUMBER
        
        :param jpype.protocol.SupportsPath projectDir: project directory (*.rep)
        :return: project properties or null if invalid project directory specified
        :rtype: java.util.Properties
        """

    def releaseDomainFiles(self, consumer: java.lang.Object):
        ...

    def removeFromIndex(self, fileID: typing.Union[java.lang.String, str]):
        """
        Remove specified fileID from index.
        
        :param java.lang.String or str fileID: the file ID
        """

    def updateFileIndex(self, fileData: GhidraFileData):
        """
        Update the file index for the specified file data
        
        :param GhidraFileData fileData: file data
        """

    @property
    def projectDisposalMonitor(self) -> ghidra.util.task.TaskMonitor:
        ...

    @property
    def projectDir(self) -> java.io.File:
        ...

    @property
    def owner(self) -> java.lang.String:
        ...

    @property
    def privateFileSystem(self) -> ghidra.framework.store.FileSystem:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class SynchronizedTransaction(ghidra.framework.model.TransactionInfo):
    """
    ``SynchronizedTransaction`` represents an atomic undoable operation performed
    on a synchronized set of domain objects.
    """

    class_: typing.ClassVar[java.lang.Class]


class LinkHandler(DBContentHandler[T], typing.Generic[T]):
    """
    NOTE:  ALL ContentHandler implementations MUST END IN "ContentHandler".  If not,
    the ClassSearcher will not find them.
     
    ``LinkHandler`` defines an application interface for handling domain files which are
    shortcut links to another supported content type.
    """

    class_: typing.ClassVar[java.lang.Class]
    URL_METADATA_KEY: typing.Final = "link.url"
    LINK_ICON: typing.Final[javax.swing.Icon]

    def __init__(self):
        ...

    def getIcon(self) -> javax.swing.Icon:
        """
        Get the base icon for this link-file which does not include the 
        link overlay icon.
        """

    @staticmethod
    def getURL(linkFile: ghidra.framework.model.DomainFile) -> java.net.URL:
        """
        Get the link URL which corresponds to the specified link file.
        See :meth:`DomainFile.isLinkFile() <DomainFile.isLinkFile>`.
        
        :param ghidra.framework.model.DomainFile linkFile: link-file domain file
        :return: link URL
        :rtype: java.net.URL
        :raises MalformedURLException: if link is bad or unsupported.
        :raises IOException: if IO error or supported link file not specified
        """

    @property
    def icon(self) -> javax.swing.Icon:
        ...


@typing.type_check_only
class GhidraFolderData(java.lang.Object):
    """
    :obj:`GhidraFolderData` provides the managed object which represents a project folder that 
    corresponds to matched folder paths across both a versioned and private 
    filesystem and viewed as a single folder at the project level.  This class closely mirrors the
    :obj:`DomainFolder` interface and is used by the :obj:`GhidraFolder` implementation; both of which
    represent immutable folder references.  Changes made to this folder's name or path are not reflected 
    in old :obj:`DomainFolder` instances and must be re-instantiated following such a change.  
    Any long-term retention of :obj:`DomainFolder` and :obj:`DomainFile` instances requires an 
    appropriate change listener to properly discard/reacquire such instances.
    """

    class_: typing.ClassVar[java.lang.Class]

    def containsFile(self, fileName: typing.Union[java.lang.String, str]) -> bool:
        """
        Check for existence of file.  If folder previously visited, rely on fileDataCache
        
        :param java.lang.String or str fileName: the name of the file to look for
        :return: true if this folder contains the fileName, else false
        :rtype: bool
        :raises IOException: if an IO error occurs while checking for file existance
        """


class DomainObjectDBChangeSet(db.DBChangeSet):
    """
    ``DomainObjectDBChangeSet`` extends ``DBChangeSet`` 
    providing methods which facilitate transaction synchronization with the domain object's DBHandle.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def clearUndo(self, isCheckedOut: typing.Union[jpype.JBoolean, bool]):
        """
        Resets the change sets after a save.
        """

    @typing.overload
    def clearUndo(self):
        """
        Clears the undo/redo stack.
        """

    def endTransaction(self, commit: typing.Union[jpype.JBoolean, bool]):
        """
        End change data transaction.
        
        :param jpype.JBoolean or bool commit: if true transaction data is committed, 
                    otherwise transaction data is discarded
        """

    def redo(self):
        """
        Redo the change data transaction associated the last Undo.
        """

    def setMaxUndos(self, maxUndos: typing.Union[jpype.JInt, int]):
        """
        Set the undo/redo stack depth
        
        :param jpype.JInt or int maxUndos: the maximum numbder of undo
        """

    def startTransaction(self):
        """
        Start change data transaction.
        """

    def undo(self):
        """
        Undo the last change data transaction
        """


class GhidraFileData(java.lang.Object):
    """
    :obj:`GhidraFileData` provides the managed object which represents a project file that 
    corresponds to matched :obj:`FolderItem` pair across both a versioned and private 
    filesystem and viewed as a single file at the project level.  This class closely mirrors the
    :obj:`DomainFile` interface and is used by the :obj:`GhidraFile` implementation; both of which
    represent immutable file references.  Changes made to this file's name or path are not reflected 
    in old :obj:`DomainFile` instances and must be re-instantiated following such a change.  
    Any long-term retention of :obj:`DomainFolder` and :obj:`DomainFile` instances requires an 
    appropriate change listener to properly discard/reacquire such instances.
    """

    @typing.type_check_only
    class GenericDomainObjectDB(DomainObjectAdapterDB):

        class_: typing.ClassVar[java.lang.Class]

        def release(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    UNSUPPORTED_FILE_ICON: typing.Final[javax.swing.Icon]
    CHECKED_OUT_ICON: typing.Final[javax.swing.Icon]
    CHECKED_OUT_EXCLUSIVE_ICON: typing.Final[javax.swing.Icon]
    HIJACKED_ICON: typing.Final[javax.swing.Icon]
    VERSION_ICON: typing.Final[javax.swing.Icon]
    READ_ONLY_ICON: typing.Final[javax.swing.Icon]
    NOT_LATEST_CHECKED_OUT_ICON: typing.Final[javax.swing.Icon]


@typing.type_check_only
class DomainObjectDBTransaction(ghidra.framework.model.TransactionInfo):
    """
    ``DomainObjectDBTransaction`` represents an atomic undoable operation performed
    on a single domain object.
    """

    @typing.type_check_only
    class TransactionEntry(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def hasCommittedDBTransaction(self) -> bool:
        """
        Returns true if this fully committed transaction has a corresponding 
        database transaction/checkpoint.
        """


class DBContentHandler(ContentHandler[T], typing.Generic[T]):
    """
    ``DBContentHandler`` provides an abstract ContentHandler for 
    domain object content which is stored within a database file.
    This class provides helper methods for working with database files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ToolStateFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createToolState(tool: ghidra.framework.plugintool.PluginTool, domainObject: ghidra.framework.model.DomainObject) -> ToolState:
        ...


class GhidraFile(ghidra.framework.model.DomainFile):

    class_: typing.ClassVar[java.lang.Class]

    def getUserFileSystem(self) -> ghidra.framework.store.local.LocalFileSystem:
        ...

    @property
    def userFileSystem(self) -> ghidra.framework.store.local.LocalFileSystem:
        ...


@typing.type_check_only
class OptionsDB(ghidra.framework.options.AbstractOptions):
    """
    Database implementation of :obj:`Option`
    """

    @typing.type_check_only
    class DBOption(ghidra.framework.options.Option):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class DefaultCheckinHandler(CheckinHandler):
    """
    ``DefaultCheckinHandler`` provides a simple
    check-in handler for use with 
    :meth:`DomainFile.checkin(CheckinHandler, ghidra.util.task.TaskMonitor) <DomainFile.checkin>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comment: typing.Union[java.lang.String, str], keepCheckedOut: typing.Union[jpype.JBoolean, bool], createKeepFile: typing.Union[jpype.JBoolean, bool]):
        ...


class ConvertFileSystem(ghidra.GhidraLaunchable):

    class MessageListener(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def println(self, string: typing.Union[java.lang.String, str]):
            ...


    class ConvertFileSystemException(java.io.IOException):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            ...

        @typing.overload
        def __init__(self, message: typing.Union[java.lang.String, str]):
            ...

        @typing.overload
        def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def convertProject(dir: jpype.protocol.SupportsPath, msgListener: ConvertFileSystem.MessageListener):
        ...


@typing.type_check_only
class DomainObjectChangeSupport(java.lang.Object):
    """
    A class to queue and send :obj:`DomainObjectChangeRecord` events.
     
    
    For simplicity, this class requires all mutations to internal data structures to be locked using
    the internal write lock.  Clients are not required to use any synchronization when using this
    class.
     
    
    Internally, events are queued and will be fired on a timer.
    """

    @typing.type_check_only
    class EventNotification(java.lang.Object):
        """
        This class allows us to bind the given event with the given listeners.  This is used to
        send events to the correct listeners as listeners are added.  In other words, new listeners
        will not receive pre-existing buffered events.   Also, using this class allows us to ensure
        events are processed linearly by processing each of these notification objects linearly
        from a single queue.
        
        Note: this class shall perform no synchronization; that shall be handled by the client
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LinkedGhidraSubFolder(ghidra.framework.model.LinkedDomainFolder):
    """
    ``LinkedGhidraSubFolder`` corresponds to a :obj:`DomainFolder` contained within a
    :obj:`LinkedGhidraFolder` or another ``LinkedGhidraSubFolder``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLinkedFileNoError(self, name: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
        """
        Get the true file within this linked folder.
        
        :param java.lang.String or str name: file name
        :return: file or null if not found or error occurs
        :rtype: ghidra.framework.model.DomainFile
        """

    def getLinkedPathname(self) -> str:
        """
        Get the pathname of this folder within the linked-project/repository
        
        :return: absolute linked folder path within the linked-project/repository
        :rtype: str
        """

    @property
    def linkedPathname(self) -> java.lang.String:
        ...

    @property
    def linkedFileNoError(self) -> ghidra.framework.model.DomainFile:
        ...


class ToolState(java.lang.Object):
    """
    Container object for the state of the tool to hold an XML element.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, domainObject: ghidra.framework.model.DomainObject):
        """
        Construct a new tool state.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool's state to save
        :param ghidra.framework.model.DomainObject domainObject: the object containing the tool state
        """

    def getAfterState(self, domainObject: ghidra.framework.model.DomainObject):
        ...

    def restoreAfterRedo(self, domainObject: ghidra.framework.model.DomainObject):
        """
        Restore the tool's state after an undo
        """

    def restoreAfterUndo(self, domainObject: ghidra.framework.model.DomainObject):
        """
        Restore the tool's state after an undo
        """


class DomainObjectMergeManager(ghidra.app.merge.MergeProgressModifier):
    """
    An interface to allow merging of domain objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearStatusText(self):
        """
        Clear the status text on the merge dialog.
        """

    def merge(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Merge domain objects and resolve any conflicts.
        
        :return: true if the merge process completed successfully
        :rtype: bool
        :raises CancelledException: if the user canceled the merge process
        """

    def setApplyEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Enable the apply button according to the "enabled" parameter.
        """

    def setResolveInformation(self, infoType: typing.Union[java.lang.String, str], infoObject: java.lang.Object):
        """
        Sets the resolve information object for the indicated standardized name.
        This is how information is passed between merge managers.
        
        :param java.lang.String or str infoType: the string indicating the type of resolve information
        :param java.lang.Object infoObject: the object for the named string. This information is
        determined by the merge manager that creates it.
        
        .. seealso::
        
            | :obj:`ghidra.app.merge.MergeManager.getResolveInformation(String)`MergeManager.getResolveInformation(String)
        """

    def setStatusText(self, msg: typing.Union[java.lang.String, str]):
        """
        Set the status text on the merge dialog.
        """

    def showComponent(self, comp: javax.swing.JComponent, componentID: typing.Union[java.lang.String, str], helpLoc: ghidra.util.HelpLocation):
        """
        Show the component that is used to resolve conflicts. This method
        is called by the MergeResolvers when user input is required. If the
        component is not null, this method blocks until the user either 
        cancels the merge process or resolves a conflict. If comp is null,
        then the default component is displayed, and the method does not
        wait for user input.
        
        :param javax.swing.JComponent comp: component to show; if component is null, show the 
        default component and do not block
        :param java.lang.String or str componentID: id or name for the component
        """


class FolderLinkContentHandler(LinkHandler[NullFolderDomainObject]):
    """
    ``FolderLinkContentHandler`` provide folder-link support.  
    Implementation relies on :meth:`AppInfo.getActiveProject() <AppInfo.getActiveProject>` to provide life-cycle 
    management for related transient-projects opened while following folder-links.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.ClassVar[FolderLinkContentHandler]
    FOLDER_LINK_CONTENT_TYPE: typing.Final = "FolderLink"

    def __init__(self):
        ...

    @staticmethod
    def getReadOnlyLinkedFolder(folderLinkFile: ghidra.framework.model.DomainFile) -> LinkedGhidraFolder:
        """
        Get linked domain folder
        
        :param ghidra.framework.model.DomainFile folderLinkFile: folder-link file.
        :return: :obj:`LinkedGhidraFolder` referenced by specified folder-link file or null if 
        folderLinkFile content type is not FolderLink.
        :rtype: LinkedGhidraFolder
        :raises IOException: if an IO or folder item access error occurs
        """


class TransientDataManager(java.lang.Object):
    """
    Simple static class to keep track of transient domain file/domain objects.
    When new domain objects are created, they may not have an associated DomainFile.
    In this case, a DomainFileProxy is created to contain it.  DomainFileProxy objects
    will add themselves to this Manager whenever a tool is using the associated
    DomainObject and will remove itself all the tools have released the domainObject.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def addTransient(domainFile: DomainFileProxy):
        """
        Adds the given transient domain file to the list.
        
        :param DomainFileProxy domainFile: the transient domain file to add to the list
        """

    @staticmethod
    def clearAll():
        """
        Removes all transients from the list.
        """

    @staticmethod
    def getTransients(l: java.util.List[ghidra.framework.model.DomainFile]):
        """
        Populates the given array list with all the transients.
        
        :param java.util.List[ghidra.framework.model.DomainFile] l: the list populate with the transients
        """

    @staticmethod
    def releaseFiles(consumer: java.lang.Object):
        """
        Releases all files for the given consumer.
        
        :param java.lang.Object consumer: the domain file consumer
        """

    @staticmethod
    def removeTransient(domainFile: DomainFileProxy):
        """
        Removes the given transient domain file from the list.
        
        :param DomainFileProxy domainFile: the transient domain file to remove
        """


class URLLinkObject(DomainObjectAdapterDB):
    """
    ``DomainObjectAdapterLink`` object provides a Ghidra URL (see :obj:`GhidraURL`) wrapper
    where the URL is intended to refer to a :obj:`DomainFile` within another local or remote
    project/repository.  Link files which correspond to this type of :obj:`DomainObject` are
    not intended to be modified and should be created or deleted.  A checkout may be used when
    an offline copy is required but otherwise serves no purpose since a modification and checkin
    is not supported.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], ghidraUrl: java.net.URL, consumer: java.lang.Object):
        """
        Constructs a new link file object
        
        :param java.lang.String or str name: link name
        :param java.net.URL ghidraUrl: link URL
        :param java.lang.Object consumer: the object that is using this program.
        :raises IOException: if there is an error accessing the database or invalid URL specified.
        """

    @typing.overload
    def __init__(self, dbh: db.DBHandle, consumer: java.lang.Object):
        """
        Constructs a link file object from a DBHandle (read-only)
        
        :param db.DBHandle dbh: a handle to an open program database.
        :param java.lang.Object consumer: the object that keeping the program open.
        :raises IOException: if an error accessing the database occurs.
        """

    def getLink(self) -> java.net.URL:
        """
        Get link URL
        
        :return: link URL
        :rtype: java.net.URL
        """

    @property
    def link(self) -> java.net.URL:
        ...


@typing.type_check_only
class MetadataManager(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LinkedGhidraFolder(LinkedGhidraSubFolder):
    """
    ``LinkedGhidraFolder`` provides the base :obj:`LinkedDomainFolder` implementation which
    corresponds to a project folder-link (see :obj:`FolderLinkContentHandler`).
    """

    class_: typing.ClassVar[java.lang.Class]
    FOLDER_LINK_CLOSED_ICON: typing.ClassVar[javax.swing.Icon]
    FOLDER_LINK_OPEN_ICON: typing.ClassVar[javax.swing.Icon]

    def getProjectURL(self) -> java.net.URL:
        """
        Get the Ghidra URL of the project/repository folder referenced by this object
        
        :return: Ghidra URL of the project/repository folder referenced by this object
        :rtype: java.net.URL
        """

    @property
    def projectURL(self) -> java.net.URL:
        ...


@typing.type_check_only
class DomainObjectTransactionManager(AbstractTransactionManager):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ContentHandler(ghidra.util.classfinder.ExtensionPoint, typing.Generic[T]):
    """
    NOTE:  ALL ContentHandler implementations MUST END IN "ContentHandler".  If not,
    the ClassSearcher will not find them.
     
    ``ContentHandler`` defines an application interface for converting 
    between a specific domain object implementation and folder item storage. 
    This interface also defines a method which provides an appropriate icon 
    corresponding to the content.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN_CONTENT: typing.Final = "Unknown-File"
    MISSING_CONTENT: typing.Final = "Missing-File"

    def canResetDBSourceFile(self) -> bool:
        """
        Determine if this content handler supports the use of 
        :meth:`resetDBSourceFile(FolderItem, DomainObjectAdapterDB) <.resetDBSourceFile>` .
         
        
        A versioned :obj:`domain object <DomainObjectAdapterDB>` open for update may have its 
        underlying database reset to the latest buffer file version:
         
        1. The :meth:`resetDBSourceFile(FolderItem, DomainObjectAdapterDB) <.resetDBSourceFile>` method is
        invoked (synchronized on filesystem) to reset the underlying database source file and
        and any corresponding change sets held by the specified domain object to the latest
        version,
        2. afterwhich the caller must :meth:`invalidate <DomainObjectAdapter.invalidate>` the domain 
        object instance which will clear all caches and generate a:obj:`DomainObjectEvent.RESTORED` 
        event.
        
        
        :return: true if this content handler supports DB source file replacement, else false
        :rtype: bool
        """

    def createFile(self, fs: ghidra.framework.store.FileSystem, userfs: ghidra.framework.store.FileSystem, path: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], domainObject: ghidra.framework.model.DomainObject, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Creates a new folder item within a specified file-system.
        If fs is versioned, the resulting item is marked as checked-out
        within the versioned file-system.  The specified domainObj
        will become associated with the newly created database.
        
        :param ghidra.framework.store.FileSystem fs: the file system in which to create the folder item
        :param ghidra.framework.store.FileSystem userfs: file system which contains associated user data
        :param java.lang.String or str path: the path of the folder item
        :param java.lang.String or str name: the name of the new folder item
        :param ghidra.framework.model.DomainObject domainObject: the domain object to store in the newly created folder item
        :param ghidra.util.task.TaskMonitor monitor: the monitor that allows the user to cancel
        :return: checkout ID for new item
        :rtype: int
        :raises IOException: if an IO error occurs or an unsupported ``domainObject`` 
        implementation is specified.
        :raises InvalidNameException: if the specified name contains invalid characters
        :raises CancelledException: if the user cancels
        """

    def getChangeSet(self, versionedFolderItem: ghidra.framework.store.FolderItem, olderVersion: typing.Union[jpype.JInt, int], newerVersion: typing.Union[jpype.JInt, int]) -> ghidra.framework.model.ChangeSet:
        """
        Returns the object change data which includes changes made to the specified
        olderVersion through to the specified newerVersion.
        
        :param ghidra.framework.store.FolderItem versionedFolderItem: versioned folder item
        :param jpype.JInt or int olderVersion: the older version number
        :param jpype.JInt or int newerVersion: the newer version number
        :return: the set of changes that were made
        :rtype: ghidra.framework.model.ChangeSet
        :raises VersionException: if a database version change prevents reading of data.
        :raises IOException: if an IO or folder item access error occurs or change set was 
        produced by newer version of software and can not be read
        """

    def getContentType(self) -> str:
        """
        Returns a unique content-type identifier
        
        :return: content type identifier for associated domain object(s).
        :rtype: str
        """

    def getContentTypeDisplayString(self) -> str:
        """
        A string that is meant to be presented to the user.
        
        :return: user friendly content type for associated domain object(s).
        :rtype: str
        """

    def getDefaultToolName(self) -> str:
        """
        Returns the name of the default tool/template that should be used to open this content type.
        
        :return: associated default tool name for this content type
        :rtype: str
        """

    def getDomainObject(self, item: ghidra.framework.store.FolderItem, userfs: ghidra.framework.store.FileSystem, checkoutId: typing.Union[jpype.JLong, int], okToUpgrade: typing.Union[jpype.JBoolean, bool], okToRecover: typing.Union[jpype.JBoolean, bool], consumer: java.lang.Object, monitor: ghidra.util.task.TaskMonitor) -> T:
        """
        Open a folder item for update.  Changes made to the returned object may be
        saved to the original folder item.
        
        :param ghidra.framework.store.FolderItem item: stored folder item
        :param ghidra.framework.store.FileSystem userfs: file system which contains associated user data
        :param jpype.JLong or int checkoutId: an appropriate checout ID required to update the specified 
        folder item.
        :param jpype.JBoolean or bool okToUpgrade: if true a version upgrade to the content will be done
        if necessary.
        :param jpype.JBoolean or bool okToRecover: if true an attempt to recover any unsaved changes resulting from
        a crash will be attempted.
        :param java.lang.Object consumer: consumer of the returned object
        :param ghidra.util.task.TaskMonitor monitor: cancelable task monitor
        :return: updateable domain object
        :rtype: T
        :raises IOException: if an IO or folder item access error occurs
        :raises CancelledException: if operation is cancelled by user
        :raises VersionException: if unable to handle file content due to version 
        difference which could not be handled.
        """

    def getDomainObjectClass(self) -> java.lang.Class[T]:
        """
        Returns domain object implementation class supported.
        
        :return: implementation class for the associated :obj:`DomainObjectAdapter` implementation.
        :rtype: java.lang.Class[T]
        """

    def getIcon(self) -> javax.swing.Icon:
        """
        Returns the Icon associated with this handlers content type.
        
        :return: base icon to be used for a :obj:`DomainFile` with the associated content type.
        :rtype: javax.swing.Icon
        """

    def getImmutableObject(self, item: ghidra.framework.store.FolderItem, consumer: java.lang.Object, version: typing.Union[jpype.JInt, int], minChangeVersion: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> T:
        """
        Open a folder item for immutable use.  If any changes are attempted on the
        returned object, an IllegalStateException state exception may be thrown.
        
        :param ghidra.framework.store.FolderItem item: stored folder item
        :param java.lang.Object consumer: consumer of the returned object
        :param jpype.JInt or int version: version of the stored folder item to be opened.
        DomainFile.DEFAULT_VERSION (-1) should be specified when not opening a specific
        file version.
        :param jpype.JInt or int minChangeVersion: the minimum version which should be included in the 
        change set for the returned object. A value of -1 indicates the default change
        set.
        :param ghidra.util.task.TaskMonitor monitor: the monitor that allows the user to cancel
        :return: immutable domain object
        :rtype: T
        :raises IOException: if an IO or folder item access error occurs
        :raises CancelledException: if operation is cancelled by user
        :raises VersionException: if unable to handle file content due to version 
        difference which could not be handled.
        """

    def getLinkHandler(self) -> LinkHandler[typing.Any]:
        """
        If linking is supported return an instanceof the appropriate :obj:`LinkHandler`.
        
        :return: corresponding link handler or null if not supported.
        :rtype: LinkHandler[typing.Any]
        """

    def getMergeManager(self, resultsObj: ghidra.framework.model.DomainObject, sourceObj: ghidra.framework.model.DomainObject, originalObj: ghidra.framework.model.DomainObject, latestObj: ghidra.framework.model.DomainObject) -> DomainObjectMergeManager:
        """
        Get an instance of a suitable merge manager to be used during the merge of a Versioned 
        object which has been modified by another user since it was last merged
        or checked-out.
        
        :param ghidra.framework.model.DomainObject resultsObj: object to which merge results should be written
        :param ghidra.framework.model.DomainObject sourceObj: object which contains user's changes to be merged
        :param ghidra.framework.model.DomainObject originalObj: object which corresponds to checked-out version state
        :param ghidra.framework.model.DomainObject latestObj: object which corresponds to latest version with which
        the sourceObj must be merged.
        :return: merge manager
        :rtype: DomainObjectMergeManager
        """

    def getReadOnlyObject(self, item: ghidra.framework.store.FolderItem, version: typing.Union[jpype.JInt, int], okToUpgrade: typing.Union[jpype.JBoolean, bool], consumer: java.lang.Object, monitor: ghidra.util.task.TaskMonitor) -> T:
        """
        Open a folder item for read-only use.  While changes are permitted on the
        returned object, the original folder item may not be overwritten / updated.
        
        :param ghidra.framework.store.FolderItem item: stored folder item
        :param jpype.JInt or int version: version of the stored folder item to be opened.
        DomainFile.DEFAULT_VERSION should be specified when not opening a specific
        file version.
        :param jpype.JBoolean or bool okToUpgrade: if true a version upgrade to the content will be done
        if necessary.
        :param java.lang.Object consumer: consumer of the returned object
        :param ghidra.util.task.TaskMonitor monitor: the monitor that allows the user to cancel
        :return: read-only domain object
        :rtype: T
        :raises IOException: if an IO or folder item access error occurs
        :raises CancelledException: if operation is cancelled by user
        :raises VersionException: if unable to handle file content due to version 
        difference which could not be handled.
        """

    def isPrivateContentType(self) -> bool:
        """
        Returns true if the content type is always private 
        (i.e., can not be added to the versioned filesystem).
        
        :return: true if private content type, else false
        :rtype: bool
        """

    def resetDBSourceFile(self, item: ghidra.framework.store.FolderItem, domainObj: DomainObjectAdapterDB):
        """
        Reset the database for the specified domain object to its latest buffer file version.
        It is very important that the specified folder item matches the item which was used to 
        originally open the specified domain object. This method should be invoked with a 
        filesystem lock.
         
        
        Following the invocation of this method, the specified domain object should be 
        :meth:`invalidated <DomainObjectAdapter.invalidate>` without a filesystem lock.
        
        :param ghidra.framework.store.FolderItem item: local versioned database folder item currently checked-out. An error will be
        thrown if not an instanceof LocalDatabaseItem.  This should always be the case for an item
        which has just processed a versioning action with a retained checkout (e.g., checkin,
        merge, add-to-version-control).
        :param DomainObjectAdapterDB domainObj: domain object which is currently open for update
        :raises IOException: if an IO error occurs
        :raises IllegalArgumentException: if invalid or unsupported arguments are provided
        """

    @property
    def defaultToolName(self) -> java.lang.String:
        ...

    @property
    def linkHandler(self) -> LinkHandler[typing.Any]:
        ...

    @property
    def privateContentType(self) -> jpype.JBoolean:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def domainObjectClass(self) -> java.lang.Class[T]:
        ...

    @property
    def contentType(self) -> java.lang.String:
        ...

    @property
    def contentTypeDisplayString(self) -> java.lang.String:
        ...


class DomainObjectFileListener(java.lang.Object):
    """
    Listener for when the :obj:`DomainFile` associated with a :obj:`DomainObject` changes, such
    as when a 'Save As' action occurs. Unlike DomainObject events, these callbacks are not buffered
    and happen immediately when the DomainFile is changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def domainFileChanged(self, domainObject: ghidra.framework.model.DomainObject):
        """
        Notification that the DomainFile for the given DomainObject has changed
        
        :param ghidra.framework.model.DomainObject domainObject: the DomainObject whose DomainFile changed
        """


@typing.type_check_only
class NullFolderDomainObject(DomainObjectAdapterDB):
    """
    Dummy domain object to satisfy :meth:`FolderLinkContentHandler.getDomainObjectClass() <FolderLinkContentHandler.getDomainObjectClass>`
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ProjectLock(java.lang.Object):
    """
    A simple delegate for creating and using locks in Ghidra.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, projectLocator: ghidra.framework.model.ProjectLocator):
        ...


class CheckinHandler(java.lang.Object):
    """
    ``CheckinHandler`` facilitates application callbacks during
    the check-in of a DomainFile.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createKeepFile(self) -> bool:
        """
        Returns true if the system should create a keep file copy of the user's check-in file.
        
        :raises CancelledException: thrown if user cancels the check-in
        """

    def getComment(self) -> str:
        """
        Returns the check-in comment.
        
        :return: the check-in comment
        :rtype: str
        :raises CancelledException: thrown if user cancels the check-in
        """

    def keepCheckedOut(self) -> bool:
        """
        Returns true if check-out state should be retained.
        
        :return: true if check-out state should be retained
        :rtype: bool
        :raises CancelledException: thrown if user cancels the check-in
        """

    @property
    def comment(self) -> java.lang.String:
        ...


class DomainObjectAdapter(ghidra.framework.model.DomainObject):
    """
    An abstract class that provides default behavior for DomainObject(s), specifically it handles
    listeners and change status; the derived class must provide the getDescription() method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def checkExclusiveAccess(self):
        ...

    def fireEvent(self, ev: ghidra.framework.model.DomainObjectChangeRecord):
        """
        Fires the specified event.
        
        :param ghidra.framework.model.DomainObjectChangeRecord ev: event to fire
        """

    def getChangeStatus(self) -> bool:
        """
        Return "changed" status
        
        :return: true if this object has changed
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def getContentHandler(contentType: typing.Union[java.lang.String, str]) -> ContentHandler[typing.Any]:
        """
        Get the :obj:`ContentHandler` associated with the specified content-type.
        
        :param java.lang.String or str contentType: domain object content type
        :return: content handler
        :rtype: ContentHandler[typing.Any]
        :raises IOException: if no content handler can be found
        """

    @staticmethod
    @typing.overload
    def getContentHandler(dobjClass: java.lang.Class[ghidra.framework.model.DomainObject]) -> ContentHandler[typing.Any]:
        """
        Get the :obj:`ContentHandler` associated with the specified domain object class
        
        :param java.lang.Class[ghidra.framework.model.DomainObject] dobjClass: domain object class
        :return: content handler
        :rtype: ContentHandler[typing.Any]
        :raises IOException: if no content handler can be found
        """

    @staticmethod
    @typing.overload
    def getContentHandler(dobj: ghidra.framework.model.DomainObject) -> ContentHandler[typing.Any]:
        """
        Get the :obj:`ContentHandler` associated with the specified domain object
        
        :param ghidra.framework.model.DomainObject dobj: domain object
        :return: content handler
        :rtype: ContentHandler[typing.Any]
        :raises IOException: if no content handler can be found
        """

    @staticmethod
    def getContentHandlers() -> java.util.Set[ContentHandler[typing.Any]]:
        """
        Get all :obj:`ContentHandler`s
        
        :return: collection of content handlers
        :rtype: java.util.Set[ContentHandler[typing.Any]]
        """

    def getLock(self) -> ghidra.util.Lock:
        ...

    def invalidate(self):
        """
        Invalidates any caching in a program and generate a :obj:`DomainObjectEvent.RESTORED`
        event. 
        NOTE: Over-using this method can adversely affect system performance.
        """

    def isUsedBy(self, consumer: java.lang.Object) -> bool:
        """
        Returns true if the given consumer is using this object.
        """

    @property
    def lock(self) -> ghidra.util.Lock:
        ...

    @property
    def changeStatus(self) -> jpype.JBoolean:
        ...

    @property
    def usedBy(self) -> jpype.JBoolean:
        ...


class RootGhidraFolderData(GhidraFolderData):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LinkedGhidraFile(ghidra.framework.model.LinkedDomainFile):
    """
    ``LinkedGhidraFile`` corresponds to a :obj:`DomainFile` contained within a
    :obj:`LinkedGhidraFolder`.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VersionIcon(javax.swing.Icon):
    """
    :obj:`VersionIcon` is the base icon for files which exist within the versioned filesystem.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["GhidraToolState", "RootGhidraFolder", "DBWithUserDataContentHandler", "SynchronizedTransactionManager", "GhidraFolder", "OpenMode", "AbstractTransactionManager", "DomainObjectAdapterDB", "LockingTaskMonitor", "DomainFileProxy", "DomainFileIndex", "DomainFolderChangeListenerList", "DefaultProjectData", "SynchronizedTransaction", "LinkHandler", "GhidraFolderData", "DomainObjectDBChangeSet", "GhidraFileData", "DomainObjectDBTransaction", "DBContentHandler", "ToolStateFactory", "GhidraFile", "OptionsDB", "DefaultCheckinHandler", "ConvertFileSystem", "DomainObjectChangeSupport", "LinkedGhidraSubFolder", "ToolState", "DomainObjectMergeManager", "FolderLinkContentHandler", "TransientDataManager", "URLLinkObject", "MetadataManager", "LinkedGhidraFolder", "DomainObjectTransactionManager", "ContentHandler", "DomainObjectFileListener", "NullFolderDomainObject", "ProjectLock", "CheckinHandler", "DomainObjectAdapter", "RootGhidraFolderData", "LinkedGhidraFile", "VersionIcon"]
