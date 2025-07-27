from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.filechooser
import generic.jar
import ghidra.app.merge
import ghidra.app.plugin.core.datamgr
import ghidra.app.services
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.options
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class ArchiveFileChooser(docking.widgets.filechooser.GhidraFileChooser):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, component: java.awt.Component):
        ...

    def promptUserForFile(self, suggestedFileName: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Shows this filechooser and uses the given suggested filename as the default filename
        
        :param java.lang.String or str suggestedFileName: The default name to show in the name field
        :return: the file selected by the user, or null if no selection was made
        :rtype: java.io.File
        """


class ArchiveManagerListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def archiveClosed(self, archive: Archive):
        """
        Called when an archive is closed.
        
        :param Archive archive: the archive that was closed.
        """

    def archiveDataTypeManagerChanged(self, archive: Archive):
        """
        Called when the :obj:`DataTypeManager` of the archive has changed.  This can happen when
        an archive is locked or unlocked.
        """

    def archiveOpened(self, archive: Archive):
        """
        Called when a new Archive is opened.
        
        :param Archive archive: the new archive that was opened.
        """

    def archiveStateChanged(self, archive: Archive):
        """
        Called when the edited state of the archive has changed, for example, when an archive
        has had a data type or category added or removed.
        """


class DefaultDataTypeArchiveService(ghidra.app.services.DataTypeArchiveService):
    """
    Simple, non-ui implementation of the :obj:`DataTypeArchiveService` interface.
    """

    @typing.type_check_only
    class DataTypeManagerInfo(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def domainObject(self) -> ghidra.framework.model.DomainObject:
            ...

        def dtm(self) -> ghidra.program.model.data.DataTypeManager:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def file(self) -> generic.jar.ResourceFile:
            ...

        def hashCode(self) -> int:
            ...

        def isClosed(self) -> bool:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...

        @property
        def closed(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def dispose(self):
        ...


class Archive(ghidra.app.merge.DataTypeManagerOwner, java.lang.Comparable[Archive]):
    """
    This is an interface for data type archives.
    """

    class_: typing.ClassVar[java.lang.Class]

    def close(self):
        """
        Closes this archive.  Some archives cannot be closed (i.e. BuiltIn data type archive.)
        """

    def getIcon(self, expanded: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Gets the icon representing this archive.
        
        :param jpype.JBoolean or bool expanded: true means show the icon for this archive as an expanded (open) tree node.
        false indicates the node is closed.
        :return: the archive's icon.
        :rtype: javax.swing.Icon
        """

    def getName(self) -> str:
        """
        Gets the name for this data type archive.
        This is the name to be presented to the user for this archive.
        
        :return: the name or null if closed
        :rtype: str
        """

    def isChanged(self) -> bool:
        """
        Determines if this archive has been changed. Some archives cannot be changed.
        
        :return: true if the archive contains unsaved changes.
        :rtype: bool
        """

    def isModifiable(self) -> bool:
        """
        Determines if this is a modifiable archive like a program archive, a non-versioned
        project archive, a checked out versioned project archive or a locked (open for editing)
        file archive.
        
        :return: true if it is a modifiable archive and can have its contents changed.
        :rtype: bool
        """

    def isSavable(self) -> bool:
        """
        Determines if this archive can be saved. Some archives cannot be saved.
        
        :return: true if the archive can be saved.
        :rtype: bool
        """

    def save(self):
        """
        Saves this archive. Some archives cannot be saved.
        
        :raises DuplicateFileException: if there is an exception saving
        :raises IOException: if there is an exception saving
        """

    def saveAs(self, component: java.awt.Component):
        """
        Saves this archive to a newly named file.
        
        :param java.awt.Component component: the parent component the any dialogs shown
        :raises IOException: if there is an exception saving
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def modifiable(self) -> jpype.JBoolean:
        ...

    @property
    def savable(self) -> jpype.JBoolean:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...


class DomainFileArchive(Archive):

    class_: typing.ClassVar[java.lang.Class]

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    def getDomainObject(self) -> ghidra.framework.model.DomainObject:
        ...

    def hasExclusiveAccess(self) -> bool:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def domainObject(self) -> ghidra.framework.model.DomainObject:
        ...


class ProjectArchive(DomainFileArchive):

    @typing.type_check_only
    class ArchiveCategoryChangeListener(ghidra.program.model.data.DataTypeManagerChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ArchiveUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def canClose(archiveList: java.util.List[Archive], component: java.awt.Component) -> bool:
        ...

    @staticmethod
    @typing.overload
    def canClose(archive: Archive, component: java.awt.Component) -> bool:
        ...

    @staticmethod
    def lockArchive(archive: FileArchive) -> bool:
        ...

    @staticmethod
    def save(component: java.awt.Component, archive: Archive):
        """
        This method will perform a save on the given archive.  However, the one caveat is that if
        the archive has never been saved, then a filename needs to be chosen.  Under this 'special'
        condition this method logically turns into a :meth:`saveAs(Component, FileArchive) <.saveAs>`.
        
        :param java.awt.Component component: The component over which GUI message will be shown when required.
        :param Archive archive: The archive to save.
        :raises DuplicateFileException: thrown only in the :meth:`saveAs(Component, FileArchive) <.saveAs>`
                    condition in the case of a naming conflict.
        :raises IOException: If the sky is falling.
        """

    @staticmethod
    def saveAs(component: java.awt.Component, archive: FileArchive):
        """
        Saves the given archive to a file of the user's choosing.
        
        :param java.awt.Component component: The component over which GUI message will be shown when required.
        :param FileArchive archive: The archive to save.
        :raises DuplicateFileException: thrown in the case of a naming conflict.
        :raises IOException: If the sky is falling.
        """


class InvalidFileArchive(Archive):

    class_: typing.ClassVar[java.lang.Class]

    def getArchiveType(self) -> ghidra.program.model.data.ArchiveType:
        ...

    def getDomainFileID(self) -> str:
        ...

    def getUniversalID(self) -> ghidra.util.UniversalID:
        ...

    @property
    def archiveType(self) -> ghidra.program.model.data.ArchiveType:
        ...

    @property
    def universalID(self) -> ghidra.util.UniversalID:
        ...

    @property
    def domainFileID(self) -> java.lang.String:
        ...


class FileArchive(Archive):
    """
    Manages a DataTypeFileManager and relative state.  For example, whether the manager is writable
    or whether changes have been made.
    """

    @typing.type_check_only
    class ArchiveCategoryChangeListener(ghidra.program.model.data.DataTypeManagerChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def acquireWriteLock(self):
        ...

    def delete(self):
        ...

    def getArchiveManager(self) -> DataTypeManagerHandler:
        ...

    def getFile(self) -> generic.jar.ResourceFile:
        ...

    def hasWriteLock(self) -> bool:
        ...

    def releaseWriteLock(self):
        ...

    def saveAs(self, file: jpype.protocol.SupportsPath):
        ...

    @property
    def file(self) -> generic.jar.ResourceFile:
        ...

    @property
    def archiveManager(self) -> DataTypeManagerHandler:
        ...


class DuplicateIdException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, newArchiveName: typing.Union[java.lang.String, str], existingArchiveName: typing.Union[java.lang.String, str]):
        ...

    def getExistingArchiveName(self) -> str:
        ...

    def getNewArchiveName(self) -> str:
        ...

    @property
    def newArchiveName(self) -> java.lang.String:
        ...

    @property
    def existingArchiveName(self) -> java.lang.String:
        ...


class BuiltInArchive(Archive):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataTypeManagerHandler(java.lang.Object):
    """
    Helper class to manage the archive files.
    """

    @typing.type_check_only
    class RecentlyUsedDataType(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getDataType(self) -> ghidra.program.model.data.DataType:
            ...

        @property
        def dataType(self) -> ghidra.program.model.data.DataType:
            ...


    @typing.type_check_only
    class DataTypeManagerListenerDelegate(ghidra.program.model.data.DataTypeManagerChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CreateDataTypeArchiveDataTreeDialog(ghidra.framework.main.DataTreeDialog):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DomainFileSaveTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DomainObjectSaveAsTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyFolderListener(ghidra.framework.model.DomainFolderListenerAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    OLD_DATA_TYPE_ARCHIVE_PATH_KEY: typing.Final = "DATA_TYPE_ARCHIVE_PATH"
    DATA_TYPE_ARCHIVE_PATH_KEY: typing.Final = "DATATYPE_ARCHIVE_PATHS"
    DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY: typing.Final = "DISABLED_DATA_TYPE_ARCHIVE_PATH"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...

    def addArchiveManagerListener(self, listener: ArchiveManagerListener):
        ...

    def addDataTypeManagerChangeListener(self, listener: ghidra.program.model.data.DataTypeManagerChangeListener):
        ...

    def closeAllArchives(self):
        ...

    @typing.overload
    def closeArchive(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...

    @typing.overload
    def closeArchive(self, archive: Archive):
        ...

    def createArchive(self, file: jpype.protocol.SupportsPath) -> Archive:
        ...

    def createProjectArchive(self) -> Archive:
        ...

    def dispose(self):
        ...

    def fireArchiveStateChanged(self, archive: Archive):
        ...

    def fireDataTypeManagerChanged(self, archive: FileArchive):
        ...

    def getAllArchives(self) -> java.util.List[Archive]:
        ...

    def getAllFileOrProjectArchives(self) -> java.util.List[Archive]:
        ...

    def getAllModifiedFileArchives(self) -> java.util.List[Archive]:
        ...

    def getArchive(self, dtm: ghidra.program.model.data.DataTypeManager) -> Archive:
        ...

    def getBuiltInDataTypesManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    def getDataTypeIndexer(self) -> DataTypeIndexer:
        ...

    def getDataTypeManager(self, source: ghidra.program.model.data.SourceArchive) -> ghidra.program.model.data.DataTypeManager:
        ...

    def getDataTypeManagers(self) -> jpype.JArray[ghidra.program.model.data.DataTypeManager]:
        ...

    def getFavoriteDataTypes(self) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Returns all favorite DataTypes in all archives.
        
        :return: all favorite DataTypes in all archives.
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    def getModificationCount(self) -> int:
        """
        Returns the current modification count which is incremented anytime any archive or any
        category or datatype it contains is changed in any way. This includes the datatypes in
        the current program.
        
        :return: the current modification id.
        :rtype: int
        """

    def getPossibleEquateNames(self, value: typing.Union[jpype.JLong, int]) -> java.util.Set[java.lang.String]:
        ...

    @typing.overload
    def getProjectPathname(self, pa: ProjectArchive, activeProjectOnly: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Determine if we can remember the specified project archive using a simple project path
        (e.g., we can't remember specific versions).
        
        :param ProjectArchive pa: project archive
        :param jpype.JBoolean or bool activeProjectOnly: if true pa must be contained within the
        active project to be remembered.
        :return: return project path which can be remembered or null
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getProjectPathname(projectName: typing.Union[java.lang.String, str], pathname: typing.Union[java.lang.String, str]) -> str:
        """
        Create project archive path string for recently used project archive
        
        :param java.lang.String or str projectName: the project name
        :param java.lang.String or str pathname: the pathname used to create the final path
        :return: recently used project pathname string
        :rtype: str
        """

    def getRecentlyDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def handleArchiveFileException(plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, archiveFile: generic.jar.ResourceFile, t: java.lang.Throwable):
        """
        Provides an exception handler for a failed attempt to open an datatype archive file.
        This method will display exception information to the user and/or log.
        
        :param ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin plugin: datatype manager plugin
        :param generic.jar.ResourceFile archiveFile: archive file resource being opened
        :param java.lang.Throwable t: throwable
        """

    def isAllowedArchivePath(self, path: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if archive path is allowed.
        An attempt is made to disallow any path which appears to be contained
        within a Ghidra installation.
        
        :param java.lang.String or str path: directory or file archive path
        :return: true if path is allowed
        :rtype: bool
        """

    def isInUse(self, file: jpype.protocol.SupportsPath) -> bool:
        ...

    @typing.overload
    def openArchive(self, file: jpype.protocol.SupportsPath, acquireWriteLock: typing.Union[jpype.JBoolean, bool], isUserAction: typing.Union[jpype.JBoolean, bool]) -> Archive:
        ...

    @typing.overload
    def openArchive(self, file: generic.jar.ResourceFile, acquireWriteLock: typing.Union[jpype.JBoolean, bool], isUserAction: typing.Union[jpype.JBoolean, bool]) -> FileArchive:
        ...

    @typing.overload
    def openArchive(self, domainFile: ghidra.framework.model.DomainFile, okToUpgrade: typing.Union[jpype.JBoolean, bool], okToRecover: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> Archive:
        ...

    @typing.overload
    def openArchive(self, dataTypeArchive: ghidra.program.model.listing.DataTypeArchive) -> Archive:
        ...

    @typing.overload
    def openArchive(self, dataTypeArchive: ghidra.program.model.listing.DataTypeArchive, domainFile: ghidra.framework.model.DomainFile) -> Archive:
        ...

    @typing.overload
    def openArchive(self, archiveName: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataTypeManager:
        ...

    @staticmethod
    def parseProjectPathname(projectFilePath: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        """
        Parse a recently used project pathname string
        
        :param java.lang.String or str projectFilePath: project pathname string
        :return: 2-element String array containing project name and pathname of project archive, or null if path is invalid
        :rtype: jpype.JArray[java.lang.String]
        """

    def programClosed(self):
        """
        Notification that the program is closed. Remove the root category
        for the program from the provider.
        """

    def programOpened(self, program: ghidra.program.model.listing.Program):
        """
        Notification that the given program is open. Add the root category
        for the program to any provider that is open.
        
        :param ghidra.program.model.listing.Program program: the program
        """

    def removeArchiveManagerListener(self, listener: ArchiveManagerListener):
        ...

    def removeDataTypeManagerChangeListener(self, listener: ghidra.program.model.data.DataTypeManagerChangeListener):
        ...

    def removeInvalidArchive(self, archive: InvalidFileArchive):
        ...

    def restore(self, saveState: ghidra.framework.options.SaveState):
        ...

    @typing.overload
    def save(self, saveState: ghidra.framework.options.SaveState):
        ...

    @typing.overload
    def save(self, domainObject: ghidra.framework.model.DomainObject):
        ...

    def saveAs(self, domainObject: ghidra.framework.model.DomainObject):
        ...

    def setRecentlyUsedDataType(self, dataType: ghidra.program.model.data.DataType):
        ...

    def updateKnownOpenArchives(self):
        """
        Signals to this manager to save the knowledge of all currently opened archives and to mark
        the tool as dirty (changed) if the current open archives are not the same as those that
        were initially opened.
        """

    @property
    def archive(self) -> Archive:
        ...

    @property
    def recentlyDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def dataTypeManagers(self) -> jpype.JArray[ghidra.program.model.data.DataTypeManager]:
        ...

    @property
    def favoriteDataTypes(self) -> java.util.List[ghidra.program.model.data.DataType]:
        ...

    @property
    def modificationCount(self) -> jpype.JLong:
        ...

    @property
    def inUse(self) -> jpype.JBoolean:
        ...

    @property
    def dataTypeIndexer(self) -> DataTypeIndexer:
        ...

    @property
    def builtInDataTypesManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    @property
    def allFileOrProjectArchives(self) -> java.util.List[Archive]:
        ...

    @property
    def allowedArchivePath(self) -> jpype.JBoolean:
        ...

    @property
    def allArchives(self) -> java.util.List[Archive]:
        ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    @property
    def allModifiedFileArchives(self) -> java.util.List[Archive]:
        ...

    @property
    def possibleEquateNames(self) -> java.util.Set[java.lang.String]:
        ...


class ProgramArchive(DomainFileArchive):

    class_: typing.ClassVar[java.lang.Class]

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class DataTypeIndexer(java.lang.Object):
    """
    A class that stores a sorted list of all the :obj:`DataType` objects in the current data type
    manager plugin.  This class does its work lazily such that no work is done until
    :meth:`getSortedDataTypeList() <.getSortedDataTypeList>` is called.  Even when that method is called no work will be
    done if the state of the data types in the system hasn't changed.
    """

    @typing.type_check_only
    class CaseInsensitiveDataTypeComparator(java.util.Comparator[ghidra.program.model.data.DataType]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IndexerTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataTypeIndexUpdateListener(ghidra.program.model.data.DataTypeManagerChangeListener, ghidra.program.model.data.InvalidatedListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addDataTypeManager(self, dataTypeManager: ghidra.program.model.data.DataTypeManager):
        ...

    def getSortedDataTypeList(self) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Returns a sorted list of the data types open in the current tool.  The sorting of the list
        is done using the :obj:`DataTypeComparator` whose primary sort is based upon the 
        :obj:`DataTypeNameComparator`.
        
        :return: a sorted list of the data types open in the current tool.
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    def removeDataTypeManager(self, dataTypeManager: ghidra.program.model.data.DataTypeManager):
        ...

    @property
    def sortedDataTypeList(self) -> java.util.List[ghidra.program.model.data.DataType]:
        ...


class BuiltInSourceArchive(ghidra.program.model.data.SourceArchive):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[ghidra.program.model.data.SourceArchive]

    def getPathname(self) -> str:
        ...

    def setPathname(self, name: typing.Union[java.lang.String, str]):
        ...

    @property
    def pathname(self) -> java.lang.String:
        ...

    @pathname.setter
    def pathname(self, value: java.lang.String):
        ...



__all__ = ["ArchiveFileChooser", "ArchiveManagerListener", "DefaultDataTypeArchiveService", "Archive", "DomainFileArchive", "ProjectArchive", "ArchiveUtils", "InvalidFileArchive", "FileArchive", "DuplicateIdException", "BuiltInArchive", "DataTypeManagerHandler", "ProgramArchive", "DataTypeIndexer", "BuiltInSourceArchive"]
