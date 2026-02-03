from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import ghidra.app.services
import ghidra.app.util.bin
import ghidra.app.util.opinion
import ghidra.formats.gfilesystem
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class BatchGroup(java.lang.Object):
    """
    A group of :obj:`LoadSpec`s (possibly from different user added sources)
    that have a common :obj:`BatchSegregatingCriteria`.
     
    
    All the Apps must have the same set of :obj:`LoadSpec`s to be included in the same
    BatchGroup.
     
    
    Each BatchGroup has a single selected (:obj:`BatchGroupLoadSpec`) that applies
    to all the Apps in the group.
    """

    class BatchLoadConfig(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
            ...

        def getLoadSpec(self, batchGroupLoadSpec: BatchGroupLoadSpec) -> ghidra.app.util.opinion.LoadSpec:
            ...

        def getLoadSpecs(self) -> java.util.Collection[ghidra.app.util.opinion.LoadSpec]:
            ...

        def getLoader(self) -> ghidra.app.util.opinion.Loader:
            ...

        def getPreferredFileName(self) -> str:
            ...

        def getUasi(self) -> UserAddedSourceInfo:
            ...

        @property
        def loadSpec(self) -> ghidra.app.util.opinion.LoadSpec:
            ...

        @property
        def uasi(self) -> UserAddedSourceInfo:
            ...

        @property
        def loader(self) -> ghidra.app.util.opinion.Loader:
            ...

        @property
        def preferredFileName(self) -> java.lang.String:
            ...

        @property
        def fSRL(self) -> ghidra.formats.gfilesystem.FSRL:
            ...

        @property
        def loadSpecs(self) -> java.util.Collection[ghidra.app.util.opinion.LoadSpec]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, criteria: BatchSegregatingCriteria):
        """
        Creates a new :obj:`BatchGroup` keyed on the specified 
        :obj:`criteria <BatchSegregatingCriteria>`.
        
        :param BatchSegregatingCriteria criteria: :obj:`BatchSegregatingCriteria` of this :obj:`BatchGroup`.
        """

    def add(self, provider: ghidra.app.util.bin.ByteProvider, loadSpecs: collections.abc.Sequence, fsrl: ghidra.formats.gfilesystem.FSRL, uasi: UserAddedSourceInfo):
        """
        Adds :obj:`LoadSpec`s to this group.
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`ByteProvider`.
        :param collections.abc.Sequence loadSpecs: :obj:`LoadSpec`s to add to this group.
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` of the application's import source file.
        :param UserAddedSourceInfo uasi: :obj:`UserAddedSourceInfo`
        """

    def getBatchLoadConfig(self) -> java.util.List[BatchGroup.BatchLoadConfig]:
        """
        Returns the list of current :obj:`BatchLoadConfig` in this group.
        
        :return: :obj:`List` of :obj:`BatchLoadConfig` :obj:`BatchLoadConfig` wrappers.
        :rtype: java.util.List[BatchGroup.BatchLoadConfig]
        """

    def getCriteria(self) -> BatchSegregatingCriteria:
        """
        Returns the :obj:`BatchSegregatingCriteria` of this group.
        
        :return: :obj:`BatchSegregatingCriteria` of this group.
        :rtype: BatchSegregatingCriteria
        """

    def getSelectedBatchGroupLoadSpec(self) -> BatchGroupLoadSpec:
        """
        Returns the selected :obj:`BatchGroupLoadSpec` that applies to the entire 
        :obj:`BatchGroup`.
        
        :return: selected :obj:`BatchGroupLoadSpec` that applies to the entire :obj:`BatchGroup`.
        :rtype: BatchGroupLoadSpec
        """

    def isEmpty(self) -> bool:
        """
        Returns true if there are no applications in this group.
        
        :return: boolean true if there are no applications in this group.
        :rtype: bool
        """

    def isEnabled(self) -> bool:
        """
        Returns true if this group is 'enabled', which means that it has a selected
        :obj:`BatchGroupLoadSpec` and the user has chosen to mark this group as importable.
        
        :return: boolean enabled status.
        :rtype: bool
        """

    def removeDescendantsOf(self, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Removes any applications that are inside the specified container file.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` of a container.
        """

    def setEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the enabled status of this group.
        
        :param jpype.JBoolean or bool enabled: boolean
        """

    def setSelectedBatchGroupLoadSpec(self, selectedBatchGroupLoadSpec: BatchGroupLoadSpec):
        """
        Sets the current :obj:`BatchGroupLoadSpec` for the entire group of applications.
        
        :param BatchGroupLoadSpec selectedBatchGroupLoadSpec: :obj:`BatchGroupLoadSpec` to set
        """

    def size(self) -> int:
        """
        Returns the number of applications in this group.
        
        :return: number of applications in this group.
        :rtype: int
        """

    @property
    def batchLoadConfig(self) -> java.util.List[BatchGroup.BatchLoadConfig]:
        ...

    @property
    def selectedBatchGroupLoadSpec(self) -> BatchGroupLoadSpec:
        ...

    @selectedBatchGroupLoadSpec.setter
    def selectedBatchGroupLoadSpec(self, value: BatchGroupLoadSpec):
        ...

    @property
    def criteria(self) -> BatchSegregatingCriteria:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class BatchImportTableModel(docking.widgets.table.AbstractSortedTableModel[BatchGroup]):
    """
    An adapter between :obj:`BatchInfo` and a :obj:`TableModel`.
    """

    class COLS(java.lang.Enum[BatchImportTableModel.COLS]):

        class_: typing.ClassVar[java.lang.Class]
        SELECTED: typing.Final[BatchImportTableModel.COLS]
        FILETYPE: typing.Final[BatchImportTableModel.COLS]
        LOADER: typing.Final[BatchImportTableModel.COLS]
        LANG: typing.Final[BatchImportTableModel.COLS]
        FILES: typing.Final[BatchImportTableModel.COLS]
        columnLabel: typing.Final[java.lang.String]
        editable: typing.Final[jpype.JBoolean]
        count: typing.Final[jpype.JInt]
        UNKNOWN_COLUMN_LABEL: typing.Final = "<unknown>"

        @staticmethod
        def getCol(i: typing.Union[jpype.JInt, int]) -> BatchImportTableModel.COLS:
            ...

        @staticmethod
        def getColumnLabel(i: typing.Union[jpype.JInt, int]) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> BatchImportTableModel.COLS:
            ...

        @staticmethod
        def values() -> jpype.JArray[BatchImportTableModel.COLS]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ibi: BatchInfo):
        ...

    def refreshData(self):
        ...


class BatchSegregatingCriteria(java.lang.Object):
    """
    Set of identifying pieces of info that allow us to segregate files that we are
    importing into groups.
     
    
    Criteria are:
     
    * Filename extension of source file
    * Loader name
    * Set of LanguageCompilerSpecs and preferred flags (ie. :obj:`BatchGroupLoadSpec`)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loader: ghidra.app.util.opinion.Loader, loadSpecs: collections.abc.Sequence, provider: ghidra.app.util.bin.ByteProvider):
        ...

    def getBatchGroupLoadSpecs(self) -> java.util.List[BatchGroupLoadSpec]:
        """
        Return the :obj:`BatchGroupLoadSpec`s as a sorted list.
        
        :return: sorted list of :obj:`BatchGroupLoadSpec`s.
        :rtype: java.util.List[BatchGroupLoadSpec]
        """

    def getFileExt(self) -> str:
        ...

    def getFirstPreferredLoadSpec(self) -> BatchGroupLoadSpec:
        ...

    def getLoader(self) -> str:
        ...

    @property
    def batchGroupLoadSpecs(self) -> java.util.List[BatchGroupLoadSpec]:
        ...

    @property
    def loader(self) -> java.lang.String:
        ...

    @property
    def firstPreferredLoadSpec(self) -> BatchGroupLoadSpec:
        ...

    @property
    def fileExt(self) -> java.lang.String:
        ...


class BatchImportDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class SourcesListModel(javax.swing.AbstractListModel[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def refresh(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def setupInitialDefaults(self) -> bool:
        ...

    @staticmethod
    def showAndImport(tool: ghidra.framework.plugintool.PluginTool, batchInfo: BatchInfo, initialFiles: java.util.List[ghidra.formats.gfilesystem.FSRL], defaultFolder: ghidra.framework.model.DomainFolder, programManager: ghidra.app.services.ProgramManager):
        """
        Shows the batch import dialog (via runSwingLater) and prompts the user to select
        a file if the supplied ``batchInfo`` is empty.
         
        
        The dialog will chain to the :obj:`ImportBatchTask` when the user clicks the
        OK button.
        
        :param ghidra.framework.plugintool.PluginTool tool: :obj:`PluginTool` that will be the parent of the dialog
        :param BatchInfo batchInfo: optional :obj:`BatchInfo` instance with already discovered applications, or null.
        :param java.util.List[ghidra.formats.gfilesystem.FSRL] initialFiles: optional :obj:`List` of :obj:`files <FSRL>` to add to the batch import dialog, or null.
        :param ghidra.framework.model.DomainFolder defaultFolder: optional default destination folder for imported files or null for root folder.
        :param ghidra.app.services.ProgramManager programManager: optional :obj:`ProgramManager` that will be used to open the newly imported
        binaries.
        """


@typing.type_check_only
class BatchProjectDestinationPanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: javax.swing.JComponent, defaultFolder: ghidra.framework.model.DomainFolder):
        ...

    def getFolder(self) -> ghidra.framework.model.DomainFolder:
        ...

    def onProjectDestinationChange(self, newDomainFolder: ghidra.framework.model.DomainFolder):
        ...

    def setFolder(self, folder: ghidra.framework.model.DomainFolder):
        ...

    @property
    def folder(self) -> ghidra.framework.model.DomainFolder:
        ...

    @folder.setter
    def folder(self, value: ghidra.framework.model.DomainFolder):
        ...


class BatchInfo(java.lang.Object):
    """
    This is the main state of a batch import task, containing the segregated groupings of
    applications.
     
    
    This class also handles populating the batch groups by recursively descending into files
    and the contents of those files.
    """

    @typing.type_check_only
    class AddFilesRunnable(ghidra.util.task.MonitoredRunnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BatchTaskMonitor(ghidra.util.task.WrappingTaskMonitor):
        """
        A task monitor that allows us to control the message content and the progress
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MAXDEPTH_UNLIMITED: typing.Final = -1
    MAXDEPTH_DEFAULT: typing.Final = 2

    @typing.overload
    def __init__(self):
        """
        Creates a new BatchInfo object with a default :obj:`.maxDepth`.
        """

    @typing.overload
    def __init__(self, maxDepth: typing.Union[jpype.JInt, int]):
        """
        Creates a new BatchInfo object using the specified maxDepth.
        
        :param jpype.JInt or int maxDepth: see :obj:`.maxDepth`.
        """

    def addFile(self, fsrl: ghidra.formats.gfilesystem.FSRL, taskMonitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Adds a file to this batch as the direct result of a user action.
         
        
        If the file is a container for other files, this method will iterate through those
        child files and recursively try to add them using this method.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` of the file to add.
        :param ghidra.util.task.TaskMonitor taskMonitor: :obj:`TaskMonitor` to watch and update with progress.
        :return: boolean true if something in the file produced something to import.
        :rtype: bool
        :raises IOException: if io error when reading files.
        :raises CancelledException: if user cancels.
        """

    def getEnabledCount(self) -> int:
        """
        Returns the count of applications in enabled :obj:`BatchGroup`s... in other
        words, the number of objects that would be imported during this batch.
        
        :return: count of enabled applications.
        :rtype: int
        """

    def getGroups(self) -> java.util.List[BatchGroup]:
        """
        Returns a list of the :obj:`BatchGroup`s that have been found when processing
        the added files.
        
        :return: :obj:`List` of :obj:`BatchGroup`s.
        :rtype: java.util.List[BatchGroup]
        """

    def getMaxDepth(self) -> int:
        """
        Maximum depth of containers (ie. filesystems) to recurse into when processing
        a file added by the user
        
        :return: the current maximum depth of containers (ie. filesystems) to recurse into when processing
        a file added by the user.
        :rtype: int
        """

    def getTotalCount(self) -> int:
        """
        Returns the count of how many importable objects (ie. :obj:`LoadSpec`s) were found.
        
        :return: count of importable objects.
        :rtype: int
        """

    def getTotalRawCount(self) -> int:
        """
        Returns the count of how many files were found while processing the source files.
        
        :return: count of files found while processing source files.
        :rtype: int
        """

    def getUserAddedSources(self) -> java.util.List[UserAddedSourceInfo]:
        """
        Returns the :obj:`List` of files added via :meth:`addFile(FSRL, TaskMonitor) <.addFile>`.
        
        :return: :obj:`List` of files added via :meth:`addFile(FSRL, TaskMonitor) <.addFile>`.
        :rtype: java.util.List[UserAddedSourceInfo]
        """

    def isSingleApp(self) -> bool:
        """
        Checks the found applications and returns true if only a single binary was found,
        even if multiple loaders claim it.
        
        :return: true if single binary and batch is probably not correct importer.
        :rtype: bool
        """

    def remove(self, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Removes a user-added source file (and all the embedded files inside it) from this
        batch.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` of the file to remove.
        """

    def setMaxDepth(self, newMaxDepth: typing.Union[jpype.JInt, int]):
        """
        Sets a new max container recursive depth limit for this batch import
         
        
        Doing this requires rescanning all original user-added source files and stopping
        at the new max depth.
        
        :param jpype.JInt or int newMaxDepth: new value for the max depth
        """

    def wasRecurseTerminatedEarly(self) -> bool:
        """
        Returns true if any of the user source files had containers that were not
        recursed into because of the :obj:`.maxDepth` limit.
        
        :return: true if any of the user source files had containers that were not
        recursed into because of the :obj:`.maxDepth` limit.
        :rtype: bool
        """

    @property
    def totalRawCount(self) -> jpype.JInt:
        ...

    @property
    def maxDepth(self) -> jpype.JInt:
        ...

    @maxDepth.setter
    def maxDepth(self, value: jpype.JInt):
        ...

    @property
    def enabledCount(self) -> jpype.JInt:
        ...

    @property
    def singleApp(self) -> jpype.JBoolean:
        ...

    @property
    def userAddedSources(self) -> java.util.List[UserAddedSourceInfo]:
        ...

    @property
    def groups(self) -> java.util.List[BatchGroup]:
        ...

    @property
    def totalCount(self) -> jpype.JInt:
        ...


class UserAddedSourceInfo(java.lang.Object):
    """
    This class holds information regarding a single user-added source file added
    to a batch import session.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getContainerCount(self) -> int:
        ...

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    def getFileCount(self) -> int:
        ...

    def getMaxNestLevel(self) -> int:
        ...

    def getRawFileCount(self) -> int:
        ...

    def incContainerCount(self):
        ...

    def incRawFileCount(self):
        ...

    def setContainerCount(self, containerCount: typing.Union[jpype.JInt, int]):
        ...

    def setFileCount(self, fileCount: typing.Union[jpype.JInt, int]):
        ...

    def setMaxNestLevel(self, maxNestLevel: typing.Union[jpype.JInt, int]):
        ...

    def setRawFileCount(self, rawFileCount: typing.Union[jpype.JInt, int]):
        ...

    def setRecurseTerminatedEarly(self, recurseTerminatedEarly: typing.Union[jpype.JBoolean, bool]):
        ...

    def wasRecurseTerminatedEarly(self) -> bool:
        ...

    @property
    def fSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    @property
    def rawFileCount(self) -> jpype.JInt:
        ...

    @rawFileCount.setter
    def rawFileCount(self, value: jpype.JInt):
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...

    @fileCount.setter
    def fileCount(self, value: jpype.JInt):
        ...

    @property
    def containerCount(self) -> jpype.JInt:
        ...

    @containerCount.setter
    def containerCount(self, value: jpype.JInt):
        ...

    @property
    def maxNestLevel(self) -> jpype.JInt:
        ...

    @maxNestLevel.setter
    def maxNestLevel(self, value: jpype.JInt):
        ...


class BatchGroupLoadSpec(java.lang.Comparable[BatchGroupLoadSpec]):
    """
    Similar to a :obj:`LoadSpec`, but not associated with a :obj:`Loader`.
     
    
    This has the same information as a :obj:`LoadSpec`, but for all the members of a 
    :obj:`BatchGroup`.
    """

    class_: typing.ClassVar[java.lang.Class]
    lcsPair: ghidra.program.model.lang.LanguageCompilerSpecPair
    preferred: jpype.JBoolean

    def __init__(self, loadSpec: ghidra.app.util.opinion.LoadSpec):
        ...

    def matches(self, loadSpec: ghidra.app.util.opinion.LoadSpec) -> bool:
        ...



__all__ = ["BatchGroup", "BatchImportTableModel", "BatchSegregatingCriteria", "BatchImportDialog", "BatchProjectDestinationPanel", "BatchInfo", "UserAddedSourceInfo", "BatchGroupLoadSpec"]
