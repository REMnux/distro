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
import ghidra.app.util
import ghidra.app.util.bin
import ghidra.app.util.opinion
import ghidra.formats.gfilesystem
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.filechooser
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


class LcsSelectionListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def valueChanged(self, e: LcsSelectionEvent):
        ...


class ProjectIndexService(ghidra.framework.model.DomainFolderChangeListener, java.lang.AutoCloseable):
    """
    An in-memory index of FSRL-to-domainfiles.
    """

    class ProjectIndexListener(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def indexUpdated(self):
            ...


    class IndexType(java.lang.Enum[ProjectIndexService.IndexType]):

        class_: typing.ClassVar[java.lang.Class]
        MD5: typing.Final[ProjectIndexService.IndexType]
        FSRL: typing.Final[ProjectIndexService.IndexType]

        def getMetadataKey(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ProjectIndexService.IndexType:
            ...

        @staticmethod
        def values() -> jpype.JArray[ProjectIndexService.IndexType]:
            ...

        @property
        def metadataKey(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class IndexInfo(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def indexType(self) -> ProjectIndexService.IndexType:
            ...

        def indexedFiles(self) -> java.util.Map[java.lang.Object, java.lang.Object]:
            ...

        def mappingFunc(self) -> java.util.function.BiFunction[ghidra.framework.model.DomainFile, java.util.Map[java.lang.String, java.lang.String], java.lang.Object]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DUMMY: typing.Final[ProjectIndexService]

    def __init__(self, project: ghidra.framework.model.Project):
        ...

    def addIndexListener(self, listener: ProjectIndexService.ProjectIndexListener):
        ...

    def findFirstByFSRL(self, fsrl: ghidra.formats.gfilesystem.FSRL) -> ghidra.framework.model.DomainFile:
        ...

    @staticmethod
    def getIndexFor(project: ghidra.framework.model.Project) -> ProjectIndexService:
        """
        Returns an index for a Project.  Instances returned by this method should not be 
        :meth:`closed <.close>` by the caller.
        
        :param ghidra.framework.model.Project project: :obj:`Project` to get index for, or ``null`` for a DUMMY placeholder
        :return: :obj:`ProjectIndexService` instance, never null
        :rtype: ProjectIndexService
        """

    def lookupFiles(self, keyType: ProjectIndexService.IndexType, keyValue: java.lang.Object) -> java.util.List[ghidra.framework.model.DomainFile]:
        ...

    @staticmethod
    def projectClosed(project: ghidra.framework.model.Project):
        """
        Notify the index instance management that a Project has been closed.  Users of this service
        need to do this because notification of Project closure is only available to GUI Plugin
        classes.
        
        :param ghidra.framework.model.Project project: :obj:`Project` that was closed
        """

    def removeIndexListener(self, listener: ProjectIndexService.ProjectIndexListener):
        ...


class LoadLibrariesOptionsDialog(ghidra.app.util.OptionsDialog):
    """
    Dialog for editing the options for the "Load Libraries" action
    """

    class_: typing.ClassVar[java.lang.Class]
    TITLE: typing.Final = "Load Libraries"

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, program: ghidra.program.model.listing.Program, tool: ghidra.framework.plugintool.PluginTool, loadSpec: ghidra.app.util.opinion.LoadSpec, addressFactoryService: ghidra.app.util.AddressFactoryService):
        """
        Creates a new :obj:`LoadLibrariesOptionsDialog`
        
        :param ghidra.app.util.bin.ByteProvider provider: The :obj:`Program`'s bytes
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to load libraries into
        :param ghidra.framework.plugintool.PluginTool tool: The tool
        :param ghidra.app.util.opinion.LoadSpec loadSpec: The :obj:`LoadSpec` that was used to load the :obj:`Program`
        :param ghidra.app.util.AddressFactoryService addressFactoryService: The :obj:`AddressFactoryService` to use
        """


class ImporterUtilities(java.lang.Object):
    """
    Utilities for importing files.
     
     
    Note: if a method takes a :obj:`TaskMonitor`, then that method should only be called 
    from a background task.
    """

    class_: typing.ClassVar[java.lang.Class]
    LOADABLE_FILES_FILTER: typing.Final[ghidra.util.filechooser.GhidraFileFilter]
    """
    File extension filter for well known 'loadable' files for GhidraFileChoosers.
    """

    CONTAINER_FILES_FILTER: typing.Final[ghidra.util.filechooser.GhidraFileFilter]
    """
    File extension filter for well known 'container' files for GhidraFileChoosers.
    """


    def __init__(self):
        ...

    @staticmethod
    def addContentToProgram(tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, fsrl: ghidra.formats.gfilesystem.FSRL, loadSpec: ghidra.app.util.opinion.LoadSpec, options: java.util.List[ghidra.app.util.Option], monitor: ghidra.util.task.TaskMonitor):
        ...

    @staticmethod
    def getLoadSpec(program: ghidra.program.model.listing.Program) -> ghidra.app.util.opinion.LoadSpec:
        """
        Get's the :obj:`LoadSpec` that was used to import the given :obj:`Program`
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :return: The :obj:`LoadSpec` that was used to import the given :obj:`Program`, or null if
        it could not be determined
        :rtype: ghidra.app.util.opinion.LoadSpec
        """

    @staticmethod
    def importSingleFile(tool: ghidra.framework.plugintool.PluginTool, programManager: ghidra.app.services.ProgramManager, fsrl: ghidra.formats.gfilesystem.FSRL, destFolder: ghidra.framework.model.DomainFolder, loadSpec: ghidra.app.util.opinion.LoadSpec, programName: typing.Union[java.lang.String, str], options: java.util.List[ghidra.app.util.Option], monitor: ghidra.util.task.TaskMonitor):
        """
        Perform file import and open using optional programManager
        
        :param ghidra.framework.plugintool.PluginTool tool: tool to which popup dialogs should be associated
        :param ghidra.app.services.ProgramManager programManager: program manager to open imported file with or null
        :param ghidra.formats.gfilesystem.FSRL fsrl: import file location
        :param ghidra.framework.model.DomainFolder destFolder: project destination folder
        :param ghidra.app.util.opinion.LoadSpec loadSpec: import :obj:`LoadSpec`
        :param java.lang.String or str programName: program name
        :param java.util.List[ghidra.app.util.Option] options: import options
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        """

    @staticmethod
    def showAddToProgramDialog(fsrl: ghidra.formats.gfilesystem.FSRL, program: ghidra.program.model.listing.Program, tool: ghidra.framework.plugintool.PluginTool, monitor: ghidra.util.task.TaskMonitor):
        ...

    @staticmethod
    @typing.overload
    def showImportDialog(tool: ghidra.framework.plugintool.PluginTool, programManager: ghidra.app.services.ProgramManager, fsrl: ghidra.formats.gfilesystem.FSRL, destinationFolder: ghidra.framework.model.DomainFolder, suggestedPath: typing.Union[java.lang.String, str]):
        """
        Displays the appropriate import dialog for the specified :obj:`file <FSRL>`.
         
        
        If the file is a container of other files, a batch import dialog will be used,
        otherwise the normal single file import dialog will be shown.
        
        :param ghidra.framework.plugintool.PluginTool tool: :obj:`PluginTool` will be used as the parent tool for dialogs
        :param ghidra.app.services.ProgramManager programManager: optional :obj:`ProgramManager` instance to use to open imported 
                    binaries with, or null
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` of the file to import
        :param ghidra.framework.model.DomainFolder destinationFolder: :obj:`DomainFolder` destination folder where the imported file
                    will default to.  (the user will be able to choose a different location)
        :param java.lang.String or str suggestedPath: optional string path that will automatically be pre-pended
                    to the destination filename
        """

    @staticmethod
    @typing.overload
    def showImportDialog(tool: ghidra.framework.plugintool.PluginTool, programManager: ghidra.app.services.ProgramManager, fsrl: ghidra.formats.gfilesystem.FSRL, destinationFolder: ghidra.framework.model.DomainFolder, suggestedPath: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Displays the appropriate import dialog for the specified :obj:`file <FSRL>`.
         
        
        If the file is a container of other files, a batch import dialog will be used,
        otherwise the normal single file import dialog will be shown.]
         
        
        If you are not in a monitored task, then call 
        :meth:`showImportDialog(PluginTool, ProgramManager, FSRL, DomainFolder, String) <.showImportDialog>`.
        
        :param ghidra.framework.plugintool.PluginTool tool: :obj:`PluginTool` will be used as the parent tool for dialogs
        :param ghidra.app.services.ProgramManager programManager: optional :obj:`ProgramManager` instance to use to open imported 
                    binaries with, or null
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` of the file to import
        :param ghidra.framework.model.DomainFolder destinationFolder: :obj:`DomainFolder` destination folder where the imported file
                    will default to.  (the user will be able to choose a different location)
        :param java.lang.String or str suggestedPath: optional string path that will automatically be pre-pended
                    to the destination filename
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to use for monitoring; cannot be null
        """

    @staticmethod
    def showImportSingleFileDialog(fsrl: ghidra.formats.gfilesystem.FSRL, destinationFolder: ghidra.framework.model.DomainFolder, suggestedPath: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool, programManager: ghidra.app.services.ProgramManager, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a :obj:`ImporterDialog` and shows it in the swing thread.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: the file system resource locater (can be a simple file or an element of
                    a more complex file such as a zip file)
        :param ghidra.framework.model.DomainFolder destinationFolder: the default destination folder for the imported file. Can be null
        :param java.lang.String or str suggestedPath: optional string path that will automatically be pre-pended
                    to the destination filename
        :param ghidra.framework.plugintool.PluginTool tool: the parent UI component
        :param ghidra.app.services.ProgramManager programManager: optional :obj:`ProgramManager` instance to open the imported file in
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        """

    @staticmethod
    def showLoadLibrariesDialog(program: ghidra.program.model.listing.Program, tool: ghidra.framework.plugintool.PluginTool, manager: ghidra.app.services.ProgramManager, monitor: ghidra.util.task.TaskMonitor):
        ...


class NewLanguagePanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addSelectionListener(self, listener: LcsSelectionListener):
        ...

    def clearSelection(self):
        ...

    def dispose(self):
        ...

    def getSelectedLcsPair(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    def removeSelectionListener(self, listener: LcsSelectionListener):
        ...

    def setAllLcsPairsList(self, allLcsPairsList: java.util.List[ghidra.program.model.lang.LanguageCompilerSpecPair]):
        ...

    def setFormatText(self, text: typing.Union[java.lang.String, str]):
        ...

    def setRecommendedLcsPair(self, lcsPair: ghidra.program.model.lang.LanguageCompilerSpecPair):
        ...

    def setRecommendedLcsPairsList(self, recommendedLcsPairsList: java.util.List[ghidra.program.model.lang.LanguageCompilerSpecPair]):
        ...

    def setSelectedLcsPair(self, lcsPair: ghidra.program.model.lang.LanguageCompilerSpecPair) -> bool:
        ...

    def setShowAllLcsPairs(self, show: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowRecommendedCheckbox(self, show: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def selectedLcsPair(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...


class AddToProgramDialog(ImporterDialog):
    """
    The AddToProgramDialog is essentially the same as the ImporterDialog with a few exceptions.  One
    difference is that the language and destination folder/name are not enabled and are initialized
    to the existing program to which the imported data will be added.  Also, the Ok callback
    is overridden to add the data to the current program instead of creating a new program.
    """

    class_: typing.ClassVar[java.lang.Class]


class LanguageSortedTableModel(docking.widgets.table.AbstractSortedTableModel[ghidra.program.model.lang.LanguageCompilerSpecPair]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getFirstLcsPairIndex(self, toFind: ghidra.program.model.lang.LanguageCompilerSpecPair) -> int:
        ...

    def getLcsPairAtRow(self, selectedRow: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    @property
    def firstLcsPairIndex(self) -> jpype.JInt:
        ...

    @property
    def lcsPairAtRow(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...


class ImporterLanguageDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loadSpecs: collections.abc.Sequence, tool: ghidra.framework.plugintool.PluginTool, defaultSelectedLanguage: ghidra.program.model.lang.LanguageCompilerSpecPair):
        ...

    def show(self, parent: java.awt.Component):
        ...


class LcsSelectionEvent(java.lang.Object):

    class Type(java.lang.Enum[LcsSelectionEvent.Type]):

        class_: typing.ClassVar[java.lang.Class]
        SELECTED: typing.Final[LcsSelectionEvent.Type]
        """
        A language was selected in the UI
        """

        PICKED: typing.Final[LcsSelectionEvent.Type]
        """
        A language was picked (e.g., double-clicked) in the UI
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LcsSelectionEvent.Type:
            ...

        @staticmethod
        def values() -> jpype.JArray[LcsSelectionEvent.Type]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, selection: ghidra.program.model.lang.LanguageCompilerSpecPair, type: LcsSelectionEvent.Type):
        ...

    def getLcs(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    def getType(self) -> LcsSelectionEvent.Type:
        ...

    @property
    def type(self) -> LcsSelectionEvent.Type:
        ...

    @property
    def lcs(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...


class ImporterPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.FileImporterService, ghidra.framework.main.ApplicationLevelPlugin, ghidra.framework.model.ProjectListener):
    """
    A :obj:`Plugin` that supplies menu items and tasks to import files into Ghidra.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ImporterDialog(docking.DialogComponentProvider):
    """
    Dialog for importing a file into Ghidra as a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, programManager: ghidra.app.services.ProgramManager, loaderMap: ghidra.app.util.opinion.LoaderMap, byteProvider: ghidra.app.util.bin.ByteProvider, suggestedDestinationPath: typing.Union[java.lang.String, str]):
        """
        Construct a new dialog for importing a file as a new program into Ghidra.
        
        :param ghidra.framework.plugintool.PluginTool tool: the active tool that spawned this dialog.
        :param ghidra.app.services.ProgramManager programManager: program manager to open imported file with or null
        :param ghidra.app.util.opinion.LoaderMap loaderMap: the loaders and their corresponding load specifications
        :param ghidra.app.util.bin.ByteProvider byteProvider: the ByteProvider for getting the bytes from the file to be imported.  The
                dialog takes ownership of the ByteProvider and it will be closed when the dialog is closed
        :param java.lang.String or str suggestedDestinationPath: optional string path that will be pre-pended to the destination
        name.  Any path specified in the destination name field will be created when
        the user performs the import (as opposed to the :meth:`destination folder <.setDestinationFolder>`
        option which requires the DomainFolder to already exist). The two destination paths work together
        to specify the final Ghidra project folder where the imported binary is placed.
        """

    def setDestinationFolder(self, folder: ghidra.framework.model.DomainFolder):
        """
        Sets the destination folder for the imported program.
        
        :param ghidra.framework.model.DomainFolder folder: the folder to store the imported program.
        """



__all__ = ["LcsSelectionListener", "ProjectIndexService", "LoadLibrariesOptionsDialog", "ImporterUtilities", "NewLanguagePanel", "AddToProgramDialog", "LanguageSortedTableModel", "ImporterLanguageDialog", "LcsSelectionEvent", "ImporterPlugin", "ImporterDialog"]
