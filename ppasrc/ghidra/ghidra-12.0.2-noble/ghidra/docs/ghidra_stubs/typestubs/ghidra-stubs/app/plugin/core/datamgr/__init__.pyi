from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.actions
import docking.menu
import docking.widgets.table
import docking.widgets.tree
import generic.jar
import ghidra.app.context
import ghidra.app.plugin
import ghidra.app.plugin.core.datamgr.archive
import ghidra.app.plugin.core.datamgr.editor
import ghidra.app.plugin.core.datamgr.tree
import ghidra.app.services
import ghidra.framework.main.datatable
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.exception
import ghidra.util.task
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import utility.function


class FilterOnNameOnlyAction(docking.action.ToggleDockingAction):
    """
    Allows user to filter on only the data type name.   When off, all information returned by
    :meth:`GTreeNode.getDisplayText() <GTreeNode.getDisplayText>` is used for filtering.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DataTypeManagerPlugin, provider: DataTypesProvider, menuSubGroup: typing.Union[java.lang.String, str]):
        ...


class DataTypeSyncInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, refDt: ghidra.program.model.data.DataType, sourceDTM: ghidra.program.model.data.DataTypeManager):
        ...

    def canCommit(self) -> bool:
        ...

    def canRevert(self) -> bool:
        ...

    def canUpdate(self) -> bool:
        ...

    def commit(self):
        """
        Commits the data type to the source archive.
        Call canCommit() to check the state before calling this.
        
        
        .. seealso::
        
            | :obj:`.canCommit()`
        """

    def disassociate(self):
        """
        Disassociates this DataTypeSyncInfo's data type from its source archive.
        """

    def getLastChangeTime(self, useSource: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getLastChangeTimeString(self, useSource: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    def getLastSyncTime(self) -> int:
        ...

    def getLastSyncTimeString(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getRefDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getRefDtPath(self) -> str:
        ...

    def getSourceDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getSourceDtPath(self) -> str:
        ...

    def getSyncState(self) -> DataTypeSyncState:
        ...

    def hasChange(self) -> bool:
        ...

    def revert(self):
        """
        Reverts the data type to match the one in the source archive.
        Call canRevert() to check the state before calling this.
        
        
        .. seealso::
        
            | :obj:`.canRevert()`
        """

    def syncTimes(self):
        ...

    def update(self):
        """
        Updates the data type from the one in the source archive.
        Call canUpdate() to check the state before calling this.
        
        
        .. seealso::
        
            | :obj:`.canUpdate()`
        """

    @property
    def sourceDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def lastSyncTime(self) -> jpype.JLong:
        ...

    @property
    def refDtPath(self) -> java.lang.String:
        ...

    @property
    def refDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def syncState(self) -> DataTypeSyncState:
        ...

    @property
    def lastChangeTime(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def sourceDtPath(self) -> java.lang.String:
        ...

    @property
    def lastSyncTimeString(self) -> java.lang.String:
        ...

    @property
    def lastChangeTimeString(self) -> java.lang.String:
        ...


class DataTypesProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, plugin: DataTypeManagerPlugin, providerName: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, plugin: DataTypeManagerPlugin, providerName: typing.Union[java.lang.String, str], isTransient: typing.Union[jpype.JBoolean, bool]):
        ...

    def editNode(self, node: docking.widgets.tree.GTreeNode):
        ...

    def getFilterState(self) -> ghidra.app.plugin.core.datamgr.tree.DtFilterState:
        ...

    def getGTree(self) -> ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree:
        ...

    def getSelectedDataTypes(self) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Returns a list of all the data types selected in the data types tree
        
        :return: a list of all the data types selected in the data types tree
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    def isFilterOnNameOnly(self) -> bool:
        ...

    def isIncludeDataMembersInSearch(self) -> bool:
        ...

    def setCategorySelected(self, category: ghidra.program.model.data.Category):
        """
        Selects the given data type category in the tree of data types.  This method will cause the
        data type tree to come to the front, scroll to the category and then to select the tree
        node that represents the category.  If the category is null, the selection is cleared.
        
        :param ghidra.program.model.data.Category category: the category to select; may be null
        """

    def setDataTypeSelected(self, dataType: ghidra.program.model.data.DataType):
        """
        Selects the given data type in the tree of data types.  This method will cause the
        data type tree to come to the front, scroll to the data type and then to select the tree
        node that represents the data type.  If the dataType parameter is null, then the tree
        selection will be cleared.
        
        :param ghidra.program.model.data.DataType dataType: the data type to select; may be null
        """

    def setFilterOnNameOnly(self, newValue: typing.Union[jpype.JBoolean, bool]):
        ...

    def setFilterOnNameOnlyCallback(self, newValue: typing.Union[jpype.JBoolean, bool]):
        ...

    def setFilterState(self, filterState: ghidra.app.plugin.core.datamgr.tree.DtFilterState):
        ...

    def setFilterText(self, text: typing.Union[java.lang.String, str]):
        ...

    def setIncludeDataTypeMembersInFilter(self, newValue: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIncludeDataTypeMembersInFilterCallback(self, newValue: typing.Union[jpype.JBoolean, bool]):
        ...

    def setPreviewWindowVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def filterState(self) -> ghidra.app.plugin.core.datamgr.tree.DtFilterState:
        ...

    @filterState.setter
    def filterState(self, value: ghidra.app.plugin.core.datamgr.tree.DtFilterState):
        ...

    @property
    def selectedDataTypes(self) -> java.util.List[ghidra.program.model.data.DataType]:
        ...

    @property
    def gTree(self) -> ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree:
        ...

    @property
    def includeDataMembersInSearch(self) -> jpype.JBoolean:
        ...

    @property
    def filterOnNameOnly(self) -> jpype.JBoolean:
        ...

    @filterOnNameOnly.setter
    def filterOnNameOnly(self, value: jpype.JBoolean):
        ...


class DataTypesActionContext(ghidra.app.context.ProgramActionContext, ghidra.framework.main.datatable.DomainFileContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: DataTypesProvider, program: ghidra.program.model.listing.Program, archiveGTree: ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree, clickedNode: docking.widgets.tree.GTreeNode):
        ...

    @typing.overload
    def __init__(self, provider: DataTypesProvider, program: ghidra.program.model.listing.Program, archiveGTree: ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree, clickedNode: docking.widgets.tree.GTreeNode, isToolbarAction: typing.Union[jpype.JBoolean, bool]):
        ...

    def getClickedNode(self) -> docking.widgets.tree.GTreeNode:
        ...

    def getClipboardNodes(self) -> java.util.List[docking.widgets.tree.GTreeNode]:
        ...

    def getDisassociatableNodes(self) -> java.util.List[ghidra.app.plugin.core.datamgr.tree.DataTypeNode]:
        ...

    def getSelectedNodes(self) -> java.util.List[docking.widgets.tree.GTreeNode]:
        ...

    def isToolbarAction(self) -> bool:
        ...

    @property
    def disassociatableNodes(self) -> java.util.List[ghidra.app.plugin.core.datamgr.tree.DataTypeNode]:
        ...

    @property
    def clickedNode(self) -> docking.widgets.tree.GTreeNode:
        ...

    @property
    def clipboardNodes(self) -> java.util.List[docking.widgets.tree.GTreeNode]:
        ...

    @property
    def selectedNodes(self) -> java.util.List[docking.widgets.tree.GTreeNode]:
        ...

    @property
    def toolbarAction(self) -> jpype.JBoolean:
        ...


class DataTypeSyncDialog(docking.DialogComponentProvider, DataTypeSyncListener):
    """
    The DataTypeSyncDialog displays a table with the data types that need to be synchronized 
    between a program and an associated archive that was used as a source of data types for 
    the program. Synchronizing data types means either Committing changes made to program 
    data types back to the associated source archive data types or Updating program data types 
    with changes that were made to the associated source data type in the archive.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DataTypeManagerPlugin, clientName: typing.Union[java.lang.String, str], sourceName: typing.Union[java.lang.String, str], list: java.util.List[DataTypeSyncInfo], preselectedInfos: java.util.Set[DataTypeSyncInfo], operationName: typing.Union[java.lang.String, str], title: typing.Union[java.lang.String, str]):
        ...

    def getSelectedInfos(self) -> java.util.List[DataTypeSyncInfo]:
        ...

    @property
    def selectedInfos(self) -> java.util.List[DataTypeSyncInfo]:
        ...


@typing.type_check_only
class DataTypeSyncTableModel(docking.widgets.table.AbstractSortedTableModel[RowData]):
    """
    Table model for showing data types that are out of sync with an archive. It can be used
    to either Commit or Update data types.
     
    Committing means overwriting the source data type in an archive with its associated
    program data type that has been changed.
     
    Updating means overwriting the program data type with its associated archive data
    type that has been changed.
     
    Currently the user can select which data types are to be synchronized
    (committed back to the archive or updated in the program).
    """

    @typing.type_check_only
    class RowDataSorter(java.util.Comparator[RowData]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, sortColumn: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def deselectAll(self):
        ...

    def getSelectedItems(self) -> java.util.List[DataTypeSyncInfo]:
        ...

    def getSyncInfo(self, selectedIndex: typing.Union[jpype.JInt, int]) -> DataTypeSyncInfo:
        ...

    def hasUnresolvedDataTypes(self) -> bool:
        ...

    def selectAll(self):
        ...

    @property
    def syncInfo(self) -> DataTypeSyncInfo:
        ...

    @property
    def selectedItems(self) -> java.util.List[DataTypeSyncInfo]:
        ...


@typing.type_check_only
class DataTypeComparePanel(javax.swing.JPanel):
    """
    Panel that displays two data types side by side.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataTypeSynchronizer(java.lang.Object):
    """
    Class for performing basic functions related to synchronizing data types between a program and
    an archive.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataTypeManagerHandler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dataTypeManager: ghidra.program.model.data.DataTypeManager, source: ghidra.program.model.data.SourceArchive):
        """
        Creates a DataTypeSynchronizer to be used for synchronizing data types between a program
        and an archive.
        
        :param ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler dataTypeManagerHandler: the handler that manages all the open data type managers
        whether built-in, program, project data type archive or file data type archive.
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: the program data type manager.
        :param ghidra.program.model.data.SourceArchive source: the data type source archive information indicating the associated archive for
        synchronizing.
        """

    @staticmethod
    def commit(dtmHandler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Commits a single program data type's changes to the associated source data type in the
        archive.
        
        :param ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler dtmHandler: the handler that manages data types
        :param ghidra.program.model.data.DataType dt: the program data type
        :return: true if the commit succeeds
        :rtype: bool
        """

    @staticmethod
    def disassociate(dataType: ghidra.program.model.data.DataType):
        """
        If the indicated data type is associated with a source archive, this will remove the
        association.
        
        :param ghidra.program.model.data.DataType dataType: the data type to be disassociated from a source archive.
        """

    def findAssociatedDataTypes(self) -> java.util.List[DataTypeSyncInfo]:
        ...

    def findOutOfSynchDataTypes(self) -> java.util.List[DataTypeSyncInfo]:
        ...

    def getArchiveName(self) -> str:
        ...

    def getClientName(self) -> str:
        ...

    def getClientType(self) -> str:
        ...

    @staticmethod
    def getDiffToolTip(handler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dataType: ghidra.program.model.data.DataType) -> str:
        ...

    def getSourceName(self) -> str:
        ...

    @staticmethod
    def getSyncStatus(handler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dataType: ghidra.program.model.data.DataType) -> DataTypeSyncState:
        ...

    def markSynchronized(self):
        ...

    def performBulkOperation(self, actionName: typing.Union[java.lang.String, str], selectedList: java.util.List[DataTypeSyncInfo], infoApplier: utility.function.ExceptionalConsumer[DataTypeSyncInfo, ghidra.util.exception.CancelledException], handleOutOfSync: java.util.function.Consumer[java.util.List[DataTypeSyncInfo]], sourceRequiresTransaction: typing.Union[jpype.JBoolean, bool]):
        ...

    def reSyncDataTypes(self):
        """
        Adjusts the data type and source archive info for an associated source archive if its sync
        state is incorrect. It makes sure that a data type that is the same as the associated
        archive one is in-sync. It also makes sure that a data type that differs from the archive
        one can be committed or updated.
        """

    def reSyncOutOfSyncInTimeOnlyDataTypes(self):
        """
        Checks if datatype is really out of sync or is only marked as out of sync but really
        is not changed. If datatypes are really in sync, updates the time marks to indicate that
        they are in sync;
        """

    def removeSourceArchive(self):
        ...

    @staticmethod
    def update(dtmHandler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Updates a single data type in the program to match the associated source data type from the
        archive.
        
        :param ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler dtmHandler: the handler that manages data types
        :param ghidra.program.model.data.DataType dt: the data type
        :return: true if the update succeeds
        :rtype: bool
        """

    @property
    def clientType(self) -> java.lang.String:
        ...

    @property
    def clientName(self) -> java.lang.String:
        ...

    @property
    def archiveName(self) -> java.lang.String:
        ...

    @property
    def sourceName(self) -> java.lang.String:
        ...


@typing.type_check_only
class OpenDomainFileTask(ghidra.util.task.Task):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DataTypeSyncListener(java.lang.Object):
    """
    Interface to define a method that is called when the selected data type changes in 
    the data type sync table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dataTypeSelected(self, syncInfo: DataTypeSyncInfo):
        """
        Notification that the given data type was selected.
        """


class DataTypeSyncState(java.lang.Enum[DataTypeSyncState]):

    class_: typing.ClassVar[java.lang.Class]
    IN_SYNC: typing.Final[DataTypeSyncState]
    UPDATE: typing.Final[DataTypeSyncState]
    COMMIT: typing.Final[DataTypeSyncState]
    CONFLICT: typing.Final[DataTypeSyncState]
    ORPHAN: typing.Final[DataTypeSyncState]
    UNKNOWN: typing.Final[DataTypeSyncState]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DataTypeSyncState:
        ...

    @staticmethod
    def values() -> jpype.JArray[DataTypeSyncState]:
        ...


class DataTypeManagerPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener, ghidra.app.services.DataTypeManagerService, docking.actions.PopupActionProvider):
    """
    Plugin to pop up the dialog to manage data types in the program
    and archived data type files. The dialog shows a single tree with
    different categories.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def addRecentlyOpenedArchiveFile(self, file: generic.jar.ResourceFile):
        ...

    @typing.overload
    def addRecentlyOpenedProjectArchive(self, projectName: typing.Union[java.lang.String, str], pathname: typing.Union[java.lang.String, str]):
        """
        Add project archive name to recently opened list
        
        :param java.lang.String or str projectName: the project name
        :param java.lang.String or str pathname: the pathname
        """

    @typing.overload
    def addRecentlyOpenedProjectArchive(self, pa: ghidra.app.plugin.core.datamgr.archive.ProjectArchive):
        """
        Add project archive to recently opened list provided it is contained within the
        active project and is not a specific version (i.e., only latest version can be
        remembered).
        
        :param ghidra.app.plugin.core.datamgr.archive.ProjectArchive pa: project archive
        """

    def commit(self, dataType: ghidra.program.model.data.DataType) -> bool:
        ...

    def createProvider(self) -> DataTypesProvider:
        ...

    def disassociate(self, dataTypes: ghidra.program.model.data.DataType):
        ...

    def getAllArchives(self) -> java.util.List[ghidra.app.plugin.core.datamgr.archive.Archive]:
        ...

    def getClipboard(self) -> java.awt.datatransfer.Clipboard:
        ...

    def getConflictHandler(self) -> ghidra.program.model.data.DataTypeConflictHandler:
        ...

    def getCurrentSelection(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def getDataTypeManagerHandler(self) -> ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler:
        ...

    def getEditorManager(self) -> ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getProgramDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    def getProjectArchiveFile(self, projectName: typing.Union[java.lang.String, str], pathname: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
        """
        Get a project archive file by project name and pathname
        
        :param java.lang.String or str projectName: the project name
        :param java.lang.String or str pathname: the project pathname
        :return: project archive domain file or null if it does not exist
        or can not be found (e.g., projectName is not the active project)
        :rtype: ghidra.framework.model.DomainFile
        """

    def getProvider(self) -> DataTypesProvider:
        ...

    def getRecentlyOpenedArchives(self) -> java.util.Collection[java.lang.String]:
        """
        A collection of files that have recently been opened by the user.
        
        :return: A collection of files that have recently been opened by the user.
        :rtype: java.util.Collection[java.lang.String]
        """

    @staticmethod
    def isValidTypeDefBaseType(parent: java.awt.Component, dataType: ghidra.program.model.data.DataType) -> bool:
        ...

    @typing.overload
    def openArchive(self, df: ghidra.framework.model.DomainFile) -> ghidra.program.model.listing.DataTypeArchive:
        ...

    @typing.overload
    def openArchive(self, df: ghidra.framework.model.DomainFile, version: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.DataTypeArchive:
        ...

    def openProjectDataTypeArchive(self):
        ...

    def revert(self, dataType: ghidra.program.model.data.DataType) -> bool:
        ...

    def update(self, dataType: ghidra.program.model.data.DataType) -> bool:
        ...

    @property
    def programDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    @property
    def provider(self) -> DataTypesProvider:
        ...

    @property
    def currentSelection(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def clipboard(self) -> java.awt.datatransfer.Clipboard:
        ...

    @property
    def allArchives(self) -> java.util.List[ghidra.app.plugin.core.datamgr.archive.Archive]:
        ...

    @property
    def recentlyOpenedArchives(self) -> java.util.Collection[java.lang.String]:
        ...

    @property
    def editorManager(self) -> ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager:
        ...

    @property
    def dataTypeManagerHandler(self) -> ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler:
        ...

    @property
    def conflictHandler(self) -> ghidra.program.model.data.DataTypeConflictHandler:
        ...


@typing.type_check_only
class RowData(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataTypePropertyManager(java.lang.Object):
    """
    Manages the attributes for data types; used by the manage data types
    dialog to populate the data types tree structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addChangeListener(self, l: javax.swing.event.ChangeListener):
        """
        Add listener that is notified if favorites list changes.
        **WARNING:**The implementation for the listeners uses weak
        references so that when listeners go away, no handle is kept for them
        in the list of listeners. Therefore, the class that creates the
        change listener must keep a handle to it so that some object keeps
        a handle; otherwise, the change listener will be garbage collected
        and the listener never gets calls.
        """

    def removeChangeListener(self, l: javax.swing.event.ChangeListener):
        """
        Remove the listener.
        """


@typing.type_check_only
class DataTypeSyncPanel(javax.swing.JPanel):
    """
    Left panel in the DataTypeSyncDialog. This panel displays a table with all the data types to
    be synchronized (committed or updated) between a program and an archive.
    """

    @typing.type_check_only
    class DataTypeSyncBooleanRenderer(docking.widgets.table.GBooleanCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def deselectAll(self):
        ...

    def getSelectedInfos(self) -> java.util.List[DataTypeSyncInfo]:
        ...

    def hasUnresolvedDataTypes(self) -> bool:
        ...

    def selectAll(self):
        ...

    @property
    def selectedInfos(self) -> java.util.List[DataTypeSyncInfo]:
        ...


@typing.type_check_only
class NextPreviousDataTypeAction(docking.menu.MultiActionDockingAction):
    """
    An action to navigate backwards or forwards in the history of data types
    """

    @typing.type_check_only
    class NavigationAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DataTypesProvider, owner: typing.Union[java.lang.String, str], isNext: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["FilterOnNameOnlyAction", "DataTypeSyncInfo", "DataTypesProvider", "DataTypesActionContext", "DataTypeSyncDialog", "DataTypeSyncTableModel", "DataTypeComparePanel", "DataTypeSynchronizer", "OpenDomainFileTask", "DataTypeSyncListener", "DataTypeSyncState", "DataTypeManagerPlugin", "RowData", "DataTypePropertyManager", "DataTypeSyncPanel", "NextPreviousDataTypeAction"]
