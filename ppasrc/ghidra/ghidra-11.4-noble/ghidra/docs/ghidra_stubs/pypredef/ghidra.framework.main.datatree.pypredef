from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.dnd
import docking.widgets.table
import docking.widgets.table.threaded
import docking.widgets.tree
import docking.widgets.tree.support
import ghidra.app.plugin.core.datamgr
import ghidra.app.plugin.core.datamgr.archive
import ghidra.app.util
import ghidra.framework.data
import ghidra.framework.main
import ghidra.framework.main.datatable
import ghidra.framework.main.projectdata.actions
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.framework.remote
import ghidra.framework.store
import ghidra.util
import ghidra.util.task
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore


class GhidraDataFlavorHandlerService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ArchiveProvider(java.lang.Object):
    """
    An interface to be implemented by any class that can return a list of Archives.
    For example, the tool's data type manager can return a list of archives within the project.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getArchives(self) -> java.util.List[ghidra.app.plugin.core.datamgr.archive.Archive]:
        ...

    @property
    def archives(self) -> java.util.List[ghidra.app.plugin.core.datamgr.archive.Archive]:
        ...


class JavaFileListHandler(AbstractFileListFlavorHandler):
    """
    A handler to facilitate drag-n-drop for a list of Java :obj:`File` objects which is dropped
    onto the Project data tree or a running Ghidra Tool (see :obj:`DataFlavor.javaFileListFlavor`).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VersionControlDataTypeArchiveUndoCheckoutAction(ghidra.framework.main.projectdata.actions.VersionControlAction):
    """
    Action to undo checkouts for domain files in the repository.
    """

    @typing.type_check_only
    class DataTypeArchiveUndoCheckOutTask(ghidra.util.task.Task):
        """
        Task for undoing check out of files that are in version control.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, provider: ArchiveProvider):
        """
        Creates an action to undo checkouts for domain files in the repository.
        
        :param ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin plugin: the plug-in that owns this action.
        :param ArchiveProvider provider: provides a list of domain files to be affected by this action.
        """


@typing.type_check_only
class AbstractFileListFlavorHandler(DataTreeFlavorHandler, ghidra.app.util.FileOpenDataFlavorHandler):
    """
    An abstract handler to facilitate drag-n-drop for a list of Java :obj:`File` objects which is 
    dropped onto the Project data tree (see :obj:`DataTreeFlavorHandler`) or a running Ghidra Tool
    (see :obj:`FileOpenDataFlavorHandler`).
    """

    class_: typing.ClassVar[java.lang.Class]


class LinuxFileUrlHandler(AbstractFileListFlavorHandler):
    """
    A handler to facilitate drag-n-drop for a Linux URL-based file list which is dropped
    onto the Project data tree or a running Ghidra Tool (see :obj:`.linuxFileUrlFlavor`).
    """

    class_: typing.ClassVar[java.lang.Class]
    linuxFileUrlFlavor: typing.Final[java.awt.datatransfer.DataFlavor]
    """
    Linux URL-based file list :obj:`DataFlavor` to be used during handler registration
    using :obj:`DataTreeDragNDropHandler.addActiveDataFlavorHandler`.
    """


    def __init__(self):
        ...


class DataTreeFlavorHandler(java.lang.Object):
    """
    Interface for classes that will handle drop actions for :obj:`DataTree`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def handle(self, tool: ghidra.framework.plugintool.PluginTool, dataTree: DataTree, destinationNode: docking.widgets.tree.GTreeNode, transferData: java.lang.Object, dropAction: typing.Union[jpype.JInt, int]) -> bool:
        ...


@typing.type_check_only
class CopyFileVersionTask(ghidra.util.task.Task):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DomainFolderRootNode(DomainFolderNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CheckInTask(VersionControlTask, ghidra.framework.data.CheckinHandler):
    """
    Task to perform a check on a list of DomainFiles.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, list: java.util.List[ghidra.framework.model.DomainFile], parent: java.awt.Component):
        """
        Construct a new CheckInTask.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool that has the files to be checked in
        :param java.util.List[ghidra.framework.model.DomainFile] list: list of domain files to be checked in
        :param java.awt.Component parent: parent of error dialog if an error occurs
        """


class ChangedFilesDialog(docking.DialogComponentProvider):
    """
    Dialog to prompt user to save files before adding files to source control
    or checking in files.
    """

    @typing.type_check_only
    class SaveTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, list: java.util.List[ghidra.framework.model.DomainFile]):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: tool to execute task and log messages in status window
        :param java.util.List[ghidra.framework.model.DomainFile] list: list of domain files that have changes
        """

    def setCancelToolTipText(self, toolTip: typing.Union[java.lang.String, str]):
        """
        Set the tool tip on the cancel button.
        
        :param java.lang.String or str toolTip: tool tip to set on the cancel button
        """

    def showDialog(self) -> bool:
        """
        Show ChangedFilesDialog.
        
        :return: whether the save button was selected; return false if the user
        canceled
        :rtype: bool
        """


@typing.type_check_only
class VersionHistoryTableModel(docking.widgets.table.AbstractSortedTableModel[ghidra.framework.store.Version]):
    """
    Table model for showing version history.
    """

    class_: typing.ClassVar[java.lang.Class]


class UndoActionDialog(docking.DialogComponentProvider):
    """
    Dialog that confirms undo of an action; specify whether a .keep file
    should be created on the undo of the action.
    """

    class_: typing.ClassVar[java.lang.Class]
    CANCEL: typing.Final = 1

    def __init__(self, title: typing.Union[java.lang.String, str], icon: javax.swing.Icon, helpTag: typing.Union[java.lang.String, str], actionString: typing.Union[java.lang.String, str], fileList: java.util.List[ghidra.framework.model.DomainFile]):
        ...

    def getSelectedDomainFiles(self) -> jpype.JArray[ghidra.framework.model.DomainFile]:
        ...

    def saveCopy(self) -> bool:
        ...

    def showDialog(self, tool: ghidra.framework.plugintool.PluginTool) -> int:
        ...

    @property
    def selectedDomainFiles(self) -> jpype.JArray[ghidra.framework.model.DomainFile]:
        ...


class Cuttable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def isCut(self) -> bool:
        ...

    def setIsCut(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def cut(self) -> jpype.JBoolean:
        ...


class FrontEndProjectTreeContext(ghidra.framework.main.datatable.ProjectDataContext, ghidra.framework.main.datatable.ProjectTreeContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, projectData: ghidra.framework.model.ProjectData, selectionPaths: jpype.JArray[javax.swing.tree.TreePath], folderList: java.util.List[ghidra.framework.model.DomainFolder], fileList: java.util.List[ghidra.framework.model.DomainFile], tree: DataTree, isActiveProject: typing.Union[jpype.JBoolean, bool]):
        ...


class ClearCutAction(ghidra.framework.main.datatable.ProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class FindCheckoutsTableModel(docking.widgets.table.threaded.ThreadedTableModelStub[CheckoutInfo]):
    """
    Table model for find checkouts for the user logged in.
    """

    @typing.type_check_only
    class NameTableColumn(docking.widgets.table.AbstractDynamicTableColumnStub[CheckoutInfo, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PathTableColumn(docking.widgets.table.AbstractDynamicTableColumnStub[CheckoutInfo, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CheckoutDateTableColumn(docking.widgets.table.AbstractDynamicTableColumnStub[CheckoutInfo, java.util.Date]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VersionTableColumn(docking.widgets.table.AbstractDynamicTableColumnStub[CheckoutInfo, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    CHECKOUT_DATE: typing.Final = "Checkout Date"

    def __init__(self, parent: ghidra.framework.model.DomainFolder, pluginTool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class ChangeManager(ghidra.framework.model.DomainFolderChangeListener):
    """
    Class to handle changes when a domain folder changes; updates the
    tree model to reflect added/removed/renamed nodes.
    """

    class_: typing.ClassVar[java.lang.Class]


class VersionInfoTransferable(java.awt.datatransfer.Transferable, java.awt.datatransfer.ClipboardOwner):
    """
    Defines a transferable
    """

    class_: typing.ClassVar[java.lang.Class]
    localVersionInfoFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    """
    DataFlavor for VersionInfoTransferable.
    """


    def getTransferData(self, flavor: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        ...

    def getTransferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    def isDataFlavorSupported(self, flavor: java.awt.datatransfer.DataFlavor) -> bool:
        ...

    def lostOwnership(self, clipboard: java.awt.datatransfer.Clipboard, contents: java.awt.datatransfer.Transferable):
        ...

    def toString(self) -> str:
        """
        Get the string representation for this transferable.
        """

    @property
    def transferData(self) -> java.lang.Object:
        ...

    @property
    def transferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def dataFlavorSupported(self) -> jpype.JBoolean:
        ...


class DomainFileNode(docking.widgets.tree.GTreeNode, Cuttable):
    """
    Class to represent a node in the Data tree.
    """

    @typing.type_check_only
    class DomainFileNodeSwingWorker(javax.swing.SwingWorker[DomainFileNode, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getDisplayText(self) -> str:
        """
        Get the name to display in tree.
        """

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        """
        Get the domain file if this node represents a file object versus a folder; interface method
        for DomainDataTransfer.
        
        :return: null if this node represents a domain folder
        :rtype: ghidra.framework.model.DomainFile
        """

    def isCut(self) -> bool:
        """
        Returns whether this node is marked as deleted.
        """

    def setIsCut(self, isCut: typing.Union[jpype.JBoolean, bool]):
        """
        Set this node to be deleted so that it can be rendered as such.
        """

    @property
    def displayText(self) -> java.lang.String:
        ...

    @property
    def cut(self) -> jpype.JBoolean:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...


class ProjectDataTreePanel(javax.swing.JPanel):
    """
    Panel that contains a DataTree for showing project data.
    Controls whether the data tree supports drag and drop operations.
    """

    @typing.type_check_only
    class FindAndSelectTask(docking.widgets.tree.GTreeTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, plugin: ghidra.framework.main.FrontEndPlugin):
        """
        Construct an empty panel that is going to be used as the active panel
        
        :param ghidra.framework.main.FrontEndPlugin plugin: front end plugin
        """

    @typing.overload
    def __init__(self, projectName: typing.Union[java.lang.String, str], isActiveProject: typing.Union[jpype.JBoolean, bool], plugin: ghidra.framework.main.FrontEndPlugin, filter: ghidra.framework.model.DomainFileFilter):
        """
        Constructor
        
        :param java.lang.String or str projectName: name of project
        :param jpype.JBoolean or bool isActiveProject: true if the project is active, and the
        data tree may be modified
        :param ghidra.framework.main.FrontEndPlugin plugin: front end plugin; will be null if the panel is used in a dialog
        :param ghidra.framework.model.DomainFileFilter filter: optional filter that is used to hide programs from view
        """

    def addTreeMouseListener(self, l: java.awt.event.MouseListener):
        ...

    def addTreeSelectionListener(self, l: docking.widgets.tree.support.GTreeSelectionListener):
        """
        Add the tree selection listener to the data tree. When the
        listener is notified of the selection change, it should
        call ``getSelectedDomainFolder()`` and
        ``getSelectedDomainFile()`` to get the last selected
        object.
        
        :param docking.widgets.tree.support.GTreeSelectionListener l: listener to add
        """

    def checkOpen(self, e: java.awt.event.MouseEvent):
        ...

    def closeRootFolder(self):
        """
        Close the root folder for this data tree.
        """

    def dispose(self):
        ...

    def findAndSelect(self, s: typing.Union[java.lang.String, str]):
        """
        Find a node that has the given name and select it.
        
        :param java.lang.String or str s: node name
        """

    def getActionContext(self, provider: docking.ComponentProvider, e: java.awt.event.MouseEvent) -> docking.ActionContext:
        """
        Get the data tree node that is selected
        
        :param docking.ComponentProvider provider: the provider with which to construct the new context
        :param java.awt.event.MouseEvent e: mouse event for the popup; may be null if this is being called as a result of 
                the key binding pressed
        :return: the new context; null if there is no selection
        :rtype: docking.ActionContext
        """

    def getDataTree(self) -> DataTree:
        ...

    def getExpandedPathsByNodeName(self) -> jpype.JArray[java.lang.String]:
        ...

    def getFilterField(self) -> java.awt.Component:
        ...

    def getProjectData(self) -> ghidra.framework.model.ProjectData:
        ...

    def getSelectedDomainFile(self) -> ghidra.framework.model.DomainFile:
        """
        Get the last selected domain file.
        
        :return: null if no domain file is selected.
        :rtype: ghidra.framework.model.DomainFile
        """

    def getSelectedDomainFolder(self) -> ghidra.framework.model.DomainFolder:
        """
        Get the last selected domain folder.
        
        :return: null if no domain folder is selected.
        :rtype: ghidra.framework.model.DomainFolder
        """

    def getSelectedItemCount(self) -> int:
        """
        Get the number of selected items in the tree.  These could be either files or folders.
        
        :return: the number of selected items in the tree.
        :rtype: int
        """

    def getTreeSelectionModel(self) -> javax.swing.tree.TreeSelectionModel:
        ...

    def projectRenamed(self, newName: typing.Union[java.lang.String, str]):
        """
        Notification that the project was renamed; update the root node name
        and reload the node
        
        :param java.lang.String or str newName: the new project name
        """

    def removeTreeMouseListener(self, l: java.awt.event.MouseListener):
        ...

    def removeTreeSelectionListener(self, l: docking.widgets.tree.support.GTreeSelectionListener):
        """
        Remove the tree selection listener from the data tree.
        
        :param docking.widgets.tree.support.GTreeSelectionListener l: listener to remove
        """

    def selectDomainFile(self, domainFile: ghidra.framework.model.DomainFile):
        ...

    def selectDomainFiles(self, files: java.util.Set[ghidra.framework.model.DomainFile]):
        ...

    def selectDomainFolder(self, domainFolder: ghidra.framework.model.DomainFolder):
        ...

    def selectRootDataFolder(self):
        """
        Select the root data folder (not root node in the tree which shows the project name).
        """

    def setDomainFileFilter(self, filter: ghidra.framework.model.DomainFileFilter):
        """
        Set the filter on this data tree.
        
        :param ghidra.framework.model.DomainFileFilter filter: determines what should be included in the data tree
        """

    def setExpandedPathsByNodeName(self, stringPaths: jpype.JArray[java.lang.String]):
        ...

    def setHelpLocation(self, helpLocation: ghidra.util.HelpLocation):
        ...

    def setPreferredTreePanelSize(self, d: java.awt.Dimension):
        ...

    def setProjectData(self, projectName: typing.Union[java.lang.String, str], projectData: ghidra.framework.model.ProjectData):
        """
        Set the project data for this data tree and populate it with
        nodes for the users in the project.
        
        :param java.lang.String or str projectName: name of project
        :param ghidra.framework.model.ProjectData projectData: data that has the root folder for the project
        """

    def setTreeFilterEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Adds or removes the filter from the tree.
        
        :param jpype.JBoolean or bool enabled: Tree adds the filter; false removes it
        """

    def updateProjectName(self, newName: typing.Union[java.lang.String, str]):
        """
        Update the project name
        
        :param java.lang.String or str newName: the new name
        """

    @property
    def projectData(self) -> ghidra.framework.model.ProjectData:
        ...

    @property
    def selectedDomainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def selectedItemCount(self) -> jpype.JInt:
        ...

    @property
    def expandedPathsByNodeName(self) -> jpype.JArray[java.lang.String]:
        ...

    @expandedPathsByNodeName.setter
    def expandedPathsByNodeName(self, value: jpype.JArray[java.lang.String]):
        ...

    @property
    def treeSelectionModel(self) -> javax.swing.tree.TreeSelectionModel:
        ...

    @property
    def selectedDomainFolder(self) -> ghidra.framework.model.DomainFolder:
        ...

    @property
    def dataTree(self) -> DataTree:
        ...

    @property
    def filterField(self) -> java.awt.Component:
        ...


@typing.type_check_only
class CheckoutInfo(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class VersionControlTask(ghidra.util.task.Task):
    """
    Task to show a dialog to enter comments for checking in a file
    """

    class_: typing.ClassVar[java.lang.Class]


class VersionInfo(java.io.Serializable):
    """
    Version info that is inside of the VersionInfoTransferable;
    must be serializable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDomainFilePath(self) -> str:
        """
        Get the path to the domain file.
        """

    def getVersionNumber(self) -> int:
        """
        Get the version number.
        """

    @property
    def domainFilePath(self) -> java.lang.String:
        ...

    @property
    def versionNumber(self) -> jpype.JInt:
        ...


class CheckoutDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]
    OK: typing.Final = 0
    CANCELED: typing.Final = 1

    def __init__(self):
        ...

    def exclusiveCheckout(self) -> bool:
        ...

    def showDialog(self, tool: ghidra.framework.plugintool.PluginTool) -> int:
        """
        Show the dialog; return an ID for the action that the user chose.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool used to show the dialog
        :return: OK, or CANCEL
        :rtype: int
        """


class CopyTask(ghidra.util.task.Task):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataTree(docking.widgets.tree.GTree):
    """
    Tree that shows the folders and domain files in a Project
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearSelection(self):
        ...

    def getLastSelectedPathComponent(self) -> docking.widgets.tree.GTreeNode:
        ...

    def getSelectionCount(self) -> int:
        ...

    def removeSelectionPath(self, path: javax.swing.tree.TreePath):
        ...

    @property
    def selectionCount(self) -> jpype.JInt:
        ...

    @property
    def lastSelectedPathComponent(self) -> docking.widgets.tree.GTreeNode:
        ...


class VersionControlDialog(docking.DialogComponentProvider):
    """
    Dialog to get comments for adding a file to version control or 
    checking in a file.
    """

    class_: typing.ClassVar[java.lang.Class]
    APPLY_TO_ALL: typing.Final = 1
    CANCEL: typing.Final = 2

    def __init__(self, addToVersionControl: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param jpype.JBoolean or bool addToVersionControl: true for adding; false for check-in
        """

    def setCurrentFileName(self, filename: typing.Union[java.lang.String, str]):
        """
        Set the name of the current file being added to version control or being updated.
        
        :param java.lang.String or str filename: the name of the file currently to be added, whose comment we need.
        """

    def setKeepCheckboxEnabled(self, enabled: typing.Union[jpype.JBoolean, bool], selected: typing.Union[jpype.JBoolean, bool], disabledMsg: typing.Union[java.lang.String, str]):
        ...


class DataTreeDragNDropHandler(docking.widgets.tree.support.GTreeDragNDropHandler):

    class_: typing.ClassVar[java.lang.Class]
    localDomainFileTreeFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    localDomainFileFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    allSupportedFlavors: typing.ClassVar[jpype.JArray[java.awt.datatransfer.DataFlavor]]

    @staticmethod
    def addActiveDataFlavorHandler(flavor: java.awt.datatransfer.DataFlavor, handler: DataTreeFlavorHandler):
        ...

    @staticmethod
    def removeActiveDataFlavorHandler(flavor: java.awt.datatransfer.DataFlavor) -> DataTreeFlavorHandler:
        ...

    def setProjectActive(self, b: typing.Union[jpype.JBoolean, bool]):
        ...


class PasteFileTask(ghidra.util.task.Task):
    """
    Task to paste files at given destination folder.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, destNode: DomainFolderNode, list: java.util.List[docking.widgets.tree.GTreeNode], isCut: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for PasteFileTask.
        
        :param DomainFolderNode destNode: destination folder
        :param java.util.List[docking.widgets.tree.GTreeNode] list: list of GTreeNodes being pasted
        :param jpype.JBoolean or bool isCut: boolean flag, true means source nodes were cut instead of copied.
        """


class VersionHistoryPanel(javax.swing.JPanel, docking.dnd.Draggable):
    """
    Panel that shows version history in a JTable
    """

    @typing.type_check_only
    class MyCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HistoryTableAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DeleteAction(VersionHistoryPanel.HistoryTableAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OpenDefaultAction(VersionHistoryPanel.HistoryTableAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OpenWithAction(VersionHistoryPanel.HistoryTableAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DeleteTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, domainFile: ghidra.framework.model.DomainFile):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: tool
        :param ghidra.framework.model.DomainFile domainFile: domain file; may be null
        :raises IOException: if there was a problem accessing the
        version history
        """

    def addListSelectionListener(self, selectionListener: javax.swing.event.ListSelectionListener):
        """
        Add the list selection listener to the history table
        
        :param javax.swing.event.ListSelectionListener selectionListener: the listener
        """

    def createPopupActions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        """
        Get current domain file
        
        :return: current domain file
        :rtype: ghidra.framework.model.DomainFile
        """

    def getDomainFilePath(self) -> str:
        """
        Get current domain file path or null
        
        :return: domain file path
        :rtype: str
        """

    def getSelectedVersion(self) -> ghidra.framework.store.Version:
        """
        Get the selected :obj:`Version`.
        
        :return: selected :obj:`Version` or null if no selection
        :rtype: ghidra.framework.store.Version
        """

    def getSelectedVersionNumber(self) -> int:
        """
        Get the selected version number or :obj:`DomainFile.DEFAULT_VERSION` if no selection.
        
        :return: selected version number
        :rtype: int
        """

    def isVersionSelected(self) -> bool:
        """
        Determine if a version selection has been made.
        
        :return: true if version selection has been made, esle false
        :rtype: bool
        """

    def removeListSelectionListener(self, selectionListener: javax.swing.event.ListSelectionListener):
        """
        Remove the list selection listener from history table.
        
        :param javax.swing.event.ListSelectionListener selectionListener: the listener
        """

    def setDomainFile(self, domainFile: ghidra.framework.model.DomainFile):
        """
        Set the domain file to show its history.
        If file not found a null file will be set.
        
        :param ghidra.framework.model.DomainFile domainFile: the file
        """

    @property
    def domainFilePath(self) -> java.lang.String:
        ...

    @property
    def versionSelected(self) -> jpype.JBoolean:
        ...

    @property
    def selectedVersion(self) -> ghidra.framework.store.Version:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @domainFile.setter
    def domainFile(self, value: ghidra.framework.model.DomainFile):
        ...

    @property
    def selectedVersionNumber(self) -> jpype.JInt:
        ...


class VersionHistoryDialog(docking.DialogComponentProvider, ghidra.framework.model.ProjectListener):

    @typing.type_check_only
    class MyFolderListener(ghidra.framework.model.DomainFolderListenerAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, domainFile: ghidra.framework.model.DomainFile):
        ...


class FindCheckoutsDialog(docking.DialogComponentProvider):
    """
    Dialog that shows all checkouts in a specific folder and all of its subfolders.
    """

    @typing.type_check_only
    class MyCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, folder: ghidra.framework.model.DomainFolder):
        ...


@typing.type_check_only
class DomainFilesPanel(javax.swing.JPanel):
    """
    Reusable Panel that shows a list of checkboxes for each domain 
    file in a list.
    """

    @typing.type_check_only
    class DataCellRenderer(javax.swing.ListCellRenderer[javax.swing.JCheckBox]):
        """
        Cell renderer to show the checkboxes for the changed data files.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ListMouseListener(java.awt.event.MouseAdapter):
        """
        Mouse listener to get the selected cell in the list.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ListKeyListener(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class DataTreeClipboardUtils(java.lang.Object):
    """
    Manages Ghidra integration with the system clipboard when doing cut/copy/paste
    operations on domainFiles and domainFolders in a data tree widget.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def clearCuttables():
        """
        Clears the :meth:`isCut <Cuttable.isCut>` flag on any GTreeNodes that are pointed to by
        the system clipboard.
        """

    @staticmethod
    @typing.overload
    def clearCuttables(transferable: java.awt.datatransfer.Transferable):
        """
        Clears the :meth:`isCut <Cuttable.isCut>` flag on any GTreeNodes that are pointed to by
        the specified :obj:`Transferable`
        
        :param java.awt.datatransfer.Transferable transferable: contains clipboard contents
        """

    @staticmethod
    def getDataTreeNodesFromClipboard() -> java.util.List[docking.widgets.tree.GTreeNode]:
        """
        Fetches any GTreeNodes from the system clipboard.
        
        :return: List of :obj:`GTreeNode`s that were in the system clipboard, or empty list if
        no nodes or some other access error.
        :rtype: java.util.List[docking.widgets.tree.GTreeNode]
        """

    @staticmethod
    def isCuttablePresent() -> bool:
        """
        Returns true if the system clipboard has any GTreeNodes that have the :meth:`Cuttable.isCut() <Cuttable.isCut>`
        flag set.
        
        :return: boolean true if there are any cut nodes in the clipboard
        :rtype: bool
        """

    @staticmethod
    def setClipboardContents(tree: DataTree, paths: jpype.JArray[javax.swing.tree.TreePath]):
        """
        Pushes the GTreeNodes in the specified TreePath array to the clipboard.
        
        :param DataTree tree: DataTree that contains the GTreeNodes
        :param jpype.JArray[javax.swing.tree.TreePath] paths: array of TreePaths containing nodes to be pushed to clipboard.
        """


@typing.type_check_only
class CheckoutsTableModel(docking.widgets.table.AbstractSortedTableModel[ghidra.framework.store.ItemCheckoutStatus]):
    """
    Table model for showing checkout information for a domain file.
    """

    class_: typing.ClassVar[java.lang.Class]


class LocalVersionInfoHandler(DataTreeFlavorHandler, ghidra.app.util.FileOpenDataFlavorHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DomainFolderNode(docking.widgets.tree.GTreeSlowLoadingNode, Cuttable):
    """
    Class to represent a node in the Data tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDomainFileFilter(self) -> ghidra.framework.model.DomainFileFilter:
        ...

    def getDomainFolder(self) -> ghidra.framework.model.DomainFolder:
        """
        Get the domain folder; returns null if this node represents a domain file.
        
        :return: DomainFolder
        :rtype: ghidra.framework.model.DomainFolder
        """

    def isCut(self) -> bool:
        """
        Returns whether this node is marked as deleted.
        """

    def isLeaf(self) -> bool:
        """
        Returns true if this node has no children.
        """

    def setIsCut(self, isCut: typing.Union[jpype.JBoolean, bool]):
        """
        Set this node to be deleted so that it can be rendered as such.
        """

    @property
    def cut(self) -> jpype.JBoolean:
        ...

    @property
    def domainFileFilter(self) -> ghidra.framework.model.DomainFileFilter:
        ...

    @property
    def leaf(self) -> jpype.JBoolean:
        ...

    @property
    def domainFolder(self) -> ghidra.framework.model.DomainFolder:
        ...


class NoProjectNode(docking.widgets.tree.GTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LocalTreeNodeHandler(DataTreeFlavorHandler, ghidra.app.util.FileOpenDataFlavorHandler):

    @typing.type_check_only
    class CopyAllTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DialogProjectTreeContext(docking.DialogActionContext, ghidra.framework.main.datatable.ProjectTreeContext):
    """
    Context specific to the DataTreeDialog.
     
    Note: this context is used from by the :obj:`ProjectDataTreePanel`.  This class may or may not
    be in a dialog.  For convenience, this class extends a dialog action context, but may not always
    be associated with a dialog.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, projectData: ghidra.framework.model.ProjectData, selectionPaths: jpype.JArray[javax.swing.tree.TreePath], folderList: java.util.List[ghidra.framework.model.DomainFolder], fileList: java.util.List[ghidra.framework.model.DomainFile], tree: DataTree):
        ...


class CheckoutsPanel(javax.swing.JPanel):
    """
    Panel that shows check out information for a domain file.
    """

    @typing.type_check_only
    class MyFolderListener(ghidra.framework.model.DomainFolderListenerAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: java.awt.Component, tool: ghidra.framework.plugintool.PluginTool, user: ghidra.framework.remote.User, domainFile: ghidra.framework.model.DomainFile, checkouts: jpype.JArray[ghidra.framework.store.ItemCheckoutStatus]):
        """
        Constructor
        
        :param java.awt.Component parent: parent dialog
        :param ghidra.framework.plugintool.PluginTool tool: tool to get project data for adding a listener
        :param ghidra.framework.remote.User user: user that is logged in
        :param ghidra.framework.model.DomainFile domainFile: domain file to view checkouts
        :param jpype.JArray[ghidra.framework.store.ItemCheckoutStatus] checkouts: the checkouts to show
        """

    def createActions(self, provider: docking.DialogComponentProvider):
        ...

    def dispose(self):
        ...

    def getSelectedRows(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def selectedRows(self) -> jpype.JArray[jpype.JInt]:
        ...



__all__ = ["GhidraDataFlavorHandlerService", "ArchiveProvider", "JavaFileListHandler", "VersionControlDataTypeArchiveUndoCheckoutAction", "AbstractFileListFlavorHandler", "LinuxFileUrlHandler", "DataTreeFlavorHandler", "CopyFileVersionTask", "DomainFolderRootNode", "CheckInTask", "ChangedFilesDialog", "VersionHistoryTableModel", "UndoActionDialog", "Cuttable", "FrontEndProjectTreeContext", "ClearCutAction", "FindCheckoutsTableModel", "ChangeManager", "VersionInfoTransferable", "DomainFileNode", "ProjectDataTreePanel", "CheckoutInfo", "VersionControlTask", "VersionInfo", "CheckoutDialog", "CopyTask", "DataTree", "VersionControlDialog", "DataTreeDragNDropHandler", "PasteFileTask", "VersionHistoryPanel", "VersionHistoryDialog", "FindCheckoutsDialog", "DomainFilesPanel", "DataTreeClipboardUtils", "CheckoutsTableModel", "LocalVersionInfoHandler", "DomainFolderNode", "NoProjectNode", "LocalTreeNodeHandler", "DialogProjectTreeContext", "CheckoutsPanel"]
