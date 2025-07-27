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
import ghidra.framework.main
import ghidra.framework.main.datatree
import ghidra.framework.model
import ghidra.util
import ghidra.util.bean
import ghidra.util.classfinder
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class DomainFileProviderContextAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...


class ProjectTreeAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...


class ProjectDataTableModel(docking.widgets.table.threaded.ThreadedTableModel[DomainFileInfo, ghidra.framework.model.ProjectData]):

    @typing.type_check_only
    class DomainFileTypeColumn(docking.widgets.table.AbstractDynamicTableColumn[DomainFileInfo, DomainFileType, ghidra.framework.model.ProjectData]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DomainFileNameColumn(docking.widgets.table.AbstractDynamicTableColumn[DomainFileInfo, java.lang.String, ghidra.framework.model.ProjectData]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ModificationDateColumn(docking.widgets.table.AbstractDynamicTableColumn[DomainFileInfo, java.util.Date, ghidra.framework.model.ProjectData]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DomainFilePathColumn(docking.widgets.table.AbstractDynamicTableColumn[DomainFileInfo, java.lang.String, ghidra.framework.model.ProjectData]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def setEditing(self, on: typing.Union[jpype.JBoolean, bool]):
        ...

    def setProjectData(self, projectData: ghidra.framework.model.ProjectData):
        ...


class ProjectDataContextToggleAction(docking.action.ToggleDockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...


class ProjectDataColumn(docking.widgets.table.AbstractDynamicTableColumn[DomainFileInfo, T, ghidra.framework.model.ProjectData], ghidra.util.classfinder.ExtensionPoint, java.lang.Comparable[ProjectDataColumn[typing.Any]], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getPriority(self) -> int:
        ...

    def isDefaultColumn(self) -> bool:
        ...

    @property
    def defaultColumn(self) -> jpype.JBoolean:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...


class ProjectDataContext(docking.DefaultActionContext, DomainFileContext):
    """
    A context that understands files that live in a :obj:`Project`.  Most of the clients of
    this context will use its notion of selected :obj:`DomainFile`s and folders.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, projectData: ghidra.framework.model.ProjectData, contextObject: java.lang.Object, selectedFolders: java.util.List[ghidra.framework.model.DomainFolder], selectedFiles: java.util.List[ghidra.framework.model.DomainFile], comp: java.awt.Component, isActiveProject: typing.Union[jpype.JBoolean, bool]):
        ...

    def containsRootFolder(self) -> bool:
        ...

    def getComponent(self) -> java.awt.Component:
        ...

    def getFolderCount(self) -> int:
        ...

    def getProjectData(self) -> ghidra.framework.model.ProjectData:
        ...

    def getSelectedFolders(self) -> java.util.List[ghidra.framework.model.DomainFolder]:
        ...

    def hasExactlyOneFileOrFolder(self) -> bool:
        ...

    def hasOneOrMoreFilesAndFolders(self) -> bool:
        ...

    def isReadOnlyProject(self) -> bool:
        ...

    @property
    def readOnlyProject(self) -> jpype.JBoolean:
        ...

    @property
    def projectData(self) -> ghidra.framework.model.ProjectData:
        ...

    @property
    def selectedFolders(self) -> java.util.List[ghidra.framework.model.DomainFolder]:
        ...

    @property
    def component(self) -> java.awt.Component:
        ...

    @property
    def folderCount(self) -> jpype.JInt:
        ...


class ProjectDataTablePanel(javax.swing.JPanel):

    @typing.type_check_only
    class ProjectDataTableDragProvider(docking.dnd.GTableDragProvider[DomainFileInfo]):

        @typing.type_check_only
        class DomainFileTransferable(java.awt.datatransfer.Transferable):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ProjectDataTableDomainFolderChangeListener(ghidra.framework.model.DomainFolderChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SelectPendingFilesListener(docking.widgets.table.threaded.ThreadedTableModelListener):
        """
        A listener that checks for files that need to be selected after each model change.  This is
        required due to the asynchronous nature of the table loading and clients that wish to make
        selections, potentially before the table has loaded the items whose selection is desired.s
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ProjectDataTable(docking.widgets.table.GTable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, m: docking.widgets.table.threaded.ThreadedTableModel[DomainFileInfo, typing.Any]):
            ...


    @typing.type_check_only
    class TableGlassPanePainter(ghidra.util.bean.GGlassPanePainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DateCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TypeCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MAX_FILE_COUNT: typing.Final[jpype.JInt]
    filesPendingSelection: java.util.Set[ghidra.framework.model.DomainFile]

    def __init__(self, plugin: ghidra.framework.main.FrontEndPlugin):
        ...

    def dispose(self):
        ...

    def getActionContext(self, provider: docking.ComponentProvider, e: java.awt.event.MouseEvent) -> docking.ActionContext:
        ...

    def isCapacityExceeded(self) -> bool:
        """
        Determine if table capacity has been exceeded and files are not shown
        
        :return: true if files are not shown in project data table, else false
        :rtype: bool
        """

    def setHelpLocation(self, helpLocation: ghidra.util.HelpLocation):
        ...

    def setProjectData(self, name: typing.Union[java.lang.String, str], projectData: ghidra.framework.model.ProjectData):
        ...

    def setSelectedDomainFiles(self, files: java.util.Set[ghidra.framework.model.DomainFile]):
        ...

    @property
    def capacityExceeded(self) -> jpype.JBoolean:
        ...


class DomainFileType(java.lang.Comparable[DomainFileType], docking.widgets.table.DisplayStringProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, contentType: typing.Union[java.lang.String, str], icon: javax.swing.Icon, isVersioned: typing.Union[jpype.JBoolean, bool]):
        ...

    def getContentType(self) -> str:
        ...

    def getIcon(self) -> javax.swing.Icon:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def contentType(self) -> java.lang.String:
        ...


class DomainFileInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, domainFile: ghidra.framework.model.DomainFile):
        ...

    def clearMetaCache(self):
        ...

    def getDisplayName(self) -> str:
        ...

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    def getDomainFileType(self) -> DomainFileType:
        ...

    def getIcon(self) -> javax.swing.Icon:
        ...

    def getMetaDataValue(self, key: typing.Union[java.lang.String, str]) -> str:
        ...

    def getModificationDate(self) -> java.util.Date:
        ...

    def getName(self) -> str:
        ...

    def getPath(self) -> str:
        ...

    def refresh(self):
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def modificationDate(self) -> java.util.Date:
        ...

    @property
    def domainFileType(self) -> DomainFileType:
        ...

    @property
    def metaDataValue(self) -> java.lang.String:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...


class DomainFileContext(java.lang.Object):
    """
    A context that provides information to actions about domain files that are selected in the tool
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFileCount(self) -> int:
        """
        Returns the count of selected files
        
        :return: the count of selected files
        :rtype: int
        """

    def getSelectedFiles(self) -> java.util.List[ghidra.framework.model.DomainFile]:
        """
        The selected files or empty if no files are selected
        
        :return: the files
        :rtype: java.util.List[ghidra.framework.model.DomainFile]
        """

    def isInActiveProject(self) -> bool:
        """
        True if the current set of files is in the active project (false implies a non-active, 
        read-only project)
        
        :return: true if in the active project
        :rtype: bool
        """

    @property
    def selectedFiles(self) -> java.util.List[ghidra.framework.model.DomainFile]:
        ...

    @property
    def inActiveProject(self) -> jpype.JBoolean:
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...


class FrontendProjectTreeAction(docking.action.ContextSpecificAction[ProjectDataContext]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...


class ProjectTreeContext(java.lang.Object):
    """
    Common methods appropriate for both the :obj:`FrontEndProjectTreeContext` and the
    :obj:`DialogProjectTreeContext`.  The project tree actions require that the contexts be
    separate even though they need many of the same methods. By extracting the methods to this
    interface, the contexts can be kept separate, but can share action code.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getContextNode(self) -> docking.widgets.tree.GTreeNode:
        """
        Returns the node that represents the context object for this context
        
        :return: the node
        :rtype: docking.widgets.tree.GTreeNode
        """

    def getFileCount(self) -> int:
        """
        Returns the number of files selected in the tree.
        
        :return: the number of files selected in the tree.
        :rtype: int
        """

    def getFolderCount(self) -> int:
        """
        Returns the number of folders selected in the tree.
        
        :return: the number of folders selected in the tree.
        :rtype: int
        """

    def getSelectedFiles(self) -> java.util.List[ghidra.framework.model.DomainFile]:
        """
        Returns a list of :obj:`DomainFile`s selected in the tree.
        
        :return: a list of :obj:`DomainFile`s selected in the tree.
        :rtype: java.util.List[ghidra.framework.model.DomainFile]
        """

    def getSelectedFolders(self) -> java.util.List[ghidra.framework.model.DomainFolder]:
        """
        Returns a list of :obj:`DomainFolder`s selected in the tree.
        
        :return: a list of :obj:`DomainFolder`s selected in the tree.
        :rtype: java.util.List[ghidra.framework.model.DomainFolder]
        """

    def getSelectionPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        """
        Returns the list of selected :obj:`TreePath`s selected.
        
        :return: the list of selected :obj:`TreePath`s selected.
        :rtype: jpype.JArray[javax.swing.tree.TreePath]
        """

    def getTree(self) -> ghidra.framework.main.datatree.DataTree:
        """
        Returns the project data tree component.
        
        :return: the project data tree component.
        :rtype: ghidra.framework.main.datatree.DataTree
        """

    @property
    def selectedFiles(self) -> java.util.List[ghidra.framework.model.DomainFile]:
        ...

    @property
    def selectedFolders(self) -> java.util.List[ghidra.framework.model.DomainFolder]:
        ...

    @property
    def selectionPaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    @property
    def tree(self) -> ghidra.framework.main.datatree.DataTree:
        ...

    @property
    def contextNode(self) -> docking.widgets.tree.GTreeNode:
        ...

    @property
    def folderCount(self) -> jpype.JInt:
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...



__all__ = ["DomainFileProviderContextAction", "ProjectTreeAction", "ProjectDataTableModel", "ProjectDataContextToggleAction", "ProjectDataColumn", "ProjectDataContext", "ProjectDataTablePanel", "DomainFileType", "DomainFileInfo", "DomainFileContext", "FrontendProjectTreeAction", "ProjectTreeContext"]
