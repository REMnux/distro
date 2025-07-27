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
import docking.framework
import docking.widgets
import docking.widgets.list
import docking.widgets.table
import docking.widgets.tree
import docking.widgets.tree.support
import ghidra.framework.client
import ghidra.framework.main.projectdata.actions
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import ghidra.framework.project.tool
import ghidra.framework.protocol.ghidra
import ghidra.framework.remote
import ghidra.util
import ghidra.util.bean
import ghidra.util.filechooser
import ghidra.util.task
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import log
import org.jdesktop.animation.timing # type: ignore


T = typing.TypeVar("T")


@typing.type_check_only
class FixedLengthTextField(javax.swing.JTextField):
    """
    Text field that has a fixed length.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPreferredSize(self) -> java.awt.Dimension:
        """
        override parent method to line up the text field with the
        scroll paths list in upper panel
        """

    @property
    def preferredSize(self) -> java.awt.Dimension:
        ...


class DataTreeDialog(AbstractDataTreeDialog):
    """
    Dialog to open or save domain data items to a new location or name.
    """

    class_: typing.ClassVar[java.lang.Class]
    OPEN: typing.Final[DataTreeDialogType]
    SAVE: typing.Final[DataTreeDialogType]
    CHOOSE_FOLDER: typing.Final[DataTreeDialogType]
    CREATE: typing.Final[DataTreeDialogType]

    @typing.overload
    def __init__(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], type: DataTreeDialogType):
        """
        Construct a new DataTreeDialog for the active project.  This chooser will show all project
        files.  Following linked-folders will only be allowed if a type of CHOOSE_FOLDER
        or OPEN is specified.  If different behavior is required a filter should 
        be specified using the other constructor.
        
        :param java.awt.Component parent: dialog's parent
        :param java.lang.String or str title: title to use
        :param DataTreeDialogType type: specify OPEN, SAVE, CHOOSE_FOLDER, CHOOSE_USER_FOLDER, or CREATE
        :raises IllegalArgumentException: if invalid type is specified
        """

    @typing.overload
    def __init__(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], type: DataTreeDialogType, filter: ghidra.framework.model.DomainFileFilter):
        """
        Construct a new DataTreeDialog for the active project.
        
        :param java.awt.Component parent: dialog's parent
        :param java.lang.String or str title: title to use
        :param DataTreeDialogType type: specify OPEN, SAVE, CHOOSE_FOLDER, or CREATE
        :param ghidra.framework.model.DomainFileFilter filter: filter used to control what is displayed in the data tree
        :raises IllegalArgumentException: if invalid type is specified
        """

    @typing.overload
    def __init__(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], type: DataTreeDialogType, filter: ghidra.framework.model.DomainFileFilter, project: ghidra.framework.model.Project):
        """
        Construct a new DataTreeDialog for the given project.
        
        :param java.awt.Component parent: dialog's parent
        :param java.lang.String or str title: title to use
        :param DataTreeDialogType type: specify OPEN, SAVE, CHOOSE_FOLDER, or CREATE
        :param ghidra.framework.model.DomainFileFilter filter: filter used to control what is displayed in the data tree
        :param ghidra.framework.model.Project project: the project to browse
        :raises IllegalArgumentException: if invalid type is specified
        """


class GhidraApplicationInformationDisplayFactory(docking.framework.ApplicationInformationDisplayFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DialogProjectDataCollapseAction(ghidra.framework.main.projectdata.actions.ProjectDataCollapseAction[ghidra.framework.main.datatree.DialogProjectTreeContext]):
    """
    :obj:`ProjectDataCollapseAction` configured to work in the frontend.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class OpenVersionedFileDialog(AbstractDataTreeDialog, typing.Generic[T]):
    """
    Dialog to open a file that is versioned and allow a version to be
    opened.
    """

    @typing.type_check_only
    class OpenObjectsTableModel(docking.widgets.table.AbstractGTableModel[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], domainObjectClass: java.lang.Class[T]):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: tool where the file is being opened.
        :param java.lang.String or str title: title to use
        :param java.lang.Class[T] domainObjectClass: allowed domain object class which corresponds to ``<T>``
        """

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], domainObjectClass: java.lang.Class[T], openDomainObjects: java.util.List[T]):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: tool where the file is being opened.
        :param java.lang.String or str title: title to use
        :param java.lang.Class[T] domainObjectClass: allowed domain object class which corresponds to ``<T>``
        :param java.util.List[T] openDomainObjects: if non-null, will cause an additional tab showing the given
        list of open domain objects that the user can select from
        """

    def getDomainObject(self, consumer: java.lang.Object, immutable: typing.Union[jpype.JBoolean, bool]) -> T:
        """
        Get the selected domain object for read-only or immutable use.
        If an existing open object is selected its original mode applies but consumer will 
        be added.  The caller/consumer is responsible for releasing the returned domain object
        when done using it (see :meth:`DomainObject.release(Object) <DomainObject.release>`).
        
        :param java.lang.Object consumer: domain object consumer
        :param jpype.JBoolean or bool immutable: true if the domain object should be opened immutable, else false for
        read-only.  Immutable mode should not be used for content that will be modified.  If 
        read-only indicated an upgrade will always be performed if required.
        :return: opened domain object or null if a file was not selected or if open failed to 
        complete.
        :rtype: T
        """

    def getVersion(self) -> int:
        """
        Return the selected version number from the history panel.
        
        :return: -1 if a version history was not selected
        :rtype: int
        """

    @property
    def version(self) -> jpype.JInt:
        ...


class ConsoleTextPane(javax.swing.JTextPane, ghidra.framework.options.OptionsChangeListener):
    """
    A generic text pane that is used as a console to which text can be written.
    """

    @typing.type_check_only
    class MessageWrapper(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ErrorMessage(ConsoleTextPane.MessageWrapper):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def addErrorMessage(self, message: typing.Union[java.lang.String, str]):
        ...

    def addMessage(self, message: typing.Union[java.lang.String, str]):
        ...

    def addPartialMessage(self, message: typing.Union[java.lang.String, str]):
        ...

    def dispose(self):
        ...

    def setScrollLock(self, lock: typing.Union[jpype.JBoolean, bool]):
        ...


class DialogProjectDataExpandAction(ghidra.framework.main.projectdata.actions.ProjectDataExpandAction[ghidra.framework.main.datatree.DialogProjectTreeContext]):
    """
    :obj:`ProjectDataExpandAction` configured to work in the frontend.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class DataTreeDialogType(java.lang.Enum[DataTreeDialogType]):
    """
    Types of ways to use a DataTreeDialog.
    """

    class_: typing.ClassVar[java.lang.Class]
    OPEN: typing.Final[DataTreeDialogType]
    """
    Dialog type for opening domain data files
    """

    SAVE: typing.Final[DataTreeDialogType]
    """
    Dialog type for saving domain data files
    """

    CHOOSE_FOLDER: typing.Final[DataTreeDialogType]
    """
    Dialog type for choosing a user folder
    """

    CREATE: typing.Final[DataTreeDialogType]
    """
    Dialog type for creating domain data files
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DataTreeDialogType:
        ...

    @staticmethod
    def values() -> jpype.JArray[DataTreeDialogType]:
        ...


@typing.type_check_only
class InfoPanel(javax.swing.JPanel):
    """
    Window to display version information about the current release of the application.
    """

    class_: typing.ClassVar[java.lang.Class]


class AbstractDataTreeDialog(docking.DialogComponentProvider, docking.widgets.tree.support.GTreeSelectionListener, java.awt.event.ActionListener):
    """
    Base dialog for choosing DomainFiles. Provides and manages the base data tree panel. Subclasses
    should call the buildDataTreePanel() when they are constructing their main panels. They should
    also call the initializeFocusedComponent() method so that default focus for the dialog is in
    the text field if it is enabled or otherwise the focus should be the tree.
    """

    @typing.type_check_only
    class FieldKeyListener(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SetNameTextTask(docking.widgets.tree.GTreeTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def addOkActionListener(self, l: java.awt.event.ActionListener):
        """
        Add action listener that is called when the OK button is hit.
        
        :param java.awt.event.ActionListener l: listener to add
        """

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        """
        Get the selected domain file.
        
        :return: null if there was no domain file selected
        :rtype: ghidra.framework.model.DomainFile
        """

    def getDomainFolder(self) -> ghidra.framework.model.DomainFolder:
        """
        Get the selected folder.
        
        :return: null if there was no domain folder selected
        :rtype: ghidra.framework.model.DomainFolder
        """

    def getNameText(self) -> str:
        ...

    def getTree(self) -> docking.widgets.tree.GTree:
        ...

    def selectDomainFile(self, file: ghidra.framework.model.DomainFile):
        """
        Select the node that corresponds to the given domain file.
        
        :param ghidra.framework.model.DomainFile file: the file
        """

    def selectFolder(self, folder: ghidra.framework.model.DomainFolder):
        """
        Select a folder in the tree.
        
        :param ghidra.framework.model.DomainFolder folder: the folder to select
        """

    def setNameText(self, name: typing.Union[java.lang.String, str]):
        ...

    def setSearchText(self, s: typing.Union[java.lang.String, str]):
        ...

    def setSelectedFolder(self, folder: ghidra.framework.model.DomainFolder):
        """
        Sets a domain folder as the initially selected folder when the dialog is first shown.
        
        :param ghidra.framework.model.DomainFolder folder: :obj:`DomainFolder` to select when showing the dialog
        """

    def setTreeSelectionMode(self, mode: typing.Union[jpype.JInt, int]):
        ...

    def show(self):
        ...

    def showComponent(self):
        """
        Shows this dialog.  The preferred show method is :meth:`show() <.show>`, as it is the preferred 
        nomenclature.
        """

    def valueChanged(self, e: docking.widgets.tree.support.GTreeSelectionEvent):
        """
        TreeSelectionListener method that is called whenever the value of the selection changes.
        
        :param docking.widgets.tree.support.GTreeSelectionEvent e: the event that characterizes the change.
        """

    def wasCancelled(self) -> bool:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def tree(self) -> docking.widgets.tree.GTree:
        ...

    @property
    def nameText(self) -> java.lang.String:
        ...

    @nameText.setter
    def nameText(self, value: java.lang.String):
        ...

    @property
    def domainFolder(self) -> ghidra.framework.model.DomainFolder:
        ...


class DialogProjectDataNewFolderAction(ghidra.framework.main.projectdata.actions.ProjectDataNewFolderAction[ghidra.framework.main.datatree.DialogProjectTreeContext]):
    """
    :obj:`ProjectDataNewFolderAction` configured to work in the frontend.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class GetDomainObjectTask(ghidra.util.task.Task):
    """
    A modal task that gets a domain object for a specified version.
    Object is either open read-only or immutable.  
     
    NOTE: This task is not intended to open a domain file for modification and saving back 
    to a project.
     
    A file open for read-only use will be upgraded if needed and is possible.  Once open it is 
    important that the specified consumer be released from the domain object when done using 
    the open object (see :meth:`DomainObject.release(Object) <DomainObject.release>`).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, consumer: java.lang.Object, domainFile: ghidra.framework.model.DomainFile, versionNumber: typing.Union[jpype.JInt, int]):
        """
        Construct task open specified domainFile read only.  
        An upgrade is performed if needed and is possible.
        
        :param java.lang.Object consumer: consumer of the domain object
        :param ghidra.framework.model.DomainFile domainFile: domain file
        :param jpype.JInt or int versionNumber: version
        """

    @typing.overload
    def __init__(self, consumer: java.lang.Object, domainFile: ghidra.framework.model.DomainFile, versionNumber: typing.Union[jpype.JInt, int], immutable: typing.Union[jpype.JBoolean, bool]):
        """
        Construct task open specified domainFile read only or immutable.  Immutable mode should not
        be used for content that will be modified.
        If read-only an upgrade is performed if needed, if immutable the user will be prompted
        if an upgrade should be performed if possible in which case it will open read-only.
        
        :param java.lang.Object consumer: consumer of the domain object
        :param ghidra.framework.model.DomainFile domainFile: domain file
        :param jpype.JInt or int versionNumber: version
        :param jpype.JBoolean or bool immutable: true if the object should be open immutable, else read-only.
        """

    def getDomainObject(self) -> ghidra.framework.model.DomainObject:
        """
        Return the domain object instance.
        
        :return: domain object which was opened or null if task cancelled or failed
        :rtype: ghidra.framework.model.DomainObject
        """

    @property
    def domainObject(self) -> ghidra.framework.model.DomainObject:
        ...


@typing.type_check_only
class ViewInfo(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ApplicationLevelOnlyPlugin(ApplicationLevelPlugin):
    """
    Marker interface to indicate this plugin is application-level tools only (see
    :obj:`ApplicationLevelPlugin`).
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SetToolAssociationsDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class ToolAssociationTableModel(docking.widgets.table.AbstractSortedTableModel[ghidra.framework.model.ToolAssociationInfo]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ContentHandlerComparator(java.util.Comparator[ghidra.framework.model.ToolAssociationInfo]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToolTemplateComparator(java.util.Comparator[ghidra.framework.model.ToolAssociationInfo]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ContentHandlerRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToolTemplateRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class PickToolDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class ToolTableModel(docking.widgets.table.AbstractSortedTableModel[ghidra.framework.model.ToolTemplate]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToolTemplateComparator(java.util.Comparator[ghidra.framework.model.ToolTemplate]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToolTemplateRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FileActionManager(java.lang.Object):
    """
    Helper class to manage actions on the File menu.
    """

    @typing.type_check_only
    class OpenTaskRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReopenProjectAction(docking.action.DockingAction):
        """
        Action for a recently opened project.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ProjectInfoDialog(docking.DialogComponentProvider):
    """
    Dialog to show project information. Allows the user to convert a local project to a shared project,
    OR to specify a different server or port, or repository for a shared project.
    """

    @typing.type_check_only
    class ConvertProjectTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ConvertProjectStorageTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UpdateInfoTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    CHANGE: typing.Final = "Change Shared Project Info..."


class FrontEndProjectDataNewFolderAction(ghidra.framework.main.projectdata.actions.ProjectDataNewFolderAction[ghidra.framework.main.datatree.FrontEndProjectTreeContext]):
    """
    :obj:`ProjectDataNewFolderAction` configured to work in the frontend.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class FrontEndPlugin(ghidra.framework.plugintool.Plugin, FrontEndService, ghidra.framework.client.RemoteAdapterListener, ghidra.framework.model.ProjectViewListener, ProgramaticUseOnly):
    """
    Main plugin component for the Ghidra Project Window, which is
    a PluginTool. This plugin manages all of the GUI elements, e.g., the
    Data tree panel, view panels for other projects, etc.
    """

    @typing.type_check_only
    class ToolButtonAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FrontEndProvider(docking.ComponentProvider):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    @typing.type_check_only
    class MyToolChestChangeListener(ghidra.framework.model.ToolChestChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Construct a new FrontEndPlugin. This plugin is constructed once when
        the Front end tool (Ghidra Project Window) is created. When a
        previously opened project is created, the Ghidra Project Window is
        restored to the state associated with that project.
        
        :param ghidra.framework.plugintool.PluginTool tool: the front end tool
        """

    def getActiveWorkspace(self) -> ghidra.framework.model.Workspace:
        ...

    def getComponent(self) -> javax.swing.JComponent:
        ...

    def openDomainFile(self, domainFile: ghidra.framework.model.DomainFile):
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def activeWorkspace(self) -> ghidra.framework.model.Workspace:
        ...


@typing.type_check_only
class ProjectActionManager(java.lang.Object):

    @typing.type_check_only
    class RecentViewPluginAction(docking.action.DockingAction):
        """
        Class for recent view actions; subclass to set the help ID.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CloseViewPluginAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class FrontEndService(java.lang.Object):
    """
    Interface for accessing front-end functionality.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addProjectListener(self, l: ghidra.framework.model.ProjectListener):
        """
        Adds the specified listener to the front-end tool.
        
        :param ghidra.framework.model.ProjectListener l: the project listener
        """

    def removeProjectListener(self, l: ghidra.framework.model.ProjectListener):
        """
        Removes the specified listener from the front-end tool.
        
        :param ghidra.framework.model.ProjectListener l: the project listener
        """


@typing.type_check_only
class MoveImageRunner(java.lang.Object):
    """
    Changes the 'containerBounds' field on the :obj:`ZoomedImagePainter` via the 
    setters/getters in order to move where the painter paints.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ghidraGlassPane: ghidra.util.bean.GGlassPane, startBounds: java.awt.Rectangle, endBounds: java.awt.Rectangle, painter: ZoomedImagePainter):
        ...

    @typing.overload
    def __init__(self, ghidraGlassPane: ghidra.util.bean.GGlassPane, startBounds: java.awt.Rectangle, endBounds: java.awt.Rectangle, painter: ZoomedImagePainter, repaint: typing.Union[jpype.JBoolean, bool]):
        """
        Changes the bounds of the given painter over a period of time
        
        :param ghidra.util.bean.GGlassPane ghidraGlassPane: The glass pane we are using to paint
        :param java.awt.Rectangle startBounds: The start position and size
        :param java.awt.Rectangle endBounds: The end position and size
        :param ZoomedImagePainter painter: The painter upon which we will update bounds
        :param jpype.JBoolean or bool repaint: true signals to repaint as the changes are made.  This can lead to 
                choppiness when using other animators in conjunction with the one used by this
                class.
        """

    def run(self):
        ...


class SaveDataDialog(docking.DialogComponentProvider):
    """
    Modal dialog to display a list of domain objects that have changed.
    The user can mark the ones to save, or pop up another dialog to save
    the files to a different location and/or name.
    Read-only files are rendered in red and the checkboxes for these files
    cannot be selected.
    If the project has changed, then the first checkbox displayed will be
    for saving the project configuration.
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


    @typing.type_check_only
    class SaveTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Construct new SaveDataDiaog
        
        :param ghidra.framework.plugintool.PluginTool tool: front end tool
        """

    def showDialog(self, domainFiles: java.util.List[ghidra.framework.model.DomainFile]) -> bool:
        """
        Shows the save dialog with the given domain files, but no options to save
        the project.  The dialog will not appear if there is no data that needs
        saving.
        
        :param java.util.List[ghidra.framework.model.DomainFile] domainFiles: The files that may need saving.
        :return: true if the user hit the 'Save' or 'Don't Save' option; return false if the
                user cancelled the operation
        :rtype: bool
        """


@typing.type_check_only
class WorkspacePanel(javax.swing.JPanel, ghidra.framework.model.WorkspaceChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def toolAdded(self, ws: ghidra.framework.model.Workspace, tool: ghidra.framework.plugintool.PluginTool):
        """
        Tool was added to the given workspace.
        """

    def toolRemoved(self, ws: ghidra.framework.model.Workspace, tool: ghidra.framework.plugintool.PluginTool):
        """
        Tool was removed from the given workspace.
        """

    def workspaceAdded(self, ws: ghidra.framework.model.Workspace):
        """
        called when a workspace is added by the ToolManager
        """

    def workspaceRemoved(self, ws: ghidra.framework.model.Workspace):
        """
        called when a workspace is removed by the ToolManager
        """

    def workspaceSetActive(self, ws: ghidra.framework.model.Workspace):
        """
        called when a workspace is setActive() by the ToolManager
        """


class TestFrontEndTool(FrontEndTool):
    """
    A test version of the :obj:`FrontEndTool` that disables some functionality
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pm: ghidra.framework.model.ProjectManager):
        ...


class FrontEndProjectDataCollapseAction(ghidra.framework.main.projectdata.actions.ProjectDataCollapseAction[ghidra.framework.main.datatree.FrontEndProjectTreeContext]):
    """
    :obj:`ProjectDataCollapseAction` configured to work in the frontend.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class ProjectToolBar(javax.swing.JToolBar, ghidra.framework.model.ToolChestChangeListener):
    """
    Toolbar that shows icons for the tools in the user's tool chest.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getToolButtonForToolConfig(self, toolTemplate: ghidra.framework.model.ToolTemplate) -> ToolButton:
        ...

    def toolSetAdded(self, toolset: ghidra.framework.model.ToolSet):
        """
        ToolSet was added to the project toolchest
        """

    @property
    def toolButtonForToolConfig(self) -> ToolButton:
        ...


class ViewProjectAccessPanel(ProjectAccessPanel):
    """
    Extension of the :obj:`ProjectAccessPanel` that only shows the user access list.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, repository: ghidra.framework.client.RepositoryAdapter, tool: ghidra.framework.plugintool.PluginTool):
        """
        Construct a new panel.
        
        :param ghidra.framework.client.RepositoryAdapter repository: handle to the repository adapter
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        :raises IOException: if there's an error processing repository information
        """

    @typing.overload
    def __init__(self, knownUsers: jpype.JArray[java.lang.String], currentUser: typing.Union[java.lang.String, str], allUsers: java.util.List[ghidra.framework.remote.User], repositoryName: typing.Union[java.lang.String, str], anonymousServerAccessAllowed: typing.Union[jpype.JBoolean, bool], anonymousAccessEnabled: typing.Union[jpype.JBoolean, bool], tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructs a new panel.
        
        :param jpype.JArray[java.lang.String] knownUsers: names of the users that are known to the remote server
        :param java.lang.String or str currentUser: the current user
        :param java.util.List[ghidra.framework.remote.User] allUsers: all users known to the repository
        :param java.lang.String or str repositoryName: the name of the repository
        :param jpype.JBoolean or bool anonymousServerAccessAllowed: true if the server allows anonymous access
        :param jpype.JBoolean or bool anonymousAccessEnabled: true if the repository allows anonymous access
        (ignored if anonymousServerAccessAllowed is false)
        :param ghidra.framework.plugintool.PluginTool tool: the current tool
        """


@typing.type_check_only
class ProjectDataPanel(javax.swing.JSplitPane, ghidra.framework.model.ProjectViewListener):
    """
    Manages the data tree for the active project, and the trees for the
    project views.
    """

    class_: typing.ClassVar[java.lang.Class]


class AppInfo(java.lang.Object):
    """
    Class with static methods to maintain application info, e.g., a handle to the
    tool that is the Ghidra Project Window, the user's name, etc.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def exitGhidra():
        ...

    @staticmethod
    def getActiveProject() -> ghidra.framework.model.Project:
        ...

    @staticmethod
    def getFrontEndTool() -> FrontEndTool:
        ...

    @staticmethod
    def setActiveProject(p: ghidra.framework.model.Project):
        ...


class FrontEndProjectDataExpandAction(ghidra.framework.main.projectdata.actions.ProjectDataExpandAction[ghidra.framework.main.datatree.FrontEndProjectTreeContext]):
    """
    :obj:`ProjectDataExpandAction` configured to work in the frontend.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class ProjectAccessPanel(javax.swing.JPanel):
    """
    Panel that shows the users for a given repository and the users associated with the current
    shared project. There are 3 main sub-panels:
     
    * Known Users Panel: Displays all users in the repository
    * Button Panel: Provides buttons for adding/removing users from the project
    * User Access Panel: Displays all users on the project, and their access permissions
    
    If the current user is an admin, he may change user permissions and add/remove them
    from the project. If not, only the User Access Panel will be visible and it will
    be read-only.
    """

    @typing.type_check_only
    class ButtonPanel(javax.swing.JPanel):
        """
        Panel containing the buttons for adding/removing users from the current project.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def updateState(self):
            """
            Ensures that all buttons are enabled/disabled appropriately based on the current
            selections.
             
            
            Note that the "add all" and "remove all" buttons are always enabled so they aren't addressed
            here.
            """


    @typing.type_check_only
    class UserAccessPanel(javax.swing.JPanel):
        """
        Panel for displaying project users and their access permissions. Users with admin rights
        can edit the permissions of other users.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, user: typing.Union[java.lang.String, str]):
            """
            Creates a new user access panel.
            
            :param java.lang.String or str user: the current user
            """


    @typing.type_check_only
    class KnownUsersPanel(javax.swing.JPanel):
        """
        Panel for displaying the list of users with repository access.
        """

        @typing.type_check_only
        class UserListCellRenderer(docking.widgets.list.GListCellRenderer[java.lang.String]):
            """
            Renderer for the :obj:`KnownUsersPanel`. This is to ensure that we render the
            correct icon for each user in the list
            """

            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, knownUsers: jpype.JArray[java.lang.String], repository: ghidra.framework.client.RepositoryAdapter, tool: ghidra.framework.plugintool.PluginTool):
        """
        Construct a new panel from a :obj:`RepositoryAdapter` instance.
        
        :param jpype.JArray[java.lang.String] knownUsers: names of the users that are known to the remote server
        :param ghidra.framework.client.RepositoryAdapter repository: the repository adapter instance
        :param ghidra.framework.plugintool.PluginTool tool: the current tool
        :raises IOException: if there's an error processing the repository user list
        """

    @typing.overload
    def __init__(self, knownUsers: jpype.JArray[java.lang.String], currentUser: typing.Union[java.lang.String, str], allUsers: java.util.List[ghidra.framework.remote.User], repositoryName: typing.Union[java.lang.String, str], anonymousServerAccessAllowed: typing.Union[jpype.JBoolean, bool], anonymousAccessEnabled: typing.Union[jpype.JBoolean, bool], tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructs a new panel from the given arguments.
        
        :param jpype.JArray[java.lang.String] knownUsers: names of the users that are known to the remote server
        :param java.lang.String or str currentUser: the current user
        :param java.util.List[ghidra.framework.remote.User] allUsers: all users known to the repository
        :param java.lang.String or str repositoryName: the name of the repository
        :param jpype.JBoolean or bool anonymousServerAccessAllowed: true if the server allows anonymous access
        :param jpype.JBoolean or bool anonymousAccessEnabled: true if the repository allows anonymous access
        (ignored if anonymousServerAccessAllowed is false)
        :param ghidra.framework.plugintool.PluginTool tool: the current tool
        """

    def allowAnonymousAccess(self) -> bool:
        """
        Returns true if anonymous access is allowed by the repository.
        
        :return: true if allowed
        :rtype: bool
        """

    def getProjectUsers(self) -> jpype.JArray[ghidra.framework.remote.User]:
        """
        Returns a list of all users with permission to access the project.
        
        :return: the list of users
        :rtype: jpype.JArray[ghidra.framework.remote.User]
        """

    @property
    def projectUsers(self) -> jpype.JArray[ghidra.framework.remote.User]:
        ...


class SelectPanel(javax.swing.JPanel):
    """
    A simple panel with buttons for selecting and de-selecting items
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, selectAllCallback: java.awt.event.ActionListener, deselectAllCallback: java.awt.event.ActionListener):
        ...


@typing.type_check_only
class EditActionManager(java.lang.Object):
    """
    Helper class to manage the actions on the Edit menu.
    """

    class_: typing.ClassVar[java.lang.Class]
    CERTIFICATE_FILE_FILTER: typing.Final[ghidra.util.filechooser.GhidraFileFilter]
    """
    PKCS Private Key/Certificate File Filter
    """



@typing.type_check_only
class ProjectAccessDialog(docking.DialogComponentProvider):
    """
    Dialog showing all users associated with a repository and those with 
    access to the current shared project. Users with admin rights can use
    this dialog to edit user permissions.
    """

    class_: typing.ClassVar[java.lang.Class]


class ToolButtonTransferable(java.awt.datatransfer.Transferable, java.awt.datatransfer.ClipboardOwner):
    """
    Defines data that is available for drag/drop and clipboard transfers.
    The data is a ToolButton object.
    """

    class_: typing.ClassVar[java.lang.Class]
    localToolButtonFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]


class AcceptUrlContentTask(ghidra.framework.protocol.ghidra.GhidraURLQueryTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, url: java.net.URL, plugin: FrontEndPlugin):
        ...


class FrontEndTool(ghidra.framework.plugintool.PluginTool, ghidra.framework.options.OptionsChangeListener):
    """
    Tool that serves as the Ghidra Project Window. Only those plugins that
    implement the FrontEndable interface may be *directly* added to this
    tool by the user. Other plugins that are not marked as FrontEndable may get
    pulled in because the FrontEndable plugins depend on them. These plugins are
    aware of what tool they live in so that they can behave in the appropriate
    manner.
    """

    @typing.type_check_only
    class LogComponentProvider(docking.ReusableDialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MergeTask(ghidra.util.task.Task):
        """
        Task to merge latest version of a domain file into the checked out
        version.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FrontEndToolTemplate(ghidra.framework.project.tool.GhidraToolTemplate):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_TOOL_LAUNCH_MODE: typing.Final = "Default Tool Launch Mode"
    AUTOMATICALLY_SAVE_TOOLS: typing.Final = "Automatically Save Tools"

    def __init__(self, pm: ghidra.framework.model.ProjectManager):
        """
        Construct a new Ghidra Project Window.
        
        :param ghidra.framework.model.ProjectManager pm: project manager
        """

    def addProjectListener(self, l: ghidra.framework.model.ProjectListener):
        """
        Add the given project listener.
        
        :param ghidra.framework.model.ProjectListener l: listener to add
        """

    @typing.overload
    def checkIn(self, tool: ghidra.framework.plugintool.PluginTool, domainFile: ghidra.framework.model.DomainFile):
        """
        Check in the given domain file.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool that has the domain file opened
        :param ghidra.framework.model.DomainFile domainFile: domain file to check in
        """

    @typing.overload
    def checkIn(self, tool: ghidra.framework.plugintool.PluginTool, fileList: java.util.List[ghidra.framework.model.DomainFile], parent: java.awt.Component):
        """
        Check in the list of domain files.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool that has the domain files opened
        :param java.util.List[ghidra.framework.model.DomainFile] fileList: list of DomainFile objects
        :param java.awt.Component parent: parent of dialog if an error occurs during checkin
        """

    def getDefaultLaunchMode(self) -> ghidra.framework.model.DefaultLaunchMode:
        """
        Get the preferred default tool launch mode
        
        :return: default tool launch mode
        :rtype: ghidra.framework.model.DefaultLaunchMode
        """

    @typing.overload
    def merge(self, tool: ghidra.framework.plugintool.PluginTool, domainFile: ghidra.framework.model.DomainFile, taskListener: ghidra.util.task.TaskListener):
        """
        Merge the latest version in the repository with the given checked out
        domain file. Upon completion of the merge, the domain file appears as
        though the latest version was checked out.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool that has the domain file opened
        :param ghidra.framework.model.DomainFile domainFile: domain file where latest version will be merged into
        :param ghidra.util.task.TaskListener taskListener: listener that is notified when the merge task
                    completes
        """

    @typing.overload
    def merge(self, tool: ghidra.framework.plugintool.PluginTool, fileList: java.util.List[ghidra.framework.model.DomainFile], taskListener: ghidra.util.task.TaskListener):
        """
        Merge the latest version (in the repository) of each checked out file in
        fileList. Upon completion of the merge, the domain file appears as though
        the latest version was checked out.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool that has the domain files opened
        :param java.util.List[ghidra.framework.model.DomainFile] fileList: list of files that are checked out and are to be merged
        :param ghidra.util.task.TaskListener taskListener: listener that is notified when the merge task
                    completes
        """

    def removeProjectListener(self, l: ghidra.framework.model.ProjectListener):
        """
        Remove the given project listener.
        
        :param ghidra.framework.model.ProjectListener l: listener to remove
        """

    def selectFiles(self, files: java.util.Set[ghidra.framework.model.DomainFile]):
        ...

    def setActiveProject(self, project: ghidra.framework.model.Project):
        """
        Set the active project.
        
        :param ghidra.framework.model.Project project: may be null if there is no active project
        """

    def setBusy(self, busy: typing.Union[jpype.JBoolean, bool]):
        ...

    def shouldRestorePreviousProject(self) -> bool:
        """
        Checks to see if the previous project should be restored
        
        :return: true if the previous project should be restored; otherwise, false
        :rtype: bool
        """

    @property
    def defaultLaunchMode(self) -> ghidra.framework.model.DefaultLaunchMode:
        ...


class ProgramaticUseOnly(java.lang.Object):
    """
    Marker interface for plugins that only get constructed programmatically for specific purposes.
    Plugins that implement this interface should never be added via the config GUIs.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RunningToolsPanel(javax.swing.JPanel):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ApplicationLevelPlugin(java.lang.Object):
    """
    Marker that signals the implementing plugin can be added to the system at the application level.
     
    
    Some applications have only a single tool while other applications may have multiple tools, with
    a top-level tool that manages other sub-tools.  A plugin implementing this interface can be used
    in any of these tools.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ApplicationLevelPluginsConfiguration(ghidra.framework.plugintool.PluginsConfiguration):
    """
    A configuration that only includes :obj:`ApplicationLevelPlugin` plugins.
    """

    class_: typing.ClassVar[java.lang.Class]


class ZoomedImagePainter(ghidra.util.bean.GGlassPanePainter):
    """
    A class that paints a given image with varying zoom levels.  The zoom is set by clients 
    according to changes made by an :obj:`org.jdesktop.animation.timing.Animator`.  In essence, 
    this class paints the given image centered over the given target bounds at some 
    level of zoom.  If the zoom or bounds of the parent container are never changed, 
    then the image painted by this class will not change.
     
    
    NOTE: This class and it's getters/setters need to be public for reflective callbacks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, targetBounds: java.awt.Rectangle, image: java.awt.Image):
        ...

    @staticmethod
    def createIconImage(icon: javax.swing.Icon) -> java.awt.Image:
        ...

    def getTargetBounds(self) -> java.awt.Rectangle:
        ...

    def getZoom(self) -> float:
        ...

    def paint(self, glassPane: ghidra.util.bean.GGlassPane, g: java.awt.Graphics):
        ...

    def setMagnifyFactor(self, factor: typing.Union[jpype.JFloat, float]):
        ...

    def setTargetBounds(self, containerBounds: java.awt.Rectangle):
        ...

    def setZoom(self, zoom: typing.Union[jpype.JFloat, float]):
        ...

    @property
    def targetBounds(self) -> java.awt.Rectangle:
        ...

    @targetBounds.setter
    def targetBounds(self, value: java.awt.Rectangle):
        ...

    @property
    def zoom(self) -> jpype.JFloat:
        ...

    @zoom.setter
    def zoom(self, value: jpype.JFloat):
        ...


@typing.type_check_only
class ToolConnectionDialog(docking.ReusableDialogComponentProvider, ghidra.framework.model.WorkspaceChangeListener):
    """
    Dialog to show existing connections between tools and
    to connect tools.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RepositoryChooser(docking.ReusableDialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ToolConnectionPanel(javax.swing.JPanel, javax.swing.event.ListSelectionListener):
    """
    Adds the listeners for the connection panel that shows 3 lists: one
    for producers of event, one for consumers of events, and one
    that shows events that are an intersection of the consumed and
    produced events.
    """

    @typing.type_check_only
    class DataCellRenderer(javax.swing.ListCellRenderer[javax.swing.JCheckBox]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ServerInfoComponent(javax.swing.JPanel):
    """
    Component that allows the user to specify the host name and port
    number for the remote repository server.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getPortNumber(self) -> int:
        """
        Get the port number.
        """

    def getServerName(self) -> str:
        """
        Get the server name.
        """

    def getStatusMessage(self) -> str:
        ...

    def isValidInformation(self) -> bool:
        """
        Return whether the fields on this panel have valid information.
        """

    def setChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Set the change listener for this component
        
        :param javax.swing.event.ChangeListener listener:
        """

    def setServerInfo(self, info: ghidra.framework.model.ServerInfo):
        """
        Set the field values using the given server info.
        """

    def setStatusListener(self, statusListener: ghidra.util.StatusListener):
        """
        Set the status listener
        
        :param ghidra.util.StatusListener statusListener:
        """

    @property
    def validInformation(self) -> jpype.JBoolean:
        ...

    @property
    def serverName(self) -> java.lang.String:
        ...

    @property
    def statusMessage(self) -> java.lang.String:
        ...

    @property
    def portNumber(self) -> jpype.JInt:
        ...


@typing.type_check_only
class ToolButton(docking.widgets.EmptyBorderButton, docking.dnd.Draggable, docking.dnd.Droppable):
    """
    Component that is a drop target for a DataTreeTransferable object.
    If the object contains a domain file that is supported by a tool of
    this tool template, then a tool is launched with the data in it.
     
    
    This button can be used in one of two ways: to launch new instances of an associated tool
    template, or to represent a running tool.
    """

    @typing.type_check_only
    class ToolButtonDropTgtAdapter(docking.dnd.DropTgtAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, acceptableDropActions: typing.Union[jpype.JInt, int], acceptableDropFlavors: jpype.JArray[java.awt.datatransfer.DataFlavor]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def launchTool(self, domainFile: ghidra.framework.model.DomainFile):
        ...


class LogPanel(javax.swing.JPanel, log.LogListener):
    """
    A JPanel that contains a label to show the last message displayed. It also has a button to
    show the Console.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setHelpLocation(self, helpLocation: ghidra.util.HelpLocation):
        """
        Set the help location for the components in the LogPanel.
        
        :param ghidra.util.HelpLocation helpLocation: help location for this LogPanel
        """


@typing.type_check_only
class ImportGhidraToolsDialog(docking.DialogComponentProvider):

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


    class_: typing.ClassVar[java.lang.Class]

    def getSelectedList(self) -> java.util.List[java.lang.String]:
        ...

    def isCancelled(self) -> bool:
        ...

    @property
    def selectedList(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class ToolActionManager(ghidra.framework.model.ToolChestChangeListener):
    """
    Helper class to manage actions on the Tool menu.
    """

    @typing.type_check_only
    class ToolAction(docking.action.DockingAction):
        """
        Subclass to set the help ID for the tool actions whose names are the same
        as the tool name for run, delete, and export.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def toolRemoved(self, toolName: typing.Union[java.lang.String, str]):
        """
        ToolConfig was removed from the project toolchest
        """

    def toolSetAdded(self, toolset: ghidra.framework.model.ToolSet):
        """
        ToolSet was added to the project toolchest
        """

    def toolTemplateAdded(self, tc: ghidra.framework.model.ToolTemplate):
        """
        ToolConfig was added to the project toolchest
        """


class UserAgreementDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, showAgreementChoices: typing.Union[jpype.JBoolean, bool], exitOnCancel: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


@typing.type_check_only
class EditPluginPathDialog(docking.DialogComponentProvider):
    """
    Dialog for editing the Plugin path and Jar directory path preferences.
    
     
    The Plugin Path and Jar directory path are locations where Ghidra searches
    for plugins to load. The Plugin Path is specified exactly as a Java Classpath
    is specified.  When changes are made to these fields in the dialog, the
    preferences file is updated and written to disk. The preferences file is
    located in the .ghidra directory in the user's home directory.
    """

    @typing.type_check_only
    class PluginPathRenderer(docking.widgets.list.GListCellRenderer[java.lang.String]):
        """
        ListCellRenderer that renders the path values in the list,
        coloring paths that are no longer readable in red.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PathListSelectionListener(javax.swing.event.ListSelectionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def show(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Reset the list of paths each time the dialog is shown
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        """


@typing.type_check_only
class ZoomImageRunner(java.lang.Object):
    """
    A class to change the bounds of a given :obj:`ZoomedImagePainter` to make the Icon appear to 
    grow and fade away over time.  This class handles setup for the painter and then makes changes
    on the painter by using callbacks from the :obj:`Animator`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, glassPane: ghidra.util.bean.GGlassPane, painter: ZoomedImagePainter, icon: javax.swing.Icon):
        ...

    def addTimingTargetListener(self, newFinishedTarget: org.jdesktop.animation.timing.TimingTarget):
        """
        Allows clients to add a callback mechanism for timing events
        """

    def run(self):
        ...


class UtilityPluginPackage(ghidra.framework.plugintool.util.PluginPackage):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Utility"

    def __init__(self):
        ...


class UserAccessTableModel(docking.widgets.table.GDynamicColumnTableModel[ghidra.framework.remote.User, java.util.List[ghidra.framework.remote.User]]):
    """
    Table model for managing a list of Ghidra users associated with a project, and
    their access permissions. The permissions (read-only, read/write, admin) are rendered
    as checkboxes that can be selected by users, provided they have admin access.
    """

    @typing.type_check_only
    class UserColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.remote.User, java.lang.String, java.util.List[ghidra.framework.remote.User]]):
        """
        Table column for displaying the user name.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReadOnlyColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.remote.User, java.lang.Boolean, java.util.List[ghidra.framework.remote.User]]):
        """
        Table column for displaying the users read only status.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReadWriteColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.remote.User, java.lang.Boolean, java.util.List[ghidra.framework.remote.User]]):
        """
        Table column for displaying the users read/write status.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AdminColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.remote.User, java.lang.Boolean, java.util.List[ghidra.framework.remote.User]]):
        """
        Table column for displaying if the user has admin status.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    USERS_COL: typing.Final = 0
    READ_ONLY_COL: typing.Final = 1
    READ_WRITE_COL: typing.Final = 2
    ADMIN_COL: typing.Final = 3

    def __init__(self, currentUser: typing.Union[java.lang.String, str], userList: java.util.List[ghidra.framework.remote.User], serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        """
        Constructs a new table model.
        
        :param java.lang.String or str currentUser: the name of the current user
        :param java.util.List[ghidra.framework.remote.User] userList: list of all users associated with the current project
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: the service provider
        """

    def addUsers(self, addedUsers: java.util.List[ghidra.framework.remote.User]):
        """
        Add a list of users to the table.
        
        :param java.util.List[ghidra.framework.remote.User] addedUsers: list of User objects
        """

    def isCellEditable(self, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        The permissions columns in the table should be editable as long as the user
        is an admin and is not trying to adjust his/her own permissions.
        """

    def removeUsers(self, removedUsers: java.util.List[ghidra.framework.remote.User]):
        """
        Remove a list of users from the table.
        
        :param java.util.List[ghidra.framework.remote.User] removedUsers: list of User objects
        """

    def setUserList(self, users: java.util.List[ghidra.framework.remote.User]):
        """
        Replaces the contents of this model with a given list of users.
        
        :param java.util.List[ghidra.framework.remote.User] users: the user list
        """

    def setValueAt(self, aValue: java.lang.Object, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]):
        """
        Invoked when the user has changed one of the access rights checkboxes. When this
        happens we have to update the associated User data.
        """


class ConsoleListener(java.lang.Object):
    """
    Listener that is called when a string should be written to the console.
    """

    class_: typing.ClassVar[java.lang.Class]

    def put(self, message: typing.Union[java.lang.String, str], isError: typing.Union[jpype.JBoolean, bool]):
        """
        Output the message to the console.
        
        :param java.lang.String or str message: to output
        :param jpype.JBoolean or bool isError: true if this is an error message
        """

    def putln(self, message: typing.Union[java.lang.String, str], isError: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["FixedLengthTextField", "DataTreeDialog", "GhidraApplicationInformationDisplayFactory", "DialogProjectDataCollapseAction", "OpenVersionedFileDialog", "ConsoleTextPane", "DialogProjectDataExpandAction", "DataTreeDialogType", "InfoPanel", "AbstractDataTreeDialog", "DialogProjectDataNewFolderAction", "GetDomainObjectTask", "ViewInfo", "ApplicationLevelOnlyPlugin", "SetToolAssociationsDialog", "PickToolDialog", "FileActionManager", "ProjectInfoDialog", "FrontEndProjectDataNewFolderAction", "FrontEndPlugin", "ProjectActionManager", "FrontEndService", "MoveImageRunner", "SaveDataDialog", "WorkspacePanel", "TestFrontEndTool", "FrontEndProjectDataCollapseAction", "ProjectToolBar", "ViewProjectAccessPanel", "ProjectDataPanel", "AppInfo", "FrontEndProjectDataExpandAction", "ProjectAccessPanel", "SelectPanel", "EditActionManager", "ProjectAccessDialog", "ToolButtonTransferable", "AcceptUrlContentTask", "FrontEndTool", "ProgramaticUseOnly", "RunningToolsPanel", "ApplicationLevelPlugin", "ApplicationLevelPluginsConfiguration", "ZoomedImagePainter", "ToolConnectionDialog", "RepositoryChooser", "ToolConnectionPanel", "ServerInfoComponent", "ToolButton", "LogPanel", "ImportGhidraToolsDialog", "ToolActionManager", "UserAgreementDialog", "EditPluginPathDialog", "ZoomImageRunner", "UtilityPluginPackage", "UserAccessTableModel", "ConsoleListener"]
