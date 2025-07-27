from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.framework.main.datatable
import ghidra.framework.main.datatree
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.framework.remote
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class VersionControlUpdateAction(VersionControlAction):
    """
    Action to update the current checked out domain file to contain the changes 
    which have been checked in to the repository since our file's version was checked out.
    The update occurs by merging the changes from the repository's latest version into 
    the current copy of the checked out file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        """
        Creates an action for updating domain files that are checked out.
        
        :param ghidra.framework.plugintool.Plugin plugin: the plug-in that owns this action.
        """


class ProjectDataSelectAction(ghidra.framework.main.datatable.ProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class VersionControlShowHistoryAction(VersionControlAction):
    """
    Action to show the version history for a single version controlled domain file in the repository.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        """
        Creates an action to show the version history for a single version controlled 
        domain file in the repository.
        
        :param ghidra.framework.plugintool.Plugin plugin: the plug-in that owns this action.
        """


class ProjectDataCutAction(ProjectDataCopyCutBaseAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class ProjectDataReadOnlyAction(ghidra.framework.main.datatable.ProjectDataContextToggleAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class VersionControlViewCheckOutAction(VersionControlAction):
    """
    Action to view the current checkouts for a single domain file in the repository.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        """
        Creates an action to view the current checkouts for a single domain file in the repository.
        
        :param ghidra.framework.plugintool.Plugin plugin: the plug-in that owns this action.
        """


class CheckoutsActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def getSelectedRows(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def selectedRows(self) -> jpype.JArray[jpype.JInt]:
        ...


class CheckoutsDialog(docking.DialogComponentProvider, ghidra.framework.model.ProjectListener):
    """
    Dialog for viewing all the current checkouts for a single domain file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, user: ghidra.framework.remote.User, domainFile: ghidra.framework.model.DomainFile, checkouts: jpype.JArray[ghidra.framework.store.ItemCheckoutStatus]):
        ...


class VersionControlAddAction(VersionControlAction):
    """
    Action to add a domain file to version control in the repository.
    """

    @typing.type_check_only
    class AddToVersionControlTask(ghidra.framework.main.datatree.VersionControlTask):
        """
        Task for adding files to version control. This task displays a dialog for each file 
        which allows a comment to be entered for each check-in.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...


class ProjectDataPasteLinkAction(ghidra.framework.main.datatable.ProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class ProjectDataRenameAction(ghidra.framework.main.datatable.FrontendProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class ProjectDataExpandAction(docking.action.ContextSpecificAction[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], contextClass: java.lang.Class[T]):
        ...


class ProjectDataOpenToolAction(ghidra.framework.main.datatable.FrontendProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], toolName: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        ...


class DeleteProjectFilesTask(ghidra.util.task.Task):
    """
    Task for recursively deleting project files from a Ghidra project
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, folders: java.util.Set[ghidra.framework.model.DomainFolder], files: java.util.Set[ghidra.framework.model.DomainFile], fileCount: typing.Union[jpype.JInt, int], parent: java.awt.Component):
        """
        Construct a new DeleteProjectFilesTask with the list of folders and files to delete.
        
        :param java.util.Set[ghidra.framework.model.DomainFolder] folders: the fist of DomainFolders (and all files contained recursively 
        in those folders) to delete
        :param java.util.Set[ghidra.framework.model.DomainFile] files: the list of DomainFiles to delete
        :param jpype.JInt or int fileCount: the number of files being deleted
        :param java.awt.Component parent: the component to use for parenting any dialogs that are shown
        """

    def getFileCount(self) -> int:
        ...

    def getTotalDeleted(self) -> int:
        ...

    @property
    def totalDeleted(self) -> jpype.JInt:
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...


@typing.type_check_only
class CountDomainFilesTask(ghidra.util.task.Task):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, folders: java.util.Set[ghidra.framework.model.DomainFolder], files: java.util.Set[ghidra.framework.model.DomainFile]):
        ...


class VersionControlUndoHijackAction(VersionControlAction):
    """
    Action to undo hijacked domain files in the project.
    """

    @typing.type_check_only
    class UndoHijackTask(ghidra.util.task.Task):
        """
        Task for undoing hijacks of files that are in version control.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        """
        Creates an action to undo hijacked domain files in the project.
        
        :param ghidra.framework.plugintool.Plugin plugin: the plug-in that owns this action.
        """


class ProjectDataCollapseAction(docking.action.ContextSpecificAction[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], contextClass: java.lang.Class[T]):
        ...


@typing.type_check_only
class FileCountStatistics(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getFileCount(self) -> int:
        ...

    def getTotalDeleted(self) -> int:
        ...

    def incrementCheckedOutVersioned(self):
        ...

    def incrementDeleted(self):
        ...

    def incrementFileCount(self, size: typing.Union[jpype.JInt, int]):
        ...

    def incrementFileInUse(self):
        ...

    def incrementGeneralFailure(self):
        ...

    def incrementReadOnly(self):
        ...

    def incrementVersioned(self):
        ...

    def showReport(self, parent: java.awt.Component):
        ...

    @property
    def totalDeleted(self) -> jpype.JInt:
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...


class ProjectDataRefreshAction(ghidra.framework.main.datatable.FrontendProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...

    def refresh(self, projectData: ghidra.framework.model.ProjectData, comp: java.awt.Component):
        ...


class ProjectDataNewFolderAction(docking.action.ContextSpecificAction[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], contextClass: java.lang.Class[T]):
        ...


class VersionControlCheckOutAction(VersionControlAction):
    """
    Action to checkout domain files from the repository.
    """

    @typing.type_check_only
    class CheckOutTask(ghidra.util.task.Task):
        """
        Task for checking out files that are in version control
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        """
        Creates an action to checkout domain files from the repository
        
        :param ghidra.framework.plugintool.Plugin plugin: the plug-in that owns this action
        """


class ProjectDataDeleteAction(ghidra.framework.main.datatable.FrontendProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class ProjectDataCopyCutBaseAction(ghidra.framework.main.datatable.ProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...


class VersionControlAction(ghidra.framework.main.datatable.DomainFileProviderContextAction):
    """
    VersionControlAction is an abstract class that can be extended by each specific version
    control action to be taken on a domain file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool):
        ...

    def isAddToPopup(self, context: ghidra.framework.main.datatable.DomainFileContext) -> bool:
        """
        Returns true if there is at least one of the provided domain files can be 
        or is version controlled.
        """

    @property
    def addToPopup(self) -> jpype.JBoolean:
        ...


class ProjectDataCopyAction(ProjectDataCopyCutBaseAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class ProjectDataDeleteTask(ghidra.util.task.Task):
    """
    :obj:`Task` that handles deleting :obj:`files <DomainFile>` and :obj:`folders <DomainFolder>`
    from the project.
     
    
    This task will iterate all the files and folders specified by the user to weed out
    common problem issues (read-only files, checked-out files), ask the user to confirm,
    and then perform the actual delete operations.
     
    
    This task will show a summary dialog if there were multiple files involved or any errors
    encountered.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, files: java.util.List[ghidra.framework.model.DomainFile], folders: java.util.List[ghidra.framework.model.DomainFolder], parentComponent: java.awt.Component):
        """
        Creates a new task to delete the specified files and folders.
        
        :param java.util.List[ghidra.framework.model.DomainFile] files: - the :obj:`files <DomainFile>` the user requested to be deleted, or null.
        :param java.util.List[ghidra.framework.model.DomainFolder] folders: - the :obj:`folders <DomainFolder>` the user requested to be deleted, or null.
        :param java.awt.Component parentComponent: - parent java awt component that will be parent of the message dialogs and such.
        """


class ProjectDataPasteAction(ProjectDataCopyCutBaseAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class FindCheckoutsAction(ghidra.framework.main.datatable.ProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], plugin: ghidra.framework.plugintool.Plugin):
        ...


class ProjectDataOpenDefaultToolAction(ghidra.framework.main.datatable.FrontendProjectTreeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        ...


class VersionControlCheckInAction(VersionControlAction):
    """
    Action to check-in domain files to the repository.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, parent: java.awt.Component):
        """
        Creates an action to check-in domain files to the repository.
        
        :param ghidra.framework.plugintool.Plugin plugin: the plug-in that owns this action.
        :param java.awt.Component parent: the component to be used as the parent of the check-in dialog.
        """

    def checkIn(self, fileList: java.util.List[ghidra.framework.model.DomainFile]):
        """
        Check in the list of domain files. 
        Domain files that cannot be closed are skipped in the list.
        
        :param java.util.List[ghidra.framework.model.DomainFile] fileList: list of DomainFile objects
        """


class VersionControlUndoCheckOutAction(VersionControlAction):
    """
    Action to undo checkouts for domain files in the repository.
    """

    @typing.type_check_only
    class UndoCheckOutTask(ghidra.util.task.Task):
        """
        Task for undoing check out of files that are in version control.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        """
        Creates an action to undo checkouts for domain files in the repository.
        
        :param ghidra.framework.plugintool.Plugin plugin: the plug-in that owns this action.
        """



__all__ = ["VersionControlUpdateAction", "ProjectDataSelectAction", "VersionControlShowHistoryAction", "ProjectDataCutAction", "ProjectDataReadOnlyAction", "VersionControlViewCheckOutAction", "CheckoutsActionContext", "CheckoutsDialog", "VersionControlAddAction", "ProjectDataPasteLinkAction", "ProjectDataRenameAction", "ProjectDataExpandAction", "ProjectDataOpenToolAction", "DeleteProjectFilesTask", "CountDomainFilesTask", "VersionControlUndoHijackAction", "ProjectDataCollapseAction", "FileCountStatistics", "ProjectDataRefreshAction", "ProjectDataNewFolderAction", "VersionControlCheckOutAction", "ProjectDataDeleteAction", "ProjectDataCopyCutBaseAction", "VersionControlAction", "ProjectDataCopyAction", "ProjectDataDeleteTask", "ProjectDataPasteAction", "FindCheckoutsAction", "ProjectDataOpenDefaultToolAction", "VersionControlCheckInAction", "VersionControlUndoCheckOutAction"]
