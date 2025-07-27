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
import docking.widgets.tree
import ghidra.app.services
import ghidra.formats.gfilesystem
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.plugin.importer
import ghidra.util.classfinder
import ghidra.util.task
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class FSBFileNode(FSBNode):
    """
    GTreeNode that represents a file on a filesystem.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFilenameExtOverride(self) -> str:
        ...

    def hasMissingPassword(self) -> bool:
        """
        Returns true if this file is missing its password
        
        :return: boolean true if this file is missing its password
        :rtype: bool
        """

    def hasPassword(self) -> bool:
        """
        Local copy of the original GFile's :obj:`FileAttributeType.HAS_GOOD_PASSWORD_ATTR` attribute.
        
        :return: boolean true if a password for the file has been found, false if missing the password
        :rtype: bool
        """

    def isEncrypted(self) -> bool:
        """
        Local copy of the original GFile's :obj:`FileAttributeType.IS_ENCRYPTED_ATTR` attribute.
        
        :return: boolean true if file needs a password to be read
        :rtype: bool
        """

    def isSymlink(self) -> bool:
        ...

    @property
    def filenameExtOverride(self) -> java.lang.String:
        ...

    @property
    def encrypted(self) -> jpype.JBoolean:
        ...

    @property
    def symlink(self) -> jpype.JBoolean:
        ...


class FSBDirNode(FSBFileNode):
    """
    GTreeNode that represents a directory on a filesystem.
    """

    class_: typing.ClassVar[java.lang.Class]


class FSBFileHandlerContext(java.lang.Record):
    """
    Context given to a :obj:`FSBFileHandler` instance when being initialized.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FileSystemBrowserPlugin, fsbComponent: FSBComponentProvider, fsService: ghidra.formats.gfilesystem.FileSystemService, projectIndex: ghidra.plugin.importer.ProjectIndexService):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def fsService(self) -> ghidra.formats.gfilesystem.FileSystemService:
        ...

    def fsbComponent(self) -> FSBComponentProvider:
        ...

    def hashCode(self) -> int:
        ...

    def plugin(self) -> FileSystemBrowserPlugin:
        ...

    def projectIndex(self) -> ghidra.plugin.importer.ProjectIndexService:
        ...

    def toString(self) -> str:
        ...


class OpenWithTarget(java.lang.Object):
    """
    Represents a way to open a :obj:`DomainFile` in a :obj:`ProgramManager`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], pm: ghidra.app.services.ProgramManager, icon: javax.swing.Icon):
        ...

    @staticmethod
    def getAll() -> java.util.List[OpenWithTarget]:
        """
        Returns a list of all running tools and tool templates that can be used to open a domainfile.
        
        :return: list of OpenWithTarget instances, maybe empty but not null
        :rtype: java.util.List[OpenWithTarget]
        """

    @staticmethod
    def getDefault(tool: ghidra.framework.plugintool.PluginTool) -> OpenWithTarget:
        """
        Returns an OpenWithTarget, or null, that represents the specified tool's default ability 
        to open a :obj:`DomainFile`.
        
        :param ghidra.framework.plugintool.PluginTool tool: a :obj:`PluginTool`
        :return: a :obj:`OpenWithTarget`, or null if the specified tool can't open a domain file
        :rtype: OpenWithTarget
        """

    def getIcon(self) -> javax.swing.Icon:
        ...

    def getName(self) -> str:
        ...

    def getPm(self) -> ghidra.app.services.ProgramManager:
        ...

    @staticmethod
    def getRunningProgramManager(tool: ghidra.framework.plugintool.PluginTool) -> OpenWithTarget:
        """
        Returns an OpenWithTarget, or null, that represents a running :obj:`ProgramManager`.
        
        :param ghidra.framework.plugintool.PluginTool tool: a :obj:`PluginTool`
        :return: a :obj:`OpenWithTarget`, or null if there is no open :obj:`ProgramManager`
        :rtype: OpenWithTarget
        """

    def open(self, files: java.util.List[ghidra.framework.model.DomainFile]):
        """
        Opens the specified files, using whatever program manager / tool this instance represents.
         
        
        The first item in the list of files will be focused / made visible, the other items in the
        list will be opened but not focused.
        
        :param java.util.List[ghidra.framework.model.DomainFile] files: :obj:`DomainFile`s  to open
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def pm(self) -> ghidra.app.services.ProgramManager:
        ...


class FSBRootNode(FSBNode):
    """
    A GTreeNode that represents the root of a :obj:`GFileSystem`, and keeps the
    filesystem pinned in memory with its :obj:`FileSystemRef`.
     
    
    The :obj:`FileSystemRef` is released when this node is :meth:`dispose() <.dispose>`d.
     
    
    Since GTreeNodes are cloned during GTree filtering, and this class has a reference to an external
    resource that needs managing, this class needs to keeps track of the original modelNode
    and does all state modification using the modelNode's context.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getContainer(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    def getFSRef(self) -> ghidra.formats.gfilesystem.FileSystemRef:
        ...

    def getGFileFSBNode(self, file: ghidra.formats.gfilesystem.GFile, monitor: ghidra.util.task.TaskMonitor) -> FSBNode:
        ...

    def getProgramProviderFSRL(self, fsrl: ghidra.formats.gfilesystem.FSRL) -> ghidra.formats.gfilesystem.FSRL:
        ...

    def setCryptoStatusUpdated(self, cryptoStatusUpdated: typing.Union[jpype.JBoolean, bool]):
        ...

    def swapBackPrevModelNodeAndDispose(self):
        ...

    @property
    def container(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    @property
    def fSRef(self) -> ghidra.formats.gfilesystem.FileSystemRef:
        ...

    @property
    def programProviderFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...


class FSBFileHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    Extension point, used by the :obj:`FSBComponentProvider` to create actions that appear
    in the fsb tree, and to delegate focus and default actions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createActions(self) -> java.util.List[docking.action.DockingAction]:
        """
        Returns a list of :obj:`DockingAction`s that should be 
        :meth:`added <PluginTool.addLocalAction>`
        to the :obj:`FSBComponentProvider` tree as local actions.
        
        :return: list of :obj:`DockingAction`s
        :rtype: java.util.List[docking.action.DockingAction]
        """

    def fileDefaultAction(self, fileNode: FSBFileNode) -> bool:
        """
        Called when a file node is the target of a 'default action' initiated by the user, such
        as a double click, etc.
        
        :param FSBFileNode fileNode: :obj:`FSBFileNode` that was acted upon
        :return: boolean true if action was taken, false if no action was taken
        :rtype: bool
        """

    def fileFocused(self, fileNode: FSBFileNode) -> bool:
        """
        Called when a file node is focused in the :obj:`FSBComponentProvider` tree.
        
        :param FSBFileNode fileNode: :obj:`FSBFileNode` that was focused
        :return: boolean true if action was taken
        :rtype: bool
        """

    def getPopupProviderActions(self) -> java.util.List[docking.action.DockingAction]:
        """
        Returns a list of :obj:`DockingAction`s that should be added to a popup menu.  Called
        each time a fsb browser tree popup menu is created.
         
        
        Only use this method to provide actions when the actions need to be created freshly
        for each popup event.  Normal long-lived actions should be published by the
        :meth:`createActions() <.createActions>` method.
        
        :return: list of :obj:`DockingAction`s
        :rtype: java.util.List[docking.action.DockingAction]
        """

    def init(self, context: FSBFileHandlerContext):
        """
        Called once after creation of each instance to provide useful info
        
        :param FSBFileHandlerContext context: references to useful objects and services
        """

    @property
    def popupProviderActions(self) -> java.util.List[docking.action.DockingAction]:
        ...


class FSBActionContext(docking.DefaultActionContext):
    """
    :obj:`FSBComponentProvider` context for actions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: FSBComponentProvider, selectedNodes: java.util.List[FSBNode], event: java.awt.event.MouseEvent, gTree: docking.widgets.tree.GTree):
        """
        Creates a new :obj:`FileSystemBrowserPlugin`-specific action context.
        
        :param FSBComponentProvider provider: the ComponentProvider that generated this context.
        :param java.util.List[FSBNode] selectedNodes: selected nodes in the tree
        :param java.awt.event.MouseEvent event: MouseEvent that caused the update, or null
        :param docking.widgets.tree.GTree gTree: :obj:`FileSystemBrowserPlugin` provider tree.
        """

    def getFSRL(self, dirsOk: typing.Union[jpype.JBoolean, bool]) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the :obj:`FSRL` of the currently selected item, as long as it conforms to
        the dirsOk requirement.
        
        :param jpype.JBoolean or bool dirsOk: boolean flag, if true the selected item can be either a file or directory
        element, if false, it must be a file or the root of a file system that has a container
        file
        :return: FSRL of the single selected item, null if no items selected or more than 1 item
        selected
        :rtype: ghidra.formats.gfilesystem.FSRL
        """

    def getFSRLs(self, dirsOk: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.formats.gfilesystem.FSRL]:
        """
        Returns a list of FSRLs of the currently selected nodes in the tree.
        
        :param jpype.JBoolean or bool dirsOk: boolean flag, if true the selected items can be either a file or directory
        element, if false, it must be a file or the root of a file system that has a container
        file before being included in the resulting list
        :return: list of FSRLs of the currently selected items, maybe empty but never null
        :rtype: java.util.List[ghidra.formats.gfilesystem.FSRL]
        """

    def getFileFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the FSRL of the currently selected file node
        
        :return: FSRL of the currently selected file, or null if not file or more than 1 selected
        :rtype: ghidra.formats.gfilesystem.FSRL
        """

    def getFileFSRLs(self) -> java.util.List[ghidra.formats.gfilesystem.FSRL]:
        """
        Returns a list of FSRLs of the currently selected file nodes in the tree.
        
        :return: list of FSRLs of the currently selected file items, maybe empty but never null
        :rtype: java.util.List[ghidra.formats.gfilesystem.FSRL]
        """

    def getLoadableFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the FSRL of the currently selected item, if it is a 'loadable' item.
        
        :return: FSRL of the currently selected loadable item, or null if nothing selected or
        more than 1 selected
        :rtype: ghidra.formats.gfilesystem.FSRL
        """

    def getSelectedCount(self) -> int:
        """
        Returns the number of selected nodes in the tree.
        
        :return: returns the number of selected nodes in the tree.
        :rtype: int
        """

    def getSelectedNode(self) -> FSBNode:
        """
        Returns the currently selected tree node
        
        :return: the currently selected tree node, or null if no nodes or more than 1 node is selected
        :rtype: FSBNode
        """

    def getSelectedNodes(self) -> java.util.List[FSBNode]:
        """
        Returns a list of the currently selected tree nodes.
        
        :return: list of currently selected tree nodes
        :rtype: java.util.List[FSBNode]
        """

    def getTree(self) -> docking.widgets.tree.GTree:
        """
        Gets the :obj:`FileSystemBrowserPlugin` provider's  tree.
        
        :return: The :obj:`FileSystemBrowserPlugin` provider's  tree.
        :rtype: docking.widgets.tree.GTree
        """

    def hasSelectedLinkedNodes(self) -> bool:
        ...

    def hasSelectedNodes(self) -> bool:
        """
        Returns true if there are selected nodes in the browser tree.
        
        :return: boolean true if there are selected nodes in the browser tree
        :rtype: bool
        """

    def isBusy(self) -> bool:
        """
        Returns true if the GTree is busy
        
        :return: boolean true if the GTree is busy
        :rtype: bool
        """

    def isSelectedAllDirs(self) -> bool:
        """
        Returns true if the currently selected items are all directory items
        
        :return: boolean true if the currently selected items are all directory items
        :rtype: bool
        """

    def notBusy(self) -> bool:
        """
        Returns true if the GTree is not busy
        
        :return: boolean true if GTree is not busy
        :rtype: bool
        """

    @property
    def selectedCount(self) -> jpype.JInt:
        ...

    @property
    def selectedAllDirs(self) -> jpype.JBoolean:
        ...

    @property
    def fileFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def selectedNode(self) -> FSBNode:
        ...

    @property
    def tree(self) -> docking.widgets.tree.GTree:
        ...

    @property
    def fSRLs(self) -> java.util.List[ghidra.formats.gfilesystem.FSRL]:
        ...

    @property
    def fSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    @property
    def selectedNodes(self) -> java.util.List[FSBNode]:
        ...

    @property
    def fileFSRLs(self) -> java.util.List[ghidra.formats.gfilesystem.FSRL]:
        ...

    @property
    def loadableFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...


class FileSystemBrowserPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelPlugin, ghidra.framework.model.ProjectListener, ghidra.app.services.FileSystemBrowserService):
    """
    A :obj:`Plugin` that supplies a :obj:`filesystem <GFileSystem>` browser component
    that allows the user to view the contents of filesystems and perform actions on the
    files inside those filesystems.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def createNewFileSystemBrowser(self, fsRef: ghidra.formats.gfilesystem.FileSystemRef, show: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new browser UI component for an already open :obj:`GFileSystem` (pinned
        with the specified :obj:`FileSystemRef` that will be taken ownership of by this
        method).
        
        :param ghidra.formats.gfilesystem.FileSystemRef fsRef: :obj:`FileSystemRef` of open :obj:`GFileSystem`
        :param jpype.JBoolean or bool show: boolean true if the new browser component should be shown
        """

    def getLastExportDirectory(self) -> java.io.File:
        ...

    def openFileSystem(self):
        """
        Prompts the user to pick a file system container file to open using a local
        filesystem browser and then displays that filesystem in a new fsb browser.
        """

    def setLastExportDirectory(self, lastExportDirectory: jpype.protocol.SupportsPath):
        ...

    @property
    def lastExportDirectory(self) -> java.io.File:
        ...

    @lastExportDirectory.setter
    def lastExportDirectory(self, value: java.io.File):
        ...


class FSBNode(docking.widgets.tree.GTreeSlowLoadingNode):
    """
    Base class for all filesystem browser gtree nodes.
    """

    class_: typing.ClassVar[java.lang.Class]
    FSBNODE_NAME_TYPE_COMPARATOR: typing.Final[java.util.Comparator[docking.widgets.tree.GTreeNode]]

    @staticmethod
    def createNodeFromFile(file: ghidra.formats.gfilesystem.GFile, monitor: ghidra.util.task.TaskMonitor) -> FSBFileNode:
        """
        Helper method to convert a single :obj:`GFile` object into a FSBNode object.
        
        :param ghidra.formats.gfilesystem.GFile file: :obj:`GFile` to convert
        :return: a new :obj:`FSBFileNode` with type specific to the GFile's type.
        :rtype: FSBFileNode
        """

    @staticmethod
    def createNodesFromFileList(files: java.util.List[ghidra.formats.gfilesystem.GFile], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[docking.widgets.tree.GTreeNode]:
        """
        Helper method to convert :obj:`GFile` objects to FSBNode objects.
        
        :param java.util.List[ghidra.formats.gfilesystem.GFile] files: :obj:`List` of :obj:`GFile` objects to convert
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: :obj:`List` of :obj:`FSBNode` instances (return typed as a GTreeNode list),
        specific to each GFile instance's type.
        :rtype: java.util.List[docking.widgets.tree.GTreeNode]
        """

    @staticmethod
    def findContainingFileSystemFSBRootNode(node: FSBNode) -> FSBRootNode:
        """
        Returns the :obj:`FSBRootNode` that represents the root of the file system that
        contains the specified file node.
        
        :param FSBNode node: GTree node that represents a file.
        :return: FSBRootNode that represents the file system holding the file.
        :rtype: FSBRootNode
        """

    def getFSBRootNode(self) -> FSBRootNode:
        ...

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the :obj:`FSRL` of the filesystem object that this node represents.
         
        
        The root of filesystems will return a :obj:`FSRLRoot`.
        
        :return: :obj:`FSRL` of the filesystem object.
        :rtype: ghidra.formats.gfilesystem.FSRL
        """

    def getFileExtension(self) -> str:
        """
        Returns the extension of this node's name, or "" if none
        
        :return: extension of this node's name, or "" if none
        :rtype: str
        """

    def getFormattedTreePath(self) -> str:
        ...

    def getGFile(self) -> ghidra.formats.gfilesystem.GFile:
        ...

    def getLoadableFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    def init(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    def refreshNode(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    @property
    def fSBRootNode(self) -> FSBRootNode:
        ...

    @property
    def fileExtension(self) -> java.lang.String:
        ...

    @property
    def fSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    @property
    def formattedTreePath(self) -> java.lang.String:
        ...

    @property
    def loadableFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        ...

    @property
    def gFile(self) -> ghidra.formats.gfilesystem.GFile:
        ...


class TextEditorComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class KeyMasterTextArea(javax.swing.JTextArea):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FileSystemBrowserPlugin, textFileName: typing.Union[java.lang.String, str], text: typing.Union[java.lang.String, str]):
        ...

    def getText(self) -> str:
        ...

    @property
    def text(self) -> java.lang.String:
        ...


class FSBIcons(java.lang.Object):
    """
    Static list of Icons for the file system browser plugin and its child windows.
     
    
    The :meth:`singleton instance <.getInstance>` provides :obj:`Icon`s that represent the type 
    and status of a file, based on a filename mapping and caller specified status overlays.
     
    
    Thread safe
    """

    @typing.type_check_only
    class Singleton(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    COPY: typing.Final[javax.swing.Icon]
    CUT: typing.Final[javax.swing.Icon]
    DELETE: typing.Final[javax.swing.Icon]
    FONT: typing.Final[javax.swing.Icon]
    LOCKED: typing.Final[javax.swing.Icon]
    NEW: typing.Final[javax.swing.Icon]
    PASTE: typing.Final[javax.swing.Icon]
    REDO: typing.Final[javax.swing.Icon]
    RENAME: typing.Final[javax.swing.Icon]
    REFRESH: typing.Final[javax.swing.Icon]
    SAVE: typing.Final[javax.swing.Icon]
    SAVE_AS: typing.Final[javax.swing.Icon]
    UNDO: typing.Final[javax.swing.Icon]
    UNLOCKED: typing.Final[javax.swing.Icon]
    CLOSE: typing.Final[javax.swing.Icon]
    COLLAPSE_ALL: typing.Final[javax.swing.Icon]
    COMPRESS: typing.Final[javax.swing.Icon]
    CREATE_FIRMWARE: typing.Final[javax.swing.Icon]
    EXPAND_ALL: typing.Final[javax.swing.Icon]
    EXTRACT: typing.Final[javax.swing.Icon]
    INFO: typing.Final[javax.swing.Icon]
    OPEN: typing.Final[javax.swing.Icon]
    OPEN_AS_BINARY: typing.Final[javax.swing.Icon]
    OPEN_IN_LISTING: typing.Final[javax.swing.Icon]
    OPEN_FILE_SYSTEM: typing.Final[javax.swing.Icon]
    PHOTO: typing.Final[javax.swing.Icon]
    VIEW_AS_IMAGE: typing.Final[javax.swing.Icon]
    VIEW_AS_TEXT: typing.Final[javax.swing.Icon]
    ECLIPSE: typing.Final[javax.swing.Icon]
    JAR: typing.Final[javax.swing.Icon]
    IMPORT: typing.Final[javax.swing.Icon]
    iOS: typing.Final[javax.swing.Icon]
    OPEN_ALL: typing.Final[javax.swing.Icon]
    LIST_MOUNTED: typing.Final[javax.swing.Icon]
    LIBRARY: typing.Final[javax.swing.Icon]
    IMPORTED_OVERLAY_ICON: typing.Final[javax.swing.Icon]
    FILESYSTEM_OVERLAY_ICON: typing.Final[javax.swing.Icon]
    MISSING_PASSWORD_OVERLAY_ICON: typing.Final[javax.swing.Icon]
    LINK_OVERLAY_ICON: typing.Final[javax.swing.Icon]
    DEFAULT_ICON: typing.Final[javax.swing.Icon]
    MY_COMPUTER: typing.Final[javax.swing.Icon]

    def getIcon(self, fileName: typing.Union[java.lang.String, str], overlays: java.util.List[javax.swing.Icon]) -> javax.swing.Icon:
        """
        Returns an :obj:`Icon` that represents a file's content based on its
        name.
        
        :param java.lang.String or str fileName: name of file that an icon is being requested for.
        :param java.util.List[javax.swing.Icon] overlays: optional list of overlay icons that
                    should be overlaid on top of the base icon. These icons represent a
                    status or feature independent of the file's base icon.
        :return: :obj:`Icon` instance that best represents the named file, never
                null.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getInstance() -> FSBIcons:
        ...


class FSBComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.formats.gfilesystem.FileSystemEventListener, docking.actions.PopupActionProvider, ghidra.plugin.importer.ProjectIndexService.ProjectIndexListener):
    """
    Plugin component provider for the :obj:`FileSystemBrowserPlugin`.
     
    
    An instance of this class is created for each file system browser window (w/tree).
     
    
    See the :obj:`FSBFileHandler` interface for how to add actions to this component.
    """

    @typing.type_check_only
    class DefaultFileHandler(FSBFileHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FileSystemBrowserPlugin, fsRef: ghidra.formats.gfilesystem.FileSystemRef):
        """
        Creates a new :obj:`FSBComponentProvider` instance, taking
        ownership of the passed-in :obj:`fsRef <FileSystemRef>`.
        
        :param FileSystemBrowserPlugin plugin: parent plugin
        :param ghidra.formats.gfilesystem.FileSystemRef fsRef: :obj:`FileSystemRef` to a :obj:`GFileSystem`.
        """

    def afterAddedToTool(self):
        ...

    def ensureFileAccessable(self, fsrl: ghidra.formats.gfilesystem.FSRL, node: FSBNode, monitor: ghidra.util.task.TaskMonitor) -> bool:
        ...

    def getGTree(self) -> docking.widgets.tree.GTree:
        """
        
        
        :return: this provider's GTree.
        :rtype: docking.widgets.tree.GTree
        """

    def getPlugin(self) -> FileSystemBrowserPlugin:
        ...

    def getProjectIndex(self) -> ghidra.plugin.importer.ProjectIndexService:
        ...

    def openFileSystem(self, node: FSBNode, nested: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def runTask(self, runnableTask: ghidra.util.task.MonitoredRunnable):
        ...

    def setProject(self, project: ghidra.framework.model.Project):
        ...

    @property
    def plugin(self) -> FileSystemBrowserPlugin:
        ...

    @property
    def gTree(self) -> docking.widgets.tree.GTree:
        ...

    @property
    def projectIndex(self) -> ghidra.plugin.importer.ProjectIndexService:
        ...



__all__ = ["FSBFileNode", "FSBDirNode", "FSBFileHandlerContext", "OpenWithTarget", "FSBRootNode", "FSBFileHandler", "FSBActionContext", "FileSystemBrowserPlugin", "FSBNode", "TextEditorComponentProvider", "FSBIcons", "FSBComponentProvider"]
