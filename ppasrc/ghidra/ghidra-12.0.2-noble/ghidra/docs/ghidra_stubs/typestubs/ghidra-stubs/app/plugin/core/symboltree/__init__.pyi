from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.tree
import docking.widgets.tree.support
import docking.widgets.tree.tasks
import ghidra.app.context
import ghidra.app.plugin.core.symboltree.nodes
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import java.awt.datatransfer # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.tree # type: ignore


class SymbolTreeActionContext(ghidra.app.context.ProgramSymbolActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def getSelectedNode(self) -> ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode:
        """
        Returns a symbol tree node if there is a single node selected and it is a symbol tree node.
        Otherwise, null is returned.
        
        :return: the selected node or null
        :rtype: ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode
        """

    def getSelectedPath(self) -> javax.swing.tree.TreePath:
        ...

    def getSelectedSymbolNodes(self) -> java.util.List[ghidra.app.plugin.core.symboltree.nodes.SymbolNode]:
        """
        Returns all selected :obj:`SymbolNode`s or an empty list.
        
        :return: all selected :obj:`SymbolNode`s or an empty list.
        :rtype: java.util.List[ghidra.app.plugin.core.symboltree.nodes.SymbolNode]
        """

    def getSelectedSymbolTreePaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    def getSymbolTree(self) -> SymbolGTree:
        ...

    def getSymbolTreeProvider(self) -> SymbolTreeProvider:
        ...

    @property
    def symbolTreeProvider(self) -> SymbolTreeProvider:
        ...

    @property
    def selectedSymbolNodes(self) -> java.util.List[ghidra.app.plugin.core.symboltree.nodes.SymbolNode]:
        ...

    @property
    def selectedSymbolTreePaths(self) -> jpype.JArray[javax.swing.tree.TreePath]:
        ...

    @property
    def selectedNode(self) -> ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode:
        ...

    @property
    def symbolTree(self) -> SymbolGTree:
        ...

    @property
    def selectedPath(self) -> javax.swing.tree.TreePath:
        ...


class SymbolTreePlugin(ghidra.framework.plugintool.Plugin, SymbolTreeService):

    @typing.type_check_only
    class SymbolTreeOptionsListener(ghidra.framework.options.OptionsChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def createNewDisconnectedProvider(self, p: ghidra.program.model.listing.Program) -> DisconnectedSymbolTreeProvider:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def goTo(self, symbol: ghidra.program.model.symbol.Symbol):
        ...

    @typing.overload
    def goTo(self, extLoc: ghidra.program.model.symbol.ExternalLocation):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class SymbolCategory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    FUNCTION_CATEGORY: typing.Final[SymbolCategory]
    EXPORTS_CATEGORY: typing.Final[SymbolCategory]
    IMPORTS_CATEGORY: typing.Final[SymbolCategory]
    LABEL_CATEGORY: typing.Final[SymbolCategory]
    ROOT_CATEGORY: typing.Final[SymbolCategory]
    NAMESPACE_CATEGORY: typing.Final[SymbolCategory]
    CLASS_CATEGORY: typing.Final[SymbolCategory]

    def getName(self) -> str:
        ...

    def getSymbolType(self) -> ghidra.program.model.symbol.SymbolType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def symbolType(self) -> ghidra.program.model.symbol.SymbolType:
        ...


class SymbolTreeProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class SearchTask(docking.widgets.tree.GTreeTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AbstractSymbolUpdateTask(docking.widgets.tree.GTreeTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolAddedTask(SymbolTreeProvider.AbstractSymbolUpdateTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolChangedTask(SymbolTreeProvider.AbstractSymbolUpdateTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolScopeChangedTask(SymbolTreeProvider.AbstractSymbolUpdateTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolRemovedTask(SymbolTreeProvider.AbstractSymbolUpdateTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BulkWorkTask(docking.widgets.tree.tasks.GTreeBulkTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, plugin: SymbolTreePlugin):
        ...

    def cloneWindow(self):
        ...

    def getClipboard(self) -> java.awt.datatransfer.Clipboard:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def locationChanged(self, loc: ghidra.program.util.ProgramLocation):
        ...

    def reparentSymbols(self, namespace: ghidra.program.model.symbol.Namespace, symbolList: java.util.List[ghidra.program.model.symbol.Symbol]) -> int:
        ...

    def selectSymbol(self, symbol: ghidra.program.model.symbol.Symbol):
        ...

    def setClipboardContents(self, symbolTreeNodeTransferable: docking.widgets.tree.support.GTreeNodeTransferable):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def clipboard(self) -> java.awt.datatransfer.Clipboard:
        ...


@typing.type_check_only
class EditExternalLocationPanel(javax.swing.JPanel):
    """
    A panel for creating or editing an external location or external function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def applyLocation(self) -> bool:
        ...


class SymbolGTree(docking.widgets.tree.GTree):

    @typing.type_check_only
    class SymbolTreeCellRenderer(docking.widgets.tree.support.GTreeRenderer):

        class_: typing.ClassVar[java.lang.Class]
        OPEN_FOLDER_GROUP_ICON: typing.Final[javax.swing.Icon]
        CLOSED_FOLDER_GROUP_ICON: typing.Final[javax.swing.Icon]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, root: docking.widgets.tree.GTreeNode, plugin: SymbolTreePlugin):
        ...


class DisconnectedSymbolTreeProvider(SymbolTreeProvider):
    """
    A disconnected symbol tree is a snapshot of the primary symbol tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, plugin: SymbolTreePlugin, program: ghidra.program.model.listing.Program):
        ...


class EditExternalLocationDialog(docking.DialogComponentProvider):
    """
    Dialog for creating or editing an external location or external function.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, externalLocation: ghidra.program.model.symbol.ExternalLocation):
        """
        Creates a dialog for editing an external location or external function. The external
        location must have a location name, or address, or both.
        
        :param ghidra.program.model.symbol.ExternalLocation externalLocation: the external location or external function being edited.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, externalLibraryName: typing.Union[java.lang.String, str]):
        """
        Creates a dialog for creating or editing an external location or external function.
        
        :param ghidra.program.model.listing.Program program: the program to which the new external location will be added
        :param java.lang.String or str externalLibraryName: the name of the external library the dialog should default 
        to when creating the location.
        """

    def dispose(self):
        """
        Dispose of this dialog.
        """


class SymbolGTreeDragNDropHandler(docking.widgets.tree.support.GTreeDragNDropHandler):
    """
    A drag and drop handler for the :obj:`SymbolTreePlugin`.  There is limited support for dragging
    nodes within the tree to move symbols.  This class also supports the dragging of symbol nodes 
    into transient symbol tables.
    """

    class_: typing.ClassVar[java.lang.Class]


class SymbolTreeService(java.lang.Object):
    """
    Service to interact with the Symbol Tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def selectSymbol(self, symbol: ghidra.program.model.symbol.Symbol):
        """
        Selects the given symbol in the symbol tree.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol to select in the symbol tree
        """



__all__ = ["SymbolTreeActionContext", "SymbolTreePlugin", "SymbolCategory", "SymbolTreeProvider", "EditExternalLocationPanel", "SymbolGTree", "DisconnectedSymbolTreeProvider", "EditExternalLocationDialog", "SymbolGTreeDragNDropHandler", "SymbolTreeService"]
