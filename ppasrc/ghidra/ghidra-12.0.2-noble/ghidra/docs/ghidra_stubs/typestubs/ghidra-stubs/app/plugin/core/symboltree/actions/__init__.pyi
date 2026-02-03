from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.widgets.tree
import docking.widgets.tree.support
import ghidra.app.context
import ghidra.app.plugin.core.symboltree
import ghidra.framework.plugintool
import java.lang # type: ignore
import java.util # type: ignore


class PasteAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin, provider: ghidra.app.plugin.core.symboltree.SymbolTreeProvider):
        ...


class ConvertToClassAction(SymbolTreeContextAction):
    """
    Symbol tree action for converting a namespace to a class
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin, group: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class CreateClassAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin, group: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class CloneSymbolTreeAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin, provider: ghidra.app.plugin.core.symboltree.SymbolTreeProvider):
        ...


class ClearPinSymbolAction(ghidra.app.context.ProgramSymbolContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], popupGroup: typing.Union[java.lang.String, str]):
        ...


class CreateExternalLocationAction(SymbolTreeContextAction):
    """
    An action in the symbol tree for creating an external location or external function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin):
        """
        Creates the action for creating a new external location or external function in the 
        symbol tree.
        
        :param ghidra.app.plugin.core.symboltree.SymbolTreePlugin plugin: the symbol tree plugin, which owns this action.
        """


class RenameAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin):
        ...


class PinSymbolAction(ghidra.app.context.ProgramSymbolContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], popupGroup: typing.Union[java.lang.String, str]):
        ...


class GoToToggleAction(docking.action.ToggleDockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin):
        ...


class CreateSymbolTableAction(ghidra.app.context.ProgramSymbolContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...


class GoToExternalLocationAction(ghidra.app.context.ProgramSymbolContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin):
        ...


class ShowSymbolReferencesAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]):
        ...


class DeleteAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin):
        ...


class SelectionAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...


class CreateLibraryAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin):
        ...


class SetExternalProgramAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin, provider: ghidra.app.plugin.core.symboltree.SymbolTreeProvider):
        ...


class CreateNamespaceAction(SymbolTreeContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin, group: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class CutAction(SymbolTreeContextAction):

    @typing.type_check_only
    class SymbolTreeNodeTransferable(docking.widgets.tree.support.GTreeNodeTransferable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handler: docking.widgets.tree.support.GTreeTransferHandler, selectedData: java.util.List[docking.widgets.tree.GTreeNode]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.symboltree.SymbolTreePlugin, provider: ghidra.app.plugin.core.symboltree.SymbolTreeProvider):
        ...


class SymbolTreeContextAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], kbType: docking.action.KeyBindingType):
        ...


class EditExternalLocationAction(docking.action.DockingAction):
    """
    A local action intended for components which supply a :obj:`ProgramSymbolActionContext` which
    facilitates editing an external location symbol.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        """
        Creates the action for editing an existing external location or external function in the 
        symbol tree.
        
        :param ghidra.framework.plugintool.Plugin plugin: the symbol tree plugin, which owns this action.
        """



__all__ = ["PasteAction", "ConvertToClassAction", "CreateClassAction", "CloneSymbolTreeAction", "ClearPinSymbolAction", "CreateExternalLocationAction", "RenameAction", "PinSymbolAction", "GoToToggleAction", "CreateSymbolTableAction", "GoToExternalLocationAction", "ShowSymbolReferencesAction", "DeleteAction", "SelectionAction", "CreateLibraryAction", "SetExternalProgramAction", "CreateNamespaceAction", "CutAction", "SymbolTreeContextAction", "EditExternalLocationAction"]
