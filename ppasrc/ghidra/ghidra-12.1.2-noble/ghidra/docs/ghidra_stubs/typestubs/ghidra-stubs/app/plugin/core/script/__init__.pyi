from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.list
import docking.widgets.searchlist
import docking.widgets.table
import docking.widgets.tree
import generic.jar
import ghidra.app.plugin
import ghidra.app.plugin.core.osgi
import ghidra.app.script
import ghidra.app.services
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.table.column
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


@typing.type_check_only
class ScriptAction(docking.action.DockingAction):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ScriptsModel(docking.widgets.searchlist.DefaultSearchListModel[ghidra.app.script.ScriptInfo]):
    """
    Model for the script selection search list that organizes scripts into
    "Recent Scripts" and "All Scripts" categories.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, allScripts: java.util.List[ghidra.app.script.ScriptInfo], recentScriptNames: java.util.List[java.lang.String]) -> None:
        ...


class ScriptList(java.lang.Object):
    """
    Loads and manages updating of available script files.
     
    
    Use the :meth:`refresh() <.refresh>` method to reload the script files.
    """

    class_: typing.ClassVar[java.lang.Class]


class GhidraScriptComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class ScriptTaskListener(ghidra.util.task.TaskListener):
        """
        passed to runScript, repaints scriptTable when a script completes
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RefreshingBundleHostListener(ghidra.app.plugin.core.osgi.BundleHostListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScriptTableSecondaryFilter(docking.widgets.table.TableFilter[generic.jar.ResourceFile]):
        """
        Table filter that uses the state of the tree to further filter
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getBundleHost(self) -> ghidra.app.plugin.core.osgi.BundleHost:
        """
        
        
        :return: the bundle host used for scripting, ultimately from
                :meth:`GhidraScriptUtil.getBundleHost() <GhidraScriptUtil.getBundleHost>`
        :rtype: ghidra.app.plugin.core.osgi.BundleHost
        """

    def getScriptDirectories(self) -> java.util.List[generic.jar.ResourceFile]:
        """
        
        
        :return: enabled bundle paths from the scripting bundle host
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    def getTable(self) -> docking.widgets.table.GTable:
        ...

    def getTree(self) -> docking.widgets.tree.GTree:
        ...

    def getWritableScriptDirectories(self) -> java.util.List[generic.jar.ResourceFile]:
        """
        
        
        :return: non-system bundle paths from the scripting bundle host
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    def readConfigState(self, saveState: ghidra.framework.options.SaveState) -> None:
        """
        Restore state for bundles, user actions, and filter.
        
        :param ghidra.framework.options.SaveState saveState: the state object
        """

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState) -> None:
        """
        Save state for bundles, user actions, and filter.
        
        :param ghidra.framework.options.SaveState saveState: the state object
        """

    @property
    def scriptDirectories(self) -> java.util.List[generic.jar.ResourceFile]:
        ...

    @property
    def writableScriptDirectories(self) -> java.util.List[generic.jar.ResourceFile]:
        ...

    @property
    def tree(self) -> docking.widgets.tree.GTree:
        ...

    @property
    def bundleHost(self) -> ghidra.app.plugin.core.osgi.BundleHost:
        ...

    @property
    def table(self) -> docking.widgets.table.GTable:
        ...


@typing.type_check_only
class GhidraScriptActionManager(java.lang.Object):

    @typing.type_check_only
    class LaunchJavadocTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RerunLastScriptAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    RERUN_LAST_SHARED_ACTION_NAME: typing.Final = "Rerun Last Script"


@typing.type_check_only
class GhidraScriptTableModel(docking.widgets.table.GDynamicColumnTableModel[generic.jar.ResourceFile, java.lang.Object]):

    @typing.type_check_only
    class ScriptActionColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.lang.Boolean, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StatusColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, javax.swing.Icon, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NameColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DescriptionColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyBindingColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, KeyBindingsInfo, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PathColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CategoryColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CreatedColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.util.Date, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ModifiedColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.util.Date, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RuntimeColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ProviderColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.jar.ResourceFile, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DateRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.util.Date]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class KeyBindingsInfo(java.lang.Comparable[KeyBindingsInfo]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GhidraScriptEditorComponentProvider(docking.ComponentProvider):

    @typing.type_check_only
    class KeyMasterTextArea(javax.swing.JTextArea):
        """
        Special JTextArea that knows how to properly handle it's key events.
        See :meth:`processKeyBinding(KeyStroke, KeyEvent, int, boolean) <.processKeyBinding>`
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ScriptGroup(java.lang.Enum[ScriptGroup]):
    """
    Categories for organizing scripts in the Script Quick Launch dialog.
    """

    class_: typing.ClassVar[java.lang.Class]
    RECENT_SCRIPTS: typing.Final[ScriptGroup]
    ALL_SCRIPTS: typing.Final[ScriptGroup]

    def getDisplayName(self) -> str:
        ...

    @staticmethod
    def getGroupByDisplayName(name: typing.Union[java.lang.String, str]) -> ScriptGroup:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ScriptGroup:
        ...

    @staticmethod
    def values() -> jpype.JArray[ScriptGroup]:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...


@typing.type_check_only
class SaveNewScriptDialog(SaveDialog):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ScriptCategoryNode(docking.widgets.tree.GTreeNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class KeyBindingInputDialog(docking.DialogComponentProvider, docking.KeyEntryListener):
    ...
    class_: typing.ClassVar[java.lang.Class]


class PickProviderDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, testItems: java.util.List[ghidra.app.script.GhidraScriptProvider], defaultItem: ghidra.app.script.GhidraScriptProvider) -> None:
        """
        Constructor used in testing only!
        
        :param java.util.List[ghidra.app.script.GhidraScriptProvider] testItems: values to populate model with
        :param ghidra.app.script.GhidraScriptProvider defaultItem: the default selection
        """


@typing.type_check_only
class RootNode(docking.widgets.tree.GTreeNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ScriptSelectionDialog(docking.DialogComponentProvider):
    """
    A dialog that prompts the user to select a script from a searchable list
    organized into "Recent Scripts" and "All Scripts" categories.
    """

    @typing.type_check_only
    class ScriptFilter(java.util.function.BiPredicate[ghidra.app.script.ScriptInfo, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScriptRenderer(docking.widgets.list.GListCellRenderer[docking.widgets.searchlist.SearchListEntry[ghidra.app.script.ScriptInfo]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getUserChoice(self) -> ghidra.app.script.ScriptInfo:
        ...

    def show(self) -> None:
        ...

    @property
    def userChoice(self) -> ghidra.app.script.ScriptInfo:
        ...


class SaveDialog(docking.DialogComponentProvider, javax.swing.event.ListSelectionListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], componentProvider: GhidraScriptComponentProvider, scriptDirs: java.util.List[generic.jar.ResourceFile], scriptFile: generic.jar.ResourceFile, scriptProvider: ghidra.app.script.GhidraScriptProvider, help: ghidra.util.HelpLocation) -> None:
        """
        Only called directly from testing!
        
        :param java.awt.Component parent: parent component
        :param java.lang.String or str title: dialog title
        :param GhidraScriptComponentProvider componentProvider: the provider
        :param java.util.List[generic.jar.ResourceFile] scriptDirs: list of directories to give as options when saving
        :param generic.jar.ResourceFile scriptFile: the default save location
        :param ghidra.app.script.GhidraScriptProvider scriptProvider: the :obj:`GhidraScriptProvider`
        :param ghidra.util.HelpLocation help: contextual help, e.g. for rename or save
        """


@typing.type_check_only
class RunScriptTask(ghidra.util.task.Task):

    class_: typing.ClassVar[java.lang.Class]

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class GhidraScriptMgrPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.app.services.GhidraScriptService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        """
        :obj:`GhidraScriptMgrPlugin` is the entry point for all :obj:`GhidraScript` capabilities.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool this plugin is added to
        """

    def runScript(self, scriptFile: generic.jar.ResourceFile) -> None:
        """
        Attempts to run a script in a :obj:`RunScriptTask`.
        
        :param generic.jar.ResourceFile scriptFile: the script's source file
        """



__all__ = ["ScriptAction", "ScriptsModel", "ScriptList", "GhidraScriptComponentProvider", "GhidraScriptActionManager", "GhidraScriptTableModel", "KeyBindingsInfo", "GhidraScriptEditorComponentProvider", "ScriptGroup", "SaveNewScriptDialog", "ScriptCategoryNode", "KeyBindingInputDialog", "PickProviderDialog", "RootNode", "ScriptSelectionDialog", "SaveDialog", "RunScriptTask", "GhidraScriptMgrPlugin"]
