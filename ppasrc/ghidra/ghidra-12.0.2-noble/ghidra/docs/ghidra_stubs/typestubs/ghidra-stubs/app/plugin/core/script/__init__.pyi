from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets
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
import javax.swing # type: ignore
import javax.swing.event # type: ignore


@typing.type_check_only
class ScriptAction(docking.action.DockingAction):
    ...
    class_: typing.ClassVar[java.lang.Class]


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

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        """
        Restore state for bundles, user actions, and filter.
        
        :param ghidra.framework.options.SaveState saveState: the state object
        """

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
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

    def __init__(self, testItems: java.util.List[ghidra.app.script.GhidraScriptProvider], defaultItem: ghidra.app.script.GhidraScriptProvider):
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
    A dialog that prompts the user to select a script.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getUserChoice(self) -> ghidra.app.script.ScriptInfo:
        ...

    def show(self):
        ...

    @property
    def userChoice(self) -> ghidra.app.script.ScriptInfo:
        ...


class SaveDialog(docking.DialogComponentProvider, javax.swing.event.ListSelectionListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], componentProvider: GhidraScriptComponentProvider, scriptDirs: java.util.List[generic.jar.ResourceFile], scriptFile: generic.jar.ResourceFile, scriptProvider: ghidra.app.script.GhidraScriptProvider, help: ghidra.util.HelpLocation):
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


class ScriptSelectionEditor(java.lang.Object):
    """
    A widget that allows the user to choose an existing script by typing its name or picking it
    from a list.
    """

    @typing.type_check_only
    class ScriptTextFieldModel(docking.widgets.DefaultDropDownSelectionDataModel[ghidra.app.script.ScriptInfo]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, data: java.util.List[ghidra.app.script.ScriptInfo], searchConverter: docking.widgets.DataToStringConverter[ghidra.app.script.ScriptInfo], descriptionConverter: docking.widgets.DataToStringConverter[ghidra.app.script.ScriptInfo]):
            ...


    @typing.type_check_only
    class ScriptSelectionTextField(docking.widgets.DropDownSelectionTextField[ghidra.app.script.ScriptInfo]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dataModel: docking.widgets.DropDownTextFieldDataModel[ghidra.app.script.ScriptInfo]):
            ...


    @typing.type_check_only
    class ScriptInfoDescriptionConverter(docking.widgets.DataToStringConverter[ghidra.app.script.ScriptInfo]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def addDocumentListener(self, listener: javax.swing.event.DocumentListener):
        """
        Adds a document listener to the text field editing component of this editor so that users
        can be notified when the text contents of the editor change.  You may verify whether the
        text changes represent a valid DataType by calling :meth:`validateUserSelection() <.validateUserSelection>`.
        
        :param javax.swing.event.DocumentListener listener: the listener to add.
        
        .. seealso::
        
            | :obj:`.validateUserSelection()`
        """

    def addEditorListener(self, l: ScriptEditorListener):
        """
        Adds a listener to know when the user has chosen a script info or cancelled editing.
        
        :param ScriptEditorListener l: the listener
        """

    def getEditorComponent(self) -> javax.swing.JComponent:
        """
        Returns the component that allows the user to edit.
        
        :return: the component that allows the user to edit.
        :rtype: javax.swing.JComponent
        """

    def getEditorText(self) -> str:
        """
        Returns the text value of the editor's text field.
        
        :return: the text value of the editor's text field.
        :rtype: str
        """

    def getEditorValue(self) -> ghidra.app.script.ScriptInfo:
        """
        Returns the currently chosen script info or null.
        
        :return: the currently chosen script info or null.
        :rtype: ghidra.app.script.ScriptInfo
        """

    def removeDocumentListener(self, listener: javax.swing.event.DocumentListener):
        """
        Removes a previously added document listener.
        
        :param javax.swing.event.DocumentListener listener: the listener to remove.
        """

    def removeEditorListener(self, l: ScriptEditorListener):
        """
        Removes the given listener.
        
        :param ScriptEditorListener l: the listener
        """

    def requestFocus(self):
        """
        Focuses this editors text field.
        """

    def setConsumeEnterKeyPress(self, consume: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether this editor should consumer Enter key presses
        
        :param jpype.JBoolean or bool consume: true to consume
        
        .. seealso::
        
            | :obj:`DropDownSelectionTextField.setConsumeEnterKeyPress(boolean)`
        """

    def validateUserSelection(self) -> bool:
        """
        Returns true if the value of this editor is valid.  Clients can use this to verify that the
        user text is a valid script selection.
        
        :return: true if the valid of this editor is valid.
        :rtype: bool
        """

    @property
    def editorText(self) -> java.lang.String:
        ...

    @property
    def editorValue(self) -> ghidra.app.script.ScriptInfo:
        ...

    @property
    def editorComponent(self) -> javax.swing.JComponent:
        ...


class ScriptEditorListener(java.lang.Object):
    """
    A simple listener to know when users have chosen a script in the :obj:`ScriptSelectionDialog`
    """

    class_: typing.ClassVar[java.lang.Class]

    def editingCancelled(self):
        """
        Called when the user cancels the script selection process.
        """

    def editingStopped(self):
        """
        Called when the user makes a selection.
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

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        :obj:`GhidraScriptMgrPlugin` is the entry point for all :obj:`GhidraScript` capabilities.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool this plugin is added to
        """

    def runScript(self, scriptFile: generic.jar.ResourceFile):
        """
        Attempts to run a script in a :obj:`RunScriptTask`.
        
        :param generic.jar.ResourceFile scriptFile: the script's source file
        """



__all__ = ["ScriptAction", "ScriptList", "GhidraScriptComponentProvider", "GhidraScriptActionManager", "GhidraScriptTableModel", "KeyBindingsInfo", "GhidraScriptEditorComponentProvider", "SaveNewScriptDialog", "ScriptCategoryNode", "KeyBindingInputDialog", "PickProviderDialog", "RootNode", "ScriptSelectionDialog", "SaveDialog", "ScriptSelectionEditor", "ScriptEditorListener", "RunScriptTask", "GhidraScriptMgrPlugin"]
