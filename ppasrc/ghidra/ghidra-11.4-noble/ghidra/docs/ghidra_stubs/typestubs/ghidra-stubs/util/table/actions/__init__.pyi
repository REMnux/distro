from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.actions
import docking.widgets.table
import ghidra.app.nav
import ghidra.framework.plugintool
import ghidra.util.table
import java.lang # type: ignore
import javax.swing.table # type: ignore


class MakeProgramSelectionAction(docking.action.DockingAction):
    """
    An action to make a program selection based on the given table's selection. For the context to
    work, the provider using this action must create an :obj:`ActionContext` that returns a context
    object that is the table passed to this action's constructor; otherwise, this action will not be
    enabled correctly.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    @deprecated("use either of the other constructors")
    def __init__(self, owner: typing.Union[java.lang.String, str], table: ghidra.util.table.GhidraTable):
        """
        Special constructor for clients that do not have a plugin.
         
        
        Clients using this constructor must override
        :meth:`makeProgramSelection(ProgramSelection, ActionContext) <.makeProgramSelection>`.
         
         
        
        Update: the preferred constructor for clients without a plugin is
        :meth:`MakeProgramSelectionAction(Navigatable, String, GhidraTable) <.MakeProgramSelectionAction>`.
        
        :param java.lang.String or str owner: the action's owner
        :param ghidra.util.table.GhidraTable table: the table needed for this action
        
        .. deprecated::
        
        use either of the other constructors
        """

    @typing.overload
    def __init__(self, navigatable: ghidra.app.nav.Navigatable, owner: typing.Union[java.lang.String, str], table: ghidra.util.table.GhidraTable):
        """
        Special constructor for clients that do not have a plugin.
         
        
        Clients using this constructor must override
        :meth:`makeProgramSelection(ProgramSelection, ActionContext) <.makeProgramSelection>`.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable that will be used to make selections; may not be null
        :param java.lang.String or str owner: the action's owner
        :param ghidra.util.table.GhidraTable table: the table needed for this action
        """

    @typing.overload
    def __init__(self, navigatable: ghidra.app.nav.Navigatable, owner: typing.Union[java.lang.String, str], table: ghidra.util.table.GhidraTable, menuGroup: typing.Union[java.lang.String, str]):
        """
        Special constructor for clients that do not have a plugin.
         
        
        Clients using this constructor must override
        :meth:`makeProgramSelection(ProgramSelection, ActionContext) <.makeProgramSelection>`.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable that will be used to make selections; may not be null
        :param java.lang.String or str owner: the action's owner
        :param ghidra.util.table.GhidraTable table: the table needed for this action
        :param java.lang.String or str menuGroup: The popup menu group for this action
        """

    @typing.overload
    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, table: ghidra.util.table.GhidraTable):
        """
        The normal constructor for this action.
         
        
        The given plugin will be used along with the given table to fire program selection events as
        the action is executed.
        
        :param ghidra.framework.plugintool.Plugin plugin: the plugin
        :param ghidra.util.table.GhidraTable table: the table
        """


class DeleteTableRowAction(docking.action.DockingAction):
    """
    An action to delete data from a table.   If your model is a :obj:`ThreadedTableModel`, then
    this class is self-contained.  If you have some other kind of model, then you must 
    override :meth:`removeSelectedItems() <.removeSelectedItems>` in order to remove items from your model when the 
    action is executed.
     
    
    Note: deleting a row object is simply removing it from the given table/model.  This code is
    not altering the database.
     
    
    Tip: if you are a plugin that uses transient providers, then use 
    :meth:`registerDummy(PluginTool, String) <.registerDummy>` at creation time to install a dummy representative of
    this action in the Tool's options so that user's can update keybindings, regardless of whether
    they have ever shown one of your transient providers.
    """

    @typing.type_check_only
    class DeleteActionPlaceholder(docking.actions.SharedDockingActionPlaceholder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, owner: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, table: docking.widgets.table.GTable, owner: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, table: docking.widgets.table.GTable, owner: typing.Union[java.lang.String, str], menuGroup: typing.Union[java.lang.String, str]):
        ...

    def checkForBusy(self, model: javax.swing.table.TableModel) -> bool:
        ...

    @staticmethod
    def registerDummy(tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]):
        """
        A special method that triggers the registration of this action's shared/dummy keybinding.
        This is needed for plugins that produce transient component providers that do not exist
        at the time the plugin is loaded.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool whose options will updated with a dummy keybinding
        :param java.lang.String or str owner: the owner of the action that may be installed
        """



__all__ = ["MakeProgramSelectionAction", "DeleteTableRowAction"]
