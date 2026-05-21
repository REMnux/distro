from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.nav
import ghidra.framework.plugintool
import ghidra.util.table
import java.lang # type: ignore


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
    def __init__(self, owner: typing.Union[java.lang.String, str], table: ghidra.util.table.GhidraTable) -> None:
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
    def __init__(self, navigatable: ghidra.app.nav.Navigatable, owner: typing.Union[java.lang.String, str], table: ghidra.util.table.GhidraTable) -> None:
        """
        Special constructor for clients that do not have a plugin.
         
        
        Clients using this constructor must override
        :meth:`makeProgramSelection(ProgramSelection, ActionContext) <.makeProgramSelection>`.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable that will be used to make selections; may not be null
        :param java.lang.String or str owner: the action's owner
        :param ghidra.util.table.GhidraTable table: the table needed for this action
        """

    @typing.overload
    def __init__(self, navigatable: ghidra.app.nav.Navigatable, owner: typing.Union[java.lang.String, str], table: ghidra.util.table.GhidraTable, menuGroup: typing.Union[java.lang.String, str]) -> None:
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
    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, table: ghidra.util.table.GhidraTable) -> None:
        """
        The normal constructor for this action.
         
        
        The given plugin will be used along with the given table to fire program selection events as
        the action is executed.
        
        :param ghidra.framework.plugintool.Plugin plugin: the plugin
        :param ghidra.util.table.GhidraTable table: the table
        """



__all__ = ["MakeProgramSelectionAction"]
