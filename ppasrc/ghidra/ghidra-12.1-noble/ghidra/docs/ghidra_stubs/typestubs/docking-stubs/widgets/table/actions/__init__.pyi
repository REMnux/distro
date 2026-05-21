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
import docking.widgets.table
import java.lang # type: ignore


class DeleteTableRowAction(docking.action.DockingAction):
    """
    An action to delete data from a table.   If your model is a :obj:`ThreadedTableModel`, then
    this class is self-contained.  If you have some other kind of model, then you must 
    override :meth:`removeSelectedItems() <.removeSelectedItems>` in order to remove items from your model when the 
    action is executed.
     
    
    Note: deleting a row object is simply removing it from the given table/model.  This code is
    not altering the database.
     
    
    Tip: if you are a plugin that uses transient providers, then use 
    :meth:`registerDummy(Tool, String) <.registerDummy>` at creation time to install a dummy representative of
    this action in the Tool's options so that user's can update keybindings, regardless of whether
    they have ever shown one of your transient providers.
    """

    @typing.type_check_only
    class DeleteActionPlaceholder(docking.actions.SharedDockingActionPlaceholder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, owner: typing.Union[java.lang.String, str]) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, table: docking.widgets.table.GTable, owner: typing.Union[java.lang.String, str]) -> None:
        ...

    @typing.overload
    def __init__(self, table: docking.widgets.table.GTable, owner: typing.Union[java.lang.String, str], menuGroup: typing.Union[java.lang.String, str]) -> None:
        ...

    @staticmethod
    def registerDummy(tool: docking.Tool, owner: typing.Union[java.lang.String, str]) -> None:
        """
        A special method that triggers the registration of this action's shared/dummy keybinding.
        This is needed for plugins that produce transient component providers that do not exist
        at the time the plugin is loaded.
        
        :param docking.Tool tool: the tool whose options will updated with a dummy keybinding
        :param java.lang.String or str owner: the owner of the action that may be installed
        """



__all__ = ["DeleteTableRowAction"]
