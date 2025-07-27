from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.app.context
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class ModuleSortPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Plugin to sort Modules and Fragments within a selected Module.
    Child Module folders are always name-sorted and placed
    above child Fragments.  When sorting on address, the minimum
    address for each fragment is used, while empty fragments are name-sorted
    and placed at the bottom.
    """

    @typing.type_check_only
    class SortTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GroupComparator(java.util.Comparator[ghidra.program.model.listing.Group]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ModuleSortAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], sortType: typing.Union[jpype.JInt, int]):
            ...

        def isEnabledForContext(self, context: docking.ActionContext) -> bool:
            """
            Determine if the Module Sort action should be visible within
            the popup menu for the specified active object.
            
            :param docking.ActionContext context: the context
            :return: true if action should be made visible in popup menu.
            :rtype: bool
            """

        @property
        def enabledForContext(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]
    SORT_BY_NAME: typing.Final = 1
    SORT_BY_ADDRESS: typing.Final = 2

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class AutoRenamePlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Plugin provides the following Fragment rename actions:
    1.  Automatically rename selected Program Fragments to match the
        minimum address Label within each fragment.
    2.  Using the active LabelFieldLocation within the code viewer,
        rename the corresponding fragment using the label.
    """

    @typing.type_check_only
    class AutoRenameAction(docking.action.DockingAction):
        """
        Defines a Fragment Auto-Rename action and controls the availability of the
        action within popup menus.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, owner: typing.Union[java.lang.String, str]):
            """
            Construct a new PluginAction
            
            :param java.lang.String or str owner: owner of the action
            :param plugin: instance of module sort plugin
            """

        def isEnabledForContext(self, context: docking.ActionContext) -> bool:
            """
            Determine if the Fragment Auto-Rename action should be visible within
            the popup menu for the selected nodes within the Program Tree View.
            
            :param activeObj: the object under the mouse location for the popup.:return: true if action should be made visible in popup menu.
            :rtype: bool
            """

        @property
        def enabledForContext(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class AutoLableRenameAction(ghidra.app.context.ListingContextAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, owner: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor.
        """



__all__ = ["ModuleSortPlugin", "AutoRenamePlugin"]
