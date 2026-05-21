from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.tool.util
import java.lang # type: ignore


class ToolConstants(docking.tool.util.DockingToolConstants):
    """
    Values used to define standard menu names and other miscellaneous constants
    """

    class_: typing.ClassVar[java.lang.Class]
    MENU_FILE: typing.Final = "&File"
    """
    Used when placing an action in the "File" menu of the tool
    """

    MENU_EDIT: typing.Final = "&Edit"
    """
    Used when placing an action in the "Edit" menu of the tool
    """

    MENU_NAVIGATION: typing.Final = "&Navigation"
    """
    Used when placing a PluginAction in the "Navigation" menu of the tool
    """

    MENU_NAVIGATION_GROUP_WINDOWS: typing.Final = "GoToWindow"
    """
    Group name for actions to navigate between windows
    """

    MENU_SEARCH: typing.Final = "&Search"
    """
    Used when placing an action in the "Search" menu of the tool
    """

    MENU_SELECTION: typing.Final = "Se&lect"
    """
    Used when placing an action in the "Selection" menu of the tool
    """

    MENU_HELP: typing.Final = "&Help"
    """
    Used when placing an action in the "About" menu of the tool
    """

    MENU_ANALYSIS: typing.Final = "&Analysis"
    """
    Used when placing an action in the "Analysis" menu of the tool
    """

    MENU_GRAPH: typing.Final = "&Graph"
    """
    Used when placing an action in the "Graph" menu of the tool
    """

    MENU_PROJECT: typing.Final = "&Project"
    """
    Used when placing an action in the "Project" menu of the tool
    """

    MENU_TOOLS: typing.Final = "&Tools"
    """
    Used when placing an action in the "Tools" menu of the tool
    """

    HELP_CONTENTS_MENU_GROUP: typing.Final = "AAAHelpContents"
    """
    A group for actions that link directly to help content
    """

    TOOL_OPTIONS_MENU_GROUP: typing.Final = "AOptions"
    """
    Constant for the options menu group for the Tool Options menu item
    """

    NO_ACTIVE_PROJECT: typing.Final = "NO ACTIVE PROJECT"
    """
    Node name used in the Data tree when a project is not open
    """

    TOOL_OWNER: typing.Final = "Tool"
    """
    This is used when an action has the tool as its owner
    """

    SHARED_OWNER: typing.Final = "Shared"
    """
    This is used when many actions wish to share a key binding.
    
    
    .. seealso::
    
        | :obj:`KeyBindingType.SHARED`
    """

    TOOL_OPTIONS: typing.Final = "Tool"
    """
    Tool options name
    """

    FILE_IMPORT_OPTIONS: typing.Final = "File Import"
    """
    File Import options name
    """

    GRAPH_OPTIONS: typing.Final = "Graph"
    """
    Graph options name
    """

    ABOUT_HELP_TOPIC: typing.Final = "About"
    """
    Name of the help topic for "About" domain objects and Ghidra
    """

    FRONT_END_HELP_TOPIC: typing.Final = "FrontEndPlugin"
    """
    Name of help topic for the front end (Ghidra Project Window)
    """

    TOOL_HELP_TOPIC: typing.Final = "Tool"
    """
    Name of help topic for the Tool
    """

    MENU_GROUP_NEXT_CODE_UNIT_NAV: typing.Final = "NextPrevCodeUnit"
    """
    Used for navigation-based action
    """

    TOOLBAR_GROUP_ONE: typing.Final = "1_Toolbar_Navigation_Group"
    """
    Primary toolbar group number 1, starting from the left
    """

    TOOLBAR_GROUP_TWO: typing.Final = "2_Toolbar_Navigation_Group"
    """
    Primary toolbar group number 2, starting from the left
    """

    TOOLBAR_GROUP_THREE: typing.Final = "3_Toolbar_Navigation_Group"
    """
    Primary toolbar group number 3, starting from the left
    """

    TOOLBAR_GROUP_FOUR: typing.Final = "4_Toolbar_Navigation_Group"
    """
    Primary toolbar group number 4, starting from the left
    """




__all__ = ["ToolConstants"]
