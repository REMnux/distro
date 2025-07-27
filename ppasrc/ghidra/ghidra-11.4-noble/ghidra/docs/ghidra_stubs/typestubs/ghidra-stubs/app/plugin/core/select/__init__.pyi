from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.nav
import ghidra.app.plugin
import ghidra.framework.plugintool
import java.lang # type: ignore


class RestoreSelectionPlugin(ghidra.app.plugin.ProgramPlugin):

    @typing.type_check_only
    class SelectionState(java.lang.Object):
        """
        A state class to keep track of past and current selections and to determine when we can
        restore an old selection.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class SelectBlockDialog(docking.ReusableDialogComponentProvider):
    """
    Class to set up dialog box that will enable the user
    to set the available options for block selection
    """

    class_: typing.ClassVar[java.lang.Class]

    def setNavigatable(self, navigatable: ghidra.app.nav.Navigatable):
        ...


class SelectBlockPlugin(ghidra.framework.plugintool.Plugin):
    """
    This plugin class contains the structure needed for the user to
    select blocks of data anywhere inside of the Code Browser and Byte Viewer.
     
    
    Note:  This plugin used to refer to selections as blocks instead of lengths
    of bytes.  The GUI has been changed, but the internal comments and 
    variable names have not.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["RestoreSelectionPlugin", "SelectBlockDialog", "SelectBlockPlugin"]
