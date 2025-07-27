from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import generic.theme
import ghidra.framework.main
import ghidra.framework.plugintool
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class WindowLocationPlugin(ghidra.framework.plugintool.Plugin):

    @typing.type_check_only
    class WindowLocationProvider(docking.ComponentProvider):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: docking.Tool):
            ...


    @typing.type_check_only
    class WindowLocationPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class WindowInfo(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ThemeChooserDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class ThemeListModel(javax.swing.AbstractListModel[generic.theme.GTheme]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager):
        ...


class CreateThemeDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def getNewTheme(self, tool: ghidra.framework.plugintool.PluginTool, suggestedName: typing.Union[java.lang.String, str]) -> generic.theme.GTheme:
        ...


class ThemeManagerPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelOnlyPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["WindowLocationPlugin", "ThemeChooserDialog", "CreateThemeDialog", "ThemeManagerPlugin"]
