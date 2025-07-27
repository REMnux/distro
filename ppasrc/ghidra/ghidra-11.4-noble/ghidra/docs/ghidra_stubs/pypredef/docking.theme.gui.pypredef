from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.table
import docking.widgets.tree
import generic.theme
import ghidra.util.table.column
import java.awt # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class FontValueEditor(ThemeValueEditor[java.awt.Font]):
    """
    Editor for Theme fonts
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listener: java.beans.PropertyChangeListener):
        """
        Constructor
        
        :param java.beans.PropertyChangeListener listener: the :obj:`PropertyChangeListener` to be notified when changes are made
        """


class ThemeColorPaletteTable(ThemeColorTable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager, valuesProvider: GThemeValuesCache):
        ...


class ThemeColorTable(javax.swing.JPanel, docking.action.ActionContextProvider, ThemeTable):
    """
    Color Table for Theme Dialog
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager, valuesProvider: GThemeValuesCache):
        ...

    def reloadAll(self):
        """
        Reloads all the values displayed in the table
        """

    def reloadCurrent(self):
        """
        Returns the current values displayed in the table
        """


class ColorValueEditor(ThemeValueEditor[java.awt.Color]):
    """
    Editor for Theme colors
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listener: java.beans.PropertyChangeListener):
        """
        Constructor
        
        :param java.beans.PropertyChangeListener listener: the :obj:`PropertyChangeListener` to be notified when changes are made
        """


class ThemeTable(java.lang.Object):
    """
    A common interface for theme tables
    """

    class_: typing.ClassVar[java.lang.Class]

    def isShowingSystemValues(self) -> bool:
        """
        True if showing system IDs
        
        :return: true if showing system IDs
        :rtype: bool
        """

    def setShowSystemValues(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        True signals to show IDs used for system values
        
        :param jpype.JBoolean or bool show: true signals to show IDs used for system values
        """

    @property
    def showingSystemValues(self) -> jpype.JBoolean:
        ...


class ThemeColorTree(javax.swing.JPanel, docking.action.ActionContextProvider):
    """
    Tree for showing colors organized by similar colors and reference relationships. This was
    built as a developer aid to help consolidate similar colors in Ghidra. This may be removed
    at any time.
    """

    @typing.type_check_only
    class SwatchIcon(javax.swing.Icon):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GroupingStrategy(java.lang.Enum[ThemeColorTree.GroupingStrategy]):

        class_: typing.ClassVar[java.lang.Class]
        REF: typing.Final[ThemeColorTree.GroupingStrategy]
        SAME_COLORS: typing.Final[ThemeColorTree.GroupingStrategy]
        BIN_8: typing.Final[ThemeColorTree.GroupingStrategy]
        BIN_64: typing.Final[ThemeColorTree.GroupingStrategy]
        BIN_512: typing.Final[ThemeColorTree.GroupingStrategy]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ThemeColorTree.GroupingStrategy:
            ...

        @staticmethod
        def values() -> jpype.JArray[ThemeColorTree.GroupingStrategy]:
            ...


    @typing.type_check_only
    class ColorNode(docking.widgets.tree.GTreeNode):

        class_: typing.ClassVar[java.lang.Class]

        def getColor(self) -> java.awt.Color:
            ...

        def sort(self, sorter: ColorSorter):
            ...

        @property
        def color(self) -> java.awt.Color:
            ...


    @typing.type_check_only
    class SameColorGroupNode(ThemeColorTree.ColorNode):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ColorValueNode(ThemeColorTree.ColorNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, colorValue: generic.theme.ColorValue):
            ...

        def getId(self) -> str:
            ...

        def getReferenceId(self) -> str:
            ...

        def isIndirect(self) -> bool:
            ...

        @property
        def indirect(self) -> jpype.JBoolean:
            ...

        @property
        def id(self) -> java.lang.String:
            ...

        @property
        def referenceId(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class ColorRootNode(docking.widgets.tree.GTreeNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager):
        ...

    def rebuild(self):
        ...


class ThemeEditorDialog(docking.DialogComponentProvider):
    """
    Primary dialog for editing Themes.
    """

    @typing.type_check_only
    class DialogThemeListener(generic.theme.ThemeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager):
        ...

    @staticmethod
    def editTheme(themeManager: generic.theme.ThemeManager):
        """
        Edits the current theme
        
        :param generic.theme.ThemeManager themeManager: the application ThemeManager
        """

    @staticmethod
    def getRunningInstance() -> ThemeEditorDialog:
        ...


class ProtectedIcon(javax.swing.Icon):
    """
    A wrapper for an icon that suppresses errors. Some Icons that are mined from a 
    :obj:`LookAndFeel` have specialized uses and will throw exceptions if used outside
    their intended component. This class is used when trying to show them in the theme
    editor table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: javax.swing.Icon):
        ...


class ThemeFontTable(javax.swing.JPanel, docking.action.ActionContextProvider, ThemeTable):
    """
    Font Table for Theme Dialog
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager, valuesProvider: GThemeValuesCache):
        ...

    def reloadAll(self):
        """
        Reloads all the values displayed in the table
        """

    def reloadCurrent(self):
        """
        Returns the current values displayed in the table
        """


class ThemeValueEditor(java.lang.Object, typing.Generic[T]):
    """
    Base class for Theme property Editors (Colors, Fonts, and Icons)
    """

    @typing.type_check_only
    class EditorDialog(docking.ReusableDialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def editValue(self, themeValue: generic.theme.ThemeValue[T]):
        """
        Edits the ThemeValue by invoking the appropriate dialog for editing the type
        
        :param generic.theme.ThemeValue[T] themeValue: the value to be edited
        """


class ThemeColorTableModel(docking.widgets.table.GDynamicColumnTableModel[generic.theme.ColorValue, java.lang.Object]):
    """
    Table model for theme colors
    """

    @typing.type_check_only
    class IdColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.theme.ColorValue, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ValueColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.theme.ColorValue, ThemeColorTableModel.ResolvedColor, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ThemeColorRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ThemeColorTableModel.ResolvedColor]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SwatchIcon(javax.swing.Icon):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ResolvedColor(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def color(self) -> java.awt.Color:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def id(self) -> str:
            ...

        def refId(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, valuesProvider: GThemeValuesCache):
        ...

    def isShowingSystemValues(self) -> bool:
        ...

    def reloadAll(self):
        """
        Reloads all the current values and all the default values in the table. Called when the
        theme changes or the application defaults have been forced to reload.
        """

    def reloadCurrent(self):
        """
        Reloads the just the current values shown in the table. Called whenever a color changes.
        """

    def setShowSystemValues(self, show: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def showingSystemValues(self) -> jpype.JBoolean:
        ...


class GThemeValuesCache(java.lang.Object):
    """
    Shares values for the three theme value tables so they all don't have their own copies
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager):
        ...

    def clear(self):
        ...

    def getCurrentValues(self) -> generic.theme.GThemeValueMap:
        ...

    def getDarkValues(self) -> generic.theme.GThemeValueMap:
        ...

    def getDefaultValues(self) -> generic.theme.GThemeValueMap:
        ...

    def getLightValues(self) -> generic.theme.GThemeValueMap:
        ...

    def getThemeValues(self) -> generic.theme.GThemeValueMap:
        ...

    @property
    def darkValues(self) -> generic.theme.GThemeValueMap:
        ...

    @property
    def lightValues(self) -> generic.theme.GThemeValueMap:
        ...

    @property
    def defaultValues(self) -> generic.theme.GThemeValueMap:
        ...

    @property
    def themeValues(self) -> generic.theme.GThemeValueMap:
        ...

    @property
    def currentValues(self) -> generic.theme.GThemeValueMap:
        ...


class ThemeIconTable(javax.swing.JPanel, docking.action.ActionContextProvider, ThemeTable):
    """
    Icon Table for Theme Dialog
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager, valuesProvider: GThemeValuesCache):
        ...

    def reloadAll(self):
        """
        Reloads all the values displayed in the table
        """

    def reloadCurrent(self):
        """
        Returns the current values displayed in the table
        """


class ThemeTableContext(docking.DefaultActionContext, typing.Generic[T]):
    """
    ActionContext for ThemeDialog tables
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, currentValue: generic.theme.ThemeValue[T], themeValue: generic.theme.ThemeValue[T], themeTable: ThemeTable):
        ...

    def getCurrentValue(self) -> generic.theme.ThemeValue[T]:
        """
        Returns the currentValue of the selected table row
        
        :return: the currentValue of the selected table row
        :rtype: generic.theme.ThemeValue[T]
        """

    def getThemeTable(self) -> ThemeTable:
        """
        Returns the theme table for this context
        
        :return: the table
        :rtype: ThemeTable
        """

    def getThemeValue(self) -> generic.theme.ThemeValue[T]:
        """
        Returns the original theme value of the selected table row
        
        :return: the original theme value of the selected table row
        :rtype: generic.theme.ThemeValue[T]
        """

    def isChanged(self) -> bool:
        """
        Returns true if the current value is not the same as the original theme value for the
        selected table row
        
        :return: true if the current value is not the same as the original theme value for the
        selected table row
        :rtype: bool
        """

    @property
    def themeTable(self) -> ThemeTable:
        ...

    @property
    def themeValue(self) -> generic.theme.ThemeValue[T]:
        ...

    @property
    def currentValue(self) -> generic.theme.ThemeValue[T]:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...


class ThemeIconTableModel(docking.widgets.table.GDynamicColumnTableModel[generic.theme.IconValue, java.lang.Object]):
    """
    Table model for theme icons
    """

    @typing.type_check_only
    class IdColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.theme.IconValue, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IconValueColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.theme.IconValue, ThemeIconTableModel.ResolvedIcon, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ThemeIconRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ThemeIconTableModel.ResolvedIcon]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ResolvedIcon(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def icon(self) -> javax.swing.Icon:
            ...

        def id(self) -> str:
            ...

        def refId(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, valuesProvider: GThemeValuesCache):
        ...

    def getThemeValue(self, id: typing.Union[java.lang.String, str]) -> generic.theme.IconValue:
        """
        Returns the original value for the id as defined by the current theme
        
        :param java.lang.String or str id: the resource id to get a font value for
        :return: the original value for the id as defined by the current theme
        :rtype: generic.theme.IconValue
        """

    def isShowingSystemValues(self) -> bool:
        ...

    def reloadAll(self):
        """
        Reloads all the current values and all the default values in the table. Called when the
        theme changes or the application defaults have been forced to reload.
        """

    def reloadCurrent(self):
        """
        Reloads the just the current values shown in the table. Called whenever an icon changes.
        """

    def setShowSystemValues(self, show: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def showingSystemValues(self) -> jpype.JBoolean:
        ...

    @property
    def themeValue(self) -> generic.theme.IconValue:
        ...


class ThemeFontTableModel(docking.widgets.table.GDynamicColumnTableModel[generic.theme.FontValue, java.lang.Object]):
    """
    Table model for theme fonts
    """

    @typing.type_check_only
    class IdColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.theme.FontValue, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FontValueColumn(docking.widgets.table.AbstractDynamicTableColumn[generic.theme.FontValue, ThemeFontTableModel.ResolvedFont, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ThemeFontRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ThemeFontTableModel.ResolvedFont]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ResolvedFont(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def font(self) -> java.awt.Font:
            ...

        def fontValue(self) -> generic.theme.FontValue:
            ...

        def hashCode(self) -> int:
            ...

        def id(self) -> str:
            ...

        def refId(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, valuesProvider: GThemeValuesCache):
        ...

    def getThemeValue(self, id: typing.Union[java.lang.String, str]) -> generic.theme.FontValue:
        """
        Returns the original value for the id as defined by the current theme
        
        :param java.lang.String or str id: the resource id to get a font value for
        :return: the original value for the id as defined by the current theme
        :rtype: generic.theme.FontValue
        """

    def isShowingSystemValues(self) -> bool:
        ...

    def reloadAll(self):
        """
        Reloads all the current values and all the default values in the table. Called when the
        theme changes or the application defaults have been forced to reload.
        """

    def reloadCurrent(self):
        """
        Reloads the just the current values shown in the table. Called whenever a font changes.
        """

    def setShowSystemValues(self, show: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def showingSystemValues(self) -> jpype.JBoolean:
        ...

    @property
    def themeValue(self) -> generic.theme.FontValue:
        ...


class IconValueEditor(ThemeValueEditor[javax.swing.Icon]):
    """
    Editor for Theme fonts
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listener: java.beans.PropertyChangeListener):
        """
        Constructor
        
        :param java.beans.PropertyChangeListener listener: the :obj:`PropertyChangeListener` to be notified when changes are made
        """


class ThemeUtils(java.lang.Object):
    """
    Some common methods related to saving themes. These are invoked from various places to handle
    what to do if a change is made that would result in loosing theme changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def askToSaveThemeChanges(themeManager: generic.theme.ThemeManager) -> bool:
        """
        Asks the user if they want to save the current theme changes. If they answer yes, it
        will handle several use cases such as whether it gets saved to a new file or
        overwrites an existing file.
        
        :param generic.theme.ThemeManager themeManager: the theme manager
        :return: true if the operation was not cancelled
        :rtype: bool
        """

    @staticmethod
    def canSaveToName(themeManager: generic.theme.ThemeManager, name: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    def deleteTheme(themeManager: generic.theme.ThemeManager):
        """
        Prompts for and deletes a selected theme.
        
        :param generic.theme.ThemeManager themeManager: the theme manager
        """

    @staticmethod
    def exportTheme(themeManager: generic.theme.ThemeManager):
        """
        Exports a theme, prompting the user to pick an file. Also handles dealing with any
        existing changes to the current theme.
        
        :param generic.theme.ThemeManager themeManager: the ThemeManager that actually does the export
        """

    @staticmethod
    def getSaveFile(themeName: typing.Union[java.lang.String, str]) -> java.io.File:
        ...

    @staticmethod
    def importTheme(themeManager: generic.theme.ThemeManager):
        """
        Imports a theme. Handles the case where there are existing changes to the current theme.
        
        :param generic.theme.ThemeManager themeManager: the application ThemeManager
        """

    @staticmethod
    def saveThemeChanges(themeManager: generic.theme.ThemeManager) -> bool:
        """
        Saves all current theme changes. Handles several use cases such as requesting a new theme
        name and asking to overwrite an existing file.
        
        :param generic.theme.ThemeManager themeManager: the theme manager
        :return: true if the operation was not cancelled
        :rtype: bool
        """


class ColorSorter(java.lang.Enum[ColorSorter], java.util.Comparator[java.awt.Color]):
    """
    Class for sorting colors by rgb values.  Each enum values changes the order of comparison for the
    red, green, and blue color values.
    """

    @typing.type_check_only
    class ColorFunction(java.util.function.Function[java.awt.Color, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    RGB: typing.Final[ColorSorter]
    RBG: typing.Final[ColorSorter]
    GRB: typing.Final[ColorSorter]
    GBR: typing.Final[ColorSorter]
    BRG: typing.Final[ColorSorter]
    BGR: typing.Final[ColorSorter]

    def getName(self) -> str:
        ...

    def toString(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ColorSorter:
        ...

    @staticmethod
    def values() -> jpype.JArray[ColorSorter]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class ExportThemeDialog(docking.DialogComponentProvider):
    """
    Dialog for exporting themes to external files or zip files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ThemeManager, exportAsZip: typing.Union[jpype.JBoolean, bool]):
        ...

    def setOutputFile(self, outputFile: jpype.protocol.SupportsPath):
        ...



__all__ = ["FontValueEditor", "ThemeColorPaletteTable", "ThemeColorTable", "ColorValueEditor", "ThemeTable", "ThemeColorTree", "ThemeEditorDialog", "ProtectedIcon", "ThemeFontTable", "ThemeValueEditor", "ThemeColorTableModel", "GThemeValuesCache", "ThemeIconTable", "ThemeTableContext", "ThemeIconTableModel", "ThemeFontTableModel", "IconValueEditor", "ThemeUtils", "ColorSorter", "ExportThemeDialog"]
