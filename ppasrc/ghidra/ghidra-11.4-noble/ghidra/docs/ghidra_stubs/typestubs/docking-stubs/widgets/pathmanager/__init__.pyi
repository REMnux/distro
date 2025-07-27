from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.filechooser
import generic.jar
import generic.util
import ghidra.framework.options
import ghidra.util.filechooser
import java.beans # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore
import utility.function


T = typing.TypeVar("T")


class PathnameTablePanel(javax.swing.JPanel):
    """
    Component that has a table to show pathnames; the panel includes buttons to control the order of
    the paths, and to add and remove paths. The add button brings up a file chooser. Call the
    setFileChooser() method to control how the file chooser should behave. If the table entries
    should not be edited, call setEditingEnabled(false).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, paths: jpype.JArray[java.lang.String], enableEdits: typing.Union[jpype.JBoolean, bool], addToTop: typing.Union[jpype.JBoolean, bool], ordered: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new PathnameTablePanel.
        
        :param jpype.JArray[java.lang.String] paths: list of paths to show; may be null
        :param jpype.JBoolean or bool enableEdits: true to allow editing of entries *directly in the table*, i.e., via
                    the cell editor. The add and remove buttons still allow modification of the list.
        :param jpype.JBoolean or bool addToTop: true if the add button should add entries to the top of the list. False to
                    add entries to the bottom. This behavior is overridden if ``ordered`` is
                    false.
        :param jpype.JBoolean or bool ordered: true if the order of entries matters. If so, up and down buttons are provided
                    so the user may arrange the entries. If not, entries are sorted alphabetically.
        """

    @typing.overload
    def __init__(self, paths: jpype.JArray[java.lang.String], resetCallback: utility.function.Callback, enableEdits: typing.Union[jpype.JBoolean, bool], addToTop: typing.Union[jpype.JBoolean, bool], ordered: typing.Union[jpype.JBoolean, bool], supportsDotPath: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new PathnameTablePanel with a reset button
        
        :param jpype.JArray[java.lang.String] paths: list of paths to show; may be null
        :param utility.function.Callback resetCallback: callback containing the action to perform if the reset button is pressed
        :param jpype.JBoolean or bool enableEdits: true to allow editing of entries *directly in the table*, i.e., via
                    the cell editor. The add and remove buttons still allow modification of the list.
        :param jpype.JBoolean or bool addToTop: true if the add button should add entries to the top of the list. False to
                    add entries to the bottom. This behavior is overridden if ``ordered`` is
                    false.
        :param jpype.JBoolean or bool ordered: true if the order of entries matters. If so, up and down buttons are provided
                    so the user may arrange the entries. If not, entries are sorted alphabetically.
        :param jpype.JBoolean or bool supportsDotPath: true if the add button should support adding the "." path.  If so,
                    the user will be prompted to choose from a file browser, or adding ".".
        """

    def clear(self):
        """
        Clear the paths in the table.
        """

    def getPaths(self) -> jpype.JArray[java.lang.String]:
        ...

    def getTable(self) -> javax.swing.JTable:
        ...

    def setAddToTop(self, addToTop: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether new paths should be added to the top of the table (true) or at the end of the
        table (false).
        
        :param jpype.JBoolean or bool addToTop: true means to add to the top of the table
        """

    def setEditingEnabled(self, enableEdits: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether the entries in the table can be edited.
        
        :param jpype.JBoolean or bool enableEdits: false means to not allow editing; the table is editable by default.
        """

    def setFileChooserProperties(self, title: typing.Union[java.lang.String, str], preferenceForLastSelectedDir: typing.Union[java.lang.String, str], selectionMode: docking.widgets.filechooser.GhidraFileChooserMode, allowMultiSelection: typing.Union[jpype.JBoolean, bool], filter: ghidra.util.filechooser.GhidraFileFilter):
        """
        Set properties on the file chooser that is displayed when the "Add" button is pressed.
        
        :param java.lang.String or str title: title of the file chooser
        :param java.lang.String or str preferenceForLastSelectedDir: Preference to use as the current directory in the file
                    chooser
        :param docking.widgets.filechooser.GhidraFileChooserMode selectionMode: mode defined in GhidraFileFilter, e.g., GhidraFileFilter.FILES_ONLY
        :param jpype.JBoolean or bool allowMultiSelection: true if multiple files can be selected
        :param ghidra.util.filechooser.GhidraFileFilter filter: filter to use; may be null if no filtering is required
        """

    def setOrdered(self, ordered: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether the order of entries in the table matters.
        
         
        
        **WARNING:** When this is set to false, the entries are immediately sorted and the up and
        down buttons removed. Setting it back to true will replace the buttons, but will *not*
        restore the order. In general, this should be set once, at the start of the table's life
        cycle.
        
        :param jpype.JBoolean or bool ordered: true means the user can control the order, false means they cannot.
        """

    def setPaths(self, paths: jpype.JArray[java.lang.String]):
        ...

    @property
    def paths(self) -> jpype.JArray[java.lang.String]:
        ...

    @paths.setter
    def paths(self, value: jpype.JArray[java.lang.String]):
        ...

    @property
    def table(self) -> javax.swing.JTable:
        ...


class AbstractTypedPropertyEditor(java.beans.PropertyEditor, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class PathnameTableModel(javax.swing.table.AbstractTableModel):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PathManagerModel(javax.swing.table.AbstractTableModel):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AbstractPathsDialog(docking.DialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


class PathManager(java.lang.Object):
    """
    Component that has a table to show pathnames; the panel includes buttons to control
    the order of the paths, and to add and remove paths. The add button brings up a
    file chooser. Call the setFileChooser() method to control how the file chooser should
    behave.  If the table entries should not be edited, call setEditingEnabled(false).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, paths: java.util.List[generic.util.Path], addToTop: typing.Union[jpype.JBoolean, bool], allowOrdering: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new PathnameTablePanel.
        
        :param java.util.List[generic.util.Path] paths: list of paths to show; may be null
        :param jpype.JBoolean or bool addToTop: true if new paths are to be added to the top of the table, false
        :param jpype.JBoolean or bool allowOrdering: if true the ability to move path items up/down will be provided
        if new paths are to be added to the end of the table
        """

    @typing.overload
    def __init__(self, addToTop: typing.Union[jpype.JBoolean, bool], allowOrdering: typing.Union[jpype.JBoolean, bool]):
        ...

    def addListener(self, listener: PathManagerListener):
        ...

    def addPath(self, file: generic.jar.ResourceFile, enabled: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Add a new file path and set its enablement
        
        :param generic.jar.ResourceFile file: the file whose path to use
        :param jpype.JBoolean or bool enabled: true if enabled
        :return: true if the enabled path did not already exist
        :rtype: bool
        """

    def clear(self):
        """
        Clear the paths in the table.
        """

    def dispose(self):
        ...

    def getComponent(self) -> javax.swing.JComponent:
        """
        Returns the GUI component for the path manager.
        
        :return: the GUI component for the path manager
        :rtype: javax.swing.JComponent
        """

    def getListeners(self) -> java.util.List[PathManagerListener]:
        ...

    @staticmethod
    def getPathsFromPreferences(enablePathKey: typing.Union[java.lang.String, str], defaultEnablePaths: jpype.JArray[generic.util.Path], disabledPathKey: typing.Union[java.lang.String, str]) -> jpype.JArray[generic.util.Path]:
        """
        Restore paths from user Preferences using the specified keys.
        If preferences have never been saved, the specified ``defaultEnablePaths``
        will be returned.  Note: the encoded path list must have been stored
        using the same keys using the :meth:`savePathsToPreferences(String, String, Path[]) <.savePathsToPreferences>`
        or :meth:`saveToPreferences(String, String) <.saveToPreferences>` methods.
        
        :param java.lang.String or str enablePathKey: preference key for storing enabled paths
        :param jpype.JArray[generic.util.Path] defaultEnablePaths: default paths
        :param java.lang.String or str disabledPathKey: preference key for storing disabled paths
        :return: ordered paths from Preferences
        :rtype: jpype.JArray[generic.util.Path]
        """

    def removeListener(self, listener: PathManagerListener):
        ...

    def restoreFromPreferences(self, enablePathKey: typing.Union[java.lang.String, str], defaultEnablePaths: jpype.JArray[generic.util.Path], disabledPathKey: typing.Union[java.lang.String, str]):
        """
        Restore paths from user Preferences using the specified keys.
        If preferences have never been saved, the specified ``defaultEnablePaths``
        will be used.  Note: the encoded path list must have been stored
        using the same keys using the :meth:`savePathsToPreferences(String, String, Path[]) <.savePathsToPreferences>`
        or :meth:`saveToPreferences(String, String) <.saveToPreferences>` methods.
        
        :param java.lang.String or str enablePathKey: preference key for storing enabled paths
        :param jpype.JArray[generic.util.Path] defaultEnablePaths: default paths
        :param java.lang.String or str disabledPathKey: preference key for storing disabled paths
        """

    def restoreState(self, ss: ghidra.framework.options.SaveState):
        """
        Restores the paths from the specified SaveState object.
        
        :param ghidra.framework.options.SaveState ss: the SaveState object
        """

    @staticmethod
    def savePathsToPreferences(enablePathKey: typing.Union[java.lang.String, str], disabledPathKey: typing.Union[java.lang.String, str], paths: jpype.JArray[generic.util.Path]) -> bool:
        """
        Save the specified paths to the user Preferences using the specified keys.
        Note: The encoded path Preferences are intended to be decoded by the
        :meth:`restoreFromPreferences(String, Path[], String) <.restoreFromPreferences>` and
        :meth:`getPathsFromPreferences(String, Path[], String) <.getPathsFromPreferences>` methods.
        
        :param java.lang.String or str enablePathKey: preference key for storing enabled paths
        :param java.lang.String or str disabledPathKey: preference key for storing disabled paths
        :param jpype.JArray[generic.util.Path] paths: paths to be saved
        :return: true if Preference saved properly
        :rtype: bool
        """

    def saveState(self, ss: ghidra.framework.options.SaveState):
        """
        Saves the paths to the specified SaveState object.
        
        :param ghidra.framework.options.SaveState ss: the SaveState object
        """

    def saveToPreferences(self, enablePathKey: typing.Union[java.lang.String, str], disabledPathKey: typing.Union[java.lang.String, str]) -> bool:
        ...

    def setFileChooserProperties(self, title: typing.Union[java.lang.String, str], preferenceForLastSelectedDir: typing.Union[java.lang.String, str], selectionMode: docking.widgets.filechooser.GhidraFileChooserMode, allowMultiSelection: typing.Union[jpype.JBoolean, bool], filter: ghidra.util.filechooser.GhidraFileFilter):
        """
        Set properties on the file chooser that is displayed when the "Add" button is pressed.
        
        :param java.lang.String or str title: title of the file chooser
        :param java.lang.String or str preferenceForLastSelectedDir: Preference to use as the current directory in the
        file chooser
        :param docking.widgets.filechooser.GhidraFileChooserMode selectionMode: mode defined in GhidraFileChooser, e.g., GhidraFileChooser.FILES_ONLY
        :param jpype.JBoolean or bool allowMultiSelection: true if multiple files can be selected
        :param ghidra.util.filechooser.GhidraFileFilter filter: filter to use; may be null if no filtering is required
        """

    def setPaths(self, paths: java.util.List[generic.util.Path]):
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def listeners(self) -> java.util.List[PathManagerListener]:
        ...


class PathManagerListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def pathMessage(self, message: typing.Union[java.lang.String, str]):
        ...

    def pathsChanged(self):
        """
        Notified when the user changes the paths in the PathManager.  This could be the addition
        or removal of Path objects, or a simple reordering of the paths.
        """



__all__ = ["PathnameTablePanel", "AbstractTypedPropertyEditor", "PathnameTableModel", "PathManagerModel", "AbstractPathsDialog", "PathManager", "PathManagerListener"]
