from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets
import docking.widgets.list
import docking.widgets.tree
import docking.widgets.tree.internal
import ghidra.framework
import ghidra.framework.options
import ghidra.util.filechooser
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.text # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.colorchooser # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore


@typing.type_check_only
class SwatchPanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getColorForLocation(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...


@typing.type_check_only
class HistorySwatchPanel(SwatchPanel):
    ...
    class_: typing.ClassVar[java.lang.Class]


class StringBasedFileEditor(FileChooserEditor):
    """
    A :obj:`PropertyEditor` that allows the user to edit strings by way of a File editor, as is
    done by :obj:`StringBasedFileEditor`.  In other words, the user can use the file chooser to
    pick a file.  That file is then turned into a String. 
     
     
    This class has the restriction that it will only 
    take in :obj:`String` objects and will only give out :obj:`String` objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class RecentSwatchPanel(SwatchPanel):
    ...
    class_: typing.ClassVar[java.lang.Class]


class EditorInitializer(ghidra.framework.ModuleInitializer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SettableColorSwatchChooserPanel(javax.swing.colorchooser.AbstractColorChooserPanel):

    @typing.type_check_only
    class HistorySwatchListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RecentSwatchListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MainSwatchListener(java.awt.event.MouseAdapter, java.io.Serializable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ColorNameListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getHistoryColors(self) -> java.util.List[java.awt.Color]:
        ...

    def getRecentColors(self) -> java.util.List[java.awt.Color]:
        ...

    def installChooserPanel(self, enclosingChooser: javax.swing.JColorChooser):
        """
        The background color, foreground color, and font are already set to the
        defaults from the defaults table before this method is called.
        """

    def setHistoryColors(self, historyColors: java.util.List[java.awt.Color]):
        ...

    def setRecentColors(self, recentColors: java.util.List[java.awt.Color]):
        ...

    @property
    def historyColors(self) -> java.util.List[java.awt.Color]:
        ...

    @historyColors.setter
    def historyColors(self, value: java.util.List[java.awt.Color]):
        ...

    @property
    def recentColors(self) -> java.util.List[java.awt.Color]:
        ...

    @recentColors.setter
    def recentColors(self, value: java.util.List[java.awt.Color]):
        ...


class ScrollableOptionsEditor(ghidra.framework.options.OptionsEditor):
    """
    Panel that shows each property in an Options category or a Group in an Options category
    """

    @typing.type_check_only
    class ScollableOptionsPanel(javax.swing.JPanel, javax.swing.Scrollable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], optionNames: java.util.List[java.lang.String]):
        """
        Creates a panel for editing options. This version of the constructor allows the client
        to specify the option names to put them in some order other than the default alphabetical
        ordering.
        
        :param java.lang.String or str title: The title of the options panel
        :param java.util.List[java.lang.String] optionNames: the names of the options for this panel
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str]):
        """
        Creates a panel for editing options. This version of the constructor will get the
        options names from the options object when
        :meth:`getEditorComponent(Options, EditorStateFactory) <.getEditorComponent>` is called.
        
        :param java.lang.String or str title: the title for the panel
        """

    def getComponent(self) -> javax.swing.JComponent:
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...


@typing.type_check_only
class OptionsTreeNode(docking.widgets.tree.GTreeLazyNode):

    class_: typing.ClassVar[java.lang.Class]

    def compareTo(self, other: OptionsTreeNode) -> int:
        ...

    def getGroupPathName(self) -> str:
        ...

    def getOptionNames(self) -> java.util.List[java.lang.String]:
        ...

    def getOptions(self) -> ghidra.framework.options.Options:
        ...

    @property
    def groupPathName(self) -> java.lang.String:
        ...

    @property
    def options(self) -> ghidra.framework.options.Options:
        ...

    @property
    def optionNames(self) -> java.util.List[java.lang.String]:
        ...


class StringWithChoicesEditor(java.beans.PropertyEditorSupport):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, choices: jpype.JArray[java.lang.String]):
        ...

    @typing.overload
    def __init__(self, choices: java.util.List[java.lang.String]):
        ...

    def setChoices(self, choices: jpype.JArray[java.lang.String]):
        ...


class IntEditor(java.beans.PropertyEditorSupport):
    """
    An editor for Boolean properties.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class MainSwatchPanel(SwatchPanel):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OptionsRootTreeNode(OptionsTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, options: ghidra.framework.options.Options):
        ...


class ColorEditor(java.beans.PropertyEditorSupport):
    """
    Color editor that is a bit unusual in that its custom component is a button that when pushed,
    pops up a dialog for editing the color. Use :obj:`ColorPropertyEditor` for a more traditional
    property editor that returns a direct color editing component.
    """

    @typing.type_check_only
    class EditorProvider(docking.DialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ColorEditorPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BooleanEditor(java.beans.PropertyEditorSupport):
    """
    An editor for Boolean properties.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OptionsEditorPanel(javax.swing.JPanel):
    """
    Panel that shows each property in an Options category or a Group in an
    Options category.
    """

    @typing.type_check_only
    class EditorPropertyChangeListener(java.beans.PropertyChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], options: ghidra.framework.options.Options, optionNames: java.util.List[java.lang.String], editorStateFactory: ghidra.framework.options.EditorStateFactory):
        """
        Creates a panel for editing the given options.
        
        :param java.lang.String or str title: The title of the options panel
        :param ghidra.framework.options.Options options: The options to display
        :param java.util.List[java.lang.String] optionNames: The list of option names
        :param ghidra.framework.options.EditorStateFactory editorStateFactory: The EditorStateFactory
        """

    def apply(self):
        ...

    def dispose(self):
        ...

    def setOptionsPropertyChangeListener(self, listener: java.beans.PropertyChangeListener):
        ...


class GhidraColorChooser(javax.swing.JColorChooser):

    @typing.type_check_only
    class OKListener(java.awt.event.ActionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RecentColorCache(java.util.LinkedHashMap[java.awt.Color, java.awt.Color], java.lang.Iterable[java.awt.Color]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def addColor(self, color: java.awt.Color):
            ...

        def getMRUColorList(self) -> java.util.List[java.awt.Color]:
            ...

        @property
        def mRUColorList(self) -> java.util.List[java.awt.Color]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, initialColor: java.awt.Color):
        ...

    def addColorToHistory(self, c: java.awt.Color):
        ...

    def getActiveTab(self) -> str:
        ...

    def getColorHistory(self) -> java.util.List[java.awt.Color]:
        ...

    def getRecentColors(self) -> java.util.List[java.awt.Color]:
        ...

    def setActiveTab(self, tabName: typing.Union[java.lang.String, str]):
        """
        Sets the active tab of this chooser to be the given tab name, if it exists (the color chooser
        UI may be different, depending upon the current Look and Feel)
        
        :param java.lang.String or str tabName: the tab name
        """

    def setColorHistory(self, colors: java.util.List[java.awt.Color]):
        ...

    def setRecentColors(self, colors: java.util.List[java.awt.Color]):
        ...

    def setTitle(self, title: typing.Union[java.lang.String, str]):
        ...

    def showDialog(self, centerOverComponent: java.awt.Component) -> java.awt.Color:
        ...

    @property
    def colorHistory(self) -> java.util.List[java.awt.Color]:
        ...

    @colorHistory.setter
    def colorHistory(self, value: java.util.List[java.awt.Color]):
        ...

    @property
    def recentColors(self) -> java.util.List[java.awt.Color]:
        ...

    @recentColors.setter
    def recentColors(self, value: java.util.List[java.awt.Color]):
        ...

    @property
    def activeTab(self) -> java.lang.String:
        ...

    @activeTab.setter
    def activeTab(self, value: java.lang.String):
        ...


class CustomOptionComponent(GenericOptionsComponent):
    """
    A custom OptionComponent that controls it's own display using the editor component of the
    given EditorState.
    """

    class_: typing.ClassVar[java.lang.Class]


class DefaultOptionComponent(GenericOptionsComponent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, editorState: ghidra.framework.options.EditorState):
        ...

    def getLabelText(self) -> str:
        ...

    @property
    def labelText(self) -> java.lang.String:
        ...


class FileChooserEditor(java.beans.PropertyEditorSupport):
    """
    Bean editor to show a text field and a browse button to bring
    up a File Chooser dialog. This editor is created as a result of
    get/setFilename() on Options.
    """

    @typing.type_check_only
    class FileChooserPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TextListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, fileFilter: ghidra.util.filechooser.GhidraFileFilter):
        ...


class IconPropertyEditor(java.beans.PropertyEditorSupport):

    @typing.type_check_only
    class IconChooserPanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def setSelectedIcon(self, icon: javax.swing.Icon):
            ...


    @typing.type_check_only
    class IconDropDownDataModel(docking.widgets.DefaultDropDownSelectionDataModel[javax.swing.Icon]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class IconListCellRender(docking.widgets.list.GListCellRenderer[javax.swing.Icon]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OptionsDialog(docking.ReusableDialogComponentProvider):
    """
    Dialog for editing options within a tool.
    """

    @typing.type_check_only
    class OptionsPropertyChangeListener(java.beans.PropertyChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], rootNodeName: typing.Union[java.lang.String, str], options: jpype.JArray[ghidra.framework.options.Options], listener: OptionsEditorListener):
        """
        Construct a new OptionsDialog.
        
        :param java.lang.String or str title: dialog title
        :param java.lang.String or str rootNodeName: name to display for the root node in the tree
        :param jpype.JArray[ghidra.framework.options.Options] options: editable options
        :param OptionsEditorListener listener: listener notified when the apply button is hit.
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], rootNodeName: typing.Union[java.lang.String, str], options: jpype.JArray[ghidra.framework.options.Options], listener: OptionsEditorListener, showRestoreDefaultsButton: typing.Union[jpype.JBoolean, bool]):
        ...

    def displayCategory(self, category: typing.Union[java.lang.String, str], filterText: typing.Union[java.lang.String, str]):
        ...

    def getSelectedPath(self) -> javax.swing.tree.TreePath:
        ...

    def setSelectedPath(self, path: javax.swing.tree.TreePath):
        ...

    @property
    def selectedPath(self) -> javax.swing.tree.TreePath:
        ...

    @selectedPath.setter
    def selectedPath(self, value: javax.swing.tree.TreePath):
        ...


class FontPropertyEditor(java.beans.PropertyEditorSupport):
    """
    Property Editor for editing :obj:`Font`s
    """

    @typing.type_check_only
    class FontChooserPanel(javax.swing.JPanel):

        @typing.type_check_only
        class FontWrapper(java.lang.Comparable[FontPropertyEditor.FontChooserPanel.FontWrapper]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def updateControls(self, font: java.awt.Font):
            ...


    class_: typing.ClassVar[java.lang.Class]
    SAMPLE_STRING: typing.Final = "ABCabc \u00a9\u00ab\u00a7\u0429\u05d1\u062c\u4eb9"

    def __init__(self):
        ...


class GenericOptionsComponent(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def alignLabels(components: java.util.List[GenericOptionsComponent]):
        """
        Creates and sets a preferred alignment based upon the given list of option components.
        
        :param java.util.List[GenericOptionsComponent] components: the list of options components from which to determine the alignment.
        """

    @staticmethod
    def createOptionComponent(state: ghidra.framework.options.EditorState) -> GenericOptionsComponent:
        """
        A factory method to create new OptionComponents.
        
        :param ghidra.framework.options.EditorState state: The state that will be used to create the correct OptionComponent
        :return: the new OptionComponent.
        :rtype: GenericOptionsComponent
        """


class ColorPropertyEditor(java.beans.PropertyEditorSupport):
    """
    Property Editor for Colors. Uses a :obj:`GhidraColorChooser` as its custom component
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def saveState(self):
        ...


class OptionsEditorListener(java.lang.Object):
    """
    Listener that is notified when the "apply" button is hit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def beforeChangesApplied(self):
        """
        Notification that changes are about to be applied.
        """

    def changesApplied(self):
        """
        Notification that the apply button was hit.
        """


class DateEditor(java.beans.PropertyEditorSupport):
    """
    Non-editable Editor for date and time; creates a text field for the string version of the date.
    """

    @typing.type_check_only
    class DatePanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_DATE_FORMAT: typing.ClassVar[java.text.DateFormat]

    def __init__(self):
        ...

    def format(self, d: java.util.Date) -> str:
        ...

    def setDateFormat(self, format: java.text.DateFormat):
        ...


class StringEditor(java.beans.PropertyEditorSupport):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setAsText(self, text: typing.Union[java.lang.String, str]):
        """
        The comment in the parent "PropertyEditorSupport" reads:
         
             
            
            Sets the property value by parsing a given String. May raise
            java.lang.IllegalArgumentException if either the String is badly formatted or if this kind of
            property can't be expressed as text.
             
        
         
         
        
        which would be fine, except for the fact that Java initializes "value" to null, so every use
        of this method has to insure that setValue has been called at least once with a non-null
        value. If not, the method throws the IllegalArgumentException despite the fact that the input
        is not badly formatted and CAN be expressed as text.
        """


class FontEditor(java.beans.PropertyEditorSupport):
    """
    Font property editor that is a bit unusual in that its custom component is a button that when 
    pushed, pops up a dialog for editing the color. Use :obj:`FontPropertyEditor` for a more
    traditional property editor that returns a direct color editing component.
    """

    @typing.type_check_only
    class EditorDialogProvider(docking.DialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def showDialog(self):
        """
        Convenience method for directly showing a dialog for editing fonts
        """


class OptionsPanel(javax.swing.JPanel):

    class OptionsDataTransformer(docking.widgets.tree.internal.DefaultGTreeDataTransformer):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rootName: typing.Union[java.lang.String, str], options: jpype.JArray[ghidra.framework.options.Options], showRestoreDefaultsButton: typing.Union[jpype.JBoolean, bool], changeListener: java.beans.PropertyChangeListener):
        ...

    def apply(self) -> bool:
        ...

    def cancel(self):
        ...

    def displayCategory(self, category: typing.Union[java.lang.String, str], filterText: typing.Union[java.lang.String, str]):
        ...

    def dispose(self):
        ...



__all__ = ["SwatchPanel", "HistorySwatchPanel", "StringBasedFileEditor", "RecentSwatchPanel", "EditorInitializer", "SettableColorSwatchChooserPanel", "ScrollableOptionsEditor", "OptionsTreeNode", "StringWithChoicesEditor", "IntEditor", "MainSwatchPanel", "OptionsRootTreeNode", "ColorEditor", "BooleanEditor", "OptionsEditorPanel", "GhidraColorChooser", "CustomOptionComponent", "DefaultOptionComponent", "FileChooserEditor", "IconPropertyEditor", "OptionsDialog", "FontPropertyEditor", "GenericOptionsComponent", "ColorPropertyEditor", "OptionsEditorListener", "DateEditor", "StringEditor", "FontEditor", "OptionsPanel"]
