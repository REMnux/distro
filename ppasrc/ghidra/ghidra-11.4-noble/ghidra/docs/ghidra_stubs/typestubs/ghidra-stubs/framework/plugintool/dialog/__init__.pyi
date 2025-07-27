from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.list
import docking.widgets.table
import docking.widgets.table.threaded
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import java.beans # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


class AbstractDetailsPanel(javax.swing.JPanel):
    """
    Abstract class that defines a panel for displaying name/value pairs with html-formatting.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PluginDetailsPanel(AbstractDetailsPanel):
    """
    Panel that contains a JTextPane to show plugin description information.
    """

    class_: typing.ClassVar[java.lang.Class]


class ManagePluginsDialog(docking.ReusableDialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, addSaveActions: typing.Union[jpype.JBoolean, bool], isNewTool: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, pluginConfigurationModel: ghidra.framework.plugintool.PluginConfigurationModel, addSaveActions: typing.Union[jpype.JBoolean, bool], isNewTool: typing.Union[jpype.JBoolean, bool]):
        ...

    def getPluginConfigurationModel(self) -> ghidra.framework.plugintool.PluginConfigurationModel:
        ...

    def stateChanged(self):
        ...

    @property
    def pluginConfigurationModel(self) -> ghidra.framework.plugintool.PluginConfigurationModel:
        ...


@typing.type_check_only
class ToolIconUrlRenderer(docking.widgets.list.GListCellRenderer[docking.util.image.ToolIconURL]):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PluginInstallerTableModel(docking.widgets.table.threaded.ThreadedTableModel[ghidra.framework.plugintool.util.PluginDescription, java.util.List[ghidra.framework.plugintool.util.PluginDescription]]):
    """
    Table model for the :obj:`PluginInstallerDialog` dialog. This defines the table columns and
    their values.
    """

    @typing.type_check_only
    class PluginInstalledColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.plugintool.util.PluginDescription, java.lang.Boolean, java.util.List[ghidra.framework.plugintool.util.PluginDescription]]):
        """
        Column for displaying the interactive checkbox, allowing the user to install or uninstall the
        plugin.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PluginStatusColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.plugintool.util.PluginDescription, javax.swing.Icon, java.util.List[ghidra.framework.plugintool.util.PluginDescription]]):
        """
        Column for displaying the status of the plugin.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PluginNameColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.plugintool.util.PluginDescription, java.lang.String, java.util.List[ghidra.framework.plugintool.util.PluginDescription]]):
        """
        Column for displaying the extension name of the plugin.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PluginDescriptionColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.plugintool.util.PluginDescription, java.lang.String, java.util.List[ghidra.framework.plugintool.util.PluginDescription]]):
        """
        Column for displaying the plugin description.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PluginModuleColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.plugintool.util.PluginDescription, java.lang.String, java.util.List[ghidra.framework.plugintool.util.PluginDescription]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PluginLocationColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.plugintool.util.PluginDescription, java.lang.String, java.util.List[ghidra.framework.plugintool.util.PluginDescription]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PluginCategoryColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.framework.plugintool.util.PluginDescription, java.lang.String, java.util.List[ghidra.framework.plugintool.util.PluginDescription]]):
        """
        Column for displaying the plugin category.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    EXPERIMENTAL_ICON: typing.Final[javax.swing.Icon]
    DEV_ICON: typing.Final[javax.swing.Icon]
    DEPRECATED_ICON: typing.Final[javax.swing.Icon]

    def setValueAt(self, aValue: java.lang.Object, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]):
        """
        Overridden to handle the case where a user has toggled the installation column checkbox.
        """


class PluginInstallerDialog(docking.DialogComponentProvider):
    """
    Dialog that displays plugins in a tabular format, allowing users to install or uninstall them. The
    plugins that are displayed are defined by the caller.
    """

    @typing.type_check_only
    class StatusCellRenderer(docking.widgets.table.GTableCellRenderer):
        """
        Renderer for the status column in the table.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class NameCellRenderer(docking.widgets.table.GTableCellRenderer):
        """
        Renderer for the plugin name column.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool, model: ghidra.framework.plugintool.PluginConfigurationModel, pluginDescriptions: java.util.List[ghidra.framework.plugintool.util.PluginDescription]):
        """
        Constructs a new provider.
        
        :param java.lang.String or str title: the title of the provider
        :param ghidra.framework.plugintool.PluginTool tool: the current tool
        :param ghidra.framework.plugintool.PluginConfigurationModel model: the plugin configuration model
        :param java.util.List[ghidra.framework.plugintool.util.PluginDescription] pluginDescriptions: the list of plugins to display in the dialog
        """


@typing.type_check_only
class IconMap(java.lang.Object):
    """
    Class with static methods to access a hash map of icons.
    Loads the names in resources/images directory; the map is updated
    as icons are needed.
    """

    class_: typing.ClassVar[java.lang.Class]


class KeyBindingsPanel(javax.swing.JPanel):
    """
    Panel to show the key bindings for the plugin actions.
    """

    @typing.type_check_only
    class TableSelectionListener(javax.swing.event.ListSelectionListener):
        """
        Selection listener class for the table model.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyBindingsTableModel(docking.widgets.table.AbstractSortedTableModel[docking.action.DockingActionIf]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActionBindingListener(docking.DockingActionInputBindingListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def apply(self):
        ...

    def cancel(self):
        ...

    def dispose(self):
        ...

    def getStatusText(self) -> str:
        ...

    def reload(self):
        ...

    def setOptionsPropertyChangeListener(self, listener: java.beans.PropertyChangeListener):
        ...

    @property
    def statusText(self) -> java.lang.String:
        ...


class SaveToolConfigDialog(docking.DialogComponentProvider, javax.swing.event.ListSelectionListener):
    """
    Shows the modal dialog to save tool configuration to the current
    name or to a new name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, toolServices: ghidra.framework.model.ToolServices):
        ...

    def didCancel(self) -> bool:
        ...

    def show(self, name: typing.Union[java.lang.String, str], newDefaultName: typing.Union[java.lang.String, str]):
        """
        Display the "Save Tool Configuration As..." dialog;
        blocks until user hits the "Cancel" button.
        
        :param java.lang.String or str name: original name for the tool
        """

    def valueChanged(self, e: javax.swing.event.ListSelectionEvent):
        """
        Listener for the icon list.
        """


class PluginManagerComponent(javax.swing.JPanel, javax.swing.Scrollable):

    @typing.type_check_only
    class PluginPackageComponent(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyToggleButton(docking.EmptyBorderToggleButton):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, icon: javax.swing.Icon):
            ...


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["AbstractDetailsPanel", "PluginDetailsPanel", "ManagePluginsDialog", "ToolIconUrlRenderer", "PluginInstallerTableModel", "PluginInstallerDialog", "IconMap", "KeyBindingsPanel", "SaveToolConfigDialog", "PluginManagerComponent"]
