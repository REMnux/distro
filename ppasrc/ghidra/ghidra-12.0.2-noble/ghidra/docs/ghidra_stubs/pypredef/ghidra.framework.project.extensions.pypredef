from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import docking.widgets.table.threaded
import ghidra.framework.plugintool
import ghidra.framework.plugintool.dialog
import ghidra.util.extensions
import ghidra.util.filechooser
import ghidra.util.table.column
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


@typing.type_check_only
class ExtensionDetailsPanel(ghidra.framework.plugintool.dialog.AbstractDetailsPanel):
    """
    Panel that shows information about the selected extension in the :obj:`ExtensionTablePanel`. This
    is essentially a view into the :obj:`ExtensionDetails` for the extension.
     
    
    Note: The text is rendered as html to allow proper formatting (colors/font weight).
    """

    class_: typing.ClassVar[java.lang.Class]

    def setDescription(self, details: ghidra.util.extensions.ExtensionDetails):
        """
        Updates this panel with the given extension.
        
        :param ghidra.util.extensions.ExtensionDetails details: the extension to display
        """


class ExtensionInstaller(java.lang.Object):
    """
    Utility class for managing Ghidra Extensions.
     
    
    Extensions are defined as any archive or folder that contains an ``extension.properties``
    file. This properties file can contain the following attributes:
     
    * name (required)
    * description
    * author
    * createdOn (format: MM/dd/yyyy)
    * version
    
    
     
    
    Extensions may be installed/uninstalled by users at runtime, using the
    :obj:`ExtensionTableProvider`. Installation consists of unzipping the extension archive to an
    installation folder, currently ``{ghidra user settings dir}/Extensions``. To uninstall,
    the unpacked folder is simply removed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def install(file: jpype.protocol.SupportsPath) -> bool:
        """
        Installs the given extension file. This can be either an archive (zip) or a directory that
        contains an extension.properties file.
        
        :param jpype.protocol.SupportsPath file: the extension to install
        :return: true if the extension was successfully installed
        :rtype: bool
        """

    @staticmethod
    def installExtensionFromArchive(extension: ghidra.util.extensions.ExtensionDetails) -> bool:
        """
        Installs the given extension from its declared archive path
        
        :param ghidra.util.extensions.ExtensionDetails extension: the extension
        :return: true if successful
        :rtype: bool
        """


class ExtensionTablePanel(javax.swing.JPanel):
    """
    Container for the :obj:`GTable` that displays ghidra extensions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor; builds the panel and sets table attributes.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool showing the extension dialog
        """

    def dispose(self):
        ...

    def getFilterPanel(self) -> docking.widgets.table.GTableFilterPanel[ghidra.util.extensions.ExtensionDetails]:
        """
        Returns the filter panel.
        
        :return: the filter panel
        :rtype: docking.widgets.table.GTableFilterPanel[ghidra.util.extensions.ExtensionDetails]
        """

    def getSelectedItem(self) -> ghidra.util.extensions.ExtensionDetails:
        ...

    def getTable(self) -> docking.widgets.table.GTable:
        ...

    def getTableModel(self) -> ExtensionTableModel:
        ...

    def refreshTable(self):
        """
        Reloads the table with current extensions.
        """

    def setExtensions(self, extensions: java.util.Set[ghidra.util.extensions.ExtensionDetails]):
        """
        Replaces the contents of the table with the given list of extensions.
        
        :param java.util.Set[ghidra.util.extensions.ExtensionDetails] extensions: the new model data
        """

    @property
    def filterPanel(self) -> docking.widgets.table.GTableFilterPanel[ghidra.util.extensions.ExtensionDetails]:
        ...

    @property
    def selectedItem(self) -> ghidra.util.extensions.ExtensionDetails:
        ...

    @property
    def tableModel(self) -> ExtensionTableModel:
        ...

    @property
    def table(self) -> docking.widgets.table.GTable:
        ...


@typing.type_check_only
class ExtensionTableModel(docking.widgets.table.threaded.ThreadedTableModel[ghidra.util.extensions.ExtensionDetails, java.lang.Object]):
    """
    Model for the :obj:`ExtensionTablePanel`. This defines 5 columns for displaying information in
    :obj:`ExtensionDetails` objects:
     
            - Installed (checkbox)
            - Name
            - Description
            - Installation directory (hidden)
            - Archive directory (hidden)
     
     
    
    All columns are for display purposes only, except for the ``installed`` column, which
    is a checkbox allowing users to install/uninstall a particular extension.
    """

    @typing.type_check_only
    class ExtensionNameColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.util.extensions.ExtensionDetails, java.lang.String, java.lang.Object]):
        """
        Table column for displaying the extension name.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtensionDescriptionColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.util.extensions.ExtensionDetails, java.lang.String, java.lang.Object]):
        """
        Table column for displaying the extension description.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtensionVersionColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.util.extensions.ExtensionDetails, java.lang.String, java.lang.Object]):
        """
        Table column for displaying the extension description.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtensionInstalledColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.util.extensions.ExtensionDetails, java.lang.Boolean, java.lang.Object]):
        """
        Table column for displaying the extension installation status.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtensionInstallationDirColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.util.extensions.ExtensionDetails, java.lang.String, java.lang.Object]):
        """
        Table column for displaying the extension installation directory.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtensionArchiveFileColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.util.extensions.ExtensionDetails, java.lang.String, java.lang.Object]):
        """
        Table column for displaying the extension archive file.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def hasModelChanged(self) -> bool:
        """
        Returns true if the model has changed as a result of installing or uninstalling an extension
        
        :return: true if the model has changed as a result of installing or uninstalling an extension
        :rtype: bool
        """

    def refreshTable(self):
        """
        Gets a new set of extensions and reloads the table.
        """

    def setModelData(self, model: java.util.List[ghidra.util.extensions.ExtensionDetails]):
        """
        Replaces the table model data with the given list.
        
        :param java.util.List[ghidra.util.extensions.ExtensionDetails] model: the list to use as the model
        """

    def setValueAt(self, aValue: java.lang.Object, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]):
        """
        Overridden to handle the case where a user has toggled the installation column
        checkbox.
        """


class ExtensionTableProvider(docking.DialogComponentProvider):
    """
    Component Provider that shows the known extensions in Ghidra in a :obj:`GTable`. Users may
    install/uninstall extensions, or add new ones.
    """

    @typing.type_check_only
    class ExtensionFileFilter(ghidra.util.filechooser.GhidraFileFilter):
        """
        Filter for a :obj:`GhidraFileChooser` that restricts selection to those files that are
        Ghidra Extensions (zip files with an extension.properties file) or folders.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor.
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        """



__all__ = ["ExtensionDetailsPanel", "ExtensionInstaller", "ExtensionTablePanel", "ExtensionTableModel", "ExtensionTableProvider"]
