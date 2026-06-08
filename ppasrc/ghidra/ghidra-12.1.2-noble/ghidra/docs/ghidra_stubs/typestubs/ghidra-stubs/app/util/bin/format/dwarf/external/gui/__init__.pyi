from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.filechooser
import docking.widgets.table
import ghidra.app.util.bin.format.dwarf.external
import ghidra.util.table.column
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore


E = typing.TypeVar("E")


@typing.type_check_only
class FilePromptDialog(docking.DialogComponentProvider):
    """
    Non-public, package-only dialog that prompts the user to enter a path
    in a text field (similar to an :obj:`OptionDialog`) and allows them to click
    a "..." browse button to pick the file and/or directory via a
    :obj:`GhidraFileChooser` dialog.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def chooseDirectory(title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str], initialValue: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Prompts the user to enter the path to a directory,
        or to pick it using a browser dialog.
        
        :param java.lang.String or str title: the dialog title
        :param java.lang.String or str prompt: HTML enabled prompt
        :param jpype.protocol.SupportsPath initialValue: initial value to pre-populate the input field with
        :return: the :obj:`File` the user entered / picked, or null if canceled
        :rtype: java.io.File
        """

    @staticmethod
    def chooseFile(title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str], chooseButtonText: typing.Union[java.lang.String, str], directory: jpype.protocol.SupportsPath, initialFileValue: jpype.protocol.SupportsPath, chooserMode: docking.widgets.filechooser.GhidraFileChooserMode, *fileFilters: ghidra.util.filechooser.GhidraFileFilter) -> java.io.File:
        """
        Prompts the user to entry the path to a file and/or directory,
        or to pick it using a browser dialog.
        
        :param java.lang.String or str title: the dialog title
        :param java.lang.String or str prompt: HTML enabled prompt
        :param java.lang.String or str chooseButtonText: text of the choose button in the browser dialog
        :param jpype.protocol.SupportsPath directory: the initial directory of the browser dialog
        :param jpype.protocol.SupportsPath initialFileValue: the initial value to pre-populate the input field with
        :param docking.widgets.filechooser.GhidraFileChooserMode chooserMode: :obj:`GhidraFileChooserMode` of the browser dialog
        :param jpype.JArray[ghidra.util.filechooser.GhidraFileFilter] fileFilters: optional :obj:`filters <GhidraFileFilter>`
        :return: the :obj:`File` the user entered / picked, or null if canceled
        :rtype: java.io.File
        """


@typing.type_check_only
class ExternalDebugInfoProviderTableModel(docking.widgets.table.GDynamicColumnTableModel[ExternalDebugInfoProviderTableRow, java.util.List[ExternalDebugInfoProviderTableRow]]):
    """
    Table model for the :obj:`ExternalDebugFilesConfigDialog` table
    """

    @typing.type_check_only
    class EnabledColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ExternalDebugInfoProviderTableRow, java.lang.Boolean], TableColumnInitializer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StatusColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ExternalDebugInfoProviderTableRow, ghidra.app.util.bin.format.dwarf.external.DebugInfoProviderStatus], TableColumnInitializer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocationColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ExternalDebugInfoProviderTableRow, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class WellKnownDebugProvider(java.lang.Record):
    """
    Represents a debug file search location that has been pre-provided by a Ghidra config file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: typing.Union[java.lang.String, str], locationCategory: typing.Union[java.lang.String, str], warning: typing.Union[java.lang.String, str], fileOrigin: typing.Union[java.lang.String, str]) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def fileOrigin(self) -> str:
        ...

    def hashCode(self) -> int:
        ...

    @staticmethod
    def loadAll(fileExt: typing.Union[java.lang.String, str]) -> java.util.List[WellKnownDebugProvider]:
        """
        Loads information about wellknown debuginfod servers from any matching file found in the 
        application and returns a list of entries.
        
        :param java.lang.String or str fileExt: extension of the url files to find
        :return: list of :obj:`WellKnownDebugProvider` elements
        :rtype: java.util.List[WellKnownDebugProvider]
        """

    def location(self) -> str:
        ...

    def locationCategory(self) -> str:
        ...

    def toString(self) -> str:
        ...

    def warning(self) -> str:
        ...


class TableColumnInitializer(java.lang.Object):
    """
    Add on interface for DynamicTableColumn classes inside a SearchLocationTableModel that let 
    them control aspects of the matching TableColumn.
    """

    class_: typing.ClassVar[java.lang.Class]

    def initializeTableColumn(self, col: javax.swing.table.TableColumn, fm: java.awt.FontMetrics, padding: typing.Union[jpype.JInt, int]) -> None:
        """
        Called to allow the initializer to modify the specified TableColumn
        
        :param javax.swing.table.TableColumn col: :obj:`TableColumn`
        :param java.awt.FontMetrics fm: :obj:`FontMetrics` used by the table header gui component
        :param jpype.JInt or int padding: padding to use in the column
        """

    @staticmethod
    def initializeTableColumns(table: docking.widgets.table.GTable, model: docking.widgets.table.GDynamicColumnTableModel[typing.Any, typing.Any]) -> None:
        """
        Best called during :obj:`DialogComponentProvider.dialogShown` or 
        :obj:`ComponentProvider.componentShown`
        
        :param docking.widgets.table.GTable table: table component
        :param docking.widgets.table.GDynamicColumnTableModel[typing.Any, typing.Any] model: table model
        """


class ExternalDebugFilesConfigDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class ExternalDebugFileProvidersPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def pushAddLocationButton(self) -> None:
        """
        Screen shot usage only
        """

    def setService(self, edfs: ghidra.app.util.bin.format.dwarf.external.ExternalDebugFilesService) -> None:
        """
        Screen shot only
        
        :param ghidra.app.util.bin.format.dwarf.external.ExternalDebugFilesService edfs: :obj:`ExternalDebugFilesService`
        """

    def setWellknownProviders(self, list: java.util.List[WellKnownDebugProvider]) -> None:
        """
        Screen shot usage only
        
        :param java.util.List[WellKnownDebugProvider] list: fake well known debug provider servers
        """

    @staticmethod
    def show() -> bool:
        ...


@typing.type_check_only
class ExternalDebugInfoProviderTableRow(java.lang.Object):
    """
    Represents a row in a ExternalDebugInfoProviderTableModel
    """

    class_: typing.ClassVar[java.lang.Class]


class EnumIconColumnRenderer(ghidra.util.table.column.AbstractGColumnRenderer[E], typing.Generic[E]):
    """
    Table column renderer to render an enum value as a icon
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["FilePromptDialog", "ExternalDebugInfoProviderTableModel", "WellKnownDebugProvider", "TableColumnInitializer", "ExternalDebugFilesConfigDialog", "ExternalDebugInfoProviderTableRow", "EnumIconColumnRenderer"]
