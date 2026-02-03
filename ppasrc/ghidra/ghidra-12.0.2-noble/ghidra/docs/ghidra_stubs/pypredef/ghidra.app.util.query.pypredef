from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.nav
import ghidra.app.plugin.core.table
import ghidra.app.tablechooser
import ghidra.program.model.listing
import ghidra.util.table
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


ROW_TYPE = typing.TypeVar("ROW_TYPE")
T = typing.TypeVar("T")


class ProgramLocationPreviewTableModel(ghidra.util.table.AddressBasedTableModel[ghidra.program.util.ProgramLocation]):
    """
    Table model that shows a location, label, and a preview column to
    show a preview of the code unit.
    """

    class_: typing.ClassVar[java.lang.Class]


class AlignedObjectBasedPreviewTableModel(ghidra.util.table.AddressBasedTableModel[ROW_TYPE], typing.Generic[ROW_TYPE]):

    class_: typing.ClassVar[java.lang.Class]

    def addAlignmentListener(self, alignmentListener: AddressAlignmentListener):
        ...

    def getAlignment(self) -> int:
        ...

    def removeAlignmentListener(self, alignmentListener: AddressAlignmentListener):
        ...

    def setAlignment(self, alignment: typing.Union[jpype.JInt, int]):
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @alignment.setter
    def alignment(self, value: jpype.JInt):
        ...


class AddressAlignmentListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def alignmentChanged(self):
        ...

    def alignmentPermissionChanged(self):
        ...


class TableService(java.lang.Object):
    """
    Service to show a component that has a JTable given a table model
    that builds up its data dynamically (a ``ThreadedTableModel``).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def createTableChooserDialog(self, executor: ghidra.app.tablechooser.TableChooserExecutor, program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], navigatable: ghidra.app.nav.Navigatable) -> ghidra.app.tablechooser.TableChooserDialog:
        ...

    @typing.overload
    def createTableChooserDialog(self, executor: ghidra.app.tablechooser.TableChooserExecutor, program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], navigatable: ghidra.app.nav.Navigatable, isModal: typing.Union[jpype.JBoolean, bool]) -> ghidra.app.tablechooser.TableChooserDialog:
        ...

    def showTable(self, componentProviderTitle: typing.Union[java.lang.String, str], tableTypeName: typing.Union[java.lang.String, str], model: ghidra.util.table.GhidraProgramTableModel[T], windowSubMenu: typing.Union[java.lang.String, str], navigatable: ghidra.app.nav.Navigatable) -> ghidra.app.plugin.core.table.TableComponentProvider[T]:
        """
        Creates a table view using the given model. This version does not create markers.
        
        :param java.lang.String or str componentProviderTitle: The title of the view
        :param java.lang.String or str tableTypeName: The name of the table's type.  This is used to group like tables 
                together
        :param ghidra.util.table.GhidraProgramTableModel[T] model: the data model
        :param java.lang.String or str windowSubMenu: the name of a sub-menu to use in the "windows" menu.
        :param ghidra.app.nav.Navigatable navigatable: the component to navigate.  If null, the "connected" components will
                navigate.
        :return: a provider to show a visible component for the data
        :rtype: ghidra.app.plugin.core.table.TableComponentProvider[T]
        """

    def showTableWithMarkers(self, componentProviderTitle: typing.Union[java.lang.String, str], tableTypeName: typing.Union[java.lang.String, str], model: ghidra.util.table.GhidraProgramTableModel[T], markerColor: java.awt.Color, markerIcon: javax.swing.Icon, windowSubMenu: typing.Union[java.lang.String, str], navigatable: ghidra.app.nav.Navigatable) -> ghidra.app.plugin.core.table.TableComponentProvider[T]:
        """
        Creates a table view using the given model. This version creates markers.
        
        :param java.lang.String or str componentProviderTitle: The title of the view
        :param java.lang.String or str tableTypeName: The name of the table's type.  This is used to group like tables 
                together
        :param ghidra.util.table.GhidraProgramTableModel[T] model: the data model
        :param java.awt.Color markerColor: the color to use for the marker
        :param javax.swing.Icon markerIcon: the icon to associate with the marker set.
        :param java.lang.String or str windowSubMenu: the name of a sub-menu to use in the "windows" menu.
        :param ghidra.app.nav.Navigatable navigatable: the component to navigate.  If null, the "connected" components will
                navigate.
        :return: a provider to show a visible component for the data
        :rtype: ghidra.app.plugin.core.table.TableComponentProvider[T]
        """



__all__ = ["ProgramLocationPreviewTableModel", "AlignedObjectBasedPreviewTableModel", "AddressAlignmentListener", "TableService"]
