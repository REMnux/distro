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
import ghidra.app.tablechooser
import ghidra.app.util.query
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util.table
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util.function # type: ignore
import javax.swing.event # type: ignore
import utility.function


T = typing.TypeVar("T")


class TableComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter, javax.swing.event.TableModelListener, ghidra.app.nav.NavigatableRemovalListener, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def addActivationListener(self, listener: docking.ComponentProviderActivationListener):
        ...

    def getActionOwner(self) -> str:
        ...

    def getModel(self) -> ghidra.util.table.GhidraProgramTableModel[T]:
        ...

    def getTable(self) -> ghidra.util.table.GhidraTable:
        ...

    def getThreadedTablePanel(self) -> ghidra.util.table.GhidraThreadedTablePanel[T]:
        ...

    def installRemoveItemsAction(self):
        ...

    def refresh(self):
        ...

    def removeActivationListener(self, listener: docking.ComponentProviderActivationListener):
        ...

    def removeAllActions(self):
        ...

    def setActionContextProvider(self, contextProvider: java.util.function.Function[java.awt.event.MouseEvent, docking.ActionContext]):
        """
        Sets a function that provides context for this component provider.
        
        :param java.util.function.Function[java.awt.event.MouseEvent, docking.ActionContext] contextProvider: a function that provides context for this component provider.
        """

    def setClosedCallback(self, c: utility.function.Callback):
        """
        Sets a listener to know when this provider is closed.
        
        :param utility.function.Callback c: the callback
        """

    @property
    def actionOwner(self) -> java.lang.String:
        ...

    @property
    def model(self) -> ghidra.util.table.GhidraProgramTableModel[T]:
        ...

    @property
    def table(self) -> ghidra.util.table.GhidraTable:
        ...

    @property
    def threadedTablePanel(self) -> ghidra.util.table.GhidraThreadedTablePanel[T]:
        ...


class TableServicePlugin(ghidra.app.plugin.ProgramPlugin, ghidra.app.util.query.TableService, ghidra.framework.model.DomainObjectListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getManagedComponents(self) -> jpype.JArray[TableComponentProvider[typing.Any]]:
        ...

    @property
    def managedComponents(self) -> jpype.JArray[TableComponentProvider[typing.Any]]:
        ...


class TableServiceTableChooserDialog(ghidra.app.tablechooser.TableChooserDialog):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, plugin: TableServicePlugin, executor: ghidra.app.tablechooser.TableChooserExecutor, program: ghidra.program.model.listing.Program, title: typing.Union[java.lang.String, str], navigatable: ghidra.app.nav.Navigatable, isModal: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, plugin: TableServicePlugin, executor: ghidra.app.tablechooser.TableChooserExecutor, program: ghidra.program.model.listing.Program, title: typing.Union[java.lang.String, str], navigatable: ghidra.app.nav.Navigatable):
        ...



__all__ = ["TableComponentProvider", "TableServicePlugin", "TableServiceTableChooserDialog"]
