from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.actions
import docking.widgets
import docking.widgets.checkbox
import docking.widgets.fieldpanel.support
import ghidra.app.context
import ghidra.app.merge
import ghidra.app.services
import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.multilisting
import ghidra.framework.main
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class ListingMergePanel(javax.swing.JPanel, ghidra.app.merge.MergeConstants, java.awt.event.FocusListener, ghidra.app.services.CodeFormatService):

    @typing.type_check_only
    class MyGoToService(ghidra.app.services.GoToService):

        class_: typing.ClassVar[java.lang.Class]

        def goTo(self, offset: typing.Union[jpype.JLong, int]) -> bool:
            ...


    @typing.type_check_only
    class ShowHeaderButton(docking.widgets.EmptyBorderButton):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LockListener(java.awt.event.ActionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MergeColorBackgroundModel(docking.widgets.fieldpanel.support.BackgroundColorModel):

        class_: typing.ClassVar[java.lang.Class]

        def notifyListeners(self):
            ...

        def setAddressSet(self, addressSet: ghidra.program.model.address.AddressSetView):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, original: ghidra.program.model.listing.Program, result: ghidra.program.model.listing.Program, myChanges: ghidra.program.model.listing.Program, latest: ghidra.program.model.listing.Program, showListings: typing.Union[jpype.JBoolean, bool]):
        ...

    def addButtonPressedListener(self, listener: ghidra.app.services.ButtonPressedListener):
        """
        Adds a button press listener.
        
        :param ghidra.app.services.ButtonPressedListener listener: the listener to add.
        """

    def addDomainObjectListener(self):
        """
        Add the result program's listing model as a listener to the result program for domain object
        events.
        """

    def clearAllBackgrounds(self):
        """
        Color the background of all 4 listings to the default color for all addresses.
        """

    def dispose(self):
        ...

    def emptyViewForProgram(self, programIndex: typing.Union[jpype.JInt, int]):
        ...

    def getActionContext(self, event: java.awt.event.MouseEvent) -> java.lang.Object:
        ...

    def getFocusedListingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    def getFocusedProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getProgram(self, version: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Program:
        """
        Get the indicated program version.
        
        :param jpype.JInt or int version: LATEST, CHECKED_OUT, ORIGINAL, RESULT from MergeConstants
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    def getResultPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    def getVersionName(self, program: ghidra.program.model.listing.Program) -> str:
        ...

    @typing.overload
    def goTo(self, addr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def goTo(self, addr: ghidra.program.model.address.Address, programIndex: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def goTo(self, loc: ghidra.program.util.ProgramLocation, centerOnScreen: typing.Union[jpype.JBoolean, bool]):
        ...

    def paintAllBackgrounds(self, addrSet: ghidra.program.model.address.AddressSetView):
        """
        Color the background of all 4 listings to the indicated color for the indicated addresses.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the addresses
        """

    def removeDomainObjectListener(self):
        """
        Remove the result program's listing model as a listener to the result program for domain
        object events.
        """

    def setAddressTranslator(self, translator: ghidra.app.util.viewer.multilisting.AddressTranslator):
        ...

    def setBottomComponent(self, comp: javax.swing.JComponent):
        ...

    def setTopComponent(self, comp: javax.swing.JComponent):
        ...

    def setViewToProgram(self, programIndex: typing.Union[jpype.JInt, int]):
        ...

    @property
    def resultPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def versionName(self) -> java.lang.String:
        ...

    @property
    def focusedProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def focusedListingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    @property
    def actionContext(self) -> java.lang.Object:
        ...


@typing.type_check_only
class LockComponent(docking.widgets.checkbox.GCheckBox):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ListingMergePanelPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ProgramaticUseOnly):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, mergePanel: ListingMergePanel):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: merge tool
        :param ListingMergePanel mergePanel: merge panel
        """

    @staticmethod
    def getCategory() -> str:
        ...

    @staticmethod
    def getDescription() -> str:
        ...

    @staticmethod
    def getDescriptiveName() -> str:
        ...

    def getProvider(self) -> docking.ComponentProvider:
        ...

    @property
    def provider(self) -> docking.ComponentProvider:
        ...


class ViewInstructionDetailsAction(ghidra.app.context.ListingContextAction):

    @typing.type_check_only
    class Dialog(docking.DialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listingMergePanelPlugin: ListingMergePanelPlugin):
        ...


class ListingMergePanelProvider(ghidra.framework.plugintool.ComponentProviderAdapter, docking.actions.PopupActionProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, plugin: ghidra.framework.plugintool.Plugin, owner: typing.Union[java.lang.String, str], mergePanel: ListingMergePanel):
        ...



__all__ = ["ListingMergePanel", "LockComponent", "ListingMergePanelPlugin", "ViewInstructionDetailsAction", "ListingMergePanelProvider"]
