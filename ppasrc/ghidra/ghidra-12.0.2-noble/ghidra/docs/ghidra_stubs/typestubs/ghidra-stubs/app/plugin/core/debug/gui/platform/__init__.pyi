from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action.builder
import docking.widgets.table
import ghidra.app.plugin.core.debug.mapping
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.trace.model
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class DebuggerPlatformPlugin(ghidra.framework.plugintool.Plugin):

    @typing.type_check_only
    class ChoosePlatformAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Choose Platform"
        DESCRIPTION: typing.Final = "Choose a platform to use with the current trace"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "choose_platform"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class ChooseMorePlatformsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Choose More Platforms"
        TITLE: typing.Final = "More..."
        DESCRIPTION: typing.Final = "Choose from more platforms to use with the current trace"
        GROUP: typing.Final = "zzzz"
        HELP_ANCHOR: typing.Final = "choose_more_platforms"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class PlatformActionSet(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, trace: ghidra.trace.model.Trace):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerSelectPlatformOfferDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class OfferTableColumns(java.lang.Enum[DebuggerSelectPlatformOfferDialog.OfferTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerSelectPlatformOfferDialog.OfferTableColumns, ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer]):

        class_: typing.ClassVar[java.lang.Class]
        CONFIDENCE: typing.Final[DebuggerSelectPlatformOfferDialog.OfferTableColumns]
        PROCESSOR: typing.Final[DebuggerSelectPlatformOfferDialog.OfferTableColumns]
        VARIANT: typing.Final[DebuggerSelectPlatformOfferDialog.OfferTableColumns]
        SIZE: typing.Final[DebuggerSelectPlatformOfferDialog.OfferTableColumns]
        ENDIAN: typing.Final[DebuggerSelectPlatformOfferDialog.OfferTableColumns]
        COMPILER: typing.Final[DebuggerSelectPlatformOfferDialog.OfferTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerSelectPlatformOfferDialog.OfferTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerSelectPlatformOfferDialog.OfferTableColumns]:
            ...


    class OfferTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerSelectPlatformOfferDialog.OfferTableColumns, ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    class OfferPanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def getDisplayedOffers(self) -> java.util.List[ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer]:
            ...

        def getSelectedOffer(self) -> ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer:
            ...

        def setFilterRecommended(self, recommendedOnly: typing.Union[jpype.JBoolean, bool]):
            ...

        def setOffers(self, offers: collections.abc.Sequence):
            ...

        def setPreferredIDs(self, langID: ghidra.program.model.lang.LanguageID, csID: ghidra.program.model.lang.CompilerSpecID):
            ...

        def setSelectedOffer(self, offer: ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer):
            ...

        @property
        def displayedOffers(self) -> java.util.List[ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer]:
            ...

        @property
        def selectedOffer(self) -> ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer:
            ...

        @selectedOffer.setter
        def selectedOffer(self, value: ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getSelectedOffer(self) -> ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer:
        ...

    def isCancelled(self) -> bool:
        ...

    def setOffers(self, offers: collections.abc.Sequence):
        ...

    def setPreferredIDs(self, langID: ghidra.program.model.lang.LanguageID, csID: ghidra.program.model.lang.CompilerSpecID):
        """
        Set the preferred language and compiler spec IDs, typically from the current program.
        
         
        
        This must be called before :meth:`setOffers(Collection) <.setOffers>`.
        
        :param ghidra.program.model.lang.LanguageID langID: the preferred language
        :param ghidra.program.model.lang.CompilerSpecID csID: the preferred compiler spec (ABI)
        """

    def setSelectedOffer(self, offer: ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer):
        ...

    @property
    def selectedOffer(self) -> ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer:
        ...

    @selectedOffer.setter
    def selectedOffer(self, value: ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer):
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...



__all__ = ["DebuggerPlatformPlugin", "DebuggerSelectPlatformOfferDialog"]
