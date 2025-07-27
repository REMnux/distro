from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.dnd
import ghidra.app.plugin
import ghidra.app.services
import ghidra.app.util
import ghidra.app.util.viewer.listingpanel
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.task
import java.awt.datatransfer # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class CodeBrowserClipboardProvider(ghidra.app.util.ByteCopier, ghidra.app.services.ClipboardContentProviderService, ghidra.framework.options.OptionsChangeListener):

    @typing.type_check_only
    class LabelStringTransferable(docking.dnd.StringTransferable):

        class_: typing.ClassVar[java.lang.Class]
        labelStringFlavor: typing.Final[java.awt.datatransfer.DataFlavor]


    @typing.type_check_only
    class NonLabelStringTransferable(docking.dnd.StringTransferable):

        class_: typing.ClassVar[java.lang.Class]
        nonLabelStringFlavor: typing.Final[java.awt.datatransfer.DataFlavor]


    class_: typing.ClassVar[java.lang.Class]
    ADDRESS_TEXT_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    ADDRESS_TEXT_WITH_OFFSET_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    BYTE_SOURCE_OFFSET_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    FUNCTION_OFFSET_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    IMAGEBASE_OFFSET_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    BLOCK_OFFSET_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    CODE_TEXT_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    LABELS_COMMENTS_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    LABELS_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    COMMENTS_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    GHIDRA_LOCAL_URL_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    GHIDRA_SHARED_URL_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    GHIDRA_DATA_TEXT_TYPE: typing.Final[ghidra.app.util.ClipboardType]
    GHIDRA_DEREFERENCED_DATA_TEXT_TYPE: typing.Final[ghidra.app.util.ClipboardType]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, codeViewerProvider: docking.ComponentProvider):
        ...

    def getStringContent(self) -> str:
        ...

    def setListingLayoutModel(self, model: ghidra.app.util.viewer.listingpanel.ListingModel):
        ...

    def setLocation(self, location: ghidra.program.util.ProgramLocation):
        ...

    def setProgram(self, p: ghidra.program.model.listing.Program):
        ...

    def setSelection(self, selection: ghidra.program.util.ProgramSelection):
        ...

    def setStringContent(self, text: typing.Union[java.lang.String, str]):
        ...

    @property
    def stringContent(self) -> java.lang.String:
        ...

    @stringContent.setter
    def stringContent(self, value: java.lang.String):
        ...


class CopyPasteSpecialDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ClipboardPlugin, availableTypes: java.util.List[typing.Any], title: typing.Union[java.lang.String, str]):
        ...

    def getSelectedType(self) -> ghidra.app.util.ClipboardType:
        ...

    @property
    def selectedType(self) -> ghidra.app.util.ClipboardType:
        ...


class ClipboardPlugin(ghidra.app.plugin.ProgramPlugin, java.awt.datatransfer.ClipboardOwner, ghidra.app.services.ClipboardService, ghidra.framework.options.OptionsChangeListener):

    @typing.type_check_only
    class ICopy(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IPaste(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CopyAction(docking.action.DockingAction, ClipboardPlugin.ICopy):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PasteAction(docking.action.DockingAction, ClipboardPlugin.IPaste):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CopySpecialAction(docking.action.DockingAction, ClipboardPlugin.ICopy):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CopySpecialAgainAction(docking.action.DockingAction, ClipboardPlugin.ICopy):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DummyTransferable(java.awt.datatransfer.Transferable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PasteTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, clipboard: java.awt.datatransfer.Clipboard, clipboardService: ghidra.app.services.ClipboardContentProviderService):
            ...


    class_: typing.ClassVar[java.lang.Class]
    GROUP_NAME: typing.Final = "Clipboard"
    TOOLBAR_GROUP_NAME: typing.Final = "ZClipboard"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["CodeBrowserClipboardProvider", "CopyPasteSpecialDialog", "ClipboardPlugin"]
