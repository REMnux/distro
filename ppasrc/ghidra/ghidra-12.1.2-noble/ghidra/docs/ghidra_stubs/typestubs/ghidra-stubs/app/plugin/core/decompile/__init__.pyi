from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.widgets.fieldpanel.support
import ghidra.app.context
import ghidra.app.decompiler
import ghidra.app.decompiler.component
import ghidra.app.nav
import ghidra.app.services
import ghidra.app.util
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.util
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class DecompilerLocationMemento(ghidra.app.nav.LocationMemento):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, viewerPosition: docking.widgets.fieldpanel.support.ViewerPosition) -> None:
        ...

    @typing.overload
    def __init__(self, saveState: ghidra.framework.options.SaveState, programs: jpype.JArray[ghidra.program.model.listing.Program]) -> None:
        ...

    def getViewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...

    @property
    def viewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...


class DecompilerClipboardProvider(ghidra.app.util.ByteCopier, ghidra.app.services.ClipboardContentProviderService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DecompilePlugin, provider: DecompilerProvider) -> None:
        ...

    def getCurrentPasteTypes(self, t: java.awt.datatransfer.Transferable) -> java.util.List[ghidra.app.util.ClipboardType]:
        ...

    def pasteSpecial(self, pasteData: java.awt.datatransfer.Transferable, pasteType: ghidra.app.util.ClipboardType) -> bool:
        ...

    def selectionChanged(self, sel: docking.widgets.fieldpanel.support.FieldSelection) -> None:
        ...

    def setFontMetrics(self, metrics: java.awt.FontMetrics) -> None:
        ...

    @property
    def currentPasteTypes(self) -> java.util.List[ghidra.app.util.ClipboardType]:
        ...


class DisplayTypeCastsAction(docking.action.ToggleDockingAction):
    """
    An action to update the Decompiler option for disabling the display of type casts.
    """

    @typing.type_check_only
    class DisplayTypeCastsOptionsListener(ghidra.framework.options.OptionsChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class DecompilePlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin for producing a high-level C interpretation of assembly functions.
    """

    class_: typing.ClassVar[java.lang.Class]
    OPTIONS_TITLE: typing.Final = "Decompiler"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...

    def getCurrentLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def currentLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class DecompilerProvider(ghidra.framework.plugintool.NavigatableComponentProviderAdapter, ghidra.framework.options.OptionsChangeListener, ghidra.app.decompiler.component.DecompilerCallbackHandler, ghidra.app.decompiler.DecompilerHighlightService, ghidra.app.decompiler.DecompilerMarginService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DecompilePlugin, isConnected: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def cloneWindow(self) -> None:
        ...

    def getController(self) -> ghidra.app.decompiler.component.DecompilerController:
        ...

    def programClosed(self, closedProgram: ghidra.program.model.listing.Program) -> None:
        ...

    def tokenRenamed(self, tokenAtCursor: ghidra.app.decompiler.ClangToken, newName: typing.Union[java.lang.String, str]) -> None:
        ...

    @property
    def controller(self) -> ghidra.app.decompiler.component.DecompilerController:
        ...


class PrimaryDecompilerProvider(DecompilerProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DecompilePlugin) -> None:
        ...


class DecompilerActionContext(ghidra.app.context.NavigatableActionContext, ghidra.app.context.RestrictedAddressSetContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: DecompilerProvider, functionEntryPoint: ghidra.program.model.address.Address, isDecompiling: typing.Union[jpype.JBoolean, bool], lineNumber: typing.Union[jpype.JInt, int]) -> None:
        """
        Construct a context specifying the line number
         
         
        
        The specified line number may not necessarily correspond to that of the current token. This
        is usually the case when the user clicks somewhere where a token is not present, e.g., the
        margin. In these cases, the line number should be that under the mouse cursor.
        
        :param DecompilerProvider provider: the decompiler provider producing the context
        :param ghidra.program.model.address.Address functionEntryPoint: the current function's entry, if applicable
        :param jpype.JBoolean or bool isDecompiling: true if the decompiler is still working
        :param jpype.JInt or int lineNumber: non-zero to specify the line number
        """

    @typing.overload
    def __init__(self, provider: DecompilerProvider, functionEntryPoint: ghidra.program.model.address.Address, isDecompiling: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Construct a context using the current token's line number
        
        :param DecompilerProvider provider: the decompiler provider producing the context
        :param ghidra.program.model.address.Address functionEntryPoint: the current function's entry, if applicable
        :param jpype.JBoolean or bool isDecompiling: true if the decompiler is still working
        """

    def getCCodeModel(self) -> ghidra.app.decompiler.ClangTokenGroup:
        ...

    def getDecompilerPanel(self) -> ghidra.app.decompiler.component.DecompilerPanel:
        ...

    def getFunction(self) -> ghidra.program.model.listing.Function:
        ...

    def getFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...

    def getLineNumber(self) -> int:
        """
        Get the line number
         
         
        
        This may not always correspond to the line number of the token at the cursor. For example, if
        there is no token under the mouse, or if the context is produced by the margin. When
        generated by a mouse event, this is the line number determined by the mouse's vertical
        position. Otherwise, this is the line number of the current token. If there is no current
        token and the line number was not given at construction, this returns 0 to indicate this
        context has no line number.
         
         
        
        If the current token's line number is desired, regardless of the user's mouse position, then
        use ``context.``:meth:`getTokenAtCursor() <.getTokenAtCursor>```.``:meth:`getLineParent() <ClangToken.getLineParent>```.``:meth:`getLineNumber() <ClangLine.getLineNumber>`.
        
        :return: the line number
        :rtype: int
        """

    def getTokenAtCursor(self) -> ghidra.app.decompiler.ClangToken:
        ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    def hasRealFunction(self) -> bool:
        ...

    def isDecompiling(self) -> bool:
        ...

    def setStatusMessage(self, msg: typing.Union[java.lang.String, str]) -> None:
        ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...

    @property
    def cCodeModel(self) -> ghidra.app.decompiler.ClangTokenGroup:
        ...

    @property
    def tokenAtCursor(self) -> ghidra.app.decompiler.ClangToken:
        ...

    @property
    def decompiling(self) -> jpype.JBoolean:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def decompilerPanel(self) -> ghidra.app.decompiler.component.DecompilerPanel:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def functionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...



__all__ = ["DecompilerLocationMemento", "DecompilerClipboardProvider", "DisplayTypeCastsAction", "DecompilePlugin", "DecompilerProvider", "PrimaryDecompilerProvider", "DecompilerActionContext"]
