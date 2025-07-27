from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.util
import docking.widgets
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.listener
import docking.widgets.fieldpanel.support
import docking.widgets.table
import ghidra.app.decompiler
import ghidra.app.decompiler.component.hover
import ghidra.app.decompiler.component.margin
import ghidra.app.plugin.core.decompile
import ghidra.app.plugin.core.decompile.actions
import ghidra.app.plugin.core.hover
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.util
import ghidra.util.bean.field
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import utility.function


class TokenHighlights(java.lang.Iterable[HighlightToken]):
    """
    A simple class to manage :obj:`HighlightToken`s used to create highlights in the Decompiler.
    This class allows clients to access highlights either by a :obj:`ClangToken` or a
    :obj:`HighlightToken`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, t: HighlightToken):
        """
        Adds the given highlight to this container
        
        :param HighlightToken t: the highlight
        """

    def clear(self):
        """
        Removes all highlights from this container
        """

    def contains(self, t: ghidra.app.decompiler.ClangToken) -> bool:
        """
        Returns true if this class has a highlight for the given token
        
        :param ghidra.app.decompiler.ClangToken t: the token
        :return: true if this class has a highlight for the given token
        :rtype: bool
        """

    def copyHighlightsByName(self) -> java.util.Map[java.lang.String, java.awt.Color]:
        ...

    def get(self, t: ghidra.app.decompiler.ClangToken) -> HighlightToken:
        """
        Gets the current highlight for the given token
        
        :param ghidra.app.decompiler.ClangToken t: the token
        :return: the highlight
        :rtype: HighlightToken
        """

    def isEmpty(self) -> bool:
        """
        Returns true if there are not highlights
        
        :return: true if there are not highlights
        :rtype: bool
        """

    def remove(self, t: ghidra.app.decompiler.ClangToken):
        """
        Removes the highlight for the given token
        
        :param ghidra.app.decompiler.ClangToken t: the token
        """

    def size(self) -> int:
        """
        Returns the number of highlights
        
        :return: the number of highlights
        :rtype: int
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class DecompilerFindDialog(docking.widgets.FindDialog):

    @typing.type_check_only
    class DecompilerFindResultsModel(ghidra.util.table.GhidraProgramTableModel[ghidra.app.plugin.core.decompile.actions.DecompilerSearchLocation]):

        @typing.type_check_only
        class LineNumberColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ghidra.app.plugin.core.decompile.actions.DecompilerSearchLocation, java.lang.Integer]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class ContextColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ghidra.app.plugin.core.decompile.actions.DecompilerSearchLocation, ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext]):

            @typing.type_check_only
            class ContextCellRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext]):
                ...
                class_: typing.ClassVar[java.lang.Class]


            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, decompilerPanel: DecompilerPanel):
        ...


class DecompilerUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def findAddressBefore(lines: jpype.JArray[docking.widgets.fieldpanel.field.Field], token: ghidra.app.decompiler.ClangToken) -> ghidra.program.model.address.Address:
        ...

    @staticmethod
    def findClosestAddressSet(program: ghidra.program.model.listing.Program, functionSpace: ghidra.program.model.address.AddressSpace, tokenList: java.util.List[ghidra.app.decompiler.ClangToken]) -> ghidra.program.model.address.AddressSet:
        ...

    @staticmethod
    def findIndexOfFirstField(queryTokens: java.util.List[ghidra.app.decompiler.ClangToken], fields: jpype.JArray[docking.widgets.fieldpanel.field.Field]) -> int:
        """
        Find index of first field containing a ClangNode in tokenList
        
        :param java.util.List[ghidra.app.decompiler.ClangToken] queryTokens: the list of tokens of interest
        :param jpype.JArray[docking.widgets.fieldpanel.field.Field] fields: the universe of fields to check
        :return: index of field, or -1
        :rtype: int
        """

    @staticmethod
    def getBackwardSlice(seed: ghidra.program.model.pcode.Varnode) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        ...

    @staticmethod
    def getBackwardSliceToPCodeOps(seed: ghidra.program.model.pcode.Varnode) -> java.util.Set[ghidra.program.model.pcode.PcodeOp]:
        ...

    @staticmethod
    def getClosestAddress(program: ghidra.program.model.listing.Program, token: ghidra.app.decompiler.ClangToken) -> ghidra.program.model.address.Address:
        ...

    @staticmethod
    @typing.overload
    def getDataType(context: ghidra.app.plugin.core.decompile.DecompilerActionContext) -> ghidra.program.model.data.DataType:
        """
        Returns the data type for the given context if the context pertains to a data type
        
        :param ghidra.app.plugin.core.decompile.DecompilerActionContext context: the context
        :return: the data type or null
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    @typing.overload
    def getDataType(token: ghidra.app.decompiler.ClangToken) -> ghidra.program.model.data.DataType:
        """
        Returns the data type for the given  token
        
        :param ghidra.app.decompiler.ClangToken token: the token
        :return: the data type or null
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getDataTypeTraceBackward(vn: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.data.DataType:
        """
        Get the data-type associated with a Varnode.  If the Varnode is produce by a CAST p-code
        op, take the most specific data-type between what it was cast from and cast to.
        
        :param ghidra.program.model.pcode.Varnode vn: is the Varnode to get the data-type for
        :return: the data-type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getDataTypeTraceForward(vn: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.data.DataType:
        """
        Get the data-type associated with a Varnode.  If the Varnode is input to a CAST p-code
        op, take the most specific data-type between what it was cast from and cast to.
        
        :param ghidra.program.model.pcode.Varnode vn: is the Varnode to get the data-type for
        :return: the data-type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getDecompileOptions(serviceProvider: ghidra.framework.plugintool.ServiceProvider, program: ghidra.program.model.listing.Program) -> ghidra.app.decompiler.DecompileOptions:
        """
        Gather decompiler options from tool and program.  If tool is null or does not provide
        a :obj:`OptionsService` provider only options stored within the program will be consumed.
        
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: plugin tool or service provider providing access to 
        :obj:`OptionsService`
        :param ghidra.program.model.listing.Program program: program
        :return: decompiler options
        :rtype: ghidra.app.decompiler.DecompileOptions
        """

    @staticmethod
    def getFieldSelection(tokens: java.util.List[ghidra.app.decompiler.ClangToken]) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @staticmethod
    def getForwardSlice(seed: ghidra.program.model.pcode.Varnode) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        """
        Construct the set of varnodes making up a simple forward slice of seed
        
        :param ghidra.program.model.pcode.Varnode seed: Varnode where the slice starts
        :return: set of Varnodes in the slice
        :rtype: java.util.Set[ghidra.program.model.pcode.Varnode]
        """

    @staticmethod
    def getForwardSliceToPCodeOps(seed: ghidra.program.model.pcode.Varnode) -> java.util.Set[ghidra.program.model.pcode.PcodeOp]:
        ...

    @staticmethod
    def getFunction(program: ghidra.program.model.listing.Program, token: ghidra.app.decompiler.ClangFuncNameToken) -> ghidra.program.model.listing.Function:
        """
        Returns the function represented by the given token.  This will be either the
        decompiled function or a function referenced within the decompiled function.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.app.decompiler.ClangFuncNameToken token: the token
        :return: the function
        :rtype: ghidra.program.model.listing.Function
        """

    @staticmethod
    def getGoToTargetToken(root: ghidra.app.decompiler.ClangTokenGroup, label: ghidra.app.decompiler.ClangLabelToken) -> ghidra.app.decompiler.ClangLabelToken:
        ...

    @staticmethod
    def getMatchingBrace(startToken: ghidra.app.decompiler.ClangSyntaxToken) -> ghidra.app.decompiler.ClangSyntaxToken:
        """
        Find the matching brace, '{' or '}', for the given brace token, taking into account brace nesting.
        For an open brace, search forward to find the corresponding close brace.
        For a close brace, search backward to find the corresponding open brace.
        
        :param ghidra.app.decompiler.ClangSyntaxToken startToken: is the given brace token
        :return: the match brace token or null if there is no match
        :rtype: ghidra.app.decompiler.ClangSyntaxToken
        """

    @staticmethod
    def getNextBrace(startToken: ghidra.app.decompiler.ClangToken, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.app.decompiler.ClangSyntaxToken:
        """
        Starts at the given token and finds the next enclosing brace, depending on the given 
        direction.  If going forward, the next unpaired closing brace will be returned; if going
        backward, the next enclosing open brace will be found.   If no enclosing braces exist, 
        then null is returned.
        
        :param ghidra.app.decompiler.ClangToken startToken: the starting token
        :param jpype.JBoolean or bool forward: true for forward; false for backward
        :return: the next enclosing brace or null
        :rtype: ghidra.app.decompiler.ClangSyntaxToken
        """

    @staticmethod
    @typing.overload
    def getTokens(root: ghidra.app.decompiler.ClangNode, addressSet: ghidra.program.model.address.AddressSetView) -> java.util.List[ghidra.app.decompiler.ClangToken]:
        """
        Find all ClangNodes that have a minimum address in the AddressSetView
        
        :param ghidra.app.decompiler.ClangNode root: the root of the token tree
        :param ghidra.program.model.address.AddressSetView addressSet: the addresses to restrict
        :return: the list of tokens
        :rtype: java.util.List[ghidra.app.decompiler.ClangToken]
        """

    @staticmethod
    @typing.overload
    def getTokens(root: ghidra.app.decompiler.ClangNode, address: ghidra.program.model.address.Address) -> java.util.List[ghidra.app.decompiler.ClangToken]:
        ...

    @staticmethod
    def getTokensFromView(fields: jpype.JArray[docking.widgets.fieldpanel.field.Field], address: ghidra.program.model.address.Address) -> java.util.List[ghidra.app.decompiler.ClangToken]:
        """
        Similar to :meth:`getTokens(ClangNode, AddressSetView) <.getTokens>`, but uses the tokens from
        the given view fields.  Sometimes the tokens in the model (represented by the
        :obj:`ClangNode`) are different than the fields in the view (such as when a list of
        comment tokens are condensed into a single comment token).
        
        :param jpype.JArray[docking.widgets.fieldpanel.field.Field] fields: the fields to check
        :param ghidra.program.model.address.Address address: the address each returned token must match
        :return: the matching tokens
        :rtype: java.util.List[ghidra.app.decompiler.ClangToken]
        """

    @staticmethod
    def getTokensInSelection(selection: docking.widgets.fieldpanel.support.FieldSelection, lines: jpype.JArray[docking.widgets.fieldpanel.field.Field]) -> java.util.List[ghidra.app.decompiler.ClangToken]:
        ...

    @staticmethod
    def getVarnodeRef(token: ghidra.app.decompiler.ClangToken) -> ghidra.program.model.pcode.Varnode:
        """
        If the token refers to an individual Varnode, return it. Otherwise return null
        
        :param ghidra.app.decompiler.ClangToken token: the token to check
        :return: the Varnode or null otherwise
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @staticmethod
    def isBrace(token: ghidra.app.decompiler.ClangToken) -> bool:
        ...

    @staticmethod
    def isGoToStatement(token: ghidra.app.decompiler.ClangToken) -> bool:
        ...

    @staticmethod
    def isThisParameter(var: ghidra.program.model.pcode.HighVariable, function: ghidra.program.model.listing.Function) -> bool:
        """
        Test specified variable to see if it corresponds to the auto ``this`` parameter
        of the specified :obj:`Function`
        
        :param ghidra.program.model.pcode.HighVariable var: decompiler :obj:`variable <HighVariable>`
        :param ghidra.program.model.listing.Function function: decompiled function
        :return: true if ``var`` corresponds to existing auto ``this`` parameter, else false
        :rtype: bool
        """

    @staticmethod
    def toLines(group: ghidra.app.decompiler.ClangTokenGroup) -> java.util.List[ghidra.app.decompiler.ClangLine]:
        """
        A token hierarchy is flattened and then split into individual lines at the
        ClangBreak tokens.  An array of the lines, each as a ClangLine object that owns
        its respective tokens, is returned.  Sequences of comment tokens are collapsed into
        a single ClangCommentToken.
        
        :param ghidra.app.decompiler.ClangTokenGroup group: is the token hierarchy
        :return: the array of ClangLine objects
        :rtype: java.util.List[ghidra.app.decompiler.ClangLine]
        """


class ColorProvider(java.lang.Object):
    """
    Functional interface to allow us to map a token to a color.
     
     
    This class allows us to avoid the namespace conflicts of Java's Function and Ghidra's
    Function since we can declare a ``ColorProvider`` as a parameter to methods instead of
    a :obj:`Function`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getColor(self, token: ghidra.app.decompiler.ClangToken) -> java.awt.Color:
        """
        Returns a color for the given token
        
        :param ghidra.app.decompiler.ClangToken token: the token
        :return: the color
        :rtype: java.awt.Color
        """

    @property
    def color(self) -> java.awt.Color:
        ...


class DecompileResultsListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def setDecompileData(self, decompileData: DecompileData):
        ...


class DecompilerController(java.lang.Object):
    """
    Coordinates the interactions between the DecompilerProvider, DecompilerPanel, and the
    DecompilerManager
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, handler: DecompilerCallbackHandler, options: ghidra.app.decompiler.DecompileOptions, clipboard: ghidra.app.plugin.core.decompile.DecompilerClipboardProvider):
        ...

    def clear(self):
        """
        clears all internal state and releases all resources. Called when the provider is no longer
        visible or the currently displayed program is closed.
        """

    def clearCache(self):
        ...

    def display(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, viewerPosition: docking.widgets.fieldpanel.support.ViewerPosition):
        """
        Shows the function containing the given location in the decompilerPanel. Also, positions the
        decompilerPanel's cursor to the closest equivalent position. If the decompilerPanel is
        already displaying the function, then only the cursor is repositioned. To force a
        re-decompile use :meth:`refreshDisplay(Program, ProgramLocation, File) <.refreshDisplay>`.
        
        :param ghidra.program.model.listing.Program program: the program for the given location
        :param ghidra.program.util.ProgramLocation location: the location containing the function to be displayed and the location in that
                    function to position the cursor.
        :param docking.widgets.fieldpanel.support.ViewerPosition viewerPosition: the viewer position
        """

    def dispose(self):
        """
        Called by the provider when the provider is disposed. Once dispose is called, it should never
        be used again.
        """

    def doWhenNotBusy(self, c: utility.function.Callback):
        ...

    def exportLocation(self):
        ...

    def getCCodeModel(self) -> ghidra.app.decompiler.ClangTokenGroup:
        ...

    def getDecompileData(self) -> DecompileData:
        ...

    def getDecompilerPanel(self) -> DecompilerPanel:
        ...

    def getFunction(self) -> ghidra.program.model.listing.Function:
        ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getServiceProvider(self) -> ghidra.framework.plugintool.ServiceProvider:
        ...

    def hasDecompileResults(self) -> bool:
        ...

    def isDecompiling(self) -> bool:
        ...

    def programClosed(self, closedProgram: ghidra.program.model.listing.Program):
        ...

    def refreshDisplay(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, debugFile: jpype.protocol.SupportsPath):
        """
        Always decompiles the function containing the given location before positioning the
        decompilerPanel's cursor to the closest equivalent position.
        
        :param ghidra.program.model.listing.Program program: the program for the given location
        :param ghidra.program.util.ProgramLocation location: the location containing the function to be displayed and the location in that
                    function to position the cursor.
        :param jpype.protocol.SupportsPath debugFile: the debug file
        """

    def resetDecompiler(self):
        """
        Resets the native decompiler process. Call this method when the decompiler's view of a
        program has been invalidated, such as when a new overlay space has been added.
        """

    def setDecompileData(self, decompileData: DecompileData):
        """
        Called by the DecompilerManager to update the currently displayed DecompileData
        
        :param DecompileData decompileData: the new data
        """

    def setMouseNavigationEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setOptions(self, decompilerOptions: ghidra.app.decompiler.DecompileOptions):
        """
        Sets new decompiler options and triggers a new decompile.
        
        :param ghidra.app.decompiler.DecompileOptions decompilerOptions: the options
        """

    def setSelection(self, selection: ghidra.program.util.ProgramSelection):
        ...

    def setStatusMessage(self, message: typing.Union[java.lang.String, str]):
        ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...

    @property
    def decompileData(self) -> DecompileData:
        ...

    @decompileData.setter
    def decompileData(self, value: DecompileData):
        ...

    @property
    def cCodeModel(self) -> ghidra.app.decompiler.ClangTokenGroup:
        ...

    @property
    def decompiling(self) -> jpype.JBoolean:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def serviceProvider(self) -> ghidra.framework.plugintool.ServiceProvider:
        ...

    @property
    def decompilerPanel(self) -> DecompilerPanel:
        ...

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class DecompilerCallbackHandler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def annotationClicked(self, annotation: ghidra.util.bean.field.AnnotatedTextFieldElement, newWindow: typing.Union[jpype.JBoolean, bool]):
        ...

    def contextChanged(self):
        ...

    def decompileDataChanged(self, decompileData: DecompileData):
        ...

    def doWhenNotBusy(self, c: utility.function.Callback):
        ...

    def exportLocation(self):
        ...

    def goToAddress(self, addr: ghidra.program.model.address.Address, newWindow: typing.Union[jpype.JBoolean, bool]):
        ...

    def goToFunction(self, function: ghidra.program.model.listing.Function, newWindow: typing.Union[jpype.JBoolean, bool]):
        ...

    def goToLabel(self, labelName: typing.Union[java.lang.String, str], newWindow: typing.Union[jpype.JBoolean, bool]):
        ...

    def goToScalar(self, value: typing.Union[jpype.JLong, int], newWindow: typing.Union[jpype.JBoolean, bool]):
        ...

    def locationChanged(self, programLocation: ghidra.program.util.ProgramLocation):
        ...

    def selectionChanged(self, programSelection: ghidra.program.util.ProgramSelection):
        ...

    def setStatusMessage(self, message: typing.Union[java.lang.String, str]):
        ...


class DecompilerHoverProvider(ghidra.app.plugin.core.hover.AbstractHoverProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addHoverService(self, hoverService: ghidra.app.decompiler.component.hover.DecompilerHoverService):
        ...

    def removeHoverService(self, hoverService: ghidra.app.decompiler.component.hover.DecompilerHoverService):
        ...


class ClangHighlightController(java.lang.Object):
    """
    Class to handle highlights for a decompiled function.
     
     
    This class does not paint directly.  Rather, this class tracks the currently highlighted
    tokens and then sets the highlight color on the token when it is highlighted and clears the
    highlight color when the highlight is removed.
     
     
    This class maintains the following types of highlights:
     
    * Context Highlights - triggered by user clicking and some user actions; considered transient
        and get cleared whenever the location changes.  These highlights show state such as the
        current field, impact of a variable (via a slicing action), or related syntax (such as
        matching braces)
    
    * Secondary Highlights - triggered by the user to show all occurrences of a particular
    variable; they will stay until they are manually cleared by a user action.  The user can
    apply multiple secondary highlights at the same time, with different colors for each
    highlight.
    These highlights apply to the function in use when the highlight is created.  Thus,
        each function has a unique set of highlights that is maintained between decompilation.
    * Service Highlights - triggered by clients of the :obj:`DecompilerHighlightService`; they
        will be stored in this class until the client of the service clears the highlight.  These
        can be global (applied to all functions) or specific to a given function.  Each user
        highlight will be called to generate highlights when a function is first decompiled.
    
    
     
     
    When multiple highlights overlap, their colors will be blended.
    """

    @typing.type_check_only
    class GeneratedColorProvider(ColorProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_HIGHLIGHT_COLOR: typing.ClassVar[java.awt.Color]

    def __init__(self):
        ...

    def addHighlighter(self, highlighter: ClangDecompilerHighlighter):
        ...

    def addHighlighterHighlights(self, highlighter: ghidra.app.decompiler.DecompilerHighlighter, tokens: java.util.function.Supplier[java.util.Collection[ghidra.app.decompiler.ClangToken]], colorProvider: ColorProvider):
        ...

    def addListener(self, listener: ClangHighlightListener):
        ...

    @typing.overload
    def addPrimaryHighlights(self, parentNode: ghidra.app.decompiler.ClangNode, ops: java.util.Set[ghidra.program.model.pcode.PcodeOp], hlColor: java.awt.Color):
        ...

    @typing.overload
    def addPrimaryHighlights(self, parentNode: ghidra.app.decompiler.ClangNode, colorProvider: ColorProvider):
        ...

    def addSecondaryHighlighter(self, function: ghidra.program.model.listing.Function, highlighter: ghidra.app.decompiler.DecompilerHighlighter):
        """
        Adds the given secondary highlighter, but does not create any highlights.  All secondary
        highlighters pertain to a given function.
        
        :param ghidra.program.model.listing.Function function: the function
        :param ghidra.app.decompiler.DecompilerHighlighter highlighter: the highlighter
        """

    def blend(self, colors: java.util.Set[java.awt.Color]) -> java.awt.Color:
        ...

    def clearPrimaryHighlights(self):
        ...

    def dispose(self):
        ...

    @staticmethod
    def dummyIfNull(c: ClangHighlightController) -> ClangHighlightController:
        ...

    def fieldLocationChanged(self, location: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field, trigger: docking.widgets.EventTrigger):
        ...

    def getCombinedColor(self, t: ghidra.app.decompiler.ClangToken) -> java.awt.Color:
        """
        Returns the current highlight color for the given token, based upon all known highlights,
        primary, secondary and highlighters
        
        :param ghidra.app.decompiler.ClangToken t: the token
        :return: the color
        :rtype: java.awt.Color
        """

    def getGeneratedColorProvider(self) -> ColorProvider:
        """
        Returns the color provider used by this class to generate colors.  The initial color
        selection is random.  Repeated calls to get a color for the same token will return the same
        color.
        
        :return: the color provider
        :rtype: ColorProvider
        """

    def getHighlightedToken(self) -> ghidra.app.decompiler.ClangToken:
        """
        Return the current highlighted token (if exists and unique)
        
        :return: token or null
        :rtype: ghidra.app.decompiler.ClangToken
        """

    def getHighlighterHighlights(self, highlighter: ghidra.app.decompiler.DecompilerHighlighter) -> TokenHighlights:
        """
        Gets all highlights for the given highlighter.
        
        :param ghidra.app.decompiler.DecompilerHighlighter highlighter: the highlighter
        :return: the highlights
        :rtype: TokenHighlights
        
        .. seealso::
        
            | :obj:`.getPrimaryHighlights()`
        """

    def getPrimaryHighlights(self) -> TokenHighlights:
        ...

    def getSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken) -> java.awt.Color:
        ...

    def getSecondaryHighlightColors(self) -> TokenHighlightColors:
        ...

    def getSecondaryHighlighters(self, function: ghidra.program.model.listing.Function) -> java.util.Set[ghidra.app.decompiler.DecompilerHighlighter]:
        """
        Returns all secondary highlighters for the given function.   This allows clients to update
        the secondary highlight state of a given function without affecting highlights applied to
        other functions.
        
        :param ghidra.program.model.listing.Function function: the function
        :return: the highlighters
        :rtype: java.util.Set[ghidra.app.decompiler.DecompilerHighlighter]
        """

    def getServiceHighlighters(self) -> java.util.Set[ghidra.app.decompiler.DecompilerHighlighter]:
        """
        Returns all highlight service highlighters installed in this controller.  The global
        highlighters apply to all functions.  This is in contrast to secondary highlighters, which 
        are function-specific.
        
        :return: the highlighters
        :rtype: java.util.Set[ghidra.app.decompiler.DecompilerHighlighter]
        """

    def getUpdateId(self) -> int:
        """
        An value that is updated every time a new highlight is added.  This allows clients to
        determine if a buffered update request is still valid.
        
        :return: the value
        :rtype: int
        """

    def hasContextHighlight(self, token: ghidra.app.decompiler.ClangToken) -> bool:
        ...

    def hasSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken) -> bool:
        ...

    def hasSecondaryHighlights(self, function: ghidra.program.model.listing.Function) -> bool:
        ...

    def reapplyAllHighlights(self, function: ghidra.program.model.listing.Function):
        ...

    def removeHighlighter(self, highlighter: ghidra.app.decompiler.DecompilerHighlighter):
        ...

    def removeHighlighterHighlights(self, highlighter: ghidra.app.decompiler.DecompilerHighlighter):
        """
        Removes all highlights for this highlighter across all functions
        
        :param ghidra.app.decompiler.DecompilerHighlighter highlighter: the highlighter
        """

    def removeListener(self, listener: ClangHighlightListener):
        ...

    @typing.overload
    def removeSecondaryHighlights(self, f: ghidra.program.model.listing.Function):
        """
        Removes all secondary highlights for the given function
        
        :param ghidra.program.model.listing.Function f: the function
        """

    @typing.overload
    def removeSecondaryHighlights(self, token: ghidra.app.decompiler.ClangToken):
        """
        Removes all secondary highlights for the given token
        
        :param ghidra.app.decompiler.ClangToken token: the token
        
        .. seealso::
        
            | :obj:`.removeSecondaryHighlights(Function)`
        """

    def togglePrimaryHighlights(self, hlColor: java.awt.Color, tokens: java.util.function.Supplier[java.util.List[ghidra.app.decompiler.ClangToken]]):
        """
        Toggles the primary highlight state of the given set of tokens.  If the given tokens do not
        all have the same highlight state (highlights on or off), then the highlights will be
        cleared.  If all tokens are not highlighted, then they will all become highlighted.
        
        :param java.awt.Color hlColor: the highlight color
        :param java.util.function.Supplier[java.util.List[ghidra.app.decompiler.ClangToken]] tokens: the tokens
        """

    @property
    def highlightedToken(self) -> ghidra.app.decompiler.ClangToken:
        ...

    @property
    def updateId(self) -> jpype.JLong:
        ...

    @property
    def generatedColorProvider(self) -> ColorProvider:
        ...

    @property
    def secondaryHighlightColors(self) -> TokenHighlightColors:
        ...

    @property
    def secondaryHighlighters(self) -> java.util.Set[ghidra.app.decompiler.DecompilerHighlighter]:
        ...

    @property
    def secondaryHighlight(self) -> java.awt.Color:
        ...

    @property
    def serviceHighlighters(self) -> java.util.Set[ghidra.app.decompiler.DecompilerHighlighter]:
        ...

    @property
    def primaryHighlights(self) -> TokenHighlights:
        ...

    @property
    def combinedColor(self) -> java.awt.Color:
        ...

    @property
    def highlighterHighlights(self) -> TokenHighlights:
        ...


class ClangHighlightListener(java.lang.Object):
    """
    Interface for a decompiler highlight change listener.
    """

    class_: typing.ClassVar[java.lang.Class]

    def tokenHighlightsChanged(self):
        """
        Method to invoke whenever the decompiler token highlights have changed.
        """


class NullClangHighlightController(ClangHighlightController):
    """
    A stub implementation of the highlight controller that allows clients to avoid null checks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LocationClangHighlightController(ClangHighlightController):
    """
    Class to handle location based highlights for a decompiled function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DecompilerPanel(javax.swing.JPanel, docking.widgets.fieldpanel.listener.FieldMouseListener, docking.widgets.fieldpanel.listener.FieldLocationListener, docking.widgets.fieldpanel.listener.FieldSelectionListener, ClangHighlightListener, docking.widgets.fieldpanel.listener.LayoutListener):
    """
    Class to handle the display of a decompiled function
    """

    @typing.type_check_only
    class SearchHighlightFactory(docking.widgets.fieldpanel.support.FieldHighlightFactory):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScrollingCallback(docking.util.SwingAnimationCallback):
        """
        A simple class that handles the animators callback to scroll the display
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DecompilerFieldPanel(docking.widgets.fieldpanel.FieldPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: docking.widgets.fieldpanel.LayoutModel):
            ...


    @typing.type_check_only
    class PendingHighlightUpdate(java.lang.Object):
        """
        A class to track pending location updates. This allows us to buffer updates, only sending the
        last one received.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MiddleMouseColorProvider(ColorProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActiveMiddleMouse(java.lang.Object):
        """
        A class to track the current middle moused token.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addHighlights(self, varnodes: java.util.Set[ghidra.program.model.pcode.Varnode], colorProvider: ColorProvider):
        ...

    @typing.overload
    def addHighlights(self, ops: java.util.Set[ghidra.program.model.pcode.PcodeOp], hlColor: java.awt.Color):
        ...

    def addHoverService(self, hoverService: ghidra.app.decompiler.component.hover.DecompilerHoverService):
        ...

    def addMarginProvider(self, provider: ghidra.app.decompiler.component.margin.DecompilerMarginProvider):
        ...

    @typing.overload
    def addSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken):
        ...

    @typing.overload
    def addSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken, color: java.awt.Color):
        ...

    def clearPrimaryHighlights(self):
        ...

    def cloneHighlights(self, sourcePanel: DecompilerPanel):
        """
        Called by the provider to clone all highlights in the source panel and apply them to this
        panel
        
        :param DecompilerPanel sourcePanel: the panel that was cloned
        """

    def containsLocation(self, location: ghidra.program.util.ProgramLocation) -> bool:
        ...

    @typing.overload
    def createHighlighter(self, f: ghidra.program.model.listing.Function, tm: ghidra.app.decompiler.CTokenHighlightMatcher) -> ghidra.app.decompiler.DecompilerHighlighter:
        ...

    @typing.overload
    def createHighlighter(self, id: typing.Union[java.lang.String, str], f: ghidra.program.model.listing.Function, tm: ghidra.app.decompiler.CTokenHighlightMatcher) -> ghidra.app.decompiler.DecompilerHighlighter:
        ...

    def dispose(self):
        ...

    def findTokensByName(self, name: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.app.decompiler.ClangToken]:
        ...

    def getController(self) -> DecompilerController:
        ...

    def getCurrentLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getCurrentVariableHighlightColor(self) -> java.awt.Color:
        ...

    def getCursorPosition(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    def getFieldPanel(self) -> docking.widgets.fieldpanel.FieldPanel:
        ...

    def getFields(self) -> java.util.List[docking.widgets.fieldpanel.field.Field]:
        ...

    def getFontMetrics(self) -> java.awt.FontMetrics:
        ...

    def getHighlightController(self) -> ClangHighlightController:
        ...

    def getHighlightedText(self) -> str:
        ...

    def getHighlighter(self, id: typing.Union[java.lang.String, str]) -> ghidra.app.decompiler.DecompilerHighlighter:
        ...

    def getHighlights(self, highligter: ghidra.app.decompiler.DecompilerHighlighter) -> TokenHighlights:
        ...

    def getLayoutController(self) -> ClangLayoutController:
        ...

    def getLineNumber(self, y: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the line number for the given y position, relative to the scroll panel
        
         
        
        If the y position is below all the lines, the last line is returned.
        
        :param jpype.JInt or int y: the y position
        :return: the line number, or 0 if not applicable
        :rtype: int
        """

    def getLines(self) -> java.util.List[ghidra.app.decompiler.ClangLine]:
        ...

    def getMiddleMouseHighlightColor(self) -> java.awt.Color:
        ...

    def getMiddleMouseHighlights(self) -> TokenHighlights:
        ...

    def getOptions(self) -> ghidra.app.decompiler.DecompileOptions:
        ...

    def getSearchResults(self) -> ghidra.app.plugin.core.decompile.actions.DecompilerSearchLocation:
        ...

    def getSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken) -> java.awt.Color:
        ...

    def getSecondaryHighlightColors(self) -> TokenHighlightColors:
        ...

    def getSelectedText(self) -> str:
        ...

    def getSelectedToken(self) -> ghidra.app.decompiler.ClangToken:
        """
        Returns a single selected token; null if there is no selection or multiple tokens selected.
        
        :return: a single selected token; null if there is no selection or multiple tokens selected.
        :rtype: ghidra.app.decompiler.ClangToken
        """

    def getSpecialHighlightColor(self) -> java.awt.Color:
        """
        The color used in a primary highlight to mark the token that was clicked. This is used in
        'slice' actions to mark the source of the slice.
        
        :return: the color
        :rtype: java.awt.Color
        """

    def getTextUnderCursor(self) -> str:
        ...

    def getTokenAtCursor(self) -> ghidra.app.decompiler.ClangToken:
        ...

    def getViewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...

    def goToToken(self, token: ghidra.app.decompiler.ClangToken):
        ...

    def hasSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken) -> bool:
        ...

    def hasSecondaryHighlights(self, function: ghidra.program.model.listing.Function) -> bool:
        ...

    def isHoverShowing(self) -> bool:
        ...

    def optionsChanged(self, decompilerOptions: ghidra.app.decompiler.DecompileOptions):
        ...

    def removeHoverService(self, hoverService: ghidra.app.decompiler.component.hover.DecompilerHoverService):
        ...

    def removeMarginProvider(self, provider: ghidra.app.decompiler.component.margin.DecompilerMarginProvider):
        ...

    def removeSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken):
        ...

    def removeSecondaryHighlights(self, function: ghidra.program.model.listing.Function):
        """
        Removes all secondary highlights for the current function
        
        :param ghidra.program.model.listing.Function function: the function containing the secondary highlights
        """

    def selectAll(self, trigger: docking.widgets.EventTrigger):
        ...

    def setCursorPosition(self, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation):
        ...

    def setDecompilerHoverProvider(self, provider: DecompilerHoverProvider):
        ...

    def setHighlightController(self, highlightController: ClangHighlightController):
        ...

    def setHoverMode(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setLocation(self, location: ghidra.program.util.ProgramLocation, viewerPosition: docking.widgets.fieldpanel.support.ViewerPosition):
        ...

    def setSearchResults(self, searchLocation: docking.widgets.SearchLocation):
        ...

    def setViewerPosition(self, viewerPosition: docking.widgets.fieldpanel.support.ViewerPosition):
        ...

    def tokenRenamed(self, token: ghidra.app.decompiler.ClangToken, newName: typing.Union[java.lang.String, str]):
        """
        This function is used to alert the panel that a token was renamed. If the token being renamed
        had a middle-mouse or secondary highlight, we must re-apply the highlights to the new token.
        
         
        
        This is not needed for highlighter service highlights, since they get called again to
        re-apply highlights. It is up to that highlighter to determine if highlighting still applies
        to the new token name. Alternatively, for secondary highlights, we know the user chose the
        highlight based upon name. Thus, when the name changes, we need to take action to update the
        secondary highlight.
        
        :param ghidra.app.decompiler.ClangToken token: the token being renamed
        :param java.lang.String or str newName: the new name of the token
        """

    @property
    def currentVariableHighlightColor(self) -> java.awt.Color:
        ...

    @property
    def selectedText(self) -> java.lang.String:
        ...

    @property
    def specialHighlightColor(self) -> java.awt.Color:
        ...

    @property
    def textUnderCursor(self) -> java.lang.String:
        ...

    @property
    def hoverShowing(self) -> jpype.JBoolean:
        ...

    @property
    def searchResults(self) -> ghidra.app.plugin.core.decompile.actions.DecompilerSearchLocation:
        ...

    @property
    def middleMouseHighlightColor(self) -> java.awt.Color:
        ...

    @property
    def highlightedText(self) -> java.lang.String:
        ...

    @property
    def layoutController(self) -> ClangLayoutController:
        ...

    @property
    def highlighter(self) -> ghidra.app.decompiler.DecompilerHighlighter:
        ...

    @property
    def tokenAtCursor(self) -> ghidra.app.decompiler.ClangToken:
        ...

    @property
    def secondaryHighlightColors(self) -> TokenHighlightColors:
        ...

    @property
    def options(self) -> ghidra.app.decompiler.DecompileOptions:
        ...

    @property
    def middleMouseHighlights(self) -> TokenHighlights:
        ...

    @property
    def lines(self) -> java.util.List[ghidra.app.decompiler.ClangLine]:
        ...

    @property
    def cursorPosition(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    @cursorPosition.setter
    def cursorPosition(self, value: docking.widgets.fieldpanel.support.FieldLocation):
        ...

    @property
    def controller(self) -> DecompilerController:
        ...

    @property
    def viewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...

    @viewerPosition.setter
    def viewerPosition(self, value: docking.widgets.fieldpanel.support.ViewerPosition):
        ...

    @property
    def secondaryHighlight(self) -> java.awt.Color:
        ...

    @property
    def selectedToken(self) -> ghidra.app.decompiler.ClangToken:
        ...

    @property
    def fontMetrics(self) -> java.awt.FontMetrics:
        ...

    @property
    def fieldPanel(self) -> docking.widgets.fieldpanel.FieldPanel:
        ...

    @property
    def currentLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def highlights(self) -> TokenHighlights:
        ...

    @property
    def highlightController(self) -> ClangHighlightController:
        ...

    @highlightController.setter
    def highlightController(self, value: ClangHighlightController):
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def fields(self) -> java.util.List[docking.widgets.fieldpanel.field.Field]:
        ...


@typing.type_check_only
class ClangDecompilerHighlighter(ghidra.app.decompiler.DecompilerHighlighter):
    """
    The implementation of :obj:`DecompilerHighlighter`.  This will get created by the
    Decompiler and then handed to clients that use the :obj:`DecompilerHighlightService`.  This
    is also used internally for 'secondary highlights'.
     
     
    This class may be :meth:`cloned <.clone>` or :meth:`copied <.copy>` as
    needed when the user creates a snapshot.  Highlight service highlighters will be cloned;
    secondary highlighters will be copied.  Cloning allows this class to delegate highlighting
    and cleanup for clones.  Contrastingly, copying allows the secondary highlights to operate
    independently.
    """

    @typing.type_check_only
    class MappedTokenColorProvider(ColorProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class NameTokenMatcher(ghidra.app.decompiler.CTokenHighlightMatcher):
    """
    Matcher used for secondary highlights in the Decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]


class DecompileData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, function: ghidra.program.model.listing.Function, location: ghidra.program.util.ProgramLocation, decompileResults: ghidra.app.decompiler.DecompileResults, errorMessage: typing.Union[java.lang.String, str], debugFile: jpype.protocol.SupportsPath, viewerPosition: docking.widgets.fieldpanel.support.ViewerPosition):
        ...

    def contains(self, programLocation: ghidra.program.util.ProgramLocation) -> bool:
        ...

    def getCCodeMarkup(self) -> ghidra.app.decompiler.ClangTokenGroup:
        ...

    def getDebugFile(self) -> java.io.File:
        ...

    def getDecompileResults(self) -> ghidra.app.decompiler.DecompileResults:
        ...

    def getErrorMessage(self) -> str:
        ...

    def getFunction(self) -> ghidra.program.model.listing.Function:
        ...

    def getFunctionSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getViewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...

    def hasDecompileResults(self) -> bool:
        ...

    def isValid(self) -> bool:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...

    @property
    def functionSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def viewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def debugFile(self) -> java.io.File:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def cCodeMarkup(self) -> ghidra.app.decompiler.ClangTokenGroup:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def decompileResults(self) -> ghidra.app.decompiler.DecompileResults:
        ...


class HighlightToken(java.lang.Object):
    """
    A class to used to track a :obj:`Decompiler` token along with its highlight color
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, token: ghidra.app.decompiler.ClangToken, color: java.awt.Color):
        ...

    def getColor(self) -> java.awt.Color:
        ...

    def getToken(self) -> ghidra.app.decompiler.ClangToken:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def token(self) -> ghidra.app.decompiler.ClangToken:
        ...


class ClangFieldElement(docking.widgets.fieldpanel.field.AbstractTextFieldElement):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, token: ghidra.app.decompiler.ClangToken, as_: docking.widgets.fieldpanel.field.AttributedString, col: typing.Union[jpype.JInt, int]):
        ...


class EmptyDecompileData(DecompileData):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class DecompileRunnable(ghidra.util.task.SwingRunnable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, debugFile: jpype.protocol.SupportsPath, viewerPosition: docking.widgets.fieldpanel.support.ViewerPosition, decompilerManager: DecompilerManager):
        """
        Constructor for a scheduled Decompile runnable
        
        :param ghidra.program.model.listing.Program program: the program containing the function to be decompiled
        :param ghidra.program.util.ProgramLocation location: the location for which to find its containing function.
        :param jpype.protocol.SupportsPath debugFile: if non-null, the file to store decompile debug information.
        """

    def monitoredRun(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Performs the decompile.
        """

    def swingRun(self, isCancelled: typing.Union[jpype.JBoolean, bool]):
        """
        Automatically called in the Swing thread by the RunManager after the run() method completes.
        If the decompile wasn't cancelled, it reports the results back to the DecompilerController.
        """

    def update(self, newRunnable: DecompileRunnable) -> bool:
        ...


@typing.type_check_only
class TokenKey(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, t: HighlightToken):
        ...

    def getToken(self) -> ghidra.app.decompiler.ClangToken:
        ...

    @property
    def token(self) -> ghidra.app.decompiler.ClangToken:
        ...


class ClangLayoutController(docking.widgets.fieldpanel.LayoutModel, docking.widgets.fieldpanel.listener.LayoutModelListener):
    """
    Control the GUI layout for displaying tokenized C code
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, opt: ghidra.app.decompiler.DecompileOptions, decompilerPanel: DecompilerPanel, met: java.awt.FontMetrics, hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        ...

    def buildLayouts(self, function: ghidra.program.model.listing.Function, doc: ghidra.app.decompiler.ClangTokenGroup, errmsg: typing.Union[java.lang.String, str], display: typing.Union[jpype.JBoolean, bool]):
        ...

    def getHighFunction(self, i: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.HighFunction:
        ...

    def getIndexBefore(self, index: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getLines(self) -> java.util.List[ghidra.app.decompiler.ClangLine]:
        ...

    def getRoot(self) -> ghidra.app.decompiler.ClangTokenGroup:
        ...

    def layoutChanged(self):
        ...

    def locationChanged(self, loc: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field, locationColor: java.awt.Color, parenColor: java.awt.Color):
        ...

    def modelChanged(self):
        ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...

    @property
    def root(self) -> ghidra.app.decompiler.ClangTokenGroup:
        ...

    @property
    def indexBefore(self) -> jpype.JInt:
        ...

    @property
    def lines(self) -> java.util.List[ghidra.app.decompiler.ClangLine]:
        ...


class DefaultColorProvider(ColorProvider):
    """
    A color provider that returns a specific color.
    """

    class_: typing.ClassVar[java.lang.Class]


class TokenHighlightColors(java.lang.Object):
    """
    A class to create and store colors related to token names
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getAppliedColorsString(self) -> str:
        ...

    def getColor(self, text: typing.Union[java.lang.String, str]) -> java.awt.Color:
        ...

    def getRecentColors(self) -> java.util.List[java.awt.Color]:
        ...

    def setColor(self, text: typing.Union[java.lang.String, str], color: java.awt.Color):
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def appliedColorsString(self) -> java.lang.String:
        ...

    @property
    def recentColors(self) -> java.util.List[java.awt.Color]:
        ...


class DecompilerCallbackHandlerAdapter(DecompilerCallbackHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DecompilerProgramListener(ghidra.framework.model.DomainObjectListener):
    """
    Listener of :obj:`Program` events for decompiler panels. Program events are buffered using 
    a :obj:`SwingUpdateManager` before triggering a new decompile process.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, controller: DecompilerController, callback: java.lang.Runnable):
        """
        Construct a listener with a callback to be called when a decompile should occur. Program
        events are buffered using SwingUpdateManager before the callback is called.
        
        :param DecompilerController controller: the DecompilerController
        :param java.lang.Runnable callback: the callback for when the decompile should be refreshed.
        """

    @typing.overload
    def __init__(self, controller: DecompilerController, updater: ghidra.util.task.SwingUpdateManager):
        """
        Construct a listener with a SwingUpdateManger that should be kicked for every
        program change.
        
        :param DecompilerController controller: the DecompilerController
        :param ghidra.util.task.SwingUpdateManager updater: A SwingUpdateManger to be kicked as program events are received which will
        eventually trigger a decompile refresh.
        """

    def dispose(self):
        ...


@typing.type_check_only
class Decompiler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def resetDecompiler(self):
        """
        Resets the native decompiler process.  Call this method when the decompiler's view
        of a program has been invalidated, such as when a new overlay space has been added.
        """


class ClangTextField(docking.widgets.fieldpanel.field.WrappingVerticalLayoutTextField):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tokenList: java.util.List[ghidra.app.decompiler.ClangToken], fieldElements: jpype.JArray[docking.widgets.fieldpanel.field.FieldElement], x: typing.Union[jpype.JInt, int], lineNumber: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        ...

    def getFirstToken(self) -> ghidra.app.decompiler.ClangToken:
        ...

    def getLastToken(self) -> ghidra.app.decompiler.ClangToken:
        ...

    def getLineNumber(self) -> int:
        ...

    def getToken(self, loc: docking.widgets.fieldpanel.support.FieldLocation) -> ghidra.app.decompiler.ClangToken:
        """
        Gets the C language token at the indicated location.
        
        :param docking.widgets.fieldpanel.support.FieldLocation loc: the field location
        :return: the token
        :rtype: ghidra.app.decompiler.ClangToken
        """

    @property
    def lastToken(self) -> ghidra.app.decompiler.ClangToken:
        ...

    @property
    def firstToken(self) -> ghidra.app.decompiler.ClangToken:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def token(self) -> ghidra.app.decompiler.ClangToken:
        ...


class UserHighlights(java.lang.Object):
    """
    A class to manage and track Decompiler highlights created by the user via the UI or from a 
    script.  This class manages secondary highlights and highlights created from the 
    :obj:`DecompilerHighlightService`, which has both global and per-function highlights.  For a 
    description of these terms, see :obj:`ClangHighlightController`.
     
    
    These highlights will remain until cleared explicitly by the user or a client API call.  
    Contrastingly, context highlights are cleared as the user moves the cursor around the Decompiler 
    display.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DecompilerManager(java.lang.Object):
    """
    Manages the threading involved with dealing with the decompiler. It uses a simpler approach
    than previous versions.  Currently, there is only one Runnable ever scheduled to the RunManager.
    If a new Decompile request comes in while a decompile is in progress, the new request is
    first checked to see if it going to result in the same function being decompile. If so, then the
    location is updated and the current decompile is allowed to continue.  If the new request is
    a new function or the "forceDecompile" option is on, then the current decompile is stopped
    and a new one is scheduled.  A SwingUpdateManger is used to prevent lots of decompile requests
    from coming to quickly.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, decompilerController: DecompilerController, options: ghidra.app.decompiler.DecompileOptions):
        ...

    def cancelAll(self):
        ...

    def dispose(self):
        ...

    def isBusy(self) -> bool:
        ...

    def resetDecompiler(self):
        """
        Resets the native decompiler process.  Call this method when the decompiler's view
        of a program has been invalidated, such as when a new overlay space has been added.
        """

    @property
    def busy(self) -> jpype.JBoolean:
        ...



__all__ = ["TokenHighlights", "DecompilerFindDialog", "DecompilerUtils", "ColorProvider", "DecompileResultsListener", "DecompilerController", "DecompilerCallbackHandler", "DecompilerHoverProvider", "ClangHighlightController", "ClangHighlightListener", "NullClangHighlightController", "LocationClangHighlightController", "DecompilerPanel", "ClangDecompilerHighlighter", "NameTokenMatcher", "DecompileData", "HighlightToken", "ClangFieldElement", "EmptyDecompileData", "DecompileRunnable", "TokenKey", "ClangLayoutController", "DefaultColorProvider", "TokenHighlightColors", "DecompilerCallbackHandlerAdapter", "DecompilerProgramListener", "Decompiler", "ClangTextField", "UserHighlights", "DecompilerManager"]
