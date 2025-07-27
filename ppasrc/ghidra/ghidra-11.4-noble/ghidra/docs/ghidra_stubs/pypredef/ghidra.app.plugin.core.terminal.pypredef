from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.listener
import docking.widgets.fieldpanel.support
import generic.theme
import ghidra.app.plugin.core.terminal.vt
import ghidra.app.services
import ghidra.framework.plugintool
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.nio # type: ignore
import java.nio.charset # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class TerminalProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    A window holding a VT100 terminal emulator.
     
     
    
    This also provides UI actions for searching the terminal's contents.
    """

    @typing.type_check_only
    class FindDialog(docking.DialogComponentProvider):

        class_: typing.ClassVar[java.lang.Class]

        def getOptions(self) -> java.util.Set[TerminalPanel.FindOptions]:
            ...

        @property
        def options(self) -> java.util.Set[TerminalPanel.FindOptions]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: TerminalPlugin, charset: java.nio.charset.Charset, helpPlugin: ghidra.framework.plugintool.Plugin):
        ...

    def addTerminalListener(self, listener: TerminalListener):
        ...

    def getColumns(self) -> int:
        ...

    def getCursorColumn(self) -> int:
        ...

    def getCursorRow(self) -> int:
        ...

    def getRangeText(self, startCol: typing.Union[jpype.JInt, int], startLine: typing.Union[jpype.JInt, int], endCol: typing.Union[jpype.JInt, int], endLine: typing.Union[jpype.JInt, int]) -> str:
        ...

    def getRows(self) -> int:
        ...

    def getScrollBackRows(self) -> int:
        ...

    def getTerminalPanel(self) -> TerminalPanel:
        ...

    def isTerminated(self) -> bool:
        ...

    def processInput(self, buffer: java.nio.ByteBuffer):
        ...

    def removeTerminalListener(self, listener: TerminalListener):
        ...

    def setClipboardService(self, clipboardService: ghidra.app.services.ClipboardService):
        ...

    def setDyanmicSize(self):
        ...

    def setFixedSize(self, cols: typing.Union[jpype.JShort, int], rows: typing.Union[jpype.JShort, int]):
        ...

    def setMaxScrollBackRows(self, rows: typing.Union[jpype.JInt, int]):
        ...

    def setOutputCallback(self, outputCb: ghidra.app.plugin.core.terminal.vt.VtOutput):
        ...

    def setTerminateAction(self, action: java.lang.Runnable):
        ...

    def terminated(self):
        """
        Notify the provider that the terminal's session has terminated
         
         
        
        The title and sub title are adjusted and all terminal listeners are removed. If/when the
        window is closed, it is removed from the tool.
        """

    @property
    def cursorRow(self) -> jpype.JInt:
        ...

    @property
    def columns(self) -> jpype.JInt:
        ...

    @property
    def terminalPanel(self) -> TerminalPanel:
        ...

    @property
    def cursorColumn(self) -> jpype.JInt:
        ...

    @property
    def scrollBackRows(self) -> jpype.JInt:
        ...

    @property
    def rows(self) -> jpype.JInt:
        ...


class TerminalTextFieldElement(docking.widgets.fieldpanel.field.FieldElement):
    """
    A text field element for rendering a full line of terminal text
     
     
    
    :obj:`TerminalTextFields` are populated by a single element. The typical pattern seems to be to
    create a separate element for each bit of text having common attributes. This pattern would
    generate quite a bit of garbage, since the terminal contents change frequently. Every time a line
    content changed, we'd have to re-construct the elements. Instead, we use a single re-usable
    element that renders the :obj:`VtLine` directly, including the variety of attributes. When the
    line changes, we merely have to re-paint.
    """

    @typing.type_check_only
    class SaveTransform(java.lang.AutoCloseable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, g: java.awt.Graphics):
            ...


    class_: typing.ClassVar[java.lang.Class]
    UNDERLINE_HEIGHT: typing.Final = 1

    def __init__(self, line: ghidra.app.plugin.core.terminal.vt.VtLine, metrics: java.awt.FontMetrics, fontSizeAdjustment: typing.Union[jpype.JFloat, float], colors: ghidra.app.plugin.core.terminal.vt.AnsiColorResolver):
        """
        Create a text field element
        
        :param ghidra.app.plugin.core.terminal.vt.VtLine line: the line of text from the :obj:`VtBuffer`
        :param java.awt.FontMetrics metrics: the font metrics
        :param jpype.JFloat or float fontSizeAdjustment: the font size adjustment
        :param ghidra.app.plugin.core.terminal.vt.AnsiColorResolver colors: the color resolver
        """

    def getNumCols(self) -> int:
        """
        Get the number of columns (total width, not just the used by the line)
        
        :return: the column count
        :rtype: int
        """

    @property
    def numCols(self) -> jpype.JInt:
        ...


class ThreadedTerminal(DefaultTerminal):
    """
    A terminal with a background thread and input stream powering its display.
     
     
    
    The thread eagerly reads the given input stream and pumps it into the given provider. Be careful
    using :meth:`injectDisplayOutput(ByteBuffer) <.injectDisplayOutput>`. While it is synchronized, there's no guarantee
    escape codes don't get mixed up. Note that this does not make any effort to connect the
    terminal's keyboard to any output stream.
    
    
    .. seealso::
    
        | :obj:`TerminalService.createWithStreams(java.nio.charset.Charset, InputStream, OutputStream)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: TerminalProvider, in_: java.io.InputStream):
        """
        Construct a terminal connected to the given input stream
        
        :param TerminalProvider provider: the provider
        :param java.io.InputStream in: the input stream
        """


class DefaultTerminal(ghidra.app.services.Terminal):
    """
    A terminal that does nothing on its own.
     
     
    
    Everything displayed happens via :meth:`injectDisplayOutput(ByteBuffer) <.injectDisplayOutput>`, and everything typed
    into it is emitted via the :obj:`VtOutput`, which was given at construction.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: TerminalProvider):
        ...


class TerminalAwtEventEncoder(java.lang.Object):
    """
    An encoder which can translate AWT/Swing events into ANSI input codes.
     
     
    
    The input system is not as well decoupled from Swing as the output system. For ease of use, the
    methods are named the same as their corresponding Swing event listener methods, though they may
    require additional arguments. These in turn invoke the :meth:`generateBytes(ByteBuffer) <.generateBytes>` method,
    which the implementor must send to the appropriate recipient, usually a pty.
    """

    class_: typing.ClassVar[java.lang.Class]
    CODE_NONE: typing.Final[jpype.JArray[jpype.JByte]]
    ESC: typing.Final = 27
    CODE_INSERT: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_DELETE: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_ENTER: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_PAGE_UP: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_PAGE_DOWN: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_NUMPAD5: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_UP_NORMAL: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_DOWN_NORMAL: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_RIGHT_NORMAL: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_LEFT_NORMAL: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_UP_APPLICATION: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_DOWN_APPLICATION: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_RIGHT_APPLICATION: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_LEFT_APPLICATION: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_HOME_NORMAL: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_END_NORMAL: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_HOME_APPLICATION: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_END_APPLICATION: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F1: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F2: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F3: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F4: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F5: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F6: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F7: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F8: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F9: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F10: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F11: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F12: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F13: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F14: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F15: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F16: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F17: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F18: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F19: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_F20: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_FOCUS_GAINED: typing.Final[jpype.JArray[jpype.JByte]]
    CODE_FOCUS_LOST: typing.Final[jpype.JArray[jpype.JByte]]

    @typing.overload
    def __init__(self, charsetName: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, charset: java.nio.charset.Charset):
        ...

    def focusGained(self):
        ...

    def focusLost(self):
        ...

    def keyPressed(self, e: java.awt.event.KeyEvent, cursorKeyMode: ghidra.app.plugin.core.terminal.vt.VtHandler.KeyMode, keypadMode: ghidra.app.plugin.core.terminal.vt.VtHandler.KeyMode):
        ...

    def keyTyped(self, e: java.awt.event.KeyEvent):
        ...

    def mousePressed(self, e: java.awt.event.MouseEvent, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        ...

    def mouseReleased(self, e: java.awt.event.MouseEvent, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        ...

    def mouseWheelMoved(self, e: java.awt.event.MouseWheelEvent, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        ...

    def sendChar(self, c: typing.Union[jpype.JChar, int, str]):
        ...

    def sendText(self, text: java.lang.CharSequence):
        ...

    @staticmethod
    def vtseq(number: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        ...


class TerminalPanel(javax.swing.JPanel, docking.widgets.fieldpanel.listener.FieldLocationListener, docking.widgets.fieldpanel.listener.FieldSelectionListener, docking.widgets.fieldpanel.listener.LayoutListener, ghidra.app.plugin.core.terminal.vt.AnsiColorResolver, generic.theme.ThemeListener):
    """
    A VT100 terminal emulator in a panel.
     
     
    
    This implementation uses Ghidra's :obj:`FieldPanel` for its rendering, highlighting, cursor
    positioning, etc. This one follows the same pattern as many other such panels in Ghidra with some
    exceptions. Namely, it removes all key listeners from the field panel to prevent any accidental
    local control of the cursor. A terminal emulator defers that entirely to the application. Key
    strokes are instead sent to the application directly, and it may respond with commands to move
    the actual cursor. This component also implements the :obj:`AnsiColorResolver`, as it makes the
    most sense to declare the various :obj:`GColor`s here.
    """

    @typing.type_check_only
    class TerminalFieldPanel(docking.widgets.fieldpanel.FieldPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: docking.widgets.fieldpanel.LayoutModel):
            ...


    class FindOptions(java.lang.Enum[TerminalPanel.FindOptions]):
        """
        Enumerated options available when searching the terminal's buffer
        """

        class_: typing.ClassVar[java.lang.Class]
        CASE_SENSITIVE: typing.Final[TerminalPanel.FindOptions]
        """
        Make the search case sensitive. If this flag is absent, the search defaults to case
        insensitive.
        """

        WRAP: typing.Final[TerminalPanel.FindOptions]
        """
        Allow the search to wrap.
        """

        WHOLE_WORD: typing.Final[TerminalPanel.FindOptions]
        """
        Require the result to be a whole word.
        """

        REGEX: typing.Final[TerminalPanel.FindOptions]
        """
        Treat the search term as a regular expression instead of literal text.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TerminalPanel.FindOptions:
            ...

        @staticmethod
        def values() -> jpype.JArray[TerminalPanel.FindOptions]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addTerminalListener(self, listener: TerminalListener):
        ...

    def dispose(self):
        ...

    def find(self, text: typing.Union[java.lang.String, str], options: java.util.Set[TerminalPanel.FindOptions], start: docking.widgets.fieldpanel.support.FieldLocation, forward: typing.Union[jpype.JBoolean, bool]) -> docking.widgets.fieldpanel.support.FieldRange:
        """
        Search the terminal's buffer for the given text.
         
         
        
        The start location should be given, so that the search can progress to each successive
        result. If no location is given, e.g., because this is the first time the user has searched,
        then a default location will be chosen based on the search direction: the start for forward
        or the end for backward.
        
        :param java.lang.String or str text: the text (or pattern for :obj:`FindOptions.REGEX`)
        :param java.util.Set[TerminalPanel.FindOptions] options: the search options
        :param docking.widgets.fieldpanel.support.FieldLocation start: the starting location, or null for a default
        :param jpype.JBoolean or bool forward: true to search forward, false to search backward
        :return: the range covering the found term, or null if not found
        :rtype: docking.widgets.fieldpanel.support.FieldRange
        """

    def getColumns(self) -> int:
        ...

    def getCursorColumn(self) -> int:
        ...

    def getCursorRow(self) -> int:
        ...

    def getFieldPanel(self) -> TerminalPanel.TerminalFieldPanel:
        ...

    def getRows(self) -> int:
        ...

    @typing.overload
    def getSelectedText(self) -> str:
        """
        Get the text selected by the user
         
         
        
        If the selection is disjoint, this returns null.
        
        :return: the selected text, or null
        :rtype: str
        """

    @typing.overload
    def getSelectedText(self, range: docking.widgets.fieldpanel.support.FieldRange) -> str:
        """
        Get the text covered by the given range
        
        :param docking.widgets.fieldpanel.support.FieldRange range: the range
        :return: the text
        :rtype: str
        """

    def paste(self, text: typing.Union[java.lang.String, str]):
        """
        Send the given text to the application, as if typed on the keyboard
         
         
        
        Note the application may request a mode called "bracketed paste," in which case the text will
        be surrounded by special control sequences, allowing the application to distinguish pastes
        from manual typing. An application may do this so that an Undo could undo the whole paste,
        and not just the last keystroke simulated by the paste.
        
        :param java.lang.String or str text: the text
        """

    def processInput(self, buffer: java.nio.ByteBuffer):
        """
        Process the given bytes as application output.
         
         
        
        In most circumstances, there is a thread that just reads an output stream, usually from a
        pty, and feeds it into this method.
        
        :param java.nio.ByteBuffer buffer: the buffer
        """

    def removeTerminalListener(self, listener: TerminalListener):
        ...

    def reportCursorPos(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        """
        Send the cursor's position to the application
        
        :param jpype.JInt or int row: the cursor's row
        :param jpype.JInt or int col: the cursor's column
        """

    def selectWordAt(self, location: docking.widgets.fieldpanel.support.FieldLocation, trigger: docking.widgets.EventTrigger):
        """
        Select the whole word at the given location.
         
         
        
        This is used for double-click to select the whole word.
        
        :param docking.widgets.fieldpanel.support.FieldLocation location: the cursor's location
        :param docking.widgets.EventTrigger trigger: the cause of the selection
        """

    def setClipboardService(self, clipboardService: ghidra.app.services.ClipboardService):
        ...

    def setDynamicTerminalSize(self):
        """
        Set the terminal to fit the window size.
         
         
        
        Immediately fit the terminal to the window. It will also respond to the window resizing by
        recalculating the rows and columns and adjusting the buffer's contents to fit. Whenever the
        terminal size changes :meth:`TerminalListener.resized(short, short) <TerminalListener.resized>` is invoked. The bottom
        scrollbar is disabled, and the vertical scrollbar is always displayed, to avoid frenetic
        horizontal resizing.
        """

    def setFixedTerminalSize(self, cols: typing.Union[jpype.JShort, int], rows: typing.Union[jpype.JShort, int]):
        """
        Set the terminal to a fixed size.
         
         
        
        The terminal will no longer respond to the window resizing, and scrollbars are displayed as
        needed. If the terminal size changes as a result of this call,
        :meth:`TerminalListener.resized(short, short) <TerminalListener.resized>` is invoked.
        
        :param jpype.JShort or int cols: the number of columns
        :param jpype.JShort or int rows: the number of rows
        """

    def setOutputCallback(self, outputCb: ghidra.app.plugin.core.terminal.vt.VtOutput):
        """
        Set the callback for application input, i.e., terminal output
         
         
        
        In most circumstances, the bytes are sent to an input stream, usually from a pty.
        
        :param ghidra.app.plugin.core.terminal.vt.VtOutput outputCb: the callback
        """

    @property
    def cursorRow(self) -> jpype.JInt:
        ...

    @property
    def selectedText(self) -> java.lang.String:
        ...

    @property
    def columns(self) -> jpype.JInt:
        ...

    @property
    def cursorColumn(self) -> jpype.JInt:
        ...

    @property
    def rows(self) -> jpype.JInt:
        ...

    @property
    def fieldPanel(self) -> TerminalPanel.TerminalFieldPanel:
        ...


class TerminalLayoutModel(docking.widgets.fieldpanel.LayoutModel, ghidra.app.plugin.core.terminal.vt.VtHandler):
    """
    The terminal layout model.
     
     
    
    This, the buffers, and the parser, comprise the core logic of the terminal emulator. This
    implements the Ghidra layout model, as well as the handler methods of the VT100 parser. Most of
    the commands it dispatches to the current buffer. A few others modify some flags, e.g., the
    handling of mouse events. Another swaps between buffers, etc. This layout model then maps each
    line to a :obj:`TerminalLayout`. Unlike some other layout models, this does not create a new
    layout whenever a line is mutated. Given the frequency with which the terminal contents change,
    that would generate a decent bit of garbage. The "layout" instead dynamically computes its
    properties from the mutable line object and paints straight from its buffers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, panel: TerminalPanel, charset: java.nio.charset.Charset, metrics: java.awt.FontMetrics, colors: ghidra.app.plugin.core.terminal.vt.AnsiColorResolver):
        """
        Create a model
        
        :param TerminalPanel panel: the panel to receive commands from the model's VT/ANSI parser
        :param java.nio.charset.Charset charset: the charset for decoding bytes to characters
        :param java.awt.FontMetrics metrics: font metrics for the monospaced terminal font
        :param fontSizeAdjustment: the font size adjustment:param ghidra.app.plugin.core.terminal.vt.AnsiColorResolver colors: a resolver for ANSI colors
        """

    def getCols(self) -> int:
        ...

    def getCursorColumn(self) -> int:
        ...

    def getCursorRow(self) -> int:
        ...

    def getRows(self) -> int:
        ...

    def getScrollBackSize(self) -> int:
        ...

    def getSelectedText(self, range: docking.widgets.fieldpanel.support.FieldRange) -> str:
        ...

    def processInput(self, buffer: java.nio.ByteBuffer):
        ...

    def resetCursorBottom(self) -> int:
        ...

    def setFontMetrics(self, metrics: java.awt.FontMetrics, fontSizeAdjustment: typing.Union[jpype.JFloat, float]):
        ...

    def setMaxScrollBackSize(self, rows: typing.Union[jpype.JInt, int]):
        ...

    @property
    def cursorRow(self) -> jpype.JInt:
        ...

    @property
    def selectedText(self) -> java.lang.String:
        ...

    @property
    def scrollBackSize(self) -> jpype.JInt:
        ...

    @property
    def cursorColumn(self) -> jpype.JInt:
        ...

    @property
    def rows(self) -> jpype.JInt:
        ...

    @property
    def cols(self) -> jpype.JInt:
        ...


class TerminalListener(java.lang.Object):
    """
    A listener for various events on a terminal panel
    """

    class_: typing.ClassVar[java.lang.Class]

    def resized(self, cols: typing.Union[jpype.JShort, int], rows: typing.Union[jpype.JShort, int]):
        """
        The terminal was resized by the user
         
         
        
        If applicable and possible, this information should be communicated to the connection
        
        :param jpype.JShort or int cols: the number of columns
        :param jpype.JShort or int rows: the number of rows
        """

    def retitled(self, title: typing.Union[java.lang.String, str]):
        """
        The application requested the window title changed
        
        :param java.lang.String or str title: the requested title
        """


class TerminalTextField(docking.widgets.fieldpanel.field.TextField):
    """
    A text field (renderer) for the terminal panel.
     
     
    
    The purpose of this thing is to hold a single text field element. It is also responsible for
    rendering selections and the cursor. Because the cursor is also supposed to be controlled by the
    application, we do less "validation" and correction of it on our end. If it's past the end of a
    line, so be it.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def create(line: ghidra.app.plugin.core.terminal.vt.VtLine, metrics: java.awt.FontMetrics, fontSizeAdjustment: typing.Union[jpype.JFloat, float], colors: ghidra.app.plugin.core.terminal.vt.AnsiColorResolver) -> TerminalTextField:
        """
        Create a text field for the given line.
         
         
        
        This method will create the sole text field element populating this field.
        
        :param ghidra.app.plugin.core.terminal.vt.VtLine line: the line from the :obj:`VtBuffer` that will be rendered in this field
        :param java.awt.FontMetrics metrics: the font metrics
        :param jpype.JFloat or float fontSizeAdjustment: the font size adjustment
        :param ghidra.app.plugin.core.terminal.vt.AnsiColorResolver colors: the color resolver
        :return: the field
        :rtype: TerminalTextField
        """


class TerminalClipboardProvider(ghidra.app.services.ClipboardContentProviderService):
    """
    The clipboard provider for the terminal plugin.
     
     
    
    In addition to providing clipboard contents and paste functionality, this customizes the Copy and
    Paste actions. We change the "owner" to be this plugin, so that the action can be configured
    independently of the standard Copy and Paste actions. Then, we re-bind the keys to Ctrl+Shift+C
    and Shift+Shift+V, respectively. This ensures that Ctrl+C will still send an Interrupt (char 3).
    This is the convention followed by just about every XTerm clone.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: TerminalProvider):
        ...

    def selectionChanged(self, selection: docking.widgets.fieldpanel.support.FieldSelection):
        ...


class TerminalFinder(java.lang.Object):
    """
    The algorithm for finding text in the terminal buffer.
     
     
    
    This is an abstract class, so that text search and regex search are better separated, while the
    common parts need not be duplicated.
    """

    class TextTerminalFinder(TerminalFinder):
        """
        A finder that searches for exact text, case insensitive by default
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: TerminalLayoutModel, cur: docking.widgets.fieldpanel.support.FieldLocation, forward: typing.Union[jpype.JBoolean, bool], text: typing.Union[java.lang.String, str], options: java.util.Set[TerminalPanel.FindOptions]):
            """
            
            
            
            .. seealso::
            
                | :obj:`TerminalPanel.find(String, Set, FieldLocation, boolean)`
            """


    class RegexTerminalFinder(TerminalFinder):
        """
        A find that searches for regex patterns, case insensitive by default
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: TerminalLayoutModel, cur: docking.widgets.fieldpanel.support.FieldLocation, forward: typing.Union[jpype.JBoolean, bool], pattern: typing.Union[java.lang.String, str], options: java.util.Set[TerminalPanel.FindOptions]):
            """
            
            
            
            .. seealso::
            
                | :obj:`TerminalPanel.find(String, Set, FieldLocation, boolean)`
            """


    class_: typing.ClassVar[java.lang.Class]

    def find(self) -> docking.widgets.fieldpanel.support.FieldRange:
        """
        Execute the search
        
        :return: the range covering the found term, or null if not found
        :rtype: docking.widgets.fieldpanel.support.FieldRange
        """


class TerminalPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.TerminalService):
    """
    The plugin that provides :obj:`TerminalService`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def createProvider(self, helpPlugin: ghidra.framework.plugintool.Plugin, charset: java.nio.charset.Charset, outputCb: ghidra.app.plugin.core.terminal.vt.VtOutput) -> TerminalProvider:
        ...


class TerminalLayout(docking.widgets.fieldpanel.support.SingleRowLayout):
    """
    A layout for a line of text in the terminal.
     
     
    
    The layout is not terribly complicated, but we must also provide the text field and text element.
    Instead of parceling out the attributed strings into different elements, we hand the entire line
    to a single element, which can then render the text, with its various attributes, straight from
    the model's character buffer. This spares us a good deal of object creation, and allows us to
    re-use the layouts more frequently.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, line: ghidra.app.plugin.core.terminal.vt.VtLine, metrics: java.awt.FontMetrics, fontSizeAdjustment: typing.Union[jpype.JFloat, float], colors: ghidra.app.plugin.core.terminal.vt.AnsiColorResolver):
        ...



__all__ = ["TerminalProvider", "TerminalTextFieldElement", "ThreadedTerminal", "DefaultTerminal", "TerminalAwtEventEncoder", "TerminalPanel", "TerminalLayoutModel", "TerminalListener", "TerminalTextField", "TerminalClipboardProvider", "TerminalFinder", "TerminalPlugin", "TerminalLayout"]
