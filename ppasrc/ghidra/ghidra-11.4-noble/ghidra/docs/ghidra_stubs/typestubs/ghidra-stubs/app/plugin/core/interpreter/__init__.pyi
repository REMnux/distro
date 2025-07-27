from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.widgets.list
import ghidra.app.plugin.core.console
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.util
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.text # type: ignore
import utility.function


class AnsiRenderer(java.lang.Object):
    """
    An object for parsing and rendering ANSI-styled strings into a Swing :obj:`Document`.
     
     
    
    Depending on the use case, it may be appropriate to instantiate multiple parsers, even if they
    are inserting contents into the same document, e.g., to process a terminal's stdout and stderr
    independently. Keep in mind, despite using separate renderers, escape codes emitted on stderr
    will still affect any following text emitted on stdout and vice versa. However, using separate
    renderers prevents the corruption of those escape sequences when interleaving the output streams.
    """

    @typing.type_check_only
    class ParserHandler(AnsiParser.AnsiParserHandler):

        class_: typing.ClassVar[java.lang.Class]
        document: javax.swing.text.StyledDocument
        attributes: javax.swing.text.MutableAttributeSet


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def renderString(self, document: javax.swing.text.StyledDocument, text: typing.Union[java.lang.String, str], attributes: javax.swing.text.MutableAttributeSet):
        """
        Render a string with embedded ANSI escape codes.
         
         
        
        The initial attributes object that is provided to this function will be used as the default
        style (e.g. after a ESC [ m).
         
         
        
        The instance may internally buffer some text. Use separate renderer objects for different
        text streams.
        
        :param javax.swing.text.StyledDocument document: Document to render the string to
        :param java.lang.String or str text: A text string which may contain 7-bit ANSI escape codes
        :param javax.swing.text.MutableAttributeSet attributes: Current text attributes; may be modified by this function
        :raises BadLocationException: if there is an error parsing the text
        """


class InterpreterPanel(javax.swing.JPanel, ghidra.framework.options.OptionsChangeListener):

    class TextType(java.lang.Enum[InterpreterPanel.TextType]):

        class_: typing.ClassVar[java.lang.Class]
        STDOUT: typing.Final[InterpreterPanel.TextType]
        STDERR: typing.Final[InterpreterPanel.TextType]
        STDIN: typing.Final[InterpreterPanel.TextType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> InterpreterPanel.TextType:
            ...

        @staticmethod
        def values() -> jpype.JArray[InterpreterPanel.TextType]:
            ...


    @typing.type_check_only
    class IPOut(java.io.OutputStream):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IPStdin(java.io.InputStream):
        """
        An :obj:`InputStream` that has as its source text strings being pushed into
        it by a thread, and being read by another thread.
         
        
        Not thread-safe for multiple readers, but is thread-safe for writers.
         
        
        :meth:`Closing <.close>` this stream (from any thread) will awaken the
        blocked reader thread and give an EOF result to the read operation it was blocking on.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OutputTextPaneKeyListener(java.awt.event.KeyListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InputTextPaneKeyListener(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, interpreter: InterpreterConnection):
        ...

    def clear(self):
        ...

    def dispose(self):
        ...

    def getErrWriter(self) -> java.io.PrintWriter:
        ...

    def getOutWriter(self) -> java.io.PrintWriter:
        ...

    def getOutputText(self) -> str:
        ...

    def getOutputTextPane(self) -> javax.swing.JTextPane:
        ...

    def getPrompt(self) -> str:
        ...

    def getStdErr(self) -> java.io.OutputStream:
        ...

    def getStdOut(self) -> java.io.OutputStream:
        ...

    def getStdin(self) -> java.io.InputStream:
        ...

    def insertCompletion(self, completion: ghidra.app.plugin.core.console.CodeCompletion):
        ...

    def isInputPermitted(self) -> bool:
        ...

    def setInputPermitted(self, permitted: typing.Union[jpype.JBoolean, bool]):
        ...

    def setPrompt(self, prompt: typing.Union[java.lang.String, str]):
        ...

    def setTextPaneFont(self, textPane: javax.swing.JTextPane, font: java.awt.Font):
        ...

    @property
    def errWriter(self) -> java.io.PrintWriter:
        ...

    @property
    def stdin(self) -> java.io.InputStream:
        ...

    @property
    def outputTextPane(self) -> javax.swing.JTextPane:
        ...

    @property
    def stdOut(self) -> java.io.OutputStream:
        ...

    @property
    def outWriter(self) -> java.io.PrintWriter:
        ...

    @property
    def inputPermitted(self) -> jpype.JBoolean:
        ...

    @inputPermitted.setter
    def inputPermitted(self, value: jpype.JBoolean):
        ...

    @property
    def stdErr(self) -> java.io.OutputStream:
        ...

    @property
    def outputText(self) -> java.lang.String:
        ...

    @property
    def prompt(self) -> java.lang.String:
        ...

    @prompt.setter
    def prompt(self, value: java.lang.String):
        ...


@typing.type_check_only
class AnsiParser(java.lang.Object):
    """
    A text stream processor that invokes callbacks for ANSI escape codes.
    
     
    
    The general pattern is: 1) Implement :obj:`AnsiParserHandler`, 2) Construct a parser, passing in
    your handler, 3) Invoke :meth:`processString(String) <.processString>` as needed. The parser keeps an internal
    buffer so that input text can be streamed incrementally.
    """

    @typing.type_check_only
    class AnsiParserHandler(java.lang.Object):
        """
        The interface for parser callbacks.
         
         
        
        See `ANSI escape code <https://en.wikipedia.org/wiki/ANSI_escape_code>`_ on
        Wikipedia.
        """

        class_: typing.ClassVar[java.lang.Class]

        def handleCSI(self, param: typing.Union[java.lang.String, str], inter: typing.Union[java.lang.String, str], finalChar: typing.Union[java.lang.String, str]):
            """
            Callback for an ANSI Control Sequence Introducer sequence
            
            :param java.lang.String or str param: zero or more parameter bytes (``0-9:;<=>?``)
            :param java.lang.String or str inter: zero or more intermediate bytes (space ``!"#$%&'()*+,-./``
            :param java.lang.String or str finalChar: the final byte (``@A-Z[\]^_`a-z{|}~``)
            :raises BadLocationException: if there was an issue applying the sequence to a document
            """

        def handleOSC(self, param: typing.Union[java.lang.String, str]):
            """
            Callback for an ANSI Operating System Command sequence
            
            :param java.lang.String or str param: zero or more parameter bytes in the ASCII printable range
            :raises BadLocationException: if there was an issue applying the sequence to a document
            """

        def handleString(self, text: typing.Union[java.lang.String, str]):
            """
            Callback for a portion of text
            
            :param java.lang.String or str text: the text
            :raises BadLocationException: if there was an issue rendering the text into a document
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handler: AnsiParser.AnsiParserHandler):
        """
        Construct a parser with the given handler
        
        :param AnsiParser.AnsiParserHandler handler: the callbacks to invoke during parsing
        """

    def processString(self, text: typing.Union[java.lang.String, str]):
        """
        Process a portion of input text
        
        :param java.lang.String or str text: the portion to process
        :raises BadLocationException: if there was an issue rendering the portion into a document
        """


class InterpreterPanelService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def createInterpreterPanel(self, interpreter: InterpreterConnection, visible: typing.Union[jpype.JBoolean, bool]) -> InterpreterConsole:
        """
        Creates a new interpreter panel.
        
        :param InterpreterConnection interpreter: A connection back to the interpreter.
        :param jpype.JBoolean or bool visible: True if the panel should be visible when created; otherwise, false.
        :return: The interpreter console that corresponds to the panel.
        :rtype: InterpreterConsole
        """


class InterpreterPanelPlugin(ghidra.framework.plugintool.Plugin, InterpreterPanelService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class CodeCompletionListModel(javax.swing.ListModel[ghidra.app.plugin.core.console.CodeCompletion]):
    """
    Code completion ListModel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, completion_list: java.util.List[ghidra.app.plugin.core.console.CodeCompletion]):
        ...


class CompletionWindowTrigger(java.lang.Enum[CompletionWindowTrigger]):

    class_: typing.ClassVar[java.lang.Class]
    TAB: typing.Final[CompletionWindowTrigger]
    CONTROL_SPACE: typing.Final[CompletionWindowTrigger]

    def getKeyStroke(self) -> javax.swing.KeyStroke:
        ...

    def isTrigger(self, e: java.awt.event.KeyEvent) -> bool:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CompletionWindowTrigger:
        ...

    @staticmethod
    def values() -> jpype.JArray[CompletionWindowTrigger]:
        ...

    @property
    def keyStroke(self) -> javax.swing.KeyStroke:
        ...

    @property
    def trigger(self) -> jpype.JBoolean:
        ...


class CodeCompletionWindow(javax.swing.JDialog):
    """
    This class encapsulates a code completion popup Window for the ConsolePlugin.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: java.awt.Window, cp: InterpreterPanel, textField: javax.swing.JTextPane):
        ...

    def getCompletion(self) -> ghidra.app.plugin.core.console.CodeCompletion:
        """
        Returns the currently selected code completion.
        
        Returns "" if there is none.
        
        :return: the currently selected code completion, or null if none selected
        :rtype: ghidra.app.plugin.core.console.CodeCompletion
        """

    def processKeyEvent(self, e: java.awt.event.KeyEvent):
        """
        Process a KeyEvent for this Window.
        
        This method is located here so that others (e.g. ConsolePlugin) can
        forward KeyEvents to us, or we can process KeyEvents that were directed
        to us (because we had focus instead).
        
        :param java.awt.event.KeyEvent e: KeyEvent
        """

    def selectNext(self):
        """
        Selects the next item in the list with a usable completion.
        """

    def selectPrevious(self):
        """
        Selects the previous item in the list with a usable completion.
        """

    def setFont(self, font: java.awt.Font):
        """
        Sets the Font on this CodeCompletionWindow.
        
        Basically sets the Font in the completion list.
        
        :param java.awt.Font font: the new Font
        """

    def updateCompletionList(self, list: java.util.List[ghidra.app.plugin.core.console.CodeCompletion]):
        """
        Updates the completion list with the given completion mapping.
        
        The format, as mentioned above, is:
        "attribute" -> "substitution value"
        If the substitution value is null, then that attribute will not be
        selectable for substitution.
        
        After updating the mapping, this Window then updates its size as
        appropriate.
        
        The Window also will attempt to move out of the way of the cursor/caret
        in the textField.  However, if the caret's position had recently been
        changed and the caret had not been repainted yet, then the caret's
        location can be null.  In this case, the Window will not move.
        You can avoid this condition by calling this method in a
        SwingUtilities.invokeLater(Runnable).
        
        :param java.util.List[ghidra.app.plugin.core.console.CodeCompletion] list: List of code completions
        """

    def updateLocation(self, caretLocation: java.awt.Point):
        ...

    @property
    def completion(self) -> ghidra.app.plugin.core.console.CodeCompletion:
        ...


class InterpreterConsole(ghidra.util.Disposable):
    """
    Interactive interpreter console.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addAction(self, action: docking.action.DockingAction):
        ...

    def addFirstActivationCallback(self, activationCallback: utility.function.Callback):
        """
        Adds the given callback which will get called the first time the interpreter console is
        activated.
        
        :param utility.function.Callback activationCallback: The callback to execute when activation occurs for the first time.
        """

    def clear(self):
        ...

    def getErrWriter(self) -> java.io.PrintWriter:
        ...

    def getOutWriter(self) -> java.io.PrintWriter:
        ...

    def getStdErr(self) -> java.io.OutputStream:
        ...

    def getStdOut(self) -> java.io.OutputStream:
        ...

    def getStdin(self) -> java.io.InputStream:
        ...

    def isInputPermitted(self) -> bool:
        """
        Checks whether the user can input commands.
        
        :return: true if permitted, false if prohibited
        :rtype: bool
        """

    def isVisible(self) -> bool:
        """
        Check if the console is visible
         
         
        
        Note if the console is on-screen, but occluded by other windows, this still returns
        ``true``.
        
        :return: true if visible, false if hidden
        :rtype: bool
        """

    def setInputPermitted(self, permitted: typing.Union[jpype.JBoolean, bool]):
        """
        Controls whether the user can input commands.
        
        :param jpype.JBoolean or bool permitted: true to permit input, false to prohibit input
        """

    def setPrompt(self, prompt: typing.Union[java.lang.String, str]):
        ...

    def setTransient(self):
        """
        Signals that this console is one that the user can remove from the tool as desired. If this
        method is not called, then the user cannot remove the console from the tool, which means that
        closing the console only hides it.
        """

    def show(self):
        """
        Show the console's provider in the tool
        """

    def updateTitle(self):
        """
        Notify the tool that this console's title has changed
        """

    @property
    def errWriter(self) -> java.io.PrintWriter:
        ...

    @property
    def stdin(self) -> java.io.InputStream:
        ...

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @property
    def stdOut(self) -> java.io.OutputStream:
        ...

    @property
    def outWriter(self) -> java.io.PrintWriter:
        ...

    @property
    def inputPermitted(self) -> jpype.JBoolean:
        ...

    @inputPermitted.setter
    def inputPermitted(self, value: jpype.JBoolean):
        ...

    @property
    def stdErr(self) -> java.io.OutputStream:
        ...


@typing.type_check_only
class HistoryManagerImpl(HistoryManager):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CodeCompletionListSelectionModel(javax.swing.DefaultListSelectionModel):
    """
    This data type handles selection changes in the CodeCompletionWindow.
    
    This contains all the "smarts" to determine whether or not indices can be
    selected.  So when the user clicks on an entry with the mouse, we choose
    whether or not that index can actually be highlighted/selected.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, l: java.util.List[ghidra.app.plugin.core.console.CodeCompletion]):
        """
        Constructs a new CodeCompletionListSelectionModel using the given List.
        
        :param java.util.List[ghidra.app.plugin.core.console.CodeCompletion] l: the List to use
        """

    def setSelectionInterval(self, index0: typing.Union[jpype.JInt, int], index1: typing.Union[jpype.JInt, int]):
        """
        Called when the selection needs updating.
        
        Here we will check the value of the new index and determine whether or
        not we actually want to select it.
        
        :param jpype.JInt or int index0: old index
        :param jpype.JInt or int index1: new index
        """


class InterpreterComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter, InterpreterConsole):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: InterpreterPanelPlugin, interpreter: InterpreterConnection, visible: typing.Union[jpype.JBoolean, bool]):
        ...

    def getOutputText(self) -> str:
        """
        For testing purposes only
        
        :return: the text in the output buffer
        :rtype: str
        """

    def getPrompt(self) -> str:
        """
        For testing purposes, but should probably be promoted to InterpreterConsole interface
        
        :return: the prompt;
        :rtype: str
        """

    def setTransient(self):
        """
        Overridden so that we can add our custom actions for transient tools.
        """

    @property
    def outputText(self) -> java.lang.String:
        ...

    @property
    def prompt(self) -> java.lang.String:
        ...


class InterpreterConnection(java.lang.Object):
    """
    A connection between an implementation of an interpreter and its generic GUI components.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    @deprecated("Additionally implement getCompletions(String, int) \n             and consider generating completions relative to the caret position")
    def getCompletions(self, cmd: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.app.plugin.core.console.CodeCompletion]:
        """
        Gets a :obj:`List` of :obj:`code completions <CodeCompletion>` for the given command.
        
        :param java.lang.String or str cmd: The command to get code completions for
        :return: A :obj:`List` of :obj:`code completions <CodeCompletion>` for the given command
        :rtype: java.util.List[ghidra.app.plugin.core.console.CodeCompletion]
        
        .. deprecated::
        
        Additionally implement :meth:`getCompletions(String, int) <.getCompletions>` 
                    and consider generating completions relative to the caret position
        """

    @typing.overload
    def getCompletions(self, cmd: typing.Union[java.lang.String, str], caretPos: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.app.plugin.core.console.CodeCompletion]:
        """
        Gets a :obj:`List` of :obj:`code completions <CodeCompletion>` for the given command
        relative to the given caret position.
        
        :param java.lang.String or str cmd: The command to get code completions for
        :param jpype.JInt or int caretPos: The position of the caret in the input string 'cmd'.
                        It should satisfy the constraint "0 <= caretPos <= cmd.length()"
        :return: A :obj:`List` of :obj:`code completions <CodeCompletion>` for the given command
        :rtype: java.util.List[ghidra.app.plugin.core.console.CodeCompletion]
        """

    def getIcon(self) -> javax.swing.Icon:
        """
        Gets the icon associated with the interpreter.
        
        :return: The icon associated with the interpreter.  Null if default icon is desired.
        :rtype: javax.swing.Icon
        """

    def getTitle(self) -> str:
        """
        Gets the title of the interpreter.
        
        :return: The title of the interpreter
        :rtype: str
        """

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def completions(self) -> java.util.List[ghidra.app.plugin.core.console.CodeCompletion]:
        ...

    @property
    def title(self) -> java.lang.String:
        ...


@typing.type_check_only
class CodeCompletionListCellRenderer(docking.widgets.list.GListCellRenderer[ghidra.app.plugin.core.console.CodeCompletion]):
    """
    Renders CodeCompletions for the CodeCompletionWindow.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getListCellRendererComponent(self, list: javax.swing.JList[ghidra.app.plugin.core.console.CodeCompletion], codeCompletion: ghidra.app.plugin.core.console.CodeCompletion, index: typing.Union[jpype.JInt, int], isSelected: typing.Union[jpype.JBoolean, bool], cellHasFocus: typing.Union[jpype.JBoolean, bool]) -> java.awt.Component:
        """
        Render either a default list cell, or use the one provided.
        
        If the CodeCompletion we got has a Component to be used, then use that.
        Otherwise, we use the DefaultListCellRenderer routine.
        """


class HistoryManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addHistory(self, command: typing.Union[java.lang.String, str]):
        ...

    def getHistoryDown(self) -> str:
        ...

    def getHistoryUp(self) -> str:
        ...

    def getRetention(self) -> int:
        ...

    def setRetention(self, retention: typing.Union[jpype.JInt, int]):
        ...

    @property
    def historyDown(self) -> java.lang.String:
        ...

    @property
    def historyUp(self) -> java.lang.String:
        ...

    @property
    def retention(self) -> jpype.JInt:
        ...

    @retention.setter
    def retention(self, value: jpype.JInt):
        ...



__all__ = ["AnsiRenderer", "InterpreterPanel", "AnsiParser", "InterpreterPanelService", "InterpreterPanelPlugin", "CodeCompletionListModel", "CompletionWindowTrigger", "CodeCompletionWindow", "InterpreterConsole", "HistoryManagerImpl", "CodeCompletionListSelectionModel", "InterpreterComponentProvider", "InterpreterConnection", "CodeCompletionListCellRenderer", "HistoryManager"]
