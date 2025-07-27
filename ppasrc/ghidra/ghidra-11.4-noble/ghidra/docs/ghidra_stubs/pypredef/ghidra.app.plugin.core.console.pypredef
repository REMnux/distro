from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.services
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


@typing.type_check_only
class ConsoleWriter(java.io.Writer):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ConsolePlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class CodeCompletion(java.lang.Comparable[CodeCompletion]):
    """
    This class encapsulates a code completion.
     
    It is intended to be used by the code completion process, especially the
    CodeCompletionWindow.  It encapsulates:
     
    *  a description of the completion (what are you completing?)
    *  the actual String that will be inserted
    *  an optional Component that will be in the completion List
    *  the number of characters to remove before the insertion of the completion
    
     
    
    For example, if one wants to autocomplete a string "Runscr" into "runScript", 
    the fields may look as follows:
     
    *  description: "runScript (Method)"
    *  insertion: "runScript"
    *  component: null or JLabel("runScript (Method)")
    *  charsToRemove: 6 (i.e. the length of "Runscr", 
    as it may be required later to correctly replace the string)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, description: typing.Union[java.lang.String, str], insertion: typing.Union[java.lang.String, str], comp: javax.swing.JComponent):
        """
        Construct a new CodeCompletion.
        
        :param java.lang.String or str description: description of this completion
        :param java.lang.String or str insertion: what will be inserted (or null)
        :param javax.swing.JComponent comp: (optional) Component to appear in completion List (or null)
        """

    @typing.overload
    def __init__(self, description: typing.Union[java.lang.String, str], insertion: typing.Union[java.lang.String, str], comp: javax.swing.JComponent, charsToRemove: typing.Union[jpype.JInt, int]):
        """
        Construct a new CodeCompletion.
        
        :param java.lang.String or str description: description of this completion
        :param java.lang.String or str insertion: what will be inserted (or null)
        :param javax.swing.JComponent comp: (optional) Component to appear in completion List (or null)
        :param jpype.JInt or int charsToRemove: the number of characters that should be removed before the insertion
        """

    def compareTo(self, that: CodeCompletion) -> int:
        ...

    def getCharsToRemove(self) -> int:
        """
        Returns the number of characters to remove from the input before the insertion
        of the code completion
        
        :return: the number of characters to remove
        :rtype: int
        """

    def getComponent(self) -> javax.swing.JComponent:
        """
        Returns the Component to display in the completion list
        
        :return: the Component to display in the completion list
        :rtype: javax.swing.JComponent
        """

    def getDescription(self) -> str:
        """
        Returns the description of this CodeCompletion.
         
        Typically this is what you are trying to complete.
        
        :return: the description of this CodeCompletion
        :rtype: str
        """

    def getInsertion(self) -> str:
        """
        Returns the text to insert to complete the code.
        
        :return: the text to insert to complete the code
        :rtype: str
        """

    @staticmethod
    def isValid(completion: CodeCompletion) -> bool:
        """
        Returns true if the given CodeCompletion actually would insert something.
        
        :param CodeCompletion completion: a CodeCompletion
        :return: true if the given CodeCompletion actually would insert something
        :rtype: bool
        """

    def toString(self) -> str:
        """
        Returns a String representation of this CodeCompletion.
        
        :return: a String representation of this CodeCompletion
        :rtype: str
        """

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def insertion(self) -> java.lang.String:
        ...

    @property
    def charsToRemove(self) -> jpype.JInt:
        ...


class ConsoleComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.app.services.ConsoleService):

    @typing.type_check_only
    class GoToMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CursorUpdateMouseMotionListener(java.awt.event.MouseMotionAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]):
        ...

    def setCurrentAddress(self, address: ghidra.program.model.address.Address):
        ...

    def setCurrentProgram(self, program: ghidra.program.model.listing.Program):
        ...


@typing.type_check_only
class ConsoleWord(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    word: typing.Final[java.lang.String]
    startPosition: typing.Final[jpype.JInt]
    endPosition: typing.Final[jpype.JInt]



__all__ = ["ConsoleWriter", "ConsolePlugin", "CodeCompletion", "ConsoleComponentProvider", "ConsoleWord"]
