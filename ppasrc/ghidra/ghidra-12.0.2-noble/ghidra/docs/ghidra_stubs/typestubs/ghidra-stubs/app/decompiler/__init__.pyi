from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.concurrent
import ghidra.app.decompiler.component
import ghidra.app.decompiler.component.margin
import ghidra.app.decompiler.signature
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.stream # type: ignore


class DecompilerHighlightService(java.lang.Object):
    """
    A service that allows clients to create highlights in the form of background colors for
    :obj:`ClangToken`s in the Decompiler UI.
     
     
    Note: highlights apply to a full token and not strings of text.  To highlight a token, you
    create an instance of the :obj:`CTokenHighlightMatcher` to pass to one of the
    :meth:`createHighlighter(String, CTokenHighlightMatcher) <.createHighlighter>` methods of this interface.
     
     
    There is no limit to the number of highlighters that may be installed.  If multiple
    highlights overlap, then their colors will be blended.  The number of color blends may be limited
    for performance reasons.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def createHighlighter(self, tm: CTokenHighlightMatcher) -> DecompilerHighlighter:
        """
        Creates a highlighter that will use the given matcher to create highlights as functions
        get decompiled.  The highlighter created will be applied to every decompiled function.
        
        :param CTokenHighlightMatcher tm: the matcher
        :return: the new highlighter
        :rtype: DecompilerHighlighter
        """

    @typing.overload
    def createHighlighter(self, function: ghidra.program.model.listing.Function, tm: CTokenHighlightMatcher) -> DecompilerHighlighter:
        """
        Creates a highlighter that will use the given matcher to create highlights as functions
        get decompiled.  The highlighter created will only be applied to the given function.
        
        :param ghidra.program.model.listing.Function function: the function to which the highlighter will be applied
        :param CTokenHighlightMatcher tm: the matcher
        :return: the new highlighter
        :rtype: DecompilerHighlighter
        
        .. seealso::
        
            | :obj:`.createHighlighter(CTokenHighlightMatcher)`for global highlights
        """

    @typing.overload
    def createHighlighter(self, id: typing.Union[java.lang.String, str], tm: CTokenHighlightMatcher) -> DecompilerHighlighter:
        """
        A version of :meth:`createHighlighter(String, CTokenHighlightMatcher) <.createHighlighter>` that allows clients
        to specify an ID.  This ID will be used to ensure that any existing highlighters with that
        ID will be removed before creating a new highlighter.  The highlighter created will be 
        applied to every decompiled function.  
         
         
        This method is convenient for scripts, since a script cannot hold on to any created
        highlighters between repeated script executions.   A good value for script writers to use
        is the name of their script class.
        
        :param java.lang.String or str id: the ID
        :param CTokenHighlightMatcher tm: the matcher
        :return: the new highlighter
        :rtype: DecompilerHighlighter
        """

    @typing.overload
    def createHighlighter(self, id: typing.Union[java.lang.String, str], function: ghidra.program.model.listing.Function, tm: CTokenHighlightMatcher) -> DecompilerHighlighter:
        """
        A version of :meth:`createHighlighter(String, CTokenHighlightMatcher) <.createHighlighter>` that allows clients
        to specify an ID.  This ID will be used to ensure that any existing highlighters with that
        ID will be removed before creating a new highlighter.  The highlighter created will only be 
        applied to the given function.  
         
         
        This method is convenient for scripts, since a script cannot hold on to any created
        highlighters between repeated script executions.   A good value for script writers to use
        is the name of their script class.
        
        :param java.lang.String or str id: the ID
        :param ghidra.program.model.listing.Function function: the function to which the highlighter will be applied
        :param CTokenHighlightMatcher tm: the matcher
        :return: the new highlighter
        :rtype: DecompilerHighlighter
        """


class DecompilerDisposer(java.lang.Object):

    @typing.type_check_only
    class DisposeCallback(generic.concurrent.QCallback[DecompilerDisposer.AbstractDisposable, DecompilerDisposer.AbstractDisposable]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AbstractDisposable(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RuntimeProcessDisposable(DecompilerDisposer.AbstractDisposable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DecompInterfaceDisposable(DecompilerDisposer.AbstractDisposable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def dispose(process: java.lang.Process, ouputStream: java.io.OutputStream, inputStream: java.io.InputStream):
        """
        Disposes the given Process and related streams from a background thread.  This is necessary
        due to a low-probability deadlock that occurs in the JVM.
        
        :param java.lang.Process process: The process to destroy.
        :param java.io.OutputStream ouputStream: The output stream to close
        :param java.io.InputStream inputStream: The input stream to close
        """

    @staticmethod
    @typing.overload
    def dispose(decompiler: DecompInterface):
        """
        Calls dispose in the given decompiler from a background thread.
         
        
        Note:
        
        A class to handle the rare case where the :obj:`DecompInterface`'s
        synchronized methods are blocking
        while a decompile operation has died and maintained the lock.  In that scenario, calling
        dispose on this class will eventually try to enter a synchronized method that will
        remain blocked forever.
         
        
        I examined the uses of dispose() on the :obj:`DecompInterface` and
        determined that calling dispose() is a
        final operation, which means that you don't have to wait.  Further, after calling
        dispose() on this class, you should no longer use it.
        
        :param DecompInterface decompiler: the decompiler
        """


class DecompiledFunction(java.lang.Object):
    """
    A class to hold pieces of a decompiled function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, signature: typing.Union[java.lang.String, str], c: typing.Union[java.lang.String, str]):
        """
        Constructs a new decompiled function.
        
        :param java.lang.String or str signature: the function signature or prototype (eg, "int foo(double d)")
        :param java.lang.String or str c: the complete C code of the function.
        """

    def getC(self) -> str:
        """
        Returns the complete C code of the function.
        
        :return: the complete C code of the function
        :rtype: str
        """

    def getSignature(self) -> str:
        """
        Returns the function signature or prototype (eg, "int foo(double d)").
        
        :return: the function signature or prototype (eg, "int foo(double d)")
        :rtype: str
        """

    @property
    def c(self) -> java.lang.String:
        ...

    @property
    def signature(self) -> java.lang.String:
        ...


class ClangReturnType(ClangTokenGroup):
    """
    A grouping of source code tokens representing the "return type" of a function,
    as at the beginning of a function prototype.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        :return: the data-type represented by this text
        :rtype: ghidra.program.model.data.DataType
        """

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        
        
        :return: a Varnode representing the return value in the function's data-flow
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...


class ClangSyntaxToken(ClangToken):
    """
    A source code token which is not an operation, variable, function name, or type. Like '(' or ','.
    A SyntaxToken may be or may include spacing.  As a special case, the token can be part of
    an enclosing pair of tokens, as with '(' and ')' or '{' and '}'. In this case, the token
    is either opening or closing and contains an id that matches it with its pair token.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, par: ClangNode):
        ...

    @typing.overload
    def __init__(self, par: ClangNode, txt: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, par: ClangNode, txt: typing.Union[java.lang.String, str], color: typing.Union[jpype.JInt, int]):
        ...

    def getClose(self) -> int:
        """
        
        
        :return: the pair id if this is a closing token, -1 otherwise
        :rtype: int
        """

    def getOpen(self) -> int:
        """
        
        
        :return: the pair id if this is an opening token, -1 otherwise
        :rtype: int
        """

    @property
    def close(self) -> jpype.JInt:
        ...

    @property
    def open(self) -> jpype.JInt:
        ...


class DecompilerLocationInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entryPoint: ghidra.program.model.address.Address, results: DecompileResults, token: ClangToken, lineNumber: typing.Union[jpype.JInt, int], charPos: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        """
        Default constructor required for restoring a program location from XML.
        """

    def getCharPos(self) -> int:
        ...

    def getDecompile(self) -> DecompileResults:
        """
        Results from the decompilation
        
        :return: C-AST, DFG, and CFG object. null if there are no results attached to this location
        :rtype: DecompileResults
        """

    def getFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...

    def getLineNumber(self) -> int:
        ...

    def getToken(self) -> ClangToken:
        """
        C text token at the current cursor location
        
        :return: token at this location, could be null if there are no decompiler results
        :rtype: ClangToken
        """

    def getTokenName(self) -> str:
        ...

    def restoreState(self, program1: ghidra.program.model.listing.Program, obj: ghidra.framework.options.SaveState):
        ...

    def saveState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def charPos(self) -> jpype.JInt:
        ...

    @property
    def tokenName(self) -> java.lang.String:
        ...

    @property
    def decompile(self) -> DecompileResults:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def functionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def token(self) -> ClangToken:
        ...


class DecompileException(java.lang.Exception):
    """
    An exception from (or that has passed through) the decompiler process
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, type: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str]):
        ...


class DecompileResults(java.lang.Object):
    """
    Class for getting at the various structures returned
    by the decompiler.  Depending on how the DecompInterface
    was called, you can get C code (with markup), the
    function' syntax tree, the prototype, etc.
     
    To check if the decompileFunction call completed normally
    use the decompileCompleted method.  If this returns false,
    the getErrorMessage method may contain a useful error
    message.  Its also possible that getErrorMessage will
    return warning messages, even if decompileFunction did
    complete.
     
    To get the resulting C code, marked up with XML in terms
    of the lines and tokens, use the getCCodeMarkup method.
     
    To get the resulting C code just as a straight String,
    use the getDecompiledFunction method which returns a
    DecompiledFunction.  Off of this, you can use the getC
    method to get the raw C code as a String or use the
    getSignature method to get the functions prototype as
    a String.
     
    To get the syntax tree use the getHighFunction method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, f: ghidra.program.model.listing.Function, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, d: ghidra.program.model.pcode.PcodeDataTypeManager, e: typing.Union[java.lang.String, str], decoder: ghidra.program.model.pcode.Decoder, processState: DecompileProcess.DisposeState):
        ...

    def decompileCompleted(self) -> bool:
        """
        Returns true if the decompilation producing these
        results completed without aborting.  If it was
        aborted, there will be no real results in this
        object, and an error message should be available via
        getErrorMessage.
        
        :return: true if the decompilation completed.
        :rtype: bool
        """

    def failedToStart(self) -> bool:
        """
        If the action producing this set of decompiler results
        didn't complete, this method can be used to determine
        if the decompiler executable was not found or failed to start properly.
        
        :return: true if the decompiler executable was not found.
        :rtype: bool
        """

    def getCCodeMarkup(self) -> ClangTokenGroup:
        """
        Get the marked up C code associated with these
        decompilation results. If there was an error, or
        code generation was turned off, return null
        
        :return: the resulting root of C markup
        :rtype: ClangTokenGroup
        """

    def getDecompiledFunction(self) -> DecompiledFunction:
        """
        Converts the C code results into an unadorned string.
        The returned object contains both the whole function
        and just the prototype as separate strings containing
        raw C code
        
        :return: a DecompiledFunction object
        :rtype: DecompiledFunction
        """

    def getErrorMessage(self) -> str:
        """
        Return any error message associated with the
        decompilation producing these results.  Generally,
        there will only be an error if the decompilation was
        aborted for some reason, but there could conceivably
        be warnings obtainable via this method, even if the
        decompilation did complete.
        
        :return: any error message associated with these results
        :rtype: str
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        """
        Get the high-level function structure associated
        with these decompilation results, or null if there
        was an error during decompilation
        
        :return: the resulting HighFunction object
        :rtype: ghidra.program.model.pcode.HighFunction
        """

    def getHighParamID(self) -> ghidra.program.model.pcode.HighParamID:
        """
        Get the high-level function structure associated
        with these decompilation results, or null if there
        was an error during decompilation
        
        :return: the resulting HighParamID object
        :rtype: ghidra.program.model.pcode.HighParamID
        """

    def isCancelled(self) -> bool:
        """
        If the action producing this set of decompiler results
        didn't complete, this method can be used to determine
        if the action was explicitly cancelled (as opposed
        to an error, a timeout, or a crash).
        
        :return: true if these results were explicitly cancelled
        :rtype: bool
        """

    def isTimedOut(self) -> bool:
        """
        If the action producing this set of decompiler results
        didn't complete, this method can be used to determine
        if the action was halted because its timer expired
        (as opposed to an error, a crash, or being explicitly
        cancelled).
        
        :return: true if the timer cancelled these results
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        Returns true if the decompile completed normally
        
        :return: true if the decompile completed normally
        :rtype: bool
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def highParamID(self) -> ghidra.program.model.pcode.HighParamID:
        ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...

    @property
    def timedOut(self) -> jpype.JBoolean:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def cCodeMarkup(self) -> ClangTokenGroup:
        ...

    @property
    def decompiledFunction(self) -> DecompiledFunction:
        ...


class ClangVariableToken(ClangToken):
    """
    Token representing a C variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...


class ClangLine(java.lang.Object):
    """
    A line of C code. This is an independent grouping
    of C tokens from the statement, vardecl retype groups
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lineNumber: typing.Union[jpype.JInt, int], indent: typing.Union[jpype.JInt, int]):
        ...

    def addToken(self, tok: ClangToken):
        ...

    def getAllTokens(self) -> java.util.List[ClangToken]:
        ...

    def getIndent(self) -> int:
        ...

    def getIndentString(self) -> str:
        ...

    def getLineNumber(self) -> int:
        ...

    def getNumTokens(self) -> int:
        ...

    def getToken(self, i: typing.Union[jpype.JInt, int]) -> ClangToken:
        ...

    def indexOfToken(self, token: ClangToken) -> int:
        ...

    @typing.overload
    def toDebugString(self, calloutTokens: java.util.List[ClangToken]) -> str:
        ...

    @typing.overload
    def toDebugString(self, calloutTokens: java.util.List[ClangToken], start: typing.Union[java.lang.String, str], end: typing.Union[java.lang.String, str]) -> str:
        ...

    @property
    def indent(self) -> jpype.JInt:
        ...

    @property
    def allTokens(self) -> java.util.List[ClangToken]:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def numTokens(self) -> jpype.JInt:
        ...

    @property
    def indentString(self) -> java.lang.String:
        ...

    @property
    def token(self) -> ClangToken:
        ...


class ClangFuncProto(ClangTokenGroup):
    """
    A grouping of source code tokens representing a function prototype
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...


class ClangCommentToken(ClangToken):
    """
    A token in source code representing (part of) a comment.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...

    @staticmethod
    def derive(source: ClangCommentToken, text: typing.Union[java.lang.String, str]) -> ClangCommentToken:
        ...


class ClangFuncNameToken(ClangToken):
    """
    A source code token representing a function name.
    It contains a link back to the p-code function object represented by the name
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode, hf: ghidra.program.model.pcode.HighFunction):
        ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        """
        
        
        :return: the HighFunction object associated with this name
        :rtype: ghidra.program.model.pcode.HighFunction
        """

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...


class TokenIterator(java.util.Iterator[ClangToken]):
    """
    An iterator over ClangToken objects.  The iterator walks a tree of ClangNode objects based on
    the Parent() and Child() methods, returning successive ClangNode leaf objects that are also
    ClangToken objects.  The iterator can run either forward or backward over the tokens.
     
    The constructor TokenIterator(ClangToken,int) initializes the iterator to start at the given
    token, which can be in the middle of the sequence.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, token: ClangToken, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Initialize an iterator to a point to a specific ClangToken, which may be anywhere in the sequence.
        
        :param ClangToken token: is the specific ClangToken
        :param jpype.JBoolean or bool forward: is true for a forward iterator, false for a backward iterator
        """

    @typing.overload
    def __init__(self, group: ClangTokenGroup, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Create iterator across all tokens under the given ClangTokenGroup.  The iterator will walk the
        entire tree of token groups under the given group.  The iterator will run over tokens in display
        order (forward=true) or in reverse of display order (forward=false)
        
        :param ClangTokenGroup group: is the given ClangTokenGroup
        :param jpype.JBoolean or bool forward: is true for a forward iterator, false for a backward iterator
        """


class ClangMarkup(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def buildClangTree(decoder: ghidra.program.model.pcode.Decoder, hfunc: ghidra.program.model.pcode.HighFunction) -> ClangTokenGroup:
        ...


class PrettyPrinter(java.lang.Object):
    """
    This class is used to convert a C/C++ language token group into readable C/C++ code.
    """

    class_: typing.ClassVar[java.lang.Class]
    INDENT_STRING: typing.Final = " "

    def __init__(self, function: ghidra.program.model.listing.Function, tokgroup: ClangTokenGroup, transformer: ghidra.program.model.symbol.NameTransformer):
        """
        Constructs a new pretty printer using the specified C language token group.
        The printer takes a NameTransformer that will be applied to symbols, which can replace
        illegal characters in the symbol name for instance. A null indicates no transform is applied.
        
        :param ghidra.program.model.listing.Function function: is the function to be printed
        :param ClangTokenGroup tokgroup: the C language token group
        :param ghidra.program.model.symbol.NameTransformer transformer: the transformer to apply to symbols
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        ...

    def getLines(self) -> java.util.List[ClangLine]:
        """
        Returns a list of the C language lines contained in the C language token group.
        
        :return: a list of the C language lines
        :rtype: java.util.List[ClangLine]
        """

    @staticmethod
    def getText(line: ClangLine) -> str:
        """
        Returns the text of the given line as seen in the UI.
        
        :param ClangLine line: the line
        :return: the text
        :rtype: str
        """

    def print(self) -> DecompiledFunction:
        """
        Prints the C language token group into a string of C code.
        
        :return: a string of readable C code
        :rtype: DecompiledFunction
        """

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def lines(self) -> java.util.List[ClangLine]:
        ...


class DecompileProcessFactory(java.lang.Object):
    """
    Factory that returns a DecompileProcess.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def get() -> DecompileProcess:
        ...

    @staticmethod
    def release(dp: DecompileProcess):
        ...


class DecompileDebug(java.lang.Object):
    """
    A container for collecting communication between the decompiler and the Ghidra database,
    as serviced through DecompileCallback during decompilation of a function.
    The query results can then be dumped as an XML document.
    The container is populated through methods that mirror the various methods in DecompileCallback.
    """

    @typing.type_check_only
    class ByteChunk(java.lang.Comparable[DecompileDebug.ByteChunk]):

        class_: typing.ClassVar[java.lang.Class]
        addr: ghidra.program.model.address.Address
        min: jpype.JInt
        max: jpype.JInt
        val: jpype.JArray[jpype.JByte]

        def __init__(self, ad: ghidra.program.model.address.Address, off: typing.Union[jpype.JInt, int], v: jpype.JArray[jpype.JByte]):
            ...

        def merge(self, op2: DecompileDebug.ByteChunk):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, debugf: jpype.protocol.SupportsPath):
        ...

    def addFlowOverride(self, addr: ghidra.program.model.address.Address, fo: ghidra.program.model.listing.FlowOverride):
        ...

    def addInject(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], injectType: typing.Union[jpype.JInt, int], payload: typing.Union[java.lang.String, str]):
        ...

    def addPossiblePrototypeExtension(self, testFunc: ghidra.program.model.listing.Function):
        ...

    def getBytes(self, addr: ghidra.program.model.address.Address, res: jpype.JArray[jpype.JByte]):
        ...

    def getCPoolRef(self, rec: typing.Union[java.lang.String, str], refs: jpype.JArray[jpype.JLong]):
        ...

    def getCodeSymbol(self, addr: ghidra.program.model.address.Address, id: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getComments(self, comm: typing.Union[java.lang.String, str]):
        ...

    def getFNTypes(self, hfunc: ghidra.program.model.pcode.HighFunction):
        ...

    def getMapped(self, namespc: ghidra.program.model.symbol.Namespace, res: typing.Union[java.lang.String, str]):
        ...

    def getNamespacePath(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    def getPcode(self, addr: ghidra.program.model.address.Address, instr: ghidra.program.model.listing.Instruction):
        ...

    def getStringData(self, addr: ghidra.program.model.address.Address, stringData: DecompileCallback.StringData):
        ...

    def getTrackedRegisters(self, doc: typing.Union[java.lang.String, str]):
        ...

    def getType(self, dt: ghidra.program.model.data.DataType):
        ...

    def nameIsUsed(self, spc: ghidra.program.model.symbol.Namespace, nm: typing.Union[java.lang.String, str]):
        ...

    def setFunction(self, f: ghidra.program.model.listing.Function):
        ...

    def setPcodeDataTypeManager(self, dtm: ghidra.program.model.pcode.PcodeDataTypeManager):
        ...

    def shutdown(self, pcodelanguage: ghidra.program.model.lang.Language, xmlOptions: typing.Union[java.lang.String, str]):
        ...


class ClangBreak(ClangToken):
    """
    A line break in source code plus the indenting for the following line.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, par: ClangNode):
        ...

    @typing.overload
    def __init__(self, par: ClangNode, indent: typing.Union[jpype.JInt, int]):
        ...

    def getIndent(self) -> int:
        """
        
        
        :return: the number of indent levels following this line break
        :rtype: int
        """

    @property
    def indent(self) -> jpype.JInt:
        ...


class ClangTypeToken(ClangToken):
    """
    A source code token representing a data-type. This does not include qualifiers on the data-type
    like '*' (pointer to) or '[]' (array of). There should be no whitespace in the name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        :return: the data-type associated with this token
        :rtype: ghidra.program.model.data.DataType
        """

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...


class ClangNode(java.lang.Object):
    """
    A collection of source code text elements, with associated attributes, grouped in
    a tree structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def Child(self, i: typing.Union[jpype.JInt, int]) -> ClangNode:
        """
        Get the i-th child grouping
        
        :param jpype.JInt or int i: is the index selecting the grouping
        :return: the selected grouping
        :rtype: ClangNode
        """

    def Parent(self) -> ClangNode:
        """
        Get the immediate grouping (parent) containing this text element. If this is a
        complete document, null is returned.
        
        :return: the parent grouping or null
        :rtype: ClangNode
        """

    def flatten(self, list: java.util.List[ClangNode]):
        """
        Flatten this text into a list of tokens (see ClangToken)
        
        :param java.util.List[ClangNode] list: is the container that will contain the tokens
        """

    def getClangFunction(self) -> ClangFunction:
        """
        Get the text representing an entire function of which this is part.
        
        :return: text for the whole function
        :rtype: ClangFunction
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the biggest Program address associated with the code that this text represents
        
        :return: the biggest Address
        :rtype: ghidra.program.model.address.Address
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the smallest Program address associated with the code that this text represents
        
        :return: the smallest Address
        :rtype: ghidra.program.model.address.Address
        """

    def numChildren(self) -> int:
        """
        Return the number of immediate groupings this text breaks up into
        
        :return: the number of child groupings
        :rtype: int
        """

    def setHighlight(self, c: java.awt.Color):
        """
        Set a highlighting background color for all text elements
        
        :param java.awt.Color c: is the color to set
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def clangFunction(self) -> ClangFunction:
        ...


class ClangFieldToken(ClangToken):
    """
    A source code token representing a structure field.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        :return: the structure datatype associated with this field token
        :rtype: ghidra.program.model.data.DataType
        """

    def getOffset(self) -> int:
        """
        
        
        :return: the byte offset of this field with its structure
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...


class ClangVariableDecl(ClangTokenGroup):
    """
    A grouping of source code tokens representing a variable declaration.
    This can be for a one line declaration (as for local variables) or
    as part of a function prototype declaring a parameter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        :return: the data-type of the variable being declared
        :rtype: ghidra.program.model.data.DataType
        """

    def getHighSymbol(self) -> ghidra.program.model.pcode.HighSymbol:
        """
        
        
        :return: the symbol defined by this variable declaration
        :rtype: ghidra.program.model.pcode.HighSymbol
        """

    def getHighVariable(self) -> ghidra.program.model.pcode.HighVariable:
        """
        
        
        :return: the HighVariable (collection of Varnodes) associated with the variable
        :rtype: ghidra.program.model.pcode.HighVariable
        """

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def highSymbol(self) -> ghidra.program.model.pcode.HighSymbol:
        ...

    @property
    def highVariable(self) -> ghidra.program.model.pcode.HighVariable:
        ...


class DecompilerHighlighter(java.lang.Object):
    """
    The highlighter interface passed to clients of the :obj:`DecompilerHighlightService`.
    
     
    The expected workflow for this class is:  create the highlighter, clients
    will request highlights via :meth:`applyHighlights() <.applyHighlights>`, clients will clear highlights via
    :meth:`clearHighlights() <.clearHighlights>` and the highlighter may be removed via :meth:`dispose() <.dispose>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def applyHighlights(self):
        """
        Call this method when you wish to apply your highlights.
        """

    def clearHighlights(self):
        """
        Call this method when you wish to remove your highlights.
        """

    def dispose(self):
        """
        Call this method to remove your highlighter from the Decompiler.
        """

    def getId(self) -> str:
        """
        Returns the ID used by this highlighter.  This will either be generated by this API or
        supplied by the client.
        
        :return: the ID
        :rtype: str
        
        .. seealso::
        
            | :obj:`DecompilerHighlightService.createHighlighter(String, CTokenHighlightMatcher)`
        """

    @property
    def id(self) -> java.lang.String:
        ...


class DecompileProcess(java.lang.Object):
    """
    Class for communicating with a single decompiler process.
    The process controls decompilation for a single Program.
    The process is initiated by the registerProgram method.
    If the process is ready, the statusGood flag will be set
    to true.  This flag must be checked via the isReady method
    prior to invoking any of the public methods.  If the
    process isn't ready, the only way to recover is by
    reissuing the registerProgram call and making any other
    necessary initialization calls.
    """

    class DisposeState(java.lang.Enum[DecompileProcess.DisposeState]):

        class_: typing.ClassVar[java.lang.Class]
        NOT_DISPOSED: typing.Final[DecompileProcess.DisposeState]
        DISPOSED_ON_TIMEOUT: typing.Final[DecompileProcess.DisposeState]
        DISPOSED_ON_CANCEL: typing.Final[DecompileProcess.DisposeState]
        DISPOSED_ON_STARTUP_FAILURE: typing.Final[DecompileProcess.DisposeState]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DecompileProcess.DisposeState:
            ...

        @staticmethod
        def values() -> jpype.JArray[DecompileProcess.DisposeState]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: typing.Union[java.lang.String, str]):
        ...

    def deregisterProgram(self) -> int:
        """
        Free decompiler resources
        
        :return: 1 if a program was actively deregistered, 0 otherwise
        :rtype: int
        :raises IOException: for problems with the pipe to the decompiler
        :raises DecompileException: for problems executing the command
        """

    def dispose(self):
        ...

    def getDisposeState(self) -> DecompileProcess.DisposeState:
        ...

    def isReady(self) -> bool:
        ...

    def registerProgram(self, cback: DecompileCallback, pspecxml: typing.Union[java.lang.String, str], cspecxml: typing.Union[java.lang.String, str], tspecxml: typing.Union[java.lang.String, str], coretypesxml: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program):
        """
        Initialize decompiler for a particular platform
        
        :param DecompileCallback cback: = callback object for decompiler
        :param java.lang.String or str pspecxml: = string containing .pspec xml
        :param java.lang.String or str cspecxml: = string containing .cspec xml
        :param java.lang.String or str tspecxml: = XML string containing translator spec
        :param java.lang.String or str coretypesxml: = XML description of core data-types
        :param ghidra.program.model.listing.Program program: is the program being registered
        :raises IOException: for problems with the pipe to the decompiler process
        :raises DecompileException: for problems executing the command
        """

    def sendCommand(self, command: typing.Union[java.lang.String, str], response: ghidra.program.model.pcode.ByteIngest):
        """
        Send a single command to the decompiler with no parameters and return response
        
        :param java.lang.String or str command: is the name of the command to execute
        :param ghidra.program.model.pcode.ByteIngest response: the response accumulator
        :raises IOException: for any problems with the pipe to the decompiler process
        :raises DecompileException: for any problems executing the command
        """

    @typing.overload
    def sendCommand1Param(self, command: typing.Union[java.lang.String, str], param1: ghidra.program.model.pcode.CachedEncoder, response: ghidra.program.model.pcode.ByteIngest):
        """
        Send a command to the decompiler with one parameter and return the result
        
        :param java.lang.String or str command: is the command string
        :param ghidra.program.model.pcode.CachedEncoder param1: is the encoded parameter
        :param ghidra.program.model.pcode.ByteIngest response: is the result accumulator
        :raises IOException: for problems with the pipe to the decompiler process
        :raises DecompileException: for problems executing the command
        """

    @typing.overload
    def sendCommand1Param(self, command: typing.Union[java.lang.String, str], param1: typing.Union[java.lang.String, str], response: ghidra.program.model.pcode.ByteIngest):
        """
        Send a command to the decompiler with one parameter and return the result
        
        :param java.lang.String or str command: is the command string
        :param java.lang.String or str param1: is the parameter encoded as a string
        :param ghidra.program.model.pcode.ByteIngest response: is the result accumulator
        :raises IOException: for problems with the pipe to the decompiler process
        :raises DecompileException: for problems executing the command
        """

    def sendCommand2Params(self, command: typing.Union[java.lang.String, str], param1: typing.Union[java.lang.String, str], param2: typing.Union[java.lang.String, str], response: ghidra.program.model.pcode.ByteIngest):
        """
        Send a command with 2 parameters to the decompiler and read the result
        
        :param java.lang.String or str command: string to send
        :param java.lang.String or str param1: is the first parameter string
        :param java.lang.String or str param2: is the second parameter string
        :param ghidra.program.model.pcode.ByteIngest response: the response accumulator
        :raises IOException: for any problems with the pipe to the decompiler process
        :raises DecompileException: for problems executing the command
        """

    def sendCommandTimeout(self, command: typing.Union[java.lang.String, str], timeoutSecs: typing.Union[jpype.JInt, int], encodeSet: DecompInterface.EncodeDecodeSet):
        """
        Execute a command with a timeout.  Parameters are in the encodingSet.mainQuery.
        The response gets written to encodingSet.mainResponse.
        
        :param java.lang.String or str command: the decompiler should execute
        :param jpype.JInt or int timeoutSecs: the number of seconds to run before timing out
        :param DecompInterface.EncodeDecodeSet encodeSet: contains encoded parameters and the response container
        :raises IOException: for any problems with the pipe to the decompiler process
        :raises DecompileException: for any problems while executing the command
        """

    def setMaxResultSize(self, maxResultSizeMBytes: typing.Union[jpype.JInt, int]):
        """
        Set an upper limit on the amount of data that can be sent back by the decompiler in response
        to a single command.
        
        :param jpype.JInt or int maxResultSizeMBytes: is the maximum size in megabytes
        """

    @property
    def disposeState(self) -> DecompileProcess.DisposeState:
        ...

    @property
    def ready(self) -> jpype.JBoolean:
        ...


class ClangLabelToken(ClangToken):
    """
    A source code token representing a control-flow label.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...


class ClangStatement(ClangTokenGroup):
    """
    A source code statement (as typically terminated by ';' in C)
    A statement must have a p-code operation associated with it. In the case of conditional
    flow control operations, there are usually two lines associated with the statement one
    containing the '{' and one containing '}'. The one containing the actual conditional branch
    is considered a C statement, while the other one is just considered a blank line.
    I.e.
        if (expression) {
    is a C statement, while the line containing the closing '}' by itself is considered blank
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...

    def getPcodeOp(self) -> ghidra.program.model.pcode.PcodeOp:
        """
        
        
        :return: the (final) p-code operation associated with the statement.
        :rtype: ghidra.program.model.pcode.PcodeOp
        """

    @property
    def pcodeOp(self) -> ghidra.program.model.pcode.PcodeOp:
        ...


class DecompInterface(java.lang.Object):
    """
    This is a self-contained interface to a single decompile
    process, suitable for an open-ended number of function
    decompilations for a single program. The interface is
    persistent. It caches all the initialization data passed
    to it, and if the underlying decompiler process crashes,
    it automatically respawns the process and reinitializes
    it the next time it is needed.  The basic usage pattern
    is as follows
     
    // Instantiate the interface
    DecompInterface ifc = new DecompInterface();
       
    // Setup any options or other initialization
    ifc.setOptions(options); // Inform interface of global options
    // ifc.toggleSyntaxTree(false);  // Don't produce syntax trees
    // ifc.toggleCCode(false);       // Don't produce C code
    // ifc.setSimplificationStyle("normalize"); // Alternate analysis style
       
    // Setup up the actual decompiler process for a
    // particular program, using all the above initialization
    ifc.openProgram(program);
       
    // Make calls to the decompiler:
    DecompileResults res = ifc.decompileFunction(func,0,taskmonitor);
       
    // Check for error conditions
    if (!res.decompileCompleted()) {
        system.out.println(res.getErrorMessage());
        return;
    }
       
    // Make use of results
        // Get C code
    ClangTokenGroup tokgroup = res.getCCodeMarkup();
    ...  
        // Get the function object/syntax tree
    HighFunction hfunc = res.getHighFunction();
    ...
    """

    class EncodeDecodeSet(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        overlay: ghidra.program.model.address.OverlayAddressSpace
        mainQuery: ghidra.program.model.pcode.CachedEncoder
        mainResponse: ghidra.program.model.pcode.PackedDecode
        callbackQuery: ghidra.program.model.pcode.PackedDecode
        callbackResponse: ghidra.program.model.pcode.PatchPackedEncode

        @typing.overload
        def __init__(self, program: ghidra.program.model.listing.Program):
            """
            Set up encoders and decoders for functions that are not in overlay address spaces
            
            :param ghidra.program.model.listing.Program program: is the active Program
            """

        @typing.overload
        def __init__(self, program: ghidra.program.model.listing.Program, spc: ghidra.program.model.address.OverlayAddressSpace):
            """
            Set up encoders and decoders for functions in an overlay space
            
            :param ghidra.program.model.listing.Program program: is the active Program
            :param ghidra.program.model.address.OverlayAddressSpace spc: is the initial overlay space to set up for
            :raises AddressFormatException: if address translation is not supported for the overlay
            """

        def setOverlay(self, spc: ghidra.program.model.address.OverlayAddressSpace):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def closeProgram(self):
        """
        Shutdown any existing decompiler process and free
        resources.  The interface cannot be used again
        to perform decompilations until an openProgram call
        is made again.
        """

    def debugEnabled(self) -> bool:
        """
        
        
        :return: true if debug has been enabled for the current/next decompilation.
        :rtype: bool
        """

    def debugSignatures(self, func: ghidra.program.model.listing.Function, timeoutSecs: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> java.util.ArrayList[ghidra.app.decompiler.signature.DebugSignature]:
        """
        Generate a signature, using the current signature settings, for the given function.
        The signature is returned as a sequence of features (feature vector). Each feature
        is returned as a separate record with additional metadata describing the information
        incorporated into it.
        
        :param ghidra.program.model.listing.Function func: is the given function
        :param jpype.JInt or int timeoutSecs: is the maximum number of seconds to spend decompiling the function
        :param ghidra.util.task.TaskMonitor monitor: is the TaskMonitor
        :return: the array of feature descriptions
        :rtype: java.util.ArrayList[ghidra.app.decompiler.signature.DebugSignature]
        """

    def decompileFunction(self, func: ghidra.program.model.listing.Function, timeoutSecs: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> DecompileResults:
        """
        Decompile function
        
        :param ghidra.program.model.listing.Function func: function to be decompiled
        :param jpype.JInt or int timeoutSecs: if decompile does not complete in this time a null value
        will be returned and a timeout error set.
        :param ghidra.util.task.TaskMonitor monitor: optional task monitor which may be used to cancel decompile
        :return: decompiled function text
        :rtype: DecompileResults
        """

    def dispose(self):
        ...

    def enableDebug(self, debugfile: jpype.protocol.SupportsPath):
        """
        Turn on debugging dump for the next decompiled
        function
        
        :param jpype.protocol.SupportsPath debugfile: the file to enable debug dubp
        """

    def flushCache(self) -> int:
        """
        Tell the decompiler to clear any function and symbol
        information it gathered from the database.  Its a good
        idea to call this after any decompileFunction call,
        as the decompile process caches and reuses this kind
        of data, and there is no explicit method for keeping
        the cache in sync with the data base. Currently the
        return value has no meaning.
        
        :return: -1
        :rtype: int
        """

    def generateSignatures(self, func: ghidra.program.model.listing.Function, keepcalllist: typing.Union[jpype.JBoolean, bool], timeoutSecs: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.decompiler.signature.SignatureResult:
        """
        Generate a signature, using the current signature settings, for the given function.
        The signature is returned as a raw feature vector, :obj:`SignatureResult`.
        
        :param ghidra.program.model.listing.Function func: is the given function
        :param jpype.JBoolean or bool keepcalllist: is true if direct call addresses are collected as part of the result
        :param jpype.JInt or int timeoutSecs: is the maximum amount of time to spend decompiling the function
        :param ghidra.util.task.TaskMonitor monitor: is the TaskMonitor
        :return: the feature vector
        :rtype: ghidra.app.decompiler.signature.SignatureResult
        """

    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    def getDataTypeManager(self) -> ghidra.program.model.pcode.PcodeDataTypeManager:
        ...

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    def getLastMessage(self) -> str:
        """
        Get the last message produced by the decompiler process.
        If the message is non-null, it is probably an error
        message, but not always.  It is better to use the
        getErrorMessage method off of DecompileResults.
        
        :return: the message string or null
        :rtype: str
        """

    def getMajorVersion(self) -> int:
        """
        
        
        :return: the major version number of the decompiler
        :rtype: int
        """

    def getMinorVersion(self) -> int:
        """
        
        
        :return: the minor version number of the decompiler
        :rtype: int
        """

    def getOptions(self) -> DecompileOptions:
        """
        Get the options currently in effect for the decompiler
        
        :return: options that will be passed to the decompiler
        :rtype: DecompileOptions
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getSignatureSettings(self) -> int:
        """
        
        
        :return: the signature settings of the decompiler
        :rtype: int
        """

    def getSimplificationStyle(self) -> str:
        """
        Return the identifier for the current simplification style
        
        :return: the identifier as a String
        :rtype: str
        """

    def openProgram(self, prog: ghidra.program.model.listing.Program) -> bool:
        """
        This call initializes a new decompiler process to do
        decompilations for a new program. This method only
        needs to be called once per program.  Even if the
        underlying decompiler process crashes, the interface
        will automatically restart and reinitialize a new
        process when it needs it, and the openProgram call
        does not need to be made again. The call can be made
        multiple times, in which case, each call terminates
        the process initialized the last time and starts a
        new process
        
        :param ghidra.program.model.listing.Program prog: = the program on which to perform decompilations
        :return: true if the decompiler process is successfully initialized
        :rtype: bool
        """

    def resetDecompiler(self):
        """
        Resets the native decompiler process.  Call this method when the decompiler's view
        of a program has been invalidated, such as when a new overlay space has been added.
        """

    def setOptions(self, options: DecompileOptions) -> bool:
        """
        Set the object controlling the list of global options
        used by the decompiler. Ideally this is called once,
        before the openProgram call is made. But it can be
        used at any time, if the options change in the middle
        of a sequence of decompiles.
        If there is no change to the options, this method
        does NOT need to be called repeatedly.  Even after
        recovering from decompiler process crash, the interface
        keeps the options object around and automatically
        sends it to the new decompiler process.
        
        :param DecompileOptions options: the new (or changed) option object
        :return: true if the decompiler process accepted the new options
        :rtype: bool
        """

    def setSignatureSettings(self, value: typing.Union[jpype.JInt, int]) -> bool:
        """
        Set the desired signature generation settings.
        
        :param jpype.JInt or int value: is the new desired setting
        :return: true if the settings took effect
        :rtype: bool
        """

    def setSimplificationStyle(self, actionstring: typing.Union[java.lang.String, str]) -> bool:
        """
        This allows the application to the type of analysis
        performed by the decompiler, by giving the name of
        an analysis class. Right now, there are a few
        predefined classes. But there soon may be support
        for applications to define their own class and
        tailoring the decompiler's behaviour for that class.
         
        
        The current predefined analysis class are:
         
        * "decompile" - this is the default, and performs all
        analysis steps suitable for producing C code.
        * "normalize" - omits type recovery from the analysis
        and some of the final clean-up steps involved in
        making valid C code.  It is suitable for creating
        normalized pcode syntax trees of the dataflow.
        * "firstpass" - does no analysis, but produces an
        unmodified syntax tree of the dataflow from the
        * "register" - does ???.
        * "paramid" - does required amount of decompilation
        followed by analysis steps that send parameter
        measure information for parameter id analysis.
        raw pcode.
        
              
         
        
        This property should ideally be set once before the
        openProgram call is made, but it can be used repeatedly
        if the application needs to change analysis style in the
        middle of a sequence of decompiles.  Unless the style
        changes, the method does NOT need to be called repeatedly.
        Even after a crash, the new decompiler process will
        automatically configured with the cached style value.
        
        :param java.lang.String or str actionstring: "decompile"|"normalize"|"register"|"firstpass"|"paramid"
        :return: true - if the decompiler process was successfully configured
        :rtype: bool
        """

    def stopProcess(self):
        """
        Stop the decompile process. 
         
        NOTE: Subsequent calls made from another  
        thread to this DecompInterface object may fail since the decompiler 
        process is being yanked away.
        """

    def structureGraph(self, ingraph: ghidra.program.model.pcode.BlockGraph, timeoutSecs: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.pcode.BlockGraph:
        ...

    def toggleCCode(self, val: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Toggle whether or not calls to the decompiler process
        (via the decompileFunction method) produce C code.
        The default is to always compute C code, but some
        applications may only need the syntax tree or other
        function information. Ideally this method should
        be called once before the openProgram call, but it
        can be used at any time, if the application wants
        to change before in the middle of a sequence of
        decompiles. Unless the desired value changes, the
        method does NOT need to be called repeatedly. Even
        after a decompiler process crash, the old value is
        cached and automatically sent to the new process
        
        :param jpype.JBoolean or bool val: = true, to produce C code, false otherwise
        :return: true if the decompiler process accepted the new state
        :rtype: bool
        """

    def toggleJumpLoads(self, val: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Toggle whether or not the decompiler process should return information about tables
        used to recover switch statements.  Most compilers implement switch statements using a
        so called "jumptable" of addresses or offsets.  The decompiler can frequently recover this
        and can return a description of the table
        
        :param jpype.JBoolean or bool val: = true, to have the decompiler return table info, false otherwise
        :return: true if the decompiler process accepted the new state
        :rtype: bool
        """

    def toggleParamMeasures(self, val: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Toggle whether or not calls to the decompiler process
        (via the decompileFunction method) produce Parameter
        Measures. The default is to not compute Parameter
        Measures. Ideally this method should
        be called once before the openProgram call, but it
        can be used at any time, if the application wants
        to change before in the middle of a sequence of
        decompiles. Unless the desired value changes, the
        method does NOT need to be called repeatedly. Even
        after a decompiler process crash, the old value is
        cached and automatically sent to the new process
        
        :param jpype.JBoolean or bool val: = true, to produce C code, false otherwise
        :return: true if the decompiler process accepted the new state
        :rtype: bool
        """

    def toggleSyntaxTree(self, val: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        This method toggles whether or not the decompiler
        produces a syntax tree (via calls to decompileFunction).
        The default is to always produce a syntax tree, but
        some applications may only need C code.  Ideally this method should
        be called once before the openProgram call, but it
        can be used at any time, if the application wants
        to change before in the middle of a sequence of
        decompiles. Unless the desired value changes, the
        method does NOT need to be called repeatedly. Even
        after a decompiler process crash, the old value is
        cached and automatically sent to the new process
        
        :param jpype.JBoolean or bool val: = true, to produce a syntax tree, false otherwise
        :return: true if the decompiler process, accepted the change of state
        :rtype: bool
        """

    @property
    def simplificationStyle(self) -> java.lang.String:
        ...

    @property
    def options(self) -> DecompileOptions:
        ...

    @property
    def lastMessage(self) -> java.lang.String:
        ...

    @property
    def signatureSettings(self) -> jpype.JInt:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def minorVersion(self) -> jpype.JShort:
        ...

    @property
    def majorVersion(self) -> jpype.JShort:
        ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.pcode.PcodeDataTypeManager:
        ...

    @property
    def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...


class DecompilerMarginService(java.lang.Object):
    """
    A service that allows clients to add custom margins in the Decompiler UI.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addMarginProvider(self, provider: ghidra.app.decompiler.component.margin.DecompilerMarginProvider):
        """
        Add a margin to the Decompiler's primary window
        
        :param ghidra.app.decompiler.component.margin.DecompilerMarginProvider provider: the margin provider
        """

    def getDecompilerPanel(self) -> ghidra.app.decompiler.component.DecompilerPanel:
        """
        Get the panel associated with this margin
        
        :return: the panel
        :rtype: ghidra.app.decompiler.component.DecompilerPanel
        """

    def removeMarginProvider(self, provider: ghidra.app.decompiler.component.margin.DecompilerMarginProvider):
        """
        Remove a margin from the Decompiler's primary window
        
        :param ghidra.app.decompiler.component.margin.DecompilerMarginProvider provider: the margin provider
        """

    @property
    def decompilerPanel(self) -> ghidra.app.decompiler.component.DecompilerPanel:
        ...


class ClangToken(ClangNode):
    """
    Class representing a source code language token.
    A token has numerous display attributes and may link to the data-flow analysis
    """

    class_: typing.ClassVar[java.lang.Class]
    KEYWORD_COLOR: typing.Final = 0
    COMMENT_COLOR: typing.Final = 1
    TYPE_COLOR: typing.Final = 2
    FUNCTION_COLOR: typing.Final = 3
    VARIABLE_COLOR: typing.Final = 4
    CONST_COLOR: typing.Final = 5
    PARAMETER_COLOR: typing.Final = 6
    GLOBAL_COLOR: typing.Final = 7
    DEFAULT_COLOR: typing.Final = 8
    ERROR_COLOR: typing.Final = 9
    SPECIAL_COLOR: typing.Final = 10
    MAX_COLOR: typing.Final = 11

    @typing.overload
    def __init__(self, par: ClangNode):
        ...

    @typing.overload
    def __init__(self, par: ClangNode, txt: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, par: ClangNode, txt: typing.Union[java.lang.String, str], color: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def buildSpacer(par: ClangNode, indent: typing.Union[jpype.JInt, int], indentStr: typing.Union[java.lang.String, str]) -> ClangToken:
        """
        Add a spacer token to the given text grouping
        
        :param ClangNode par: is the text grouping
        :param jpype.JInt or int indent: is the number of levels to indent
        :param java.lang.String or str indentStr: is a string representing containg the number of spaces in one indent level
        :return: the new spacer token
        :rtype: ClangToken
        """

    @staticmethod
    def buildToken(node: typing.Union[jpype.JInt, int], par: ClangNode, decoder: ghidra.program.model.pcode.Decoder, pfactory: ghidra.program.model.pcode.PcodeFactory) -> ClangToken:
        """
        Decode one specialized token from the current position in an encoded stream.  This
        serves as a factory for allocating the various objects derived from ClangToken
        
        :param jpype.JInt or int node: is the particular token type (already) decoded from the stream
        :param ClangNode par: is the text grouping which will contain the token
        :param ghidra.program.model.pcode.Decoder decoder: is the decoder for the stream
        :param ghidra.program.model.pcode.PcodeFactory pfactory: is used to look up p-code objects associated with tokens
        :return: the new ClangToken
        :rtype: ClangToken
        :raises DecoderException: for problems decoding the stream
        """

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, pfactory: ghidra.program.model.pcode.PcodeFactory):
        """
        Decode this token from the current position in an encoded stream
        
        :param ghidra.program.model.pcode.Decoder decoder: is the decoder for the stream
        :param ghidra.program.model.pcode.PcodeFactory pfactory: is used to look up p-code objects associated with the token
        :raises DecoderException: for problems decoding the stream
        """

    def getHighSymbol(self, highFunction: ghidra.program.model.pcode.HighFunction) -> ghidra.program.model.pcode.HighSymbol:
        """
        Get the symbol associated with this token or null otherwise.
        This token may be directly associated with the symbol or a reference, in which
        case the symbol is looked up in the containing HighFunction
        
        :param ghidra.program.model.pcode.HighFunction highFunction: is the function
        :return: HighSymbol
        :rtype: ghidra.program.model.pcode.HighSymbol
        """

    def getHighVariable(self) -> ghidra.program.model.pcode.HighVariable:
        """
        Get the high-level variable associate with this
        token or null otherwise
        
        :return: HighVariable
        :rtype: ghidra.program.model.pcode.HighVariable
        """

    def getHighlight(self) -> java.awt.Color:
        """
        Get the background highlight color used to render this token, or null if not highlighted
        
        :return: the Color or null
        :rtype: java.awt.Color
        """

    def getLineParent(self) -> ClangLine:
        """
        Get the element representing an entire line of text that contains this element
        
        :return: the containing ClangLine
        :rtype: ClangLine
        """

    def getPcodeOp(self) -> ghidra.program.model.pcode.PcodeOp:
        """
        Many tokens directly represent a pcode operator in the data-flow
        
        :return: the operation (PcodeOp) associated with this token or null
        :rtype: ghidra.program.model.pcode.PcodeOp
        """

    def getScalar(self) -> ghidra.program.model.scalar.Scalar:
        """
        If the token represents an underlying integer constant, return the constant as a Scalar.
        Otherwise return null.
        
        :return: the Scalar that the token represents or null
        :rtype: ghidra.program.model.scalar.Scalar
        """

    def getSyntaxType(self) -> int:
        """
        Get the "syntax" type (color) associated with this token (keyword, type, etc)
        
        :return: the color code
        :rtype: int
        """

    def getText(self) -> str:
        """
        
        
        :return: this token's display text as a string
        :rtype: str
        """

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        Many tokens directly represent a variable in the data-flow
        
        :return: the variable (Varnode) associated with this token or null
        :rtype: ghidra.program.model.pcode.Varnode
        """

    def isMatchingToken(self) -> bool:
        """
        
        
        :return: true if this token should be displayed with "matching" highlighting
        :rtype: bool
        """

    def isVariableRef(self) -> bool:
        """
        
        
        :return: true if this token represents a variable (in source code)
        :rtype: bool
        """

    def iterator(self, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Iterator[ClangToken]:
        """
        Get an iterator over tokens starting with this ClangToken.  Tokens are returned in normal
        display order (forward=true) or in the reverse of normal display order (forward=false)
        
        :param jpype.JBoolean or bool forward: is true for forward iterator, false for a backward iterator
        :return: the Iterator object
        :rtype: java.util.Iterator[ClangToken]
        """

    def setLineParent(self, line: ClangLine):
        """
        Set (change) the line which this text element part of.
        
        :param ClangLine line: is the new ClangLine
        """

    def setMatchingToken(self, matchingToken: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether or not additional "matching" highlighting is applied to this token.
        Currently this means a bounding box is drawn around the token.
        
        :param jpype.JBoolean or bool matchingToken: is true to enable highlighting, false to disable
        """

    @property
    def highlight(self) -> java.awt.Color:
        ...

    @property
    def matchingToken(self) -> jpype.JBoolean:
        ...

    @matchingToken.setter
    def matchingToken(self, value: jpype.JBoolean):
        ...

    @property
    def scalar(self) -> ghidra.program.model.scalar.Scalar:
        ...

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def pcodeOp(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def variableRef(self) -> jpype.JBoolean:
        ...

    @property
    def highSymbol(self) -> ghidra.program.model.pcode.HighSymbol:
        ...

    @property
    def lineParent(self) -> ClangLine:
        ...

    @lineParent.setter
    def lineParent(self, value: ClangLine):
        ...

    @property
    def syntaxType(self) -> jpype.JInt:
        ...

    @property
    def highVariable(self) -> ghidra.program.model.pcode.HighVariable:
        ...


class DecompileOptions(java.lang.Object):
    """
    Configuration options for the decompiler
    This stores the options and can create an XML
    string to be sent to the decompiler process
    """

    class NanIgnoreEnum(java.lang.Enum[DecompileOptions.NanIgnoreEnum]):

        class_: typing.ClassVar[java.lang.Class]
        None_: typing.Final[DecompileOptions.NanIgnoreEnum]
        Compare: typing.Final[DecompileOptions.NanIgnoreEnum]
        All: typing.Final[DecompileOptions.NanIgnoreEnum]

        def getOptionString(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DecompileOptions.NanIgnoreEnum:
            ...

        @staticmethod
        def values() -> jpype.JArray[DecompileOptions.NanIgnoreEnum]:
            ...

        @property
        def optionString(self) -> java.lang.String:
            ...


    class AliasBlockEnum(java.lang.Enum[DecompileOptions.AliasBlockEnum]):

        class_: typing.ClassVar[java.lang.Class]
        None_: typing.Final[DecompileOptions.AliasBlockEnum]
        Struct: typing.Final[DecompileOptions.AliasBlockEnum]
        Array: typing.Final[DecompileOptions.AliasBlockEnum]
        All: typing.Final[DecompileOptions.AliasBlockEnum]

        def getOptionString(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DecompileOptions.AliasBlockEnum:
            ...

        @staticmethod
        def values() -> jpype.JArray[DecompileOptions.AliasBlockEnum]:
            ...

        @property
        def optionString(self) -> java.lang.String:
            ...


    class BraceStyle(java.lang.Enum[DecompileOptions.BraceStyle]):

        class_: typing.ClassVar[java.lang.Class]
        Same: typing.Final[DecompileOptions.BraceStyle]
        Next: typing.Final[DecompileOptions.BraceStyle]
        Skip: typing.Final[DecompileOptions.BraceStyle]

        def getOptionString(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DecompileOptions.BraceStyle:
            ...

        @staticmethod
        def values() -> jpype.JArray[DecompileOptions.BraceStyle]:
            ...

        @property
        def optionString(self) -> java.lang.String:
            ...


    class CommentStyleEnum(java.lang.Enum[DecompileOptions.CommentStyleEnum]):

        class_: typing.ClassVar[java.lang.Class]
        CStyle: typing.Final[DecompileOptions.CommentStyleEnum]
        CPPStyle: typing.Final[DecompileOptions.CommentStyleEnum]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DecompileOptions.CommentStyleEnum:
            ...

        @staticmethod
        def values() -> jpype.JArray[DecompileOptions.CommentStyleEnum]:
            ...


    class NamespaceStrategy(java.lang.Enum[DecompileOptions.NamespaceStrategy]):

        class_: typing.ClassVar[java.lang.Class]
        Minimal: typing.Final[DecompileOptions.NamespaceStrategy]
        All: typing.Final[DecompileOptions.NamespaceStrategy]
        Never: typing.Final[DecompileOptions.NamespaceStrategy]

        def getOptionString(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DecompileOptions.NamespaceStrategy:
            ...

        @staticmethod
        def values() -> jpype.JArray[DecompileOptions.NamespaceStrategy]:
            ...

        @property
        def optionString(self) -> java.lang.String:
            ...


    class IntegerFormatEnum(java.lang.Enum[DecompileOptions.IntegerFormatEnum]):

        class_: typing.ClassVar[java.lang.Class]
        Hexadecimal: typing.Final[DecompileOptions.IntegerFormatEnum]
        Decimal: typing.Final[DecompileOptions.IntegerFormatEnum]
        BestFit: typing.Final[DecompileOptions.IntegerFormatEnum]

        def getOptionString(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DecompileOptions.IntegerFormatEnum:
            ...

        @staticmethod
        def values() -> jpype.JArray[DecompileOptions.IntegerFormatEnum]:
            ...

        @property
        def optionString(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]
    SUGGESTED_DECOMPILE_TIMEOUT_SECS: typing.Final = 30
    SUGGESTED_MAX_PAYLOAD_BYTES: typing.Final = 50
    SUGGESTED_MAX_INSTRUCTIONS: typing.Final = 100000
    SUGGESTED_MAX_JUMPTABLE_ENTRIES: typing.Final = 1024
    DEFAULT_FONT_ID: typing.Final = "font.decompiler"

    def __init__(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder, iface: DecompInterface):
        """
        Encode all the configuration options to a stream for the decompiler process.
        This object is global to all decompile processes so we can tailor to the specific process
        by passing in the interface.
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :param DecompInterface iface: specific DecompInterface being sent options
        :raises IOException: for errors writing to the underlying stream
        """

    def getBackgroundColor(self) -> java.awt.Color:
        """
        
        
        :return: the background color for the decompiler window
        :rtype: java.awt.Color
        """

    def getCacheSize(self) -> int:
        """
        Return the maximum number of decompiled function results that should be cached
        by the controller of the decompiler process.
        
        :return: the number of functions to cache
        :rtype: int
        """

    def getCommentColor(self) -> java.awt.Color:
        """
        
        
        :return: color used to display comments
        :rtype: java.awt.Color
        """

    def getCommentStyle(self) -> DecompileOptions.CommentStyleEnum:
        """
        
        
        :return: the style in which comments are printed in decompiler output
        :rtype: DecompileOptions.CommentStyleEnum
        """

    def getConstantColor(self) -> java.awt.Color:
        """
        
        
        :return: color associated with constant tokens
        :rtype: java.awt.Color
        """

    def getCurrentVariableHighlightColor(self) -> java.awt.Color:
        """
        
        
        :return: the color used display the current highlighted variable
        :rtype: java.awt.Color
        """

    def getDefaultColor(self) -> java.awt.Color:
        """
        
        
        :return: color for generic syntax or other unspecified tokens
        :rtype: java.awt.Color
        """

    def getDefaultFont(self) -> java.awt.Font:
        """
        
        
        :return: the font that should be used to render decompiler output
        :rtype: java.awt.Font
        """

    def getDefaultTimeout(self) -> int:
        """
        If the time a decompiler process is allowed to analyze a single
        function exceeds this value, decompilation is aborted.
        
        :return: the maximum time in seconds
        :rtype: int
        """

    def getDisplayLanguage(self) -> ghidra.program.model.lang.DecompilerLanguage:
        """
        
        
        :return: the source programming language that decompiler output is rendered in
        :rtype: ghidra.program.model.lang.DecompilerLanguage
        """

    def getErrorColor(self) -> java.awt.Color:
        """
        
        
        :return: color used on tokens that need to warn of an error or other unusual conditions
        :rtype: java.awt.Color
        """

    def getFunctionBraceFormat(self) -> DecompileOptions.BraceStyle:
        """
        
        
        :return: the brace formatting style for function bodies
        :rtype: DecompileOptions.BraceStyle
        """

    def getGlobalColor(self) -> java.awt.Color:
        """
        
        
        :return: color associated with global variable tokens
        :rtype: java.awt.Color
        """

    def getIfElseBraceFormat(self) -> DecompileOptions.BraceStyle:
        """
        
        
        :return: the brace formatting style for if/else code blocks
        :rtype: DecompileOptions.BraceStyle
        """

    def getKeywordColor(self) -> java.awt.Color:
        """
        
        
        :return: color associated with keyword tokens
        :rtype: java.awt.Color
        """

    def getLoopBraceFormat(self) -> DecompileOptions.BraceStyle:
        """
        
        
        :return: the brace formatting style for loop bodies
        :rtype: DecompileOptions.BraceStyle
        """

    def getMaxInstructions(self) -> int:
        """
        If the number of assembly instructions in a function exceeds this value, the function
        is not decompiled.
        
        :return: the maximum number of instructions
        :rtype: int
        """

    def getMaxJumpTableEntries(self) -> int:
        """
        If the number of entries in a single jumptable exceeds this value, the decompiler will
        not recover the table and control flow from the indirect jump corresponding to the table
        will not be followed.
        
        :return: the maximum number of entries
        :rtype: int
        """

    def getMaxPayloadMBytes(self) -> int:
        """
        If the size (in megabytes) of the payload returned by the decompiler
        process exceeds this value for a single function, decompilation is
        aborted.
        
        :return: the maximum number of megabytes in a function payload
        :rtype: int
        """

    def getMaxWidth(self) -> int:
        """
        
        
        :return: the maximum number of characters the decompiler displays in a single line of output
        :rtype: int
        """

    def getMiddleMouseHighlightButton(self) -> int:
        """
        
        
        :return: the mouse button that should be used to toggle the primary token highlight
        :rtype: int
        """

    def getMiddleMouseHighlightColor(self) -> java.awt.Color:
        """
        
        
        :return: color used to highlight token(s) selected with a middle button clock
        :rtype: java.awt.Color
        """

    def getNameTransformer(self) -> ghidra.program.model.symbol.NameTransformer:
        """
        Retrieve the transformer being applied to data-type, function, and namespace names.
        If no transform is being applied, a pass-through object is returned.
        
        :return: the transformer object
        :rtype: ghidra.program.model.symbol.NameTransformer
        """

    def getParameterColor(self) -> java.awt.Color:
        """
        
        
        :return: color associated with parameter tokens
        :rtype: java.awt.Color
        """

    def getProtoEvalModel(self) -> str:
        """
        
        
        :return: the default prototype to assume if no other information about a function is known
        :rtype: str
        """

    def getSearchHighlightColor(self) -> java.awt.Color:
        """
        
        
        :return: color used to highlight search results
        :rtype: java.awt.Color
        """

    def getSpecialColor(self) -> java.awt.Color:
        """
        
        
        :return: color associated with volatile variables or other special tokens
        :rtype: java.awt.Color
        """

    def getSwitchBraceFormat(self) -> DecompileOptions.BraceStyle:
        """
        
        
        :return: the brace formatting style for switch blocks
        :rtype: DecompileOptions.BraceStyle
        """

    def getTypeColor(self) -> java.awt.Color:
        """
        
        
        :return: color associated with data-type tokens
        :rtype: java.awt.Color
        """

    def getVariableColor(self) -> java.awt.Color:
        """
        
        
        :return: color associated with (local) variable tokens
        :rtype: java.awt.Color
        """

    def grabFromProgram(self, program: ghidra.program.model.listing.Program):
        """
        Grab all the decompiler options from the program specifically
        and cache them in this object.
        
        :param ghidra.program.model.listing.Program program: the program whose "program options" are relevant to the decompiler
        """

    def grabFromToolAndProgram(self, fieldOptions: ghidra.framework.options.ToolOptions, opt: ghidra.framework.options.ToolOptions, program: ghidra.program.model.listing.Program):
        """
        Grab all the decompiler options from various sources within a specific tool and program
        and cache them in this object.
        
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options object containing options specific to listing fields
        :param ghidra.framework.options.ToolOptions opt: the Options object that contains the "tool options" specific to the decompiler
        :param ghidra.program.model.listing.Program program: the program whose "program options" are relevant to the decompiler
        """

    def isConventionPrint(self) -> bool:
        """
        
        
        :return: true if calling convention names are displayed as part of function signatures
        :rtype: bool
        """

    def isDisplayLineNumbers(self) -> bool:
        """
        
        
        :return: true if line numbers should be displayed with decompiler output.
        :rtype: bool
        """

    def isEOLCommentIncluded(self) -> bool:
        """
        
        
        :return: true if End-of-line comments are included as part of decompiler output
        :rtype: bool
        """

    def isEliminateUnreachable(self) -> bool:
        """
        
        
        :return: true if the decompiler currently eliminates unreachable code
        :rtype: bool
        """

    def isHeadCommentIncluded(self) -> bool:
        """
        
        
        :return: true if function header comments are included as part of decompiler output
        :rtype: bool
        """

    def isNoCastPrint(self) -> bool:
        """
        
        
        :return: true if cast operations are not displayed in decompiler output
        :rtype: bool
        """

    def isPLATECommentIncluded(self) -> bool:
        """
        
        
        :return: true if Plate comments are included as part of decompiler output
        :rtype: bool
        """

    def isPOSTCommentIncluded(self) -> bool:
        """
        
        
        :return: true if Post comments are included as part of decompiler output
        :rtype: bool
        """

    def isPRECommentIncluded(self) -> bool:
        """
        
        
        :return: true if Pre comments are included as part of decompiler output
        :rtype: bool
        """

    def isRespectReadOnly(self) -> bool:
        """
        
        
        :return: true if the decompiler currently respects read-only flags
        :rtype: bool
        """

    def isSimplifyDoublePrecision(self) -> bool:
        """
        If the decompiler currently applies transformation rules that identify and
        simplify double precision arithmetic operations, true is returned.
        
        :return: true if the decompiler applies double precision rules
        :rtype: bool
        """

    def isWARNCommentIncluded(self) -> bool:
        """
        
        
        :return: true if WARNING comments are included as part of decompiler output
        :rtype: bool
        """

    def registerOptions(self, fieldOptions: ghidra.framework.options.ToolOptions, opt: ghidra.framework.options.ToolOptions, program: ghidra.program.model.listing.Program):
        """
        This registers all the decompiler tool options with ghidra, and has the side effect of
        pulling all the current values for the options if they exist
        
        :param ghidra.framework.options.ToolOptions fieldOptions: the options object specific to listing fields
        :param ghidra.framework.options.ToolOptions opt: the options object specific to the decompiler
        :param ghidra.program.model.listing.Program program: the program
        """

    def setCommentStyle(self, commentStyle: DecompileOptions.CommentStyleEnum):
        """
        Set the style in which comments are printed as part of decompiler output
        
        :param DecompileOptions.CommentStyleEnum commentStyle: is the new style to set
        """

    def setConventionPrint(self, conventionPrint: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether the calling convention name should be displayed as part of function signatures
        in decompiler output.
        
        :param jpype.JBoolean or bool conventionPrint: is true if calling convention names should be displayed
        """

    def setDefaultTimeout(self, timeout: typing.Union[jpype.JInt, int]):
        """
        Set the maximum time (in seconds) a decompiler process is allowed to analyze a single
        function. If it is exceeded, decompilation is aborted.
        
        :param jpype.JInt or int timeout: is the maximum time in seconds
        """

    def setDisplayLanguage(self, val: ghidra.program.model.lang.DecompilerLanguage):
        """
        Set the source programming language that decompiler output should be rendered in.
        
        :param ghidra.program.model.lang.DecompilerLanguage val: is the source language
        """

    def setEOLCommentIncluded(self, commentEOLInclude: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether End-of-line comments are displayed as part of decompiler output.
        
        :param jpype.JBoolean or bool commentEOLInclude: is true if End-of-line comments are output
        """

    def setEliminateUnreachable(self, eliminateUnreachable: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether the decompiler should eliminate unreachable code as part of its analysis.
        
        :param jpype.JBoolean or bool eliminateUnreachable: is true if unreachable code is eliminated
        """

    def setFunctionBraceFormat(self, style: DecompileOptions.BraceStyle):
        """
        Set how braces are formatted around a function body
        
        :param DecompileOptions.BraceStyle style: is the formatting style
        """

    def setHeadCommentIncluded(self, commentHeadInclude: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether function header comments are included as part of decompiler output.
        
        :param jpype.JBoolean or bool commentHeadInclude: is true if header comments are output
        """

    def setIfElseBraceFormat(self, style: DecompileOptions.BraceStyle):
        """
        Set how braces are formatted around an if/else code block
        
        :param DecompileOptions.BraceStyle style: is the formatting style
        """

    def setLoopBraceFormat(self, style: DecompileOptions.BraceStyle):
        """
        Set how braces are formatted a loop body
        
        :param DecompileOptions.BraceStyle style: is the formatting style
        """

    def setMaxInstructions(self, num: typing.Union[jpype.JInt, int]):
        """
        Set the maximum number of assembly instructions in a function to decompile.
        If the number exceeds this, the function is not decompiled.
        
        :param jpype.JInt or int num: is the number of instructions
        """

    def setMaxJumpTableEntries(self, num: typing.Union[jpype.JInt, int]):
        """
        Set the maximum number of entries the decompiler will recover from a single jumptable.
        If the number exceeds this, the table is not recovered and control flow from the
        corresponding indirect jump is not followed.
        
        :param jpype.JInt or int num: is the number of entries
        """

    def setMaxPayloadMBytes(self, mbytes: typing.Union[jpype.JInt, int]):
        """
        Set the maximum size (in megabytes) of the payload that can be returned by the decompiler
        process when analyzing a single function.  If this size is exceeded, decompilation is
        aborted.
        
        :param jpype.JInt or int mbytes: is the maximum number of megabytes in a function payload
        """

    def setMaxWidth(self, maxwidth: typing.Union[jpype.JInt, int]):
        """
        Set the maximum number of characters the decompiler displays in a single line of output
        
        :param jpype.JInt or int maxwidth: is the maximum number of characters
        """

    def setNameTransformer(self, transformer: ghidra.program.model.symbol.NameTransformer):
        """
        Set a specific transformer to be applied to all data-type, function, and namespace
        names in decompiler output.  A null value indicates no transform should be applied.
        
        :param ghidra.program.model.symbol.NameTransformer transformer: is the transformer to apply
        """

    def setNoCastPrint(self, noCastPrint: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether decompiler output should display cast operations.
        
        :param jpype.JBoolean or bool noCastPrint: is true if casts should NOT be displayed.
        """

    def setPLATECommentIncluded(self, commentPLATEInclude: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether Plate comments are displayed as part of decompiler output
        
        :param jpype.JBoolean or bool commentPLATEInclude: is true if Plate comments are output
        """

    def setPOSTCommentIncluded(self, commentPOSTInclude: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether Post comments are displayed as part of decompiler output
        
        :param jpype.JBoolean or bool commentPOSTInclude: is true if Post comments are output
        """

    def setPRECommentIncluded(self, commentPREInclude: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether Pre comments are displayed as part of decompiler output
        
        :param jpype.JBoolean or bool commentPREInclude: is true if Pre comments are output
        """

    def setProtoEvalModel(self, protoEvalModel: typing.Union[java.lang.String, str]):
        """
        Set the default prototype model for the decompiler.  This is the model assumed if no other
        information about a function is known.
        
        :param java.lang.String or str protoEvalModel: is the name of the prototype model to set as default
        """

    def setRespectReadOnly(self, readOnly: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether the decompiler should respect read-only flags as part of its analysis.
        
        :param jpype.JBoolean or bool readOnly: is true if read-only flags are respected
        """

    def setSimplifyDoublePrecision(self, simplifyDoublePrecision: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether the decompiler should apply transformation rules that identify and
        simplify double precision arithmetic operations.
        
        :param jpype.JBoolean or bool simplifyDoublePrecision: is true if double precision rules should be applied
        """

    def setSwitchBraceFormat(self, style: DecompileOptions.BraceStyle):
        """
        Set how braces are formatted around a switch block
        
        :param DecompileOptions.BraceStyle style: is the formatting style
        """

    def setWARNCommentIncluded(self, commentWARNInclude: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether automatically generated WARNING comments are displayed as part of
        decompiler output.
        
        :param jpype.JBoolean or bool commentWARNInclude: is true if WARNING comments are output
        """

    @property
    def pRECommentIncluded(self) -> jpype.JBoolean:
        ...

    @pRECommentIncluded.setter
    def pRECommentIncluded(self, value: jpype.JBoolean):
        ...

    @property
    def currentVariableHighlightColor(self) -> java.awt.Color:
        ...

    @property
    def errorColor(self) -> java.awt.Color:
        ...

    @property
    def pLATECommentIncluded(self) -> jpype.JBoolean:
        ...

    @pLATECommentIncluded.setter
    def pLATECommentIncluded(self, value: jpype.JBoolean):
        ...

    @property
    def conventionPrint(self) -> jpype.JBoolean:
        ...

    @conventionPrint.setter
    def conventionPrint(self, value: jpype.JBoolean):
        ...

    @property
    def defaultTimeout(self) -> jpype.JInt:
        ...

    @defaultTimeout.setter
    def defaultTimeout(self, value: jpype.JInt):
        ...

    @property
    def keywordColor(self) -> java.awt.Color:
        ...

    @property
    def eOLCommentIncluded(self) -> jpype.JBoolean:
        ...

    @eOLCommentIncluded.setter
    def eOLCommentIncluded(self, value: jpype.JBoolean):
        ...

    @property
    def globalColor(self) -> java.awt.Color:
        ...

    @property
    def loopBraceFormat(self) -> DecompileOptions.BraceStyle:
        ...

    @loopBraceFormat.setter
    def loopBraceFormat(self, value: DecompileOptions.BraceStyle):
        ...

    @property
    def ifElseBraceFormat(self) -> DecompileOptions.BraceStyle:
        ...

    @ifElseBraceFormat.setter
    def ifElseBraceFormat(self, value: DecompileOptions.BraceStyle):
        ...

    @property
    def eliminateUnreachable(self) -> jpype.JBoolean:
        ...

    @eliminateUnreachable.setter
    def eliminateUnreachable(self, value: jpype.JBoolean):
        ...

    @property
    def displayLineNumbers(self) -> jpype.JBoolean:
        ...

    @property
    def middleMouseHighlightColor(self) -> java.awt.Color:
        ...

    @property
    def switchBraceFormat(self) -> DecompileOptions.BraceStyle:
        ...

    @switchBraceFormat.setter
    def switchBraceFormat(self, value: DecompileOptions.BraceStyle):
        ...

    @property
    def maxPayloadMBytes(self) -> jpype.JInt:
        ...

    @maxPayloadMBytes.setter
    def maxPayloadMBytes(self, value: jpype.JInt):
        ...

    @property
    def wARNCommentIncluded(self) -> jpype.JBoolean:
        ...

    @wARNCommentIncluded.setter
    def wARNCommentIncluded(self, value: jpype.JBoolean):
        ...

    @property
    def pOSTCommentIncluded(self) -> jpype.JBoolean:
        ...

    @pOSTCommentIncluded.setter
    def pOSTCommentIncluded(self, value: jpype.JBoolean):
        ...

    @property
    def commentStyle(self) -> DecompileOptions.CommentStyleEnum:
        ...

    @commentStyle.setter
    def commentStyle(self, value: DecompileOptions.CommentStyleEnum):
        ...

    @property
    def headCommentIncluded(self) -> jpype.JBoolean:
        ...

    @headCommentIncluded.setter
    def headCommentIncluded(self, value: jpype.JBoolean):
        ...

    @property
    def constantColor(self) -> java.awt.Color:
        ...

    @property
    def defaultColor(self) -> java.awt.Color:
        ...

    @property
    def functionBraceFormat(self) -> DecompileOptions.BraceStyle:
        ...

    @functionBraceFormat.setter
    def functionBraceFormat(self, value: DecompileOptions.BraceStyle):
        ...

    @property
    def respectReadOnly(self) -> jpype.JBoolean:
        ...

    @respectReadOnly.setter
    def respectReadOnly(self, value: jpype.JBoolean):
        ...

    @property
    def commentColor(self) -> java.awt.Color:
        ...

    @property
    def defaultFont(self) -> java.awt.Font:
        ...

    @property
    def maxWidth(self) -> jpype.JInt:
        ...

    @maxWidth.setter
    def maxWidth(self, value: jpype.JInt):
        ...

    @property
    def typeColor(self) -> java.awt.Color:
        ...

    @property
    def nameTransformer(self) -> ghidra.program.model.symbol.NameTransformer:
        ...

    @nameTransformer.setter
    def nameTransformer(self, value: ghidra.program.model.symbol.NameTransformer):
        ...

    @property
    def middleMouseHighlightButton(self) -> jpype.JInt:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def cacheSize(self) -> jpype.JInt:
        ...

    @property
    def variableColor(self) -> java.awt.Color:
        ...

    @property
    def displayLanguage(self) -> ghidra.program.model.lang.DecompilerLanguage:
        ...

    @displayLanguage.setter
    def displayLanguage(self, value: ghidra.program.model.lang.DecompilerLanguage):
        ...

    @property
    def maxJumpTableEntries(self) -> jpype.JInt:
        ...

    @maxJumpTableEntries.setter
    def maxJumpTableEntries(self, value: jpype.JInt):
        ...

    @property
    def protoEvalModel(self) -> java.lang.String:
        ...

    @protoEvalModel.setter
    def protoEvalModel(self, value: java.lang.String):
        ...

    @property
    def simplifyDoublePrecision(self) -> jpype.JBoolean:
        ...

    @simplifyDoublePrecision.setter
    def simplifyDoublePrecision(self, value: jpype.JBoolean):
        ...

    @property
    def specialColor(self) -> java.awt.Color:
        ...

    @property
    def maxInstructions(self) -> jpype.JInt:
        ...

    @maxInstructions.setter
    def maxInstructions(self, value: jpype.JInt):
        ...

    @property
    def parameterColor(self) -> java.awt.Color:
        ...

    @property
    def noCastPrint(self) -> jpype.JBoolean:
        ...

    @noCastPrint.setter
    def noCastPrint(self, value: jpype.JBoolean):
        ...

    @property
    def searchHighlightColor(self) -> java.awt.Color:
        ...


class DecompileCallback(java.lang.Object):
    """
    Routines that the decompiler invokes to gather info during decompilation of a
    function.
    """

    class StringData(java.lang.Object):
        """
        Data returned for a query about strings
        """

        class_: typing.ClassVar[java.lang.Class]
        byteData: jpype.JArray[jpype.JByte]

        def __init__(self, stringVal: typing.Union[java.lang.String, str], maxChars: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    MAX_SYMBOL_COUNT: typing.Final = 16

    def __init__(self, prog: ghidra.program.model.listing.Program, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, dt: ghidra.program.model.pcode.PcodeDataTypeManager):
        ...

    @staticmethod
    def encodeInstruction(encoder: ghidra.program.model.pcode.Encoder, addr: ghidra.program.model.address.Address, ops: jpype.JArray[ghidra.program.model.pcode.PcodeOp], fallthruoffset: typing.Union[jpype.JInt, int], paramshift: typing.Union[jpype.JInt, int], addrFactory: ghidra.program.model.address.AddressFactory):
        """
        Encode a list of pcode, representing an entire Instruction, to the stream
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :param ghidra.program.model.address.Address addr: is the Address to associate with the Instruction
        :param jpype.JArray[ghidra.program.model.pcode.PcodeOp] ops: is the pcode ops
        :param jpype.JInt or int fallthruoffset: number of bytes after instruction start that pcode
                    flow falls into
        :param jpype.JInt or int paramshift: special instructions for injection use
        :param ghidra.program.model.address.AddressFactory addrFactory: is the address factory for recovering address space names
        :raises IOException: for errors in the underlying stream
        """

    def getBytes(self, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Get bytes from the program's memory image.
        Any exceptions are caught, resulting in null being returned. The decompiler treats a null
        as a DataUnavailError but will continue to process the function.
        
        :param ghidra.program.model.address.Address addr: is the starting address to fetch bytes from
        :param jpype.JInt or int size: is the number of bytes to fetch
        :return: the bytes matching the query or null if the query can't be met
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getCPoolRef(self, refs: jpype.JArray[jpype.JLong], resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Look up details of a specific constant pool reference
        
        :param jpype.JArray[jpype.JLong] refs: is the constant id (which may consist of multiple integers)
        :param ghidra.program.model.pcode.Encoder resultEncoder: will contain the reference details
        :raises IOException: for errors in the underlying stream while encoding results
        """

    def getCodeLabel(self, addr: ghidra.program.model.address.Address) -> str:
        """
        Return the first symbol name at the given address
        
        :param ghidra.program.model.address.Address addr: is the given address
        :return: the symbol or null if no symbol is found
        :rtype: str
        :raises IOException: for errors trying to encode the symbol
        """

    def getComments(self, addr: ghidra.program.model.address.Address, types: typing.Union[jpype.JInt, int], resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Collect any/all comments for the function starting at the indicated
        address.  Filter based on selected comment types.
        
        :param ghidra.program.model.address.Address addr: is the indicated address
        :param jpype.JInt or int types: is the set of flags
        :param ghidra.program.model.pcode.Encoder resultEncoder: will contain the collected comments
        :raises IOException: for errors in the underlying stream
        """

    def getDataType(self, name: typing.Union[java.lang.String, str], id: typing.Union[jpype.JLong, int], resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Get a description of a data-type given its name and type id
        
        :param java.lang.String or str name: is the name of the data-type
        :param jpype.JLong or int id: is the type id
        :param ghidra.program.model.pcode.Encoder resultEncoder: will contain the resulting description
        :raises IOException: for errors in the underlying stream while encoding
        """

    def getExternalRef(self, addr: ghidra.program.model.address.Address, resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Get a description of an external reference at the given address
        
        :param ghidra.program.model.address.Address addr: is the given address
        :param ghidra.program.model.pcode.Encoder resultEncoder: will contain the resulting description
        :raises IOException: for errors encoding the result
        """

    def getMappedSymbols(self, addr: ghidra.program.model.address.Address, resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Describe data or functions at the given address; either function, reference, data, or hole.
        Called by the native decompiler to query the GHIDRA database about any
        symbols at the given address.
        
        :param ghidra.program.model.address.Address addr: is the given address
        :param ghidra.program.model.pcode.Encoder resultEncoder: is where to write encoded description
        :raises IOException: for errors encoding the result
        """

    def getNamespacePath(self, id: typing.Union[jpype.JLong, int], resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Write a description of the formal namespace path to the given namespace
        
        :param jpype.JLong or int id: is the ID of the given namespace
        :param ghidra.program.model.pcode.Encoder resultEncoder: is where to write the encoded result
        :raises IOException: for errors in the underlying stream
        """

    def getNativeMessage(self) -> str:
        """
        
        
        :return: the last message from the decompiler
        :rtype: str
        """

    def getPcode(self, addr: ghidra.program.model.address.Address, resultEncoder: ghidra.program.model.pcode.PatchEncoder):
        """
        Generate p-code ops for the instruction at the given address.
        Any exceptions are caught, resulting in an empty result. The decompiler interprets these
        as a BadDataError, but will continue to process the function.
        
        :param ghidra.program.model.address.Address addr: is the given address
        :param ghidra.program.model.pcode.PatchEncoder resultEncoder: will contain the generated p-code ops
        """

    def getPcodeInject(self, nm: typing.Union[java.lang.String, str], paramDecoder: ghidra.program.model.pcode.Decoder, type: typing.Union[jpype.JInt, int], resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Generate p-code ops for a named injection payload
        
        :param java.lang.String or str nm: is the name of the payload
        :param ghidra.program.model.pcode.Decoder paramDecoder: contains the context
        :param jpype.JInt or int type: is the type of payload
        :param ghidra.program.model.pcode.Encoder resultEncoder: will contain the generated p-code ops
        :raises DecoderException: for problems decoding the injection context
        :raises UnknownInstructionException: if there is no instruction at the injection site
        :raises IOException: for errors encoding the injection result
        :raises NotFoundException: if an expected aspect of the injection is not present in context
        :raises MemoryAccessException: for problems establishing the injection context
        """

    def getRegister(self, name: typing.Union[java.lang.String, str], resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Return a description of the register with the given name
        
        :param java.lang.String or str name: is the given name
        :param ghidra.program.model.pcode.Encoder resultEncoder: is where to write the description
        :raises IOException: for errors writing to the underlying stream
        """

    def getRegisterName(self, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]) -> str:
        """
        Given a storage location, return the register name for that location, or null if there
        is no register there.
        
        :param ghidra.program.model.address.Address addr: is the starting address of the storage location
        :param jpype.JInt or int size: is the size of storage in bytes
        :return: the register name or null
        :rtype: str
        """

    def getStringData(self, addr: ghidra.program.model.address.Address, maxChars: typing.Union[jpype.JInt, int], dtName: typing.Union[java.lang.String, str], dtId: typing.Union[jpype.JLong, int]) -> DecompileCallback.StringData:
        """
        Check for a string at the given address and return a UTF8 encoded byte array.
        If there is already data present at the address, use this to determine the
        string encoding. Otherwise use the data-type info passed in to determine the encoding.
        Check that the bytes at the address represent a valid string encoding that doesn't
        exceed the maximum character limit passed in.  Return null if the string is invalid.
        Return the string translated into a UTF8 byte array otherwise.  A (valid) empty
        string is returned as a zero length array.
        
        :param ghidra.program.model.address.Address addr: is the given address
        :param jpype.JInt or int maxChars: is the maximum character limit
        :param java.lang.String or str dtName: is the name of a character data-type
        :param jpype.JLong or int dtId: is the id associated with the character data-type
        :return: the UTF8 encoded byte array or null
        :rtype: DecompileCallback.StringData
        """

    def getTrackedRegisters(self, addr: ghidra.program.model.address.Address, resultEncoder: ghidra.program.model.pcode.Encoder):
        """
        Get "tracked" register values, constant values associated with a specific register at
        a specific point in the code.
        
        :param ghidra.program.model.address.Address addr: is the "point" in the code to look for tracked values
        :param ghidra.program.model.pcode.Encoder resultEncoder: will hold the resulting description of registers and values
        :raises IOException: for errors in the underlying stream writing the result
        """

    def getUserOpName(self, index: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the name of a user op given its index
        
        :param jpype.JInt or int index: is the given index
        :return: the userop name or null
        :rtype: str
        """

    def isNameUsed(self, name: typing.Union[java.lang.String, str], startId: typing.Union[jpype.JLong, int], stopId: typing.Union[jpype.JLong, int]) -> bool:
        """
        Decide if a given name is used by any namespace between a starting namespace
        and a stopping namespace.  I.e. check for a name collision along a specific namespace path.
        Currently, Ghidra is inefficient at calculating this perfectly, so this routine calculates
        an approximation that can occasionally indicate a collision when there isn't.
        
        :param java.lang.String or str name: is the given name to check for collisions
        :param jpype.JLong or int startId: is the id specifying the starting namespace
        :param jpype.JLong or int stopId: is the id specifying the stopping namespace
        :return: true if the name (likely) occurs in one of the namespaces on the path
        :rtype: bool
        """

    def setFunction(self, func: ghidra.program.model.listing.Function, entry: ghidra.program.model.address.Address, dbg: DecompileDebug):
        """
        Establish function and debug context for next decompilation
        
        :param ghidra.program.model.listing.Function func: is the function to be decompiled
        :param ghidra.program.model.address.Address entry: is the function's entry address
        :param DecompileDebug dbg: is the debugging context (or null)
        """

    @property
    def nativeMessage(self) -> java.lang.String:
        ...

    @property
    def codeLabel(self) -> java.lang.String:
        ...

    @property
    def userOpName(self) -> java.lang.String:
        ...


class ClangFunction(ClangTokenGroup):
    """
    A grouping of source code tokens representing an entire function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: ClangNode, hfunc: ghidra.program.model.pcode.HighFunction):
        ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        """
        
        
        :return: the HighFunction object represented by this source code
        :rtype: ghidra.program.model.pcode.HighFunction
        """

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction:
        ...


class CTokenHighlightMatcher(java.lang.Object):
    """
    The interface that clients must define to create a :obj:`DecompilerHighlighter`
     
     
    Every function decompiled will trigger this matcher to get called.  The order of method
    calls is: :meth:`start(ClangNode) <.start>`, repeated calls to :meth:`getTokenHighlight(ClangToken) <.getTokenHighlight>`
    and then :meth:`end() <.end>`.
    
    
    .. seealso::
    
        | :obj:`DecompilerHighlightService`
    """

    class_: typing.ClassVar[java.lang.Class]

    def end(self):
        ...

    def getTokenHighlight(self, token: ClangToken) -> java.awt.Color:
        """
        The basic method clients must implement to determine if a token should be highlighted.
        Returning a non-null Color will trigger the given token to be highlighted.
        
        :param ClangToken token: the token
        :return: the highlight color or null
        :rtype: java.awt.Color
        """

    def start(self, root: ClangNode):
        ...

    @property
    def tokenHighlight(self) -> java.awt.Color:
        ...


class ClangCaseToken(ClangToken):
    """
    A token representing a switch "case" label, or other constant not directly linked to data-flow.
    The token has an associated constant value and a data-type
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...

    def getSwitchOp(self) -> ghidra.program.model.pcode.PcodeOp:
        """
        
        
        :return: the BRANCHIND PcodeOp that jumps to this label
        :rtype: ghidra.program.model.pcode.PcodeOp
        """

    @property
    def switchOp(self) -> ghidra.program.model.pcode.PcodeOp:
        ...


class ClangTokenGroup(ClangNode, java.lang.Iterable[ClangNode]):
    """
    A sequence of tokens that form a meaningful group in source code.  This group may
    break up into subgroups and may be part of a larger group.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...

    def AddTokenGroup(self, obj: ClangNode):
        """
        Add additional text to this group
        
        :param ClangNode obj: is the additional text
        """

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, pfactory: ghidra.program.model.pcode.PcodeFactory):
        """
        Decode this text from an encoded stream.
        
        :param ghidra.program.model.pcode.Decoder decoder: is the decoder for the stream
        :param ghidra.program.model.pcode.PcodeFactory pfactory: is used to look up p-code attributes to associate with tokens
        :raises DecoderException: for problems decoding the stream
        """

    def stream(self) -> java.util.stream.Stream[ClangNode]:
        """
        Gets a stream over this group's children
        
        :return: a stream of this group's children
        :rtype: java.util.stream.Stream[ClangNode]
        """

    def tokenIterator(self, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Iterator[ClangToken]:
        """
        Create iterator across all ClangToken objects in this group.
        The iterator will run over tokens in display order (forward=true) or in reverse of
        display order (forward=false)
        
        :param jpype.JBoolean or bool forward: is true for a forward iterator, false for a backward iterator
        :return: the iterator
        :rtype: java.util.Iterator[ClangToken]
        """


class ClangOpToken(ClangToken):
    """
    A token representing a source code "operation". This could be a keyword like
    "if" or "while" but could also be an operator like '+' or '*'.
    The token may contain an id for the p-code object representing the operation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, par: ClangNode):
        ...


class DecompilerLocation(java.lang.Object):
    """
    Represents a location in the Decompiler.  This interface allows the Decompiler to subclass more
    general :obj:`ProgramLocation`s while adding more detailed Decompiler information.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCharPos(self) -> int:
        """
        :return: the character position
        :rtype: int
        """

    def getDecompile(self) -> DecompileResults:
        """
        Results from the decompilation
        
        :return: C-AST, DFG, and CFG object. null if there are no results attached to this location
        :rtype: DecompileResults
        """

    def getFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...

    def getLineNumber(self) -> int:
        """
        :return: the line number
        :rtype: int
        """

    def getToken(self) -> ClangToken:
        """
        C text token at the current cursor location
        
        :return: token at this location, could be null if there are no decompiler results
        :rtype: ClangToken
        """

    def getTokenName(self) -> str:
        """
        :return: the name of the token for the current location
        :rtype: str
        """

    @property
    def charPos(self) -> jpype.JInt:
        ...

    @property
    def tokenName(self) -> java.lang.String:
        ...

    @property
    def decompile(self) -> DecompileResults:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def functionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def token(self) -> ClangToken:
        ...



__all__ = ["DecompilerHighlightService", "DecompilerDisposer", "DecompiledFunction", "ClangReturnType", "ClangSyntaxToken", "DecompilerLocationInfo", "DecompileException", "DecompileResults", "ClangVariableToken", "ClangLine", "ClangFuncProto", "ClangCommentToken", "ClangFuncNameToken", "TokenIterator", "ClangMarkup", "PrettyPrinter", "DecompileProcessFactory", "DecompileDebug", "ClangBreak", "ClangTypeToken", "ClangNode", "ClangFieldToken", "ClangVariableDecl", "DecompilerHighlighter", "DecompileProcess", "ClangLabelToken", "ClangStatement", "DecompInterface", "DecompilerMarginService", "ClangToken", "DecompileOptions", "DecompileCallback", "ClangFunction", "CTokenHighlightMatcher", "ClangCaseToken", "ClangTokenGroup", "ClangOpToken", "DecompilerLocation"]
