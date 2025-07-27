from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.template
import ghidra.app.util.pcode
import ghidra.pcode.opbehavior
import ghidra.pcodeCPort.sleighbase
import ghidra.pcodeCPort.slghsymbol
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.sleigh.grammar
import java.lang # type: ignore
import java.lang.annotation # type: ignore
import java.lang.reflect # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import org.antlr.runtime.tree # type: ignore
import org.apache.commons.lang3.tuple # type: ignore


A = typing.TypeVar("A")
B = typing.TypeVar("B")
L = typing.TypeVar("L")
R = typing.TypeVar("R")
S = typing.TypeVar("S")
T = typing.TypeVar("T")
U = typing.TypeVar("U")


class BytesPcodeExecutorStateSpace(java.lang.Object, typing.Generic[B]):
    """
    A p-code executor state space for storing and retrieving bytes as arrays
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, space: ghidra.program.model.address.AddressSpace, backing: B):
        """
        Construct an internal space for the given address space
        
        :param ghidra.program.model.lang.Language language: the language, for logging diagnostics
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param B backing: the backing object, possibly ``null``
        """

    def clear(self):
        ...

    def fork(self) -> BytesPcodeExecutorStateSpace[B]:
        ...

    def getRegisterValues(self, registers: java.util.List[ghidra.program.model.lang.Register]) -> java.util.Map[ghidra.program.model.lang.Register, jpype.JArray[jpype.JByte]]:
        ...

    def read(self, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], reason: PcodeExecutorStatePiece.Reason) -> jpype.JArray[jpype.JByte]:
        """
        Read a value from the space at the given offset
         
         
        
        If this space is not acting as a cache, this simply delegates to
        :meth:`readBytes(long, int, Reason) <.readBytes>`. Otherwise, it will first ensure the cache covers the
        requested value.
        
        :param jpype.JLong or int offset: the offset
        :param jpype.JInt or int size: the number of bytes to read (the size of the value)
        :param PcodeExecutorStatePiece.Reason reason: the reason for reading state
        :return: the bytes read
        :rtype: jpype.JArray[jpype.JByte]
        """

    def write(self, offset: typing.Union[jpype.JLong, int], val: jpype.JArray[jpype.JByte], srcOffset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Write a value at the given offset
        
        :param jpype.JLong or int offset: the offset
        :param jpype.JArray[jpype.JByte] val: the value
        :param jpype.JInt or int srcOffset: offset within val to start
        :param jpype.JInt or int length: the number of bytes to write
        """

    @property
    def registerValues(self) -> java.util.Map[ghidra.program.model.lang.Register, jpype.JArray[jpype.JByte]]:
        ...


class SleighUtils(java.lang.Enum[SleighUtils]):
    """
    A collection of utilities for parsing and manipulating Sleigh semantic source
    """

    class SleighParseErrorEntry(java.lang.Record):
        """
        A Sleigh parsing error
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, header: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], start: typing.Union[jpype.JInt, int], stop: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def fullMessage(self) -> str:
            ...

        def hashCode(self) -> int:
            ...

        def header(self) -> str:
            ...

        def message(self) -> str:
            ...

        def start(self) -> int:
            ...

        def stop(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class SleighParseError(java.lang.RuntimeException):
        """
        An exception carrying one or more Sleigh parsing errors
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, errors: collections.abc.Sequence):
            ...

        def getErrors(self) -> java.util.List[SleighUtils.SleighParseErrorEntry]:
            """
            Get the actual errors
            
            :return: the list of entries
            :rtype: java.util.List[SleighUtils.SleighParseErrorEntry]
            """

        @property
        def errors(self) -> java.util.List[SleighUtils.SleighParseErrorEntry]:
            ...


    class ParseFunction(java.lang.Object, typing.Generic[T]):
        """
        A function representing a non-terminal in the Sleigh semantic grammar
        """

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, parser: ghidra.sleigh.grammar.SleighParser) -> T:
            ...


    class MismatchException(java.lang.RuntimeException):
        """
        An exception indicating the parse tree did not match a pattern
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class AddressOf(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, space: typing.Union[java.lang.String, str], offset: org.antlr.runtime.tree.Tree):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def offset(self) -> org.antlr.runtime.tree.Tree:
            ...

        def space(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    CONDITION_ALWAYS: typing.Final = "1:1"
    UNCONDITIONAL_BREAK: typing.Final = "emu_swi();\nemu_exec_decoded();\n"

    @staticmethod
    def generateSleighExpression(tree: org.antlr.runtime.tree.Tree) -> str:
        """
        Generate source for the given Sleigh parse tree
         
         
        
        Currently, only nodes that could appear in a Sleigh expression are supported.
        
        :param org.antlr.runtime.tree.Tree tree: the expression tree
        :return: the generated string
        :rtype: str
        """

    @staticmethod
    def getChildren(tree: org.antlr.runtime.tree.Tree) -> java.util.List[org.antlr.runtime.tree.Tree]:
        """
        Get the children of a parse tree node
        
        :param org.antlr.runtime.tree.Tree tree: the node
        :return: the list of children
        :rtype: java.util.List[org.antlr.runtime.tree.Tree]
        """

    @staticmethod
    def isUnconditionalBreakpoint(tree: org.antlr.runtime.tree.Tree) -> bool:
        """
        Check if the given tree represents an unconditional breakpoint in the emulator
        
        :param org.antlr.runtime.tree.Tree tree: the result of parsing a semantic block
        :return: true if an unconditional breakpoint, false otherwise
        :rtype: bool
        """

    @staticmethod
    def makeTree(type: typing.Union[jpype.JInt, int], text: typing.Union[java.lang.String, str], children: java.util.List[org.antlr.runtime.tree.Tree]) -> org.antlr.runtime.tree.Tree:
        """
        Synthesize a tree (node)
        
        :param jpype.JInt or int type: the type of the node
        :param java.lang.String or str text: the "text" of the node
        :param java.util.List[org.antlr.runtime.tree.Tree] children: the children
        :return: the new node
        :rtype: org.antlr.runtime.tree.Tree
        """

    @staticmethod
    def match(tree: org.antlr.runtime.tree.Tree, type: typing.Union[jpype.JInt, int], *onChild: java.util.function.Consumer[org.antlr.runtime.tree.Tree]):
        """
        Match the given tree to a given pattern with per-child actions
        
        :param org.antlr.runtime.tree.Tree tree: the (sub-)tree to match, actually its root node
        :param jpype.JInt or int type: the expected type of the given node
        :param jpype.JArray[java.util.function.Consumer[org.antlr.runtime.tree.Tree]] onChild: a list of actions (usually sub-matching) to perform on each corresponding
                    child. The matcher will verify the number of children matches the number of
                    actions.
        """

    @staticmethod
    def matchDereference(tree: org.antlr.runtime.tree.Tree, onSpace: java.util.function.Consumer[org.antlr.runtime.tree.Tree], onSize: java.util.function.Consumer[org.antlr.runtime.tree.Tree], onOffset: java.util.function.Consumer[org.antlr.runtime.tree.Tree]):
        ...

    @staticmethod
    def matchTree(tree: org.antlr.runtime.tree.Tree, type: typing.Union[jpype.JInt, int], onChildren: java.util.function.Consumer[java.util.List[org.antlr.runtime.tree.Tree]]):
        """
        Match the given tree to a given pattern
        
        :param org.antlr.runtime.tree.Tree tree: the (sub-)tree to match, actually its root node
        :param jpype.JInt or int type: the expected type of the given node
        :param java.util.function.Consumer[java.util.List[org.antlr.runtime.tree.Tree]] onChildren: actions (usually sub-matching) to perform on the children
        """

    @staticmethod
    def notTree(boolExpr: org.antlr.runtime.tree.Tree) -> org.antlr.runtime.tree.Tree:
        """
        Apply the boolean "not" operator to a Sleigh expression
         
         
        
        This will attempt to invert the expression when possible, e.g., by changing a top-level
        "equals" to "not equals." If that is not possible, the this adds parenthesis and applies the
        actual Sleigh boolean "not" operator.
        
        :param org.antlr.runtime.tree.Tree boolExpr: the result of parsing a Sleigh expression
        :return: the tree for the inverted expression
        :rtype: org.antlr.runtime.tree.Tree
        """

    @staticmethod
    def parseSleigh(nt: SleighUtils.ParseFunction[T], text: typing.Union[java.lang.String, str], follow: typing.Union[java.lang.String, str]) -> T:
        """
        Parse a non-terminal symbol from the Sleigh semantic grammar
         
         
        
        Because the ANTLR parsing function for the non-terminal symbol depends on the "follows" set
        to determine when it has finished, we can't just invoke the function in isolation without
        some hacking. If EOF is not in the non-terminal's follows set, then it won't recognize EOF as
        completing the non-terminal. Instead, we have to present some token that it will recognize.
        Furthermore, regardless of the follow token, we have to check that all of the given input was
        consumed by the parser.
        
        :param T: the type of result from parsing:param SleighUtils.ParseFunction[T] nt: the function from the parser implementing the non-terminal symbol
        :param java.lang.String or str text: the text to parse
        :param java.lang.String or str follow: a token that would ordinarily follow the non-terminal symbol, or empty for EOF
        :return: the parsed result
        :rtype: T
        """

    @staticmethod
    def parseSleighExpression(expression: typing.Union[java.lang.String, str]) -> org.antlr.runtime.tree.Tree:
        """
        Parse a semantic expression
        
        :param java.lang.String or str expression: the expression as a string
        :return: the parse tree
        :rtype: org.antlr.runtime.tree.Tree
        """

    @staticmethod
    def parseSleighSemantic(sleigh: typing.Union[java.lang.String, str]) -> org.antlr.runtime.tree.Tree:
        """
        Parse a semantic block, that is a list of Sleigh semantic statements
        
        :param java.lang.String or str sleigh: the source
        :return: the parse tree
        :rtype: org.antlr.runtime.tree.Tree
        """

    @staticmethod
    @typing.overload
    def recoverAddressOf(defaultSpace: typing.Union[java.lang.String, str], tree: org.antlr.runtime.tree.Tree) -> SleighUtils.AddressOf:
        ...

    @staticmethod
    @typing.overload
    def recoverAddressOf(defaultSpace: typing.Union[java.lang.String, str], expression: typing.Union[java.lang.String, str]) -> SleighUtils.AddressOf:
        ...

    @staticmethod
    @typing.overload
    def recoverConditionFromBreakpoint(tree: org.antlr.runtime.tree.Tree) -> str:
        """
        Check if the given tree represents a conditional breakpoint, and recover that condition
        
        :param org.antlr.runtime.tree.Tree tree: the result of parsing a semantic block
        :return: the condition if matched, null otherwise
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def recoverConditionFromBreakpoint(sleigh: typing.Union[java.lang.String, str]) -> str:
        """
        Check if the given Sleigh semantic block implements a conditional breakpoint, and recover
        that condition
        
        :param java.lang.String or str sleigh: the source for a Sleigh semantic block
        :return: the condition if matched, null otherwise
        :rtype: str
        """

    @staticmethod
    def removeParenthesisTree(tree: org.antlr.runtime.tree.Tree) -> org.antlr.runtime.tree.Tree:
        """
        Remove parenthesis from the root of the given tree
         
         
        
        If the root is parenthesis, this simply gets the child. This is applied recursively until a
        non-parenthesis child is encountered.
        
        :param org.antlr.runtime.tree.Tree tree: the result of parsing a Sleigh expression
        :return: the same or sub-tree
        :rtype: org.antlr.runtime.tree.Tree
        """

    @staticmethod
    def requireCount(count: typing.Union[jpype.JInt, int], list: java.util.List[typing.Any]):
        """
        Require (as part of pattern matching) that the given list of children has a particular size
        
        :param jpype.JInt or int count: the required size
        :param java.util.List[typing.Any] list: the list of children
        """

    @staticmethod
    def sleighForConditionalBreak(condition: typing.Union[java.lang.String, str]) -> str:
        """
        Generate Sleigh source for a breakpoint predicated on the given condition
        
        :param java.lang.String or str condition: a Sleigh expression
        :return: the Sleigh source
        :rtype: str
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SleighUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[SleighUtils]:
        ...


class PcodeFrame(java.lang.Object):
    """
    The executor's internal counter
     
     
    
    To distinguish the program counter of a p-code program from the program counter of the machine it
    models, we address p-code ops by "index." When derived from an instruction, the address and index
    together form the "sequence number." Because the executor care's not about the derivation of a
    p-code program, it counts through indices. The frame carries with it the p-code ops comprising
    its current p-code program.
     
     
    
    A p-code emulator feeds p-code to an executor by decoding one instruction at a time. Thus, the
    "current p-code program" comprises only those ops generated by a single instruction. Or else, it
    is a user-supplied p-code program, e.g., to evaluate a Sleigh expression. The frame completes the
    program by falling-through, i.e., stepping past the final op, or by branching externally, i.e.,
    to a different machine instruction. The emulator must then update its program counter accordingly
    and proceed to the next instruction.
    """

    @typing.type_check_only
    class MyAppender(ghidra.app.util.pcode.AbstractAppender[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language):
            ...


    @typing.type_check_only
    class MyFormatter(ghidra.app.util.pcode.AbstractPcodeFormatter[java.lang.String, PcodeFrame.MyAppender]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, code: java.util.List[ghidra.program.model.pcode.PcodeOp], useropNames: collections.abc.Mapping):
        """
        Construct a frame of p-code execution
         
         
        
        The passed in code should be an immutable list. It is returned directly by
        :meth:`getCode() <.getCode>`, which would otherwise allow mutation. The frame does not create its own
        immutable copy as a matter of efficiency. Instead, the provider of the code should create an
        immutable copy, probably once, e.g., when compiling a :obj:`PcodeProgram`.
        
        :param ghidra.program.model.lang.Language language: the language to which the program applies
        :param java.util.List[ghidra.program.model.pcode.PcodeOp] code: the program's p-code
        :param collections.abc.Mapping useropNames: a map of additional sleigh/p-code userops linked to the program
        """

    def advance(self) -> int:
        """
        Advance the index
        
        :return: the value of the index *before* it was advanced
        :rtype: int
        """

    def branch(self, rel: typing.Union[jpype.JInt, int]):
        """
        Perform an internal branch, relative to the *current op*.
         
         
        
        Because index advances before execution of each op, the index is adjusted by an extra -1.
        
        :param jpype.JInt or int rel: the adjustment to the index
        """

    def copyCode(self) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        """
        Copy the frame's code (shallow copy) into a new array
        
        :return: the array of ops
        :rtype: jpype.JArray[ghidra.program.model.pcode.PcodeOp]
        """

    def finishAsBranch(self):
        """
        Complete the p-code program, indicating an external branch
        """

    def getBranched(self) -> int:
        """
        Get the index of the last (branch) op executed
         
         
        
        The behavior here is a bit strange for compatibility with
        :obj:`EmulateInstructionStateModifier`. If the p-code program (likely derived from a machine
        instruction) completed with fall-through, then this will return -1. If it completed on a
        branch, then this will return the index of that branch.
        
        :return: the last index executed
        :rtype: int
        """

    def getCode(self) -> java.util.List[ghidra.program.model.pcode.PcodeOp]:
        """
        Get all the ops in the current p-code program.
        
        :return: the list of ops
        :rtype: java.util.List[ghidra.program.model.pcode.PcodeOp]
        """

    def getUseropName(self, userop: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the name of the userop for the given number
        
        :param jpype.JInt or int userop: the userop number, as encoded in the first operand of :obj:`PcodeOp.CALLOTHER`
        :return: the name of the userop, as expressed in the Sleigh source
        :rtype: str
        """

    def getUseropNames(self) -> java.util.Map[java.lang.Integer, java.lang.String]:
        """
        Get the map of userop numbers to names
        
        :return: the map
        :rtype: java.util.Map[java.lang.Integer, java.lang.String]
        """

    def index(self) -> int:
        """
        The index of the *next* p-code op to be executed
         
         
        
        If the last p-code op resulted in a branch, this will instead return -1.
        
        :return: the index, i.e, p-code "program counter."
        :rtype: int
        
        .. seealso::
        
            | :obj:`.isBranch()`
        
            | :obj:`.isFallThrough()`
        
            | :obj:`.isFinished()`
        """

    def isBranch(self) -> bool:
        """
        Check if the p-code program has executed a branch
         
         
        
        Branches can be internal, i.e., within the current program, or external, i.e., to another
        machine instructions. This refers strictly to the latter.
        
        :return: true if the program completed with an external branch
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.isFallThrough()`
        
            | :obj:`.isFinished()`
        """

    def isFallThrough(self) -> bool:
        """
        Check if the index has advanced past the end of the p-code program
         
         
        
        If the index has advanced beyond the program, it implies the program has finished executing.
        In the case of instruction emulation, no branch was encountered. The machine should advance
        to the fall-through instruction.
        
        :return: true if the program completed without branching
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.isBranch()`
        
            | :obj:`.isFinished()`
        """

    def isFinished(self) -> bool:
        """
        Check if the p-code program is completely executed
        
        :return: true if execution finished, either in fall-through or an external branch
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.isFallThrough()`
        
            | :obj:`.isBranch()`
        """

    def nextOp(self) -> ghidra.program.model.pcode.PcodeOp:
        """
        Get the op at the current index, and then advance that index
         
         
        
        This is used in the execution loop to retrieve each op to execute
        
        :return: the op to execute
        :rtype: ghidra.program.model.pcode.PcodeOp
        """

    def resetCount(self) -> int:
        """
        Get and reset the number of p-code ops executed
         
         
        
        Contrast this to :meth:`index() <.index>`, which marks the next op to be executed. This counts the
        number of ops executed, which will differ from index when an internal branch is taken.
        
        :return: the count
        :rtype: int
        """

    def stepBack(self) -> int:
        """
        Step the index back one
        
        :return: the value of the index *before* it was stepped back
        :rtype: int
        """

    @property
    def useropName(self) -> java.lang.String:
        ...

    @property
    def code(self) -> java.util.List[ghidra.program.model.pcode.PcodeOp]:
        ...

    @property
    def fallThrough(self) -> jpype.JBoolean:
        ...

    @property
    def useropNames(self) -> java.util.Map[java.lang.Integer, java.lang.String]:
        ...

    @property
    def finished(self) -> jpype.JBoolean:
        ...

    @property
    def branched(self) -> jpype.JInt:
        ...


class DefaultPcodeExecutorState(PcodeExecutorState[T], typing.Generic[T]):
    """
    A p-code executor state formed from a piece whose address and value types are the same
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, piece: PcodeExecutorStatePiece[T, T], arithmetic: PcodeArithmetic[T]):
        ...

    @typing.overload
    def __init__(self, piece: PcodeExecutorStatePiece[T, T]):
        ...


class AddressesReadPcodeArithmetic(java.lang.Enum[AddressesReadPcodeArithmetic], PcodeArithmetic[ghidra.program.model.address.AddressSetView]):
    """
    An auxilliary arithmetic that reports the union of all addresses read, typically during the
    evaluation of an expression.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[AddressesReadPcodeArithmetic]
    """
    The singleton instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> AddressesReadPcodeArithmetic:
        ...

    @staticmethod
    def values() -> jpype.JArray[AddressesReadPcodeArithmetic]:
        ...


class LocationPcodeExecutorStatePiece(PcodeExecutorStatePiece[jpype.JArray[jpype.JByte], ValueLocation]):
    """
    An auxiliary state piece that reports the location of the control value
     
     
    
    This is intended for use as the right side of a :obj:`PairedPcodeExecutorState` or
    :obj:`PairedPcodeExecutorStatePiece`. Except for unique spaces, sets are ignored, and gets
    simply echo back the location of the requested read. In unique spaces, the "location" is treated
    as the value, so that values transiting unique space can correctly have their source locations
    reported.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Construct a "location" state piece
        
        :param ghidra.program.model.lang.Language language: the language of the machine
        """


class ConcretionError(PcodeExecutionException):
    """
    The emulator or a client attempted to concretize an abstract value
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str], purpose: PcodeArithmetic.Purpose):
        """
        Create the exception
        
        :param java.lang.String or str message: a message for the client
        :param PcodeArithmetic.Purpose purpose: the reason why the emulator needs a concrete value
        """

    def getPurpose(self) -> PcodeArithmetic.Purpose:
        """
        Get the reason why the emulator needs a concrete value
        
        :return: the purpose
        :rtype: PcodeArithmetic.Purpose
        """

    @property
    def purpose(self) -> PcodeArithmetic.Purpose:
        ...


class BytesPcodeExecutorState(DefaultPcodeExecutorState[jpype.JArray[jpype.JByte]]):
    """
    A state composing a single :obj:`BytesPcodeExecutorStatePiece`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Create the state
        
        :param ghidra.program.model.lang.Language language: the language (processor model)
        """


class AbstractBytesPcodeExecutorStatePiece(AbstractLongOffsetPcodeExecutorStatePiece[jpype.JArray[jpype.JByte], jpype.JArray[jpype.JByte], S], typing.Generic[S]):
    """
    An abstract p-code executor state piece for storing and retrieving bytes as arrays
    """

    @typing.type_check_only
    class StateMemBuffer(ghidra.program.model.mem.MemBufferMixin):
        """
        A memory buffer bound to a given space in this state
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, address: ghidra.program.model.address.Address, source: BytesPcodeExecutorStateSpace[typing.Any], reason: PcodeExecutorStatePiece.Reason):
            """
            Construct a buffer bound to the given space, at the given address
            
            :param ghidra.program.model.address.Address address: the address
            :param BytesPcodeExecutorStateSpace[typing.Any] source: the space
            :param PcodeExecutorStatePiece.Reason reason: the reason this buffer reads from the state, as in
                        :meth:`PcodeExecutorStatePiece.getVar(Varnode, Reason) <PcodeExecutorStatePiece.getVar>`
            """


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Construct a state for the given language
        
        :param ghidra.program.model.lang.Language language: the language, used for its memory model and arithmetic
        """

    @typing.overload
    def __init__(self, language: ghidra.program.model.lang.Language, arithmetic: PcodeArithmetic[jpype.JArray[jpype.JByte]]):
        """
        Construct a state for the given language
        
        :param ghidra.program.model.lang.Language language: the language, used for its memory model
        :param PcodeArithmetic[jpype.JArray[jpype.JByte]] arithmetic: the arithmetic
        """


class PcodeProgram(java.lang.Object):
    """
    A p-code program to be executed by a :obj:`PcodeExecutor`
     
     
    
    This is a list of p-code operations together with a map of expected userops.
    """

    @typing.type_check_only
    class MyAppender(ghidra.app.util.pcode.AbstractAppender[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: PcodeProgram, language: ghidra.program.model.lang.Language, numberOps: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class MyFormatter(ghidra.app.util.pcode.AbstractPcodeFormatter[java.lang.String, PcodeProgram.MyAppender]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: PcodeProgram, numberOps: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: PcodeProgram, code: java.util.List[ghidra.program.model.pcode.PcodeOp]):
        """
        Construct a p-code program from a derivative of the given one
        
        :param PcodeProgram program: the original program
        :param java.util.List[ghidra.program.model.pcode.PcodeOp] code: the code portion for this program
        """

    def execute(self, executor: PcodeExecutor[T], library: PcodeUseropLibrary[T]):
        """
        Execute this program using the given executor and library
        
        :param T: the type of values to be operated on:param PcodeExecutor[T] executor: the executor
        :param PcodeUseropLibrary[T] library: the library
        """

    @typing.overload
    def format(self, numberOps: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @typing.overload
    def format(self) -> str:
        ...

    @staticmethod
    def fromInject(program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], type: typing.Union[jpype.JInt, int]) -> PcodeProgram:
        """
        Generate a p-code program from a given program's inject library
        
        :param ghidra.program.model.listing.Program program: the program
        :param java.lang.String or str name: the name of the snippet
        :param jpype.JInt or int type: the type of the snippet
        :return: the p-code program
        :rtype: PcodeProgram
        :raises MemoryAccessException: for problems establishing the injection context
        :raises IOException: for problems while emitting the injection p-code
        :raises UnknownInstructionException: if there is no underlying instruction being injected
        :raises NotFoundException: if an expected aspect of the injection is not present in context
        """

    @staticmethod
    @typing.overload
    def fromInstruction(instruction: ghidra.program.model.listing.Instruction) -> PcodeProgram:
        """
        Generate a p-code program from the given instruction, without overrides
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :return: the p-code program
        :rtype: PcodeProgram
        """

    @staticmethod
    @typing.overload
    def fromInstruction(instruction: ghidra.program.model.listing.Instruction, includeOverrides: typing.Union[jpype.JBoolean, bool]) -> PcodeProgram:
        """
        Generate a p-code program from the given instruction
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JBoolean or bool includeOverrides: as in :meth:`Instruction.getPcode(boolean) <Instruction.getPcode>`
        :return: the p-code program
        :rtype: PcodeProgram
        """

    def getCode(self) -> java.util.List[ghidra.program.model.pcode.PcodeOp]:
        ...

    def getLanguage(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        """
        Get the language generating this program
        
        :return: the language
        :rtype: ghidra.app.plugin.processors.sleigh.SleighLanguage
        """

    def getUseropName(self, opNo: typing.Union[jpype.JInt, int]) -> str:
        ...

    @property
    def useropName(self) -> java.lang.String:
        ...

    @property
    def code(self) -> java.util.List[ghidra.program.model.pcode.PcodeOp]:
        ...

    @property
    def language(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        ...


class InjectionErrorPcodeExecutionException(PcodeExecutionException):
    """
    Exception thrown by :meth:`PcodeEmulationLibrary.emu_injection_err() <PcodeEmulationLibrary.emu_injection_err>`, a p-code userop invoked
    when client-provided Sleigh code in an injection could not be compiled.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, frame: PcodeFrame, cause: java.lang.Throwable):
        ...


class PcodeArithmetic(java.lang.Object, typing.Generic[T]):
    """
    An interface that defines arithmetic p-code operations on values of type ``T``.
    
     
    
    See :obj:`BytesPcodeArithmetic` for the typical pattern when implementing an arithmetic. There
    are generally two cases: 1) Where endianness matters, 2) Where endianness does not matter. The
    first is typical. The implementation should be an :obj:`Enum` with two constants, one for the
    big endian implementation, and one for the little endian implementation. The class should also
    provide static methods: ``forEndian(boolean isBigEndian)`` for getting the correct one based
    on endianness, and ``forLanguage(Language language)`` for getting the correct one given a
    language. If endianness does not matter, then the implementation should follow a singleton
    pattern. See notes on :meth:`getEndian() <.getEndian>` for the endian-agnostic case.
    """

    class Purpose(java.lang.Enum[PcodeArithmetic.Purpose]):
        """
        Reasons for requiring a concrete value
        """

        class_: typing.ClassVar[java.lang.Class]
        DECODE: typing.Final[PcodeArithmetic.Purpose]
        """
        The value is needed to parse an instruction
        """

        CONTEXT: typing.Final[PcodeArithmetic.Purpose]
        """
        The value is needed for disassembly context
        """

        CONDITION: typing.Final[PcodeArithmetic.Purpose]
        """
        The value is needed to decide a conditional branch
        """

        BRANCH: typing.Final[PcodeArithmetic.Purpose]
        """
        The value will be used as the address of an indirect branch
        """

        LOAD: typing.Final[PcodeArithmetic.Purpose]
        """
        The value will be used as the address of a value to load
        """

        STORE: typing.Final[PcodeArithmetic.Purpose]
        """
        The value will be used as the address of a value to store
        """

        OTHER: typing.Final[PcodeArithmetic.Purpose]
        """
        Some other reason, perhaps for userop library use
        """

        INSPECT: typing.Final[PcodeArithmetic.Purpose]
        """
        The user or a tool is inspecting the value
        """


        def reason(self) -> PcodeExecutorStatePiece.Reason:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PcodeArithmetic.Purpose:
            ...

        @staticmethod
        def values() -> jpype.JArray[PcodeArithmetic.Purpose]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    SIZEOF_SIZEOF: typing.Final = 8
    """
    The number of bytes needed to encode the size (in bytes) of any value
    """


    @typing.overload
    def binaryOp(self, opcode: typing.Union[jpype.JInt, int], sizeout: typing.Union[jpype.JInt, int], sizein1: typing.Union[jpype.JInt, int], in1: T, sizein2: typing.Union[jpype.JInt, int], in2: T) -> T:
        """
        Apply a binary operator to the given inputs
         
         
        
        Note the sizes of variables are given, because values don't necessarily have an intrinsic
        size. For example, a :obj:`BigInteger` may have a minimum encoding size, but that does not
        necessarily reflect the size of the variable from which is was read.
        
        
        .. admonition:: Implementation Note
        
            :meth:`OpBehaviorFactory.getOpBehavior(int) <OpBehaviorFactory.getOpBehavior>` for the given opcode is guaranteed to
            return a derivative of :obj:`BinaryOpBehavior`.
        
        
        :param jpype.JInt or int opcode: the operation's opcode. See :obj:`PcodeOp`.
        :param jpype.JInt or int sizeout: the size (in bytes) of the output variable
        :param jpype.JInt or int sizein1: the size (in bytes) of the first (left) input variable
        :param T in1: the first (left) input value
        :param jpype.JInt or int sizein2: the size (in bytes) of the second (right) input variable
        :param T in2: the second (right) input value
        :return: the output value
        :rtype: T
        """

    @typing.overload
    def binaryOp(self, op: ghidra.program.model.pcode.PcodeOp, in1: T, in2: T) -> T:
        """
        Apply a binary operator to the given input
         
         
        
        This provides the full p-code op, allowing deeper inspection of the code. For example, an
        arithmetic may wish to distinguish immediate (constant) values from variables. By default,
        this unpacks the details and defers to :meth:`binaryOp(int, int, int, Object, int, Object) <.binaryOp>`.
        
        
        .. admonition:: Implementation Note
        
            :meth:`OpBehaviorFactory.getOpBehavior(int) <OpBehaviorFactory.getOpBehavior>` for the given opcode is guaranteed to
            return a derivative of :obj:`BinaryOpBehavior`.
        
        
        :param ghidra.program.model.pcode.PcodeOp op: the operation
        :param T in1: the first (left) input value
        :param T in2: the second (right) input value
        :return: the output value
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: jpype.JArray[jpype.JByte]) -> T:
        """
        Convert the given constant concrete value to type ``T`` having the same size.
        
        :param jpype.JArray[jpype.JByte] value: the constant value
        :return: the value as a ``T``
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: typing.Union[jpype.JByte, int], size: typing.Union[jpype.JInt, int]) -> T:
        """
        Convert a ``byte`` to ``T``, with unsigned extension
        
        :param jpype.JByte or int value: the constant value
        :param jpype.JInt or int size: the size in bytes
        :return: the value
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: typing.Union[jpype.JShort, int], size: typing.Union[jpype.JInt, int]) -> T:
        """
        Convert a ``short`` to ``T``, with unsigned extension
        
        :param jpype.JShort or int value: the constant value
        :param jpype.JInt or int size: the size in bytes
        :return: the value
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> T:
        """
        Convert an ``int`` to ``T``, with unsigned extension
        
        :param jpype.JInt or int value: the constant value
        :param jpype.JInt or int size: the size in bytes
        :return: the value
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> T:
        """
        Convert the given constant concrete value to type ``T`` having the given size.
         
         
        
        Note that the size may not be applicable to ``T``. It is given to ensure the value can be
        held in a variable of that size when passed to downstream operators or stored in the executor
        state.
        
        :param jpype.JLong or int value: the constant value
        :param jpype.JInt or int size: the size (in bytes) of the variable into which the value is to be stored
        :return: the value as a ``T``
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: typing.Union[jpype.JFloat, float], size: typing.Union[jpype.JInt, int]) -> T:
        """
        Convert a ``float`` to ``T``
         
         
        
        If size is not :const:`Float.BYTES`, bytes are truncated or passed with 0s, according to
        machine endianness.
        
        :param jpype.JFloat or float value: the constant value
        :param jpype.JInt or int size: the size in bytes
        :return: the value
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: typing.Union[jpype.JDouble, float], size: typing.Union[jpype.JInt, int]) -> T:
        """
        Convert a ``double`` to ``T``
         
         
        
        If size is not :const:`Double.BYTES`, bytes are truncated or passed with 0s, according to
        machine endianness.
        
        :param jpype.JDouble or float value: the constant value
        :param jpype.JInt or int size: the size in bytes
        :return: the value
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: typing.Union[jpype.JBoolean, bool], size: typing.Union[jpype.JInt, int]) -> T:
        """
        Convert a ``boolean`` to ``T``
         
         
        
        ``true`` is represented as 1, and ``false`` as 0, padded to the given size.
        
        :param jpype.JBoolean or bool value: the constant value
        :param jpype.JInt or int size: the size in bytes
        :return: the value
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: java.math.BigInteger, size: typing.Union[jpype.JInt, int], isContextreg: typing.Union[jpype.JBoolean, bool]) -> T:
        """
        Convert the given constant concrete value to type ``T`` having the given size.
         
         
        
        Note that the size may not be applicable to ``T``. It is given to ensure the value can be
        held in a variable of that size when passed to downstream operators or stored in the executor
        state.
        
        :param java.math.BigInteger value: the constant value
        :param jpype.JInt or int size: the size (in bytes) of the variable into which the value is to be stored
        :param jpype.JBoolean or bool isContextreg: true to indicate the value is from the disassembly context register. If
                    ``T`` represents bytes, and the value is the contextreg, then the bytes are in
                    big endian, no matter the machine language's endianness.
        :return: the value as a ``T``
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: ghidra.program.model.lang.RegisterValue) -> T:
        """
        Convert the given constant concrete register value to type ``T``
        
        :param ghidra.program.model.lang.RegisterValue value: the register value
        :return: the value as a ``T``
        :rtype: T
        """

    @typing.overload
    def fromConst(self, value: java.math.BigInteger, size: typing.Union[jpype.JInt, int]) -> T:
        """
        Convert the given constant concrete value to type ``T`` having the given size.
         
         
        
        The value is assumed *not* to be for the disassembly context register.
        
        :param java.math.BigInteger value: the constant value
        :param jpype.JInt or int size: the size (in bytes) of the variable into which the value is to be stored
        :return: the value as a ``T``
        :rtype: T
        
        .. seealso::
        
            | :obj:`.fromConst(BigInteger, int, boolean)`
        """

    def getEndian(self) -> ghidra.program.model.lang.Endian:
        """
        Get the endianness of this arithmetic
         
         
        
        Often T is a byte array, or at least represents one abstractly. Ideally, it is an array where
        each element is an abstraction of a byte. If that is the case, then the arithmetic likely has
        to interpret those bytes as integral values according to an endianness. This should return
        that endianness.
         
         
        
        If the abstraction has no notion of endianness, return null. In that case, the both
        :meth:`fromConst(BigInteger, int, boolean) <.fromConst>` and :meth:`fromConst(long, int) <.fromConst>` must be
        overridden. Furthermore, unless :meth:`toConcrete(Object, Purpose) <.toConcrete>` is guaranteed to throw
        an exception, then :meth:`toBigInteger(Object, Purpose) <.toBigInteger>` and
        :meth:`toLong(Object, Purpose) <.toLong>` must also be overridden.
        
        :return: the endianness or null
        :rtype: ghidra.program.model.lang.Endian
        """

    def isTrue(self, cond: T, purpose: PcodeArithmetic.Purpose) -> bool:
        """
        Convert, if possible, the given abstract condition to a concrete boolean value
        
        :param T cond: the abstract condition
        :param PcodeArithmetic.Purpose purpose: probably :obj:`Purpose.CONDITION`
        :return: the boolean value
        :rtype: bool
        """

    @typing.overload
    def modAfterLoad(self, sizeinOffset: typing.Union[jpype.JInt, int], space: ghidra.program.model.address.AddressSpace, inOffset: T, sizeinValue: typing.Union[jpype.JInt, int], inValue: T) -> T:
        """
        Apply any modifications after a value is loaded
         
         
        
        This implements any abstractions associated with :obj:`PcodeOp.LOAD`. This is called on the
        address/offset and the value after the value is actually loaded from the state. **NOTE:**
        LOAD ops always quantize the offset.
        
        :param jpype.JInt or int sizeinOffset: the size (in bytes) of the variable used for indirection
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param T inOffset: the value used as the offset
        :param jpype.JInt or int sizeinValue: the size (in bytes) of the variable loaded and of the output variable
        :param T inValue: the value loaded
        :return: the modified value loaded
        :rtype: T
        """

    @typing.overload
    def modAfterLoad(self, op: ghidra.program.model.pcode.PcodeOp, space: ghidra.program.model.address.AddressSpace, inOffset: T, inValue: T) -> T:
        """
        Apply any modifications after a value is loaded
         
         
        
        This provides the full p-code op, allowing deeper inspection of the code. **NOTE:** LOAD
        ops always quantize the offset.
        
        :param ghidra.program.model.pcode.PcodeOp op: the operation
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param T inOffset: the value used as the offset
        :param T inValue: the value loaded
        :return: the modified value loaded
        :rtype: T
        """

    @typing.overload
    def modBeforeStore(self, sizeinOffset: typing.Union[jpype.JInt, int], space: ghidra.program.model.address.AddressSpace, inOffset: T, sizeinValue: typing.Union[jpype.JInt, int], inValue: T) -> T:
        """
        Apply any modifications before a value is stored
         
         
        
        This implements any abstractions associated with :obj:`PcodeOp.STORE`. This is called on the
        offset and the value before the value is actually stored into the state. **NOTE:** STORE
        ops always quantize the offset.
        
        :param jpype.JInt or int sizeinOffset: the size (in bytes) of the variable used for indirection
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param T inOffset: the value used as the address (or offset)
        :param jpype.JInt or int sizeinValue: the size (in bytes) of the variable to store and of the output variable
        :param T inValue: the value to store
        :return: the modified value to store
        :rtype: T
        """

    @typing.overload
    def modBeforeStore(self, op: ghidra.program.model.pcode.PcodeOp, space: ghidra.program.model.address.AddressSpace, inOffset: T, inValue: T) -> T:
        """
        Apply any modifications before a value is stored
         
         
        
        This provides the full p-code op, allowing deeper inspection of the code. **NOTE:** STORE
        ops always quantize the offset.
        
        :param ghidra.program.model.pcode.PcodeOp op: the operation
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param T inOffset: the value used as the offset
        :param T inValue: the value to store
        :return: the modified value to store
        :rtype: T
        """

    def ptrAdd(self, sizeout: typing.Union[jpype.JInt, int], sizeinBase: typing.Union[jpype.JInt, int], inBase: T, sizeinIndex: typing.Union[jpype.JInt, int], inIndex: T, inSize: typing.Union[jpype.JInt, int]) -> T:
        """
        Apply the :obj:`PcodeOp.PTRADD` operator to the given inputs
         
         
        
        The "pointer add" op takes three operands: base, index, size; and is used as a more compact
        representation of array index address computation. The ``size`` operand must be constant.
        Suppose ``arr`` is an array whose elements are ``size`` bytes each, and the address
        of its first element is ``base``. The decompiler would likely render the
        :obj:`PcodeOp.PTRADD` op as ``&arr[index]``. An equivalent SLEIGH expression is
        ``base + index*size``.
         
         
        
        NOTE: This op is always a result of decompiler simplification, not low p-code generation, and
        so are not ordinarily used by a :obj:`PcodeExecutor`.
        
        :param jpype.JInt or int sizeout: the size (in bytes) of the output variable
        :param jpype.JInt or int sizeinBase: the size (in bytes) of the variable used for the array's base address
        :param T inBase: the value used as the array's base address
        :param jpype.JInt or int sizeinIndex: the size (in bytes) of the variable used for the index
        :param T inIndex: the value used as the index
        :param jpype.JInt or int inSize: the size of each array element in bytes
        :return: the output value
        :rtype: T
        """

    def ptrSub(self, sizeout: typing.Union[jpype.JInt, int], sizeinBase: typing.Union[jpype.JInt, int], inBase: T, sizeinOffset: typing.Union[jpype.JInt, int], inOffset: T) -> T:
        """
        Apply the :obj:`PcodeOp.PTRSUB` operator to the given inputs
         
         
        
        The "pointer subfield" op takes two operands: base, offset; and is used as a more specific
        representation of structure field address computation. Its behavior is exactly equivalent to
        :obj:`PcodeOp.INT_ADD`. Suppose ``st`` is a structure pointer with a field ``f``
        located ``inOffset`` bytes into the structure, and ``st`` has the value ``base``.
        The decompiler would likely render the :obj:`PcodeOp.PTRSUB` op as ``&st->f``. An
        equivalent SLEIGH expression is ``base + offset``.
         
         
        
        NOTE: This op is always a result of decompiler simplification, not low p-code generation, and
        so are not ordinarily used by a :obj:`PcodeExecutor`.
        
        :param jpype.JInt or int sizeout: the size (in bytes) of the output variable
        :param jpype.JInt or int sizeinBase: the size (in bytes) of the variable used for the structure's base address
        :param T inBase: the value used as the structure's base address
        :param jpype.JInt or int sizeinOffset: the size (in bytes) of the variable used for the offset
        :param T inOffset: the value used as the offset
        :return: the output value
        :rtype: T
        """

    def sizeOf(self, value: T) -> int:
        """
        Get the size in bytes, if possible, of the given abstract value
         
         
        
        If the abstract value does not conceptually have a size, throw an exception.
        
        :param T value: the abstract value
        :return: the size in bytes
        :rtype: int
        """

    def sizeOfAbstract(self, value: T) -> T:
        """
        Get the size in bytes, if possible, of the given abstract value, as an abstract value
         
         
        
        The returned size should itself has a size of :obj:`.SIZEOF_SIZEOF`.
        
        :param T value: the abstract value
        :return: the size in bytes, as an abstract value
        :rtype: T
        """

    def toBigInteger(self, value: T, purpose: PcodeArithmetic.Purpose) -> java.math.BigInteger:
        """
        Convert, if possible, the given abstract value to a concrete big integer
         
         
        
        If the conversion is not possible, throw an exception.
        
        :param T value: the abstract value
        :param PcodeArithmetic.Purpose purpose: the reason why the emulator needs a concrete value
        :return: the concrete value
        :rtype: java.math.BigInteger
        :raises ConcretionError: if the value cannot be made concrete
        """

    def toBoolean(self, value: T, purpose: PcodeArithmetic.Purpose) -> bool:
        """
        Convert, if possible, the given abstract value to a concrete boolean
         
         
        
        Any non-zero value is considered true
        
        :param T value: the abstract value
        :param PcodeArithmetic.Purpose purpose: the reason why the emulator needs a concrete value
        :return: the concrete value
        :rtype: bool
        :raises ConcretionError: if the value cannot be made concrete
        """

    def toConcrete(self, value: T, purpose: PcodeArithmetic.Purpose) -> jpype.JArray[jpype.JByte]:
        """
        Convert, if possible, the given abstract value to a concrete byte array
        
        :param T value: the abstract value
        :param PcodeArithmetic.Purpose purpose: the purpose for which the emulator needs a concrete value
        :return: the array
        :rtype: jpype.JArray[jpype.JByte]
        :raises ConcretionError: if the value cannot be made concrete
        """

    def toDouble(self, value: T, purpose: PcodeArithmetic.Purpose) -> float:
        """
        Convert, if possible, the given abstract value to a concrete double
         
         
        
        If value does not have size :const:`Double.BYTES`, it is truncated or padded, according to
        machine endianness, before the raw bits are converted to a double.
        
        :param T value: the abstract value
        :param PcodeArithmetic.Purpose purpose: the reason why the emulator needs a concrete value
        :return: the concrete value
        :rtype: float
        :raises ConcretionError: if the value cannot be made concrete
        """

    def toFloat(self, value: T, purpose: PcodeArithmetic.Purpose) -> float:
        """
        Convert, if possible, the given abstract value to a concrete float
         
         
        
        If value does not have size :const:`Float.BYTES`, it is truncated or padded, according to
        machine endianness, before the raw bits are converted to a float.
        
        :param T value: the abstract value
        :param PcodeArithmetic.Purpose purpose: the reason why the emulator needs a concrete value
        :return: the concrete value
        :rtype: float
        :raises ConcretionError: if the value cannot be made concrete
        """

    def toLong(self, value: T, purpose: PcodeArithmetic.Purpose) -> int:
        """
        Convert, if possible, the given abstract value to a concrete long
         
         
        
        If the conversion is not possible, throw an exception.
        
        :param T value: the abstract value
        :param PcodeArithmetic.Purpose purpose: the reason why the emulator needs a concrete value
        :return: the concrete value
        :rtype: int
        :raises ConcretionError: if the value cannot be made concrete
        """

    def toRegisterValue(self, register: ghidra.program.model.lang.Register, value: T, purpose: PcodeArithmetic.Purpose) -> ghidra.program.model.lang.RegisterValue:
        """
        Convert, if possible, the given abstract value to a concrete register value
        
        :param ghidra.program.model.lang.Register register: the register
        :param T value: the abstract value
        :param PcodeArithmetic.Purpose purpose: the reason why the emulator needs a concrete value
        :return: the concrete value
        :rtype: ghidra.program.model.lang.RegisterValue
        :raises ConcretionError: if the value cannot be made concrete
        """

    @typing.overload
    def unaryOp(self, opcode: typing.Union[jpype.JInt, int], sizeout: typing.Union[jpype.JInt, int], sizein1: typing.Union[jpype.JInt, int], in1: T) -> T:
        """
        Apply a unary operator to the given input
         
         
        
        Note the sizes of variables are given, because values don't necessarily have an intrinsic
        size. For example, a :obj:`BigInteger` may have a minimum encoding size, but that does not
        necessarily reflect the size of the variable from which is was read.
        
        
        .. admonition:: Implementation Note
        
            :meth:`OpBehaviorFactory.getOpBehavior(int) <OpBehaviorFactory.getOpBehavior>` for the given opcode is guaranteed to
            return a derivative of :obj:`UnaryOpBehavior`.
        
        
        :param jpype.JInt or int opcode: the p-code opcode
        :param jpype.JInt or int sizeout: the size (in bytes) of the output variable
        :param jpype.JInt or int sizein1: the size (in bytes) of the input variable
        :param T in1: the input value
        :return: the output value
        :rtype: T
        """

    @typing.overload
    def unaryOp(self, op: ghidra.program.model.pcode.PcodeOp, in1: T) -> T:
        """
        Apply a unary operator to the given input
         
         
        
        This provides the full p-code op, allowing deeper inspection of the code. For example, an
        arithmetic may wish to distinguish immediate (constant) values from variables. By default,
        this unpacks the details and defers to :meth:`unaryOp(int, int, int, Object) <.unaryOp>`.
        
        
        .. admonition:: Implementation Note
        
            :meth:`OpBehaviorFactory.getOpBehavior(int) <OpBehaviorFactory.getOpBehavior>` for the given opcode is guaranteed to
            return a derivative of :obj:`UnaryOpBehavior`.
        
        
        :param ghidra.program.model.pcode.PcodeOp op: the operation
        :param T in1: the input value
        :return: the output value
        :rtype: T
        """

    @property
    def endian(self) -> ghidra.program.model.lang.Endian:
        ...


class PcodeExecutor(java.lang.Object, typing.Generic[T]):
    """
    An executor of p-code programs
     
     
    
    This is the kernel of Sleigh expression evaluation and p-code emulation. For a complete example
    of a p-code emulator, see :obj:`PcodeEmulator`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, arithmetic: PcodeArithmetic[T], state: PcodeExecutorState[T], reason: PcodeExecutorStatePiece.Reason):
        """
        Construct an executor with the given bindings
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the processor language
        :param PcodeArithmetic[T] arithmetic: an implementation of arithmetic p-code ops
        :param PcodeExecutorState[T] state: an implementation of load/store p-code ops
        :param PcodeExecutorStatePiece.Reason reason: a reason for reading the state with this executor
        """

    @typing.overload
    def begin(self, program: PcodeProgram) -> PcodeFrame:
        """
        Begin execution of the given program
        
        :param PcodeProgram program: the program, e.g., from an injection, or a decoded instruction
        :return: the frame
        :rtype: PcodeFrame
        """

    @typing.overload
    def begin(self, code: java.util.List[ghidra.program.model.pcode.PcodeOp], useropNames: collections.abc.Mapping) -> PcodeFrame:
        """
        Begin execution of a list of p-code ops
        
        :param java.util.List[ghidra.program.model.pcode.PcodeOp] code: the ops
        :param collections.abc.Mapping useropNames: the map of userop numbers to names
        :return: the frame
        :rtype: PcodeFrame
        """

    @typing.overload
    def execute(self, program: PcodeProgram, library: PcodeUseropLibrary[T]) -> PcodeFrame:
        """
        Execute a program using the given library
        
        :param PcodeProgram program: the program, e.g., from an injection, or a decoded instruction
        :param PcodeUseropLibrary[T] library: the library
        :return: the frame
        :rtype: PcodeFrame
        """

    @typing.overload
    def execute(self, code: java.util.List[ghidra.program.model.pcode.PcodeOp], useropNames: collections.abc.Mapping, library: PcodeUseropLibrary[T]) -> PcodeFrame:
        """
        Execute a list of p-code ops
        
        :param java.util.List[ghidra.program.model.pcode.PcodeOp] code: the ops
        :param collections.abc.Mapping useropNames: the map of userop numbers to names
        :param PcodeUseropLibrary[T] library: the library of userops
        :return: the frame
        :rtype: PcodeFrame
        """

    def executeBinaryOp(self, op: ghidra.program.model.pcode.PcodeOp, b: ghidra.pcode.opbehavior.BinaryOpBehavior):
        """
        Execute the given binary op
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param ghidra.pcode.opbehavior.BinaryOpBehavior b: the op behavior
        """

    def executeBranch(self, op: ghidra.program.model.pcode.PcodeOp, frame: PcodeFrame):
        """
        Execute a branch
         
         
        
        This merely defers to :meth:`doExecuteBranch(PcodeOp, PcodeFrame) <.doExecuteBranch>`. To instrument the
        operation, override this. To modify or instrument branching in general, override
        :meth:`doExecuteBranch(PcodeOp, PcodeFrame) <.doExecuteBranch>`,
        :meth:`branchToOffset(PcodeOp, Object, PcodeFrame) <.branchToOffset>`, and/or
        :meth:`branchToAddress(PcodeOp, Address) <.branchToAddress>`.
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param PcodeFrame frame: the frame
        """

    def executeCall(self, op: ghidra.program.model.pcode.PcodeOp, frame: PcodeFrame, library: PcodeUseropLibrary[T]):
        """
        Execute a call
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param PcodeFrame frame: the frame
        :param PcodeUseropLibrary[T] library: the userop library
        """

    def executeCallother(self, op: ghidra.program.model.pcode.PcodeOp, frame: PcodeFrame, library: PcodeUseropLibrary[T]):
        """
        Execute a userop call
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param PcodeFrame frame: the frame
        :param PcodeUseropLibrary[T] library: the library of userops
        """

    def executeConditionalBranch(self, op: ghidra.program.model.pcode.PcodeOp, frame: PcodeFrame):
        """
        Execute a conditional branch
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param PcodeFrame frame: the frame
        """

    def executeIndirectBranch(self, op: ghidra.program.model.pcode.PcodeOp, frame: PcodeFrame):
        """
        Execute an indirect branch
         
         
        
        This merely defers to :meth:`doExecuteIndirectBranch(PcodeOp, PcodeFrame) <.doExecuteIndirectBranch>`. To instrument
        the operation, override this. To modify or instrument indirect branching in general, override
        :meth:`doExecuteIndirectBranch(PcodeOp, PcodeFrame) <.doExecuteIndirectBranch>`.
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param PcodeFrame frame: the frame
        """

    def executeIndirectCall(self, op: ghidra.program.model.pcode.PcodeOp, frame: PcodeFrame):
        """
        Execute an indirect call
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param PcodeFrame frame: the frame
        """

    def executeLoad(self, op: ghidra.program.model.pcode.PcodeOp):
        """
        Execute a load
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        """

    def executeReturn(self, op: ghidra.program.model.pcode.PcodeOp, frame: PcodeFrame):
        """
        Execute a return
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param PcodeFrame frame: the frame
        """

    def executeSleigh(self, source: typing.Union[java.lang.String, str]):
        """
        Compile and execute a block of Sleigh
        
        :param java.lang.String or str source: the Sleigh source
        """

    def executeStore(self, op: ghidra.program.model.pcode.PcodeOp):
        """
        Execute a store
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        """

    def executeUnaryOp(self, op: ghidra.program.model.pcode.PcodeOp, b: ghidra.pcode.opbehavior.UnaryOpBehavior):
        """
        Execute the given unary op
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param ghidra.pcode.opbehavior.UnaryOpBehavior b: the op behavior
        """

    def finish(self, frame: PcodeFrame, library: PcodeUseropLibrary[T]):
        """
        Finish execution of a frame
         
         
        
        TODO: This is not really sufficient for continuation after a break, esp. if that break occurs
        within a nested call back into the executor. This would likely become common when using pCode
        injection.
        
        :param PcodeFrame frame: the incomplete frame
        :param PcodeUseropLibrary[T] library: the library of userops to use
        """

    def getArithmetic(self) -> PcodeArithmetic[T]:
        """
        Get the arithmetic applied by the executor
        
        :return: the arithmetic
        :rtype: PcodeArithmetic[T]
        """

    def getLanguage(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        """
        Get the executor's Sleigh language (processor model)
        
        :return: the language
        :rtype: ghidra.app.plugin.processors.sleigh.SleighLanguage
        """

    def getReason(self) -> PcodeExecutorStatePiece.Reason:
        """
        Get the reason for reading state with this executor
        
        :return: the reason
        :rtype: PcodeExecutorStatePiece.Reason
        """

    def getState(self) -> PcodeExecutorState[T]:
        """
        Get the state bound to this executor
        
        :return: the state
        :rtype: PcodeExecutorState[T]
        """

    def getUseropName(self, opNo: typing.Union[jpype.JInt, int], frame: PcodeFrame) -> str:
        """
        Get the name of a userop
        
        :param jpype.JInt or int opNo: the userop number
        :param PcodeFrame frame: the frame
        :return: the name, or null if it is not defined
        :rtype: str
        """

    def skip(self, frame: PcodeFrame):
        """
        Skip a single p-code op
        
        :param PcodeFrame frame: the frame whose next op to skip
        """

    def step(self, frame: PcodeFrame, library: PcodeUseropLibrary[T]):
        """
        Step a single p-code op
        
        :param PcodeFrame frame: the frame whose next op to execute
        :param PcodeUseropLibrary[T] library: the userop library
        """

    def stepOp(self, op: ghidra.program.model.pcode.PcodeOp, frame: PcodeFrame, library: PcodeUseropLibrary[T]):
        """
        Step one p-code op
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param PcodeFrame frame: the current frame
        :param PcodeUseropLibrary[T] library: the library, invoked in case of :obj:`PcodeOp.CALLOTHER`
        """

    @property
    def reason(self) -> PcodeExecutorStatePiece.Reason:
        ...

    @property
    def arithmetic(self) -> PcodeArithmetic[T]:
        ...

    @property
    def language(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        ...

    @property
    def state(self) -> PcodeExecutorState[T]:
        ...


class BytesPcodeExecutorStatePiece(AbstractBytesPcodeExecutorStatePiece[BytesPcodeExecutorStateSpace[java.lang.Void]]):
    """
    A plain concrete state piece without any backing objects
    """

    @typing.type_check_only
    class BytesSpaceMap(AbstractLongOffsetPcodeExecutorStatePiece.SimpleSpaceMap[BytesPcodeExecutorStateSpace[java.lang.Void]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Construct a state for the given language
        
        :param ghidra.program.model.lang.Language language: the language (used for its memory model)
        """


class PairedPcodeExecutorStatePiece(PcodeExecutorStatePiece[A, org.apache.commons.lang3.tuple.Pair[L, R]], typing.Generic[A, L, R]):
    """
    A paired executor state piece
     
     
    
    This composes two delegate pieces "left" and "right" creating a single piece which stores pairs
    of values, where the left component has the value type of the left piece, and the right component
    has the value type of the right piece. Both pieces must have the same address type. Every
    operation on this piece is decomposed into operations upon the delegate pieces, and the final
    result composed from the results of those operations.
     
     
    
    To compose three or more states, first ask if it is really necessary. Second, consider
    implementing the :obj:`PcodeExecutorStatePiece` interface for a record type. Third, use the
    Church-style triple. In that third case, it is recommended to compose the nested pair on the
    right of the top pair: Compose the two right pieces into a single piece, then use
    :obj:`PairedPcodeExecutorState` to compose a concrete state with the composed piece, yielding a
    state of triples. This can be applied ad nauseam to compose arbitrarily large tuples; however, at
    a certain point clients should consider creating a record and implementing the state piece and/or
    state interface. It's helpful to use this implementation as a reference. Alternatively, the
    ``Debugger`` module has a ``WatchValuePcodeExecutorState`` which follows this
    recommendation.
    
    
    .. seealso::
    
        | :obj:`PairedPcodeExecutorState`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, left: PcodeExecutorStatePiece[A, L], right: PcodeExecutorStatePiece[A, R], addressArithmetic: PcodeArithmetic[A], arithmetic: PcodeArithmetic[org.apache.commons.lang3.tuple.Pair[L, R]]):
        ...

    @typing.overload
    def __init__(self, left: PcodeExecutorStatePiece[A, L], right: PcodeExecutorStatePiece[A, R]):
        ...

    def getLeft(self) -> PcodeExecutorStatePiece[A, L]:
        """
        Get the delegate backing the left side of paired values
        
        :return: the left piece
        :rtype: PcodeExecutorStatePiece[A, L]
        """

    def getRight(self) -> PcodeExecutorStatePiece[A, R]:
        """
        Get the delegate backing the right side of paired values
        
        :return: the right piece
        :rtype: PcodeExecutorStatePiece[A, R]
        """

    @property
    def left(self) -> PcodeExecutorStatePiece[A, L]:
        ...

    @property
    def right(self) -> PcodeExecutorStatePiece[A, R]:
        ...


class PcodeExecutorState(PcodeExecutorStatePiece[T, T], typing.Generic[T]):
    """
    An interface that provides storage for values of type ``T``
     
     
    
    This is not much more than a stricter form of :obj:`PcodeExecutorStatePiece`, in that it
    requires the value and address offset types to agree, so that a p-code executor or emulator can
    perform loads and stores using indirect addresses. The typical pattern for implementing a state
    is to compose it from pieces. See :obj:`PcodeExecutorStatePiece`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def paired(self, right: PcodeExecutorStatePiece[T, U]) -> PcodeExecutorState[org.apache.commons.lang3.tuple.Pair[T, U]]:
        """
        Use this state as the control, paired with the given auxiliary state.
         
         
        
        **CAUTION:** Often, the default paired state is not quite sufficient. Consider
        :meth:`getVar(AddressSpace, Object, int, boolean, Reason) <.getVar>`. The rider on the offset may
        offer information that must be incorporated into the rider of the value just read. This is
        the case, for example, with taint propagation. In those cases, an anonymous inner class
        extending :obj:`PairedPcodeExecutorState` is sufficient.
        
        :param U: the type of values and offsets stored by the rider:param PcodeExecutorStatePiece[T, U] right: the rider state
        :return: the paired state
        :rtype: PcodeExecutorState[org.apache.commons.lang3.tuple.Pair[T, U]]
        """


class PairedPcodeArithmetic(PcodeArithmetic[org.apache.commons.lang3.tuple.Pair[L, R]], typing.Generic[L, R]):
    """
    An arithmetic composed from two.
     
     
    
    The new arithmetic operates on tuples where each is subject to its respective arithmetic. One
    exception is :meth:`toConcrete(Pair, Purpose) <.toConcrete>`. This arithmetic defers to left ("control")
    arithmetic. Thus, conventionally, when part of the pair represents the concrete value, it should
    be the left.
     
     
    
    See :obj:`PairedPcodeExecutorStatePiece` regarding composing three or more elements. Generally,
    it's recommended the client provide its own "record" type and the corresponding arithmetic and
    state piece to manipulate it. Nesting pairs would work, but is not recommended.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, leftArith: PcodeArithmetic[L], rightArith: PcodeArithmetic[R]):
        """
        Construct a composed arithmetic from the given two
        
        :param PcodeArithmetic[L] leftArith: the left ("control") arithmetic
        :param PcodeArithmetic[R] rightArith: the right ("rider") arithmetic
        """

    def getLeft(self) -> PcodeArithmetic[L]:
        """
        Get the left ("control") arithmetic
        
        :return: the arithmetic
        :rtype: PcodeArithmetic[L]
        """

    def getRight(self) -> PcodeArithmetic[R]:
        """
        Get the right ("rider") arithmetic
        
        :return: the arithmetic
        :rtype: PcodeArithmetic[R]
        """

    @property
    def left(self) -> PcodeArithmetic[L]:
        ...

    @property
    def right(self) -> PcodeArithmetic[R]:
        ...


class InterruptPcodeExecutionException(PcodeExecutionException):
    """
    Exception thrown by :meth:`PcodeEmulationLibrary.emu_swi() <PcodeEmulationLibrary.emu_swi>`, a p-code userop exported by
    emulators for implementing breakpoints.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, frame: PcodeFrame, cause: java.lang.Throwable):
        ...


class PcodeExpression(PcodeProgram):
    """
    A p-code program that evaluates a Sleigh expression
    """

    @typing.type_check_only
    class ValueCapturingPcodeUseropLibrary(AnnotatedPcodeUseropLibrary[T], typing.Generic[T]):
        """
        A clever means of capturing the result of the expression.
        
        
        .. admonition:: Implementation Note
        
            The compiled source is actually ``___result(<expression>);`` which allows us to
            capture the value (and size) of arbitrary expressions. Assigning the value to a
            temp variable instead of a userop does not quite suffice, since it requires a fixed
            size, which cannot be known ahead of time.
        """

        class_: typing.ClassVar[java.lang.Class]

        def ___result(self, result: T):
            ...


    class_: typing.ClassVar[java.lang.Class]
    RESULT_NAME: typing.Final = "___result"

    def evaluate(self, executor: PcodeExecutor[T]) -> T:
        """
        Evaluate the expression using the given executor
        
        :param T: the type of the result:param PcodeExecutor[T] executor: the executor
        :return: the result
        :rtype: T
        """


class ComposedPcodeUseropLibrary(PcodeUseropLibrary[T], typing.Generic[T]):
    """
    A p-code userop library composed of other libraries
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, libraries: collections.abc.Sequence):
        """
        Construct a composed userop library from the given libraries
         
         
        
        This uses :meth:`composeUserops(Collection) <.composeUserops>`, so its restrictions apply here, too.
        
        :param collections.abc.Sequence libraries: the libraries
        """

    @staticmethod
    def composeUserops(libraries: collections.abc.Sequence) -> java.util.Map[java.lang.String, PcodeUseropLibrary.PcodeUseropDefinition[T]]:
        """
        Obtain a map representing the composition of userops from all the given libraries
         
         
        
        Name collisions are not allowed. If any two libraries export the same symbol, even if the
        definitions happen to do the same thing, it is an error.
        
        :param T: the type of values processed by the libraries:param collections.abc.Sequence libraries: the libraries whose userops to collect
        :return: the resulting map
        :rtype: java.util.Map[java.lang.String, PcodeUseropLibrary.PcodeUseropDefinition[T]]
        """


class PcodeExecutionException(java.lang.RuntimeException):
    """
    The base exception for all p-code execution errors
     
     
    
    Exceptions caught by the executor that are not of this type are typically caught and wrapped, so
    that the frame can be recovered. The frame is important for diagnosing the error, because it
    records what the executor was doing. It essentially serves as the "line number" of the p-code
    program within the greater Java stack. Additionally, if execution of p-code is to resume, the
    frame must be recovered, and possibly stepped back one.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], frame: PcodeFrame, cause: java.lang.Throwable):
        """
        Construct an execution exception
         
         
        
        The frame is often omitted at the throw site. The executor should catch the exception, fill
        in the frame, and re-throw it.
        
        :param java.lang.String or str message: the message
        :param PcodeFrame frame: if known, the frame at the time of the exception
        :param java.lang.Throwable cause: the exception that caused this one
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], frame: PcodeFrame):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    def getFrame(self) -> PcodeFrame:
        """
        Get the frame at the time of the exception
         
         
        
        Note that the frame counter is advanced *before* execution of the p-code op. Thus, the
        counter often points to the op following the one which caused the exception. For a frame to
        be present and meaningful, the executor must intervene between the throw and the catch. In
        other words, if you're invoking the executor, you should always expect to see a frame. If you
        are implementing, e.g., a userop, then it is possible to catch an exception without frame
        information populated. You might instead retrieve the frame from the executor, if you have a
        handle to it.
        
        :return: the frame, possibly ``null``
        :rtype: PcodeFrame
        """

    @property
    def frame(self) -> PcodeFrame:
        ...


class ValueLocation(java.lang.Object):
    """
    The location of a value
     
     
    
    This is an analog to :obj:`VariableStorage`, except that this records the actual storage
    location of the evaluated variable or expression. This does not incorporate storage of
    intermediate dereferenced values. For example, suppose ``R0 = 0xdeadbeef``, and we want to
    evaluate ``*:4 R0``. The storage would be ``ram:deadbeef:4``, not
    ``R0,ram:deadbeef:4``.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, *nodes: ghidra.program.model.pcode.Varnode):
        """
        Construct a location from a list of varnodes
         
         
        
        Any leading varnodes which are constant 0s are removed.
        
        :param jpype.JArray[ghidra.program.model.pcode.Varnode] nodes: the varnodes
        """

    @typing.overload
    def __init__(self, nodes: java.util.List[ghidra.program.model.pcode.Varnode]):
        """
        Construct a location from a list of varnodes
         
         
        
        Any leading varnodes which are constant 0s are removed.
        
        :param java.util.List[ghidra.program.model.pcode.Varnode] nodes: the varnodes
        """

    @staticmethod
    def fromConst(value: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> ValueLocation:
        """
        Generate the "location" of a constant
        
        :param jpype.JLong or int value: the value
        :param jpype.JInt or int size: the size of the constant in bytes
        :return: the "location"
        :rtype: ValueLocation
        """

    @staticmethod
    def fromVarnode(address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]) -> ValueLocation:
        """
        Generate a location from a varnode
        
        :param ghidra.program.model.address.Address address: the dynamic address of the variable
        :param jpype.JInt or int size: the size of the variable in bytes
        :return: the location
        :rtype: ValueLocation
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the first varnode
        
        :return: the address, or null if this location has no varnodes
        :rtype: ghidra.program.model.address.Address
        """

    def getConst(self) -> java.math.BigInteger:
        """
        If the location represents a constant, get its value
        
        :return: the constant value
        :rtype: java.math.BigInteger
        """

    def intOr(self, that: ValueLocation) -> ValueLocation:
        """
        Apply a :obj:`PcodeOp.INT_OR` operator
         
         
        
        There is a very restrictive set of constraints for which this yields a non-null location. If
        either this or that is empty, the other is returned. Otherwise, the varnodes are arranged in
        pairs by taking one from each storage starting at the right, or least-significant varnode.
        Each pair must match in length, and one of the pair must be a constant zero. The non-zero
        varnode is taken. The unpaired varnodes to the left, if any, are all taken. If any pair does
        not match in length, or if neither is zero, the resulting location is null. This logic is to
        ensure location information is accrued during concatenation.
        
        :param ValueLocation that: the other location
        :return: the location
        :rtype: ValueLocation
        """

    def isEmpty(self) -> bool:
        """
        Check if this location includes any varnodes
         
         
        
        Note that a location cannot consist entirely of constant zeros and be non-empty. The
        constructor will have removed them all.
        
        :return: true if empty
        :rtype: bool
        """

    def nodeCount(self) -> int:
        """
        Get the number of varnodes for this location
        
        :return: the count
        :rtype: int
        """

    def shiftLeft(self, amount: typing.Union[jpype.JInt, int]) -> ValueLocation:
        """
        Apply a :obj:`PcodeOp.INT_LEFT` operator
         
         
        
        This requires the shift amount to represent an integral number of bytes. Otherwise, the
        result is null. This simply inserts a constant zero to the right, having the number of bytes
        indicated by the shift amount. This logic is to ensure location information is accrued during
        concatenation.
        
        :param jpype.JInt or int amount: the number of bits to shift
        :return: the location.
        :rtype: ValueLocation
        """

    def size(self) -> int:
        """
        Get the total size of this location in bytes
        
        :return: the size in bytes
        :rtype: int
        """

    def toString(self, language: ghidra.program.model.lang.Language) -> str:
        """
        Render this location as a string, substituting registers where applicable
        
        :param ghidra.program.model.lang.Language language: the optional language for register substitution
        :return: the string
        :rtype: str
        """

    @staticmethod
    def vnToString(vn: ghidra.program.model.pcode.Varnode, language: ghidra.program.model.lang.Language) -> str:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def const(self) -> java.math.BigInteger:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class BytesPcodeArithmetic(java.lang.Enum[BytesPcodeArithmetic], PcodeArithmetic[jpype.JArray[jpype.JByte]]):
    """
    A p-code arithmetic that operates on concrete byte array values
     
     
    
    The arithmetic interprets the arrays as big- or little-endian values, then performs the
    arithmetic as specified by the p-code operation. The implementation defers to :obj:`OpBehavior`.
    """

    class_: typing.ClassVar[java.lang.Class]
    BIG_ENDIAN: typing.Final[BytesPcodeArithmetic]
    """
    The instance which interprets arrays as big-endian values
    """

    LITTLE_ENDIAN: typing.Final[BytesPcodeArithmetic]
    """
    The instance which interprets arrays as little-endian values
    """


    @staticmethod
    def forEndian(bigEndian: typing.Union[jpype.JBoolean, bool]) -> BytesPcodeArithmetic:
        """
        Obtain the instance for the given endianness
        
        :param jpype.JBoolean or bool bigEndian: true for :obj:`.BIG_ENDIAN`, false of :obj:`.LITTLE_ENDIAN`
        :return: the arithmetic
        :rtype: BytesPcodeArithmetic
        """

    @staticmethod
    def forLanguage(language: ghidra.program.model.lang.Language) -> BytesPcodeArithmetic:
        """
        Obtain the instance for the given language's endianness
        
        :param ghidra.program.model.lang.Language language: the language
        :return: the arithmetic
        :rtype: BytesPcodeArithmetic
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BytesPcodeArithmetic:
        ...

    @staticmethod
    def values() -> jpype.JArray[BytesPcodeArithmetic]:
        ...


class PcodeUseropLibrary(java.lang.Object, typing.Generic[T]):
    """
    A "library" of p-code userops available to a p-code executor
    
     
    
    The library can provide definitions of p-code userops already declared by the executor's language
    as well as completely new userops accessible to Sleigh/p-code later compiled for the executor.
    The recommended way to implement a library is to extend :obj:`AnnotatedPcodeUseropLibrary`.
    """

    class EmptyPcodeUseropLibrary(PcodeUseropLibrary[java.lang.Object]):
        """
        The class of the empty userop library.
        
        
        .. seealso::
        
            | :obj:`PcodeUseropLibrary.nil()`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class PcodeUseropDefinition(java.lang.Object, typing.Generic[T]):
        """
        The definition of a p-code userop.
        """

        class_: typing.ClassVar[java.lang.Class]

        def canInlinePcode(self) -> bool:
            """
            Indicates whether or not this userop definition produces p-code suitable for inlining in
            place of its invocation.
             
             
            
            Generally, if all the userop definition does is feed additional p-code to the executor
            with the same userop library, then it is suitable for inlining. It is possible for the
            p-code to depend on other factors, but care must be taken, since the decision could be
            fixed by the underlying execution system at any time. E.g., if the p-code is translated
            to JVM byte code, then the userop may be inlined at translation time rather than
            execution time. Recommended factors include configuration, placement within surrounding
            instructions, static analysis, etc., but the p-code should probably not depend on the
            machine's dynamic run-time state.
            
            :return: true if inlining is possible, false otherwise.
            :rtype: bool
            
            .. seealso::
            
                | :obj:`PcodeUserop.canInline()`
            """

        @typing.overload
        def execute(self, executor: PcodeExecutor[T], library: PcodeUseropLibrary[T], outVar: ghidra.program.model.pcode.Varnode, inVars: java.util.List[ghidra.program.model.pcode.Varnode]):
            """
            Invoke/execute the userop.
            
            :param PcodeExecutor[T] executor: the executor invoking this userop.
            :param PcodeUseropLibrary[T] library: the complete library for this execution. Note the library may have been
                        composed from more than the one defining this userop.
            :param ghidra.program.model.pcode.Varnode outVar: if invoked as an rval, the destination varnode for the userop's output.
                        Otherwise, ``null``.
            :param java.util.List[ghidra.program.model.pcode.Varnode] inVars: the input varnodes as ordered in the source.
            
            .. seealso::
            
                | :obj:`AnnotatedPcodeUseropLibrary.AnnotatedPcodeUseropDefinition`
            """

        @typing.overload
        def execute(self, executor: PcodeExecutor[T], library: PcodeUseropLibrary[T], op: ghidra.program.model.pcode.PcodeOp):
            """
            Invoke/execute the raw userop.
             
             
            
            **NOTE:** The first input to the raw p-code op is the id of this userop. The userop
            inputs are thus at indices 1..N.
            
            :param PcodeExecutor[T] executor: the executor invoking this userop.
            :param PcodeUseropLibrary[T] library: the complete library for this execution. Note the library may have been
                        composed from more than the one defining this userop.
            :param ghidra.program.model.pcode.PcodeOp op: the :obj:`PcodeOp.CALLOTHER` op
            """

        def getDefiningLibrary(self) -> PcodeUseropLibrary[typing.Any]:
            """
            Get the library that defines (or "owns") this userop
             
             
            
            A userop can become part of other composed libraries, so the library from which this
            userop was retrieved may not be the same as the one that defined it. This returns the one
            that defined it.
             
             
            
            As a special consideration, if this userop is a wrapper around another, and this wrapper
            returns the java method of the delegate, this *must* return the defining library
            of the delegate. If this is not defined by a java callback, this method (the defining
            library) may be null.
            
            :return: the defining library
            :rtype: PcodeUseropLibrary[typing.Any]
            """

        def getInputCount(self) -> int:
            """
            Get the number of *input* operands accepted by the userop.
            
            :return: the count or -1 if the userop is variadic
            :rtype: int
            """

        def getJavaMethod(self) -> java.lang.reflect.Method:
            """
            If this userop is defined as a java callback, get the method
            
            :return: the method, or null
            :rtype: java.lang.reflect.Method
            """

        def getName(self) -> str:
            """
            Get the name of the userop.
             
             
            
            This is the symbol assigned to the userop when compiling new Sleigh code. It cannot
            conflict with existing userops (except those declared, but not defined, by the executor's
            language) or other symbols of the executor's language. If this userop is to be used
            generically across many languages, choose an unlikely name. Conventionally, these start
            with two underscores ``__``.
            
            :return: the name of the userop
            :rtype: str
            """

        def hasSideEffects(self) -> bool:
            """
            Indicates whether this userop may have side effects.
             
             
            
            This means that the function may have an output or an effect other than returning a
            value. Even if :meth:`isFunctional() <.isFunctional>` is true, it is possible for a userop to have side
            effects, e.g., updating a field in a library or printing to the screen.
            
            :return: true if it has side effects.
            :rtype: bool
            
            .. seealso::
            
                | :obj:`PcodeUserop.hasSideEffects()`
            """

        def isFunctional(self) -> bool:
            """
            Indicates whether this userop is a "pure function."
             
             
            
            This means all inputs are given in the arguments to the userop and the output, if
            applicable, is given via the return. Technically, this is only with respect to the
            emulated machine state. If the library carries its own state, and the userop is stateful
            with respect to the library, it is still okay to set this to true. When this is set to
            false, the underlying execution engine must ensure the machine state is consistent,
            because the userop may access any part of it directly. Functional userops ought to take
            primitive parameters and return primitives, and should receive neither the executor nor
            its state object.
             
             
            
            **WARNING:** The term "inputs" include disassembly context. Unfortunately, there is
            currently no way to access that context via p-code ops generated by Sleigh, so the only
            way to obtain it is to ask the emulator thread for it out of band. Userops that require
            this are *not* "pure functions."
            
            :return: true if a pure function.
            :rtype: bool
            
            .. seealso::
            
                | :obj:`PcodeUserop.functional()`
            """

        def modifiesContext(self) -> bool:
            """
            Indicates that this userop may modify the decode context.
             
             
            
            This means that the userop may set a field in ``contextreg``, which could thus affect
            how subsequent instructions are decoded. Executors which decode ahead will have to
            consider this effect.
            
            :return: true if this can modify the context.
            :rtype: bool
            
            .. seealso::
            
                | :obj:`PcodeUserop.modifiesContext()`
            """

        @property
        def functional(self) -> jpype.JBoolean:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def javaMethod(self) -> java.lang.reflect.Method:
            ...

        @property
        def definingLibrary(self) -> PcodeUseropLibrary[typing.Any]:
            ...

        @property
        def inputCount(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    NIL: typing.Final[PcodeUseropLibrary[typing.Any]]
    """
    The empty userop library.
     
     
    
    Executors cannot accept ``null`` libraries. Instead, give it this empty library. To
    satisfy Java's type checker, you may use :meth:`nil() <.nil>` instead.
    """


    def compose(self, lib: PcodeUseropLibrary[T]) -> PcodeUseropLibrary[T]:
        """
        Compose this and the given library into a new library.
        
        :param PcodeUseropLibrary[T] lib: the other library
        :return: a new library having all userops defined between the two
        :rtype: PcodeUseropLibrary[T]
        """

    @staticmethod
    def getOperandType(cls: java.lang.Class[typing.Any]) -> java.lang.reflect.Type:
        """
        Get the type ``T`` for the given class
         
         
        
        If the class does not implement :obj:`PcodeUseropLibrary`, this returns null. If it does,
        but no arguments are given (i.e., it implements the raw type), this return :obj:`Object`.
        
        :param java.lang.Class[typing.Any] cls: the class
        :return: the type, or null
        :rtype: java.lang.reflect.Type
        """

    def getSymbols(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage) -> java.util.Map[java.lang.Integer, ghidra.pcodeCPort.slghsymbol.UserOpSymbol]:
        """
        Get named symbols defined by this library that are not already declared in the language
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the language whose existing symbols to consider
        :return: a map of new userop indices to extra userop symbols
        :rtype: java.util.Map[java.lang.Integer, ghidra.pcodeCPort.slghsymbol.UserOpSymbol]
        """

    def getUserops(self) -> java.util.Map[java.lang.String, PcodeUseropLibrary.PcodeUseropDefinition[T]]:
        """
        Get all the userops defined in this library, keyed by (symbol) name.
        
        :return: the map of names to defined userops
        :rtype: java.util.Map[java.lang.String, PcodeUseropLibrary.PcodeUseropDefinition[T]]
        """

    @staticmethod
    def nil() -> PcodeUseropLibrary[T]:
        """
        The empty userop library, cast to match parameter types.
        
        :param T: the type required by the executor:return: the empty userop library
        :rtype: PcodeUseropLibrary[T]
        """

    @property
    def userops(self) -> java.util.Map[java.lang.String, PcodeUseropLibrary.PcodeUseropDefinition[T]]:
        ...

    @property
    def symbols(self) -> java.util.Map[java.lang.Integer, ghidra.pcodeCPort.slghsymbol.UserOpSymbol]:
        ...


class AbstractLongOffsetPcodeExecutorStatePiece(PcodeExecutorStatePiece[A, T], typing.Generic[A, T, S]):
    """
    An abstract executor state piece which internally uses ``long`` to address contents
     
     
    
    This also provides an internal mechanism for breaking the piece down into the spaces defined by a
    language. It also provides for the special treatment of the ``unique`` space.
    """

    class AbstractSpaceMap(java.lang.Object, typing.Generic[S]):
        """
        A map of address spaces to objects which store or cache state for that space
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @typing.overload
        def fork(self) -> AbstractLongOffsetPcodeExecutorStatePiece.AbstractSpaceMap[S]:
            """
            Deep copy this map, for use in a forked state (or piece)
            
            :return: the copy
            :rtype: AbstractLongOffsetPcodeExecutorStatePiece.AbstractSpaceMap[S]
            """

        @typing.overload
        def fork(self, s: S) -> S:
            """
            Deep copy the given space
            
            :param S s: the space
            :return: the copy
            :rtype: S
            """

        @typing.overload
        def fork(self, spaces: collections.abc.Mapping) -> java.util.Map[ghidra.program.model.address.AddressSpace, S]:
            """
            Produce a deep copy of the given map
            
            :param collections.abc.Mapping spaces: the map to copy
            :return: the copy
            :rtype: java.util.Map[ghidra.program.model.address.AddressSpace, S]
            """

        def getForSpace(self, space: ghidra.program.model.address.AddressSpace, toWrite: typing.Union[jpype.JBoolean, bool]) -> S:
            ...

        def values(self) -> java.util.Collection[S]:
            ...


    class SimpleSpaceMap(AbstractLongOffsetPcodeExecutorStatePiece.AbstractSpaceMap[S], typing.Generic[S]):
        """
        Use this when each S contains the complete state for the address space
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class CacheingSpaceMap(AbstractLongOffsetPcodeExecutorStatePiece.AbstractSpaceMap[S], typing.Generic[B, S]):
        """
        Use this when each S is possibly a cache to some other state (backing) object
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, addressArithmetic: PcodeArithmetic[A], arithmetic: PcodeArithmetic[T]):
        """
        Construct a state piece for the given language and arithmetic
        
        :param ghidra.program.model.lang.Language language: the language (used for its memory model)
        :param PcodeArithmetic[T] arithmetic: an arithmetic used to generate default values of ``T``
        """


class PcodeExecutorStatePiece(java.lang.Object, typing.Generic[A, T]):
    """
    An interface that provides storage for values of type ``T``, addressed by offsets of type
    ``A``
     
     
    
    The typical pattern for implementing a state is to compose it from one or more state pieces. Each
    piece must use the same address type and arithmetic. If more than one piece is needed, they are
    composed using :obj:`PairedPcodeExecutorStatePiece`. Once all the pieces are composed, the root
    piece can be wrapped to make a state using :obj:`DefaultPcodeExecutorState` or
    :obj:`PairedPcodeExecutorState`. The latter corrects the address type to be a pair so it matches
    the type of values.
    """

    class Reason(java.lang.Enum[PcodeExecutorStatePiece.Reason]):
        """
        Reasons for reading state
        """

        class_: typing.ClassVar[java.lang.Class]
        RE_INIT: typing.Final[PcodeExecutorStatePiece.Reason]
        """
        The value is needed as the default program counter or disassembly context
        """

        EXECUTE_READ: typing.Final[PcodeExecutorStatePiece.Reason]
        """
        The value is being read by the emulator as data in the course of execution
        """

        EXECUTE_DECODE: typing.Final[PcodeExecutorStatePiece.Reason]
        """
        The value is being decoded by the emulator as an instruction for execution
        """

        INSPECT: typing.Final[PcodeExecutorStatePiece.Reason]
        """
        The value is being inspected by something other than an emulator
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PcodeExecutorStatePiece.Reason:
            ...

        @staticmethod
        def values() -> jpype.JArray[PcodeExecutorStatePiece.Reason]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def checkRange(self, space: ghidra.program.model.address.AddressSpace, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
        """
        Construct a range, if only to verify the range is valid
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param jpype.JLong or int offset: the starting offset
        :param jpype.JInt or int size: the length (in bytes) of the range
        """

    def clear(self):
        """
        Erase the entire state or piece
         
         
        
        This is generally only useful when the state is itself a cache to another object. This will
        ensure the state is reading from that object rather than a stale cache. If this is not a
        cache, this could in fact clear the whole state, and the machine using it will be left in the
        dark.
        """

    def fork(self) -> PcodeExecutorStatePiece[A, T]:
        """
        Create a deep copy of this state
        
        :return: the copy
        :rtype: PcodeExecutorStatePiece[A, T]
        """

    def getAddressArithmetic(self) -> PcodeArithmetic[A]:
        """
        Get the arithmetic used to manipulate addresses of the type used by this state
        
        :return: the address (or offset) arithmetic
        :rtype: PcodeArithmetic[A]
        """

    def getArithmetic(self) -> PcodeArithmetic[T]:
        """
        Get the arithmetic used to manipulate values of the type stored by this state
        
        :return: the arithmetic
        :rtype: PcodeArithmetic[T]
        """

    def getConcreteBuffer(self, address: ghidra.program.model.address.Address, purpose: PcodeArithmetic.Purpose) -> ghidra.program.model.mem.MemBuffer:
        """
        Bind a buffer of concrete bytes at the given start address
        
        :param ghidra.program.model.address.Address address: the start address
        :param PcodeArithmetic.Purpose purpose: the reason why the emulator needs a concrete value
        :return: a buffer
        :rtype: ghidra.program.model.mem.MemBuffer
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language defining the address spaces of this state piece
        
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """

    def getRegisterValues(self) -> java.util.Map[ghidra.program.model.lang.Register, T]:
        """
        Get all register values known to this state
         
         
        
        When the state acts as a cache, it should only return those cached.
        
        :return: a map of registers and their values
        :rtype: java.util.Map[ghidra.program.model.lang.Register, T]
        """

    @typing.overload
    def getVar(self, reg: ghidra.program.model.lang.Register, reason: PcodeExecutorStatePiece.Reason) -> T:
        """
        Get the value of a register variable
        
        :param ghidra.program.model.lang.Register reg: the register
        :param PcodeExecutorStatePiece.Reason reason: the reason for reading the register
        :return: the value
        :rtype: T
        """

    @typing.overload
    def getVar(self, var: ghidra.program.model.pcode.Varnode, reason: PcodeExecutorStatePiece.Reason) -> T:
        """
        Get the value of a variable
        
        :param ghidra.program.model.pcode.Varnode var: the variable
        :param PcodeExecutorStatePiece.Reason reason: the reason for reading the variable
        :return: the value
        :rtype: T
        """

    @typing.overload
    def getVar(self, space: ghidra.program.model.address.AddressSpace, offset: A, size: typing.Union[jpype.JInt, int], quantize: typing.Union[jpype.JBoolean, bool], reason: PcodeExecutorStatePiece.Reason) -> T:
        """
        Get the value of a variable
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param A offset: the offset within the space
        :param jpype.JInt or int size: the size of the variable
        :param jpype.JBoolean or bool quantize: true to quantize to the language's "addressable unit"
        :param PcodeExecutorStatePiece.Reason reason: the reason for reading the variable
        :return: the value
        :rtype: T
        """

    @typing.overload
    def getVar(self, space: ghidra.program.model.address.AddressSpace, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], quantize: typing.Union[jpype.JBoolean, bool], reason: PcodeExecutorStatePiece.Reason) -> T:
        """
        Get the value of a variable
         
         
        
        This method is typically used for reading memory variables.
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param jpype.JLong or int offset: the offset within the space
        :param jpype.JInt or int size: the size of the variable
        :param jpype.JBoolean or bool quantize: true to quantize to the language's "addressable unit"
        :param PcodeExecutorStatePiece.Reason reason: the reason for reading the variable
        :return: the value
        :rtype: T
        """

    @typing.overload
    def getVar(self, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], quantize: typing.Union[jpype.JBoolean, bool], reason: PcodeExecutorStatePiece.Reason) -> T:
        """
        Get the value of a variable
         
         
        
        This method is typically used for reading memory variables.
        
        :param ghidra.program.model.address.Address address: the address of the variable
        :param jpype.JInt or int size: the size of the variable
        :param jpype.JBoolean or bool quantize: true to quantize to the language's "addressable unit"
        :param PcodeExecutorStatePiece.Reason reason: the reason for reading the variable
        :return: the value
        :rtype: T
        """

    def quantizeOffset(self, space: ghidra.program.model.address.AddressSpace, offset: typing.Union[jpype.JLong, int]) -> int:
        """
        Quantize the given offset to the language's "addressable unit"
        
        :param ghidra.program.model.address.AddressSpace space: the space where the offset applies
        :param jpype.JLong or int offset: the offset
        :return: the quantized offset
        :rtype: int
        """

    @typing.overload
    def setVar(self, reg: ghidra.program.model.lang.Register, val: T):
        """
        Set the value of a register variable
        
        :param ghidra.program.model.lang.Register reg: the register
        :param T val: the value
        """

    @typing.overload
    def setVar(self, var: ghidra.program.model.pcode.Varnode, val: T):
        """
        Set the value of a variable
        
        :param ghidra.program.model.pcode.Varnode var: the variable
        :param T val: the value
        """

    @typing.overload
    def setVar(self, space: ghidra.program.model.address.AddressSpace, offset: A, size: typing.Union[jpype.JInt, int], quantize: typing.Union[jpype.JBoolean, bool], val: T):
        """
        Set the value of a variable
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param A offset: the offset within the space
        :param jpype.JInt or int size: the size of the variable
        :param jpype.JBoolean or bool quantize: true to quantize to the language's "addressable unit"
        :param T val: the value
        """

    @typing.overload
    def setVar(self, space: ghidra.program.model.address.AddressSpace, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], quantize: typing.Union[jpype.JBoolean, bool], val: T):
        """
        Set the value of a variable
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param jpype.JLong or int offset: the offset within the space
        :param jpype.JInt or int size: the size of the variable
        :param jpype.JBoolean or bool quantize: true to quantize to the language's "addressable unit"
        :param T val: the value
        """

    @typing.overload
    def setVar(self, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], quantize: typing.Union[jpype.JBoolean, bool], val: T):
        """
        Set the value of a variable
        
        :param ghidra.program.model.address.Address address: the address in memory
        :param jpype.JInt or int size: the size of the variable
        :param jpype.JBoolean or bool quantize: true to quantize to the language's "addressable unit"
        :param T val: the value
        """

    @property
    def registerValues(self) -> java.util.Map[ghidra.program.model.lang.Register, T]:
        ...

    @property
    def arithmetic(self) -> PcodeArithmetic[T]:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def addressArithmetic(self) -> PcodeArithmetic[A]:
        ...


class SleighProgramCompiler(java.lang.Enum[SleighProgramCompiler]):
    """
    Methods for compiling p-code programs for various purposes
     
     
    
    Depending on the purpose, special provisions may be necessary around the execution of the
    resulting program. Many utility methods are declared public here because they, well, they have
    utility. The main public methods of this class, however, all start with ``compile``....
    """

    class PcodeLogEntry(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def format(self) -> str:
            ...

        @staticmethod
        def formatList(list: java.util.List[SleighProgramCompiler.PcodeLogEntry]) -> str:
            ...

        def loc(self) -> ghidra.sleigh.grammar.Location:
            ...

        def msg(self) -> str:
            ...

        def type(self) -> str:
            ...


    @typing.type_check_only
    class PcodeError(java.lang.Record, SleighProgramCompiler.PcodeLogEntry):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def loc(self) -> ghidra.sleigh.grammar.Location:
            ...

        def msg(self) -> str:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class PcodeWarning(java.lang.Record, SleighProgramCompiler.PcodeLogEntry):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def loc(self) -> ghidra.sleigh.grammar.Location:
            ...

        def msg(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class DetailedSleighException(ghidra.app.plugin.processors.sleigh.SleighException):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, details: java.util.List[SleighProgramCompiler.PcodeLogEntry]):
            ...

        def getDetails(self) -> java.util.List[SleighProgramCompiler.PcodeLogEntry]:
            ...

        @property
        def details(self) -> java.util.List[SleighProgramCompiler.PcodeLogEntry]:
            ...


    class ErrorCollectingPcodeParser(ghidra.program.model.lang.PcodeParser):
        """
        A p-code parser that provides programmatic access to error diagnostics.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage):
            ...


    class PcodeProgramConstructor(java.lang.Object, typing.Generic[T]):
        """
        A factory for ``PcodeProgram``s
        """

        class_: typing.ClassVar[java.lang.Class]

        def construct(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, ops: java.util.List[ghidra.program.model.pcode.PcodeOp], symbols: collections.abc.Mapping) -> T:
            ...


    class_: typing.ClassVar[java.lang.Class]
    NIL_SYMBOL_NAME: typing.Final = "__nil"

    @staticmethod
    def buildOps(language: ghidra.program.model.lang.Language, template: ghidra.app.plugin.processors.sleigh.template.ConstructTpl) -> java.util.List[ghidra.program.model.pcode.PcodeOp]:
        """
        Construct a list of p-code ops from the given template
        
        :param ghidra.program.model.lang.Language language: the language generating the template and p-code
        :param ghidra.app.plugin.processors.sleigh.template.ConstructTpl template: the template
        :return: the list of p-code ops
        :rtype: java.util.List[ghidra.program.model.pcode.PcodeOp]
        :raises UnknownInstructionException: in case of crossbuilds, the target instruction is unknown
        :raises MemoryAccessException: in case of crossbuilds, the target address cannot be accessed
        :raises IOException: for errors in during emitting
        """

    @staticmethod
    @typing.overload
    def compileExpression(parser: ghidra.program.model.lang.PcodeParser, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, expression: typing.Union[java.lang.String, str]) -> PcodeExpression:
        """
        Compile the given Sleigh expression into a p-code program that can evaluate it, using the
        given parser
         
         
        
        TODO: Currently, expressions cannot be compiled for a user-supplied userop library. The
        evaluator p-code program uses its own library as a means of capturing the result; however,
        userop libraries are easily composed. It should be easy to add that feature if needed.
        
        :param ghidra.program.model.lang.PcodeParser parser: a parser for the given language
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the language of the target p-code machine
        :param java.lang.String or str expression: the Sleigh expression to be evaluated
        :return: a p-code program whose :meth:`PcodeExpression.evaluate(PcodeExecutor) <PcodeExpression.evaluate>` method will
                evaluate the expression on the given executor and its state.
        :rtype: PcodeExpression
        """

    @staticmethod
    @typing.overload
    def compileExpression(language: ghidra.app.plugin.processors.sleigh.SleighLanguage, expression: typing.Union[java.lang.String, str]) -> PcodeExpression:
        """
        Compile the given Sleigh expression into a p-code program that can evaluate it
        
        
        .. seealso::
        
            | :obj:`.compileExpression(PcodeParser, SleighLanguage, String)`
        """

    @staticmethod
    @typing.overload
    def compileProgram(parser: ghidra.program.model.lang.PcodeParser, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, sourceName: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], library: PcodeUseropLibrary[typing.Any]) -> PcodeProgram:
        """
        Compile the given Sleigh source into a simple p-code program with the given parser
         
         
        
        This is suitable for modifying program state using Sleigh statements. Most likely, in
        scripting, or perhaps in a Sleigh repl. The library given during compilation must match the
        library given for execution, at least in its binding of userop IDs to symbols.
        
        :param ghidra.program.model.lang.PcodeParser parser: the parser to use
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the language of the target p-code machine
        :param java.lang.String or str sourceName: a diagnostic name for the Sleigh source
        :param java.lang.String or str source: the Sleigh source
        :param PcodeUseropLibrary[typing.Any] library: the userop library or stub library for binding userop symbols
        :return: the compiled p-code program
        :rtype: PcodeProgram
        """

    @staticmethod
    @typing.overload
    def compileProgram(language: ghidra.app.plugin.processors.sleigh.SleighLanguage, sourceName: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], library: PcodeUseropLibrary[typing.Any]) -> PcodeProgram:
        """
        Compile the given Sleigh source into a simple p-code program
        
        
        .. seealso::
        
            | :obj:`.compileProgram(PcodeParser, SleighLanguage, String, String, PcodeUseropLibrary)`
        """

    @staticmethod
    def compileTemplate(language: ghidra.program.model.lang.Language, parser: ghidra.program.model.lang.PcodeParser, sourceName: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str]) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl:
        """
        Compile the given source into a p-code template
        
        :param ghidra.program.model.lang.Language language: the language
        :param ghidra.program.model.lang.PcodeParser parser: the parser
        :param java.lang.String or str sourceName: the name of the program, for error diagnostics
        :param java.lang.String or str source: the Sleigh source
        :return: the constructor template
        :rtype: ghidra.app.plugin.processors.sleigh.template.ConstructTpl
        
        .. seealso::
        
            | :obj:`.compileProgram(SleighLanguage, String, String, PcodeUseropLibrary)`
        """

    @staticmethod
    def compileUserop(language: ghidra.app.plugin.processors.sleigh.SleighLanguage, opName: typing.Union[java.lang.String, str], params: java.util.List[java.lang.String], source: typing.Union[java.lang.String, str], library: PcodeUseropLibrary[typing.Any], args: java.util.List[ghidra.program.model.pcode.Varnode]) -> PcodeProgram:
        """
        Compile the definition of a p-code userop from Sleigh source into a p-code program
         
         
        
        TODO: Defining a userop from Sleigh source is currently a bit of a hack. It would be nice if
        there were a formalization of Sleigh/p-code subroutines. At the moment, the control flow for
        subroutines is handled out of band, which actually works fairly well. However, parameter
        passing and returning results is not well defined. The current solution is to alias the
        parameters to their arguments, implementing a pass-by-reference scheme. Similarly, the output
        variable is aliased to the symbol named :obj:`SleighPcodeUseropDefinition.OUT_SYMBOL_NAME`,
        which could be problematic if no output variable is given. In this setup, the use of
        temporary variables is tenuous, since no provision is made to ensure a subroutine's
        allocation of temporary variables do not collide with those of callers lower in the stack.
        This could be partly resolved by creating a fresh unique space for each invocation, but then
        it becomes necessary to copy values from the caller's to the callee's. If we're strict about
        parameters being inputs, this is straightforward. If parameters can be used to communicate
        results, then we may need parameter attributes to indicate in, out, or inout. Of course,
        having a separate unique space per invocation implies the executor state can't simply have
        one unique space. Likely, the :obj:`PcodeFrame` would come to own its own unique space, but
        the :obj:`PcodeExecutorState` should probably still manufacture it.
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the language of the target p-code machine
        :param java.lang.String or str opName: the name of the userop (used only for diagnostics here)
        :param java.util.List[java.lang.String] params: the names of parameters in order. Index 0 names the output symbol, probably
                    :obj:`SleighPcodeUseropDefinition.OUT_SYMBOL_NAME`
        :param java.lang.String or str source: the Sleigh source
        :param PcodeUseropLibrary[typing.Any] library: the userop library or stub library for binding userop symbols
        :param java.util.List[ghidra.program.model.pcode.Varnode] args: the varnode arguments in order. Index 0 is the output varnode.
        :return: a p-code program that implements the userop for the given arguments
        :rtype: PcodeProgram
        """

    @staticmethod
    def constructProgram(ctor: SleighProgramCompiler.PcodeProgramConstructor[T], language: ghidra.app.plugin.processors.sleigh.SleighLanguage, template: ghidra.app.plugin.processors.sleigh.template.ConstructTpl, libSyms: collections.abc.Mapping) -> T:
        """
        Invoke the given constructor with the given template and library symbols
        
        :param T: the type of the p-code program:param SleighProgramCompiler.PcodeProgramConstructor[T] ctor: the constructor, often a method reference to ``::new``
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the language producing the p-code
        :param ghidra.app.plugin.processors.sleigh.template.ConstructTpl template: the p-code constructor template
        :param collections.abc.Mapping libSyms: the map of symbols by userop ID
        :return: the p-code program
        :rtype: T
        """

    @staticmethod
    def createParser(language: ghidra.app.plugin.processors.sleigh.SleighLanguage) -> ghidra.program.model.lang.PcodeParser:
        """
        Create a p-code parser for the given language
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the language
        :return: a parser
        :rtype: ghidra.program.model.lang.PcodeParser
        """

    @staticmethod
    def paramSym(language: ghidra.program.model.lang.Language, sleigh: ghidra.pcodeCPort.sleighbase.SleighBase, opName: typing.Union[java.lang.String, str], paramName: typing.Union[java.lang.String, str], arg: ghidra.program.model.pcode.Varnode) -> ghidra.pcodeCPort.slghsymbol.VarnodeSymbol:
        """
        Generate a Sleigh symbol for context when compiling a userop definition
        
        :param ghidra.program.model.lang.Language language: the language of the target p-code machine
        :param ghidra.pcodeCPort.sleighbase.SleighBase sleigh: a means of translating address spaces between execution and compilation
                    contexts
        :param java.lang.String or str opName: a diagnostic name for the userop in which this parameter applies
        :param java.lang.String or str paramName: the symbol name for the parameter
        :param ghidra.program.model.pcode.Varnode arg: the varnode to bind to the parameter symbol
        :return: the named Sleigh symbol bound to the given varnode
        :rtype: ghidra.pcodeCPort.slghsymbol.VarnodeSymbol
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SleighProgramCompiler:
        ...

    @staticmethod
    def values() -> jpype.JArray[SleighProgramCompiler]:
        ...


class SleighPcodeUseropDefinition(PcodeUseropLibrary.PcodeUseropDefinition[T], typing.Generic[T]):
    """
    A p-code userop defined using Sleigh source
    """

    class Factory(java.lang.Object):
        """
        A factory for building :obj:`SleighPcodeUseropDefinition`s.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage):
            """
            Construct a factory for the given language
            
            :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the language
            """

        def define(self, name: typing.Union[java.lang.String, str]) -> SleighPcodeUseropDefinition.Builder:
            """
            Begin building the definition for a userop with the given name
            
            :param java.lang.String or str name: the name of the new userop
            :return: a builder for the userop
            :rtype: SleighPcodeUseropDefinition.Builder
            """


    class Builder(java.lang.Object):
        """
        A builder for a particular userop
        
        
        .. seealso::
        
            | :obj:`Factory`
        """

        class_: typing.ClassVar[java.lang.Class]

        def body(self, additionalBody: java.lang.CharSequence) -> SleighPcodeUseropDefinition.Builder:
            """
            Add Sleigh source to the body
            
            :param java.lang.CharSequence additionalBody: the additional source
            :return: this builder
            :rtype: SleighPcodeUseropDefinition.Builder
            """

        def build(self) -> SleighPcodeUseropDefinition[T]:
            """
            Build the actual definition
             
             
            
            NOTE: Compilation of the sleigh source is delayed until the first invocation, since the
            compiler must know about the varnodes used as parameters. TODO: There may be some way to
            template it at the p-code level instead of the Sleigh source level.
            
            :param T: no particular type, except to match the executor:return: the definition
            :rtype: SleighPcodeUseropDefinition[T]
            """

        @typing.overload
        def params(self, additionalParams: collections.abc.Sequence) -> SleighPcodeUseropDefinition.Builder:
            """
            Add parameters with the given names (to the end)
            
            :param collections.abc.Sequence additionalParams: the additional parameter names
            :return: this builder
            :rtype: SleighPcodeUseropDefinition.Builder
            """

        @typing.overload
        def params(self, *additionalParams: typing.Union[java.lang.String, str]) -> SleighPcodeUseropDefinition.Builder:
            """
            
            
            :param jpype.JArray[java.lang.String] additionalParams: the additional parameter names
            :return: this builder
            :rtype: SleighPcodeUseropDefinition.Builder
            
            .. seealso::
            
                | :obj:`.params(Collection)`
            """


    class_: typing.ClassVar[java.lang.Class]
    OUT_SYMBOL_NAME: typing.Final = "__op_output"

    def getBody(self) -> str:
        """
        Get the Sleigh source that defines this userop
        
        :return: the lines
        :rtype: str
        """

    def getInputs(self) -> java.util.List[java.lang.String]:
        """
        Get the names of the inputs in order
        
        :return: the input names
        :rtype: java.util.List[java.lang.String]
        """

    def programFor(self, outArg: ghidra.program.model.pcode.Varnode, inArgs: java.util.List[ghidra.program.model.pcode.Varnode], library: PcodeUseropLibrary[typing.Any]) -> PcodeProgram:
        """
        Get the p-code program implementing this userop for the given arguments and library.
         
         
        
        This will compile and cache a program for each new combination of arguments seen.
        
        :param ghidra.program.model.pcode.Varnode outArg: the output operand, if applicable
        :param java.util.List[ghidra.program.model.pcode.Varnode] inArgs: the input operands
        :param PcodeUseropLibrary[typing.Any] library: the complete userop library
        :return: the p-code program to be fed to the same executor as invoked this userop, but in a
                new frame
        :rtype: PcodeProgram
        """

    @property
    def inputs(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def body(self) -> java.lang.String:
        ...


class PairedPcodeExecutorState(PcodeExecutorState[org.apache.commons.lang3.tuple.Pair[L, R]], typing.Generic[L, R]):
    """
    A paired executor state
     
     
    
    This composes a delegate state and piece "left" and "write" creating a single state which instead
    stores pairs of values, where the left component has the value type of the left state, and the
    right component has the value type of the right state. Note that both states are addressed using
    only the left "control" component. Otherwise, every operation on this state is decomposed into
    operations upon the delegate states, and the final result composed from the results of those
    operations.
     
     
    
    Where a response cannot be composed of both states, the paired state defers to the left. In this
    way, the left state controls the machine, while the right is computed in tandem. The right never
    directly controls the machine
     
     
    
    See :obj:`PairedPcodeExecutorStatePiece` regarding the composition of three or more pieces.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, piece: PairedPcodeExecutorStatePiece[L, L, R]):
        ...

    @typing.overload
    def __init__(self, left: PcodeExecutorState[L], right: PcodeExecutorStatePiece[L, R], arithmetic: PcodeArithmetic[org.apache.commons.lang3.tuple.Pair[L, R]]):
        """
        Compose a paired state from the given left and right states
        
        :param PcodeExecutorState[L] left: the state backing the left side of paired values ("control")
        :param PcodeExecutorStatePiece[L, R] right: the state backing the right side of paired values ("auxiliary")
        """

    @typing.overload
    def __init__(self, left: PcodeExecutorState[L], right: PcodeExecutorStatePiece[L, R]):
        ...

    def getLeft(self) -> PcodeExecutorStatePiece[L, L]:
        """
        Get the delegate backing the left side of paired values
        
        :return: the left state
        :rtype: PcodeExecutorStatePiece[L, L]
        """

    def getRight(self) -> PcodeExecutorStatePiece[L, R]:
        """
        Get the delegate backing the right side of paired values
        
        :return: the right state
        :rtype: PcodeExecutorStatePiece[L, R]
        """

    @property
    def left(self) -> PcodeExecutorStatePiece[L, L]:
        ...

    @property
    def right(self) -> PcodeExecutorStatePiece[L, R]:
        ...


class SuspendedPcodeExecutionException(PcodeExecutionException):
    """
    An exception thrown during execution if :meth:`PcodeThread.setSuspended(boolean) <PcodeThread.setSuspended>` is invoked with
    ``true``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, frame: PcodeFrame, cause: java.lang.Throwable):
        ...


class SleighLinkException(java.lang.RuntimeException):
    """
    An exception thrown by
    :meth:`PcodeExecutor.executeCallother(PcodeOp, PcodeFrame, PcodeUseropLibrary) <PcodeExecutor.executeCallother>` when a p-code
    userop turns up missing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class AccessPcodeExecutionException(PcodeExecutionException):
    """
    There was an issue accessing the executor's state, i.e., memory or register values
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], frame: PcodeFrame, cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Exception):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class DecodePcodeExecutionException(PcodeExecutionException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str], pc: ghidra.program.model.address.Address):
        ...

    def getProgramCounter(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def programCounter(self) -> ghidra.program.model.address.Address:
        ...


class AnnotatedPcodeUseropLibrary(PcodeUseropLibrary[T], typing.Generic[T]):
    """
    A userop library wherein Java methods are exported via a special annotation
    
     
    
    See ``StandAloneEmuExampleScript`` for an example of implementing a userop library.
    """

    @typing.type_check_only
    class ParamAnnotProc(java.lang.Enum[AnnotatedPcodeUseropLibrary.ParamAnnotProc]):

        class_: typing.ClassVar[java.lang.Class]
        EXECUTOR: typing.Final[AnnotatedPcodeUseropLibrary.ParamAnnotProc]
        STATE: typing.Final[AnnotatedPcodeUseropLibrary.ParamAnnotProc]
        LIBRARY: typing.Final[AnnotatedPcodeUseropLibrary.ParamAnnotProc]
        OUTPUT: typing.Final[AnnotatedPcodeUseropLibrary.ParamAnnotProc]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AnnotatedPcodeUseropLibrary.ParamAnnotProc:
            ...

        @staticmethod
        def values() -> jpype.JArray[AnnotatedPcodeUseropLibrary.ParamAnnotProc]:
            ...


    @typing.type_check_only
    class AnnotatedPcodeUseropDefinition(PcodeUseropLibrary.PcodeUseropDefinition[T], typing.Generic[T]):
        """
        A wrapped, annotated Java method, exported as a userop definition
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, library: AnnotatedPcodeUseropLibrary[T], opType: java.lang.reflect.Type, lookup: java.lang.invoke.MethodHandles.Lookup, method: java.lang.reflect.Method, annot: AnnotatedPcodeUseropLibrary.PcodeUserop):
            ...


    @typing.type_check_only
    class FixedArgsAnnotatedPcodeUseropDefinition(AnnotatedPcodeUseropLibrary.AnnotatedPcodeUseropDefinition[T], typing.Generic[T]):
        """
        An annotated userop with a fixed number of arguments
        """

        @typing.type_check_only
        class UseropInputParam(java.lang.Object):

            class_: typing.ClassVar[java.lang.Class]

            def convert(self, vn: ghidra.program.model.pcode.Varnode, executor: PcodeExecutor[T]) -> java.lang.Object:
                ...

            def position(self) -> int:
                ...


        @typing.type_check_only
        class VarnodeUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class TValUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class ByteUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class ShortUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class IntUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class LongUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class FloatUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class DoubleUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class BooleanUseropInputParam(java.lang.Record, AnnotatedPcodeUseropLibrary.FixedArgsAnnotatedPcodeUseropDefinition.UseropInputParam):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def position(self) -> int:
                ...

            def toString(self) -> str:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, library: AnnotatedPcodeUseropLibrary[T], opType: java.lang.reflect.Type, lookup: java.lang.invoke.MethodHandles.Lookup, method: java.lang.reflect.Method, annot: AnnotatedPcodeUseropLibrary.PcodeUserop):
            ...


    @typing.type_check_only
    class VariadicAnnotatedPcodeUseropDefinition(AnnotatedPcodeUseropLibrary.AnnotatedPcodeUseropDefinition[T], typing.Generic[T]):
        """
        An annotated userop with a variable number of arguments
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, library: AnnotatedPcodeUseropLibrary[T], opType: java.lang.reflect.Type, lookup: java.lang.invoke.MethodHandles.Lookup, method: java.lang.reflect.Method, annot: AnnotatedPcodeUseropLibrary.PcodeUserop):
            ...


    class PcodeUserop(java.lang.annotation.Annotation):
        """
        An annotation to export a Java method as a userop in the library.
         
         
        
        Ordinarily, each parameter receives an input to the userop. Each parameter may be annotated
        with at most one of :obj:`OpExecutor`, :obj:`OpState`, :obj:`OpLibrary`, or
        :obj:`OpOutput` to change what it receives. If :meth:`variadic() <.variadic>` is false, non-annotated
        parameters receive the inputs to the userop in matching order. Conventionally, annotated
        parameters should be placed first or last. Parameters accepting inputs must have type either
        :obj:`Varnode` or assignable from ``T``. A parameter of type :obj:`Varnode` will
        receive the input :obj:`Varnode`. A parameter that is assignable from ``T`` will receive
        the input value. If it so happens that ``T`` is assignable from :obj:`Varnode`, the
        parameter will receive the :obj:`Varnode`, not the value. **NOTE:** Receiving a value
        instead of a variable may lose its size. Depending on the type of the value, that size may or
        may not be recoverable.
         
         
        
        If :meth:`variadic() <.variadic>` is true, then a single non-annotated parameter receives all inputs in
        order. This parameter must have a type :obj:`Varnode```[]`` to receive variables or have
        type assignable from ``T[]`` to receive values.
         
         
        
        Note that there is no annotation to receive the "thread," because threads are not a concept
        known to the p-code executor or userop libraries, in general. In most cases, receiving the
        executor and/or state (which are usually bound to a specific thread) is sufficient. The
        preferred means of exposing thread-specific userops is to construct a library bound to that
        specific thread. That strategy should preserve compile-time type safety. Alternatively, you
        can receive the executor or state, cast it to your specific type, and use an accessor to get
        its thread.
        """

        class_: typing.ClassVar[java.lang.Class]

        def canInline(self) -> bool:
            """
            Set to true to suggest inlining.
            
            
            .. seealso::
            
                | :obj:`PcodeUseropLibrary.PcodeUseropDefinition.canInlinePcode()`
            """

        def functional(self) -> bool:
            """
            Set to true to attest that the userop is a pure function.
             
             
            
            An incorrect attestation can lead to erroneous execution results.
            
            
            .. seealso::
            
                | :obj:`PcodeUseropLibrary.PcodeUseropDefinition.isFunctional()`
            """

        def hasSideEffects(self) -> bool:
            """
            Set to false to attest the userop has no side effects.
             
             
            
            An incorrect attestation can lead to erroneous execution results.
            
            
            .. seealso::
            
                | :obj:`PcodeUseropLibrary.PcodeUseropDefinition.hasSideEffects()`
            """

        def modifiesContext(self) -> bool:
            """
            Set to true to indicate the userop can modify the decode context.
             
             
            
            Failure to indicate context modifications can lead to erroneous decodes and thus
            incorrect execution results.
            
            
            .. seealso::
            
                | :obj:`PcodeUseropLibrary.PcodeUseropDefinition.modifiesContext()`
            """

        def variadic(self) -> bool:
            """
            Set to true to receive all inputs in an array.
            """


    class OpExecutor(java.lang.annotation.Annotation):
        """
        An annotation to receive the executor itself into a parameter
         
         
        
        The annotated parameter must have type :obj:`PcodeExecutor` with the same ``<T>`` as the
        class declaring the method.
        """

        class_: typing.ClassVar[java.lang.Class]


    class OpState(java.lang.annotation.Annotation):
        """
        An annotation to receive the executor's state into a parameter
        
         
        
        The annotated parameter must have type :obj:`PcodeExecutorState` with the same ``<T>``
        as the class declaring the method.
        """

        class_: typing.ClassVar[java.lang.Class]


    class OpLibrary(java.lang.annotation.Annotation):
        """
        An annotation to receive the complete library into a parameter
         
         
        
        Because the library defining the userop may be composed with other libraries, it is not
        sufficient to use the "``this``" reference to obtain the library. If the library being
        used for execution needs to be passed to a dependent component of execution, it must be the
        complete library, not just the one defining the userop. This annotation allows a userop
        definition to receive the complete library.
         
         
        
        The annotated parameter must have type :obj:`PcodeUseropLibrary` with the same ``<T>``
        as the class declaring the method.
        """

        class_: typing.ClassVar[java.lang.Class]


    class OpOutput(java.lang.annotation.Annotation):
        """
        An annotation to receive the output varnode into a parameter
         
         
        
        The annotated parameter must have type :obj:`Varnode`.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default constructor, usually invoked implicitly
        """


class LocationPcodeArithmetic(java.lang.Enum[LocationPcodeArithmetic], PcodeArithmetic[ValueLocation]):
    """
    An auxiliary arithmetic that reports the location the control value
     
     
    
    This is intended for use as the right side of a :obj:`PairedPcodeArithmetic`. Note that constant
    and unique spaces are never returned. Furthermore, any computation performed on a value,
    producing a temporary value, philosophically does not exist at any location in the state. Thus,
    most operations in this arithmetic result in ``null``. The accompanying state piece
    :obj:`LocationPcodeExecutorStatePiece` generates the actual locations.
    """

    class_: typing.ClassVar[java.lang.Class]
    BIG_ENDIAN: typing.Final[LocationPcodeArithmetic]
    LITTLE_ENDIAN: typing.Final[LocationPcodeArithmetic]

    @staticmethod
    def forEndian(bigEndian: typing.Union[jpype.JBoolean, bool]) -> LocationPcodeArithmetic:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LocationPcodeArithmetic:
        ...

    @staticmethod
    def values() -> jpype.JArray[LocationPcodeArithmetic]:
        ...



__all__ = ["BytesPcodeExecutorStateSpace", "SleighUtils", "PcodeFrame", "DefaultPcodeExecutorState", "AddressesReadPcodeArithmetic", "LocationPcodeExecutorStatePiece", "ConcretionError", "BytesPcodeExecutorState", "AbstractBytesPcodeExecutorStatePiece", "PcodeProgram", "InjectionErrorPcodeExecutionException", "PcodeArithmetic", "PcodeExecutor", "BytesPcodeExecutorStatePiece", "PairedPcodeExecutorStatePiece", "PcodeExecutorState", "PairedPcodeArithmetic", "InterruptPcodeExecutionException", "PcodeExpression", "ComposedPcodeUseropLibrary", "PcodeExecutionException", "ValueLocation", "BytesPcodeArithmetic", "PcodeUseropLibrary", "AbstractLongOffsetPcodeExecutorStatePiece", "PcodeExecutorStatePiece", "SleighProgramCompiler", "SleighPcodeUseropDefinition", "PairedPcodeExecutorState", "SuspendedPcodeExecutionException", "SleighLinkException", "AccessPcodeExecutionException", "DecodePcodeExecutionException", "AnnotatedPcodeUseropLibrary", "LocationPcodeArithmetic"]
