from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.expr
import ghidra.app.plugin.assembler.sleigh.grammars
import ghidra.app.plugin.assembler.sleigh.symbol
import ghidra.app.plugin.assembler.sleigh.tree
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.expression
import ghidra.app.plugin.processors.sleigh.pattern
import ghidra.app.plugin.processors.sleigh.symbol
import ghidra.graph
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.stream # type: ignore
import org.apache.commons.collections4.set # type: ignore


B = typing.TypeVar("B")
BF = typing.TypeVar("BF")
N = typing.TypeVar("N")
RP = typing.TypeVar("RP")
T = typing.TypeVar("T")


class AssemblyConstructState(AbstractAssemblyState):
    """
    The state corresponding to a sub-table operand
     
     
    
    This is roughly analogous to :obj:`ConstructState`, but for assembly. It records the assembly
    semantic, i.e., SLEIGH constructor, and the child states, one for each operand in the
    constructor. It's implementation of :meth:`resolve(AssemblyResolvedPatterns, Collection) <.resolve>`
    encapsulates, perhaps the very kernel of, machine-code generation. Operands can have there own
    complexity, but most of the core machine-code concepts of SLEIGH are handled by constructors.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], path: java.util.List[AssemblyConstructorSemantic], shift: typing.Union[jpype.JInt, int], sem: AssemblyConstructorSemantic, children: java.util.List[AbstractAssemblyState]):
        """
        Construct the state for a selected SLEIGH constructor of a sub-table operand
         
         
        
        The operand's length is computed from the constructors length and the shifts and lengths of
        its generated operands.
        
        :param AbstractAssemblyTreeResolver[typing.Any] resolver: the resolver
        :param java.util.List[AssemblyConstructorSemantic] path: the path for diagnostics
        :param jpype.JInt or int shift: the (right) shift of this operand
        :param AssemblyConstructorSemantic sem: the selected SLEIGH constructor
        :param java.util.List[AbstractAssemblyState] children: the child state for each operand in the constructor
        """


class AbstractAssemblyResolution(AssemblyResolution):
    """
    The (often intermediate) result of assembly
     
     
    
    These may represent a successful construction (:obj:`AssemblyResolvedPatterns`, a future field
    (:obj:`AssemblyResolvedBackfill`), or an error (:obj:`AssemblyResolvedError`).
     
     
    
    This class also provides the static factory methods for constructing any of its subclasses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def withRight(self, right: AssemblyResolution) -> AssemblyResolution:
        """
        Get this same resolution, but with the given right sibling
        
        :param AssemblyResolution right: the right sibling
        :return: the resolution
        :rtype: AssemblyResolution
        """

    def withoutRight(self) -> AssemblyResolution:
        """
        Get this same resolution, but without any right siblings
        
        :return: the resolution
        :rtype: AssemblyResolution
        """


class AssemblyResolvedPatterns(AssemblyResolution):

    class_: typing.ClassVar[java.lang.Class]

    def backfill(self, solver: ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver, vals: collections.abc.Mapping) -> AssemblyResolution:
        """
        Apply as many backfill records as possible
         
         
        
        Each backfill record is resolved in turn, if the record cannot be resolved, it remains
        listed. If the record can be resolved, but it conflicts, an error record is returned. Each
        time a record is resolved and combined successfully, all remaining records are tried again.
        The result is the combined resolved backfills, with only the unresolved backfill records
        listed.
        
        :param ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver solver: the solver, usually the same as the original attempt to solve.
        :param collections.abc.Mapping vals: the values.
        :return: the result, or an error.
        :rtype: AssemblyResolution
        """

    def bitsEqual(self, that: AssemblyResolvedPatterns) -> bool:
        """
        Check if this and another resolution have equal encodings
         
         
        
        This is like :meth:`Object.equals(Object) <Object.equals>`, but it ignores backfill records and forbidden 
        patterns.
        
        :param AssemblyResolvedPatterns that: the other resolution
        :return: true if both have equal encodings
        :rtype: bool
        """

    def checkNotForbidden(self) -> AssemblyResolution:
        """
        Check if the current encoding is forbidden by one of the attached patterns
         
         
        
        The pattern becomes forbidden if this encoding's known bits are an overset of any forbidden
        pattern's known bits.
        
        :return: false if the pattern is forbidden (and thus in error), true if permitted
        :rtype: AssemblyResolution
        """

    @typing.overload
    def combine(self, pat: AssemblyResolvedPatterns) -> AssemblyResolvedPatterns:
        """
        Combine the encodings and backfills of the given resolution into this one
         
         
        
        This combines corresponding pattern blocks (assuming they agree), collects backfill records,
        and collects forbidden patterns.
        
        :param AssemblyResolvedPatterns pat: the other resolution
        :return: the result if successful, or null
        :rtype: AssemblyResolvedPatterns
        """

    @typing.overload
    def combine(self, bf: AssemblyResolvedBackfill) -> AssemblyResolvedPatterns:
        """
        Combine the given backfill record into this resolution
        
        :param AssemblyResolvedBackfill bf: the backfill record
        :return: the result
        :rtype: AssemblyResolvedPatterns
        """

    def combineLessBackfill(self, that: AssemblyResolvedPatterns, bf: AssemblyResolvedBackfill) -> AssemblyResolvedPatterns:
        """
        Combine a backfill result
         
         
        
        When a backfill is successful, the result should be combined with the owning resolution. In
        addition, for bookkeeping's sake, the resolved record should be removed from the list of
        backfills.
        
        :param AssemblyResolvedPatterns that: the result from backfilling
        :param AssemblyResolvedBackfill bf: the resolved backfilled record
        :return: the result if successful, or null
        :rtype: AssemblyResolvedPatterns
        """

    def dumpConstructorTree(self) -> str:
        """
        Used for testing and diagnostics: list the constructor line numbers used to resolve this
        encoding
         
         
        
        This includes braces to describe the tree structure
        
        :return: the constructor tree
        :rtype: str
        
        .. seealso::
        
            | :obj:`ConstructState.dumpConstructorTree()`
        """

    def equivalentConstructState(self, state: ghidra.app.plugin.processors.sleigh.ConstructState) -> bool:
        """
        Check if this assembled construct state is the same as the given dis-assembled construct
        state.
        """

    def getBackfills(self) -> java.util.Collection[AssemblyResolvedBackfill]:
        """
        Get the backfill records for this resolution, if any
        
        :return: the backfills
        :rtype: java.util.Collection[AssemblyResolvedBackfill]
        """

    def getContext(self) -> AssemblyPatternBlock:
        """
        Get the context block
        
        :return: the context block
        :rtype: AssemblyPatternBlock
        """

    def getDefinedInstructionLength(self) -> int:
        """
        Get the length of the instruction encoding, excluding trailing undefined bytes
         
         
        
        **NOTE:** this DOES include the offset
        
        **NOTE:** this DOES NOT include pending backfills
        
        :return: the length of the defined bytes in the instruction block
        :rtype: int
        """

    def getForbids(self) -> java.util.Collection[AssemblyResolvedPatterns]:
        """
        Get the forbidden patterns for this resolution
         
         
        
        These represent patterns included in the current resolution that would actually get matched
        by a more specific constructor somewhere in the resolved tree, and thus are subtracted.
        
        :return: the forbidden patterns
        :rtype: java.util.Collection[AssemblyResolvedPatterns]
        """

    def getInstruction(self) -> AssemblyPatternBlock:
        """
        Get the instruction block
        
        :return: the instruction block
        :rtype: AssemblyPatternBlock
        """

    def getInstructionLength(self) -> int:
        """
        Get the length of the instruction encoding
         
         
        
        This is used to ensure each operand is encoded at the correct offset
         
         
        
        **NOTE:** this DOES include the offset
        
        **NOTE:** this DOES include pending backfills
        
        :return: the length of the instruction block
        :rtype: int
        """

    def hasBackfills(self) -> bool:
        """
        Check if this resolution has pending backfills to apply
        
        :return: true if there are backfills
        :rtype: bool
        """

    def maskOut(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp) -> AssemblyResolvedPatterns:
        """
        Set all bits read by a given context operation to unknown
        
        :param ghidra.app.plugin.processors.sleigh.ContextOp cop: the context operation
        :return: the result
        :rtype: AssemblyResolvedPatterns
        
        .. seealso::
        
            | :obj:`AssemblyPatternBlock.maskOut(ContextOp)`
        """

    def nopLeftSibling(self) -> AssemblyResolvedPatterns:
        """
        Generate a new nop right this resolution to its right.
         
         
        
        Alternatively phrased: append a nop to the left of this list of siblings, returning the new
        head.
        
        :return: the nop resolution
        :rtype: AssemblyResolvedPatterns
        """

    def possibleInsVals(self, forCtx: AssemblyPatternBlock) -> java.lang.Iterable[jpype.JArray[jpype.JByte]]:
        """
        Get an iterable over all the possible fillings of the instruction pattern given a context
         
         
        
        This is meant to be used idiomatically, as in an enhanced for loop:
         
         
        for (byte[] ins : rcon.possibleInsVals(ctx)) {
            System.out.println(format(ins));
        }
         
         
         
        
        This is similar to calling
        :meth:`getInstruction() <.getInstruction>`.:meth:`AssemblyPatternBlock.possibleVals() <AssemblyPatternBlock.possibleVals>`, *but* with
        forbidden patterns removed. A context is required so that only those forbidden patterns
        matching the given context are actually removed. This method should always be preferred to
        the sequence mentioned above, since :meth:`AssemblyPatternBlock.possibleVals() <AssemblyPatternBlock.possibleVals>` on its own
        may yield bytes that do not produce the desired instruction.
         
         
        
        **NOTE:** The implementation is based on :meth:`AssemblyPatternBlock.possibleVals() <AssemblyPatternBlock.possibleVals>`, so
        be aware that a single array is reused for each iterate. You should not retain a pointer to
        the array, but rather make a copy.
        
        :param AssemblyPatternBlock forCtx: the context at the assembly address
        :return: the iterable
        :rtype: java.lang.Iterable[jpype.JArray[jpype.JByte]]
        """

    def readContext(self, start: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Decode a portion of the context block
        
        :param jpype.JInt or int start: the first byte to decode
        :param jpype.JInt or int len: the number of bytes to decode
        :return: the read masked value
        :rtype: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong
        
        .. seealso::
        
            | :obj:`AssemblyPatternBlock.readBytes(int, int)`
        """

    def readContextOp(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Decode the value from the context located where the given context operation would write
         
         
        
        This is used to read the value from the left-hand-side "variable" of a context operation. It
        seems backward, because it is. When assembling, the right-hand-side expression of a context
        operation must be solved. This means the "variable" is known from the context(s) of the
        resolved children constructors. The value read is then used as the goal in solving the
        expression.
        
        :param ghidra.app.plugin.processors.sleigh.ContextOp cop: the context operation whose "variable" to read.
        :return: the masked result.
        :rtype: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong
        """

    def readInstruction(self, byteStart: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Decode a portion of the instruction block
        
        :param jpype.JInt or int byteStart: the first byte to decode
        :param jpype.JInt or int size: the number of bytes to decode
        :return: the read masked value
        :rtype: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong
        
        .. seealso::
        
            | :obj:`AssemblyPatternBlock.readBytes(int, int)`
        """

    def solveContextChangesForForbids(self, sem: AssemblyConstructorSemantic, vals: collections.abc.Mapping) -> AssemblyResolvedPatterns:
        """
        Solve and apply context changes in reverse to forbidden patterns
         
         
        
        To avoid circumstances where a context change during disassembly would invoke a more specific
        sub-constructor than was used to assembly the instruction, we must solve the forbidden
        patterns in tandem with the overall resolution. If the context of any forbidden pattern
        cannot be solved, we simply drop the forbidden pattern -- the lack of a solution implies
        there is no way the context change could produce the forbidden pattern.
        
        :param AssemblyConstructorSemantic sem: the constructor whose context changes to solve
        :param collections.abc.Mapping vals: any defined symbols
        :return: the result
        :rtype: AssemblyResolvedPatterns
        
        .. seealso::
        
            | :obj:`AssemblyConstructorSemantic.solveContextChanges(AssemblyResolvedPatterns, Map)`
        """

    def truncate(self, shamt: typing.Union[jpype.JInt, int]) -> AssemblyResolvedPatterns:
        """
        Truncate (unshift) the resolved instruction pattern from the left
         
        **NOTE:** This drops all backfill and forbidden pattern records, since this method is
        typically used to read token fields rather than passed around for resolution.
        
        :param jpype.JInt or int shamt: the number of bytes to remove from the left
        :return: the result
        :rtype: AssemblyResolvedPatterns
        """

    def withConstructor(self, cons: ghidra.app.plugin.processors.sleigh.Constructor) -> AssemblyResolvedPatterns:
        """
        Create a copy of this resolution with a replaced constructor
        
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the new constructor
        :return: the copy
        :rtype: AssemblyResolvedPatterns
        """

    def withContext(self, ctx: AssemblyPatternBlock) -> AssemblyResolvedPatterns:
        """
        Create a copy of this resolution with a new context
        
        :param AssemblyPatternBlock ctx: the new context
        :return: the copy
        :rtype: AssemblyResolvedPatterns
        """

    def withDescription(self, description: typing.Union[java.lang.String, str]) -> AssemblyResolvedPatterns:
        """
        Create a copy of this resolution with a new description
        
        :param java.lang.String or str description: the new description
        :return: the copy
        :rtype: AssemblyResolvedPatterns
        """

    def withForbids(self, more: java.util.Set[AssemblyResolvedPatterns]) -> AssemblyResolvedPatterns:
        """
        Create a new resolution from this one with the given forbidden patterns recorded
        
        :param java.util.Set[AssemblyResolvedPatterns] more: the additional forbidden patterns to record
        :return: the new resolution
        :rtype: AssemblyResolvedPatterns
        """

    def withRight(self, right: AssemblyResolution) -> AssemblyResolvedPatterns:
        """
        Create a copy of this resolution with a sibling to the right
         
         
        
        The right sibling is a mechanism for collecting children of a parent yet to be created. See
        :meth:`parent(String, int) <.parent>`.
        
        :param AssemblyResolution right: the right sibling
        :return: the new resolution
        :rtype: AssemblyResolvedPatterns
        """

    def writeContextOp(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp, val: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong) -> AssemblyResolvedPatterns:
        """
        Encode the given value into the context block as specified by an operation
         
         
        
        This is the forward (as in disassembly) direction of applying context operations. The pattern
        expression is evaluated, and the result is written as specified.
        
        :param ghidra.app.plugin.processors.sleigh.ContextOp cop: the context operation specifying the location of the value to encode
        :param ghidra.app.plugin.assembler.sleigh.expr.MaskedLong val: the masked value to encode
        :return: the result
        :rtype: AssemblyResolvedPatterns
        """

    @property
    def forbids(self) -> java.util.Collection[AssemblyResolvedPatterns]:
        ...

    @property
    def instruction(self) -> AssemblyPatternBlock:
        ...

    @property
    def context(self) -> AssemblyPatternBlock:
        ...

    @property
    def instructionLength(self) -> jpype.JInt:
        ...

    @property
    def backfills(self) -> java.util.Collection[AssemblyResolvedBackfill]:
        ...

    @property
    def definedInstructionLength(self) -> jpype.JInt:
        ...


class AssemblyTreeResolver(AbstractAssemblyTreeResolver[AssemblyResolvedPatterns]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: AbstractAssemblyResolutionFactory[AssemblyResolvedPatterns, typing.Any], lang: ghidra.app.plugin.processors.sleigh.SleighLanguage, at: ghidra.program.model.address.Address, tree: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch, context: AssemblyPatternBlock, ctxGraph: AssemblyContextGraph):
        ...


class AssemblyOperandStateGenerator(AbstractAssemblyStateGenerator[ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken]):
    """
    The generator of :obj:`AssemblyOperandState` from :obj:`AssemblyParseNumericToken`
    
     
    
    In short, this handles generation of a single operand state for the operand and value recorded by
    the given parse token.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], node: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken, opSym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol, fromLeft: AssemblyResolvedPatterns):
        """
        Construct the operand state generator
        
        :param AbstractAssemblyTreeResolver[typing.Any] resolver: the resolver
        :param ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken node: the node from which to generate the state
        :param AssemblyResolvedPatterns fromLeft: the accumulated patterns from the left sibling or parent
        :param ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol opSym: the operand symbol
        """


class DefaultAssemblyResolvedError(AbstractAssemblyResolution, AssemblyResolvedError):
    """
    A :obj:`AssemblyResolution` indicating the occurrence of a (usually semantic) error
     
     
    
    The description should indicate where the error occurred. The error message should explain the
    actual error. To help the user diagnose the nature of the error, errors in sub-constructors
    should be placed as children of an error given by the parent constructor.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getError(self) -> str:
        """
        Get a description of the error
        
        :return: the description
        :rtype: str
        """

    @property
    def error(self) -> java.lang.String:
        ...


class DefaultAssemblyResolvedPatterns(AbstractAssemblyResolution, AssemblyResolvedPatterns):
    """
    A :obj:`AssemblyResolution` indicating successful application of a constructor
     
     
    
    This is almost analogous to :obj:`DisjointPattern <ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern>`, in that is joins an instruction :obj:`AssemblyPatternBlock` with a
    corresponding context :obj:`AssemblyPatternBlock`. However, this object is mutable, and it
    collects backfill records, as well as forbidden patterns.
     
     
    
    When the applied constructor is from the "instruction" subtable, this represents a fully-
    constructed instruction with required context. All backfill records ought to be resolved and
    applied before the final result is given to the user, i.e., passed into the
    :obj:`AssemblySelector`. If at any time during the resolution or backfill process, the result
    becomes confined to one of the forbidden patterns, it must be dropped, since the encoding will
    actually invoke a more specific SLEIGH constructor.
    """

    class_: typing.ClassVar[java.lang.Class]

    def combineLessBackfill(self, that: AssemblyResolvedPatterns, bf: AssemblyResolvedBackfill) -> AssemblyResolvedPatterns:
        """
        Combine a backfill result
         
         
        
        When a backfill is successful, the result should be combined with the owning resolution. In
        addition, for bookkeeping's sake, the resolved record should be removed from the list of
        backfills.
        
        :param AssemblyResolvedPatterns that: the result from backfilling
        :param AssemblyResolvedBackfill bf: the resolved backfilled record
        :return: the result if successful, or null
        :rtype: AssemblyResolvedPatterns
        """

    def copyAppendDescription(self, append: typing.Union[java.lang.String, str]) -> AssemblyResolvedPatterns:
        """
        Duplicate this resolution, with additional description text appended
        
        :param java.lang.String or str append: the text to append
        :return: the duplicate NOTE: An additional separator ``": "`` is inserted
        :rtype: AssemblyResolvedPatterns
        """

    def getConstructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor:
        ...

    def getSpecificity(self) -> int:
        """
        Count the number of bits specified in the resolution patterns
         
         
        
        Totals the specificity of the instruction and context pattern blocks.
        
        :return: the number of bits in the resulting patterns
        :rtype: int
        
        .. seealso::
        
            | :obj:`AssemblyPatternBlock.getSpecificity()`
        """

    @property
    def specificity(self) -> jpype.JInt:
        ...

    @property
    def constructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor:
        ...


class AssemblyNopState(AbstractAssemblyState):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], path: java.util.List[AssemblyConstructorSemantic], shift: typing.Union[jpype.JInt, int], opSym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol):
        ...


class AssemblyStringStateGenerator(AbstractAssemblyStateGenerator[ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], node: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken, opSym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol, fromLeft: AssemblyResolvedPatterns):
        ...


class AbstractAssemblyResolutionFactory(java.lang.Object, typing.Generic[RP, BF]):

    class AbstractAssemblyResolutionBuilder(java.lang.Object, typing.Generic[B, T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def children(self, children: java.util.List[AssemblyResolution]) -> B:
            ...

        def copyFromDefault(self, ar: AbstractAssemblyResolution):
            ...

        def description(self, description: typing.Union[java.lang.String, str]) -> B:
            ...

        def right(self, right: AssemblyResolution) -> B:
            ...


    class AbstractAssemblyResolvedPatternsBuilder(AbstractAssemblyResolutionFactory.AbstractAssemblyResolutionBuilder[AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedPatternsBuilder[RP], RP], typing.Generic[RP]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def copyFromDefault(self, rp: DefaultAssemblyResolvedPatterns):
            ...


    class AbstractAssemblyResolvedBackfillBuilder(AbstractAssemblyResolutionFactory.AbstractAssemblyResolutionBuilder[AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedBackfillBuilder[BF], BF], typing.Generic[BF]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class DefaultAssemblyResolvedPatternBuilder(AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedPatternsBuilder[AssemblyResolvedPatterns]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class DefaultAssemblyResolvedBackfillBuilder(AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedBackfillBuilder[AssemblyResolvedBackfill]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class AssemblyResolvedErrorBuilder(AbstractAssemblyResolutionFactory.AbstractAssemblyResolutionBuilder[AbstractAssemblyResolutionFactory.AssemblyResolvedErrorBuilder, AssemblyResolvedError]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def error(self, error: typing.Union[java.lang.String, str]) -> AbstractAssemblyResolutionFactory.AssemblyResolvedErrorBuilder:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def backfill(self, exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, goal: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong, inslen: typing.Union[jpype.JInt, int], description: typing.Union[java.lang.String, str]) -> AssemblyResolution:
        """
        Build a backfill record to attach to a successful resolution result
        
        :param ghidra.app.plugin.processors.sleigh.expression.PatternExpression exp: the expression depending on a missing symbol
        :param ghidra.app.plugin.assembler.sleigh.expr.MaskedLong goal: the desired value of the expression
        :param jpype.JInt or int inslen: the length of instruction portion expected in the future solution
        :param java.lang.String or str description: a description of the backfill record
        :return: the new record
        :rtype: AssemblyResolution
        """

    def backfillBuilder(self, exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, goal: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong, inslen: typing.Union[jpype.JInt, int], description: typing.Union[java.lang.String, str]) -> AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedBackfillBuilder[BF]:
        ...

    def contextOnly(self, ctx: AssemblyPatternBlock, description: typing.Union[java.lang.String, str]) -> RP:
        """
        Build a context-only successful resolution result
        
        :param AssemblyPatternBlock ctx: the context pattern block
        :param java.lang.String or str description: a description of the resolution
        :return: the new resolution
        :rtype: RP
        
        .. seealso::
        
            | :obj:`.resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List,
            AssemblyResolution)`
        """

    def error(self, error: typing.Union[java.lang.String, str], res: AssemblyResolution) -> AssemblyResolution:
        """
        Build an error resolution record, based on an intermediate SLEIGH constructor record
        
        :param java.lang.String or str error: a description of the error
        :param AssemblyResolution res: the constructor record that was being populated when the error occurred
        :return: the new error resolution
        :rtype: AssemblyResolution
        """

    def errorBuilder(self, error: typing.Union[java.lang.String, str], res: AssemblyResolution) -> AbstractAssemblyResolutionFactory.AssemblyResolvedErrorBuilder:
        ...

    def fromPattern(self, pat: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern, minLen: typing.Union[jpype.JInt, int], description: typing.Union[java.lang.String, str], cons: ghidra.app.plugin.processors.sleigh.Constructor) -> RP:
        """
        Build a successful resolution result from a SLEIGH constructor's patterns
        
        :param ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern pat: the constructor's pattern
        :param java.lang.String or str description: a description of the resolution
        :return: the new resolution
        :rtype: RP
        """

    def fromString(self, str: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], children: java.util.List[AssemblyResolution]) -> AssemblyResolvedPatterns:
        """
        Build a new successful SLEIGH constructor resolution from a string representation
         
         
        
        This was used primarily in testing, to specify expected results.
        
        :param java.lang.String or str str: the string representation: "``ins:[pattern],ctx:[pattern]``"
        :param java.lang.String or str description: a description of the resolution
        :param java.util.List[AssemblyResolution] children: any children involved in the resolution
        :return: the decoded resolution
        :rtype: AssemblyResolvedPatterns
        
        .. seealso::
        
            | :obj:`ghidra.util.NumericUtilities.convertHexStringToMaskedValue(AtomicLong, AtomicLong,
            String, int, int, String)`NumericUtilities.convertHexStringToMaskedValue(AtomicLong,
            AtomicLong, String, int, int, String)
        """

    def instrOnly(self, ins: AssemblyPatternBlock, description: typing.Union[java.lang.String, str]) -> RP:
        """
        Build an instruction-only successful resolution result
        
        :param AssemblyPatternBlock ins: the instruction pattern block
        :param java.lang.String or str description: a description of the resolution
        :return: the new resolution
        :rtype: RP
        
        .. seealso::
        
            | :obj:`.resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List,
            AssemblyResolution)`
        """

    def newAssemblyResolutionResults(self) -> AssemblyResolutionResults:
        ...

    def newBackfillBuilder(self) -> AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedBackfillBuilder[BF]:
        ...

    def newErrorBuilder(self) -> AbstractAssemblyResolutionFactory.AssemblyResolvedErrorBuilder:
        ...

    def newPatternsBuilder(self) -> AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedPatternsBuilder[RP]:
        ...

    @typing.overload
    def nop(self, description: typing.Union[java.lang.String, str]) -> RP:
        """
        Obtain a new "blank" resolved SLEIGH constructor record
        
        :param java.lang.String or str description: a description of the resolution
        :return: the new resolution
        :rtype: RP
        """

    @typing.overload
    def nop(self, description: typing.Union[java.lang.String, str], children: java.util.List[AssemblyResolution], right: AssemblyResolution) -> RP:
        """
        Obtain a new "blank" resolved SLEIGH constructor record
        
        :param java.lang.String or str description: a description of the resolution
        :param java.util.List[AssemblyResolution] children: any children that will be involved in populating this record
        :return: the new resolution
        :rtype: RP
        """

    def resolved(self, ins: AssemblyPatternBlock, ctx: AssemblyPatternBlock, description: typing.Union[java.lang.String, str], cons: ghidra.app.plugin.processors.sleigh.Constructor, children: java.util.List[AssemblyResolution], right: AssemblyResolution) -> RP:
        """
        Build the result of successfully resolving a SLEIGH constructor
         
         
        
        **NOTE:** This is not used strictly for resolved SLEIGH constructors. It may also be used
        to store intermediates, e.g., encoded operands, during constructor resolution.
        
        :param AssemblyPatternBlock ins: the instruction pattern block
        :param AssemblyPatternBlock ctx: the context pattern block
        :param java.lang.String or str description: a description of the resolution
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the constructor, or null
        :param java.util.List[AssemblyResolution] children: the children of this constructor, or null
        :return: the new resolution
        :rtype: RP
        """


class AssemblyGeneratedPrototype(java.lang.Object):
    """
    A tree of generated assembly node states, paired with the resulting patterns
     
     
    
    This is used as the intermediate result when generating states, since the patterns must be
    propagated to each operand as generation proceeds. Usually, the patterns in the final output are
    discarded, and machine code generation proceeds using only the state tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: AbstractAssemblyState, patterns: AssemblyResolvedPatterns):
        ...


class AssemblyResolution(java.lang.Comparable[AssemblyResolution]):

    class_: typing.ClassVar[java.lang.Class]

    def collectAllRight(self, into: collections.abc.Sequence):
        ...

    def getChildren(self) -> java.util.List[AssemblyResolution]:
        ...

    def getDescription(self) -> str:
        ...

    def getRight(self) -> AssemblyResolution:
        ...

    def hasChildren(self) -> bool:
        """
        Check if this record has children
         
         
        
        If a subclass has another, possibly additional, notion of children that it would like to
        include in :meth:`toString() <.toString>`, it must override this method to return true when such
        children are present.
        
        :return: true if this record has children
        :rtype: bool
        """

    def isBackfill(self) -> bool:
        """
        Check if this record describes a backfill
        
        :return: true if the record is a backfill
        :rtype: bool
        """

    def isError(self) -> bool:
        """
        Check if this record describes an error
        
        :return: true if the record is an error
        :rtype: bool
        """

    def lineToString(self) -> str:
        """
        Display the resolution result in one line (omitting child details)
        
        :return: the display description
        :rtype: str
        """

    def parent(self, description: typing.Union[java.lang.String, str], opCount: typing.Union[jpype.JInt, int]) -> AssemblyResolution:
        """
        Get this same resolution, pushing its right siblings down to its children
        """

    def shift(self, amt: typing.Union[jpype.JInt, int]) -> AssemblyResolution:
        """
        Shift the resolution's instruction pattern to the right, if applicable
         
         
        
        This also shifts any backfill and forbidden pattern records.
        
        :param jpype.JInt or int amt: the number of bytes to shift.
        :return: the result
        :rtype: AssemblyResolution
        """

    def toString(self, indent: typing.Union[java.lang.String, str]) -> str:
        """
        Used only by parents: get a multi-line description of this record, indented
        
        :param java.lang.String or str indent: the current indentation
        :return: the indented description
        :rtype: str
        """

    @property
    def children(self) -> java.util.List[AssemblyResolution]:
        ...

    @property
    def backfill(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def right(self) -> AssemblyResolution:
        ...

    @property
    def error(self) -> jpype.JBoolean:
        ...


class DefaultAssemblyResolutionFactory(AbstractAssemblyResolutionFactory[AssemblyResolvedPatterns, AssemblyResolvedBackfill]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AssemblyResolvedBackfill(AssemblyResolution):

    class_: typing.ClassVar[java.lang.Class]

    def getInstructionLength(self) -> int:
        """
        Get the expected length of the instruction portion of the future encoding
         
        This is used to make sure that operands following a to-be-determined encoding are placed
        properly. Even though the actual encoding cannot yet be determined, its length can.
        
        :return: the total expected length (including the offset)
        :rtype: int
        """

    def solve(self, solver: ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver, vals: collections.abc.Mapping, cur: AssemblyResolvedPatterns) -> AssemblyResolution:
        """
        Attempt (again) to solve the expression that generated this backfill record
         
         
        
        This will attempt to solve the same expression and goal again, using the same parameters as
        were given to the original attempt, except with additional defined symbols. Typically, the
        symbol that required backfill is ``inst_next``. This method will not throw
        :obj:`NeedsBackfillException`, since that would imply the missing symbol(s) from the
        original attempt are still missing. Instead, the method returns an instance of
        :obj:`AssemblyResolvedError`.
        
        :param ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver solver: a solver, usually the same as the one from the original attempt.
        :param collections.abc.Mapping vals: the defined symbols, usually the same, but with the missing symbol(s).
        :return: the solution result
        :rtype: AssemblyResolution
        """

    @property
    def instructionLength(self) -> jpype.JInt:
        ...


class AssemblyNopStateGenerator(AbstractAssemblyStateGenerator[ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken]):
    """
    The generator of :obj:`AssemblyOperandState` for a hidden value operand
     
     
    
    In short, this does nothing, except to hold the place of the operand for diagnostics. Likely, the
    "hidden" operand appears in the defining expression of a temporary symbol used in the print
    pieces.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], opSym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol, fromLeft: AssemblyResolvedPatterns):
        """
        Construct the hidden value operand state generator
        
        :param AbstractAssemblyTreeResolver[typing.Any] resolver: the resolver
        :param ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol opSym: the operand symbol
        :param AssemblyResolvedPatterns fromLeft: the accumulated patterns from the left sibling or parent
        """


class AssemblyDefaultContext(ghidra.program.model.lang.DisassemblerContext, ghidra.program.model.listing.DefaultProgramContext):
    """
    A class that computes the default context for a language, and acts as a pseudo context
     
     
    
    This class helps maintain context consistency when performing both assembly and disassembly.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lang: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        """
        Compute the default context at most addresses for the given language
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage lang: the language
        """

    def getDefault(self) -> AssemblyPatternBlock:
        """
        Get the default value of the context register
        
        :return: the value as a pattern block for assembly
        :rtype: AssemblyPatternBlock
        """

    def getDefaultAt(self, addr: ghidra.program.model.address.Address) -> AssemblyPatternBlock:
        """
        Compute the default value of the context register at the given address
        
        :param ghidra.program.model.address.Address addr: the addres
        :return: the value as a pattern block for assembly
        :rtype: AssemblyPatternBlock
        """

    @typing.overload
    def setContextRegister(self, val: jpype.JArray[jpype.JByte]):
        """
        Set the value of the pseudo context register
         
         
        
        If the provided value has length less than the register, it will be left aligned, and the
        remaining bytes will be set to unknown (masked out).
        
        :param jpype.JArray[jpype.JByte] val: the value of the register
        """

    @typing.overload
    def setContextRegister(self, ctx: AssemblyPatternBlock):
        ...

    @property
    def default(self) -> AssemblyPatternBlock:
        ...

    @property
    def defaultAt(self) -> AssemblyPatternBlock:
        ...


class AbstractAssemblyTreeResolver(java.lang.Object, typing.Generic[RP]):
    """
    The workhorse of semantic resolution for the assembler
     
     
    
    This class takes a parse tree and some additional information (start address, context, etc.) and
    attempts to determine possible encodings using the semantics associated with each branch of the
    given parse tree. Details of this process are described in :obj:`SleighAssemblerBuilder`.
    
    
    .. seealso::
    
        | :obj:`SleighAssemblerBuilder`
    """

    class_: typing.ClassVar[java.lang.Class]
    INST_START: typing.Final = "inst_start"
    INST_NEXT: typing.Final = "inst_next"
    INST_NEXT2: typing.Final = "inst_next2"

    def __init__(self, factory: AbstractAssemblyResolutionFactory[RP, typing.Any], lang: ghidra.app.plugin.processors.sleigh.SleighLanguage, at: ghidra.program.model.address.Address, tree: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch, context: AssemblyPatternBlock, ctxGraph: AssemblyContextGraph):
        """
        Construct a resolver for the given parse tree
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage lang: 
        :param ghidra.program.model.address.Address at: the address where the instruction will start
        :param ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch tree: the parse tree
        :param AssemblyPatternBlock context: the context expected at ``instStart``
        :param AssemblyContextGraph ctxGraph: the context transition graph used to resolve purely-recursive productions
        """

    @staticmethod
    def computeOffset(opsym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol, cons: ghidra.app.plugin.processors.sleigh.Constructor) -> int:
        """
        Compute the offset of an operand encoded in the instruction block
         
         
        
        TODO: Currently, there are duplicate mechanisms for resolving a constructor: 1) The newer
        mechanism implemented in :obj:`AssemblyConstructState`, and 2) the older one implemented in
        :meth:`applyPatterns(AssemblyConstructorSemantic, int, AssemblyResolutionResults) <.applyPatterns>`. The
        latter seems to require this method, since it does not have pre-computed shifts as in the
        former. We should probably remove the latter in favor of the former....
        
        :param ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol opsym: the operand symbol
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the constructor containing the operand
        :return: the offset (right shift) to apply to the encoded operand
        :rtype: int
        """

    def getFactory(self) -> AbstractAssemblyResolutionFactory[RP, typing.Any]:
        ...

    def getGrammar(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar:
        ...

    def resolve(self) -> AssemblyResolutionResults:
        """
        Resolve the tree for the given parameters
        
        :return: a set of resolutions (encodings and errors)
        :rtype: AssemblyResolutionResults
        """

    def resolveRootRecursion(self, temp: AssemblyResolutionResults) -> AssemblyResolutionResults:
        """
        If necessary, resolve recursive constructors at the root, usually for prefixes
         
         
        
        If there are no pure recursive constructors at the root, then this simply returns
        ``temp`` unmodified.
        
        :param AssemblyResolutionResults temp: the resolved root results
        :return: the results with pure recursive constructors applied to obtain a compatible context
        :rtype: AssemblyResolutionResults
        """

    @property
    def factory(self) -> AbstractAssemblyResolutionFactory[RP, typing.Any]:
        ...

    @property
    def grammar(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar:
        ...


class AssemblyContextGraph(ghidra.graph.GImplicitDirectedGraph[AssemblyContextGraph.Vertex, AssemblyContextGraph.Edge]):
    """
    A graph of possible context changes via the application of various constructors
     
     
    
    This is used primarily to find optimal paths for the application of recursive rules, i.e., those
    of the form I => I. These cannot be resolved without some form of semantic analysis. The most
    notable disadvantage to all of this is that you no longer get all of the possible assemblies, but
    only those with the fewest rule applications.
     
     
    
    Conceivably, this may also be used to prune some possibilities during semantic resolution of a
    parse tree. Even better, it may be possible to derive a grammar which accounts for the context
    changes already; however, it's unclear how many rules this will generate, and consequently, how
    much larger its LALR(1) parser would become.
    """

    @typing.type_check_only
    class Vertex(java.lang.Comparable[AssemblyContextGraph.Vertex]):
        """
        A vertex in a context transition graph
         
         
        
        Each vertex consists of a context block and a (sub-)table name
        """

        class_: typing.ClassVar[java.lang.Class]

        def matches(self, that: AssemblyContextGraph.Vertex) -> bool:
            """
            Check if this and another vertex "agree"
             
             
            
            This does not mean they are equal, but that they share a sub-table, and the defined bits
            of their context blocks agree.
            
            :param AssemblyContextGraph.Vertex that: the other vertex
            :return: true iff they share sub-tables and defined bits
            :rtype: bool
            """


    @typing.type_check_only
    class Edge(ghidra.graph.GEdge[AssemblyContextGraph.Vertex], java.lang.Comparable[AssemblyContextGraph.Edge]):
        """
        A transition in a context transition graph
         
         
        
        A transition consists of the constructor whose context changes were applied. The operand
        index is included for reference and debugging. If we ever need to process rules with multiple
        sub-constructors, the operand index explains the sub-table name of the destination vertex.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, sem: AssemblyConstructorSemantic, op: typing.Union[jpype.JInt, int], start: AssemblyContextGraph.Vertex, end: AssemblyContextGraph.Vertex):
            """
            Construct a new transition associated with the given constructor and operand index
            
            :param AssemblyConstructorSemantic sem: the constructor semantic
            :param jpype.JInt or int op: the operand index
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: AbstractAssemblyResolutionFactory[typing.Any, typing.Any], lang: ghidra.app.plugin.processors.sleigh.SleighLanguage, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar):
        """
        Build the context change graph for a given language and grammar
         
         
        
        The grammar must have been constructed from the given language. The language is used just to
        obtain the most common default context.
         
         
        
        At the moment, this graph only expands the recursive rules at the root constructor table,
        i.e., "instruction". Thus, the assembler will not be able to process any language that has
        *purely*-recursive rules at sub-constructors.
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage lang: the language
        :param ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar grammar: the grammar derived from the given language
        """

    def computeOptimalApplications(self, src: AssemblyPatternBlock, srcTable: typing.Union[java.lang.String, str], dst: AssemblyPatternBlock, dstTable: typing.Union[java.lang.String, str]) -> java.util.Collection[java.util.Deque[AssemblyConstructorSemantic]]:
        """
        Compute the optimal, i.e., shortest, sequences of applications to resolve a given context to
        another, often the language's default context.
        
        :param AssemblyPatternBlock src: presumably, the language's default context
        :param java.lang.String or str srcTable: the name of the SLEIGH constructor table, presumably "instruction"
        :param AssemblyPatternBlock dst: the context block being resolved
        :param java.lang.String or str dstTable: the name of the SLEIGH constructor table being resolved
        :return: a collection of sequences of constructor applications from ``src`` to ``dst``
         
                NOTE: For assembly, the sequences will need to be applied right-to-left.
        :rtype: java.util.Collection[java.util.Deque[AssemblyConstructorSemantic]]
        """

    def copy(self) -> ghidra.graph.GDirectedGraph[AssemblyContextGraph.Vertex, AssemblyContextGraph.Edge]:
        """
        Returns a copy of the graph explored so far
        """

    def getInEdges(self, v: AssemblyContextGraph.Vertex) -> java.util.Collection[AssemblyContextGraph.Edge]:
        """
        This operation is not supported.
         
         
        
        I could implement this using the cached edges, but that may not be semantically, what a path
        computation algorithm actually requires. Instead, I will assume the algorithm only explores
        the graph in the same direction as its edges. If not, I will hear about it quickly.
        """

    @property
    def inEdges(self) -> java.util.Collection[AssemblyContextGraph.Edge]:
        ...


class AbstractAssemblyStateGenerator(java.lang.Object, typing.Generic[N]):
    """
    Base class for generating prototype nodes ("states") from a parse tree node
    """

    @typing.type_check_only
    class GeneratorContext(java.lang.Object):
        """
        Context to pass along as states are generated
        """

        class_: typing.ClassVar[java.lang.Class]
        path: typing.Final[java.util.List[AssemblyConstructorSemantic]]
        shift: typing.Final[jpype.JInt]

        def __init__(self, path: java.util.List[AssemblyConstructorSemantic], shift: typing.Union[jpype.JInt, int]):
            """
            Construct a context
            
            :param java.util.List[AssemblyConstructorSemantic] path: the path of constructors, for diagnostics
            :param jpype.JInt or int shift: the (right) shift in bytes of the operand whose state is being generated
            """

        def dbg(self, string: typing.Union[java.lang.String, str]):
            """
            Print a debug line
            
            :param java.lang.String or str string: the message
            """

        @staticmethod
        def pathToString(path: java.util.List[AssemblyConstructorSemantic]) -> str:
            """
            Render the path as a printable string
            
            :param java.util.List[AssemblyConstructorSemantic] path: the path
            :return: the string
            :rtype: str
            """

        def push(self, cons: AssemblyConstructorSemantic, shift: typing.Union[jpype.JInt, int]) -> AbstractAssemblyStateGenerator.GeneratorContext:
            """
            Construct a context suitable for descent into an operand
            
            :param AssemblyConstructorSemantic cons: the parent constructor
            :param jpype.JInt or int shift: the shift offset of the operand
            :return: the context
            :rtype: AbstractAssemblyStateGenerator.GeneratorContext
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], node: N, fromLeft: AssemblyResolvedPatterns):
        """
        Construct a generator
        
        :param AbstractAssemblyTreeResolver[typing.Any] resolver: the resolver
        :param N node: the node from which to generate states
        :param AssemblyResolvedPatterns fromLeft: the accumulated patterns from the left sibling or the parent
        """

    def generate(self, gc: AbstractAssemblyStateGenerator.GeneratorContext) -> java.util.stream.Stream[AssemblyGeneratedPrototype]:
        """
        Generate states
        
        :param AbstractAssemblyStateGenerator.GeneratorContext gc: the generator context for this node
        :return: the stream of prototypes, each including accumulated patterns
        :rtype: java.util.stream.Stream[AssemblyGeneratedPrototype]
        """


class AbstractAssemblyState(java.lang.Object):
    """
    Base for a node in an assembly prototype
    """

    class_: typing.ClassVar[java.lang.Class]

    def computeHash(self) -> int:
        """
        Pre compute this nodes hash
        
        :return: the hash
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Get the length in bytes of the operand represented by this node
        
        :return: the length
        :rtype: int
        """

    def getPath(self) -> java.util.List[AssemblyConstructorSemantic]:
        ...

    def getResolver(self) -> AbstractAssemblyTreeResolver[typing.Any]:
        ...

    def getShift(self) -> int:
        ...

    @property
    def resolver(self) -> AbstractAssemblyTreeResolver[typing.Any]:
        ...

    @property
    def path(self) -> java.util.List[AssemblyConstructorSemantic]:
        ...

    @property
    def shift(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class DefaultAssemblyResolvedBackfill(AbstractAssemblyResolution, AssemblyResolvedBackfill):
    """
    A :obj:`AssemblyResolution` indicating the need to solve an expression in the future
     
     
    
    Such records are collected within a :obj:`AssemblyResolvedPatterns` and then solved just before
    the final result(s) are assembled. This is typically required by instructions that refer to the
    ``inst_next`` symbol.
     
     
    
    **NOTE:** These are used internally. The user ought never to see these from the assembly API.
    """

    class_: typing.ClassVar[java.lang.Class]


class AssemblyResolvedError(AssemblyResolution):

    class_: typing.ClassVar[java.lang.Class]

    def getError(self) -> str:
        ...

    @property
    def error(self) -> java.lang.String:
        ...


class AssemblyPatternBlock(java.lang.Comparable[AssemblyPatternBlock]):
    """
    The analog of :obj:`PatternBlock`, designed for use by the assembler
     
     
    
    It is suitable for the assembler because it is represented byte-by-byte, and it offers a number
    of useful conversions and operations.
     
     
    
    TODO: A lot of this could probably be factored into the :obj:`PatternBlock` class, but it was
    best to experiment in another class altogether to avoid breaking things.
    """

    class_: typing.ClassVar[java.lang.Class]

    def assign(self, that: AssemblyPatternBlock) -> AssemblyPatternBlock:
        """
        Combine this pattern block with another given block
         
         
        
        The two blocks are combined regardless if their corresponding defined bits agree. When blocks
        are combined, their bytes are aligned according to their shifts, and the defined bits are
        taken from either block. If neither block defines a bit (i.e., the mask bit at that position
        is 0 for both input blocks), then the output has an undefined bit in the corresponding
        position. If both blocks define the bit, but they have opposite values, then the value from
        ``that`` takes precedence.
        
        :param AssemblyPatternBlock that: the other block
        :return: the new combined block
        :rtype: AssemblyPatternBlock
        
        .. seealso::
        
            | :obj:`RegisterValue.combineValues(RegisterValue)`
        """

    def combine(self, that: AssemblyPatternBlock) -> AssemblyPatternBlock:
        """
        Combine this pattern block with another given block
         
         
        
        Two blocks can be combined in their corresponding defined bits agree. When blocks are
        combined, their bytes are aligned according to their shifts, and the defined bits are taken
        from either block. If neither block defines a bit (i.e., the mask bit at that position is 0
        for both input blocks, then the output has an undefined bit in the corresponding position. If
        both blocks define the bit, but they have opposite values, then the result is an error.
        
        :param AssemblyPatternBlock that: the other block
        :return: the new combined block, or null if the blocks disagree for any bit
        :rtype: AssemblyPatternBlock
        """

    def copy(self) -> AssemblyPatternBlock:
        """
        Duplicate this pattern block
        
        :return: the duplicate
        :rtype: AssemblyPatternBlock
        """

    def countPossibleVals(self) -> int:
        ...

    def fillMask(self) -> AssemblyPatternBlock:
        """
        Fill all unknown bits with 0 bits
        
        :return: the result
        :rtype: AssemblyPatternBlock
        """

    @staticmethod
    def fromBytes(offset: typing.Union[jpype.JInt, int], vals: jpype.JArray[jpype.JByte]) -> AssemblyPatternBlock:
        """
        Get a pattern block with the given (fully-included) values at the given offset
        
        :param jpype.JInt or int offset: the offset (0-up, left-to-right)
        :param jpype.JArray[jpype.JByte] vals: the values
        :return: a pattern block (having a full mask)
        :rtype: AssemblyPatternBlock
        """

    @staticmethod
    def fromContextField(cf: ghidra.app.plugin.processors.sleigh.expression.ContextField, val: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong) -> AssemblyPatternBlock:
        """
        Encode the given masked long into a pattern block as specified by a given context field
        
        :param ghidra.app.plugin.processors.sleigh.expression.ContextField cf: the context field specifying the location of the value to encode
        :param ghidra.app.plugin.assembler.sleigh.expr.MaskedLong val: the value to encode
        :return: the pattern block with the encoded value
        :rtype: AssemblyPatternBlock
        """

    @staticmethod
    def fromLength(length: typing.Union[jpype.JInt, int]) -> AssemblyPatternBlock:
        """
        Allocate a fully-undefined pattern block of the given length
        
        :param jpype.JInt or int length: the length in bytes
        :return: the block of all unknown bits
        :rtype: AssemblyPatternBlock
        """

    @staticmethod
    def fromPattern(pat: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern, minLen: typing.Union[jpype.JInt, int], context: typing.Union[jpype.JBoolean, bool]) -> AssemblyPatternBlock:
        """
        Convert a block from a disjoint pattern into an assembly pattern block
        
        :param ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern pat: the pattern to convert
        :param jpype.JInt or int minLen: the minimum byte length of the block
        :param jpype.JBoolean or bool context: true to select the context block, false to select the instruction block
        :return: the converted pattern block
        :rtype: AssemblyPatternBlock
        """

    @staticmethod
    def fromRegisterValue(rv: ghidra.program.model.lang.RegisterValue) -> AssemblyPatternBlock:
        """
        Convert a register value into a pattern block
         
         
        
        This is used primarily to compute default context register values, and pass them into an
        assembler.
        
        :param ghidra.program.model.lang.RegisterValue rv: the register value
        :return: the pattern block
        :rtype: AssemblyPatternBlock
        """

    @staticmethod
    def fromString(str: typing.Union[java.lang.String, str]) -> AssemblyPatternBlock:
        """
        Convert a string representation to a pattern block
        
        :param java.lang.String or str str: the string to convert
        :return: the resulting pattern block
        :rtype: AssemblyPatternBlock
        
        .. seealso::
        
            | :obj:`NumericUtilities.convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int,
            String)`
        """

    @staticmethod
    def fromTokenField(tf: ghidra.app.plugin.processors.sleigh.expression.TokenField, val: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong) -> AssemblyPatternBlock:
        """
        Encode the given masked long into a pattern block as specified by a given token field
        
        :param ghidra.app.plugin.processors.sleigh.expression.TokenField tf: the token field specifying the location of the value to encode
        :param ghidra.app.plugin.assembler.sleigh.expr.MaskedLong val: the value to encode
        :return: the pattern block with the encoded value
        :rtype: AssemblyPatternBlock
        """

    def getMask(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the mask array
         
         
        
        Modifications to the returned array will affect the pattern block. It is *not* a copy.
        Furthermore, the offset is not incorporated. See :meth:`getOffset() <.getOffset>`. For a copy of the
        array with offset applied, use :meth:`getMaskAll() <.getMaskAll>`.
        
        :return: the array
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getMaskAll(self) -> jpype.JArray[jpype.JByte]:
        """
        Get an array representing the full mask of the pattern
         
         
        
        This is a copy of the :meth:`getMask() <.getMask>` array, but with 0s prepended to apply the offset.
        See :meth:`getOffset() <.getOffset>`.
        
        :return: the array
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getMaskedValue(self, unmasked: jpype.JArray[jpype.JByte]) -> AssemblyPatternBlock:
        """
        Mask the given ``unmasked`` value with the mask contained in this pattern block.
         
         
        
        The returned :obj:`AssemblyPatternBlock` has an identical mask as ``this`` but with a 
        value taken from the given ``unmasked``.
        
        :param jpype.JArray[jpype.JByte] unmasked: the value to be masked into the result
        :return: a combination of the given unmasked value and this mask
        :rtype: AssemblyPatternBlock
        """

    def getOffset(self) -> int:
        """
        Get the number of undefined bytes preceding the mask and values arrays
        
        :return: the offset
        :rtype: int
        """

    def getSpecificity(self) -> int:
        """
        Counts the total number of known bits in the pattern
         
         
        
        At a slightly lower level, counts the number of 1-bits in the mask.
        
        :return: the count
        :rtype: int
        """

    def getVals(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the values array
         
         
        
        Modifications to the returned array will affect the pattern block. It is *not* a copy.
        Furthermore, the offset is not incorporated. See :meth:`getOffset() <.getOffset>`. For a copy of the
        array with offset applied, use :meth:`getValsAll() <.getValsAll>`.
        
        :return: the array
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getValsAll(self) -> jpype.JArray[jpype.JByte]:
        """
        Get an array representing the full value of the pattern
         
         
        
        This is a copy of the :meth:`getVals() <.getVals>` array, but with 0s prepended to apply the offset.
        See :meth:`getOffset() <.getOffset>`.
        
        :return: the array
        :rtype: jpype.JArray[jpype.JByte]
        """

    def invertMask(self) -> AssemblyPatternBlock:
        """
        Invert the mask bits of this pattern block
        
        :return: a copy of this pattern block with mask bits inverted
        :rtype: AssemblyPatternBlock
        """

    def isFullMask(self) -> bool:
        """
        Check if there are any unknown bits
        
        :return: true if no unknown bits are present, false otherwise
        :rtype: bool
        """

    def isZero(self) -> bool:
        """
        Check if all bits are 0 bits
        
        :return: true if all are 0, false otherwise
        :rtype: bool
        """

    def length(self) -> int:
        """
        Get the length (plus the offset) of this pattern block
        
        :return: the total length
        :rtype: int
        """

    @typing.overload
    def maskOut(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp) -> AssemblyPatternBlock:
        """
        Set all bits read by a given context operation to unknown
         
         
        
        This is used during resolution to remove a context requirement passed upward by a child. When
        a parent constructor writes the required value to the context register, that requirement need
        not be passed further upward, since the write satisfies the requirement.
        
        :param ghidra.app.plugin.processors.sleigh.ContextOp cop: the context operation
        :return: the result
        :rtype: AssemblyPatternBlock
        """

    @typing.overload
    def maskOut(self, other: AssemblyPatternBlock) -> AssemblyPatternBlock:
        """
        Set all bits that are known (1 in mask) in ``other`` to unknown.
         
         
        
        Other must have the same or shorter length than this.
        
        :param AssemblyPatternBlock other: the other pattern block whose mask bits are examined
        :return: a copy of this pattern with mask bits set to unknown
        :rtype: AssemblyPatternBlock
        """

    @staticmethod
    def nop() -> AssemblyPatternBlock:
        """
        Get an empty pattern block
        
        :return: the pattern block
        :rtype: AssemblyPatternBlock
        """

    def possibleVals(self) -> java.lang.Iterable[jpype.JArray[jpype.JByte]]:
        """
        Get an iterable over all the possible fillings of the value, given a partial mask
         
         
        
        This is meant to be used idiomatically, as in an enhanced for loop:
         
         
        for (byte[] val : pattern.possibleVals()) {
            System.out.println(format(val));
        }
         
         
         
        
        **NOTE:** A single byte array is instantiated with the call to
        :meth:`Iterable.iterator() <Iterable.iterator>`. Each call to :meth:`Iterator.next() <Iterator.next>` modifies the one byte array
        and returns it. As such, if you intend to preserve the value in the array for later use, you
        *must* make a copy.
        
        :return: the iterable.
        :rtype: java.lang.Iterable[jpype.JArray[jpype.JByte]]
        """

    def readBytes(self, start: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Decode ``len`` bytes (values and mask) in big-endian format, beginning at ``start``
        
        :param jpype.JInt or int start: the first byte to decode
        :param jpype.JInt or int len: the number of bytes to decode
        :return: the decoded masked long
        :rtype: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong
        """

    def readContextOp(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Read the input of a context operation from this pattern block
        
        :param ghidra.app.plugin.processors.sleigh.ContextOp cop: the context operation
        :return: the decoded input, as a masked value
        :rtype: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong
        """

    def readMaskBytes(self, start: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Decode ``len`` mask bytes in big-endian format, beginning at ``start``
        
        :param jpype.JInt or int start: the first byte to decode
        :param jpype.JInt or int len: the number of bytes to decode
        :return: the decoded long
        :rtype: int
        """

    def readValBytes(self, start: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Decode ``len`` value bytes in big-endian format, beginning at ``start``
        
        :param jpype.JInt or int start: the first byte to decode
        :param jpype.JInt or int len: the number of bytes to decode
        :return: the decoded long
        :rtype: int
        """

    def shift(self, amt: typing.Union[jpype.JInt, int]) -> AssemblyPatternBlock:
        """
        Shift, i.e., increase the offset of, this pattern block
        
        :param jpype.JInt or int amt: the amount to shift right
        :return: the shifted pattern block
        :rtype: AssemblyPatternBlock
        """

    def toBigInteger(self, n: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        """
        Decode the values array into a :obj:`BigInteger` of length ``n`` bytes
         
         
        
        The array is either truncated or zero-extended *on the right* to match the requested
        number of bytes, then decoded in big-endian format as an unsigned value.
        
        :param jpype.JInt or int n: the number of bytes (left-to-right) to decode
        :return: the decoded big integer
        :rtype: java.math.BigInteger
        """

    def trim(self) -> AssemblyPatternBlock:
        """
        Remove all unknown bits from both left and right
        
        :return: new value without any left or right unknown bits (but may have unknown bits in the
                middle)
        :rtype: AssemblyPatternBlock
        """

    def truncate(self, amt: typing.Union[jpype.JInt, int]) -> AssemblyPatternBlock:
        """
        Truncate (unshift) this pattern block by removing bytes from the left
        
        :param jpype.JInt or int amt: the amount to truncate or shift left
        :return: the truncated pattern block
        :rtype: AssemblyPatternBlock
        """

    def writeContextCommitMask(self, cc: ghidra.app.plugin.processors.sleigh.ContextCommit) -> AssemblyPatternBlock:
        """
        Write mask bits from context commit to mask array of block
        
        
        .. admonition:: Implementation Note
        
            This is used when scraping for valid input contexts to determine which context variables
            are passed to the ``globalset`` directive.
        
        
        :param ghidra.app.plugin.processors.sleigh.ContextCommit cc: the context commit
        :return: the result
        :rtype: AssemblyPatternBlock
        """

    def writeContextOp(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp, val: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong) -> AssemblyPatternBlock:
        """
        Encode the given value into a copy of this pattern block as specified by a context operation
         
         
        
        **NOTE:** this method is given as a special operation, instead of a conversion factory
        method, because this is a write operation, not a combine operation. As such, the bits
        (including undefined bits) replace the bits in the existing pattern block. Were this a
        conversion method, we would lose the distinction between unknown bits being written, and bits
        whose values are simply not included in the write.
        
        :param ghidra.app.plugin.processors.sleigh.ContextOp cop: the context operation specifying the location of the value to encode
        :param ghidra.app.plugin.assembler.sleigh.expr.MaskedLong val: the value to encode
        :return: the new copy with the encoded value
        :rtype: AssemblyPatternBlock
        """

    @property
    def zero(self) -> jpype.JBoolean:
        ...

    @property
    def valsAll(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def vals(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def maskedValue(self) -> AssemblyPatternBlock:
        ...

    @property
    def maskAll(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def specificity(self) -> jpype.JInt:
        ...

    @property
    def fullMask(self) -> jpype.JBoolean:
        ...

    @property
    def mask(self) -> jpype.JArray[jpype.JByte]:
        ...


class AssemblyConstructStateGenerator(AbstractAssemblyStateGenerator[ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch]):
    """
    The generator of :obj:`AssemblyConstructState` from :obj:`AssemblyParseBranch`
     
     
    
    In short, this handles the selection of each possible constructor for the production recorded by
    a given parse branch.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], node: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch, fromLeft: AssemblyResolvedPatterns):
        """
        Construct the instruction state generator or a sub-table operand state generator
        
        :param AbstractAssemblyTreeResolver[typing.Any] resolver: the resolver
        :param ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch node: the node from which to generate states
        :param AssemblyResolvedPatterns fromLeft: the accumulated patterns from the left sibling or the parent
        """


class AssemblyConstructorSemantic(java.lang.Comparable[AssemblyConstructorSemantic]):
    """
    Describes a SLEIGH constructor semantic
     
     
    
    These are collected and associated with productions in the grammar based on the given
    constructor's print pieces.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: AbstractAssemblyResolutionFactory[typing.Any, typing.Any], cons: ghidra.app.plugin.processors.sleigh.Constructor, indices: java.util.List[java.lang.Integer]):
        """
        Build a new SLEIGH constructor semantic
        
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the SLEIGH constructor
        :param java.util.List[java.lang.Integer] indices: the indices of RHS non-terminals in the associated production that represent
                    an operand in the SLEIGH constructor
        """

    @typing.overload
    def addPattern(self, pat: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern):
        """
        Record a pattern that would select the constructor
        
        :param ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern pat: the pattern
        """

    @typing.overload
    def addPattern(self, pat: AssemblyResolvedPatterns):
        """
        Record a pattern that would select the constructor
        
        :param AssemblyResolvedPatterns pat: the pattern
        """

    def applyContextChangesForward(self, vals: collections.abc.Mapping, fromLeft: AssemblyResolvedPatterns) -> AssemblyResolvedPatterns:
        """
        Apply just context transformations in the forward (disassembly) direction
         
         
        
        Unlike the usual disassembly process, this method does not take into account any information
        from the instruction encoding. Any context bits that depend on it are set to unknown
        (``x``) in the output. This method is used to pre-compute a context transition graph in
        order to quickly resolve purely-recursive semantics on the root constructor table.
        
        :param AssemblyResolvedPatterns fromLeft: the state before context changes
        :return: the state after context changes
        :rtype: AssemblyResolvedPatterns
        """

    def applyPatternsForward(self, shift: typing.Union[jpype.JInt, int], fromLeft: AssemblyResolvedPatterns) -> java.util.stream.Stream[AssemblyResolvedPatterns]:
        """
        Apply just the instruction patterns in the forward (disassembly) direction
        
        :param jpype.JInt or int shift: the (right) shift in bytes to apply to the patterns before combining
        :param AssemblyResolvedPatterns fromLeft: the accumulated patterns from the left sibling or parent
        :return: 
        :rtype: java.util.stream.Stream[AssemblyResolvedPatterns]
        """

    def getConstructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor:
        """
        Get the SLEIGH constructor
        
        :return: the constructor
        :rtype: ghidra.app.plugin.processors.sleigh.Constructor
        """

    @staticmethod
    @typing.overload
    def getLocation(cons: ghidra.app.plugin.processors.sleigh.Constructor) -> str:
        """
        Render the constructor's source location for diagnostics
        
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the constructor
        :return: the location as ``file:lineno``
        :rtype: str
        """

    @typing.overload
    def getLocation(self) -> str:
        """
        Render this constructor's source location for diagnostics
        
        :return: the location
        :rtype: str
        """

    def getOperandIndex(self, printpos: typing.Union[jpype.JInt, int]) -> int:
        """
        Convert the index of a print piece to its associated operand index
        
        :param jpype.JInt or int printpos: position excluding whitespace and string tokens.
        :return: the operand index
        :rtype: int
        """

    def getOperandIndexIterator(self) -> java.util.Iterator[java.lang.Integer]:
        """
        Get an iterator over the operand indices
         
         
        
        If this iterator is advanced for each non-terminal, while simultaneously iterating over the
        RHS of the associated production, then this will identify the corresponding operand index for
        each non-terminal
        
        :return: the iterator
        :rtype: java.util.Iterator[java.lang.Integer]
        """

    def getOperandIndices(self) -> java.util.List[java.lang.Integer]:
        """
        Get the list of operand indices in print piece order
        
        :return: the list
        :rtype: java.util.List[java.lang.Integer]
        """

    def getPatterns(self) -> java.util.Collection[AssemblyResolvedPatterns]:
        """
        Get the associated encoding patterns for the constructor
        
        :return: the patterns
        :rtype: java.util.Collection[AssemblyResolvedPatterns]
        """

    def solveContextChanges(self, res: AssemblyResolvedPatterns, vals: collections.abc.Mapping) -> AssemblyResolution:
        """
        Solve this constructor's context changes
         
         
        
        Each value in ``opvals`` must either be a numeric value, e.g., an index from a varnode
        list, or another :obj:`AssemblyResolvedPatterns` for a subconstructor operand.
         
         
        
        It's helpful to think of the SLEIGH disassembly process here. Normally, once the appropriate
        constructor has been identified (by matching patterns), its context changes are applied, and
        then its operands parsed (possibly parsing subconstructor operands). Thus, ``res`` can be
        thought of as the intermediate result between applying context changes and parsing operands,
        except in reverse. The output of this method corresponds to the state before context changes
        were applied, i.e., immediately after selecting the constructor. Thus, in reverse, the
        context is solved immediately before applying the selected constructor patterns.
        
        :param AssemblyResolvedPatterns res: the combined resolution requirements derived from the subconstructors
        :param collections.abc.Mapping vals: any defined symbols (usually ``inst_start``, and ``inst_next``)
        :return: the resolution with context changes applied in reverse, or an error
        :rtype: AssemblyResolution
        """

    @property
    def operandIndexIterator(self) -> java.util.Iterator[java.lang.Integer]:
        ...

    @property
    def operandIndices(self) -> java.util.List[java.lang.Integer]:
        ...

    @property
    def patterns(self) -> java.util.Collection[AssemblyResolvedPatterns]:
        ...

    @property
    def constructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor:
        ...

    @property
    def location(self) -> java.lang.String:
        ...

    @property
    def operandIndex(self) -> jpype.JInt:
        ...


class AssemblyResolutionResults(org.apache.commons.collections4.set.AbstractSetDecorator[AssemblyResolution]):
    """
    A set of possible assembly resolutions for a single SLEIGH constructor
     
     
    
    Since the assembler works from the leaves up, it's unclear in what context a given token appears.
    Thus, every possible encoding is collected and passed upward. As resolution continues, many of
    the possible encodings are pruned out. When the resolver reaches the root, we end up with every
    possible encoding (less some prefixes) of an instruction. This object stores the possible
    encodings, including error records describing the pruned intermediate results.
    """

    class Applicator(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def combine(self, cur: AssemblyResolvedPatterns, pat: AssemblyResolution) -> AssemblyResolvedPatterns:
            ...

        def combineBackfill(self, cur: AssemblyResolvedPatterns, bf: AssemblyResolvedBackfill) -> AssemblyResolvedPatterns:
            ...

        def combineConstructor(self, cur: AssemblyResolvedPatterns, pat: AssemblyResolvedPatterns) -> AssemblyResolvedPatterns:
            ...

        def describeError(self, rc: AssemblyResolvedPatterns, pat: AssemblyResolution) -> str:
            ...

        def finish(self, resolved: AssemblyResolvedPatterns) -> AssemblyResolution:
            ...

        def getPatterns(self, cur: AssemblyResolvedPatterns) -> java.lang.Iterable[AssemblyResolution]:
            ...

        def setDescription(self, res: AssemblyResolvedPatterns, from_: AssemblyResolution) -> AssemblyResolvedPatterns:
            ...

        def setRight(self, res: AssemblyResolvedPatterns, cur: AssemblyResolvedPatterns) -> AssemblyResolvedPatterns:
            ...

        @property
        def patterns(self) -> java.lang.Iterable[AssemblyResolution]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Construct a new (mutable) empty set of resolutions
        """

    def absorb(self, that: AssemblyResolutionResults):
        """
        A synonym for :meth:`addAll(Collection) <.addAll>` that accepts only another resolution set
        
        :param AssemblyResolutionResults that: the other set
        """

    def getResolutions(self) -> java.util.Set[AssemblyResolution]:
        """
        Get an unmodifiable reference to this set
        
        :return: the set
        :rtype: java.util.Set[AssemblyResolution]
        """

    def remove(self, ar: AssemblyResolution) -> bool:
        ...

    @property
    def resolutions(self) -> java.util.Set[AssemblyResolution]:
        ...


class AssemblyHiddenConstructStateGenerator(AssemblyConstructStateGenerator):
    """
    The generator of :obj:`AssemblyConstructState` for a hidden sub-table operand
     
     
    
    In short, this exhausts all possible constructors in the given sub-table. For well-designed
    languages, such exhaustion produces a very small set of possibilities. In general, hidden
    sub-table operands are a bad idea.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], subtableSym: ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol, fromLeft: AssemblyResolvedPatterns):
        """
        Construct the hidden sub-table operand state generator
        
        :param AbstractAssemblyTreeResolver[typing.Any] resolver: the resolver
        :param ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol subtableSym: 
        :param AssemblyResolvedPatterns fromLeft: the accumulated patterns from the left sibling or the parent
        """


class AssemblyOperandState(AbstractAssemblyState):
    """
    The state corresponding to a non-sub-table operand
     
     
    
    This is roughly analogous to :obj:`ConstructState`, but for assembly. However, it also records
    the value of the operand and the actual operand symbol whose value it specifies.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resolver: AbstractAssemblyTreeResolver[typing.Any], path: java.util.List[AssemblyConstructorSemantic], shift: typing.Union[jpype.JInt, int], terminal: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal, value: typing.Union[jpype.JLong, int], opSym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol):
        """
        Construct the state for a given operand and selected value
        
        :param AbstractAssemblyTreeResolver[typing.Any] resolver: the resolver
        :param java.util.List[AssemblyConstructorSemantic] path: the path for diagnostics
        :param jpype.JInt or int shift: the (right) shift of this operand
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal terminal: the terminal that generated this state
        :param jpype.JLong or int value: the value of the operand
        :param ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol opSym: the operand symbol
        """

    def getOperandSymbol(self) -> ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol:
        ...

    def getTerminal(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal:
        ...

    def getValue(self) -> int:
        ...

    @property
    def operandSymbol(self) -> ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol:
        ...

    @property
    def terminal(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...



__all__ = ["AssemblyConstructState", "AbstractAssemblyResolution", "AssemblyResolvedPatterns", "AssemblyTreeResolver", "AssemblyOperandStateGenerator", "DefaultAssemblyResolvedError", "DefaultAssemblyResolvedPatterns", "AssemblyNopState", "AssemblyStringStateGenerator", "AbstractAssemblyResolutionFactory", "AssemblyGeneratedPrototype", "AssemblyResolution", "DefaultAssemblyResolutionFactory", "AssemblyResolvedBackfill", "AssemblyNopStateGenerator", "AssemblyDefaultContext", "AbstractAssemblyTreeResolver", "AssemblyContextGraph", "AbstractAssemblyStateGenerator", "AbstractAssemblyState", "DefaultAssemblyResolvedBackfill", "AssemblyResolvedError", "AssemblyPatternBlock", "AssemblyConstructStateGenerator", "AssemblyConstructorSemantic", "AssemblyResolutionResults", "AssemblyHiddenConstructStateGenerator", "AssemblyOperandState"]
