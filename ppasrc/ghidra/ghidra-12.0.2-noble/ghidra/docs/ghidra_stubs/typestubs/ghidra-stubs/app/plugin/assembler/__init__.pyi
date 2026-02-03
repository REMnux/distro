from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.parse
import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang # type: ignore
import java.util # type: ignore


A = typing.TypeVar("A")
RP = typing.TypeVar("RP")


class GenericAssemblerBuilder(java.lang.Object, typing.Generic[RP, A]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getAssembler(self, selector: AssemblySelector) -> A:
        """
        Build an assembler with the given selector callback
        
        :param AssemblySelector selector: the selector callback
        :return: the built assembler
        :rtype: A
        """

    @typing.overload
    def getAssembler(self, selector: AssemblySelector, program: ghidra.program.model.listing.Program) -> A:
        """
        Build an assembler with the given selector callback and program binding
        
        :param AssemblySelector selector: the selector callback
        :param ghidra.program.model.listing.Program program: the bound program
        :return: the built assembler
        :rtype: A
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language for which this instance builds an assembler
        
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """

    def getLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        """
        Get the ID of the language for which this instance builds an assembler
        
        :return: the language ID
        :rtype: ghidra.program.model.lang.LanguageID
        """

    @property
    def languageID(self) -> ghidra.program.model.lang.LanguageID:
        ...

    @property
    def assembler(self) -> A:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...


class AssemblyException(java.lang.Exception):
    """
    A checked exception used for input errors regarding the assembler
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class Assemblers(java.lang.Object):
    """
    The primary class for obtaining an :obj:`Assembler` for a Ghidra-supported language.
     
     
    
    The general flow is: First, obtain an assembler for a language or program. Second, call its
    :meth:`Assembler.assemble(Address, String...) <Assembler.assemble>` and related methods to perform assembly. More
    advanced uses pass a :obj:`AssemblySelector` to control certain aspects of assembly instruction
    selection, and to obtain advanced diagnostics, like detailed errors and code completion.
     
     
    Assembler asm = Assemblers.getAssembler(currentProgram);
    asm.assemble(currentAddress, "ADD ...");
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def getAssembler(program: ghidra.program.model.listing.Program, selector: AssemblySelector) -> Assembler:
        """
        Get an assembler for the given program.
         
         
        
        Provides an assembler suitable for the program's language, and bound to the program. Calls to
        its Assembler#assemble() function will cause modifications to the bound program. If this is
        the first time an assembler for the program's language has been requested, this function may
        take some time to build the assembler.
        
        :param AssemblySelector selector: a method to select a single result from many
        :param ghidra.program.model.listing.Program program: the program for which an assembler is requested
        :return: the assembler bound to the given program
        :rtype: Assembler
        """

    @staticmethod
    @typing.overload
    def getAssembler(lang: ghidra.program.model.lang.Language, selector: AssemblySelector) -> Assembler:
        """
        Get an assembler for the given language.
         
         
        
        Provides a suitable assembler for the given language. Only calls to its
        Assembler#assembleLine() method are valid. If this is the first time a language has been
        requested, this function may take some time to build the assembler. Otherwise, it returns a
        cached assembler.
        
        :param AssemblySelector selector: a method to select a single result from many
        :param ghidra.program.model.lang.Language lang: the language for which an assembler is requested
        :return: the assembler for the given language
        :rtype: Assembler
        """

    @staticmethod
    @typing.overload
    def getAssembler(program: ghidra.program.model.listing.Program) -> Assembler:
        """
        Get an assembler for the given program.
        
        :param ghidra.program.model.listing.Program program: the program
        :return: a suitable assembler
        :rtype: Assembler
        
        .. seealso::
        
            | :obj:`.getAssembler(Program, AssemblySelector)`
        """

    @staticmethod
    @typing.overload
    def getAssembler(lang: ghidra.program.model.lang.Language) -> Assembler:
        """
        Get an assembler for the given language.
        
        :param ghidra.program.model.lang.Language lang: the language
        :return: a suitable assembler
        :rtype: Assembler
        
        .. seealso::
        
            | :obj:`.getAssembler(Language, AssemblySelector)`
        """


class AssemblyError(java.lang.RuntimeException):
    """
    An exception for programmer errors regarding an assembler
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class AssemblySelectionError(AssemblyError):
    """
    Thrown when a programmer selects an improper instruction during assembly
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class AssemblerBuilder(GenericAssemblerBuilder[ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, Assembler]):
    """
    An interface to build an assembler for a given language
    """

    class_: typing.ClassVar[java.lang.Class]


class AssemblySyntaxException(AssemblyException):
    """
    Thrown when all parses of an assembly instruction result in syntax errors.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, errors: java.util.Set[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult]):
        """
        Construct a syntax exception with the associated syntax errors
        
        :param java.util.Set[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult] errors: the associated syntax errors
        """

    def getErrors(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult]:
        """
        Get the collection of associated syntax errors
        
        :return: the collection
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult]
        """

    @property
    def errors(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult]:
        ...


class AssemblyBuffer(java.lang.Object):
    """
    A convenience for accumulating bytes output by an :obj:`Assembler`
     
     
    
    This is most useful when there is not a :obj:`Program` available for assembly. If a program is
    available, consider using :meth:`Assembler.assemble(Address, String...) <Assembler.assemble>` and reading the bytes
    from the program. If not, or the program should not be modified, then the pattern of use is
    generally:
     
     
    Address start = space.getAdddress(0x00400000);
    Assembler asm = Assemblers.getAssembler(...);
    AssemblyBuffer buffer = new AssemblyBuffer(asm, start);
     
    buffer.assemble("PUSH R15");
    buffer.assemble("PUSH R14");
    buffer.assemble("PUSH R13");
    ...
    byte[] bytes = buffer.getBytes();
    state.setVar(start, bytes.length, true, bytes);
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, asm: Assembler, entry: ghidra.program.model.address.Address):
        """
        Create a buffer with the given assembler starting at the given entry
        
        :param Assembler asm: the assembler
        :param ghidra.program.model.address.Address entry: the starting address where the resulting code will be located
        """

    @typing.overload
    def assemble(self, line: typing.Union[java.lang.String, str], ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> jpype.JArray[jpype.JByte]:
        """
        Assemble a line and append it to the buffer
        
        :param java.lang.String or str line: the line
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock ctx: the assembly context
        :return: the resulting bytes for the assembled instruction
        :rtype: jpype.JArray[jpype.JByte]
        :raises AssemblySyntaxException: if the instruction cannot be parsed
        :raises AssemblySemanticException: if the instruction cannot be encoded
        :raises IOException: if the buffer cannot be written
        """

    @typing.overload
    def assemble(self, line: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
        """
        Assemble a line and append it to the buffer
        
        :param java.lang.String or str line: the line
        :return: the resulting bytes for the assembled instruction
        :rtype: jpype.JArray[jpype.JByte]
        :raises AssemblySyntaxException: if the instruction cannot be parsed
        :raises AssemblySemanticException: if the instruction cannot be encoded
        :raises IOException: if the buffer cannot be written
        """

    @typing.overload
    def assemble(self, at: ghidra.program.model.address.Address, line: typing.Union[java.lang.String, str], ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> jpype.JArray[jpype.JByte]:
        """
        Assemble a line and patch into the buffer
         
         
        
        This will not grow the buffer, so the instruction being patched must already exist in the
        buffer. The typical use case is to fix up a reference:
         
         
        AssemblyBuffer buf = new AssemblyBuffer(asm, entry);
        // ...
        Address jumpCheck = buf.getNext();
        buf.assemble("JMP 0x" + buf.getNext()); // Template must accommodate expected jump distance
        // ...
        Address labelCheck = buf.getNext();
        buf.assemble(jumpCheck, "JMP 0x" + labelCheck);
        buf.assemble("CMP ECX, 0");
        // ...
         
         
         
        
        This does not check that the patched instruction matches length with the new instruction. In
        fact, the buffer does not remember instruction boundaries at all. If verification is needed,
        the caller should check the lengths of the returned byte arrays for the template and the
        patch.
        
        :param ghidra.program.model.address.Address at: the address of the instruction to patch
        :param java.lang.String or str line: the line
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock ctx: the assembly context
        :return: the resulting bytes for the assembled instruction
        :rtype: jpype.JArray[jpype.JByte]
        :raises AssemblySyntaxException: if the instruction cannot be parsed
        :raises AssemblySemanticException: if the instruction cannot be encoded
        :raises IOException: if the buffer cannot be written
        """

    @typing.overload
    def assemble(self, at: ghidra.program.model.address.Address, line: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
        """
        Assemble a line and patch into the buffer
        
        :param ghidra.program.model.address.Address at: the address of the instruction to patch
        :param java.lang.String or str line: the line
        :return: the resulting bytes for the assembled instruction
        :rtype: jpype.JArray[jpype.JByte]
        :raises AssemblySyntaxException: if the instruction cannot be parsed
        :raises AssemblySemanticException: if the instruction cannot be encoded
        :raises IOException: if the buffer cannot be written
        
        .. seealso::
        
            | :obj:`.assemble(Address, String, AssemblyPatternBlock)`
        """

    def emit(self, bytes: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        Append arbitrary bytes to the buffer
        
        :param jpype.JArray[jpype.JByte] bytes: the bytes to append
        :return: bytes
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if the buffer cannot be written
        """

    def getAssembler(self) -> Assembler:
        """
        Get the assembler for this buffer
        
        :return: the assembler
        :rtype: Assembler
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the complete buffer of bytes
         
         
        
        However used, the bytes should be placed at the ``entry`` given at construction, unless
        the client is certain the code is position independent.
        
        :return: the bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getEntry(self) -> ghidra.program.model.address.Address:
        """
        Get the starting address
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getNext(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the "cursor" where the next instruction will be assembled
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def next(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def entry(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def assembler(self) -> Assembler:
        ...


class AssemblySelector(java.lang.Object):
    """
    Provides a mechanism for pruning and selecting binary assembled instructions from the results of
    parsing textual assembly instructions. There are two opportunities: After parsing, but before
    prototype generation, and after machine code generation. In the first opportunity, filtering is
    optional --- the user may discard any or all parse trees. The second is required, since only one
    instruction may be placed at the desired address --- the user must select one instruction among
    the many results, and if a mask is present, decide on a value for the omitted bits.
     
     
    
    Extensions of this class are also suitable for collecting diagnostic information about attempted
    assemblies. For example, an implementation may employ the syntax errors in order to produce code
    completion suggestions in a GUI.
    """

    class Selection(java.lang.Record):
        """
        A resolved selection from the results given to
        :meth:`AssemblySelector.select(AssemblyResolutionResults, AssemblyPatternBlock) <AssemblySelector.select>`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, ins: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock, ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock):
            ...

        def ctx(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def ins(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def filterParse(self, parse: collections.abc.Sequence) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult]:
        """
        Filter a collection of parse trees.
         
         
        
        Generally, the assembly resolver considers every possible parsing of an assembly instruction.
        If, for some reason, the user wishes to ignore certain trees (perhaps for efficiency, or
        perhaps because a certain form of instruction is desired), entire parse trees may be pruned
        here.
         
         
        
        It is possible that no trees pass the filter. In this case, this method ought to throw an
        :obj:`AssemblySyntaxException`. Another option is to pass the erroneous result on for
        semantic analysis, in which case, the error is simply copied into an erroneous semantic
        result. Depending on preferences, this may simplify the overall filtering and error-handling
        logic.
         
         
        
        By default, no filtering is applied. If all the trees produce syntax errors, an exception is
        thrown.
        
        :param collections.abc.Sequence parse: the collection of parse results (errors and trees).
        :return: the filtered collection, optionally in-place.
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult]
        :raises AssemblySyntaxException: if the selector wishes to forward one or more syntax errors
        """

    def select(self, rr: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults, ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> AssemblySelector.Selection:
        """
        Select an instruction from the possible results.
         
         
        
        This must select precisely one resolved constructor from the results given back by the
        assembly resolver. This further implies the mask of the returned result must consist of all
        1s. If no selection is suitable, this must throw an exception.
         
         
        
        By default, this method selects the shortest instruction that is compatible with the given
        context and takes 0 for bits that fall outside the mask. If all possible resolutions produce
        errors, an exception is thrown.
        
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults rr: the collection of resolved constructors
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock ctx: the applicable context.
        :return: a single resolved constructor with a full instruction mask.
        :rtype: AssemblySelector.Selection
        :raises AssemblySemanticException: if all the given results are semantic errors
        """


class Assembler(GenericAssembler[ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns]):
    """
    The primary interface for performing assembly in Ghidra.
     
     
    
    Use the :obj:`Assemblers` class to obtain a suitable implementation for a given program or
    language.
    """

    class_: typing.ClassVar[java.lang.Class]


class GenericAssembler(java.lang.Object, typing.Generic[RP]):

    class_: typing.ClassVar[java.lang.Class]

    def assemble(self, at: ghidra.program.model.address.Address, *listing: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.InstructionIterator:
        """
        Assemble a sequence of instructions and place them at the given address.
         
         
        
        This method is only valid if the assembler is bound to a program. An instance may optionally
        implement this method without a program binding. In that case, the returned iterator will
        refer to pseudo instructions.
         
         
        
        **NOTE:** There must be an active transaction on the bound program for this method to
        succeed.
        
        :param ghidra.program.model.address.Address at: the location where the resulting instructions should be placed
        :param jpype.JArray[java.lang.String] listing: a new-line separated or array sequence of instructions
        :return: an iterator over the resulting instructions
        :rtype: ghidra.program.model.listing.InstructionIterator
        :raises AssemblySyntaxException: a textual instruction is non well-formed
        :raises AssemblySemanticException: a well-formed instruction cannot be assembled
        :raises MemoryAccessException: there is an issue writing the result to program memory
        :raises AddressOverflowException: the resulting block is beyond the valid address range
        """

    @typing.overload
    def assembleLine(self, at: ghidra.program.model.address.Address, line: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
        """
        Assemble a line instruction at the given address.
         
         
        
        This method is valid with or without a bound program. Even if bound, the program is not
        modified; however, the appropriate context information is taken from the bound program.
        Without a program, the language's default context is taken at the given location.
        
        :param ghidra.program.model.address.Address at: the location of the start of the instruction
        :param java.lang.String or str line: the textual assembly code
        :return: the binary machine code, suitable for placement at the given address
        :rtype: jpype.JArray[jpype.JByte]
        :raises AssemblySyntaxException: the textual instruction is not well-formed
        :raises AssemblySemanticException: the well-formed instruction cannot be assembled
        """

    @typing.overload
    def assembleLine(self, at: ghidra.program.model.address.Address, line: typing.Union[java.lang.String, str], ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> jpype.JArray[jpype.JByte]:
        """
        Assemble a line instruction at the given address, assuming the given context.
         
         
        
        This method works like :meth:`assembleLine(Address, String) <.assembleLine>` except that it allows you to
        override the assumed context at that location.
        
        :param ghidra.program.model.address.Address at: the location of the start of the instruction
        :param java.lang.String or str line: the textual assembly code
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock ctx: the context register value at the start of the instruction
        :return: the results of semantic resolution (from all parse results)
        :rtype: jpype.JArray[jpype.JByte]
        :raises AssemblySyntaxException: the textual instruction is not well-formed
        :raises AssemblySemanticException: the well-formed instruction cannot be assembled
        """

    def getContextAt(self, addr: ghidra.program.model.address.Address) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock:
        """
        Get the context at a given address
         
         
        
        If there is a program binding, this will extract the actual context at the given address.
        Otherwise, it will obtain the default context at the given address for the language.
        
        :param ghidra.program.model.address.Address addr: the address
        :return: the context
        :rtype: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language of this assembler
        
        :return: the processor language
        :rtype: ghidra.program.model.lang.Language
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        If the assembler is bound to a program, get that program
        
        :return: the program, or null
        :rtype: ghidra.program.model.listing.Program
        """

    def parseLine(self, line: typing.Union[java.lang.String, str]) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult]:
        """
        Parse a line instruction.
         
         
        
        Generally, you should just use :meth:`assembleLine(Address, String) <.assembleLine>`, but if you'd like
        access to the parse trees outside of an :obj:`AssemblySelector`, then this may be an
        acceptable option. Most notably, this is an excellent way to obtain suggestions for
        auto-completion.
         
         
        
        Each item in the returned collection is either a complete parse tree, or a syntax error
        Because all parse paths are attempted, it's possible to get many mixed results. For example,
        The input line may be a valid instruction; however, there may be suggestions to continue the
        line toward another valid instruction.
        
        :param java.lang.String or str line: the line (or partial line) to parse
        :return: the results of parsing
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult]
        """

    @typing.overload
    def patchProgram(self, res: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, at: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Place a resolved (and fully-masked) instruction into the bound program.
         
         
        
        This method is not valid without a program binding. Also, this method must be called during a
        program database transaction.
        
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns res: the resolved and fully-masked instruction
        :param ghidra.program.model.address.Address at: the location of the start of the instruction
        :return: the new :obj:`Instruction` code unit
        :rtype: ghidra.program.model.listing.Instruction
        :raises MemoryAccessException: there is an issue writing the result to program memory
        """

    @typing.overload
    def patchProgram(self, insbytes: jpype.JArray[jpype.JByte], at: ghidra.program.model.address.Address) -> ghidra.program.model.listing.InstructionIterator:
        """
        Place instruction bytes into the bound program.
         
         
        
        This method is not valid without a program binding. Also, this method must be called during a
        program database transaction.
        
        :param jpype.JArray[jpype.JByte] insbytes: the instruction data
        :param ghidra.program.model.address.Address at: the location of the start of the instruction
        :return: an iterator over the disassembled instructions
        :rtype: ghidra.program.model.listing.InstructionIterator
        :raises MemoryAccessException: there is an issue writing the result to program memory
        """

    @typing.overload
    def resolveLine(self, at: ghidra.program.model.address.Address, line: typing.Union[java.lang.String, str]) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults:
        """
        Assemble a line instruction at the given address.
         
         
        
        This method works like :meth:`resolveLine(Address, String, AssemblyPatternBlock) <.resolveLine>`, except
        that it derives the context using :meth:`getContextAt(Address) <.getContextAt>`.
        
        :param ghidra.program.model.address.Address at: the location of the start of the instruction
        :param java.lang.String or str line: the textual assembly code
        :return: the collection of semantic resolution results
        :rtype: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults
        :raises AssemblySyntaxException: the textual instruction is not well-formed
        """

    @typing.overload
    def resolveLine(self, at: ghidra.program.model.address.Address, line: typing.Union[java.lang.String, str], ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults:
        """
        Assemble a line instruction at the given address, assuming the given context.
         
         
        
        This method works like :meth:`assembleLine(Address, String, AssemblyPatternBlock) <.assembleLine>`, except
        that it returns all possible resolutions for the parse trees that pass the
        :obj:`AssemblySelector`.
        
        :param ghidra.program.model.address.Address at: the location of the start of the instruction
        :param java.lang.String or str line: the textual assembly code
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock ctx: the context register value at the start of the instruction
        :return: the collection of semantic resolution results
        :rtype: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults
        :raises AssemblySyntaxException: the textual instruction is not well-formed
        """

    @typing.overload
    def resolveTree(self, parse: ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult, at: ghidra.program.model.address.Address, ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults:
        """
        Resolve a given parse tree at the given address, assuming the given context
         
         
        
        Each item in the returned collection is either a completely resolved instruction, or a
        semantic error. Because all resolutions are attempted, it's possible to get many mixed
        results.
         
         
        
        **NOTE:** The resolved instructions are given as masks and values. Where the mask does not
        cover, you can choose any value.
        
        :param ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult parse: a parse result giving a valid tree
        :param ghidra.program.model.address.Address at: the location of the start of the instruction
        :param ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock ctx: the context register value at the start of the instruction
        :return: the results of semantic resolution
        :rtype: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults
        """

    @typing.overload
    def resolveTree(self, parse: ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult, at: ghidra.program.model.address.Address) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults:
        """
        Resolve a given parse tree at the given address.
         
         
        
        Each item in the returned collection is either a completely resolved instruction, or a
        semantic error. Because all resolutions are attempted, it's possible to get many mixed
        results.
         
         
        
        **NOTE:** The resolved instructions are given as masks and values. Where the mask does not
        cover, you can choose any value.
        
        :param ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult parse: a parse result giving a valid tree
        :param ghidra.program.model.address.Address at: the location of the start of the instruction
        :return: the results of semantic resolution
        :rtype: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults
        """

    @property
    def contextAt(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class AssemblySemanticException(AssemblyException):
    """
    Thrown when all resolutions of an assembly instruction result in semantic errors.
     
     
    
    For SLEIGH, semantic errors amount to incompatible contexts
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, errors: java.util.Set[ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError]):
        """
        Construct a semantic exception with the associated semantic errors
        
        :param java.util.Set[ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError] errors: the associated semantic errors
        """

    def getErrors(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError]:
        """
        Get the collection of associated semantic errors
        
        :return: the collection
        :rtype: java.util.Collection[ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError]
        """

    @property
    def errors(self) -> java.util.Collection[ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError]:
        ...



__all__ = ["GenericAssemblerBuilder", "AssemblyException", "Assemblers", "AssemblyError", "AssemblySelectionError", "AssemblerBuilder", "AssemblySyntaxException", "AssemblyBuffer", "AssemblySelector", "Assembler", "GenericAssembler", "AssemblySemanticException"]
