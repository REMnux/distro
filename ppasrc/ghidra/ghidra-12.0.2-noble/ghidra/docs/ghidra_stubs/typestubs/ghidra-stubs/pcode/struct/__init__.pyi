from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.exec_
import ghidra.program.model.address
import ghidra.program.model.data
import java.lang # type: ignore
import java.lang.annotation # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


@typing.type_check_only
class BreakStmt(LoopTruncateStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class WhileStmt(LoopStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DefaultUseropDecl(StructuredSleigh.UseropDecl):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ctx: StructuredSleigh, retType: ghidra.program.model.data.DataType, name: typing.Union[java.lang.String, str], paramTypes: java.util.List[ghidra.program.model.data.DataType]):
        ...


@typing.type_check_only
class UnExpr(Expr):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class IfStmt(ConditionalStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class NotExpr(UnExpr):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BlockStmt(AbstractStmt):
    """
    A block statement
    """

    class_: typing.ClassVar[java.lang.Class]

    def addChild(self, child: AbstractStmt):
        """
        Add a child to this statement
        
        :param AbstractStmt child: the child statement
        """


@typing.type_check_only
class LValInternal(StructuredSleigh.LVal, RValInternal):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LoopStmt(ConditionalStmt):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ctx: StructuredSleigh, cond: StructuredSleigh.RVal, stmt: StructuredSleigh.Stmt):
        ...


@typing.type_check_only
class AbstractStmt(StructuredSleigh.Stmt):

    class_: typing.ClassVar[java.lang.Class]

    def getContext(self) -> StructuredSleigh:
        """
        Internal: Provides the implementation of :meth:`RValInternal.getContext() <RValInternal.getContext>` for
        :obj:`AssignStmt`
        
        :return: the context
        :rtype: StructuredSleigh
        """

    @property
    def context(self) -> StructuredSleigh:
        ...


@typing.type_check_only
class ForStmt(LoopStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GotoStmt(AbstractStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ReturnStmt(AbstractStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class AssignStmt(AbstractStmt, RValInternal, StructuredSleigh.StmtWithVal):
    """
    An assignment statement
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ctx: StructuredSleigh, lhs: StructuredSleigh.LVal, rhs: StructuredSleigh.RVal):
        ...


@typing.type_check_only
class LocalVar(DefaultVar):
    ...
    class_: typing.ClassVar[java.lang.Class]


class RawExpr(Expr):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RoutineStmt(BlockStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ConditionalStmt(AbstractStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


class Expr(RValInternal):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CmpExpr(BinExpr):

    @typing.type_check_only
    class Op(java.lang.Enum[CmpExpr.Op]):

        class_: typing.ClassVar[java.lang.Class]
        EQ: typing.Final[CmpExpr.Op]
        NEQ: typing.Final[CmpExpr.Op]
        EQF: typing.Final[CmpExpr.Op]
        NEQF: typing.Final[CmpExpr.Op]
        LTIU: typing.Final[CmpExpr.Op]
        LTIS: typing.Final[CmpExpr.Op]
        LTF: typing.Final[CmpExpr.Op]
        LTEIU: typing.Final[CmpExpr.Op]
        LTEIS: typing.Final[CmpExpr.Op]
        LTEF: typing.Final[CmpExpr.Op]
        GTIU: typing.Final[CmpExpr.Op]
        GTIS: typing.Final[CmpExpr.Op]
        GTF: typing.Final[CmpExpr.Op]
        GTEIU: typing.Final[CmpExpr.Op]
        GTEIS: typing.Final[CmpExpr.Op]
        GTEF: typing.Final[CmpExpr.Op]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CmpExpr.Op:
            ...

        @staticmethod
        def values() -> jpype.JArray[CmpExpr.Op]:
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LangVar(DefaultVar):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BinExpr(Expr):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RValInternal(StructuredSleigh.RVal):

    class_: typing.ClassVar[java.lang.Class]

    def generate(self, parent: RValInternal) -> StringTree:
        ...

    def getContext(self) -> StructuredSleigh:
        ...

    @property
    def context(self) -> StructuredSleigh:
        ...


@typing.type_check_only
class LiteralExpr(Expr):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LiteralFloatExpr(LiteralExpr):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LoopTruncateStmt(AbstractStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ResultStmt(AbstractStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ContinueStmt(LoopTruncateStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CallExpr(Expr):
    """
    A p-code userop invocation expression
     
     
    
    Userops are essentially treated as functions. They can be invoked passing a list of parameters,
    and the expression takes the value it returns (via :meth:`StructuredSleigh._result(RVal) <StructuredSleigh._result>`.
    """

    class_: typing.ClassVar[java.lang.Class]


class StructuredSleigh(java.lang.Object):
    """
    The primary class for using the "structured sleigh" DSL
     
     
    
    This provides some conveniences for generating Sleigh source code, which is otherwise completely
    typeless and lacks basic control structure. In general, the types are not used so much for type
    checking as they are for easing access to fields of C structures, array indexing, etc.
    Furthermore, it becomes possible to re-use code when data types differ among platforms, so long
    as those variations are limited to field offsets and type sizes.
     
     
    
    Start by declaring an extension of :obj:`StructuredSleigh`. Then put any necessary "forward
    declarations" as fields of the class. Then declare methods annotated with
    :obj:`StructuredUserop`. Inside those methods, all the protected methods of this class are
    accessible, providing a DSL (as far as Java can provide :/ ) for writing Sleigh code. For
    example:
     
     
    class MyStructuredPart extends StructuredSleigh {
        Var r0 = lang("r0", "/long");
     
        protected MyStructuredPart() {
            super(program);
        }
     
        @StructuredUserop
        public void my_userop() {
            r0.set(0xdeadbeef);
        }
    }
     
     
     
    
    This will simply generate the source "``r0 = 0xdeadbeef:4``", but it also provides all the
    scaffolding to compile and invoke the userop as in a :obj:`PcodeUseropLibrary`. Internal methods
    -- which essentially behave like macros -- may be used, so only annotate methods to export as
    userops. For a more complete and practical example of using structured sleigh in a userop
    library, see :obj:`AbstractEmuUnixSyscallUseropLibrary`.
     
     
    
    Structured sleigh is also usable in a more standalone manner:
     
     
    StructuredSleigh ss = new StructuredSleigh(compilerSpec) {
        @StructuredUserop
        public void my_userop() {
            // Something interesting, I'm sure
        }
    };
     
    SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
    // To print source
    myUserop.getLines().forEach(System.out::print);
     
    // To compile for given parameters (none in this case) and print the p-code
    Register r0 = lang.getRegister("r0");
    System.out.println(myUserop.programFor(new Varnode(r0.getAddress(), r0.getNumBytes()), List.of(),
        PcodeUseropLibrary.NIL));
     
     
     
    
    Known limitations:
     
    * Recursion is not really possible. Currently, local variables of a userop do not actually get
    their own unique storage per invocation record. Furthermore, it's possible that local variable in
    different userop definition will be assigned the same storage location, meaning they could be
    unintentionally aliased if one invokes the other. Care should be taken when invoking one
    sleigh-based userop from another, or it should be avoided altogether until this limitation is
    addressed. It's generally safe to allow such invocations at the tail.
    * Parameters are passed by reference. Essentially, the formal argument becomes an alias to its
    parameter. This is more a feature, but can be surprising if C semantics are expected.
    * Calling one Structured Sleigh userop from another still requires a "external declaration" of
    the callee, despite being defined in the same "compilation unit."
    """

    @typing.type_check_only
    class StructuredUserop(java.lang.annotation.Annotation):
        """
        "Export" a method as a p-code userop implemented using p-code compiled from structured Sleigh
        
         
        
        This is applied to methods used to generate Sleigh source code. Take note that the method is
        only invoked once (for a given library instance) to generate code. Thus, beware of
        non-determinism during code generation. For example, implementing something like
        ``rdrnd`` in structured Sleigh is rife with peril. Take the following implementation:
         
         
        @StructuredUserop
        public void rdrnd() {
            r0.set(Random.nextLong()); // BAD: Die rolled once at compile time
        }
         
         
         
        
        The random number will be generated once at structured Sleigh compilation time, and then that
        same number used on every invocation of the p-code userop. Instead, this userop should be
        implemented using a Java callback, i.e., :obj:`AnnotatedPcodeUseropLibrary.PcodeUserop`.
         
         
        
        The userop may accept parameters and return a result. To accept parameters, declare them in
        the Java method signature and annotate them with :obj:`Param`. To return a result, name the
        appropriate type in the :meth:`type() <.type>` attribute and use
        :meth:`StructuredSleigh._result(RVal) <StructuredSleigh._result>`. The Java return type of the method must still be
        ``void``. Note that parameters are passed by reference, so results can also be
        communicated by setting a parameter's value.
        """

        class_: typing.ClassVar[java.lang.Class]

        def type(self) -> str:
            """
            The data type path for the "return type" of the userop. See
            :meth:`StructuredSleigh.type(String) <StructuredSleigh.type>`.
            """


    @typing.type_check_only
    class Param(java.lang.annotation.Annotation):
        """
        Declare a parameter of the p-code userop
         
         
        
        This is attached to parameters of methods annotated with :obj:`StructuredUserop`, providing
        the type and name of the parameter. The Java type of the parameter must be :obj:`Var`. For
        example:
         
         
        @StructuredUserop
        public void twice(@Param(name = "p0", type = "void *") Var p0) {
            _result(p0.mul(2));
        }
        """

        class_: typing.ClassVar[java.lang.Class]

        def name(self) -> str:
            """
            The name of the parameter in the output Sleigh code
             
             
            
            If the variable is referenced via :meth:`StructuredSleigh.s(String) <StructuredSleigh.s>` or
            :meth:`StructuredSleigh.e(String) <StructuredSleigh.e>`, then is it necessary to specify the name used in the
            Sleigh code. Otherwise, the name is typically derived from the Java parameter name, which
            Java platforms are not required to preserve. If the variable is referenced only by its
            handle, then the name will be consistent and unique in the generated Sleigh code. When
            diagnosing Structured Sleigh compilation issues, it may be desirable to specify the
            variable name, regardless.
            """

        def type(self) -> str:
            """
            The data type path for the type of the parameter. See
            :meth:`StructuredSleigh.type(String) <StructuredSleigh.type>`.
            """


    @typing.type_check_only
    class UseropDecl(java.lang.Object):
        """
        The declaration of an "imported" userop
         
         
        
        Because Sleigh is typeless, structured Sleigh needs additional type information about the
        imported userop. The referenced userop may be implemented by another library and may be a
        Java callback or a p-code based userop, or something else. Note that if the userop is
        missing, it might not be detected until the calling Sleigh code is invoked for the first
        time.
        """

        class_: typing.ClassVar[java.lang.Class]

        def call(self, *args: StructuredSleigh.RVal) -> StructuredSleigh.StmtWithVal:
            """
            Generate an invocation of the userop
             
             
            
            If the userop has a result type, then the resulting statement will also have a value. If
            the user has a ``void`` result type, the "value" should not be used. Otherwise, a
            warning will likely be generated, and the "result value" will be undefined.
            
            :param jpype.JArray[StructuredSleigh.RVal] args: the arguments to pass
            :return: a handle to the statement
            :rtype: StructuredSleigh.StmtWithVal
            """

        def getName(self) -> str:
            """
            Get the name of the userop
            
            :return: the name
            :rtype: str
            """

        def getParameterTypes(self) -> java.util.List[ghidra.program.model.data.DataType]:
            """
            Get the parameter types of the userop
            
            :return: the types, in order of parameters
            :rtype: java.util.List[ghidra.program.model.data.DataType]
            """

        def getReturnType(self) -> ghidra.program.model.data.DataType:
            """
            Get the userop's return type
            
            :return: the return type
            :rtype: ghidra.program.model.data.DataType
            """

        @property
        def parameterTypes(self) -> java.util.List[ghidra.program.model.data.DataType]:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def returnType(self) -> ghidra.program.model.data.DataType:
            ...


    @typing.type_check_only
    class RVal(java.lang.Object):
        """
        A value which can only be used on the right-hand side of an assignment
        """

        class_: typing.ClassVar[java.lang.Class]

        def addf(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float addition
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def addi(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate integer addition
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def addi(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate integer addition
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def andb(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate boolean and
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def andb(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate boolean and
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def andi(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate an integer (bitwise) and
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def andi(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate an integer (bitwise) and
            
            :param jpype.JLong or int rhs: the immediate operand (mask)
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def cast(self, type: ghidra.program.model.data.DataType) -> StructuredSleigh.RVal:
            """
            Cast the value to the given type
             
             
            
            This functions like a C-style pointer cast. There are no implied operations or
            conversions. Notably, casting between integers and floats is just a re-interpretation of
            the underlying bits.
            
            :param ghidra.program.model.data.DataType type: the type
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def deref(self, space: ghidra.program.model.address.AddressSpace) -> StructuredSleigh.LVal:
            """
            Generate a dereference (in the C sense)
             
             
            
            The value is treated as an address, and the result is essentially a variable in the given
            target address space.
            
            :param ghidra.program.model.address.AddressSpace space: the address space of the result
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.LVal
            """

        @typing.overload
        def deref(self) -> StructuredSleigh.LVal:
            """
            Generate a dereference (in the C sense) in the default address space
            
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.LVal
            """

        def divf(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float division
            
            :param StructuredSleigh.RVal rhs: the divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def divis(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate signed integer division
            
            :param StructuredSleigh.RVal rhs: the divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def divis(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate signed integer division
            
            :param jpype.JLong or int rhs: the immediate divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def diviu(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer division
            
            :param StructuredSleigh.RVal rhs: the divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def diviu(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer division
            
            :param jpype.JLong or int rhs: the immediate divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def eq(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate integer comparison: equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def eq(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate integer comparison: equal to
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def eqf(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float comparison: equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def getType(self) -> ghidra.program.model.data.DataType:
            """
            Get the type of the value
            
            :return: the type
            :rtype: ghidra.program.model.data.DataType
            """

        def gtef(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float comparison: greater than or equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def gteis(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate signed integer comparison: greater than or equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def gteis(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate signed integer comparison: greater than or equal to
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def gteiu(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: greater than or equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def gteiu(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: greater than or equal to
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def gtf(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float comparison: greater than
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def gtis(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate signed integer comparison: greater than
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def gtis(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate signed integer comparison: greater than
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def gtiu(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: greater than
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def gtiu(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: greater than
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def ltef(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float comparison: less than or equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def lteis(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate signed integer comparison: less than or equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def lteis(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate signed integer comparison: less than or equal to
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def lteiu(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: less than or equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def lteiu(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: less than or equal to
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def ltf(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: less than
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def ltis(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate signed integer comparison: less than
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def ltis(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate signed integer comparison: less than
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def ltiu(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: less than
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def ltiu(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer comparison: less than
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def mulf(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float multiplication
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def muli(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate integer multiplication
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def muli(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate integer multiplication
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def neq(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate integer comparison: not equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def neq(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate integer comparison: not equal to
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def neqf(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float comparison: not equal to
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def notb(self) -> StructuredSleigh.RVal:
            """
            Generate boolean inversion
            
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def noti(self) -> StructuredSleigh.RVal:
            """
            Generate integer (bitwise) inversion
            
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def orb(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate boolean or
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def orb(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate boolean or
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def ori(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate an integer (bitwise) or
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def ori(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate an integer (bitwise) or
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def remis(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate signed integer division remainder
            
            :param StructuredSleigh.RVal rhs: the divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def remis(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate signed integer division remainder
            
            :param jpype.JLong or int rhs: the immediate divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def remiu(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer division remainder
            
            :param StructuredSleigh.RVal rhs: the divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def remiu(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate unsigned integer division remainder
            
            :param jpype.JLong or int rhs: the immediate divisor
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def shli(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate bit shift to the left
            
            :param StructuredSleigh.RVal rhs: the second operand (shift amount)
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def shli(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate bit shift to the left
            
            :param jpype.JLong or int rhs: the immediate operand (shift amount)
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def shris(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate signed bit shift to the right
            
            :param StructuredSleigh.RVal rhs: the second operand (shift amount)
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def shris(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate signed bit shift to the right
            
            :param jpype.JLong or int rhs: the immediate operand (shift amount)
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def shriu(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate unsigned bit shift to the right
            
            :param StructuredSleigh.RVal rhs: the second operand (shift amount)
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def shriu(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate unsigned bit shift to the right
            
            :param jpype.JLong or int rhs: the immediate operand (shift amount)
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        def subf(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate float subtraction
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def subi(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate integer subtraction
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def subi(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate integer subtraction of an immediate
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def xorb(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate boolean exclusive or
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def xorb(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate boolean exclusive or
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def xori(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.RVal:
            """
            Generate an integer (bitwise) exclusive or
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @typing.overload
        def xori(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.RVal:
            """
            Generate an integer (bitwise) exclusive or
            
            :param jpype.JLong or int rhs: the immediate operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.RVal
            """

        @property
        def type(self) -> ghidra.program.model.data.DataType:
            ...


    @typing.type_check_only
    class LVal(StructuredSleigh.RVal):
        """
        A value which can be used on either side of an assignment
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def addiTo(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.StmtWithVal:
            """
            Generate in-place integer addition
            
            :param StructuredSleigh.RVal rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.StmtWithVal
            """

        @typing.overload
        def addiTo(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.StmtWithVal:
            """
            Generate in-place integer addition
            
            :param jpype.JLong or int rhs: the second operand
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.StmtWithVal
            """

        def field(self, name: typing.Union[java.lang.String, str]) -> StructuredSleigh.LVal:
            """
            Generate a field offset
             
             
            
            This departs subtly from expected C semantics. This value's type is assumed to be a
            pointer to a :obj:`Composite`. That type is retrieved and the field located. This then
            generates unsigned addition of that field offset to this value. The type of the result is
            a pointer to the type of the field. The C equivalent is "``&(val->field)``".
            Essentially, it's just address computation. Note that this operator will fail if the type
            is not a pointer. It cannot be used directly on the :obj:`Composite` type.
             
             
            
            TODO: Allow direct use on the composite type? Some mechanism for dealing with bitfields?
            Bitfields cannot really work if this is just pointer manipulation. If it's also allowed
            to manipulate raw bytes of a composite, then bitfield access could work. Assignment would
            be odd, but doable. The inputs would be the composite-typed value, the field name, and
            the desired field value. The output would be the resulting composite-typed value. For
            large structures, though, we'd like to manipulate the least number of bytes possible,
            since they'll likely need to be written back out to target memory.
            
            :param java.lang.String or str name: the name of the field
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.LVal
            """

        def inc(self) -> StructuredSleigh.StmtWithVal:
            """
            Generate an in-place increment (by 1)
            
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.StmtWithVal
            """

        @typing.overload
        def index(self, index: StructuredSleigh.RVal) -> StructuredSleigh.LVal:
            """
            Generate an array index
             
             
            
            This departs subtly from expected C semantics. This value's type is assumed to be a
            pointer to the element type. The size of the element type is computed, and this generates
            unsigned multiplcation of the index and size, then addition to this value. The type of
            the result is the same as this value's type. The C equivalent is "``&(val[index])``".
            Essentially, it's just address computation. Note that this operator will fail if the type
            is not a pointer. It cannot be used on an :obj:`Array` type.
             
             
             
            
            TODO: Allow use of :obj:`Array` type? While it's possible for authors to specify pointer
            types for their variables, the types of fields they access may not be under their
            control. In particular, between :meth:`field(String) <.field>` and :meth:`index(RVal) <.index>`, we ought
            to support accessing fixed-length array fields.
            
            :param StructuredSleigh.RVal index: the operand to use as the index into the array
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.LVal
            """

        @typing.overload
        def index(self, index: typing.Union[jpype.JLong, int]) -> StructuredSleigh.LVal:
            """
            Generate an array index
            
            :param jpype.JLong or int index: the immediate to use as the index into the array
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.LVal
            
            .. seealso::
            
                | :obj:`.index(RVal)`
            """

        @typing.overload
        def set(self, rhs: StructuredSleigh.RVal) -> StructuredSleigh.StmtWithVal:
            """
            Assign this value
            
            :param StructuredSleigh.RVal rhs: the value to assign
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.StmtWithVal
            """

        @typing.overload
        def set(self, rhs: typing.Union[jpype.JLong, int]) -> StructuredSleigh.StmtWithVal:
            """
            Assign this value
            
            :param jpype.JLong or int rhs: the immediate value to assign
            :return: a handle to the resulting value
            :rtype: StructuredSleigh.StmtWithVal
            """


    @typing.type_check_only
    class Var(StructuredSleigh.LVal):
        """
        A Sleigh variable
        """

        class_: typing.ClassVar[java.lang.Class]

        def getName(self) -> str:
            """
            Get the name of the variable as it appears in generated Sleigh code
            
            :return: the name
            :rtype: str
            """

        @property
        def name(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class Stmt(java.lang.Object):
        """
        A Structured Sleigh statement
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StmtWithVal(StructuredSleigh.Stmt, StructuredSleigh.RVal):
        """
        A Structured Sleigh statement that also has a value
        """

        class_: typing.ClassVar[java.lang.Class]


    class StructuredSleighError(java.lang.RuntimeException):
        """
        An exception for unrecoverable Structured Sleigh compilation errors
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Label(java.lang.Object):
        """
        A generated Sleigh label
        """

        class_: typing.ClassVar[java.lang.Class]

        def freshOrBorrow(self) -> StructuredSleigh.Label:
            """
            Borrow this label
             
             
            
            This should be used whenever a statement (or its children) may need to generate a goto
            using the "next" label passed into it. If "next" is the fall-through label, this will
            generate a fresh label. If this label is already fresh, this will "borrow" the label,
            meaning references will be generated, but it will not produce another anchor. This is to
            prevent generation of duplicate anchors.
            
            :return: the resulting label
            :rtype: StructuredSleigh.Label
            """

        def genAnchor(self) -> StringTree:
            """
            Generate code for this label
             
             
            
            This must be the last method called on the label, because it relies on knowing whether or
            not the label is actually used. (The Sleigh compiler rejects code if it contains unused
            labels.)
            
            :return: the Sleigh code
            :rtype: StringTree
            """

        @typing.overload
        def genGoto(self, fall: StructuredSleigh.Label) -> StringTree:
            """
            Generate a goto statement that targets this label
            
            :param StructuredSleigh.Label fall: the label following the goto
            :return: the Sleigh code
            :rtype: StringTree
            """

        @typing.overload
        def genGoto(self, cond: StructuredSleigh.RVal, fall: StructuredSleigh.Label) -> StringTree:
            """
            Generate a conditional goto statement that targets this label
            
            :param StructuredSleigh.RVal cond: the condition value
            :param StructuredSleigh.Label fall: the label following the goto
            :return: the Sleigh code
            :rtype: StringTree
            """

        def ref(self) -> StringTree:
            """
            Generate a reference to this label as it should appear in a Sleigh "``goto``"
            statement
            
            :return: the label's expression
            :rtype: StringTree
            """


    @typing.type_check_only
    class FreshLabel(StructuredSleigh.Label):
        """
        A fresh Sleigh label
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BorrowedLabel(StructuredSleigh.Label):
        """
        A label whose anchor placement is already claimed
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FallLabel(StructuredSleigh.Label):
        """
        The virtual fall-through label
         
         
        
        The idea is that no one should ever need to generate labels or gotos to achieve fall-through.
        Any attempt to do so probably indicates an implementation error where code generation failed
        to place a label.
        """

        class_: typing.ClassVar[java.lang.Class]


    class WrapIf(java.lang.Object):
        """
        The wrapper around an :meth:`StructuredSleigh._if(RVal, Runnable) <StructuredSleigh._if>` statement providing
        additional DSL syntax
        """

        class_: typing.ClassVar[java.lang.Class]

        def _elif(self, cond: Expr, body: java.lang.Runnable) -> StructuredSleigh.WrapIf:
            """
            Generate an "else if" clause for the wrapped "if" statement
             
             
            
            This is shorthand for ``_else(_if(...))`` but avoids the unnecessary nesting of
            parentheses.
            
            :param Expr cond: the condition
            :param java.lang.Runnable body: the body of the clause
            :return: a wrapper to the second "if" statement
            :rtype: StructuredSleigh.WrapIf
            """

        def _else(self, body: java.lang.Runnable):
            """
            Generate an "else" clause for the wrapped "if" statement
            
            :param java.lang.Runnable body: the body of the clause
            """


    class_: typing.ClassVar[java.lang.Class]

    def e(self, rawExpr: typing.Union[java.lang.String, str]) -> Expr:
        """
        Generate a Sleigh expression
         
         
        
        This is similar in concept to inline assembly, except it also has a value. It allows the
        embedding of Sleigh code into Structured Sleigh that is otherwise impossible or inconvenient
        to express. No effort is made to ensure the correctness of the given Sleigh expression nor
        its impact in context. The result is assigned a type of "void".
        
        :param java.lang.String or str rawExpr: the Sleigh expression
        :return: a handle to the value
        :rtype: Expr
        """

    @typing.overload
    def generate(self, into: collections.abc.Mapping):
        """
        Generate all the exported userops and place them into the given map
        
        :param T: the type of values used by the userops. For sleigh, this can be anything.:param collections.abc.Mapping into: the destination map, usually belonging to a :obj:`PcodeUseropLibrary`.
        """

    @typing.overload
    def generate(self, m: java.lang.reflect.Method) -> ghidra.pcode.exec_.SleighPcodeUseropDefinition[T]:
        """
        Generate the userop for a given Java method
        
        :param T: the type of values used by the userop. For sleigh, this can be anything.:param java.lang.reflect.Method m: the method exported as a userop
        :return: the userop
        :rtype: ghidra.pcode.exec_.SleighPcodeUseropDefinition[T]
        """

    @typing.overload
    def generate(self) -> java.util.Map[java.lang.String, ghidra.pcode.exec_.SleighPcodeUseropDefinition[T]]:
        """
        Generate all the exported userops and return them in a map
         
         
        
        This is typically only used when not part of a larger :obj:`PcodeUseropLibrary`, for example
        to aid in developing a Sleigh module or for generating injects.
        
        :param T: the type of values used by the userop. For sleigh, this can be anything.:return: the userop
        :rtype: java.util.Map[java.lang.String, ghidra.pcode.exec_.SleighPcodeUseropDefinition[T]]
        """

    def s(self, rawStmt: typing.Union[java.lang.String, str]) -> StructuredSleigh.Stmt:
        """
        Generate Sleigh code
         
         
        
        This is similar in concept to inline assembly. It allows the embedding of Sleigh code into
        Structured Sleigh that is otherwise impossible or inconvenient to state. No effort is made to
        ensure the correctness of the given Sleigh code nor its impact in context.
        
        :param java.lang.String or str rawStmt: the Sleigh code
        :return: a handle to the statement
        :rtype: StructuredSleigh.Stmt
        """


class StringTree(java.lang.Object):

    @typing.type_check_only
    class Node(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def walk(self, buf: java.lang.StringBuffer):
            ...


    @typing.type_check_only
    class Branch(StringTree.Node):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Leaf(StringTree.Node):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, seq: java.lang.CharSequence):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def append(self, seq: java.lang.CharSequence):
        ...

    @typing.overload
    def append(self, tree: StringTree):
        ...

    @staticmethod
    def single(seq: java.lang.CharSequence) -> StringTree:
        ...


@typing.type_check_only
class InvExpr(UnExpr):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ctx: StructuredSleigh, u: StructuredSleigh.RVal):
        ...


@typing.type_check_only
class DerefExpr(Expr, LValInternal):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DeclStmt(AbstractStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LiteralLongExpr(LiteralExpr):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DefaultVar(LValInternal, StructuredSleigh.Var):

    @typing.type_check_only
    class Check(java.lang.Enum[DefaultVar.Check]):
        """
        The rule for name collision
        """

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[DefaultVar.Check]
        """
        The name may or may not already be defined by the language
        """

        IMPORT: typing.Final[DefaultVar.Check]
        """
        The name must already be defined by the language so it can be imported
        """

        FREE: typing.Final[DefaultVar.Check]
        """
        The name cannot already be defined by the language so it is free
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DefaultVar.Check:
            ...

        @staticmethod
        def values() -> jpype.JArray[DefaultVar.Check]:
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ArithBinExpr(BinExpr):

    @typing.type_check_only
    class Op(java.lang.Enum[ArithBinExpr.Op]):

        class_: typing.ClassVar[java.lang.Class]
        ORB: typing.Final[ArithBinExpr.Op]
        ORI: typing.Final[ArithBinExpr.Op]
        XORB: typing.Final[ArithBinExpr.Op]
        XORI: typing.Final[ArithBinExpr.Op]
        ANDB: typing.Final[ArithBinExpr.Op]
        ANDI: typing.Final[ArithBinExpr.Op]
        SHLI: typing.Final[ArithBinExpr.Op]
        SHRIU: typing.Final[ArithBinExpr.Op]
        SHRIS: typing.Final[ArithBinExpr.Op]
        ADDI: typing.Final[ArithBinExpr.Op]
        ADDF: typing.Final[ArithBinExpr.Op]
        SUBI: typing.Final[ArithBinExpr.Op]
        SUBF: typing.Final[ArithBinExpr.Op]
        MULI: typing.Final[ArithBinExpr.Op]
        MULF: typing.Final[ArithBinExpr.Op]
        DIVIU: typing.Final[ArithBinExpr.Op]
        DIVIS: typing.Final[ArithBinExpr.Op]
        DIVF: typing.Final[ArithBinExpr.Op]
        REMIU: typing.Final[ArithBinExpr.Op]
        REMIS: typing.Final[ArithBinExpr.Op]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ArithBinExpr.Op:
            ...

        @staticmethod
        def values() -> jpype.JArray[ArithBinExpr.Op]:
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class IndexExpr(Expr, LValInternal):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FieldExpr(Expr, LValInternal):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RawStmt(AbstractStmt):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VoidExprStmt(AbstractStmt, RValInternal, StructuredSleigh.StmtWithVal):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["BreakStmt", "WhileStmt", "DefaultUseropDecl", "UnExpr", "IfStmt", "NotExpr", "BlockStmt", "LValInternal", "LoopStmt", "AbstractStmt", "ForStmt", "GotoStmt", "ReturnStmt", "AssignStmt", "LocalVar", "RawExpr", "RoutineStmt", "ConditionalStmt", "Expr", "CmpExpr", "LangVar", "BinExpr", "RValInternal", "LiteralExpr", "LiteralFloatExpr", "LoopTruncateStmt", "ResultStmt", "ContinueStmt", "CallExpr", "StructuredSleigh", "StringTree", "InvExpr", "DerefExpr", "DeclStmt", "LiteralLongExpr", "DefaultVar", "ArithBinExpr", "IndexExpr", "FieldExpr", "RawStmt", "VoidExprStmt"]
