from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import org.apache.commons.lang3.reflect # type: ignore
import org.objectweb.asm # type: ignore


A = typing.TypeVar("A")
A0 = typing.TypeVar("A0")
A1 = typing.TypeVar("A1")
A2 = typing.TypeVar("A2")
A3 = typing.TypeVar("A3")
A4 = typing.TypeVar("A4")
A5 = typing.TypeVar("A5")
A6 = typing.TypeVar("A6")
A7 = typing.TypeVar("A7")
AT = typing.TypeVar("AT")
CN = typing.TypeVar("CN")
CN0 = typing.TypeVar("CN0")
CN1 = typing.TypeVar("CN1")
CR = typing.TypeVar("CR")
CT = typing.TypeVar("CT")
ET = typing.TypeVar("ET")
FT = typing.TypeVar("FT")
LN = typing.TypeVar("LN")
MN = typing.TypeVar("MN")
MN0 = typing.TypeVar("MN0")
MN1 = typing.TypeVar("MN1")
MR = typing.TypeVar("MR")
N = typing.TypeVar("N")
N0 = typing.TypeVar("N0")
N1 = typing.TypeVar("N1")
N2 = typing.TypeVar("N2")
N3 = typing.TypeVar("N3")
N4 = typing.TypeVar("N4")
OT = typing.TypeVar("OT")
P = typing.TypeVar("P")
P1 = typing.TypeVar("P1")
PT = typing.TypeVar("PT")
R = typing.TypeVar("R")
RT = typing.TypeVar("RT")
SN = typing.TypeVar("SN")
SN0 = typing.TypeVar("SN0")
SN1 = typing.TypeVar("SN1")
ST = typing.TypeVar("ST")
T = typing.TypeVar("T")
T1 = typing.TypeVar("T1")
T2 = typing.TypeVar("T2")
TL = typing.TypeVar("TL")
TR = typing.TypeVar("TR")
V1 = typing.TypeVar("V1")
V2 = typing.TypeVar("V2")
V3 = typing.TypeVar("V3")
V4 = typing.TypeVar("V4")


class Scope(java.lang.Object):
    """
    A scope for local variable declarations, but not treated as a resource
    """

    class_: typing.ClassVar[java.lang.Class]

    def close(self) -> None:
        """
        Close this scope
         
        
        This resets the index to what it was at the start of this scope. In general, there is no need
        for the user to call this on the root scope. This is automatically done by
        :meth:`Misc.finish(Emitter) <Misc.finish>`.
        """

    def decl(self, type: T, name: typing.Union[java.lang.String, str]) -> Local[T]:
        """
        Declare a local variable in this scope
         
        
        This assigns the local the next available index, being careful to increment the index
        according to the category of the given type. When this scope is closed, that index is reset
        to what is was at the start of this scope.
        
        :param T: the type of the variable:param T type: the type of the variable
        :param java.lang.String or str name: the name of the variable
        :return: the handle to the variable
        :rtype: Local[T]
        """

    def sub(self) -> SubScope:
        """
        Open a child scope of this scope, usually for temporary declarations/allocations
         
        
        The variables declared in this scope (see :meth:`decl(BNonVoid, String) <.decl>`) are reserved only
        with the scope of the ``try-with-resources`` block that ought to be used to managed this
        resource. Local variables meant to be in scope for the method's full scope should just be
        declared in the :meth:`root scope <Emitter.rootScope>`.
        
        :return: the child scope
        :rtype: SubScope
        """


class Lbl(java.lang.Record, typing.Generic[N]):
    """
    Utility for defining and placing labels.
     
    
    These are used as control-flow targets, to specify the scope of local variables, and to specify
    the bounds of ``try-catch`` blocks.
     
    
    Labels, and the possibility of control flow, necessitate some care when trying to validate stack
    contents in generated code. Again, our goal is to find an acceptable syntax that also provides as
    much flexibility as possible for later maintenance and refactoring. The requirements:
     
    * Where code can jump, the stack at the jump target must agree with the resulting stack at the
    jump site.
    * If code is only reachable by a jump, then the stack there must be the resulting stack at the
    jump site.
    * If code is reachable by multiple jumps and/or fall-through, then the stack must agree along
    all those paths.
    
     
    
    To enforce these requirements, we encode thhe stack contents at a label's position in the same
    manner as we encode the emitter's current stack contents. Now, when a label is placed, there are
    two possibilities: 1) The code is reachable, in which case the label's and the emitter's stacks
    must agree. 2) The code is unreachable, in which case the emitter's incoming stack does not
    matter. Its resulting stack is the label's stack, and the code at this point is now presumed
    reachable. Because we would have collisions due to type erasure, these two cases are implemented
    in non-overloaded methods :meth:`place(Emitter, Lbl) <.place>` and :meth:`placeDead(Emitter, Lbl) <.placeDead>`.
     
    
    As an example, we show an ``if-else`` construct:
     
     
    var lblLess = em
            .emit(Op::iload, params.a)
            .emit(Op::ldc__i, 20)
            .emit(Op::if_icmple);
    var lblDone = lblLess.em()
            .emit(Op::ldc__i, 0xcafe)
            .emit(Op::goto_);
    return lblDone.em()
            .emit(Lbl::placeDead, lblLess.lbl())
            .emit(Op::ldc__i, 0xbabe)
            .emit(Lbl::place, lblDone.lbl())
            .emit(Op::ireturn, retReq);
     
     
    
    This would be equivalent to
     
     
    int myFunc(int a) {
        if (a <= 20) {
            return 0xbabe;
        }
        else {
            return 0xcafe;
        }
    }
     
     
    
    Note that we allow the Java compiler to infer the type of the label targeted by the
    :meth:`Op.if_icmple(Emitter) <Op.if_icmple>`. That form of the operator generates a label for us, and the
    inferred type of ``lblLess`` is an :obj:`LblEm```<Bot>``, representing the empty stack,
    because the conditional jump consumes both ints without pushing anything. The emitter in that
    returned tuple has the same stack contents, representing the fall-through case, and so we emit
    code into the false branch. To avoid falling through into the true branch, we emit an
    unconditional jump, i.e., :meth:`Op.goto_(Emitter) <Op.goto_>`, again taking advantage of Java's type
    inference to automatically derive the stack contents. Similar to the previous jump instruction,
    this returns a tuple, but this time, while the label still expects an empty stack, the emitter
    now has ``<N>:=``:obj:`Dead`, because any code emitted after this point would be
    unreachable. It is worth noting that *none* of the methods in :obj:`Op` accept a dead
    emitter. The only way (don't you dare cast it!) to resurrect the emitter is to place a label
    using :meth:`placeDead(Emitter, Lbl) <.placeDead>`. This is fitting, since we need to emit the true branch,
    so we place ``lblLess`` and emit the appropriate code. There is no need to jump after the
    true branch. We just allow both branches to flow into the same
    :meth:`Op.ireturn(Emitter, RetReq) <Op.ireturn>`. Thus, we place ``lblDone``, which is checked by the Java
    compiler to have matching stack contents, and finally emit the return.
     
    
    There is some manual bookkeeping here to ensure we use each previous emitter, but this is not too
    much worse than the manual bookkeeping needed to track label placement. In our experience, when
    we get that wrong, the compiler reports it as inconsistent, anyway. One drawback to using type
    inference is that the label's name does not appear in the jump instruction that targets it. We do
    not currently have a solution to that complaint.
    """

    class LblEm(java.lang.Record, typing.Generic[LN, N]):
        """
        A tuple providing both a (new) label and a resulting emitter
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, lbl: Lbl[LN], em: Emitter[N]) -> None:
            ...

        def em(self) -> Emitter[N]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def lbl(self) -> Lbl[LN]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, label: org.objectweb.asm.Label) -> None:
        ...

    @staticmethod
    def create() -> Lbl[N]:
        """
        Create a fresh label with any expected stack contents
         
        
        Using this to forward declare labels requires the user to explicate the expected stack, which
        may not be ideal, as it may require updating during refactoring. Consider using
        :meth:`Lbl.place(Emitter) <Lbl.place>` instead, which facilitates inference of the stack contents.
        
        :param N: the expected stack contents:return: the label
        :rtype: Lbl[N]
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def label(self) -> org.objectweb.asm.Label:
        ...

    @staticmethod
    @typing.overload
    def place(em: Emitter[N]) -> Lbl.LblEm[N, N]:
        """
        Generate a place a label where execution could already reach
         
        
        The returned label's stack will match this emitter's stack, since the code could be reached
        by multiple paths, likely fall-through and a jump to the returned label.
        
        :param N: the emitter's and the label's stack, i.e., as where the returned label is
                    referenced:param Emitter[N] em: the emitter
        :return: the label and emitter
        :rtype: Lbl.LblEm[N, N]
        """

    @staticmethod
    @typing.overload
    def place(em: Emitter[N], lbl: Lbl[N]) -> Emitter[N]:
        """
        Place the given label at a place where execution could already reach
         
        
        The emitter's stack and the label's stack must agree, since the code is reachable by multiple
        paths, likely fallthrough and a jump to the given label.
        
        :param N: the emitter's and the label's stack, i.e., as where the given label is referenced:param Emitter[N] em: the emitter
        :param Lbl[N] lbl: the label to place
        :return: the same emitter
        :rtype: Emitter[N]
        """

    @staticmethod
    def placeDead(em: Emitter[Emitter.Dead], lbl: Lbl[N]) -> Emitter[N]:
        """
        Place the given label at a place where execution could not otherwise reach
         
        
        The emitter must be dead, i.e., if it were to emit code, that code would be unreachable. By
        placing a referenced label at this place, the code following becomes reachable, and so the
        given emitter becomes alive again, having the stack that results from the referenced code. If
        the label has not yet been referenced, it must be forward declared with the expected stack.
        There is no equivalent of :meth:`place(Emitter) <.place>` for a dead emitter, because there is no way
        to know the resulting stack.
        
        :param N: the stack where the given label is referenced:param Emitter[Emitter.Dead] em: the emitter for otherwise-unreachable code
        :param Lbl[N] lbl: the label to place
        :return: the emitter, as reachable via the given label
        :rtype: Emitter[N]
        """

    def toString(self) -> str:
        ...


class Methods(java.lang.Object):
    """
    Utilities for invoking, declaring, and defining methods
     
    
    Method invocation requires a bit more kruft than we would like, it that kruft does have its
    benefits. (For an example of method definition, see :obj:`Emitter`.)
     
    
    Consider the example where we'd like to invoke :meth:`Integer.compare(int, int) <Integer.compare>`:
     
     
    var mdescIntegerCompare = MthDesc.derive(Integer::compare)
            .check(MthDesc::returns, Types.T_INT)
            .check(MthDesc::param, Types.T_INT)
            .check(MthDesc::param, Types.T_INT)
            .check(MthDesc::build);
    em
            .emit(Op::iload, params.a)
            .emit(Op::ldc__i, 20)
            .emit(Op::invokestatic, Types.refOf(Integer.class), "compare", mdescIntegerCompare,
                false)
            .step(Inv::takeArg)
            .step(Inv::takeArg)
            .step(Inv::ret)
            .emit(Op::ireturn, retReq);
     
     
    
    The first requirement (as in the case of defining a method) is to obtain the descriptor of the
    target method. There are a few ways to generate method descriptors, but the safest when calling a
    compiled or library method is to derive it from a reference to that method. There is no such
    thing as a "method literal" in Java, but there are method references, and we can match the types
    of those references. One wrinkle to this, however, is that we cannot distinguish auto-boxed
    parameters from those that genuinely accept the boxed type, i.e., both ``void f(int a)`` and
    ``void g(Integer b)`` can be made into references of type :obj:`Consumer```<Integer>``,
    because ``<int>`` is not a legal type signature. Thus, we require the user to call
    :meth:`MthDescCheckedBuilderP.check(BiFunction, Object) <MthDescCheckedBuilderP.check>` with, e.g.,
    :meth:`MthDesc.param(MthDescCheckedBuilderP, TInt) <MthDesc.param>` to specify that an :obj:`Integer` is
    actually an ``int``. However, we cannot check that the user did this correctly until runtime.
    Still, we are able to prevent a ``Hippo`` parameter from receiving an ``int``, and that
    is much better than nothing.
     
    
    Once we have the method descriptor, we can use it in invocation operators, e.g.,
    :meth:`Op.invokestatic(Emitter, TRef, String, MthDesc, boolean) <Op.invokestatic>`. In an of itself, this operator
    does *not* consume nor push anything to the stack. Instead, it returns an :obj:`Inv`
    object, which facilitates the popping and checking of each parameter, followed by the pushing of
    the returned value, if non-void. It is not obvious to us (if such a technique even exists) to pop
    an arbitrary number of entries from ``<N>`` in a single method. Instead, we have to treat
    Java's type checker as a sort of automaton that we can step, one pop at a time, by invoking a
    method. This method is :meth:`Inv.takeArg(Inv) <Inv.takeArg>`, which for chaining purposes, is most easily
    invoked using the aptly-named :meth:`Inv.step(Function) <Inv.step>` instance method. We would rather not
    have to do it this way, as it is unnecessary kruft that may also have a run-time cost. One
    benefit, however, is that if the arguments on the stack do not match the parameters required by
    the descriptor, the first mismatched ``takeArg`` line (corresponding to the right-most
    mismatched parameter) will fail to compile, and so we know *which* argument is incorrect.
    Finally, we must do one last step to to push the return value, e.g., :meth:`Inv.ret(Inv) <Inv.ret>`. This
    will check that all parameters have been popped, and then push a value of the descriptor's return
    type. It returns the resulting emitter. For a void method, use :meth:`Inv.retVoid(Inv) <Inv.retVoid>` to avert
    the push. Unfortunately, ``ret`` is still permitted, but at least downstream operators are
    likely to fail, since nothing should consume :obj:`TVoid`.
    """

    class MthDesc(java.lang.Record, typing.Generic[MR, N]):
        """
        A method descriptor
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, desc: typing.Union[java.lang.String, str]) -> None:
            ...

        @staticmethod
        def build(builder: Methods.MthDescCheckedBuilderP[MR, N, Methods.CkBot]) -> Methods.MthDesc[MR, N]:
            """
            Finish building the method descriptor (checked)
             
            
            This cannot be invoked until the (boxed) parameter types remaining is empty
            
            :param MR: the method return type:param N: the actual parameter types, all specified:param Methods.MthDescCheckedBuilderP[MR, N, Methods.CkBot] builder: the builder with no remaining boxed (unspecified) parameter types
            :return: the method descriptor
            :rtype: Methods.MthDesc[MR, N]
            """

        @staticmethod
        @typing.overload
        def derive(func: java.util.function.Function[A0, R]) -> Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkBot, A0]]:
            """
            Begin building a method descriptor derived from the given method reference
             
            
            NOTE: This is imperfect because method refs allow ``? super`` for the return type and
            ``? extends`` for each parameter. Furthermore, primitives must be boxed, and so we
            can't distinguish primitive parameters from their boxed types. Still, this is better than
            nothing. For an example of this, see :obj:`Methods` or :obj:`Emitter`.
            
            :param R: the return type, boxed:param A0: the first argument type, boxed:param java.util.function.Function[A0, R] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkBot, A0]]
            """

        @staticmethod
        @typing.overload
        def derive(func: java.util.function.BiFunction[A0, A1, R]) -> Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A1], A0]]:
            """
            Begin building a method descriptor derived from the given method reference
            
            :param R: the return type, boxed:param A0: the first argument type, boxed:param A1: another argument type, boxed:param java.util.function.BiFunction[A0, A1, R] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A1], A0]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def derive(func: Emitter.A3Function[A0, A1, A2, R]) -> Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A2], A1], A0]]:
            """
            Begin building a method descriptor derived from the given method reference
            
            :param R: the return type, boxed:param A0: the first argument type, boxed:param A1: another argument type, boxed:param A2: another argument type, boxed:param Emitter.A3Function[A0, A1, A2, R] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A2], A1], A0]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def derive(func: Emitter.A3Consumer[A0, A1, A2]) -> Methods.MthDescCheckedBuilderR[java.lang.Void, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A2], A1], A0]]:
            """
            Begin building a method descriptor derived from the given method reference
            
            :param A0: the first argument type, boxed:param A1: another argument type, boxed:param A2: another argument type, boxed:param Emitter.A3Consumer[A0, A1, A2] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[java.lang.Void, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A2], A1], A0]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def derive(func: Emitter.A4Function[A0, A1, A2, A3, R]) -> Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A3], A2], A1], A0]]:
            """
            Begin building a method descriptor derived from the given method reference
            
            :param R: the return type, boxed:param A0: the first argument type, boxed:param A1: another argument type, boxed:param A2: another argument type, boxed:param A3: another argument type, boxed:param Emitter.A4Function[A0, A1, A2, A3, R] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A3], A2], A1], A0]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def derive(func: Emitter.A4Consumer[A0, A1, A2, A3]) -> Methods.MthDescCheckedBuilderR[java.lang.Void, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A3], A2], A1], A0]]:
            """
            Begin building a method descriptor derived from the given method reference
            
            :param A0: the first argument type, boxed:param A1: another argument type, boxed:param A2: another argument type, boxed:param A3: another argument type, boxed:param Emitter.A4Consumer[A0, A1, A2, A3] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[java.lang.Void, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A3], A2], A1], A0]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def derive(func: Emitter.A5Function[A0, A1, A2, A3, A4, R]) -> Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A4], A3], A2], A1], A0]]:
            """
            Begin building a method descriptor derived from the given method reference
            
            :param R: the return type, boxed:param A0: the first argument type, boxed:param A1: another argument type, boxed:param A2: another argument type, boxed:param A3: another argument type, boxed:param Emitter.A5Function[A0, A1, A2, A3, A4, R] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A4], A3], A2], A1], A0]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def derive(func: Emitter.A7Function[A0, A1, A2, A3, A4, A5, A6, R]) -> Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A6], A5], A4], A3], A2], A1], A0]]:
            """
            Begin building a method descriptor derived from the given method reference
            
            :param R: the return type, boxed:param A0: the first argument type, boxed:param A1: another argument type, boxed:param A2: another argument type, boxed:param A3: another argument type, boxed:param Emitter.A7Function[A0, A1, A2, A3, A4, A5, A6, R] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A6], A5], A4], A3], A2], A1], A0]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def deriveInst(func: java.util.function.BiFunction[A0, A1, R]) -> Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkBot, A1]]:
            """
            Begin building an instance method descriptor derived from the given method reference
             
            
            This implicitly drops the object reference that is normally included in static references
            to instance methods.
            
            :param R: the return type, boxed:param A0: the object reference type, dropped:param A1: another argument type, boxed:param java.util.function.BiFunction[A0, A1, R] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[R, Methods.CkEnt[Methods.CkBot, A1]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def deriveInst(func: Emitter.A3Consumer[A0, A1, A2]) -> Methods.MthDescCheckedBuilderR[java.lang.Void, Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A2], A1]]:
            """
            Begin building a method descriptor derived from the given method reference
            
            :param A0: the object type, dropped:param A1: another argument type, boxed:param A2: another argument type, boxed:param Emitter.A3Consumer[A0, A1, A2] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[java.lang.Void, Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A2], A1]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        @staticmethod
        @typing.overload
        def deriveInst(func: Emitter.A4Consumer[A0, A1, A2, A3]) -> Methods.MthDescCheckedBuilderR[java.lang.Void, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A3], A2], A1]]:
            """
            Begin building an instance method descriptor derived from the given method reference
            
            :param A0: the object reference:param A1: another argument type, boxed:param A2: another argument type, boxed:param A3: another argument type, boxed:param Emitter.A4Consumer[A0, A1, A2, A3] func: the method reference
            :return: the checked builder
            :rtype: Methods.MthDescCheckedBuilderR[java.lang.Void, Methods.CkEnt[Methods.CkEnt[Methods.CkEnt[Methods.CkBot, A3], A2], A1]]
            
            .. seealso::
            
                | :obj:`.derive(Function)`
            """

        def desc(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TRef[P]) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TRef[P]], CN1]:
            """
            Specify a reference parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param P: the parameter type:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TRef[P] paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TRef[P]], CN1]
            """

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TBool) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]:
            """
            Specify a boolean parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TBool paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]
            """

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TByte) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]:
            """
            Specify a byte parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TByte paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]
            """

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TChar) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]:
            """
            Specify a char parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TChar paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]
            """

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TShort) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]:
            """
            Specify a short parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TShort paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]
            """

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TInt) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]:
            """
            Specify an int parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TInt paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TInt], CN1]
            """

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TLong) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TLong], CN1]:
            """
            Specify a long parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TLong paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TLong], CN1]
            """

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TFloat) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TFloat], CN1]:
            """
            Specify a float parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TFloat paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TFloat], CN1]
            """

        @staticmethod
        @typing.overload
        def param(builder: Methods.MthDescCheckedBuilderP[MR, N, CN0], paramType: Types.TDouble) -> Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TDouble], CN1]:
            """
            Specify a double parameter type
            
            :param MR: the method return type:param N: the actual parameter types specified so far:param CN1: the boxed parameter types remaining:param CN0: the boxed type for the parameter whose type is being specified:param Methods.MthDescCheckedBuilderP[MR, N, CN0] builder: the builder
            :param Types.TDouble paramType: the specified parameter type
            :return: the builder
            :rtype: Methods.MthDescCheckedBuilderP[MR, Emitter.Ent[N, Types.TDouble], CN1]
            """

        @staticmethod
        def reflect(method: java.lang.reflect.Method) -> Methods.MthDesc[typing.Any, typing.Any]:
            """
            Obtain a method descriptor for a reflected method of unknown or unspecified type
             
            
            All bets are off for static type checking, but this at least obtains the descriptor as a
            string at runtime.
            
            :param java.lang.reflect.Method method: the method
            :return: the untyped descriptor
            :rtype: Methods.MthDesc[typing.Any, typing.Any]
            """

        @staticmethod
        @typing.overload
        def returns(retType: MR) -> Methods.MthDescBuilder[MR, Emitter.Bot]:
            """
            Begin building a method descriptor that returns the given (machine) type
            
            :param MR: the return type:param MR retType: the return type
            :return: the builder
            :rtype: Methods.MthDescBuilder[MR, Emitter.Bot]
            """

        @staticmethod
        @typing.overload
        def returns(retType: Types.SType) -> Methods.MthDescBuilder[Types.TInt, Emitter.Bot]:
            """
            Begin building a method descriptor that returns the given (source) type
            
            :param Types.SType retType: the return type
            :return: the builder
            :rtype: Methods.MthDescBuilder[Types.TInt, Emitter.Bot]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[R, CN], retType: Types.TRef[R]) -> Methods.MthDescCheckedBuilderP[Types.TRef[R], Emitter.Bot, CN]:
            """
            Specify the return type of a checked builder
             
            
            This may not be used for primitive types, but can be used if the method genuinely returns
            the boxed type.
            
            :param R: the (perhaps boxed) return type:param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[R, CN] builder: the (stage 1) builder
            :param Types.TRef[R] retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TRef[R], Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Void, CN], retType: Types.TVoid) -> Methods.MthDescCheckedBuilderP[Types.TVoid, Emitter.Bot, CN]:
            """
            Specify a void return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Void, CN] builder: the (stage 1) builder
            :param Types.TVoid retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TVoid, Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Boolean, CN], retType: Types.TBool) -> Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]:
            """
            Specify a boolean return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Boolean, CN] builder: the (stage 1) builder
            :param Types.TBool retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Boolean, CN], retType: Types.TByte) -> Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]:
            """
            Specify a byte return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Boolean, CN] builder: the (stage 1) builder
            :param Types.TByte retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Boolean, CN], retType: Types.TChar) -> Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]:
            """
            Specify a char return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Boolean, CN] builder: the (stage 1) builder
            :param Types.TChar retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Boolean, CN], retType: Types.TShort) -> Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]:
            """
            Specify a short return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Boolean, CN] builder: the (stage 1) builder
            :param Types.TShort retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Integer, CN], retType: Types.TInt) -> Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]:
            """
            Specify an int return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Integer, CN] builder: the (stage 1) builder
            :param Types.TInt retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TInt, Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Long, CN], retType: Types.TLong) -> Methods.MthDescCheckedBuilderP[Types.TLong, Emitter.Bot, CN]:
            """
            Specify a long return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Long, CN] builder: the (stage 1) builder
            :param Types.TLong retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TLong, Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Integer, CN], retType: Types.TFloat) -> Methods.MthDescCheckedBuilderP[Types.TFloat, Emitter.Bot, CN]:
            """
            Specify a float return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Integer, CN] builder: the (stage 1) builder
            :param Types.TFloat retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TFloat, Emitter.Bot, CN]
            """

        @staticmethod
        @typing.overload
        def returns(builder: Methods.MthDescCheckedBuilderR[java.lang.Long, CN], retType: Types.TDouble) -> Methods.MthDescCheckedBuilderP[Types.TDouble, Emitter.Bot, CN]:
            """
            Specify a double return type for a checked builder
            
            :param CN: the boxed parameter types for later checking:param Methods.MthDescCheckedBuilderR[java.lang.Long, CN] builder: the (stage 1) builder
            :param Types.TDouble retType: the return type
            :return: the (stage 2) builder
            :rtype: Methods.MthDescCheckedBuilderP[Types.TDouble, Emitter.Bot, CN]
            """

        def toString(self) -> str:
            ...


    class MthDescBuilder(java.lang.Object, typing.Generic[MR, N]):
        """
        An unchecked builder of a method descriptor
        """

        class_: typing.ClassVar[java.lang.Class]

        def build(self) -> Methods.MthDesc[MR, N]:
            """
            Finished building the method descriptor
            
            :return: the method descriptor
            :rtype: Methods.MthDesc[MR, N]
            """

        @typing.overload
        def param(self, paramType: P) -> Methods.MthDescBuilder[MR, Emitter.Ent[N, P]]:
            """
            Add a parameter (to the right)
            
            :param P: the type of the parameter:param P paramType: the type of the parameter
            :return: the builder
            :rtype: Methods.MthDescBuilder[MR, Emitter.Ent[N, P]]
            """

        @typing.overload
        def param(self, paramType: Types.SType) -> Methods.MthDescBuilder[MR, Emitter.Ent[N, Types.TInt]]:
            """
            Add a parameter (to the right)
            
            :param Types.SType paramType: the (source) type of the parameter
            :return: the builder
            :rtype: Methods.MthDescBuilder[MR, Emitter.Ent[N, Types.TInt]]
            """


    class CkNext(java.lang.Object):
        """
        The analog of :obj:`Next`, but for unspecified parameter types to be checked
        """

        class_: typing.ClassVar[java.lang.Class]


    class CkEnt(Methods.CkNext, typing.Generic[N, T]):
        """
        The analog of :obj:`Ent`, but for :obj:`CkNext`
        """

        class_: typing.ClassVar[java.lang.Class]


    class CkBot(Methods.CkNext):
        """
        The analog of :obj:`Bot`, but for :obj:`CkNext`
        """

        class_: typing.ClassVar[java.lang.Class]


    class MthDescCheckedBuilderR(java.lang.Object, typing.Generic[CR, CN]):
        """
        A checked builder (stage 1) of a method descriptor
         
        
        Only :meth:`MthDesc.returns(BType) <MthDesc.returns>` or similar may be used on this stage 1 builder.
        """

        class_: typing.ClassVar[java.lang.Class]

        def check(self, func: java.util.function.BiFunction[Methods.MthDescCheckedBuilderR[CR, CN], A1, R], arg1: A1) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param A1: the first argument type of ``func``:param java.util.function.BiFunction[Methods.MthDescCheckedBuilderR[CR, CN], A1, R] func: the method to invoke
            :param A1 arg1: the first argument to ``func``
            :return: the return value from ``func``
            :rtype: R
            """


    class MthDescCheckedBuilderP(java.lang.Object, typing.Generic[MR, N, CN]):
        """
        A checked builder (stage 2) of a method descriptor
         
        
        Only :meth:`MthDesc.param(MthDescCheckedBuilderP, TRef) <MthDesc.param>` or similar and
        :meth:`MthDesc.build(MthDescCheckedBuilderP) <MthDesc.build>` may be used on this stage 2 builder.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def check(self, func: java.util.function.Function[Methods.MthDescCheckedBuilderP[MR, N, CN], R]) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param java.util.function.Function[Methods.MthDescCheckedBuilderP[MR, N, CN], R] func: the method to invoke
            :return: the return value from ``func``
            :rtype: R
            """

        @typing.overload
        def check(self, func: java.util.function.BiFunction[Methods.MthDescCheckedBuilderP[MR, N, CN], A1, R], arg1: A1) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param A1: the first argument type of ``func``:param java.util.function.BiFunction[Methods.MthDescCheckedBuilderP[MR, N, CN], A1, R] func: the method to invoke
            :param A1 arg1: the first argument to ``func``
            :return: the return value from ``func``
            :rtype: R
            """


    class Inv(java.lang.Record, typing.Generic[MR, SN, MN]):
        """
        An invocation object to facilitate the checked popping of arguments for a static method
        invocation and the final push of its returned value.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, em: Emitter[SN]) -> None:
            ...

        def em(self) -> Emitter[SN]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        @staticmethod
        def ret(inv: Methods.Inv[MR, SN, Emitter.Bot]) -> Emitter[Emitter.Ent[SN, MR]]:
            """
            Finish checking an invocation of a static method
            
            :param MR: the return type:param SN: the stack contents before pushing the returned result:param Methods.Inv[MR, SN, Emitter.Bot] inv: the invocation object
            :return: the emitter typed with the resulting stack, i.e., having pushed the returned
                    value
            :rtype: Emitter[Emitter.Ent[SN, MR]]
            """

        @staticmethod
        def retQ(inv: Methods.Inv[typing.Any, SN, typing.Any], returnType: RT) -> Emitter[Emitter.Ent[SN, RT]]:
            """
            Finish invocation of a static method without checking
             
            
            NOTE: This should only be used with :meth:`MthDesc.reflect(Method) <MthDesc.reflect>`.
            
            :param RT: the asserted return type:param SN: the stack contents before pushing the returned result:param Methods.Inv[typing.Any, SN, typing.Any] inv: the invocation object
            :param RT returnType: the asserted return type
            :return: the emitter typed with the resulting stack, i.e., having pushed the returned
                    value
            :rtype: Emitter[Emitter.Ent[SN, RT]]
            """

        @staticmethod
        def retQVoid(inv: Methods.Inv[typing.Any, SN, typing.Any]) -> Emitter[SN]:
            """
            Finish an invocation of a static void method without checking
             
            
            NOTE: This should only be used with :meth:`MthDesc.reflect(Method) <MthDesc.reflect>`.
            
            :param SN: the stack contents after the invocation:param Methods.Inv[typing.Any, SN, typing.Any] inv: the invocation object
            :return: the emitter typed with the resulting stack
            :rtype: Emitter[SN]
            """

        @staticmethod
        def retVoid(inv: Methods.Inv[Types.TVoid, SN, Emitter.Bot]) -> Emitter[SN]:
            """
            Finish checking an invocation of a static void method
            
            :param SN: the stack contents after the invocation:param Methods.Inv[Types.TVoid, SN, Emitter.Bot] inv: the invocation object
            :return: the emitter typed with the resulting stack
            :rtype: Emitter[SN]
            """

        @typing.overload
        def step(self, func: java.util.function.Function[Methods.Inv[MR, SN, MN], R]) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param java.util.function.Function[Methods.Inv[MR, SN, MN], R] func: the method to invoke
            :return: the return value from ``func``
            :rtype: R
            """

        @typing.overload
        def step(self, func: java.util.function.BiFunction[Methods.Inv[MR, SN, MN], A1, R], arg1: A1) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param A1: the first argument type of ``func``:param java.util.function.BiFunction[Methods.Inv[MR, SN, MN], A1, R] func: the method to invoke
            :param A1 arg1: the first argument to ``func``
            :return: the return value from ``func``
            :rtype: R
            """

        @staticmethod
        @typing.overload
        def takeArg(inv: Methods.Inv[MR, SN0, MN0]) -> Methods.Inv[MR, SN1, MN1]:
            """
            Pop an argument and match/check it against the next (right-most unmatched) parameter
             
            
            NOTE: This will not work for polymorphic arguments. For ref-typed arguments, use
            :meth:`takeRefArg(Inv) <.takeRefArg>`.
            
            :param P1: the parameter type popped from the remaining parameter types:param A1: the argument type popped from the stack contents:param MR: the return type:param MN1: the new remaining parameter types:param MN0: the current parameter types having the popped parameter on top:param SN1: the new remaining stack contents:param SN0: the current stack contents having the popped argument on top:param Methods.Inv[MR, SN0, MN0] inv: the invocation object
            :return: the invocation object with remaining parameters and stack contents
            :rtype: Methods.Inv[MR, SN1, MN1]
            """

        @staticmethod
        @typing.overload
        def takeArg(inv: Methods.ObjInv[MR, OT, SN0, MN0]) -> Methods.ObjInv[MR, OT, SN1, MN1]:
            """
            Pop an argument and match/check it against the next (right-most unmatched) parameter
             
            
            NOTE: This will not work for polymorphic arguments. For ref-typed arguments, use
            :meth:`takeRefArg(ObjInv) <.takeRefArg>`.
            
            :param OT: the method's owning type:param P1: the parameter type popped from the remaining parameter types:param A1: the argument type popped from the stack contents:param MR: the return type:param MN1: the new remaining parameter types:param MN0: the current parameter types having the popped parameter on top:param SN1: the new remaining stack contents:param SN0: the current stack contents having the popped argument on top:param Methods.ObjInv[MR, OT, SN0, MN0] inv: the invocation object
            :return: the invocation object with remaining parameters and stack contents
            :rtype: Methods.ObjInv[MR, OT, SN1, MN1]
            """

        @staticmethod
        def takeObjRef(inv: Methods.ObjInv[MR, OT, SN0, Emitter.Bot]) -> Methods.Inv[MR, SN1, Emitter.Bot]:
            """
            Pop the object reference from the stack and check it against the owning type
             
            
            This must be used, but only once the parameter type list is empty
            
            :param OT: the method's owning type:param MR: the return type:param SN1: the new remaining stack contents:param SN0: the current stack contents having popped the reference on top:param Methods.ObjInv[MR, OT, SN0, Emitter.Bot] inv: the invocation object
            :return: the invocation object with remaining stack contents
            :rtype: Methods.Inv[MR, SN1, Emitter.Bot]
            """

        @staticmethod
        @typing.overload
        def takeQArg(inv: Methods.Inv[MR, SN0, typing.Any]) -> Methods.Inv[MR, SN1, typing.Any]:
            """
            Pop an argument and a parameter without checking
             
            
            NOTE: This should only be used with :meth:`MthDesc.reflect(Method) <MthDesc.reflect>`. When dealing with a
            parameter list whose length is only known at runtime, recursion should be favored, so
            that each argument pushed by the emitter is provably paired with a parameter denoted by
            calling this method.
            
            :param MR: the return type:param SN1: the new remaining stack contents:param SN0: the current stack contents having the popped argument on top:param Methods.Inv[MR, SN0, typing.Any] inv: the invocation object
            :return: the invocation object with remaining parameters and stack contents
            :rtype: Methods.Inv[MR, SN1, typing.Any]
            """

        @staticmethod
        @typing.overload
        def takeQArg(inv: Methods.ObjInv[MR, OT, SN0, typing.Any]) -> Methods.ObjInv[MR, OT, SN1, typing.Any]:
            """
            Pop an argument and a parameter without checking
             
            
            NOTE: This should only be used with :meth:`MthDesc.reflect(Method) <MthDesc.reflect>`. When dealing with a
            parameter list whose length is only known at runtime, recursion should be favored, so
            that each argument pushed by the emitter is provably paired with a parameter denoted by
            calling this method.
            
            :param OT: the method's owning type:param MR: the return type:param SN1: the new remaining stack contents:param SN0: the current stack contents having the popped argument on top:param Methods.ObjInv[MR, OT, SN0, typing.Any] inv: the invocation object
            :return: the invocation object with remaining parameters and stack contents
            :rtype: Methods.ObjInv[MR, OT, SN1, typing.Any]
            """

        @staticmethod
        def takeQObjRef(inv: Methods.ObjInv[MR, OT, SN0, typing.Any]) -> Methods.Inv[MR, SN1, Emitter.Bot]:
            """
            Pop the object reference from the stack without checking it
             
            
            NOTE: This should only be used with :meth:`MthDesc.reflect(Method) <MthDesc.reflect>`. This must be used,
            but only when sufficient arguments have been popped to satisfy the reflected parameters.
            It is up to the caller to know how many arguments are expected.
            
            :param OT: the method's owning type:param MR: the return type:param SN1: the new remaining stack contents:param SN0: the current stack contents having popped the reference on top:param Methods.ObjInv[MR, OT, SN0, typing.Any] inv: the invocation object
            :return: the invocation object with remaining stack contents
            :rtype: Methods.Inv[MR, SN1, Emitter.Bot]
            """

        @staticmethod
        @typing.overload
        def takeRefArg(inv: Methods.Inv[MR, SN0, MN0]) -> Methods.Inv[MR, SN1, MN1]:
            """
            Pop a polymorphic reference argument and match/check it against the next (right-most
            unmatched parameter)
            
            :param PT: the parameter's object type:param AT: the argument's object type:param P1: the parameter type popped from the remaining parameter types:param A1: the argument type popped from the stack contents:param MR: the return type:param MN1: the new remaining parameter types:param MN0: the current parameter types having the popped parameter on top:param SN1: the new remaining stack contents:param SN0: the current stack contents having the popped argument on top:param Methods.Inv[MR, SN0, MN0] inv: the invocation object
            :return: the invocation object with remaining parameters and stack contents
            :rtype: Methods.Inv[MR, SN1, MN1]
            """

        @staticmethod
        @typing.overload
        def takeRefArg(inv: Methods.ObjInv[MR, OT, SN0, MN0]) -> Methods.ObjInv[MR, OT, SN1, MN1]:
            """
            Pop a polymorphic reference argument and match/check it against the next (right-most
            unmatched parameter)
            
            :param OT: the method's owning type:param PT: the parameter's object type:param AT: the argument's object type:param P1: the parameter type popped from the remaining parameter types:param A1: the argument type popped from the stack contents:param MR: the return type:param MN1: the new remaining parameter types:param MN0: the current parameter types having the popped parameter on top:param SN1: the new remaining stack contents:param SN0: the current stack contents having the popped argument on top:param Methods.ObjInv[MR, OT, SN0, MN0] inv: the invocation object
            :return: the invocation object with remaining parameters and stack contents
            :rtype: Methods.ObjInv[MR, OT, SN1, MN1]
            """

        def toString(self) -> str:
            ...


    class ObjInv(java.lang.Record, typing.Generic[MR, OT, SN, MN]):
        """
        An invocation object to facilitate the checked popping of arguments for an instance method
        invocation and the final push of its returned value.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, em: Emitter[SN]) -> None:
            ...

        def em(self) -> Emitter[SN]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def step(self, func: java.util.function.Function[Methods.ObjInv[MR, OT, SN, MN], R]) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param java.util.function.Function[Methods.ObjInv[MR, OT, SN, MN], R] func: the method to invoke
            :return: the return value from ``func``
            :rtype: R
            """

        def toString(self) -> str:
            ...


    class MthParam(java.lang.Record, typing.Generic[T]):
        """
        A defined parameter, which was checked against a method descriptor
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, type: T, name: typing.Union[java.lang.String, str], receiver: java.util.function.Consumer[Local[T]]) -> None:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def receiver(self) -> java.util.function.Consumer[Local[T]]:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> T:
            ...


    class Def(java.lang.Record, typing.Generic[MR, N]):
        """
        A static method definition (builder)
        """

        class ParamFunction(java.lang.Object, typing.Generic[A0, T1, R]):
            """
            A method reference for defining a parameter
            """

            class_: typing.ClassVar[java.lang.Class]

            def apply(self, arg0: A0, type: T1, name: typing.Union[java.lang.String, str], receiver: java.util.function.Consumer[Local[T1]]) -> R:
                ...


        class DoneFunction(java.lang.Object, typing.Generic[A0, R]):
            """
            A method reference for finishing a static method definition
            """

            class_: typing.ClassVar[java.lang.Class]

            def apply(self, arg: A0) -> R:
                ...


        class ThisFunction(java.lang.Object, typing.Generic[A0, OT, R]):
            """
            A method reference for finishing an instance method definition
            """

            class_: typing.ClassVar[java.lang.Class]

            def apply(self, arg0: A0, type: Types.TRef[OT], receiver: java.util.function.Consumer[Local[Types.TRef[OT]]]) -> R:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, em: Emitter[Emitter.Bot], params: java.util.List[Methods.MthParam[typing.Any]]) -> None:
            ...

        @staticmethod
        @typing.overload
        def done(mdef: Methods.Def[MR, Emitter.Bot]) -> Methods.RetReqEm[MR]:
            """
            Finish defining a static method and begin emitting bytecode
            
            :param MR: the return type:param Methods.Def[MR, Emitter.Bot] mdef: the method definition
            :return: the return request and emitter typed with an empty stack
            :rtype: Methods.RetReqEm[MR]
            """

        @staticmethod
        @typing.overload
        def done(mdef: Methods.ObjDef[MR, OT, Emitter.Bot], type: Types.TRef[OT], receiver: java.util.function.Consumer[Local[Types.TRef[OT]]]) -> Methods.RetReqEm[MR]:
            """
            Finish defining an instance method and begin emitting bytecode
            
            :param MR: the return type:param OT: the owning type:param Methods.ObjDef[MR, OT, Emitter.Bot] mdef: the method definition
            :param Types.TRef[OT] type: the owning type (for this ``this``) parameter
            :param java.util.function.Consumer[Local[Types.TRef[OT]]] receiver: a consumer to accept the declared ``this`` local handle
            :return: the return request and emitter typed with an empty stack
            :rtype: Methods.RetReqEm[MR]
            """

        def em(self) -> Emitter[Emitter.Bot]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        @staticmethod
        @typing.overload
        def param(mdef: Methods.Def[MR, N0], type: T1, name: typing.Union[java.lang.String, str], receiver: java.util.function.Consumer[Local[T1]]) -> Methods.Def[MR, N1]:
            """
            Define a parameter for a static method
            
            :param MR: the return type:param T1: the parameter type:param N1: the remaining parameters still requiring definition:param N0: the parameters remaining and the one being defined:param Methods.Def[MR, N0] mdef: the method definition
            :param T1 type: the parameter type
            :param java.lang.String or str name: the name
            :param java.util.function.Consumer[Local[T1]] receiver: a consumer to accept the declared local variable handle
            :return: the method definition
            :rtype: Methods.Def[MR, N1]
            """

        @staticmethod
        @typing.overload
        def param(mdef: Methods.ObjDef[MR, OT, N0], type: T1, name: typing.Union[java.lang.String, str], receiver: java.util.function.Consumer[Local[T1]]) -> Methods.ObjDef[MR, OT, N1]:
            """
            Define a parameter for an instance method
            
            :param MR: the return type:param OT: the owning type:param T1: the parameter type:param N1: the remaining parameters still requiring definition:param N0: the parameters remaining and the one being defined:param Methods.ObjDef[MR, OT, N0] mdef: the method definition
            :param T1 type: the parameter type
            :param java.lang.String or str name: the name
            :param java.util.function.Consumer[Local[T1]] receiver: a consumer to accept the declared local variable handle
            :return: the method definition
            :rtype: Methods.ObjDef[MR, OT, N1]
            """

        @typing.overload
        def param(self, func: Methods.Def.ParamFunction[Methods.Def[MR, N], T1, R], type: T1, name: typing.Union[java.lang.String, str], receiver: java.util.function.Consumer[Local[T1]]) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param T1: the parameter type:param Methods.Def.ParamFunction[Methods.Def[MR, N], T1, R] func: the static method reference that actually processes the parameter
            :param T1 type: the parameter type
            :param java.lang.String or str name: the name
            :param java.util.function.Consumer[Local[T1]] receiver: the receiver
            :return: the return value from ``func``
            :rtype: R
            """

        @typing.overload
        def param(self, func: Methods.Def.DoneFunction[Methods.Def[MR, N], R]) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param Methods.Def.DoneFunction[Methods.Def[MR, N], R] func: the static method reference
            :return: the return value from ``func``
            :rtype: R
            """

        def params(self) -> java.util.List[Methods.MthParam[typing.Any]]:
            ...

        def toString(self) -> str:
            ...


    class ObjDef(java.lang.Record, typing.Generic[MR, OT, N]):
        """
        An instance method definition (builder)
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, em: Emitter[Emitter.Bot], params: java.util.List[Methods.MthParam[typing.Any]]) -> None:
            ...

        def em(self) -> Emitter[Emitter.Bot]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        @typing.overload
        def param(self, func: Methods.Def.ParamFunction[Methods.ObjDef[MR, OT, N], T1, R], type: T1, name: typing.Union[java.lang.String, str], receiver: java.util.function.Consumer[Local[T1]]) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param T1: the parameter type:param Methods.Def.ParamFunction[Methods.ObjDef[MR, OT, N], T1, R] func: the static method reference that actually processes the parameter
            :param T1 type: the parameter type
            :param java.lang.String or str name: the name
            :param java.util.function.Consumer[Local[T1]] receiver: the receiver
            :return: the return value from ``func``
            :rtype: R
            """

        @typing.overload
        def param(self, func: Methods.Def.ThisFunction[Methods.ObjDef[MR, OT, N], OT, R], type: Types.TRef[OT], receiver: java.util.function.Consumer[Local[Types.TRef[OT]]]) -> R:
            """
            A syntactic workaround for static method chaining
            
            :param R: the return type of ``func``:param Methods.Def.ThisFunction[Methods.ObjDef[MR, OT, N], OT, R] func: the static method reference that actually processes the parameter
            :param Types.TRef[OT] type: the ``this`` type
            :param java.util.function.Consumer[Local[Types.TRef[OT]]] receiver: the receiver
            :return: the return value from ``func``
            :rtype: R
            """

        def params(self) -> java.util.List[Methods.MthParam[typing.Any]]:
            ...

        def toString(self) -> str:
            ...


    class RetReq(java.lang.Record, typing.Generic[T]):
        """
        A return request
         
        
        This is just a witness to the required return type of a method. Technically, there's nothing
        that prevents a user from passing a request meant for one method into, e.g.,
        :meth:`Op.return_(Emitter, RetReq) <Op.return_>` for bytecode emitted into another, but such should be
        unlikely to happen accidentally.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self) -> None:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class RetReqEm(java.lang.Record, typing.Generic[T]):
        """
        A tuple of return request and emitter with empty stack
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, ret: Methods.RetReq[T], em: Emitter[Emitter.Bot]) -> None:
            ...

        def em(self) -> Emitter[Emitter.Bot]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def ret(self) -> Methods.RetReq[T]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]


class Misc(java.lang.Object):
    """
    Miscellaneous utilities
    """

    class TryCatchBlock(java.lang.Record, typing.Generic[T, N]):
        """
        A handle to an (incomplete) ``try-catch`` block
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, end: Lbl[N], handler: Lbl[Emitter.Ent[N, Types.TRef[T]]], em: Emitter[N]) -> None:
            ...

        def em(self) -> Emitter[N]:
            ...

        def end(self) -> Lbl[N]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def handler(self) -> Lbl[Emitter.Ent[N, Types.TRef[T]]]:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def cast1(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, T1]]:
        """
        Fix the top of the stack, so it doesn't "extend" :obj:`Ent`, but just is :obj:`Ent`.
         
        
        This may be necessary when a code generating method is typed to pop then push something of
        the same type, but in some conditions actually just leaves the stack as is.
        
        :param T1: the type at the top of the stack:param N1: the tail of the stack:param N0: the full stack:param Emitter[N0] em: the emitter
        :return: the same emitter
        :rtype: Emitter[Emitter.Ent[N1, T1]]
        """

    @staticmethod
    def finish(em: Emitter[Emitter.Dead]) -> java.lang.Void:
        """
        Finish emitting bytecode
         
        
        This is where we invoke :meth:`MethodVisitor.visitMaxs(int, int) <MethodVisitor.visitMaxs>`. Frameworks that require
        bytecode generation can try to enforce this by requiring bytecode generation methods to
        return :obj:`Void`. Sure, a user can just return null, but this will at least remind them
        that they should call this method, as convention is to use a pattern like:
         
         
        return em
                .emit(Op::ldc__i, 0)
                .emit(Op::ireturn, retReq)
                .emit(Misc::finish);
         
         
        
        A user of this pattern would be reminded were ``finish`` missing. Provided the generation
        method returns :obj:`Void`, this pattern should compile.
        
        :param Emitter[Emitter.Dead] em: the emittter
        :return: null
        :rtype: java.lang.Void
        """

    @staticmethod
    def lineNumber(em: Emitter[N], number: typing.Union[jpype.JInt, int]) -> Emitter[N]:
        """
        Place a line number
        
        :param N: any live stack:param Emitter[N] em: the emitter
        :param jpype.JInt or int number: the (non zero) line number
        :return: the emitter
        :rtype: Emitter[N]
        """

    @staticmethod
    def tryCatch(em: Emitter[N], end: Lbl[N], handler: Lbl[Emitter.Ent[N, Types.TRef[T]]], type: Types.TRef[T]) -> Misc.TryCatchBlock[T, N]:
        """
        Start a try-catch block
         
        
        This places a label to mark the start of the ``try`` block. The user must provide labels
        for the end and the handler. Note that the stack contents at the handler must be the same as
        at the bounds, but with the exception type pushed. While this can check that the labels are
        correctly placed, it cannot check if placement is altogether forgotten. Ideally, the handler
        label is placed where code is otherwise unreachable, i.e., using
        ``Lbl#placeDead(Emitter, Lbl)``.
        
        :param T: the type caught by the block:param N: the stack contents at the bounds of the ``try`` block:param Emitter[N] em: the emitter
        :param Lbl[N] end: the end label, often just :meth:`Lbl.create() <Lbl.create>`.
        :param Lbl[Emitter.Ent[N, Types.TRef[T]]] handler: the handler label, often just :meth:`Lbl.create() <Lbl.create>`
        :param Types.TRef[T] type: the exception type. If multiple types are caught, this must be the join of those
                    types, and the user must emit code to distinguish each, possibly re-throwing if
                    the join is larger than the union.
        :return: a handle to the block.
        :rtype: Misc.TryCatchBlock[T, N]
        """


class Fld(java.lang.Object):
    """
    Utilities for declaring fields in an ASM :obj:`ClassVisitor`
     
    
    LATER: We do not yet return a "field handle." Ideally, we would and that would be the required
    argument for :meth:`Op.getfield(Emitter, TRef, String, BNonVoid) <Op.getfield>` and related ops.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.TBool, name: typing.Union[java.lang.String, str], init: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Declare an initialized boolean field
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.TBool type: the type
        :param java.lang.String or str name: the name
        :param jpype.JBoolean or bool init: the initial value
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.TByte, name: typing.Union[java.lang.String, str], init: typing.Union[jpype.JByte, int]) -> None:
        """
        Declare an initialized byte field
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.TByte type: the type
        :param java.lang.String or str name: the name
        :param jpype.JByte or int init: the initial value
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.TShort, name: typing.Union[java.lang.String, str], init: typing.Union[jpype.JShort, int]) -> None:
        """
        Declare an initialized short field
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.TShort type: the type
        :param java.lang.String or str name: the name
        :param jpype.JShort or int init: the initial value
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.TInt, name: typing.Union[java.lang.String, str], init: typing.Union[jpype.JInt, int]) -> None:
        """
        Declare an initialized int field
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.TInt type: the type
        :param java.lang.String or str name: the name
        :param jpype.JInt or int init: the initial value
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.TLong, name: typing.Union[java.lang.String, str], init: typing.Union[jpype.JLong, int]) -> None:
        """
        Declare an initialized long field
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.TLong type: the type
        :param java.lang.String or str name: the name
        :param jpype.JLong or int init: the initial value
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.TFloat, name: typing.Union[java.lang.String, str], init: typing.Union[jpype.JFloat, float]) -> None:
        """
        Declare an initialized float field
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.TFloat type: the type
        :param java.lang.String or str name: the name
        :param jpype.JFloat or float init: the initial value
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.TDouble, name: typing.Union[java.lang.String, str], init: typing.Union[jpype.JDouble, float]) -> None:
        """
        Declare an initialized double field
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.TDouble type: the type
        :param java.lang.String or str name: the name
        :param jpype.JDouble or float init: the initial value
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.TRef[T], name: typing.Union[java.lang.String, str], init: T) -> None:
        """
        Declare an initialized reference field
         
        
        Note that only certain types of fields can have initial values specified in this manner. A
        :obj:`String` is one such type. For other types, the initializer must be provided in a
        generated class initializer (for static fields) or constructor (for instance fields).
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.TRef[T] type: the type
        :param java.lang.String or str name: the name
        :param T init: the initial value
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: Types.SNonVoid, name: typing.Union[java.lang.String, str]) -> None:
        """
        Declare an uninitialized field of any type
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param Types.SNonVoid type: the type
        :param java.lang.String or str name: the name
        """

    @staticmethod
    @typing.overload
    def decl(cv: org.objectweb.asm.ClassVisitor, flags: typing.Union[jpype.JInt, int], type: org.apache.commons.lang3.reflect.TypeLiteral[T], name: typing.Union[java.lang.String, str]) -> None:
        """
        Declare an uninitialized field of any type with a type signature
        
        :param org.objectweb.asm.ClassVisitor cv: the class visitor
        :param jpype.JInt or int flags: the flags as in
                    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`
        :param org.apache.commons.lang3.reflect.TypeLiteral[T] type: the type with signature
        :param java.lang.String or str name: the name
        """


class Local(java.lang.Record, typing.Generic[T]):
    """
    The handle to a local variable
     
    
    Direct use of the canonical constructor is not recommended. We may later hide this behind an
    interface.
     
    
    The JVM ``<t>load`` and ``<t>store`` instructions all take an index argument. We would
    rather not have to keep track of indices, but instead wrap them in some named handle. These
    handles are generated by :meth:`Scope.decl(BNonVoid, String) <Scope.decl>`,
    :meth:`Def.param(ParamFunction, BNonVoid, String, Consumer) <Def.param>`, and
    :meth:`Def.done(ObjDef, TRef, Consumer) <Def.done>`. For the most part, the user need not worry at all about
    indices, only types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, type: T, name: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int]) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def index(self) -> int:
        ...

    def name(self) -> str:
        ...

    @staticmethod
    def of(type: T, name: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int]) -> Local[T]:
        """
        Construct a local variable handle
         
        
        Direct use of this method is not recommended. It may be made private later.
        
        :param T: the type of the variable:param T type: the type
        :param java.lang.String or str name: the name
        :param jpype.JInt or int index: the index
        :return: the handle
        :rtype: Local[T]
        """

    def toString(self) -> str:
        ...

    def type(self) -> T:
        ...


class SubScope(Scope, java.lang.AutoCloseable):
    """
    A sub scope for local variable declarations
    """

    class_: typing.ClassVar[java.lang.Class]


class Check(java.lang.Object):
    """
    Utility for explicitly checking the stack at a given point in a bytecode sequence.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def expect(em: Emitter[N]) -> Emitter[N]:
        """
        Explicitly check the stack at this point in the bytecode sequence
         
        
        This is meant to be used with chosen type parameters, e.g.:
         
         
        return em
                .emit(Op::ldc__i, 42)
                .emit(Check::<Ent<Bot, TInt>> expect);
         
         
        
        Granted, that's not a particularly complicated case warranting such a check, it demonstrates
        the idiom for placing the check. These are often only in place while the sequence is devised,
        and then removed.
        
        :param N: the expected stack:param Emitter[N] em: the emitter typed with the expected stack
        :return: the same emitter
        :rtype: Emitter[N]
        """


@typing.type_check_only
class ChildScope(RootScope[N], SubScope, typing.Generic[N]):
    """
    The implementation of a child scope for local variable declarations
    """

    class_: typing.ClassVar[java.lang.Class]


class Op(java.lang.Object):
    """
    This interface is a namespace that defines all (well most) JVM bytecode operations.
     
    
    These also provide small examples of how to declare the type signatures for methods that generate
    portions of bytecode. Inevitably, those methods will have expectations of what is on the stack,
    and would like to express the overall effect on that stack in terms of the incoming stack.
    Conventionally, generation methods should accept the emitter (typed with the incoming stack) as
    its first parameter and return that emitter typed with the resulting stack. This allows those
    methods to be invoked using, e.g., :meth:`Emitter.emit(Function) <Emitter.emit>`, and also sets them up to use
    the pattern:
     
     
    return em
            .emit(Op::ldc__i, 1)
            .emit(Op::iadd);
     
     
    
    With this pattern, the Java type checker will ensure that the expected effect on the stack is in
    fact what the emitted code does. Once the pattern is understood, the type signature of each
    opcode method is trivially derived from Chapter 6 of the JVM specification. We do, however, have
    to treat each form separately. Method invocation opcodes require some additional support (see
    :obj:`Inv`), because they consume arguments of arbitrary number and types.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def aaload(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TRef[ET]]]:
        """
        Emit an ``aaload`` instruction
        
        :param ET: the element type:param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TRef[ET]]]
        """

    @staticmethod
    def aastore(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit an ``aastore`` instruction
        
        :param ET: the element type:param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index,:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def aconst_null(em: Emitter[N], type: T) -> Emitter[Emitter.Ent[N, T]]:
        """
        Emit an ``aconst_null`` instruction
        
        :param T: the ascribed type of the ``null``:param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param T type: the ascribed type of the ``null``
        :return: the emitter with ..., ``(T) null``
        :rtype: Emitter[Emitter.Ent[N, T]]
        """

    @staticmethod
    def aload(em: Emitter[N], local: Local[T]) -> Emitter[Emitter.Ent[N, T]]:
        """
        Emit an ``aload`` instruction
        
        :param T: the type of the local:param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Local[T] local: the handle to the local
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, T]]
        """

    @staticmethod
    def anewarray(em: Emitter[N0], elemType: Types.TRef[ET]) -> Emitter[Emitter.Ent[N1, Types.TRef[jpype.JArray[ET]]]]:
        """
        Emit an ``anewarray`` instruction
        
        :param ET: the element type:param N1: the tail of the stack (...):param N0: ..., count:param Emitter[N0] em: the emitter
        :param Types.TRef[ET] elemType: the element type
        :return: the emitter with ..., arrayref
        :rtype: Emitter[Emitter.Ent[N1, Types.TRef[jpype.JArray[ET]]]]
        """

    @staticmethod
    def areturn(em: Emitter[N0], retReq: Methods.RetReq[Types.TRef[TL]]) -> Emitter[Emitter.Dead]:
        """
        Emit an ``areturn`` instruction
        
        :param TL: the required return (ref) type:param TR: the value (ref) type on the stack:param N1: the tail of the stack (...):param N0: ..., objectref:param Emitter[N0] em: the emitter
        :param Methods.RetReq[Types.TRef[TL]] retReq: some proof of this method's required return type
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def arraylength__prim(em: Emitter[N0], elemType: ET) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``arraylength`` instruction, when the array has primitive elements
        
        :param ET: the element type:param N1: the tail of the stack (...):param N0: ..., arrayref:param Emitter[N0] em: the emitter
        :param ET elemType: the element type
        :return: the emitter with ..., length
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def arraylength__ref(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``arraylength`` instruction, when the array has reference elements
        
        :param ET: the element type:param N1: the tail of the stack (...):param N0: ..., arrayref:param Emitter[N0] em: the emitter
        :return: the emitter with ..., length
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def astore(em: Emitter[N0], local: Local[Types.TRef[TL]]) -> Emitter[N1]:
        """
        Emit an ``astore`` instruction
        
        :param TL: the local variable (ref) type:param TR: the value (ref) type on the stack:param N1: the tail of the stack (...):param N0: ..., objectref:param Emitter[N0] em: the emitter
        :param Local[Types.TRef[TL]] local: the target local variable
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def athrow(em: Emitter[N0]) -> Emitter[Emitter.Dead]:
        """
        Emit an ``athrow`` instruction
        
        :param T1: the value (Throwable ref) type on the stack:param N1: the tail of the stack (...):param N0: ..., objectref:param Emitter[N0] em: the emitter
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def baload(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit a ``baload`` instruction for a byte array
        
        :param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def baload__boolean(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit a ``baload`` instruction for a boolean array
        
        :param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def bastore(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit a ``bastore`` instruction for a byte array
        
        :param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def bastore__boolean(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit a ``bastore`` instruction for a boolean array
        
        :param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def caload(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit a ``caload`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def castore(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit a ``castore`` instruction
        
        :param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def checkcast(em: Emitter[N0], type: Types.TRef[CT]) -> Emitter[Emitter.Ent[N1, Types.TRef[CT]]]:
        """
        Emit a ``checkcast`` instruction
        
        :param ST: the inferred type of the value on the stack, i.e., the less-specific type:param CT: the desired type, i.e., the more-specific type:param T1: the reference type for the inferred type:param N1: the tail of the stack (...):param N0: ..., objectref:param Emitter[N0] em: the emitter
        :param Types.TRef[CT] type: the reference type for the desired type
        :return: the emitter with ..., objectref
        :rtype: Emitter[Emitter.Ent[N1, Types.TRef[CT]]]
        """

    @staticmethod
    def d2f(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TFloat]]:
        """
        Emit a ``d2f`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TFloat]]
        """

    @staticmethod
    def d2i(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit a ``d2i`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def d2l(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TLong]]:
        """
        Emit a ``d2l`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TLong]]
        """

    @staticmethod
    def dadd(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TDouble]]:
        """
        Emit a ``dadd`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TDouble]]
        """

    @staticmethod
    def daload(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TDouble]]:
        """
        Emit a ``daload`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TDouble]]
        """

    @staticmethod
    def dastore(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit a ``dastore`` instruction
        
        :param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def dcmpg(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit a ``dcmpg`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def dcmpl(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit a ``dcmpl`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def ddiv(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TDouble]]:
        """
        Emit a ``ddiv`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TDouble]]
        """

    @staticmethod
    def dload(em: Emitter[N], local: Local[Types.TDouble]) -> Emitter[Emitter.Ent[N, Types.TDouble]]:
        """
        Emit a ``dload`` instruction
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Local[Types.TDouble] local: the handle to the local
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TDouble]]
        """

    @staticmethod
    def dmul(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TDouble]]:
        """
        Emit a ``dmul`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TDouble]]
        """

    @staticmethod
    def dneg(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TDouble]]:
        """
        Emit a ``dneg`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TDouble]]
        """

    @staticmethod
    def drem(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TDouble]]:
        """
        Emit a ``drem`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TDouble]]
        """

    @staticmethod
    def dreturn(em: Emitter[N0], retReq: Methods.RetReq[Types.TDouble]) -> Emitter[Emitter.Dead]:
        """
        Emit a ``dreturn`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Methods.RetReq[Types.TDouble] retReq: some proof of this method's required return type
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def dstore(em: Emitter[N0], local: Local[Types.TDouble]) -> Emitter[N1]:
        """
        Emit a ``dstore`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Local[Types.TDouble] local: the target local variable
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def dsub(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TDouble]]:
        """
        Emit a ``dsub`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TDouble]]
        """

    @staticmethod
    def dup(em: Emitter[N0]) -> Emitter[Emitter.Ent[N0, V1]]:
        """
        Emit a ``dup`` instruction
        
        :param V1: the type of the value on the stack:param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value, value
        :rtype: Emitter[Emitter.Ent[N0, V1]]
        """

    @staticmethod
    def dup2__11(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[N0, V2], V1]]:
        """
        Emit a ``dup2`` instruction, duplicating two operands (Form 1)
        
        :param V2: the type of value2 on the stack:param V1: the type of vlaue1 on the stack:param N2: the tail of the stack (...):param N1: ..., value2:param N0: ..., value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value2, value1, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[N0, V2], V1]]
        """

    @staticmethod
    def dup2__2(em: Emitter[N0]) -> Emitter[Emitter.Ent[N0, V1]]:
        """
        Emit a ``dup2`` instruction, duplicating one operand (Form 2)
        
        :param V1: the type of the value on the stack:param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value, value
        :rtype: Emitter[Emitter.Ent[N0, V1]]
        """

    @staticmethod
    def dup2_x1__111(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N3, V2], V1], V3], V2], V1]]:
        """
        Emit a ``dup2_x1`` instruction, duplicating two operands, three values down (Form 1)
        
        :param V3: the type of value3 on the stack:param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N3: the tail of the stack (...):param N2: ..., value3:param N1: ..., value3, value2:param N0: ..., value3, value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value2, value1, value3, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N3, V2], V1], V3], V2], V1]]
        """

    @staticmethod
    def dup2_x1__12(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[N2, V1], V2], V1]]:
        """
        Emit a ``dup2_x1`` instruction, duplicating one operand, two values down (Form 2)
        
        :param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N2: the tail of the stack (...):param N1: ..., value2:param N0: ..., value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value1, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[N2, V1], V2], V1]]
        """

    @staticmethod
    def dup2_x2_1111(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N4, V2], V1], V4], V3], V2], V1]]:
        """
        Emit a ``dup2_x2`` instruction, duplicating two operands, four values down (Form 1)
        
        :param V4: the type of value4 on the stack:param V3: the type of value3 on the stack:param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N4: the tail of the stack (...):param N3: ..., value4:param N2: ..., value4, value3:param N1: ..., value4, value3, value2:param N0: ..., value4, value3, value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value2, value1, value4, value3, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N4, V2], V1], V4], V3], V2], V1]]
        """

    @staticmethod
    def dup2_x2_112(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N3, V1], V3], V2], V1]]:
        """
        Emit a ``dup2_x2`` instruction, duplicating one operand, three values down (Form 2)
        
        :param V3: the type of value3 on the stack:param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N3: the tail of the stack (...):param N2: ..., value3:param N1: ..., value3, value2:param N0: ..., value3, value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value1, value3, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N3, V1], V3], V2], V1]]
        """

    @staticmethod
    def dup2_x2_211(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N3, V2], V1], V3], V2], V1]]:
        """
        Emit a ``dup2_x2`` instruction, duplicating two operands, three values down (Form 3)
        
        :param V3: the type of value3 on the stack:param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N3: the tail of the stack (...):param N2: ..., value3:param N1: ..., value3, value2:param N0: ..., value3, value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value2, value1, value3, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N3, V2], V1], V3], V2], V1]]
        """

    @staticmethod
    def dup2_x2_22(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[N2, V1], V2], V1]]:
        """
        Emit a ``dup2_x2`` instruction, duplicating one operand, two values down (Form 4)
        
        :param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N2: the tail of the stack (...):param N1: ..., value2:param N0: ..., value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value1, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[N2, V1], V2], V1]]
        """

    @staticmethod
    def dup_x1(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[N2, V1], V2], V1]]:
        """
        Emit a ``dup_x1`` instruction
        
        :param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N2: the tail of the stack (...):param N1: ..., value2:param N0: ..., value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value1, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[N2, V1], V2], V1]]
        """

    @staticmethod
    def dup_x2__111(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N3, V1], V3], V2], V1]]:
        """
        Emit a ``dup_x2`` instruction, inserting 3 values down (Form 1)
        
        :param V3: the type of value3 on the stack:param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N3: the tail of the stack (...):param N2: ..., value3:param N1: ..., value3, value2:param N0: ..., value3, value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value1, value3, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[Emitter.Ent[N3, V1], V3], V2], V1]]
        """

    @staticmethod
    def dup_x2__21(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[N2, V1], V2], V1]]:
        """
        Emit a ``dup_x2`` instruction, inserting 2 values down (Form 2)
        
        :param V2: the type of value2 on the stack:param V1: the type of value1 on the stack:param N2: the tail of the stack (...):param N1: ..., value2:param N0: ..., value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value1, value2, value1
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[Emitter.Ent[N2, V1], V2], V1]]
        """

    @staticmethod
    def f2d(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TDouble]]:
        """
        Emit an ``f2d`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TDouble]]
        """

    @staticmethod
    def f2i(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``f2i`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def f2l(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TLong]]:
        """
        Emit an ``f2l`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TLong]]
        """

    @staticmethod
    def fadd(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TFloat]]:
        """
        Emit an ``fadd`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TFloat]]
        """

    @staticmethod
    def faload(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TFloat]]:
        """
        Emit an ``faload`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TFloat]]
        """

    @staticmethod
    def fastore(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit an ``fastore`` instruction
        
        :param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def fcmpg(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``fcmpg`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def fcmpl(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``fcmpl`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def fdiv(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TFloat]]:
        """
        Emit an ``fdiv`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TFloat]]
        """

    @staticmethod
    def fload(em: Emitter[N], local: Local[Types.TFloat]) -> Emitter[Emitter.Ent[N, Types.TFloat]]:
        """
        Emit an ``fload`` instruction
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Local[Types.TFloat] local: the handle to the local
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TFloat]]
        """

    @staticmethod
    def fmul(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TFloat]]:
        """
        Emit an ``fmul`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TFloat]]
        """

    @staticmethod
    def fneg(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TFloat]]:
        """
        Emit an ``fneg`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TFloat]]
        """

    @staticmethod
    def frem(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TFloat]]:
        """
        Emit an ``frem`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TFloat]]
        """

    @staticmethod
    def freturn(em: Emitter[N0], retReq: Methods.RetReq[Types.TFloat]) -> Emitter[Emitter.Dead]:
        """
        Emit an ``freturn`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Methods.RetReq[Types.TFloat] retReq: some proof of this method's required return type
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def fstore(em: Emitter[N0], local: Local[Types.TFloat]) -> Emitter[N1]:
        """
        Emit an ``fstore`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Local[Types.TFloat] local: the target local variable
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def fsub(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TFloat]]:
        """
        Emit an ``fsub`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TFloat]]
        """

    @staticmethod
    def getfield(em: Emitter[N0], owner: Types.TRef[OT], name: typing.Union[java.lang.String, str], type: FT) -> Emitter[Emitter.Ent[N1, FT]]:
        """
        Emit a ``getfield`` instruction
         
        
        LATER: Some sort of field handle?
        
        :param OT: the owner type:param T1: the type of the object on the stack owning the field:param FT: the type of the field:param N1: the tail of the stack (...):param N0: ..., objectref:param Emitter[N0] em: the emitter
        :param Types.TRef[OT] owner: the owner type
        :param java.lang.String or str name: the name of the field
        :param FT type: the type of the field
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N1, FT]]
        """

    @staticmethod
    def getstatic(em: Emitter[N], owner: Types.TRef[typing.Any], name: typing.Union[java.lang.String, str], type: FT) -> Emitter[Emitter.Ent[N, FT]]:
        """
        Emit a ``getstatic`` instruction
         
        
        LATER: Some sort of field handle?
        
        :param FT: the type of the field:param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Types.TRef[typing.Any] owner: the owner type
        :param java.lang.String or str name: the name of the field
        :param FT type: the type of the field
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, FT]]
        """

    @staticmethod
    @typing.overload
    def goto_(em: Emitter[N]) -> Lbl.LblEm[N, Emitter.Dead]:
        """
        Emit a ``goto`` instruction to a new target label
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :return: the new target label and the dead emitter
        :rtype: Lbl.LblEm[N, Emitter.Dead]
        """

    @staticmethod
    @typing.overload
    def goto_(em: Emitter[N], target: Lbl[N]) -> Emitter[Emitter.Dead]:
        """
        Emit a ``goto`` instruction to a given target label
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Lbl[N] target: the target label
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def i2b(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``i2b`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def i2c(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``i2c`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def i2d(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TDouble]]:
        """
        Emit an ``i2d`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TDouble]]
        """

    @staticmethod
    def i2f(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TFloat]]:
        """
        Emit an ``i2f`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TFloat]]
        """

    @staticmethod
    def i2l(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TLong]]:
        """
        Emit an ``i2l`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TLong]]
        """

    @staticmethod
    def i2s(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``i2s`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def iadd(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``iadd`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def iaload(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``iaload`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def iand(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``iand`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def iastore(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit an ``iastore`` instruction
        
        :param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def idiv(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``idiv`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    @typing.overload
    def if_acmpeq(em: Emitter[N0]) -> Lbl.LblEm[N2, N2]:
        """
        Emit an ``if_acmpeq`` instruction to a new target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N2, N2]
        """

    @staticmethod
    @typing.overload
    def if_acmpeq(em: Emitter[N0], target: Lbl[N2]) -> Emitter[N2]:
        """
        Emit an ``if_acmpeq`` instruction to a given target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :param Lbl[N2] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    @typing.overload
    def if_acmpne(em: Emitter[N0]) -> Lbl.LblEm[N2, N2]:
        """
        Emit an ``if_acmpne`` instruction to a new target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N2, N2]
        """

    @staticmethod
    @typing.overload
    def if_acmpne(em: Emitter[N0], target: Lbl[N2]) -> Emitter[N2]:
        """
        Emit an ``if_acmpne`` instruction to a given target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :param Lbl[N2] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    @typing.overload
    def if_icmpeq(em: Emitter[N0]) -> Lbl.LblEm[N2, N2]:
        """
        Emit an ``if_icmpeq`` instruction to a new target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N2, N2]
        """

    @staticmethod
    @typing.overload
    def if_icmpeq(em: Emitter[N0], target: Lbl[N2]) -> Emitter[N2]:
        """
        Emit an ``if_icmpeq`` instruction to a given target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :param Lbl[N2] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    @typing.overload
    def if_icmpge(em: Emitter[N0]) -> Lbl.LblEm[N2, N2]:
        """
        Emit an ``if_icmpge`` instruction to a new target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N2, N2]
        """

    @staticmethod
    @typing.overload
    def if_icmpge(em: Emitter[N0], target: Lbl[N2]) -> Emitter[N2]:
        """
        Emit an ``if_icmpge`` instruction to a given target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :param Lbl[N2] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    @typing.overload
    def if_icmpgt(em: Emitter[N0]) -> Lbl.LblEm[N2, N2]:
        """
        Emit an ``if_icmpgt`` instruction to a new target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N2, N2]
        """

    @staticmethod
    @typing.overload
    def if_icmpgt(em: Emitter[N0], target: Lbl[N2]) -> Emitter[N2]:
        """
        Emit an ``if_icmpgt`` instruction to a given target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :param Lbl[N2] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    @typing.overload
    def if_icmple(em: Emitter[N0]) -> Lbl.LblEm[N2, N2]:
        """
        Emit an ``if_icmple`` instruction to a new target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N2, N2]
        """

    @staticmethod
    @typing.overload
    def if_icmple(em: Emitter[N0], target: Lbl[N2]) -> Emitter[N2]:
        """
        Emit an ``if_icmple`` instruction to a given target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :param Lbl[N2] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    @typing.overload
    def if_icmplt(em: Emitter[N0]) -> Lbl.LblEm[N2, N2]:
        """
        Emit an ``if_icmplt`` instruction to a new target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N2, N2]
        """

    @staticmethod
    @typing.overload
    def if_icmplt(em: Emitter[N0], target: Lbl[N2]) -> Emitter[N2]:
        """
        Emit an ``if_icmplt`` instruction to a given target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :param Lbl[N2] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    @typing.overload
    def if_icmpne(em: Emitter[N0]) -> Lbl.LblEm[N2, N2]:
        """
        Emit an ``if_icmpne`` instruction to a new target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N2, N2]
        """

    @staticmethod
    @typing.overload
    def if_icmpne(em: Emitter[N0], target: Lbl[N2]) -> Emitter[N2]:
        """
        Emit an ``if_icmpne`` instruction to a given target label
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :param Lbl[N2] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    @typing.overload
    def ifeq(em: Emitter[N0]) -> Lbl.LblEm[N1, N1]:
        """
        Emit an ``ifeq`` instruction to a new target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N1, N1]
        """

    @staticmethod
    @typing.overload
    def ifeq(em: Emitter[N0], target: Lbl[N1]) -> Emitter[N1]:
        """
        Emit an ``ifeq`` instruction to a given target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Lbl[N1] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def ifge(em: Emitter[N0]) -> Lbl.LblEm[N1, N1]:
        """
        Emit an ``ifge`` instruction to a new target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N1, N1]
        """

    @staticmethod
    @typing.overload
    def ifge(em: Emitter[N0], target: Lbl[N1]) -> Emitter[N1]:
        """
        Emit an ``ifge`` instruction to a given target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Lbl[N1] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def ifgt(em: Emitter[N0]) -> Lbl.LblEm[N1, N1]:
        """
        Emit an ``ifgt`` instruction to a new target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N1, N1]
        """

    @staticmethod
    @typing.overload
    def ifgt(em: Emitter[N0], target: Lbl[N1]) -> Emitter[N1]:
        """
        Emit an ``ifgt`` instruction to a given target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Lbl[N1] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def ifle(em: Emitter[N0]) -> Lbl.LblEm[N1, N1]:
        """
        Emit an ``ifle`` instruction to a new target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N1, N1]
        """

    @staticmethod
    @typing.overload
    def ifle(em: Emitter[N0], target: Lbl[N1]) -> Emitter[N1]:
        """
        Emit an ``ifle`` instruction to a given target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Lbl[N1] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def iflt(em: Emitter[N0]) -> Lbl.LblEm[N1, N1]:
        """
        Emit an ``iflt`` instruction to a new target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N1, N1]
        """

    @staticmethod
    @typing.overload
    def iflt(em: Emitter[N0], target: Lbl[N1]) -> Emitter[N1]:
        """
        Emit an ``iflt`` instruction to a given target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Lbl[N1] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def ifne(em: Emitter[N0]) -> Lbl.LblEm[N1, N1]:
        """
        Emit an ``ifne`` instruction to a new target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N1, N1]
        """

    @staticmethod
    @typing.overload
    def ifne(em: Emitter[N0], target: Lbl[N1]) -> Emitter[N1]:
        """
        Emit an ``ifne`` instruction to a given target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Lbl[N1] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def ifnonnull(em: Emitter[N0]) -> Lbl.LblEm[N1, N1]:
        """
        Emit an ``ifnonnull`` instruction to a new target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N1, N1]
        """

    @staticmethod
    @typing.overload
    def ifnonnull(em: Emitter[N0], target: Lbl[N1]) -> Emitter[N1]:
        """
        Emit an ``ifnonnull`` instruction to a given target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Lbl[N1] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def ifnull(em: Emitter[N0]) -> Lbl.LblEm[N1, N1]:
        """
        Emit an ``ifnull`` instruction to a new target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the new target label and the emitter with ...
        :rtype: Lbl.LblEm[N1, N1]
        """

    @staticmethod
    @typing.overload
    def ifnull(em: Emitter[N0], target: Lbl[N1]) -> Emitter[N1]:
        """
        Emit an ``ifnull`` instruction to a given target label
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Lbl[N1] target: the target label
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def iinc(em: Emitter[N], local: Local[Types.TInt], increment: typing.Union[jpype.JInt, int]) -> Emitter[N]:
        """
        Emit an ``iinc`` instruction
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Local[Types.TInt] local: the target local to increment
        :param jpype.JInt or int increment: the constant value to increment by
        :return: the emitter with ...
        :rtype: Emitter[N]
        """

    @staticmethod
    def iload(em: Emitter[N], local: Local[Types.TInt]) -> Emitter[Emitter.Ent[N, Types.TInt]]:
        """
        Emit an ``iload`` instruction
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Local[Types.TInt] local: the handle to the local
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TInt]]
        """

    @staticmethod
    def imul(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``imul`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def ineg(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``ineg`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def instanceof_(em: Emitter[N0], type: Types.TRef[typing.Any]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``instanceof`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., objectref:param Emitter[N0] em: the emitter
        :param Types.TRef[typing.Any] type: the given type (T)
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def invokedynamic__unsupported(em: Emitter[SN], name: typing.Union[java.lang.String, str], desc: Methods.MthDesc[MR, MN], bootstrapMethodHandle: org.objectweb.asm.Handle, *bootstrapMethodArguments: java.lang.Object) -> Methods.Inv[MR, SN, MN]:
        """
        Emit an ``invokedynamic`` instruction
         
        
        **WARNING:** This is probably not implemented correctly. The JVM spec does not provide an
        example, but the best we can tell, after all the call site resolution machinery, the net
        arguments actually consumed from the stack is determined by the given method descriptor. We
        also just let the ASM types :obj:`Type`, :obj:`Handle`, and :obj:`ConstantDynamic` leak
        from an API perspective.
        
        :param SN: the JVM stack at the call site. Some may be popped as arguments:param MN: the parameters expected by the method descriptor:param MR: the return type from the method descriptor:param Emitter[SN] em: the emitter
        :param java.lang.String or str name: the name of the method
        :param Methods.MthDesc[MR, MN] desc: the method descriptor
        :param org.objectweb.asm.Handle bootstrapMethodHandle: as in
                    :meth:`MethodVisitor.visitInvokeDynamicInsn(String, String, Handle, Object...) <MethodVisitor.visitInvokeDynamicInsn>`
        :param jpype.JArray[java.lang.Object] bootstrapMethodArguments: as in
                    :meth:`MethodVisitor.visitInvokeDynamicInsn(String, String, Handle, Object...) <MethodVisitor.visitInvokeDynamicInsn>`
        :return: an object to complete type checking of the arguments and, if applicable, the result
        :rtype: Methods.Inv[MR, SN, MN]
        """

    @staticmethod
    def invokeinterface(em: Emitter[SN], ownerType: Types.TRef[OT], name: typing.Union[java.lang.String, str], desc: Methods.MthDesc[MR, MN]) -> Methods.ObjInv[MR, OT, SN, MN]:
        """
        Emit an ``invokeinterface`` instruction
        
        :param OT: the owner (interface) type:param SN: the JVM stack at the call site. Some may be popped as arguments:param MN: the parameters expected by the method descriptor:param MR: the return type from the method descriptor:param Emitter[SN] em: the emitter
        :param Types.TRef[OT] ownerType: the owner (interface) type
        :param java.lang.String or str name: the name of the method
        :param Methods.MthDesc[MR, MN] desc: the method descriptor
        :return: an object to complete type checking of the arguments and, if applicable, the result
        :rtype: Methods.ObjInv[MR, OT, SN, MN]
        """

    @staticmethod
    def invokespecial(em: Emitter[SN], ownerType: Types.TRef[OT], name: typing.Union[java.lang.String, str], desc: Methods.MthDesc[MR, MN], isInterface: typing.Union[jpype.JBoolean, bool]) -> Methods.ObjInv[MR, OT, SN, MN]:
        """
        Emit an ``invokespecial`` instruction
        
        :param OT: the owner (super) type:param SN: the JVM stack at the call site. Some may be popped as arguments:param MN: the parameters expected by the method descriptor:param MR: the return type from the method descriptor:param Emitter[SN] em: the emitter
        :param Types.TRef[OT] ownerType: the owner (super) type
        :param java.lang.String or str name: the name of the method
        :param Methods.MthDesc[MR, MN] desc: the method descriptor
        :param jpype.JBoolean or bool isInterface: true to indicate the owner type is an interface
        :return: an object to complete type checking of the arguments and, if applicable, the result
        :rtype: Methods.ObjInv[MR, OT, SN, MN]
        """

    @staticmethod
    def invokestatic(em: Emitter[SN], ownerType: Types.TRef[typing.Any], name: typing.Union[java.lang.String, str], desc: Methods.MthDesc[MR, MN], isInterface: typing.Union[jpype.JBoolean, bool]) -> Methods.Inv[MR, SN, MN]:
        """
        Emit an ``invokestatic`` instruction
        
        :param SN: the JVM stack at the call site. Some may be popped as arguments:param MN: the parameters expected by the method descriptor:param MR: the return type from the method descriptor:param Emitter[SN] em: the emitter
        :param Types.TRef[typing.Any] ownerType: the owner type
        :param java.lang.String or str name: the name of the method
        :param Methods.MthDesc[MR, MN] desc: the method descriptor
        :param jpype.JBoolean or bool isInterface: true to indicate the owner type is an interface
        :return: an object to complete type checking of the arguments and, if applicable, the result
        :rtype: Methods.Inv[MR, SN, MN]
        """

    @staticmethod
    def invokevirtual(em: Emitter[SN], ownerType: Types.TRef[OT], name: typing.Union[java.lang.String, str], desc: Methods.MthDesc[MR, MN], isInterface: typing.Union[jpype.JBoolean, bool]) -> Methods.ObjInv[MR, OT, SN, MN]:
        """
        Emit an ``invokevirtual`` instruction
        
        :param OT: the owner type:param SN: the JVM stack at the call site. Some may be popped as arguments:param MN: the parameters expected by the method descriptor:param MR: the return type from the method descriptor:param Emitter[SN] em: the emitter
        :param Types.TRef[OT] ownerType: the owner type
        :param java.lang.String or str name: the name of the method
        :param Methods.MthDesc[MR, MN] desc: the method descriptor
        :param jpype.JBoolean or bool isInterface: true to indicate the owner type is an interface
        :return: an object to complete type checking of the arguments and, if applicable, the result
        :rtype: Methods.ObjInv[MR, OT, SN, MN]
        """

    @staticmethod
    def ior(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``ior`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def irem(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``irem`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def ireturn(em: Emitter[N0], retReq: Methods.RetReq[Types.TInt]) -> Emitter[Emitter.Dead]:
        """
        Emit an ``ireturn`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Methods.RetReq[Types.TInt] retReq: some proof of this method's required return type
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def ishl(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``ishl`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def ishr(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``ishr`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def istore(em: Emitter[N0], local: Local[Types.TInt]) -> Emitter[N1]:
        """
        Emit an ``istore`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Local[Types.TInt] local: the target local variable
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def isub(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``isub`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def iushr(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``iushr`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def ixor(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``ixor`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def jsr__deprecated(em: Emitter[typing.Any], target: Lbl[typing.Any]) -> Emitter[typing.Any]:
        """
        DO NOT emit an ``jsr`` instruction
         
        
        According to Oracle's documentation, this deprecated instruction was used in the
        implementation of ``finally`` blocks prior to Java SE 6. This method is here only to
        guide users searching for the ``jsr`` opcode toward the replacement:
        :meth:`Misc.tryCatch(Emitter, Lbl, Lbl, TRef) <Misc.tryCatch>`. Syntactically, trying to use this method
        should result in all sorts of compilation errors, if not on the invocation itself, then on
        anything following it in the chain. At runtime, this *always* throws an
        :obj:`UnsupportedOperationException`.
        
        :param Emitter[typing.Any] em: the emitter
        :param Lbl[typing.Any] target: the target label
        :return: never
        :rtype: Emitter[typing.Any]
        """

    @staticmethod
    def l2d(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TDouble]]:
        """
        Emit an ``l2d`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TDouble]]
        """

    @staticmethod
    def l2f(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TFloat]]:
        """
        Emit an ``l2f`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TFloat]]
        """

    @staticmethod
    def l2i(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TInt]]:
        """
        Emit an ``l2i`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TInt]]
        """

    @staticmethod
    def ladd(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``ladd`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def laload(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``laload`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def land(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``land`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lastore(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit an ``lastore`` instruction
        
        :param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def lcmp(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``lcmp`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def ldc__a(em: Emitter[N], value: T) -> Emitter[Emitter.Ent[N, Types.TRef[T]]]:
        """
        Emit an ``ldc`` instruction for a reference
         
        
        NOTE: Only certain reference types are permitted. Some of the permitted types are those
        leaked (API-wise) from the underlying ASM library. The underlying ASM library may emit
        alternative instructions at its discretion.
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param T value: the value to push
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TRef[T]]]
        """

    @staticmethod
    def ldc__d(em: Emitter[N], value: typing.Union[jpype.JDouble, float]) -> Emitter[Emitter.Ent[N, Types.TDouble]]:
        """
        Emit an ``ldc`` instruction for a double
         
        
        NOTE: The underlying ASM library may emit alternative instructions at its discretion.
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param jpype.JDouble or float value: the value to push
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TDouble]]
        """

    @staticmethod
    def ldc__f(em: Emitter[N], value: typing.Union[jpype.JFloat, float]) -> Emitter[Emitter.Ent[N, Types.TFloat]]:
        """
        Emit an ``ldc`` instruction for a float
         
        
        NOTE: The underlying ASM library may emit alternative instructions at its discretion.
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param jpype.JFloat or float value: the value to push
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TFloat]]
        """

    @staticmethod
    def ldc__i(em: Emitter[N], value: typing.Union[jpype.JInt, int]) -> Emitter[Emitter.Ent[N, Types.TInt]]:
        """
        Emit an ``ldc`` instruction for an integer
         
        
        NOTE: The underlying ASM library may emit alternative instructions at its discretion.
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param jpype.JInt or int value: the value to push
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TInt]]
        """

    @staticmethod
    def ldc__l(em: Emitter[N], value: typing.Union[jpype.JLong, int]) -> Emitter[Emitter.Ent[N, Types.TLong]]:
        """
        Emit an ``ldc`` instruction for a long
         
        
        NOTE: The underlying ASM library may emit alternative instructions at its discretion.
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param jpype.JLong or int value: the value to push
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TLong]]
        """

    @staticmethod
    def ldiv(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``ldiv`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lload(em: Emitter[N], local: Local[Types.TLong]) -> Emitter[Emitter.Ent[N, Types.TLong]]:
        """
        Emit an ``lload`` instruction
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Local[Types.TLong] local: the handle to the local
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N, Types.TLong]]
        """

    @staticmethod
    def lmul(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``lmul`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lneg(em: Emitter[N0]) -> Emitter[Emitter.Ent[N1, Types.TLong]]:
        """
        Emit an ``lneg`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N1, Types.TLong]]
        """

    @staticmethod
    def lookupswitch(em: Emitter[N0], dflt: Lbl[N1], cases: collections.abc.Mapping) -> Emitter[Emitter.Dead]:
        """
        Emit a ``lookupswitch`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., key:param Emitter[N0] em: the emitter
        :param Lbl[N1] dflt: a target label for the default case. The stack at the label must be ...
        :param collections.abc.Mapping cases: a map of integer case value to target label. The stack at each label must be ...
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def lor(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``lor`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lrem(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``lrem`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lreturn(em: Emitter[N0], retReq: Methods.RetReq[Types.TInt]) -> Emitter[Emitter.Dead]:
        """
        Emit an ``lreturn`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Methods.RetReq[Types.TInt] retReq: some proof of this method's required return type
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def lshl(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``lshl`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lshr(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``lshr`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lstore(em: Emitter[N0], local: Local[Types.TLong]) -> Emitter[N1]:
        """
        Emit an ``lstore`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Local[Types.TLong] local: the target local variable
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def lsub(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``lsub`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lushr(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``lushr`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def lxor(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TLong]]:
        """
        Emit an ``lxor`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param Emitter[N0] em: the emitter
        :return: the emitter with ..., result
        :rtype: Emitter[Emitter.Ent[N2, Types.TLong]]
        """

    @staticmethod
    def monitorenter(em: Emitter[N0]) -> Emitter[N1]:
        """
        Emit a ``monitorenter`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., objectref:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def monitorexit(em: Emitter[N0]) -> Emitter[N1]:
        """
        Emit a ``monitorexit`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., objectref:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def multianewarray__unsupported(em: Emitter[typing.Any], type: Types.TRef[typing.Any], dimensions: typing.Union[jpype.JInt, int]) -> Emitter[typing.Any]:
        """
        Emit a ``multianewarray`` instruction
         
        
        NOTE: This will emit the instruction, but derivation of the resulting stack contents is not
        implemented. The user must cast the emitter to the resulting type. LATER: If required, we may
        implement this for specific dimensions. Or, we might use a pattern similar to what we used
        for method invocation to allow us an arbitrary number of stack arguments.
        
        :param Emitter[typing.Any] em: the emitter
        :param Types.TRef[typing.Any] type: the type of the full multidimensional array (not just the element type)
        :param jpype.JInt or int dimensions: the number of dimensions to allocate
        :return: the emitter with unknown stack
        :rtype: Emitter[typing.Any]
        """

    @staticmethod
    def new_(em: Emitter[N], type: T) -> Emitter[Emitter.Ent[N, T]]:
        """
        Emit a ``new`` instruction
        
        :param T: the type of object:param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param T type: the type of object
        :return: the emitter with ..., objectref (uninitialized)
        :rtype: Emitter[Emitter.Ent[N, T]]
        
        .. admonition:: Implementation Note
        
            We considered using a separate ``URef`` type to indicate an uninitialized
            reference; however, this would fail for the standard ``new-dup-invokespecial``
            sequence, as the reference remaining on the stack would appear uninitialized when
            it is in fact initialized.
        """

    @staticmethod
    def newarray(em: Emitter[N0], elemType: ET) -> Emitter[Emitter.Ent[N1, Types.TRef[AT]]]:
        """
        Emit a ``newarray`` instruction
        
        :param AT: the resulting array type:param ET: the (primitive) element type:param N1: the tail of the stack (...):param N0: ..., count:param Emitter[N0] em: the emitter
        :param ET elemType: the element type
        :return: the emitter with ..., arrayref
        :rtype: Emitter[Emitter.Ent[N1, Types.TRef[AT]]]
        """

    @staticmethod
    def nop(em: Emitter[N]) -> Emitter[N]:
        """
        Emit a ``nop`` instruction
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N]
        """

    @staticmethod
    def pop(em: Emitter[N0]) -> Emitter[N1]:
        """
        Emit a ``pop`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def pop2__11(em: Emitter[N0]) -> Emitter[N2]:
        """
        Emit a ``pop2`` instruction to pop two operands (Form 1)
        
        :param N2: the tail of the stack (...):param N1: ..., value2:param N0: ..., value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    def pop2__2(em: Emitter[N0]) -> Emitter[N1]:
        """
        Emit a ``pop2`` instruction to pop one operand (Form 2)
        
        :param N1: the tail of the stack (...):param N0: ..., value1:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def putfield(em: Emitter[N0], owner: Types.TRef[OT], name: typing.Union[java.lang.String, str], type: FT) -> Emitter[N2]:
        """
        Emit a ``putfield`` instruction
        
        :param OT: the owner type:param T2: the type of the object on the stack owning the field:param FT: the type of the field:param N2: the tail of the stack (...):param N1: ..., objectref:param N0: ..., objectref, value:param Emitter[N0] em: the emitter
        :param Types.TRef[OT] owner: the owner type
        :param java.lang.String or str name: the name of the field
        :param FT type: the type of the field
        :return: the emitter with ...
        :rtype: Emitter[N2]
        """

    @staticmethod
    def putstatic(em: Emitter[N0], owner: Types.TRef[typing.Any], name: typing.Union[java.lang.String, str], type: FT) -> Emitter[N1]:
        """
        Emit a ``putstatic`` instruction
        
        :param FT: the type of the field:param N1: the tail of the stack (...):param N0: ..., value:param Emitter[N0] em: the emitter
        :param Types.TRef[typing.Any] owner: the owner type
        :param java.lang.String or str name: the name of the field
        :param FT type: the type of the field
        :return: the emitter with ...
        :rtype: Emitter[N1]
        """

    @staticmethod
    def ret__deprecated(em: Emitter[typing.Any], local: Local[typing.Any]) -> Emitter[typing.Any]:
        """
        DO NOT emit an ``ret`` instruction
         
        
        According to Oracle's documentation, this deprecated instruction was used in the
        implementation of ``finally`` blocks prior to Java SE 6. You may actually be searching
        for the :meth:`return_(Emitter, RetReq) <.return_>` method. This method is here only to guide users
        searching for the ``ret`` opcode toward the replacement:
        :meth:`Misc.tryCatch(Emitter, Lbl, Lbl, TRef) <Misc.tryCatch>`. Syntactically, trying to use this method
        should result in all sorts of compilation errors, if not on the invocation itself, then on
        anything following it in the chain. At runtime, this *always* throws an
        :obj:`UnsupportedOperationException`.
        
        :param Emitter[typing.Any] em: the emitter
        :param Local[typing.Any] local: the local variable (NOTE: ``returnAddress`` is not a supported type)
        :return: never
        :rtype: Emitter[typing.Any]
        """

    @staticmethod
    def return_(em: Emitter[N], retReq: Methods.RetReq[Types.TVoid]) -> Emitter[Emitter.Dead]:
        """
        Emit a ``return`` instruction
        
        :param N: the tail of the stack (...):param Emitter[N] em: the emitter
        :param Methods.RetReq[Types.TVoid] retReq: some proof of this method's required return type
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """

    @staticmethod
    def saload(em: Emitter[N0]) -> Emitter[Emitter.Ent[N2, Types.TInt]]:
        """
        Emit an ``saload`` instruction
        
        :param N2: the tail of the stack (...):param N1: ..., arrayref:param N0: ..., arrayref, index:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value
        :rtype: Emitter[Emitter.Ent[N2, Types.TInt]]
        """

    @staticmethod
    def sastore(em: Emitter[N0]) -> Emitter[N3]:
        """
        Emit an ``sastore`` instruction
        
        :param N3: the tail of the stack (...):param N2: ..., arrayref:param N1: ..., arrayref, index:param N0: ..., arrayref, index, value:param Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: Emitter[N3]
        """

    @staticmethod
    def swap(em: Emitter[N0]) -> Emitter[Emitter.Ent[Emitter.Ent[N2, T1], T2]]:
        """
        Emit a ``swap`` instruction
        
        :param T2: the type of value2 on the stack:param T1: the type of value1 on the stack:param N2: the tail of the stack (...):param N1: ..., value2:param N0: ..., value2, value1:param Emitter[N0] em: the emitter
        :return: the emitter with ..., value1, value2
        :rtype: Emitter[Emitter.Ent[Emitter.Ent[N2, T1], T2]]
        """

    @staticmethod
    def tableswitch(em: Emitter[N0], low: typing.Union[jpype.JInt, int], dflt: Lbl[N1], cases: java.util.List[Lbl[N1]]) -> Emitter[Emitter.Dead]:
        """
        Emit a ``tableswitch`` instruction
        
        :param N1: the tail of the stack (...):param N0: ..., index:param Emitter[N0] em: the emitter
        :param jpype.JInt or int low: the low index
        :param Lbl[N1] dflt: a target label for the default case. The stack at the label must be ...
        :param java.util.List[Lbl[N1]] cases: a list of target labels. The stack at each label must be ...
        :return: the dead emitter
        :rtype: Emitter[Emitter.Dead]
        """


@typing.type_check_only
class RootScope(Scope, typing.Generic[N]):
    """
    The implementation of the root scope for local variable declarations
    """

    class_: typing.ClassVar[java.lang.Class]


class Emitter(java.lang.Object, typing.Generic[N]):
    """
    The central object for emitting type checked JVM bytecode.
     
    
    This is either genius or a sign of some deep pathology. On one hand it allows the type-safe
    generation of bytecode in Java classfiles. On the other, it requires an often onerous type
    signature on any method of appreciable sophistication that uses it. The justification for this
    utility library stems from our difficulties with error reporting in the ASM library. We certainly
    appreciate the effort that has gone into that library, and must recognize its success in that it
    has been used by the OpenJDK itself and eventually prompted them to devise an official classfile
    API. Nevertheless, its analyses (e.g., max-stack computation) fail with inscrutable messages.
    Admittedly, this only happens when we have generated invalid bytecode. For example, popping too
    many items off the stack usually results in an :obj:`ArrayIndexOutOfBoundsException` instead of,
    "Hey, you can't pop that here: [offset]". Similarly, if you push a long and then pop an int, you
    typically get a :obj:`NullPointerException`. Unfortunately, these errors do not occur with the
    offending ``visitXInstruction()`` call on the stack, but instead during
    :meth:`MethodVisitor.visitMaxs(int, int) <MethodVisitor.visitMaxs>`, and so we could not easily debug and identify the
    cause. We did find some ways to place breakpoints and at least derive the bytecode offset. We
    then used additional dumps and instrumentation to map that back to our source that generated the
    offending instruction. This has been an extremely onerous process. Additionally, when refactoring
    bytecode generation, we are left with little if any assistance from the compiler or IDE. These
    utilities seek to improve the situation.
     
    
    Our goal is to devise a way leverage Java's Generics and its type checker to enforce stack
    consistency of generated JVM bytecode. We want the Java compiler to reject code that tries, for
    example, to emit an ``iload`` followed by an ``lstore``, because there is clearly an
    ``int`` on the stack where a ``long`` is required. We accomplish this by encoding the
    stack contents (or at least the local knowledge of the stack contents) in this emitter's type
    variable ``<N>``. We encode the types of stack entries using a Lisp-style list. The bottom of
    the stack is encoded as :obj:`Bot`. A list is encoded with :obj:`Ent` where the first type
    parameter is the tail of the list (for things further down the stack), and the second type
    parameter encodes the JVM machine type, e.g., :obj:`TInt`, of the element at that position. The
    head of this list, i.e., the type ``<N>``, is the top of the stack.
     
    
    The resulting syntax for emitting code is a bit strange, but still quite effective in practice. A
    problem we encounter in Java (and most OOP languages to our knowledge) is that an instance method
    can always be invoked on a variable, no matter the variable's type parameters. Sure, we can
    always throw an exception at runtime, but we want the compiler to reject it, which implies static
    checking. Thus, while instance methods can be used for pure pushes, we cannot use them to
    validate stack contents, e.g., for pops. Suppose we'd like to specify the ``lcmp`` bytecode
    op. This would require a :obj:`long <TLong>` at the top of the stack, but there's no way we can
    restrict ``<N>`` on the implied ``this`` parameter. Nor is there an obvious way to unpack
    the contents of ``<N>`` so that we can remove the :obj:`TLong` and add a :obj:`TInt`.
    Instead, we must turn to static methods.
     
    
    This presents a different problem. We'd like to provide a syntax where the ops appear in the
    order they are emitted. Usually, we'd chain instance methods, like such:
     
     
    em
            .ldc(1)
            .pop();
     
     
    
    However, we've already ruled out instance methods. Were we to use static methods, we'd get
    something like:
     
     
    Op.pop(Op.ldc(em, 1));
     
     
     
    
    However, that fails to display the ops in order. We could instead use:
     
     
    var em1 = Op.ldc(em, 1);
    var em2 = Op.pop(em1);
     
     
    However, that requires more syntactic kruft, not to mention the manual bookkeeping to ensure we
    use the previous ``em``*n* at each step. To work around this, we define instance
    methods, e.g., :meth:`emit(Function) <.emit>`, that can accept references to static methods we provide,
    each representing a JVM bytecode instruction. This allows those static methods to impose a
    required structure on the stack. The static method can then return an emitter with a type
    encoding the new stack contents. (See the :obj:`Op` class for examples.) Thus, we have a syntax
    like:
     
     
    em
            .emit(Op::ldc__i, 1)
            .emit(Op::pop);
     
     
    
    While not ideal, it is succinct, allows method chaining, and displays the ops in order of
    emission. (Note that we use this pattern even for pure pushes, where restricting ``<N>`` is
    not necessary, just for syntactic consistency.) There are some rubs for operators that have
    different forms, e.g., :meth:`Op.ldc__i(Emitter, int) <Op.ldc__i>`, but as a matter of opinion, having to
    specify the intended form here is a benefit. The meat of this class is just the specification of
    the many arities of ``emit``. It also includes some utilities for declaring local variables,
    and the entry points for generating and defining methods.
     
    
    To give an overall taste of using this utility library, here is an example for dynamically
    generating a class that implements an interface. Note that the interface is *not*
    dynamically generated. This is a common pattern as it allows the generated method to be invoked
    without reflection.
     
     
    interface MyIf {
        int myMethod(int a, String b);
    }
     
    <THIS extends MyIf> void doGenerate(ClassVisitor cv) {
        var mdescMyMethod = MthDesc.derive(MyIf::myMethod)
                .check(MthDesc::returns, Types.T_INT)
                .check(MthDesc::param, Types.T_INT)
                .check(MthDesc::param, Types.refOf(String.class))
                .check(MthDesc::build);
        TRef<THIS> typeThis = Types.refExtends(MyIf.class, "Lmy.pkg.ImplMyIf;");
        var paramsMyMethod = new Object() {
            Local<TRef<THIS>> this_;
            Local<TInt> a;
            Local<TRef<String>> b;
        };
        var retMyMethod = Emitter.start(typeThis, cv, ACC_PUBLIC, "myMethod", mdescMyMethod)
                .param(Def::param, Types.refOf(String.class), l -> paramsMyMethod.b = l)
                .param(Def::param, Types.T_INT, l -> paramsMyMethod.a = l)
                .param(Def::done, typeThis, l -> paramsMyMethod.this_ = l);
        retMyMethod.em()
                .emit(Op::iload, paramsMyMethod.a)
                .emit(Op::ldc__i, 10)
                .emit(Op::imul)
                .emit(Op::ireturn, retMyMethod.ret())
                .emit(Misc::finish);
    }
     
     
    
    Yes, there is a bit of repetition; however, this accomplishes all our goals and a little more.
    Note that the generated bytecode is essentially type checked all the way through to the method
    definition in the ``MyIf`` interface. Here is the key: *We were to change the ``MyIf``
    interface, the compiler (and our IDE) would point out the inconsistency.* The first such
    errors would be on ``mdescMyMethod``. So, we would adjust it to match the new definition. The
    compiler would then point out issues at ``retMyMethod`` -- assuming the parameters to
    ``myMethod`` changed, and not just the return type. We would adjust it, along with the
    contents of ``paramsMyMethod`` to accept the new parameter handles. If the return type of
    ``myMethod`` changed, then the inferred type of ``retMyMethod`` will change accordingly.
     
    
    Now for the generated bytecode. The :meth:`Op.iload(Emitter, Local) <Op.iload>` requires the given variable
    handle to have type :obj:`TInt`, and so if the parameter "``a``" changed type, the compiler
    will point out that the opcode must also change. Similarly, the :meth:`Op.imul(Emitter) <Op.imul>` requires
    two ints and pushes an int result, so any resulting inconsistency will be caught. Finally, when
    calling :meth:`Op.ireturn(Emitter, RetReq) <Op.ireturn>`, two things are checked: 1) there is indeed an int on
    the stack, and 2) the return type of the method, witnessed by ``retMyMethod.ret()``, is also
    an int. There are some occasional wrinkles, but for the most part, once we resolve all the
    compilation errors, we are assured of type consistency in the generated code, both internally and
    in its interface to other compiled code.
    """

    class Next(java.lang.Object):
        """
        Stack contents
         
         
        
        There is really only one instance of :obj:`Next` and that is :obj:`SingletonEnt.INSTANCE`.
        We just cast it to the various types. Otherwise, these interfaces just exist as a means of
        leveraging Java's type checker.
        """

        class_: typing.ClassVar[java.lang.Class]
        BOTTOM: typing.Final[Emitter.Bot]
        """
        The bottom of the stack
        """



    class Ent(Emitter.Next, typing.Generic[N, T]):
        """
        An entry on the stack
        """

        class_: typing.ClassVar[java.lang.Class]


    class Bot(Emitter.Next):
        """
        The bottom of the stack, i.e., the empty stack
        """

        class_: typing.ClassVar[java.lang.Class]


    class Dead(java.lang.Object):
        """
        Use in place of stack contents when code emitted at this point would be unreachable
         
        
        Note that this does not extend :obj:`Next`, which is why :obj:`Emitter` does not require
        ``N`` to extend :obj:`Next`. This interface also has no implementation.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SingletonEnt(java.lang.Record, Emitter.Ent[N, T], Emitter.Bot, typing.Generic[N, T]):
        """
        Defines the singleton instance of :obj:`Next`
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class A3Function(java.lang.Object, typing.Generic[A0, A1, A2, R]):
        """
        A 3-argument function
        """

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, arg0: A0, arg1: A1, arg2: A2) -> R:
            """
            Invoke the function
            
            :param A0 arg0: the first argument
            :param A1 arg1: the next argument
            :param A2 arg2: the next argument
            :return: the result
            :rtype: R
            """


    class A3Consumer(java.lang.Object, typing.Generic[A0, A1, A2]):
        """
        A 3-argument consumer
        """

        class_: typing.ClassVar[java.lang.Class]

        def accept(self, arg0: A0, arg1: A1, arg2: A2) -> None:
            """
            Invoke the consumer
            
            :param A0 arg0: the first argument
            :param A1 arg1: the next argument
            :param A2 arg2: the next argument
            """


    class A4Function(java.lang.Object, typing.Generic[A0, A1, A2, A3, R]):
        """
        A 4-argument function
        """

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, arg0: A0, arg1: A1, arg2: A2, arg3: A3) -> R:
            """
            Invoke the function
            
            :param A0 arg0: the first argument
            :param A1 arg1: the next argument
            :param A2 arg2: the next argument
            :param A3 arg3: the next argument
            :return: the result
            :rtype: R
            """


    class A4Consumer(java.lang.Object, typing.Generic[A0, A1, A2, A3]):
        """
        A 4-argument consumer
        """

        class_: typing.ClassVar[java.lang.Class]

        def accept(self, arg0: A0, arg1: A1, arg2: A2, arg3: A3) -> None:
            """
            Invoke the consumer
            
            :param A0 arg0: the first argument
            :param A1 arg1: the next argument
            :param A2 arg2: the next argument
            :param A3 arg3: the next argument
            """


    class A5Function(java.lang.Object, typing.Generic[A0, A1, A2, A3, A4, R]):
        """
        A 5-argument function
        """

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, arg0: A0, arg1: A1, arg2: A2, arg3: A3, arg4: A4) -> R:
            """
            Invoke the function
            
            :param A0 arg0: the first argument
            :param A1 arg1: the next argument
            :param A2 arg2: the next argument
            :param A3 arg3: the next argument
            :param A4 arg4: the next argument
            :return: the result
            :rtype: R
            """


    class A6Function(java.lang.Object, typing.Generic[A0, A1, A2, A3, A4, A5, R]):
        """
        A 6-argument function
        """

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, arg0: A0, arg1: A1, arg2: A2, arg3: A3, arg4: A4, arg5: A5) -> R:
            """
            Invoke the function
            
            :param A0 arg0: the first argument
            :param A1 arg1: the next argument
            :param A2 arg2: the next argument
            :param A3 arg3: the next argument
            :param A4 arg4: the next argument
            :param A5 arg5: the next argument
            :return: the result
            :rtype: R
            """


    class A7Function(java.lang.Object, typing.Generic[A0, A1, A2, A3, A4, A5, A6, R]):
        """
        A 7-argument function
        """

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, arg0: A0, arg1: A1, arg2: A2, arg3: A3, arg4: A4, arg5: A5, arg6: A6) -> R:
            """
            Invoke the function
            
            :param A0 arg0: the first argument
            :param A1 arg1: the next argument
            :param A2 arg2: the next argument
            :param A3 arg3: the next argument
            :param A4 arg4: the next argument
            :param A5 arg5: the next argument
            :param A6 arg6: the next argument
            :return: the result
            :rtype: R
            """


    class A8Function(java.lang.Object, typing.Generic[A0, A1, A2, A3, A4, A5, A6, A7, R]):
        """
        A 7-argument function
        """

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, arg0: A0, arg1: A1, arg2: A2, arg3: A3, arg4: A4, arg5: A5, arg6: A6, arg7: A7) -> R:
            """
            Invoke the function
            
            :param A0 arg0: the first argument
            :param A1 arg1: the next argument
            :param A2 arg2: the next argument
            :param A3 arg3: the next argument
            :param A4 arg4: the next argument
            :param A5 arg5: the next argument
            :param A6 arg6: the next argument
            :param A7 arg7: the next argument
            :return: the result
            :rtype: R
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mv: org.objectweb.asm.MethodVisitor) -> None:
        """
        Create a new emitter by wrapping the given method visitor.
         
        
        Direct use of this constructor is not recommended, but is useful during transition from
        unchecked to checked bytecode generation.
        
        :param org.objectweb.asm.MethodVisitor mv: the ASM method visitor
        """

    @staticmethod
    def assume(mv: org.objectweb.asm.MethodVisitor, assumedStack: N) -> Emitter[N]:
        """
        (Not recommended) Wrap the given method visitor with assumed stack contents
         
        
        :meth:`start(ClassVisitor, int, String, MthDesc) <.start>` or
        :meth:`start(TRef, ClassVisitor, int, String, MthDesc) <.start>` is recommended instead.
        
        :param N: the stack contents:param org.objectweb.asm.MethodVisitor mv: the ASM method visitor
        :param N assumedStack: the assumed stack contents
        :return: the emitter
        :rtype: Emitter[N]
        """

    @typing.overload
    def emit(self, func: java.util.function.Function[Emitter[N], R]) -> R:
        """
        Emit a 0-argument operator
         
        
        This can also be used to invoke generator subroutines whose only argument is the emitter.
        
        :param R: the return type:param java.util.function.Function[Emitter[N], R] func: the method reference, e.g., :meth:`Op.pop(Emitter) <Op.pop>`.
        :return: the value returned by ``func``
        :rtype: R
        """

    @typing.overload
    def emit(self, func: java.util.function.BiFunction[Emitter[N], A1, R], arg1: A1) -> R:
        """
        Emit a 1-argument operator
         
        
        This can also be used to invoke generator subroutines.
        
        :param R: the return type:param java.util.function.BiFunction[Emitter[N], A1, R] func: the method reference, e.g., :meth:`Op.ldc__i(Emitter, int) <Op.ldc__i>`.
        :param A1 arg1: the argument (other than the emitter) to pass to ``func``
        :return: the value returned by ``func``
        :rtype: R
        """

    @typing.overload
    def emit(self, func: Emitter.A3Function[Emitter[N], A1, A2, R], arg1: A1, arg2: A2) -> R:
        """
        Emit a 2-argument operator
         
        
        This can also be used to invoke generator subroutines.
        
        :param R: the return type:param Emitter.A3Function[Emitter[N], A1, A2, R] func: the method reference
        :param A1 arg1: an argument (other than the emitter) to pass to ``func``
        :param A2 arg2: the next argument
        :return: the value returned by ``func``
        :rtype: R
        """

    @typing.overload
    def emit(self, func: Emitter.A4Function[Emitter[N], A1, A2, A3, R], arg1: A1, arg2: A2, arg3: A3) -> R:
        """
        Emit a 3-argument operator
         
        
        This can also be used to invoke generator subroutines.
        
        :param R: the return type:param Emitter.A4Function[Emitter[N], A1, A2, A3, R] func: the method reference
        :param A1 arg1: an argument (other than the emitter) to pass to ``func``
        :param A2 arg2: the next argument
        :param A3 arg3: the next argument
        :return: the value returned by ``func``
        :rtype: R
        """

    @typing.overload
    def emit(self, func: Emitter.A5Function[Emitter[N], A1, A2, A3, A4, R], arg1: A1, arg2: A2, arg3: A3, arg4: A4) -> R:
        """
        Emit a 4-argument operator
         
        
        This can also be used to invoke generator subroutines.
        
        :param R: the return type:param Emitter.A5Function[Emitter[N], A1, A2, A3, A4, R] func: the method reference
        :param A1 arg1: an argument (other than the emitter) to pass to ``func``
        :param A2 arg2: the next argument
        :param A3 arg3: the next argument
        :param A4 arg4: the next argument
        :return: the value returned by ``func``
        :rtype: R
        """

    @typing.overload
    def emit(self, func: Emitter.A6Function[Emitter[N], A1, A2, A3, A4, A5, R], arg1: A1, arg2: A2, arg3: A3, arg4: A4, arg5: A5) -> R:
        """
        Emit a 5-argument operator
         
        
        This can also be used to invoke generator subroutines.
        
        :param R: the return type:param Emitter.A6Function[Emitter[N], A1, A2, A3, A4, A5, R] func: the method reference
        :param A1 arg1: an argument (other than the emitter) to pass to ``func``
        :param A2 arg2: the next argument
        :param A3 arg3: the next argument
        :param A4 arg4: the next argument
        :param A5 arg5: the next argument
        :return: the value returned by ``func``
        :rtype: R
        """

    @typing.overload
    def emit(self, func: Emitter.A7Function[Emitter[N], A1, A2, A3, A4, A5, A6, R], arg1: A1, arg2: A2, arg3: A3, arg4: A4, arg5: A5, arg6: A6) -> R:
        """
        Emit a 6-argument operator
         
        
        This can also be used to invoke generator subroutines.
        
        :param R: the return type:param Emitter.A7Function[Emitter[N], A1, A2, A3, A4, A5, A6, R] func: the method reference
        :param A1 arg1: an argument (other than the emitter) to pass to ``func``
        :param A2 arg2: the next argument
        :param A3 arg3: the next argument
        :param A4 arg4: the next argument
        :param A5 arg5: the next argument
        :param A6 arg6: the next argument
        :return: the value returned by ``func``
        :rtype: R
        """

    @typing.overload
    def emit(self, func: Emitter.A8Function[Emitter[N], A1, A2, A3, A4, A5, A6, A7, R], arg1: A1, arg2: A2, arg3: A3, arg4: A4, arg5: A5, arg6: A6, arg7: A7) -> R:
        """
        Emit a 7-argument operator
         
        
        This can also be used to invoke generator subroutines.
        
        :param R: the return type:param Emitter.A8Function[Emitter[N], A1, A2, A3, A4, A5, A6, A7, R] func: the method reference
        :param A1 arg1: an argument (other than the emitter) to pass to ``func``
        :param A2 arg2: the next argument
        :param A3 arg3: the next argument
        :param A4 arg4: the next argument
        :param A5 arg5: the next argument
        :param A6 arg6: the next argument
        :param A7 arg7: the next argument
        :return: the value returned by ``func``
        :rtype: R
        """

    def rootScope(self) -> Scope:
        """
        Get the root scope for declaring local variables
        
        :return: the root scope
        :rtype: Scope
        """

    @staticmethod
    @typing.overload
    def start(mv: org.objectweb.asm.MethodVisitor) -> Emitter[Emitter.Bot]:
        """
        Wrap the given method visitor assuming an empty stack
         
        
        :meth:`start(ClassVisitor, int, String, MthDesc) <.start>` or
        :meth:`start(TRef, ClassVisitor, int, String, MthDesc) <.start>` is recommended instead.
        
        :param org.objectweb.asm.MethodVisitor mv: the ASM method visitor
        :return: the emitter
        :rtype: Emitter[Emitter.Bot]
        """

    @staticmethod
    @typing.overload
    def start(cv: org.objectweb.asm.ClassVisitor, access: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], desc: Methods.MthDesc[MR, N]) -> Methods.Def[MR, N]:
        """
        Define a static method
        
        :param MR: the type returned by the method:param N: the parameter types of the method:param org.objectweb.asm.ClassVisitor cv: the ASM class visitor
        :param jpype.JInt or int access: the access flags (static is added automatically)
        :param java.lang.String or str name: the name of the method
        :param Methods.MthDesc[MR, N] desc: the method descriptor
        :return: an object to aid further definition of the method
        :rtype: Methods.Def[MR, N]
        """

    @staticmethod
    @typing.overload
    def start(owner: Types.TRef[OT], cv: org.objectweb.asm.ClassVisitor, access: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], desc: Methods.MthDesc[MR, N]) -> Methods.ObjDef[MR, OT, N]:
        """
        Define an instance method
        
        :param MR: the type returned by the method:param OT: the type owning the method:param N: the parameter types of the method:param Types.TRef[OT] owner: the owner type (as a reference type)
        :param org.objectweb.asm.ClassVisitor cv: the ASM class visitor
        :param jpype.JInt or int access: the access flags (static is forcibly removed)
        :param java.lang.String or str name: the name of the method
        :param Methods.MthDesc[MR, N] desc: the method descriptor
        :return: an object to aid further definition of the method
        :rtype: Methods.ObjDef[MR, OT, N]
        """


class Types(java.lang.Object):
    """
    A namespace for types describing Java types
    """

    class SType(java.lang.Object):
        """
        Types that may be returned by a method in Java source
         
        
        This is essentially "all types including ``void``" as far as Java is concerned.
        """

        class_: typing.ClassVar[java.lang.Class]

        def cls(self) -> java.lang.Class[typing.Any]:
            """
            Get the Java class to describe this type
             
            
            For generated types, this may instead be a suitable super type.
            
            :return: the class
            :rtype: java.lang.Class[typing.Any]
            """

        def type(self) -> org.objectweb.asm.Type:
            """
            Get the ASM type for this type
            
            :return: the type
            :rtype: org.objectweb.asm.Type
            """


    class SNonVoid(Types.SType):
        """
        Types that may be ascribed to a variable in Java source
         
        
        This is essentially "all types except ``void``" as far as Java is concerned.
        """

        class_: typing.ClassVar[java.lang.Class]


    class SPrim(Types.SNonVoid, typing.Generic[A]):
        """
        The primitive types that may be ascribed to a variable in Java source
         
        
        This is essentially "all non-reference types" as far as Java is concerned.
        """

        class_: typing.ClassVar[java.lang.Class]

        def t(self) -> int:
            """
            The type id, as in :meth:`MethodVisitor.visitIntInsn(int, int) <MethodVisitor.visitIntInsn>` for
            :obj:`Opcodes.NEWARRAY`, e.g., :obj:`Opcodes.T_INT`.
            
            :return: the type id
            :rtype: int
            """


    class BType(Types.SType):
        """
        The types that may be ascribed to local variables in JVM bytecode, and ``void``
         
        
        This includes ``void``, all reference types, but only the primitive types ``int``,
        ``float``, ``long``, and ``double``. The other primitive types are stored in
        ``int`` local variables.
        """

        class_: typing.ClassVar[java.lang.Class]

        def internalName(self) -> str:
            """
            Get the internal name of the type
            
            :return: the internal name
            :rtype: str
            """


    class BNonVoid(Types.BType, Types.SNonVoid):
        """
        The types that may be ascribed to local variables in JVM bytecode
        """

        class_: typing.ClassVar[java.lang.Class]

        def slots(self) -> int:
            """
            :return: the number of slots (stack entries or local indices) taken by this type
            :rtype: int
            """


    class BPrim(Types.BNonVoid, Types.SPrim[A], typing.Generic[A]):
        """
        The primitive types that may be ascribed to local variables in JVM bytecode
         
        
        This includes only ``int``, ``float``, ``long``, and ``double``.
        """

        class_: typing.ClassVar[java.lang.Class]


    class TVoid(java.lang.Enum[Types.TVoid], Types.BType):
        """
        The ``void`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TVoid]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TVoid:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TVoid]:
            ...


    class TCat1(Types.BNonVoid):
        """
        Category 1 types as defined by the JVM specification
         
        
        This includes reference types, ``int``, and ``float``.
        """

        class_: typing.ClassVar[java.lang.Class]


    class TRef(java.lang.Record, Types.TCat1, typing.Generic[T]):
        """
        Reference types
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, cls: java.lang.Class[T], type: org.objectweb.asm.Type) -> None:
            ...

        def cls(self) -> java.lang.Class[T]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> org.objectweb.asm.Type:
            ...


    class TBool(java.lang.Enum[Types.TBool], Types.SPrim[jpype.JArray[jpype.JBoolean]]):
        """
        The ``boolean`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TBool]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TBool:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TBool]:
            ...


    class TByte(java.lang.Enum[Types.TByte], Types.SPrim[jpype.JArray[jpype.JByte]]):
        """
        The ``byte`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TByte]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TByte:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TByte]:
            ...


    class TChar(java.lang.Enum[Types.TChar], Types.SPrim[jpype.JArray[jpype.JChar]]):
        """
        The ``char`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TChar]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TChar:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TChar]:
            ...


    class TShort(java.lang.Enum[Types.TShort], Types.SPrim[jpype.JArray[jpype.JShort]]):
        """
        The ``short`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TShort]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TShort:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TShort]:
            ...


    class TInt(java.lang.Enum[Types.TInt], Types.TCat1, Types.BPrim[jpype.JArray[jpype.JInt]]):
        """
        The ``int`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TInt]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TInt]:
            ...


    class TFloat(java.lang.Enum[Types.TFloat], Types.TCat1, Types.BPrim[jpype.JArray[jpype.JFloat]]):
        """
        The ``float`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TFloat]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TFloat:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TFloat]:
            ...


    class TCat2(Types.BNonVoid):
        """
        Category 2 types as defined by the JVM specification
         
        
        This includes ``long`` and ``double``.
        """

        class_: typing.ClassVar[java.lang.Class]


    class TLong(java.lang.Enum[Types.TLong], Types.TCat2, Types.BPrim[jpype.JArray[jpype.JLong]]):
        """
        The ``long`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TLong]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TLong:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TLong]:
            ...


    class TDouble(java.lang.Enum[Types.TDouble], Types.TCat2, Types.BPrim[jpype.JArray[jpype.JDouble]]):
        """
        The ``double`` type
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Types.TDouble]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Types.TDouble:
            ...

        @staticmethod
        def values() -> jpype.JArray[Types.TDouble]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    T_VOID: typing.Final[Types.TVoid]
    """
    The ``void`` type
    """

    T_BOOL: typing.Final[Types.TBool]
    """
    The ``boolean`` type
    """

    T_BYTE: typing.Final[Types.TByte]
    """
    The ``byte`` type
    """

    T_CHAR: typing.Final[Types.TChar]
    """
    The ``char`` type
    """

    T_SHORT: typing.Final[Types.TShort]
    """
    The ``short`` type
    """

    T_INT: typing.Final[Types.TInt]
    """
    The ``int`` type
    """

    T_LONG: typing.Final[Types.TLong]
    """
    The ``long`` type
    """

    T_FLOAT: typing.Final[Types.TFloat]
    """
    The ``float`` type
    """

    T_DOUBLE: typing.Final[Types.TDouble]
    """
    The ``double`` type
    """

    T_BOOL_ARR: typing.Final[Types.TRef[jpype.JArray[jpype.JBoolean]]]
    """
    The ``boolean[]`` type
    """

    T_BYTE_ARR: typing.Final[Types.TRef[jpype.JArray[jpype.JByte]]]
    """
    The ``byte[]`` type
    """

    T_CHAR_ARR: typing.Final[Types.TRef[jpype.JArray[jpype.JChar]]]
    """
    The ``char[]`` type
    """

    T_SHORT_ARR: typing.Final[Types.TRef[jpype.JArray[jpype.JShort]]]
    """
    The ``short[]`` type
    """

    T_INT_ARR: typing.Final[Types.TRef[jpype.JArray[jpype.JInt]]]
    """
    The ``int[]`` type
    """

    T_LONG_ARR: typing.Final[Types.TRef[jpype.JArray[jpype.JLong]]]
    """
    The ``long[]`` type
    """

    T_FLOAT_ARR: typing.Final[Types.TRef[jpype.JArray[jpype.JFloat]]]
    """
    The ``float[]`` type
    """

    T_DOUBLE_ARR: typing.Final[Types.TRef[jpype.JArray[jpype.JDouble]]]
    """
    The ``double[]`` type
    """


    @staticmethod
    @typing.overload
    def refExtends(cls: java.lang.Class[ST], desc: typing.Union[java.lang.String, str]) -> Types.TRef[T]:
        """
        Create a type describing an extension of the given class (or interface) type
         
        
        This is used when the type is itself dynamically generated, but it is at least known to
        extend a type defined by compiled Java source. This is best used with a type variable on the
        class in the Java source that generates the type. Unfortunately, that variable may bleed into
        any number of classes and methods which support that generation, esp., since this is almost
        always required to describe the type of ``this``, and ``this`` is frequently accessed
        in generated code. Conventionally, the type variable is called ``THIS``:
         
         
        class MyGenerator<THIS extends MyIf> {
            private final TRef<THIS> typeThis = refExtends(MyIf.class, generateDesc());
        }
         
        
        :param ST: the super type:param T: the type variable used to refer to the extension:param java.lang.Class[ST] cls: the class of the super type
        :param java.lang.String or str desc: the internal name of the actual generated extension type
        :return: the type
        :rtype: Types.TRef[T]
        """

    @staticmethod
    @typing.overload
    def refExtends(st: Types.TRef[ST], desc: typing.Union[java.lang.String, str]) -> Types.TRef[T]:
        """
        See :meth:`refExtends(Class, String) <.refExtends>`
        
        :param ST: the super type:param T: the type variable used to refer to the extension:param Types.TRef[ST] st: the super type
        :param java.lang.String or str desc: the internal name of the actual generated extension type
        :return: the type
        :rtype: Types.TRef[T]
        """

    @staticmethod
    @typing.overload
    def refExtends(st: Types.TRef[ST], reflected: java.lang.Class[typing.Any]) -> Types.TRef[T]:
        """
        Create a type describing a reflected extension of a given class (or interface) type
         
        
        This is used when the type is only known through reflection, but it is at least known to
        extend some other fixed type. This is best used with a type variable on the method that
        generates code wrt. the reflected class.
        
        :param ST: the super type:param T: the type variable used to refer to the extension:param Types.TRef[ST] st: the super type
        :param java.lang.Class[typing.Any] reflected: the reflected class
        :return: the type
        :rtype: Types.TRef[T]
        """

    @staticmethod
    def refOf(cls: java.lang.Class[T]) -> Types.TRef[T]:
        """
        Create a type describing a reference of the given class (or interface) type
        
        :param T: the type of the Java class:param java.lang.Class[T] cls: the class
        :return: the type
        :rtype: Types.TRef[T]
        """



__all__ = ["Scope", "Lbl", "Methods", "Misc", "Fld", "Local", "SubScope", "Check", "ChildScope", "Op", "RootScope", "Emitter", "Types"]
