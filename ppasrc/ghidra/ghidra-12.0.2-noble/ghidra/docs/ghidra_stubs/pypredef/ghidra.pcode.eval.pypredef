from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.exec_
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang # type: ignore


T = typing.TypeVar("T")


class AbstractVarnodeEvaluator(VarnodeEvaluator[T], typing.Generic[T]):
    """
    An abstract implementation of :obj:`VarnodeEvaluator`
     
     
    
    Unlike :obj:`PcodeExecutor` this abstract class is not explicitly bound to a p-code state nor
    arithmetic. Instead it defines abstract methods for accessing "leaf" varnodes and evaluating ops.
    To evaluate a varnode, it first checks if the varnode is a leaf, which is defined by an extension
    class. If it is, it converts the static address to a dynamic one and invokes the appropriate
    value getter. An extension class would likely implement those getters using a
    :obj:`PcodeExecutorState`. If the varnode is not a leaf, the evaluator will ascend by examining
    its defining p-code op, evaluate its input varnodes recursively and then compute the output using
    the provided p-code arithmetic. This implementation maintains a map of evaluated varnodes and
    their values so that any intermediate varnode is evaluated just once. Note that the evaluation
    algorithm assumes their are no cycles in the AST, which should be the case by definition.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def evaluateVarnode(self, program: ghidra.program.model.listing.Program, vn: ghidra.program.model.pcode.Varnode) -> T:
        """
        Evaluate a varnode
        
        :param ghidra.program.model.listing.Program program: the program containing the varnode
        :param ghidra.program.model.pcode.Varnode vn: the varnode to evaluate
        :return: the value of the varnode
        :rtype: T
        """


class VarnodeEvaluator(java.lang.Object, typing.Generic[T]):
    """
    An evaluator of high varnodes
     
     
    
    This is a limited analog to :obj:`PcodeExecutor` but for high p-code. It is limited in that it
    can only "execute" parts of the AST that represent expressions, as a means of evaluating them. If
    it encounters, e.g., a :obj:`PcodeOp.MULTIEQUAL` or phi node, it will terminate throw an
    exception.
    """

    class_: typing.ClassVar[java.lang.Class]

    def evaluateOp(self, program: ghidra.program.model.listing.Program, op: ghidra.program.model.pcode.PcodeOp) -> T:
        """
        Evaluate a high p-code op
        
        :param ghidra.program.model.listing.Program program: the program containing the op
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op
        :return: the value of the op's output
        :rtype: T
        """

    def evaluateStorage(self, program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage) -> T:
        """
        Evaluate variable storage
         
         
        
        Each varnode is evaluated as in :meth:`evaluateStorage(Program, VariableStorage) <.evaluateStorage>` and then
        concatenated. The lower-indexed varnodes in storage are the more significant pieces, similar
        to big endian.
        
        :param ghidra.program.model.listing.Program program: the program containing the variable storage
        :param ghidra.program.model.listing.VariableStorage storage: the storage
        :return: the value of the storage
        :rtype: T
        """

    def evaluateVarnode(self, program: ghidra.program.model.listing.Program, vn: ghidra.program.model.pcode.Varnode) -> T:
        """
        Evaluate a varnode
        
        :param ghidra.program.model.listing.Program program: the program containing the varnode
        :param ghidra.program.model.pcode.Varnode vn: the varnode to evaluate
        :return: the value of the varnode
        :rtype: T
        """


class ArithmeticVarnodeEvaluator(AbstractVarnodeEvaluator[T], typing.Generic[T]):
    """
    An abstract implementation of :obj:`VarnodeEvaluator` that evaluates ops using a bound
    :obj:`PcodeArithmetic`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, arithmetic: ghidra.pcode.exec_.PcodeArithmetic[T]):
        """
        Construct an evaluator
        
        :param ghidra.pcode.exec_.PcodeArithmetic[T] arithmetic: the arithmetic for computing p-code op outputs
        """

    @staticmethod
    def catenate(arithmetic: ghidra.pcode.exec_.PcodeArithmetic[T], sizeTotal: typing.Union[jpype.JInt, int], upper: T, lower: T, sizeLower: typing.Union[jpype.JInt, int]) -> T:
        """
        A convenience for concatenating two varnodes
         
         
        
        There is no p-code op for catenation, but it is easily achieved as one might do in C or
        SLEIGH: ``shift`` the left piece then ``or`` it with the right piece.
        
        :param T: the type of values:param ghidra.pcode.exec_.PcodeArithmetic[T] arithmetic: the p-code arithmetic for values of type ``T``
        :param jpype.JInt or int sizeTotal: the expected output size in bytes
        :param T upper: the value of the left (more significant) piece
        :param T lower: the value of the right (less significant) piece
        :param jpype.JInt or int sizeLower: the size of the lower piece
        :return: the result of concatenation
        :rtype: T
        """



__all__ = ["AbstractVarnodeEvaluator", "VarnodeEvaluator", "ArithmeticVarnodeEvaluator"]
