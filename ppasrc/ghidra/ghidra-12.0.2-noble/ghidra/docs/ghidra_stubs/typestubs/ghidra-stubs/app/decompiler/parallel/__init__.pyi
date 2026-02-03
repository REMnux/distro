from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic
import generic.cache
import generic.concurrent
import ghidra.app.decompiler
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


D = typing.TypeVar("D")
R = typing.TypeVar("R")


class DecompilerMapFunction(java.lang.Object, typing.Generic[D]):

    class_: typing.ClassVar[java.lang.Class]

    def evaluate(self, decompiler: ghidra.app.decompiler.DecompInterface, function: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor) -> D:
        ...


class DecompilerCallback(generic.concurrent.QCallback[ghidra.program.model.listing.Function, R], typing.Generic[R]):
    """
    An implementation of :obj:`QCallback` that performs the management of the 
    :obj:`DecompInterface` instances using a Pool.
     
     
    Clients will get a chance to configure each newly created decompiler via the passed-in
    :obj:`DecompileConfigurer`.
     
     
    Clients must implement :meth:`process(DecompileResults, TaskMonitor) <.process>`, which will be
    called for each function that is decompiled.
    """

    @typing.type_check_only
    class DecompilerFactory(generic.cache.CountingBasicFactory[ghidra.app.decompiler.DecompInterface]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, configurer: DecompileConfigurer):
        ...

    def dispose(self):
        """
        Call this when all work is done so that the pooled decompilers can be disposed
        """

    def process(self, results: ghidra.app.decompiler.DecompileResults, monitor: ghidra.util.task.TaskMonitor) -> R:
        """
        This is called when a function is decompiled.
        
        :param ghidra.app.decompiler.DecompileResults results: the decompiled results
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the client result
        :rtype: R
        :raises java.lang.Exception: if there is any issue processing the given results
        """

    def setTimeout(self, timeoutSecs: typing.Union[jpype.JInt, int]):
        """
        Sets the timeout for each decompile
        
        :param jpype.JInt or int timeoutSecs: the timeout in seconds
        """


class ChunkingParallelDecompiler(java.lang.Object, typing.Generic[R]):
    """
    A class that simplifies some the concurrent datastructure setup required for decompiling 
    functions.  This class is meant to be used when you wish to decompile functions in groups 
    (or chunks) rather than decompiling all functions at once.
    """

    class_: typing.ClassVar[java.lang.Class]

    def decompileFunctions(self, functions: java.util.List[ghidra.program.model.listing.Function]) -> java.util.List[R]:
        ...

    def dispose(self):
        ...


class ParallelDecompiler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createChunkingParallelDecompiler(callback: generic.concurrent.QCallback[ghidra.program.model.listing.Function, R], monitor: ghidra.util.task.TaskMonitor) -> ChunkingParallelDecompiler[R]:
        """
        Creates an object that can be used to perform decompilation of a limited number of
        functions at a time, as opposed to working over an entire range of functions at once.
        :meth:`decompileFunctions(QCallback, Program, AddressSetView, TaskMonitor) <.decompileFunctions>` will create
        and tear down concurrent data structures on each use, making repeated calls less efficient.
        You would use this method when you wish to perform periodic work as results are returned
        **and when using the callback mechanism is not sufficient** such as when ordering of
        results is required.
        
        :param generic.concurrent.QCallback[ghidra.program.model.listing.Function, R] callback: the callback required to perform work.
        :param ghidra.util.task.TaskMonitor monitor: the monitor used to report progress and to cancel
        :return: the parallel decompiler used for decompiling.
        :rtype: ChunkingParallelDecompiler[R]
        """

    @staticmethod
    @typing.overload
    def decompileFunctions(callback: generic.concurrent.QCallback[ghidra.program.model.listing.Function, R], program: ghidra.program.model.listing.Program, addresses: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[R]:
        """
        Decompile the given functions using multiple decompilers
        
        :param generic.concurrent.QCallback[ghidra.program.model.listing.Function, R] callback: the callback to be called for each item that is processed
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.AddressSetView addresses: the addresses restricting which functions to decompile
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the list of client results
        :rtype: java.util.List[R]
        :raises java.lang.InterruptedException: if interrupted
        :raises java.lang.Exception: if any other exception occurs
        """

    @staticmethod
    @typing.overload
    def decompileFunctions(callback: generic.concurrent.QCallback[ghidra.program.model.listing.Function, R], functions: collections.abc.Sequence, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[R]:
        """
        Decompile the given functions using multiple decompilers
        
        :param generic.concurrent.QCallback[ghidra.program.model.listing.Function, R] callback: the callback to be called for each item that is processed
        :param collections.abc.Sequence functions: the functions to decompile
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the list of client results
        :rtype: java.util.List[R]
        :raises java.lang.InterruptedException: if interrupted
        :raises java.lang.Exception: if any other exception occurs
        """

    @staticmethod
    @typing.overload
    def decompileFunctions(callback: generic.concurrent.QCallback[ghidra.program.model.listing.Function, R], program: ghidra.program.model.listing.Program, functions: java.util.Iterator[ghidra.program.model.listing.Function], resultsConsumer: java.util.function.Consumer[R], monitor: ghidra.util.task.TaskMonitor):
        """
        Decompile the given functions using multiple decompilers.
        
         
        Results will be passed to the given consumer as they are produced.  Calling this
        method allows you to handle results as they are discovered.
        
         
        **This method will wait for all processing before returning.**
        
        :param generic.concurrent.QCallback[ghidra.program.model.listing.Function, R] callback: the callback to be called for each that is processed
        :param ghidra.program.model.listing.Program program: the program
        :param java.util.Iterator[ghidra.program.model.listing.Function] functions: the functions to decompile
        :param java.util.function.Consumer[R] resultsConsumer: the consumer to which results will be passed
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises java.lang.InterruptedException: if interrupted
        :raises java.lang.Exception: if any other exception occurs
        """


class DecompileConfigurer(java.lang.Object):
    """
    A callback interface that will be given a newly created :obj:`DecompInterface` to 
    configure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def configure(self, decompiler: ghidra.app.decompiler.DecompInterface):
        """
        Configure the given decompiler
        
        :param ghidra.app.decompiler.DecompInterface decompiler: the decompiler to configure
        """


class DecompilerReducer(java.lang.Object, typing.Generic[R, D]):

    class_: typing.ClassVar[java.lang.Class]

    def reduce(self, list: java.util.List[generic.DominantPair[ghidra.program.model.address.Address, D]]) -> R:
        ...



__all__ = ["DecompilerMapFunction", "DecompilerCallback", "ChunkingParallelDecompiler", "ParallelDecompiler", "DecompileConfigurer", "DecompilerReducer"]
