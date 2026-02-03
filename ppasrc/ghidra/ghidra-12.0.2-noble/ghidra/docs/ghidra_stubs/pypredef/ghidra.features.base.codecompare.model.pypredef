from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.listing
import java.lang # type: ignore
import java.util # type: ignore


class MatchedFunctionComparisonModel(AbstractFunctionComparisonModel):
    """
    A FunctionComparisonModel comprised of matched pairs of source and target functions. Each
    source function has its own set of target functions that it can be compared with.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addMatch(self, sourceFunction: ghidra.program.model.listing.Function, targetFunction: ghidra.program.model.listing.Function):
        """
        Adds a new comparison to the model. If the sourceFunction already exists on the left side,
        then the target function will be added to that specific function's right side functions. 
        Otherwise, the source function will be added to the left side the given target as its only
        right side function.
        
        :param ghidra.program.model.listing.Function sourceFunction: the left side function to add
        :param ghidra.program.model.listing.Function targetFunction: the right side function to add for that source function
        """

    def getSourceFunctions(self) -> java.util.List[ghidra.program.model.listing.Function]:
        ...

    def removeFunction(self, function: ghidra.program.model.listing.Function):
        """
        Removes the given function from all comparisons in the model, whether
        stored as a source or target
        
        :param ghidra.program.model.listing.Function function: the function to remove
        """

    @typing.overload
    def removeFunctions(self, functions: collections.abc.Sequence):
        """
        Removes all the given functions from all comparisons in the model
        
        :param collections.abc.Sequence functions: the functions to remove
        """

    @typing.overload
    def removeFunctions(self, program: ghidra.program.model.listing.Program):
        """
        Removes all functions in the model that come from the given
        program
        
        :param ghidra.program.model.listing.Program program: the program to remove functions from
        """

    @property
    def sourceFunctions(self) -> java.util.List[ghidra.program.model.listing.Function]:
        ...


class FunctionComparisonModel(java.lang.Object):
    """
    A model for comparing one or more functions in a side by side display. The model supports the
    concept of a set of functions that can be selected for each side of the comparison. It also 
    maintains the selected function for each side. The default model simply has a single set
    of functions that can be selected for either side of the comparison. The model supports the
    concept of different sets of functions for each and even the idea that the active function for
    one side can determine the set of functions for the other side. See 
    :obj:`MatchedFunctionComparisonModel`.
     
    
    This model is intended to be used by the :obj:`FunctionComparisonService` to generate
    a function comparison display window. 
     
    
    Note: Subscribers may register to be informed of changes to this model via the
    :obj:`comparison model listener <FunctionComparisonModelListener>` interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addFunctionComparisonModelListener(self, listener: FunctionComparisonModelListener):
        """
        Adds the given listener to the list of those to be notified of model changes.
        
        :param FunctionComparisonModelListener listener: the listener to add
        """

    def getActiveFunction(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.listing.Function:
        """
        Returns the active (selected) function for the given side.
        
        :param ghidra.util.datastruct.Duo.Side side: the side to get the active function for
        :return: the active function for the given side
        :rtype: ghidra.program.model.listing.Function
        """

    def getFunctions(self, side: ghidra.util.datastruct.Duo.Side) -> java.util.List[ghidra.program.model.listing.Function]:
        """
        Returns the list of all functions on the given side that could be made active.
        
        :param ghidra.util.datastruct.Duo.Side side: the side to get functions for
        :return: the list of all functions on the given side that could be made active
        :rtype: java.util.List[ghidra.program.model.listing.Function]
        """

    def isEmpty(self) -> bool:
        """
        Returns true if the model has no function to compare.
        
        :return: true if the model has no functions to compare
        :rtype: bool
        """

    def removeFunction(self, function: ghidra.program.model.listing.Function):
        """
        Removes the given function from both sides of the comparison.
        
        :param ghidra.program.model.listing.Function function: the function to remove
        """

    def removeFunctionComparisonModelListener(self, listener: FunctionComparisonModelListener):
        """
        Removes the given listener from the list of those to be notified of model changes.
        
        :param FunctionComparisonModelListener listener: the listener to remove
        """

    @typing.overload
    def removeFunctions(self, functions: collections.abc.Sequence):
        """
        Removes all the given functions from both sides of the comparison.
        
        :param collections.abc.Sequence functions: the functions to remove
        """

    @typing.overload
    def removeFunctions(self, program: ghidra.program.model.listing.Program):
        """
        Removes all functions from the given program from both sides of the comparison
        
        :param ghidra.program.model.listing.Program program: that program whose functions should be removed from this model
        """

    def setActiveFunction(self, side: ghidra.util.datastruct.Duo.Side, function: ghidra.program.model.listing.Function) -> bool:
        """
        Sets the function for the given side. The function must be one of the functions from that
        side's set of functions
        
        :param ghidra.util.datastruct.Duo.Side side: the side to set the function for
        :param ghidra.program.model.listing.Function function: the function so set for the given side
        :return: true if the function was made active or false if the function does not exist for the
        given side
        :rtype: bool
        """

    @property
    def functions(self) -> java.util.List[ghidra.program.model.listing.Function]:
        ...

    @property
    def activeFunction(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class FunctionComparisonModelListener(java.lang.Object):
    """
    Allows subscribers to register for :obj:`function
    comparison model <FunctionComparisonModel>` changes
    """

    class_: typing.ClassVar[java.lang.Class]

    def activeFunctionChanged(self, side: ghidra.util.datastruct.Duo.Side, function: ghidra.program.model.listing.Function):
        """
        Notification that the selected function changed on one side or the other.
        
        :param ghidra.util.datastruct.Duo.Side side: the side whose selected function changed
        :param ghidra.program.model.listing.Function function: the new selected function for the given side
        """

    def modelDataChanged(self):
        """
        Notification that the set of functions on at least one side changed. The selected functions
        on either side may have also changed.
        """


class AbstractFunctionComparisonModel(FunctionComparisonModel):
    """
    Base class for implementers of the FunctionComparisonModel. Provides listener support and
    tracking for the selected function for each side.
    """

    @typing.type_check_only
    class FunctionComparator(java.util.Comparator[ghidra.program.model.listing.Function]):
        """
        Orders functions by program path and then name and then address
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FUNCTION_COMPARATOR: typing.ClassVar[java.util.Comparator[ghidra.program.model.listing.Function]]

    def __init__(self):
        ...


class AnyToAnyFunctionComparisonModel(AbstractFunctionComparisonModel):
    """
    Basic FunctionComparisonModel where a set of functions can be compared with each other
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, functions: collections.abc.Sequence):
        ...

    @typing.overload
    def __init__(self, left: ghidra.program.model.listing.Function, right: ghidra.program.model.listing.Function):
        ...

    @typing.overload
    def __init__(self, *functions: ghidra.program.model.listing.Function):
        ...

    def addFunction(self, function: ghidra.program.model.listing.Function):
        ...

    def addFunctions(self, additionalFunctions: collections.abc.Sequence):
        ...



__all__ = ["MatchedFunctionComparisonModel", "FunctionComparisonModel", "FunctionComparisonModelListener", "AbstractFunctionComparisonModel", "AnyToAnyFunctionComparisonModel"]
