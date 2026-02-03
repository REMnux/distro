from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import java.lang # type: ignore


class SignatureWithDatatypesApplyAction(AbstractFunctionComparisonApplyAction):
    """
    Action for applying full function signatures and referenced data types from one function to
    another in the dual decompiler or dual listing view.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str]):
        """
        Constructor for applying function signature and all its referenced data types action
        
        :param java.lang.String or str owner: the action owner
        """


class EmptySignatureApplyAction(AbstractFunctionComparisonApplyAction):
    """
    Action for applying skeleton function signatures from one function to another in the dual
    decompiler or dual listing view. By skeleton, we mean signatures where all complex data types 
    (e.g., Structures) are replaced by empty placeholder data types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str]):
        """
        Constructor for applying skeleton function signatures action
        
        :param java.lang.String or str owner: the action owner
        """


class FunctionNameApplyAction(AbstractFunctionComparisonApplyAction):
    """
    Action for applying function names and namespaces from one function to another in the dual
    decompiler or dual listing view.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str]):
        """
        Constructor for applying function name and namespace action
        
        :param java.lang.String or str owner: the action owner
        """


class AbstractFunctionComparisonApplyAction(docking.action.DockingAction):
    """
    Base classes for applying function information from a one side or the other in the function
    comparison window
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Constructor for base apply action
        
        :param java.lang.String or str name: the name of the action
        :param java.lang.String or str owner: the owner of the action
        the dual listing view or the dual decompiler view each of which produce their own action
        context types. Each different view creates their own version of each action using the
        context handler appropriate for that view.
        """



__all__ = ["SignatureWithDatatypesApplyAction", "EmptySignatureApplyAction", "FunctionNameApplyAction", "AbstractFunctionComparisonApplyAction"]
