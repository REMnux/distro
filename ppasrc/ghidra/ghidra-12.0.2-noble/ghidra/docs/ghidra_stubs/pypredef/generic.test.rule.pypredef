from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import org.junit.rules # type: ignore
import org.junit.runner # type: ignore
import org.junit.runners.model # type: ignore


class IgnoreUnfinishedRule(org.junit.rules.TestRule):
    """
    A test rule which processes the :obj:`IgnoreUnfinished` annotation
     
     
    
    This must be included in your test case (or a superclass) as a field with the :obj:`Rule`
    annotation. It's included in the :obj:`AbstractGenericTest`, so most Ghidra test classes already
    have it.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IgnoreUnfinishedStatement(org.junit.runners.model.Statement):
    """
    A JUnit test statement that ignores :obj:`TODOException`
    
    
    .. seealso::
    
        | :obj:`IgnoreUnfinished`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, base: org.junit.runners.model.Statement):
        ...


class RepeatedTestRule(org.junit.rules.TestRule):
    """
    A test rule which processes the :obj:`Repeated` annotation
     
     
    
    This must be included in your test case (or a superclass) as a field with the :obj:`Rule`
    annotation. It's included in :obj:`AbstractGenericTest`, so most Ghidra test classes already
    have it.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RepeatedStatement(org.junit.runners.model.Statement):
    """
    A JUnit test statement that repeats its base statement 1 or more times
    
    
    .. seealso::
    
        | :obj:`Repeated`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, base: org.junit.runners.model.Statement, description: org.junit.runner.Description, count: typing.Union[jpype.JInt, int]):
        """
        Construct the statement
        
        :param org.junit.runners.model.Statement base: the base statement to repeat
        :param org.junit.runner.Description description: the description of the test
        :param jpype.JInt or int count: the number of repetitions, must be positive
        """



__all__ = ["IgnoreUnfinishedRule", "IgnoreUnfinishedStatement", "RepeatedTestRule", "RepeatedStatement"]
