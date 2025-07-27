from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.xml.sax # type: ignore


T = typing.TypeVar("T")


class DecisionSet(java.lang.Object):
    """
    The result object returned from a scan of a decision tree looking for property values that
    match the constrains for some test object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, propertyName: typing.Union[java.lang.String, str]):
        ...

    def getDecisionPropertyName(self) -> str:
        """
        Returns the name of the property that was scanned for in the decision tree.
        
        :return: the name of the property that was scanned for in the decision tree.
        :rtype: str
        """

    def getDecisions(self) -> java.util.List[Decision]:
        """
        Returns a list of all the decisions whose descision path constraints matched the given
        test object.
        
        :return: a list of all the decisions whose descision path constraints matched the given
        test object.
        :rtype: java.util.List[Decision]
        """

    def getValues(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of property values from decision paths that matched the constraints.
        
        :return: a list of property values from decision paths that matched the constraints.
        :rtype: java.util.List[java.lang.String]
        """

    def isEmpty(self) -> bool:
        """
        Returns true if this decisionSet has no results.
        
        :return: true if this decisionSet has no results.
        :rtype: bool
        """

    @property
    def values(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def decisionPropertyName(self) -> java.lang.String:
        ...

    @property
    def decisions(self) -> java.util.List[Decision]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class Decision(java.lang.Object):
    """
    Result object from getting values that match the constraints for given test object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: typing.Union[java.lang.String, str], decisionPath: java.util.List[java.lang.String], source: typing.Union[java.lang.String, str]):
        ...

    def getDecisionPath(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of strings where each string is a description of the constraint that passed
        to reach this decision.
        
        :return: a list of strings where each string is a description of the constraint that passed
        to reach this decision.
        :rtype: java.util.List[java.lang.String]
        """

    def getDescisionPathString(self) -> str:
        """
        Returns a string that is a description of the constraints that passed
        to reach this decision.
        
        :return: a string that is a description of the constraints that passed
        to reach this decision.
        :rtype: str
        """

    def getSource(self) -> str:
        """
        Returns the constraint source file that added the value for this decision.
        
        :return: the constraint source file that added the value for this decision.
        :rtype: str
        """

    def getValue(self) -> str:
        """
        Returns the value of the property for which this decision matched the constraints
        
        :return: the value of the property for which this decision matched the constraints
        :rtype: str
        """

    @property
    def descisionPathString(self) -> java.lang.String:
        ...

    @property
    def source(self) -> java.lang.String:
        ...

    @property
    def decisionPath(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def value(self) -> java.lang.String:
        ...


class DecisionTree(java.lang.Object, typing.Generic[T]):
    """
    A decisionTree is used to find property values that are determined by traversing a tree
    of constraints. Each node in the tree has an associated constraint.  If the constraint is
    satisfied for a given test object, then its child nodes are tested to find more and more
    specific results.  When either there are no children in a node or none of the children's 
    constraints are satisfied or by traversing those that are satisfied did not result in find
    a property match, the current node is check to see if it has a value for the property being
    search.  If so, that result is added as a Decision.
     
     
    There can be multiple paths where all constraints a matched resulting in multiple possible
    decisions.</P>
     
    A non-leaf node can have properties as well, that serve as a default if it's constraint
    is satisfied, but not of its children is satisfied or resulted in a decision.</P>
    """

    @typing.type_check_only
    class XMLErrorHandler(org.xml.sax.ErrorHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getDecisionsSet(self, testObject: T, propertyName: typing.Union[java.lang.String, str]) -> DecisionSet:
        """
        Searches the decision tree for values of given property name that match the constraints
        within this tree.
        
        :param T testObject: the object that the constraints are test against.
        :param java.lang.String or str propertyName: the name of the property whose values are being collected.
        :return: a DecisionSet containing all the values of the given property whose path in the
        tree matched all the constraints for the given test object.
        :rtype: DecisionSet
        """

    @typing.overload
    def loadConstraints(self, name: typing.Union[java.lang.String, str], stream: java.io.InputStream):
        """
        Loads the tree from an xml data contained within an input stream. Note: this method can be
        called multiple times, with each call appending to the existing tree.
        
        :param java.lang.String or str name: the name of the input source so that decisions can be traced back to 
        the appropriate xml constraints source.
        :param java.io.InputStream stream: the InputStream from which to read an xml constraints specification.
        :raises IOException: if an I/O problem occurs reading from the stream.
        :raises XmlParseException: if the XML is not property formatted or a tag that is not
        a constraint name or property name is encountered.
        """

    @typing.overload
    def loadConstraints(self, file: generic.jar.ResourceFile):
        """
        Loads the tree from an xml constraint file. Note: this method can be called multiple times,
        with each call appending to the existing tree.
        
        :param generic.jar.ResourceFile file: the file that contains the xml for the constraint.
        :raises IOException: if an I/O problem occurs reading from the stream.
        :raises XmlParseException: if the XML is not property formatted or a tag that is not
        a constraint name or property name is encountered.
        """

    def registerConstraintType(self, name: typing.Union[java.lang.String, str], constraintClass: java.lang.Class[Constraint[T]]):
        """
        Registers a constraint class to be recognized from an xml constraint specification file.
        
        :param java.lang.String or str name: the name of the constraint which is also the xml tag value.
        :param java.lang.Class[Constraint[T]] constraintClass: the constraint type which will be initialized from the xml constraint
        specification file.
        """

    def registerPropertyName(self, propertyName: typing.Union[java.lang.String, str]):
        """
        Registers a property name.  Every tag in an xml constraint file (except the root tag which
        is unused) must be either a constraint name or a property name.
        
        :param java.lang.String or str propertyName: the name of a valid property to be expected in an xml constraints file.
        """


class ConstraintData(java.lang.Object):
    """
    Convenience class that converts XML attributes into typed property values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mappings: collections.abc.Mapping):
        ...

    def getBoolean(self, name: typing.Union[java.lang.String, str]) -> bool:
        ...

    def getDouble(self, name: typing.Union[java.lang.String, str]) -> float:
        ...

    def getFloat(self, name: typing.Union[java.lang.String, str]) -> float:
        ...

    def getInt(self, name: typing.Union[java.lang.String, str]) -> int:
        ...

    def getLong(self, name: typing.Union[java.lang.String, str]) -> int:
        ...

    def getString(self, name: typing.Union[java.lang.String, str]) -> str:
        ...

    def hasValue(self, name: typing.Union[java.lang.String, str]) -> bool:
        ...

    @property
    def boolean(self) -> jpype.JBoolean:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def double(self) -> jpype.JDouble:
        ...

    @property
    def float(self) -> jpype.JFloat:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...


class Constraint(java.lang.Object, typing.Generic[T]):
    """
    Constraints are used to make decisions to traverse a decision tree where each node in the
    tree has a constraint that is used to decide if that node is part of the successful decision path.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructor takes the name of the constraint.  This name will be tag used in the XML
        specification file.
        
        :param java.lang.String or str name: the name of the constraint
        """

    def getDescription(self) -> str:
        """
        Returns a description of this constraint (with its configuration data) to be used
        to journal the decision path that was taken.
        
        :return: a description of this constraint with its configuration data.
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of the constraint.  Note: this name is also the XML tag used in the 
        constraints specification files.
        
        :return: the name of the constraint
        :rtype: str
        """

    def isSatisfied(self, t: T) -> bool:
        """
        Returns true if the given object satisfies this constraint.
        
        :param T t: the object to test this constraint on.
        :return: true if the given object satisfies this constraint.
        :rtype: bool
        """

    def loadConstraintData(self, data: ConstraintData):
        """
        Initialized this constraint state.  Attributes in the xml element with this constaints
        tag name will be extracted into the ConstraintData object for easy retrieval.
        
        :param ConstraintData data: the ConstraintData object used to initialize this constraint.
        """

    @property
    def satisfied(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class RootDecisionNode(DecisionNode[T], typing.Generic[T]):
    """
    Special root node for a decision tree.  Root nodes don't have a real constraint, so 
    a dummy constraint that is always satisfied is used.
    """

    @typing.type_check_only
    class DummyConstraint(Constraint[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DecisionNode(java.lang.Object, typing.Generic[T]):
    """
    A node in a decision tree.  Each node contains exactly one constraint and a map of property
    values.
    """

    @typing.type_check_only
    class PropertyValue(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, constraint: Constraint[T], parent: DecisionNode[T]):
        ...

    def getOrCreateNodeForContraint(self, newConstraint: Constraint[T]) -> DecisionNode[T]:
        ...

    def populateDecisions(self, t: T, decisionSet: DecisionSet, propertyName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def setProperty(self, propertyName: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str]):
        ...

    @property
    def orCreateNodeForContraint(self) -> DecisionNode[T]:
        ...



__all__ = ["DecisionSet", "Decision", "DecisionTree", "ConstraintData", "Constraint", "RootDecisionNode", "DecisionNode"]
