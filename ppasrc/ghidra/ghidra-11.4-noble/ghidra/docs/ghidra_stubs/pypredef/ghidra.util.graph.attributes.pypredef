from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.graph
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class LongAttribute(Attribute[T], typing.Generic[T]):
    """
    This class provides a storage mechanism for long-valued information about
    the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
    """

    @typing.type_check_only
    class LongComparator(java.util.Comparator[ghidra.util.graph.KeyedObject]):
        """
        This class is a comparator (see java.util.Comparator) for
        KeyedObjects having a LongAttribute. Keyed Objects are first
        compared by the value of the attribute. Ties are broken by
        considering the keys of the KeyedObjects.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], set: ghidra.util.graph.KeyIndexableSet[T]):
        """
        Constructor.
        
        :param java.lang.String or str name: The name used to identify this attribute.
        :param ghidra.util.graph.KeyIndexableSet[T] set: The KeyIndexableSet whose elements can be assigned
        a value within this attribute.
        """

    def attributeType(self) -> str:
        """
        Return the type of Attribute, i.e. what kind of values does
        this attribute hold. "Long", "Object", "Double" are examples.
        """

    def clear(self):
        """
        Removes all assigned values of this attribute.
        """

    def getValue(self, o: ghidra.util.graph.KeyedObject) -> int:
        """
        Return the value associated to the specified KeyedObject.
        
        :raises NoValueException: if the value has not been set or 
        the KeyedObject does not belong to the owningSet.
        """

    def getValueAsString(self, o: ghidra.util.graph.KeyedObject) -> str:
        """
        Return the attribute of the specified KeyedObject as a String.
        """

    def setValue(self, o: ghidra.util.graph.KeyedObject, value: typing.Union[jpype.JLong, int]):
        """
        Set the value of this attribute for the specified KeyedObject.
        
        :param ghidra.util.graph.KeyedObject o: The KeyedObject that is assigned the value. Should
        be a member of the owningSet.
        :param jpype.JLong or int value: The value to associate with the specified KeyedObject.
        """

    @typing.overload
    def toSortedArray(self) -> jpype.JArray[ghidra.util.graph.KeyedObject]:
        """
        Returns the elements of the owningSet sorted by their
        values of this Attribute.
        """

    @typing.overload
    def toSortedArray(self, keyedObjects: jpype.JArray[ghidra.util.graph.KeyedObject]) -> jpype.JArray[ghidra.util.graph.KeyedObject]:
        """
        Sorts the array of keyedObjects by their values of this 
        Attribute.
        """

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class AttributeManager(java.lang.Object, typing.Generic[T]):
    """
    Class which creates and keeps track of attributes defined 
    for a single KeyIndexableSet.
    """

    class_: typing.ClassVar[java.lang.Class]
    INTEGER_TYPE: typing.Final = "INTEGER_TYPE"
    """
    Use this String as the attributeType to create an IntegerAttribute.
    """

    LONG_TYPE: typing.Final = "LONG_TYPE"
    """
    Use this String as the attributeType to create an LongAttribute.
    """

    DOUBLE_TYPE: typing.Final = "DOUBLE_TYPE"
    """
    Use this String as the attributeType to create an DoubleAttribute.
    """

    STRING_TYPE: typing.Final = "STRING_TYPE"
    """
    Use this String as the attributeType to create an StringAttribute.
    """

    OBJECT_TYPE: typing.Final = "OBJECT_TYPE"
    """
    Use this String as the attributeType to create an ObjectAttribute.
    """


    def __init__(self, attributedSet: ghidra.util.graph.KeyIndexableSet[T]):
        """
        Constructor.
        
        :param ghidra.util.graph.KeyIndexableSet[T] attributedSet: The KeyIndexableSet whose Attributes this
        AttributeManager manages.
        """

    def clear(self):
        """
        Clears all of the attributes managed by this AttributeManager 
        while leaving the attributes defined.
        """

    def createAttribute(self, attributeName: typing.Union[java.lang.String, str], attributeType: typing.Union[java.lang.String, str]) -> Attribute[T]:
        """
        Create a new attribute.
        
        :param java.lang.String or str attributeName: The name used to identify this Attribute.
        :param java.lang.String or str attributeType: The type of Attribute to construct. Public static
        Strings have been defined for the various choices.
        """

    def getAttribute(self, attributeName: typing.Union[java.lang.String, str]) -> Attribute[T]:
        """
        Returns the attribute with the specified name. Returns null
        if there is no attribute with that name.
        """

    def getAttributeNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns an array of all names of attributes managed by
        this AttributeManager.
        """

    def hasAttributeNamed(self, attributeName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if there is an attribute with the specified name managed
        by this attribute manager.
        """

    def removeAttribute(self, attributeName: typing.Union[java.lang.String, str]):
        """
        Remove the attribute with the specified name from this AttributeManager.
        """

    @property
    def attributeNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def attribute(self) -> Attribute[T]:
        ...


class ObjectAttribute(Attribute[T], typing.Generic[T]):
    """
    This class provides a storage mechanism for Object-valued information about
    the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], set: ghidra.util.graph.KeyIndexableSet[T]):
        """
        Constructor.
        
        :param java.lang.String or str name: The name used to identify this attribute.
        :param ghidra.util.graph.KeyIndexableSet[T] set: The KeyIndexableSet whose elements can be assigned
        a value within this attribute.
        """

    def attributeType(self) -> str:
        """
        Return the type of Attribute, i.e. what kind of values does
        this attribute hold. "Long", "Object", "Double" are examples.
        """

    def clear(self):
        """
        Removes all assigned values of this attribute.
        """

    def getValue(self, o: ghidra.util.graph.KeyedObject) -> java.lang.Object:
        """
        Return the value associated to the specified KeyedObject.
        """

    def getValueAsString(self, o: ghidra.util.graph.KeyedObject) -> str:
        """
        Return the attribute of the specified KeyedObject as a String.
        """

    def setValue(self, o: T, value: java.lang.Object) -> bool:
        """
        Set the value of this attribute for the specified KeyedObject.
        
        :param T o: The KeyedObject that is assigned the value. Should
        be a member of the owningSet.
        :param java.lang.Object value: The value to associate with the specified KeyedObject.
        :return: true if the value could be set. Return false if o is
        not a member of the owningSet.
        :rtype: bool
        """

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...


class IntegerAttribute(Attribute[T], typing.Generic[T]):
    """
    This class provides a storage mechanism for integer-valued information about
    the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
    """

    @typing.type_check_only
    class IntegerComparator(java.util.Comparator[ghidra.util.graph.KeyedObject]):
        """
        This class is a comparator (see java.util.Comparator) for
        KeyedObjects having a IntegerAttribute. Keyed Objects are first
        compared by the value of the attribute. Ties are broken by
        considering the keys of the KeyedObjects.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], set: ghidra.util.graph.KeyIndexableSet[T]):
        """
        Constructor.
        
        :param java.lang.String or str name: The name used to identify this attribute.
        :param ghidra.util.graph.KeyIndexableSet[T] set: The KeyIndexableSet whose elements can be assigned
        a value within this attribute.
        """

    def attributeType(self) -> str:
        """
        Return the type of Attribute, i.e. what kind of values does
        this attribute hold. "Long", "Object", "Double" are examples.
        """

    def clear(self):
        """
        Removes all assigned values of this attribute.
        """

    def getValue(self, o: ghidra.util.graph.KeyedObject) -> int:
        """
        Return the value associated to the specified KeyedObject.
        
        :raises NoValueException: if the value has not been set or 
        the KeyedObject does not belong to the owningSet.
        """

    def getValueAsString(self, o: ghidra.util.graph.KeyedObject) -> str:
        """
        Return the attribute of the specified KeyedObject as a String.
        """

    def setValue(self, o: T, value: typing.Union[jpype.JInt, int]):
        """
        Set the value of this attribute for the specified KeyedObject.
        
        :param T o: The KeyedObject that is assigned the value. Should
        be a member of the owningSet.
        :param jpype.JInt or int value: The value to associate with the specified KeyedObject.
        """

    @typing.overload
    def toSortedArray(self) -> jpype.JArray[ghidra.util.graph.KeyedObject]:
        """
        Returns the elements of the owningSet sorted by their
        values of this Attribute.
        """

    @typing.overload
    def toSortedArray(self, keyedObjects: jpype.JArray[ghidra.util.graph.KeyedObject]) -> jpype.JArray[ghidra.util.graph.KeyedObject]:
        """
        Sorts the array of keyedObjects by their values of this 
        Attribute.
        """

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class DoubleAttribute(Attribute[T], typing.Generic[T]):
    """
    This class provides a storage mechanism for double-valued information about
    the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
    """

    @typing.type_check_only
    class DoubleComparator(java.util.Comparator[ghidra.util.graph.KeyedObject]):
        """
        This class is a comparator (see java.util.Comparator) for
        KeyedObjects having a DoubleAttribute. Keyed Objects are first
        compared by the value of the attribute. Ties are broken by
        considering the keys of the KeyedObjects.
        """

        class_: typing.ClassVar[java.lang.Class]

        def compare(self, object1: ghidra.util.graph.KeyedObject, object2: ghidra.util.graph.KeyedObject) -> int:
            """
            Compares two Objects. See java.util.Comparator
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], set: ghidra.util.graph.KeyIndexableSet[T]):
        """
        Constructor.
        
        :param java.lang.String or str name: The name used to identify this attribute.
        :param ghidra.util.graph.KeyIndexableSet[T] set: The KeyIndexableSet whose elements can be assigned
        a value within this attribute.
        """

    def attributeType(self) -> str:
        """
        Return the type of Attribute, i.e. what kind of values does
        this attribute hold. "Long", "Object", "Double" are examples.
        """

    def clear(self):
        """
        Removes all assigned values of this attribute.
        """

    def getValue(self, o: ghidra.util.graph.KeyedObject) -> float:
        """
        Return the value associated to the specified KeyedObject.
        
        :raises NoValueException: if the value has not been set or 
        the KeyedObject does not belong to the owningSet.
        """

    def getValueAsString(self, o: ghidra.util.graph.KeyedObject) -> str:
        """
        Return the attribute of the specified KeyedObject as a String.
        """

    def setValue(self, o: T, value: typing.Union[jpype.JDouble, float]) -> bool:
        """
        Set the value of this attribute for the specified KeyedObject.
        
        :param T o: The KeyedObject that is assigned the value. Should
        be a member of the owningSet.
        :param jpype.JDouble or float value: The value to associate with the specified KeyedObject.
        :return: true if the value could be set. Return false if o is
        not a member of the owningSet.
        :rtype: bool
        """

    @typing.overload
    def toSortedArray(self) -> jpype.JArray[ghidra.util.graph.KeyedObject]:
        """
        Returns the elements of the owningSet sorted by their
        values of this Attribute.
        """

    @typing.overload
    def toSortedArray(self, keyedObjects: jpype.JArray[ghidra.util.graph.KeyedObject]) -> jpype.JArray[ghidra.util.graph.KeyedObject]:
        """
        Sorts the array of keyedObjects by their values of this 
        Attribute.
        """

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def value(self) -> jpype.JDouble:
        ...


class StringAttribute(Attribute[T], typing.Generic[T]):
    """
    This class provides a storage mechanism for String-valued information about
    the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
    """

    @typing.type_check_only
    class StringComparator(java.util.Comparator[ghidra.util.graph.KeyedObject]):
        """
        This class is a comparator (see java.util.Comparator) for
        KeyedObjects having a StringAttribute. Keyed Objects are first
        compared by the value of the attribute. Ties are broken by
        considering the keys of the KeyedObjects.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], set: ghidra.util.graph.KeyIndexableSet[T]):
        """
        Constructor.
        
        :param java.lang.String or str name: The name used to identify this attribute.
        :param ghidra.util.graph.KeyIndexableSet[T] set: The KeyIndexableSet whose elements can be assigned
        a value within this attribute.
        """

    def attributeType(self) -> str:
        """
        Return the type of Attribute, i.e. what kind of values does
        this attribute hold. "Long", "Object", "Double" are examples.
        """

    def clear(self):
        """
        Removes all assigned values of this attribute.
        """

    def getValue(self, o: ghidra.util.graph.KeyedObject) -> str:
        """
        Return the value associated to the specied KeyedObject.
        """

    def getValueAsString(self, o: ghidra.util.graph.KeyedObject) -> str:
        """
        Return the attribute of the specified KeyedObject as a String.
        """

    def setValue(self, o: T, value: typing.Union[java.lang.String, str]) -> bool:
        """
        Set the value of this attribute for the specified KeyedObject.
        
        :param T o: The KeyedObject that is assigned the value. Should
        be a member of the owningSet.
        :param java.lang.String or str value: The value to associate with the specified KeyedObject.
        :return: true if the value could be set. Return false if o is
        not a member of the owningSet.
        :rtype: bool
        """

    @typing.overload
    def toSortedArray(self) -> jpype.JArray[ghidra.util.graph.KeyedObject]:
        """
        Returns the elements of the owningSet sorted by their
        values of this Attribute.
        """

    @typing.overload
    def toSortedArray(self, keyedObjects: jpype.JArray[ghidra.util.graph.KeyedObject]) -> jpype.JArray[ghidra.util.graph.KeyedObject]:
        """
        Sorts the array of keyedObjects by their values of this 
        Attribute.
        """

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def value(self) -> java.lang.String:
        ...


class Attribute(java.lang.Object, typing.Generic[T]):
    """
    Base class for attributes -- int, double, or String values -- which can
    be assigned to the members of a KeyIndexableSet, e.g. the vertices or
    edges of a DirectedGraph. The attributes do not track changes in the owning
    set, but you can check if the owning set has been modified since creation
    time. It is possible to create an attribute on the vertex set and then
    remove the vertex from the graph. An attempt to get the value associated
    with that vertex will cause a NoValueException to be thrown.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], set: ghidra.util.graph.KeyIndexableSet[T]):
        """
        Constructor
        
        :param java.lang.String or str name: name of the attribute
        :param ghidra.util.graph.KeyIndexableSet[T] set: set whose members may have attribute values defined
        """

    def attributeType(self) -> str:
        """
        Return the type of Attribute, i.e. what kind of values does
        this attribute hold. "Long", "Object", "Double" are examples.
        """

    def clear(self):
        """
        Undefine all values set for this attribute.
        """

    def getModificationNumber(self) -> int:
        """
        Return the current value of the modificationNumber which counts
        the number of changes this Attribute has undergone.
        """

    def getValueAsString(self, o: ghidra.util.graph.KeyedObject) -> str:
        """
        Return the attribute of the specified KeyedObject as a String.
        """

    def name(self) -> str:
        """
        Return the name of this Attribute.
        """

    def owningSet(self) -> ghidra.util.graph.KeyIndexableSet[T]:
        """
        Return the KeyIndexableSet, typically a VertexSet or EdgeSet, that
        this attribute is defined for. An attribute value can only be set
        for a KeyedObject if it is a member of the owningSet.
        """

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def modificationNumber(self) -> jpype.JLong:
        ...



__all__ = ["LongAttribute", "AttributeManager", "ObjectAttribute", "IntegerAttribute", "DoubleAttribute", "StringAttribute", "Attribute"]
