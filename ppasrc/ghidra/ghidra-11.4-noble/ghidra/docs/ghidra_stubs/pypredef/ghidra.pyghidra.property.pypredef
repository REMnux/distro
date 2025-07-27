from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


T = typing.TypeVar("T")


class ByteJavaProperty(AbstractJavaProperty[java.lang.Byte]):
    """
    The :obj:`JavaProperty` for the primitive **byte** type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> int:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: int
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


class IntegerJavaProperty(AbstractJavaProperty[java.lang.Integer]):
    """
    The :obj:`JavaProperty` for the primitive **int** type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> int:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: int
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


class LongJavaProperty(AbstractJavaProperty[java.lang.Long]):
    """
    The :obj:`JavaProperty` for the primitive **long** type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> int:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: int
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


class ShortJavaProperty(AbstractJavaProperty[java.lang.Short]):
    """
    The :obj:`JavaProperty` for the primitive **short** type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> int:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: int
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


class JavaProperty(java.lang.Object, typing.Generic[T]):
    """
    Property interface for creating a Python property for getters and setters.
    
    Each implementation is required to have a defined fget method which returns
    the corresponding primitive type. By doing so we can utilize Python duck typing,
    auto boxing/unboxing and the Jpype conversion system to automatically convert
    the primitive return types to the equivalent Python type. This removes the
    headache of having to carefully and explicitly cast things to an int to
    avoid exceptions in Python code related to type conversion or type attributes.
    
    The fget and fset methods are named to correspond with the fget and fset members
    of Python's property type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fset(self, self_: java.lang.Object, value: T):
        """
        The method to be used as the fset value for a Python property.
        
        This method will be called by the Python property __set__ function.
        
        :param java.lang.Object self: the object containing the property
        :param T value: the value to be set
        :raises java.lang.Throwable: if any exception occurs while setting the value
        """


class CharacterJavaProperty(AbstractJavaProperty[java.lang.Character]):
    """
    The :obj:`JavaProperty` for the primitive **char** type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> str:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: str
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


class BooleanJavaProperty(AbstractJavaProperty[java.lang.Boolean]):
    """
    The :obj:`JavaProperty` for the primitive **boolean** type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> bool:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: bool
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


class PropertyUtils(java.lang.Object):
    """
    Utility class for working with classes to obtain and create Python properties.
     
    This class is for **internal use only** and is only public so it can be
    reached from Python.
    """

    @typing.type_check_only
    class PropertyPairFactory(java.lang.Object):
        """
        Helper class for merging methods and removing a layer of reflection
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PartialProperty(java.lang.Object):
        """
        Helper class for combining the methods into a property
        """

        class_: typing.ClassVar[java.lang.Class]

        def getName(self) -> str:
            ...

        def isGetter(self) -> bool:
            ...

        def isSetter(self) -> bool:
            ...

        @property
        def getter(self) -> jpype.JBoolean:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def setter(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getProperties(cls: java.lang.Class[typing.Any]) -> jpype.JArray[JavaProperty[typing.Any]]:
        """
        Gets an array of :obj:`JavaProperty` for the provided class.
         
        This method is for **internal use only** and is only public
        so it can be called from Python.
        
        :param java.lang.Class[typing.Any] cls: the class to get the properties for
        :return: an array of properties
        :rtype: jpype.JArray[JavaProperty[typing.Any]]
        """


class ObjectJavaProperty(AbstractJavaProperty[java.lang.Object]):
    """
    The :obj:`JavaProperty` for a reference type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> java.lang.Object:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: java.lang.Object
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


class FloatJavaProperty(AbstractJavaProperty[java.lang.Float]):
    """
    The :obj:`JavaProperty` for the primitive **float** type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> float:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: float
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


@typing.type_check_only
class AbstractJavaProperty(JavaProperty[T], typing.Generic[T]):
    """
    Abstract base class for implementing a :obj:`JavaProperty`.
    
    This class provides the fset implementation as well as all helpers so
    that each child class only needs to define a constructor and a fget
    method returning the correct primitive type. Each child class can
    implement fget as follows:
    
    .. code-block:: java
        :dedent: 4
    
        public type fget(Object self) throws Throwable { // @highlight substring="type"
            return doGet(self);
        }
         
    
    
    
    The PyGhidra internals expects every :obj:`JavaProperty` to be an instance of this class.
    No checking is required or performed since the :obj:`JavaProperty` interface and this
    class are sealed.
    """

    class_: typing.ClassVar[java.lang.Class]
    field: typing.Final[java.lang.String]
    """
    The name of the property
    """


    def hasGetter(self) -> bool:
        """
        Checks if this property has a getter
        
        :return: true if this property has a getter
        :rtype: bool
        """

    def hasSetter(self) -> bool:
        """
        Checks if this property has a setter
        
        :return: true if this property has a setter
        :rtype: bool
        """


class DoubleJavaProperty(AbstractJavaProperty[java.lang.Double]):
    """
    The :obj:`JavaProperty` for the primitive **double** type
    """

    class_: typing.ClassVar[java.lang.Class]

    def fget(self, self_: java.lang.Object) -> float:
        """
        The method to be used as the fget value for a Python property.
        
        This method will be called by the Python property __get__ function.
        
        :param java.lang.Object self: the object containing the property
        :return: the property's value
        :rtype: float
        :raises java.lang.Throwable: if any exception occurs while getting the value
        """


@typing.type_check_only
class JavaPropertyFactory(java.lang.Object):
    """
    Factory class for a :obj:`JavaProperty`
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ByteJavaProperty", "IntegerJavaProperty", "LongJavaProperty", "ShortJavaProperty", "JavaProperty", "CharacterJavaProperty", "BooleanJavaProperty", "PropertyUtils", "ObjectJavaProperty", "FloatJavaProperty", "AbstractJavaProperty", "DoubleJavaProperty", "JavaPropertyFactory"]
