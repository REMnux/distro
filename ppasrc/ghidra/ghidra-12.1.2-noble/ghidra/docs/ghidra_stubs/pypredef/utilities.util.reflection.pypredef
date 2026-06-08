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


T = typing.TypeVar("T")


class ReflectionUtilities(java.lang.Object):

    @typing.type_check_only
    class StackElementMatcher(java.lang.Object):

        @typing.type_check_only
        class Match(java.lang.Enum[ReflectionUtilities.StackElementMatcher.Match]):

            class_: typing.ClassVar[java.lang.Class]
            EXACT: typing.Final[ReflectionUtilities.StackElementMatcher.Match]
            CONTAINS: typing.Final[ReflectionUtilities.StackElementMatcher.Match]

            @staticmethod
            def valueOf(name: typing.Union[java.lang.String, str]) -> ReflectionUtilities.StackElementMatcher.Match:
                ...

            @staticmethod
            def values() -> jpype.JArray[ReflectionUtilities.StackElementMatcher.Match]:
                ...


        @typing.type_check_only
        class Content(java.lang.Enum[ReflectionUtilities.StackElementMatcher.Content]):

            class_: typing.ClassVar[java.lang.Class]
            CLASS_NAME: typing.Final[ReflectionUtilities.StackElementMatcher.Content]
            CLASS_AND_METHOD_NAME: typing.Final[ReflectionUtilities.StackElementMatcher.Content]
            ALL: typing.Final[ReflectionUtilities.StackElementMatcher.Content]

            @staticmethod
            def valueOf(name: typing.Union[java.lang.String, str]) -> ReflectionUtilities.StackElementMatcher.Content:
                ...

            @staticmethod
            def values() -> jpype.JArray[ReflectionUtilities.StackElementMatcher.Content]:
                ...


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createFilteredThrowable(*patterns: typing.Union[java.lang.String, str]) -> java.lang.Throwable:
        """
        A convenience method to create a throwable, filtering any lines that contain the given
        non-regex patterns.  This can be useful for emitting diagnostic stack traces.
        
        :param jpype.JArray[java.lang.String] patterns: the non-regex patterns used to perform a
                            :meth:`String.contains(CharSequence) <String.contains>` on each :obj:`StackTraceElement`
                            line.
        :return: the new throwable
        :rtype: java.lang.Throwable
        """

    @staticmethod
    def createJavaFilteredThrowable() -> java.lang.Throwable:
        """
        A convenience method to create a throwable, filtering boiler-plate Java-related
        lines (e.g., AWT, Swing, Security, etc).
        This can be useful for emitting diagnostic stack traces with reduced noise.
        
        :return: the new throwable
        :rtype: java.lang.Throwable
        """

    @staticmethod
    def createJavaFilteredThrowableString() -> str:
        """
        A convenience method to create a throwable, filtering boiler-plate Java-related
        lines (e.g., AWT, Swing, Security, etc).
        This can be useful for emitting diagnostic stack traces with reduced noise.
        
         
        This method differs from :meth:`createJavaFilteredThrowable() <.createJavaFilteredThrowable>` in that this method
        returns a String, which is useful when printing log messages without having to directly
        print the stack trace.
        
        :return: the new throwable
        :rtype: str
        """

    @staticmethod
    def createStackTraceForAllThreads() -> str:
        """
        Returns a string which is a printout of a stack trace for each thread running in the
        current JVM
        
        :return: the stack trace string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def createThrowableWithStackOlderThan(*patterns: typing.Union[java.lang.String, str]) -> java.lang.Throwable:
        """
        Creates a throwable whose stack trace is based upon the current call stack, with any
        information coming before, and including, the given patterns removed.
        
        :param jpype.JArray[java.lang.String] patterns: the strings to ignore (e.g., class or package names)
        :return: the new throwable
        :rtype: java.lang.Throwable
        
        .. seealso::
        
            | :obj:`.createThrowableWithStackOlderThan(Class...)`
        """

    @staticmethod
    @typing.overload
    def createThrowableWithStackOlderThan(*classes: java.lang.Class[typing.Any]) -> java.lang.Throwable:
        """
        Creates a throwable whose stack trace is based upon the current call stack, with any
        information coming before, and including, the given classes removed.
         
        
        This method can take multiple classes, but you really only need to pass the oldest
        class of disinterest.
        
        :param jpype.JArray[java.lang.Class[typing.Any]] classes: the classes to ignore
        :return: the new throwable
        :rtype: java.lang.Throwable
        """

    @staticmethod
    def filterJavaThrowable(t: java.lang.Throwable) -> java.lang.Throwable:
        """
        A convenience method to take a throwable, filter boiler-plate Java-related
        lines (e.g., AWT, Swing, Security, etc).
        This can be useful for emitting diagnostic stack traces with reduced noise.
        
        :param java.lang.Throwable t: the throwable to filter
        :return: the throwable
        :rtype: java.lang.Throwable
        """

    @staticmethod
    def filterStackTrace(trace: jpype.JArray[java.lang.StackTraceElement], *patterns: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.StackTraceElement]:
        """
        Uses the given ``patterns`` to remove elements from the given stack trace.
        The current implementation will simply perform a ``toString()`` on each element and
        then check to see if that string contains any of the ``patterns``.
        
        :param jpype.JArray[java.lang.StackTraceElement] trace: the trace to filter
        :param jpype.JArray[java.lang.String] patterns: the non-regex patterns used to perform a
                            :meth:`String.contains(CharSequence) <String.contains>` on each :obj:`StackTraceElement`
                            line.
        :return: the filtered trace
        :rtype: jpype.JArray[java.lang.StackTraceElement]
        """

    @staticmethod
    def getAllParents(c: java.lang.Class[typing.Any]) -> java.util.LinkedHashSet[java.lang.Class[typing.Any]]:
        """
        Returns an order set of all interfaces implemented and classes extended for the entire
        type structure of the given class.
         
        
        If ``Object.class`` is passed to this method, then it will be returned in the
        result of this method.
        
        :param java.lang.Class[typing.Any] c: the class to introspect
        :return: the set of parents
        :rtype: java.util.LinkedHashSet[java.lang.Class[typing.Any]]
        """

    @staticmethod
    @typing.overload
    def getClassNameOlderThan(*classes: java.lang.Class[typing.Any]) -> str:
        """
        Returns the class name of the entry in the stack that comes before all references to the
        given classes.  This is useful for figuring out at runtime who is calling a particular
        method.
         
        
        This method can take multiple classes, but you really only need to pass the oldest
        class of disinterest.
        
        :param jpype.JArray[java.lang.Class[typing.Any]] classes: the classes to ignore
        :return: the desired class name
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getClassNameOlderThan(*patterns: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the class name of the entry in the stack that comes before all references to the
        given patterns.  This is useful for figuring out at runtime who is calling a particular
        method.
        
        :param jpype.JArray[java.lang.String] patterns: the patterns to ignore
        :return: the desired class name
        :rtype: str
        """

    @staticmethod
    def getSharedHierarchy(list: java.util.List[typing.Any]) -> java.util.LinkedHashSet[java.lang.Class[typing.Any]]:
        """
        Returns an ordered set of interfaces and classes that are shared amongst the items in
        the list.
         
        
        The order of the items is as they are first encountered, favoring interfaces before
        classes.  Further, interface hierarchies are examined before concrete parent extensions.
         
        
        If the given items have no parents in common, then the result will be a list with
        only ``Object.class``.
        
        :param java.util.List[typing.Any] list: the items to examine
        :return: the set of items
        :rtype: java.util.LinkedHashSet[java.lang.Class[typing.Any]]
        """

    @staticmethod
    def getSharedParents(list: java.util.List[typing.Any]) -> java.util.LinkedHashSet[java.lang.Class[typing.Any]]:
        """
        Returns an ordered set of parent interfaces and classes that are shared
        amongst the items in the list.
         
        
        The order of the items is as they are first encountered, favoring interfaces before
        classes.  Further, interface hierarchies are examined before concrete parent extensions.
         
        
        If the given items have no parents in common, then the result will be a list with
        only ``Object.class``.
        
        :param java.util.List[typing.Any] list: the items to examine
        :return: the set of items
        :rtype: java.util.LinkedHashSet[java.lang.Class[typing.Any]]
        """

    @staticmethod
    def getTypeArguments(baseClass: java.lang.Class[T], childClass: java.lang.Class[T]) -> java.util.List[java.lang.Class[typing.Any]]:
        """
        Returns the type arguments for the given base class and extension.
        
         
        Caveat: this lookup will only work if the given child class is a concrete class that
        has its type arguments specified.  For example, these cases will work:
         
                // anonymous class definition
                List<String> myList = new ArrayList<String>() {
                    ...
                };
        
                // class definition
                public class MyList implements List<String> {
         
        
        Whereas this case will not work:
         
                // local variable with the type specified
                List<String> myList = new ArrayList<String>();
         
        
         
        Note: a null entry in the result list will exist for any type that was unrecoverable
        
        :param T: the type of the base and child class:param java.lang.Class[T] baseClass: the base class
        :param java.lang.Class[T] childClass: the child class
        :return: the type arguments
        :rtype: java.util.List[java.lang.Class[typing.Any]]
        """

    @staticmethod
    def locateConstructorOnClass(containingClass: java.lang.Class[typing.Any], parameterTypes: jpype.JArray[java.lang.Class[typing.Any]]) -> java.lang.reflect.Constructor[typing.Any]:
        ...

    @staticmethod
    def locateFieldByTypeOnClass(classType: java.lang.Class[typing.Any], containingClass: java.lang.Class[typing.Any]) -> java.lang.reflect.Field:
        """
        Get the first field specification contained within containingClass which has the type classType.
        This method is only really useful if it is known that only a single field of
        classType exists within the containingClass hierarchy.
        
        :param java.lang.Class[typing.Any] classType: the class
        :param java.lang.Class[typing.Any] containingClass: the class that contains a field of the given type
        :return: field which corresponds to type classType or null
        :rtype: java.lang.reflect.Field
        """

    @staticmethod
    def locateFieldObjectOnClass(fieldName: typing.Union[java.lang.String, str], containingClass: java.lang.Class[typing.Any]) -> java.lang.reflect.Field:
        """
        Locates the field of the name ``fieldName`` on the given
        class.  If the given class does not contain the field, then this
        method will recursively call up ``containingClass``'s
        implementation tree looking for a parent implementation of the
        requested field.
        
        :param java.lang.String or str fieldName: The name of the field to locate.
        :param java.lang.Class[typing.Any] containingClass: The class that contains the desired field.
        :return: The Field object that matches the given name, or null if not
                suitable field could be found.
        :rtype: java.lang.reflect.Field
        """

    @staticmethod
    def locateMethodObjectOnClass(methodName: typing.Union[java.lang.String, str], containingClass: java.lang.Class[typing.Any], parameterTypes: jpype.JArray[java.lang.Class[typing.Any]]) -> java.lang.reflect.Method:
        """
        Locates the method of the name ``methodName`` on the given
        class.  If the given class does not contain the method, then this
        method will recursively call up ``containingClass``'s
        implementation tree looking for a parent implementation of the
        requested method.
        
        :param java.lang.String or str methodName: The name of the method to locate.
        :param java.lang.Class[typing.Any] containingClass: The class that contains the desired method.
        :param jpype.JArray[java.lang.Class[typing.Any]] parameterTypes: The parameters of the desired method (may be null).
        :return: The Method object that matches the given name, or null if not
                suitable method could be found.
        :rtype: java.lang.reflect.Method
        """

    @staticmethod
    def locateStaticFieldObjectOnClass(fieldName: typing.Union[java.lang.String, str], containingClass: java.lang.Class[typing.Any]) -> java.lang.reflect.Field:
        """
        Locates the field of the name ``fieldName`` on the given
        class.  If the given class does not contain the field, then this
        method will recursively call up ``containingClass``'s
        implementation tree looking for a parent implementation of the
        requested field.
        
        :param java.lang.String or str fieldName: The name of the field to locate.
        :param java.lang.Class[typing.Any] containingClass: The class that contains the desired field.
        :return: The Field object that matches the given name, or null if not
                suitable field could be found.
        :rtype: java.lang.reflect.Field
        """

    @staticmethod
    def movePastStackTracePattern(trace: jpype.JArray[java.lang.StackTraceElement], pattern: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.StackTraceElement]:
        """
        Finds the first occurrence of the given pattern and then stops filtering when it finds
        something that is not that pattern
        
        :param jpype.JArray[java.lang.StackTraceElement] trace: the trace to update
        :param java.lang.String or str pattern: the non-regex patterns used to perform a
                        :meth:`String.contains(CharSequence) <String.contains>` on each :obj:`StackTraceElement` line
        :return: the updated trace
        :rtype: jpype.JArray[java.lang.StackTraceElement]
        """

    @staticmethod
    @typing.overload
    def stackTraceToString(t: java.lang.Throwable) -> str:
        """
        Turns the given :obj:`Throwable` into a String version of its
        :meth:`Throwable.printStackTrace() <Throwable.printStackTrace>` method.
        
        :param java.lang.Throwable t: the throwable
        :return: the string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def stackTraceToString(message: typing.Union[java.lang.String, str], t: java.lang.Throwable) -> str:
        """
        Turns the given :obj:`Throwable` into a String version of its
        :meth:`Throwable.printStackTrace() <Throwable.printStackTrace>` method.
        
        :param java.lang.String or str message: the preferred message to use.  If null, the throwable message will be used
        :param java.lang.Throwable t: the throwable
        :return: the string
        :rtype: str
        """



__all__ = ["ReflectionUtilities"]
