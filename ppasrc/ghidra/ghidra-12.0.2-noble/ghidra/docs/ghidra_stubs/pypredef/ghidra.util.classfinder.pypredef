from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing.event # type: ignore


T = typing.TypeVar("T")


class ClassTranslator(java.lang.Object):
    """
    ``ClassTranslator`` provides a way to map an old Ghidra class to
    a current Ghidra class. It can be used whenever a class is moved or renamed
    and Ghidra needs to know.
     
    **Important**: Any class that is indicated by the currentClassPath
    passed to the ``put`` method should implement ``ExtensionPoint``.
     
    Whenever a class whose name gets stored in the data base is moved to 
    another package or renamed, the map of the old class path name to the 
    new one should get put into the ClassTranslator.
     
    Example:  The class ``ghidra.app.plugin.core.MyPlugin.MyInfo`` is in Ghidra version 1.
    In Ghidra version 2, it is moved and renamed to ``ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo``.
    Put the following static initializer in the version 2 SaveInfo class.
     
    ``
    static {
        ClassTranslator.put("ghidra.app.plugin.core.MyPlugin.MyInfo", SaveInfo.class.getName());
    }
    ``
     
    Warning: If the class gets moved or renamed again in a subsequent version 
    of Ghidra, a new translation (put call) should get added to the static initializer block 
    and any old translations should have their current path name changed to the new
    class path.
     
    Example: The class ``ghidra.app.plugin.core.MyPlugin.MyInfo`` is in Ghidra version 1.
    In Ghidra version 2, it is moved and renamed to ``ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo``.
    In Ghidra version 3, it is renamed to ``ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo``.
    Put the following static initializer in the version 3 SaveInfo class.
    ``
    static {
        ClassTranslator.put("ghidra.app.plugin.core.MyPlugin.MyInfo", SaveInfo.class.getName());
        ClassTranslator.put("ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo", SaveInfo.class.getName());
    }
    ``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def contains(oldClassPath: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if this ClassTranslator has a mapping for the indicated old class path name.
        
        :param java.lang.String or str oldClassPath: the old class path name of the class.
        :return: true if the old class path is mapped to a new class path name in
        the current Ghidra version.
        :rtype: bool
        """

    @staticmethod
    def get(oldClassPath: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the current class path name that is mapped for the indicated old class path name.
        
        :param java.lang.String or str oldClassPath: the old class path name of the class.
        :return: the class path name of the current Ghidra version's class file. Otherwise, null if the old class path name isn't mapped.
        :rtype: str
        """

    @staticmethod
    def put(oldClassPath: typing.Union[java.lang.String, str], currentClassPath: typing.Union[java.lang.String, str]):
        """
        Defines a mapping indicating the class path name of the current Ghidra class 
        that is the same class as the indicated old class path name from a previous Ghidra version.
        
        :param java.lang.String or str oldClassPath: the old class path name of the class.
        :param java.lang.String or str currentClassPath: the current class path name of the class.
         
        **Important**: Any class that is indicated by the currentClassPath
        passed to the ``put`` method should implement ``ExtensionPoint``.
        """


class ClassFileInfo(java.lang.Record):
    """
    Information about a class file on disk
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], suffix: typing.Union[java.lang.String, str]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def name(self) -> str:
        ...

    def path(self) -> str:
        ...

    def suffix(self) -> str:
        ...

    def toString(self) -> str:
        ...


class ClassExclusionFilter(ClassFilter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, *exclusions: java.lang.Class[typing.Any]):
        ...


class ClassFilter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def accepts(self, c: java.lang.Class[typing.Any]) -> bool:
        ...


@typing.type_check_only
class ClassDir(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ClassLocation(java.lang.Object):
    """
    Represents a place from which :obj:`Class`s can be obtained
    """

    class_: typing.ClassVar[java.lang.Class]
    CLASS_EXT: typing.Final = ".class"

    def getClasses(self, list: java.util.List[ClassFileInfo], monitor: ghidra.util.task.TaskMonitor):
        ...


class ExtensionPoint(java.lang.Object):
    """
    NOTE: ExtensionPoint logistics have changed! It is no longer sufficient to
    implement ExtensionPoint in order for the ClassSearcher to dynamically pick
    up your class. Your class also needs to conform to a class name suffix rule.
    The modules included in your application can have a file named
    "{ModuleRoot}/data/ExtensionPoint.manifest". This file contains (one per
    line) the suffixes that should be checked for inclusion into the class
    searching. IF YOUR EXTENSION POINT DOES NOT HAVE A SUFFIX INDICATED IN ONE OF
    THESE FILES, IT WILL NOT BE AUTOMATICALLY DISCOVERED.
     
    This is a marker interface used to mark classes and interfaces that Ghidra
    will automatically search for and load.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ClassJar(ClassLocation):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ClassSearcher(java.lang.Object):
    """
    This class is a collection of static methods used to discover classes that implement a
    particular interface or extend a particular base class.
     
    
    **Warning: Using the search feature of this class will trigger other classes to be loaded.
    Thus, clients should not make calls to this class inside of static initializer blocks**
    
     
    Note: if your application is not using a module structure for its release build, then
    your application must create the following file, with the required entries,
    in order to find extension points:
     
        <install dir>/data/ExtensionPoint.manifest
    """

    class_: typing.ClassVar[java.lang.Class]
    SEARCH_ALL_JARS_PROPERTY: typing.Final = "class.searcher.search.all.jars"
    """
    This provides a means for custom apps that do not use a module structure to search all jars
    """


    @staticmethod
    def addChangeListener(l: javax.swing.event.ChangeListener):
        """
        Add a change listener that will be notified when the classpath
        is searched for new classes.
         
        **Note:** The listener list is implemented
        using WeakReferences. Therefore, the caller must maintain a handle to
        the listener being added, or else it will be garbage collected and
        never called.
        
        
        :param javax.swing.event.ChangeListener l: the listener to add
        """

    @staticmethod
    @typing.overload
    def getClasses(ancestorClass: java.lang.Class[T]) -> java.util.List[java.lang.Class[T]]:
        """
        Get :meth:`priority-sorted <ExtensionPointProperties.priority>` classes that implement or
        derive from the given ancestor class
        
        :param java.lang.Class[T] ancestorClass: the ancestor class
        :return: set of classes that implement or extend T
        :rtype: java.util.List[java.lang.Class[T]]
        """

    @staticmethod
    @typing.overload
    def getClasses(ancestorClass: java.lang.Class[T], classFilter: java.util.function.Predicate[java.lang.Class[T]]) -> java.util.List[java.lang.Class[T]]:
        """
        Get :meth:`priority-sorted <ExtensionPointProperties.priority>` classes that
        implement or derive from the given ancestor class
        
        :param java.lang.Class[T] ancestorClass: the ancestor class
        :param java.util.function.Predicate[java.lang.Class[T]] classFilter: A Predicate that tests class objects (that are already of type T)
                    for further filtering, ``null`` is equivalent to "return true"
        :return: :meth:`priority-sorted <ExtensionPointProperties.priority>` list of
                    classes that implement or extend T and pass the filtering test performed by the
                    predicate
        :rtype: java.util.List[java.lang.Class[T]]
        """

    @staticmethod
    def getExtensionPointInfo() -> java.util.Set[ClassFileInfo]:
        """
        Gets class information about each discovered potential extension point.
         
        
        NOTE: A discovered potential extension point may end up not getting loaded if it is not
        "of interest" (see :meth:`isClassOfInterest(Class) <.isClassOfInterest>`. These are referred to as false
        positives.
        
        :return: A :obj:`Set` of class information about each discovered potential extension point
        :rtype: java.util.Set[ClassFileInfo]
        """

    @staticmethod
    def getExtensionPointSuffix(className: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the given class's extension point suffix.
         
        
        Note that if multiple suffixes match, the smallest will be chosen. For a detailed
        explanation, see the comment inside :meth:`loadExtensionPointSuffixes() <.loadExtensionPointSuffixes>`.
        
        :param java.lang.String or str className: The name of the potential extension point class
        :return: The given class's extension point suffix, or null if it is not an extension point or
        :meth:`search(TaskMonitor) <.search>` has not been called yet
        :rtype: str
        """

    @staticmethod
    def getFalsePositives() -> java.util.Set[ClassFileInfo]:
        """
        Gets class information about discovered potential extension points that end up not getting
        loaded.
         
        
        NOTE: Ghidra may load more classes as it runs. Therefore, repeated calls to this method may
        return more results, as more potential extension points are identified as false positives.
        
        :return: A :obj:`Set` of class information about each loaded extension point
        :rtype: java.util.Set[ClassFileInfo]
        """

    @staticmethod
    @typing.overload
    def getInstances(c: java.lang.Class[T]) -> java.util.List[T]:
        """
        Gets all :meth:`priority-sorted <ExtensionPointProperties.priority>` class instances that 
        implement or derive from the given filter class
        
        :param java.lang.Class[T] c: the filter class
        :return: :meth:`priority-sorted <ExtensionPointProperties.priority>` :obj:`List` of 
        class instances that implement or extend T
        :rtype: java.util.List[T]
        """

    @staticmethod
    @typing.overload
    def getInstances(c: java.lang.Class[T], filter: ClassFilter) -> java.util.List[T]:
        """
        Get :meth:`priority-sorted <ExtensionPointProperties.priority>` classes instances that 
        implement or derive from the given filter class and pass the given filter predicate
        
        :param java.lang.Class[T] c: the filter class
        :param ClassFilter filter: A filter predicate that tests class objects (that are already of type T).
        ``null`` is equivalent to "return true".
        :return: :meth:`priority-sorted <ExtensionPointProperties.priority>` :obj:`List` of class 
        instances that implement or extend T and pass the filtering test performed by the predicate
        :rtype: java.util.List[T]
        """

    @staticmethod
    def getLoaded() -> java.util.Set[ClassFileInfo]:
        """
        Gets class information about each loaded extension point.
         
        
        NOTE: Ghidra may load more classes as it runs. Therefore, repeated calls to this method may
        return more results, as more extension points are loaded.
        
        :return: A :obj:`Set` of class information about each loaded extension point
        :rtype: java.util.Set[ClassFileInfo]
        """

    @staticmethod
    def isClassOfInterest(c: java.lang.Class[typing.Any]) -> bool:
        """
        Checks to see if the given class is an extension point of interest.
        
        :param java.lang.Class[typing.Any] c: The class to check.
        :return: True if the given class is an extension point of interest; otherwise, false.
        :rtype: bool
        """

    @staticmethod
    def logStatistics():
        """
        Writes the current class searcher statistics to the info log
        """

    @staticmethod
    def removeChangeListener(l: javax.swing.event.ChangeListener):
        """
        Remove the change listener
        
        :param javax.swing.event.ChangeListener l: the listener to remove
        """

    @staticmethod
    def search(monitor: ghidra.util.task.TaskMonitor):
        """
        Searches the classpath and updates the list of available classes which satisfies the 
        internal class filter. When the search completes (and was not cancelled), any registered 
        change listeners are notified.
        
        :param ghidra.util.task.TaskMonitor monitor: the progress monitor for the search
        :raises CancelledException: if the operation was cancelled
        """


@typing.type_check_only
class ClassPackage(ClassLocation):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ClassTranslator", "ClassFileInfo", "ClassExclusionFilter", "ClassFilter", "ClassDir", "ClassLocation", "ExtensionPoint", "ClassJar", "ClassSearcher", "ClassPackage"]
