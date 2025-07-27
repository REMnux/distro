from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


E = typing.TypeVar("E")
T = typing.TypeVar("T")


class JarArchiveBuilder(ArchiveBuilder):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, outputFile: jpype.protocol.SupportsPath):
        ...


class NamedDaemonThreadFactory(java.util.concurrent.ThreadFactory):
    """
    NamedDaemonThreadFactory is a thread factory which forms daemon threads
    with a specified name prefix for the Java concurrent Executors pools.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...


class Beanify(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def beanify(beany: java.lang.Object) -> java.util.Map[java.lang.String, java.lang.Object]:
        ...


class ZipArchiveBuilder(ArchiveBuilder):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, outputFile: jpype.protocol.SupportsPath):
        ...


class LockFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createFileLocker(lockFile: jpype.protocol.SupportsPath) -> FileLocker:
        ...


class ChannelLocker(FileLocker):
    ...
    class_: typing.ClassVar[java.lang.Class]


class Path(java.lang.Comparable[Path]):
    """
    A class to represent a PATH item.
    """

    class_: typing.ClassVar[java.lang.Class]
    GHIDRA_HOME: typing.Final = "$GHIDRA_HOME"
    USER_HOME: typing.Final = "$USER_HOME"

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Identifies an absolute directory path which has the following attributes:
         
        * isEnabled = true
        * isEditable = true
        * isReadOnly = false
        
        
        :param jpype.protocol.SupportsPath file: absolute directory path
        """

    @typing.overload
    def __init__(self, file: generic.jar.ResourceFile):
        """
        Identifies an absolute directory path which has the following attributes:
         
        * isEnabled = true
        * isEditable = true
        * isReadOnly = false
        
        
        :param generic.jar.ResourceFile file: absolute directory path
        """

    @typing.overload
    def __init__(self, file: generic.jar.ResourceFile, isEnabled: typing.Union[jpype.JBoolean, bool], isEditable: typing.Union[jpype.JBoolean, bool], isReadOnly: typing.Union[jpype.JBoolean, bool]):
        """
        Identifies an absolute directory path with the specified attributes.
        
        :param generic.jar.ResourceFile file: absolute directory path
        :param jpype.JBoolean or bool isEnabled: directory path will be searched if true
        :param jpype.JBoolean or bool isEditable: if true files contained within directory are considered editable
        :param jpype.JBoolean or bool isReadOnly: if true files contained within directory are considered read-only
        """

    @typing.overload
    def __init__(self, path: typing.Union[java.lang.String, str]):
        """
        Identifies an absolute directory path which has the following attributes:
         
        * isEnabled = true
        * isEditable = true
        * isReadOnly = false
        
        
        :param java.lang.String or str path: absolute directory path
        """

    @typing.overload
    def __init__(self, path: typing.Union[java.lang.String, str], enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Identifies an absolute directory path which has the following attributes:
         
        * isEditable = true
        * isReadOnly = false
        
        
        :param java.lang.String or str path: absolute directory path
        :param jpype.JBoolean or bool enabled: directory path will be searched if true
        """

    @typing.overload
    def __init__(self, path: typing.Union[java.lang.String, str], isEnabled: typing.Union[jpype.JBoolean, bool], isEditable: typing.Union[jpype.JBoolean, bool], isReadOnly: typing.Union[jpype.JBoolean, bool]):
        """
        Identifies an absolute directory path with the specified attributes.
        
        :param java.lang.String or str path: absolute directory path
        :param jpype.JBoolean or bool isEnabled: directory path will be searched if true
        :param jpype.JBoolean or bool isEditable: if true files contained within directory are considered editable
        :param jpype.JBoolean or bool isReadOnly: if true files contained within directory are considered read-only
        """

    def exists(self) -> bool:
        ...

    @staticmethod
    def fromPathString(path: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Parse the path string **with path element placeholders**, such as 
        :obj:`.GHIDRA_HOME`.
        
        :param java.lang.String or str path: the path
        :return: the path as a ResourceFile.
        :rtype: generic.jar.ResourceFile
        """

    def getPath(self) -> generic.jar.ResourceFile:
        ...

    def getPathAsString(self) -> str:
        """
        Returns the path as a string **with path element placeholders**, such as 
        :obj:`.GHIDRA_HOME`.
        
        :return: the path as a string .
        :rtype: str
        """

    def isEditable(self) -> bool:
        """
        Returns true if this path can be modified.
        
        :return: true if this path can be modified
        :rtype: bool
        """

    def isEnabled(self) -> bool:
        """
        Returns true if this path is enabled.
        Enablement indicates the path should be used.
        
        :return: true if this path is enabled
        :rtype: bool
        """

    def isInstallationFile(self) -> bool:
        """
        Returns true if the given path is a file inside of the current Ghidra application.
        
        :return: true if the given path is a file inside of the current Ghidra application.
        :rtype: bool
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if this path is read-only, which
        indicates the path cannot be written.
        
        :return: true if this path is read-only
        :rtype: bool
        """

    def setEnabled(self, isEnabled: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def setPath(self, path: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def setPath(self, file: generic.jar.ResourceFile):
        ...

    @staticmethod
    def toPathString(file: generic.jar.ResourceFile) -> str:
        """
        Returns the path as a string **with path element placeholders**, such as 
        :obj:`.GHIDRA_HOME`.
        
        :param generic.jar.ResourceFile file: the file to translate
        :return: the path as a string .
        :rtype: str
        """

    @property
    def path(self) -> generic.jar.ResourceFile:
        ...

    @path.setter
    def path(self, value: generic.jar.ResourceFile):
        ...

    @property
    def editable(self) -> jpype.JBoolean:
        ...

    @property
    def installationFile(self) -> jpype.JBoolean:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...

    @property
    def pathAsString(self) -> java.lang.String:
        ...


class FileLocker(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def canForceLock(self) -> bool:
        ...

    def forceLock(self) -> bool:
        ...

    def getExistingLockFileInformation(self) -> str:
        ...

    def isLocked(self) -> bool:
        ...

    def lock(self) -> bool:
        ...

    def release(self):
        ...

    @property
    def existingLockFileInformation(self) -> java.lang.String:
        ...

    @property
    def locked(self) -> jpype.JBoolean:
        ...


class DequePush(java.lang.AutoCloseable, typing.Generic[E]):
    """
    A context utility allowing stack management via a try-with-resources block
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def push(stack: java.util.Deque[E], elem: E) -> DequePush[E]:
        """
        Push an element to the given stack
        
        :param java.util.Deque[E] stack: the stack
        :param E elem: the element
        :return: a context used to pop the element
         
        This is an idiomatic convenience, as in a try-with-resources block:
         
        ``Deque<String> stack = new LinkedList<>();try(DequePush<?> p = DequePush.push(stack, "Hello, World!\n")) {    System.out.println(stack.peek());}``
         
         
        This idiom can be very useful if there is complex logic between the push and pop. It's easy
        to forget to pop; however, this convenience comes at the cost of a heap allocation.
        :rtype: DequePush[E]
        """


class FileChannelLock(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lockFile: jpype.protocol.SupportsPath):
        ...


class ArchiveBuilder(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addFile(self, path: typing.Union[java.lang.String, str], file: jpype.protocol.SupportsPath):
        ...

    def close(self):
        ...

    def createFile(self, path: typing.Union[java.lang.String, str], lines: java.util.List[java.lang.String]):
        ...


class WrappingPeekableIterator(PeekableIterator[T], typing.Generic[T]):
    """
    An implementation of :obj:`PeekableIterator` that can take a Java :obj:`Iterator` and 
    wrap it to implement the :obj:`PeekableIterator` interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iterator: java.util.Iterator[T]):
        ...


class ArchiveExtractor(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def explode(baseDir: jpype.protocol.SupportsPath, archiveFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        ...


class WindowUtilities(java.lang.Object):
    """
    A collection of window related utility methods
    """

    @typing.type_check_only
    class ScreenBounds(java.lang.Object):
        """
        Class that knows the screen bounds, insets and bounds without the insets
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, bounds: java.awt.Rectangle, insets: java.awt.Insets):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def areModalDialogsVisible() -> bool:
        """
        Returns true if there are one or more modal dialogs displayed in the current JVM.
        
        :return: true if there are one or more modal dialogs displayed in the current JVM.
        :rtype: bool
        """

    @staticmethod
    def bringModalestDialogToFront(activeWindow: java.awt.Window):
        """
        Attempts to locate the topmost modal dialog and then bring that dialog to the front of
        the window hierarchy
        
        :param java.awt.Window activeWindow: the system's active window
        """

    @staticmethod
    def centerOnComponent(parent: java.awt.Component, child: java.awt.Component) -> java.awt.Point:
        """
        Creates a point that is centered over the given ``parent`` component, based upon
        the size of the given ``child``.
        
        :param java.awt.Component parent: The component over which to center the child.
        :param java.awt.Component child: The component which will be centered over the parent
        :return: a point that is centered over the given ``parent`` component, based upon
        the size of the given ``child``.
        :rtype: java.awt.Point
        """

    @staticmethod
    @typing.overload
    def centerOnScreen(d: java.awt.Dimension) -> java.awt.Point:
        """
        Computes the point such that a rectangle with the given size would be centered on the
        screen.   The chosen screen in this case is the screen defined by
         
            GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
         
        
         
        If the given size is too big to fit on the screen in either dimension,
        then it will be placed at the 0 position for that dimension.
        
        :param java.awt.Dimension d: the size of the rectangle to center
        :return: the upper-left point of the given centered dimension
        :rtype: java.awt.Point
        
        .. seealso::
        
            | :obj:`.centerOnScreen(Component, Dimension)`
        """

    @staticmethod
    @typing.overload
    def centerOnScreen(c: java.awt.Component, d: java.awt.Dimension) -> java.awt.Point:
        """
        Computes the point such that a rectangle with the given size would be centered on the
        screen.   The chosen screen in this case is the screen defined by using the given
        component.  If the given size is too big to fit on the screen in either dimension,
        then it will be placed at the 0 position for that dimension.
        
        :param java.awt.Component c: the component that should be used to find the current screen
        :param java.awt.Dimension d: the size of the rectangle to center
        :return: the upper-left point of the given centered dimension
        :rtype: java.awt.Point
        
        .. seealso::
        
            | :obj:`.centerOnScreen(Dimension)`
        """

    @staticmethod
    @typing.overload
    def ensureEntirelyOnScreen(c: java.awt.Component):
        """
        Update the component to be within visible bounds of the screen.
        
         
        This method differs from :meth:`ensureEntirelyOnScreen(Component, Rectangle) <.ensureEntirelyOnScreen>` in that
        the other method does not adjust the component's bounds like this method does.
        
        :param java.awt.Component c: the component to move on screen as necessary
        :raises IllegalArgumentException: if the given component is not yet realized (see
                :meth:`Component.isShowing() <Component.isShowing>`
        """

    @staticmethod
    @typing.overload
    def ensureEntirelyOnScreen(c: java.awt.Component, bounds: java.awt.Rectangle):
        """
        Update the bounds to be within contained within the visible bounds of the screen.  The given
        component is used to determine which screen to use for updating the bounds.
        
         
        Note: the given comonent's bounds will not be adjusted by this method
        
        :param java.awt.Component c: the on screen component, used to determine which screen to check against the given
                bounds
        :param java.awt.Rectangle bounds: the bounds to adjust
        :raises IllegalArgumentException: if the given component is not yet realized (see
                :meth:`Component.isShowing() <Component.isShowing>`
        """

    @staticmethod
    @typing.overload
    def ensureOnScreen(c: java.awt.Component):
        """
        Update the component to intersect the visible bounds of the screen.
        
         
        This method differs from :meth:`ensureOnScreen(Component, Rectangle) <.ensureOnScreen>` in that
        the other method does not adjust the component's bounds like this method does.
        
        :param java.awt.Component c: the component to move on screen as necessary
        :raises IllegalArgumentException: if the given component is not yet realized (see
                :meth:`Component.isShowing() <Component.isShowing>`
        """

    @staticmethod
    @typing.overload
    def ensureOnScreen(c: java.awt.Component, bounds: java.awt.Rectangle):
        """
        Update the bounds to intersect visible bounds of the screen.  The given component is
        used to determine which screen to use for updating the bounds.
        
         
        Note: the given component's bounds will not be adjusted by this method
        
        :param java.awt.Component c: the on screen component, used to determine which screen to check against the given
                bounds
        :param java.awt.Rectangle bounds: the bounds to adjust
        :raises IllegalArgumentException: if the given component is not yet realized (see
                :meth:`Component.isShowing() <Component.isShowing>`
        """

    @staticmethod
    def findModalestDialog() -> java.awt.Dialog:
        ...

    @staticmethod
    def getOpenModalDialogsFor(parent: java.awt.Frame) -> java.util.List[java.awt.Dialog]:
        """
        Returns a list of all ``parent``'s descendant modal dialogs.
        
        :param java.awt.Frame parent: the parent for which to find modal dialogs
        :return: a list of all ``parent``'s descendant modal dialogs.
        :rtype: java.util.List[java.awt.Dialog]
        """

    @staticmethod
    def getScreenBounds(c: java.awt.Component) -> java.awt.Rectangle:
        """
        Gets the **usable** screen bounds for the screen in which the given component is
        showing.  Returns null if the given component is not showing.   Usable bounds are the
        screen bounds after subtracting insets (for things like menu bars and task bars).
        
        :param java.awt.Component c: the component
        :return: the screen bounds; null if the component is not showing
        :rtype: java.awt.Rectangle
        """

    @staticmethod
    def getTitle(w: java.awt.Window) -> str:
        """
        Returns the title for the given window
        
        :param java.awt.Window w: the window
        :return: the title
        :rtype: str
        """

    @staticmethod
    def getVirtualScreenBounds() -> java.awt.Rectangle:
        """
        Returns the a rectangle representing the screen bounds for the entire screen space for
        all screens in use.  The result will include virtual space that may not be rendered on
        any physical hardware.   Said differently, the rectangle returned from this method will
        contain all visible display coordinates, as well as potentially coordinates that are
        virtual and not displayed on any physical screen.  The OS's window manager is responsible
        for controlling how the virtual space is created.
        
        :return: the virtual screen bounds
        :rtype: java.awt.Rectangle
        """

    @staticmethod
    def getVisibleScreenBounds() -> java.awt.Shape:
        """
        Returns a shape that represents the visible portion of the virtual screen bounds
        returned from :meth:`getVirtualScreenBounds() <.getVirtualScreenBounds>`
        
        :return: the visible shape of all screen devices
        :rtype: java.awt.Shape
        """

    @staticmethod
    def windowForComponent(c: java.awt.Component) -> java.awt.Window:
        """
        Returns the window parent of c.  If c is a window, then c is returned.
        
         
        Warning: this differs from :meth:`SwingUtilities.windowForComponent(Component) <SwingUtilities.windowForComponent>` in
        that the latter method will not return the given component if it is a window.
        
        :param java.awt.Component c: the component
        :return: the window
        :rtype: java.awt.Window
        """


class MultiIterator(java.util.Iterator[T], typing.Generic[T]):
    """
    An iterator that is comprised of one or more :obj:`PeekableIterator`s.  The type ``T`` of the 
    the iterators must either implement :obj:`Comparable` directly or you must provide a 
    :obj:`Comparator` for comparing the types.  Further, it is assumed that the iterators return
    values in sorted order.  If the sorted order is reversed, then that must be indicated in 
    the constructor of this class.
     
    
    This class allows duplicate items in the iterators.  Thus, if you do not wish to process 
    duplicate values, then you need to de-dup the data returned from :meth:`next() <.next>`.  
    Alternatively, you could subclass this iterator and de-dup the returned values.
     
    
    This class also does not handle null items returned during the iteration process.
    """

    @typing.type_check_only
    class TComparator(java.util.Comparator[T], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReverseComparatorWrapper(java.util.Comparator[T], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, iterators: java.util.List[PeekableIterator[T]], forward: typing.Union[jpype.JBoolean, bool]):
        """
        Use this constructor when the items of the iterators are naturally comparable (i.e., 
        they implement :obj:`Comparable`).
        
        :param java.util.List[PeekableIterator[T]] iterators: the iterators that provide the data
        :param jpype.JBoolean or bool forward: true if the iterators provide data sorted ascending; false for descending
        """

    @typing.overload
    def __init__(self, iterators: java.util.List[PeekableIterator[T]], comparator: java.util.Comparator[T], forward: typing.Union[jpype.JBoolean, bool]):
        """
        Use this constructor when the items of the iterators are not naturally comparable (i.e., 
        they do not implement :obj:`Comparable`).
        
        :param java.util.List[PeekableIterator[T]] iterators: the iterators that provide the data
        :param java.util.Comparator[T] comparator: the comparator used to find the next item
        :param jpype.JBoolean or bool forward: true if the iterators provide data sorted ascending; false for descending
        """


class PeekableIterator(java.util.Iterator[T], typing.Generic[T]):
    """
    An iterator that allows you to peek at the next item on the iterator.
    """

    class_: typing.ClassVar[java.lang.Class]

    def peek(self) -> T:
        """
        Returns the item that would be returned by calling :meth:`next() <.next>`, but does not 
        increment the iterator as ``next`` would.
        
        :return: the item that would be returned by calling :meth:`next() <.next>`
        :rtype: T
        """



__all__ = ["JarArchiveBuilder", "NamedDaemonThreadFactory", "Beanify", "ZipArchiveBuilder", "LockFactory", "ChannelLocker", "Path", "FileLocker", "DequePush", "FileChannelLock", "ArchiveBuilder", "WrappingPeekableIterator", "ArchiveExtractor", "WindowUtilities", "MultiIterator", "PeekableIterator"]
