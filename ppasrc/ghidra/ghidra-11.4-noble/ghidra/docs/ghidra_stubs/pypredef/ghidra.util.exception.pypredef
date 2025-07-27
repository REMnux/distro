from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class BadLinkException(java.io.IOException):
    """
    ``BadLinkException`` occurs when a link-file expected linked content type does not 
    match the actual content type of the linked file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...


class RollbackException(java.lang.RuntimeException):
    """
    Exception thrown when a transaction should be rolled back.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        """
        Constructor
        
        :param java.lang.Throwable cause: cause of exception
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str message: the message explaining what caused the exception.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Constructor
        
        :param java.lang.String or str message: the message explaining what caused the exception.
        :param java.lang.Throwable cause: cause of exception
        """


class VersionException(UsrException):
    """
    Exception thrown when an object's version does not match its expected version.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN_VERSION: typing.Final = 0
    """
    Object created with unknown software version.
    """

    OLDER_VERSION: typing.Final = 1
    """
    Object created with older software version.
    """

    NEWER_VERSION: typing.Final = 2
    """
    Object created with newer software version.
    """


    @typing.overload
    def __init__(self):
        """
        Constructor - not upgradeable
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor - not upgradeable
        
        :param java.lang.String or str msg: detailed message
        """

    @typing.overload
    def __init__(self, upgradable: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor.
        
        :param jpype.JBoolean or bool upgradable: true indicates that an upgrade is possible.
        If true the version indicator value is set to OLDER_VERSION, if false
        it is set to UNKNOWN_VERSION.
        """

    @typing.overload
    def __init__(self, versionIndicator: typing.Union[jpype.JInt, int], upgradable: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor.
        
        :param jpype.JInt or int versionIndicator: OLDER_VERSION, NEWER_VERSION or UNKNOWN_VERSION
        :param jpype.JBoolean or bool upgradable: true indicates that an upgrade is possible.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], versionIndicator: typing.Union[jpype.JInt, int], upgradable: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor.
        
        :param java.lang.String or str msg: detailed message
        :param jpype.JInt or int versionIndicator: OLDER_VERSION, NEWER_VERSION or UNKNOWN_VERSION
        :param jpype.JBoolean or bool upgradable: true indicates that an upgrade is possible.
        """

    def combine(self, ve: VersionException) -> VersionException:
        """
        Combine another VersionException with this one.
        
        :param VersionException ve: another version exception
        :return: this combined version exception
        :rtype: VersionException
        """

    def getDetailMessage(self) -> str:
        ...

    def getVersionIndicator(self) -> int:
        """
        Return a version indicator (OLDER_VERSION, NEWER_VERSION or UNKNOWN_VERSION).
        Only an OLDER_VERSION has the possibility of being upgradeable.
        """

    def isUpgradable(self) -> bool:
        """
        Return true if the file can be upgraded to the current version.
        """

    def setDetailMessage(self, message: typing.Union[java.lang.String, str]):
        ...

    @property
    def versionIndicator(self) -> jpype.JInt:
        ...

    @property
    def upgradable(self) -> jpype.JBoolean:
        ...

    @property
    def detailMessage(self) -> java.lang.String:
        ...

    @detailMessage.setter
    def detailMessage(self, value: java.lang.String):
        ...


class UserAccessException(java.io.IOException):
    """
    Exception thrown when a user requests some operation to be performed
    but does not have sufficient privileges.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Create a new UserAccessException with the given message.
        
        :param java.lang.String or str msg: the message explaining what caused the exception.
        """


class InvalidInputException(UsrException):
    """
    Exception thrown if input is invalid.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """


class NoValueException(UsrException):
    """
    Exception thrown if there is no value at a
    requested index.
    """

    class_: typing.ClassVar[java.lang.Class]
    noValueException: typing.Final[NoValueException]

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str message: detailed message
        """


class NotEmptyException(UsrException):
    """
    exception thrown whenever some container is expected to be empty and it isn't.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        construct a new NotEmptyException with a default message.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        construct a new NotEmptyException with a given message.
        
        :param java.lang.String or str msg: overides the default message.
        """


class ClosedException(java.io.IOException):
    """
    ``ClosedException`` indicates that the underlying resource has been 
    closed and read/write operations have failed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor.  Message indicates 'File is closed'.
        """

    @typing.overload
    def __init__(self, resourceName: typing.Union[java.lang.String, str]):
        """
        Constructor which indicates resource which has been closed.
        Message indicates '<resourceName> is closed'.
        
        :param java.lang.String or str resourceName: name of closed resource.
        """

    def getResourceName(self) -> str:
        """
        
        
        :return: name of resource which is closed.
        :rtype: str
        """

    @property
    def resourceName(self) -> java.lang.String:
        ...


class GraphException(UsrException):
    """
    Exception thrown if a failure occurs while generating a Graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str message: detailed message
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class DuplicateFileException(java.io.IOException):
    """
    ``DuplicateFileException`` is thrown whenever a file or folder can't
    be created because one with that name already exists at the same location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Create a new DuplicateFileException with the given message.
        
        :param java.lang.String or str msg: the exception message.
        """


class DuplicateNameException(UsrException):
    """
    Exception thrown whenever a method tries give something a name and that name is already used.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        constructs a new DuplicatenameException with a default message.
        """

    @typing.overload
    def __init__(self, usrMessage: typing.Union[java.lang.String, str]):
        """
        construct a new DuplicateNameException with a given message.
        
        :param java.lang.String or str usrMessage: overrides the default message.
        """


class CryptoException(java.io.IOException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, cause: java.lang.Exception):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class MultipleCauses(java.lang.Throwable):
    """
    Use an instance of this class as the cause when you need to record several causes of an
    exception.
     
    This paradigm would be necessary when multiple attempts can be made to complete a task, e.g.,
    traversing a list of plugins until one can handle a given condition. If all attempts fail, it is
    desirable to report on each attempt.
     
    This class acts as a wrapper allowing multiple causes to be recorded in place of one. The causes
    recorded in this wrapper actually apply to the throwable ("parent") which has this
    MultipleCauses exception as its cause.
    """

    class Util(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @staticmethod
        def iterCauses(exc: java.lang.Throwable) -> java.lang.Iterable[java.lang.Throwable]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new MultipleCauses wrapper with no causes
        NOTE: it is rude to leave this empty
        """

    @typing.overload
    def __init__(self, causes: collections.abc.Sequence):
        """
        Constructs a new MultipleCauses wrapper with the given causes
        
        :param collections.abc.Sequence causes:
        """

    @typing.overload
    def addAllCauses(self, e: java.lang.Throwable):
        """
        Assuming a throwable has multiple causes, add them all to this MultipleCauses
        
        :param java.lang.Throwable e: the throwable having multiple causes
         
        This is useful for flattening causes into a common exception. For instance, if a method is
        collecting multiple causes for a potential WidgetException, and it catches a
        WidgetException, instead of collecting the caught WidgetException, it might instead copy
        its causes into its own collection.
        """

    @typing.overload
    def addAllCauses(self, that: MultipleCauses):
        """
        Add the causes from another MultipleCauses into this one
        
        :param MultipleCauses that: the source to copy from
        """

    def addCause(self, cause: java.lang.Throwable):
        """
        Add the cause to the collection of causes (for the "parent" throwable)
        
        :param java.lang.Throwable cause: the throwable to add as a cause
        """

    def addFlattenedIfMultiple(self, e: java.lang.Throwable):
        """
        If the throwable has multiple causes, collect its causes into this MultipleCauses.
        Otherwise, just add it as a cause.
        
        :param java.lang.Throwable e:
        """

    def getCause(self) -> java.lang.Throwable:
        """
        Use getCauses instead
        
        :return: null
        :rtype: java.lang.Throwable
        """

    def getCauses(self) -> java.util.Collection[java.lang.Throwable]:
        """
        Returns the causes of the parent throwable (possibly an empty collection)
        
        :return: the collection of causes of the parent throwable
        NOTE: it is rude to leave this empty. If the parent throwable has no cause, or the cause is
        unknown, leave its cause null.
        :rtype: java.util.Collection[java.lang.Throwable]
        """

    @staticmethod
    def hasMultiple(e: java.lang.Throwable) -> bool:
        ...

    def initCause(self, cause: java.lang.Throwable) -> java.lang.Throwable:
        """
        Use addCause instead
        """

    def isEmpty(self) -> bool:
        ...

    @staticmethod
    @typing.overload
    def printTree(out: java.io.PrintStream, e: java.lang.Throwable):
        ...

    @staticmethod
    @typing.overload
    def printTree(out: java.io.PrintStream, prefix: typing.Union[java.lang.String, str], e: java.lang.Throwable):
        ...

    @property
    def causes(self) -> java.util.Collection[java.lang.Throwable]:
        ...

    @property
    def cause(self) -> java.lang.Throwable:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class PropertyTypeMismatchException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class NotYetImplementedException(java.lang.RuntimeException):
    """
    
    NotYetImplementedException is used during development of a class.
    It is expected that this Exception should not exist in final
    released classes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs a NotYetImplementedException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs a NotYetImplementedException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class NotFoundException(UsrException):
    """
    Exception thrown when an object is not found.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """


class FileInUseException(java.io.IOException):
    """
    ``FileInUseException`` indicates that there was contention
    for a file which is in-use.  This can be caused for various reasons
    including a file lock of some kind.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Create a new FileInUseException with the given message.
        
        :param java.lang.String or str msg: the exception message.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Create a new FileInUseException with the given message and cause.
        
        :param java.lang.String or str msg: the exception message.
        """


class UnableToSwingException(java.lang.Exception):
    """
    Signals that a background thread attempted to :meth:`SwingUtilities.invokeAndWait(Runnable) <SwingUtilities.invokeAndWait>`
    operation that timed-out because the Swing thread was busy.  This can be a sign of 
    a deadlock.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class UsrException(java.lang.Exception):
    """
    Base Class for all ghidra non-runtime exceptions
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a new UsrException with no message
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Construct a new UsrException with the given message
        
        :param java.lang.String or str msg: the exception message
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Construct a new UsrException with the given message and cause
        
        :param java.lang.String or str msg: the exception message
        :param java.lang.Throwable cause: the exception cause
        """


class CancelledException(UsrException):
    """
    ``CancelledException`` indicates that the user cancelled
    the current operation.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor.  Message indicates 'Operation cancelled'.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...


class TimeoutException(CancelledException):
    """
    Indicates that a :obj:`CancelledException` happened due to a timeout.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class AssertException(java.lang.RuntimeException):
    """
    ``AssertException`` is used in situations that the programmer believes can't happen.
    If it does, then there is a programming error of some kind.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Create a new AssertException with no message.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Create a new AssertException with the given message.
        
        :param java.lang.String or str msg: the exception message.
        """

    @typing.overload
    def __init__(self, t: java.lang.Throwable):
        """
        Create a new AssertException using another exception (Throwable) has occurred.
        The message for this exception will be derived from the Throwable.
        
        :param java.lang.Throwable t: the Throwable which caused this exception to be generated.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], throwable: java.lang.Throwable):
        """
        Create a new AssertException with the given message.
        
        :param java.lang.String or str message: the exception message.
        :param java.lang.Throwable throwable: the Throwable which caused this exception to be generated.
        """


class IOCancelledException(java.io.IOException):
    """
    An IO operation was cancelled by the user.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """



__all__ = ["BadLinkException", "RollbackException", "VersionException", "UserAccessException", "InvalidInputException", "NoValueException", "NotEmptyException", "ClosedException", "GraphException", "DuplicateFileException", "DuplicateNameException", "CryptoException", "MultipleCauses", "PropertyTypeMismatchException", "NotYetImplementedException", "NotFoundException", "FileInUseException", "UnableToSwingException", "UsrException", "CancelledException", "TimeoutException", "AssertException", "IOCancelledException"]
