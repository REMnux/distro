from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.formats.gfilesystem
import ghidra.framework.generic.auth
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


T = typing.TypeVar("T")


@typing.type_check_only
class PasswordDialog(docking.DialogComponentProvider):
    """
    Simple dialog with single input field to prompt user for password.
     
    
    User can cancel, or cancel-all, which can be determined by inspecting
    the value of the semi-visible member variables.
     
    
    Treat this as an internal detail of PopupGUIPasswordProvider.
    """

    @typing.type_check_only
    class RESULT_STATE(java.lang.Enum[PasswordDialog.RESULT_STATE]):

        class_: typing.ClassVar[java.lang.Class]
        OK: typing.Final[PasswordDialog.RESULT_STATE]
        CANCELED: typing.Final[PasswordDialog.RESULT_STATE]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PasswordDialog.RESULT_STATE:
            ...

        @staticmethod
        def values() -> jpype.JArray[PasswordDialog.RESULT_STATE]:
            ...


    class_: typing.ClassVar[java.lang.Class]


class PopupGUIPasswordProvider(PasswordProvider):
    """
    Pops up a GUI dialog prompting the user to enter a password for the specified file.
     
    
    The dialog is presented to the user when the iterator's hasNext() is called.
     
    
    Repeated requests to the same iterator will adjust the dialog's title with a "try count" to
    help the user understand the previous password was unsuccessful.
     
    
    Iterator's hasNext() will return false if the user has previously canceled the dialog,
    """

    @typing.type_check_only
    class SessionState(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PasswordIterator(java.util.Iterator[ghidra.framework.generic.auth.Password]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CryptoProviders(java.lang.Object):
    """
    Registry of :obj:`crypto providers <CryptoProvider>` and :meth:`session creator <.newSession>`.
    """

    @typing.type_check_only
    class CryptoProviderSessionImpl(CryptoProvider.Session, CryptoSession):

        @typing.type_check_only
        class PasswordIterator(java.util.Iterator[ghidra.framework.generic.auth.Password]):
            """
            Union iterator of all password providers
            """

            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, providers: java.util.List[CryptoProvider]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getCachedCryptoProvider(self) -> CachedPasswordProvider:
        """
        Returns the :obj:`CachedPasswordProvider`.
         
        
        (Used by GUI actions to manage the cache)
        
        :return: cached crypto provider instance
        :rtype: CachedPasswordProvider
        """

    def getCryptoProviderInstance(self, providerClass: java.lang.Class[T]) -> T:
        """
        Returns the previously registered matching :obj:`CryptoProvider` instance.
        
        :param T: CryptoProvider type:param java.lang.Class[T] providerClass: :obj:`CryptoProvider` class
        :return: previously registered CryptoProvider instance, or null if not found
        :rtype: T
        """

    @staticmethod
    def getInstance() -> CryptoProviders:
        """
        Fetch the global :obj:`CryptoProviders` singleton instance.
        
        :return: shared :obj:`CryptoProviders` singleton instance
        :rtype: CryptoProviders
        """

    def newSession(self) -> CryptoSession:
        """
        Creates a new :obj:`CryptoSession`.
         
        
        TODO: to truly be effective when multiple files
        are being opened (ie. batch import), nested sessions
        need to be implemented.
        
        :return: new :obj:`CryptoSession` instance
        :rtype: CryptoSession
        """

    def registerCryptoProvider(self, provider: CryptoProvider):
        """
        Adds a :obj:`CryptoProvider` to this registry.
         
        
        TODO: do we need provider priority ordering?
        
        :param CryptoProvider provider: :obj:`CryptoProvider`
        """

    def unregisterCryptoProvider(self, provider: CryptoProvider):
        """
        Removes a :obj:`CryptoProvider` from this registry.
        
        :param CryptoProvider provider: :obj:`CryptoProvider` to remove
        """

    @property
    def cryptoProviderInstance(self) -> T:
        ...

    @property
    def cachedCryptoProvider(self) -> CachedPasswordProvider:
        ...


class CachedPasswordProvider(PasswordProvider):
    """
    Caches passwords used to unlock a file.
     
    
    Threadsafe.
    """

    @typing.type_check_only
    class CryptoRec(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CloningPasswordIterator(java.util.Iterator[ghidra.framework.generic.auth.Password]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addPassword(self, fsrl: ghidra.formats.gfilesystem.FSRL, password: ghidra.framework.generic.auth.Password):
        """
        Adds a password / file combo to the cache.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` file
        :param ghidra.framework.generic.auth.Password password: password to unlock the file.  Specified :obj:`Password` is
        only copied, clearing is still callers responsibility
        """

    def clearCache(self):
        """
        Remove all cached information.
        """

    def getCount(self) -> int:
        """
        Returns the number of items in cache
        
        :return: number of items in cache
        :rtype: int
        """

    @property
    def count(self) -> jpype.JInt:
        ...


class CryptoProvider(java.lang.Object):
    """
    Common interface for provider interfaces that provide crypto information.
     
    
    TODO: add CryptoKeyProvider.
    """

    class Session(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getCryptoProviders(self) -> CryptoProviders:
            """
            Returns the :obj:`CryptoProviders` instance that created this session.
            
            :return: the :obj:`CryptoProviders` instance that created this session
            :rtype: CryptoProviders
            """

        def getStateValue(self, cryptoProvider: CryptoProvider, stateFactory: java.util.function.Supplier[T]) -> T:
            """
            Retrieves a state object from the session
            
            :param T: the type of the state object:param CryptoProvider cryptoProvider: the CryptoProvider instance
            :param java.util.function.Supplier[T] stateFactory: supplier that will create a new instance of the requested
            state object if not present in the session
            :return: state object (either previously saved or newly created by the factory supplier)
            :rtype: T
            """

        def setStateValue(self, cryptoProvider: CryptoProvider, value: java.lang.Object):
            """
            Saves a state object into the session using the cryptoprovider's identity as the key
            
            :param CryptoProvider cryptoProvider: the instance storing the value
            :param java.lang.Object value: the value to store
            """

        @property
        def cryptoProviders(self) -> CryptoProviders:
            ...


    class_: typing.ClassVar[java.lang.Class]


class CmdLinePasswordProvider(PasswordProvider):
    """
    A :obj:`PasswordProvider` that supplies passwords to decrypt files via the java jvm invocation.
     
    
    Example: java -Dfilesystem.passwords=/fullpath/to/textfile
     
    
    The password file is a plain text tabbed-csv file, where each line
    specifies a password and an optional file identifier.
     
    
    Example file contents, where each line is divided into fields by a tab
    character where the first field is the password and the second optional field
    is the file's identifying information (name, path, etc):
     
    ``password1   [tab]   myfirstzipfile.zip`` **← supplies a password for the named file located in any directory**
    ``someOtherPassword   [tab]   /full/path/tozipfile.zip`` **← supplies password for file at specified location** 
    ``anotherPassword [tab]   file:///full/path/tozipfile.zip|zip:///subdir/in/zip/somefile.txt`` **← supplies password for file embedded inside a zip**
    ``yetAnotherPassword`` **← a password to try for any file that needs a password**
    """

    class_: typing.ClassVar[java.lang.Class]
    CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME: typing.Final = "filesystem.passwords"

    def __init__(self):
        ...


class CryptoSession(java.io.Closeable):
    """
    Provides the caller with the ability to perform crypto querying operations
    for a group of related files.
     
    
    Typically used to query passwords and to add known good passwords
    to caches for later re-retrieval.
     
    
    Closing a CryptoSession instance does not invalidate the instance, instead it is a suggestion
    that the instance should not be used for any further nested sessions.
     
    
    See :meth:`CryptoProviders.newSession() <CryptoProviders.newSession>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addSuccessfulPassword(self, fsrl: ghidra.formats.gfilesystem.FSRL, password: ghidra.framework.generic.auth.Password):
        """
        Pushes a known good password into a cache for later re-retrieval.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` path to the file that was unlocked by the password
        :param ghidra.framework.generic.auth.Password password: the good password
        """

    def close(self):
        """
        Closes this session.
        """

    def getPasswordsFor(self, fsrl: ghidra.formats.gfilesystem.FSRL, prompt: typing.Union[java.lang.String, str]) -> java.util.Iterator[ghidra.framework.generic.auth.Password]:
        """
        Returns a sequence of passwords (sorted by quality) that may apply to
        the specified file.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` path to the password protected file
        :param java.lang.String or str prompt: optional prompt that may be displayed to a user
        :return: :obj:`Iterator` of possible passwords
        :rtype: java.util.Iterator[ghidra.framework.generic.auth.Password]
        """

    def isClosed(self) -> bool:
        """
        Returns true if this session has been closed.
        
        :return: boolean true if closed
        :rtype: bool
        """

    @property
    def closed(self) -> jpype.JBoolean:
        ...


class PasswordProvider(CryptoProvider):
    """
    Instances of this interface provide passwords to decrypt files.
     
    
    Instances are typically not called directly, instead are used 
    by a :obj:`CryptoSession` along with other provider instances to provide
    a balanced breakfast. 
     
    
    Multiple passwords can be returned for each request with the
    assumption that the consumer of the values can test and validate each one
    to find the correct value.  Conversely, it would not be appropriate to use this to get
    a password for a login service that may lock the requester out after a small number
    of failed attempts.
     
    
    TODO: add negative password result that can be persisted / cached so
    user isn't spammed with requests for an unknown password during batch / recursive
    operations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPasswordsFor(self, fsrl: ghidra.formats.gfilesystem.FSRL, prompt: typing.Union[java.lang.String, str], session: CryptoProvider.Session) -> java.util.Iterator[ghidra.framework.generic.auth.Password]:
        """
        Returns a sequence of passwords (ordered by quality) that may apply to
        the specified file.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: :obj:`FSRL` path to the password protected file
        :param java.lang.String or str prompt: optional prompt that may be displayed to a user
        :param CryptoProvider.Session session: a place to hold state values that persist across
        related queries
        :return: :obj:`Iterator` of possible passwords
        :rtype: java.util.Iterator[ghidra.framework.generic.auth.Password]
        """


class CryptoProviderSessionChildImpl(CryptoSession):
    """
    A stub implementation of CryptoSession that relies on a parent instance.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parentSession: CryptoSession):
        ...



__all__ = ["PasswordDialog", "PopupGUIPasswordProvider", "CryptoProviders", "CachedPasswordProvider", "CryptoProvider", "CmdLinePasswordProvider", "CryptoSession", "PasswordProvider", "CryptoProviderSessionChildImpl"]
