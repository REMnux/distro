from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import docking.util.image
import ghidra.framework.client
import ghidra.framework.data
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.remote
import ghidra.framework.store
import ghidra.framework.store.local
import ghidra.util.task
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import org.jdom # type: ignore
import utility.function


B = typing.TypeVar("B")
B2 = typing.TypeVar("B2")
E = typing.TypeVar("E")
R = typing.TypeVar("R")
R2 = typing.TypeVar("R2")
RR = typing.TypeVar("RR")
T = typing.TypeVar("T")


class ToolChestChangeListener(java.lang.Object):
    """
    Listener that is notified when a ToolTemplate is added or removed from a
    project
    """

    class_: typing.ClassVar[java.lang.Class]

    def toolRemoved(self, toolName: typing.Union[java.lang.String, str]):
        """
        ToolConfig was removed from the project toolchest
        """

    def toolSetAdded(self, toolset: ToolSet):
        """
        ToolSet was added to the project toolchest
        """

    def toolTemplateAdded(self, tool: ToolTemplate):
        """
        ToolConfig was added to the project toolchest
        """


class DomainObjectListener(java.util.EventListener):
    """
    The interface an object must support to be registered with a Domain Object
    and thus be informed of changes to the object.
       
    NOTE: The DomainObjectChangeEvent is TRANSIENT: it is only valid during the
    life of calls to all the DomainObjectChangeListeners.
    """

    class_: typing.ClassVar[java.lang.Class]

    def domainObjectChanged(self, ev: DomainObjectChangedEvent):
        """
        Method called when a change is made to the domain object.
        
        :param DomainObjectChangedEvent ev: event containing the change record and type of change that
        was made
        """


class RuntimeIOException(java.lang.RuntimeException):
    """
    :obj:`RuntimeIOException` provide a wrapped :obj:`IOException` wrapped
    within a :obj:`RuntimeException`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, e: java.io.IOException):
        """
        Construct :obj:`RuntimeIOException`
        
        :param java.io.IOException e: :obj:`IOException` instance
        """


class DomainFolderListenerAdapter(DomainFolderChangeListener):
    """
    Adapter for the domain folder change listener.
    
    
    .. seealso::
    
        | :obj:`DomainFolderChangeListener`for details regarding listener use
    """

    class_: typing.ClassVar[java.lang.Class]

    def stateChanged(self, affectedNewPath: typing.Union[java.lang.String, str], affectedOldPath: typing.Union[java.lang.String, str], isFolder: typing.Union[jpype.JBoolean, bool]):
        """
        Provides a consolidated callback for those listener methods which have not been
        overridden.  This callback is NOT invoked for the following callbacks:
         
        * domainFolderSetActive
        * domainFileObjectReplaced
        * domainFileObjectOpenedForUpdate
        * domainFileObjectClosed
        
        
        :param java.lang.String or str affectedNewPath: new path of affected folder/file, or null if item was 
        removed (see affectedOldPath)
        :param java.lang.String or str affectedOldPath: original path of affected folder/file, or null for new
        item (see affectedOldPath)
        :param jpype.JBoolean or bool isFolder: true if affected item is/was a folder
        """


class DomainObjectException(java.lang.RuntimeException):
    """
    ``DomainObjectException`` provides a general RuntimeException 
    when a catastrophic error occurs which may affect the integrity of a 
    domain object such as an IOException.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, t: java.lang.Throwable):
        """
        Constructor.
        
        :param java.lang.Throwable t: throwable error/exception which provides failure detail.
        """


class ToolListener(java.lang.Object):
    """
    Interface to be implemented by objects that want to receive PluginEvents.
    Tools must be registered for a particular event to actually receive it.
    
    
    .. seealso::
    
        | :obj:`PluginEvent`
    """

    class_: typing.ClassVar[java.lang.Class]

    def processToolEvent(self, toolEvent: ghidra.framework.plugintool.PluginEvent):
        """
        This method is invoked when the registered PluginEvent event occurs.
        
        :param ghidra.framework.plugintool.PluginEvent toolEvent: The cross-tool PluginEvent.
        """


class ProjectViewListener(java.lang.Object):
    """
    ``ProjectViewListener`` provides a listener interface for tracking project views added
    and removed from the associated project. 
     
    
    NOTE: notification callbacks are not guarenteed to occur within the swing thread.
    """

    class_: typing.ClassVar[java.lang.Class]

    def viewedProjectAdded(self, projectView: java.net.URL):
        """
        Provides notification that a read-only viewed project has been added which is intended to
        be visible.  Notification for hidden viewed projects will not be provided.
        
        :param java.net.URL projectView: project view URL
        """

    def viewedProjectRemoved(self, projectView: java.net.URL):
        """
        Provides notification that a viewed project is being removed from the project.
        Notification for hidden viewed project removal will not be provided.
        
        :param java.net.URL projectView: project view URL
        """


class ToolChest(java.lang.Object):
    """
    Interface to define methods to manage tools in a central location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addToolChestChangeListener(self, l: ToolChestChangeListener):
        """
        Add a listener to be notified when the tool chest is changed.
        
        :param ToolChestChangeListener l: listener to add
        """

    def addToolTemplate(self, template: ToolTemplate) -> bool:
        """
        Add tool template to the tool chest.
         
        
        Note: If the given tool template name already exists in the project, then the name will 
        be altered by appending an underscore and a one-up value.  The ``template``
        parameter's name is also updated with then new name. 
         
        
        To simply replace a tool with without changing its name, call 
        :meth:`replaceToolTemplate(ToolTemplate) <.replaceToolTemplate>`
        
        :param ToolTemplate template: tool template to add
        """

    def getToolCount(self) -> int:
        """
        Get the number of tools in this tool chest.
        
        :return: tool count.
        :rtype: int
        """

    def getToolTemplate(self, toolName: typing.Union[java.lang.String, str]) -> ToolTemplate:
        """
        Get the tool template for the given tool name.
        
        :param java.lang.String or str toolName: name of tool
        :return: null if there is no tool template for the given
        toolName.
        :rtype: ToolTemplate
        """

    def getToolTemplates(self) -> jpype.JArray[ToolTemplate]:
        """
        Get the tool templates from the tool chest.
        
        :return: list of tool template
        :rtype: jpype.JArray[ToolTemplate]
        """

    def remove(self, toolName: typing.Union[java.lang.String, str]) -> bool:
        """
        Remove entry (toolTemplate or toolSet) from the tool chest.
        
        :param java.lang.String or str toolName: name of toolConfig or toolSet to remove
        :return: true if the toolConfig or toolset was
        successfully removed from the tool chest.
        :rtype: bool
        """

    def removeToolChestChangeListener(self, l: ToolChestChangeListener):
        """
        Remove a listener that is listening to when the tool chest is changed.
        
        :param ToolChestChangeListener l: to remove
        """

    def replaceToolTemplate(self, template: ToolTemplate) -> bool:
        """
        Performs the same action as calling :meth:`remove(String) <.remove>` and then 
        :meth:`addToolTemplate(ToolTemplate) <.addToolTemplate>`.  However, calling this method prevents state from 
        being lost in the transition, such as position in the tool chest and default tool status.
        
        :param ToolTemplate template: The template to add to the tool chest, replacing any tools with the same name.
        :return: True if the template was added.
        :rtype: bool
        """

    @property
    def toolTemplate(self) -> ToolTemplate:
        ...

    @property
    def toolTemplates(self) -> jpype.JArray[ToolTemplate]:
        ...

    @property
    def toolCount(self) -> jpype.JInt:
        ...


class DomainObjectListenerBuilder(AbstractDomainObjectListenerBuilder[DomainObjectChangeRecord, DomainObjectListenerBuilder]):
    """
    Builder for creating a compact and efficient :obj:`DomainObjectListener` for 
    :obj:`DomainObjectChangedEvent`s
     
    
    There are three basic ways to process :obj:`DomainObjectChangeRecord`s within a 
    :obj:`DomainObjectChangedEvent`. 
     
    The first way is to look for the event to contain one or more
    records of a certain type, and if it is there, do some major refresh operation, and ignore
    the remaining event records. This is can be handled with an :meth:`any(EventType...) <.any>`,  
    followed by a :meth:`AnyBuilder.terminate(Callback) <AnyBuilder.terminate>` or :meth:`AnyBuilder.terminate(Consumer) <AnyBuilder.terminate>` 
    if you want the event.
     
    new DomainObjectListenerBuilder()
        .any(DomainObjectEvent.RESTORED).call(() -> refreshAll())
        .build();
     
     
    or if you need the event, you can use a consumer
    
      
    new DomainObjectListenerBuilder()
        .any(DomainObjectEvent.RESTORED).call(e -> refreshAll(e))
        .build();
     
     
    
    The second way is to just test for presence of one or more records of a certain type, and if
    any of those types exist is the event, call a method. In this case you don't need to know the 
    details of the record, only that one of the  given events was fired. This can be handled using 
    the  :meth:`any(EventType...) <.any>`, followed by a  call to :meth:`AnyBuilder.call(Callback) <AnyBuilder.call>` or
    :meth:`AnyBuilder.call(Consumer) <AnyBuilder.call>`
     
    new DomainObjectListenerBuilder()
        .onAny(ProgramEvent.FUNCTION_CHANGED).call(() -> refreshFunctions())
        .build();
     
    or if you need the event, you can use a consumer
     
    
    new DomainObjectListenerBuilder()
        .onAny(ProgramEvent.FUNCTION_CHANGED).call(e -> refreshFunctions(e))
        .build();
     
     
    
    And finally, the third way is where you have to perform some processing on each record of a 
    certain type. This can be done using the :meth:`each(EventType...) <.each>`, followed by the
    :meth:`EachBuilder.call(Consumer) <EachBuilder.call>` if you just want the record, or 
    :meth:`EachBuilder.call(BiConsumer) <EachBuilder.call>` if you want the record and the event.
     
    
    By default, the consumer for the "each" case is typed on DomainObjectChangeRecord. But that
    can be changed by calling :meth:`with(Class) <.with>`. Once this is called the builder
    will require that all consumers being passed in will now be typed on that record
    class. 
     
    new DomainObjectListenerBuilder()
        .each(DomainObjectEvent.PROPERTY_CHANGED).call(r -> processPropertyChanged(r))
        .withRecord(ProgramChangeRecord.class)
        .each(ProgramEvent.SYMBOL_RENANED).call(r -> symbolRenamed(r)
        .build();
    
    private void processPropertyChanged(DomainObjectChangeRecord record) {
            ...
    }
    private void symbolRenamed(ProgramChangeRecord record) {
            ...
    }
     
     
    or if you also need the event (to get the domainObject that is the event source)
     
     
    new DomainObjectListenerBuilder()
        .each(DomainObjectEvent.PROPERTY_CHANGED).call((e, r) -> processPropertyChanged(e, r))
        .withRecord(ProgramChangeRecord.class)
        .each(ProgramEvent.SYMBOL_RENANED).call((e, r) -> symbolRenamed(e, r)
        .build();
    
    private void propertyChanged(DomainObjectChangedEvent e, DomainObjectChangeRecord record) {
            Program p = (Program)e.getSource().
            ...
    }
    private void symbolRenamed(DomainObjectChangedEvent e, ProgramChangeRecord record) {
            Program p = (Program)e.getSource().
            ...
    }
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, creator: java.lang.Object):
        """
        Constructs a new builder
        
        :param java.lang.Object creator: the object that created this builder (usually, just pass in "this"). This
        will help with debugging event processing
        """


class AbortedTransactionListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def transactionAborted(self, transactionID: typing.Union[jpype.JLong, int]):
        ...


class EventType(java.lang.Object):
    """
    Interface for objects that represent event types. This interface has only one method and that
    method exists to facilitate fast checking if an event type is present in a collection of events.
    The value returned from getId() is arbitrary and can change from run to run. Its only purpose
    is to give each event type a unique compact id that can be used as an index into a bit set. It is
    important that implementers of this interface get their id values by calling 
    :meth:`DomainObjectEventIdGenerator.next() <DomainObjectEventIdGenerator.next>` so that all event ids are coordinated and as 
    small as possible.
     
    
    The preferred implementation of EventType is an enum that enumerates the valid event types
    for any application sub-system. See :obj:`DomainObjectEvent` for an example implementation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getId(self) -> int:
        """
        Returns the unique id assigned to this event type. The value is guaranteed to be constant
        for any given run of the application, but can vary from run to run.
        
        :return: the unique event id assigned to this EventType.
        :rtype: int
        """

    @property
    def id(self) -> jpype.JInt:
        ...


class TransactionInfo(java.lang.Object):

    class Status(java.lang.Enum[TransactionInfo.Status]):

        class_: typing.ClassVar[java.lang.Class]
        NOT_DONE: typing.Final[TransactionInfo.Status]
        COMMITTED: typing.Final[TransactionInfo.Status]
        ABORTED: typing.Final[TransactionInfo.Status]
        NOT_DONE_BUT_ABORTED: typing.Final[TransactionInfo.Status]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TransactionInfo.Status:
            ...

        @staticmethod
        def values() -> jpype.JArray[TransactionInfo.Status]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self) -> str:
        """
        Returns the description of this transaction.
        
        :return: the description of this transaction
        :rtype: str
        """

    def getID(self) -> int:
        ...

    def getOpenSubTransactions(self) -> java.util.ArrayList[java.lang.String]:
        """
        Returns the list of open sub-transactions that are contained
        inside this transaction.
        
        :return: the list of open sub-transactions
        :rtype: java.util.ArrayList[java.lang.String]
        """

    def getStatus(self) -> TransactionInfo.Status:
        """
        Get the status of the corresponding transaction.
        
        :return: status
        :rtype: TransactionInfo.Status
        """

    def hasCommittedDBTransaction(self) -> bool:
        """
        Determine if the corresponding transaction, and all of its sub-transactions, has been 
        committed to the underlying database.
        
        :return: true if the corresponding transaction has been committed, else false.
        :rtype: bool
        """

    @property
    def openSubTransactions(self) -> java.util.ArrayList[java.lang.String]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...

    @property
    def status(self) -> TransactionInfo.Status:
        ...


class TransactionListener(java.lang.Object):
    """
    An interface for listening to transactions
    """

    class_: typing.ClassVar[java.lang.Class]

    def transactionEnded(self, domainObj: ghidra.framework.data.DomainObjectAdapterDB):
        """
        Invoked when a transaction is ended.
        
        :param ghidra.framework.data.DomainObjectAdapterDB domainObj: the domain object where the transaction was ended
        """

    def transactionStarted(self, domainObj: ghidra.framework.data.DomainObjectAdapterDB, tx: TransactionInfo):
        """
        Invoked when a transaction is started.
        
        :param ghidra.framework.data.DomainObjectAdapterDB domainObj: the domain object where the transaction was started
        :param TransactionInfo tx: the transaction that was started
        """

    def undoRedoOccurred(self, domainObj: ghidra.framework.data.DomainObjectAdapterDB):
        """
        Notification that undo or redo has occurred.
        
        :param ghidra.framework.data.DomainObjectAdapterDB domainObj: the affected domain object
        """

    def undoStackChanged(self, domainObj: ghidra.framework.data.DomainObjectAdapterDB):
        """
        Invoked when the stack of available undo/redo's has changed.
        
        :param ghidra.framework.data.DomainObjectAdapterDB domainObj: the affected domain object
        """


class DomainObject(java.lang.Object):
    """
    ``DomainObject`` is the interface that must be supported by
    data objects that are persistent. ``DomainObject``s maintain an
    association with a ``DomainFile``. A ``DomainObject`` that
    has never been saved will have a null ``DomainFile``.
     
    
    Supports transactions and the ability to undo/redo changes made within a stack of 
    recent transactions.  Each transactions may contain many sub-transactions which
    reflect concurrent changes to the domain object.  If any sub-transaction fails to commit,
    all concurrent sub-transaction changes will be rolled-back. 
     
    
    NOTE: A *transaction* must be started in order
    to make any change to this domain object - failure to do so will result in a 
    IOException.
     
    
    Note: Previously (before 11.1), domain object change event types were defined in this file as
    integer constants. Event ids have since been converted to enum types. The defines in this file  
    have been converted to point to the new enum values to make it easier to convert to this new way  
    and to clearly see how the old values map to the new enums. In future releases, these defines 
    will be removed.
    """

    class_: typing.ClassVar[java.lang.Class]
    DO_OBJECT_SAVED: typing.Final[EventType]
    """
    Event type generated when the domain object is saved.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DO_DOMAIN_FILE_CHANGED: typing.Final[EventType]
    """
    Event type generated when the domain file associated with
    the domain object changes.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DO_OBJECT_RENAMED: typing.Final[EventType]
    """
    Event type generated when the object name changes.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DO_OBJECT_RESTORED: typing.Final[EventType]
    """
    Event type generated when domain object is restored.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DO_PROPERTY_CHANGED: typing.Final[EventType]
    """
    Event type generated when a property on this DomainObject is changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DO_OBJECT_CLOSED: typing.Final[EventType]
    """
    Event type generated when this domain object is closed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DO_OBJECT_ERROR: typing.Final[EventType]
    """
    Event type generated when a fatal error occurs which renders the domain object invalid.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    undoLock: typing.Final[java.lang.Object]
    """
    Object to synchronize on for undo/redo operations.
    """


    def addCloseListener(self, listener: DomainObjectClosedListener):
        """
        Adds a listener that will be notified when this DomainObject is closed.  This is meant
        for clients to have a chance to cleanup, such as reference removal.
        
        :param DomainObjectClosedListener listener: the reference to add
        """

    def addConsumer(self, consumer: java.lang.Object) -> bool:
        """
        Adds the given object as a consumer.  The release method must be invoked
        with this same consumer instance when this domain object is no longer in-use.
        
        :param java.lang.Object consumer: domain object consumer
        :return: false if this domain object has already been closed
        :rtype: bool
        """

    def addDomainFileListener(self, listener: ghidra.framework.data.DomainObjectFileListener):
        """
        Adds a listener that will be notified when this DomainFile associated with this
        DomainObject changes, such as when a 'Save As' action occurs. Unlike DomainObject events,
        these notifications are not buffered and happen immediately when the DomainFile is changed.
        
        :param ghidra.framework.data.DomainObjectFileListener listener: the listener to be notified when the associated DomainFile changes
        """

    def addListener(self, dol: DomainObjectListener):
        """
        Adds a listener for this object.
        
        :param DomainObjectListener dol: listener notified when any change occurs to this domain object
        """

    def addSynchronizedDomainObject(self, domainObj: DomainObject):
        """
        Synchronize the specified domain object with this domain object
        using a shared transaction manager.  If either or both is already shared, 
        a transition to a single shared transaction manager will be 
        performed.
        
        :param DomainObject domainObj: the domain object
        :raises LockException: if lock or open transaction is active on either
        this or the specified domain object
        """

    def addTransactionListener(self, listener: TransactionListener):
        """
        Adds the given transaction listener to this domain object
        
        :param TransactionListener listener: the new transaction listener to add
        """

    def canLock(self) -> bool:
        """
        Returns true if a modification lock can be obtained on this
        domain object.  Care should be taken with using this method since
        this will not prevent another thread from modifying the domain object.
        
        :return: true if can lock
        :rtype: bool
        """

    def canRedo(self) -> bool:
        """
        :return: true if there is a later state to "redo" to.
        :rtype: bool
        """

    def canSave(self) -> bool:
        """
        Returns true if this object can be saved; a read-only file cannot be saved.
        
        :return: true if this object can be saved
        :rtype: bool
        """

    def canUndo(self) -> bool:
        """
        :return: true if there is a previous state to "undo" to.
        :rtype: bool
        """

    def clearUndo(self):
        """
        Clear all undoable/redoable transactions
        """

    def createPrivateEventQueue(self, listener: DomainObjectListener, maxDelay: typing.Union[jpype.JInt, int]) -> EventQueueID:
        """
        Creates a private event queue that can be flushed independently from the main event queue.
        
        :param DomainObjectListener listener: the listener to be notified of domain object events.
        :param jpype.JInt or int maxDelay: the time interval (in milliseconds) used to buffer events.
        :return: a unique identifier for this private queue.
        :rtype: EventQueueID
        """

    def endTransaction(self, transactionID: typing.Union[jpype.JInt, int], commit: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Terminate the specified transaction for this domain object.
         
        
        NOTE: If multiple transactions are outstanding the full transaction will not be ended
        until all transactions have been ended.  If any of the transactions indicate a 
        false for ``commit`` the transaction will ultimately be rolled-back when the final
        transaction is ended.
         
        
        NOTE: Use of rollback (``commit=false`` should be avoided unless absolutely
        neccessary since it will incur overhead to revert changes and may rollback multiple
        concurrent transactions if they exist.
        
        :param jpype.JInt or int transactionID: transaction ID obtained from startTransaction method
        :param jpype.JBoolean or bool commit: if true the changes made in this transaction will be marked for commit,
        if false this and any concurrent transaction will be rolled-back.
        :return: true if this invocation was the final transaction and all changes were comitted.
        :rtype: bool
        """

    def flushEvents(self):
        """
        Makes sure all pending domainEvents have been sent.
        """

    def flushPrivateEventQueue(self, id: EventQueueID):
        """
        Flush events from the specified event queue.
        
        :param EventQueueID id: the id specifying the event queue to be flushed.
        """

    def forceLock(self, rollback: typing.Union[jpype.JBoolean, bool], reason: typing.Union[java.lang.String, str]):
        """
        Force transaction lock and terminate current transaction.
        
        :param jpype.JBoolean or bool rollback: true if rollback of non-commited changes should occurs, false if commit
        should be done.  NOTE: it can be potentially detrimental to commit an incomplete transaction
        which should be avoided.
        :param java.lang.String or str reason: very short reason for requesting lock
        """

    def getAllRedoNames(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of the names of all current redo transactions
        
        :return: a list of the names of all current redo transactions
        :rtype: java.util.List[java.lang.String]
        """

    def getAllUndoNames(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of the names of all current undo transactions
        
        :return: a list of the names of all current undo transactions
        :rtype: java.util.List[java.lang.String]
        """

    def getConsumerList(self) -> java.util.List[java.lang.Object]:
        """
        Returns the list of consumers on this domainObject
        
        :return: the list of consumers.
        :rtype: java.util.List[java.lang.Object]
        """

    def getCurrentTransactionInfo(self) -> TransactionInfo:
        """
        Returns the current transaction info
        
        :return: the current transaction info
        :rtype: TransactionInfo
        """

    def getDescription(self) -> str:
        """
        Returns a word or short phrase that best describes or categorizes
        the object in terms that a user will understand.
        
        :return: the description
        :rtype: str
        """

    def getDomainFile(self) -> DomainFile:
        """
        Get the domain file for this domain object.
        
        :return: the associated domain file
        :rtype: DomainFile
        """

    def getMetadata(self) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Returns a map containing all the stored metadata associated with this domain object.  The map
        contains key,value pairs and are ordered by their insertion order.
        
        :return: a map containing all the stored metadata associated with this domain object.
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def getModificationNumber(self) -> int:
        """
        Returns a long value that gets incremented every time a change, undo, or redo takes place.
        Useful for implementing a lazy caching system.
        
        :return: a long value that is incremented for every change to the program.
        :rtype: int
        """

    def getName(self) -> str:
        """
        Get the name of this domain object.
        
        :return: the name
        :rtype: str
        """

    def getOptions(self, propertyListName: typing.Union[java.lang.String, str]) -> ghidra.framework.options.Options:
        """
        Get the property list for the given name.
        
        :param java.lang.String or str propertyListName: name of property list
        :return: the options
        :rtype: ghidra.framework.options.Options
        """

    def getOptionsNames(self) -> java.util.List[java.lang.String]:
        """
        Returns all properties lists contained by this domain object.
        
        :return: all property lists contained by this domain object.
        :rtype: java.util.List[java.lang.String]
        """

    def getRedoName(self) -> str:
        """
        Returns a description of the change that would be "redone".
        
        :return: a description of the change that would be "redone".
        :rtype: str
        """

    def getSynchronizedDomainObjects(self) -> jpype.JArray[DomainObject]:
        """
        Return array of all domain objects synchronized with a 
        shared transaction manager.
        
        :return: returns array of synchronized domain objects or
        null if this domain object is not synchronized with others.
        :rtype: jpype.JArray[DomainObject]
        """

    def getUndoName(self) -> str:
        """
        Returns a description of the change that would be "undone".
        
        :return: a description of the change that would be "undone".
        :rtype: str
        """

    def hasExclusiveAccess(self) -> bool:
        """
        Returns true if the user has exclusive access to the domain object.  Exclusive access means
        either the object is not shared or the user has an exclusive checkout on the object.
        
        :return: true if has exclusive access
        :rtype: bool
        """

    def hasTerminatedTransaction(self) -> bool:
        """
        Returns true if the last transaction was terminated from the action that started it.
        
        :return: true if the last transaction was terminated from the action that started it.
        :rtype: bool
        """

    def isChangeable(self) -> bool:
        """
        Returns true if changes are permitted.
        
        :return: true if changes are permitted.
        :rtype: bool
        """

    def isChanged(self) -> bool:
        """
        Returns whether the object has changed.
        
        :return: whether the object has changed.
        :rtype: bool
        """

    def isClosed(self) -> bool:
        """
        Returns true if this domain object has been closed as a result of the last release
        
        :return: true if closed
        :rtype: bool
        """

    def isLocked(self) -> bool:
        """
        Returns true if the domain object currently has a modification lock enabled.
        
        :return: true if locked
        :rtype: bool
        """

    def isSendingEvents(self) -> bool:
        """
        Returns true if this object is sending out events as it is changed.  The default is
        true.  You can change this value by calling :meth:`setEventsEnabled(boolean) <.setEventsEnabled>`.
        
        :return: true if sending events
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.setEventsEnabled(boolean)`
        """

    def isTemporary(self) -> bool:
        """
        Returns true if this object has been marked as Temporary.
        
        :return: true if this object has been marked as Temporary.
        :rtype: bool
        """

    def isUsedBy(self, consumer: java.lang.Object) -> bool:
        """
        Returns true if the given consumer is using (has open) this domain object.
        
        :param java.lang.Object consumer: the object to test to see if it is a consumer of this domain object.
        :return: true if the given consumer is using (has open) this domain object;
        :rtype: bool
        """

    def lock(self, reason: typing.Union[java.lang.String, str]) -> bool:
        """
        Attempt to obtain a modification lock on the domain object.  Multiple locks may be granted
        on this domain object, although all lock owners must release their lock in a timely fashion.
        
        :param java.lang.String or str reason: very short reason for requesting lock
        :return: true if lock obtained successfully, else false which indicates that a modification
        is in process.
        :rtype: bool
        """

    def openTransaction(self, description: typing.Union[java.lang.String, str]) -> db.Transaction:
        """
        Open new transaction.  This should generally be done with a try-with-resources block:
         
        try (Transaction tx = dobj.openTransaction(description)) {
            // ... Do something
        }
         
        
        :param java.lang.String or str description: a short description of the changes to be made.
        :return: transaction object
        :rtype: db.Transaction
        :raises java.lang.IllegalStateException: if this :obj:`DomainObject` has already been closed.
        """

    def redo(self):
        """
        Returns to a latter state that exists because of an undo.  Normally, this
        will cause the current state to appear on the "undo" stack.  This method
        will do nothing if there are no latter states to "redo".
        
        :raises IOException: if an IO error occurs
        """

    def release(self, consumer: java.lang.Object):
        """
        Notify the domain object that the specified consumer is no longer using it.
        When the last consumer invokes this method, the domain object will be closed
        and will become invalid.
        
        :param java.lang.Object consumer: the consumer (e.g., tool, plugin, etc) of the domain object
        previously established with the addConsumer method.
        """

    def releaseSynchronizedDomainObject(self):
        """
        Remove this domain object from a shared transaction manager.  If
        this object has not been synchronized with others via a shared
        transaction manager, this method will have no affect.
        
        :raises LockException: if lock or open transaction is active
        """

    def removeCloseListener(self, listener: DomainObjectClosedListener):
        """
        Removes the given close listener.
        
        :param DomainObjectClosedListener listener: the listener to remove.
        """

    def removeDomainFileListener(self, listener: ghidra.framework.data.DomainObjectFileListener):
        """
        Removes the given DomainObjectFileListener listener.
        
        :param ghidra.framework.data.DomainObjectFileListener listener: the listener to remove.
        """

    def removeListener(self, dol: DomainObjectListener):
        """
        Remove the listener for this object.
        
        :param DomainObjectListener dol: listener
        """

    def removePrivateEventQueue(self, id: EventQueueID) -> bool:
        """
        Removes the specified private event queue
        
        :param EventQueueID id: the id of the queue to remove.
        :return: true if the id represents a valid queue that was removed.
        :rtype: bool
        """

    def removeTransactionListener(self, listener: TransactionListener):
        """
        Removes the given transaction listener from this domain object.
        
        :param TransactionListener listener: the transaction listener to remove
        """

    def save(self, comment: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Saves changes to the DomainFile.
        
        :param java.lang.String or str comment: comment used for new version
        :param ghidra.util.task.TaskMonitor monitor: monitor that shows the progress of the save
        :raises IOException: thrown if there was an error accessing this
        domain object
        :raises ReadOnlyException: thrown if this DomainObject is read only
        and cannot be saved
        :raises CancelledException: thrown if the user canceled the save
        operation
        """

    def saveToPackedFile(self, outputFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        """
        Saves (i.e., serializes) the current content to a packed file.
        
        :param jpype.protocol.SupportsPath outputFile: packed output file
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises IOException: if an exception occurs
        :raises CancelledException: if the user cancels
        :raises UnsupportedOperationException: if not supported by object implementation
        """

    def setEventsEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        If true, domain object change events are sent. If false, no events are sent.
         
        
        **
        NOTE: disabling events could cause plugins to be out of sync!
        **
         
        
        NOTE: when re-enabling events, an event will be sent to the system to signal that
            every listener should update.
        
        :param jpype.JBoolean or bool enabled: true means to enable events
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Set the name for this domain object.
        
        :param java.lang.String or str name: object name
        """

    def setTemporary(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Set the temporary state of this object.
        If this object is temporary, the isChanged() method will
        always return false.  The default temporary state is false.
        
        :param jpype.JBoolean or bool state: if true object is marked as temporary
        """

    @typing.overload
    def startTransaction(self, description: typing.Union[java.lang.String, str]) -> int:
        """
        Start a new transaction in order to make changes to this domain object.
        All changes must be made in the context of a transaction. 
        If a transaction is already in progress, a sub-transaction 
        of the current transaction will be returned.
        
        :param java.lang.String or str description: brief description of transaction
        :return: transaction ID
        :rtype: int
        :raises DomainObjectLockedException: the domain object is currently locked
        :raises TerminatedTransactionException: an existing transaction which has not yet ended was terminated early.
        Sub-transactions are not permitted until the terminated transaction ends.
        """

    @typing.overload
    def startTransaction(self, description: typing.Union[java.lang.String, str], listener: AbortedTransactionListener) -> int:
        """
        Start a new transaction in order to make changes to this domain object.
        All changes must be made in the context of a transaction. 
        If a transaction is already in progress, a sub-transaction 
        of the current transaction will be returned.
        
        :param java.lang.String or str description: brief description of transaction
        :param AbortedTransactionListener listener: listener to be notified if the transaction is aborted.
        :return: transaction ID
        :rtype: int
        :raises DomainObjectLockedException: the domain object is currently locked
        :raises TerminatedTransactionException: an existing transaction which has not yet ended was terminated early.
        Sub-transactions are not permitted until the terminated transaction ends.
        """

    def undo(self):
        """
        Returns to the previous state.  Normally, this will cause the current state
        to appear on the "redo" stack.  This method will do nothing if there are
        no previous states to "undo".
        
        :raises IOException: if an IO error occurs
        """

    def unlock(self):
        """
        Release a modification lock previously granted with the lock method.
        """

    @typing.overload
    def withTransaction(self, description: typing.Union[java.lang.String, str], callback: utility.function.ExceptionalCallback[E]):
        """
        Performs the given callback inside of a transaction.  Use this method in place of the more
        verbose try/catch/finally semantics.
         
        program.withTransaction("My Description", () -> {
            // ... Do something
        });
         
         
         
        
        Note: the transaction created by this method will always be committed when the call is 
        finished.  If you need the ability to abort transactions, then you need to use the other 
        methods on this interface.
        
        :param java.lang.String or str description: brief description of transaction
        :param utility.function.ExceptionalCallback[E] callback: the callback that will be called inside of a transaction
        :raises E: any exception that may be thrown in the given callback
        """

    @typing.overload
    def withTransaction(self, description: typing.Union[java.lang.String, str], supplier: utility.function.ExceptionalSupplier[T, E]) -> T:
        """
        Calls the given supplier inside of a transaction.  Use this method in place of the more
        verbose try/catch/finally semantics.
         
        program.withTransaction("My Description", () -> {
            // ... Do something
            return result;
        });
         
         
        
        If you do not need to supply a result, then use 
        :meth:`withTransaction(String, ExceptionalCallback) <.withTransaction>` instead.
        
        :param E: the exception that may be thrown from this method:param T: the type of result returned by the supplier:param java.lang.String or str description: brief description of transaction
        :param utility.function.ExceptionalSupplier[T, E] supplier: the supplier that will be called inside of a transaction
        :return: the result returned by the supplier
        :rtype: T
        :raises E: any exception that may be thrown in the given callback
        """

    @property
    def temporary(self) -> jpype.JBoolean:
        ...

    @temporary.setter
    def temporary(self, value: jpype.JBoolean):
        ...

    @property
    def metadata(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def redoName(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def consumerList(self) -> java.util.List[java.lang.Object]:
        ...

    @property
    def allUndoNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def allRedoNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def undoName(self) -> java.lang.String:
        ...

    @property
    def domainFile(self) -> DomainFile:
        ...

    @property
    def options(self) -> ghidra.framework.options.Options:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def changeable(self) -> jpype.JBoolean:
        ...

    @property
    def synchronizedDomainObjects(self) -> jpype.JArray[DomainObject]:
        ...

    @property
    def optionsNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def currentTransactionInfo(self) -> TransactionInfo:
        ...

    @property
    def sendingEvents(self) -> jpype.JBoolean:
        ...

    @property
    def locked(self) -> jpype.JBoolean:
        ...

    @property
    def usedBy(self) -> jpype.JBoolean:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...

    @property
    def modificationNumber(self) -> jpype.JLong:
        ...


class DefaultLaunchMode(java.lang.Enum[DefaultLaunchMode]):
    """
    :obj:`DefaultLaunchMode` provides an :obj:`Options` value which indicates how a default tool
    launch should be performed.
    """

    class_: typing.ClassVar[java.lang.Class]
    REUSE_TOOL: typing.Final[DefaultLaunchMode]
    NEW_TOOL: typing.Final[DefaultLaunchMode]
    DEFAULT: typing.ClassVar[DefaultLaunchMode]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DefaultLaunchMode:
        ...

    @staticmethod
    def values() -> jpype.JArray[DefaultLaunchMode]:
        ...


class DomainFile(java.lang.Comparable[DomainFile]):
    """
    ``DomainFile`` provides a storage interface for project files.  A 
    ``DomainFile`` is an immutable reference to file contained within a project.  The state 
    of a ``DomainFile`` object does not track name/parent changes made to the referenced 
    project file.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNSUPPORTED_FILE_ICON: typing.Final[javax.swing.Icon]
    DEFAULT_VERSION: typing.Final = -1
    """
    Use with getDomainObject to request the default version.  The default version is
    the private file or check-out file if one exists, or the latest version from the
    version controlled file system.
    """

    READ_ONLY_PROPERTY: typing.Final = "READ_ONLY"
    """
    Event property name for Read-only setting.
    """


    def addToVersionControl(self, comment: typing.Union[java.lang.String, str], keepCheckedOut: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Adds this private file to version control.
        
        :param java.lang.String or str comment: new version comment
        :param jpype.JBoolean or bool keepCheckedOut: if true, the file will be initially checked-out.  This option will be
        ignored if file is currently open in which case file will remain checked-out.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises FileInUseException: if this file is in-use.
        :raises IOException: if an IO or access error occurs.  Also if file is not 
        private.
        :raises CancelledException: if the monitor cancelled the operation
        """

    def canAddToRepository(self) -> bool:
        """
        Returns true if this private file may be added to the associated repository.
         
        Note: this does not take into consideration cases where the file is currently
        in-use which may cause a failure if add to repository is attempted.
        
        :return: true if add to the repository can be attempted (i.e., file in active project
        is not versioned or hijacked)
        :rtype: bool
        """

    def canCheckin(self) -> bool:
        """
        Returns true if this file may be checked-in to the associated repository.
         
        Note: this does not take into consideration cases where the file is currently
        in-use which may cause a failure if a checkin is attempted.
        
        :return: true if a check-in can be attempted (i.e., file is checked-out with changes),
        else false
        :rtype: bool
        """

    def canCheckout(self) -> bool:
        """
        Returns true if this file may be checked-out from the associated repository.
        User's with read-only repository access will not have checkout ability.
        
        :return: true if can checkout
        :rtype: bool
        """

    def canMerge(self) -> bool:
        """
        Returns true if this file can be merged with the current versioned file.
         
        Note: this does not take into consideration cases where the file is currently
        in-use which may cause a failure if a merge is attempted.
        
        :return: true if a merge can be attempted (i.e., file is checked-out and a newer 
        version exists), else false
        :rtype: bool
        """

    def canRecover(self) -> bool:
        """
        Prior to invoking getDomainObject, this method can be used to determine if
        unsaved changes can be recovered on the next open.
        
        :return: true if recovery data exists.
        :rtype: bool
        """

    def canSave(self) -> bool:
        """
        Return whether this domain object can be saved (i.e., updated/overwritten).
        
        :return: true if the user is the owner AND the file is in
        the active project AND the file is not read-only.
        :rtype: bool
        """

    @typing.overload
    def checkin(self, checkinHandler: ghidra.framework.data.CheckinHandler, monitor: ghidra.util.task.TaskMonitor):
        """
        Performs check in to associated repository.  File must be checked-out 
        and modified since checkout.
        
        :param ghidra.framework.data.CheckinHandler checkinHandler: provides user input data to complete checkin process.
        The keep-checked-out option supplied by this handler will be ignored if file is currently 
        open in which case file will remain checked-out.
        :param ghidra.util.task.TaskMonitor monitor: the TaskMonitor.
        :raises IOException: if an IO or access error occurs
        :raises VersionException: if unable to handle domain object version in versioned filesystem.
        We are unable to upgrade since this would only occur if checkout is not exclusive.
        :raises CancelledException: if task monitor cancelled operation
        """

    @typing.overload
    @deprecated("use alternative checkin(CheckinHandler, TaskMonitor) method since\n okToUpgrade cannot be respected and is ignored.  Upgrade cannot be performed during checkin.")
    def checkin(self, checkinHandler: ghidra.framework.data.CheckinHandler, okToUpgrade: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Performs check in to associated repository.  File must be checked-out 
        and modified since checkout.
        
        :param ghidra.framework.data.CheckinHandler checkinHandler: provides user input data to complete checkin process.
        This keep-checked-out option supplied by this handler will be ignored and forced true 
        if file is currently open.
        :param jpype.JBoolean or bool okToUpgrade: if true an upgrade will be performed if needed (ignored)
        :param ghidra.util.task.TaskMonitor monitor: the TaskMonitor.
        :raises IOException: if an IO or access error occurs
        :raises VersionException: if unable to handle domain object version in versioned filesystem.
        If okToUpgrade was false, check exception to see if it can be upgraded
        sometime after doing a checkout.
        :raises CancelledException: if task monitor cancelled operation
        
        .. deprecated::
        
        use alternative :meth:`checkin(CheckinHandler, TaskMonitor) <.checkin>` method since
        okToUpgrade cannot be respected and is ignored.  Upgrade cannot be performed during checkin.
        """

    def checkout(self, exclusive: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Checkout this file for update.  If this file is already 
        private, this method does nothing.
        
        :param jpype.JBoolean or bool exclusive: if true an exclusive checkout will be requested
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :return: true if checkout successful, false if an exclusive checkout was not possible
        due to other users having checkouts of this file.  A request for a non-exclusive checkout 
        will never return false.
        :rtype: bool
        :raises IOException: if an IO or access error occurs.
        :raises CancelledException: if task monitor cancelled operation.
        """

    def copyTo(self, newParent: DomainFolder, monitor: ghidra.util.task.TaskMonitor) -> DomainFile:
        """
        Copy this file into the newParent folder as a private file.
        
        :param DomainFolder newParent: new parent folder
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: newly created domain file
        :rtype: DomainFile
        :raises FileInUseException: if this file is in-use / checked-out.
        :raises IOException: if an IO or access error occurs.
        :raises CancelledException: if task monitor cancelled operation.
        """

    def copyToAsLink(self, newParent: DomainFolder) -> DomainFile:
        """
        Copy this file into the newParent folder as a link file.  Restrictions:
         
        * Specified newParent must reside within a different project since internal linking is
        not currently supported.
        * Content type must support linking (see :meth:`isLinkingSupported() <.isLinkingSupported>`).
        
        If this file is associated with a temporary transient project (i.e., not a locally 
        managed project) the generated link will refer to the remote file with a remote
        Ghidra URL, otherwise a local project storage path will be used.
        
        :param DomainFolder newParent: new parent folder
        :return: newly created domain file or null if content type does not support link use.
        :rtype: DomainFile
        :raises IOException: if an IO or access error occurs.
        """

    def copyVersionTo(self, version: typing.Union[jpype.JInt, int], destFolder: DomainFolder, monitor: ghidra.util.task.TaskMonitor) -> DomainFile:
        """
        Copy a specific version of this file to the specified destFolder.
        
        :param jpype.JInt or int version: version to copy
        :param DomainFolder destFolder: destination parent folder
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: the copied file
        :rtype: DomainFile
        :raises IOException: if an IO or access error occurs.
        :raises CancelledException: if task monitor cancelled operation.
        """

    @typing.overload
    def delete(self):
        """
        Delete the entire database for this file, including any version files.
        
        :raises FileInUseException: if this file is in-use / checked-out.
        :raises UserAccessException: if the user does not have permission to delete the file.
        :raises IOException: if an IO or access error occurs.
        """

    @typing.overload
    def delete(self, version: typing.Union[jpype.JInt, int]):
        """
        Deletes a specific version of a file from the versioned filesystem.
        
        :param jpype.JInt or int version: specific version to be deleted.  The version must either
        be the oldest or latest, or -1 which will attempt to remove all versions.
        When deleting the latest version, this method could take a long time
        to return since the previous version must be reconstructed within the
        versioned filesystem.
        :raises IOException: if an IO error occurs, including the inability 
        to delete a version because this item is checked-out, the user does
        not have permission, or the specified version is not the oldest or
        latest.
        """

    def exists(self) -> bool:
        """
        Check for existence of domain file.
        
        :return: true if file exists.  A proxy domain file will always return false.
        :rtype: bool
        """

    def followLink(self) -> DomainFolder:
        """
        If this is a folder-link file get the corresponding linked folder.
        
        :return: a linked domain folder or null if not a folder-link.
        :rtype: DomainFolder
        """

    def getChangesByOthersSinceCheckout(self) -> ChangeSet:
        """
        Returns changes made to versioned file by others since checkout was performed.
        NOTE: This method is unable to cope with version issues which may require an
        upgrade.
        
        :return: change set or null
        :rtype: ChangeSet
        :raises VersionException: latest version was created with a different version of software
        which prevents rapid determination of change set.
        :raises IOException: if a folder item access error occurs or change set was 
        produced by newer version of software and can not be read
        """

    def getCheckoutStatus(self) -> ghidra.framework.store.ItemCheckoutStatus:
        """
        Get checkout status associated with a versioned file.
        
        :return: checkout status or null if not checked-out to current associated project.
        :rtype: ghidra.framework.store.ItemCheckoutStatus
        :raises IOException: if an IO or access error occurs
        """

    def getCheckouts(self) -> jpype.JArray[ghidra.framework.store.ItemCheckoutStatus]:
        """
        Get a list of checkouts by all users for the associated versioned file.
        
        :return: list of checkouts
        :rtype: jpype.JArray[ghidra.framework.store.ItemCheckoutStatus]
        :raises IOException: if an IO or access error occurs
        """

    def getConsumers(self) -> java.util.List[typing.Any]:
        """
        Get the list of consumers (Objects) for this domain file.
        
        :return: true if linking is supported allowing a link-file to be created which 
        references this file, else false.
        :rtype: java.util.List[typing.Any]
        """

    def getContentType(self) -> str:
        """
        Returns content-type string for this file
        
        :return: the file content type or a reserved content type :obj:`ContentHandler.MISSING_CONTENT`
        or :obj:`ContentHandler.UNKNOWN_CONTENT`.
        :rtype: str
        """

    def getDomainObject(self, consumer: java.lang.Object, okToUpgrade: typing.Union[jpype.JBoolean, bool], okToRecover: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> DomainObject:
        """
        Opens and returns the current domain object.  If the domain object is already opened,
        then the existing open domain object is returned.
        
        :param java.lang.Object consumer: consumer of the domain object which is responsible for
        releasing it after use. When all the consumers using the domain object release it, then
        the object is closed and its resources released.
        :param jpype.JBoolean or bool okToUpgrade: if true, allows the system to upgrade out of data domain objects to
        be in compliance with the current version of Ghidra. A Version exception will be thrown
        if the domain object cannot be upgraded OR okToUpgrade is false and the domain object is
        out of date.
        :param jpype.JBoolean or bool okToRecover: if true, allows the system to recover unsaved file changes which 
        resulted from a crash.  If false, any existing recovery data will be deleted.
        This flag is only relevant if project is open for update (isInProject) and the file can be
        opened for update.
        :param ghidra.util.task.TaskMonitor monitor: permits monitoring of open progress.
        :return: an open domain object can be modified and saved. (Not read-only)
        :rtype: DomainObject
        :raises VersionException: if the domain object could not be read due
        to a version format change.  If okToUpgrade is true, then a VersionException indicates
        that the domain object cannot be upgraded to the current format.  If okToUpgrade is false,
        then the VersionException only means the object is not in the current format - it 
        may or may not be possible to upgrade.
        :raises IOException: if an IO or access error occurs.
        :raises CancelledException: if monitor cancelled operation
        """

    def getDomainObjectClass(self) -> java.lang.Class[DomainObject]:
        """
        Returns the underlying Class for the domain object in this domain file.
        
        :return: the class or null if does not correspond to a domain object.
        :rtype: java.lang.Class[DomainObject]
        """

    def getFileID(self) -> str:
        """
        Returns a unique file-ID if one has been established or null.  Examples which may result in 
        null ID:
         
        * Very old project file which pre-dates introduction of file ID, or
        * Remote versioned file with lost connection
        
        
        :return: the file-ID or null if failed to obtain ID.
        :rtype: str
        """

    def getIcon(self, disabled: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Get the state based Icon image for the domain file based upon its content class.
        
        :param jpype.JBoolean or bool disabled: true if the icon return should be rendered as 
        not enabled
        :return: image icon
        :rtype: javax.swing.Icon
        """

    def getImmutableDomainObject(self, consumer: java.lang.Object, version: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> DomainObject:
        """
        Returns a new DomainObject that cannot be changed or saved to its original file.
        NOTE: The use of this method should generally be avoided since it can't
        handle version changes that may have occured and require a data upgrade
        (e.g., DB schema change).
        
        :param java.lang.Object consumer: consumer of the domain object which is responsible for
        releasing it after use.
        :param jpype.JInt or int version: the domain object version requested.  DEFAULT_VERSION should be 
        specified to open the current version.
        :param ghidra.util.task.TaskMonitor monitor: permits monitoring of open progress.
        :return: a new domain object that is disassociated from its original domain file
        and cannot be modified
        :rtype: DomainObject
        :raises VersionException: if the domain object could not be read due
        to a version format change.
        :raises FileNotFoundException: if the stored file/version was not found.
        :raises IOException: if an IO or access error occurs.
        :raises CancelledException: if monitor cancelled operation
        """

    def getLastModifiedTime(self) -> int:
        """
        Get a long value representing the time when the data was last modified.
        
        :return: the time
        :rtype: int
        """

    def getLatestVersion(self) -> int:
        """
        Return the latest version
        
        :return: the version
        :rtype: int
        """

    def getLocalProjectURL(self, ref: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Get a local Ghidra URL for this domain file if available within the associated non-transient
        local project.  A null value will be returned if project is transient.
        
        :param java.lang.String or str ref: reference within a file, may be null.  NOTE: such reference interpretation
        is specific to a domain object and tooling with limited support.
        :return: local Ghidra URL for this file or null if transient or not applicable
        :rtype: java.net.URL
        """

    def getMetadata(self) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Returns an ordered map containing the metadata that has been associated with the 
        corresponding domain object. The map contains key,value pairs and are ordered by their 
        insertion order.
        
        :return: a map containing the metadata that has been associated with the corresponding domain 
        object.
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def getName(self) -> str:
        """
        Get the name of this project file
        
        :return: the name
        :rtype: str
        """

    def getOpenedDomainObject(self, consumer: java.lang.Object) -> DomainObject:
        """
        Returns the domainObject for this DomainFile only if it is already open.
        
        :param java.lang.Object consumer: the consumer that will use the object.
        :return: the already opened domainObject or null if it is not currently open.
        :rtype: DomainObject
        """

    def getParent(self) -> DomainFolder:
        """
        Get the parent domain folder for this domain file.
        
        :return: the parent
        :rtype: DomainFolder
        """

    def getPathname(self) -> str:
        """
        Returns the full path name to this file
        
        :return: the path name
        :rtype: str
        """

    def getProjectLocator(self) -> ProjectLocator:
        """
        Returns the local storage location for the project that this DomainFile belongs to.
        
        :return: the location
        :rtype: ProjectLocator
        """

    def getReadOnlyDomainObject(self, consumer: java.lang.Object, version: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> DomainObject:
        """
        Returns a "read-only" version of the domain object.  "Read-only" means that the domain
        object cannot be saved back into its original domain object. It can still be modified
        and saved to a new domain file.  The domain object will be assigned a temporary domain
        file that will not allow a "save" operation. The user must do a "save as"
        to a new filename.
        
        :param java.lang.Object consumer: consumer of the domain object which is responsible for
        releasing it after use.
        :param jpype.JInt or int version: the domain object version requested.  DEFAULT_VERSION should be 
        specified to open the current version.
        :param ghidra.util.task.TaskMonitor monitor: permits monitoring of open progress.
        :return: a new domain object that is disassociated from its original domain file.
        :rtype: DomainObject
        :raises VersionException: if the domain object could not be read due
        to a version format change.
        :raises FileNotFoundException: if the stored file/version was not found.
        :raises IOException: if an IO or access error occurs.
        :raises CancelledException: if monitor cancelled operation
        """

    def getSharedProjectURL(self, ref: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Get a remote Ghidra URL for this domain file if available within an associated shared
        project repository.  A null value will be returned if shared file does not exist and
        may also be returned if shared repository is not connected or a connection error occurs.
        
        :param java.lang.String or str ref: reference within a file, may be null.  NOTE: such reference interpretation
        is specific to a domain object and tooling with limited support.
        :return: remote Ghidra URL for this file or null
        :rtype: java.net.URL
        """

    def getVersion(self) -> int:
        """
        Return either the latest version if the file is not checked-out or the version that
        was checked-out or a specific version that was requested.
        
        :return: the version
        :rtype: int
        """

    def getVersionHistory(self) -> jpype.JArray[ghidra.framework.store.Version]:
        """
        Returns list of all available versions.
        
        :return: the versions
        :rtype: jpype.JArray[ghidra.framework.store.Version]
        :raises IOException: if there is an exception getting the history
        """

    def isBusy(self) -> bool:
        """
        Returns true if the domain object in this domain file exists and has an open transaction.
        
        :return: true if busy
        :rtype: bool
        """

    def isChanged(self) -> bool:
        """
        Return whether the domain object in this domain file has changed.
        
        :return: true if changed
        :rtype: bool
        """

    def isCheckedOut(self) -> bool:
        """
        Returns true if this is a checked-out file.
        
        :return: true if checked-out
        :rtype: bool
        """

    def isCheckedOutExclusive(self) -> bool:
        """
        Returns true if this a checked-out file with exclusive access.
        
        :return: true if checked-out exclusively
        :rtype: bool
        """

    def isHijacked(self) -> bool:
        """
        Returns true if the file is versioned but a private copy also exists.
        
        :return: true if hijacked
        :rtype: bool
        """

    def isInWritableProject(self) -> bool:
        """
        Returns true if this file is in a writable project.
        
        :return: true if writable
        :rtype: bool
        """

    def isLatestVersion(self) -> bool:
        """
        Returns true if this file represents the latest version of the associated domain object.
        
        :return: true if the latest version
        :rtype: bool
        """

    def isLinkFile(self) -> bool:
        """
        Determine if this file is a link file which corresponds to either a file or folder link.  
        The :obj:`DomainObject` referenced by a link-file may be opened using 
        :meth:`getReadOnlyDomainObject(Object, int, TaskMonitor) <.getReadOnlyDomainObject>`.  The 
        :meth:`getDomainObject(Object, boolean, boolean, TaskMonitor) <.getDomainObject>` method may also be used
        to obtain a read-only instance.  :meth:`getImmutableDomainObject(Object, int, TaskMonitor) <.getImmutableDomainObject>`
        use is not supported.
        If the link-file content type equals :const:`FolderLinkContentHandler.FOLDER_LINK_CONTENT_TYPE`
        the method :meth:`followLink() <.followLink>` can be used to get the linked domain folder. 
        The associated link URL may be obtained with :meth:`LinkHandler.getURL(DomainFile) <LinkHandler.getURL>`.
        The content type (see :meth:`getContentType() <.getContentType>` of a link file will differ from that of the
        linked object (e.g., "LinkedProgram" vs "Program").
        
        :return: true if link file else false for a normal domain file
        :rtype: bool
        """

    def isLinkingSupported(self) -> bool:
        """
        Determine if this file's content type supports linking.
        
        :return: true if linking is supported, else false.
        :rtype: bool
        """

    def isOpen(self) -> bool:
        """
        Returns true if there is an open domainObject for this file.
        
        :return: true if open
        :rtype: bool
        """

    def isReadOnly(self) -> bool:
        """
        Returns whether this file is explicitly marked as read-only.  This method is only supported
        by the local file system and does not apply to a versioned file that is not checked-out.
        A versioned file that is not checked-out will always return false, while a 
        :obj:`DomainFileProxy` will always return true.
        From a framework point of view a read-only file can never be changed.
        
        :return: true if this file is marked read-only
        :rtype: bool
        """

    def isVersioned(self) -> bool:
        """
        Return true if this is a versioned database, else false
        
        :return: true if versioned
        :rtype: bool
        """

    def length(self) -> int:
        """
        Returns the length of this domain file.  This size is the minimum disk space
        used for storing this file, but does not account for additional storage space
        used to track changes, etc.
        
        :return: file length
        :rtype: int
        :raises IOException: if IO or access error occurs
        """

    def merge(self, okToUpgrade: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Performs merge from current version of versioned file into local checked-out file.
        
        :param jpype.JBoolean or bool okToUpgrade: if true an upgrade will be performed if needed
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if an IO or access error occurs
        :raises VersionException: if unable to handle domain object version in versioned filesystem.
        If okToUpgrade was false, check exception to see if it can be upgraded
        :raises CancelledException: if task monitor cancelled operation
        """

    def modifiedSinceCheckout(self) -> bool:
        """
        Returns true if this is a checked-out file which has been modified since it was checked-out.
        
        :return: true if modified since check-out
        :rtype: bool
        """

    def moveTo(self, newParent: DomainFolder) -> DomainFile:
        """
        Move this file into the newParent folder.
        
        :param DomainFolder newParent: new parent folder within the same project
        :return: the newly relocated domain file (the original DomainFile object becomes invalid since it is immutable)
        :rtype: DomainFile
        :raises DuplicateFileException: if a file with the same name 
        already exists in newParent folder.
        :raises FileInUseException: if this file is in-use / checked-out.
        :raises IOException: if an IO or access error occurs.
        """

    def packFile(self, file: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        """
        Pack domain file into specified file.
        Specified file will be overwritten if it already exists.
        
        :param jpype.protocol.SupportsPath file: destination file
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if there is an exception packing the file
        :raises CancelledException: if monitor cancels operation
        """

    def save(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Save the ``DomainObject`` associated with this file.
        
        :param ghidra.util.task.TaskMonitor monitor: monitor for the task that is doing the save on the file
        :raises FileInUseException: if the file is open for update by someone else, or
        a transient-read is in progress.
        :raises IOException: if an IO error occurs.
        :raises CancelledException: if monitor cancelled operation
        """

    def setName(self, newName: typing.Union[java.lang.String, str]) -> DomainFile:
        """
        Set the name on this domain file.
        
        :param java.lang.String or str newName: domain file name
        :return: renamed domain file (the original DomainFile object becomes invalid since it is immutable)
        :rtype: DomainFile
        :raises InvalidNameException: if newName contains illegal characters
        :raises DuplicateFileException: if a file named newName 
        already exists in this files domain folder.
        :raises FileInUseException: if this file is in-use / checked-out.
        :raises IOException: if an IO or access error occurs.
        """

    def setReadOnly(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the object to read-only.  This method may only be invoked
        for private files (i.e., not versioned).
        
        :param jpype.JBoolean or bool state: if true file will be read-only and may not be updated, if false the 
        file may be updated.
        :raises IOException: if an IO error occurs.
        """

    def takeRecoverySnapshot(self) -> bool:
        """
        If the file has an updatable domain object with unsaved changes, generate a recovery 
        snapshot.
        
        :return: true if snapshot successful or not needed, false if file is busy which prevents 
        snapshot, or snapshot was cancelled.
        :rtype: bool
        :raises IOException: if there is an exception saving the snapshot
        """

    def terminateCheckout(self, checkoutId: typing.Union[jpype.JLong, int]):
        """
        Forcefully terminate a checkout for the associated versioned file.
        The user must be the owner of the checkout or have administrator privilege
        on the versioned filesystem (i.e., repository).
        
        :param jpype.JLong or int checkoutId: checkout ID
        :raises IOException: if an IO or access error occurs
        """

    @typing.overload
    def undoCheckout(self, keep: typing.Union[jpype.JBoolean, bool]):
        """
        Undo "checked-out" file.  The original repository file is restored.
        
        :param jpype.JBoolean or bool keep: if true, the private database will be renamed with a .keep
        extension.
        :raises NotConnectedException: if shared project and not connected to repository
        :raises FileInUseException: if this file is in-use.
        :raises IOException: if file is not checked-out or an IO / access error occurs.
        """

    @typing.overload
    def undoCheckout(self, keep: typing.Union[jpype.JBoolean, bool], force: typing.Union[jpype.JBoolean, bool]):
        """
        Undo "checked-out" file.  The original repository file is restored.
        
        :param jpype.JBoolean or bool keep: if true, the private database will be renamed with a .keep
        extension.
        :param jpype.JBoolean or bool force: if not connected to the repository the local checkout file will be removed.
            Warning: forcing undo checkout will leave a stale checkout in place for the associated 
            repository if not connected.
        :raises NotConnectedException: if shared project and not connected to repository and
            force is false
        :raises FileInUseException: if this file is in-use / checked-out.
        :raises IOException: thrown if file is not checked-out or an IO / access error occurs.
        """

    @property
    def checkedOut(self) -> jpype.JBoolean:
        ...

    @property
    def parent(self) -> DomainFolder:
        ...

    @property
    def metadata(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def lastModifiedTime(self) -> jpype.JLong:
        ...

    @property
    def sharedProjectURL(self) -> java.net.URL:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def domainObjectClass(self) -> java.lang.Class[DomainObject]:
        ...

    @property
    def projectLocator(self) -> ProjectLocator:
        ...

    @property
    def checkoutStatus(self) -> ghidra.framework.store.ItemCheckoutStatus:
        ...

    @property
    def versionHistory(self) -> jpype.JArray[ghidra.framework.store.Version]:
        ...

    @property
    def versioned(self) -> jpype.JBoolean:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def inWritableProject(self) -> jpype.JBoolean:
        ...

    @property
    def consumers(self) -> java.util.List[typing.Any]:
        ...

    @property
    def contentType(self) -> java.lang.String:
        ...

    @property
    def fileID(self) -> java.lang.String:
        ...

    @property
    def checkouts(self) -> jpype.JArray[ghidra.framework.store.ItemCheckoutStatus]:
        ...

    @property
    def checkedOutExclusive(self) -> jpype.JBoolean:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @readOnly.setter
    def readOnly(self, value: jpype.JBoolean):
        ...

    @property
    def linkingSupported(self) -> jpype.JBoolean:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def pathname(self) -> java.lang.String:
        ...

    @property
    def hijacked(self) -> jpype.JBoolean:
        ...

    @property
    def linkFile(self) -> jpype.JBoolean:
        ...

    @property
    def latestVersion(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def localProjectURL(self) -> java.net.URL:
        ...

    @property
    def openedDomainObject(self) -> DomainObject:
        ...

    @property
    def open(self) -> jpype.JBoolean:
        ...

    @property
    def changesByOthersSinceCheckout(self) -> ChangeSet:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...


class DomainObjectLockedException(java.lang.RuntimeException):
    """
    Thrown when a method fails due to a locked domain object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reason: typing.Union[java.lang.String, str]):
        ...


class Workspace(java.lang.Object):
    """
    Defines methods for accessing a workspace; a workspace is
    simply a group of running tools and their templates.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch an empty tool.
        
        :return: name of empty tool that is launched.
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def getName(self) -> str:
        """
        Get the workspace name
        
        :return: the name
        :rtype: str
        """

    def getTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        """
        Get the running tools in the workspace.
        
        :return: list of running tools or zero-length array if there are no tools in the workspace
        :rtype: jpype.JArray[ghidra.framework.plugintool.PluginTool]
        """

    def runTool(self, template: ToolTemplate) -> ghidra.framework.plugintool.PluginTool:
        """
        Run the tool specified by the tool template object.
        
        :param ToolTemplate template: the template
        :return: launched tool that is now running.
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def setActive(self):
        """
        Set this workspace to be the active workspace, i.e.,
        all tools become visible.
        The currently active workspace becomes inactive, and
        this workspace becomes active.
        """

    def setName(self, newName: typing.Union[java.lang.String, str]):
        """
        Rename this workspace.
        
        :param java.lang.String or str newName: new workspace name
        :raises DuplicateNameException: if newName is already the
        name of a workspace.
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def tools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        ...


class ProjectManager(java.lang.Object):
    """
    Interface for methods to create, open, and delete projects; maintains a
    list of known project views that the user opened. 
    It has a handle to the currently opened project. A project can be
    opened by one user at a time.
    """

    class_: typing.ClassVar[java.lang.Class]
    APPLICATION_TOOL_EXTENSION: typing.Final = ".tcd"
    APPLICATION_TOOLS_DIR_NAME: typing.Final = "tools"

    def createProject(self, projectLocator: ProjectLocator, repAdapter: ghidra.framework.client.RepositoryAdapter, remember: typing.Union[jpype.JBoolean, bool]) -> Project:
        """
        Create a project on the local filesystem.
        
        :param ProjectLocator projectLocator: location for where the project should be created
        :param ghidra.framework.client.RepositoryAdapter repAdapter: repository adapter if this project is to be a 
                shared project; may be null if the project is not shared.
        :param jpype.JBoolean or bool remember: if false the new project should not be remembered (i.e., recently opened, etc.)
        :return: the new project
        :rtype: Project
        :raises IOException: if user cannot access/write the project location
        """

    def deleteProject(self, projectLocator: ProjectLocator) -> bool:
        """
        Delete the project in the given location.
        
        :param ProjectLocator projectLocator: project location
        :return: false if no project was deleted.
        :rtype: bool
        """

    def forgetViewedProject(self, url: java.net.URL):
        """
        Remove the project url from the list of known viewed projects.
        
        :param java.net.URL url: project identifier
        """

    def getActiveProject(self) -> Project:
        """
        Get the project that is currently open.
        
        :return: currently open project, return null if there is no
        project opened
        :rtype: Project
        """

    def getLastOpenedProject(self) -> ProjectLocator:
        """
        Get the last opened (active) project.
        
        :return: project last opened by the user; returns NULL if a project
        was never opened OR the last opened project is no longer valid
        :rtype: ProjectLocator
        """

    def getMostRecentServerInfo(self) -> ServerInfo:
        """
        Get the information that was last used to access a repository
        managed by a Ghidra server.
        """

    def getRecentProjects(self) -> jpype.JArray[ProjectLocator]:
        """
        Get list of projects that user most recently opened.
        
        :return: list of project URLs
        :rtype: jpype.JArray[ProjectLocator]
        """

    def getRecentViewedProjects(self) -> jpype.JArray[java.net.URL]:
        """
        Get list of projects that user most recently viewed.
        
        :return: list of project URLs
        :rtype: jpype.JArray[java.net.URL]
        """

    def getRepositoryServerAdapter(self, host: typing.Union[java.lang.String, str], portNumber: typing.Union[jpype.JInt, int], forceConnect: typing.Union[jpype.JBoolean, bool]) -> ghidra.framework.client.RepositoryServerAdapter:
        """
        Establish a connection to the given host and port number.
        
        :param java.lang.String or str host: server name or IP address
        :param jpype.JInt or int portNumber: server port or 0 for default
        :param jpype.JBoolean or bool forceConnect: if true and currently not connected, an attempt will be made to connect
        :return: a handle to the remote server containing shared repositories
        :rtype: ghidra.framework.client.RepositoryServerAdapter
        """

    def getUserToolChest(self) -> ToolChest:
        """
        Return the user's ToolChest
        """

    def openProject(self, projectLocator: ProjectLocator, doRestore: typing.Union[jpype.JBoolean, bool], resetOwner: typing.Union[jpype.JBoolean, bool]) -> Project:
        """
        Open a project from the file system. Add the project url
        to the list of known projects.
        
        :param ProjectLocator projectLocator: project location
        :param jpype.JBoolean or bool doRestore: true if the project should be restored
        :param jpype.JBoolean or bool resetOwner: if true, the owner of the project will be changed to the current user.
        :return: opened project
        :rtype: Project
        :raises NotFoundException: if the file for the project was
        not found.
        :raises NotOwnerException: if the project owner is not the user
        :raises LockException: if the project is already opened by another user
        :raises IOException: if there was an IO-related error
        """

    def projectExists(self, projectLocator: ProjectLocator) -> bool:
        """
        Returns true if a project with the given projectLocator exists.
        
        :param ProjectLocator projectLocator: project location
        """

    def rememberProject(self, projectLocator: ProjectLocator):
        """
        Keep the projectLocator on the list of known projects.
        
        :param ProjectLocator projectLocator: project location
        """

    def rememberViewedProject(self, url: java.net.URL):
        """
        Keep the url on the list of known projects.
        
        :param java.net.URL url: project identifier
        """

    def setLastOpenedProject(self, projectLocator: ProjectLocator):
        """
        Set the projectLocator of last opened (active) project; this projectLocator is returned
        in the getLastOpenedProject() method.
        
        :param ProjectLocator projectLocator: project location of last project that was opened
        """

    @property
    def activeProject(self) -> Project:
        ...

    @property
    def recentProjects(self) -> jpype.JArray[ProjectLocator]:
        ...

    @property
    def recentViewedProjects(self) -> jpype.JArray[java.net.URL]:
        ...

    @property
    def lastOpenedProject(self) -> ProjectLocator:
        ...

    @lastOpenedProject.setter
    def lastOpenedProject(self, value: ProjectLocator):
        ...

    @property
    def mostRecentServerInfo(self) -> ServerInfo:
        ...

    @property
    def userToolChest(self) -> ToolChest:
        ...


class UserData(java.lang.Object):
    """
    ``UserData`` is a marker interface for
    DomainObjects used to store user-data associated with
    another DomainObject.
    """

    class_: typing.ClassVar[java.lang.Class]


class DomainObjectChangeRecord(java.io.Serializable):
    """
    Information about a change that was made to a domain object. The record is delivered as part of
    the change notification. The event types correspond to Enums defined in :obj:`DomainObjectEvent`
    and other Enums or objects that implement the :obj:`EventType` interface.
     
     
    
    Each event record contains the event type and optionally an old value and a new value. The old
    value and new value meaning are determined by the event type.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, eventType: EventType):
        """
        Construct a new DomainObjectChangeRecord.
        
        :param EventType eventType: the type of event
        """

    @typing.overload
    def __init__(self, eventType: EventType, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Construct a new DomainObjectChangeRecord.
        
        :param EventType eventType: the type of
        :param java.lang.Object oldValue: old value
        :param java.lang.Object newValue: new value
        """

    def getEventType(self) -> EventType:
        """
        Returns the event type for this change.
        
        :return: the event type for this change
        :rtype: EventType
        """

    def getNewValue(self) -> java.lang.Object:
        """
        Return the new value for this event or null if not applicable.
        
        :return: the old value or null if not applicable for this event.
        :rtype: java.lang.Object
        """

    def getOldValue(self) -> java.lang.Object:
        """
        Return the old value for this event or null if not applicable.
        
        :return: the old value or null if not applicable
        :rtype: java.lang.Object
        """

    @property
    def newValue(self) -> java.lang.Object:
        ...

    @property
    def oldValue(self) -> java.lang.Object:
        ...

    @property
    def eventType(self) -> EventType:
        ...


class LinkedDomainFolder(DomainFolder):
    """
    ``LinkedDomainFolder`` extends :obj:`DomainFolder` for all folders which are 
    accessable via a folder-link (see :obj:`FolderLinkContentHandler`).
    """

    class_: typing.ClassVar[java.lang.Class]

    def getIcon(self, isOpen: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Get the appropriate icon for this folder
        
        :param jpype.JBoolean or bool isOpen: true if open icon, false for closed
        :return: folder icon
        :rtype: javax.swing.Icon
        """

    def getLinkedFolder(self) -> DomainFolder:
        """
        Get the real domain folder which corresponds to this linked-folder.
        
        :return: domain folder
        :rtype: DomainFolder
        :raises IOException: if an IO error occurs
        """

    @property
    def linkedFolder(self) -> DomainFolder:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...


class AbstractDomainObjectListenerBuilder(java.lang.Object, typing.Generic[R, B]):
    """
    Base class for creating a compact and efficient :obj:`DomainObjectListener`s. See
    :obj:`DomainObjectListenerBuilder` for full documentation.
    """

    class AnyBuilder(java.lang.Object):
        """
        Sub-builder for collection eventTypes before eventually being association with a
        callback or callback with termination
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, eventTypes: jpype.JArray[EventType]):
            ...

        @typing.overload
        def call(self, callback: utility.function.Callback) -> B:
            """
            Provides the callback to be associated with this collection of event types.
            
            :param utility.function.Callback callback: the callback for this collection of event types
            :return: the main event builder that created this sub-builder
            :rtype: B
            """

        @typing.overload
        def call(self, consumer: java.util.function.Consumer[DomainObjectChangedEvent]) -> B:
            """
            Provides the callback to be associated with this collection of event types.
            
            :param java.util.function.Consumer[DomainObjectChangedEvent] consumer: the callback for this collection of event types
            :return: the main event builder that created this sub-builder
            :rtype: B
            """

        @typing.overload
        def terminate(self, callback: utility.function.Callback) -> B:
            """
            Provides the callback with termination to be associated with this collection of event
            types.
            
            :param utility.function.Callback callback: the callback for this collection of event types
            :return: the main event builder that created this sub-builder
            :rtype: B
            """

        @typing.overload
        def terminate(self, consumer: java.util.function.Consumer[DomainObjectChangedEvent]) -> B:
            """
            Provides the consumer with termination to be associated with this collection of event
            types. This form of terminate includes the event when performing the callback.
            
            :param java.util.function.Consumer[DomainObjectChangedEvent] consumer: the consumer for this collection of event types
            :return: the main event builder that created this sub-builder
            :rtype: B
            """


    class EachBuilder(java.lang.Object):
        """
        Sub-builder for collection eventTypes before eventually being associated with a
        consumer for records with those types
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, eventTypes: jpype.JArray[EventType]):
            ...

        @typing.overload
        def call(self, consumer: java.util.function.Consumer[R]) -> B:
            """
            Provides the consumer to be associated with this collection of event types.
            
            :param java.util.function.Consumer[R] consumer: the consumer for this collection of event types
            :return: the main event builder that created this sub-builder
            :rtype: B
            """

        @typing.overload
        def call(self, biConsumer: java.util.function.BiConsumer[DomainObjectChangedEvent, R]) -> B:
            """
            Provides the consumer to be associated with this collection of event types.
            
            :param java.util.function.BiConsumer[DomainObjectChangedEvent, R] biConsumer: the consumer for this collection of event types
            :return: the main event builder that created this sub-builder
            :rtype: B
            """


    @typing.type_check_only
    class EventTrigger(java.util.function.Consumer[DomainObjectChangedEvent]):

        class_: typing.ClassVar[java.lang.Class]

        def isTriggered(self, event: DomainObjectChangedEvent) -> bool:
            ...

        @property
        def triggered(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class TypedRecordConsumer(java.util.function.BiConsumer[DomainObjectChangedEvent, DomainObjectChangeRecord], typing.Generic[RR]):
        """
        Class for tracking the record classes and consumers for records of that type. Also
        contains inception information if the consumers and record classes don't match up.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BuilderDomainObjectListener(DomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def getName(self) -> str:
            ...

        @property
        def name(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], recordClass: java.lang.Class[R]):
        """
        Creates a builder with the given recordClass as the default record class
        
        :param java.lang.String or str name: the name of the client class that created this builder
        :param java.lang.Class[R] recordClass: the class of event records consumers will be using in any calls that
        take a consumer
        """

    def any(self, *eventTypes: EventType) -> AbstractDomainObjectListenerBuilder.AnyBuilder:
        """
        Allows for specifying multiple event types that if the event contains any records with
        and of the given types, then a callback or callback with terminate will be triggered, 
        depending on if the next builder operation is either a call or terminate respectively.
        
        :param jpype.JArray[EventType] eventTypes: the list of events to trigger on
        :return: A sub-builder for specifying the call or call with terminate
        :rtype: AbstractDomainObjectListenerBuilder.AnyBuilder
        """

    def build(self) -> DomainObjectListener:
        """
        Builds and returns a new DomainObjectEventHandler
        
        :return: a new DomainObjectEventHandler from this builder
        :rtype: DomainObjectListener
        """

    def each(self, *eventTypes: EventType) -> AbstractDomainObjectListenerBuilder.EachBuilder:
        """
        Allows for specifying multiple event types that for each record with one of the specified
        types, the follow on consumer will be called.
        
        :param jpype.JArray[EventType] eventTypes: the list of events to trigger on
        :return: A sub-builder for specifying the consumer to be used for records with any of
        these types
        :rtype: AbstractDomainObjectListenerBuilder.EachBuilder
        """

    def getName(self) -> str:
        """
        Returns the name that will be associated with the domainObjectListener. this is for
        debugging purposes so that you can tell where this listener came from (since it is
        no longer implemented by the client class)
        
        :return: the name assigned to this builder (and ultimately the listener)
        :rtype: str
        """

    def ignoreWhen(self, supplier: java.util.function.BooleanSupplier) -> B:
        """
        Sets a boolean supplier that can be checked to see if the client is in a state where
        they don't want events to be processed at this time.
        
        :param java.util.function.BooleanSupplier supplier: the boolean supplier that if returns true, events are not processed
        :return: this builder (for chaining)
        :rtype: B
        """

    def with_(self, clazz: java.lang.Class[R2]) -> B2:
        """
        Allows for specifying a new record type that any follow on consumers will use for any
        defined "each" handlers.
        
        :param R2: the new record type:param B2: the new builder type that expects consumers of the new record type:param java.lang.Class[R2] clazz: the class of the new record type
        :return: this builder with its consumer record type changed
        :rtype: B2
        """

    @property
    def name(self) -> java.lang.String:
        ...


class ToolSet(java.lang.Object):
    """
    Interface to define a set of Tools. NOTE: ToolSets are currently not
    implemented.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self) -> str:
        """
        Get the description of the toolset.
        """

    def getName(self) -> str:
        """
        Get the name for the toolset.
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Set the name on the toolset.
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class XmlDataReader(java.lang.Object):
    """
    Defines the method for creating an Object from an 
    XML file in a JarInputStream.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addXMLObject(self, tool: ghidra.framework.plugintool.PluginTool, basePath: typing.Union[java.lang.String, str], relPathName: typing.Union[java.lang.String, str], removeFile: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Reads the XML file indicated by the base path and relative path name.
        It creates an object(s) from this, that is used by the project.
        
        :param java.lang.String or str basePath: the prefix part of the path for the XML file
        :param java.lang.String or str relPathName: a pathname for the file relative to the basePath.
        :param jpype.JBoolean or bool removeFile: on success this should remove the original file.
        :param ghidra.util.task.TaskMonitor monitor: a monitor for providing progress information to the user.
        :return: true if an object associated with the file was added to the
        project. false if the file couldn't be processed.
        :rtype: bool
        :raises SAXException: if the XML file has a XML parsing error.
        :raises IOException: if there is problem reading/removing the XML file
        or if there is a problem creating any resulting file.
        :raises NotFoundException: if a required service can't be found in 
        the service registry.
        """

    def getSummary(self) -> str:
        """
        Returns a string summarizing the results of the XML data read
        or ``null`` if there was nothing to report.
        
        :return: a string summarizing the results of the xml data read
                or ``null`` if there was nothing to report
        :rtype: str
        """

    @property
    def summary(self) -> java.lang.String:
        ...


class Project(java.lang.AutoCloseable, java.lang.Iterable[DomainFile]):
    """
    Interface to define methods to manage data and tools for users working on a
    particular effort. Project represents the container object for users, data,
    and tools to work together.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addProjectView(self, projectURL: java.net.URL, visible: typing.Union[jpype.JBoolean, bool]) -> ProjectData:
        """
        Add the given project URL to this project's list project views.
        The project view allows users to look at data files from another
        project.
        
        :param java.net.URL projectURL: identifier for the project view (ghidra protocol only).
        :param jpype.JBoolean or bool visible: true if project may be made visible or false if hidden.  Hidden viewed
        projects are used when only life-cycle management is required (e.g., close view project 
        when this project is closed).
        :return: project data for this view
        :rtype: ProjectData
        :raises IOException: if I/O error occurs or if project/repository not found
        """

    def addProjectViewListener(self, listener: ProjectViewListener):
        """
        Add a listener to be notified when a visible project view is added or removed.
        
        :param ProjectViewListener listener: project view listener
        """

    def close(self):
        """
        Close the project.
        """

    def getLocalToolChest(self) -> ToolChest:
        """
        Return the local tool chest for the user logged in.
        """

    def getName(self) -> str:
        """
        Convenience method to get the name of this project.
        """

    def getOpenData(self) -> java.util.List[DomainFile]:
        """
        Get list of domain files that are open.
        
        :return: the files; empty if no files
        :rtype: java.util.List[DomainFile]
        """

    @typing.overload
    def getProjectData(self) -> ProjectData:
        """
        Get the root domain data folder in the project.
        """

    @typing.overload
    def getProjectData(self, projectLocator: ProjectLocator) -> ProjectData:
        """
        Returns the Project Data for the given Project locator.  The Project locator must
        be either the current active project or an currently open project view.
        """

    def getProjectLocator(self) -> ProjectLocator:
        """
        Get the project locator for this project.
        """

    def getProjectManager(self) -> ProjectManager:
        """
        Returns the project manager of this project.
        
        :return: the project manager of this project.
        :rtype: ProjectManager
        """

    def getProjectViews(self) -> jpype.JArray[ProjectLocator]:
        """
        Return the list of visible project views in this project.
        """

    def getRepository(self) -> ghidra.framework.client.RepositoryAdapter:
        """
        Get the repository that this project is associated with.
        
        :return: null if the project is not associated with a remote
        repository
        :rtype: ghidra.framework.client.RepositoryAdapter
        """

    def getSaveableData(self, key: typing.Union[java.lang.String, str]) -> ghidra.framework.options.SaveState:
        """
        The analog for :meth:`setSaveableData(String, SaveState) <.setSaveableData>`.
        """

    def getToolManager(self) -> ToolManager:
        """
        Return the tool manager for this project.
        """

    def getToolServices(self) -> ToolServices:
        """
        Return the tool services for this project.
        """

    def getToolTemplate(self, tag: typing.Union[java.lang.String, str]) -> ToolTemplate:
        """
        Get the tool template with the given tag.
        
        :param java.lang.String or str tag: ID or name for the tool template to get
        :return: tool template
        :rtype: ToolTemplate
        """

    def getViewedProjectData(self) -> jpype.JArray[ProjectData]:
        """
        Get the project data for visible viewed projects that are
        managed by this project.
        
        :return: zero length array if there are no visible viewed projects open
        :rtype: jpype.JArray[ProjectData]
        """

    def hasChanged(self) -> bool:
        """
        Return whether the project configuration has changed.
        """

    def isClosed(self) -> bool:
        """
        Returns whether this project instance has been closed
        """

    def releaseFiles(self, consumer: java.lang.Object):
        """
        Releases all DomainObjects used by the given consumer
        
        :param java.lang.Object consumer: object no longer using any DomainObjects.
        """

    def removeProjectView(self, projectURL: java.net.URL):
        """
        Remove the project view from this project.
        
        :param java.net.URL projectURL: identifier for the project
        """

    def removeProjectViewListener(self, listener: ProjectViewListener):
        """
        Remove a project view listener previously added.
        
        :param ProjectViewListener listener: project view listener
        """

    def restore(self):
        """
        Restore this project's state.
        """

    def save(self):
        """
        Save the project and the list of project views.
        """

    def saveSessionTools(self) -> bool:
        """
        Saves any tools that are associated with the opened project when the project is closed.
        
        :return: True if the save was not cancelled.
        :rtype: bool
        """

    def saveToolTemplate(self, tag: typing.Union[java.lang.String, str], template: ToolTemplate):
        """
        Save the given tool template as part of the project.
        
        :param java.lang.String or str tag: ID or name for the tool template
        :param ToolTemplate template: template to save
        """

    def setSaveableData(self, key: typing.Union[java.lang.String, str], saveState: ghidra.framework.options.SaveState):
        """
        Allows the user to store data related to the project.
        
        :param java.lang.String or str key: A value used to store and lookup saved data
        :param ghidra.framework.options.SaveState saveState: a container of data that will be written out when persisted
        """

    @property
    def projectManager(self) -> ProjectManager:
        ...

    @property
    def viewedProjectData(self) -> jpype.JArray[ProjectData]:
        ...

    @property
    def toolTemplate(self) -> ToolTemplate:
        ...

    @property
    def projectViews(self) -> jpype.JArray[ProjectLocator]:
        ...

    @property
    def projectLocator(self) -> ProjectLocator:
        ...

    @property
    def repository(self) -> ghidra.framework.client.RepositoryAdapter:
        ...

    @property
    def toolManager(self) -> ToolManager:
        ...

    @property
    def projectData(self) -> ProjectData:
        ...

    @property
    def openData(self) -> java.util.List[DomainFile]:
        ...

    @property
    def localToolChest(self) -> ToolChest:
        ...

    @property
    def toolServices(self) -> ToolServices:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def saveableData(self) -> ghidra.framework.options.SaveState:
        ...


class ProjectData(java.lang.Iterable[DomainFile]):
    """
    The ProjectData interface provides access to all the data files and folders
    in a project.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addDomainFolderChangeListener(self, listener: DomainFolderChangeListener):
        """
        Adds a listener that will be notified when any folder or file
        changes in the project.
        
        :param DomainFolderChangeListener listener: the listener to be notified of folder and file changes.
        """

    def close(self):
        """
        Initiate disposal of this project data object.  Any files already open will delay 
        disposal until they are closed.
        NOTE: This should only be invoked by the controlling object which created/opened this
        instance to avoid premature disposal.
        """

    def convertProjectToShared(self, repository: ghidra.framework.client.RepositoryAdapter, monitor: ghidra.util.task.TaskMonitor):
        """
        Convert a local project to a shared project. NOTE: The project should be closed and
        then reopened after this method is called.
        
        :param ghidra.framework.client.RepositoryAdapter repository: the repository that the project will be associated with.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: thrown if files under version control are still checked out, or
        if there was a problem accessing the filesystem
        :raises CancelledException: if the conversion was cancelled while versioned files were being
        converted to private files.
        """

    def findCheckedOutFiles(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[DomainFile]:
        """
        Find all project files which are currently checked-out to this project
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor (no progress updates)
        :return: list of current checkout files
        :rtype: java.util.List[DomainFile]
        :raises IOException: if IO error occurs
        :raises CancelledException: if task cancelled
        """

    def findOpenFiles(self, list: java.util.List[DomainFile]):
        """
        Finds all open domain files and appends
        them to the specified list.
        
        :param java.util.List[DomainFile] list: the list to receive the open domain files
        """

    def getFile(self, path: typing.Union[java.lang.String, str]) -> DomainFile:
        """
        Get domain file specified by an absolute data path.
        
        :param java.lang.String or str path: the absolute path of domain file relative to the root folder.
        :return: domain file or null if file not found
        :rtype: DomainFile
        """

    def getFileByID(self, fileID: typing.Union[java.lang.String, str]) -> DomainFile:
        """
        Get domain file specified by its unique fileID.
        
        :param java.lang.String or str fileID: domain file ID
        :return: domain file or null if file not found
        :rtype: DomainFile
        """

    def getFileCount(self) -> int:
        """
        Get the approximate number of files contained within the project.  The number 
        may be reduced if not connected to the shared repository.  Only the newer 
        indexed file-system supports this capability, a value of -1 will be
        returned for older projects utilizing the mangled file-system or if an
        IO Error occurs.
        An approximate number is provided since the two underlying file systems
        are consulted separately and the local private file-system does not
        distinguish between checked-out files and private files.  This number 
        is currently intended as a rough sizing number to disable certain features
        when very large projects are in use.  Generally the larger of the two
        file counts will be returned.
        
        :return: number of project files or -1 if unknown.
        :rtype: int
        """

    def getFolder(self, path: typing.Union[java.lang.String, str]) -> DomainFolder:
        """
        Get domain folder specified by an absolute data path.
        
        :param java.lang.String or str path: the absolute path of domain folder relative to the data folder.
        :return: domain folder or null if folder not found
        :rtype: DomainFolder
        """

    def getLocalProjectURL(self) -> java.net.URL:
        """
        Generate a local URL which corresponds to this project data if applicable.
        Remote transient project data will return null;
        
        :return: local URL which corresponds to this project data or null if not applicable.
        :rtype: java.net.URL
        """

    def getLocalStorageClass(self) -> java.lang.Class[ghidra.framework.store.local.LocalFileSystem]:
        """
        
        
        :return: local storage implementation class
        :rtype: java.lang.Class[ghidra.framework.store.local.LocalFileSystem]
        """

    def getMaxNameLength(self) -> int:
        """
        
        
        :return: the maximum name length permitted for folders or items.
        :rtype: int
        """

    def getProjectLocator(self) -> ProjectLocator:
        """
        Returns the projectLocator for the this ProjectData.
        
        :return: project locator object
        :rtype: ProjectLocator
        """

    def getRepository(self) -> ghidra.framework.client.RepositoryAdapter:
        """
        Return the repository for this project data.
        
        :return: null if the project is not associated with a repository
        :rtype: ghidra.framework.client.RepositoryAdapter
        """

    def getRootFolder(self) -> DomainFolder:
        """
        Returns the root folder of the project.
        
        :return: root :obj:`DomainFolder` within project.
        :rtype: DomainFolder
        """

    def getSharedProjectURL(self) -> java.net.URL:
        """
        Generate a repository URL which corresponds to this project data if applicable.
        Local private projects will return null;
        
        :return: repository URL which corresponds to this project data or null if not applicable.
        :rtype: java.net.URL
        """

    def getUser(self) -> ghidra.framework.remote.User:
        """
        Returns User object associated with remote repository or null if a remote repository
        is not used.
        
        :return: current remote user identity or null
        :rtype: ghidra.framework.remote.User
        """

    def hasInvalidCheckouts(self, checkoutList: java.util.List[DomainFile], newRepository: ghidra.framework.client.RepositoryAdapter, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Determine if any domain files listed do not correspond to a checkout in the specified 
        newRespository prior to invoking :meth:`updateRepositoryInfo(RepositoryAdapter, boolean, TaskMonitor) <.updateRepositoryInfo>`.
        
        :param java.util.List[DomainFile] checkoutList: project domain files to check
        :param ghidra.framework.client.RepositoryAdapter newRepository: repository to check against before updating
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if one or more files are not valid checkouts in newRepository
        :rtype: bool
        :raises IOException: if IO error occurs
        :raises CancelledException: if task cancelled
        """

    def makeValidName(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Transform the specified name into an acceptable folder or file item name.  Only an individual folder
        or file name should be specified, since any separators will be stripped-out.
        NOTE: Uniqueness of name within the intended target folder is not considered.
        
        :param java.lang.String or str name: 
        :return: valid name or "unknown" if no valid characters exist within name provided
        :rtype: str
        """

    def refresh(self, force: typing.Union[jpype.JBoolean, bool]):
        """
        Sync the Domain folder/file structure with the underlying file structure.
        
        :param jpype.JBoolean or bool force: if true all folders will be visited and refreshed, if false
        only those folders previously visited will be refreshed.
        """

    def removeDomainFolderChangeListener(self, listener: DomainFolderChangeListener):
        """
        Removes the listener to be notified of folder and file changes.
        
        :param DomainFolderChangeListener listener: the listener to be removed.
        """

    def testValidName(self, name: typing.Union[java.lang.String, str], isPath: typing.Union[jpype.JBoolean, bool]):
        """
        Validate a folder/item name or path.
        
        :param java.lang.String or str name: folder or item name
        :param jpype.JBoolean or bool isPath: if true name represents full path
        :raises InvalidNameException: if name is invalid
        """

    def updateRepositoryInfo(self, newRepository: ghidra.framework.client.RepositoryAdapter, force: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Update the repository for this project; the server may have changed or a different 
        repository is being used.  Any existing checkout which is not recognized/valid by 
        newRepository will be terminated and a local .keep file created.  
        NOTE: The project should be closed and then reopened after this method is called.
        
        :param ghidra.framework.client.RepositoryAdapter newRepository: new repository to use
        :param jpype.JBoolean or bool force: if true any existing local checkout which is not recognized/valid
            for newRepository will be forceably terminated if offline with old repository.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: thrown if files are still checked out, or if there was a problem accessing
        the filesystem
        :raises CancelledException: if the user canceled the update
        """

    @property
    def maxNameLength(self) -> jpype.JInt:
        ...

    @property
    def folder(self) -> DomainFolder:
        ...

    @property
    def file(self) -> DomainFile:
        ...

    @property
    def sharedProjectURL(self) -> java.net.URL:
        ...

    @property
    def localStorageClass(self) -> java.lang.Class[ghidra.framework.store.local.LocalFileSystem]:
        ...

    @property
    def rootFolder(self) -> DomainFolder:
        ...

    @property
    def localProjectURL(self) -> java.net.URL:
        ...

    @property
    def projectLocator(self) -> ProjectLocator:
        ...

    @property
    def repository(self) -> ghidra.framework.client.RepositoryAdapter:
        ...

    @property
    def user(self) -> ghidra.framework.remote.User:
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...

    @property
    def fileByID(self) -> DomainFile:
        ...


class ToolTemplate(java.lang.Object):
    """
    Configuration of a tool that knows how to create tools.
    """

    class_: typing.ClassVar[java.lang.Class]
    TOOL_XML_NAME: typing.Final = "TOOL"
    TOOL_NAME_XML_NAME: typing.Final = "TOOL_NAME"
    TOOL_INSTANCE_NAME_XML_NAME: typing.Final = "INSTANCE_NAME"

    def createTool(self, project: Project) -> ghidra.framework.plugintool.PluginTool:
        """
        Creates a tool like only this template knows how.
        
        :param Project project: the project in which the tool will be living.
        :return: a new tool for this template implementation.
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def getIcon(self) -> javax.swing.ImageIcon:
        """
        Get the icon for this tool template.  This is equivalent to calling
        ``getIconURL().getIcon()``
        
        :return: the icon for this tool template.
        :rtype: javax.swing.ImageIcon
        """

    def getIconURL(self) -> docking.util.image.ToolIconURL:
        """
        Get the iconURL for this tool template
        
        :return: the iconURL for this tool template
        :rtype: docking.util.image.ToolIconURL
        """

    def getName(self) -> str:
        """
        Get the name for the tool.
        
        :return: the name
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Returns the path from whence this tool template came; may be null if the tool was not 
        loaded from the filesystem
        
        :return: the path
        :rtype: str
        """

    def getSupportedDataTypes(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        """
        Get the classes of the data types that this tool supports,
        i.e., what data types can be dropped onto this tool.
        
        :return: list of supported data type classes.
        :rtype: jpype.JArray[java.lang.Class[typing.Any]]
        """

    def getToolElement(self) -> org.jdom.Element:
        """
        This returns the XML element that represents the tool part of the overall XML hierarchy.
        
        :return: the XML element that represents the tool part of the overall XML hierarchy.
        :rtype: org.jdom.Element
        """

    def restoreFromXml(self, root: org.jdom.Element):
        """
        Restore this object from a saved XML element.
        
        :param org.jdom.Element root: element to restore this object into
        """

    def saveToXml(self) -> org.jdom.Element:
        """
        Save this object to an XML Element.
        
        :return: the ToolConfig saved as an XML element
        :rtype: org.jdom.Element
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Set the name for the tool template.
        
        :param java.lang.String or str name: new tool template name
        """

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def icon(self) -> javax.swing.ImageIcon:
        ...

    @property
    def supportedDataTypes(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        ...

    @property
    def toolElement(self) -> org.jdom.Element:
        ...

    @property
    def iconURL(self) -> docking.util.image.ToolIconURL:
        ...


class DomainObjectEvent(java.lang.Enum[DomainObjectEvent], EventType):
    """
    Basic event types for all Domain Objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    SAVED: typing.Final[DomainObjectEvent]
    FILE_CHANGED: typing.Final[DomainObjectEvent]
    RENAMED: typing.Final[DomainObjectEvent]
    RESTORED: typing.Final[DomainObjectEvent]
    PROPERTY_CHANGED: typing.Final[DomainObjectEvent]
    CLOSED: typing.Final[DomainObjectEvent]
    ERROR: typing.Final[DomainObjectEvent]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DomainObjectEvent:
        ...

    @staticmethod
    def values() -> jpype.JArray[DomainObjectEvent]:
        ...


class ToolAssociationInfo(java.lang.Object):
    """
    A class that describes a content types and the tool used to open it.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, contentHandler: ghidra.framework.data.ContentHandler, associatedToolName: typing.Union[java.lang.String, str], currentToolTemplate: ToolTemplate, defaultTemplate: ToolTemplate):
        ...

    def getAssociatedToolName(self) -> str:
        ...

    def getContentHandler(self) -> ghidra.framework.data.ContentHandler:
        ...

    def getCurrentTemplate(self) -> ToolTemplate:
        """
        Returns the currently assigned tool used to open the content type of this association.
        """

    def getDefaultTemplate(self) -> ToolTemplate:
        ...

    def isDefault(self) -> bool:
        ...

    def restoreDefaultAssociation(self):
        ...

    def setCurrentTool(self, toolTemplate: ToolTemplate):
        """
        Sets the tool name that should be used to open files for the content type represented 
        by this tool association.
        """

    @property
    def default(self) -> jpype.JBoolean:
        ...

    @property
    def associatedToolName(self) -> java.lang.String:
        ...

    @property
    def defaultTemplate(self) -> ToolTemplate:
        ...

    @property
    def contentHandler(self) -> ghidra.framework.data.ContentHandler:
        ...

    @property
    def currentTemplate(self) -> ToolTemplate:
        ...


class DomainObjectClosedListener(java.lang.Object):
    """
    An interface that allows for a callback when a :obj:`DomainObject` is closed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def domainObjectClosed(self, dobj: DomainObject):
        """
        Callback indicating that the specified :obj:`DomainObject` has been closed.
        
        :param DomainObject dobj: domain object
        """


class WorkspaceChangeListener(java.beans.PropertyChangeListener):
    """
    Listener that is notified when a tool is added or removed from a 
    workspace, or when workspace properties change.
    """

    class_: typing.ClassVar[java.lang.Class]

    def toolAdded(self, ws: Workspace, tool: ghidra.framework.plugintool.PluginTool):
        """
        Notification that a tool was added to the given workspace.
        
        :param Workspace ws: workspace the affected workspace
        :param ghidra.framework.plugintool.PluginTool tool: tool that was added
        """

    def toolRemoved(self, ws: Workspace, tool: ghidra.framework.plugintool.PluginTool):
        """
        Notification that a tool was removed from the given workspace.
        
        :param Workspace ws: workspace the affected workspace
        :param ghidra.framework.plugintool.PluginTool tool: tool that was removed from the workspace
        """

    def workspaceAdded(self, ws: Workspace):
        """
        Notification that the given workspace was added by the ToolManager.
        
        :param Workspace ws: workspace the affected workspace
        """

    def workspaceRemoved(self, ws: Workspace):
        """
        Notification that the given workspace was removed by the ToolManager.
        
        :param Workspace ws: workspace the affected workspace
        """

    def workspaceSetActive(self, ws: Workspace):
        """
        Notification that the given workspace is the current one.
        
        :param Workspace ws: workspace the affected workspace
        """


class DomainObjectDisplayUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getShortPath(df: DomainFile) -> str:
        ...

    @staticmethod
    @typing.overload
    def getTabText(df: DomainFile) -> str:
        ...

    @staticmethod
    @typing.overload
    def getTabText(object: DomainObject) -> str:
        ...

    @staticmethod
    def getToolTip(object: DomainObject) -> str:
        ...


class DomainObjectEventIdGenerator(java.lang.Object):
    """
    Class for providing unique, compact ids for domain object event types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def next() -> int:
        ...


class EventQueueID(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProjectLocator(java.lang.Object):
    """
    Lightweight descriptor of a local Project storage location.
    """

    class_: typing.ClassVar[java.lang.Class]
    PROJECT_FILE_SUFFIX: typing.Final = ".gpr"
    PROJECT_DIR_SUFFIX: typing.Final = ".rep"
    DISALLOWED_CHARS: typing.ClassVar[java.util.Set[java.lang.Character]]
    """
    Set of characters specifically disallowed in project name or path.
    These characters may interfere with path and URL parsing.
    """


    def __init__(self, path: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Construct a project locator object.
        
        :param java.lang.String or str path: absolute path to parent directory (may or may not exist).  The user's temp directory
        will be used if this value is null or blank.  The use of "\" characters will always be replaced 
        with "/".
        WARNING: Use of a relative paths should be avoided (e.g., on a windows platform
        an absolute path should start with a drive letter specification such as C:\path).
        A path such as "/path" on windows will utilize the current default drive and will
        not throw an exception.  If a drive letter is specified it must specify an absolute
        path (e.g., C:\, C:\path).
        :param java.lang.String or str name: name of the project (may only contain alphanumeric characters or
        :raises IllegalArgumentException: if an absolute path is not specified or invalid project name
        """

    def exists(self) -> bool:
        """
        :return: true if project storage exists
        :rtype: bool
        """

    def getLocation(self) -> str:
        """
        Get the location of the project which will contain marker file
        (:meth:`getMarkerFile() <.getMarkerFile>`) and project directory (:meth:`getProjectDir() <.getProjectDir>`). 
         
        
        Note: directory may or may not exist.
        
        :return: project location directory
        :rtype: str
        """

    def getMarkerFile(self) -> java.io.File:
        """
        :return: the file that indicates a Ghidra project.
        :rtype: java.io.File
        """

    def getName(self) -> str:
        """
        :return: the name of the project identified by this project info.
        :rtype: str
        """

    def getProjectDir(self) -> java.io.File:
        """
        :return: the project directory
        :rtype: java.io.File
        """

    @staticmethod
    def getProjectDirExtension() -> str:
        """
        :return: the project directory file extension.
        :rtype: str
        """

    @staticmethod
    def getProjectExtension() -> str:
        """
        :return: the file extension suitable for creating file filters for the file chooser
        :rtype: str
        """

    def getProjectLockFile(self) -> java.io.File:
        """
        :return: project lock file to prevent multiple accesses to the same project at once.
        :rtype: java.io.File
        """

    def getURL(self) -> java.net.URL:
        """
        :return: the URL associated with this local project.  If using a temporary transient
        project location this URL should not be used.
        :rtype: java.net.URL
        """

    @staticmethod
    def isProjectDir(file: jpype.protocol.SupportsPath) -> bool:
        """
        :return: whether the given file is a project directory.
        :rtype: bool
        
        
        :param jpype.protocol.SupportsPath file: file to check
        """

    def isTransient(self) -> bool:
        """
        :return: true if this project URL corresponds to a transient project
        (e.g., corresponds to remote Ghidra URL)
        :rtype: bool
        """

    @property
    def projectDir(self) -> java.io.File:
        ...

    @property
    def markerFile(self) -> java.io.File:
        ...

    @property
    def transient(self) -> jpype.JBoolean:
        ...

    @property
    def projectLockFile(self) -> java.io.File:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def location(self) -> java.lang.String:
        ...

    @property
    def uRL(self) -> java.net.URL:
        ...


class ToolManager(java.lang.Object):
    """
    Interface to define methods to manage running tools and tools in
    the Tool Chest. The ToolManager also keeps track of the workspaces, and
    what tools are running in workspace, as well as the connections among tools
    across all workspaces.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_WORKSPACE_NAME: typing.Final = "Workspace"
    """
    The name to use for a new unnamed workspace; used by the Ghidra
    Project Window when the user creates a new workspace.
    """

    WORKSPACE_NAME_PROPERTY: typing.Final = "WorkspaceName"
    """
    Property used when sending the change event when a workspace name is
    changed.
    """


    def addWorkspaceChangeListener(self, listener: WorkspaceChangeListener):
        """
        Add the listener that will be notified when a tool is added
        or removed.
        
        :param WorkspaceChangeListener listener: workspace listener to add
        """

    def createWorkspace(self, name: typing.Union[java.lang.String, str]) -> Workspace:
        """
        Create a workspace with the given name.
        
        :param java.lang.String or str name: name of workspace
        :return: the workspace
        :rtype: Workspace
        :raises DuplicateNameException: if a workspace with this name already exists
        """

    def disconnectTool(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Removes all connections involving tool
        
        :param ghidra.framework.plugintool.PluginTool tool: tool for which to remove all connections
        """

    def getActiveWorkspace(self) -> Workspace:
        """
        Get the active workspace
        
        :return: the active workspace
        :rtype: Workspace
        """

    def getConnection(self, producer: ghidra.framework.plugintool.PluginTool, consumer: ghidra.framework.plugintool.PluginTool) -> ToolConnection:
        """
        Get the connection object for the producer and consumer tools
        
        :param ghidra.framework.plugintool.PluginTool producer: tool that is producing the tool event
        :param ghidra.framework.plugintool.PluginTool consumer: tool that is consuming the tool event
        :return: the connection
        :rtype: ToolConnection
        """

    def getConsumerTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        """
        Get a list of tools that consume at least one tool event.
        
        :return: zero-length array if no tool consumes any events
        :rtype: jpype.JArray[ghidra.framework.plugintool.PluginTool]
        """

    def getProducerTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        """
        Get a list of tools that produce at least one tool event.
        
        :return: zero-length array if no tool produces any events
        :rtype: jpype.JArray[ghidra.framework.plugintool.PluginTool]
        """

    def getRunningTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        """
        Get a list running tools across all workspaces.
        
        :return: zero-length array if there are no running tools.
        :rtype: jpype.JArray[ghidra.framework.plugintool.PluginTool]
        """

    def getWorkspaces(self) -> jpype.JArray[Workspace]:
        """
        Get list of known workspaces.
        
        :return: an array of known workspaces
        :rtype: jpype.JArray[Workspace]
        """

    def removeWorkspace(self, ws: Workspace):
        """
        Remove the workspace.
        
        :param Workspace ws: workspace to remove
        """

    def removeWorkspaceChangeListener(self, l: WorkspaceChangeListener):
        """
        Remove the workspace listener.
        
        :param WorkspaceChangeListener l: workspace listener to remove
        """

    def toolChanged(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        A configuration change was made to the tool; a plugin was added
        or removed.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool that changed
        """

    @property
    def consumerTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        ...

    @property
    def workspaces(self) -> jpype.JArray[Workspace]:
        ...

    @property
    def runningTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        ...

    @property
    def producerTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        ...

    @property
    def activeWorkspace(self) -> Workspace:
        ...


class LinkedDomainFile(DomainFile):
    """
    ``LinkedDomainFile`` corresponds to a :obj:`DomainFile` contained within a
    :obj:`LinkedDomainFolder`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLinkedFile(self) -> DomainFile:
        """
        Get the real domain file which corresponds to this file contained within a linked-folder.
        
        :return: domain file
        :rtype: DomainFile
        :raises IOException: if IO error occurs or file not found
        """

    @property
    def linkedFile(self) -> DomainFile:
        ...


class DomainFolderChangeListener(java.lang.Object):
    """
    Methods for notifications when changes are made to a domain folder or
    a domain file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def domainFileAdded(self, file: DomainFile):
        """
        Notification that a file is added to parent folder. You can
        get the parent from the file.
        
        :param DomainFile file: domain file which was just added.
        """

    def domainFileMoved(self, file: DomainFile, oldParent: DomainFolder, oldName: typing.Union[java.lang.String, str]):
        """
        Notification that the domain file was moved.
        
        :param DomainFile file: the file (after move)
        :param DomainFolder oldParent: original parent folder
        :param java.lang.String or str oldName: file name prior to move
        """

    def domainFileObjectClosed(self, file: DomainFile, object: DomainObject):
        """
        Notification that a domain file previously open for update is in the process of closing.
        
        :param DomainFile file: domain file
        :param DomainObject object: domain object which was open for update
        """

    def domainFileObjectOpenedForUpdate(self, file: DomainFile, object: DomainObject):
        """
        Notification that a domain file has been opened for update.
        
        :param DomainFile file: domain file
        :param DomainObject object: domain object open for update
        """

    def domainFileRemoved(self, parent: DomainFolder, name: typing.Union[java.lang.String, str], fileID: typing.Union[java.lang.String, str]):
        """
        Notification that a file was removed
        
        :param DomainFolder parent: domain folder which contained the file that was just removed.
        :param java.lang.String or str name: the name of the file that was removed.
        :param java.lang.String or str fileID: file ID or null
        """

    def domainFileRenamed(self, file: DomainFile, oldName: typing.Union[java.lang.String, str]):
        """
        Notification that the domain file was renamed.
        
        :param DomainFile file: file that was renamed
        :param java.lang.String or str oldName: old name of the file
        """

    def domainFileStatusChanged(self, file: DomainFile, fileIDset: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that the status for a domain file has changed.
        
        :param DomainFile file: file whose status has changed.
        :param jpype.JBoolean or bool fileIDset: if true indicates that the previously missing fileID has been
        established for the specified file.
        """

    def domainFolderAdded(self, folder: DomainFolder):
        """
        Notification that a folder is added to parent.
        
        :param DomainFolder folder: domain folder which was just added.
        """

    def domainFolderMoved(self, folder: DomainFolder, oldParent: DomainFolder):
        """
        Notification that the domain folder was moved.
        
        :param DomainFolder folder: the folder (after move)
        :param DomainFolder oldParent: original parent folder
        """

    def domainFolderRemoved(self, parent: DomainFolder, name: typing.Union[java.lang.String, str]):
        """
        Notification that a domain folder is removed.
        
        :param DomainFolder parent: domain folder which contained the folder that was just removed.
        :param java.lang.String or str name: the name of the folder that was removed.
        """

    def domainFolderRenamed(self, folder: DomainFolder, oldName: typing.Union[java.lang.String, str]):
        """
        Notify listeners when a domain folder is renamed.
        
        :param DomainFolder folder: folder that was renamed
        :param java.lang.String or str oldName: old name of folder
        """

    def domainFolderSetActive(self, folder: DomainFolder):
        """
        Notification that the setActive() method on the folder was called.
        
        :param DomainFolder folder: folder which was activated/visited
        """


class DomainObjectChangedEvent(java.util.EventObject, java.lang.Iterable[DomainObjectChangeRecord]):
    """
    An event indicating a DomainObject has changed.  This event is actually
    a list of DomainObjectChangeRecords.
      
    NOTE: This object is TRANSIENT - it is only valid during the life of calls
    to all the DomainObjectChangeListeners.  Listeners who need to retain
    any of this event information past the listener call should save the 
    DomainObjectChangeRecords, which will remain valid always.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, src: DomainObject, subEvents: java.util.List[DomainObjectChangeRecord]):
        """
        Constructor
        
        :param DomainObject src: the object which has changed
        :param java.util.List[DomainObjectChangeRecord] subEvents: a List of DomainObjectChangeRecords;
        """

    @typing.overload
    def contains(self, eventType: EventType) -> bool:
        """
        Returns true if this event contains a record with the given event type
        
        :param EventType eventType: the event type to check
        :return: the number of change records contained within this event.
        :rtype: bool
        """

    @typing.overload
    def contains(self, *types: EventType) -> bool:
        """
        Returns true if this event contains a record with any of the given event types.
        
        :param jpype.JArray[EventType] types: the event types to check for
        :return: true if this event contains a record with any of the given event types
        :rtype: bool
        """

    @deprecated("use contains(EventType) instead. This is here to help\n transition older code from using integer constants for even types to the new enum way\n that uses enums instead.")
    def containsEvent(self, eventType: EventType) -> bool:
        """
        Returns true if this event contains a record with the given event type.
        
        :param EventType eventType: the event type to check
        :return: the number of change records contained within this event.
        :rtype: bool
        
        .. deprecated::
        
        use :meth:`contains(EventType) <.contains>` instead. This is here to help
        transition older code from using integer constants for even types to the new enum way
        that uses enums instead.
        """

    def findFirst(self, eventType: EventType) -> DomainObjectChangeRecord:
        """
        Finds the first record with the given event type.
        
        :param EventType eventType: the event type to search for
        :return: the first record with the given event type
        :rtype: DomainObjectChangeRecord
        """

    def forEach(self, type: EventType, consumer: java.util.function.Consumer[DomainObjectChangeRecord]):
        """
        Loops over all records in this event and calls the consumer for each record that matches
        the given type.
        
        :param EventType type: the event type to apply the consumer
        :param java.util.function.Consumer[DomainObjectChangeRecord] consumer: the consumer to call for each record of the given type
        """

    def getChangeRecord(self, i: typing.Union[jpype.JInt, int]) -> DomainObjectChangeRecord:
        """
        Get the specified change record within this event.
        
        :param jpype.JInt or int i: change record number
        :return: change record
        :rtype: DomainObjectChangeRecord
        """

    def iterator(self) -> java.util.Iterator[DomainObjectChangeRecord]:
        """
        Returns iterator over all sub-events
        """

    def numRecords(self) -> int:
        """
        Return the number of change records contained within this event.
        
        :return: the number of change records contained within this event
        :rtype: int
        """

    @property
    def changeRecord(self) -> DomainObjectChangeRecord:
        ...


class ProjectListener(java.lang.Object):
    """
    Listener that is notified when a project is opened, closed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def projectClosed(self, project: Project):
        """
        Notification that the given project is closed.
        
        :param Project project: project that is closed
        """

    def projectOpened(self, project: Project):
        """
        Notification that the given project is open.
        
        :param Project project: project that is opened
        """


class DomainFileFilter(java.lang.Object):
    """
    Interface  to indicate whether a domain file should be included in a list or
    set of domain files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def accept(self, df: DomainFile) -> bool:
        """
        Tests whether or not the specified domain file should be
        included in a domain file list.
        
        :param DomainFile df: The domain file to be tested
        :return: ``true`` if and only if ``df``
        :rtype: bool
        """

    def followLinkedFolders(self) -> bool:
        """
        Determine if linked folders represented by a link-file should be followed.
        If this method is not implemented the default will return ``true``.
        
        :return: true if linked-folders should be followed or false to ignore.
        :rtype: bool
        """


class ProjectDataUtils(java.lang.Object):

    class DomainFileIterator(java.util.Iterator[DomainFile]):
        """
        A not-thread-safe :obj:`DomainFile` iterator that recursively walks a
        :obj:`project's data <ProjectData>` and returns each ``DomainFile`` that is
        found.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, project: Project):
            """
            Recursively traverse a :obj:`Project` starting in its root folder.
            
            :param Project project:
            """

        @typing.overload
        def __init__(self, startFolder: DomainFolder):
            """
            Recursively traverse the :obj:`DomainFile`s under a specific :obj:`DomainFolder`.
            
            :param DomainFolder startFolder:
            """


    class DomainFolderIterator(java.util.Iterator[DomainFolder]):
        """
        A not-thread-safe :obj:`DomainFolder` iterator that recursively walks a
        :obj:`project's data <ProjectData>` and returns each ``DomainFolder`` that is
        found.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, project: Project):
            """
            Recursively traverse a :obj:`Project` starting in its root folder.
            
            :param Project project:
            """

        @typing.overload
        def __init__(self, startFolder: DomainFolder):
            """
            Recursively traverse the :obj:`DomainFolder`s under a specific :obj:`DomainFolder`.
            
            :param DomainFolder startFolder:
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createDomainFolderPath(currentFolder: DomainFolder, path: typing.Union[java.lang.String, str]) -> DomainFolder:
        """
        Returns a Ghidra :obj:`DomainFolder` with the matching path, creating
        any missing parent folders as needed.
        
        :param DomainFolder currentFolder: starting :obj:`DomainFolder`.
        :param java.lang.String or str path: relative path to the desired DomainFolder, using forward slashes
        as separators.  Empty string ok, multiple slashes in a row treated as single slash,
        trailing slashes ignored.
        :return: :obj:`DomainFolder` that the path points to.
        :rtype: DomainFolder
        :raises InvalidNameException: if bad name
        :raises IOException: if problem when creating folder
        """

    @staticmethod
    def descendantFiles(folder: DomainFolder) -> java.lang.Iterable[DomainFile]:
        """
        Returns a :obj:`Iterable` sequence of all the :obj:`DomainFile`s that exist under
        the specified :obj:`folder <DomainFolder>`.
        
        :param DomainFolder folder: 
        :return: 
        :rtype: java.lang.Iterable[DomainFile]
        """

    @staticmethod
    def descendantFolders(folder: DomainFolder) -> java.lang.Iterable[DomainFolder]:
        """
        Returns a :obj:`Iterable` sequence of all the :obj:`DomainFolder`s that exist under
        the specified :obj:`folder <DomainFolder>`.
        
        :param DomainFolder folder: 
        :return: 
        :rtype: java.lang.Iterable[DomainFolder]
        """

    @staticmethod
    def getUniqueName(folder: DomainFolder, baseName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a unique name in a Ghidra :obj:`DomainFolder`.
        
        :param DomainFolder folder: :obj:`DomainFolder` to check for child name collisions.
        :param java.lang.String or str baseName: String base name of the file or folder
        :return: "baseName" if no collisions, or "baseNameNNN" (where NNN is an incrementing
        integer value) when collisions are found, or null if there are more than 1000 collisions.
        :rtype: str
        """

    @staticmethod
    def lookupDomainPath(currentFolder: DomainFolder, path: typing.Union[java.lang.String, str]) -> DomainFolder:
        """
        Returns a Ghidra :obj:`DomainFolder` with the matching path, or null if not found.
        
        :param DomainFolder currentFolder: starting :obj:`DomainFolder`.
        :param java.lang.String or str path: relative path to the desired DomainFolder, using forward slashes
        as separators.  Empty string ok, multiple slashes in a row treated as single slash,
        trailing slashes ignored.
        :return: :obj:`DomainFolder` that the path points to or null if not found.
        :rtype: DomainFolder
        """


class ChangeSet(java.lang.Object):
    """
    Generic marker to denote changes made to some object.
    """

    class_: typing.ClassVar[java.lang.Class]


class DomainFolder(java.lang.Comparable[DomainFolder]):
    """
    ``DomainFolder`` provides a storage interface for project folders.  A 
    ``DomainFolder`` is an immutable reference to a folder contained within a project.  The 
    state of a ``DomainFolder`` object does not track name/parent changes made to the 
    referenced project folder.
    """

    class_: typing.ClassVar[java.lang.Class]
    OPEN_FOLDER_ICON: typing.Final[javax.swing.Icon]
    CLOSED_FOLDER_ICON: typing.Final[javax.swing.Icon]
    SEPARATOR: typing.Final = "/"
    """
    Character used to separate folder and item names within a path string.
    """

    COPY_SUFFIX: typing.Final = ".copy"
    """
    Name extension to add when attempting to avoid a duplicate name.
    """


    def copyTo(self, newParent: DomainFolder, monitor: ghidra.util.task.TaskMonitor) -> DomainFolder:
        """
        Copy this folder into the newParent folder.
        
        :param DomainFolder newParent: new parent folder
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the new copied folder
        :rtype: DomainFolder
        :raises DuplicateFileException: if a folder or file by
        this name already exists in the newParent folder
        :raises IOException: thrown if an IO or access error occurs.
        :raises CancelledException: if task monitor cancelled operation.
        """

    def copyToAsLink(self, newParent: DomainFolder) -> DomainFile:
        """
        Create a new link-file in the specified newParent which will reference this folder 
        (i.e., linked-folder). Restrictions:
         
        * Specified newParent must reside within a different project since internal linking is
        not currently supported.
        
        If this folder is associated with a temporary transient project (i.e., not a locally 
        managed project) the generated link will refer to the remote folder with a remote
        Ghidra URL, otherwise a local project storage path will be used.
        
        :param DomainFolder newParent: new parent folder where link-file is to be created
        :return: newly created domain file (i.e., link-file) or null if link use not supported.
        :rtype: DomainFile
        :raises IOException: if an IO or access error occurs.
        """

    @typing.overload
    def createFile(self, name: typing.Union[java.lang.String, str], obj: DomainObject, monitor: ghidra.util.task.TaskMonitor) -> DomainFile:
        """
        Add a domain object to this folder.
        
        :param java.lang.String or str name: domain file name
        :param DomainObject obj: domain object to be stored
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :return: domain file created as a result of adding
        the domain object to this folder
        :rtype: DomainFile
        :raises DuplicateFileException: thrown if the file name already exists
        :raises InvalidNameException: if name is an empty string
        or if it contains characters other than alphanumerics.
        :raises IOException: if IO or access error occurs
        :raises CancelledException: if the user cancels the create.
        """

    @typing.overload
    def createFile(self, name: typing.Union[java.lang.String, str], packFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor) -> DomainFile:
        """
        Add a new domain file to this folder.
        
        :param java.lang.String or str name: domain file name
        :param jpype.protocol.SupportsPath packFile: packed file containing domain file data
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :return: domain file created as a result of adding
        the domain object to this folder
        :rtype: DomainFile
        :raises DuplicateFileException: thrown if the file name already exists
        :raises InvalidNameException: if name is an empty string
        or if it contains characters other than alphanumerics.
        :raises IOException: if IO or access error occurs
        :raises CancelledException: if the user cancels the create.
        """

    def createFolder(self, folderName: typing.Union[java.lang.String, str]) -> DomainFolder:
        """
        Create a subfolder within this folder.
        
        :param java.lang.String or str folderName: sub-folder name
        :return: the new folder
        :rtype: DomainFolder
        :raises DuplicateFileException: if a folder by this name already exists
        :raises InvalidNameException: if name is an empty string of if it contains characters other 
        than alphanumerics.
        :raises IOException: if IO or access error occurs
        """

    def delete(self):
        """
        Deletes this folder, if empty, from the local filesystem
        
        :raises IOException: if IO or access error occurs
        :raises FolderNotEmptyException: Thrown if this folder is not empty.
        """

    def getFile(self, name: typing.Union[java.lang.String, str]) -> DomainFile:
        """
        Get the domain file in this folder with the given name.
        
        :param java.lang.String or str name: name of file in this folder to retrieve
        :return: domain file or null if there is no domain file in this folder with the given name.
        :rtype: DomainFile
        """

    def getFiles(self) -> jpype.JArray[DomainFile]:
        """
        Get all domain files in this folder.
        This may return cached information and does not force a full refresh.
        
        :return: list of domain files
        :rtype: jpype.JArray[DomainFile]
        """

    def getFolder(self, name: typing.Union[java.lang.String, str]) -> DomainFolder:
        """
        Return the folder for the given name.
        
        :param java.lang.String or str name: of folder to retrieve
        :return: folder or null if there is no folder by the given name.
        :rtype: DomainFolder
        """

    def getFolders(self) -> jpype.JArray[DomainFolder]:
        """
        Get DomainFolders in this folder.
        This may return cached information and does not force a full refresh.
        
        :return: list of sub-folders
        :rtype: jpype.JArray[DomainFolder]
        """

    def getLocalProjectURL(self) -> java.net.URL:
        """
        Get a local Ghidra URL for this domain file if available within the associated non-transient
        local project.  A null value will be returned if project is transient.
        
        :return: local Ghidra URL for this folder or null if transient or not applicable
        :rtype: java.net.URL
        """

    def getName(self) -> str:
        """
        Return this folder's name.
        
        :return: the name
        :rtype: str
        """

    def getParent(self) -> DomainFolder:
        """
        Return parent folder or null if this DomainFolder is the root folder.
        
        :return: the parent
        :rtype: DomainFolder
        """

    def getPathname(self) -> str:
        """
        Returns the full path name to this folder
        
        :return: the path name
        :rtype: str
        """

    def getProjectData(self) -> ProjectData:
        """
        Returns the project data
        
        :return: the project data
        :rtype: ProjectData
        """

    def getProjectLocator(self) -> ProjectLocator:
        """
        Returns the local storage location for the project that this DomainFolder belongs to.
        
        :return: the locator
        :rtype: ProjectLocator
        """

    def getSharedProjectURL(self) -> java.net.URL:
        """
        Get a remote Ghidra URL for this domain folder if available within an associated shared
        project repository.  URL path will end with "/".  A null value will be returned if shared 
        folder does not exist and may also be returned if shared repository is not connected or a 
        connection error occurs.
        
        :return: remote Ghidra URL for this folder or null
        :rtype: java.net.URL
        """

    def isEmpty(self) -> bool:
        """
        Determine if this folder contains any sub-folders or domain files.
        
        :return: true if this folder is empty.
        :rtype: bool
        """

    def isInWritableProject(self) -> bool:
        """
        Returns true if this file is in a writable project.
        
        :return: true if writable
        :rtype: bool
        """

    def isLinked(self) -> bool:
        """
        Determine if this folder corresponds to a linked-folder.
        
        :return: true if folder corresponds to a linked-folder, else false.
        :rtype: bool
        """

    def moveTo(self, newParent: DomainFolder) -> DomainFolder:
        """
        Move this folder into the newParent folder.  If connected to a repository
        this moves both private and repository folders/files.  If not
        connected, only private folders/files are moved.
        
        :param DomainFolder newParent: new parent folder within the same project
        :return: the newly relocated folder (the original DomainFolder object becomes invalid since 
        it is immutable)
        :rtype: DomainFolder
        :raises DuplicateFileException: if a folder with the same name 
        already exists in newParent folder.
        :raises FileInUseException: if this folder or one of its descendants 
        contains a file which is in-use / checked-out.
        :raises IOException: thrown if an IO or access error occurs.
        """

    def setActive(self):
        """
        Allows the framework to react to a request to make this folder the "active" one.
        """

    def setName(self, newName: typing.Union[java.lang.String, str]) -> DomainFolder:
        """
        Set the name on this domain folder.
        
        :param java.lang.String or str newName: domain folder name
        :return: renamed domain file (the original DomainFolder object becomes invalid since it is 
        immutable)
        :rtype: DomainFolder
        :raises InvalidNameException: if newName contains illegal characters
        :raises DuplicateFileException: if a folder named newName 
        already exists in this files domain folder.
        :raises FileInUseException: if any file within this folder or its descendants is 
        in-use / checked-out.
        :raises IOException: thrown if an IO or access error occurs.
        """

    @property
    def parent(self) -> DomainFolder:
        ...

    @property
    def folders(self) -> jpype.JArray[DomainFolder]:
        ...

    @property
    def sharedProjectURL(self) -> java.net.URL:
        ...

    @property
    def projectLocator(self) -> ProjectLocator:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def pathname(self) -> java.lang.String:
        ...

    @property
    def projectData(self) -> ProjectData:
        ...

    @property
    def folder(self) -> DomainFolder:
        ...

    @property
    def file(self) -> DomainFile:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def localProjectURL(self) -> java.net.URL:
        ...

    @property
    def files(self) -> jpype.JArray[DomainFile]:
        ...

    @property
    def inWritableProject(self) -> jpype.JBoolean:
        ...

    @property
    def linked(self) -> jpype.JBoolean:
        ...


class ToolServices(java.lang.Object):
    """
    Services that the Tool uses.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_TOOLNAME: typing.Final = "DefaultTool"
    """
    The default tool name for Ghidra
    """


    def canAutoSave(self, tool: ghidra.framework.plugintool.PluginTool) -> bool:
        """
        Returns true if this tool should be saved base on the state of other running instances of
        the same tool
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool to check for saving
        :return: true if the tool should be saved
        :rtype: bool
        """

    def closeTool(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Notify the framework that the tool is closing.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool that is closing
        """

    def exportTool(self, tool: ToolTemplate) -> java.io.File:
        """
        Save the tool to the given location on the local file system.
        
        :param ToolTemplate tool: the tool template to write
        :return: the file to which the tool was saved
        :rtype: java.io.File
        :raises FileNotFoundException: thrown if the file's directory doesn't exist.
        :raises IOException: thrown if there is an error writing the file.
        """

    def getCompatibleTools(self, domainClass: java.lang.Class[DomainObject]) -> java.util.Set[ToolTemplate]:
        """
        Returns a set of tools that can open the given domain file class.
        
        :param java.lang.Class[DomainObject] domainClass: The domain file class type for which to get tools
        :return: the tools
        :rtype: java.util.Set[ToolTemplate]
        """

    def getContentTypeToolAssociations(self) -> java.util.Set[ToolAssociationInfo]:
        """
        Returns the :obj:`associations <ToolAssociationInfo>`, which describe content
        types and the tools used to open them, for all content types known to the system.
        
        :return: the associations
        :rtype: java.util.Set[ToolAssociationInfo]
        
        .. seealso::
        
            | :obj:`.setContentTypeToolAssociations(Set)`
        """

    @typing.overload
    def getDefaultToolTemplate(self, domainFile: DomainFile) -> ToolTemplate:
        """
        Returns the default/preferred tool template which should be used to open the specified
        domain file, whether defined by the user or the system default.
        
        :param DomainFile domainFile: The file whose preferred tool should be found.
        :return: The preferred tool that should be used to open the given file or null if none found.
        :rtype: ToolTemplate
        """

    @typing.overload
    def getDefaultToolTemplate(self, contentType: typing.Union[java.lang.String, str]) -> ToolTemplate:
        """
        Returns the default/preferred tool template which should be used to open the specified
        domain file content type, whether defined by the user or the system default.
        
        :param java.lang.String or str contentType: The content type whose preferred tool should be found.
        :return: The preferred tool that should be used to open the given file or null if none found.
        :rtype: ToolTemplate
        """

    def getRunningTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        """
        Return array of running tools
        
        :return: array of Tools
        :rtype: jpype.JArray[ghidra.framework.plugintool.PluginTool]
        """

    def getToolChest(self) -> ToolChest:
        """
        Get the tool chest for the project
        
        :return: the tool chest
        :rtype: ToolChest
        """

    def launchDefaultTool(self, domainFiles: collections.abc.Sequence) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch the default :obj:`tool <PluginTool>` and open the specified domainFiles.
        NOTE: running tool reuse is implementation dependent
        
        :param collections.abc.Sequence domainFiles: the files to open.  A null or empty list will results in an immediate 
        return of a null :obj:`PluginTool`.  Null entries are not permitted.
        :return: the launched tool.  Null returned if a suitable default tool
        for the file content type was not found or failed to launch.
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def launchDefaultToolWithURL(self, ghidraUrl: java.net.URL) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch the default tool and open the specified Ghidra URL resource.
        The tool chosen will be based upon the content type of the specified resource.
        NOTE: running tool re-use is implementation dependent
        
        :param java.net.URL ghidraUrl: resource to be opened (see :obj:`GhidraURL`)
        :return: the launched tool.  Null returned if a failure occurs while accessing the specified
        resource or a suitable default tool for the file content type was not found.
        :rtype: ghidra.framework.plugintool.PluginTool
        :raises IllegalArgumentException: if URL protocol is not supported.  Currently, only
        the ``ghidra`` protocol is supported.
        """

    def launchTool(self, toolName: typing.Union[java.lang.String, str], domainFiles: collections.abc.Sequence) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch the :obj:`tool <PluginTool>` with the given name and open the specified domainFiles.
        Only those domainFiles with a content type supported by the specified tool will be opened.
        NOTE: running tool reuse is implementation dependent.
        
        :param java.lang.String or str toolName: name of the :obj:`tool template <ToolTemplate>` to launch or re-use
        :param collections.abc.Sequence domainFiles: the files to open; may be null or empty.  Null entries are not permitted.
        :return: the resulting :obj:`tool <PluginTool>` or null if the specified tool was not found
        or failed to launch
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def launchToolWithURL(self, toolName: typing.Union[java.lang.String, str], ghidraUrl: java.net.URL) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch the tool with the given name and attempt to open the specified Ghidra URL resource.
        
        :param java.lang.String or str toolName: name of the tool to launch
        :param java.net.URL ghidraUrl: resource to be opened (see :obj:`GhidraURL`)
        :return: the requested tool or null if the specified tool not found.
        :rtype: ghidra.framework.plugintool.PluginTool
        :raises IllegalArgumentException: if URL protocol is not supported.  Currently, only
        the ``ghidra`` protocol is supported.
        """

    def saveTool(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Saves the tool's configuration in the standard
        tool location.
        
        :param ghidra.framework.plugintool.PluginTool tool: tool to save.
        """

    def setContentTypeToolAssociations(self, infos: java.util.Set[ToolAssociationInfo]):
        """
        Sets the  :obj:`associations <ToolAssociationInfo>`, which describe content
        types and the tools used to open them, for the system.
        
        :param java.util.Set[ToolAssociationInfo] infos: The associations to be applied
        
        .. seealso::
        
            | :obj:`.getContentTypeToolAssociations()`
        """

    @property
    def defaultToolTemplate(self) -> ToolTemplate:
        ...

    @property
    def contentTypeToolAssociations(self) -> java.util.Set[ToolAssociationInfo]:
        ...

    @contentTypeToolAssociations.setter
    def contentTypeToolAssociations(self, value: java.util.Set[ToolAssociationInfo]):
        ...

    @property
    def runningTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        ...

    @property
    def toolChest(self) -> ToolChest:
        ...

    @property
    def compatibleTools(self) -> java.util.Set[ToolTemplate]:
        ...


class ToolConnection(java.lang.Object):
    """
    Represents a connection between a producer tool and a
    consumer tool.
    """

    class_: typing.ClassVar[java.lang.Class]

    def connect(self, eventName: typing.Union[java.lang.String, str]):
        """
        Connect the tools for the given event name.
        
        :param java.lang.String or str eventName: name of event to connect
        :raises IllegalArgumentException: if eventName is not valid for this
        producer/consumer pair.
        """

    def disconnect(self, eventName: typing.Union[java.lang.String, str]):
        """
        Break the connection between the tools for the
        given event name.
        
        :param java.lang.String or str eventName: name of event to disconnect
        :raises IllegalArgumentException: if eventName is not valid for this
        producer/consumer pair.
        """

    def getConsumer(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Get the tool that consumes an event
        
        :return: the tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def getEvents(self) -> jpype.JArray[java.lang.String]:
        """
        Get the list of event names that is an intersection
        between what the producer produces and what the
        consumers consumes.
        
        :return: an array of event names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getProducer(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Get the tool that produces an event
        
        :return: the tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def isConnected(self, eventName: typing.Union[java.lang.String, str]) -> bool:
        """
        Return whether the tools are connected for the
        given event name.
        
        :param java.lang.String or str eventName: name of event to check
        :return: true if the tools are connected by eventName.
        :rtype: bool
        """

    @property
    def connected(self) -> jpype.JBoolean:
        ...

    @property
    def producer(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    @property
    def events(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def consumer(self) -> ghidra.framework.plugintool.PluginTool:
        ...


class ServerInfo(java.io.Serializable):
    """
    Container for a host name and port number.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, host: typing.Union[java.lang.String, str], portNumber: typing.Union[jpype.JInt, int]):
        """
        Construct a new ServerInfo object
        
        :param java.lang.String or str host: host name
        :param jpype.JInt or int portNumber: port number
        """

    def getPortNumber(self) -> int:
        """
        Get the port number.
        
        :return: port number
        :rtype: int
        """

    def getServerName(self) -> str:
        """
        Get the server hostname or IP address as originally specified.
        
        :return: hostname or IP address as originally specified
        :rtype: str
        """

    @property
    def serverName(self) -> java.lang.String:
        ...

    @property
    def portNumber(self) -> jpype.JInt:
        ...



__all__ = ["ToolChestChangeListener", "DomainObjectListener", "RuntimeIOException", "DomainFolderListenerAdapter", "DomainObjectException", "ToolListener", "ProjectViewListener", "ToolChest", "DomainObjectListenerBuilder", "AbortedTransactionListener", "EventType", "TransactionInfo", "TransactionListener", "DomainObject", "DefaultLaunchMode", "DomainFile", "DomainObjectLockedException", "Workspace", "ProjectManager", "UserData", "DomainObjectChangeRecord", "LinkedDomainFolder", "AbstractDomainObjectListenerBuilder", "ToolSet", "XmlDataReader", "Project", "ProjectData", "ToolTemplate", "DomainObjectEvent", "ToolAssociationInfo", "DomainObjectClosedListener", "WorkspaceChangeListener", "DomainObjectDisplayUtils", "DomainObjectEventIdGenerator", "EventQueueID", "ProjectLocator", "ToolManager", "LinkedDomainFile", "DomainFolderChangeListener", "DomainObjectChangedEvent", "ProjectListener", "DomainFileFilter", "ProjectDataUtils", "ChangeSet", "DomainFolder", "ToolServices", "ToolConnection", "ServerInfo"]
