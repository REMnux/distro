from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.target.iface
import ghidra.trace.model.target.path
import ghidra.trace.model.target.schema
import java.lang # type: ignore
import java.util # type: ignore
import java.util.stream # type: ignore


I = typing.TypeVar("I")
T = typing.TypeVar("T")


class DuplicateKeyException(java.lang.RuntimeException):
    """
    Thrown when there are "duplicate keys" and the :obj:`ConflictResolution.DENY` strategy is passed
     
     
    
    There are said to be "duplicate keys" when two value entries having the same parent and key have
    overlapping lifespans. Such would create the possibility of a non-uniquely-defined value for a
    given path, and so it is not allowed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, key: typing.Union[java.lang.String, str]):
        """
        Notify of a given conflicting key
        
        :param java.lang.String or str key: the key in conflict
        """


class TraceObjectManager(java.lang.Object):
    """
    A store of objects observed over time in a trace
    """

    class_: typing.ClassVar[java.lang.Class]

    def clear(self):
        """
        Delete the *entire object model*, including the schema
         
         
        
        This is the only mechanism to modify the schema. This should almost never be necessary,
        because a connector should provide its immutable schema immediately. Nevertheless, the
        database permits schema modification, but requires that the entire model be replaced.
        """

    def createObject(self, path: ghidra.trace.model.target.path.KeyPath) -> TraceObject:
        """
        Create (or get) an object with the given canonical path
        
        :param ghidra.trace.model.target.path.KeyPath path: the object's canonical path
        :return: the new object
        :rtype: TraceObject
        """

    def createRootObject(self, schema: ghidra.trace.model.target.schema.TraceObjectSchema) -> TraceObjectValue:
        """
        Creates the root object of the model, fixing its schema
         
         
        
        Note the schema cannot be changed once the root object is created. The only means to "change"
        the schema is to delete the root object (and thus the entire tree) then re-create the root
        object with the new schema.
        
        :param ghidra.trace.model.target.schema.TraceObjectSchema schema: the schema
        :return: the new object
        :rtype: TraceObjectValue
        """

    def cullDisconnectedObjects(self):
        """
        For maintenance, remove all disconnected objects
         
         
        
        An object is disconnected if it is neither the child nor parent of any value for any span. In
        other words, it's unused.
        """

    def getAllObjects(self) -> java.util.stream.Stream[TraceObject]:
        """
        Get all the objects in the database
        
        :return: the stream of all objects
        :rtype: java.util.stream.Stream[TraceObject]
        """

    def getAllValues(self) -> java.util.stream.Stream[TraceObjectValue]:
        """
        Get all the values (edges) in the database
        
        :return: the stream of all values
        :rtype: java.util.stream.Stream[TraceObjectValue]
        """

    def getObjectByCanonicalPath(self, path: ghidra.trace.model.target.path.KeyPath) -> TraceObject:
        """
        Get objects in the database having the given canonical path
        
        :param ghidra.trace.model.target.path.KeyPath path: the canonical path of the desired objects
        :return: the collection of objects
        :rtype: TraceObject
        """

    def getObjectById(self, key: typing.Union[jpype.JLong, int]) -> TraceObject:
        """
        Get the object with the given database key, if it exists
        
        :param jpype.JLong or int key: the desired object's key
        :return: the object, or null
        :rtype: TraceObject
        """

    def getObjectCount(self) -> int:
        """
        Get the number of objects in the database
        
        :return: the number of objects
        :rtype: int
        """

    def getObjectsByPath(self, span: ghidra.trace.model.Lifespan, path: ghidra.trace.model.target.path.KeyPath) -> java.util.stream.Stream[TraceObject]:
        """
        Get objects in the database having the given path intersecting the given span
        
        :param ghidra.trace.model.target.path.KeyPath path: the path of the desired objects
        :param ghidra.trace.model.Lifespan span: the span that desired objects' lifespans must intersect
        :return: the iterable of objects
        :rtype: java.util.stream.Stream[TraceObject]
        """

    def getRootObject(self) -> TraceObject:
        """
        Get the root object, if it has been created
        
        :return: the root object, or null
        :rtype: TraceObject
        """

    def getRootSchema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        """
        Get the schema of the root object
        
        :return: the schema or null
        :rtype: ghidra.trace.model.target.schema.TraceObjectSchema
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace to which the object manager belongs
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def getValuePaths(self, span: ghidra.trace.model.Lifespan, predicates: ghidra.trace.model.target.path.PathFilter) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Get value entries in the database matching the given predicates intersecting the given span
         
         
        
        While the manager does not maintain integrity wrt. child lifespans and that of their parents,
        nor even the connectivity of objects to their canonical parents, this search depends on that
        consistency. An object may not be discovered unless it is properly connected to the root
        object. Furthermore, it will not be discovered unless it and its ancestors' lifespans all
        intersect the given span.
        
        :param ghidra.trace.model.Lifespan span: the span that desired objects' lifespans must intersect
        :param ghidra.trace.model.target.path.PathFilter predicates: predicates to match the desired objects
        :return: an iterator over the matching objects
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    @typing.overload
    def getValuesIntersecting(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, entryKey: typing.Union[java.lang.String, str]) -> java.util.Collection[TraceObjectValue]:
        """
        Get all address-ranged values intersecting the given span and address range
        
        :param ghidra.trace.model.Lifespan span: the span that desired values lifespans must intersect
        :param ghidra.program.model.address.AddressRange range: the range that desired address-ranged values must intersect
        :param java.lang.String or str entryKey: the entry key if a single one should be matched, or null for any
        :return: the collection of values
        :rtype: java.util.Collection[TraceObjectValue]
        """

    @typing.overload
    def getValuesIntersecting(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.util.Collection[TraceObjectValue]:
        """
        Get all address-ranged values intersecting the given span and address range
        
        :param ghidra.trace.model.Lifespan span: the span that desired values lifespans must intersect
        :param ghidra.program.model.address.AddressRange range: the range that desired address-ranged values must intersect
        :return: the collection of values
        :rtype: java.util.Collection[TraceObjectValue]
        """

    def queryAllInterface(self, span: ghidra.trace.model.Lifespan, iface: java.lang.Class[I]) -> java.util.stream.Stream[I]:
        """
        Get all interfaces of the given type in the database
        
        :param I: the type of the desired interface:param ghidra.trace.model.Lifespan span: the span that desired objects must intersect
        :param java.lang.Class[I] iface: the class of the desired interface
        :return: the collection of all instances of the given interface
        :rtype: java.util.stream.Stream[I]
        """

    def requireRootSchema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        """
        Get the schema of the root object, failing if no root object exists
        
        :return: the schema
        :rtype: ghidra.trace.model.target.schema.TraceObjectSchema
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def objectCount(self) -> jpype.JInt:
        ...

    @property
    def objectByCanonicalPath(self) -> TraceObject:
        ...

    @property
    def rootSchema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    @property
    def rootObject(self) -> TraceObject:
        ...

    @property
    def allValues(self) -> java.util.stream.Stream[TraceObjectValue]:
        ...

    @property
    def allObjects(self) -> java.util.stream.Stream[TraceObject]:
        ...

    @property
    def objectById(self) -> TraceObject:
        ...


class TraceObjectValPath(java.lang.Comparable[TraceObjectValPath]):
    """
    A path of values leading from one object to another
     
     
    
    Often, the source object is the root. These are often returned in streams where the search
    involves a desired "span." The path satisfies that requirement, i.e., "the path intersects the
    span" if the cumulative intersection of all values' lifespans along the path and the given span
    is non-empty. Paths may also be empty, implying the source is the destination. Empty paths
    "intersect" any given span.
    """

    class_: typing.ClassVar[java.lang.Class]

    def append(self, entry: TraceObjectValue) -> TraceObjectValPath:
        """
        Append the entry to this path, generating a new path
         
         
        
        This performs no validation. The parent of the given entry should be the child of the last
        entry in this path.
        
        :param TraceObjectValue entry: the entry to append
        :return: the new path
        :rtype: TraceObjectValPath
        """

    def contains(self, entry: TraceObjectValue) -> bool:
        """
        Check if a given value appears on this path
        
        :param TraceObjectValue entry: the value entry to check
        :return: true if it appears on the path, false otherwise
        :rtype: bool
        """

    def getDestination(self, ifEmpty: TraceObject) -> TraceObject:
        """
        Get the destination object
         
         
        
        This returns the child object of the last entry of the path, unless the path is empty. If the
        path is empty, then this returns the object passed in ``ifEmpty``, which is presumably
        the source object. Note that values may be primitive, so the destination is not always an
        object, i.e., :obj:`TraceObject`. Use :meth:`getDestinationValue(Object) <.getDestinationValue>` when it is not
        safe to assume the destination is an object.
        
        :param TraceObject ifEmpty: the object to return when the path is empty
        :return: the destination object
        :rtype: TraceObject
        :raises ClassCastException: if the destination value is not an object
        """

    def getDestinationValue(self, ifEmpty: java.lang.Object) -> java.lang.Object:
        """
        Get the destination value
         
         
        
        This returns the value of the last entry of the path, unless the path is empty. If the path
        is empty, then this returns the object passed in ``ifEmpty``, which is presumably the
        source object. Note that values may be a primitive, so the destination is not always an
        object, i.e., :obj:`TraceObject`. Use :meth:`getDestination(TraceObject) <.getDestination>` to assume the
        destination is an object.
        
        :param java.lang.Object ifEmpty: the value to return when the path is empty
        :return: the destination value
        :rtype: java.lang.Object
        """

    def getEntryList(self) -> java.util.List[TraceObjectValue]:
        """
        Get the values in the path, ordered from source to destination
        
        :return: the list of value entries
        :rtype: java.util.List[TraceObjectValue]
        """

    def getFirstEntry(self) -> TraceObjectValue:
        """
        Get the first entry, i.e., the one adjacent to the source object
        
        :return: the entry, or null if the path is empty
        :rtype: TraceObjectValue
        """

    def getLastEntry(self) -> TraceObjectValue:
        """
        Get the last entry, i.e., the one adjacent to the destination object
        
        :return: the entry, or null if the path is empty
        :rtype: TraceObjectValue
        """

    def getPath(self) -> ghidra.trace.model.target.path.KeyPath:
        """
        Get the keys in the path, ordered from source to destination
         
         
        
        The returned list is suited for testing with :obj:`PathFilter` or other path-manipulation
        methods.
        
        :return: the list of keys
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def getSource(self, ifEmpty: TraceObject) -> TraceObject:
        """
        Get the source object
         
         
        
        This returns the parent object of the first entry of the path, unless the path is empty. If
        the path is empty, then this returns the value passed in ``ifEmpty``, which is presumably
        the destination object.
        
        :param TraceObject ifEmpty: the object to return when this path is empty
        :return: the source object
        :rtype: TraceObject
        """

    @staticmethod
    def of() -> TraceObjectValPath:
        """
        Get the zero-length path
        
        :return: the empty path
        :rtype: TraceObjectValPath
        """

    def prepend(self, entry: TraceObjectValue) -> TraceObjectValPath:
        """
        Prepend the entry to this path, generating a new path
         
         
        
        This performs no validation. The child of the given entry should be the parent of the first
        entry in this path.
        
        :param TraceObjectValue entry: the entry to prepend
        :return: the new path
        :rtype: TraceObjectValPath
        """

    @property
    def path(self) -> ghidra.trace.model.target.path.KeyPath:
        ...

    @property
    def destinationValue(self) -> java.lang.Object:
        ...

    @property
    def lastEntry(self) -> TraceObjectValue:
        ...

    @property
    def destination(self) -> TraceObject:
        ...

    @property
    def entryList(self) -> java.util.List[TraceObjectValue]:
        ...

    @property
    def source(self) -> TraceObject:
        ...

    @property
    def firstEntry(self) -> TraceObjectValue:
        ...


class TraceObjectValue(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def castValue(self) -> T:
        """
        A convenience to get and cast the value, without checking
        
        :param T: the desired type:return: the value
        :rtype: T
        """

    def delete(self):
        """
        Delete this entry
        """

    def getCanonicalPath(self) -> ghidra.trace.model.target.path.KeyPath:
        """
        Get the "canonical path" of this value
         
         
        
        This is the parent's canonical path extended by this value's entry key. Note, in the case
        this value has a child object, this is not necessarily its canonical path.
        
        :return: the canonical path
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def getChild(self) -> TraceObject:
        """
        Get the value as an object
        
        :return: the child
        :rtype: TraceObject
        :raises ClassCastException: if the value is not an object
        """

    def getEntryKey(self) -> str:
        """
        Get the key identifying this child to its parent
        
        :return: the key
        :rtype: str
        """

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        """
        Get the lifespan of this entry
        
        :return: the lifespan
        :rtype: ghidra.trace.model.Lifespan
        """

    def getMaxSnap(self) -> int:
        """
        Get the maximum snap of this entry
        
        :return: the maximum snap, or :obj:`Long.MAX_VALUE` for "to the end of time"
        :rtype: int
        """

    def getMinSnap(self) -> int:
        """
        Get the minimum snap of this entry
        
        :return: the minimum snap, or :obj:`Long.MIN_VALUE` for "since the beginning of time"
        :rtype: int
        """

    def getParent(self) -> TraceObject:
        """
        Get the parent object of this entry
        
        :return: the parent
        :rtype: TraceObject
        """

    def getTargetSchema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        """
        Get the (target) schema for the value
        
        :return: the schema
        :rtype: ghidra.trace.model.target.schema.TraceObjectSchema
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this value entry
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def getValue(self) -> java.lang.Object:
        """
        Get the value
        
        :return: the value
        :rtype: java.lang.Object
        """

    def hasEntryKey(self, keyOrAlias: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if the given key (or alias) matches this entry's key
        
        :param java.lang.String or str keyOrAlias: the key or alias
        :return: true if the key matches this entry's key, or it is an alias for it
        :rtype: bool
        """

    def isCanonical(self) -> bool:
        """
        Check if this value represents its child's canonical location
         
         
        
        The value is canonical if the parent's canonical path extended by this value's key gives the
        child's canonical path. If the value is not a child object, the value cannot be canonical.
        
        :return: true if canonical
        :rtype: bool
        """

    def isDeleted(self) -> bool:
        """
        Check if this value entry has been deleted
        
        :return: true if the entry has been deleted
        :rtype: bool
        """

    def isHidden(self) -> bool:
        """
        Check if the schema designates this value as hidden
        
        :return: true if hidden
        :rtype: bool
        """

    def isObject(self) -> bool:
        """
        Check if the value is an object (i.e., :obj:`TraceObject`)
        
        :return: true if an object, false otherwise
        :rtype: bool
        """

    @typing.overload
    def setLifespan(self, lifespan: ghidra.trace.model.Lifespan):
        """
        Set the lifespan of this entry, truncating duplicates
        
        :param ghidra.trace.model.Lifespan lifespan: the new lifespan
        """

    @typing.overload
    def setLifespan(self, span: ghidra.trace.model.Lifespan, resolution: TraceObject.ConflictResolution):
        """
        Set the lifespan of this entry
         
         
        
        **NOTE:** For storage efficiency, when expanding the lifespan, the manager may coalesce
        this value with intersecting values having equal keys and values. Thus, the resulting
        lifespan may be larger than specified.
         
         
        
        Values cannot intersect and have the same key, otherwise the value of that key could not be
        uniquely determined at a given snap. Thus, when lifespans are being adjusted, such conflicts
        must be resolved.
        
        :param ghidra.trace.model.Lifespan span: the new lifespan
        :param TraceObject.ConflictResolution resolution: specifies how to resolve duplicate keys with intersecting lifespans
        :raises DuplicateKeyException: if there are denied duplicate keys
        """

    def setMaxSnap(self, maxSnap: typing.Union[jpype.JLong, int]):
        """
        Set the maximum snap of this entry
        
        :param jpype.JLong or int maxSnap: the maximum snap, or :obj:`Long.MAX_VALUE` for "to the end of time"
        
        .. seealso::
        
            | :obj:`.setLifespan(Lifespan)`
        """

    def setMinSnap(self, minSnap: typing.Union[jpype.JLong, int]):
        """
        Set the minimum snap of this entry
        
        :param jpype.JLong or int minSnap: the minimum snap, or :obj:`Long.MIN_VALUE` for "since the beginning of time"
        
        .. seealso::
        
            | :obj:`.setLifespan(Lifespan)`
        """

    def truncateOrDelete(self, span: ghidra.trace.model.Lifespan) -> TraceObjectValue:
        """
        Modify the lifespan or delete this entry, such that it no longer intersects the given span.
         
         
        
        If the given span and the current lifespan are already disjoint, this does nothing. If the
        given span splits the current lifespan in two, then a new entry is created for the later
        lifespan.
        
        :param ghidra.trace.model.Lifespan span: the span to clear
        :return: this if the one entry remains, null if the entry is deleted, or the generated entry
                if a second is created.
        :rtype: TraceObjectValue
        """

    @property
    def targetSchema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    @property
    def parent(self) -> TraceObject:
        ...

    @property
    def maxSnap(self) -> jpype.JLong:
        ...

    @maxSnap.setter
    def maxSnap(self, value: jpype.JLong):
        ...

    @property
    def hidden(self) -> jpype.JBoolean:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @lifespan.setter
    def lifespan(self, value: ghidra.trace.model.Lifespan):
        ...

    @property
    def canonical(self) -> jpype.JBoolean:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def minSnap(self) -> jpype.JLong:
        ...

    @minSnap.setter
    def minSnap(self, value: jpype.JLong):
        ...

    @property
    def canonicalPath(self) -> ghidra.trace.model.target.path.KeyPath:
        ...

    @property
    def entryKey(self) -> java.lang.String:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...

    @property
    def object(self) -> jpype.JBoolean:
        ...

    @property
    def child(self) -> TraceObject:
        ...


class TraceObject(ghidra.trace.model.TraceUniqueObject):
    """
    A record of a target object in a debugger
     
     
    
    This object supports querying for and obtaining the interfaces which constitute what the object
    is and define how the client may interact with it. The object may also have children, e.g., a
    process should likely have threads.
     
     
    
    This interface is the focal point of the "debug target model." A debugger may present itself as
    an arbitrary directory of "target objects." The root object is typically the debugger's session,
    and one its attributes is a collection for its attached targets. These objects, including the
    root object, may implement any number of interfaces extending :obj:`TraceObjectInterface`. These
    interfaces comprise the type and behavior of the object. An object's children comprise its
    elements (for collection-like objects) and attributes. Every object in the directory has a path.
    Each element ("key") in the path identifies an index (if the child is an element) or a name (if
    the child is an attribute). It is the implementation's responsibility to ensure each object's
    path correctly identifies that same object in the model directory. The root has the empty path.
    Every object must have a unique path; thus, every object must have a unique key among its
    sibling.
     
     
    
    The objects are arranged in a directory with links permitted. Links come in the form of
    object-valued attributes or elements where the path does not match the object value's path. Thus,
    the overall structure remains a tree, but by resolving links, the model may be treated as a
    directed graph, likely containing cycles.
     
     
    
    The implementation must guarantee that distinct :obj:`TraceObject`s from the same model do not
    share the same path. That is, checking for object identity is sufficient to check that two
    variables refer to the same object.
     
     
    
    Various conventions govern where the client/user should search to obtain a given interface in the
    context of some target object. For example, if the user is interacting with a thread, and wishes
    to access that thread's memory, it needs to follow a given search order to find the appropriate
    target object(s), if they exist, implementing the desired interface. See
    :meth:`TraceObjectSchema.searchForSuitable(TraceObjectSchema, KeyPath) <TraceObjectSchema.searchForSuitable>` for details. In summary,
    the order is:
     
     
    1. The object itself: Test if the context target object supports the desired interface.
    If it does, take it.
    2. Aggregate objects: If the object is marked with :obj:`TraceAggregate`, collect all
    attributes supporting the desired interface. If there are any, take them. This step is applied
    recursively if any child attribute is also marked with:obj:`TraceAggregate`.
    3. Ancestry: Apply these same steps to the object's (canonical) parent, recursively.
    
     
     
    
    For some situations, exactly one object is required. In that case, take the first obtained by
    applying the above rules. In other situations, multiple objects may be acceptable. Again, apply
    the rules until a sufficient collection of objects is obtained. If an object is in conflict with
    another, take the first encountered. This situation may be appropriate if, e.g., multiple target
    memories present disjoint regions. There should not be conflicts among sibling. If there are,
    then either the model or the query is not sound. The order siblings considered should not matter.
     
     
    
    This relatively free structure and corresponding conventions allow for debuggers to present a
    model which closely reflects the structure of its session. For example, the following structure
    may be presented by a user-space debugger for a desktop operating system:
     
     
    * "Session" : :obj:`TraceObject`    
        * "Process 789" : :obj:`TraceProcess`, :obj:`TraceAggregate`    
            * "Threads" : :obj:`TraceObject`    
                * "Thread 1" : :obj:`TraceThread`, :obj:`TraceExecutionStateful`, :obj:`TraceAggregate`    
                    * "Registers" : :obj:`TraceRegisterContainer`    
                        * "r1" : :obj:`TraceRegister`
                        * ...
                    
                
                * ...more threads
            
            * "Memory" : :obj:`TraceMemory`    
                * "[0x00400000:0x00401234]" : :obj:`TraceMemoryRegion`
                * ...more regions
            
            * "Modules" : :obj:`TraceObject`    
                * "/usr/bin/echo" : :obj:`TraceModule`    
                    * ".text" : :obj:`TraceSection`
                    * ...more sections
                
                * ...more modules
            
        
        * "Environment": :obj:`TraceEnvironment`    
            * "Process 321" : :obj:`TraceObject`
            * ...more processes
        
    
    
     
     
    
    Note that this interface does not provide target-related operations, but only a means of
    modifying the database. The target connector, if this trace is still "live," should have a handle
    to this same trace and so can update the records as events occur in the debugger session and keep
    the target state up to date. Commands for manipulating the target and/or session itself are
    provided by that connector.
    """

    class ConflictResolution(java.lang.Enum[TraceObject.ConflictResolution]):
        """
        Specifies a strategy for resolving duplicate keys
         
         
        
        Values are not permitted to have intersecting lifespans if they have the same parent and key,
        since this would imply the value is not unique for a given parent, key, and snap. Thus, when
        values and lifespans are being set that would result in conflicting entries, the conflict
        must be resolved, either by clearing the span or by denying the change.
        """

        class_: typing.ClassVar[java.lang.Class]
        TRUNCATE: typing.Final[TraceObject.ConflictResolution]
        """
        Truncate, split, or delete conflicting entries to make way for the specified lifespan
        """

        DENY: typing.Final[TraceObject.ConflictResolution]
        """
        Throw :obj:`DuplicateKeyException` if the specified lifespan would result in conflicting
        entries
        """

        ADJUST: typing.Final[TraceObject.ConflictResolution]
        """
        Adjust the new entry to fit into the span available, possibly ignoring it altogether
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceObject.ConflictResolution:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceObject.ConflictResolution]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    EXTRA_INTERFACES_ATTRIBUTE_NAME: typing.Final = "_extra_ifs"

    def delete(self):
        """
        Delete this object along with parent and child value entries referring to it
         
         
        
        **Warning:** This will remove the object from the manager *entirely*, not just over
        a given span. In general, this is used for cleaning and maintenance. Consider
        :meth:`remove(Lifespan) <.remove>` or :meth:`TraceObjectValue.delete() <TraceObjectValue.delete>` instead. Note, this does not
        delete the child objects or any successors. It is not recommended to invoke this on the root
        object, since it cannot be replaced without first clearing the manager.
        """

    def findAncestorsInterface(self, span: ghidra.trace.model.Lifespan, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Search for ancestors having the given interface
        
        :param ghidra.trace.model.Lifespan span: the span which the found objects must intersect
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] iface: the interface class
        :return: the stream of found paths to values
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    def findCanonicalAncestorsInterface(self, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> java.util.stream.Stream[TraceObject]:
        """
        Search for ancestors on the canonical path having the given interface
         
         
        
        The object may not yet be inserted at its canonical path.
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] iface: the interface class
        :return: the stream of objects
        :rtype: java.util.stream.Stream[TraceObject]
        """

    def findRegisterContainer(self, frameLevel: typing.Union[jpype.JInt, int]) -> TraceObject:
        """
        Search for a suitable register container
        
        :param jpype.JInt or int frameLevel: the frame level. Must be 0 if not applicable
        :return: the register container, or null
        :rtype: TraceObject
        
        .. seealso::
        
            | :obj:`TraceObjectSchema.searchForRegisterContainer(int, KeyPath)`
        """

    def findSuccessorsInterface(self, span: ghidra.trace.model.Lifespan, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface], requireCanonical: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Search for successors having the given interface
        
        :param ghidra.trace.model.Lifespan span: the span which the found paths must intersect
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] iface: the interface class
        :param jpype.JBoolean or bool requireCanonical: if the objects must be found within their canonical container
        :return: the stream of found paths to values
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    def findSuitableContainerInterface(self, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> TraceObject:
        """
        Search for a suitable canonical container of the given interface
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] iface: the interface
        :return: the container, or null if not found
        :rtype: TraceObject
        """

    def findSuitableInterface(self, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> TraceObject:
        """
        Search for a suitable object having the given interface
         
         
        
        This operates by examining the schema for a unique suitable path, without regard to
        lifespans. If needed, the caller should inspect the object's life.
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] iface: the interface
        :return: the suitable object, or null if not found
        :rtype: TraceObject
        """

    def findSuitableSchema(self, schema: ghidra.trace.model.target.schema.TraceObjectSchema) -> TraceObject:
        """
        Search for a suitable object having the given schema
         
         
        
        This operates by examining the schema for a unique suitable path, without regard to
        lifespans. If needed, the caller should inspect the object's life.
        
        :param ghidra.trace.model.target.schema.TraceObjectSchema schema: the schema
        :return: the suitable object, or null if not found
        :rtype: TraceObject
        """

    def getAllPaths(self, span: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Get all paths actually leading to this object, from the root, within the given span
         
         
        
        Aliased keys are excluded.
        
        :param ghidra.trace.model.Lifespan span: the span which every value entry on each path must intersect
        :return: the paths
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    def getAncestors(self, span: ghidra.trace.model.Lifespan, relativeFilter: ghidra.trace.model.target.path.PathFilter) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Stream all ancestor values of this object matching the given filter, intersecting the given
        span
         
         
        
        Aliased keys are excluded. The filter should be formulated to use the aliases' target
        attributes.
        
        :param ghidra.trace.model.Lifespan span: a span which values along the path must intersect
        :param ghidra.trace.model.target.path.PathFilter relativeFilter: the filter for matching path keys, relative to this object
        :return: the stream of matching paths to values
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    def getAncestorsRoot(self, span: ghidra.trace.model.Lifespan, rootFilter: ghidra.trace.model.target.path.PathFilter) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Stream all ancestor values of this object matching the given filter, intersecting the given
        span
         
         
        
        Aliased keys are excluded. The filter should be formulated to use the aliases' target
        attributes.
        
        :param ghidra.trace.model.Lifespan span: a span which values along the path must intersect
        :param ghidra.trace.model.target.path.PathFilter rootFilter: the filter for matching path keys, relative to the root
        :return: the stream of matching paths to values
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    def getAttribute(self, snap: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str]) -> TraceObjectValue:
        """
        Get the value for the given snap and attribute name
         
         
        
        This is equivalent to :meth:`getValue(long, String) <.getValue>`, except it validates that name is not
        an index.
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str name: the name
        :return: the value entry
        :rtype: TraceObjectValue
        """

    def getAttributes(self, span: ghidra.trace.model.Lifespan) -> java.util.Collection[TraceObjectValue]:
        """
        Get all attributes of this object intersecting the given span
         
         
        
        Aliased keys are excluded.
        
        :param ghidra.trace.model.Lifespan span: the span
        :return: the attribute values
        :rtype: java.util.Collection[TraceObjectValue]
        """

    def getCanonicalParent(self, snap: typing.Union[jpype.JLong, int]) -> TraceObjectValue:
        """
        Get the parent value along this object's canonical path for a given snapshot
         
         
        
        To be the canonical parent value at a given snapshot, three things must be true: 1) The
        parent object must have this object's path with the final key removed. 2) The parent value's
        entry key must be equal to the final key of this object's path. 3) The value's lifespan must
        contain the given snapshot. If no value satisfies these, null is returned, and the object and
        its subtree are said to be "detached" at the given snapshot.
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the canonical parent value, or null
        :rtype: TraceObjectValue
        """

    def getCanonicalParents(self, lifespan: ghidra.trace.model.Lifespan) -> java.util.stream.Stream[TraceObjectValue]:
        """
        Get the parent values along this object's canonical path for a given lifespan
         
         
        
        To be a canonical parent in a given lifespan, three things must be true: 1) The parent object
        must have this object's path with the final key removed. 2) The parent value's entry key must
        be equal to the final key of this object's path. 3) The value's lifespan must intersect the
        given lifespan. If the result is empty, the object and its subtree are said to be "detatched"
        during the given lifespan.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan to consider
        :return: the stream of canonical parents
        :rtype: java.util.stream.Stream[TraceObjectValue]
        """

    def getCanonicalPath(self) -> ghidra.trace.model.target.path.KeyPath:
        """
        Get the canonical path of this object
        
        :return: the path
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def getCanonicalSuccessors(self, relativeFilter: ghidra.trace.model.target.path.PathFilter) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Stream all canonical successor values of this object matching the given filter
         
         
        
        If an object has a disjoint life, i.e., multiple canonical parents, then only the
        least-recent of those is traversed. Aliased keys are excluded; those can't be canonical
        anyway. By definition, a primitive value is not canonical, even if it is the final value in
        the path.
        
        :param ghidra.trace.model.target.path.PathFilter relativeFilter: filter on the relative path from this object to desired successors
        :return: the stream of value paths
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    @typing.overload
    def getElement(self, snap: typing.Union[jpype.JLong, int], index: typing.Union[java.lang.String, str]) -> TraceObjectValue:
        """
        Get the value for the given snap and element index
         
         
        
        This is equivalent to :meth:`getValue(long, String) <.getValue>`, but converts index to a key, i.e.,
        adds brackets.
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str index: the index
        :return: the value entry
        :rtype: TraceObjectValue
        """

    @typing.overload
    def getElement(self, snap: typing.Union[jpype.JLong, int], index: typing.Union[jpype.JLong, int]) -> TraceObjectValue:
        """
        Get the value for the given snap and element index
         
         
        
        This is equivalent to :meth:`getElement(long, String) <.getElement>`, but converts index to a string in
        decimal.
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JLong or int index: the index
        :return: the value entry
        :rtype: TraceObjectValue
        """

    def getElements(self, span: ghidra.trace.model.Lifespan) -> java.util.Collection[TraceObjectValue]:
        """
        Get all elements of this object intersecting the given span
        
        :param ghidra.trace.model.Lifespan span: the span
        :return: the element values
        :rtype: java.util.Collection[TraceObjectValue]
        """

    def getExecutionState(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.TraceExecutionState:
        """
        Get the execution state, if applicable, of this object
         
         
        
        This searches for the conventional stateful object defining this object's execution state. If
        such an object does not exist, null is returned. If one does exist, then its execution state
        at the given snap is returned. If that state is null, it is assumed
        :obj:`TraceExecutionState.INACTIVE`.
        
        :param jpype.JLong or int snap: the snap
        :return: the state or null
        :rtype: ghidra.trace.model.TraceExecutionState
        """

    def getInterfaces(self) -> java.util.Collection[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]:
        """
        Get all the interface classes provided by this object, according to the schema
        
        :return: the collection of interface classes
        :rtype: java.util.Collection[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]
        """

    def getKey(self) -> int:
        """
        Get the database key for this object
        
        :return: the key
        :rtype: int
        """

    def getLife(self) -> ghidra.trace.model.Lifespan.LifeSet:
        """
        Get all ranges of this object's life
         
         
        
        Essentially, this is the union of the lifespans of all canonical parent values
        
        :return: the range set for snaps at which this object is considered "inserted."
        :rtype: ghidra.trace.model.Lifespan.LifeSet
        """

    def getOrderedSuccessors(self, span: ghidra.trace.model.Lifespan, relativePath: ghidra.trace.model.target.path.KeyPath, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Stream all successor values of this object at the given relative path, intersecting the given
        span, ordered by time.
         
         
        
        Aliased keys are excluded. The filter should be formulated to use the aliases' target
        attributes.
        
        :param ghidra.trace.model.Lifespan span: the span which values along the path must intersect
        :param ghidra.trace.model.target.path.KeyPath relativePath: the path relative to this object
        :param jpype.JBoolean or bool forward: true to order from least- to most-recent, false for most- to least-recent
        :return: the stream of value paths
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    def getOrderedValues(self, span: ghidra.trace.model.Lifespan, key: typing.Union[java.lang.String, str], forward: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[TraceObjectValue]:
        """
        Get values with the given key intersecting the given span ordered by time
         
         
        
        If the key is an alias, the target key's values are retrieved instead.
        
        :param ghidra.trace.model.Lifespan span: the span
        :param java.lang.String or str key: the key
        :param jpype.JBoolean or bool forward: true to order from least- to most-recent, false for most- to least-recent
        :return: the stream of values
        :rtype: java.util.stream.Stream[TraceObjectValue]
        """

    def getParents(self, span: ghidra.trace.model.Lifespan) -> java.util.Collection[TraceObjectValue]:
        """
        Get all values intersecting the given span and whose child is this object
         
         
        
        Aliased keys are excluded.
        
        :param ghidra.trace.model.Lifespan span: the span
        :return: the parent values
        :rtype: java.util.Collection[TraceObjectValue]
        """

    def getRoot(self) -> TraceObject:
        """
        Get the root of the tree containing this object
        
        :return: the root
        :rtype: TraceObject
        """

    def getSchema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        """
        Get the schema for this object
        
        :return: the schema
        :rtype: ghidra.trace.model.target.schema.TraceObjectSchema
        """

    def getSuccessors(self, span: ghidra.trace.model.Lifespan, relativeFilter: ghidra.trace.model.target.path.PathFilter) -> java.util.stream.Stream[TraceObjectValPath]:
        """
        Stream all successor values of this object matching the given filter, intersecting the given
        span
         
         
        
        Aliased keys are excluded. The filter should be formulated to use the aliases' target
        attributes.
        
        :param ghidra.trace.model.Lifespan span: a span which values along the path must intersect
        :param ghidra.trace.model.target.path.PathFilter relativeFilter: the filter for matching path keys, relative to this object
        :return: the stream of matching paths to values
        :rtype: java.util.stream.Stream[TraceObjectValPath]
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this object
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def getValue(self, snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str]) -> TraceObjectValue:
        """
        Get the value for the given snap and key
         
         
        
        If the key is an alias, the target key's value is retrieved instead.
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str key: the key
        :return: the value entry
        :rtype: TraceObjectValue
        """

    @typing.overload
    def getValues(self, span: ghidra.trace.model.Lifespan) -> java.util.Collection[TraceObjectValue]:
        """
        Get all values (elements and attributes) of this object intersecting the given span
         
         
        
        Aliased keys are excluded.
        
        :param ghidra.trace.model.Lifespan span: the span
        :return: the values
        :rtype: java.util.Collection[TraceObjectValue]
        """

    @typing.overload
    def getValues(self, span: ghidra.trace.model.Lifespan, key: typing.Union[java.lang.String, str]) -> java.util.Collection[TraceObjectValue]:
        """
        Get values with the given key intersecting the given span
         
         
        
        If the key is an alias, the target key's values are retrieved instead.
        
        :param ghidra.trace.model.Lifespan span: the span
        :param java.lang.String or str key: the key
        :return: the collection of values
        :rtype: java.util.Collection[TraceObjectValue]
        """

    def insert(self, lifespan: ghidra.trace.model.Lifespan, resolution: TraceObject.ConflictResolution) -> TraceObjectValPath:
        """
        Inserts this object at its canonical path for the given lifespan
         
         
        
        Any ancestor which does not exist is created. Values' lifespans are added or expanded to
        contain the given lifespan. Only the canonical path is considered when looking for existing
        ancestry.
        
        :param ghidra.trace.model.Lifespan lifespan: the minimum lifespan of edges from the root to this object
        :param TraceObject.ConflictResolution resolution: the rule for handling duplicate keys when setting values.
        :return: the value path from root to the newly inserted object
        :rtype: TraceObjectValPath
        """

    @typing.overload
    def isAlive(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the object is alive at the given snap
         
         
        
        This is preferable to :meth:`getLife() <.getLife>`, when we only need to check one snap
        
        :param jpype.JLong or int snap: the snap
        :return: true if alive, false if not
        :rtype: bool
        """

    @typing.overload
    def isAlive(self, span: ghidra.trace.model.Lifespan) -> bool:
        """
        Check if the object is alive at all in the given span
        
        :param ghidra.trace.model.Lifespan span: the span
        :return: true if alive, false if not
        :rtype: bool
        """

    def isDeleted(self) -> bool:
        """
        Check if this object has been deleted
        
        :return: true if the object has been deleted
        :rtype: bool
        """

    def isMethod(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the child represents a method at the given snap
        
        :param jpype.JLong or int snap: the snap
        :return: true if a method
        :rtype: bool
        """

    def isRoot(self) -> bool:
        """
        Check if this object is the root
        
        :return: true if root
        :rtype: bool
        """

    def queryAncestorsInterface(self, span: ghidra.trace.model.Lifespan, iface: java.lang.Class[I]) -> java.util.stream.Stream[I]:
        """
        Search for ancestors having the given interface and retrieve those interfaces
        
        :param I: the interface type:param ghidra.trace.model.Lifespan span: the span which the found objects must intersect
        :param java.lang.Class[I] iface: the interface class
        :return: the stream of interfaces
        :rtype: java.util.stream.Stream[I]
        """

    def queryCanonicalAncestorsInterface(self, iface: java.lang.Class[I]) -> java.util.stream.Stream[I]:
        """
        Search for ancestors on the canonical path having the given interface and retrieve those
        interfaces
         
         
        
        The object may not yet be inserted at its canonical path.
        
        :param I: the interface type:param java.lang.Class[I] iface: the interface class
        :return: the stream of interfaces
        :rtype: java.util.stream.Stream[I]
        """

    def queryInterface(self, iface: java.lang.Class[I]) -> I:
        """
        Request the specified interface provided by this object
        
        :param I: the type of the interface:param java.lang.Class[I] iface: the class of the interface
        :return: the interface, or null if not provided
        :rtype: I
        """

    def querySuccessorsInterface(self, span: ghidra.trace.model.Lifespan, iface: java.lang.Class[I], requireCanonical: typing.Union[jpype.JBoolean, bool]) -> java.util.stream.Stream[I]:
        """
        Search for successors having the given interface and retrieve those interfaces
        
        :param I: the interface type:param ghidra.trace.model.Lifespan span: the span which the found objects must intersect
        :param java.lang.Class[I] iface: the interface class
        :param jpype.JBoolean or bool requireCanonical: if the objects must be found within their canonical container
        :return: the stream of interfaces
        :rtype: java.util.stream.Stream[I]
        """

    def remove(self, span: ghidra.trace.model.Lifespan):
        """
        Remove this object from its canonical path for the given lifespan
         
         
        
        Truncate the lifespans of this object's canonical parent value by the given span. If the
        parent value's lifespan is contained in the given span, the parent value will be deleted.
        
        :param ghidra.trace.model.Lifespan span: the span during which this object should be removed
        """

    def removeTree(self, span: ghidra.trace.model.Lifespan):
        """
        Remove this object and its successors from their canonical paths for the given span
         
         
        
        Truncate the lifespans of this object's parent values and all canonical values succeeding
        this object. If a truncated value's lifespan is contained in the given span, the value will
        be deleted.
        
        :param ghidra.trace.model.Lifespan span: the span during which this object and its canonical successors should be removed
        """

    def setAttribute(self, lifespan: ghidra.trace.model.Lifespan, name: typing.Union[java.lang.String, str], value: java.lang.Object) -> TraceObjectValue:
        """
        Set an attribute for the given lifespan
         
         
        
        This is equivalent to :meth:`setValue(Lifespan, String, Object) <.setValue>`, except it verifies the key
        is an attribute name.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the attribute
        :param java.lang.String or str name: the name to set
        :param java.lang.Object value: the new value
        :return: the created value entry
        :rtype: TraceObjectValue
        """

    @typing.overload
    def setElement(self, lifespan: ghidra.trace.model.Lifespan, index: typing.Union[java.lang.String, str], value: java.lang.Object) -> TraceObjectValue:
        """
        Set an element for the given lifespan
         
         
        
        This is equivalent to :meth:`setValue(Lifespan, String, Object) <.setValue>`, except it converts the
        index to a key, i.e., add brackets.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the element
        :param java.lang.String or str index: the index to set
        :param java.lang.Object value: the new value
        :return: the created value entry
        :rtype: TraceObjectValue
        """

    @typing.overload
    def setElement(self, lifespan: ghidra.trace.model.Lifespan, index: typing.Union[jpype.JLong, int], value: java.lang.Object) -> TraceObjectValue:
        """
        Set an element for the given lifespan
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the element
        :param jpype.JLong or int index: the index to set
        :param java.lang.Object value: the new value
        :return: the created value entry
        :rtype: TraceObjectValue
        """

    @typing.overload
    def setValue(self, lifespan: ghidra.trace.model.Lifespan, key: typing.Union[java.lang.String, str], value: java.lang.Object, resolution: TraceObject.ConflictResolution) -> TraceObjectValue:
        """
        Set a value for the given lifespan
         
         
        
        If the key is an alias, the target key's value is set instead.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the value
        :param java.lang.String or str key: the key to set
        :param java.lang.Object value: the new value
        :param TraceObject.ConflictResolution resolution: determines how to resolve duplicate keys with intersecting lifespans
        :return: the created value entry
        :rtype: TraceObjectValue
        :raises DuplicateKeyException: if there are denied duplicate keys
        """

    @typing.overload
    def setValue(self, lifespan: ghidra.trace.model.Lifespan, key: typing.Union[java.lang.String, str], value: java.lang.Object) -> TraceObjectValue:
        """
        Set a value for the given lifespan, truncating existing entries
         
         
        
        Setting a value of ``null`` effectively deletes the value for the given lifespan and
        returns ``null``. Values of the same key intersecting the given lifespan or either
        truncated or deleted. If the key is an alias, the target key's value is set instead.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the value
        :param java.lang.String or str key: the key to set
        :param java.lang.Object value: the new value
        :return: the created value entry, or null
        :rtype: TraceObjectValue
        """

    @property
    def schema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    @property
    def interfaces(self) -> java.util.Collection[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]:
        ...

    @property
    def method(self) -> jpype.JBoolean:
        ...

    @property
    def alive(self) -> jpype.JBoolean:
        ...

    @property
    def values(self) -> java.util.Collection[TraceObjectValue]:
        ...

    @property
    def executionState(self) -> ghidra.trace.model.TraceExecutionState:
        ...

    @property
    def canonicalParent(self) -> TraceObjectValue:
        ...

    @property
    def life(self) -> ghidra.trace.model.Lifespan.LifeSet:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def canonicalSuccessors(self) -> java.util.stream.Stream[TraceObjectValPath]:
        ...

    @property
    def root(self) -> TraceObject:
        ...

    @property
    def elements(self) -> java.util.Collection[TraceObjectValue]:
        ...

    @property
    def canonicalPath(self) -> ghidra.trace.model.target.path.KeyPath:
        ...

    @property
    def canonicalParents(self) -> java.util.stream.Stream[TraceObjectValue]:
        ...

    @property
    def attributes(self) -> java.util.Collection[TraceObjectValue]:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...

    @property
    def allPaths(self) -> java.util.stream.Stream[TraceObjectValPath]:
        ...

    @property
    def parents(self) -> java.util.Collection[TraceObjectValue]:
        ...



__all__ = ["DuplicateKeyException", "TraceObjectManager", "TraceObjectValPath", "TraceObjectValue", "TraceObject"]
