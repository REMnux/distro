from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.trace.model.target
import ghidra.trace.model.target.iface
import ghidra.trace.model.target.path
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.jdom # type: ignore


T = typing.TypeVar("T")


class TraceObjectSchema(java.lang.Object):
    """
    Type information for a particular value or :obj:`TraceObject`
     
     
    
    This allows a client to inspect predictable aspects of a model before fetching any actual
    objects. This also helps a client understand where to listen for particular types of objects and
    comprehend the model's structure in general.
     
     
    
    For a primitive type, the type is given by :meth:`getType() <.getType>`. For :obj:`TraceObject`s,
    supported interfaces are given by :meth:`getInterfaces() <.getInterfaces>`. The types of children are determined
    by matching on the keys (indices and names), the result being a subordinate
    :obj:`TraceObjectSchema`. Keys must match exactly, unless the "pattern" is the empty string,
    which matches any key. Similarly, the wild-card index is ``[]``.
     
     
    
    The schema can specify attribute aliases, which implies that a particular key ("from") will
    always have the same value as another ("to"). As a result, the schemas of aliased keys will also
    implicitly match.
    """

    class SchemaName(java.lang.Record, java.lang.Comparable[TraceObjectSchema.SchemaName]):
        """
        An identifier for schemas within a context.
        
         
        
        This is essentially a wrapper on :obj:`String`, but typed so that strings and names cannot
        be accidentally interchanged.
         
         
        
        TODO: In retrospect, I'm not sure having this has improved anything. Might just replace this
        with a plain :obj:`String`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...


    class Hidden(java.lang.Enum[TraceObjectSchema.Hidden]):

        class_: typing.ClassVar[java.lang.Class]
        DEFAULT: typing.Final[TraceObjectSchema.Hidden]
        TRUE: typing.Final[TraceObjectSchema.Hidden]
        FALSE: typing.Final[TraceObjectSchema.Hidden]

        def adjust(self, name: typing.Union[java.lang.String, str]) -> TraceObjectSchema.Hidden:
            ...

        def isHidden(self, name: typing.Union[java.lang.String, str]) -> bool:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceObjectSchema.Hidden:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceObjectSchema.Hidden]:
            ...

        @property
        def hidden(self) -> jpype.JBoolean:
            ...


    class AttributeSchema(java.lang.Object):
        """
        Schema descriptor for a child attribute.
        """

        class_: typing.ClassVar[java.lang.Class]
        DEFAULT_ANY: typing.Final[TraceObjectSchema.AttributeSchema]
        """
        A descriptor suitable as a default that imposes no restrictions.
        """

        DEFAULT_OBJECT: typing.Final[TraceObjectSchema.AttributeSchema]
        """
        A descriptor suitable as a default that requires an object
        """

        DEFAULT_VOID: typing.Final[TraceObjectSchema.AttributeSchema]
        """
        A descriptor suitable as a default that forbids an attribute name
        """


        def getHidden(self) -> TraceObjectSchema.Hidden:
            ...

        def getName(self) -> str:
            """
            Get the name of the attribute
            
            :return: the name of the attribute
            :rtype: str
            """

        def getSchema(self) -> TraceObjectSchema.SchemaName:
            """
            Get the schema name for the named attribute
            
            :return: the schema name
            :rtype: TraceObjectSchema.SchemaName
            """

        def isFixed(self) -> bool:
            """
            Check if the named attribute can be modified
            
            :return: true if immutable, false if mutable
            :rtype: bool
            """

        def isHidden(self, name: typing.Union[java.lang.String, str]) -> bool:
            """
            Check if the named attribute should be displayed be default
             
             
            
            This is purely a UI hint. It has no other semantic consequence.
            
            :param java.lang.String or str name: the actual name of the attribute, in case this is the default attribute
            :return: true if hidden, false if visible
            :rtype: bool
            """

        def isRequired(self) -> bool:
            """
            Check if the named attribute must always be present
            
            :return: true if required, false if optional
            :rtype: bool
            """

        @property
        def schema(self) -> TraceObjectSchema.SchemaName:
            ...

        @property
        def hidden(self) -> TraceObjectSchema.Hidden:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def fixed(self) -> jpype.JBoolean:
            ...

        @property
        def required(self) -> jpype.JBoolean:
            ...


    class Private(java.lang.Object):

        @typing.type_check_only
        class BreadthFirst(java.lang.Object, typing.Generic[T]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, seed: java.util.Set[T]):
                ...

            def descendAttributes(self, ent: T) -> bool:
                ...

            def descendElements(self, ent: T) -> bool:
                ...

            def expandAttribute(self, nextLevel: java.util.Set[T], ent: T, schema: TraceObjectSchema, path: ghidra.trace.model.target.path.KeyPath):
                ...

            def expandAttributes(self, nextLevel: java.util.Set[T], ent: T):
                ...

            def expandDefaultAttribute(self, nextLevel: java.util.Set[T], ent: T):
                ...

            def expandDefaultElement(self, nextLevel: java.util.Set[T], ent: T):
                ...

            def expandElement(self, nextLevel: java.util.Set[T], ent: T, schema: TraceObjectSchema, path: ghidra.trace.model.target.path.KeyPath):
                ...

            def expandElements(self, nextLevel: java.util.Set[T], ent: T):
                ...

            def nextLevel(self):
                ...


        @typing.type_check_only
        class SearchEntry(java.lang.Object):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, path: ghidra.trace.model.target.path.KeyPath, schema: TraceObjectSchema):
                ...


        @typing.type_check_only
        class CanonicalSearchEntry(TraceObjectSchema.Private.SearchEntry):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, path: ghidra.trace.model.target.path.KeyPath, parentIsCanonical: typing.Union[jpype.JBoolean, bool], schema: TraceObjectSchema):
                ...


        @typing.type_check_only
        class InAggregateSearch(TraceObjectSchema.Private.BreadthFirst[TraceObjectSchema.Private.SearchEntry]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, seed: TraceObjectSchema):
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def checkAliasedAttribute(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Check if the given name is an alias and get the target attribute name
        
        :param java.lang.String or str name: the name
        :return: the alias' target, or the given name if not an alias
        :rtype: str
        """

    def computeFrameLevel(self, path: ghidra.trace.model.target.path.KeyPath) -> int:
        """
        Compute the frame level of the object at the given path relative to this schema
         
         
        
        If there is no :obj:`TraceStackFrame` in the path, this will return 0 since it is not
        applicable to the object. If there is a stack frame in the path, this will examine its
        ancestry, up to and excluding the :obj:`TraceStack` for an index. If there isn't a stack in
        the path, it is assumed to be an ancestor of this schema, meaning the examination will
        exhaust the ancestry provided in the path. If no index is found, an exception is thrown,
        because the frame level is applicable, but couldn't be computed from the path given. In that
        case, the client should include more ancestry in the path. Ideally, this is invoked relative
        to the root schema.
        
        :param ghidra.trace.model.target.path.KeyPath path: the path
        :return: the frame level, or 0 if not applicable
        :rtype: int
        :raises IllegalArgumentException: if frame level is applicable but not given in the path
        """

    def filterForSuitable(self, type: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface], path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.target.path.PathFilter:
        """
        Search for all suitable objects with this schema at the given path
         
         
        
        This behaves like :meth:`searchForSuitable(Class, KeyPath) <.searchForSuitable>`, except that it returns a
        matcher for all possibilities. Conventionally, when the client uses the matcher to find
        suitable objects and must choose from among the results, those having the longer paths should
        be preferred. More specifically, it should prefer those sharing the longer path prefixes with
        the given path. The client should *not* just take the first objects, since these will
        likely have the shortest paths. If exactly one object is required, consider using
        :meth:`searchForSuitable(Class, KeyPath) <.searchForSuitable>` instead.
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] type: 
        :param ghidra.trace.model.target.path.KeyPath path: 
        :return: the filter for finding objects
        :rtype: ghidra.trace.model.target.path.PathFilter
        """

    def getAttributeAliases(self) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Get the map of attribute name aliases
         
         
        
        The returned map must provide the *direct* alias names. For any given key, the client
        need only query the map once to determine the name of the attribute to which the alias
        refers. Consequently, the map also cannot indicate a cycle.
         
         
        
        An aliased attribute takes the value of its target implicitly.
        
        :return: the map
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def getAttributeSchema(self, name: typing.Union[java.lang.String, str]) -> TraceObjectSchema.AttributeSchema:
        """
        Get the attribute schema for a given attribute name
         
         
        
        If there's a schema specified for the given name, that schema is taken. If the name refers to
        an alias, its schema is taken. Otherwise, the default attribute schema is taken.
        
        :param java.lang.String or str name: the name
        :return: the attribute schema
        :rtype: TraceObjectSchema.AttributeSchema
        """

    def getAttributeSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.AttributeSchema]:
        """
        Get the map of attribute names to named schemas
         
         
        
        The returned map will include aliases. To determine whether or not an attribute key is an
        alias, check whether the entry's key matches the name of the attribute (see
        :meth:`AttributeSchema.getName() <AttributeSchema.getName>`). It is possible the schema's name is empty, i.e., the
        default schema. This indicates an alias to a key that was not named in the schema. Use
        :meth:`getAttributeAliases() <.getAttributeAliases>` to determine the name of that key.
        
        :return: the map
        :rtype: java.util.Map[java.lang.String, TraceObjectSchema.AttributeSchema]
        """

    def getChildSchema(self, key: typing.Union[java.lang.String, str]) -> TraceObjectSchema:
        """
        Get the schema for a child having the given key
         
         
        
        This is the preferred method for navigating a schema and computing the expected type of a
        child.
        
        :param java.lang.String or str key: the key
        :return: the schema
        :rtype: TraceObjectSchema
        """

    def getChildSchemaName(self, key: typing.Union[java.lang.String, str]) -> TraceObjectSchema.SchemaName:
        """
        Get the named schema for a child having the given key
        
        :param java.lang.String or str key: the key
        :return: the named schema
        :rtype: TraceObjectSchema.SchemaName
        """

    def getContext(self) -> SchemaContext:
        """
        Get the context of which this schema is a member
         
         
        
        All schema names are resolved in this same context
        
        :return: the context
        :rtype: SchemaContext
        """

    def getDefaultAttributeSchema(self) -> TraceObjectSchema.AttributeSchema:
        """
        Get the default schema for attributes
         
         
        
        Since the expected attributes and their respective schemas are generally enumerated, this
        most commonly returns :obj:`AttributeSchema.DEFAULT_ANY`, to allow unrestricted use of
        additional attributes, or :obj:`AttributeSchema.DEFAULT_VOID`, to forbid any additional
        attributes.
        
        :return: the default attribute schema
        :rtype: TraceObjectSchema.AttributeSchema
        """

    def getDefaultElementSchema(self) -> TraceObjectSchema.SchemaName:
        """
        Get the default schema for elements
         
         
        
        Since elements of a given container are typically uniform in type, this is the primary means
        of specifying element schemas.
        
        :return: the default named schema
        :rtype: TraceObjectSchema.SchemaName
        """

    def getElementSchema(self, index: typing.Union[java.lang.String, str]) -> TraceObjectSchema.SchemaName:
        """
        Get the named schema for a given element index
         
         
        
        If there's a schema specified for the given index, that schema is taken. Otherwise, the
        default element schema is taken.
        
        :param java.lang.String or str index: the index
        :return: the named schema
        :rtype: TraceObjectSchema.SchemaName
        """

    def getElementSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.SchemaName]:
        """
        Get the map of element indices to named schemas
         
         
        
        It is uncommon for this map to be populated, since the elements of a given container are
        typically uniform in type. Nevertheless, there can be restrictions imposed on -- and
        information provided for -- specific indices.
        
        :return: the map
        :rtype: java.util.Map[java.lang.String, TraceObjectSchema.SchemaName]
        """

    def getInterfaces(self) -> java.util.Set[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]:
        """
        Get the minimum interfaces supported by a conforming object
        
        :return: the set of required interfaces
        :rtype: java.util.Set[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]
        """

    def getName(self) -> TraceObjectSchema.SchemaName:
        """
        Get the name of this schema
        
        :return: the name
        :rtype: TraceObjectSchema.SchemaName
        """

    def getSuccessorSchema(self, path: ghidra.trace.model.target.path.KeyPath) -> TraceObjectSchema:
        """
        Get the schema for a successor at the given (sub) path
         
         
        
        If this is the schema of the root object, then this gives the schema of the object at the
        given path in the model. This will always give a non-null result, though that result might be
        :obj:`PrimitiveTraceObjectSchema.VOID`.
        
        :param ghidra.trace.model.target.path.KeyPath path: the relative path from an object having this schema to the desired successor
        :return: the schema for the successor
        :rtype: TraceObjectSchema
        """

    def getSuccessorSchemas(self, path: ghidra.trace.model.target.path.KeyPath) -> java.util.List[TraceObjectSchema]:
        """
        Get the list of schemas traversed from this schema along the given (sub) path
         
         
        
        This list always begins with this schema, followed by the child schema for each key in the
        path. Thus, for a path of length n, the resulting list has n+1 entries. This is useful for
        searches along the ancestry of a given path:
         
        ``List<TargetObjectSchema> schemas = getSuccessorSchemas(path);for (; path != null; path = PathUtils.parent(path)) {    TargetObjectSchema schema = schemas.get(path.size());    // ...}``
         
         
        
        All entries are non-null, though they may be :obj:`PrimitiveTraceObjectSchema.VOID`.
        
        :param ghidra.trace.model.target.path.KeyPath path: the relative path from an object having this schema to the desired successor
        :return: the list of schemas traversed, ending with the successor's schema
        :rtype: java.util.List[TraceObjectSchema]
        """

    def getType(self) -> java.lang.Class[typing.Any]:
        """
        Get the Java class that best represents this type.
         
         
        
        Note that this is either a primitive, or :obj:`TraceObject`. Even though an object
        implementation is necessarily a sub-type of :obj:`TraceObject`, for any object schema, this
        return :obj:`TraceObject`. Information about a "sub-type" of object is communicated via
        interfaces, element schemas, and attribute schemas.
        
        :return: the Java class for this type
        :rtype: java.lang.Class[typing.Any]
        """

    def isAssignableFrom(self, that: TraceObjectSchema) -> bool:
        """
        Check if this schema can accept a value of the given other schema
         
         
        
        This works analogously to :meth:`Class.isAssignableFrom(Class) <Class.isAssignableFrom>`, except that schemas are
        quite a bit less flexible. Only :obj:`PrimitiveTraceObjectSchema.ANY` and
        :obj:`PrimitiveTraceObjectSchema.OBJECT` can accept anything other than exactly themselves.
        
        :param TraceObjectSchema that: 
        :return: true if an object of that schema can be assigned to this schema.
        :rtype: bool
        """

    def isCanonicalContainer(self) -> bool:
        """
        Check if this object is the canonical container for its elements
         
         
        
        This is generally in reference to the default type of this object's elements. For example, if
        elements of this object are all expected to support the "Process" interface, then this is the
        canonical Process container. Any Process ought to have a (canonical) path in this container.
        Any other path referring to such a Process ought to be a link.
         
         
        
        NOTE: the concept of links is still in incubation, as some native debugging APIs seem to have
        made it difficult to detect object identity. Additionally, it's possible a caller's first
        encounter with an object is not via its canonical path, and it may be difficult to assign a
        path having only the native-API-given object in hand.
        
        :return: true if this is a canonical container, false otherwise
        :rtype: bool
        """

    def isHidden(self, key: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if the given key should be hidden for an object having this schema
         
         
        
        Elements ought never to be hidden. Otherwise, this defers to the attribute schema.
        
        :param java.lang.String or str key: the child key to check
        :return: true if hidden
        :rtype: bool
        """

    @typing.overload
    def searchFor(self, type: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface], requireCanonical: typing.Union[jpype.JBoolean, bool]) -> ghidra.trace.model.target.path.PathFilter:
        """
        Do the same as :meth:`searchFor(Class, KeyPath, boolean) <.searchFor>` with an empty prefix
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] type: the sub-type of :obj:`TraceObjectInterface` to search for
        :param jpype.JBoolean or bool requireCanonical: only return patterns matching a canonical location for the type
        :return: a set of patterns where such objects could be found
        :rtype: ghidra.trace.model.target.path.PathFilter
        """

    @typing.overload
    def searchFor(self, type: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface], prefix: ghidra.trace.model.target.path.KeyPath, requireCanonical: typing.Union[jpype.JBoolean, bool]) -> ghidra.trace.model.target.path.PathFilter:
        """
        Find (sub) path patterns that match objects implementing a given interface
         
         
        
        Each returned path pattern accepts relative paths from an object having this schema to a
        successor implementing the interface.
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] type: the sub-type of :obj:`TraceObjectInterface` to search for
        :param ghidra.trace.model.target.path.KeyPath prefix: the prefix for each relative path pattern
        :param jpype.JBoolean or bool requireCanonical: only return patterns matching a canonical location for the type
        :return: a set of patterns where such objects could be found
        :rtype: ghidra.trace.model.target.path.PathFilter
        """

    def searchForAncestor(self, type: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface], path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.target.path.KeyPath:
        """
        Find the nearest ancestor implementing the given interface along the given path
         
         
        
        If the given path implements the interface, it is returned, i.e., it is not strictly an
        ancestor.
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] type: the interface to search for
        :param ghidra.trace.model.target.path.KeyPath path: the seed path
        :return: the found path, or ``null`` if no ancestor implements the interface
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def searchForAncestorContainer(self, type: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface], path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.target.path.KeyPath:
        """
        Find the nearest ancestor which is the canonical container of the given interface
         
         
        
        If the given path is such a container, it is returned, i.e., it is not strictly an ancestor.
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] type: the interface whose canonical container to search for
        :param ghidra.trace.model.target.path.KeyPath path: the seed path
        :return: the found path, or ``null`` if no such ancestor was found
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def searchForCanonicalContainer(self, type: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> ghidra.trace.model.target.path.KeyPath:
        """
        Find the (sub) path to the canonical container for objects implementing a given interface
         
         
        
        If more than one container is found having the shortest path, then ``null`` is returned.
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] type: the sub-type of :obj:`TraceObjectInterface` to search for
        :return: the single path to that container
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def searchForRegisterContainer(self, frameLevel: typing.Union[jpype.JInt, int], path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.target.path.PathFilter:
        """
        Search for a suitable register container
         
         
        
        This will try with and without considerations for frames. If the schema indicates that
        register containers are not contained within frames, then frameLevel must be 0, otherwise
        this will return empty. If dependent on frameLevel, this will return two singleton paths: one
        for a decimal index and another for a hexadecimal index. If not, this will return a singleton
        path. If it fails to find a unique container, this will return empty.
         
         
        
        **NOTE:** This must be used at the top of the search scope, probably the root schema. For
        example, to search the entire model for a register container related to ``myObject``:
         
         
        for (PathPattern regPattern : myObject.getModel()
                .getSchema()
                .searchForRegisterContainer(0, myObject.getPath())) {
            TargetObject objRegs = myObject.getModel().getModelObject(regPattern.getSingletonPath());
            if (objRegs != null) {
                // found it
            }
        }
         
         
         
        
        This places some conventional restrictions / expectations on models where registers are given
        on a frame-by-frame basis. The schema should present the :obj:`TraceRegisterContainer` as
        the same object or a successor to :obj:`TraceStackFrame`, which must in turn be a successor
        to :obj:`TraceStack`. The frame level (an index) must be in the path from stack to frame.
        There can be no wildcards between the frame and the register container. For example, the
        container for ``Threads[1]`` may be ``Threads[1].Stack[n].Registers``, where
        ``n`` is the frame level. ``Threads[1].Stack`` would have the :obj:`TraceStack`
        interface, ``Threads[1].Stack[0]`` would have the :obj:`TraceStackFrame` interface, and
        ``Threads[1].Stack[0].Registers`` would have the :obj:`TraceRegisterContainer`
        interface. Note it is not sufficient for :obj:`TraceRegisterContainer` to be a successor of
        :obj:`TraceStack` with a single index between. There *must* be an intervening
        :obj:`TraceStackFrame`, and the frame level (index) must precede it.
        
        :param jpype.JInt or int frameLevel: the frame level. May be ignored if not applicable
        :param ghidra.trace.model.target.path.KeyPath path: the path of the seed object relative to the root
        :return: the filter where the register container should be found, possibly
                :obj:`PathFilter.NONE`
        :rtype: ghidra.trace.model.target.path.PathFilter
        """

    @typing.overload
    def searchForSuitable(self, type: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface], path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.target.path.KeyPath:
        """
        Search for a suitable object with this schema at the given path
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] type: the type of object sought
        :param ghidra.trace.model.target.path.KeyPath path: the path of a seed object
        :return: the expected path of the suitable object, or null
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    @typing.overload
    def searchForSuitable(self, schema: TraceObjectSchema, path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.target.path.KeyPath:
        """
        Search for a suitable object with this schema at the given path
        
        :param TraceObjectSchema schema: the schema of object sought
        :param ghidra.trace.model.target.path.KeyPath path: the path of a seed object
        :return: the expected path of the suitable object, or null
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def searchForSuitableContainer(self, type: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface], path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.target.path.KeyPath:
        """
        Like :meth:`searchForSuitable(Class, KeyPath) <.searchForSuitable>`, but searches for the canonical container
        whose elements have the given type
        
        :param java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface] type: the type of object sought
        :param ghidra.trace.model.target.path.KeyPath path: the path of a seed object
        :return: the expected path of the suitable container of those objects, or null
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def validateRequiredAttributes(self, object: ghidra.trace.model.target.TraceObject, strict: typing.Union[jpype.JBoolean, bool], snap: typing.Union[jpype.JLong, int]):
        """
        Verify that all required attributes are present
         
         
        
        NOTE: This may become part of a schema and/or connector tester/validator later.
        
        :param ghidra.trace.model.target.TraceObject object: the object whose schema is this one
        :param jpype.JBoolean or bool strict: to throw exceptions upon violations
        :param jpype.JLong or int snap: the relevant snapshot
        """

    def validateTypeAndInterfaces(self, value: java.lang.Object, parentPath: ghidra.trace.model.target.path.KeyPath, key: typing.Union[java.lang.String, str], strict: typing.Union[jpype.JBoolean, bool]):
        """
        Verify that the given value is of this schema's required type and, if applicable, implements
        the required interfaces
        
        :param java.lang.Object value: the value being assigned to the key
        :param ghidra.trace.model.target.path.KeyPath parentPath: the path of the object whose key is being assigned, for diagnostics
        :param java.lang.String or str key: the key that is being assigned
        :param jpype.JBoolean or bool strict: true to throw an exception upon violation; false to just log and continue
        """

    @property
    def elementSchema(self) -> TraceObjectSchema.SchemaName:
        ...

    @property
    def canonicalContainer(self) -> jpype.JBoolean:
        ...

    @property
    def interfaces(self) -> java.util.Set[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]:
        ...

    @property
    def childSchemaName(self) -> TraceObjectSchema.SchemaName:
        ...

    @property
    def hidden(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def attributeSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.AttributeSchema]:
        ...

    @property
    def defaultAttributeSchema(self) -> TraceObjectSchema.AttributeSchema:
        ...

    @property
    def attributeSchema(self) -> TraceObjectSchema.AttributeSchema:
        ...

    @property
    def attributeAliases(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def childSchema(self) -> TraceObjectSchema:
        ...

    @property
    def successorSchemas(self) -> java.util.List[TraceObjectSchema]:
        ...

    @property
    def elementSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.SchemaName]:
        ...

    @property
    def assignableFrom(self) -> jpype.JBoolean:
        ...

    @property
    def successorSchema(self) -> TraceObjectSchema:
        ...

    @property
    def name(self) -> TraceObjectSchema.SchemaName:
        ...

    @property
    def defaultElementSchema(self) -> TraceObjectSchema.SchemaName:
        ...

    @property
    def context(self) -> SchemaContext:
        ...


class SchemaBuilder(java.lang.Object):
    """
    A builder for a :obj:`TraceObjectSchema`.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_ELEMENT_SCHEMA: typing.Final[TraceObjectSchema.SchemaName]
    DEFAULT_ATTRIBUTE_SCHEMA: typing.Final[TraceObjectSchema.AttributeSchema]

    @typing.overload
    def __init__(self, context: DefaultSchemaContext, name: TraceObjectSchema.SchemaName):
        ...

    @typing.overload
    def __init__(self, context: DefaultSchemaContext, schema: TraceObjectSchema):
        ...

    def addAttributeAlias(self, from_: typing.Union[java.lang.String, str], to: typing.Union[java.lang.String, str], origin: java.lang.Object) -> SchemaBuilder:
        ...

    def addAttributeSchema(self, schema: TraceObjectSchema.AttributeSchema, origin: java.lang.Object) -> SchemaBuilder:
        """
        Define the schema for a child attribute.
         
         
        
        If the attribute schema's name is empty, the given schema becomes the default attribute
        schema.
        
        :param TraceObjectSchema.AttributeSchema schema: the attribute schema to add to the definition
        :param java.lang.Object origin: optional, for diagnostics, an object describing the attribute schema's origin
        :return: this builder
        :rtype: SchemaBuilder
        """

    def addElementSchema(self, index: typing.Union[java.lang.String, str], schema: TraceObjectSchema.SchemaName, origin: java.lang.Object) -> SchemaBuilder:
        """
        Define the schema for a child element
        
        :param java.lang.String or str index: the index whose schema to define, or "" for the default
        :param TraceObjectSchema.SchemaName schema: the schema defining the element
        :param java.lang.Object origin: optional, for diagnostics, an object describing the element schema's origin
        :return: this builder
        :rtype: SchemaBuilder
        """

    def addInterface(self, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> SchemaBuilder:
        ...

    def build(self) -> TraceObjectSchema:
        ...

    def buildAndAdd(self) -> TraceObjectSchema:
        ...

    def buildAndReplace(self) -> TraceObjectSchema:
        ...

    def getAttributeSchema(self, name: typing.Union[java.lang.String, str]) -> TraceObjectSchema.AttributeSchema:
        ...

    def getAttributeSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.AttributeSchema]:
        ...

    def getDefaultAttributeSchema(self) -> TraceObjectSchema.AttributeSchema:
        ...

    def getDefaultElementSchema(self) -> TraceObjectSchema.SchemaName:
        ...

    def getElementSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.SchemaName]:
        ...

    def getInterfaces(self) -> java.util.Set[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]:
        ...

    def getType(self) -> java.lang.Class[typing.Any]:
        ...

    def isCanonicalContaineration(self) -> bool:
        ...

    def removeAttributeSchema(self, name: typing.Union[java.lang.String, str]) -> SchemaBuilder:
        ...

    def removeElementSchema(self, index: typing.Union[java.lang.String, str]) -> SchemaBuilder:
        ...

    def removeInterface(self, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> SchemaBuilder:
        ...

    def replaceAttributeAlias(self, from_: typing.Union[java.lang.String, str], to: typing.Union[java.lang.String, str], origin: java.lang.Object) -> SchemaBuilder:
        ...

    def replaceAttributeSchema(self, schema: TraceObjectSchema.AttributeSchema, origin: java.lang.Object) -> SchemaBuilder:
        ...

    def setCanonicalContainer(self, isCanonicalContainer: typing.Union[jpype.JBoolean, bool]) -> SchemaBuilder:
        ...

    def setDefaultAttributeSchema(self, defaultAttributeSchema: TraceObjectSchema.AttributeSchema) -> SchemaBuilder:
        ...

    def setDefaultElementSchema(self, defaultElementSchema: TraceObjectSchema.SchemaName) -> SchemaBuilder:
        ...

    def setInterfaces(self, interfaces: java.util.Set[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]) -> SchemaBuilder:
        ...

    def setType(self, type: java.lang.Class[typing.Any]) -> SchemaBuilder:
        ...

    @property
    def interfaces(self) -> java.util.Set[java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]]:
        ...

    @property
    def elementSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.SchemaName]:
        ...

    @property
    def defaultElementSchema(self) -> TraceObjectSchema.SchemaName:
        ...

    @property
    def type(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def attributeSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.AttributeSchema]:
        ...

    @property
    def canonicalContaineration(self) -> jpype.JBoolean:
        ...

    @property
    def defaultAttributeSchema(self) -> TraceObjectSchema.AttributeSchema:
        ...

    @property
    def attributeSchema(self) -> TraceObjectSchema.AttributeSchema:
        ...


class PrimitiveTraceObjectSchema(java.lang.Enum[PrimitiveTraceObjectSchema], TraceObjectSchema):
    """
    The schemas common to all contexts, as they describe the primitive and built-in types.
    """

    class MinimalSchemaContext(DefaultSchemaContext):

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[SchemaContext]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    ANY: typing.Final[PrimitiveTraceObjectSchema]
    """
    The top-most type descriptor
     
     
    
    The described value can be any primitive or a :obj:`TraceObject`.
    """

    OBJECT: typing.Final[PrimitiveTraceObjectSchema]
    """
    The least restrictive, but least informative object schema.
     
     
    
    This requires nothing more than the described value to be a :obj:`TraceObject`.
    """

    TYPE: typing.Final[PrimitiveTraceObjectSchema]
    VOID: typing.Final[PrimitiveTraceObjectSchema]
    """
    A type so restrictive nothing can satisfy it.
     
     
    
    This is how a schema specifies that a particular key is not allowed. It is commonly used as
    the default attribute when only certain enumerated attributes are allowed. It is also used as
    the type for the children of primitives, since primitives cannot have successors.
    """

    BOOL: typing.Final[PrimitiveTraceObjectSchema]
    BYTE: typing.Final[PrimitiveTraceObjectSchema]
    SHORT: typing.Final[PrimitiveTraceObjectSchema]
    INT: typing.Final[PrimitiveTraceObjectSchema]
    LONG: typing.Final[PrimitiveTraceObjectSchema]
    STRING: typing.Final[PrimitiveTraceObjectSchema]
    ADDRESS: typing.Final[PrimitiveTraceObjectSchema]
    RANGE: typing.Final[PrimitiveTraceObjectSchema]
    EXECUTION_STATE: typing.Final[PrimitiveTraceObjectSchema]
    MAP_PARAMETERS: typing.Final[PrimitiveTraceObjectSchema]
    CHAR: typing.Final[PrimitiveTraceObjectSchema]
    BOOL_ARR: typing.Final[PrimitiveTraceObjectSchema]
    BYTE_ARR: typing.Final[PrimitiveTraceObjectSchema]
    CHAR_ARR: typing.Final[PrimitiveTraceObjectSchema]
    SHORT_ARR: typing.Final[PrimitiveTraceObjectSchema]
    INT_ARR: typing.Final[PrimitiveTraceObjectSchema]
    LONG_ARR: typing.Final[PrimitiveTraceObjectSchema]
    STRING_ARR: typing.Final[PrimitiveTraceObjectSchema]

    def getTypes(self) -> java.util.List[java.lang.Class[typing.Any]]:
        ...

    @staticmethod
    def nameForPrimitive(cls: java.lang.Class[typing.Any]) -> TraceObjectSchema.SchemaName:
        """
        Get the name of a suitable enumerable schema for a given Java class
        
        :param java.lang.Class[typing.Any] cls: the class, which may or may no be the boxed form
        :return: the name or null if no schema is suitable
        :rtype: TraceObjectSchema.SchemaName
        
        .. seealso::
        
            | :obj:`.schemaForPrimitive(Class)`
        """

    @staticmethod
    def schemaForPrimitive(cls: java.lang.Class[typing.Any]) -> PrimitiveTraceObjectSchema:
        """
        Get a suitable schema for a given Java primitive class
         
         
        
        The term "primitive" here is used in terms of object schemas, not in terms of Java types.
        
        :param java.lang.Class[typing.Any] cls: the class, which may or may not be the boxed form
        :return: the schema or null if no schema is suitable
        :rtype: PrimitiveTraceObjectSchema
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PrimitiveTraceObjectSchema:
        ...

    @staticmethod
    def values() -> jpype.JArray[PrimitiveTraceObjectSchema]:
        ...

    @property
    def types(self) -> java.util.List[java.lang.Class[typing.Any]]:
        ...


class BadSchemaException(java.lang.IllegalStateException):
    """
    An exception that indicates a path or object does not provide a required interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Construct an exception with a human-readable message.
        
        :param java.lang.String or str message: the message
        """


class DefaultSchemaContext(SchemaContext):
    """
    The default implementation of a schema context
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, ctx: SchemaContext):
        ...

    @typing.overload
    def builder(self, schema: TraceObjectSchema) -> SchemaBuilder:
        ...

    @typing.overload
    def builder(self, name: TraceObjectSchema.SchemaName) -> SchemaBuilder:
        ...

    def modify(self, name: TraceObjectSchema.SchemaName) -> SchemaBuilder:
        ...

    def putSchema(self, schema: TraceObjectSchema):
        ...

    def replaceSchema(self, schema: TraceObjectSchema):
        ...


class DefaultTraceObjectSchema(TraceObjectSchema, java.lang.Comparable[DefaultTraceObjectSchema]):
    """
    The "type descriptor" of a :obj:`TraceObject`.
     
     
    
    These are typically loaded from XML anymore. See :obj:`XmlSchemaContext`. It typically consists
    of a list of expected attributes and their respective schemas, some of which may be
    :obj:`primitive <PrimitiveTraceObjectSchema>`; and the schema of elements, if this is a container.
    It is a bit more flexible than that, but that is the usual case. A schema may also specify one or
    more interfaces it supports. An interface typically requires certain attributes, but also implies
    some debugger-related behavior should be available via the target's command set. See
    :obj:`TraceObjectInterface` and its derivatives for information about each interface.
    """

    class DefaultAttributeSchema(TraceObjectSchema.AttributeSchema, java.lang.Comparable[DefaultTraceObjectSchema.DefaultAttributeSchema]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], schema: TraceObjectSchema.SchemaName, isRequired: typing.Union[jpype.JBoolean, bool], isFixed: typing.Union[jpype.JBoolean, bool], hidden: TraceObjectSchema.Hidden):
            ...


    @typing.type_check_only
    class AliasResolver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, schemas: collections.abc.Mapping, aliases: collections.abc.Mapping, defaultSchema: TraceObjectSchema.AttributeSchema):
            ...

        def resolveAliases(self) -> java.util.Map[java.lang.String, java.lang.String]:
            ...

        def resolveSchemas(self) -> java.util.Map[java.lang.String, TraceObjectSchema.AttributeSchema]:
            ...


    class_: typing.ClassVar[java.lang.Class]


class XmlSchemaContext(DefaultSchemaContext):
    """
    A :obj:`SchemaContext` decoded from XML.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def aliasToXml(alias: java.util.Map.Entry[java.lang.String, java.lang.String]) -> org.jdom.Element:
        ...

    @staticmethod
    def attributeSchemaToXml(as_: TraceObjectSchema.AttributeSchema) -> org.jdom.Element:
        ...

    @staticmethod
    def contextFromXml(contextElem: org.jdom.Element) -> XmlSchemaContext:
        ...

    @staticmethod
    def contextToXml(ctx: SchemaContext) -> org.jdom.Element:
        ...

    @staticmethod
    @typing.overload
    def deserialize(xml: typing.Union[java.lang.String, str]) -> XmlSchemaContext:
        ...

    @staticmethod
    @typing.overload
    def deserialize(xml: jpype.JArray[jpype.JByte]) -> XmlSchemaContext:
        ...

    @staticmethod
    @typing.overload
    def deserialize(file: jpype.protocol.SupportsPath) -> XmlSchemaContext:
        ...

    @staticmethod
    @typing.overload
    def deserialize(is_: java.io.InputStream) -> XmlSchemaContext:
        ...

    def name(self, name: typing.Union[java.lang.String, str]) -> TraceObjectSchema.SchemaName:
        ...

    def schemaFromXml(self, schemaElem: org.jdom.Element) -> TraceObjectSchema:
        ...

    @staticmethod
    def schemaToXml(schema: TraceObjectSchema) -> org.jdom.Element:
        ...

    @staticmethod
    def serialize(ctx: SchemaContext) -> str:
        ...


class SchemaContext(java.lang.Object):
    """
    A collection of related schemas all for the same trace or target
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAllSchemas(self) -> java.util.SequencedSet[TraceObjectSchema]:
        """
        Collect all schemas in this context
        
        :return: the set of all schemas
        :rtype: java.util.SequencedSet[TraceObjectSchema]
        """

    def getSchema(self, name: TraceObjectSchema.SchemaName) -> TraceObjectSchema:
        """
        Resolve a schema in this context by name
         
         
        
        Note that resolving a name generated outside of this context may have undefined results.
        
        :param TraceObjectSchema.SchemaName name: the schema's name
        :return: the schema or :obj:`PrimitiveTraceObjectSchema.ANY` if no schema by the given name
                exists
        :rtype: TraceObjectSchema
        """

    def getSchemaOrNull(self, name: TraceObjectSchema.SchemaName) -> TraceObjectSchema:
        """
        Resolve a schema in this context by name
        
        :param TraceObjectSchema.SchemaName name: the schema's name
        :return: the schema, or null if no schema by the given name exists
        :rtype: TraceObjectSchema
        """

    @property
    def schemaOrNull(self) -> TraceObjectSchema:
        ...

    @property
    def schema(self) -> TraceObjectSchema:
        ...

    @property
    def allSchemas(self) -> java.util.SequencedSet[TraceObjectSchema]:
        ...



__all__ = ["TraceObjectSchema", "SchemaBuilder", "PrimitiveTraceObjectSchema", "BadSchemaException", "DefaultSchemaContext", "DefaultTraceObjectSchema", "XmlSchemaContext", "SchemaContext"]
