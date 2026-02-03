from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import generic
import ghidra.framework.data
import ghidra.framework.model
import ghidra.program.database
import ghidra.program.model.address
import ghidra.util
import java.io # type: ignore
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.nio # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore
import java.util.function # type: ignore


E = typing.TypeVar("E")
FT = typing.TypeVar("FT")
K = typing.TypeVar("K")
OT = typing.TypeVar("OT")
R = typing.TypeVar("R")
T = typing.TypeVar("T")
U = typing.TypeVar("U")
VT = typing.TypeVar("VT")
W = typing.TypeVar("W")


class DBCachedObjectStoreSubMap(DBCachedObjectStoreMap[T], typing.Generic[T]):
    """
    This is the sub-ranged form of :obj:`DBCachedObjectStoreMap`
    
     
    
    For example, this can be obtained via ``store.asMap().subMap(...)``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[T], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, direction: DirectedIterator.Direction, keySpan: KeySpan):
        ...


class SchemaBuilder(java.lang.Object):
    """
    A builder for :obj:`Schema`
     
     
    
    Provides a more fluent syntax for creating table schemas. For example:
     
     
    new Schema(1, StringField.class, "UUID",
        new Class[] { StringField.class, IntField.class }, new String[] { "Name", "Flags" },
        new int[] { 1 });
     
     
     
    
    Can be expressed using the builder:
     
     
    new SchemaBuilder().keyField("UUID", StringField.class)
            .field("Name", StringField.class)
            .field("Flags", IntField.class, true)
            .build();
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def build(self) -> db.Schema:
        ...

    @typing.overload
    def field(self, name: typing.Union[java.lang.String, str], cls: java.lang.Class[db.Field], sparse: typing.Union[jpype.JBoolean, bool]) -> SchemaBuilder:
        ...

    @typing.overload
    def field(self, name: typing.Union[java.lang.String, str], cls: java.lang.Class[db.Field]) -> SchemaBuilder:
        ...

    def fieldCount(self) -> int:
        ...

    @staticmethod
    def getColumnIndex(schema: db.Schema, name: typing.Union[java.lang.String, str]) -> int:
        ...

    def keyField(self, name: typing.Union[java.lang.String, str], cls: java.lang.Class[db.Field]) -> SchemaBuilder:
        ...

    @staticmethod
    def toIntArray(list: java.util.List[java.lang.Integer]) -> jpype.JArray[jpype.JInt]:
        ...

    def version(self, version: typing.Union[jpype.JInt, int]) -> SchemaBuilder:
        ...


class BackwardLongKeyIterator(AbstractDirectedLongKeyIterator):
    """
    A wrapper of :obj:`DBLongIterator` that runs it backward and implements
    :obj:`DirectedLongKeyIterator`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: db.DBLongIterator):
        ...


class DBCachedObjectStoreFactory(java.lang.Object):
    """
    A factory for creating object stores for classes extending :obj:`DBAnnotatedObject`
     
     
    
    See :obj:`DBAnnotatedObject` for more documentation, including an example object definition. To
    create a store, e.g., for ``Person``:
     
    ``interface MyDomainObject {    Person createPerson(String name, String address);    Person getPerson(long id);    Collection<? extends Person> getPeopleNamed(String name);}public class DBMyDomainObject extends DBCachedDomainObjectAdapter implements MyDomainObject {    private final DBCachedObjectStoreFactory factory;    private final DBCachedObjectStore<DBPerson> people;    private final DBCachedObjectIndex<String, DBPerson> peopleByName;    public DBMyDomainObject() { // Constructor parameters elided        // super() invocation elided        factory = new DBCachedObjectStoreFactory(this);        try {            people = factory.getOrCreateCachedStore(DBPerson.TABLE_NAME, DBPerson.class,                DBPerson::new, false);            peopleByName = people.getIndex(String.class, DBPerson.NAME_COLUMN);        }        catch (VersionException e) {            // ...        }        catch (IOException e) {            // ...        }    }    @Override    public Person createPerson(String name, String address) {        // Locking details elided        DBPerson person = people.create();        person.set(name, address);        return person;    }    @Override    public Person getPerson(int id) {        // Locking details elided        return people.getAt(id);    }    @Override    public Collection<Person> getPeopleNamed(String name) {        // Locking details elided        return peopleByName.get(name);    }}``
     
     
    
    The factory manages tables on behalf of the domain object, so it is typically the first thing
    constructed. In practice, complex domain objects should be composed of several managers, each of
    which constructs its own stores, but for simplicity in this example, we construct the people
    store in the domain object. This will check the schema and could throw a
    :obj:`VersionException`. Typically, immediately after constructing the store, all desired
    indexes of the store are retrieved. The domain object then provides API methods for creating and
    retrieving people. Providing direct API client access to the store from a domain object is highly
    discouraged.
    
    
    .. admonition:: Implementation Note
    
        This class bears the responsibility of processing the :obj:`DBAnnotatedField`,
        :obj:`DBAnnotatedColumn`, and :obj:`DBAnnotatedObjectInfo` annotations. The relevant
        entry point is {:meth:`buildInfo(Class) <.buildInfo>`. It creates a :obj:`TableInfo` for the given
        class, which builds the schema for creating the :obj:`Table` that backs an object
        store for that class.
    """

    class RecAddress(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, spaceId: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JLong, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromAddress(address: ghidra.program.model.address.Address) -> DBCachedObjectStoreFactory.RecAddress:
            ...

        def hashCode(self) -> int:
            ...

        def offset(self) -> int:
            ...

        def spaceId(self) -> int:
            ...

        def toAddress(self, factory: ghidra.program.model.address.AddressFactory) -> ghidra.program.model.address.Address:
            ...

        def toString(self) -> str:
            ...


    class RecRange(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, spaceId: typing.Union[jpype.JInt, int], min: typing.Union[jpype.JLong, int], max: typing.Union[jpype.JLong, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromRange(range: ghidra.program.model.address.AddressRange) -> DBCachedObjectStoreFactory.RecRange:
            ...

        def hashCode(self) -> int:
            ...

        def max(self) -> int:
            ...

        def min(self) -> int:
            ...

        def spaceId(self) -> int:
            ...

        def toRange(self, factory: ghidra.program.model.address.AddressFactory) -> ghidra.program.model.address.AddressRange:
            ...

        def toString(self) -> str:
            ...


    class DBFieldCodec(java.lang.Object, typing.Generic[VT, OT, FT]):
        """
        A codec for encoding alternative data types
        
         
        
        The database framework supports limited types of fields, each capable for storing a specific
        Java data type. A simple codec is provided for "encoding" each of the supported types into
        its corresponding :obj:`db.Field` type. For other types, additional custom codecs must be
        implemented. Custom codecs must be explicitly selected using the
        :meth:`DBAnnotatedField.codec() <DBAnnotatedField.codec>` attribute.
         
         
        
        **NOTE:** When changing the implementation of a codec, keep in mind whether or not it
        implies a change to the schema of tables that use the codec. If it does, their schema
        versions, i.e., :meth:`DBAnnotatedObjectInfo.version() <DBAnnotatedObjectInfo.version>` should be incremented and
        considerations made for supporting upgrades.
         
         
        
        In some cases, the codec may require context information from the containing object. This is
        facilitated via the :obj:`OT` type parameter. If no additional context is required,
        :obj:`DBAnnotatedObject` is sufficient. If context is required, then additional interfaces
        can be required via type intersection:
         
        ``public interface MyContext {    // ...}public interface ContextProvider {    MyContext getContext();}public static class MyDBFieldCodec<OT extends DBAnnotatedObject & ContextProvider> extends        AbstractDBFieldCodec<MyType, OT, BinaryField> {    public MyDBFieldCodec(Class<OT> objectType, Field field, int column) {        super(MyType.class, objectType, BinaryField.class, field, column);    }    @Override    protected void doStore(OT obj, DBRecord record) {        MyContext ctx = obj.getContext();        // ...    }    // ...}``
         
         
        
        Note that this implementation uses :obj:`AbstractDBFieldCodec`, which is highly recommended.
        Whether or not the abstract codec is used, the constructor must have the signature
        ``(Class<OT>, Field, int)``, which are the containing object's actual type, the field of
        the Java class whose values to encode, and the record column number into which to store those
        encoded values. The type variables :obj:`VT` and :obj:`FT` of the codec indicate it can
        encode values of type ``MyType`` into a byte array for storage into a
        :obj:`BinaryField`. See :obj:`ByteDBFieldCodec` for the simplest example with actual
        encoding and decoding implementations. To use the example codec in an object:
         
        ``@DBAnnotatedObjectInfo(version = 1)public static class SomeObject extends DBAnnotatedObject implements ContextProvider {    static final String MY_COLUMN_NAME = "My";    @DBAnnotatedColumn(MY_COLUMN_NAME)    static DBObjectColumn MY_COLUMN;    @DBAnnotatedField(column = MY_COLUMN_NAME, codec = MyDBFieldCodec.class)    private MyType my;    // ...    @Override    public MyContext getContext() {        // ...    }}``
         
         
        
        Notice that ``SomeObject`` must implement ``ContextProvider``. This restriction is
        checked at runtime when the object store is created, but a compile-time annotation processor
        can check this restriction sooner. This has been implemented, at least in part, in the
        ``AnnotationProcessor`` project. It is recommended that at most one additional interface
        is required in by :obj:`OT`. If multiple contexts are required, consider declaring an
        interface that extends the multiple required interfaces. Alternatively, consider a new
        interface that provides one composite context.
        """

        class_: typing.ClassVar[java.lang.Class]

        def encodeField(self, value: VT) -> FT:
            """
            Encode the given value into a new field
            
            :param VT value: the value
            :return: the field with the encoded value
            :rtype: FT
            """

        def getFieldType(self) -> java.lang.Class[FT]:
            """
            Get the type of field storing the values
            
            :return: the field type
            :rtype: java.lang.Class[FT]
            """

        def getObjectType(self) -> java.lang.Class[OT]:
            """
            Get the upper bound on objects with fields using this codec
            
            :return: the upper bound
            :rtype: java.lang.Class[OT]
            """

        def getValue(self, obj: OT) -> VT:
            """
            Get the value from the object
            
            :param OT obj: the source object
            :return: the value
            :rtype: VT
            """

        def getValueType(self) -> java.lang.Class[VT]:
            """
            Get the type of values encoded and decoded
            
            :return: the value type
            :rtype: java.lang.Class[VT]
            """

        def load(self, obj: OT, record: db.DBRecord):
            """
            Decode the field from the given record into the given object
            
            :param OT obj: the destination object
            :param db.DBRecord record: the source record
            """

        @typing.overload
        def store(self, obj: OT, record: db.DBRecord):
            """
            Encode the field from the given object into the given record
            
            :param OT obj: the source object
            :param db.DBRecord record: the destination record
            """

        @typing.overload
        def store(self, value: VT, f: FT):
            """
            Encode the given field value into the given field
            
            :param VT value: the value
            :param FT f: the field
            """

        @property
        def valueType(self) -> java.lang.Class[VT]:
            ...

        @property
        def value(self) -> VT:
            ...

        @property
        def fieldType(self) -> java.lang.Class[FT]:
            ...

        @property
        def objectType(self) -> java.lang.Class[OT]:
            ...


    class AbstractDBFieldCodec(DBCachedObjectStoreFactory.DBFieldCodec[VT, OT, FT], typing.Generic[VT, OT, FT]):
        """
        An abstract implementation of :obj:`DBFieldCodec`
         
         
        
        This reduces the implementation burden to :meth:`doLoad(DBAnnotatedObject, DBRecord) <.doLoad>`,
        :meth:`doStore(DBAnnotatedObject, DBRecord) <.doStore>`, and :meth:`store(Object, db.Field) <.store>`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, valueType: java.lang.Class[VT], objectType: java.lang.Class[OT], fieldType: java.lang.Class[FT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            """
            Construct a codec
            
            :param java.lang.Class[VT] valueType: 
            :param java.lang.Class[OT] objectType: 
            :param java.lang.Class[FT] fieldType: 
            :param java.lang.reflect.Field field: 
            :param jpype.JInt or int column:
            """


    class BooleanDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[java.lang.Boolean, OT, db.BooleanField], typing.Generic[OT]):
        """
        The built-in codec for ``boolean``
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class ByteDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[java.lang.Byte, OT, db.ByteField], typing.Generic[OT]):
        """
        The built-in codec for ``byte``
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class ShortDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[java.lang.Short, OT, db.ShortField], typing.Generic[OT]):
        """
        The built-in codec for ``short``
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class IntDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[java.lang.Integer, OT, db.IntField], typing.Generic[OT]):
        """
        The built-in codec for ``int``
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class LongDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[java.lang.Long, OT, db.LongField], typing.Generic[OT]):
        """
        The built-in codec for ``long``
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class StringDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[java.lang.String, OT, db.StringField], typing.Generic[OT]):
        """
        The built-in codec for :obj:`String`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class ByteArrayDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[jpype.JArray[jpype.JByte], OT, db.BinaryField], typing.Generic[OT]):
        """
        The built-in codec for ``byte[]``
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class LongArrayDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[jpype.JArray[jpype.JLong], OT, db.BinaryField], typing.Generic[OT]):
        """
        The built-in codec for ``long[]``
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class EnumDBByteFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[E, OT, db.ByteField], typing.Generic[OT, E]):
        """
        The built-in codec for :obj:`Enum`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    class PrimitiveCodec(java.lang.Object, typing.Generic[T]):
        """
        Codec for a primitive type
         
         
        
        This is used by :obj:`VariantDBFieldCodec` to encode primitive values. Sadly, the existing
        primitive field codecs cannot be used, since they write to fields directly. All these encode
        into byte buffers, since the variant codec uses :obj:`BinaryField`.
        """

        class AbstractPrimitiveCodec(DBCachedObjectStoreFactory.PrimitiveCodec[T], typing.Generic[T]):
            """
            An abstract implementation of :obj:`PrimitiveCodec`
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, valueClass: java.lang.Class[T]):
                ...


        class SimplePrimitiveCodec(DBCachedObjectStoreFactory.PrimitiveCodec.AbstractPrimitiveCodec[T], typing.Generic[T]):
            """
            A implementation of :obj:`PrimitiveCodec` from lambdas or method references
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, valueClass: java.lang.Class[T], decode: java.util.function.Function[java.nio.ByteBuffer, T], encode: java.util.function.BiConsumer[java.nio.ByteBuffer, T]):
                ...


        class ArrayPrimitiveCodec(DBCachedObjectStoreFactory.PrimitiveCodec.AbstractPrimitiveCodec[T], typing.Generic[E, T]):
            """
            An implementation of an array codec, using its element codec, where elements can be
            primitives
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, valueClass: java.lang.Class[T], elemCodec: DBCachedObjectStoreFactory.PrimitiveCodec[E]):
                ...


        class ArrayObjectCodec(DBCachedObjectStoreFactory.PrimitiveCodec.ArrayPrimitiveCodec[E, jpype.JArray[E]], typing.Generic[E]):
            """
            An implementation of an array codec, using its element codec, where elements are objects
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, elemCodec: DBCachedObjectStoreFactory.PrimitiveCodec[E]):
                ...


        class LengthBoundCodec(DBCachedObjectStoreFactory.PrimitiveCodec.AbstractPrimitiveCodec[T], typing.Generic[T]):
            """
            A codec which encodes length-value, using the (unbounded) codec for value
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, unbounded: DBCachedObjectStoreFactory.PrimitiveCodec[T]):
                ...


        class_: typing.ClassVar[java.lang.Class]
        BOOL: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[java.lang.Boolean]]
        """
        Codec for ``boolean``
        """

        BYTE: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[java.lang.Byte]]
        """
        Codec for ``byte``
        """

        CHAR: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[java.lang.Character]]
        """
        Codec for ``char``
        """

        SHORT: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[java.lang.Short]]
        """
        Codec for ``short``
        """

        INT: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[java.lang.Integer]]
        """
        Codec for ``int``
        """

        LONG: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[java.lang.Long]]
        """
        Codec for ``long``
        """

        STRING: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[java.lang.String]]
        """
        Codec for :obj:`String`
        """

        BOOL_ARR: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[jpype.JArray[jpype.JBoolean]]]
        """
        Codec for ``boolean[]``
        """

        BYTE_ARR: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[jpype.JArray[jpype.JByte]]]
        """
        Codec for ``byte[]``
        """

        CHAR_ARR: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[jpype.JArray[jpype.JChar]]]
        """
        Codec for ``char[]``
        """

        SHORT_ARR: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[jpype.JArray[jpype.JShort]]]
        """
        Codec for ``short[]``
        """

        INT_ARR: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[jpype.JArray[jpype.JInt]]]
        """
        Codec for ``int[]``
        """

        LONG_ARR: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[jpype.JArray[jpype.JLong]]]
        """
        Codec for ``long[]``
        """

        STRING_ARR: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[jpype.JArray[java.lang.String]]]
        """
        Codec for ``String[]``
        """

        ADDRESS: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[DBCachedObjectStoreFactory.RecAddress]]
        RANGE: typing.Final[DBCachedObjectStoreFactory.PrimitiveCodec[DBCachedObjectStoreFactory.RecRange]]
        CODECS_BY_SELECTOR: typing.Final[java.util.Map[java.lang.Byte, DBCachedObjectStoreFactory.PrimitiveCodec[typing.Any]]]
        CODECS_BY_CLASS: typing.Final[java.util.Map[java.lang.Class[typing.Any], DBCachedObjectStoreFactory.PrimitiveCodec[typing.Any]]]

        def decode(self, buffer: java.nio.ByteBuffer) -> T:
            """
            Decode the value from the given buffer
            
            :param java.nio.ByteBuffer buffer: the source buffer
            :return: the value
            :rtype: T
            """

        def encode(self, buffer: java.nio.ByteBuffer, value: T):
            """
            Encode the value into the given buffer
            
            :param java.nio.ByteBuffer buffer: the destination buffer
            :param T value: the value
            """

        @staticmethod
        @typing.overload
        def getCodec(cls: java.lang.Class[T]) -> DBCachedObjectStoreFactory.PrimitiveCodec[T]:
            """
            Get the codec for the given type
            
            :param T: the type:param java.lang.Class[T] cls: the class describing :obj:`T`
            :return: the codec
            :rtype: DBCachedObjectStoreFactory.PrimitiveCodec[T]
            :raises IllegalArgumentException: if the type is not supported
            """

        @staticmethod
        @typing.overload
        def getCodec(sel: typing.Union[jpype.JByte, int]) -> DBCachedObjectStoreFactory.PrimitiveCodec[typing.Any]:
            """
            Get the codec for the given selector
            
            :param jpype.JByte or int sel: the selector
            :return: the codec
            :rtype: DBCachedObjectStoreFactory.PrimitiveCodec[typing.Any]
            :raises IllegalArgumentException: if the selector is unknown
            """

        def getSelector(self) -> int:
            """
            A byte value which identifies this codec's type as the selected type
            
            :return: the selector
            :rtype: int
            """

        def getValueClass(self) -> java.lang.Class[T]:
            """
            The class describing :obj:`T`
            
            :return: the class
            :rtype: java.lang.Class[T]
            """

        @property
        def selector(self) -> jpype.JByte:
            ...

        @property
        def valueClass(self) -> java.lang.Class[T]:
            ...


    class VariantDBFieldCodec(DBCachedObjectStoreFactory.AbstractDBFieldCodec[java.lang.Object, OT, db.BinaryField], typing.Generic[OT]):
        """
        A custom codec for field of "variant" type
         
         
        
        This is suitable for use on fields of type :obj:`Object`; however, only certain types can
        actually be encoded. The encoding uses a 1-byte type selector followed by the byte-array
        encoded value.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class TableInfo(java.lang.Object, typing.Generic[OT]):
        """
        The information needed to construct a :obj:`Table` and store objects into it
        """

        class_: typing.ClassVar[java.lang.Class]
        schema: typing.Final[db.Schema]
        indexColumns: typing.Final[jpype.JArray[jpype.JInt]]
        codecs: typing.Final[java.util.ArrayList[DBCachedObjectStoreFactory.DBFieldCodec[typing.Any, OT, typing.Any]]]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, adapter: DBCachedDomainObjectAdapter):
        """
        Construct an object store factory
        
        :param DBCachedDomainObjectAdapter adapter: the object whose tables to manage
        """

    def getOrCreateCachedStore(self, tableName: typing.Union[java.lang.String, str], cls: java.lang.Class[T], factory: DBAnnotatedObjectFactory[T], upgradable: typing.Union[jpype.JBoolean, bool]) -> DBCachedObjectStore[T]:
        """
        Get or create a cached store of objects of the given class
        
        :param T: the type of objects in the store:param java.lang.String or str tableName: the table name
        :param java.lang.Class[T] cls: the class describing :obj:`T`
        :param DBAnnotatedObjectFactory[T] factory: the object's constructor, usually a method reference or lambda
        :param jpype.JBoolean or bool upgradable: true if :obj:`VersionException`s should be marked upgradable when an
                    existing table's version is earlier than expected
        :return: the table
        :rtype: DBCachedObjectStore[T]
        :raises IOException: if there's an issue accessing the database
        :raises VersionException: if an existing table's version does not match that expected
        """

    def getOrCreateTable(self, name: typing.Union[java.lang.String, str], cls: java.lang.Class[DBAnnotatedObject], upgradable: typing.Union[jpype.JBoolean, bool]) -> db.Table:
        """
        Get or create the table needed to store objects of the given class
         
         
        
        See :meth:`getOrCreateCachedStore(String, Class, DBAnnotatedObjectFactory, boolean) <.getOrCreateCachedStore>`
        
        :param java.lang.String or str name: the table name
        :param java.lang.Class[DBAnnotatedObject] cls: the type of objects to store
        :param jpype.JBoolean or bool upgradable: true if :obj:`VersionException`s should be marked upgradable when an
                    existing table's version is earlier than expected
        :return: the table
        :rtype: db.Table
        :raises IOException: if there's an issue accessing the database
        :raises VersionException: if an existing table's version does not match that expected
        """


class DBAnnotatedObjectFactory(java.lang.Object, typing.Generic[T]):
    """
    Needed by a :obj:`DBCachedObjectStore` to describe how to construct the objects it manages
    """

    class_: typing.ClassVar[java.lang.Class]

    def create(self, store: DBCachedObjectStore[T], record: db.DBRecord) -> T:
        ...


class ObjectKey(java.lang.Comparable[ObjectKey]):
    """
    An opaque handle uniquely identifying a database-backed object
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: db.Table, key: typing.Union[jpype.JLong, int]):
        ...


class DBCachedDomainObjectAdapter(ghidra.framework.data.DBDomainObjectSupport):
    """
    A domain object that can use :obj:`DBCachedObjectStoreFactory`.
    
     
    
    Technically, this only introduces a read-write lock to the domain object. The
    :obj:`DBCachedObjectStoreFactory` and related require this read-write lock. Sadly, this idea
    didn't pan out, and that read-write lock is just a degenerate wrapper of the Ghidra
    :obj:`ghidra.util.Lock`, which is not a read-write lock. This class may disappear.
    """

    @typing.type_check_only
    class SwingAwareReadWriteLock(java.util.concurrent.locks.ReentrantReadWriteLock):

        @typing.type_check_only
        class SwingAwareReadLock(java.util.concurrent.locks.ReentrantReadWriteLock.ReadLock):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class SwingAwareWriteLock(java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GhidraLockWrappingLock(java.util.concurrent.locks.Lock):
        """
        Adapts a :obj:`ghidra.util.Lock` to the :obj:`Lock` interface
         
         
        
        Not all operations are supported. In particular, no :meth:`lockInterruptibly() <.lockInterruptibly>`,
        :meth:`tryLock(long,TimeUnit) <.tryLock>`, nor :meth:`newCondition() <.newCondition>`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, ghidraLock: ghidra.util.Lock):
            ...


    @typing.type_check_only
    class GhidraLockWrappingRWLock(java.util.concurrent.locks.ReadWriteLock):
        """
        Not a true read-write lock, but adapts a :obj:`ghidra.util.Lock` to the
        :obj:`ReadWriteLock` interface. The read lock and the write lock are just the same lock
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, ghidraLock: ghidra.util.Lock):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getReadWriteLock(self) -> java.util.concurrent.locks.ReadWriteLock:
        """
        Get the "read-write" lock
        
        :return: the lock
        :rtype: java.util.concurrent.locks.ReadWriteLock
        """

    @property
    def readWriteLock(self) -> java.util.concurrent.locks.ReadWriteLock:
        ...


class DBSynchronizedIterator(java.util.Iterator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iterator: java.util.Iterator[T], lock: java.util.concurrent.locks.ReadWriteLock):
        ...


class DBObjectColumn(java.lang.Object):
    """
    An opaque handle to the column backing an object field
     
     
    
    Each should be declared as a static field of the same class whose field it describes, probably
    with package-only access. Each must also be annotated with :obj:`DBAnnotatedColumn`. For an
    example, see the documentation of :obj:`DBAnnotatedObject`. The annotated field receives its
    value the first time a store is created for the containing class. Until then, it is
    uninitialized.
    """

    class_: typing.ClassVar[java.lang.Class]


class DBCachedObjectStoreFoundKeysValueCollection(java.util.Collection[T], typing.Generic[T]):
    """
    This provides the implementation of :meth:`DBCachedObjectIndex.get(Object) <DBCachedObjectIndex.get>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[T], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, keys: jpype.JArray[db.Field]):
        ...


class DirectedRecordIterator(DirectedIterator[db.DBRecord]):
    """
    An iterator over records of a table
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[DirectedRecordIterator]

    @staticmethod
    def getIndexIterator(table: db.Table, columnIndex: typing.Union[jpype.JInt, int], fieldSpan: FieldSpan, direction: DirectedIterator.Direction) -> DirectedRecordIterator:
        """
        Get an iterator over the table using a given index, restricted to the given range of values,
        in the given direction
        
        :param db.Table table: the table
        :param jpype.JInt or int columnIndex: the column number of the index
        :param FieldSpan fieldSpan: the limited range
        :param DirectedIterator.Direction direction: the direction
        :return: the iterator
        :rtype: DirectedRecordIterator
        :raises IOException: if the table cannot be read
        """

    @staticmethod
    def getIterator(table: db.Table, keySpan: KeySpan, direction: DirectedIterator.Direction) -> DirectedRecordIterator:
        """
        Get an iterator over the table, restricted to the given range of keys, in the given direction
        
        :param db.Table table: the table
        :param KeySpan keySpan: the limited range
        :param DirectedIterator.Direction direction: the direction
        :return: the iterator
        :rtype: DirectedRecordIterator
        :raises IOException: if the table cannot be read
        """


class DBCachedObjectIndex(java.lang.Object, typing.Generic[K, T]):
    """
    An index on a field in a :obj:`DBCachedObjectStore`
     
     
    
    This provides access to a table index backing the store, allowing clients to retrieve objects
    having specified field values. Its methods are inspired by :obj:`NavigableMap`; however, its
    semantics permit duplicate keys, so this cannot implement it in the manner desired.
    
    
    .. admonition:: Implementation Note
    
        This seems rife for implementing a collection interface, but each defies implementation
        on our DB framework. Probably because it's better understood as a multimap, which is
        not a standard Java collection. Guava's proved too burdensome to implement. We never
        tried Apache's.
    """

    class_: typing.ClassVar[java.lang.Class]

    def ceilingEntry(self, key: K) -> java.util.Map.Entry[K, T]:
        """
        Get the entry at or after the given key
        
        :param K key: the key
        :return: the entry of the same or next key, or null
        :rtype: java.util.Map.Entry[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def ceilingKey(self, key: K) -> K:
        """
        Get the key at or after the given key
        
        :param K key: the key
        :return: the same or next key, or null
        :rtype: K
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def ceilingValue(self, key: K) -> T:
        """
        Get the value at or after the given key
        
        :param K key: the key
        :return: the value of the same or next key, or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def containsKey(self, key: K) -> bool:
        """
        Check if there is any object having the given value for its indexed field
         
         
        
        This method is more efficient than using ``get(key).isEmpty()``, since it need only find
        one match, whereas :meth:`get(Object) <.get>` will retrieve every match. Granted, it doesn't make
        sense to immediately call :meth:`get(Object) <.get>` after :meth:`containsKey(Object) <.containsKey>` returns
        true.
        """

    def containsValue(self, value: T) -> bool:
        """
        Check if the given object is in the index
         
         
        
        Except for sub-ranged indexes, this is equivalent to checking if the object is in the store.
        For a sub-ranged index, the value of its indexed field must fall within the restricted range.
        
        :param T value: the object
        :return: true if it appears in this (sub-ranged) index.
        :rtype: bool
        """

    def countKey(self, key: K) -> int:
        """
        Count the number of objects whose indexed field has the given value
        
        :param K key: the value
        :return: the count
        :rtype: int
        """

    def descending(self) -> DBCachedObjectIndex[K, T]:
        """
        Get a reversed view of this index
         
         
        
        This affects iteration as well as all the navigation and sub-ranging methods. E.g.,
        :meth:`lowerKey(Object) <.lowerKey>` in the reversed view will behave like :meth:`higherKey(Object) <.higherKey>` in
        the original. In other words, the returned index is equivalent to the original, but with a
        negated comparator. Calling :meth:`descending() <.descending>` on the returned view will return a view
        equivalent to the original.
        
        :return: the reversed view
        :rtype: DBCachedObjectIndex[K, T]
        """

    def entries(self) -> java.lang.Iterable[java.util.Map.Entry[K, T]]:
        """
        Iterate over the entries as ordered by the index
         
         
        
        Each entry is a key-value value where the "key" is the value of the indexed field, and the
        "value" is the object.
        
        :return: the iterator
        :rtype: java.lang.Iterable[java.util.Map.Entry[K, T]]
        """

    def firstEntry(self) -> java.util.Map.Entry[K, T]:
        """
        Get the first entry in the index
        
        :return: the first key, or null
        :rtype: java.util.Map.Entry[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def firstKey(self) -> K:
        """
        Get the first key in the index
        
        :return: the first key, or null
        :rtype: K
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def firstValue(self) -> T:
        """
        Get the first object in the index
        
        :return: the first object, or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def floorEntry(self, key: K) -> java.util.Map.Entry[K, T]:
        """
        Get the entry at or before the given key
        
        :param K key: the key
        :return: the entry of the same or previous key, or null
        :rtype: java.util.Map.Entry[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def floorKey(self, key: K) -> K:
        """
        Get the key at or before the given key
        
        :param K key: the key
        :return: the same or previous key, or null
        :rtype: K
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def floorValue(self, key: K) -> T:
        """
        Get the value at or before the given key
        
        :param K key: the key
        :return: the value of the same or previous key, or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def get(self, key: K) -> java.util.Collection[T]:
        """
        Get the objects having the given value in the indexed field
         
         
        
        **NOTE:** The objects' primary keys are retrieved immediately, but the returned collection
        loads each requested object lazily. This may have timing implications. If the returned
        collection is used at a later time, the keys found may no longer be valid, and even if they
        are, the indexed field may no longer have the requested value when retrieved. See
        :meth:`getLazily(Object) <.getLazily>`.
        
        :param K key: the value
        :return: the collection of objects
        :rtype: java.util.Collection[T]
        """

    def getLazily(self, key: K) -> java.util.Collection[T]:
        """
        Get the objects having the given value in the index field
         
         
        
        This differs from :meth:`get(Object) <.get>` in that the keys are retrieved each time the
        collection is iterated. The returned collection can be saved and used later. The iterator
        itself still has a fixed set of keys, though, so clients should use it and discard it in a
        timely fashion, and/or while holding the domain object's lock.
        
        :param K key: the value
        :return: the lazy collection of objects
        :rtype: java.util.Collection[T]
        """

    def getOne(self, value: K) -> T:
        """
        Get a unique object having the given value in the index field
         
         
        
        Clients should use this method when the index behaves like a map, rather than a multimap. It
        is the client's responsibility to ensure that duplicate values do not exist in the indexed
        column.
        
        :param K value: the value
        :return: the object, if found, or null
        :rtype: T
        :raises IllegalStateException: if the object is not unique
        """

    def head(self, to: K, toInclusive: typing.Union[jpype.JBoolean, bool]) -> DBCachedObjectIndex[K, T]:
        """
        Get a sub-ranged view of this index, limited to entries whose keys occur before the given key
        
        :param K to: the upper bound
        :param jpype.JBoolean or bool toInclusive: whether the upper bound is included in the restricted view
        :return: the restricted view
        :rtype: DBCachedObjectIndex[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def higherEntry(self, key: K) -> java.util.Map.Entry[K, T]:
        """
        Get the entry after the given key
        
        :param K key: the key
        :return: the entry of the next key, or null
        :rtype: java.util.Map.Entry[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def higherKey(self, key: K) -> K:
        """
        Get the key after the given key
        
        :param K key: the key
        :return: the same or next key, or null
        :rtype: K
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def higherValue(self, key: K) -> T:
        """
        Get the value after the given key
        
        :param K key: the key
        :return: the value of the next key, or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def isEmpty(self) -> bool:
        """
        Check if this index is empty
         
         
        
        Except for sub-ranged indexes, this is equivalent to checking if the object store is empty.
        For sub-ranged indexes, this checks if the store contains any object whose value for the
        indexed field falls within the restricted range.
        
        :return: true if empty
        :rtype: bool
        """

    def keys(self) -> java.lang.Iterable[K]:
        """
        Iterate over the values of the indexed column, in order
         
         
        
        Despite being called keys, the values may not be unique
        
        :return: the iterator
        :rtype: java.lang.Iterable[K]
        """

    def lastEntry(self) -> java.util.Map.Entry[K, T]:
        """
        Get the last entry in the index
        
        :return: the first key, or null
        :rtype: java.util.Map.Entry[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def lastKey(self) -> K:
        """
        Get the last key in the index
        
        :return: the first key, or null
        :rtype: K
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def lastValue(self) -> T:
        """
        Get the last object in the index
        
        :return: the first object, or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def lowerEntry(self, key: K) -> java.util.Map.Entry[K, T]:
        """
        Get the entry before the given key
        
        :param K key: the key
        :return: the entry of the previous key, or null
        :rtype: java.util.Map.Entry[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def lowerKey(self, key: K) -> K:
        """
        Get the key before the given key
        
        :param K key: the key
        :return: the previous key, or null
        :rtype: K
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def lowerValue(self, key: K) -> T:
        """
        Get the value before the given key
        
        :param K key: the key
        :return: the value of the previous key, or null
        :rtype: T
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def sub(self, from_: K, fromInclusive: typing.Union[jpype.JBoolean, bool], to: K, toInclusive: typing.Union[jpype.JBoolean, bool]) -> DBCachedObjectIndex[K, T]:
        """
        Get a sub-ranged view of this index
        
        :param K from: the lower bound
        :param jpype.JBoolean or bool fromInclusive: whether the lower bound is included in the restricted view
        :param K to: the upper bound
        :param jpype.JBoolean or bool toInclusive: whether the upper bound is included in the restricted view
        :return: the restricted view
        :rtype: DBCachedObjectIndex[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        """

    def tail(self, from_: K, fromInclusive: typing.Union[jpype.JBoolean, bool]) -> DBCachedObjectIndex[K, T]:
        """
        Get a sub-ranged view of this index, limited to entries whose keys occur after the given key
        
        :param K from: the lower bound
        :param jpype.JBoolean or bool fromInclusive: whether the lower bound is included in the restricted view
        :return: the restricted view
        :rtype: DBCachedObjectIndex[K, T]
        
        .. seealso::
        
            | :obj:`.descending()`
        
            | :obj:`.sub(Object, boolean, Object, boolean)`
        """

    def values(self) -> java.lang.Iterable[T]:
        """
        Iterate over the objects as ordered by the index
        
        :return: the iterator
        :rtype: java.lang.Iterable[T]
        """

    @property
    def one(self) -> T:
        ...

    @property
    def lazily(self) -> java.util.Collection[T]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class AbstractDirectedLongKeyIterator(DirectedLongKeyIterator):
    """
    An abstract implementation of :obj:`DirectedLongKeyIterator`
     
     
    
    Essentially, this just wraps a :obj:`DBLongIterator`, but imposes and encapsulates its
    direction.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: db.DBLongIterator):
        """
        Wrap the given iterator
        
        :param db.DBLongIterator it: the iterator
        """


class DBBufferOutputStream(java.io.OutputStream):
    """
    An output stream backed by a database chained buffer
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, buffer: db.DBBuffer):
        ...

    @typing.overload
    def __init__(self, buffer: db.DBBuffer, increment: typing.Union[jpype.JInt, int]):
        ...


class DBSynchronizedCollection(java.util.Collection[E], typing.Generic[E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: collections.abc.Sequence, lock: java.util.concurrent.locks.ReadWriteLock):
        ...


class DBCachedObjectStoreValueCollection(java.util.Collection[T], typing.Generic[T]):
    """
    This provides the implementation of :meth:`Map.values() <Map.values>` for :meth:`DBCachedObjectStore.asMap() <DBCachedObjectStore.asMap>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[T], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, direction: DirectedIterator.Direction):
        ...


class KeySpan(generic.Span[java.lang.Long, KeySpan]):
    """
    An interval of database (primary) keys
    """

    class Domain(generic.Span.Domain[java.lang.Long, KeySpan]):
        """
        The domain of keys
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class Empty(KeySpan, generic.Span.Empty[java.lang.Long, KeySpan]):
        """
        The singleton empty span of keys
        """

        class_: typing.ClassVar[java.lang.Class]


    class Impl(java.lang.Record, KeySpan):
        """
        A non-empty span of keys
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, min: typing.Union[java.lang.Long, int], max: typing.Union[java.lang.Long, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def max(self) -> int:
            ...

        def min(self) -> int:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DOMAIN: typing.Final[KeySpan.Domain]
    EMPTY: typing.Final[KeySpan.Empty]
    ALL: typing.Final[KeySpan.Impl]

    @staticmethod
    def closed(from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> KeySpan:
        """
        Get the span for a closed interval
        
        
        .. admonition:: Implementation Note
        
            this is used primarily in testing
        
        
        :param jpype.JLong or int from: the lower endpoint
        :param jpype.JLong or int to: the upper endpoint
        :return: the interval
        :rtype: KeySpan
        """

    @staticmethod
    def head(to: typing.Union[jpype.JLong, int], toInclusive: typing.Union[jpype.JBoolean, bool], direction: DirectedIterator.Direction) -> KeySpan:
        """
        Get the span for the head of a collection
         
         
        
        When ``direction`` is :obj:`Direction.BACKWARD` this behaves as if a tail collection;
        however, the implication is that iteration will start from the maximum and proceed toward the
        given bound.
        
        :param jpype.JLong or int to: the upper bound
        :param jpype.JBoolean or bool toInclusive: true if the bound includes ``to``
        :param DirectedIterator.Direction direction: the direction, true to create a tail instead
        :return: the span
        :rtype: KeySpan
        """

    @staticmethod
    def sub(from_: typing.Union[jpype.JLong, int], fromInclusive: typing.Union[jpype.JBoolean, bool], to: typing.Union[jpype.JLong, int], toInclusive: typing.Union[jpype.JBoolean, bool], direction: DirectedIterator.Direction) -> KeySpan:
        """
        Get the span for a sub collection
         
         
        
        ``from`` must precede ``to``, unless direction is :obj:`Direction.BACKWARD`, in
        which case the opposite is required. The endpoints may be equal but unless both are
        inclusive, the result is :obj:`.EMPTY`. The two endpoints are not automatically inverted to
        correct ordering. More often than not, accidental mis-ordering indicates an implementation
        flaw.
        
        :param jpype.JLong or int from: the lower bound
        :param jpype.JBoolean or bool fromInclusive: true if the bound includes ``from``
        :param jpype.JLong or int to: the upper bound
        :param jpype.JBoolean or bool toInclusive: true if the bound includes ``to``
        :param DirectedIterator.Direction direction: the direction, true to swap ``from`` and ``to``
        :return: the span
        :rtype: KeySpan
        """

    @staticmethod
    def tail(from_: typing.Union[jpype.JLong, int], fromInclusive: typing.Union[jpype.JBoolean, bool], direction: DirectedIterator.Direction) -> KeySpan:
        """
        Get the span for the tail of a collection
         
         
        
        When ``direction`` is :obj:`Direction.BACKWARD` this behaves as if a head collection;
        however, the implication is that iteration will start from the bound and proceed toward the
        minimum.
        
        :param jpype.JLong or int from: the lower bound
        :param jpype.JBoolean or bool fromInclusive: true if the bound includes ``to``
        :param DirectedIterator.Direction direction: the direction, true to create a head instead
        :return: the span
        :rtype: KeySpan
        """


class DBBufferInputStream(java.io.InputStream):
    """
    An input stream backed by a database chained buffer
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buffer: db.DBBuffer):
        ...


class DBSynchronizedSpliterator(java.util.Spliterator[T], typing.Generic[T]):
    """
    Wraps an unsynchronized spliterator in one that synchronizes on a given :obj:`Lock`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spliterator: java.util.Spliterator[T], lock: java.util.concurrent.locks.Lock):
        ...


class DBCachedObjectStoreValueSubCollection(DBCachedObjectStoreValueCollection[T], typing.Generic[T]):
    """
    This is the sub-ranged form of :obj:`DBCachedObjectStoreValueCollection`
    
     
    
    For example, this can be obtained via ``store.asMap().subMap(...).values()``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[T], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, direction: DirectedIterator.Direction, keySpan: KeySpan):
        ...


class DBCachedObjectStoreMap(java.util.NavigableMap[java.lang.Long, T], typing.Generic[T]):
    """
    This provides the implementation of :meth:`DBCachedObjectStore.asMap() <DBCachedObjectStore.asMap>`
    
     
    
    This implements a map from object id (long) to object. Objects cannot be added directly to this
    map, e.g., :meth:`put(Long, DBAnnotatedObject) <.put>` is not supported. Instead use
    :meth:`DBCachedObjectStore.create(long) <DBCachedObjectStore.create>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[T], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, direction: DirectedIterator.Direction):
        ...


class DBCachedObjectStoreEntrySubSet(DBCachedObjectStoreEntrySet[T], typing.Generic[T]):
    """
    This is the sub-ranged form of :obj:`DBCachedObjectStoreEntrySet`
     
     
    
    For example, this can be obtained via ``store.asMap().subMap(...).entrySet()``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[T], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, direction: DirectedIterator.Direction, keySpan: KeySpan):
        ...


class BackwardRecordIterator(AbstractDirectedRecordIterator):
    """
    A wrapper of :obj:`RecordIterator` that runs it backward and implements
    :obj:`DirectedRecordIterator`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: db.RecordIterator):
        ...


class DBCachedObjectStoreEntrySet(java.util.NavigableSet[java.util.Map.Entry[java.lang.Long, T]], typing.Generic[T]):
    """
    This provides the implementation of :meth:`Map.entrySet() <Map.entrySet>` for
    :meth:`DBCachedObjectStore.asMap() <DBCachedObjectStore.asMap>`
     
     
    
    The store acts as a map from object id to object, thus an entry has a long key and object value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[T], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, direction: DirectedIterator.Direction):
        ...


class DBAnnotatedObject(ghidra.program.database.DatabaseObject):
    """
    An object backed by a :obj:`DBRecord`
     
     
    
    Essentially, this is a data access object (DAO) for Ghidra's custom database engine. Not all
    object fields necessarily have a corresponding database field. Instead, those fields are
    annotated, and various methods are provided for updating the record, and conversely, re-loading
    fields from the record. These objects are managed using a :obj:`DBCachedObjectStore`. An example
    object definition:
     
    ``interface Person {    // ...}@DBAnnotatedObjectInfo(version = 1)public class DBPerson extends DBAnnotatedObject implements Person {    public static final String TABLE_NAME = "Person"; // Conventionally defined here    // Best practice is to define column names, then use in annotations    static final String NAME_COLUMN_NAME = "Name";    static final String ADDRESS_COLUMN_NAME = "Address";    // Column handles    @DBAnnotatedColumn(NAME_COLUMN_NAME)    static DBObjectColumn NAME_COLUMN;    @DBAnnotatedColumn(ADDRESS_COLUMN_NAME)    static DBObjectColumn ADDRESS_COLUMN;    // Column-backed fields    @DBAnnotatedField(column = NAME_COLUMN_NAME, indexed = true)    private String name;    @DBAnnotatedField(column = ADDRESS_COLUMN_NAME)    private String address;    DBPerson(DBCachedObjectStore<DBPerson> store, DBRecord record) {        super(store, record);    }    // Not required, but best practice    private void set(String name, String address) {        this.name = name;        this.address = address;        update(NAME_COLUMN, ADDRESS_COLUMN);    }    // ... other methods, getters, setters}``
     
     
    
    See :obj:`DBCachedObjectStoreFactory` for example code that uses the example ``DBPerson``
    class.
     
     
    
    All realizations of :obj:`DBAnnotatedObject` must be annotated with
    :obj:`DBAnnotatedObjectInfo`. This, along with the field annotations, are used to derive the
    table schema. Note the inclusion of a ``TABLE_NAME`` field. It is not required, nor is it
    used implicitly. It's included in this example as a manner of demonstrating best practice. When
    instantiating the object store, the field is used to provide the table name.
     
    
    Next, we define the column names. These are not required nor used implicitly, but using literal
    strings in the column annotations is discouraged. Next, we declare variables to receive column
    handles. These are essentially the column numbers, but we have a named handle for each. They are
    initialized automatically the first time a store is created for this class.
     
    
    Next we declare the variables representing the actual column values. Their initialization varies
    depending on how the object is instantiated. When creating a new object, the fields remain
    uninitialized. In some cases, it may be appropriate to provide an initial (default) value in the
    usual fashion, e.g., ``private String address = "123 Pine St.";`` In this case, the
    corresponding database field of the backing record is implicitly initialized upon creation. If
    the object is being loaded from a table, its fields are initialized with values from its backing
    record.
    
     
    
    Next we define the constructor. There are no requirements on its signature, but it must call
    :meth:`super <.DBAnnotatedObject>`, so it likely takes its
    containing store and its backing record. Having the same signature as its super constructor
    allows the store to be created using a simple method reference, e.g., ``DBPerson::new``.
    Additional user-defined parameters may be accepted. To pass such parameters, a lambda is
    recommended when creating the object store.
     
    
    Finally, we demonstrate how to update the record. The record is *not* implicitly updated
    by direct modification of an annotated field. All setters must call
    :meth:`update(DBObjectColumn...) <.update>` after updating a field. A common practice, especially when the
    object will have all its fields set at once, is to include a ``set`` method that initializes
    the fields and updates the record in one :meth:`update(DBObjectColumn...) <.update>`.
     
     
    
    Note that there is no way to specify the primary key. For object stores, the primary key is
    always the object id, and its type is always ``long``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getObjectKey(self) -> ObjectKey:
        """
        Get an opaque unique id for this object, whose hash is immutable
        
        :return: the opaque object id
        :rtype: ObjectKey
        """

    def getTableName(self) -> str:
        ...

    def isDeleted(self) -> bool:
        """
        Check if this object has been deleted
        
        :return: true if deleted
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.isDeleted(ghidra.util.Lock)`
        """

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def objectKey(self) -> ObjectKey:
        ...

    @property
    def tableName(self) -> java.lang.String:
        ...


class FieldSpan(generic.End.EndSpan[db.Field, FieldSpan]):
    """
    A span of database field values
     
     
    
    We must allow open endpoints here. Consider a string field. There is no well-defined increment or
    decrement on strings. Let them be ordered lexicographically. What string *immediately*
    precedes ``"Span"``? It is not ``"Spam"``, since ``"Spammer"`` falls between. In
    fact, for any string having the prefix ``"Spam"``, you can add another character to it to
    find a string after it, but still preceding ``"Span"``. Thus, we use :obj:`EndSpan`, so that
    ``End("Span" - epsilon)`` can stand in for the value immediately preceding ``"Span"``.
    """

    class Domain(generic.End.EndDomain[db.Field, FieldSpan]):
        """
        The domain of field values, allowing open endpoints
        """

        class_: typing.ClassVar[java.lang.Class]


    class Empty(FieldSpan, generic.Span.Empty[generic.End[db.Field], FieldSpan]):
        """
        The singleton empty span of field values
        """

        class_: typing.ClassVar[java.lang.Class]


    class Impl(java.lang.Record, FieldSpan):
        """
        A span of field values
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, min: generic.End[db.Field], max: generic.End[db.Field]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def max(self) -> generic.End[db.Field]:
            ...

        def min(self) -> generic.End[db.Field]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DOMAIN: typing.Final[FieldSpan.Domain]
    EMPTY: typing.Final[FieldSpan.Empty]
    ALL: typing.Final[FieldSpan.Impl]

    @staticmethod
    def head(to: db.Field, toInclusive: typing.Union[jpype.JBoolean, bool], direction: DirectedIterator.Direction) -> FieldSpan:
        """
        Get the span for the head of a collection
         
         
        
        When ``direction`` is :obj:`Direction.BACKWARD` this behaves as if a tail collection;
        however, the implication is that iteration will start from the maximum and proceed toward the
        given bound.
        
        :param db.Field to: the upper bound
        :param jpype.JBoolean or bool toInclusive: true if the bound includes ``to``
        :param DirectedIterator.Direction direction: the direction, true to create a tail instead
        :return: the span
        :rtype: FieldSpan
        """

    @staticmethod
    def sub(from_: db.Field, fromInclusive: typing.Union[jpype.JBoolean, bool], to: db.Field, toInclusive: typing.Union[jpype.JBoolean, bool], direction: DirectedIterator.Direction) -> FieldSpan:
        """
        Get the span for a sub collection
         
         
        
        ``from`` must precede ``to``, unless direction is :obj:`Direction.BACKWARD`, in
        which case the opposite is required. The endpoints may be equal but unless both are
        inclusive, the result is :obj:`.EMPTY`. The two endpoints are not automatically inverted to
        correct ordering. More often than not, accidental mis-ordering indicates an implementation
        flaw.
        
        :param db.Field from: the lower bound
        :param jpype.JBoolean or bool fromInclusive: true if the bound includes ``from``
        :param db.Field to: the upper bound
        :param jpype.JBoolean or bool toInclusive: true if the bound includes ``to``
        :param DirectedIterator.Direction direction: the direction, true to swap ``from`` and ``to``
        :return: the span
        :rtype: FieldSpan
        """

    @staticmethod
    def tail(from_: db.Field, fromInclusive: typing.Union[jpype.JBoolean, bool], direction: DirectedIterator.Direction) -> FieldSpan:
        """
        Get the span for the tail of a collection
         
         
        
        When ``direction`` is :obj:`Direction.BACKWARD` this behaves as if a head collection;
        however, the implication is that iteration will start from the bound and proceed toward the
        minimum.
        
        :param db.Field from: the lower bound
        :param jpype.JBoolean or bool fromInclusive: true if the bound includes ``to``
        :param DirectedIterator.Direction direction: the direction, true to create a head instead
        :return: the span
        :rtype: FieldSpan
        """


class DBCachedObjectStore(db.util.ErrorHandler, typing.Generic[T]):
    """
    An object store backed by a :obj:`db.Table`
    
     
    
    Essentially, this provides object-based accessed to records in the table via DAOs. See
    :obj:`DBAnnotatedObject` for further documentation including an example object definition. The
    store keeps a cache of objects using :obj:`DBObjectCache`. See
    :obj:`DBCachedObjectStoreFactory` for documentation describing how to create a store, including
    for the example object definition.
     
     
    
    The store provides views for locating, iterating, and retrieving its objects in a variety of
    fashions. This includes the primary key (object id), or any indexed column (see
    :meth:`DBAnnotatedField.indexed() <DBAnnotatedField.indexed>`). These views generally implement an interface from Java's
    Collections API, providing for familiar semantics. A notable exception is that none of the
    interfaces support mutation, aside from deletion. The store is populated only via the
    :meth:`create() <.create>` methods.
    """

    @typing.type_check_only
    class BoundedStuff(java.lang.Object, typing.Generic[E, R]):
        """
        Abstractions for navigating within a given view
         
         
        
        Generally, these are all methods that facilitate implementation of a :obj:`Collection` or
        :obj:`NavigableMap`. The idea is that the abstract methods are required to translate from
        various object types and to facilitate table access. This class then provides all the methods
        needed to navigate the table with respect to a desired element type. These types will be
        those typically exposed as collections by the :obj:`Map` interface: keys, values, and
        entries. The implementations of those collections can then call those methods as needed.
        
         
        
        The methods are implemented in various groups and with a variety of parameters. The first
        group is the abstract methods. The next simply wraps the table's navigations methods to
        retrieve elements of the view. Many of these accept an optional range to limit the search or
        effect. This is to facilitate the implementation of sub-maps. The next are named after their
        counterparts in the navigable interfaces. In addition to the optional range, many of these
        take a direction. This is to facilitate the implementation of reversed collections. To best
        understand the methods, examine the callers-to tree and see the relevant documentation,
        probably in the Java Collections API.
        """

        class_: typing.ClassVar[java.lang.Class]

        def toArray(self, direction: DirectedIterator.Direction, keySpan: KeySpan, a: jpype.JArray[W], size: typing.Union[jpype.JInt, int]) -> jpype.JArray[W]:
            ...


    @typing.type_check_only
    class SupplierAllowsIOException(java.lang.Object, typing.Generic[U]):
        """
        A variation of :obj:`Supplier` that allows :obj:`IOException` to pass through
        """

        class_: typing.ClassVar[java.lang.Class]

        def get(self) -> U:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def asMap(self) -> DBCachedObjectStoreMap[T]:
        """
        Provides access to the store as a :obj:`NavigableMap`.
        
        :return: the map
        :rtype: DBCachedObjectStoreMap[T]
        """

    def contains(self, obj: T) -> bool:
        """
        Check if the given object exists in the store
         
         
        
        No matter the definition of :meth:`T.equals(Object) <T.equals>`, this requires the identical object to
        be present.
        
        :param T obj: the object
        :return: 
        :rtype: bool
        """

    def containsKey(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if an object with the given key exists in the store
         
         
        
        Using this is preferred to :meth:`getObjectAt(long) <.getObjectAt>` and checking for null, if that object
        does not actually need to be retrieved.
        
        :param jpype.JLong or int key: the key
        :return: true if it exists
        :rtype: bool
        """

    @typing.overload
    def create(self, key: typing.Union[jpype.JLong, int]) -> T:
        """
        Create a new object with the given key.
         
         
        
        If the key already exists in the table, the existing record is overwritten.
        
        :param jpype.JLong or int key: the key for the new object
        :return: the new object
        :rtype: T
        """

    @typing.overload
    def create(self) -> T:
        """
        Create a new object with the next available key.
        
        :return: the new object
        :rtype: T
        """

    def delete(self, obj: T) -> bool:
        """
        Delete the given object
        
        :param T obj: the object
        :return: true if the object was removed, false for no effect
        :rtype: bool
        """

    def deleteAll(self):
        """
        Clear the entire table
        """

    def deleteKey(self, key: typing.Union[jpype.JLong, int]) -> T:
        """
        Delete the object with the given key
        
        :param jpype.JLong or int key: the key
        :return: true if the key was removed, false for no effect
        :rtype: T
        """

    @typing.overload
    def getIndex(self, fieldClass: java.lang.Class[K], column: DBObjectColumn) -> DBCachedObjectIndex[K, T]:
        """
        Get the index for a given column
         
         
        
        See :obj:`DBCachedObjectStoreFactory` for an example that includes use of an index
        
        :param K: the type of the object field for the indexed column:param java.lang.Class[K] fieldClass: the class specifying :obj:`K`
        :param DBObjectColumn column: the indexed column
        :return: the index
        :rtype: DBCachedObjectIndex[K, T]
        :raises IllegalArgumentException: if the column has a different type than :obj:`K`
        """

    @typing.overload
    def getIndex(self, fieldClass: java.lang.Class[K], columnName: typing.Union[java.lang.String, str]) -> DBCachedObjectIndex[K, T]:
        """
        Get the index for a given column by name
         
         
        
        See :obj:`DBCachedObjectStoreFactory` for an example that includes use of an index
        
        :param K: the type of the object field for the indexed column:param java.lang.Class[K] fieldClass: the class specifying :obj:`K`
        :param java.lang.String or str columnName: the name of the indexed column
        :return: the index
        :rtype: DBCachedObjectIndex[K, T]
        :raises IllegalArgumentException: if the given column is not indexed
        """

    def getLock(self) -> java.util.concurrent.locks.ReadWriteLock:
        """
        Get the read-write lock
        
        :return: the lock
        :rtype: java.util.concurrent.locks.ReadWriteLock
        """

    def getMaxKey(self) -> int:
        """
        Get the maximum key which has ever existed in this store
         
         
        
        Note, the returned key may not actually be present
        
        :return: the maximum, or null if the store is unused
        :rtype: int
        """

    def getObjectAt(self, key: typing.Union[jpype.JLong, int]) -> T:
        """
        Get the object having the given key
        
        :param jpype.JLong or int key: the key
        :return: the object, or null
        :rtype: T
        """

    def getRecordCount(self) -> int:
        """
        Get the number of objects (records) in this store
        
        :return: the record count
        :rtype: int
        """

    def getTableName(self) -> str:
        """
        Get the name of the table backing this store
        
        :return: the name
        :rtype: str
        """

    def invalidateCache(self):
        """
        Invalidate this store's cache
         
         
        
        This should be called whenever the table may have changed in a way not caused by the store
        itself, e.g., whenever :meth:`DBHandle.undo() <DBHandle.undo>` is called.
        """

    def readLock(self) -> java.util.concurrent.locks.Lock:
        """
        Get the read lock
        
        :return: the lock
        :rtype: java.util.concurrent.locks.Lock
        """

    def toString(self) -> str:
        """
        Display useful information about this cached store
         
         
        
        Please avoid calling this except for debugging.
        
        :return: a string representation of the store's cache
        :rtype: str
        """

    def writeLock(self) -> java.util.concurrent.locks.Lock:
        """
        Get the write lock
        
        :return: the lock
        :rtype: java.util.concurrent.locks.Lock
        """

    @property
    def maxKey(self) -> jpype.JLong:
        ...

    @property
    def objectAt(self) -> T:
        ...

    @property
    def recordCount(self) -> jpype.JInt:
        ...

    @property
    def lock(self) -> java.util.concurrent.locks.ReadWriteLock:
        ...

    @property
    def tableName(self) -> java.lang.String:
        ...


class DomainObjectLockHold(java.lang.AutoCloseable):
    """
    A hold on the lock for a domain object, obtained via :meth:`lock(DomainObject, String) <.lock>` or
    :meth:`forceLock(DomainObject, boolean, String) <.forceLock>`
     
     
    
    This is designed for use in a ``try-with-resources`` block to ensure the timely release of
    the lock even in exceptional conditions, as in:
     
     
    try (DomainObjectLockHold hold = DomainObjectLockHold.lock("Demonstration")) {
        // Do stuff while holding the lock
    }
    """

    class DefaultHold(DomainObjectLockHold):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, object: ghidra.framework.model.DomainObject):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def forceLock(object: ghidra.framework.model.DomainObject, rollback: typing.Union[jpype.JBoolean, bool], reason: typing.Union[java.lang.String, str]) -> DomainObjectLockHold:
        """
        Wrapper for :meth:`DomainObject.forceLock(boolean, String) <DomainObject.forceLock>`
        
        :param ghidra.framework.model.DomainObject object: the object
        :param jpype.JBoolean or bool rollback: as in :meth:`DomainObject.forceLock(boolean, String) <DomainObject.forceLock>`
        :param java.lang.String or str reason: as in :meth:`DomainObject.forceLock(boolean, String) <DomainObject.forceLock>`
        :return: the hold, which should be used in a ``try-with-resources`` block
        :rtype: DomainObjectLockHold
        """

    @staticmethod
    def lock(object: ghidra.framework.model.DomainObject, reason: typing.Union[java.lang.String, str]) -> DomainObjectLockHold:
        """
        Wrapper for :meth:`DomainObject.lock(String) <DomainObject.lock>`
        
        :param ghidra.framework.model.DomainObject object: the object
        :param java.lang.String or str reason: as in :meth:`DomainObject.lock(String) <DomainObject.lock>`
        :return: the hold, which should be used in a ``try-with-resources`` block
        :rtype: DomainObjectLockHold
        :raises DomainObjectLockedException: if the lock could not be obtained
        """


class DirectedLongKeyIterator(DirectedIterator[java.lang.Long]):
    """
    An iterator over keys of a table
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getIterator(table: db.Table, keySpan: KeySpan, direction: DirectedIterator.Direction) -> AbstractDirectedLongKeyIterator:
        """
        Get an iterator over the table, restricted to the given range, in the given direction
        
        :param db.Table table: the table
        :param KeySpan keySpan: the limited range
        :param DirectedIterator.Direction direction: the direction
        :return: the iterator
        :rtype: AbstractDirectedLongKeyIterator
        :raises IOException: if the table cannot be read
        """


class SynchronizedSpliterator(java.util.Spliterator[T], typing.Generic[T]):
    """
    Wraps an unsynchronized spliterator in one that synchronizes on a given object's intrinsic lock,
    often the collection that provided the stream or spliterator.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spliterator: java.util.Spliterator[T], lock: java.lang.Object):
        ...


class ForwardLongKeyIterator(AbstractDirectedLongKeyIterator):
    """
    A wrapper of :obj:`DBLongIterator` that runs it forward and implements
    :obj:`DirectedLongKeyIterator`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: db.DBLongIterator):
        ...


class AbstractDirectedRecordIterator(DirectedRecordIterator):
    """
    An abstract implementation of :obj:`DirectedRecordIterator`
     
     
    
    Essentially, this just wraps a :obj:`RecordIterator`, but imposes and encapsulates its
    direction.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: db.RecordIterator):
        """
        Wrap the given iterator
        
        :param db.RecordIterator it: the iterator
        """


class DBCachedObjectStoreKeySet(java.util.NavigableSet[java.lang.Long]):
    """
    This provides the implementation of :meth:`Map.keySet() <Map.keySet>` for :meth:`DBCachedObjectStore.asMap() <DBCachedObjectStore.asMap>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[typing.Any], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, direction: DirectedIterator.Direction):
        ...


class ForwardRecordIterator(AbstractDirectedRecordIterator):
    """
    A wrapper of :obj:`RecordIterator` that runs it forward and implements
    :obj:`DirectedRecordIterator`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: db.RecordIterator):
        ...


class DBCachedObjectStoreKeySubSet(DBCachedObjectStoreKeySet):
    """
    This is the sub-ranged form of :obj:`DBCachedObjectStoreKeySubSet`
    
     
    
    For example, this can be obtained via ``store.asMap().subMap(...).keySet()`` or
    ``map.keySet().subSet(...)``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: DBCachedObjectStore[typing.Any], errHandler: db.util.ErrorHandler, lock: java.util.concurrent.locks.ReadWriteLock, direction: DirectedIterator.Direction, keySpan: KeySpan):
        ...


class DirectedIterator(java.lang.Object, typing.Generic[T]):
    """
    An iterator over some component of a :obj:`Table`
    """

    class Direction(java.lang.Enum[DirectedIterator.Direction]):
        """
        The direction of iteration
        """

        class_: typing.ClassVar[java.lang.Class]
        FORWARD: typing.Final[DirectedIterator.Direction]
        BACKWARD: typing.Final[DirectedIterator.Direction]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DirectedIterator.Direction:
            ...

        @staticmethod
        def values() -> jpype.JArray[DirectedIterator.Direction]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def delete(self) -> bool:
        """
        Delete the current record
        
        :return: true if successful
        :rtype: bool
        :raises IOException: if the table cannot be accessed
        """

    def hasNext(self) -> bool:
        """
        Check if the table has another record
        
        :return: true if so
        :rtype: bool
        :raises IOException: if the table cannot be read
        """

    def next(self) -> T:
        """
        Get the component of the next record
        
        :return: the component
        :rtype: T
        :raises IOException: if the table cannot be read
        """



__all__ = ["DBCachedObjectStoreSubMap", "SchemaBuilder", "BackwardLongKeyIterator", "DBCachedObjectStoreFactory", "DBAnnotatedObjectFactory", "ObjectKey", "DBCachedDomainObjectAdapter", "DBSynchronizedIterator", "DBObjectColumn", "DBCachedObjectStoreFoundKeysValueCollection", "DirectedRecordIterator", "DBCachedObjectIndex", "AbstractDirectedLongKeyIterator", "DBBufferOutputStream", "DBSynchronizedCollection", "DBCachedObjectStoreValueCollection", "KeySpan", "DBBufferInputStream", "DBSynchronizedSpliterator", "DBCachedObjectStoreValueSubCollection", "DBCachedObjectStoreMap", "DBCachedObjectStoreEntrySubSet", "BackwardRecordIterator", "DBCachedObjectStoreEntrySet", "DBAnnotatedObject", "FieldSpan", "DBCachedObjectStore", "DomainObjectLockHold", "DirectedLongKeyIterator", "SynchronizedSpliterator", "ForwardLongKeyIterator", "AbstractDirectedRecordIterator", "DBCachedObjectStoreKeySet", "ForwardRecordIterator", "DBCachedObjectStoreKeySubSet", "DirectedIterator"]
