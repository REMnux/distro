from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf
import ghidra.app.util.bin.format.dwarf.expression
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


E = typing.TypeVar("E")


class DWARFFormContext(java.lang.Record):
    """
    Context given to the :meth:`DWARFForm.readValue(DWARFFormContext) <DWARFForm.readValue>` method to enable it to
    create :obj:`DWARFAttributeValue`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, compUnit: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit, def_: DWARFAttributeDef[typing.Any]):
        ...

    def compUnit(self) -> ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit:
        ...

    def def_(self) -> DWARFAttributeDef[typing.Any]:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    def toString(self) -> str:
        ...


class DWARFBooleanAttribute(DWARFAttributeValue):
    """
    DWARF boolean attribute.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: typing.Union[jpype.JBoolean, bool], def_: DWARFAttributeDef[typing.Any]):
        ...

    def getValue(self) -> bool:
        ...

    @property
    def value(self) -> jpype.JBoolean:
        ...


class DWARFNumericAttribute(DWARFAttributeValue):
    """
    DWARF numeric attribute.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, value: typing.Union[jpype.JLong, int], def_: DWARFAttributeDef[typing.Any]):
        """
        Creates a new numeric value, using 64 bits and marked as signed
        
        :param jpype.JLong or int value: long 64 bit value
        :param DWARFAttributeDef[typing.Any] def: attribute id and form of this value
        """

    @typing.overload
    def __init__(self, bitLength: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int], signed: typing.Union[jpype.JBoolean, bool], def_: DWARFAttributeDef[typing.Any]):
        """
        Creates a new numeric value, using the specific bitLength and value.
        
        :param jpype.JInt or int bitLength: number of bits, valid values are 1..64, or 0 if value is also 0
        :param jpype.JLong or int value: value of the scalar, any bits that are set above bitLength will be ignored
        :param jpype.JBoolean or bool signed: true for a signed value, false for an unsigned value.
        :param DWARFAttributeDef[typing.Any] def: attribute id and form of this value
        """

    @typing.overload
    def __init__(self, bitLength: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int], signed: typing.Union[jpype.JBoolean, bool], ambiguous: typing.Union[jpype.JBoolean, bool], def_: DWARFAttributeDef[typing.Any]):
        """
        Creates a new numeric value, using the specific bitLength and value.
        
        :param jpype.JInt or int bitLength: number of bits, valid values are 1..64, or 0 if value is also 0
        :param jpype.JLong or int value: value of the scalar, any bits that are set above bitLength will be ignored
        :param jpype.JBoolean or bool signed: true for a signed value, false for an unsigned value.
        :param jpype.JBoolean or bool ambiguous: true for value with ambiguous signedness (``signed`` parameter should
        not be trusted), false for value where the ``signed`` parameter is known to be correct
        :param DWARFAttributeDef[typing.Any] def: attribute id and form of this value
        """

    def getUnsignedIntExact(self) -> int:
        ...

    def getUnsignedValue(self) -> int:
        ...

    def getValue(self) -> int:
        ...

    def getValueWithSignednessHint(self, signednessHint: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        :return: the value, forcing the signedness of ambiguous values using the specified hint
        :rtype: int
        
        
        :param jpype.JBoolean or bool signednessHint: true to default to a signed value, false to default to an 
        unsigned value
        """

    def isAmbiguousSignedness(self) -> bool:
        """
        :return: boolean flag, if true this value's signedness is up to the user of the value,
        if false the signedness was determined when the value was constructed
        :rtype: bool
        """

    def isHighbitSet(self) -> bool:
        ...

    def toElementLocationString(self, elementType: typing.Union[java.lang.String, str], sectionName: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JLong, int], ver: typing.Union[jpype.JInt, int]) -> str:
        ...

    @property
    def ambiguousSignedness(self) -> jpype.JBoolean:
        ...

    @property
    def highbitSet(self) -> jpype.JBoolean:
        ...

    @property
    def unsignedIntExact(self) -> jpype.JInt:
        ...

    @property
    def unsignedValue(self) -> jpype.JLong:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @property
    def valueWithSignednessHint(self) -> jpype.JLong:
        ...


class DWARFAttributeClass(java.lang.Enum[DWARFAttributeClass]):
    """
    Categories that a DWARF attribute value may belong to.
    """

    class_: typing.ClassVar[java.lang.Class]
    address: typing.Final[DWARFAttributeClass]
    addrptr: typing.Final[DWARFAttributeClass]
    block: typing.Final[DWARFAttributeClass]
    constant: typing.Final[DWARFAttributeClass]
    exprloc: typing.Final[DWARFAttributeClass]
    flag: typing.Final[DWARFAttributeClass]
    lineptr: typing.Final[DWARFAttributeClass]
    loclist: typing.Final[DWARFAttributeClass]
    loclistsptr: typing.Final[DWARFAttributeClass]
    macptr: typing.Final[DWARFAttributeClass]
    reference: typing.Final[DWARFAttributeClass]
    rnglist: typing.Final[DWARFAttributeClass]
    rnglistsptr: typing.Final[DWARFAttributeClass]
    string: typing.Final[DWARFAttributeClass]
    stroffsetsptr: typing.Final[DWARFAttributeClass]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFAttributeClass:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFAttributeClass]:
        ...


class DWARFDeferredStringAttribute(DWARFStringAttribute):
    """
    DWARF string attribute, where getting the value from the string table is deferred
    until requested for the first time.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, offset: typing.Union[jpype.JLong, int], def_: DWARFAttributeDef[typing.Any]):
        ...

    def getOffset(self) -> int:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...


class DWARFAttributeDef(java.lang.Object, typing.Generic[E]):
    """
    Information about a single DWARF attribute, as specified in a 
    :obj:`abbreviation <DWARFAbbreviation>`.
     
    
    This class handles the case where a specified attribute id is unknown to us (therefore not
    listed in the attribute enum class), as well as the case where the form is customized with
    an implicitValue.
     
    
    Unknown forms are not supported and cause an exception.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, attributeId: E, rawAttributeId: typing.Union[jpype.JInt, int], attributeForm: DWARFForm, implicitValue: typing.Union[jpype.JLong, int]):
        ...

    def getAttributeForm(self) -> DWARFForm:
        """
        Get the form of the attribute specification.
        
        :return: the form value
        :rtype: DWARFForm
        """

    def getAttributeId(self) -> E:
        """
        Get the attribute id of the attribute specification.
        
        :return: the attribute value
        :rtype: E
        """

    def getAttributeName(self) -> str:
        ...

    def getImplicitValue(self) -> int:
        ...

    def getRawAttributeId(self) -> int:
        ...

    def isImplicit(self) -> bool:
        ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, mapper: java.util.function.Function[java.lang.Integer, E]) -> DWARFAttributeDef[E]:
        """
        Reads a :obj:`DWARFAttributeDef` instance from the :obj:`reader <BinaryReader>`.
         
        
        Returns a null if its a end-of-list marker (which is only used by an attributespec list).
        
        :param E: attribute id enum type:param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader`
        :param java.util.function.Function[java.lang.Integer, E] mapper: func that converts an attribute id int into its enum
        :return: DWARFAttributeDef instance, or null if EOL marker was read from the stream
        :rtype: DWARFAttributeDef[E]
        :raises IOException: if error reading
        """

    def withForm(self, newForm: DWARFForm) -> DWARFAttributeDef[E]:
        ...

    @property
    def attributeId(self) -> E:
        ...

    @property
    def implicit(self) -> jpype.JBoolean:
        ...

    @property
    def rawAttributeId(self) -> jpype.JInt:
        ...

    @property
    def implicitValue(self) -> jpype.JLong:
        ...

    @property
    def attributeName(self) -> java.lang.String:
        ...

    @property
    def attributeForm(self) -> DWARFForm:
        ...


class DWARFAttributeValue(java.lang.Object):
    """
    Base class for all DWARF attribute value implementations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, def_: DWARFAttributeDef[typing.Any]):
        ...

    def getAttributeForm(self) -> DWARFForm:
        ...

    def getAttributeName(self) -> str:
        ...

    def toString(self, compilationUnit: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit) -> str:
        ...

    @property
    def attributeName(self) -> java.lang.String:
        ...

    @property
    def attributeForm(self) -> DWARFForm:
        ...


class DWARFAttribute(java.lang.Enum[DWARFAttribute]):
    """
    Defines the names and numeric ids of known DWARF attributes.  Well-known attributes are also
    constrained to certain value types (see :obj:`DWARFAttributeClass`).
     
    
    Users of this enum should be tolerant of unknown attribute id values.  See 
    :meth:`AttrDef.getRawAttributeId() <AttrDef.getRawAttributeId>`.
    """

    class AttrDef(DWARFAttributeDef[DWARFAttribute]):
        """
        Represents how a specific DWARF attribute is stored in a DIE record.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, attributeId: DWARFAttribute, rawAttributeId: typing.Union[jpype.JInt, int], attributeForm: DWARFForm, implicitValue: typing.Union[jpype.JLong, int]):
            ...

        @staticmethod
        def read(reader: ghidra.app.util.bin.BinaryReader) -> DWARFAttribute.AttrDef:
            """
            Reads a :obj:`DWARFAttribute.AttrDef` instance from the :obj:`reader <BinaryReader>`.
             
            
            Returns a null if its a end-of-list marker.
            
            :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` abbr stream
            :return: new :obj:`AttrDef`, or null if end-of-list
            :rtype: DWARFAttribute.AttrDef
            :raises IOException: if error reading
            """


    class_: typing.ClassVar[java.lang.Class]
    DW_AT_sibling: typing.Final[DWARFAttribute]
    DW_AT_location: typing.Final[DWARFAttribute]
    DW_AT_name: typing.Final[DWARFAttribute]
    DW_AT_ordering: typing.Final[DWARFAttribute]
    DW_AT_byte_size: typing.Final[DWARFAttribute]
    DW_AT_bit_offset: typing.Final[DWARFAttribute]
    DW_AT_bit_size: typing.Final[DWARFAttribute]
    DW_AT_stmt_list: typing.Final[DWARFAttribute]
    DW_AT_low_pc: typing.Final[DWARFAttribute]
    DW_AT_high_pc: typing.Final[DWARFAttribute]
    DW_AT_language: typing.Final[DWARFAttribute]
    DW_AT_discr: typing.Final[DWARFAttribute]
    DW_AT_discr_value: typing.Final[DWARFAttribute]
    DW_AT_visibility: typing.Final[DWARFAttribute]
    DW_AT_import: typing.Final[DWARFAttribute]
    DW_AT_string_length: typing.Final[DWARFAttribute]
    DW_AT_common_reference: typing.Final[DWARFAttribute]
    DW_AT_comp_dir: typing.Final[DWARFAttribute]
    DW_AT_const_value: typing.Final[DWARFAttribute]
    DW_AT_containing_type: typing.Final[DWARFAttribute]
    DW_AT_default_value: typing.Final[DWARFAttribute]
    DW_AT_inline: typing.Final[DWARFAttribute]
    DW_AT_is_optional: typing.Final[DWARFAttribute]
    DW_AT_lower_bound: typing.Final[DWARFAttribute]
    DW_AT_producer: typing.Final[DWARFAttribute]
    DW_AT_prototyped: typing.Final[DWARFAttribute]
    DW_AT_return_addr: typing.Final[DWARFAttribute]
    DW_AT_start_scope: typing.Final[DWARFAttribute]
    DW_AT_bit_stride: typing.Final[DWARFAttribute]
    DW_AT_upper_bound: typing.Final[DWARFAttribute]
    DW_AT_abstract_origin: typing.Final[DWARFAttribute]
    DW_AT_accessibility: typing.Final[DWARFAttribute]
    DW_AT_address_class: typing.Final[DWARFAttribute]
    DW_AT_artificial: typing.Final[DWARFAttribute]
    DW_AT_base_types: typing.Final[DWARFAttribute]
    DW_AT_calling_convention: typing.Final[DWARFAttribute]
    DW_AT_count: typing.Final[DWARFAttribute]
    DW_AT_data_member_location: typing.Final[DWARFAttribute]
    DW_AT_decl_column: typing.Final[DWARFAttribute]
    DW_AT_decl_file: typing.Final[DWARFAttribute]
    DW_AT_decl_line: typing.Final[DWARFAttribute]
    DW_AT_declaration: typing.Final[DWARFAttribute]
    DW_AT_discr_list: typing.Final[DWARFAttribute]
    DW_AT_encoding: typing.Final[DWARFAttribute]
    DW_AT_external: typing.Final[DWARFAttribute]
    DW_AT_frame_base: typing.Final[DWARFAttribute]
    DW_AT_friend: typing.Final[DWARFAttribute]
    DW_AT_identifier_case: typing.Final[DWARFAttribute]
    DW_AT_macro_info: typing.Final[DWARFAttribute]
    DW_AT_namelist_item: typing.Final[DWARFAttribute]
    DW_AT_priority: typing.Final[DWARFAttribute]
    DW_AT_segment: typing.Final[DWARFAttribute]
    DW_AT_specification: typing.Final[DWARFAttribute]
    DW_AT_static_link: typing.Final[DWARFAttribute]
    DW_AT_type: typing.Final[DWARFAttribute]
    DW_AT_use_location: typing.Final[DWARFAttribute]
    DW_AT_variable_parameter: typing.Final[DWARFAttribute]
    DW_AT_virtuality: typing.Final[DWARFAttribute]
    DW_AT_vtable_elem_location: typing.Final[DWARFAttribute]
    DW_AT_allocated: typing.Final[DWARFAttribute]
    DW_AT_associated: typing.Final[DWARFAttribute]
    DW_AT_data_location: typing.Final[DWARFAttribute]
    DW_AT_byte_stride: typing.Final[DWARFAttribute]
    DW_AT_entry_pc: typing.Final[DWARFAttribute]
    DW_AT_use_UTF8: typing.Final[DWARFAttribute]
    DW_AT_extension: typing.Final[DWARFAttribute]
    DW_AT_ranges: typing.Final[DWARFAttribute]
    DW_AT_trampoline: typing.Final[DWARFAttribute]
    DW_AT_call_column: typing.Final[DWARFAttribute]
    DW_AT_call_file: typing.Final[DWARFAttribute]
    DW_AT_call_line: typing.Final[DWARFAttribute]
    DW_AT_description: typing.Final[DWARFAttribute]
    DW_AT_binary_scale: typing.Final[DWARFAttribute]
    DW_AT_decimal_scale: typing.Final[DWARFAttribute]
    DW_AT_small: typing.Final[DWARFAttribute]
    DW_AT_decimal_sign: typing.Final[DWARFAttribute]
    DW_AT_digit_count: typing.Final[DWARFAttribute]
    DW_AT_picture_string: typing.Final[DWARFAttribute]
    DW_AT_mutable: typing.Final[DWARFAttribute]
    DW_AT_threads_scaled: typing.Final[DWARFAttribute]
    DW_AT_explicit: typing.Final[DWARFAttribute]
    DW_AT_object_pointer: typing.Final[DWARFAttribute]
    DW_AT_endianity: typing.Final[DWARFAttribute]
    DW_AT_elemental: typing.Final[DWARFAttribute]
    DW_AT_pure: typing.Final[DWARFAttribute]
    DW_AT_recursive: typing.Final[DWARFAttribute]
    DW_AT_signature: typing.Final[DWARFAttribute]
    DW_AT_main_subprogram: typing.Final[DWARFAttribute]
    DW_AT_data_bit_offset: typing.Final[DWARFAttribute]
    DW_AT_const_expr: typing.Final[DWARFAttribute]
    DW_AT_enum_class: typing.Final[DWARFAttribute]
    DW_AT_linkage_name: typing.Final[DWARFAttribute]
    DW_AT_string_length_bit_size: typing.Final[DWARFAttribute]
    DW_AT_string_length_byte_size: typing.Final[DWARFAttribute]
    DW_AT_rank: typing.Final[DWARFAttribute]
    DW_AT_str_offsets_base: typing.Final[DWARFAttribute]
    DW_AT_addr_base: typing.Final[DWARFAttribute]
    DW_AT_rnglists_base: typing.Final[DWARFAttribute]
    DW_AT_dwo_name: typing.Final[DWARFAttribute]
    DW_AT_reference: typing.Final[DWARFAttribute]
    DW_AT_rvalue_reference: typing.Final[DWARFAttribute]
    DW_AT_macros: typing.Final[DWARFAttribute]
    DW_AT_call_all_calls: typing.Final[DWARFAttribute]
    DW_AT_call_all_source_calls: typing.Final[DWARFAttribute]
    DW_AT_call_all_tail_calls: typing.Final[DWARFAttribute]
    DW_AT_call_return_pc: typing.Final[DWARFAttribute]
    DW_AT_call_value: typing.Final[DWARFAttribute]
    DW_AT_call_origin: typing.Final[DWARFAttribute]
    DW_AT_call_parameter: typing.Final[DWARFAttribute]
    DW_AT_call_pc: typing.Final[DWARFAttribute]
    DW_AT_call_tail_call: typing.Final[DWARFAttribute]
    DW_AT_call_target: typing.Final[DWARFAttribute]
    DW_AT_call_target_clobbered: typing.Final[DWARFAttribute]
    DW_AT_call_data_location: typing.Final[DWARFAttribute]
    DW_AT_call_data_value: typing.Final[DWARFAttribute]
    DW_AT_noreturn: typing.Final[DWARFAttribute]
    DW_AT_alignment: typing.Final[DWARFAttribute]
    DW_AT_export_symbols: typing.Final[DWARFAttribute]
    DW_AT_deleted: typing.Final[DWARFAttribute]
    DW_AT_defaulted: typing.Final[DWARFAttribute]
    DW_AT_loclists_base: typing.Final[DWARFAttribute]
    DW_AT_lo_user: typing.Final[DWARFAttribute]
    DW_AT_hi_user: typing.Final[DWARFAttribute]
    DW_AT_MIPS_linkage_name: typing.Final[DWARFAttribute]
    DW_AT_GNU_dwo_name: typing.Final[DWARFAttribute]
    DW_AT_GNU_dwo_id: typing.Final[DWARFAttribute]
    DW_AT_GNU_ranges_base: typing.Final[DWARFAttribute]
    DW_AT_GNU_addr_base: typing.Final[DWARFAttribute]
    DW_AT_GNU_pubnames: typing.Final[DWARFAttribute]
    DW_AT_GNU_pubtypes: typing.Final[DWARFAttribute]
    DW_AT_go_kind: typing.Final[DWARFAttribute]
    DW_AT_go_key: typing.Final[DWARFAttribute]
    DW_AT_go_elem: typing.Final[DWARFAttribute]
    DW_AT_go_embedded_field: typing.Final[DWARFAttribute]
    DW_AT_go_runtime_type: typing.Final[DWARFAttribute]
    DW_AT_go_package_name: typing.Final[DWARFAttribute]
    DW_AT_go_dict_index: typing.Final[DWARFAttribute]
    DW_AT_APPLE_ptrauth_key: typing.Final[DWARFAttribute]
    DW_AT_APPLE_ptrauth_address_discriminated: typing.Final[DWARFAttribute]
    DW_AT_APPLE_ptrauth_extra_discriminator: typing.Final[DWARFAttribute]
    DW_AT_APPLE_omit_frame_ptr: typing.Final[DWARFAttribute]
    DW_AT_APPLE_optimized: typing.Final[DWARFAttribute]
    EOL: typing.Final = 0

    def getAttributeClass(self) -> java.util.Set[DWARFAttributeClass]:
        ...

    def getId(self) -> int:
        ...

    @staticmethod
    def of(attributeInt: typing.Union[jpype.JInt, int]) -> DWARFAttribute:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFAttribute:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFAttribute]:
        ...

    @property
    def attributeClass(self) -> java.util.Set[DWARFAttributeClass]:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...


class DWARFBlobAttribute(DWARFAttributeValue):
    """
    DWARF attribute with binary bytes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bytes: jpype.JArray[jpype.JByte], def_: DWARFAttributeDef[typing.Any]):
        ...

    def evaluateExpression(self, cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit) -> ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionEvaluator:
        ...

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getLength(self) -> int:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class DWARFForm(java.lang.Enum[DWARFForm]):
    """
    DWARF attribute encodings.
     
    
    Unknown encodings will prevent deserialization of DIE records.
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_FORM_addr: typing.Final[DWARFForm]
    DW_FORM_block2: typing.Final[DWARFForm]
    DW_FORM_block4: typing.Final[DWARFForm]
    DW_FORM_data2: typing.Final[DWARFForm]
    DW_FORM_data4: typing.Final[DWARFForm]
    DW_FORM_data8: typing.Final[DWARFForm]
    DW_FORM_string: typing.Final[DWARFForm]
    DW_FORM_block: typing.Final[DWARFForm]
    DW_FORM_block1: typing.Final[DWARFForm]
    DW_FORM_data1: typing.Final[DWARFForm]
    DW_FORM_flag: typing.Final[DWARFForm]
    DW_FORM_sdata: typing.Final[DWARFForm]
    DW_FORM_strp: typing.Final[DWARFForm]
    DW_FORM_udata: typing.Final[DWARFForm]
    DW_FORM_ref_addr: typing.Final[DWARFForm]
    DW_FORM_ref1: typing.Final[DWARFForm]
    DW_FORM_ref2: typing.Final[DWARFForm]
    DW_FORM_ref4: typing.Final[DWARFForm]
    DW_FORM_ref8: typing.Final[DWARFForm]
    DW_FORM_ref_udata: typing.Final[DWARFForm]
    DW_FORM_indirect: typing.Final[DWARFForm]
    DW_FORM_sec_offset: typing.Final[DWARFForm]
    DW_FORM_exprloc: typing.Final[DWARFForm]
    DW_FORM_flag_present: typing.Final[DWARFForm]
    DW_FORM_strx: typing.Final[DWARFForm]
    DW_FORM_addrx: typing.Final[DWARFForm]
    DW_FORM_ref_sup4: typing.Final[DWARFForm]
    DW_FORM_strp_sup: typing.Final[DWARFForm]
    DW_FORM_data16: typing.Final[DWARFForm]
    DW_FORM_line_strp: typing.Final[DWARFForm]
    DW_FORM_ref_sig8: typing.Final[DWARFForm]
    DW_FORM_implicit_const: typing.Final[DWARFForm]
    DW_FORM_loclistx: typing.Final[DWARFForm]
    DW_FORM_rnglistx: typing.Final[DWARFForm]
    DW_FORM_ref_sup8: typing.Final[DWARFForm]
    DW_FORM_strx1: typing.Final[DWARFForm]
    DW_FORM_strx2: typing.Final[DWARFForm]
    DW_FORM_strx3: typing.Final[DWARFForm]
    DW_FORM_strx4: typing.Final[DWARFForm]
    DW_FORM_addrx1: typing.Final[DWARFForm]
    DW_FORM_addrx2: typing.Final[DWARFForm]
    DW_FORM_addrx3: typing.Final[DWARFForm]
    DW_FORM_addrx4: typing.Final[DWARFForm]
    EOL: typing.Final = 0
    MAX_BLOCK4_SIZE: typing.Final = 1048576

    def getFormClasses(self) -> java.util.Set[DWARFAttributeClass]:
        ...

    def getId(self) -> int:
        """
        Returns the id of this DWARFForm.
        
        :return: DWARFForm numeric id
        :rtype: int
        """

    def getSize(self, context: DWARFFormContext) -> int:
        """
        Returns the size the attribute value occupies in the stream.
         
        
        This default implementation handles static sizes, as well as LEB128 and DWARF_INT sizes.
        DWARFForms that are more complex and marked as :obj:`.DYNAMIC_SIZE` will need to override
        this method and provide custom logic to determine the size of a value.
        
        :param DWARFFormContext context: :obj:`DWARFFormContext`
        :return: size of the attribute value
        :rtype: int
        :raises IOException: if error reading
        """

    def isClass(self, attrClass: DWARFAttributeClass) -> bool:
        ...

    @staticmethod
    def of(key: typing.Union[jpype.JInt, int]) -> DWARFForm:
        """
        Find the form value given raw int.
        
        :param jpype.JInt or int key: value to check
        :return: DWARFForm enum, or null if it is an unknown form
        :rtype: DWARFForm
        """

    def readValue(self, context: DWARFFormContext) -> DWARFAttributeValue:
        """
        Reads a DIE attribute value from a stream.
        
        :param DWARFFormContext context: :obj:`DWARFFormContext`
        :return: :obj:`DWARFAttributeValue`
        :rtype: DWARFAttributeValue
        :raises IOException: if error reading
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFForm:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFForm]:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def class_(self) -> jpype.JBoolean:
        ...

    @property
    def formClasses(self) -> java.util.Set[DWARFAttributeClass]:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...


class DWARFIndirectAttribute(DWARFNumericAttribute):
    """
    DWARF numeric attribute value that is an index into a lookup table
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, index: typing.Union[jpype.JLong, int], def_: DWARFAttributeDef[typing.Any]):
        ...

    def getIndex(self) -> int:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class DWARFStringAttribute(DWARFAttributeValue):
    """
    DWARF string attribute.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: typing.Union[java.lang.String, str], def_: DWARFAttributeDef[typing.Any]):
        ...

    def getValue(self, cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit) -> str:
        ...

    @property
    def value(self) -> java.lang.String:
        ...



__all__ = ["DWARFFormContext", "DWARFBooleanAttribute", "DWARFNumericAttribute", "DWARFAttributeClass", "DWARFDeferredStringAttribute", "DWARFAttributeDef", "DWARFAttributeValue", "DWARFAttribute", "DWARFBlobAttribute", "DWARFForm", "DWARFIndirectAttribute", "DWARFStringAttribute"]
