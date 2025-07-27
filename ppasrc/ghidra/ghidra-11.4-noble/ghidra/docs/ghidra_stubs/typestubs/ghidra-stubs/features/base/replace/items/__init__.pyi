from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.base.quickfix
import ghidra.features.base.replace
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import java.lang # type: ignore


class RenameMemoryBlockQuickFix(ghidra.features.base.replace.RenameQuickFix):
    """
    QuickFix for renaming memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock, newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the memory block to be renamed
        :param ghidra.program.model.mem.MemoryBlock block: the memory block to be renamed
        :param java.lang.String or str newName: the new name for the memory block
        """


class UpdateCommentQuickFix(ghidra.features.base.quickfix.QuickFix):
    """
    QuickFix for updating listing comments.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, type: ghidra.program.model.listing.CommentType, comment: typing.Union[java.lang.String, str], newComment: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the comment to be renamed
        :param ghidra.program.model.address.Address address: The address where the comment is located
        :param ghidra.program.model.listing.CommentType type: the type of comment (Pre, Post, EOL, etc.)
        :param java.lang.String or str comment: the original comment text
        :param java.lang.String or str newComment: the new comment text
        """


class UpdateEnumCommentQuickFix(ghidra.features.base.quickfix.QuickFix):
    """
    QuickFix for updating enum value comments
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, enumDt: ghidra.program.model.data.Enum, valueName: typing.Union[java.lang.String, str], newComment: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the enum value whose comment is to be updated
        :param ghidra.program.model.data.Enum enumDt: the enum whose field value comment is to be changed
        :param java.lang.String or str valueName: the enum value name whose comment is to be changed
        :param java.lang.String or str newComment: the new comment for the enum value
        """


class UpdateDataTypeDescriptionQuickFix(ghidra.features.base.quickfix.QuickFix):
    """
    QuickFix for updating a datatype's description (Only supported on structures, unions, or enums)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, dataType: ghidra.program.model.data.DataType, newDescription: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the datatype description to be updated.
        :param ghidra.program.model.data.DataType dataType: the datatype being renamed
        :param java.lang.String or str newDescription: the new name for the datatype
        """


class RenameProgramTreeGroupQuickFix(ghidra.features.base.replace.RenameQuickFix):
    """
    QuickFix for renaming program tree groups (modules or fragments)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, group: ghidra.program.model.listing.Group, newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the program tree group to be renamed
        :param ghidra.program.model.listing.Group group: the program tree module or fragment to be renamed
        :param java.lang.String or str newName: the new name for the memory block
        """


class RenameSymbolQuickFix(ghidra.features.base.replace.RenameQuickFix):
    """
    QuickFix for renaming symbols (labels, functions, namespaces, classes, parameters, or 
    local variables).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbol: ghidra.program.model.symbol.Symbol, newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol to be renamed
        :param java.lang.String or str newName: the new name for the symbol
        """


class RenameCategoryQuickFix(ghidra.features.base.replace.RenameQuickFix):
    """
    QuickFix for renaming datatype categories.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, category: ghidra.program.model.data.Category, newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the category to be renamed
        :param ghidra.program.model.data.Category category: the category to be renamed
        :param java.lang.String or str newName: the new name for the category
        """


class RenameDataTypeQuickFix(ghidra.features.base.replace.RenameQuickFix):
    """
    QuickFix for renaming datatypes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, dataType: ghidra.program.model.data.DataType, newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the datatype to be renamed
        :param ghidra.program.model.data.DataType dataType: the datatype being renamed
        :param java.lang.String or str newName: the new name for the datatype
        """


class UpdateFieldCommentQuickFix(CompositeFieldQuickFix):
    """
    QuickFix for updating structure or union field comments
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, composite: ghidra.program.model.data.Composite, fieldName: typing.Union[java.lang.String, str], ordinal: typing.Union[jpype.JInt, int], original: typing.Union[java.lang.String, str], newComment: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the enum value whose comment is to be updated
        :param ghidra.program.model.data.Composite composite: the structure or union whose field comment is to be changed
        :param java.lang.String or str fieldName: the field name whose comment is to be changed
        :param jpype.JInt or int ordinal: the ordinal of the field being renamed with its containing composite
        :param java.lang.String or str original: the original comment of the field
        :param java.lang.String or str newComment: the new comment for the field
        """


class RenameFieldQuickFix(CompositeFieldQuickFix):
    """
    QuickFix for renaming structure or union fields
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, composite: ghidra.program.model.data.Composite, ordinal: typing.Union[jpype.JInt, int], original: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the structure or union field to be renamed
        :param ghidra.program.model.data.Composite composite: the composite whose field is being renamed
        :param jpype.JInt or int ordinal: the ordinal of the field being renamed with its containing composite
        :param java.lang.String or str original: the original name of the field
        :param java.lang.String or str newName: the new name for the enum value
        """


class RenameEnumValueQuickFix(ghidra.features.base.replace.RenameQuickFix):
    """
    QuickFix for renaming enum values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, enumDt: ghidra.program.model.data.Enum, valueName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the enum to be renamed
        :param ghidra.program.model.data.Enum enumDt: the enum whose value is being renamed
        :param java.lang.String or str valueName: the enum value name being changed
        :param java.lang.String or str newName: the new name for the enum value
        """


class CompositeFieldQuickFix(ghidra.features.base.quickfix.QuickFix):
    """
    Base class for Composite field Quick Fixes. Primarily exists to host the logic for finding
    components in a composite even as it is changing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, composite: ghidra.program.model.data.Composite, ordinal: typing.Union[jpype.JInt, int], original: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program containing the composite.
        :param ghidra.program.model.data.Composite composite: the composite being changed
        :param jpype.JInt or int ordinal: the ordinal of the field within the composite
        :param java.lang.String or str original: the original name of the field
        :param java.lang.String or str newName: the new name for the field
        """



__all__ = ["RenameMemoryBlockQuickFix", "UpdateCommentQuickFix", "UpdateEnumCommentQuickFix", "UpdateDataTypeDescriptionQuickFix", "RenameProgramTreeGroupQuickFix", "RenameSymbolQuickFix", "RenameCategoryQuickFix", "RenameDataTypeQuickFix", "UpdateFieldCommentQuickFix", "RenameFieldQuickFix", "RenameEnumValueQuickFix", "CompositeFieldQuickFix"]
