from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang # type: ignore


class FunctionSignatureParser(java.lang.Object):
    """
    Class for parsing function signatures. This class attempts to be much more
    flexible than a full parser that requires correct C or C++ syntax. To achieve
    this, it scans the original function signature (if present) for names that
    would cause parse problems (parens, brackets, asterisk, commas, and spaces). 
    If it finds any problem names, it looks for those strings in the text to be 
    parsed and if it finds them, it replaces them with substitutes that parse 
    easily. Then, after parsing, those replacement strings are then restored to 
    their original values.
     
    
    Some examples of valid c++ that would fail due to the current limitations:
     
    
    void foo(myclass<int, float> x) - fails due to comma in x's data type name
    int operator()(int x) - fails due to parens in function name unsigned int
    bar(float y) - fails due to space in return type name
     
    
    Note: you can edit signatures that already have these features as long as
    your modifications don't affect the pieces containing parens, commas or
    spaces in their name.
    """

    @typing.type_check_only
    class ParserDataTypeManagerService(ghidra.app.services.DataTypeQueryService):
        """
        Provides a simple caching datatype manager service wrapper.
        
        Implementation intended for use with :obj:`FunctionSignatureParser`
        and underlying :obj:`DataTypeParser` and :obj:`DataTypeUtilities` classes.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, destDataTypeManager: ghidra.program.model.data.DataTypeManager, service: ghidra.app.services.DataTypeQueryService):
        """
        Constructs a SignatureParser for a program.  The destDataTypeManager and/or
        service must be specified.
        
        :param ghidra.program.model.data.DataTypeManager destDataTypeManager: the destination datatype maanger.
        :param ghidra.app.services.DataTypeQueryService service: the DataTypeManagerService to use for resolving datatypes that
                        can't be found in the given program. Can be null to utilize
                        program based types only.
        """

    def parse(self, originalSignature: ghidra.program.model.listing.FunctionSignature, signatureText: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.FunctionDefinitionDataType:
        """
        Parse the given function signature text into a FunctionDefinitionDataType.
        
        :param ghidra.program.model.listing.FunctionSignature originalSignature: the function signature before editing. This may be
                                null if the user is entering a new signature instead
                                of editing an existing one.
        :param java.lang.String or str signatureText: the text to be parsed into a function signature.
        :return: the FunctionDefinitionDataType resulting from parsing.
        :rtype: ghidra.program.model.data.FunctionDefinitionDataType
        :raises ParseException: if the text could not be parsed.
        :raises CancelledException: if parse cancelled by user
        """



__all__ = ["FunctionSignatureParser"]
