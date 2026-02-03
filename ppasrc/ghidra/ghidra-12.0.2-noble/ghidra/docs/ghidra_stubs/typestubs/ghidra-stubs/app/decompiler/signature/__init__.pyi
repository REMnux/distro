from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.util # type: ignore


class BlockSignature(DebugSignature):
    """
    A feature rooted in a basic block.  There are two forms of a block feature.
    Form 1 contains only local control-flow information about the basic block.
    Form 2 is a feature that combines two operations that occur in sequence within the block.
    This form incorporates info about the operations and data-flow info about their inputs.
    """

    class_: typing.ClassVar[java.lang.Class]
    blockSeq: ghidra.program.model.address.Address
    index: jpype.JInt
    opSeq: ghidra.program.model.pcode.SequenceNumber
    opcode: java.lang.String
    previousOpSeq: ghidra.program.model.pcode.SequenceNumber
    previousOpcode: java.lang.String

    def __init__(self):
        ...


class CopySignature(DebugSignature):
    """
    A feature representing 1 or more "stand-alone" copies in a basic block.
    A COPY operation is considered stand-alone if either a constant or a function input
    is copied into a location that is then not read directly by the function.
    These COPYs are incorporated into a single feature, which encodes the number
    and type of COPYs but does not encode the order in which they occur within the block.
    """

    class_: typing.ClassVar[java.lang.Class]
    index: jpype.JInt

    def __init__(self):
        ...


class DebugSignature(java.lang.Object):
    """
    A feature extracted from a function, with an additional description of what information is
    incorporated into the feature.  The feature may incorporate data-flow and/or control-flow
    information from the function. Internally, the feature is a 32-bit hash of this information, but
    derived classes from this abstract class include more detailed information about how the hash was formed.
    """

    class_: typing.ClassVar[java.lang.Class]
    hash: jpype.JInt

    def __init__(self):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        """
        Decode the feature from a stream.
        
        :param ghidra.program.model.pcode.Decoder decoder: is the stream decoder
        :raises DecoderException: for problems reading the stream
        """

    @staticmethod
    def decodeSignatures(decoder: ghidra.program.model.pcode.Decoder, func: ghidra.program.model.listing.Function) -> java.util.ArrayList[DebugSignature]:
        """
        Decode an array of features from the stream. Collectively, the features make up
        a "feature vector" for a specific function.  Each feature is returned as a separate descriptive object.
        
        :param ghidra.program.model.pcode.Decoder decoder: is the stream decoder
        :param ghidra.program.model.listing.Function func: is the specific function whose feature vector is being decoded
        :return: the array of feature objects
        :rtype: java.util.ArrayList[DebugSignature]
        :raises DecoderException: for problems reading from the stream
        """

    def printRaw(self, language: ghidra.program.model.lang.Language, buf: java.lang.StringBuffer):
        """
        Write a brief description of this feature to the given StringBuffer.
        
        :param ghidra.program.model.lang.Language language: is the underlying language of the function
        :param java.lang.StringBuffer buf: is the given StringBuffer
        """


class SignatureResult(java.lang.Object):
    """
    An unordered list of features describing a single function.
    Each feature represents partial information about the control-flow and/or data-flow
    making up the function. Together the features form an (approximately) complete representation
    of the function. Each feature is represented internally as 32-bit hash.  Details of how the
    feature was formed are not available through this object, but see :obj:`DebugSignature`
    This object may optionally include a list of addresses of functions directly called by
    the function being described.
    """

    class_: typing.ClassVar[java.lang.Class]
    features: jpype.JArray[jpype.JInt]
    calllist: java.util.ArrayList[ghidra.program.model.address.Address]
    hasunimplemented: jpype.JBoolean
    hasbaddata: jpype.JBoolean

    def __init__(self):
        ...

    @staticmethod
    def decode(decoder: ghidra.program.model.pcode.Decoder, func: ghidra.program.model.listing.Function, keepcalllist: typing.Union[jpype.JBoolean, bool]) -> SignatureResult:
        """
        Decode a sequence of raw feature hashes associated with a specific function from a stream.
        The stream may optionally include addresses of called functions.
        
        :param ghidra.program.model.pcode.Decoder decoder: is the stream decoder
        :param ghidra.program.model.listing.Function func: is the specific function being described
        :param jpype.JBoolean or bool keepcalllist: is true if call addresses should be stored in the result object
        :return: the decoded SignatureResult
        :rtype: SignatureResult
        :raises DecoderException: for problems reading from the stream
        """


class VarnodeSignature(DebugSignature):
    """
    A feature representing a portion of the data-flow graph rooted at a particular Varnode.
    The feature recursively incorporates details about the Varnode, the operation that defined it, and
    the operation's input Varnodes, up to a specific depth.
    """

    class_: typing.ClassVar[java.lang.Class]
    vn: ghidra.program.model.pcode.Varnode
    seqNum: ghidra.program.model.pcode.SequenceNumber
    opcode: java.lang.String

    def __init__(self):
        ...



__all__ = ["BlockSignature", "CopySignature", "DebugSignature", "SignatureResult", "VarnodeSignature"]
