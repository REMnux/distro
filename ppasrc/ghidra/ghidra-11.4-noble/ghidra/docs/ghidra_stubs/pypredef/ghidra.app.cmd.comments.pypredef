from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util
import ghidra.framework.cmd
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang # type: ignore
import java.util # type: ignore


class AppendCommentCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to append a specific type of comment on a code unit.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, commentType: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str], separator: typing.Union[java.lang.String, str]):
        """
        Construct command
        
        :param ghidra.program.model.address.Address addr: address of code unit where comment will be placed
        :param jpype.JInt or int commentType: valid comment type (see :obj:`CodeUnit.EOL_COMMENT`, 
        :obj:`CodeUnit.PLATE_COMMENT`, etc)
        :param java.lang.String or str comment: comment for code unit, should not be null
        :param java.lang.String or str separator: characters to separate the new comment from the previous comment when
        concatenating.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, commentType: ghidra.program.model.listing.CommentType, comment: typing.Union[java.lang.String, str], separator: typing.Union[java.lang.String, str]):
        """
        Construct command
        
        :param ghidra.program.model.address.Address addr: address of code unit where comment will be placed
        :param ghidra.program.model.listing.CommentType commentType: comment type
        :param java.lang.String or str comment: comment for code unit, should not be null
        :param java.lang.String or str separator: characters to separate the new comment from the previous comment when
        concatenating.
        """


class SetCommentCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to set a specific type of comment on a code unit.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, commentType: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str]):
        """
        Construct command
        
        :param ghidra.program.model.address.Address addr: address of code unit where comment will be placed
        :param jpype.JInt or int commentType: valid comment type (see CodeUnit)
        :param java.lang.String or str comment: comment for code unit
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, commentType: ghidra.program.model.listing.CommentType, comment: typing.Union[java.lang.String, str]):
        """
        Construct command
        
        :param ghidra.program.model.address.Address addr: address of code unit where comment will be placed
        :param ghidra.program.model.listing.CommentType commentType: valid comment type (see CodeUnit)
        :param java.lang.String or str comment: comment for code unit
        """

    @staticmethod
    @typing.overload
    @deprecated("Use createComment(Program, Address, String, CommentType) instead")
    def createComment(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str], commentType: typing.Union[jpype.JInt, int]):
        """
        Creates the specified comment of the specified type at address.  The current comment of
        this commentType will be cleared.
        
        :param ghidra.program.model.listing.Program program: the program being analyzed
        :param ghidra.program.model.address.Address addr: the address where data is created
        :param java.lang.String or str comment: the comment about the data
        :param jpype.JInt or int commentType: the type of comment (:obj:`CodeUnit.PLATE_COMMENT`, 
        :obj:`CodeUnit.PRE_COMMENT`, :obj:`CodeUnit.EOL_COMMENT`, :obj:`CodeUnit.POST_COMMENT`,
        :obj:`CodeUnit.REPEATABLE_COMMENT`)
        
        .. deprecated::
        
        Use :meth:`createComment(Program, Address, String, CommentType) <.createComment>` instead
        """

    @staticmethod
    @typing.overload
    def createComment(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str], commentType: ghidra.program.model.listing.CommentType):
        """
        Creates the specified comment of the specified type at address.  The current comment of
        this commentType will be cleared.
        
        :param ghidra.program.model.listing.Program program: the program being analyzed
        :param ghidra.program.model.address.Address addr: the address where data is created
        :param java.lang.String or str comment: the comment about the data
        :param ghidra.program.model.listing.CommentType commentType: the type of comment
        """


class SetCommentsCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for editing and removing comments at an address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, newPreComment: typing.Union[java.lang.String, str], newPostComment: typing.Union[java.lang.String, str], newEolComment: typing.Union[java.lang.String, str], newPlateComment: typing.Union[java.lang.String, str], newRepeatableComment: typing.Union[java.lang.String, str]):
        """
        Construct command for setting all the different types of comments at an
        address.
        
        :param ghidra.program.model.address.Address addr: address of code unit where comment will edited
        :param java.lang.String or str newPreComment: new pre comment
        :param java.lang.String or str newPostComment: new post comment
        :param java.lang.String or str newEolComment: new eol comment
        :param java.lang.String or str newPlateComment: new plate comment
        :param java.lang.String or str newRepeatableComment: new repeatable comment
        """

    def getName(self) -> str:
        """
        The name of the edit action.
        """

    @property
    def name(self) -> java.lang.String:
        ...


class CodeUnitInfoPasteCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Undoable edit for pasting code unit information at a location.
    This class actually does the work of the "paste."
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startAddr: ghidra.program.model.address.Address, infoList: java.util.List[ghidra.app.util.CodeUnitInfo], pasteLabels: typing.Union[jpype.JBoolean, bool], pasteComments: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new command for pasting comments/labels.
        
        :param ghidra.program.model.address.Address startAddr: starting address for info
        :param java.util.List[ghidra.app.util.CodeUnitInfo] infoList: list of CodeUnitInfo objects that will be applied
        :param jpype.JBoolean or bool pasteLabels: true if labels should be applied, else false
        :param jpype.JBoolean or bool pasteComments: true if comments should be applied, else false
        """

    def getName(self) -> str:
        """
        The name of the edit action.
        """

    @property
    def name(self) -> java.lang.String:
        ...



__all__ = ["AppendCommentCmd", "SetCommentCmd", "SetCommentsCmd", "CodeUnitInfoPasteCmd"]
