from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import junit.framework # type: ignore
import org.jdom2 # type: ignore


class PCodeTestCombinedTestResults(java.lang.Object):

    @typing.type_check_only
    class IgnoreTestPredicate(java.util.function.Predicate[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NamedTestColumn(java.lang.Comparable[PCodeTestCombinedTestResults.NamedTestColumn]):

        class_: typing.ClassVar[java.lang.Class]

        def adjustWidth(self, testResults: PCodeTestResults.TestResults) -> None:
            ...

        def getColumnWidth(self) -> int:
            ...

        def getGroupTestName(self) -> str:
            """
            
            
            :return: ``<group-name>.<test-name>``
            :rtype: str
            """

        def getTestName(self) -> str:
            """
            
            
            :return: ``<test-name>``
            :rtype: str
            """

        @property
        def groupTestName(self) -> java.lang.String:
            ...

        @property
        def columnWidth(self) -> jpype.JInt:
            ...

        @property
        def testName(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]
    FILENAME: typing.Final = "pcode_test_results"

    def addIgnoredTests(self, junitName: typing.Union[java.lang.String, str], *testNames: typing.Union[java.lang.String, str]) -> None:
        ...

    def getTestResults(self, jUnitName: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]) -> PCodeTestResults:
        ...


class PCodeTestGroup(java.lang.Comparable[PCodeTestGroup]):
    """
    ``PCodeTestGroup`` identifies a test group function and its corresponding
    PCodeTestGroupControlBlock.
    """

    class_: typing.ClassVar[java.lang.Class]
    FUNCTION_NAME_PREFIX: typing.Final = "main_"
    """
    All test-group function names defined within the test binary must start with "main_"
    """

    IGNORED_TAG: typing.Final = "IGNORED"
    testGroupName: typing.Final[java.lang.String]
    functionEntryPtr: typing.Final[ghidra.program.model.address.Address]
    mainTestControlBlock: typing.Final[PCodeTestControlBlock]
    controlBlock: typing.Final[PCodeTestGroupControlBlock]

    def getTestFailures(self) -> java.util.List[java.lang.String]:
        """
        
        
        :return: list of recorded emulation test failures
        :rtype: java.util.List[java.lang.String]
        """

    @property
    def testFailures(self) -> java.util.List[java.lang.String]:
        ...


@typing.type_check_only
class TestLogger(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def log(self, testGroup: PCodeTestGroup, msg: typing.Union[java.lang.String, str]) -> None:
        ...

    @typing.overload
    def log(self, testGroup: PCodeTestGroup, msg: typing.Union[java.lang.String, str], t: java.lang.Throwable) -> None:
        ...

    @typing.overload
    def logState(self, testRunner: EmulatorTestRunner) -> None:
        ...

    @typing.overload
    def logState(self, emulatorTestRunner: EmulatorTestRunner, dumpAddr: ghidra.program.model.address.Address, dumpSize: typing.Union[jpype.JInt, int], elementSize: typing.Union[jpype.JInt, int], elementFormat: EmulatorTestRunner.DumpFormat, comment: typing.Union[java.lang.String, str]) -> None:
        ...


class PCodeTestControlBlock(PCodeTestAbstractControlBlock):
    """
    ``PCodeTestControlBlock`` data is read from each binary test file and identified by the
    MAIN_CONTROL_BLOCK_MAGIC 64-bit character field value at the start of the data structure. Only
    one instance of this should exist within the binary.
    """

    class_: typing.ClassVar[java.lang.Class]
    testFile: typing.Final[PCodeTestFile]
    cachedProgramPath: typing.Final[java.lang.String]

    def getBreakOnDoneAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getBreakOnErrorAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getBreakOnPassAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getPrintfBufferAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getSprintf5Address(self) -> ghidra.program.model.address.Address:
        ...

    def getTestGroups(self) -> java.util.List[PCodeTestGroup]:
        ...

    def getTestResults(self) -> PCodeTestResults:
        ...

    @property
    def testResults(self) -> PCodeTestResults:
        ...

    @property
    def breakOnPassAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def testGroups(self) -> java.util.List[PCodeTestGroup]:
        ...

    @property
    def sprintf5Address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def breakOnErrorAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def printfBufferAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def breakOnDoneAddress(self) -> ghidra.program.model.address.Address:
        ...


class PCodeTestAbstractControlBlock(java.lang.Object):
    """
    ``PCodeTestAbstractControlBlock`` data is models the general capabilities of the
    TestInfo data structure which is used for different puposes as handled by extensions of this
    class.
    """

    @typing.type_check_only
    class InvalidControlBlockException(java.lang.Exception):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, msg: typing.Union[java.lang.String, str]) -> None:
            ...

        @typing.overload
        def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable) -> None:
            ...


    class FunctionInfo(java.lang.Comparable[PCodeTestAbstractControlBlock.FunctionInfo]):

        class_: typing.ClassVar[java.lang.Class]
        functionName: typing.Final[java.lang.String]
        functionAddr: typing.Final[ghidra.program.model.address.Address]
        numberOfAsserts: typing.Final[jpype.JInt]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getFunctionInfo(self, functionName: typing.Union[java.lang.String, str]) -> PCodeTestAbstractControlBlock.FunctionInfo:
        ...

    @typing.overload
    def getFunctionInfo(self, functionIndex: typing.Union[jpype.JInt, int]) -> PCodeTestAbstractControlBlock.FunctionInfo:
        ...

    def getInfoStructureAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getNumberFunctions(self) -> int:
        ...

    @property
    def functionInfo(self) -> PCodeTestAbstractControlBlock.FunctionInfo:
        ...

    @property
    def numberFunctions(self) -> jpype.JInt:
        ...

    @property
    def infoStructureAddress(self) -> ghidra.program.model.address.Address:
        ...


class EmulatorTestRunner(java.lang.Object):

    @typing.type_check_only
    class MyCallbacks(ghidra.pcode.emu.PcodeEmulationCallbacks[jpype.JArray[jpype.JByte]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class DumpFormat(java.lang.Enum[EmulatorTestRunner.DumpFormat]):

        class_: typing.ClassVar[java.lang.Class]
        HEX: typing.Final[EmulatorTestRunner.DumpFormat]
        DECIMAL: typing.Final[EmulatorTestRunner.DumpFormat]
        FLOAT: typing.Final[EmulatorTestRunner.DumpFormat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> EmulatorTestRunner.DumpFormat:
            ...

        @staticmethod
        def values() -> jpype.JArray[EmulatorTestRunner.DumpFormat]:
            ...


    @typing.type_check_only
    class DumpPoint(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def toString(self, addrStr: typing.Union[java.lang.String, str]) -> str:
            ...


    @typing.type_check_only
    class AddressDumpPoint(EmulatorTestRunner.DumpPoint):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RegisterRelativeDumpPoint(EmulatorTestRunner.DumpPoint):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, testGroup: PCodeTestGroup, executionListener: ExecutionListener) -> None:
        ...

    @typing.overload
    def addDumpPoint(self, breakAddr: ghidra.program.model.address.Address, dumpAddr: ghidra.program.model.address.Address, dumpSize: typing.Union[jpype.JInt, int], elementSize: typing.Union[jpype.JInt, int], elementFormat: EmulatorTestRunner.DumpFormat, comment: typing.Union[java.lang.String, str]) -> None:
        """
        Add memory dump point
        
        :param ghidra.program.model.address.Address breakAddr: instruction address at which execution should pause (before it is executed)
                    so that the specified memory may be dumped to the log during trace execution mode.
        :param ghidra.program.model.address.Address dumpAddr: memory address which should be dumped
        :param jpype.JInt or int dumpSize: number elements which should be dumped
        :param jpype.JInt or int elementSize: size of each element in bytes (be reasonable!)
        :param EmulatorTestRunner.DumpFormat elementFormat: HEX, DECIMAL or FLOAT
        :param java.lang.String or str comment: dump comment
        """

    @typing.overload
    def addDumpPoint(self, breakAddr: ghidra.program.model.address.Address, dumpAddrReg: ghidra.program.model.lang.Register, relativeOffset: typing.Union[jpype.JInt, int], dumpAddrSpace: ghidra.program.model.address.AddressSpace, dumpSize: typing.Union[jpype.JInt, int], elementSize: typing.Union[jpype.JInt, int], elementFormat: EmulatorTestRunner.DumpFormat, comment: typing.Union[java.lang.String, str]) -> None:
        """
        Add memory dump point
        
        :param ghidra.program.model.address.Address breakAddr: instruction address at which execution should pause (before it is executed)
                    so that the specified memory may be dumped to the log during trace execution mode.
        :param ghidra.program.model.lang.Register dumpAddrReg: register containing the memory address offset which should be dumped
        :param jpype.JInt or int relativeOffset: dump register relative offset
        :param ghidra.program.model.address.AddressSpace dumpAddrSpace: address space to which memory offset should be applied
        :param jpype.JInt or int dumpSize: number elements which should be dumped
        :param jpype.JInt or int elementSize: size of each element in bytes (be reasonable!)
        :param EmulatorTestRunner.DumpFormat elementFormat: HEX, DECIMAL or FLOAT
        :param java.lang.String or str comment: dump comment
        """

    def dispose(self) -> None:
        ...

    def execute(self, timeLimitMS: typing.Union[jpype.JInt, int]) -> bool:
        """
        Execute test group without instruction stepping/tracing
        
        :param jpype.JInt or int timeLimitMS: the maximum number of milliseconds to execute before suspending and
                    terminating
        :return: true if execution reached the "done" breakpoint
        :rtype: bool
        """

    def executeSingleStep(self, stepLimit: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def getCallOtherErrors(self) -> int:
        """
        Get number of CALLOTHER errors detected when a test pass was registered. This number should
        be subtracted from the pass count and possibly added to the failure count. Number does not
        reflect total number of CALLOTHER pcodeops encountered but only the number of passed tests
        affected. See log for all CALLOTHER executions detected.
        
        :return: number of CALLOTHER errors
        :rtype: int
        """

    def getCurrentAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getCurrentInstruction(self) -> ghidra.program.model.listing.Instruction:
        ...

    def getEmuError(self) -> str:
        ...

    def getEmulatorThread(self) -> ghidra.pcode.emu.PcodeThread[jpype.JArray[jpype.JByte]]:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getRegisterValue(self, reg: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        ...

    def getRegisterValueString(self, reg: ghidra.program.model.lang.Register) -> str:
        ...

    def getTestGroup(self) -> PCodeTestGroup:
        ...

    def runToBreakpoint(self) -> bool:
        """
        Allows the emulator to run until it's interrupted, returning true if the interrupt is caused
        by a breakpoint.
        
        :return: true if interrupted by a breakpoint, false otherwise. This may also run indefinitely.
        :rtype: bool
        """

    def setContextRegister(self, ctxRegValue: ghidra.program.model.lang.RegisterValue) -> None:
        ...

    @typing.overload
    def setRegister(self, regName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]) -> None:
        ...

    @typing.overload
    def setRegister(self, regName: typing.Union[java.lang.String, str], value: java.math.BigInteger) -> None:
        ...

    def stepIgnoreBreakpoints(self) -> bool:
        """
        Step the emulator one instruction, returning true if it's completed without interruption.
        
        :return: true if completed, false if interrupted. Though unlikely, this may also run
                indefinitely.
        :rtype: bool
        """

    @property
    def currentInstruction(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def emulatorThread(self) -> ghidra.pcode.emu.PcodeThread[jpype.JArray[jpype.JByte]]:
        ...

    @property
    def callOtherErrors(self) -> jpype.JInt:
        ...

    @property
    def testGroup(self) -> PCodeTestGroup:
        ...

    @property
    def registerValueString(self) -> java.lang.String:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def emuError(self) -> java.lang.String:
        ...

    @property
    def registerValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def currentAddress(self) -> ghidra.program.model.address.Address:
        ...


class PCodeTestGroupControlBlock(PCodeTestAbstractControlBlock):
    """
    ``PCodeTestGroupControlBlock`` corresponds to each test group contained within 
    a binary test file and identified by the GROUP_CONTROL_BLOCK_MAGIC 64-bit character 
    field value at the start of the data structure.
    """

    class_: typing.ClassVar[java.lang.Class]
    mainTestControlBlock: typing.Final[PCodeTestControlBlock]

    def getTestGroupMainAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getTestGroupName(self) -> str:
        ...

    @property
    def testGroupMainAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def testGroupName(self) -> java.lang.String:
        ...


class PCodeTestFile(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    file: typing.Final[java.io.File]
    fileReferencePath: typing.Final[java.lang.String]

    def __init__(self, f: jpype.protocol.SupportsPath, fileReferencePath: typing.Union[java.lang.String, str]) -> None:
        ...


class ExecutionListener(TestLogger):

    class_: typing.ClassVar[java.lang.Class]

    def logRead(self, testRunner: EmulatorTestRunner, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], values: jpype.JArray[jpype.JByte]) -> None:
        ...

    def logWrite(self, testRunner: EmulatorTestRunner, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], values: jpype.JArray[jpype.JByte]) -> None:
        ...


class PCodeTestResults(java.lang.Object):

    @typing.type_check_only
    class TestResults(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    TAG_NAME: typing.ClassVar[java.lang.String]

    def __init__(self, root: org.jdom2.Element, ignoreTestPredicate: java.util.function.Predicate[java.lang.String]) -> None:
        ...

    def getCallOtherResult(self, groupName: typing.Union[java.lang.String, str], testName: typing.Union[java.lang.String, str]) -> int:
        ...

    def getFailResult(self, groupName: typing.Union[java.lang.String, str], testName: typing.Union[java.lang.String, str]) -> int:
        ...

    def getGroupTestNames(self) -> java.util.Collection[java.lang.String]:
        """
        
        
        :return: collection of group/testNames in the form ``"<groupName>.<testName>"``
        :rtype: java.util.Collection[java.lang.String]
        """

    def getIgnoredResult(self, groupName: typing.Union[java.lang.String, str], testName: typing.Union[java.lang.String, str]) -> int:
        ...

    def getJUnitName(self) -> str:
        ...

    def getNumberOfTests(self) -> int:
        ...

    def getPassResult(self, groupName: typing.Union[java.lang.String, str], testName: typing.Union[java.lang.String, str]) -> int:
        ...

    def getTime(self) -> str:
        ...

    def getTotalAsserts(self, groupName: typing.Union[java.lang.String, str], testName: typing.Union[java.lang.String, str]) -> int:
        ...

    def hadSevereFailure(self, groupName: typing.Union[java.lang.String, str], testName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def isIgnoredTest(self, testName: typing.Union[java.lang.String, str]) -> bool:
        ...

    @property
    def jUnitName(self) -> java.lang.String:
        ...

    @property
    def groupTestNames(self) -> java.util.Collection[java.lang.String]:
        ...

    @property
    def ignoredTest(self) -> jpype.JBoolean:
        ...

    @property
    def time(self) -> java.lang.String:
        ...

    @property
    def numberOfTests(self) -> jpype.JInt:
        ...


class ProcessorEmulatorTestAdapter(junit.framework.TestCase, ExecutionListener):
    """
    ``ProcessorEmulatorTestAdapter`` provides an abstract JUnit test implementation for
    processor-specific test cases. All test cases which extend this class must have a class name
    which ends with 'EmulatorTest' and starts with the processor designator which will be used to
    identify associated test binaries within either the processor module's data/pcodetests/ directory
    or the Ghidra/Test/TestResources/data/pcodetests/ directory generally contained within the binary
    repository (e.g., ghidra.bin).
     
    
    Within the pcodetests directory all files and folders which start with the prefix
    <processor-designator>_pcodetest* will be processed. All files contained within a
    matching subdirectory will be treated as related binaries and imported. Any *.gzf file will be
    imported but assumed to be pre-analyzed. Binary files to be imported and analyzed must utilize
    the *.out file extension.
     
    
    JUnit X86EmulatorTest could utilize the following binary file naming strategy:
     
     
    pcodetests/X86_PCodeTests
    - binary1.o
    - binary2.o
    - binary3.gzf
    pcodetests/X86_PCodeTests/data (could be used for any associated files not to be imported)
    - binary3.o
    - binary3.d
    
    or, a single binary file could suffice:
    - pcodetests/X86_PCodeTest.out
     
    
    Any *.out binary found will be imported and analyzed. The resulting program will be stored as a
    gzf in the test-output cache directory. These cached files will be used instead of a test
    resource binary if that binary's md5 checksum has not changed since its cached gzf was created.
    This use of cache files will allow the tests to run quickly on subsequent executions. If
    re-analysis is required, the cache will need to be cleared manually.
     
    NOTES: 1. Dummy Test Methods must be added for all known test groups. See bottom of this file.
    This all allows for the single test trace mode execution to work within Eclipse. 2. Trace logging
    disabled by default when all test groups are run (see buildEmulatorTestSuite method). Specific
    traceLevel and traceLog file controlled via environment properties EmuTestTraceLevel and
    EmuTestTraceFile. 3. The TestInfo structure must be properly maintained within the datatype
    archive EmuTesting.gdt and field naming consistent with use in PCodeTestControlBlock.java 4. The
    :meth:`initializeState(EmulatorTestRunner, Program) <.initializeState>` may be overriden to initialize the register
    values if needed. This should be based upon symbols or other program information if possible
    since hardcoded constants may not track future builds of a test binaries. An attempt is made to
    initialize the stack pointer automatically based upon well known stack initialization symbols.
    """

    @typing.type_check_only
    class MyTestFailure(junit.framework.TestSuite):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EmulationTestSuite(junit.framework.TestSuite):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DumpFormatter(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HexFormatter(ProcessorEmulatorTestAdapter.DumpFormatter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DecimalFormatter(ProcessorEmulatorTestAdapter.DumpFormatter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FloatFormatter(ProcessorEmulatorTestAdapter.DumpFormatter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LogData(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    BATCH_MODE_OUTPUT_DIR: typing.Final[java.lang.String]
    traceDisabled: typing.ClassVar[jpype.JBoolean]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], languageID: typing.Union[java.lang.String, str], compilerSpecID: typing.Union[java.lang.String, str], regDumpSetNames: jpype.JArray[java.lang.String]) -> None:
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], languageID: typing.Union[java.lang.String, str], compilerSpecID: typing.Union[java.lang.String, str], regDumpSetNames: jpype.JArray[java.lang.String], floatRegSetNames: jpype.JArray[java.lang.String]) -> None:
        ...

    @staticmethod
    def buildEmulatorTestSuite(emulatorTestClass: java.lang.Class[typing.Any]) -> junit.framework.Test:
        """
        Create TestSuite based upon available test groups contained within binary test files
        associated with target processor.
        
        :param java.lang.Class[typing.Any] emulatorTestClass: test which extends ``ProcessorEmulatorTestAdapter`` and
                    whose name ends with "EmulatorTest".
        :return: test suite
        :rtype: junit.framework.Test
        """

    @staticmethod
    def deleteResultFilesOnStartup() -> None:
        ...

    def failOnDisassemblyErrors(self) -> bool:
        """
        
        
        :return: true if test run should fail up-front if binary contains disassembly errors
        :rtype: bool
        """

    def failOnRelocationErrors(self) -> bool:
        """
        
        
        :return: true if test run should fail up-front if binary contains relocation errors
        :rtype: bool
        """

    @staticmethod
    def getTestFailure(emulatorTestClass: java.lang.Class[typing.Any], message: typing.Union[java.lang.String, str], t: java.lang.Throwable) -> junit.framework.Test:
        ...

    def getUniqueGlobalSymbol(self, program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        ...

    def runTest(self) -> None:
        """
        Single unit test which handles named test group specified during test instantiation.
        """

    def test_BIOPS(self) -> None:
        ...

    def test_BIOPS2(self) -> None:
        ...

    def test_BIOPS4(self) -> None:
        ...

    def test_BIOPS_DOUBLE(self) -> None:
        ...

    def test_BIOPS_FLOAT(self) -> None:
        ...

    def test_BIOPS_LONGLONG(self) -> None:
        ...

    def test_BitManipulation(self) -> None:
        ...

    def test_DecisionMaking(self) -> None:
        ...

    def test_GlobalVariables(self) -> None:
        ...

    def test_IterativeProcessingDoWhile(self) -> None:
        ...

    def test_IterativeProcessingFor(self) -> None:
        ...

    def test_IterativeProcessingWhile(self) -> None:
        ...

    def test_ParameterPassing1(self) -> None:
        ...

    def test_ParameterPassing2(self) -> None:
        ...

    def test_ParameterPassing3(self) -> None:
        ...

    def test_PointerManipulation(self) -> None:
        ...

    def test_StructUnionManipulation(self) -> None:
        ...

    def test_asm(self) -> None:
        ...

    def test_misc(self) -> None:
        ...



__all__ = ["PCodeTestCombinedTestResults", "PCodeTestGroup", "TestLogger", "PCodeTestControlBlock", "PCodeTestAbstractControlBlock", "EmulatorTestRunner", "PCodeTestGroupControlBlock", "PCodeTestFile", "ExecutionListener", "PCodeTestResults", "ProcessorEmulatorTestAdapter"]
