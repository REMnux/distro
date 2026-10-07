@echo off

if /i "%1"=="release" (
	set mode=Release
	set suf=
) else (
	set mode=Debug
	set suf=d
)

if /i "%PROCESSOR_ARCHITECTURE%" == "AMD64" (
	set mode="%mode%|x64"
) else (
	set mode="%mode%|Win32"
)

@echo.
@echo ******** Building project(%mode%) ********
@echo.
mkdir bin lib include
devenv cybozulib.sln /Build %mode%
@rem for /F "usebackq" %%p in (`"dir /S /B *.vcproj"`) do devenv %%p /Build %mode%
@echo.
@echo ******** Unit test ********
@echo.
rm -rf result.txt
for %%e in (bin\*_test%suf%.exe) do (%%e | grep "ctest:name") >> result.txt
grep -v "ng=0, exception=0" result.txt
if %ERRORLEVEL% == 0 goto sample
echo "all unit tests are ok"
:sample
@echo.
@echo ******** Run sample ********
@echo.
bin\exception_smpl%suf%.exe

:end
