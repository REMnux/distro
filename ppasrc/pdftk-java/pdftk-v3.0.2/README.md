This is a port of [pfdtk](https://www.pdflabs.com/tools/pdftk-server/)
into Java. The current goal is to make a translation as faithful as it
is reasonable, and to leave possible improvements and refactoring for
later. So far all code has been manually translated and it passes the
test suite of [php-pdftk](https://github.com/mikehaertl/php-pdftk),
but a lot more testing is needed. Due to the differences between C++
and Java, it is likely that a few bugs have sneaked in with respect to
the original; any help in catching them will be appreciated.

## Dependencies

 - jdk >= 1.7
 - commons-lang3
 - bcprov
 - gradle or ant (build time)
 - ivy (optionally for ant, for resolving dependencies at build time)

## Building and running with Gradle

If you have gradle installed you can produce a standalone jar with:
```
gradle shadowJar
```

This can then be run with just java installed like:
```
java -jar build/libs/pdftk-all.jar
```

The build configuration is relatively simple so it should work with most 
versions of gradle (tested from 3.4 to 4.8) but if you have problems try
installing gradle wrapper at a particular version and then running the wrapper:
```
gradle wrapper --gradle-version 4.8
./gradlew shadowJar
```

## Building and running with ant

With ivy:
```
$ ant
```

Without ivy: install bcprov and commons-lang3, make a directory `lib`
and link `bcprov.jar` and `commons-lang3.jar` into it. Then:
```
$ ant jar
```

To run:
```
$ java -cp build/jar/pdftk.jar:lib/bcprov.jar:lib/commons-lang3.jar com.gitlab.pdftk_java.pdftk
```

## Source organization

`java/com/` contains the translated Java sources. Currently these are a
few large files, but they should be split into one class per file.

`java/pdftk/` contains the sources for an old, yet-to-be-determined
version of the iText library. They were modified in the original C++
sources, hence it is not obvious whether they can be replaced by a
more recent vanilla version.
