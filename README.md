# log4j

## Paths to check

### UNIX

* /opt
* /usr/local
* /home

### OS X

(see also UNIX)

* /Applications
* /Library
* /Users/*/Applications
* /Users/*/Library

### Windows

* c:\Program Files
* c:\Program Files (x86)
* c:\Documents and Settings
* c:\User

## Dirty checks

* find /path/to/check -iname "*log4j*"
* grep -rq log4j /path/to/check && echo log4j matches

## Yara rules

### Personal

* log4jball.yara - Hunts for references to Log4J balls
* log4jjavaclass.yara - Hunts for references to Log4J java in class form
* log4jjavasrc.yara - Hunts for references to Log4J java in source form
* log4jimport.yara - Hunts for references to Log4J imports

## Source code to check

* https://codesearch.debian.net/search?q=log4j&literal=1&perpkg=1
