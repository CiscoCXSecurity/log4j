rule log4jimport {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J imports"
    version = "1.0"
    creation_date = "2021-12-12"
    modification_date = "2021-12-15"
    classification = "TLP:WHITE"
  strings:
    $importjava = /import\w+org\.apache\.logging\.log4j/
    $importivy = /<dependency\w+org="org\.apache\.logging\.log4j"/
    $importmaven = /<groupId>.{1,128}log4j/
    $importgradle = /compile\w+group:\w*'org\.apache\.logging\.log4j'/
  condition:
   $importjava or $importivy or $importmaven or $importgradle
}
