rule log4jjavaclass {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J java in class form"
    version = "1.0"
    creation_date = "2021-12-12"
    modification_date = "2021-12-15"
    classification = "TLP:WHITE"
  strings:
    $javaclass = "org/apache/logging/log4j"
  condition:
    $javaclass
}
