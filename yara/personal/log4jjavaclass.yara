rule log4jjavaclass {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J java in class form"
  strings:
    $javaclass = "org/apache/logging/log4j"
  condition:
    $javaclass
}
