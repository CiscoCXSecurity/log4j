rule log4jjavaclass {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J java in binary form"
  strings:
    $javaclass = "org/apache/logging/log4j"
  condition:
    $javaclass
}
