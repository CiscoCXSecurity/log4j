rule log4jJndiLookup {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J JndiLookup"
  strings:
    $jndilookup = "JndiLookup"
  condition:
    $jndilookup
}
