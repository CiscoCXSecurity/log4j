rule log4jJndiLookup {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J JndiLookup"
    version = "1.0"
    creation_date = "2021-12-13"
    modification_date = "2021-12-15"
    classification = "TLP:WHITE"
  strings:
    $jndilookup = "JndiLookup"
  condition:
    $jndilookup
}
