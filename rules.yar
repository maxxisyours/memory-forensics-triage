rule SuspiciousProcess {
    meta:
        description = "Detects suspicious process names"
        severity = "HIGH"
    strings:
        $a = "mimikatz" nocase
        $b = "dumpit" nocase
        $c = "pwdump" nocase
        $d = "fgdump" nocase
    condition:
        any of them
}

rule RansomwareBehaviour {
    meta:
        description = "Detects common ransomware strings"
        severity = "HIGH"
    strings:
        $a = "YOUR FILES ARE ENCRYPTED" nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
        $d = "ransom" nocase
    condition:
        any of them
}
