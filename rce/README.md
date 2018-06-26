# BlueBorne Android Exploit PoC

Basiert zu Teilen auf [Armis Poc](https://github.com/ArmisSecurity/blueborne/tree/master/android)

## Abhängigkeiten:

- Linux-System (Tool verwendet API von `bluez`; entwickelt und getestet auf Kali 2018.1 und Fedora 27)
- Development-Header der `libbluetooth` (z.B. per `apt install libbluetooth-dev`)
- Python 2 (leider kein Python 3, da `pwn` damit nicht richtig funktioniert)
- Python-Module (am Besten per `pip` o.ä.):
    - `pybluez` (Bluetooth-Protokoll-Unterstützung)
    - `pwn`     (Sammlung an nützlichen Funktionen für PoCs und Exploits)
    - `pick`    (für komfortable Auswahl von Opfergerät, lokales Bluetooth-Device, ...)
    - `toml`    (zum Parsender Geräte-Konfigurationen im TOML-Format)

## Benutzung

Das gesamte Script muss als Root ausgeführt werden. Die Befehle, die dies erfordern sind:

- einige Interaktionen mit dem Bluetooth-Adapter per HCI
- das Ändern der Bluetooth-Adresse des Adapters

**Hinweis**: Das Ändern der Bluetooth-Adresse ist notwendig, da die Payload des Exploits in der globalen Variable REMOTE_NAME des angegriffenen Bluetooth-Gerätes gespeichert wird. Ist dem Gerät die Adresse des Angreifers bekannt, kann es sein, dass der REMOTE_NAME aus dem Cache geladen wird und die Payload wird daher nicht korrekt platziert. Daher wird bei jedem Aufruf des Scripts die eigene Adresse des Angreifers auf eine zufällige Adresse geändert. Die eigentliche Änderung der Adresse wird an das beiliegende Tool `bdaddr` ausgelagert (muss evtl. neu kompiliert werden; beiliegendes Kompilat wurde erstellt mit GCC 7 auf 64-Bit Fedora 27). Um diesen Vorgang explizit zu unterbinden, kann die Option `--no-addr` verwendet werden. `bdaddr` funktioniert evtl. nicht für alle Bluetooth-Chips, da das Ändern der Adresse per HCI funktioniert und diese Schnittstelle Hardware-abhängig ist. Die meisten Hersteller/Chips sollten aber mittlerweile implementiert sein.

Um das Script zu starten wird die Datei `exploit.py` mittels Python 2 aufgerufen.

`sudo python2 exploit.py`

Das Script hat zusätzlich ein Kommandozeileninterface per `argparse` (auch Angreifer verdienen eine komfortable Bedienung ;-)). Darüber können ein paar Dinge angepasst werden. Die Standardeinstellungen sollten zum Ausprobieren allerdings auch reichen.

Am Interessantesten ist hier das Argument `-t|--target`, dem die Bluetooth-Adresse des Ziels übergeben wird, sofern man diese kennt. Falls diese nicht spezifiziert wird, wird nach Bluetooth-Geräten in der Umgebung gesucht und man kann sich aus einer Liste eines aussuchen. Dies erfordert allerdings, dass das Ziel zumindest kurzzeitig sichtbar ist (es ginge theoretisch auch ohne Sichtbarkeit; das habe ich allerdings hier nicht implementiert, da das relativ aufwendig ist).

Das verpflichtende Argument `--device` spezifiziert die Konfiguration/Gerät, welches für den Angriff verwendet werden soll. Es handelt sich dabei um spezifische Offsets der Bibliotheken libc.so und bluetooth.default.so des Zielgeräts. Diese werden zum Umgehen von ASLR benötigt. Zum Ermitteln wird eine Kopie der Bibliotheken und ein Gerät benötigt, welches den Bluetooth-Service zur Laufzeit debuggen kann (z.B. per Remote-Debugging in GDB).
