"""sovereignwatch — Prinzipbeweis: Telemetrie zuordnen, belegen und ersetzen.

Ein Netzwerkfilter wie Pi-hole oder AdGuard sieht eine Verbindung. Er sieht nicht, **welches
Programm** sie aufbaut und **was darin steht**. Wer sie trotzdem blockiert, bringt
Anwendungen zum Stillstand, weil sie auf eine Antwort warten, die nie kommt. Genau
zwischen diesen zwei schlechten Möglichkeiten sitzt heute jede Datenschutzbeauftragte.

Dieses Modul zeigt die drei Schritte, mit denen SovereignWatch da herauskommt:

1. **Zuordnung.** Aus den aufgezeichneten Ereignissen (produktiv: eBPF über `bcc`) wird
   abgeleitet, welcher Prozess welche Verbindung verursacht hat. Das ist der blinde Fleck
   jedes DNS-Filters — und die Voraussetzung dafür, dass ein Befund jemandem zuzurechnen
   ist.
2. **Beleg.** Die Nutzdaten werden gegen bekannte Systemkennungen gehalten (MAC-Adresse,
   Rechnername, Seriennummer). Gefunden wird nicht „verdächtiger Verkehr", sondern: dieses
   Programm hat diese Kennung an diesen Server geschickt. Auch verschachtelt und
   base64-kodiert.
3. **Ersatz.** Aus der aufgezeichneten Serverantwort wird deren Schema abgeleitet und ein
   lokaler Antwortdienst erzeugt, der sie liefert. Damit läuft das Programm ohne die
   Verbindung weiter, statt zu hängen.

Ausführen:   python3 sovereignwatch.py
Tests:       python3 sovereignwatch.py --selftest
"""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import dataclass, field

# --- Was auf diesem Rechner geheim ist. Produktiv aus /sys und uname gelesen. ------

KENNUNGEN: dict[str, str] = {
    "MAC-Adresse": "a4:5e:60:c1:9f:02",
    "Rechnername": "redaktion-arbeitsplatz-07",
    "Festplatten-Seriennummer": "S4EWNX0R512831",
}


@dataclass(frozen=True)
class Ereignis:
    """Ein aufgezeichnetes Ereignis, wie eBPF es liefern würde."""

    pid: int
    prozess: str
    art: str            # "connect" | "send" | "recv" | "open"
    ziel: str = ""
    nutzlast: str = ""


@dataclass
class Fund:
    prozess: str
    pid: int
    ziel: str
    kennungen: list[str] = field(default_factory=list)
    pfade: list[str] = field(default_factory=list)

    @property
    def schwere(self) -> str:
        if not self.kennungen:
            return "unauffällig"
        return "kritisch" if len(self.kennungen) > 1 else "auffällig"


def _suche_kennungen(wert, pfad: str = "") -> list[tuple[str, str]]:
    """Durchsucht eine beliebig verschachtelte Struktur nach Systemkennungen.

    Findet sie auch base64-kodiert — das ist der übliche Weg, mit dem Telemetrie
    einer naiven Textsuche entgeht.
    """
    treffer: list[tuple[str, str]] = []

    if isinstance(wert, dict):
        for k, v in wert.items():
            treffer += _suche_kennungen(v, f"{pfad}.{k}" if pfad else k)
    elif isinstance(wert, list):
        for i, v in enumerate(wert):
            treffer += _suche_kennungen(v, f"{pfad}[{i}]")
    elif isinstance(wert, str):
        for name, geheim in KENNUNGEN.items():
            if geheim in wert:
                treffer.append((name, pfad))
                continue
            # base64-kodiert?
            try:
                roh = base64.b64decode(wert, validate=True).decode("utf-8", "ignore")
                if geheim in roh:
                    treffer.append((name, f"{pfad} (base64)"))
            except Exception:
                pass
    return treffer


def pruefe(ereignisse: list[Ereignis]) -> list[Fund]:
    """Ordnet Verbindungen Prozessen zu und belegt abfliessende Kennungen."""
    funde: dict[tuple[int, str], Fund] = {}

    for e in ereignisse:
        if e.art not in ("connect", "send") or not e.ziel:
            continue
        schluessel = (e.pid, e.ziel)
        f = funde.setdefault(schluessel, Fund(e.prozess, e.pid, e.ziel))

        if e.nutzlast:
            try:
                daten = json.loads(e.nutzlast)
            except json.JSONDecodeError:
                daten = e.nutzlast
            for name, pfad in _suche_kennungen(daten):
                if name not in f.kennungen:
                    f.kennungen.append(name)
                    f.pfade.append(pfad or "(Textkörper)")

    rang = {"kritisch": 0, "auffällig": 1, "unauffällig": 2}
    return sorted(funde.values(), key=lambda f: (rang[f.schwere], f.ziel))


def schema_von(antwort: str) -> dict:
    """Leitet aus einer aufgezeichneten Serverantwort ihr Schema ab."""
    def typ(v) -> object:
        if isinstance(v, bool):
            return "bool"
        if isinstance(v, (int, float)):
            return "number"
        if isinstance(v, str):
            return "string"
        if isinstance(v, list):
            return [typ(v[0])] if v else []
        if isinstance(v, dict):
            return {k: typ(x) for k, x in v.items()}
        return "null"

    return typ(json.loads(antwort))


def baue_shim(schema: dict) -> dict:
    """Erzeugt die kleinste Antwort, die dem Schema genügt.

    Das Programm wartet auf eine Struktur, nicht auf Inhalte. Wer die Struktur
    liefert, kann die Verbindung kappen, ohne die Anwendung zu brechen.
    """
    def wert(t) -> object:
        if t == "bool":
            return True
        if t == "number":
            return 0
        if t == "string":
            return ""
        if isinstance(t, list):
            return []
        if isinstance(t, dict):
            return {k: wert(x) for k, x in t.items()}
        return None

    return wert(schema)


def filterliste(funde: list[Fund]) -> list[str]:
    """Pi-hole-/AdGuard-taugliche Zeilen für die kritischen Ziele."""
    return [f"||{f.ziel.split('/')[0]}^   # {f.prozess}: "
            f"{', '.join(f.kennungen)}"
            for f in funde if f.kennungen]


# --- Eine aufgezeichnete Sitzung. ---------------------------------------------------

SITZUNG = [
    Ereignis(4711, "scanner-suite", "connect", "telemetry.vendor.example/v1/ping"),
    Ereignis(4711, "scanner-suite", "send", "telemetry.vendor.example/v1/ping",
             json.dumps({
                 "app": "ScannerSuite 4.2",
                 "device": {"mac": "a4:5e:60:c1:9f:02",
                            "host": "redaktion-arbeitsplatz-07"},
                 "disk": base64.b64encode(b"S4EWNX0R512831").decode(),
                 "session": {"duration": 1204, "pages": 7},
             })),
    Ereignis(4711, "scanner-suite", "connect", "license.vendor.example/check"),
    Ereignis(4711, "scanner-suite", "send", "license.vendor.example/check",
             json.dumps({"product": "scanner-suite", "version": "4.2"})),
    Ereignis(5012, "updater", "connect", "updates.vendor.example/latest"),
    Ereignis(5012, "updater", "send", "updates.vendor.example/latest",
             json.dumps({"channel": "stable"})),
]

# Die Antwort, auf die das Programm wartet, bevor es weiterarbeitet.
LIZENZ_ANTWORT = json.dumps({
    "valid": True,
    "expires": "2027-12-31",
    "seats": 5,
    "features": ["ocr", "duplex"],
    "owner": {"name": "Beispielredaktion", "id": 8821},
})


def vorfuehrung() -> int:
    print("1) Zuordnung und Beleg")
    print()
    funde = pruefe(SITZUNG)
    for f in funde:
        print(f"   {f.prozess} (PID {f.pid}) → {f.ziel}")
        print(f"     {f.schwere.upper()}")
        if f.kennungen:
            for name, pfad in zip(f.kennungen, f.pfade):
                print(f"       {name} gefunden unter: {pfad}")
        else:
            print("       keine Systemkennung in der Nutzlast")
    print()
    print("   Die Festplatten-Seriennummer war base64-kodiert. Eine Textsuche über")
    print("   die Nutzlast hätte sie nicht gefunden.")
    print()

    print("2) Filterliste für die kritischen Ziele")
    print()
    for zeile in filterliste(funde):
        print(f"   {zeile}")
    print()

    print("3) Lokaler Ersatz, damit das Programm ohne die Verbindung läuft")
    print()
    schema = schema_von(LIZENZ_ANTWORT)
    print("   Schema der aufgezeichneten Antwort:")
    print("   " + json.dumps(schema, ensure_ascii=False))
    print()
    print("   Lokal erzeugte Antwort:")
    print("   " + json.dumps(baue_shim(schema), ensure_ascii=False))
    print()
    print("   Das Programm wartet auf die Struktur, nicht auf die Inhalte. Wer sie")
    print("   lokal liefert, kann die Verbindung kappen, ohne die Anwendung zu")
    print("   brechen — das ist der Unterschied zum reinen Blockieren.")
    return 0


def selftest() -> int:
    ok = True

    def expect(c: bool, m: str) -> None:
        nonlocal ok
        if not c:
            ok = False
            print(f"FAIL: {m}", file=sys.stderr)

    funde = pruefe(SITZUNG)
    nach_ziel = {f.ziel: f for f in funde}

    expect(len(funde) == 3, f"drei Ziele erkannt, waren {len(funde)}")

    tele = nach_ziel["telemetry.vendor.example/v1/ping"]
    expect(tele.prozess == "scanner-suite" and tele.pid == 4711,
           "Verbindung ist dem richtigen Prozess zugeordnet")
    expect(len(tele.kennungen) == 3,
           f"alle drei Kennungen gefunden, waren {tele.kennungen}")
    expect(tele.schwere == "kritisch", "drei Kennungen = kritisch")
    expect(any("base64" in p for p in tele.pfade),
           "die base64-kodierte Seriennummer wird als solche gemeldet")
    expect(any(p.startswith("device.mac") for p in tele.pfade),
           "der Pfad in der verschachtelten Struktur wird genannt")

    lic = nach_ziel["license.vendor.example/check"]
    expect(lic.kennungen == [] and lic.schwere == "unauffällig",
           "Lizenzabfrage ohne Kennung gilt als unauffällig")

    upd = nach_ziel["updates.vendor.example/latest"]
    expect(upd.pid == 5012, "zweiter Prozess korrekt getrennt")

    # Ohne Kennungen keine Filterzeile
    liste = filterliste(funde)
    expect(len(liste) == 1, f"nur das kritische Ziel wird gefiltert, waren {len(liste)}")
    expect(liste[0].startswith("||telemetry.vendor.example^"),
           "Filterzeile hat Pi-hole-Form")

    schema = schema_von(LIZENZ_ANTWORT)
    expect(schema["valid"] == "bool" and schema["seats"] == "number",
           "Typen im Schema erkannt")
    expect(schema["owner"] == {"name": "string", "id": "number"},
           "verschachteltes Objekt im Schema erkannt")
    expect(schema["features"] == ["string"], "Liste im Schema erkannt")

    shim = baue_shim(schema)
    expect(set(shim) == set(json.loads(LIZENZ_ANTWORT)),
           "der Shim hat dieselben Schlüssel wie das Original")
    expect(shim["valid"] is True, "bool wird mit True gefüllt")
    expect(shim["owner"] == {"name": "", "id": 0}, "Verschachtelung wird gefüllt")
    expect(json.dumps(shim), "der Shim ist serialisierbar")

    # Nicht-JSON-Nutzlast darf nicht abstürzen
    roh = pruefe([Ereignis(1, "p", "send", "x.example",
                           "host=redaktion-arbeitsplatz-07&v=1")])
    expect(roh and roh[0].kennungen == ["Rechnername"],
           "Kennung auch in reinem Text gefunden")

    expect(pruefe([Ereignis(1, "p", "open", "", "")]) == [],
           "Ereignisse ohne Verbindung erzeugen keinen Fund")

    print("selftest: PASS" if ok else "selftest: FAIL", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else vorfuehrung())
