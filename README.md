# SovereignWatch

**Sehen, was Desktop-Programme nach Hause senden, und es abstellen.**

Auch wer ein freies Betriebssystem benutzt, kommt um geschlossene Programme oft nicht
herum: der Scanner im Büro, die Software zum Messgerät im Labor, das Programm zur
Steuerung einer Kamera. Diese Programme sammeln Gerätekennungen, senden sie an Server in
den USA oder China, und viele verweigern den Dienst, wenn kein Herstellerkonto angemeldet
ist.

Für Webseiten und Handy-Apps gibt es Werkzeuge, die das untersuchen und belegen. Für
Desktop-Programme nicht. Ein Netzwerkfilter zeigt die Verbindung, aber nicht ihren Urheber
und nicht ihren Inhalt — und wer sie blockiert, bringt die Anwendung zum Stillstand.

> **Stand: Prinzipbeweis.** Dieses Repository zeigt die drei Schritte an einer
> aufgezeichneten Sitzung. Der produktive Teil — eBPF-Aufzeichnung über `bcc`,
> `mitmproxy` für die Inhaltsebene, `frida`-Haken auf die auslesenden Funktionen, Export
> ins [Tweasel](https://docs.tweasel.org/)-Schema, öffentliche Übersicht geprüfter
> Programme — ist Gegenstand der Bewerbung beim Prototype Fund, Jahrgang 03.

## Ausprobieren

Keine Abhängigkeiten, Python 3.11 genügt:

```
python3 sovereignwatch.py            # Vorführung
python3 sovereignwatch.py --selftest # Tests
```

## Was die Vorführung zeigt

Ausgabe eines echten Durchlaufs (14.10.2026):

```
1) Zuordnung und Beleg

   scanner-suite (PID 4711) → telemetry.vendor.example/v1/ping
     KRITISCH
       MAC-Adresse gefunden unter: device.mac
       Rechnername gefunden unter: device.host
       Festplatten-Seriennummer gefunden unter: disk (base64)
   scanner-suite (PID 4711) → license.vendor.example/check
     UNAUFFÄLLIG
       keine Systemkennung in der Nutzlast
   updater (PID 5012) → updates.vendor.example/latest
     UNAUFFÄLLIG
       keine Systemkennung in der Nutzlast

2) Filterliste für die kritischen Ziele

   ||telemetry.vendor.example^   # scanner-suite: MAC-Adresse, Rechnername, Festplatten-Seriennummer

3) Lokaler Ersatz, damit das Programm ohne die Verbindung läuft

   Schema der aufgezeichneten Antwort:
   {"valid": "bool", "expires": "string", "seats": "number", "features": ["string"], "owner": {"name": "string", "id": "number"}}

   Lokal erzeugte Antwort:
   {"valid": true, "expires": "", "seats": 0, "features": [], "owner": {"name": "", "id": 0}}
```

### Die Zuordnung ist der Punkt

Ein DNS-Filter sieht `telemetry.vendor.example`. Er sieht nicht, dass **`scanner-suite` mit
PID 4711** diese Verbindung aufbaut und dass **drei Systemkennungen** darin stehen. Ohne
diese Zuordnung ist ein Befund niemandem zuzurechnen — und damit für eine
datenschutzrechtliche Beschwerde wertlos.

Umgekehrt gilt: Zwei der drei Verbindungen sind **unauffällig**. Eine Lizenzabfrage ohne
Gerätekennung ist kein Datenschutzvorfall. Ein Werkzeug, das alles als verdächtig meldet,
wird nicht benutzt.

### Die Seriennummer war base64-kodiert

`"disk": "UzRFV05YMFI1MTI4MzE="` — eine Textsuche über die Nutzlast findet das nicht. Die
Prüfung geht deshalb durch die verschachtelte Struktur und versucht auf jedem Stringwert
eine base64-Dekodierung. Gemeldet wird der **Pfad**, an dem die Kennung sitzt
(`device.mac`, `disk (base64)`), nicht nur die Tatsache.

### Der lokale Ersatz ist der Unterschied zum Blockieren

Das Programm wartet auf eine **Struktur**, nicht auf Inhalte. Aus der aufgezeichneten
Antwort wird ihr Schema abgeleitet und die kleinste Antwort erzeugt, die diesem Schema
genügt. Damit läuft die Anwendung ohne Herstellerserver weiter.

Das ist der Ausweg aus den zwei schlechten Möglichkeiten „Filter aus" oder „Programm weg".

## Synergie: SpyCheck

[SpyCheck](https://www.prototypefund.de/projects/spycheck) (Prototype Fund, Jahrgang 01,
Martin Berg, Förderzeitraum 01.06.–30.11.2025) erkennt Spionagesoftware **anhand ihrer
Netzwerkverbindungen**. Was SpyCheck nicht sagen kann, ist, **welches Binary** den
Verbindungsaufbau verursacht — genau die Zuordnung, die SovereignWatch liefert.

Der Austausch geht in beide Richtungen: SovereignWatch übernimmt SpyChecks
Verbindungs-Indikatoren als Startkorpus und liefert Binary-zu-Endpunkt-Zuordnungen zurück,
mit denen SpyCheck Fehlalarme auflösen kann.

## Herkunft

Ich filtere mein Heimnetz seit Jahren mit AdGuard und kenne den Moment, in dem ein Programm
stehen bleibt, weil man ihm seinen Server abgeschnitten hat. Beruflich habe ich mit
[LLMSecTest](https://github.com/wehnsdaefflae/llmsectest) (Prototype Fund, Jahrgang 02) ein
halbes Jahr fremde Anwendungen auf Sicherheitsprobleme geprüft und gelernt, dass ein Befund
ohne nachvollziehbaren Beleg nichts bewegt.

## Lizenz

AGPL-3.0 — siehe [LICENSE](LICENSE).
