# ECLIPSE

![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)
![Python 3.14](https://img.shields.io/badge/Python-3.14-3776AB)
![Licenza MIT](https://img.shields.io/badge/licenza-MIT-green)

Scanner di minacce open source per Windows, con interfaccia desktop (PySide6). Analizza file, link, processi, programmi in avvio automatico e connessioni di rete, e spiega sempre **perché** qualcosa è considerato pericoloso.

> **Nota:** Eclipse è un progetto indipendente basato su analisi euristica. È utile come secondo parere, ma non sostituisce un antivirus certificato (ad esempio Microsoft Defender): tienilo attivo insieme a Eclipse.

## Download

**[⬇ Scarica Eclipse.exe](https://github.com/heykalux-max/Eclipse/raw/main/release/Eclipse.exe)** (Windows 10/11, 64 bit, versione 1.1.0)

Un solo file, nessuna installazione: mettilo in una cartella a tua scelta e avvialo. Accanto all'eseguibile vengono create le cartelle `data`, `Quarantine` e `Reports`.

> Windows SmartScreen può mostrare "Windows ha protetto il PC" perché l'eseguibile non è ancora firmato digitalmente: clicca **Ulteriori informazioni → Esegui comunque**. Se preferisci, puoi compilarlo tu dal codice sorgente (vedi [Build](#build-eseguibile-singolo)).

## Funzionalità

- **Scansione file e link**: analisi euristica di eseguibili PE, script, archivi e documenti, con verdetto SAFE / SUSPICIOUS / DANGEROUS e spiegazione dei motivi.
- **System Scan**: scansione Rapida, Completa o Personalizzata del PC, multi-processo, con cache e verifica delle firme digitali (Authenticode) per ridurre i falsi positivi.
- **Protezione in tempo reale**: monitoraggio delle cartelle a rischio (Download, Desktop, Temp…).
- **Processi**: elenco dei processi attivi con analisi e possibilità di terminarli.
- **Avvio automatico**: controllo delle voci di avvio (registro, cartelle Startup, attività pianificate).
- **Rete**: connessioni attive per processo, con DNS inverso e porte sospette.
- **Quarantena e report** esportabili.

## Privacy

L'analisi dei file avviene sul tuo PC: i file, la quarantena e i report restano nelle cartelle locali accanto all'eseguibile e non vengono mai caricati online. Eclipse usa la rete solo in questi casi:

- **VirusTotal (facoltativo)**: se inserisci una tua chiave API, invia a VirusTotal l'hash SHA-256 dei file analizzati (non il file) e gli indirizzi dei link che controlli.
- **Liste di phishing**: scarica elenchi pubblici di siti di phishing noti (OpenPhish, Phishing.Database).
- **Analisi dei link**: risolve il dominio e contatta il sito per seguire i redirect e leggere la pagina.
- **Rete**: il DNS inverso delle connessioni attive.

## Avvio dal codice sorgente

Requisiti:

- Windows 10/11
- Python 3.14

```powershell
git clone https://github.com/heykalux-max/Eclipse.git
cd Eclipse
pip install -r requirements.txt
python src\main.py
```

Opzioni da riga di comando:

| Opzione | Effetto |
|---|---|
| `--tray` | avvia ridotto nell'area di notifica |
| `--quick-scan` | avvia subito una scansione rapida del sistema |

## Build (eseguibile singolo)

Serve Visual Studio Build Tools (MSVC).

```powershell
pip install nuitka zstandard
.\build.ps1
```

L'eseguibile viene creato in `dist\Eclipse.exe`. Per tenere i file intermedi fuori da OneDrive usa `.\build.ps1 -BuildDir C:\temp\ecl`.

## Struttura

| File | Contenuto |
|---|---|
| `src/main.py` | interfaccia grafica e avvio |
| `src/engine.py` | motore di analisi file e link |
| `src/fullscan.py` | System Scan (multi-processo, cache, policy anti falsi positivi) |
| `src/sysmon.py` | processi, rete, avvio automatico, firme digitali |
| `src/make_icon.py` | genera `eclipse.ico` / `eclipse.png` |
| `release/Eclipse.exe` | ultima versione compilata, per il download diretto |

Le cartelle `data/`, `Quarantine/` e `Reports/` contengono i dati locali dell'utente e sono escluse dal repository tramite `.gitignore`.

## Contribuire

Contributi, segnalazioni e idee sono benvenuti.

- **Bug o falsi positivi**: apri una [issue](https://github.com/heykalux-max/Eclipse/issues) indicando la versione di Windows, il file o il processo coinvolto (nome e hash SHA-256, mai il file stesso se è malware) e il verdetto ricevuto.
- **Codice**: fai un fork, crea un branch per la modifica e apri una pull request con una breve descrizione di cosa cambia e come l'hai provato.
- **Vulnerabilità di sicurezza** in Eclipse stesso: non aprire una issue pubblica, usa la funzione [Report a vulnerability](https://github.com/heykalux-max/Eclipse/security/advisories/new) di GitHub.

## Licenza

Distribuito con licenza [MIT](LICENSE): puoi usarlo, modificarlo e ridistribuirlo liberamente, mantenendo l'avviso di copyright.

Eclipse usa librerie di terze parti con le proprie licenze: [PySide6](https://doc.qt.io/qtforpython-6/licenses.html) (LGPL v3), [pefile](https://github.com/erocarrera/pefile) (MIT) e [psutil](https://github.com/giampaolo/psutil) (BSD-3-Clause).
