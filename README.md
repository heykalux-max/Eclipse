# ECLIPSE

Scanner di minacce per Windows con interfaccia desktop (PySide6).

## Download

**[⬇ Scarica Eclipse.exe](https://github.com/heykalux-max/Eclipse/raw/main/release/Eclipse.exe)** (Windows 10/11, 64 bit, versione 1.1.0)

Un solo file, nessuna installazione: mettilo in una cartella a tua scelta e avvialo. Accanto all'eseguibile vengono create le cartelle `data`, `Quarantine` e `Reports`.

> Windows SmartScreen può mostrare "Windows ha protetto il PC" perché l'eseguibile non è ancora firmato digitalmente: clicca **Ulteriori informazioni → Esegui comunque**.

## Funzionalità

- **Scansione file e link**: analisi euristica di eseguibili PE, script, archivi e documenti, con verdetto SAFE / SUSPICIOUS / DANGEROUS e spiegazione dei motivi.
- **System Scan**: scansione Rapida, Completa o Personalizzata del PC, multi-processo, con cache e verifica delle firme digitali (Authenticode) per ridurre i falsi positivi.
- **Protezione in tempo reale**: monitoraggio delle cartelle a rischio (Download, Desktop, Temp…).
- **Processi**: elenco dei processi attivi con analisi e possibilità di terminarli.
- **Avvio automatico**: controllo delle voci di avvio (registro, cartelle Startup, attività pianificate).
- **Rete**: connessioni attive per processo, con DNS inverso e porte sospette.
- **Quarantena e report** esportabili.

## Requisiti

- Windows 10/11
- Python 3.14

```powershell
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

L'eseguibile viene creato in `dist\Eclipse.exe`. Gli eseguibili si distribuiscono tramite **GitHub Releases**, non vanno inseriti nel repository.

## Struttura

| File | Contenuto |
|---|---|
| `src/main.py` | interfaccia grafica e avvio |
| `src/engine.py` | motore di analisi file e link |
| `src/fullscan.py` | System Scan (multi-processo, cache, policy anti falsi positivi) |
| `src/sysmon.py` | processi, rete, avvio automatico, firme digitali |
| `src/make_icon.py` | genera `eclipse.ico` / `eclipse.png` |

Le cartelle `data/`, `Quarantine/` e `Reports/` vengono create accanto all'eseguibile e contengono i dati locali dell'utente: non vengono mai caricate nel repository.
