# CerberoSOC

Questa è la repository che CodyCloud mette a disposizione gratuitamente: raccoglie e pubblica IP malevoli rilevati dalla sala operativa (SOC) per facilitare attività di blocco e prevenzione.

## Feed disponibili
- `blocklist.txt`: feed testuale vendor-neutral (un IP per riga), adatto all'import su firewall e piattaforme diverse (es. Fortinet e altri).
- `blocklist.rsc`: script Mikrotik che aggiunge gli IP nella address-list `codycloud`.

## Quick check
```bash
python3 scripts/validate_blocklist.py
```
Controlla struttura del file `.rsc`, validità IP e duplicati.

## Rigenerare il feed TXT
```bash
python3 scripts/generate_txt_feed.py
```
Genera/aggiorna `blocklist.txt` partendo da `blocklist.rsc`.
