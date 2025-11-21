**Démo portable du Seclab SXN**, incluant :

* configuration SXN (IP, Syslog TLS, NTP, SNMP, interlink)
* détection automatique des gates A/B via `tio`
* déploiement d’une stack Docker prête à l’emploi :

  * **syslog-ng TLS**
  * **NTP (cturra/ntp)**
  * **SNMP traps (Zabbix snmptrapd)**
* génération de PKI locale (CA, server cert, client cert, p12, base64)
* modes interactifs ou automatiques
* logs détaillés

---

# 📁 Structure du projet

```
sxn-portable-demo/
├── bin/
│   ├── prereqs.sh          # installation Docker + tio
│   └── portable_demo.sh    # orchestrateur principal
├── config/
│   ├── sxn_lab.env         # configuration utilisateur
│   └── sxn_lab.env.example
├── dockers/
│   └── base_SXN/           # stack syslog-ng / ntp / snmp
├── tio/
│   └── setup_tio_base_sxn.sh   # configuration SXN via LUA+tio
└── lib/
    └── common.sh
└── logs/
    └── portable_demo_D_H.log
```

---

# 🚀 Installation rapide

## 1. Cloner

```bash
git clone https://github.com/<org>/sxn-portable-demo.git
cd sxn-portable-demo
```

## 2. Préparer l’environnement

```bash
bin/prereqs.sh
```

Ce script installe/configure automatiquement :

* Docker Desktop (macOS) ou vérifie Docker (Linux)
* tio (serial console)
* dépendances basiques

## 3. Configurer le `.env`

```bash
cp config/sxn_lab.env.example config/sxn_lab.env
nano config/sxn_lab.env
```

Le `.env` contient :

* IP & interfaces gate A/B
* paramètres Syslog (TLS ou basic)
* NTP
* **SNMP (agent + traps)**
* PKI (passphrases…)

Chaque valeur est **optionnelle**, l’orchestrateur peut tout demander **interactivement**.

---

# 🏎️ Lancer la démo

## Mode complet (Docker + SXN)

```bash
bin/portable_demo.sh -c config/sxn_lab.env -m all
```

Ce mode :

1. détecte gate A / gate B via tio
2. propose les valeurs par défaut du `.env`
3. déploie Docker (syslog-ng TLS, NTP, SNMP traps)
4. configure les SXN :

   * IP des interfaces
   * Syslog (TLS ou basic)
   * NTP (direct ou interlink)
   * **SNMPd + SNMP-traps**
5. affiche un **check services** (NTP, Syslog, SNMP)

---

## Modes spécifiques

### SXN uniquement

```bash
bin/portable_demo.sh -c config/sxn_lab.env -m sxn
```

### Docker uniquement

```bash
bin/portable_demo.sh -c config/sxn_lab.env -m dockers
```

---

# 🧩 Principaux scripts

| Script                                       | Rôle                                                                             |
| -------------------------------------------- | -------------------------------------------------------------------------------- |
| `bin/prereqs.sh`                             | Installe Docker & tio, détecte l’OS, configure l’environnement                   |
| `bin/portable_demo.sh`                       | Orchestrateur principal : discovery gates, Docker, config SXN                    |
| `lib/common.sh`                              | Helpers : logs, prompts (Y/n), checks (docker, compose…)                         |
| `tio/setup_tio_base_sxn.sh`                  | Génère les scripts Lua (IP, Syslog TLS, NTP, SNMP, reboot) et les pousse via tio |
| `dockers/base_SXN/setup_dockers_base_sxn.sh` | PKI locale + déploiement syslog-ng, NTP, SNMP traps + tests TLS                  |

---

# 📡 Services déployés

### Syslog-ng TLS

* Écoute sur `${SYSLOG_LISTEN_PORT}`
* Logs exportés dans `dockers/base_SXN/syslog-ng/logs/messages`

### NTP

* Serveur `cturra/ntp`
* Par défaut IP côté host Docker : `192.168.2.2`

### SNMP traps (Zabbix)

* Reçoit sur **UDP 162**
* Logs persistants dans `dockers/base_SXN/zabbix-snmptraps/logs/snmptraps.log`

---

# 📑 Commandes utiles

### Voir les logs syslog (patienter que les premiers logs arrivent)

```bash
tail -f dockers/base_SXN/syslog-ng/logs/messages
```

### Voir les traps SNMP (patienter que les premiers logs arrivent)

```bash
tail -f dockers/base_SXN/zabbix-snmptraps/logs/snmptraps.log
```

### État des conteneurs

```bash
docker ps
```

### Logs d’un container

```bash
docker logs -f syslog-ng
docker logs -f zabbix-snmptraps
```

### Vérifier services sur une gate

```bash
tio --script-file tio/base_SXN/check_services_A.lua /dev/tty.usbserial-XXXX
```

---

# 🩺 Dépannage rapide

| Problème                   | Solution                                                       |
| -------------------------- | -------------------------------------------------------------- |
| Pas de traps SNMP sur host | Vérifie le port : SXN → 162, container expose 162:1162         |
| Syslog TLS KO              | Vérifie la PKI dans `syslog-ng/cert/` et le SAN dans le `.env` |
| NTP non synchronisé        | Vérifier interface + IP du conteneur NTP                       |
| Docker non détecté         | Relancer Docker Desktop + `bin/prereqs.sh`                     |

---



