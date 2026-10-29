# ReportHub Medium 🛡️

**Machine CTF Linux | Difficulté : Medium | Auteur : CyberParcours**

> Un portail de rapports d’entreprise, une API et un système de maintenance : saurez-vous remonter jusqu’à `root` ?

## Présentation

**ReportHub** est une machine virtuelle de type *Capture The Flag* basée sur Ubuntu Server. Dans le rôle d’un auditeur en sécurité, explorez la plateforme de rapports de **Meridian Retail Group**, identifiez ses faiblesses et obtenez les deux flags.

| Information | Détail |
| --- | --- |
| Difficulté | Medium |
| Système | Ubuntu Server 20.04 |
| Catégories | Web, API, Linux Privilege Escalation |
| Durée indicative | 60 minutes |
| Objectif | `user.txt` et `root.txt` |
| Plateformes prévues | Creed CTF et TryHackMe |

## Accès à la machine

La machine est destinée aux environnements CTF autorisés. Une fois la VM lancée, identifiez son adresse IP sur votre réseau de laboratoire et accédez à l’application web dans un navigateur.

> **Attention :** ne publiez pas la machine intentionnellement vulnérable directement sur Internet. Utilisez un environnement isolé et contrôlé.

## Writeup officiel

⚠️ **Spoilers :** le document suivant révèle l’intégralité de la solution, y compris les étapes d’exploitation et l’élévation des privilèges.

📖 **[Consulter le writeup officiel](Writeup_ReportHub_Medium.md)**

Les illustrations Burp Suite utilisées dans le writeup se trouvent dans le dossier [`images/`](images/).

## Structure du dépôt

```text
ReportHub/
├── README.md
├── Writeup_ReportHub_Medium.md
└── images/
    ├── 01_register.png
    ├── 02_public_user_enum.png
    ├── 03_standard_report_idempotency.png
    ├── 04_custom_forbidden.png
    ├── 05_custom_bypass.png
    └── 06_yaml_rce.png
```

## Avertissement

Ce projet est conçu exclusivement pour l’apprentissage, les compétitions CTF et les laboratoires autorisés. Il contient des vulnérabilités intentionnelles. Les valeurs réelles des flags ne figurent pas dans ce dépôt.

---

*Créé par **Alexandru Stancu - CyberParcours** · ReportHub Medium*
