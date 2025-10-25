# 🚀 ETWThreatHunter


**WinToolsSuite Serie 3 - Forensics Tool #24**

## 📋 Description

ETWThreatHunter est un outil forensique et de threat hunting en temps réel basé sur ETW (Event Tracing for Windows). Il souscrit aux providers ETW critiques, notamment **Microsoft-Windows-Threat-Intelligence**, pour détecter les techniques d'injection de processus, process hollowing, tampering et autres activités malveillantes en temps réel.


## ✨ Fonctionnalités

### Subscription ETW Real-Time
- **Session ETW** : Création de session avec `StartTrace` et `ProcessTrace`
- **Mode Real-Time** : Traitement des événements en temps réel (pas de fichier log)
- **Providers surveillés** :
  - **Microsoft-Windows-Threat-Intelligence** : Détection d'injections et tampering
  - **Microsoft-Windows-Kernel-Process** : Création de processus avec command line

### Détection de Techniques Malveillantes

#### Microsoft-Windows-Threat-Intelligence (Event IDs)
1. **Event ID 1** : **SetThreadContext** (Process Hollowing)
   - Technique : Modification du contexte d'un thread pour détourner l'exécution
   - Usage malware : Injection de code dans processus légitime

2. **Event ID 2** : **QueueUserAPC** (APC Injection)
   - Technique : Injection via Asynchronous Procedure Call
   - Usage malware : Injection furtive dans processus existant

3. **Event ID 3** : **SetWindowsHookEx** (Hook Injection)
   - Technique : Installation de hook Windows pour intercepter événements
   - Usage malware : Keyloggers, screen capture, DLL injection

4. **Event ID 8** : **CreateRemoteThread** (Classic Injection)
   - Technique : Injection classique via création de thread distant
   - Usage malware : DLL injection standard

5. **Event ID 10** : **Process Tampering**
   - Technique : Modification de l'en-tête PE ou manipulation de sections
   - Usage malware : Évasion de signatures AV

### Corrélation d'Événements
- **PID Source** : Processus qui effectue l'injection/tampering
- **PID Target** : Processus victime de l'injection
- **Timestamp précis** : Millisecondes pour corrélation
- **Process Names** : Résolution automatique PID → nom de processus

### Interface Graphique
- **ListView 7 colonnes** :
  - **Timestamp** : Date/heure précise (millisecondes)
  - **Technique** : Type d'attaque détectée
  - **Process Source** : Nom du processus source
  - **PID Source** : Process ID source
  - **Process Cible** : Nom du processus cible
  - **PID Cible** : Process ID cible
  - **Details** : Description de la technique

- **Boutons** :
  - **Démarrer ETW Session** : Lance la session de surveillance
  - **Arrêter Session** : Stoppe la surveillance
  - **Filtrer Injections** : Statistiques par technique
  - **Exporter Alertes** : Export CSV UTF-8

### Export et Logging
- **Export CSV UTF-8** avec BOM
- **Colonnes** : Timestamp, Technique, ProcessSource, PIDSource, ProcessCible, PIDCible, Details
- **Logging automatique** : `ETWThreatHunter.log`


## Architecture Technique

### ETW (Event Tracing for Windows)

**ETW** est un mécanisme de traçage haute performance intégré à Windows :
- **Providers** : Sources d'événements (kernel, drivers, applications)
- **Consumers** : Applications qui consomment les événements
- **Sessions** : Canaux de communication entre providers et consumers

### Provider GUID

#### Microsoft-Windows-Threat-Intelligence
```cpp
GUID = {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
```
**Disponibilité** : Windows 10+ avec fonctionnalités de sécurité activées

#### Microsoft-Windows-Kernel-Process
```cpp
GUID = {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
```
**Disponibilité** : Toutes versions Windows modernes

### APIs Utilisées

#### Création de Session
```cpp
StartTraceW(
    &hSession,           // Handle de session
    sessionName,         // Nom unique
    pSessionProperties   // Configuration
);
```

#### Activation de Provider
```cpp
EnableTraceEx2(
    hSession,            // Session handle
    &providerGuid,       // GUID du provider
    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    TRACE_LEVEL_VERBOSE, // Niveau de détail
    0, 0, 0, NULL
);
```

#### Consommation d'Événements
```cpp
OpenTraceW(&logfile);    // Ouvrir la trace
ProcessTrace(&hTrace, 1, NULL, NULL); // Traiter (bloquant)
```

#### Callback d'Événement
```cpp
VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    // Parser l'événement
    // Extraire les données (PID source, PID target, etc.)
    // Générer une alerte
}
```

### Structure EVENT_RECORD

```cpp
typedef struct _EVENT_RECORD {
    EVENT_HEADER EventHeader;    // Métadonnées (timestamp, PID, provider GUID)
    ETW_BUFFER_CONTEXT BufferContext;
    USHORT ExtendedDataCount;
    USHORT UserDataLength;
    PEVENT_HEADER_EXTENDED_DATA_ITEM ExtendedData;
    PVOID UserData;              // Données spécifiques à l'événement
    PVOID UserContext;           // Contexte custom (pointeur vers classe)
} EVENT_RECORD, *PEVENT_RECORD;
```

### Parsing des Données d'Événement

Pour une implémentation complète, il faut utiliser **TDH (Trace Data Helper)** :

```cpp
#include <tdh.h>

// Obtenir les informations de l'événement
PTRACE_EVENT_INFO pInfo = NULL;
DWORD bufferSize = 0;
TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);

// Allouer buffer
pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);

// Extraire les propriétés
for (DWORD i = 0; i < pInfo->TopLevelPropertyCount; i++) {
    // Obtenir le nom de la propriété
    // Obtenir la valeur de la propriété (PID, thread ID, etc.)
}
```

**Note** : L'implémentation actuelle est simplifiée pour démo. Une version production nécessiterait TDH complet.

### Threading
- **Worker thread** pour ProcessTrace (bloquant)
- **UI thread** reste réactive
- **Message WM_USER + 2** pour notifier nouvel événement
- **Arrêt** : `CloseTrace` déclenche la sortie de `ProcessTrace`


## 🚀 Utilisation

### Scénario 1 : Détection en Temps Réel

**Contexte** : Surveillance active d'un système pour détecter injections

1. **Lancer l'outil en Administrateur**
   - ETW nécessite privilèges élevés

2. **Cliquer "Démarrer ETW Session"**
   - Session créée
   - Providers activés
   - Surveillance active

3. **Laisser tourner**
   - Les événements apparaissent en temps réel dans la ListView

4. **Analyser les alertes**
   - Chaque technique détectée est affichée
   - Corrélation PID source → PID cible

5. **Arrêter la session**
   - Cliquer "Arrêter Session"
   - Exporter les alertes pour analyse

### Scénario 2 : Chasse de Malware Actif

**Contexte** : Malware suspecté actif sur le système

1. **Démarrer ETW Session**

2. **Provoquer l'activité du malware**
   - Ouvrir application infectée
   - Naviguer vers site compromis
   - Déclencher payload

3. **Observer les détections**
   - Injection détectée → PID source = malware
   - PID cible = processus légitime injecté

4. **Investigation** :
   - Noter PID source
   - Utiliser Process Explorer pour examiner le processus
   - Dump mémoire pour analyse malware

**Exemple d'alerte** :
```
15/03/2024 14:23:45.123
Technique : CreateRemoteThread (Classic Injection)
Process Source : malware.exe (PID 4532)
Process Cible : explorer.exe (PID 1024)
Details : Injection classique via CreateRemoteThread
```

### Scénario 3 : Hunting APT

**Contexte** : Recherche d'APT utilisant techniques avancées

**Techniques APT courantes** :
- **Process Hollowing** : APT crée processus légitime puis le "vide" et inject payload
- **APC Injection** : Furtivité élevée, utilisée par APTs sophistiqués
- **Process Tampering** : Modification PE headers pour évasion

**Méthodologie** :
1. Démarrer ETW Session
2. Laisser tourner pendant heures/jours
3. Cliquer "Filtrer Injections" régulièrement
4. Chercher patterns :
   - Injections multiples depuis même source
   - Injections vers processus système critiques (lsass.exe, services.exe)
   - Techniques rares (SetThreadContext moins commun)

### Scénario 4 : Validation Sandbox

**Contexte** : Tester un exécutable suspect en sandbox

1. **Préparer sandbox** : VM isolée, snapshot propre

2. **Démarrer ETW Session** dans la VM

3. **Exécuter l'exécutable suspect**

4. **Observer les comportements** :
   - Injections détectées = malware confirmé
   - Pas d'injection = possiblement légitime ou malware dormant

5. **Exporter les résultats** pour rapport

### Scénario 5 : Corrélation avec SIEM

**Objectif** : Intégration dans infrastructure SOC

1. **ETWThreatHunter tourne sur endpoints critiques**

2. **Export automatique** (script batch) :
   ```batch
   REM Exporter toutes les 5 minutes
   ETWThreatHunter.exe --auto-export C:\Logs\etw_%date%.csv
   ```

3. **Ingestion dans SIEM** :
   - Splunk, ELK, QRadar, etc.
   - Parsing CSV
   - Corrélation avec Event Logs, Network logs

4. **Alerting** :
   - Règles SIEM pour techniques spécifiques
   - Alerte SOC en temps réel


## Techniques Détectées en Détail

### 1. SetThreadContext (Process Hollowing)

**Technique** :
1. Attaquant crée processus légitime suspendu (ex: svchost.exe)
2. "Vide" la mémoire du processus (unmapping)
3. Écrit payload malveillant à la place
4. Modifie le contexte du thread (registres, EIP) avec `SetThreadContext`
5. Reprend le thread → exécution du payload sous identité légitime

**Détection ETW** :
- Event ID 1 : `SetThreadContext` détecté
- PID source = processus malveillant
- PID target = processus "creux" (hollow)

**Faux positifs** : Très rares (debuggers peuvent utiliser SetThreadContext)

### 2. QueueUserAPC (APC Injection)

**Technique** :
1. Attaquant ouvre handle vers processus cible
2. Alloue mémoire dans processus cible (`VirtualAllocEx`)
3. Écrit shellcode (`WriteProcessMemory`)
4. Queue APC (Asynchronous Procedure Call) vers un thread du processus
5. APC exécuté quand le thread entre en état "alertable"

**Détection ETW** :
- Event ID 2 : `QueueUserAPC` détecté
- Furtivité élevée (pas de nouveau thread créé)

**Faux positifs** : Applications légitimes utilisent APC (rare)

### 3. SetWindowsHookEx (Hook Injection)

**Technique** :
1. Attaquant installe hook global Windows
2. Hook intercepte événements (clavier, souris, fenêtres)
3. Windows charge automatiquement la DLL du hook dans tous les processus
4. Résultat : DLL malveillante injectée partout

**Détection ETW** :
- Event ID 3 : `SetWindowsHookEx` détecté
- Hooks globaux = très suspects

**Faux positifs** : Logiciels de contrôle parental, keyloggers légitimes

### 4. CreateRemoteThread (Classic Injection)

**Technique** :
1. Attaquant ouvre handle vers processus cible
2. Alloue mémoire dans processus cible
3. Écrit DLL path ou shellcode
4. Crée thread distant avec `CreateRemoteThread`
5. Thread exécute `LoadLibrary` → DLL chargée

**Détection ETW** :
- Event ID 8 : `CreateRemoteThread` détecté
- Technique classique, bien documentée

**Faux positifs** : Outils de débug, certains logiciels anti-cheat

### 5. Process Tampering

**Technique** :
1. Modification de l'en-tête PE d'un processus en mémoire
2. Changement de sections (code, data)
3. Masquage de signatures malware

**Détection ETW** :
- Event ID 10 : Tampering détecté
- Modification suspecte détectée par kernel

**Faux positifs** : Packers légitimes, protections anti-debug


## Avantages ETW pour Threat Hunting

### Avantages
1. **Temps réel** : Détection instantanée (pas de polling)
2. **Performance** : Overhead minimal (intégré au kernel)
3. **Fiabilité** : Difficile de contourner (kernel-level)
4. **Exhaustif** : Tous les processus surveillés
5. **Natif Windows** : Pas de driver tiers à installer

### Limitations
1. **Windows 10+ requis** : Threat-Intelligence provider récent
2. **Admin requis** : Privilèges élevés nécessaires
3. **Pas de prévention** : Détection seulement (pas de blocage)
4. **Volume** : Beaucoup d'événements si système actif
5. **Parsing complexe** : Nécessite TDH pour extraction complète

### Comparaison avec EDR

**ETWThreatHunter** :
- Gratuit, open-source
- Léger, pas d'agent
- Détection basique

**EDR Commercial** (CrowdStrike, Carbon Black, etc.) :
- Détection avancée + réponse automatique
- ML pour détection d'anomalies
- Threat intelligence intégrée
- Support 24/7

**Utilisation** : ETWThreatHunter = complément ou PoC pour développer EDR custom


## Évolutions Futures

### Fonctionnalités Planifiées
1. **Parsing TDH complet** :
   - Extraction de toutes les propriétés d'événements
   - PID target réel (actuellement placeholder)
   - Command lines des processus

2. **Réponse automatique** :
   - Termination automatique du processus source
   - Isolation de processus injecté
   - Alert SIEM automatique

3. **Machine Learning** :
   - Baseline de comportement normal
   - Détection d'anomalies (injection inhabituelle)

4. **Multi-providers** :
   - Ajout de providers réseau (DNS, HTTP)
   - Providers registry (modifications suspectes)
   - Providers file system (ransomware détection)

5. **Dashboard Web** :
   - Interface web temps réel
   - Graphes de menaces
   - Corrélation multi-endpoints


## Compilation

### Prérequis
- Visual Studio 2019 ou supérieur
- Windows SDK 10.0 ou supérieur
- Architecture : x86 ou x64

### Build
```batch
go.bat
```

### Fichiers Générés
- `ETWThreatHunter.exe` (exécutable principal)
- `ETWThreatHunter.log` (log runtime)


## Permissions

**Important** : L'outil nécessite **droits administrateur** pour créer session ETW.

### Lancer en Administrateur
1. Clic droit sur `ETWThreatHunter.exe`
2. "Exécuter en tant qu'administrateur"


## Références Techniques

### Documentation Microsoft
- [ETW (Event Tracing for Windows)](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [Threat Intelligence Provider](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence-etw)
- [TDH (Trace Data Helper)](https://docs.microsoft.com/en-us/windows/win32/etw/consuming-events)

### Articles de Recherche
- [ETW Threat Hunting by Matt Graeber](https://posts.specterops.io/data-source-analysis-and-dynamic-windows-re-using-wpp-and-tracelogging-e465f8b653f7)
- [Windows 10 Threat Detection by Red Canary](https://redcanary.com/blog/threat-detection/)

### Outils Similaires
- **SilkETW** : ETW consumer en .NET (très complet)
- **Sysmon** : Monitoring basé sur ETW (Microsoft Sysinternals)
- **WEF (Windows Event Forwarding)** : Forwarding ETW vers central


## 🔒 Sécurité

### Données Sensibles
Les événements ETW peuvent contenir :
- PIDs de processus système critiques
- Informations sur applications en cours

### Recommandations
1. **Protection des exports** : Chiffrer les CSV
2. **Accès restreint** : Limiter qui peut exécuter l'outil
3. **Logging sécurisé** : Protéger le fichier .log


## 🔧 Troubleshooting

### Problème : "Impossible de démarrer la session ETW"
- **Cause** : Permissions insuffisantes
- **Solution** : Exécuter en tant qu'Administrateur

### Problème : "Provider Threat Intelligence non disponible"
- **Cause 1** : Windows < 10
- **Cause 2** : Fonctionnalités de sécurité désactivées
- **Solution** : Vérifier version Windows, activer Windows Defender

### Problème : "Aucun événement détecté"
- **Cause** : Pas d'activité malveillante sur le système
- **Solution** : Normal si système propre, tester avec outil d'injection bénin

### Problème : "Trop d'événements"
- **Cause** : Système très actif
- **Solution** : Filtrer par technique spécifique, augmenter buffer size


## 📄 Licence

MIT License - WinToolsSuite Project


## 👤 Auteur

WinToolsSuite Development Team


## 📝 Changelog

### Version 1.0 (2025)
- Version initiale
- Support Windows 10/11
- Provider Threat-Intelligence
- Détection 5 techniques d'injection
- Export CSV UTF-8
- Interface française
- Logging complet


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>