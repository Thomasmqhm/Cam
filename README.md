# CamCtl : contrôleur local pour caméras Tapo

Une petite appli Android qui pilote une caméra Tapo **directement sur le réseau local**, sans passer par le cloud TP-Link ni par l'appli officielle. Le firmware de la caméra n'est pas modifié : l'appli utilise uniquement l'API que la caméra expose déjà à l'appli officielle.

## Installer sans ordinateur

**Option 1 : APK prêt à l'emploi.** Sur le téléphone, ouvrez `dist/CamCtl.apk` dans ce dépôt GitHub, puis « Download raw file ». Ouvrez le fichier et autorisez l'installation depuis votre navigateur.

**Option 2 : compiler dans CodeAssist.** Importez le dépôt (bouton « Code » › Download ZIP, ou clone git). Ouvrez le dossier racine comme projet Gradle et lancez *Run*. Le projet est fait pour ça :
- un seul module (`app/`), en Kotlin ;
- dépendances uniquement sur Maven Central / Google Maven : Compose, Media3, coroutines ;
- aucun plugin Gradle maison. Seul le plugin Compose est utilisé, et CodeAssist l'embarque ;
- le JSON passe par `org.json`, intégré à Android.

**Option 3 : GitHub Actions.** Chaque push compile l'APK et lance les tests (onglet *Actions* › artefact `CamCtl-apk`).

## Utilisation

1. Le téléphone doit être sur **le même Wi-Fi** que la caméra.
2. **Scanner le réseau**. L'appli envoie une sonde ONVIF multicast, puis balaie le /24 sur les ports 443, 554, 2020 et 8800. Elle identifie ensuite chaque caméra probable avec une requête `login/discover`, qui n'envoie aucun mot de passe.
3. Saisissez le **mot de passe de votre compte TP-Link**. C'est celui que la caméra utilise localement pour l'utilisateur `admin`.
4. Pour la **vidéo** : dans l'appli Tapo, *Paramètres avancés › Compte caméra*, créez un identifiant et un mot de passe RTSP, puis saisissez-les dans CamCtl. Sur les firmwares récents, il faut aussi activer *Tapo Lab › Compatibilité tierce*.

Les identifiants sont chiffrés sur le téléphone avec une clé du Keystore Android.

## Comment l'appli officielle parle à la caméra

Tout passe en **HTTPS sur le port 443** de la caméra, avec un certificat auto-signé :

```
POST https://<ip>/                 → login (3 variantes selon le firmware)
POST https://<ip>/stok=<jeton>/ds  → commandes, toujours sous la forme :
{"method":"multipleRequest","params":{"requests":[{"method":"<fonction>","params":{...}}]}}
```

| Firmware | Login | Chiffrement des commandes |
|---|---|---|
| Ancien | `password = MD5(mdp)` en clair dans le TLS | aucun (JSON en clair dans le TLS) |
| Intermédiaire (`encrypt_type 3`) | défi/réponse `cnonce`/`nonce`, preuve SHA-256 mutuelle | AES-128-CBC (`securePassthrough`), en-têtes `Seq` et `Tapo_tag` |
| Récent (**TPAP**) | SPAKE2+ P-256 (`pake_register` / `pake_share`), mot de passe dérivé par SHA-256-crypt et PBKDF2 | AES-128-CCM, numéro de séquence en tête de chaque message |

L'appli détecte la variante toute seule (`login/discover` puis une sonde sans mot de passe). Elle gère aussi l'expiration de session et le verrouillage après trop d'essais.

Vidéo : `rtsp://<compte>:<mdp>@<ip>:554/stream1` (HD) ou `/stream2` (SD).

## Ce que l'appli contrôle

| Fonction | Méthode API |
|---|---|
| Infos (modèle, firmware, MAC) | `getDeviceInfo` |
| Pan/tilt, pas réglable | `motorMove` |
| Calibrage moteur | `manualCalibrate` |
| Préréglages : lister, aller à, enregistrer, supprimer | `getPresetConfig`, `motorMoveToPreset`, `addMotorPostion`, `deletePreset` |
| Mode privé (masque l'objectif) | `get/setLensMaskConfig` |
| Voyant LED | `get/setLedStatus` |
| Détection de mouvement on/off | `get/setDetectionConfig` |
| Suivi automatique | `get/setTargetTrackConfig` |
| Vision nocturne auto / IR / couleur | `get/setNightVisionModeConfig`, ou `DayNightModeConfig` sur les anciens firmwares |
| Sirène manuelle | `do` › `msg_alarm.manual_msg_alarm` |
| Redémarrage | `rebootDevice` |
| Vidéo en direct HD/SD | RTSP (Media3, RTP sur TCP) |
| **Diagnostic** : teste chaque fonction en lecture seule sur *votre* modèle | — |
| **Console brute** : envoie n'importe quelle méthode et affiche la réponse | — |

Ce que l'appli ne fait pas : audio bidirectionnel (talkback), relecture de la carte SD, notifications push, accès hors du domicile. Tout cela passe par le cloud TP-Link ou par le flux propriétaire du port 8800.

## Code

- `app/src/main/java/com/camctl/core/` : le protocole, sans dépendance Android (`TapoClient`, `TapoCamera`, `Discovery`, crypto)
- `app/src/main/java/com/camctl/app/` : l'interface Compose, le lecteur RTSP et le stockage chiffré
- `app/src/test/` : 18 tests sur JVM. La crypto est vérifiée contre BouncyCastle, le JDK et OpenSSL. Le SPAKE2+ est vérifié contre un vérificateur RFC 9383 indépendant. Une caméra simulée couvre les 3 modes de login, y compris derrière un vrai serveur TLS auto-signé.

Références : protocole documenté par les projets open source [pytapo](https://github.com/JurajNyiri/pytapo) et [tapo-v4-protocol](https://github.com/freeKC/tapo-v4-protocol).
