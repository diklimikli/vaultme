**log101 Vault – README**

Ez az alkalmazás egy offline jelszótároló rendszer, amely a felhasználók jelszavait és jegyzeteit biztonságosan, AES titkosítással tárolja.

**Fő jellemzők:**

* Offline működés (nincs hálózati kommunikáció)
* AES-256 titkosítás CFB módban
* Mesterjelszavas hozzáférés
* Bejelentkezési rendszer
* Kategorizált jelszókezelés és keresés
* Jegyzetek és lejárati dátumok jelszavakhoz
* Beépített jelszógenerátor
* Adat exportálás/importálás JSON fájlba
* Automatikus zárolás inaktivitás esetén (5 perc)
* Önvédelmi jelszó, amely törli az adatokat vészhelyzet esetén
* Eseménynaplózás (`._vaultlog.88`)

**Titkosítás részletei:**

* Algoritmus: AES-256 (CFB mód)
* Kulcs deriválás: PBKDF2 (SHA-256, 200 000 iteráció, 16 bájtos só)
* A fájlformátum az alábbiakat tartalmazza:
  `[salt (16B)] + [iv (16B)] + [ciphertext]`

**Fájlok:**

* `.vault_user.key`: a mesterjelszó ellenőrzésére szolgáló titkosított referenciafájl
* `.vault._data.11`: a jelszavakat tartalmazó AES-titkosított JSON adat
* `._vaultlog.88`: napló az eseményekről (bejelentkezés, törlés, stb.)

**Használat:**

1. **Bejelentkezés** a megadott mesterjelszóval történik.
2. Jelszavak hozzáadhatók, törölhetők, másolhatók, exportálhatók, stb.
3. A rendszer automatikusan kiléptet 5 perc inaktivitás után.
4. Az „önvédelmi mód” aktiválása az adatbázis végleges törlését eredményezi.