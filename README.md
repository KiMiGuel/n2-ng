<p align="center">
  <b>For English, click <a href="https://github.com/KiMiGuel/n2-ng/blob/main/README.md">here</a>.</b>
</p>

<p align="center">
  <img src="docs/n2-ng-banner.png" alt="N2-NG Banner" width="100%">
</p>

<p align="center">
  <b>Una ventana. Un adaptador. Cero malabares con terminales.</b>
</p>

<p align="center">
  <a href="https://github.com/KiMiGuel/n2-ng/releases"><img src="https://img.shields.io/github/v/release/KiMiGuel/n2-ng?style=flat-square&color=%2300ff41&label=release" alt="Release"></a>
  <img src="https://img.shields.io/badge/version-1.1.0-%2300ff41?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/license-GPL--3.0-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Kali-compatible-purple?style=flat-square" alt="Kali">
  <img src="https://img.shields.io/github/last-commit/KiMiGuel/n2-ng?style=flat-square" alt="Last Commit">
</p>

---

## El Problema

Ya sabes que la suite aircrack-ng es la mejor. También sabes que tiene la experiencia de usuario de un panel de administración de router de los años 90.

Tres ventanas de terminal. Una chuleta de comandos. Un rezo. El mismatch de canal no es una función — es un grito de auxilio. Nadie debería escribir `aireplay-ng --help` a las 3 de la mañana y cuestionar sus decisiones de vida.

## La Solución

**N2-NG** envuelve `airmon-ng` / `airodump-ng` / `aireplay-ng` en una sola interfaz tkinter con palabras de verdad en los botones ("Deauthenticate", no "-0"), detección automática de handshakes, channel hopping en vivo y ninguna de las piezas de museo de WEP.

Hecho para **Kali Linux**. Probado con cafeína. Aprobado por cualquiera que haya olvidado alguna vez en qué terminal estaba el adaptador en monitor mode.

---

## Capturas de Pantalla

<p align="center">
  <img src="docs/screenshot-gui.png" alt="N2-NG Main Interface" width="90%">
  <br><sub><i>Interfaz principal — escaneo en vivo con columnas ordenables, panel de objetivo y lista de clientes</i></sub>
</p>

<p align="center">
  <img src="docs/screenshot-handshake.png" alt="WPA Handshake Capture" width="45%">
  &nbsp;
  <img src="docs/screenshot-settings.png" alt="Airodump Settings" width="45%">
  <br><sub><i>Izquierda: aviso emergente de detección automática de handshake &nbsp;|&nbsp; Derecha: ajustes de escaneo configurables</i></sub>
</p>

---

## Funciones

| Función | N2-NG | aircrack-ng puro |
|---------|-------|------------------|
| Interfaz de una sola ventana | ✅ | ❌ (3+ terminales) |
| Botones legibles ("Deauth", no `-0`) | ✅ | ❌ |
| Escaneo con channel hopping en vivo | ✅ | Flags `-C` manuales |
| Detección automática de handshake | ✅ | Revisar a ojo en Wireshark |
| Puerta de verificación de handshake (messagepair: AUTHORIZED vs solo challenge) | ✅ (v1.1) | ❌ |
| Extracción automática de hashes .22000 (captura/fix/merge/lazy) | ✅ (v1.1) | Ejecuciones manuales de `hcxpcapngtool` |
| BSSID/PWR/Beacons/#Data/CH/MB/ENC/CIPHER/AUTH/ESSID en tiempo real | ✅ | Salida de `airodump-ng` |
| Columnas ordenables (PWR, Beacons, #Data) | ✅ | ❌ |
| Menú contextual con clic derecho (merge/fix de capturas) | ✅ | `mergecap` manual |
| Exportación .cap / .pcap / .22000 | ✅ | Herramientas separadas |
| Formatos de salida configurables (csv, pcap, kismet) | ✅ | Solo prefijo `-w` |
| Detección de fabricante | ✅ | Requiere el flag `-M` |
| Integración de WPS Scan | ✅ | Herramienta `wash` separada |

---

## Inicio Rápido

```bash
# Clonar e instalar
git clone https://github.com/KiMiGuel/n2-ng.git
cd n2-ng
sudo ./install.sh

# Lanzar
n2-ng
```

---

## Dependencias

**Requeridas:**
- Kali Linux o una distro basada en Debian
- Python 3.10+
- `python3-tk`
- `aircrack-ng`
- `wireless-tools`
- `scapy`

**Opcionales (recomendadas):**
- `hcxtools` — soporte de conversión para hashcat
- `reaver` — ataques WPS PIN
- `wireshark-common` — análisis de pcap
- `pcapfix` — reparación de capturas corruptas

Todas las dependencias opcionales se comprueban en tiempo de ejecución — la herramienta te avisa si falta algo en lugar de fallar.

---

## Documentación

- [Guía de Instalación](docs/INSTALL.md) — instalación detallada y solución de problemas
- [Guía de Usuario](docs/USER_GUIDE.md) — recorrido completo por las funciones
- [Funciones](docs/FEATURES.md) — lista de funciones de v1.1 y comparación contra aircrack-ng/hcxtools puros

---

## ¿Por Qué N2-NG y No...?

**¿Wifite?** Wifite lo automatiza todo, incluido el cracking. N2-NG te da control manual total con una GUI — elige tu objetivo, elige tu ataque, exporta capturas limpias. Es la diferencia entre un bisturí y un mazo.

**¿Fern WiFi Cracker?** Fern es pesado, está desactualizado e intenta hacer demasiado. N2-NG hace una cosa bien: capturar. Sin ataques de diccionario integrados, sin relleno. Solo handshakes y PMKIDs limpios.

**¿aircrack-ng puro?** Si disfrutas haciendo malabares con `airmon-ng`, `airodump-ng`, `aireplay-ng`, `wash` y `mergecap` en cuatro terminales mientras rezas por no haber escrito mal el BSSID — adelante, sigue así. Para todos los demás, está N2-NG.

---

## Contribuir

¿Encontraste un bug? ¿Tienes una idea? Consulta [CONTRIBUTING.md](CONTRIBUTING.md).

¿Temas de seguridad? Consulta [SECURITY.md](SECURITY.md).

---

## Licencia

GPL-3.0. Consulta [LICENSE](LICENSE).

---

<p align="center">
  <sub>Por <b>KiMiGuEL</b> — <a href="https://github.com/KiMiGuel">INDEPENTEST</a></sub>
</p>
