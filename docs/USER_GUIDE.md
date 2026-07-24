# Guía de Usuario de N2-NG (v1.1)

Usa N2-NG únicamente en redes de tu propiedad o que estés explícitamente autorizado a auditar.

## Inicio

```bash
n2-ng
```

Desde una copia del código fuente:

```bash
cd /home/kali/n2-ng
./n2-ng
```

## Diseño de la GUI

- **Barra de herramientas**: selección de adaptador y banda, controles de monitor/escaneo, WPS scan, ajustes, indicador de bloqueo de canal.
- **Tabla principal**: resultados del escaneo de puntos de acceso en vivo.
- **Pestaña Scan**: detalles del objetivo bloqueado, lista de clientes, gráfica de señal, controles de ataque, sesiones de captura.
- **Pestaña Raw View**: salida en vivo de `airodump-ng` del mismo proceso de escaneo.
- **Panel de log**: estado de la aplicación, comandos ejecutados y avisos de captura.

## El flujo de trabajo básico

1. Elige tu adaptador en el desplegable **Adapter** (su MAC actual se muestra al lado) y una banda (**2.4GHz**, **5GHz** o **Both**).
2. Haz clic en **Start Monitor**. El adaptador entra en monitor mode (con una MAC aleatorizada si ese ajuste está activo) y el escaneo comienza de inmediato.
3. Localiza tu objetivo en la tabla. Haz clic en la cabecera de una columna para ordenar — por ejemplo PWR para ver primero la señal más fuerte.
4. Haz doble clic en la red (o clic derecho → Lock Target). El adaptador se fija en el canal del objetivo y el panel de objetivo se rellena.
5. Activa **Auto-deauth until handshake** y observa el log. Los clientes reciben deauth en el intervalo elegido hasta que se captura un handshake *verificado* o un PMKID — entonces el bucle se detiene solo.
6. Revisa la **insignia de veredicto** (verdict badge) en la barra de acciones de Capture Sessions (ver abajo) para confirmar que la captura realmente es crackeable.
7. Selecciona la sesión y haz clic en **Hashcat** para crackear, o clic derecho para copiar el comando de hashcat / el contenido del .22000 para tu propio equipo de cracking.

### La insignia de veredicto

Cada captura se convierte automáticamente al formato 22000 de hashcat, y los registros EAPOL se clasifican por su byte messagepair:

| Insignia | Significado | Qué hacer |
|----------|-------------|-----------|
| **AUTHORIZED** (verde) | El AP aceptó la prueba del cliente (messagepair 1–5). El handshake es crackeable. | Crackearlo. |
| **CHALLENGE** (naranja) | Solo M1+M2 (messagepair 0) — el AP nunca confirmó al cliente. Típico de un cliente que usó la contraseña incorrecta; el MIC es imposible de crackear. | Seguir capturando. El bucle de auto-deauth **no** se detiene con esto. |
| **PMKID** (verde) | Se capturó un PMKID. Siempre es material de ataque válido. | Crackearlo. |
| **NO PAIR** (gris/rojo) | El .22000 existe pero no contiene registros utilizables. | Seguir capturando o elegir otra sesión. |
| **—** | Nada seleccionado, o el .22000 aún no se ha generado. | Esperar un momento — la conversión es automática. |

Desde v1.1 el bucle de auto-deauth solo se detiene con AUTHORIZED o PMKID. Un veredicto CHALLENGE registra en el log
`Handshake UNVERIFIED (M1+M2 challenge only — possible failed auth, keep capturing)`
y el bucle sigue ejecutándose.

### Conversión automática a .22000

Ya nunca conviertes capturas a mano. Un .22000 se (re)genera automáticamente: continuamente mientras se captura, después de Fix Capture, después de Merge, y en segundo plano cada vez que seleccionas una captura que todavía no tiene uno. El antiguo botón **Convert to 22000** se eliminó en v1.1 por este motivo. La insignia se actualiza en cuanto aparece el nuevo .22000.

## Referencia de la barra de herramientas

| Control | Qué hace |
|---------|----------|
| Desplegable **Adapter** | Selecciona la interfaz inalámbrica; muestra su MAC al lado. |
| Desplegable **Band** | Restringe el escaneo a 2.4 GHz, 5 GHz o Both. |
| **Start Monitor** | Pone el adaptador en monitor mode (aleatorizando su MAC primero si está activado) e inicia el escaneo. Usa la interfaz tal cual si ya es una interfaz en monitor mode. |
| **Stop Scan** | Detiene `airodump-ng` y limpia la tabla de redes. El monitor mode permanece activo. |
| **Pause Scan** / **Resume Scan** | Suspende/reanuda el proceso de escaneo (SIGSTOP/SIGCONT) sin perder el estado. La barra espaciadora hace lo mismo. |
| **Unlock** | Libera el bloqueo de canal para que el adaptador vuelva a saltar entre canales. Solo está habilitado mientras hay un canal bloqueado. |
| **Stop Monitor** | Detiene el escaneo y devuelve el adaptador a managed mode. |
| **WPS Scan** | Ejecuta `wash` (o `reaver --scan` si falta wash) y muestra las redes con WPS habilitado en un diálogo en vivo. |
| **Refresh Adapters** | Vuelve a detectar las interfaces inalámbricas (úsalo tras conectar un adaptador USB). |
| **Settings** | Abre el diálogo Airodump Settings (ver abajo). |
| Píldora de canal (borde derecho) | Muestra `SCANNING ALL` (rojo) mientras salta entre canales, o el canal bloqueado mientras está fijado. |

## Tabla de redes y ordenación

Columnas: PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, MANU, ESSID, BSSID.

- **Haz clic en la cabecera de una columna** para ordenar por ella; haz clic de nuevo para invertir la dirección. Una flecha ▲/▼ marca la columna activa. BSSID no es ordenable.
- **Desempate en dos niveles (nuevo en v1.1):** al ordenar por PWR, los valores de potencia iguales se ordenan por canal ascendente; al ordenar por CH, los canales iguales se ordenan por potencia descendente. Las demás columnas se ordenan con clave única como antes.
- Clic derecho en una cabecera para mostrar/ocultar columnas.
- Clic derecho en una fila de red: bloquear objetivo, copiar BSSID/ESSID.
- Doble clic en una fila de red: bloquearla como objetivo.
- Los colores de **ENC**: verde = Open, rojo = WEP, amarillo = WPA, blanco = WPA2, azul = WPA3.

## Panel de ataques

| Control | Qué hace |
|---------|----------|
| **Deauthenticate All Clients** | Una ráfaga `aireplay-ng -0 10` contra el BSSID del objetivo bloqueado. Úsalo para un intento rápido y manual de handshake. |
| **Deauthenticate Specific Client** | Lo mismo, dirigido a un solo cliente (elígelo en la lista de clientes o clic derecho en un cliente → deauth). Más suave con la red. |
| **Reaver WPS Attack** | Inicia un ataque Reaver WPS PIN contra el objetivo bloqueado (requiere `reaver`; revisa primero WPS Scan). |
| **Stop Attack** | Mata todo el grupo de procesos del ataque (aireplay/reaver), no solo el proceso padre. |
| **Show Legacy WEP Attacks** | Revela el museo WEP: Fake Authentication, ARP Replay, Chopchop, Fragmentation. Solo útil en redes WEP. |
| **Auto-deauth until handshake** | Casilla: ráfagas de deauth cada **10 / 30 / 60 s** (desplegable) hasta capturar un handshake verificado (AUTHORIZED) o un PMKID. No se detiene con CHALLENGE. |

## Panel Capture Sessions

Lista todas las capturas y archivos de hashes bajo `~/hs/n2-ng/` (se actualiza automáticamente cada 20 s). Selecciona una o más filas para habilitar las acciones.

Barra de acciones:

| Control | Qué hace |
|---------|----------|
| **Inspect** | Muestra los metadatos del archivo en el panel de detalles: tamaño, mtime, conteo/tipos de registros hashcat, .22000 relacionado. |
| Insignia de veredicto | Veredicto de la sesión seleccionada (AUTHORIZED / CHALLENGE / PMKID / NO PAIR / —). Ver la tabla anterior. |
| **Fix Capture** | Repara una captura dañada con `pcapfix`. El .22000 del archivo reparado se genera automáticamente. |
| **Merge** | Fusiona 2+ capturas seleccionadas con `mergecap` y verifica que el resultado sigue conteniendo registros WPA. Si *Archive originals* está activo, las fuentes se mueven a `~/hs/n2-ng/.archive/<fecha>/` tras un merge verificado. El .22000 del archivo fusionado se genera automáticamente. |
| **Hashcat** | Abre el diálogo de hashcat para el .22000 de la sesión (habilitado cuando existe uno válido). |

El menú de clic derecho añade: **Copy hashcat command** (copiar el comando de hashcat), **Copy .22000 content** (copiar el contenido del .22000), **Fix capture** (reparar la captura), **Normalize to PCAPNG** (normalizar a PCAPNG con editcap), **Reconstruct CAP from Hash** (reconstruir un CAP desde el hash con hcxhash2cap — crea un cap *sintético* a partir del material de hash, no los paquetes originales), **Copy path** (copiar la ruta), **Merge selected** (fusionar la selección). La antigua entrada **Convert to 22000** se eliminó en v1.1 — la conversión es automática.

## Diálogo de hashcat

Ataque de diccionario (`hashcat -m 22000 -a 0`) contra el .22000 de la sesión:

- **Hash file**: el .22000 a crackear (pre-rellenado).
- **Wordlist** + **Browse**: por defecto `/usr/share/wordlists/rockyou.txt` cuando existe.
- **Vista previa del comando** en vivo para que veas exactamente lo que se ejecutará.
- **Start** / **Stop**: ejecuta hashcat con salida en streaming en el diálogo. Se ejecuta bajo una sesión con nombre (`n2ng-<timestamp>`) — reanuda más tarde con `hashcat --session n2ng-<timestamp> --restore`.
- **Close** detiene un ataque en curso antes de cerrar.

## Diálogo de ajustes

| Ajuste | Efecto |
|--------|--------|
| **Color output** | Pasa `--color` a airodump-ng (colores en Raw View). |
| **Quiet mode (-q)** | Menos ruido de terminal de airodump-ng. |
| **Pause scan** | Abre el diálogo con el escaneo pausado. |
| **Realtime sort** | Reordena la tabla continuamente a medida que llegan datos del escaneo (en lugar de solo al hacer clic en las cabeceras). |
| **Show manufacturers (-M)** | Rellena la columna MANU mediante la búsqueda OUI de airodump-ng. |
| **Sort by** | Columna de ordenación por defecto cuando no has hecho clic en una cabecera (PWR / Beacons / #Data / CH / ESSID / BSSID). |
| **Filter encryption** | Mostrar solo redes All / WEP / WPA-WPA2 / WPA3 / Open. |
| **Write interval (s)** | Con qué frecuencia airodump-ng vuelca los archivos de salida (1–60). |
| **Output formats** | Qué archivos escribe airodump-ng: csv / pcap / kismet (csv siempre se conserva). |
| **Auto-unlock channel after capture** | Reanudar el channel hopping automáticamente una vez capturado un handshake/PMKID verificado. |
| **Randomize MAC before monitor mode** | Aleatorizar la MAC del adaptador cada vez que inicia el monitor mode (activado por defecto). |
| **Archive originals after successful merge** | Mover las fuentes del merge a `~/hs/n2-ng/.archive/<fecha>/` tras verificar la salida fusionada. |

**Apply** guarda de inmediato; los ajustes que solo afectan a la GUI se aplican sin reiniciar el escaneo, los que afectan al escaneo lo reinician.

## Capturas en disco

```text
~/hs/n2-ng/<ESSID>_<BSSID>/           capturas crudas por objetivo
~/hs/n2-ng/hashcat/<fecha>/           archivos .22000 generados
~/hs/n2-ng/fixed/<fecha>/             capturas reparadas
~/hs/n2-ng/merged/<fecha>/            capturas fusionadas
~/hs/n2-ng/pcapng/<fecha>/            archivos pcapng normalizados
~/hs/n2-ng/reconstructed/<fecha>/     caps sintéticos reconstruidos desde hashes
~/hs/n2-ng/.archive/<fecha>/          fuentes de merges (archivado opcional)
```

## Atajos de teclado

- **Barra espaciadora**: pausar/reanudar el escaneo (no mientras escribes en un campo de texto).
- **Doble clic** en una red: bloquear objetivo.
- **Clic derecho** en una red: copiar BSSID/ESSID o bloquear objetivo.
- **Clic derecho** en un cliente: deauth a ese cliente.
- **Clic derecho** en una sesión de captura: menú completo de acciones.

## Casos de uso comunes

- Escanear los APs cercanos con channel hopping en vivo; ordenar por PWR (los empates ahora se resuelven por canal) para encontrar el objetivo más fuerte.
- Bloquear un objetivo y dejar el auto-deauth corriendo hasta que un handshake AUTHORIZED lo detenga — una insignia CHALLENGE significa seguir esperando, no empezar a crackear.
- Fusionar varias capturas del mismo objetivo en una sola, dejar que el .22000 se regenere, y luego crackear desde el diálogo de hashcat.
- Reparar una captura truncada con Fix Capture; el archivo reparado se re-convierte automáticamente.
- Exportar material .22000 limpio para un equipo de cracking externo mediante clic derecho → Copy hashcat command / Copy .22000 content.
