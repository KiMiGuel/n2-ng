# Instalar N2-NG

## Método Git Clone

```bash
git clone https://github.com/KiMiGuel/n2-ng.git
cd n2-ng
sudo ./install.sh
```

Alternativa sin el instalador:

```bash
sudo apt update
sudo apt install -y aircrack-ng python3 python3-tk wireless-tools
python3 -m pip install .
n2-ng
```

## Dependencias

- `aircrack-ng`
- `python3`
- `python3-tk`
- `wireless-tools`
- `scapy`

Utilidades opcionales:

- `hcxtools` para la conversión a `.22000`
- `reaver` / `wash` para WPS scanning y soporte de Reaver
- `wireshark-common` para `mergecap`
- `pcapfix` para reparación de capturas

## Notas para Kali Linux

N2-NG está hecho para Kali. Ejecútalo desde una sesión gráfica con un adaptador inalámbrico compatible que soporte monitor mode e inyección de paquetes.

La herramienta pide privilegios de root porque el monitor mode, los cambios de canal, la escritura de capturas y la deauthentication requieren root.

## Notas para NetHunter

La compatibilidad con NetHunter depende del kernel, del soporte de adaptadores externos y de si `python3-tk` puede abrir una pantalla gráfica usable. Cuando sea posible, usa una sesión completa de escritorio Kali NetHunter.

## Solución de problemas

- No aparecen adaptadores: confirma que el adaptador es visible con `ip link` y que el kernel lo soporta.
- El monitor mode inicia pero no aparecen redes: revisa la pestaña Raw View y verifica que `airodump-ng` esté produciendo datos.
- La tabla principal está vacía pero Raw View funciona: elimina archivos de escaneo obsoletos solo si es necesario; las versiones actuales siguen automáticamente el CSV numerado más reciente.
- El deauth falla: bloquea primero un objetivo y verifica que el adaptador soporte inyección de paquetes.
- Falla la importación de Tkinter: instala `python3-tk`.
