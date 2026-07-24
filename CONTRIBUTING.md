# Contribuir a N2-NG

¡Gracias por dedicar tiempo a contribuir! Este proyecto está hecho por pentesters, para pentesters — tu aporte importa.

## Cómo Contribuir

### Reportar Bugs

Abre un issue con:
- Tu versión de Kali / Debian (`lsb_release -a`)
- Versión de Python (`python3 --version`)
- Chipset del adaptador inalámbrico (`lsusb` o `iw dev`)
- Qué esperabas vs. qué ocurrió
- Pasos para reproducir
- Captura de pantalla si es un problema de la GUI

### Solicitar Funciones

Abre un issue con la etiqueta `enhancement`. Describe:
- Qué debería hacer la función
- Por qué ayuda (¿ahorra clics? ¿evita errores?)
- Boceto o descripción del flujo de UI esperado

### Pull Requests

1. Haz fork del repo y crea una rama: `git checkout -b feature/your-thing`
2. Haz tus cambios
3. Ejecuta los tests: `python3 -m pytest test_helpers.py test_ui.py -v`
4. Asegúrate de que tu código sigue PEP 8 (ejecuta `flake8 src/`)
5. Envía el PR con una descripción clara

### Estilo de Código

- Sigue PEP 8
- Usa type hints en las funciones nuevas
- Mantén la lógica de tkinter en `main.py`, la lógica de negocio en `capture.py`/`scanner.py`/`utils.py`
- Añade docstrings a las funciones públicas

### Mensajes de Commit

Mantenlos descriptivos:
- `feat: add WPA3 detection in scan table`
- `fix: resolve channel hop freeze on RTL8812AU`
- `docs: update install steps for ARM64`

## Entorno de Desarrollo

```bash
git clone https://github.com/KiMiGuel/n2-ng.git
cd n2-ng
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python3 n2_ng.py
```

## ¿Preguntas?

Abre un issue o ponte en contacto. Somos amigables.
