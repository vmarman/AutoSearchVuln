!/bin/zsh
set -Eeuo pipefail
trap 'echo "❌ Error en línea $LINENO"; return 1' ERR

[[ -d venv ]] || python3 -m venv venv
source venv/bin/activate

export OPENAI_API_KEY="sk-proj-HERE API KEY"
echo "[*] Instalando deps..."
pip install --upgrade pip

# 1) instalar zapcli SIN dependencias (evita pin de requests=2.13)
pip install --no-deps zapcli

# 2) instalar requests y urllib3 modernos (sin módulo cgi)
pip install --upgrade --pre "requests>=2.32" "urllib3>=2.2"

# 3) resto de librerías
pip install rich beautifulsoup4 openai

echo "✅ Listo. Ejemplo:"
echo "   python autosearchvuln.py -t 192.168.1.147 --html"

exec zsh -i         # mantiene terminal abierta con venv activo

