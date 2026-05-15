#!/bin/bash
# CyberHound Pro — Instalación de integración Wazuh
# Ejecutar en el Wazuh Manager como root:
#   bash install_wazuh_integration.sh

set -e

WAZUH_DIR="/var/ossec"
DECODER_DST="$WAZUH_DIR/etc/decoders/cyberhound_decoder.xml"
RULES_DST="$WAZUH_DIR/etc/rules/cyberhound_rules.xml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🐾 CyberHound Pro — Instalación de integración Wazuh"
echo "======================================================"

# Verificar que Wazuh está instalado
if [ ! -d "$WAZUH_DIR" ]; then
    echo "❌ Wazuh no encontrado en $WAZUH_DIR"
    echo "   Instala Wazuh Manager primero: https://documentation.wazuh.com"
    exit 1
fi

# Copiar decoder
echo "📋 Instalando decoder..."
cp "$SCRIPT_DIR/cyberhound_decoder.xml" "$DECODER_DST"
chown ossec:ossec "$DECODER_DST"
chmod 640 "$DECODER_DST"
echo "   ✓ $DECODER_DST"

# Copiar reglas
echo "📋 Instalando reglas..."
cp "$SCRIPT_DIR/cyberhound_rules.xml" "$RULES_DST"
chown ossec:ossec "$RULES_DST"
chmod 640 "$RULES_DST"
echo "   ✓ $RULES_DST"

# Verificar sintaxis
echo "🔍 Verificando sintaxis..."
if command -v /var/ossec/bin/verify-rules &>/dev/null; then
    /var/ossec/bin/verify-rules && echo "   ✓ Sintaxis correcta"
fi

# Reiniciar Wazuh Manager
echo "🔄 Reiniciando Wazuh Manager..."
if systemctl restart wazuh-manager 2>/dev/null; then
    echo "   ✓ Wazuh Manager reiniciado"
else
    /var/ossec/bin/ossec-control restart
    echo "   ✓ Wazuh reiniciado (ossec-control)"
fi

echo ""
echo "✅ Integración instalada correctamente."
echo ""
echo "Próximos pasos:"
echo "  1. Configura CyberHound para enviar a Wazuh:"
echo "     En la UI: ⚙️ Config → 🛡 SIEM → Wazuh"
echo "     Host: $(hostname -I | awk '{print $1}')"
echo "     Puerto: 1514"
echo ""
echo "  2. Verifica que llegan eventos:"
echo "     tail -f /var/ossec/logs/alerts/alerts.log | grep cyberhound"
echo ""
echo "  3. En Wazuh Dashboard busca: rule.groups: cyberhound"
