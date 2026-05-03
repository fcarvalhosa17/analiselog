# VoIP Log Analyzer

Ferramenta web para análise estática de logs do Asterisk e arquivos PCAP com foco em sinalização SIP.

```
┌─────────────────────────────────────────────────────────────┐
│                      Browser :8000                          │
│   ┌──────────────────────┐  ┌──────────────────────────┐   │
│   │  Asterisk Log / PCAP │  │  Filtros (Call-ID/Src/   │   │
│   │  textarea + upload   │  │  Dst) + botão Analisar   │   │
│   └──────────────────────┘  └──────────────────────────┘   │
│                   ↕ fetch /api/analyze/*                    │
├─────────────────────────────────────────────────────────────┤
│                   FastAPI (uvicorn :8000)                    │
│   ┌──────────────┐   ┌───────────────┐   ┌──────────────┐  │
│   │ asterisk_    │   │  pcap_parser  │   │ sip_analyzer │  │
│   │ parser.py    │   │  (tshark sub) │   │ (SIP+Q.850)  │  │
│   └──────────────┘   └───────────────┘   └──────────────┘  │
│                      tmpfs /app/uploads                      │
└─────────────────────────────────────────────────────────────┘
         Docker container — Debian Bookworm Slim
```

## Pré-requisitos

- **Docker** e **Docker Compose** (somente — nenhuma outra dependência no host)

## Subir o serviço

```bash
docker compose up -d --build
```

Acesse: **http://localhost:8000**

Para acompanhar logs em tempo real:

```bash
docker compose logs -f
```

Para parar:

```bash
docker compose down
```

## Habilitar log SIP no Asterisk

**chan_pjsip:**
```
asterisk -rx "pjsip set logger on"
```

**chan_sip (legado):**
```
asterisk -rx "sip set debug on"
```

Após reproduzir o problema, copie `/var/log/asterisk/full` e cole na interface ou faça upload.

## Capturar PCAP

```bash
# Capturar sinalização SIP e RTP (tudo na porta 5060 e range de RTP)
tcpdump -i any -w /tmp/sip_capture.pcap -s 0 'port 5060 or portrange 10000-20000'

# Apenas sinalização SIP
tcpdump -i any -w /tmp/sip_only.pcap -s 0 'port 5060'
```

Faça upload do `.pcap` na aba **PCAP Capture**.

## Códigos SIP cobertos

| Código | Nome | Categoria |
|--------|------|-----------|
| 100 | Trying | Provisional |
| 180 | Ringing | Provisional |
| 183 | Session Progress | Provisional |
| 200 | OK | Sucesso |
| 301/302 | Moved | Redirecionamento |
| 400 | Bad Request | Erro cliente |
| 401 | Unauthorized | Erro cliente |
| 403 | Forbidden | Erro cliente |
| 404 | Not Found | Erro cliente |
| 405 | Method Not Allowed | Erro cliente |
| 407 | Proxy Auth Required | Erro cliente |
| 408 | Request Timeout | Erro cliente |
| 480 | Temporarily Unavailable | Erro cliente |
| 481 | Call Does Not Exist | Erro cliente |
| 486 | Busy Here | Erro cliente |
| 487 | Request Terminated | Normal (CANCEL) |
| 488 | Not Acceptable Here | Erro cliente |
| 500 | Server Internal Error | Erro servidor |
| 501 | Not Implemented | Erro servidor |
| 503 | Service Unavailable | Erro servidor |
| 504 | Server Time-out | Erro servidor |
| 603 | Decline | Erro global |
| 604 | Does Not Exist Anywhere | Erro global |
| 606 | Not Acceptable | Erro global |

Causas Q.850 cobertas: 1, 16, 17, 18, 19, 21, 22, 27, 28, 29, 31, 34, 38, 41, 42, 47, 50, 57, 58, 63, 65, 79, 88, 102, 111, 127.

## Estrutura do projeto

```
voip-analyzer/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── app/
    ├── main.py                  # FastAPI: rotas e orquestração
    ├── parsers/
    │   ├── asterisk_parser.py   # Regex parser chan_sip / chan_pjsip
    │   └── pcap_parser.py       # Wrapper tshark via subprocess
    ├── analyzers/
    │   └── sip_analyzer.py      # Database SIP/Q.850 + heurísticas
    └── static/
        └── index.html           # UI single-page vanilla JS
```

## Limitações conhecidas e evolução futura

- **RTP não analisado** — jitter, MOS e packet loss não são verificados nesta versão.
- **Correlação log × PCAP** — análise simultânea de log e PCAP não é suportada; cada análise é independente.
- **Sem persistência** — histórico de análises não é mantido; cada envio é stateless.
- **Export PDF** — resultados só estão disponíveis na interface web.
- **Modo IA híbrido** — a análise é puramente baseada em regras; integração com LLM para sugestões contextuais é uma evolução natural.
- **SRTP/TLS** — PCAPs com tráfego SIP criptografado não são decodificados (requer chaves de sessão).
- **IPv6** — testado principalmente com IPv4; suporte a IPv6 no parser PCAP não foi validado.
