from __future__ import annotations

SIP_RESPONSE_CODES: dict[int, dict] = {
    100: {
        "name": "Trying",
        "category": "provisional",
        "is_error": False,
        "description": "Solicitação recebida e processamento iniciado. Resposta provisória indicando que o servidor está trabalhando na requisição.",
        "causes": [],
        "solutions": [],
    },
    180: {
        "name": "Ringing",
        "category": "provisional",
        "is_error": False,
        "description": "Destino localizado e telefone está chamando. Indica que o UA de destino está gerando sinalização de chamada.",
        "causes": [],
        "solutions": [],
    },
    183: {
        "name": "Session Progress",
        "category": "provisional",
        "is_error": False,
        "description": "Progresso da sessão — frequentemente enviado com SDP para estabelecer early media (ringback tone, anúncios, etc.).",
        "causes": [],
        "solutions": [],
    },
    200: {
        "name": "OK",
        "category": "success",
        "is_error": False,
        "description": "Requisição processada com sucesso. Para INVITE, indica que a chamada foi atendida e a sessão está estabelecida.",
        "causes": [],
        "solutions": [],
    },
    301: {
        "name": "Moved Permanently",
        "category": "redirect",
        "is_error": False,
        "description": "O usuário não pode ser alcançado neste endereço. Novo endereço retornado no header Contact.",
        "causes": ["Ramal ou endpoint foi movido permanentemente", "Configuração de redirecionamento no proxy"],
        "solutions": ["Atualizar o endereço de destino no dialplan ou na trunk", "Verificar header Contact na resposta e reencaminhar"],
    },
    302: {
        "name": "Moved Temporarily",
        "category": "redirect",
        "is_error": False,
        "description": "Usuário temporariamente em outro endereço (ex: follow-me, desvio de chamada).",
        "causes": ["Desvio de chamada ativo", "Follow-me configurado", "Registro temporário em outro servidor"],
        "solutions": ["Verificar configurações de desvio no PBX", "Seguir o novo endereço no header Contact"],
    },
    400: {
        "name": "Bad Request",
        "category": "client_error",
        "is_error": True,
        "description": "Requisição malformada — o servidor não conseguiu interpretá-la. Problema de sintaxe ou headers obrigatórios ausentes.",
        "causes": [
            "Header obrigatório ausente ou malformado (From, To, Call-ID, CSeq, Via, Max-Forwards)",
            "URI SIP inválida",
            "Codec ou parâmetro SDP inválido",
            "Versão do protocolo incorreta",
            "Incompatibilidade de implementação entre equipamentos",
        ],
        "solutions": [
            "Habilitar log SIP detalhado: `pjsip set logger on` ou `sip set debug on`",
            "Capturar o tráfego com `tcpdump -i any -w /tmp/sip.pcap 'port 5060'` e analisar os headers",
            "Verificar se o transport está configurado corretamente (UDP/TCP/TLS)",
            "Conferir se o Max-Forwards está sendo decrementado corretamente",
            "Checar configuração de `realm` e `domain` no pjsip.conf",
        ],
    },
    401: {
        "name": "Unauthorized",
        "category": "client_error",
        "is_error": True,
        "description": "Autenticação necessária. O servidor exige credenciais via WWW-Authenticate.",
        "causes": [
            "Senha incorreta ou usuário inexistente",
            "Realm diferente do configurado no endpoint",
            "Desync de nonce (relógio muito descompasso entre UA e servidor)",
            "Autenticação habilitada no servidor mas não configurada no cliente",
        ],
        "solutions": [
            "Conferir username e password no pjsip.conf (`auth` section) ou sip.conf",
            "Verificar `realm` no servidor e no cliente — devem ser iguais",
            "Sincronizar relógio com NTP: `timedatectl status`",
            "No Asterisk: `pjsip show auths` para listar autenticações configuradas",
            "No Yeastar: Account → SIP Account → confirmar senha e realm",
            "Checar se fail2ban não está bloqueando após tentativas falhas: `fail2ban-client status asterisk`",
        ],
    },
    403: {
        "name": "Forbidden",
        "category": "client_error",
        "is_error": True,
        "description": "Autenticação bem-sucedida mas acesso negado por política. O servidor entende mas recusa a requisição.",
        "causes": [
            "ACL (permit/deny) bloqueando o IP de origem",
            "Trunk sem permissão para o destino discado",
            "Bloqueio por fail2ban ou firewall",
            "Restrição de horário ou rota no dialplan",
            "Permissão de codec negada",
        ],
        "solutions": [
            "Verificar ACL no pjsip.conf: `acl` e `contact_acl` sections",
            "Checar regras de firewall: `iptables -L -n | grep 5060`",
            "Fail2ban: `fail2ban-client status asterisk` — se bloqueado, `fail2ban-client set asterisk unbanip <IP>`",
            "No Yeastar: System → Security → Firewall Rules — verificar IP na lista branca",
            "Revisar dialplan para restrições de destino: `dialplan show`",
            "Verificar se o trunk tem prefixo de discagem configurado corretamente",
        ],
    },
    404: {
        "name": "Not Found",
        "category": "client_error",
        "is_error": True,
        "description": "Usuário ou ramal não encontrado. O número discado não existe ou não está registrado.",
        "causes": [
            "Ramal não existe no PBX",
            "Endpoint SIP não registrado (offline)",
            "Número externo inválido ou portabilidade não resolvida",
            "Prefixo de discagem ausente ou incorreto na trunk",
            "Dialplan não possui contexto para o destino",
            "DID não mapeado no PBX",
        ],
        "solutions": [
            "Verificar se o ramal existe: `pjsip show endpoints` ou `sip show peers`",
            "Checar registro do endpoint: `pjsip show contacts` — endpoint deve aparecer como `Avail`",
            "Conferir contexto e extensão no dialplan: `dialplan show <contexto>`",
            "Verificar configuração de DID/inbound route no PBX",
            "No Yeastar: Extensions → confirmar ramal ativo; Trunks → Inbound Routes",
            "Testar discagem interna antes de testar via trunk",
            "Verificar se a trunk está enviando o número com ou sem prefixo de país",
        ],
    },
    405: {
        "name": "Method Not Allowed",
        "category": "client_error",
        "is_error": True,
        "description": "Método SIP não suportado pelo servidor. O header Allow indica os métodos aceitos.",
        "causes": [
            "Servidor não suporta SUBSCRIBE, NOTIFY, REFER ou outro método utilizado",
            "Configuração incorreta de allow/disallow no endpoint",
            "Feature phone ou softphone enviando método não padrão",
        ],
        "solutions": [
            "Verificar header `Allow` na resposta 405 para saber o que o servidor aceita",
            "Desabilitar funcionalidades não suportadas no cliente (ex: presença, BLF)",
            "No pjsip.conf: verificar `allow_subscribe` e `accept_multiple_sdp_answers`",
        ],
    },
    407: {
        "name": "Proxy Authentication Required",
        "category": "client_error",
        "is_error": True,
        "description": "Autenticação requerida pelo proxy SIP intermediário via Proxy-Authenticate.",
        "causes": [
            "Trunk SIP requerendo autenticação no proxy (não no servidor final)",
            "Credenciais de proxy não configuradas",
            "Proxy intermediário de operadora exigindo autenticação",
        ],
        "solutions": [
            "Configurar credenciais de autenticação para o proxy no pjsip.conf (`outbound_auth`)",
            "No sip.conf: configurar `fromuser`, `username` e `secret` no peer da trunk",
            "Contatar operadora para obter credenciais de proxy corretas",
            "Verificar se `registersip` está habilitado corretamente na trunk",
        ],
    },
    408: {
        "name": "Request Timeout",
        "category": "client_error",
        "is_error": True,
        "description": "Tempo esgotado aguardando resposta. O servidor não obteve resposta em tempo hábil.",
        "causes": [
            "Problema de conectividade de rede ou firewall bloqueando UDP/5060",
            "NAT sem keep-alive configurado — binding NAT expirou",
            "Servidor sobrecarregado ou indisponível",
            "Timer SIP mal configurado (T1, T2)",
            "Rota de retorno incorreta para respostas SIP",
        ],
        "solutions": [
            "Verificar conectividade: `ping <IP_servidor>` e `traceroute <IP_servidor>`",
            "Testar porta UDP: `nc -u <IP> 5060` ou SIPVicious",
            "Habilitar keep-alive no pjsip.conf: `keep_alive_interval=30`",
            "Verificar se SIP ALG está habilitado no roteador — desabilitar se estiver",
            "Checar `qualify_frequency` no endpoint pjsip para monitorar disponibilidade",
            "Capturar tráfego e verificar se as respostas estão chegando: `tcpdump -i any 'port 5060'`",
        ],
    },
    480: {
        "name": "Temporarily Unavailable",
        "category": "client_error",
        "is_error": True,
        "description": "Destino temporariamente indisponível — endpoint offline, DND ativo, ou fora do horário de atendimento.",
        "causes": [
            "Endpoint não registrado (softphone fechado, telefone desligado)",
            "DND (Não Perturbe) ativo no ramal",
            "Fora do horário de funcionamento configurado no PBX",
            "Trunk SIP fora do ar ou sem registro",
            "Capacidade máxima de chamadas simultâneas atingida",
        ],
        "solutions": [
            "Verificar status do endpoint: `pjsip show contacts` ou `sip show peers`",
            "Checar se o ramal está registrado e online",
            "Verificar configuração de horário de atendimento no PBX",
            "Checar DND: `database get DND <ramal>`",
            "Verificar status da trunk: `pjsip show registrations` ou `sip show registry`",
            "No Yeastar: Extensions → verificar status online do ramal",
        ],
    },
    481: {
        "name": "Call/Transaction Does Not Exist",
        "category": "client_error",
        "is_error": True,
        "description": "A chamada ou transação referenciada não existe. Geralmente ocorre com BYE ou CANCEL para chamadas já encerradas.",
        "causes": [
            "BYE enviado para chamada já encerrada",
            "Re-INVITE para sessão inexistente",
            "Reinício do Asterisk durante chamada ativa",
            "Problema de sincronização de estado entre endpoints",
            "NAT causando duplicação de pacotes",
        ],
        "solutions": [
            "Verificar logs do Asterisk no momento do erro para contexto da chamada",
            "Implementar lógica de retry com backoff no cliente",
            "Se ocorre após reinício: configurar estado persistente ou alertar usuários",
            "Verificar se NAT está causando pacotes duplicados",
        ],
    },
    486: {
        "name": "Busy Here",
        "category": "client_error",
        "is_error": True,
        "description": "Destino ocupado — endpoint está em outra chamada e não aceita chamada em espera.",
        "causes": [
            "Ramal em chamada e call waiting desabilitado",
            "Limite de canais simultâneos atingido no endpoint",
            "Trunk sem canais disponíveis",
            "Configuração de `busylevel` atingida no sip.conf",
        ],
        "solutions": [
            "Habilitar call waiting no ramal se desejado",
            "Configurar grupo de ramais (hunt group/ring group) para distribuir chamadas",
            "Aumentar limite de canais simultâneos: `max_contacts` no pjsip.conf",
            "Configurar fila de espera (Queue) para lidar com overflow",
            "Verificar capacidade da trunk com a operadora",
        ],
    },
    487: {
        "name": "Request Terminated",
        "category": "client_error",
        "is_error": False,
        "description": "Requisição encerrada normalmente por CANCEL — o chamador desligou antes do atendimento. Não é um erro.",
        "causes": [
            "Chamador desligou antes do atendimento (comportamento normal)",
            "Timeout de ring configurado no dialplan",
            "Redirecionamento para caixa postal após N segundos",
        ],
        "solutions": [
            "Comportamento normal — não requer ação corretiva",
            "Se frequente e inesperado: verificar timeout de ring no dialplan (`Dial(,30,)`)",
            "Considerar implementar caixa postal para capturar chamadas perdidas",
        ],
    },
    488: {
        "name": "Not Acceptable Here",
        "category": "client_error",
        "is_error": True,
        "description": "Parâmetros de mídia incompatíveis — nenhum codec em comum entre os endpoints.",
        "causes": [
            "Nenhum codec em comum entre chamador e chamado",
            "SDP offer com codecs que o destino não suporta",
            "Configuração incorreta de allow/disallow no endpoint ou trunk",
            "Problema com early media ou ptime incompatível",
        ],
        "solutions": [
            "Verificar codecs configurados: `pjsip show endpoint <nome>` — campo `allow`",
            "No pjsip.conf: adicionar `allow=ulaw,alaw,g729` conforme necessário",
            "No sip.conf: ajustar `allow=` e `disallow=` no peer",
            "Habilitar transcoding se licença disponível: `allow=all`",
            "Verificar se G.729 requer licença no Asterisk",
            "No Yeastar: Extensions → Codec Settings — verificar codecs habilitados",
            "Capturar SDP nas duas pontas e comparar codecs ofertados",
        ],
    },
    500: {
        "name": "Server Internal Error",
        "category": "server_error",
        "is_error": True,
        "description": "Erro interno no servidor SIP. Falha inesperada no processamento da requisição.",
        "causes": [
            "Bug no Asterisk ou módulo com falha",
            "Recurso esgotado (memória, CPU, file descriptors)",
            "Módulo não carregado ou com erro de configuração",
            "Dialplan com erro de sintaxe ou aplicação inexistente",
        ],
        "solutions": [
            "Verificar logs detalhados do Asterisk: `tail -f /var/log/asterisk/full`",
            "Verificar módulos carregados: `module show`",
            "Checar uso de recursos: `top`, `free -m`, `ulimit -n`",
            "Recarregar módulo problemático: `module reload res_pjsip.so`",
            "Verificar configuração: `pjsip show settings`",
            "Considerar reinicialização do Asterisk: `core restart gracefully`",
        ],
    },
    501: {
        "name": "Not Implemented",
        "category": "server_error",
        "is_error": True,
        "description": "Método ou feature SIP não implementado pelo servidor.",
        "causes": [
            "Servidor não suporta o método solicitado",
            "Módulo necessário não instalado ou carregado",
        ],
        "solutions": [
            "Verificar se o módulo está carregado: `module show like <nome>`",
            "Instalar módulo faltante no Asterisk",
            "Verificar header `Require` na requisição — pode exigir extensão não suportada",
        ],
    },
    503: {
        "name": "Service Unavailable",
        "category": "server_error",
        "is_error": True,
        "description": "Serviço indisponível — servidor sobrecarregado ou em manutenção.",
        "causes": [
            "Asterisk sobrecarregado ou reiniciando",
            "Trunk da operadora indisponível",
            "Capacidade máxima de chamadas simultâneas atingida no servidor",
            "Falha em recurso dependente (banco de dados, LDAP, etc.)",
        ],
        "solutions": [
            "Verificar carga do servidor: `core show calls`, `core show channels`",
            "Checar status da trunk: `pjsip show registrations`",
            "Verificar logs de erro: `tail -f /var/log/asterisk/full | grep ERROR`",
            "Implementar failover para trunk alternativa",
            "Contatar operadora se o 503 vier dela",
            "Verificar `max_channels` na configuração da trunk",
        ],
    },
    504: {
        "name": "Server Time-out",
        "category": "server_error",
        "is_error": True,
        "description": "Servidor proxy esgotou o tempo aguardando resposta de servidor downstream.",
        "causes": [
            "Servidor final não responde ao proxy",
            "Problema de roteamento entre proxy e servidor destino",
            "Timer de gateway configurado muito baixo",
            "Firewall bloqueando tráfego entre proxy e servidor",
        ],
        "solutions": [
            "Verificar conectividade entre proxy e servidor destino",
            "Checar configuração de timers no proxy SIP",
            "Verificar firewall entre os servidores",
            "Analisar logs no servidor proxy para identificar onde o timeout ocorre",
        ],
    },
    603: {
        "name": "Decline",
        "category": "global_error",
        "is_error": True,
        "description": "Chamada recusada explicitamente pelo usuário ou pelo sistema — destino existe mas não deseja atender.",
        "causes": [
            "Usuário recusou a chamada manualmente",
            "Lista negra (blacklist) bloqueou o chamador",
            "Política de privacidade recusando chamadas anônimas",
            "Horário de não perturbação configurado",
        ],
        "solutions": [
            "Verificar se o número chamador está na lista negra",
            "Checar configurações de privacidade do ramal",
            "Verificar dialplan para lógica de rejeição",
            "Conferir se Privacy/DND está ativo: `database show DND`",
        ],
    },
    604: {
        "name": "Does Not Exist Anywhere",
        "category": "global_error",
        "is_error": True,
        "description": "O usuário destino não existe em nenhum servidor — diferente do 404, indica certeza absoluta de inexistência.",
        "causes": [
            "Número discado inválido ou não alocado",
            "Portabilidade numérica não resolvida corretamente",
            "DID não configurado no PBX nem na operadora",
        ],
        "solutions": [
            "Verificar se o número existe e está ativo",
            "Checar configuração de DID com a operadora",
            "Verificar rotas de portabilidade numérica",
        ],
    },
    606: {
        "name": "Not Acceptable",
        "category": "global_error",
        "is_error": True,
        "description": "Nenhum parâmetro de sessão aceitável — nenhum codec, bandwidth ou tipo de chamada compatível.",
        "causes": [
            "Incompatibilidade total de codecs",
            "Bandwidth insuficiente declarada no SDP",
            "Requisitos de segurança (SRTP) incompatíveis",
        ],
        "solutions": [
            "Revisar codecs suportados em ambas as pontas",
            "Verificar configuração de SRTP — habilitar ou desabilitar consistentemente",
            "Checar parâmetros de bandwidth no SDP",
        ],
    },
}

Q850_CAUSES: dict[int, dict] = {
    1: {
        "name": "Unallocated Number",
        "description": "Número não alocado — o número discado não está atribuído a nenhum destino.",
        "solution": "Verificar se o número existe. Checar portabilidade numérica. Conferir DID na operadora.",
    },
    16: {
        "name": "Normal Call Clearing",
        "description": "Encerramento normal da chamada. Não indica erro.",
        "solution": "Comportamento esperado — chamada encerrada normalmente por uma das partes.",
    },
    17: {
        "name": "User Busy",
        "description": "Usuário ocupado — destino em outra chamada.",
        "solution": "Implementar fila de espera ou call waiting. Verificar capacidade de canais simultâneos.",
    },
    18: {
        "name": "No User Responding",
        "description": "Nenhuma resposta do usuário — telefone chamando mas não atendido.",
        "solution": "Verificar se o endpoint está registrado. Configurar timeout de ring e desvio para caixa postal.",
    },
    19: {
        "name": "No Answer From User",
        "description": "Usuário não atendeu — chamada aceita mas não atendida dentro do timeout.",
        "solution": "Configurar caixa postal ou grupo de ramais para garantir atendimento.",
    },
    21: {
        "name": "Call Rejected",
        "description": "Chamada rejeitada — destino recusou explicitamente.",
        "solution": "Verificar lista negra, DND e políticas de rejeição no PBX.",
    },
    22: {
        "name": "Number Changed",
        "description": "Número alterado — destino mudou de número.",
        "solution": "Atualizar agenda e dialplan com o novo número.",
    },
    27: {
        "name": "Destination Out of Order",
        "description": "Destino fora de serviço — endpoint inacessível.",
        "solution": "Verificar status do endpoint. Checar conectividade de rede e registro SIP.",
    },
    28: {
        "name": "Invalid Number Format",
        "description": "Formato de número inválido — o número discado tem formato incorreto.",
        "solution": "Verificar manipulação de números no dialplan. Conferir prefixos e formato E.164.",
    },
    29: {
        "name": "Facility Rejected",
        "description": "Funcionalidade rejeitada pelo destino.",
        "solution": "Verificar se a funcionalidade solicitada é suportada pelo destino.",
    },
    31: {
        "name": "Normal, Unspecified",
        "description": "Encerramento normal sem causa específica.",
        "solution": "Geralmente normal. Se frequente e inesperado, habilitar logs detalhados para diagnóstico.",
    },
    34: {
        "name": "No Circuit Available",
        "description": "Sem circuito disponível — capacidade esgotada na trunk ou na rede.",
        "solution": "Verificar capacidade da trunk. Adicionar canais ou trunk alternativa. Contatar operadora.",
    },
    38: {
        "name": "Network Out of Order",
        "description": "Rede fora de ordem — problema na infraestrutura de rede.",
        "solution": "Contatar operadora. Verificar status de links WAN. Implementar trunk de backup.",
    },
    41: {
        "name": "Temporary Failure",
        "description": "Falha temporária — problema transitório na rede ou no equipamento.",
        "solution": "Aguardar e tentar novamente. Se persistir, verificar status da operadora.",
    },
    42: {
        "name": "Switching Equipment Congestion",
        "description": "Congestionamento no equipamento de comutação — sobrecarga na rede da operadora.",
        "solution": "Implementar retry com backoff. Contatar operadora. Considerar QoS na rede.",
    },
    47: {
        "name": "Resource Unavailable",
        "description": "Recurso indisponível — capacity ou feature requerida não disponível.",
        "solution": "Verificar capacidade de canais. Checar licenças de codec. Contatar operadora.",
    },
    50: {
        "name": "Requested Facility Not Subscribed",
        "description": "Funcionalidade não contratada com a operadora.",
        "solution": "Contatar operadora para habilitar a funcionalidade ou remover sua solicitação.",
    },
    57: {
        "name": "Bearer Capability Not Authorized",
        "description": "Tipo de chamada não autorizado — ex: dados em trunk de voz.",
        "solution": "Verificar tipo de chamada configurado. Conferir permissões na trunk.",
    },
    58: {
        "name": "Bearer Capability Not Available",
        "description": "Capacidade de portadora não disponível temporariamente.",
        "solution": "Tentar novamente. Verificar status da operadora.",
    },
    63: {
        "name": "Service or Option Not Available",
        "description": "Serviço ou opção não disponível.",
        "solution": "Verificar funcionalidades contratadas. Revisar configuração do serviço.",
    },
    65: {
        "name": "Bearer Capability Not Implemented",
        "description": "Tipo de bearer não implementado no equipamento.",
        "solution": "Verificar compatibilidade de codecs e capacidades entre os equipamentos.",
    },
    79: {
        "name": "Service or Option Not Implemented",
        "description": "Serviço ou opção não implementado.",
        "solution": "Verificar se a funcionalidade está disponível na versão do Asterisk instalada.",
    },
    88: {
        "name": "Incompatible Destination",
        "description": "Destino incompatível — parâmetros de chamada incompatíveis com o destino.",
        "solution": "Verificar codecs, tipo de chamada e capacidades. Conferir configuração de transcoding.",
    },
    102: {
        "name": "Recovery on Timer Expiry",
        "description": "Recuperação por expiração de timer — chamada encerrada por timeout SIP.",
        "solution": "Verificar timers SIP (T1, T2, sessão). Checar keep-alive. Investigar NAT binding.",
    },
    111: {
        "name": "Protocol Error",
        "description": "Erro de protocolo — mensagem malformada ou sequência inválida.",
        "solution": "Capturar tráfego SIP e analisar. Verificar compatibilidade de implementações.",
    },
    127: {
        "name": "Interworking, Unspecified",
        "description": "Erro de interoperabilidade não especificado — problema entre redes diferentes.",
        "solution": "Habilitar log máximo e capturar PCAP. Contatar suporte da operadora com logs.",
    },
}


def analyze_sip_code(code: int) -> dict:
    if code in SIP_RESPONSE_CODES:
        return SIP_RESPONSE_CODES[code]
    if 100 <= code <= 199:
        return {
            "name": f"Provisional {code}",
            "category": "provisional",
            "is_error": False,
            "description": f"Resposta provisória {code} — processamento em andamento.",
            "causes": [],
            "solutions": [],
        }
    if 200 <= code <= 299:
        return {
            "name": f"Success {code}",
            "category": "success",
            "is_error": False,
            "description": f"Resposta de sucesso {code}.",
            "causes": [],
            "solutions": [],
        }
    if 300 <= code <= 399:
        return {
            "name": f"Redirect {code}",
            "category": "redirect",
            "is_error": False,
            "description": f"Redirecionamento {code} — verificar header Contact para novo destino.",
            "causes": ["Redirecionamento configurado no servidor"],
            "solutions": ["Seguir novo endereço indicado no header Contact"],
        }
    if 400 <= code <= 499:
        return {
            "name": f"Client Error {code}",
            "category": "client_error",
            "is_error": True,
            "description": f"Erro do cliente {code} — problema na requisição enviada.",
            "causes": ["Requisição malformada ou parâmetros inválidos"],
            "solutions": ["Verificar logs e capturar tráfego SIP para diagnóstico"],
        }
    if 500 <= code <= 599:
        return {
            "name": f"Server Error {code}",
            "category": "server_error",
            "is_error": True,
            "description": f"Erro interno do servidor {code}.",
            "causes": ["Falha interna no servidor SIP"],
            "solutions": ["Verificar logs do servidor: `tail -f /var/log/asterisk/full`"],
        }
    if 600 <= code <= 699:
        return {
            "name": f"Global Error {code}",
            "category": "global_error",
            "is_error": True,
            "description": f"Erro global {code} — falha definitiva.",
            "causes": ["Requisição não pode ser atendida em nenhum servidor"],
            "solutions": ["Verificar disponibilidade do destino e configuração de rotas"],
        }
    return {
        "name": f"Código desconhecido {code}",
        "category": "unknown",
        "is_error": True,
        "description": f"Código SIP {code} não reconhecido.",
        "causes": [],
        "solutions": ["Consultar RFC 3261 e extensões SIP relevantes"],
    }


def analyze_q850_cause(cause: int) -> dict:
    if cause in Q850_CAUSES:
        return Q850_CAUSES[cause]
    return {
        "name": f"Causa Q.850 {cause}",
        "description": f"Causa de desconexão Q.850 {cause} não catalogada.",
        "solution": "Consultar ITU-T Q.850 para descrição completa da causa.",
    }


def _detect_heuristic_issues(messages: list, methods: list, statuses: list) -> list[dict]:
    issues = []

    invite_indices = [i for i, m in enumerate(messages) if m.get("method") == "INVITE" and not m.get("status_code")]
    response_codes = [m.get("status_code") for m in messages if m.get("status_code")]
    ack_count = sum(1 for m in messages if m.get("method") == "ACK")

    non_100_responses = [c for c in response_codes if c and c >= 200]
    has_any_non_100_response = bool(non_100_responses)

    if invite_indices and not response_codes:
        issues.append({
            "severity": "alta",
            "title": "INVITE sem nenhuma resposta SIP",
            "description": "Um ou mais INVITEs foram enviados mas nenhuma resposta SIP foi recebida. Indica falha de conectividade na camada de sinalização.",
            "solutions": [
                "Verificar conectividade L3: `ping <IP_destino>`",
                "Confirmar que UDP/5060 não está bloqueado: `nc -u <IP> 5060`",
                "Capturar tráfego no destino: `tcpdump -i any 'port 5060'` para ver se os pacotes chegam",
                "Verificar se o SIP ALG está desabilitado no roteador/firewall",
                "Confirmar rota de retorno — o destino pode não conseguir responder ao IP de origem",
            ],
        })

    invite_count = len(invite_indices)
    if invite_count >= 3 and not has_any_non_100_response:
        issues.append({
            "severity": "alta",
            "title": f"Retransmissão de INVITE detectada ({invite_count} INVITEs sem resposta ≥ 200)",
            "description": "Múltiplos INVITEs foram enviados sem receber resposta definitiva. Indica que o servidor está recebendo mas não consegue responder, ou as respostas não estão chegando de volta.",
            "solutions": [
                "Desabilitar SIP ALG no roteador — é a causa mais comum: verificar configurações do roteador/firewall",
                "No PBX: habilitar `rtp_symmetric=yes` e `force_rport=yes` no pjsip.conf",
                "Validar a rota de retorno — o destino pode estar respondendo para IP/porta errados",
                "Capturar PCAP no destino para confirmar se as respostas são enviadas",
                "Verificar MTU — pacotes SIP com SDP podem ser fragmentados: `ping -M do -s 1472 <IP>`",
            ],
        })

    ok_for_invite = any(
        m.get("status_code") == 200 and m.get("cseq_method", "").upper() == "INVITE"
        for m in messages
    )
    if ok_for_invite and ack_count == 0:
        issues.append({
            "severity": "alta",
            "title": "200 OK para INVITE sem ACK correspondente",
            "description": "O destino atendeu (200 OK) mas nenhum ACK foi detectado. O chamador pode não estar conseguindo completar o three-way handshake SIP, causando retransmissões do 200 OK e possível queda da chamada.",
            "solutions": [
                "Habilitar `rtp_symmetric=yes` no pjsip.conf do endpoint",
                "Habilitar `force_rport=yes` no pjsip.conf do endpoint",
                "No chan_sip (sip.conf): `nat=force_rport,comedia`",
                "Verificar se o ACK está sendo enviado mas bloqueado pelo firewall/NAT",
                "Capturar PCAP nos dois lados para identificar onde o ACK se perde",
                "Desabilitar SIP ALG no roteador se estiver ativo",
            ],
        })

    if "CANCEL" in methods:
        issues.append({
            "severity": "info",
            "title": "Chamada cancelada pelo originador (CANCEL)",
            "description": "O chamador enviou CANCEL antes do atendimento. Indica que desligou antes de ser atendido, ou que o dialplan realizou cancelamento programático.",
            "solutions": [
                "Comportamento normal se o usuário desligou antes do atendimento",
                "Se inesperado: verificar timeout de ring no dialplan — ex: `Dial(SIP/ramal,30)` limita a 30 segundos",
                "Verificar se o PBX está cancelando por política de horário ou capacidade",
            ],
        })

    return issues


def compute_verdict(diagnostics: list, final_response: int | None, methods: list) -> str:
    has_error_diagnostic = any(d.get("type") == "sip_response" for d in diagnostics)
    if has_error_diagnostic:
        return "error"
    if final_response is not None:
        if 200 <= final_response <= 299:
            return "success"
        if final_response == 487:
            return "cancelled"
    return "inconclusive"


def analyze_call(call_id: str, messages: list, hangup_causes: list[int]) -> dict:
    methods_ordered: list[str] = []
    seen_methods: set[str] = set()
    all_responses: list[int] = []
    from_users: list[str] = []
    to_users: list[str] = []
    error_codes: list[int] = []
    final_response: int | None = None
    last_invite_response: int | None = None

    for msg in messages:
        method = msg.get("method")
        status = msg.get("status_code")
        from_user = msg.get("from_user")
        to_user = msg.get("to_user")

        if method and method not in seen_methods:
            seen_methods.add(method)
            methods_ordered.append(method)

        if status:
            all_responses.append(status)
            final_response = status
            cseq_method = msg.get("cseq_method", "").upper()
            if cseq_method == "INVITE" or not cseq_method:
                last_invite_response = status
            if status >= 400:
                error_codes.append(status)

        if from_user and from_user not in from_users:
            from_users.append(from_user)
        if to_user and to_user not in to_users:
            to_users.append(to_user)

    effective_final = last_invite_response if last_invite_response is not None else final_response
    statuses = list(dict.fromkeys(all_responses))

    diagnostics: list[dict] = []
    for code in set(error_codes):
        info = analyze_sip_code(code)
        if info.get("is_error"):
            diagnostics.append({
                "type": "sip_response",
                "code": code,
                "name": info["name"],
                "description": info["description"],
                "causes": info["causes"],
                "solutions": info["solutions"],
            })

    for cause in set(hangup_causes):
        info = analyze_q850_cause(cause)
        diagnostics.append({
            "type": "q850",
            "code": cause,
            "name": info["name"],
            "description": info["description"],
            "causes": [],
            "solutions": [info["solution"]],
        })

    heuristics = _detect_heuristic_issues(messages, methods_ordered, statuses)
    verdict = compute_verdict(diagnostics, effective_final, methods_ordered)

    return {
        "call_id": call_id,
        "verdict": verdict,
        "from_users": from_users,
        "to_users": to_users,
        "methods": methods_ordered,
        "all_responses": statuses,
        "final_response": effective_final,
        "error_codes": list(set(error_codes)),
        "diagnostics": diagnostics,
        "heuristics": heuristics,
        "messages": messages,
        "message_count": len(messages),
    }
