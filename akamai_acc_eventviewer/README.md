###################
Criação de QIDs
###################

Critérios de Severidade (1-10)
Crítico (9-10)

Falhas de autenticação com bloqueio
Suspeita de login malicioso
Bloqueio de tráfego
Alterações em DDoS comportamental

Alto (7-8)

Falhas de autenticação gerais
Eliminação de configurações de segurança
Desativação de proteções (WAF, MFA, 2FA)
Gestão de utilizadores críticos
Alterações em firewalls e políticas de segurança

Médio-Alto (6-7)

Criação/modificação de regras de segurança
Ativação de configurações em produção
Gestão de certificados
Alterações de roles e permissões

Médio (5-6)

Configurações gerais
Ativações em staging
Criação de políticas
Alterações DNS

Baixo (3-4)

Operações de purge/cache
Login/logout bem-sucedidos
Visualização de dados
Criação de tags

Informacional (1-2)

Notificações email
Tickets de suporte
Subscrições de newsletters

Funcionalidades do Script Atualizado:

Mapeamento específico para cada um dos 800+ eventos
Relatório CSV com justificação de severidade
Processamento prioritário (eventos críticos primeiro)
Sumário de distribuição de severidades
Logs detalhados com timestamp
Códigos de cores no output

Como Usar:
bash# Executar o script Python
python3 qradar_qid_creator.py events.json

# Ficheiros gerados:
# 1. qradar_qid_commands_*.sh - Script principal
# 2. qradar_qid_report_*.csv - Relatório detalhado
# 3. severity_summary_*.txt - Análise de severidades
# 4. check_qradar_categories.sh - Verificador de categorias
Exemplos de Severidades Atribuídas:

Severidade 9: "Authentication failure (user locked)", "Suspicious login notification"
Severidade 8: "Delete user", "Deactivate 2FA", "WAF configuration deletion"
Severidade 7: "Create custom WAF rule", "Add new user", "Certificate deletion"
Severidade 6: "Activate configuration", "Enable MFA"
Severidade 5: "Property creation", "DNS zone edit"
Severidade 3: "Purge request", "View report"
Severidade 2: "Email subscription", "Open support ticket"