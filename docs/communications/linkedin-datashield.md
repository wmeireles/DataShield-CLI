# Post para LinkedIn — DataShield CLI

## Versão principal

Privacidade precisa fazer parte do fluxo de desenvolvimento com IA — antes que dados sensíveis cheguem ao modelo.

É com esse princípio que estou desenvolvendo o **DataShield CLI**, um projeto open source para detectar e mascarar informações pessoais localmente antes de usá-las como contexto em LLMs.

O projeto nasceu de um problema concreto: equipes querem aproveitar IA em tarefas de engenharia e análise de dados, mas CPFs, CNPJs, e-mails, telefones e credenciais não deveriam ser enviados por acidente junto com prompts, arquivos ou logs.

Hoje, o DataShield já oferece:

• processamento local e sem chamadas de rede;

• detecção de CPF e CNPJ com validação dos dígitos verificadores;

• suporte a e-mails, telefones brasileiros e padrões de chaves de API;

• substituição determinística por tokens como `<CPF_1>` e `<EMAIL_1>`;

• entrada e saída em JSON, CSV, texto e pipelines via stdin/stdout;

• arquitetura extensível para novos detectores.

A base atual conta com **62 testes automatizados aprovados**, análise estática com Ruff e tipagem estrita com mypy. Nesta nova etapa, incorporei ao repositório um conjunto de **37 skills de engenharia para Codex**, com fluxos reutilizáveis para revisão de código, diagnóstico, TDD, arquitetura, pesquisa, especificação e planejamento.

Mais do que acelerar a escrita de código, meu objetivo é usar agentes com disciplina de engenharia: contexto versionado, mudanças revisáveis, testes executados e decisões documentadas.

Os próximos passos incluem ampliar a cobertura da CLI e dos formatadores, fortalecer o modelo de persistência segura do vault, adicionar novos detectores brasileiros e preparar automações de CI para contribuições externas.

Estou construindo o DataShield de forma aberta e quero trocar experiências com pessoas interessadas em privacidade, segurança, Python e desenvolvimento assistido por IA. Feedback técnico, issues e pull requests são muito bem-vindos.

Repositório: https://github.com/wmeireles/DataShield-CLI

Também estou me preparando para uma futura turma do **Codex Ambassadors**, conectando duas frentes em que acredito: manter software open source útil e compartilhar práticas concretas que ajudem outros desenvolvedores a trabalhar melhor com agentes de IA.

Se esse problema aparece no seu dia a dia, quero ouvir: quais tipos de dados sensíveis o seu fluxo com IA precisa proteger?

#OpenSource #OpenAI #Codex #Python #DataPrivacy #Cybersecurity #LLM #AIEngineering #PrivacyByDesign #DeveloperTools

## Aberturas alternativas

### Foco no problema

Quantos dados pessoais entram em prompts de IA sem que a equipe perceba? Estou construindo uma ferramenta open source para reduzir esse risco antes que o contexto saia da máquina.

### Foco técnico

62 testes aprovados, processamento local e tokenização determinística de PII: esta é a base atual do DataShield CLI, meu projeto open source para tornar fluxos com LLMs mais seguros.

### Foco em comunidade

Estou transformando um problema recorrente de privacidade em uma ferramenta aberta — e documentando como uso Codex, testes e revisão disciplinada para evoluí-la com a comunidade.

## Notas para publicação

- Substituir a URL do repositório caso o endereço público mude.
- Publicar junto com uma captura limpa do terminal mostrando um arquivo fictício antes e depois da sanitização. Não usar dados pessoais reais.
- Marcar OpenAI apenas se a menção estiver adequada ao contexto da publicação; não sugerir vínculo oficial com o programa.
- Manter os números de testes e skills atualizados se houver mudanças antes da publicação.
- Responder aos comentários com exemplos técnicos e links para issues abertas; isso demonstra manutenção ativa e cria uma conversa útil para a comunidade.

## Roteiro do visual sugerido

```text
ANTES                              DEPOIS
CPF: 111.444.777-35                CPF: <CPF_1>
email: pessoa@exemplo.com          email: <EMAIL_1>

             DataShield CLI
       processamento local • open source
```

