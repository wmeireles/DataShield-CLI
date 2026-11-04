# DataShield CLI

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-000000)](https://github.com/astral-sh/ruff)
[![Type Checking](https://img.shields.io/badge/type%20checking-mypy-blue)](https://github.com/mypyc/mypy)

Ferramenta de linha de comando offline-first para detecção, mascaramento e mapeamento determinístico de PII (Dados Pessoais Identificáveis) antes de enviar contexto para LLMs.

## Sumário

- [Visão Geral](#visão-geral)
- [Instalação](#instalação)
- [Início Rápido](#início-rápido)
- [Comandos](#comandos)
- [Detectores Suportados](#detectores-suportados)
- [Arquitetura](#arquitetura)
- [Modelo de Segurança](#modelo-de-segurança)
- [Vault (Mapeamento de Tokens)](#vault-mapeamento-de-tokens)
- [Extensão com Detectores Personalizados](#extensão-com-detectores-personalizados)
- [Configuração](#configuração)
- [Exemplos](#exemplos)
- [Desenvolvimento](#desenvolvimento)
- [Portões de Qualidade](#portões-de-qualidade)
- [Roteiro](#roteiro)
- [Contribuição](#contribuição)
- [Licença](#licença)

## Visão Geral

O DataShield CLI sanitiza dados estruturados e não-estruturados detectando PII (CPF, CNPJ, e-mails, telefones, chaves de API) e substituindo-os por tokens determinísticos (`<CPF_1>`, `<EMAIL_1>`, etc.). Todo o processamento ocorre localmente, sem chamadas de rede.

Principais propriedades:

- **Offline-first**: Zero dependências de rede, adequado para ambientes air-gapped
- **Validação matemática**: CPF e CNPJ usam algoritmo Módulo 11 de dígitos verificadores, não apenas regex
- **Mapeamento determinístico**: Mesma entidade sempre mapeia para o mesmo token dentro de uma sessão
- **Vault criptografado**: Mapeamentos token-para-original armazenados em memória com AES-256 (Fernet)
- **Multi-formato**: JSON, CSV, texto plano, stdin/stdout com preservação de estrutura
- **CLI Rich**: Barras de progresso, tabelas de comparação, resumos coloridos

## Instalação

### Requisitos

- Python 3.11+
- `uv` (recomendado) ou `pip`

### Usando uv

```bash
# Instalação direta
uv pip install datashield

# Ou instalação do source para desenvolvimento
git clone https://github.com/seu-org/datashield
cd datashield
uv venv
uv pip install -e ".[dev]"
```

### Usando pip

```bash
pip install datashield
```

### Verificar Instalação

```bash
datashield --version
# DataShield CLI v0.1.0
```

## Início Rápido

```bash
# Sanitizar arquivo (JSON, CSV ou texto)
datashield clean dados.json -o sanitizado.json

# Sanitizar da stdin
cat dados.json | datashield clean

# Detectar sem sanitizar
datashield detect dados.json

# Restaurar dados originais (requer vault exportado)
datashield restore sanitizado.json -v vault.enc --vault-key sessao.key -o original.json
```

## Comandos

### `datashield clean`

Sanitiza PII dos dados de entrada.

```bash
datashield clean [OPÇÕES] [CAMINHO_ARQUIVO]
```

| Opção | Descrição |
|-------|-----------|
| `CAMINHO_ARQUIVO` | Arquivo de entrada (lê de stdin se omitido) |
| `-o, --output CAMINHO` | Arquivo de saída (escreve em stdout se omitido) |
| `-f, --format FORMATO` | Força formato de entrada: `json`, `csv`, `text` |
| `--export-vault CAMINHO` | Exporta vault criptografado para arquivo |
| `--vault-key CAMINHO` | Lê ou cria a chave separada usada com `--export-vault` |

### `datashield detect`

Detecta e relata PII sem sanitizar.

```bash
datashield detect [OPÇÕES] [CAMINHO_ARQUIVO]
```

| Opção | Descrição |
|-------|-----------|
| `CAMINHO_ARQUIVO` | Arquivo de entrada (lê de stdin se omitido) |
| `-f, --format FORMATO` | Força formato de entrada: `json`, `csv`, `text` |

### `datashield restore`

Restaura PII original a partir de tokens usando vault exportado.

```bash
datashield restore [OPÇÕES] [CAMINHO_ARQUIVO]
```

| Opção | Descrição |
|-------|-----------|
| `CAMINHO_ARQUIVO` | Arquivo com tokens (lê de stdin se omitido) |
| `-v, --vault CAMINHO` | Arquivo vault exportado durante sanitização (obrigatório) |
| `--vault-key CAMINHO` | Chave Fernet separada usada para descriptografar o vault |
| `-o, --output CAMINHO` | Arquivo de saída (escreve em stdout se omitido) |

### Opções Globais

| Opção | Descrição |
|-------|-----------|
| `--version, -V` | Mostra versão e sai |
| `--help` | Mostra ajuda e sai |

## Detectores Suportados

### Identificadores Brasileiros (Validação Matemática)

| Detector | Formato | Validação | Token | Exemplo Válido |
|----------|---------|-----------|-------|----------------|
| CPF | `XXX.XXX.XXX-XX` ou 11 dígitos | Módulo 11 (dígitos verificadores) | `<CPF_1>` | `111.444.777-35` |
| CNPJ | `XX.XXX.XXX/XXXX-XX` ou 14 dígitos | Módulo 11 (dígitos verificadores) | `<CNPJ_1>` | `11.222.333/0001-81` |

Ambos os detectores CPF e CNPJ implementam o algoritmo oficial Módulo 11. Números com dígitos verificadores inválidos ou sequências repetidas (ex: `111.111.111-11`) são rejeitados.

### Identificadores Globais (Padrão + Validação Semântica)

| Detector | Padrão | Validação | Token | Exemplo |
|----------|--------|-----------|-------|---------|
| E-mail | RFC 5322 regex | `@` único, domínio válido | `<EMAIL_1>` | `usuario@empresa.com.br` |
| Telefone (BR) | `(XX) 9XXXX-XXXX` + variantes | 9º dígito = 9 (móvel), DDD válido | `<PHONE_1>` | `(11) 99999-9999` |
| API Key | 8 padrões compilados | Entropia >= 10 chars únicos, comprimento >= 20 | `<API_KEY_1>` | `sk-abc...xyz` |

**Padrões de API Key detectados:**
- OpenAI: `sk-[a-zA-Z0-9]{48}`
- Anthropic: `sk-ant-[a-zA-Z0-9_-]{95}`
- Bearer tokens: `Bearer [a-zA-Z0-9_-]{20,}`
- AWS Access Key: `aws_access_key_id = [A-Z0-9]{20}`
- AWS Secret Key: `aws_secret_access_key = [A-Za-z0-9/+=]{40}`
- GitHub tokens: `gh[pousr]_[a-zA-Z0-9]{36,}`
- Genérico: `api_key = [a-zA-Z0-9_-]{20,}` com alta entropia

## Arquitetura

```
[Entrada: Texto / JSON / CSV / STDIN]
                  |
                  v
┌─────────────────────────────────────────────┐
│      Data Engine / Format Parsers           │
│  - Detecção automática de formato           │
│  - JSON -> dict/list (orjson)               │
│  - CSV -> list[dict]                        │
│  - Texto plano -> str                       │
└─────────────────────────┬───────────────────┘
                          |
                          v
┌─────────────────────────────────────────────┐
│           PII Sanitizer Engine              │
│  1. Executa todos detectores plugáveis      │
│  2. Coleta detecções com posição            │
│  3. Ordena forward para atribuição token    │
│  4. Atribui tokens determinísticos          │
│  5. Ordena reverso para substituição segura │
│  6. Substitui no texto original             │
│  7. Atualiza vault + estatísticas           │
└─────────────────────────┬───────────────────┘
                          |
                          v
┌─────────────────────────────────────────────┐
│           Session Token Vault               │
│  - Fernet com chave fornecida separadamente │
│  - Mapeamentos Token <-> Original em memória│
│  - Índice reverso Original -> Token         │
│  - Export/Import criptografado              │
└─────────────────────────┬───────────────────┘
                          |
                          v
┌─────────────────────────────────────────────┐
│              CLI / Output Layer             │
│  - Rich: tabelas, progress bars, painéis    │
│  - Saída: stdout (padrão) ou arquivo        │
│  - Formatos: JSON, CSV, texto (estrutura)   │
└─────────────────────────────────────────────┘
```

### Módulos Principais

| Módulo | Caminho | Responsabilidade |
|--------|---------|------------------|
| CLI | `datashield/main.py` | Aplicação Typer, comandos, UI Rich |
| Engine | `datashield/core/engine.py` | SanitizerEngine, SanitizeResult, orquestração |
| Vault | `datashield/core/vault.py` | Vault, TokenMapping, criptografia Fernet |
| Base Detector | `datashield/detectors/base.py` | BaseDetector (ABC), Detection dataclass |
| CPF | `datashield/detectors/br/cpf.py` | Regex + Módulo 11 |
| CNPJ | `datashield/detectors/br/cnpj.py` | Regex + Módulo 11 |
| Comuns | `datashield/detectors/br/common.py` | Email, Phone, APIKey |
| Formatters | `datashield/utils/formatters.py` | Parse JSON/CSV, detecção formato |

## Modelo de Segurança

### Vetores de Ameaça e Mitigações

| Vetor | Mitigação |
|-------|-----------|
| PII escrito em disco | Nunca escrito — apenas tokens aparecem na saída |
| PII em logs/stdout | Nunca logado — Rich UI exibe apenas tokens |
| Mapeamento token-para-PII | Fernet; chave mantida separadamente |
| Chave de criptografia | Gerada por sessão via `Fernet.generate_key()` |
| Persistência acidental | Morte do processo = perda da chave = irreversível |
| Engenharia reversa | Código aberto, sem ofuscação, sem telemetria |

### Garantias de Fluxo de Dados

- PII bruto nunca persiste no sistema de arquivos
- PII bruto nunca aparece em logs da aplicação
- Mapeamentos de token existem apenas na memória do processo
- Chave de criptografia do vault é escopo de sessão
- Zero dependências externas ou chamadas de rede

## Vault (Mapeamento de Tokens)

O vault fica em memória durante o processamento. Ao exportá-lo, o arquivo contém
os mapeamentos cifrados, enquanto a chave Fernet é salva em um arquivo separado.
Proteja a chave com os mesmos controles de acesso usados para os dados originais:
quem obtiver o vault e sua chave poderá restaurar os valores. A ferramenta não
gerencia senhas, rotação ou backup dessa chave.

O vault mantém mapeamentos bidirecionais:

```
Token -> Original  (para desanonimização)
Original -> Token  (para atribuição determinística)
```

### Operações

| Método | Descrição |
|--------|-----------|
| `store(token, original, detector, confidence)` | Armazena mapeamento |
| `retrieve(token)` | Retorna PII original ou None |
| `get_token_for(original)` | Retorna token existente ou None |
| `export_encrypted(key)` | Retorna bytes criptografados usando uma chave Fernet externa |
| `import_encrypted(bytes, key)` | Restaura vault em nova sessão com a mesma chave |
| `clear()` | Remove todos mapeamentos da memória |
| `get_all_mappings()` | Retorna cópia de todos mapeamentos |

### Fluxo Export/Import

```bash
# Durante sanitização
datashield clean dados.json --export-vault sessao.vault --vault-key sessao.key

# Em outra sessão ou máquina
datashield restore sanitizado.json -v sessao.vault --vault-key sessao.key -o original.json
```

Uso programático:

```python
from datashield.core.engine import create_engine
from datashield.core.vault import Vault

engine = create_engine()
result = engine.sanitize("CPF: 111.444.777-35")

# Export
key = Vault.generate_key()
vault_bytes = engine.vault.export_encrypted(key)

# Depois / em outro lugar
new_vault = Vault()
new_vault.import_encrypted(vault_bytes, key)
new_engine = create_engine()
original = new_engine.desanitize("<CPF_1>", new_vault)  # "111.444.777-35"
```

## Extensão com Detectores Personalizados

```python
# detector_personalizado.py
import re
from typing import List
from datashield.detectors.base import BaseDetector, Detection

class MeuDetector(BaseDetector):
    _PATTERN = re.compile(r"MEU_PADRAO_REGEX")

    @property
    def name(self) -> str:
        return "meu_detector"

    @property
    def token_prefix(self) -> str:
        return "MEU"

    def validate(self, candidate: str) -> bool:
        # Implementar validação (checksum, semântica, etc.)
        return True

    def find_candidates(self, text: str) -> List[str]:
        return [m.group() for m in self._PATTERN.finditer(text)]

# Uso
from datashield.core.engine import create_engine

engine = create_engine(detectors=[MeuDetector()])
result = engine.sanitize("Texto com MEU_PADRAO_REGEX")
```

## Configuração

### Variáveis de Ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `DATASHIELD_LOG_LEVEL` | `WARNING` | Nível de log: DEBUG, INFO, WARNING, ERROR |
| `NO_COLOR` | não definido | Desabilita saída colorida |

### Seleção Programática de Detectores

```python
from datashield.core.engine import create_engine
from datashield.detectors.br import CPFDetector, CNPJDetector, EmailDetector

# Usar apenas detectores específicos (mais rápido, menos falsos positivos)
engine = create_engine(detectors=[CPFDetector(), CNPJDetector()])

# Adicionar detector personalizado junto aos built-ins
engine = create_engine(detectors=[CPFDetector(), MeuDetector()])
```

## Exemplos

### Sanitizar Arquivo JSON

```bash
# Entrada: usuarios.json
# {"usuarios": [{"nome": "João", "cpf": "111.444.777-35", "email": "joao@email.com"}]}

datashield clean usuarios.json -o usuarios_sanitizado.json

# Saída:
# {"usuarios": [{"nome": "João", "cpf": "<CPF_1>", "email": "<EMAIL_1>"}]}
```

### Sanitizar CSV com Preservação de Estrutura

```bash
# Entrada: clientes.csv
# nome,cpf,email,telefone
# João,111.444.777-35,joao@email.com,(11) 99999-9999

datashield clean clientes.csv -o clientes_sanitizado.csv

# Saída preserva cabeçalho e estrutura CSV:
# nome,cpf,email,telefone
# João,<CPF_1>,<EMAIL_1>,<PHONE_1>
```

### Pipeline com jq

```bash
# Extrair campos, sanitizar, recompor
cat dados.json | jq '.registros[] | {cpf, email}' | \
  datashield clean --format json --no-keep-format | \
  jq -s '.'
```

### API Python

```python
from datashield.core.engine import create_engine
from datashield.core.vault import Vault

engine = create_engine()

# Texto simples
result = engine.sanitize("CPF: 111.444.777-35")
print(result.sanitized_text)  # "CPF: <CPF_1>"
print(result.stats)           # {"cpf": 1}

# Dicionário aninhado
data = {"usuario": {"cpf": "111.444.777-35", "email": "a@b.com"}}
sanitized = engine.sanitize_dict(data)
# {"usuario": {"cpf": "<CPF_1>", "email": "<EMAIL_1>"}}

# Desanonimizar
original = engine.desanitize_dict(sanitized, engine.vault)

# Exportar/Importar vault para restauração cross-sessão
key = Vault.generate_key()
vault_bytes = engine.vault.export_encrypted(key)
# Salvar vault_bytes em arquivo...

# Em outro processo
new_vault = Vault()
new_vault.import_encrypted(vault_bytes, key)
new_engine = create_engine()
restored = new_engine.desanitize("<CPF_1>", new_vault)  # "111.444.777-35"
```

### Apenas Detecção (Modo Auditoria)

```bash
datashield detect dados_sensiveis.json

# Saída:
# ┌─────────────────────────────────────────────────────────────┐
# │ PII Detection Report                                        │
# ├────────┬──────────────────────┬────────────┬────────────────┤
# │ Tipo   │ Original             │ Token      │ Posição        │
# ├────────┼──────────────────────┼────────────┼────────────────┤
# │ CPF    │ 111.444.777-35       │ <CPF_1>    │ 10-24          │
# │ EMAIL  │ usuario@empresa.com  │ <EMAIL_1>  │ 28-48          │
# │ CNPJ   │ 11.222.333/0001-81   │ <CNPJ_1>   │ 52-70          │
# └────────┴──────────────────────┴────────────┴────────────────┘
```

## Desenvolvimento

### Configuração

```bash
git clone https://github.com/seu-org/datashield
cd datashield
uv venv
uv pip install -e ".[dev]"
```

### Executar Testes

```bash
# Todos os testes
uv run pytest -v

# Com cobertura
uv run pytest --cov=datashield --cov-report=term-missing --cov-report=html

# Arquivo específico
uv run pytest tests/test_detectors_br.py -v
```

### Cobertura Atual

| Módulo | Statements | Missing | Coverage |
|--------|------------|---------|----------|
| `datashield.core.vault` | 57 | 5 | 91% |
| `datashield.core.engine` | 84 | 6 | 93% |
| `datashield.detectors.base` | 37 | 0 | 100% |
| `datashield.detectors.br.cpf` | 63 | 11 | 83% |
| `datashield.detectors.br.cnpj` | 63 | 20 | 68% |
| `datashield.detectors.br.common` | 75 | 6 | 92% |
| **Total** | **572** | **118** | **79%** |

## Portões de Qualidade

### Linting (Ruff)

```bash
ruff check .
ruff check . --fix
```

### Type Checking (Mypy Strict)

```bash
mypy datashield
```

### Configuração Mypy

```toml
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
no_implicit_optional = true
```

### Pre-commit (Opcional)

```bash
pre-commit install
pre-commit run --all-files
```

## Roteiro

- [ ] Detector de RG (estados brasileiros)
- [ ] Detector de endereço (CEP + logradouro)
- [ ] Detector de cartão de crédito (Luhn)
- [ ] Suporte a Parquet/Arrow
- [ ] Plugin VS Code / JetBrains
- [ ] API REST opcional (FastAPI)
- [ ] Integração GitHub Actions
- [ ] Build WebAssembly para browser

## Contribuição

### Fluxo de Trabalho

1. Fork do repositório
2. Criar branch: `git checkout -b feature/novo-detector`
3. Desenvolver com testes e type hints
4. Executar portões de qualidade: `ruff check . && mypy datashield && pytest`
5. Commit seguindo Conventional Commits: `git commit -m 'feat: adiciona detector RG'`
6. Push: `git push origin feature/novo-detector`
7. Abrir Pull Request para `main`

### Padrões de Código

- **Tipagem**: 100% type hints, `mypy --strict` passa
- **Formatação**: `ruff` (line-length=100, alvo py311)
- **Testes**: `pytest` com fixtures, coverage >= 80% para código novo
- **Commits**: Formato Conventional Commits

### Ideias para Contribuição

- Detectores adicionais brasileiros (RG, CNH, Título Eleitor)
- Identificadores internacionais (SSN, NIN, VAT)
- Novos formatters (XML, YAML, Parquet)
- Benchmarks de performance
- Melhorias na documentação

## Licença

Licença MIT — veja [LICENSE](LICENSE) para detalhes.

```
MIT License

Copyright (c) 2024 DataShield Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Suporte

| Canal | Link |
|-------|------|
| Issues / Bugs | [GitHub Issues](https://github.com/seu-org/datashield/issues) |
| Feature Requests | [GitHub Discussions](https://github.com/seu-org/datashield/discussions) |
| Documentação | [Wiki](https://github.com/seu-org/datashield/wiki) |
| Segurança | [Security Policy](https://github.com/seu-org/datashield/security/policy) |

---

DataShield — Privacidade por Design
