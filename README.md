# IDE Online para C e Python

Bem-vindo ao **IDE Online**, uma aplicação web simples que permite editar, compilar e executar códigos nas linguagens **C/C++** e **Python** diretamente no navegador!

---

## 📋 Sumário

- [📝 Descrição](#-descrição)
- [✨ Funcionalidades](#-funcionalidades)
- [🚀 Começando](#-começando)
  - [Pré-requisitos](#pré-requisitos)
  - [Instalação](#instalação)
  - [Inicialização](#inicialização)
- [🛠️ Como usar](#️-como-usar)
- [📁 Estrutura do Projeto](#-estrutura-do-projeto)
- [🔧 Tecnologias](#-tecnologias)
- [🤝 Contribuição](#-contribuição)
- [⚖️ Licença](#️-licença)

---

## 📝 Descrição

Este projeto oferece um ambiente de desenvolvimento integrado (IDE) online com suporte a:

- Edição de múltiplos arquivos (C, C++, Python)
- Salvamento automático e manual dos arquivos no banco de dados
- Compilação e execução de códigos C/C++ com limites de tempo e memória
- Execução interativa de scripts Python em ambiente restrito
- Upload e download de arquivos do usuário
- Autenticação de usuários com registro e login

Ideal para praticar algoritmos, testar trechos de código ou compartilhar programas simples sem precisar instalar compiladores localmente.

## ✨ Funcionalidades

- Autenticação de usuários (registrar e login)
- Criação, edição e exclusão de arquivos no workspace
- Editor de código com **Monaco Editor** (mesmo do VS Code)
- Execução de código C/C++ via **GCC/G++**
- Execução de código Python via **python3**
- Limites configuráveis de tempo (15s) e memória (50MB)
- Console de saída interativo
- Download dos arquivos criados

## 🚀 Começando

### Pré-requisitos

- Python 3.8+ instalado na máquina
- GCC/G++ (para compilação de C/C++)
- MySQL ou MariaDB rodando (configurar conexão em `SQLALCHEMY_DATABASE_URI`)

### Instalação

1. Clone este repositório:
   ```bash
   git clone https://github.com/chiapettaiago/code.git
   cd code
   ```

2. Crie e ative um ambiente virtual:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   source venv/bin/activate # Linux/Mac
   ```

3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure a conexão ao banco de dados no arquivo `app.py` (variável `SQLALCHEMY_DATABASE_URI`).

### Inicialização

- Para criar as tabelas no banco:
  ```bash
  flask run --host=0.0.0.0 --port=13000
  ```

- Acesse em seu navegador:
  ```
  http://localhost:13000
  ```

---

## 🛠️ Como usar

1. Cadastre-se ou faça login.
2. Crie um novo arquivo (.c, .cpp, .py).
3. Edite seu código no editor.
4. Digite entradas no console de entrada (se necessário).
5. Clique em **Executar** para ver o resultado.
6. Baixe seu arquivo clicando em **Download**.

## 📁 Estrutura do Projeto

```
/ide-online
│
├─ app.py              # Aplicação Flask (backend)
├─ requirements.txt    # Dependências Python
├─ instance/           # Pasta para banco de dados (SQLite opcional)
├─ static/             # Arquivos estáticos (favicon, CSS adicional)
└─ templates/
   └─ index.html       # Interface web (frontend)
```

## 🔧 Tecnologias

- **Flask** para backend e rotas REST
- **Flask-Login** para autenticação
- **SQLAlchemy** para ORM
- **Monaco Editor** para edição de código
- **GCC/G++** para compilação de C/C++
- **Python3** para execução de scripts

## 🤝 Contribuição

Contribuições são bem-vindas! Siga estes passos:

1. Fork este repositório
2. Crie uma branch: `git checkout -b feature/nova-funcionalidade`
3. Faça commit de suas mudanças: `git commit -m 'Adiciona nova funcionalidade'`
4. Envie para o branch: `git push origin feature/nova-funcionalidade`
5. Abra um Pull Request

## ⚖️ Licença

Este projeto está licenciado sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

*Desenvolvido com ❤️ por Iago Chiapetta*