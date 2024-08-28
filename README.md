# Lazy Coin — Blockchain de Transações

## Descrição

O projeto **Lazy Coin** tem como objetivo desenvolver um sistema semelhante a um CRUD bancário, focado em transações financeiras sem a funcionalidade de deleção de dados ou carteiras. A aplicação simula uma blockchain de um único nó com uma API para registrar transações entre carteiras, oferecendo funcionalidades básicas inspiradas em blockchains comerciais, como Ethereum e Bitcoin, mas com uma abordagem mais simples.

## Funcionalidades

- **Blockchain**:
  - Armazena informações sobre transações de carteiras em blocos.
  - Não permite a deleção de dados ou carteiras.
  - Implementação de uma blockchain de nó único, sem algoritmos complexos de consenso.

- **Endpoints HTTP**:
  1 . `GET /chain`: Retorna toda a blockchain em formato JSON.
  2. `GET /pending`: Lista todas as transações pendentes de inclusão na blockchain.
  3. `GET /block/:number`: Retorna o bloco específico pelo número fornecido.
  4. `GET /transaction/:id`: Retorna a transação com o ID especificado.
  5. `GET /wallet/`: Lista todas as carteiras registradas na blockchain.
  6. `GET /wallet/:id`: Retorna saldo e transações de uma carteira específica.
  7. `GET /balance/:id`: Retorna apenas o saldo de uma carteira específica.
  8. `POST /wallet`: Cria uma nova carteira e retorna um par de chaves assimétricas.
  9. `POST /mine`: Minera um novo bloco, esvaziando as transações pendentes.
  10. `POST /transfer`: Realiza uma transação entre duas carteiras.

## Front-End

O projeto inclui uma interface front-end desenvolvida em **HTML**, **CSS** e **JavaScript (ES6)**, permitindo a interação com todos os endpoints disponíveis. A interface simula uma aplicação de carteira de blockchain, semelhante ao Metamask ou Binance.

## Comportamento Esperado

- A quantidade de moedas será constante desde o bloco gênesis, sem criação de novas moedas em blocos subsequentes.
- Apenas valores inteiros positivos não-nulos poderão ser transferidos.
- Transações só serão realizadas se a carteira remetente tiver saldo suficiente.
- Não será possível transferir para carteiras inexistentes na blockchain.
- Blocos já minerados não poderão ser alterados, deletados ou re-minerados.

## Estrutura do Bloco

Cada bloco na blockchain contém os seguintes dados:
- **ID**: Número do bloco.
- **Nonce**: Número único usado uma vez.
- **Dados**: Informações serializadas em JSON.
- **Hash-Prévia**: Hash do bloco anterior.
- **Hash**: Hash do bloco atual.

### Exemplo de Dados do Bloco

```json
[
    {"wallet": "ABC", "currency": 10},
    {"wallet": "XYZ", "currency": 0},
    {"from": "ABC", "to": "XYZ", "currency": 1}
]
