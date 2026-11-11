# Organiza

Organizador de tarefas com login e tarefas privadas para cada conta. As senhas são protegidas com scrypt; as sessões usam cookies `HttpOnly`; os dados ficam em um banco SQLite local.

## Iniciar no Windows

1. Instale o Python 3, se ainda não estiver instalado.
2. Dê dois cliques em `Iniciar Organiza.bat` ou abra o terminal nesta pasta e execute:

   ```powershell
   python server.py
   ```

3. O navegador abrirá em `http://127.0.0.1:3000`. Mantenha a janela do servidor aberta enquanto usa o organizador.

O arquivo `organiza.sqlite` e as tabelas são criados automaticamente na primeira execução. Não é necessário instalar Node.js, npm ou MySQL.

## Testes

```powershell
python -m unittest discover -s test -v
```

Os testes usam um banco SQLite temporário e não alteram as tarefas locais.

## Segurança

Cada operação de leitura, edição ou exclusão confere a conta autenticada no servidor. Para publicar o aplicativo na internet, configure HTTPS e um servidor de produção apropriado; o servidor incluído foi preparado para uso local.
