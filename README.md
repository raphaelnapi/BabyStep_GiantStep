# BabyStep_GiantStep
Ataque a troca de chaves Diffie Hellman utilizando o algoritmo BabyStep GiantStep (ataque a números primos genéricos).

Os números primos utilizados são primos seguros gerados utilizando o terminal de comando OpenSSL.

# Parâmetros para execução
Dentro da função Main(), altere as linhas de 25 a 40 conforme objetivo de pesquisa:
```C#
            //Parâmetros para experimento
            TAMANHO_EM_BITS Tamanho_do_Primo = TAMANHO_EM_BITS.Bit16;
            int Tamanho_Chave_Privada_em_Bytes = 2; //O código atual não permite trabalhar com tamanho de chaves em bits
            EXPERIMENTO Experimento = EXPERIMENTO.Experimento1;
            int g = 2;
            string DataPath = "";  //Finalize com "\\", Ex: "C:\\". Recomendável utilizar um HD externo como banco de dados (grande volume de dados dependendo do tamanho do número primo)
            int Threads = 7;
            BigInteger AliceKpv = 0; //0 para random
            BigInteger BobKpv = 0; //0 para random 
            bool realiza_brute_force = true;
            bool realiza_babystep_giantstep_singlethreading = false;
            bool realiza_babystep_giantstep_multithreading = true;
            bool calcula_ordem = false;
            bool registra_relatorio = false;
            bool relatorio_bit_a_bit = false;  //Para testes de tempo para quebra da cifra a cada aumento de 1 bit na chave (a chave privada das partes tem que estar no limite da faixa para que o teste seja fidedigno)
            //Fim dos parâmetros para experimento
```

## Explicação dos parâmetros
> TAMANHO_EM_BITS Tamanho_do_Primo
 
Quantidade de bits do número primo seguro que será utilizado como parâmetro de domínio da troca de chave

> int Tamanho_Chave_Privada_em_Bytes
 
Tamanho em bytes da chave privada de Alice e Bob

> EXPERIMENTO Experimento
 
Seleção de 1 dos números primos seguros gerados por comando de linha do OpenSSL e que estão registrados na função PrimoGeradoOpenSSL()

> int g

Parâmetro de domínio gerador, normalmente 2

> string DataPath

Caminho da pasta Data (Deve-se utilizar \\ ao final do caminho)

> int Threads

Número de Threads simultâneas empregadas na quebra da chave

> BigInteger AliceKpv

Chave privada de Alice, 0 para uma chave aleatória

> BigInteger BobKpv

Chave privada de Bob, 0 para uma chave aleatória

> bool realiza_brute_force

Ativa/Desativa ataque de força bruta

> bool realiza_babystep_giantstep_singlethreading

Ativa/Desativa ataque BabyStep GiantStep com apenas uma Thread

> bool realiza_babystep_giantstep_multithreading

Ativa/Desativa ataque BabyStep GiantStep com mais de uma Thread

> bool calcula_ordem

Ativa/Desativa calcula da ordem do grupo finito

> bool registra_relatorio

Salva relatório do teste executado no diretório DataPath

> bool relatorio_bit_a_bit

Utilizado para testes que precisam verificar a diferença de tempo entre chaves de tamanhos diferentes, nestes casos as chaves privadas devem ser as maiores possíveis para que as varreduras sejam as maiores possíveis


Exemplo de saída:
```
Parâmetros de Domínio:
P: 52379
g: 2

:: Alice
Private Key: 28556
Public Key: 32603

:: Bob
Private Key: 45555
Public Key: 30749

:: Segredo compartilhado:
Alice: 8208
Bob: 8208


----- INICIO DO ATAQUE -----
Ord(2): 52378
Tempo gasto: 0,00016


:: Brute Force
BruteForce Chave Privada Alice: 28556
Tempo gasto: 0,04913

BruteForce Chave Privada Bob: 45555
Tempo gasto: 0,06376

Segredo compartilhado encontrado: 8208, 8208

:: BabyStep - GiantStep
Calcula raiz de Ord(g): 229
Tempo gasto: 0,00119

DataBase Throughput escrita: 461,93 mB/s
DataBase Throughput leitura: 1031,57 mB/s

BabyStep de 229: OK
Tamanho DB: 2704 bytes
Tempo gasto: 0,00518


:: GiantStep Multithreading
GiantStep Chave Privada Alice: 28556
Tempo gasto: 5,91321

Segredo compartilhado encontrado: 8208
GiantStep Chave Privada Bob: 45555
Tempo gasto: 7,16436

Segredo compartilhado encontrado: 8208
```
Observa-se o tempo gasto para encontrar a chave em um ataque de Força Bruta e em um ataque BabyStep GiantStep.
Nota: A medida que a quantidade de Bits da chave aumenta o ataque BabyStep GiantStep se torna muito mais vantajoso que o ataque de Força Bruta.
