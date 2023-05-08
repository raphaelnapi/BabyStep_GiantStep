# BabyStep_GiantStep
Ataque a troca de chaves Diffie Hellman utilizando o algoritmo BabyStep GiantStep (ataque a números primos genéricos).

Os números primos utilizados são primos seguros gerados utilizando o terminal de comando OpenSSL.

# Parâmetros para execução
Dentro da função Main(), altere as linhas de 25 a 40 conforme objetivo de pesquisa:
```C#
            //Parâmetros para experimento
            TAMANHO_EM_BITS Tamanho_do_Primo = TAMANHO_EM_BITS.Bit8;
            int Tamanho_Chave_Privada_em_Bytes = 2; //O código atual não permite trabalhar com tamanho de chaves em bits
            EXPERIMENTO Experimento = EXPERIMENTO.Experimento1;
            int g = 2;
            string DataPath = "";  //Recomendável utilizar um HD externo como banco de dados (grande volume de dados dependendo do tamanho do número primo)
            int Threads = 7;
            BigInteger AliceKpv = 177; //0 para random
            BigInteger BobKpv = 177; //0 para random 
            bool realiza_brute_force = false;
            bool realiza_babystep_giantstep_singlethreading = false;
            bool realiza_babystep_giantstep_multithreading = true;
            bool calcula_ordem = false;
            bool registra_relatorio = false;
            bool relatorio_bit_a_bit = true;
            //Fim dos parâmetros para experimento
```
