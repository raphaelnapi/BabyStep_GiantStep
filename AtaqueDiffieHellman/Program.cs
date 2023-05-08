using System;
using System.Numerics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace AtaqueDiffieHellman
{
    class Program
    {
        /********************************
         * Proximo:
         * Tam Primo: Bit32
         * Tam Chave: 4
         * Experimento: 3
         * 
         * Experimento Bit a Bit
         * Próximo:
         * Tam P: 12
        *******************************/
        static void Main(string[] args)
        {
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

            //Carrega número primo
            BigInteger P = PrimoGeradoOpenSSL(Tamanho_do_Primo, Experimento);

            //Maior chave possível no relatorio bit a bit
            if (relatorio_bit_a_bit)
            {
                AliceKpv = P - 2;
                BobKpv = P - 2;
            }

            //Carrega chaves privadas de Alice e Bob
            Party Alice;
            if (AliceKpv == 0)
                Alice = new Party(P, g, Tamanho_Chave_Privada_em_Bytes * 8);
            else
                Alice = new Party(P, g, AliceKpv);

            Party Bob;
            if(BobKpv == 0)
                Bob = new Party(P, g, Tamanho_Chave_Privada_em_Bytes * 8);
            else
                Bob = new Party(P, g, BobKpv);


            //Imprime na tela parâmetros do experimento
            Console.WriteLine("Parâmetros de Domínio:");
            Console.WriteLine("P: {0}", P);
            Console.WriteLine("g: {0}", g);

            Console.WriteLine("\n:: Alice");
            Console.WriteLine("Private Key: {0}", Alice.Kpv);
            Console.WriteLine("Public Key: {0}", Alice.Kpub);

            Console.WriteLine("\n:: Bob");
            Console.WriteLine("Private Key: {0}", Bob.Kpv);
            Console.WriteLine("Public Key: {0}", Bob.Kpub);

            Console.WriteLine("\n:: Segredo compartilhado: ");
            Alice.SharedSecret = BigInteger.ModPow(Bob.Kpub, Alice.Kpv, P);
            Bob.SharedSecret = BigInteger.ModPow(Alice.Kpub, Bob.Kpv, P);
            Console.WriteLine("Alice: {0}", Alice.SharedSecret);
            Console.WriteLine("Bob: {0}", Bob.SharedSecret);


            //Ataques
            Console.WriteLine("\n\n----- INICIO DO ATAQUE -----");

            Stopwatch cronometro = new Stopwatch();
            TEMPOS_REGISTRADOS Tempos = new TEMPOS_REGISTRADOS();
            long Tamanho_DB_bytes = 0;

            //Encontra ordem do elemento g no grupo P
            BigInteger ordem;
            cronometro.Restart();
            if (calcula_ordem)
                ordem = CalculaOrdemElemento(P, g, Threads); //CalculaOrdemElemento(P, g);
            else
                ordem = OrdemElemento2(P);
            cronometro.Stop();
            Console.WriteLine("Ord({0}): {1}", g, ordem);
            Console.WriteLine("Tempo gasto: {0:F5}\n", TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds);

            //BruteForce
            KEYFOUND Chaves_Encontradas_BruteForce = new KEYFOUND();
            if (realiza_brute_force)
            {
                BruteForce bruteforce = new BruteForce(g, P, ordem);

                Console.WriteLine("\n:: Brute Force");
                Console.Write("BruteForce Chave Privada Alice: ");
                cronometro.Restart();

                Chaves_Encontradas_BruteForce.Alice_Kpv = bruteforce.DHBruteForce_Multithreading(Alice.Kpub, Threads);

                //Chaves_Encontradas_BruteForce.Alice_Kpv = DHBruteForce(g, P, ordem, Alice.Kpub);
                cronometro.Stop();
                Tempos.BruteForceAlice = TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                Console.WriteLine(Chaves_Encontradas_BruteForce.Alice_Kpv);
                Console.WriteLine("Tempo gasto: {0:F5}\n", Tempos.BruteForceAlice);

                Console.Write("BruteForce Chave Privada Bob: ");
                cronometro.Restart();
                Chaves_Encontradas_BruteForce.Bob_Kpv = bruteforce.DHBruteForce_Multithreading(Bob.Kpub, Threads);

                //Chaves_Encontradas_BruteForce.Bob_Kpv = DHBruteForce(g, P, ordem, Bob.Kpub);
                cronometro.Stop();
                Tempos.BruteForceBob = TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                Console.WriteLine(Chaves_Encontradas_BruteForce.Bob_Kpv);
                Console.WriteLine("Tempo gasto: {0:F5}\n", Tempos.BruteForceBob);

                Chaves_Encontradas_BruteForce.Alice_SharedSecret = BigInteger.ModPow(Bob.Kpub, Chaves_Encontradas_BruteForce.Alice_Kpv, P);
                Chaves_Encontradas_BruteForce.Bob_SharedSecret = BigInteger.ModPow(Alice.Kpub, Chaves_Encontradas_BruteForce.Bob_Kpv, P);
                Console.WriteLine("Segredo compartilhado encontrado: {0}, {1}", Chaves_Encontradas_BruteForce.Alice_SharedSecret, Chaves_Encontradas_BruteForce.Bob_SharedSecret);
            }

            //BabyStep - GiantStep
            KEYFOUND Chaves_Encontradas_BabyStepGiantStep = new KEYFOUND();
            BigInteger m = 0;
            FileStream fs;
            if (realiza_babystep_giantstep_singlethreading || realiza_babystep_giantstep_multithreading)
            {
                Console.WriteLine("\n:: BabyStep - GiantStep");
                //Encontra raiz quadrada (aproximada) da ordem do corpo finito
                Console.Write("Calcula raiz de Ord(g): ");
                cronometro.Restart();
                m = NewtonPlusSqrt(ordem);
                if ((m ^ 2) < ordem)
                    m++;
                cronometro.Stop();
                Tempos.RaizQuadrada = TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                Console.WriteLine(m);
                Console.WriteLine("Tempo gasto: {0:F5}\n", Tempos.RaizQuadrada);

                //Calcula taxa de transferência de dados com banco de dados (Throughput)
                //Faz um acesso ao banco de dados:
                //  observou-se que ao ficar muito tempo sem acessar o banco de dados, fazia
                //  o primeiro experimento ter taxa de transferência menor do que os demais.
                //  por conta disso foi feito uma primeira transferência de dados ao banco de
                //  dados antes dos cálculos de Troughput e posteriores cálculos de tempo de
                //  execução dos algoritmos.
                FileStream fs_ativa_DB = new FileStream(DataPath + "ativa_DB.bin", FileMode.Create, FileAccess.ReadWrite);
                BinaryWriter bw_ativa_DB = new BinaryWriter(fs_ativa_DB);
                int megabytes_para_ativar = 100; //100 mB para testar velocidade
                byte[] null_bytes_ativa_DB = new byte[megabytes_para_ativar * 1024 * 1024];
                bw_ativa_DB.Write(null_bytes_ativa_DB);
                bw_ativa_DB.Close();
                fs_ativa_DB.Close();

                Console.Write("DataBase Throughput escrita: ");
                fs = new FileStream(DataPath + "speed_test.bin", FileMode.Create, FileAccess.ReadWrite);
                BinaryWriter speed_test_writer = new BinaryWriter(fs);
                int megabytes_para_teste = 100; //100 mB para testar velocidade
                byte[] null_bytes = new byte[megabytes_para_teste * 1000 * 1000];
                cronometro.Restart();
                speed_test_writer.Write(null_bytes);
                cronometro.Stop();
                Tempos.DatabaseThroughputWrite = megabytes_para_teste / TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                Console.WriteLine("{0:F2} mB/s", Tempos.DatabaseThroughputWrite);

                fs.Seek(0, SeekOrigin.Begin);
                Console.Write("DataBase Throughput leitura: ");
                BinaryReader speed_test_reader = new BinaryReader(fs);
                cronometro.Restart();
                null_bytes = speed_test_reader.ReadBytes(megabytes_para_teste * 1000 * 1000);
                cronometro.Stop();
                Tempos.DatabaseThroughputRead = megabytes_para_teste / TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                Console.WriteLine("{0:F2} mB/s\n", Tempos.DatabaseThroughputRead);

                speed_test_writer.Close();
                speed_test_reader.Close();
                fs.Close();

                File.Delete(DataPath + "speed_test.bin");

                BabyStep_GiantStep babystep_giantstep = new BabyStep_GiantStep(g, P, ordem, m, DataPath);

                //Etapa BabyStep
                Console.Write("BabyStep de {0}: ", m);
                cronometro.Restart();
                //BabyStep(DataPath, P, g, m);
                babystep_giantstep.BabyStep();
                cronometro.Stop();
                Tempos.BabyStep = TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                Console.WriteLine("OK");

                fs = new FileStream(DataPath + "BabyStep.bin", FileMode.Open);
                long Tamanho_BabyStep_DB = fs.Length;
                fs.Close();

                fs = new FileStream(DataPath + "BabyStep_index.bin", FileMode.Open);
                long Tamanho_Index_DB = fs.Length;
                fs.Close();

                Tamanho_DB_bytes = (Tamanho_BabyStep_DB + Tamanho_Index_DB);
                Console.WriteLine("Tamanho DB: {0} bytes", Tamanho_DB_bytes);

                Console.WriteLine("Tempo gasto: {0:F5}\n", Tempos.BabyStep);
                /*
                fs = new FileStream(DataPath + "BabyStep.bin", FileMode.Open);
                long Tam_BabyStep_DB = fs.Length;
                fs.Close();

                fs = new FileStream(DataPath + "BabyStep_index.bin", FileMode.Open);
                long Tam_Index_DB = fs.Length;
                fs.Close();

                long Tam_DB_bytes = (Tam_BabyStep_DB + Tam_Index_DB);

                Console.WriteLine("Tamanho DB: {0}", Tam_DB_bytes);
                return;
                */
                if (realiza_babystep_giantstep_singlethreading)
                {
                    Console.WriteLine("\n:: GiantStep 1 Thread");

                    Console.Write("GiantStep Chave Privada Alice: ");
                    cronometro.Restart();
                    Chaves_Encontradas_BabyStepGiantStep.Alice_Kpv = GiantStep(DataPath, Alice.Kpub, P, g, ordem, m);
                    cronometro.Stop();
                    Tempos.GiantStepAlice = TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                    Console.WriteLine(Chaves_Encontradas_BabyStepGiantStep.Alice_Kpv);
                    Console.WriteLine("Tempo gasto: {0:F5}\n", Tempos.GiantStepAlice);

                    Console.Write("GiantStep Chave Privada Bob: ");
                    cronometro.Restart();
                    Chaves_Encontradas_BabyStepGiantStep.Bob_Kpv = GiantStep(DataPath, Bob.Kpub, P, g, ordem, m);
                    cronometro.Stop();
                    Tempos.GiantStepBob = TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                    Console.WriteLine(Chaves_Encontradas_BabyStepGiantStep.Bob_Kpv);
                    Console.WriteLine("Tempo gasto: {0:F5}\n", Tempos.GiantStepBob);

                    Chaves_Encontradas_BabyStepGiantStep.Alice_SharedSecret = BigInteger.ModPow(Bob.Kpub, Chaves_Encontradas_BabyStepGiantStep.Alice_Kpv, P);
                    Chaves_Encontradas_BabyStepGiantStep.Bob_SharedSecret = BigInteger.ModPow(Alice.Kpub, Chaves_Encontradas_BabyStepGiantStep.Bob_Kpv, P);
                    Console.WriteLine("Segredo compartilhado encontrado: {0}, {1}", Chaves_Encontradas_BabyStepGiantStep.Alice_SharedSecret, Chaves_Encontradas_BabyStepGiantStep.Bob_SharedSecret);
                }

                if (realiza_babystep_giantstep_multithreading)
                {
                    Console.WriteLine("\n:: GiantStep Multithreading");
                    Console.Write("GiantStep Chave Privada Alice: ");
                    cronometro.Restart();
                    Chaves_Encontradas_BabyStepGiantStep.Alice_Kpv = babystep_giantstep.GiantStep(Alice.Kpub, Threads);
                    cronometro.Stop();
                    Tempos.GiantStepAlice = TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                    Console.WriteLine(Chaves_Encontradas_BabyStepGiantStep.Alice_Kpv);
                    Console.WriteLine("Tempo gasto: {0:F5}\n", Tempos.GiantStepAlice);
                    Chaves_Encontradas_BabyStepGiantStep.Alice_SharedSecret = BigInteger.ModPow(Bob.Kpub, Chaves_Encontradas_BabyStepGiantStep.Alice_Kpv, P);
                    Console.WriteLine("Segredo compartilhado encontrado: {0}", Chaves_Encontradas_BabyStepGiantStep.Alice_SharedSecret);

                    if (!relatorio_bit_a_bit)
                    {
                        Console.Write("GiantStep Chave Privada Bob: ");
                        cronometro.Restart();
                        Chaves_Encontradas_BabyStepGiantStep.Bob_Kpv = babystep_giantstep.GiantStep(Bob.Kpub, Threads);
                        cronometro.Stop();
                        Tempos.GiantStepBob = TimeSpan.FromTicks(cronometro.ElapsedTicks).TotalSeconds;
                        Console.WriteLine(Chaves_Encontradas_BabyStepGiantStep.Bob_Kpv);
                        Console.WriteLine("Tempo gasto: {0:F5}\n", Tempos.GiantStepBob);
                        Chaves_Encontradas_BabyStepGiantStep.Bob_SharedSecret = BigInteger.ModPow(Alice.Kpub, Chaves_Encontradas_BabyStepGiantStep.Bob_Kpv, P);
                        Console.WriteLine("Segredo compartilhado encontrado: {0}", Chaves_Encontradas_BabyStepGiantStep.Bob_SharedSecret);
                    }
                }
            }


            //Registra dados obtidos
            if (registra_relatorio)
            {
                StreamWriter sw = new StreamWriter("C:\\Users\\rapha\\Desktop\\Profissional\\EsAO\\Presencial\\TCC\\Experimentos\\Dados_Ataque_DiffieHellman.csv", true);
                sw.WriteLine((int)Tamanho_do_Primo + ";" + P + ";" + ((P - 1) / 2) + ";" + g + ";" + ordem + ";" + Tamanho_Chave_Privada_em_Bytes * 8 + ";" + Alice.Kpv + ";" + Alice.Kpub + ";" + Bob.Kpv + ";" + Bob.Kpub + ";" + Bob.SharedSecret + ";" + Chaves_Encontradas_BruteForce.Alice_Kpv + ";" + Chaves_Encontradas_BruteForce.Alice_SharedSecret + ";" + Tempos.BruteForceAlice.ToString("F5") + ";" + Chaves_Encontradas_BruteForce.Bob_Kpv + ";" + Chaves_Encontradas_BruteForce.Bob_SharedSecret + ";" + Tempos.BruteForceBob.ToString("F5") + ";" + Tempos.DatabaseThroughputWrite.ToString("F2") + ";" + Tempos.DatabaseThroughputRead.ToString("F2") + ";" + m + ";" + Tempos.RaizQuadrada.ToString("F5") + ";" + Tempos.BabyStep.ToString("F5") + ";" + Tamanho_DB_bytes.ToString() + ";" + Chaves_Encontradas_BabyStepGiantStep.Alice_Kpv + ";" + Chaves_Encontradas_BabyStepGiantStep.Alice_SharedSecret + ";" + Tempos.GiantStepAlice.ToString("F5") + ";" + Chaves_Encontradas_BabyStepGiantStep.Bob_Kpv + ";" + Chaves_Encontradas_BabyStepGiantStep.Bob_SharedSecret + ";" + Tempos.GiantStepBob.ToString("F5"));
                sw.Close();

                Console.WriteLine("\n:: Registro salvo.");
            }

            if (relatorio_bit_a_bit)
            {
                StreamWriter sw = new StreamWriter("C:\\Users\\rapha\\Desktop\\Profissional\\EsAO\\Presencial\\TCC\\Experimentos\\Dados_Ataque_DiffieHellman_Bit_a_Bit.csv", true);
                sw.WriteLine((int)Tamanho_do_Primo + ";" + P + ";" + ordem + ";" + m + ";" + Alice.Kpv + ";" + Tamanho_DB_bytes + ";" + Tempos.DatabaseThroughputWrite.ToString("F2") + ";" + Tempos.BabyStep + ";" + Tempos.DatabaseThroughputRead.ToString("F2") + ";" + Tempos.GiantStepAlice);
                sw.Close();

                Console.WriteLine("\n:: Registro salvo.");
            }
        }

        enum EXPERIMENTO
        {
            Experimento1 = 1,
            Experimento2 = 2,
            Experimento3 = 3,
            Experimento4 = 4,
            Experimento5 = 5,
            Experimento6 = 6,
            Experimento7 = 7,
            Experimento8 = 8,
            Experimento9 = 9,
            Experimento10 = 10,
        };

        enum TAMANHO_EM_BITS
        {
            Bit4 = 4,
            Bit8 = 8,
            Bit9 = 9,
            Bit10 = 10,
            Bit11 = 11,
            Bit12 = 12,
            Bit13 = 13,
            Bit14 = 14,
            Bit15 = 15,
            Bit16 = 16,
            Bit17 = 17,
            Bit18 = 18,
            Bit19 = 19,
            Bit20 = 20,
            Bit21 = 21,
            Bit22 = 22,
            Bit23 = 23,
            Bit24 = 24,
            Bit25 = 25,
            Bit26 = 26,
            Bit27 = 27,
            Bit28 = 28,
            Bit29 = 29,
            Bit30 = 30,
            Bit31 = 31,
            Bit32 = 32,
            Bit64 = 64,
            Bit128 = 128,
            Bit256 = 256,
            Bit512 = 512
        };

        static BigInteger PrimoGeradoOpenSSL(TAMANHO_EM_BITS tamanho_em_bits, EXPERIMENTO Experimento)
        {
            //Foram utilizados comandos do OpenSSL para gerar os números primos seguros para teste
            //Comando para gerar número primo utilizado: openssl dhparam -C -2 [tamanho em bits]

            byte[] byte_primo = new byte[0]; //foi atribuído valor aqui para não ocorrer retorno de variável não atribuída
            
            switch (tamanho_em_bits)
            {
                case TAMANHO_EM_BITS.Bit4:
                    byte_primo = new byte[]{ 0x0B };
                    break;

                case TAMANHO_EM_BITS.Bit8:
                    if (Experimento == EXPERIMENTO.Experimento1)
                        byte_primo = new byte[] { 0xB3 };
                    else if (Experimento == EXPERIMENTO.Experimento2)
                        byte_primo = new byte[] { 0xE3 };
                    break;

                case TAMANHO_EM_BITS.Bit9:
                    byte_primo = new byte[] { 0x01, 0xD3 };
                    break;

                case TAMANHO_EM_BITS.Bit10:
                    byte_primo = new byte[] { 0x03, 0xFB };
                    break;

                case TAMANHO_EM_BITS.Bit11:
                    byte_primo = new byte[] { 0x07, 0x73 };
                    break;

                case TAMANHO_EM_BITS.Bit12:
                    byte_primo = new byte[] { 0x0E, 0xC3 };
                    break;

                case TAMANHO_EM_BITS.Bit13:
                    byte_primo = new byte[] { 0x1F, 0xD3 };
                    break;

                case TAMANHO_EM_BITS.Bit14:
                    byte_primo = new byte[] { 0x3D, 0x43 };
                    break;

                case TAMANHO_EM_BITS.Bit15:
                    byte_primo = new byte[] { 0x7F, 0x5B };
                    break;

                case TAMANHO_EM_BITS.Bit16:
                    if (Experimento == EXPERIMENTO.Experimento1)
                        byte_primo = new byte[] { 0xCC, 0x9B };
                    else if (Experimento == EXPERIMENTO.Experimento2)
                        byte_primo = new byte[] { 0xEF, 0xC3 };
                    else if (Experimento == EXPERIMENTO.Experimento3)
                        byte_primo = new byte[] { 0xA5, 0xCB }; 
                    else if (Experimento == EXPERIMENTO.Experimento4)
                        byte_primo = new byte[] { 0xBD, 0xB3 }; 
                    else if (Experimento == EXPERIMENTO.Experimento5)
                        byte_primo = new byte[] { 0xE6, 0x1B }; 
                    else if (Experimento == EXPERIMENTO.Experimento6)
                        byte_primo = new byte[] { 0xE0, 0xF3 };
                    else if (Experimento == EXPERIMENTO.Experimento7)
                        byte_primo = new byte[] { 0xBB, 0x5B };
                    else if (Experimento == EXPERIMENTO.Experimento8)
                        byte_primo = new byte[] { 0xCC, 0x9B };
                    else if (Experimento == EXPERIMENTO.Experimento9)
                        byte_primo = new byte[] { 0xC3, 0xE3 };
                    else if (Experimento == EXPERIMENTO.Experimento10)
                        byte_primo = new byte[] { 0x92, 0xAB };
                    break;

                case TAMANHO_EM_BITS.Bit17:
                    byte_primo = new byte[] { 0x01, 0xC3, 0x5B };
                    break;

                case TAMANHO_EM_BITS.Bit18:
                    byte_primo = new byte[] { 0x04, 0x01, 0xF3 };
                    break;

                case TAMANHO_EM_BITS.Bit19:
                    byte_primo = new byte[] { 0x07, 0x97, 0x63 };
                    break;

                case TAMANHO_EM_BITS.Bit20:
                    byte_primo = new byte[] { 0x0F, 0xB1, 0xE3 };
                    break;

                case TAMANHO_EM_BITS.Bit21:
                    byte_primo = new byte[] { 0x1F, 0xA0, 0x7B };
                    break;

                case TAMANHO_EM_BITS.Bit22:
                    byte_primo = new byte[] { 0x3F, 0xF9, 0x23 };
                    break;

                case TAMANHO_EM_BITS.Bit23:
                    byte_primo = new byte[] { 0x7F, 0xDC, 0x4B };
                    break;

                case TAMANHO_EM_BITS.Bit24:
                    if (Experimento == EXPERIMENTO.Experimento1)
                        byte_primo = new byte[] { 0xA8, 0xE1, 0x9B };
                    if (Experimento == EXPERIMENTO.Experimento2)
                        byte_primo = new byte[] { 0x8B, 0x7E, 0x13 };
                    if (Experimento == EXPERIMENTO.Experimento3)
                        byte_primo = new byte[] { 0xCD, 0x2F, 0x9B };
                    if (Experimento == EXPERIMENTO.Experimento4)
                        byte_primo = new byte[] { 0x9E, 0x18, 0xAB };
                    if (Experimento == EXPERIMENTO.Experimento5)
                        byte_primo = new byte[] { 0xFB, 0xCC, 0x93 };
                    if (Experimento == EXPERIMENTO.Experimento6)
                        byte_primo = new byte[] { 0xA4, 0xA7, 0xD3 };
                    if (Experimento == EXPERIMENTO.Experimento7)
                        byte_primo = new byte[] { 0xDC, 0x1D, 0xCB };
                    if (Experimento == EXPERIMENTO.Experimento8)
                        byte_primo = new byte[] { 0xB8, 0x8F, 0x6B };
                    if (Experimento == EXPERIMENTO.Experimento9)
                        byte_primo = new byte[] { 0xF3, 0x74, 0xC3 };
                    if (Experimento == EXPERIMENTO.Experimento10)
                        byte_primo = new byte[] { 0x95, 0xFE, 0xD3 };
                    break;

                case TAMANHO_EM_BITS.Bit25:
                    byte_primo = new byte[] { 0x01, 0xFC, 0x91, 0xAB };
                    break;

                case TAMANHO_EM_BITS.Bit26:
                    byte_primo = new byte[] { 0x03, 0xC4, 0x6B, 0xFB };
                    break;

                case TAMANHO_EM_BITS.Bit27:
                    byte_primo = new byte[] { 0x07, 0xE3, 0x15, 0x53 };
                    break;

                case TAMANHO_EM_BITS.Bit28:
                    byte_primo = new byte[] { 0x0F, 0xA5, 0x55, 0x8B };
                    break;

                case TAMANHO_EM_BITS.Bit29:
                    byte_primo = new byte[] { 0x1F, 0xC7, 0x57, 0x33 };
                    break;

                case TAMANHO_EM_BITS.Bit30:
                    byte_primo = new byte[] { 0x3F, 0x29, 0xC6, 0xAB };
                    break;

                case TAMANHO_EM_BITS.Bit31:
                    byte_primo = new byte[] { 0x7E, 0x33, 0x45, 0x83 };
                    break;

                case TAMANHO_EM_BITS.Bit32:
                    if (Experimento == EXPERIMENTO.Experimento1)
                        byte_primo = new byte[] { 0xE1, 0x72, 0xE0, 0x63 };
                    else if (Experimento == EXPERIMENTO.Experimento2)
                        byte_primo = new byte[] { 0x98, 0x9F, 0x2D, 0x1B };
                    else if (Experimento == EXPERIMENTO.Experimento3)
                        byte_primo = new byte[] { 0xA0, 0x63, 0xDD, 0xCB };
                    else if (Experimento == EXPERIMENTO.Experimento4)
                        byte_primo = new byte[] { 0x8F, 0x00, 0xE3, 0xA3 };
                    else if (Experimento == EXPERIMENTO.Experimento5)
                        byte_primo = new byte[] { 0xE6, 0xFD, 0xDC, 0x13 };
                    else if (Experimento == EXPERIMENTO.Experimento6)
                        byte_primo = new byte[] { 0x91, 0x6D, 0xF0, 0xDB };
                    else if (Experimento == EXPERIMENTO.Experimento7)
                        byte_primo = new byte[] { 0x82, 0x9A, 0x28, 0x23 };
                    else if (Experimento == EXPERIMENTO.Experimento8)
                        byte_primo = new byte[] { 0xB6, 0x50, 0x2D, 0x5B };
                    else if (Experimento == EXPERIMENTO.Experimento9)
                        byte_primo = new byte[] { 0xCB, 0xDD, 0xA9, 0x63 };
                    else if (Experimento == EXPERIMENTO.Experimento10)
                        byte_primo = new byte[] { 0x96, 0x61, 0x8F, 0xB3 };
                    break;

                case TAMANHO_EM_BITS.Bit64:
                    if (Experimento == EXPERIMENTO.Experimento1)
                        byte_primo = new byte[] { 0xA5, 0x33, 0x41, 0xB9, 0xDF, 0x34, 0x5D, 0x53 };
                    else if (Experimento == EXPERIMENTO.Experimento2)
                        byte_primo = new byte[] { 0xFE, 0x1B, 0x75, 0xA3, 0xA8, 0xAD, 0x49, 0x53 };
                    break;

                case TAMANHO_EM_BITS.Bit128:
                    if (Experimento == EXPERIMENTO.Experimento1)
                        byte_primo = new byte[] { 0xBE, 0x03, 0x0C, 0x68, 0x1A, 0xAA, 0x7C, 0x29, 0x0C, 0xF7, 0x43, 0x70, 0x59, 0xA6, 0xF5, 0x9B };
                    else if (Experimento == EXPERIMENTO.Experimento2)
                        byte_primo = new byte[] { 0xEA, 0x08, 0x82, 0x24, 0x31, 0x1C, 0xE6, 0xAA, 0xCC, 0x04, 0x3C, 0xDD, 0xF9, 0x58, 0x33, 0x73 };
                    break;

                case TAMANHO_EM_BITS.Bit256:
                    if (Experimento == EXPERIMENTO.Experimento1)
                        byte_primo = new byte[] {
                            0xB1, 0x1D, 0xEA, 0x77, 0xFA, 0x3F, 0x08, 0x6E, 0x42, 0xA7,
                            0x1D, 0xDD, 0xF4, 0xB5, 0x2E, 0x7F, 0x9D, 0x85, 0x48, 0x50,
                            0x3F, 0xB5, 0xF6, 0xC6, 0xBF, 0x60, 0x1E, 0x94, 0x07, 0x98,
                            0x42, 0xE3
                        };
                    else if (Experimento == EXPERIMENTO.Experimento2)
                        byte_primo = new byte[] {
                            0xC9, 0xAF, 0xA0, 0x09, 0x5A, 0x71, 0x33, 0xFA, 0x37, 0x82,
                            0x16, 0xD1, 0x55, 0x9B, 0x14, 0x5D, 0x4E, 0x4C, 0xA8, 0x4D,
                            0x97, 0xAF, 0xD2, 0xEA, 0x4F, 0x28, 0x6C, 0x45, 0x63, 0x2E,
                            0x3C, 0x4B
                        };
                    break;

                case TAMANHO_EM_BITS.Bit512:
                    if (Experimento == EXPERIMENTO.Experimento1)
                        byte_primo = new byte[] {
                            0x8A, 0xA6, 0xDC, 0xBB, 0x74, 0x20, 0x20, 0xFC, 0xC5, 0xDF,
                            0xFC, 0x5D, 0xC7, 0xD1, 0xE5, 0xE5, 0xE6, 0x5D, 0x17, 0xAB,
                            0xD0, 0xA4, 0xC3, 0xEC, 0x43, 0xC8, 0x57, 0x46, 0x44, 0xB2,
                            0x42, 0xD2, 0xA0, 0x6D, 0xA1, 0x5B, 0xF3, 0x4D, 0xE5, 0xF3,
                            0xE5, 0x82, 0x9C, 0x38, 0xC1, 0x02, 0xCC, 0x4B, 0x18, 0xE2,
                            0x70, 0xF1, 0x10, 0xFA, 0x55, 0xFF, 0xD2, 0x9A, 0xD3, 0x0B,
                            0x49, 0xE2, 0xBA, 0x3B
                        };
                    else if (Experimento == EXPERIMENTO.Experimento2)
                        byte_primo = new byte[] {
                            0xAA, 0xBB, 0x7E, 0xE0, 0xC1, 0x00, 0xEB, 0x07, 0x3A, 0xBA,
                            0x46, 0xB3, 0x0A, 0xF1, 0x49, 0x43, 0x3A, 0xEC, 0x8D, 0x9E,
                            0x8F, 0x7E, 0x53, 0x4B, 0x56, 0x63, 0x24, 0x29, 0x30, 0x7C,
                            0xA4, 0x38, 0xE9, 0x5A, 0x84, 0xBA, 0xB9, 0x83, 0x08, 0xEE,
                            0x30, 0x8C, 0xE4, 0x1D, 0x51, 0x19, 0x85, 0xC5, 0xD8, 0xDA,
                            0x8D, 0xDF, 0xD8, 0x9C, 0x6B, 0x25, 0x46, 0x83, 0x4C, 0xD8,
                            0xCE, 0x82, 0x65, 0x23
                        };
                    break;

                default:
                    return -1;
            }

            return new BigInteger(byte_primo, true, true);
        }

        static BigInteger DHBruteForce(BigInteger g, BigInteger P, BigInteger Ord, BigInteger Kpub)
        {
            for (BigInteger i = 1; i <= Ord; i++)
            {
                BigInteger KpubEncontrado = BigInteger.ModPow(g, i, P);

                if (KpubEncontrado == Kpub)
                    return i;
            }

            return -1; //Não encontrou resultado satisfatório
        }

        //Reformular Calculo da Ord com base nos primos seguros e não seguros, observando se (P - 1) / 2 é primo
        //Se for primo, Ord(2) será P - 1
        //Se não for primo, Ord(2) será (P - 1) / 2
        static private BigInteger Thread_P;
        static private BigInteger Thread_Elm;
        static private BigInteger Thread_Ord;

        static void Thread_CalculaOrdem(Object Param)
        {
            BigInteger P = Thread_P;
            BigInteger Elm = Thread_Elm;

            BigInteger[] Limites = (BigInteger[])Param;

            //Console.Write("\nLimites: {0}, {1}", Limites[0], Limites[1]);
            //Console.WriteLine(BigInteger.ModPow(2, 5533901, P));

            for (BigInteger i = Limites[0]; i < Limites[1]; i++)
            {
                //Alguma outra Thread já encontrou
                if (Thread_Ord != -1)
                    return;

                if (BigInteger.ModPow(Elm, i, P) == 1)
                {
                    Thread_Ord = i;
                    return;
                }
            }
        }
        static BigInteger CalculaOrdemElemento(BigInteger P, BigInteger Elm, int Threads)
        {
            Thread_Ord = -1;
            Thread_P = P;
            Thread_Elm = Elm;

            Thread[] threads = new Thread[Threads];
            
            BigInteger thread_step = P / Threads;
            BigInteger inicio = 1;
            for(int i = 0; i < Threads; i ++)
            {
                BigInteger[] Limites = new BigInteger[2] { inicio, inicio + thread_step };
                if (i == Threads - 1)
                    Limites[1] = P;
                threads[i] = new Thread(Thread_CalculaOrdem);
                threads[i].Start(Limites);
                inicio += thread_step;
            }

            foreach (Thread T in threads)
                T.Join();

            return Thread_Ord;
        }

        static BigInteger OrdemElemento2(BigInteger P)
        {
            BigInteger OrdDivisor = (P - 1) / 2;
            if (OrdDivisor % 2 == 0)
                return OrdDivisor;
            else
                return P - 1;
        }

        //BabyStep-GiantStep
        public static BigInteger NewtonPlusSqrt(BigInteger x)
        {
            if (x < 144838757784765629)          // 1.448e17 = ~1<<57
            {
                uint vInt = (uint)Math.Sqrt((ulong)x);
                if ((x <= 4503599761588224) && ((ulong)vInt * vInt > (ulong)x)) //4.5e15 = ~1<<52
                {
                    vInt--;
                }
                return vInt;
            }

            double xAsDub = (double)x;
            if (xAsDub < 8.5e37)   //   8.5e37 is V<sup>2</sup>long.max * long.max
            {
                ulong vInt = (ulong)Math.Sqrt(xAsDub);
                BigInteger v = (vInt + ((ulong)(x / vInt))) >> 1;
                return (v * v >= x) ? v : v - 1;
            }

            if (xAsDub < 4.3322e127)
            {
                BigInteger v = (BigInteger)Math.Sqrt(xAsDub);
                v = (v + (x / v)) >> 1;
                if (xAsDub > 2e63)
                {
                    v = (v + (x / v)) >> 1;
                }
                return (v * v >= x) ? v : v - 1;
            }

            int xLen = (int)x.GetByteCount() * 8;
            int wantedPrecision = (xLen + 1) / 2;
            int xLenMod = xLen + (xLen & 1) + 1;

            //////// Do the first Sqrt on hardware ////////
            long tempX = (long)(x >> (xLenMod - 63));
            double tempSqrt1 = Math.Sqrt(tempX);
            ulong valLong = (ulong)BitConverter.DoubleToInt64Bits(tempSqrt1) & 0x1fffffffffffffL;
            if (valLong == 0)
            {
                valLong = 1UL << 53;
            }

            ////////  Classic Newton Iterations ////////
            BigInteger val = ((BigInteger)valLong << (53 - 1)) + (x >> xLenMod - (3 * 53)) / valLong;
            int size = 106;
            for (; size < 256; size <<= 1)
            {
                val = (val << (size - 1)) + (x >> xLenMod - (3 * size)) / val;
            }

            if (xAsDub > 4e254)
            {                      // 1 << 845
                int numOfNewtonSteps = BitOperations.Log2((uint)(wantedPrecision / size)) + 2;

                //////  Apply Starting Size  ////////
                int wantedSize = (wantedPrecision >> numOfNewtonSteps) + 2;
                int needToShiftBy = size - wantedSize;
                val >>= needToShiftBy;
                size = wantedSize;
                do
                {
                    ////////  Newton Plus Iterations  ////////
                    int shiftX = xLenMod - (3 * size);
                    BigInteger valSqrd = (val * val) << (size - 1);
                    BigInteger valSU = (x >> shiftX) - valSqrd;
                    val = (val << size) + (valSU / val);
                    size *= 2;
                } while (size < wantedPrecision);
            }

            /////// There are a few extra digits here, lets save them ///////
            int oversidedBy = size - wantedPrecision;
            BigInteger saveDroppedDigitsBI = val & ((BigInteger.One << oversidedBy) - 1);
            int downby = (oversidedBy < 64) ? (oversidedBy >> 2) + 1 : (oversidedBy - 32);
            ulong saveDroppedDigits = (ulong)(saveDroppedDigitsBI >> downby);

            ////////  Shrink result to wanted Precision  ////////
            val >>= oversidedBy;

            ////////  Detect a round-ups  ////////
            if ((saveDroppedDigits == 0) && (val * val > x))
            {
                val--;
            }

            // //////// Error Detection ////////
            // // I believe the above has no errors but to guarantee the following can be added.
            // // If an error is found, please report it.
            // BigInteger tmp = val * val;
            // if (tmp > x)
            // {
            //     throw new Exception("Sqrt function had internal error - value too high");
            // }
            // if ((tmp + 2 * val + 1) >= x)
            // {
            //     throw new Exception("Sqrt function had internal error - value too low");
            // }

            return val;
        }

        static void BabyStep(string DataPath, BigInteger P, BigInteger g, BigInteger m)
        {
            //Console.WriteLine(limite);
            //Console.WriteLine(Math.Sqrt((double)Ordem));

            if (File.Exists(DataPath + "BabyStep.bin"))
                File.Delete(DataPath + "BabyStep.bin");

            if (File.Exists(DataPath + "BabyStep_index.bin"))
                File.Delete(DataPath + "BabyStep_index.bin");

            BinaryDatabase DB = new BinaryDatabase(DataPath + "BabyStep.bin");
            BinaryDatabase Index_DB = new BinaryDatabase(DataPath + "BabyStep_index.bin");

            //BINARY_DATABASE Index_DB = new BINARY_DATABASE(DB.FilePath.Split('.')[0] + "_index.bin");

            DB.OpenFile();
            Index_DB.OpenFile();

            for (BigInteger x = 1; x <= m; x++)
            {
                BigInteger GroupElm = BigInteger.ModPow(g, x, P);
                DB.WriteNextKey(GroupElm);
                Index_DB.WriteNextKey(x);
            }

            DB.CloseFile();
            Index_DB.CloseFile();
        }

        static BigInteger GiantStep(string DataPath, BigInteger Kpub, BigInteger P, BigInteger g, BigInteger Ord, BigInteger m)
        {
            BinaryDatabase DB = new BinaryDatabase(DataPath + "BabyStep.bin");
            BinaryDatabase Index_DB = new BinaryDatabase(DataPath + "BabyStep_index.bin");
            DB.OpenFile();
            Index_DB.OpenFile();

            //Utilizei [X = Xb * m - Xg], pois dessa forma não preciso calcular o inverso multiplicativo de m, diminuindo
            //a necessidade de processamento. Ficando assim:
            //g^(Xb*m - Xg) = B Mod P
            //g^Xb*m == B * g^Xg

            
            //Carregar até 15.150.000 elementos (aproximadamente 2 GB de MB considerando elementos de 1024 bits precedidos por 4 bytes
            //contendo o seu tamanho)

            long next_step = 15150000;

            for (BigInteger count_baby = 0; count_baby < m; count_baby += next_step)
            {
                BigInteger[] BabyElements = DB.ReadKeys(next_step);
                BigInteger[] BabyIndex = Index_DB.ReadKeys(next_step);

                BigInteger baby_offset = DB.offset;
                BigInteger baby_index_offset = Index_DB.offset;

                //Retorna leitura para o começo do banco de dados para varredura
                DB.offset = 0;
                Index_DB.offset = 0;

                for (BigInteger count_giant = 0; count_giant < m; count_giant += next_step)
                {
                    BigInteger[] GiantElements = DB.ReadKeys(next_step);
                    BigInteger[] GiantIndex = Index_DB.ReadKeys(next_step);

                    int Xb = 0;
                    int Xg = 0;
                    foreach(BigInteger BabyElm in BabyElements)
                    {
                        if (BabyElm == 0)
                            break;

                        BigInteger BabyElmPowM = BigInteger.ModPow(BabyElm, m, P);

                        Xg = 0;
                        foreach(BigInteger GiantElm in GiantElements)
                        {
                            if (GiantElm == 0)
                                break;

                            if((GiantElm * Kpub % P) == BabyElmPowM)
                            {
                                DB.CloseFile();
                                Index_DB.CloseFile();
                                //Console.WriteLine((BabyIndex[Xb] * m) - GiantIndex[Xg]);
                                return (BabyIndex[Xb] * m) - GiantIndex[Xg];
                            }
                            Xg++;
                        }
                        Xb++;
                    }

                }

                //Retorna a leitura para a sequência do expoente Baby (j)
                DB.offset = baby_offset;
                Index_DB.offset = baby_index_offset;
            }

            DB.CloseFile();
            Index_DB.CloseFile();
            return -1;
        }

        static KEYFOUND ComparaListaChaves(BinaryDatabase Alice_DB, BinaryDatabase Bob_DB, BigInteger Kpub_Alice, BigInteger Kpub_Bob, BigInteger P)
        {
            KEYFOUND ret = new KEYFOUND();

            Alice_DB.OpenFile();
            Bob_DB.OpenFile();

            BigInteger Kpv_Alice;
            BigInteger Kpv_Bob;
            while((Kpv_Alice = Alice_DB.ReadNextKey()) != -1)
            {
                while((Kpv_Bob = Bob_DB.ReadNextKey()) != -1)
                {
                    if (BigInteger.ModPow(Kpub_Bob, Kpv_Alice, P) == BigInteger.ModPow(Kpub_Alice, Kpv_Bob, P))
                    {
                        ret.Alice_Kpv = Kpv_Alice;
                        ret.Bob_Kpv = Kpv_Bob;

                        Alice_DB.CloseFile();
                        Bob_DB.CloseFile();

                        return ret;
                    }
                }
            }

            Alice_DB.CloseFile();
            Bob_DB.CloseFile();

            ret.Alice_Kpv = -1;
            ret.Bob_Kpv = -1;
            return ret;
        }

    }

    
    //Classes
    class Party
    {
        //Chave Privada
        private BigInteger _Kpv;
        public BigInteger Kpv
        {
            get => _Kpv;
            set => _Kpv = value;
        }

        //Chave Pública
        private BigInteger _Kpub;
        public BigInteger Kpub
        {
            get => _Kpub;
            set => _Kpub = value;
        }

        //Segredo Compartilhado
        private BigInteger _SharedSecret;
        public BigInteger SharedSecret
        {
            get => _SharedSecret;
            set => _SharedSecret = value;
        }

        public Party(BigInteger P, BigInteger g, int Private_Key_Length_Bits)
        {
            //Recomendação NIST SP 800-57 Tamanho mínimo da Chave PRIVADA para Finite Field Cryptography (FFC): 160 bits
            //Gerar grande inteiro aleatório baseado em bytes
            while(_Kpv < 2 || _Kpv > P - 1)
            {
                byte[] kpv_bytes = new byte[Private_Key_Length_Bits / 8]; //20 * 8 == 160 bits
                for (int i = 0; i < kpv_bytes.Length; i++)
                    kpv_bytes[i] = (byte)RandomNumberGenerator.GetInt32(1, 255);

                _Kpv = new BigInteger(kpv_bytes, true);
            }

            //Recomendação NIST SP 800-57 Chave PÚBLICA para Finite Field Cryptography (FFC): 1024 bits
            _Kpub = BigInteger.ModPow(g, _Kpv, P);
        }

        public Party(BigInteger P, BigInteger g, BigInteger Kpv)
        {
            _Kpv = Kpv;

            //Recomendação NIST SP 800-57 Chave PÚBLICA para Finite Field Cryptography (FFC): 1024 bits
            _Kpub = BigInteger.ModPow(g, _Kpv, P);
        }
    }

    class TEMPOS_REGISTRADOS
    {
        public double BruteForceAlice;
        public double BruteForceBob;
        public double DatabaseThroughputWrite;
        public double DatabaseThroughputRead;
        public double RaizQuadrada;
        public double BabyStep;
        public double GiantStepAlice;
        public double GiantStepBob;
    }

    class KEYFOUND
    {
        public BigInteger Alice_Kpv;
        public BigInteger Bob_Kpv;
        public BigInteger Alice_SharedSecret;
        public BigInteger Bob_SharedSecret;
    }

}
