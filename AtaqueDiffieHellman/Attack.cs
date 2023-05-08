using System;
using System.Collections.Generic;
using System.Text;

using System.Numerics;
using System.Threading;
using System.IO;

using System.Diagnostics;

namespace AtaqueDiffieHellman
{
    public class Attack
    {
        protected BigInteger P;
        protected BigInteger g;
        protected BigInteger Ord;
        protected BigInteger Kpv = -1;
        protected BigInteger Kpub;
        protected BigInteger m;
        protected string DataPath;


        public Attack(BigInteger g, BigInteger P, BigInteger Ord)
        {
            this.P = P;
            this.g = g;
            this.Ord = Ord;
        }
    }

    public class BruteForce : Attack
    {

        public BruteForce(BigInteger g, BigInteger P, BigInteger Ord) : base(g, P, Ord)
        {

        }

        private void DHBruteForce_Thread(Object Parameters)
        {
            BigInteger[] Limits = (BigInteger[])Parameters;
            for (BigInteger i = Limits[0]; i <= Limits[1]; i++)
            {
                BigInteger KpubEncontrado = BigInteger.ModPow(this.g, i, this.P);

                if (KpubEncontrado == this.Kpub)
                {
                    this.Kpv = i;
                    return;
                }

                //Outra Thread encontrou
                if (this.Kpv != -1)
                    return;
            }
        }

        public BigInteger DHBruteForce_Multithreading(BigInteger Kpub, int Threads)
        {
            this.Kpub = Kpub;

            this.Kpv = -1;

            //if (Threads > 7)
              //  Threads = 7;

            Thread[] threads = new Thread[Threads];

            //Divide Ord no número de Threads:
            BigInteger step = Ord / Threads;

            //Inicia as Threads
            BigInteger inicio = 1;

            for (int i = 0; i < Threads; i++)
            {
                threads[i] = new Thread(DHBruteForce_Thread);
                BigInteger[] Limits = new BigInteger[2] { inicio, inicio + step };
                if (i == Threads - 1)
                    Limits[1] = Ord;
                threads[i].Start(Limits);
                inicio += step + 1;
            }

            //Aguarda Threads para retornar o valor
            foreach (Thread T in threads)
                T.Join();
            

            return this.Kpv;
        }
    }

    //BabyStep-GiantStep
    public class BabyStep_GiantStep : Attack
    {
        public BabyStep_GiantStep(BigInteger g, BigInteger P, BigInteger Ord, BigInteger m, string DataPath): base(g, P, Ord)
        {
            this.m = m;
            this.DataPath = DataPath;
        }

        public BigInteger NewtonPlusSqrt(BigInteger x)
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


        /*
        private void BabyStep_Thread(Object Parameter)
        {
            BigInteger[] Limite = (BigInteger[])Parameter;

            string BabyStep_Element_File = DataPath + "BabyStep" + Limite[2] + ".bin";
            string BabyStep_Index_File = DataPath + "BabyStep_index" + Limite[2] + ".bin";

            if (File.Exists(BabyStep_Element_File))
                File.Delete(BabyStep_Element_File);

            if (File.Exists(BabyStep_Index_File))
                File.Delete(BabyStep_Index_File);

            BinaryDatabase Elm_DB = new BinaryDatabase(BabyStep_Element_File);
            BinaryDatabase Index_DB = new BinaryDatabase(BabyStep_Index_File);

            Elm_DB.OpenFile();
            Index_DB.OpenFile();

            for (BigInteger x = Limite[0]; x <= Limite[1]; x++)
            {
                BigInteger GroupElm = BigInteger.ModPow(g, x, P);
                Elm_DB.WriteNextKey(GroupElm);
                Index_DB.WriteNextKey(x);
            }

            Elm_DB.CloseFile();
            Index_DB.CloseFile();
        }

        public void BabyStep_Multithreading(string DataPath, BigInteger m, int Threads)
        {
            if (Threads > 7)
                Threads = 7;

            this.DataPath = DataPath;
            this.m = m;

            BigInteger step = m / Threads;

            //Inicia as Threads
            BigInteger inicio = 1;

            Thread[] threads = new Thread[Threads];
            for(int i = 0; i < Threads; i++)
            {
                threads[i] = new Thread(BabyStep_Thread);
                BigInteger[] Limites = new BigInteger[3] { inicio, inicio + step, i };
                if (i == Threads - 1)
                    Limites[1] = m;
                threads[i].Start(Limites);
                inicio += step + 1;
            }

            //Aguarda Threads
            bool ThreadsAlive = true;
            while (ThreadsAlive)
            {
                ThreadsAlive = false;
                for (int i = 0; i < Threads; i++)
                {
                    if (threads[i].IsAlive)
                    {
                        ThreadsAlive = true;
                        break;
                    }
                }
            }
        }


        void GiantStep_Thread(Object Parameter)
        {
            BigInteger[] Limite = (BigInteger[])Parameter;

            string BabyStep_Element_File = DataPath + "BabyStep" + Limite[2] + ".bin";
            string BabyStep_Index_File = DataPath + "BabyStep_index" + Limite[2] + ".bin";

            BinaryDatabase Elm_DB = new BinaryDatabase(BabyStep_Element_File);
            BinaryDatabase Index_DB = new BinaryDatabase(BabyStep_Index_File);
            Elm_DB.OpenFile();
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
                BigInteger[] BabyElements = Elm_DB.ReadKeys(next_step);
                BigInteger[] BabyIndex = Index_DB.ReadKeys(next_step);

                BigInteger baby_offset = Elm_DB.offset;
                BigInteger baby_index_offset = Index_DB.offset;

                //Retorna leitura para o começo do banco de dados para varredura
                Elm_DB.offset = 0;
                Index_DB.offset = 0;

                for (BigInteger count_giant = 0; count_giant < m; count_giant += next_step)
                {
                    BigInteger[] GiantElements = Elm_DB.ReadKeys(next_step);
                    BigInteger[] GiantIndex = Index_DB.ReadKeys(next_step);

                    int Xb = 0;
                    int Xg = 0;
                    foreach (BigInteger BabyElm in BabyElements)
                    {
                        if (BabyElm == 0)
                            break;

                        Xg = 0;
                        foreach (BigInteger GiantElm in GiantElements)
                        {
                            if (GiantElm == 0)
                                break;

                            if ((GiantElm * Kpub % P) == BigInteger.ModPow(BabyElm, m, P))
                            {
                                Elm_DB.CloseFile();
                                Index_DB.CloseFile();
                                //Console.WriteLine((BabyIndex[Xb] * m) - GiantIndex[Xg]);
                                this.Kpv = (BabyIndex[Xb] * m) - GiantIndex[Xg];
                            }
                            Xg++;
                        }
                        Xb++;
                    }

                }

                //Retorna a leitura para a sequência do expoente Baby (j)
                Elm_DB.offset = baby_offset;
                Index_DB.offset = baby_index_offset;
            }

            Elm_DB.CloseFile();
            Index_DB.CloseFile();
            this.Kpv = -1;
        }
        */


        private BinaryDatabase Elm_DB;
        private BinaryDatabase Index_DB;

        public void BabyStep()
        {
            if (File.Exists(this.DataPath + "BabyStep.bin"))
                File.Delete(this.DataPath + "BabyStep.bin");

            if (File.Exists(this.DataPath + "BabyStep_index.bin"))
                File.Delete(this.DataPath + "BabyStep_index.bin");

            this.Elm_DB = new BinaryDatabase(this.DataPath + "BabyStep.bin");
            this.Index_DB = new BinaryDatabase(this.DataPath + "BabyStep_index.bin");

            this.Elm_DB.OpenFile();
            this.Index_DB.OpenFile();

            for (BigInteger j = 1; j <= m; j++)
            {
                BigInteger GroupElm = BigInteger.ModPow(this.g, j, this.P);
                this.Elm_DB.WriteNextKey(GroupElm);
                this.Index_DB.WriteNextKey(j);
            }

            this.Elm_DB.CloseFile();
            this.Index_DB.CloseFile();
        }

        private BigInteger[] Threading_GiantElements;
        private BigInteger[] Threading_GiantIndexes;

        private BigInteger[] Threading_BabyElements;
        private BigInteger[] Threading_BabyIndexes;

        private BigInteger Threading_BabyElmPowM;
        private int Threading_Xb;
        
        private void GiantStep_Thread(Object Param)
        {
            //int Xg = 0;

            BigInteger[] GiantElements = this.Threading_GiantElements;
            BigInteger Kpub = this.Kpub;
            BigInteger P = this.P;
            BigInteger BabyElmPowM = this.Threading_BabyElmPowM;

            int[] Limites = (int[])Param;

            for(int Xg = Limites[0]; Xg < Limites[1]; Xg ++)
            {
                if (this.Kpv != -1 || GiantElements[Xg] == 0)
                    return;

                if ((GiantElements[Xg] * Kpub % P) == BabyElmPowM)
                {
                    //this.Elm_DB.CloseFile();
                    //this.Index_DB.CloseFile();
                    //Console.WriteLine((BabyIndex[Xb] * m) - GiantIndex[Xg]);
                    this.Kpv = (this.Threading_BabyIndexes[this.Threading_Xb] * m) - this.Threading_GiantIndexes[Xg];
                }
                //Xg++;
            }
        }

        public BigInteger GiantStep(BigInteger Kpub, int Threads)
        {
            //if (Threads > 7)
              //  Threads = 7;

            Thread[] threads = new Thread[Threads];

            this.Kpub = Kpub;

            this.Elm_DB = new BinaryDatabase(this.DataPath + "BabyStep.bin"); ;
            this.Index_DB = new BinaryDatabase(this.DataPath + "BabyStep_index.bin");
            this.Elm_DB.OpenFile();
            this.Index_DB.OpenFile();

            //Utilizei [X = Xb * m - Xg], pois dessa forma não preciso calcular o inverso multiplicativo de m, diminuindo
            //a necessidade de processamento. Ficando assim:
            //g^(Xb*m - Xg) = B Mod P
            //g^Xb*m == B * g^Xg


            //Carregar até 15.150.000 elementos (aproximadamente 2 GB de memória RAM considerando elementos de 1024 bits precedidos por 4 bytes
            //contendo o seu tamanho)

            //1024 bits == 128 bytes (tamanho máximo de 1 elemento BigInteger num ataque contra chaves de 1024 bytes)
            //next_step = Capacidade de memoria RAM em bytes / 128 bytes

            long capacidade_memoria_ram = 7000000000;
            long next_step = 0;
            if (128 * this.m > capacidade_memoria_ram)
                next_step = capacidade_memoria_ram / 128;
            else
                next_step = (long)this.m;

            for (BigInteger count_baby = 0; count_baby < this.m; count_baby += next_step)
            {
                this.Threading_BabyElements = this.Elm_DB.ReadKeys(next_step);
                this.Threading_BabyIndexes = this.Index_DB.ReadKeys(next_step);

                BigInteger baby_offset = this.Elm_DB.offset;
                BigInteger baby_index_offset = this.Index_DB.offset;

                //Retorna leitura para o começo do banco de dados para varredura
                this.Elm_DB.offset = 0;
                this.Index_DB.offset = 0;

                //enquanto Offset nao chegou em FileLength
                for (BigInteger count_giant = 0; count_giant < m; count_giant += next_step)
                {

                    //Ler próxima remessa
                    this.Threading_GiantElements = this.Elm_DB.ReadKeys(next_step);
                    this.Threading_GiantIndexes = this.Index_DB.ReadKeys(next_step);

                    //Dividir remessa na quantidade de Thread
                    int threading_step = this.Threading_GiantElements.Length / Threads;

                    this.Threading_Xb = 0;
                    foreach (BigInteger BabyElm in this.Threading_BabyElements)
                    {
                        if (BabyElm == 0)
                            break;

                        this.Threading_BabyElmPowM = BigInteger.ModPow(BabyElm, this.m, this.P);
                        this.Kpv = -1;

                        //Inicia Threads
                        int inicio = 0;
                        for(int i = 0; i < threads.Length; i++)
                        {
                            threads[i] = new Thread(GiantStep_Thread);
                            int[] Limites = new int[] { inicio, inicio + threading_step };
                            if (i == threads.Length - 1)
                                Limites[1] = Threading_GiantElements.Length;
                            threads[i].Start(Limites);

                            inicio += threading_step;
                        }

                        //Aguarda Threads encerrarem
                        foreach (Thread T in threads)
                            T.Join();

                        if (this.Kpv != -1)
                        {
                            this.Elm_DB.CloseFile();
                            this.Index_DB.CloseFile();
                            return this.Kpv;
                        }

                        this.Threading_Xb++;
                    }

                }

                //Retorna a leitura para a sequência do expoente Baby (j)
                this.Elm_DB.offset = baby_offset;
                this.Index_DB.offset = baby_index_offset;
            }

            this.Elm_DB.CloseFile();
            this.Index_DB.CloseFile();
            return -1;
        }


    }
}
