using System;
using System.Collections.Generic;
using System.Text;

using System.Numerics;
using System.IO;

namespace AtaqueDiffieHellman
{
    class BinaryDatabase
    {
        public BinaryDatabase(string FilePath)
        {
            this.FilePath = FilePath;
        }

        public string FilePath;

        private BigInteger _offset;
        public BigInteger offset
        {
            set
            {
                _offset = value;
                //offset tem que ser BigInteger devido a possibilidade de arquivo muito grande, porém a função seek não suporta
                //para mudar a posição do FileStream utilizar valores de 64 bits!

                byte[] b = new byte[8];
                _offset.ToByteArray().CopyTo(b, 0);

                fs.Seek(BitConverter.ToInt64(b), SeekOrigin.Begin);
            }
            get
            {
                return _offset;
            }
        }

        public long FileLength
        {
            get
            {
                return _FileLength;
            }
        }

        private FileStream fs;
        private BinaryReader br;
        private BinaryWriter bw;
        private long _FileLength;

        public void OpenFile()
        {
            fs = new FileStream(FilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
            br = new BinaryReader(fs);
            bw = new BinaryWriter(fs);
            _offset = 0;
            _FileLength = fs.Length;
        }

        public void CloseFile()
        {
            bw.Close();
            br.Close();
            fs.Close();
        }

        public BigInteger ReadNextKey()
        {
            BigInteger Numero_Lido = -1;
            if (_offset <= _FileLength - 5)
            {
                int length = BitConverter.ToInt32(br.ReadBytes(4));
                byte[] b = br.ReadBytes(length);
                Numero_Lido = new BigInteger(b, true);

                _offset += 4 + b.Length;
            }

            return Numero_Lido;
        }

        public BigInteger[] ReadKeys(long count)
        {
            BigInteger[] ret = new BigInteger[count];

            for (long i = 0; i < count; i++)
            {
                BigInteger key = ReadNextKey();

                if (key == -1)
                    break;

                ret[i] = key;
            }

            return ret;
        }

        public void WriteNextKey(BigInteger Key)
        {
            byte[] b = Key.ToByteArray();
            bw.Write(b.Length);
            bw.Write(b);
        }
    }
}
