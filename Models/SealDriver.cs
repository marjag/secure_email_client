using System;
using System.Text;
using System.Collections.Generic;

namespace mailer.Models
{
    class SealDriver : ICipherDriver
    {
        private uint[] keyAsWords = new uint[5];
        private uint[] s_t = new uint[512];
        private uint[] s_s = new uint[256];
        private uint[] s_r = new uint[20];
        private uint keyStreamCnt = 0;
        private int keyStreamIndex = 0;
        private int perBlock = 1024;
        private int rounds;
        private uint[] keyStreamBlock;
        private string key;
        public string Key
        {
            get => key;
            set => key = value;
        }
        
        /**
        * Konstruktor
        * @param string key - dla uproszczenia, klucz w postaci jawnej
        */
        public SealDriver(string key = "abcdefghijklmnoprstu")
        {
            this.rounds = perBlock / 256;
            this.keyStreamBlock = new uint[perBlock];
            this.key = key;
            MakeKeyWords(key);
        }

        /**
         * Generuje szyfrogram w postaci heksadecymalnej na podstawie
         * ustawionego klucza i tekstu jawnego
         * @param string plaintextMessage - tekst w wersji jawnej
         * @return string - szyfrogram (postac heksadecymalna)
         */
        public string Encrypt(string plaintextMessage)
        {
            if (this.key.Length == 0) {
                throw new InvalidOperationException("Key is not set yet");
            }
            string keyString = this.key;
            int len = plaintextMessage.Length;
            int i;
            string outMsg = "";
            // tablice bajtow wiadomosci i wyjscia
            uint[] msgArr = new uint[len];
            uint[] outArr = new uint[len];
            // klucz opcjonalnie moze byc krotszy/dluzszy. Obcinanie/uzupelnienie znakami '0' do |20|
            keyString +="00000000000000000000";
            keyString = keyString.Substring(0,20);

            KeyStreamGenerateTables(keyString);
            // litery wiadomosci na bajty
            for (i = 0; i < len; i++) {
                msgArr[i] = Convert.ToUInt32(plaintextMessage[i]);
            }
            
            outArr = StreamXor(msgArr);

            // szyfrogram heksadecymalnie
            // bajty na hex
            for (i = 0; i < len; i++) {
                outMsg += UintToHex(outArr[i]) + " ";
            }
            return outMsg.Trim();
        }

        /**
         * Generuje tekst w wersji jawnej na podstawie
         * ustawionego klucza i szyfrogramu
         * @param ciphertextHex - kompatybilny szyfrogram w postaci heksadecymalnej
         * @return string - tekst w wersji jawnej
         */
        public string Decrypt(string ciphertextHex)
        {
            if (this.key.Length == 0) {
                throw new InvalidOperationException("Key is not set yet");
            }
            string keyString = this.key;
            int i;
            string outMsg = "";
            // klucz opcjonalnie moze byc krotszy/dluzszy. Obcinanie/uzupelnienie znakami '0' do |20|
            keyString +="00000000000000000000";
            keyString = keyString.Substring(0,20);

            KeyStreamGenerateTables(keyString);
            
            string[] encrypted = ciphertextHex.Split(" ");
            // tablice bajtow wiadomosci i wyjscia
            uint[] msgArr = new uint[encrypted.Length];
            uint[] outArr = new uint[encrypted.Length];

            // szyfrogram na bajty
            // hex na uint
            for (i = 0; i < encrypted.Length; i++) {
                msgArr[i] = HexToUint(encrypted[i]);
            }
            outArr = StreamXor(msgArr);
            // bajty na litery
            for (i = 0; i < encrypted.Length; i++) {
                // Console.WriteLine(outArr[i]);
                outMsg += Convert.ToChar(outArr[i]);
            }
            
            return outMsg.Trim();
        }

        /**
         * Wykonuje operacje XOR znakow ze strumieniem klucza
         * @param uint[] inMsg - zakodowana w bajtach tablica znakow 
         * @return uint[] - tablica po operacji
         */
        private uint[] StreamXor(uint[] inMsg)
        {
            int i = 0;
            uint[] result = new uint[inMsg.Length];
            for (i = 0; i < result.Length; i++) {
                if(keyStreamIndex >= perBlock) {
                    KeyStreamMakeBlock();
                }
                // XOR
                result[i] = inMsg[i] ^ keyStreamBlock[keyStreamIndex];
                keyStreamIndex++;
            }
            return result;
        }

        /**
        * Generuje tablice
        * @param string keyString - klucz
        */     
        private void KeyStreamGenerateTables(string keyString)
        {
            KeyStreamFillTables(keyString);
            keyStreamCnt = 0;
            keyStreamIndex = perBlock;
        }

        /**
        * Generuje nowy blok strumienia klucza
        */
        private void KeyStreamMakeBlock()
        {
            KeyStreamGenerate(keyStreamCnt);
            keyStreamCnt++;
            keyStreamIndex = 0;
        }

        /**
         * Generuje 5 slow z zlancucha klucza
         * @param string key - klucz
         */
        private void MakeKeyWords(string key)
        {
            string[] pieces = CutString(key, 5);
            uint[] h = new uint[5];
            for (int i = 0; i < 5; i++) {
                h[i] = this._01sToInt(TextTo01s(pieces[i]));
            }
            this.keyAsWords = h;
        }
        
        /**
        * Generuje strumien klucza
        * @param uint sectionsCnt - ilosc sekcji
        */
        private void KeyStreamGenerate(uint sectionsCnt)
        {
            uint a,b,c,d,n1,n2,n3,n4;
            uint p,q;
            uint m = 0;
            int rounds = 4;

            for (int l = 0; l < rounds; l++) {
                a = sectionsCnt ^ s_r[4*l];
                b = ByteRotR(sectionsCnt, 8) ^ s_r[4*l+1];
                c = ByteRotR(sectionsCnt, 16) ^ s_r[4*l+2];
                d = ByteRotR(sectionsCnt, 24) ^ s_r[4*l+3];


                for (int j = 0; j < 2; j++) {
                    p = a & 0x7fc;
                    b += s_t[p/4];
                    a = ByteRotR(a, 9);
                    p = b & 0x7fc;
                    c += s_t[p/4];
                    b = ByteRotR(b, 9);
                    p = c & 0x7fc;
                    d += s_t[p/4];
                    c = ByteRotR(c, 9);
                    p = d & 0x7fc;
                    a += s_t[p/4];
                    d = ByteRotR(d, 9);
                }
                n1 = d;
                n2 = b;
                n3 = a;
                n4 = c;

                p = a & 0x7fc;
                b += s_t[p/4];
                a = ByteRotR(a, 9);
                p = b & 0x7fc;
                c += s_t[p/4];
                b = ByteRotR(b, 9);
                p = c & 0x7fc;
                d += s_t[p/4];
                c = ByteRotR(c, 9);
                p = d & 0x7fc;
                a += s_t[p/4];
                d = ByteRotR(d, 9);
                
                for (int i = 0; i < 64; i++) {
                    p = a & 0x7fc;
                    b += s_t[p/4]; a = ByteRotR(a, 9); b ^= a;

                    q = b & 0x7fc;
                    c ^= s_t[q/4]; b = ByteRotR(b, 9); c += b;

                    p = (p+c) & 0x7fc;
                    d += s_t[p/4]; c = ByteRotR(c, 9); d ^= c;

                    q = (q+d) & 0x7fc;
                    a ^= s_t[q/4]; d = ByteRotR(d, 9); a += d;

                    p = (p+a) & 0x7fc;
                    b ^= s_t[p/4]; a = ByteRotR(a, 9);

                    q = (q+b) & 0x7fc;
                    c += s_t[q/4]; b = ByteRotR(b, 9);

                    p = (p+c) & 0x7fc;
                    d ^= s_t[p/4]; c = ByteRotR(c, 9);

                    q = (q+d) & 0x7fc;
                    a += s_t[q/4]; d = ByteRotR(d, 9);

                    keyStreamBlock[m] = b + s_s[4*i]; m++;
                    keyStreamBlock[m] = c ^ s_s[4*i+1]; m++;
                    keyStreamBlock[m] = d + s_s[4*i+2]; m++;
                    keyStreamBlock[m] = a ^ s_s[4*i+3]; m++;
                    // modulo 2
                    if (1 == (i & 1)) {
                        a += n3;
                        c += n4;
                    } else {
                        a += n1;
                        c += n2;
                    }
                }
            }
        }

        /**
         * Wypelnia tablice dla strumienia klucza
         * @param string key - klucz
         */
        private void KeyStreamFillTables(string key)
        {
            int[] result = new int[3];

            uint[] h = new uint[5];
            uint[] tt = new uint[5];
            for (int i = 0; i < 5; i++) { 
                h[i] = 0;
                tt[i] = 0;
            }
            for (uint i = 0; i < 510; i += 5) {
                tt =  Generator(i/5);
                for (int k = 0; k < 5; k++) {
                    s_t[i+k] = tt[k];
                }
            }

            h = Generator(510/5);
            for(uint i = 510; i < 512; i++) {
                s_t[i] = h[i-510];
            }
            h = Generator((-1+0x1000)/5);
            for (uint i = 0; i < 4; i++) {
                s_s[i] = h[i+1];
            }
            for (uint i = 4; i < 254; i += 5) {
                tt = Generator((i+0x1000)/5);
                for (int k = 0; k < 5; k++) {
                    s_s[i+k] = tt[k];
                }
            }
            h = Generator((254+0x1000)/5);
            for (int i = 254; i < 256; i++){
                s_s[i] = h[i-254];
            }
            h = Generator((-2+0x2000)/5);
            for(int i = 0; i < 3; i++) {
                s_r[i] = h[i+2];
            }
            for (uint i = 3; i < 13; i += 5) {
                tt = Generator((i+0x2000)/5);
                for (int k = 0; k < 5; k++) {
                    s_r[i+k] = tt[k];
                }
            }
            h = Generator((13+0x2000)/5);
            for (int i = 13; i < 16; i++) {
                s_r[i] = h[i-13];
            }
        }

        /**
        * Subgenerator dla strumienia klucza
        * @param index - indeks "SHA-1 hash"
        * @return uint[5] - wygenerowane liczby calkowite
        */
        private uint[] Generator(uint ii)
        {
            uint[] h = this.keyAsWords;
            if (h.Length < 5 || h[0] == 0) {
                throw new Exception("Generator aborted, no words initialized from key, call MakeKeyWords() first");
            }

            uint[] result = new uint[5];
            uint k1 = 0x5a827999;
            uint k2 = 0x6ed9eba1;
            uint k3 = 0x8f1bbcdc;
            uint k4 = 0xca62c1d6;

            uint[] w = new uint[80];
            w[0] = ii;

            for (int i = 0; i < 16; i++) {
                w[i] = 0x00000000;
            }
            for (int i = 16; i < 80; i++) {
                w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
            }
            uint a = h[0];
            uint b = h[1];
            uint c = h[2];
            uint d = h[3];
            uint e = h[4];

            for(int i = 0; i < 20; i++) {
                uint tmp = ByteRotR(a, 27) + HashF1(b, c, d) + e + w[i] + k1;
                e = d;
                d = c;
                c = ByteRotR(c, 2);
                b = a;
                a = tmp;
            }
            for (int i = 20; i < 40; i++) {
                uint tmp = ByteRotR(a, 27) + HashF2(b, c, d) + e + w[i] + k2;
                e = d;
                d = c;
                c = ByteRotR(b, 2);
                b = a;
                a = tmp;
            }
            for (int i = 40; i < 60; i++) {
                uint tmp = ByteRotR(a, 27) + HashF3(b, c, d) + e + w[i] + k3;
                e = d;
                d = c;
                c = ByteRotR(b, 2);
                b = a;
                a = tmp;
            }
            for (int i = 60; i < 80; i++) {
                uint tmp = ByteRotR(a, 27) + HashF4(b, c, d) + e + w[i] + k4;
                e = d;
                d = c;
                c = ByteRotR(b, 2);
                b = a;
                a = tmp;
            }

            result[0] = h[0] + a;
            result[1] = h[1] + b;
            result[2] = h[2] + c;
            result[3] = h[3] + d;
            result[4] = h[4] +a;
            return result;
        }
        private uint HashF1(uint x, uint y, uint z)
        {
            return (((x) & (y)) | ((~x) & (z)));
        }
        private uint HashF2(uint x, uint y, uint z)
        {
            return ((x) ^ (y) ^ (z));
        }
        private uint HashF3(uint x, uint y, uint z)
        {
            return (((x) & (y)) | ((x) & (z)) | ((y) & (z)));
        }
        private uint HashF4(uint x, uint y, uint z)
        {
            return ((x) ^ (y) ^ (z));
        }

        /**
        * koduje tekst -data- na postac zerojedynkowa
        * jego znakow
        */
        private string TextTo01s(string data)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in data.ToCharArray())
            {
                sb.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
            }
            return sb.ToString();
        }

        /**
        * zamienia tablice bajtow (liczb) na tekst
        */
        private string BytesToText(byte[] input)
        {
            return Encoding.ASCII.GetString(input);
        }

        /**
        * Zamienia wartosc w postaci zerojedynkowej -data-
        * na wartosc bajta w postaci dziesietnej liczby calkowitej
        */
        private uint _01sToInt(string data)
        {
            return Convert.ToUInt32(data, 2);
        }

        /**
        * ucina lancuch word na pieces porcji
        * @param word - lancuch do rozbicia na fragmenty
        * @param pieces - docelowa ilosc fragmentow
        * @return string[] - pociety lancuch
        */
        private string[] CutString(string word, int pieces)
        {
            int pieceLen = word.Length/pieces;
            string[] hn = new string[pieces];
            for (int i = 0; i < hn.Length; i++)
            {
                hn[i] = word.Substring(i*pieceLen, pieceLen);
            }
            return hn;
        }

        /**
        * Konwertuje liczbe calkowita -intValue- w wersji 
        * dziesietnej na lancuch postaci szesnastkowej
        */
        private string UintToHex(uint intValue)
        {
            return intValue.ToString("X");
        }

        /**
        * Konwertuje liczbe calkowita -hexvalue- w postaci 
        * szesnastkowej na uinta w wersji dziesietnej
        */
        private uint HexToUint(string hexValue)
        {
            return uint.Parse(hexValue, System.Globalization.NumberStyles.HexNumber);
        }

        /**
         * Obrot bitowy na bajcie -input- o -rotVal- miejsc
         */
        private uint ByteRotR(uint input, int rotVal)
        {
            return input >> rotVal;
        }
                
        /**
        * +++
        * zamienia tekst w postaci zerojedynkowej na tablice bajtow 
        * (liczb oznaczajacych wartosci liczbowe dla liter ASCII)
        */
        private byte[] TextToBytes(string inStr)
        {
            return Encoding.ASCII.GetBytes(inStr);
        }

        /**
        * +++
        * zamienia liczbe lub bajt na postac zerojedynkowa
        */
        private string IntTo01s(UInt32 input)
        {
            return Convert.ToString(input, 2).PadLeft(32, '0');
        }

        /**
        * +++
        * zamienia tekst w postaci zerojedynkowej na tekst
        */
        private string _01sToText(string data)
        {
            data = data.PadLeft(data.Length + (8-data.Length%8), '0');

            List<Byte> byteList = new List<Byte>();
            for (int i = 0; i < data.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(data.Substring(i, 8), 2));
            }
            return BytesToText(byteList.ToArray());
        }

    }
}
